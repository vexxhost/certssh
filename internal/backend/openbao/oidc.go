package openbao

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openbao/openbao/api/v2"

	"github.com/vexxhost/certssh/internal/backend"
	"github.com/vexxhost/certssh/internal/config"
)

const (
	// callbackTimeout bounds a login waiting for a browser on this machine.
	callbackTimeout = 5 * time.Minute
	// pollTimeout matches how long OpenBao keeps a pending OIDC request.
	pollTimeout = 10 * time.Minute
)

func (b *Backend) loginOIDC(ctx context.Context, l config.Login, opts backend.LoginOptions) (*api.Secret, error) {
	c, err := b.with("")
	if err != nil {
		return nil, err
	}
	nonce, err := randomString()
	if err != nil {
		return nil, err
	}
	out := opts.Out
	if out == nil {
		out = io.Discard
	}

	var redirect string
	var listener net.Listener
	switch l.Callback {
	case "client":
		listener, err = (&net.ListenConfig{}).Listen(ctx, "tcp", l.ListenAddress)
		if err != nil {
			return nil, fmt.Errorf("listening for the OIDC callback on %s: %w", l.ListenAddress, err)
		}
		defer listener.Close()
		redirect = "http://" + l.ListenAddress + "/oidc/callback"
	case "direct":
		redirect, err = directRedirect(b.ctx.Address, l.Mount)
		if err != nil {
			return nil, err
		}
	case "device":
	default:
		return nil, fmt.Errorf("unknown callback mode %q", l.Callback)
	}

	data := map[string]any{"role": l.Role, "client_nonce": nonce}
	if redirect != "" {
		data["redirect_uri"] = redirect
	}
	secret, err := c.Logical().WriteWithContext(ctx, "auth/"+l.Mount+"/oidc/auth_url", data)
	if err != nil {
		return nil, err
	}
	authURL, state, interval, userCode := "", "", 5, ""
	if secret != nil {
		authURL, _ = secret.Data["auth_url"].(string)
		state, _ = secret.Data["state"].(string)
		userCode, _ = secret.Data["user_code"].(string)
		if s, ok := secret.Data["poll_interval"].(string); ok {
			if n, err := strconv.Atoi(s); err == nil && n > 0 {
				interval = n
			}
		}
	}
	if authURL == "" {
		return nil, fmt.Errorf("auth/%s refused the login request (check the role %q and that %q is an allowed redirect URI)", l.Mount, l.Role, redirect)
	}
	if l.Callback != "client" && state == "" {
		return nil, fmt.Errorf("auth/%s did not return a state; is the role's callback_mode %q?", l.Mount, l.Callback)
	}

	fmt.Fprintf(out, "Complete the login in your browser:\n\n    %s\n\n", authURL)
	if userCode != "" {
		fmt.Fprintf(out, "Enter the code %s when asked.\n\n", userCode)
	}
	if opts.OpenURL != nil && !opts.NoBrowser {
		if err := opts.OpenURL(authURL); err != nil {
			fmt.Fprintf(out, "Could not open a browser (%v); open the link yourself.\n", err)
		}
	}

	if l.Callback == "client" {
		return b.awaitCallback(ctx, c, l.Mount, nonce, listener, out)
	}
	fmt.Fprintf(out, "Waiting for approval (up to %s)...\n", pollTimeout)
	return b.poll(ctx, c, l.Mount, state, nonce, time.Duration(interval)*time.Second)
}

// directRedirect builds OpenBao's own callback URL with an explicit port,
// the form roles list in allowed_redirect_uris.
func directRedirect(address, mount string) (string, error) {
	u, err := url.Parse(address)
	if err != nil {
		return "", err
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	return fmt.Sprintf("%s://%s/v1/auth/%s/oidc/callback", u.Scheme, net.JoinHostPort(u.Hostname(), port), mount), nil
}

type callbackResult struct {
	secret *api.Secret
	err    error
}

func (b *Backend) awaitCallback(ctx context.Context, c *api.Client, mount, nonce string, listener net.Listener, out io.Writer) (*api.Secret, error) {
	done := make(chan callbackResult, 1)
	var once sync.Once
	finish := func(r callbackResult) { once.Do(func() { done <- r }) }

	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		data := map[string][]string{
			"state":        {r.FormValue("state")},
			"code":         {r.FormValue("code")},
			"id_token":     {r.FormValue("id_token")},
			"client_nonce": {nonce},
		}
		if r.Method == http.MethodPost {
			// form_post response mode: hand the form to OpenBao first,
			// then complete with a GET as for a redirect.
			form := url.Values(data)
			req, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
				strings.TrimSuffix(c.Address(), "/")+"/v1/auth/"+mount+"/oidc/callback", strings.NewReader(form.Encode()))
			if err == nil {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if resp, err := c.CloneConfig().HttpClient.Do(req); err == nil {
					_ = resp.Body.Close()
				}
			}
			delete(data, "id_token")
		}
		secret, err := c.Logical().ReadWithDataWithContext(r.Context(), "auth/"+mount+"/oidc/callback", data)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, page, "Login failed", html.EscapeString(err.Error()))
		} else {
			fmt.Fprintf(w, page, "Logged in", "You can close this window and return to the terminal.")
		}
		finish(callbackResult{secret, err})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			finish(callbackResult{nil, err})
		}
	}()
	defer srv.Close()

	fmt.Fprintln(out, "Waiting for the browser...")
	timer := time.NewTimer(callbackTimeout)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.secret, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, errors.New("timed out waiting for the browser")
	}
}

func (b *Backend) poll(ctx context.Context, c *api.Client, mount, state, nonce string, interval time.Duration) (*api.Secret, error) {
	deadline := time.Now().Add(pollTimeout)
	data := map[string]any{"state": state, "client_nonce": nonce}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
		secret, err := c.Logical().WriteWithContext(ctx, "auth/"+mount+"/oidc/poll", data)
		if err == nil {
			return secret, nil
		}
		msg := err.Error()
		switch {
		case strings.Contains(msg, "slow_down"):
			interval *= 2
		case strings.Contains(msg, "authorization_pending"):
		default:
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, errors.New("timed out waiting for approval")
		}
	}
}

func randomString() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

const page = `<!doctype html><html><head><meta charset="utf-8"><title>certssh</title></head>
<body style="font-family:sans-serif;margin:4em"><h1>%s</h1><p>%s</p></body></html>`
