package openbao

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"golang.org/x/crypto/ssh"

	"github.com/vexxhost/certssh/internal/backend"
	"github.com/vexxhost/certssh/internal/config"
)

const rootToken = "certssh-test-root"

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startBao runs an OpenBao dev server and returns its address and a root
// client. Tests are skipped unless BAO_BIN points at a bao binary.
func startBao(t *testing.T) (string, *api.Client) {
	t.Helper()
	bin := os.Getenv("BAO_BIN")
	if bin == "" {
		t.Skip("BAO_BIN not set")
	}
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	cmd := exec.Command(bin, "server", "-dev", "-dev-root-token-id="+rootToken, "-dev-listen-address="+addr)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	address := "http://" + addr
	cfg := api.DefaultConfig()
	cfg.Address = address
	client, err := api.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(rootToken)
	for i := 0; ; i++ {
		if _, err := client.Sys().Health(); err == nil {
			break
		}
		if i > 100 {
			t.Fatal("OpenBao did not start")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return address, client
}

func write(t *testing.T, c *api.Client, path string, data map[string]any) *api.Secret {
	t.Helper()
	s, err := c.Logical().Write(path, data)
	if err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return s
}

// setupSSH mirrors a production layout: one user CA with a role allowing two
// principals, and a policy that lets the caller sign exactly one of them.
func setupSSH(t *testing.T, c *api.Client) {
	t.Helper()
	for _, m := range []string{"ssh-client-signer", "ssh-host-signer"} {
		if err := c.Sys().Mount(m, &api.MountInput{Type: "ssh"}); err != nil {
			t.Fatal(err)
		}
		write(t, c, m+"/config/ca", map[string]any{"generate_signing_key": true, "key_type": "ssh-ed25519"})
	}
	write(t, c, "ssh-client-signer/roles/human", map[string]any{
		"key_type": "ca", "allow_user_certificates": true, "allowed_users": "env:infra,env:public",
		"default_extensions": map[string]string{"permit-pty": ""}, "allowed_extensions": "permit-pty",
		"ttl": "1h", "key_id_format": "{{token_display_name}}",
	})
	if err := c.Sys().PutPolicy("ssh-infra", `
path "ssh-client-signer/sign/human" {
  capabilities        = ["create", "update"]
  required_parameters = ["valid_principals"]
  allowed_parameters = {
    "valid_principals" = ["env:infra"]
    "*"                = []
  }
  denied_parameters = {
    "key_id" = []
  }
}`); err != nil {
		t.Fatal(err)
	}
}

func userToken(t *testing.T, c *api.Client) string {
	t.Helper()
	s, err := c.Auth().Token().Create(&api.TokenCreateRequest{
		DisplayName: "alice", Policies: []string{"ssh-infra"}, TTL: "1h", Renewable: boolPtr(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s.Auth.ClientToken
}

func boolPtr(b bool) *bool { return &b }

func pubKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestTokenLoginSignRenewLogout(t *testing.T) {
	address, root := startBao(t)
	setupSSH(t, root)
	ctx := context.Background()
	b, err := New("test", &config.Context{Address: address, Login: map[string]config.Login{"human": {Method: "token"}}})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := b.Login(ctx, "human", backend.LoginOptions{Token: userToken(t, root)})
	if err != nil {
		t.Fatal(err)
	}
	if sess.DisplayName != "token-alice" || !sess.Renewable || sess.Accessor == "" {
		t.Fatalf("session: %+v", sess)
	}
	if d := time.Until(sess.ExpiresAt); d < 50*time.Minute || d > 61*time.Minute {
		t.Fatalf("expires in %s, want about an hour", d)
	}

	key := pubKey(t)
	cert, err := b.Sign(ctx, sess, backend.SignRequest{PublicKey: key, Principals: []string{"env:infra"}, Role: "human"})
	if err != nil {
		t.Fatal(err)
	}
	if cert.KeyId != "token-alice" || len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "env:infra" {
		t.Fatalf("certificate: key id %q, principals %v", cert.KeyId, cert.ValidPrincipals)
	}
	if string(cert.Key.Marshal()) != string(key.Marshal()) {
		t.Fatal("certificate is for another key")
	}

	_, err = b.Sign(ctx, sess, backend.SignRequest{PublicKey: key, Principals: []string{"env:public"}, Role: "human"})
	if !errors.Is(err, backend.ErrDenied) {
		t.Fatalf("signing env:public: got %v, want ErrDenied", err)
	}
	_, err = b.Sign(ctx, sess, backend.SignRequest{PublicKey: key, Principals: []string{"env:infra"}, Role: "nope"})
	if !errors.Is(err, backend.ErrDenied) {
		t.Fatalf("signing with an unknown role: got %v, want ErrDenied", err)
	}

	cas, err := b.HostCAs(ctx)
	if err != nil || len(cas) != 1 {
		t.Fatalf("host CAs: %v %v", cas, err)
	}

	renewed, err := b.Renew(ctx, sess)
	if err != nil || renewed.RenewedAt.IsZero() {
		t.Fatalf("renew: %+v %v", renewed, err)
	}

	if err := b.Logout(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if err := b.Logout(ctx, sess); err != nil {
		t.Fatalf("second logout should be a no-op: %v", err)
	}
	_, err = b.Sign(ctx, sess, backend.SignRequest{PublicKey: key, Principals: []string{"env:infra"}, Role: "human"})
	if !errors.Is(err, backend.ErrSessionExpired) {
		t.Fatalf("signing after logout: got %v, want ErrSessionExpired", err)
	}
}

func TestEnvironmentTokenIsNotUsedForSigning(t *testing.T) {
	address, root := startBao(t)
	setupSSH(t, root)
	t.Setenv("BAO_TOKEN", rootToken)
	t.Setenv("VAULT_TOKEN", rootToken)
	b, err := New("test", &config.Context{Address: address})
	if err != nil {
		t.Fatal(err)
	}
	sess := &backend.Session{Token: userToken(t, root), ExpiresAt: time.Now().Add(time.Hour)}
	_, err = b.Sign(context.Background(), sess, backend.SignRequest{PublicKey: pubKey(t), Principals: []string{"env:public"}, Role: "human"})
	if !errors.Is(err, backend.ErrDenied) {
		t.Fatalf("got %v: the root token in the environment must not be used", err)
	}
}

func TestTokenFromEnvironmentForTokenLogin(t *testing.T) {
	address, root := startBao(t)
	setupSSH(t, root)
	t.Setenv("BAO_TOKEN", userToken(t, root))
	b, err := New("test", &config.Context{Address: address, Login: map[string]config.Login{"human": {Method: "token"}}})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := b.Login(context.Background(), "human", backend.LoginOptions{})
	if err != nil || sess.DisplayName != "token-alice" {
		t.Fatalf("%+v %v", sess, err)
	}
}

// idp is a minimal OpenID Connect provider that approves every request.
type idp struct {
	srv   *httptest.Server
	key   *rsa.PrivateKey
	mu    sync.Mutex
	codes map[string]url.Values
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &idp{key: key, codes: map[string]url.Values{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		u := p.srv.URL
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": u, "authorization_endpoint": u + "/authorize", "token_endpoint": u + "/token",
			"jwks_uri": u + "/keys", "response_types_supported": []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
			"n": b64(p.key.N.Bytes()), "e": b64(bigEndian(p.key.E)),
		}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := fmt.Sprintf("code-%d", time.Now().UnixNano())
		p.mu.Lock()
		p.codes[code] = q
		p.mu.Unlock()
		target, _ := url.Parse(q.Get("redirect_uri"))
		v := target.Query()
		v.Set("code", code)
		v.Set("state", q.Get("state"))
		target.RawQuery = v.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		q, ok := p.codes[r.PostForm.Get("code")]
		delete(p.codes, r.PostForm.Get("code"))
		p.mu.Unlock()
		if !ok {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		if ch := q.Get("code_challenge"); ch != "" {
			sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if b64(sum[:]) != ch {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
		}
		now := time.Now()
		idToken := p.sign(map[string]any{
			"iss": p.srv.URL, "sub": "alice", "aud": q.Get("client_id"), "iat": now.Unix(),
			"exp": now.Add(time.Hour).Unix(), "nonce": q.Get("nonce"), "email": "alice@example.com",
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": idToken,
		})
	})
	p.srv = httptest.NewTLSServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func bigEndian(n int) []byte {
	var out []byte
	for ; n > 0; n >>= 8 {
		out = append([]byte{byte(n)}, out...)
	}
	return out
}

func (p *idp) sign(claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	c, _ := json.Marshal(claims)
	input := b64(h) + "." + b64(c)
	sum := sha256.Sum256([]byte(input))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	return input + "." + b64(sig)
}

func (p *idp) caPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.srv.Certificate().Raw}))
}

// browser follows the login URL the way a user's browser would, in the
// background as a real browser does.
func (p *idp) browser(t *testing.T) func(string) error {
	return func(u string) error {
		client := p.srv.Client()
		go func() {
			resp, err := client.Get(u) //nolint:noctx // test browser
			if err != nil {
				t.Logf("browser: %v", err)
				return
			}
			resp.Body.Close()
		}()
		return nil
	}
}

func TestOIDCClientAndDirectCallbacks(t *testing.T) {
	address, root := startBao(t)
	setupSSH(t, root)
	p := newIDP(t)
	if err := root.Sys().EnableAuthWithOptions("oidc", &api.EnableAuthOptions{Type: "oidc"}); err != nil {
		t.Fatal(err)
	}
	write(t, root, "auth/oidc/config", map[string]any{
		"oidc_discovery_url": p.srv.URL, "oidc_discovery_ca_pem": p.caPEM(),
		"oidc_client_id": "certssh", "oidc_client_secret": "s3cret", "default_role": "human",
	})
	listen := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	write(t, root, "auth/oidc/role/human", map[string]any{
		"role_type": "oidc", "user_claim": "email", "bound_audiences": []string{"certssh"},
		"allowed_redirect_uris": []string{"http://" + listen + "/oidc/callback"},
		"token_policies":        []string{"ssh-infra"}, "token_ttl": "1h",
	})
	direct, err := directRedirect(address, "oidc")
	if err != nil {
		t.Fatal(err)
	}
	write(t, root, "auth/oidc/role/agent", map[string]any{
		"role_type": "oidc", "user_claim": "email", "bound_audiences": []string{"certssh"},
		"allowed_redirect_uris": []string{direct}, "callback_mode": "direct",
		"oidc_disable_confirmation": true, "poll_interval": 1,
		"token_policies": []string{"ssh-infra"}, "token_ttl": "30m",
	})

	b, err := New("test", &config.Context{Address: address, Login: map[string]config.Login{
		"human": {Method: "oidc", Mount: "oidc", ListenAddress: listen},
		"agent": {Method: "oidc", Mount: "oidc", Role: "agent"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var out strings.Builder
	for _, persona := range []string{"human", "agent"} {
		sess, err := b.Login(ctx, persona, backend.LoginOptions{Out: &out, OpenURL: p.browser(t)})
		if err != nil {
			t.Fatalf("%s login: %v\n%s", persona, err, out.String())
		}
		if sess.DisplayName != "oidc-alice@example.com" || sess.Persona != persona {
			t.Fatalf("%s session: %+v", persona, sess)
		}
		if _, err := b.Sign(ctx, sess, backend.SignRequest{PublicKey: pubKey(t), Principals: []string{"env:infra"}, Role: "human"}); err != nil {
			t.Fatalf("%s sign: %v", persona, err)
		}
	}
	if !strings.Contains(out.String(), "Waiting for approval") {
		t.Fatalf("direct mode did not tell the user it is waiting:\n%s", out.String())
	}
}

func TestOIDCRefusedRedirectExplainsWhy(t *testing.T) {
	address, root := startBao(t)
	p := newIDP(t)
	if err := root.Sys().EnableAuthWithOptions("oidc", &api.EnableAuthOptions{Type: "oidc"}); err != nil {
		t.Fatal(err)
	}
	write(t, root, "auth/oidc/config", map[string]any{
		"oidc_discovery_url": p.srv.URL, "oidc_discovery_ca_pem": p.caPEM(),
		"oidc_client_id": "certssh", "oidc_client_secret": "s3cret", "default_role": "human",
	})
	write(t, root, "auth/oidc/role/human", map[string]any{
		"role_type": "oidc", "user_claim": "email", "bound_audiences": []string{"certssh"},
		"allowed_redirect_uris": []string{"http://localhost:1/oidc/callback"},
	})
	b, _ := New("test", &config.Context{Address: address, Login: map[string]config.Login{
		"human": {ListenAddress: fmt.Sprintf("127.0.0.1:%d", freePort(t))},
	}})
	_, err := b.Login(context.Background(), "human", backend.LoginOptions{})
	if err == nil || !strings.Contains(err.Error(), "allowed redirect URI") {
		t.Fatalf("got %v", err)
	}
}

func TestCleanErrors(t *testing.T) {
	got := cleanErrors([]string{"1 error occurred:\n\t* permission denied\n\n", "env:x is not a valid value for valid_principals"})
	if want := "permission denied; env:x is not a valid value for valid_principals"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestDirectRedirect(t *testing.T) {
	cases := map[string]string{
		"https://openbao.example.com":       "https://openbao.example.com:443/v1/auth/atlas/oidc/callback",
		"https://openbao.example.com:8200/": "https://openbao.example.com:8200/v1/auth/atlas/oidc/callback",
		"http://127.0.0.1":                  "http://127.0.0.1:80/v1/auth/atlas/oidc/callback",
	}
	for in, want := range cases {
		got, err := directRedirect(in, "atlas")
		if err != nil || got != want {
			t.Errorf("directRedirect(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}
