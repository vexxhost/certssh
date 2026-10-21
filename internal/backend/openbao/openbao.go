// Package openbao signs certificates with the SSH secrets engine of OpenBao
// or HashiCorp Vault.
package openbao

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/openbao/openbao/api/v2"
	"golang.org/x/crypto/ssh"

	"github.com/vexxhost/certssh/internal/backend"
	"github.com/vexxhost/certssh/internal/config"
)

// Backend talks to one OpenBao or Vault server.
type Backend struct {
	name   string
	ctx    *config.Context
	client *api.Client
	now    func() time.Time
}

// New returns a backend for a context.
func New(name string, c *config.Context) (*Backend, error) {
	cfg := api.DefaultConfig()
	if cfg.Error != nil {
		return nil, cfg.Error
	}
	cfg.Address = c.Address
	cfg.AgentAddress = ""
	cfg.Timeout = 30 * time.Second
	if c.CACert != "" {
		if err := cfg.ConfigureTLS(&api.TLSConfig{CACert: config.Expand(c.CACert)}); err != nil {
			return nil, err
		}
	}
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	b := &Backend{name: name, ctx: c, client: client, now: time.Now}
	b.prepare(client, "")
	return b, nil
}

// prepare pins a client to the context's namespace and the given token,
// overriding whatever BAO_TOKEN or BAO_NAMESPACE the environment holds.
func (b *Backend) prepare(c *api.Client, token string) {
	if token == "" {
		c.ClearToken()
	} else {
		c.SetToken(token)
	}
	if b.ctx.Namespace != "" {
		c.SetNamespace(b.ctx.Namespace)
	} else {
		c.ClearNamespace()
	}
}

func (b *Backend) with(token string) (*api.Client, error) {
	c, err := b.client.Clone()
	if err != nil {
		return nil, err
	}
	b.prepare(c, token)
	return c, nil
}

// Login opens a session with the persona's configured method.
func (b *Backend) Login(ctx context.Context, persona string, opts backend.LoginOptions) (*backend.Session, error) {
	l := b.ctx.LoginFor(persona)
	var token string
	switch l.Method {
	case "token":
		token = opts.Token
		if token == "" {
			token = tokenFromEnvironment()
		}
		if token == "" {
			return nil, errors.New("no token given (use -token, BAO_TOKEN, VAULT_TOKEN or ~/.vault-token)")
		}
	case "oidc":
		secret, err := b.loginOIDC(ctx, l, opts)
		if err != nil {
			return nil, err
		}
		if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
			return nil, errors.New("login returned no token")
		}
		token = secret.Auth.ClientToken
	default:
		return nil, fmt.Errorf("unsupported login method %q", l.Method)
	}
	sess, err := b.lookup(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("looking up the new token: %w", err)
	}
	sess.Persona = persona
	return sess, nil
}

func tokenFromEnvironment() string {
	for _, v := range []string{"BAO_TOKEN", "VAULT_TOKEN"} {
		if t := os.Getenv(v); t != "" {
			return t
		}
	}
	if h, err := os.UserHomeDir(); err == nil {
		if data, err := os.ReadFile(filepath.Join(h, ".vault-token")); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

func (b *Backend) lookup(ctx context.Context, token string) (*backend.Session, error) {
	c, err := b.with(token)
	if err != nil {
		return nil, err
	}
	secret, err := c.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.New("empty token lookup")
	}
	now := b.now()
	sess := &backend.Session{Context: b.name, Token: token, IssuedAt: now}
	sess.Accessor, _ = secret.TokenAccessor()
	sess.Policies, _ = secret.TokenPolicies()
	sess.Renewable, _ = secret.TokenIsRenewable()
	if s, ok := secret.Data["display_name"].(string); ok {
		sess.DisplayName = s
	}
	if s, ok := secret.Data["issue_time"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			sess.IssuedAt = t
		}
	}
	if s, ok := secret.Data["expire_time"].(string); ok && s != "" {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			sess.ExpiresAt = t
		}
	} else if ttl, err := secret.TokenTTL(); err == nil && ttl > 0 {
		sess.ExpiresAt = now.Add(ttl)
	}
	return sess, nil
}

// Sign asks the user CA's role to sign the key.
func (b *Backend) Sign(ctx context.Context, s *backend.Session, req backend.SignRequest) (*ssh.Certificate, error) {
	if s.Expired(b.now()) {
		return nil, backend.ErrSessionExpired
	}
	c, err := b.with(s.Token)
	if err != nil {
		return nil, err
	}
	data := map[string]any{
		"public_key":       strings.TrimSpace(string(ssh.MarshalAuthorizedKey(req.PublicKey))),
		"valid_principals": strings.Join(req.Principals, ","),
		"cert_type":        "user",
	}
	if req.TTL > 0 {
		data["ttl"] = req.TTL.String()
	}
	path := b.ctx.UserCA() + "/sign/" + req.Role
	secret, err := c.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, b.classify(ctx, s, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("%s returned nothing", path)
	}
	signed, _ := secret.Data["signed_key"].(string)
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signed))
	if err != nil {
		return nil, fmt.Errorf("parsing signed key: %w", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("signed key is not a certificate")
	}
	return cert, nil
}

// classify maps API errors onto the backend's error kinds. OpenBao answers
// 403 both for a dead token and for a policy refusal, so a 403 is followed by
// a token lookup to tell them apart.
func (b *Backend) classify(ctx context.Context, s *backend.Session, err error) error {
	var re *api.ResponseError
	if !errors.As(err, &re) {
		return err
	}
	msg := cleanErrors(re.Errors)
	switch re.StatusCode {
	case http.StatusForbidden:
		if _, lerr := b.lookup(ctx, s.Token); lerr != nil {
			var lre *api.ResponseError
			if errors.As(lerr, &lre) && lre.StatusCode == http.StatusForbidden {
				return backend.ErrSessionExpired
			}
		}
		if msg == "" || msg == "permission denied" {
			return fmt.Errorf("%w by policy", backend.ErrDenied)
		}
		return fmt.Errorf("%w: %s", backend.ErrDenied, msg)
	case http.StatusBadRequest:
		return fmt.Errorf("%w: %s", backend.ErrDenied, msg)
	case http.StatusUnauthorized:
		return backend.ErrSessionExpired
	}
	return err
}

var errorCount = regexp.MustCompile(`^\d+ errors? occurred:$`)

// cleanErrors flattens OpenBao's error list, which often holds one
// multi-line "1 error occurred: * ..." string, into a single line.
func cleanErrors(errs []string) string {
	var parts []string
	for _, e := range errs {
		for _, line := range strings.Split(e, "\n") {
			line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "*"))
			if line != "" && !errorCount.MatchString(line) {
				parts = append(parts, line)
			}
		}
	}
	return strings.Join(parts, "; ")
}

// HostCAs reads the host CA's public key, which needs no token.
func (b *Backend) HostCAs(ctx context.Context) ([]ssh.PublicKey, error) {
	mount := b.ctx.HostCA()
	if mount == "-" {
		return nil, nil
	}
	c, err := b.with("")
	if err != nil {
		return nil, err
	}
	resp, err := c.Logical().ReadRawWithContext(ctx, mount+"/public_key")
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s/public_key: HTTP %d", mount, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	var keys []ssh.PublicKey
	for len(data) > 0 {
		k, _, _, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			break
		}
		keys = append(keys, k)
		data = rest
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s/public_key holds no key", mount)
	}
	return keys, nil
}

// Renew extends the token's lease.
func (b *Backend) Renew(ctx context.Context, s *backend.Session) (*backend.Session, error) {
	c, err := b.with(s.Token)
	if err != nil {
		return nil, err
	}
	secret, err := c.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		return nil, b.classify(ctx, s, err)
	}
	if secret == nil || secret.Auth == nil {
		return s, nil
	}
	now := b.now()
	renewed := *s
	renewed.RenewedAt = now
	renewed.Renewable = secret.Auth.Renewable
	if secret.Auth.LeaseDuration > 0 {
		renewed.ExpiresAt = now.Add(time.Duration(secret.Auth.LeaseDuration) * time.Second)
	}
	return &renewed, nil
}

// Logout revokes the token.
func (b *Backend) Logout(ctx context.Context, s *backend.Session) error {
	c, err := b.with(s.Token)
	if err != nil {
		return err
	}
	err = c.Auth().Token().RevokeSelfWithContext(ctx, "")
	var re *api.ResponseError
	if errors.As(err, &re) && re.StatusCode == http.StatusForbidden {
		return nil
	}
	return err
}
