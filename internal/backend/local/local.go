// Package local signs certificates with a CA private key on disk. It is meant
// for tests, demos and very small sites; there is no login beyond being able
// to read the key.
package local

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"os/user"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/vexxhost/certssh/internal/backend"
	"github.com/vexxhost/certssh/internal/config"
)

// Backend is the local CA.
type Backend struct {
	name string
	cfg  config.Local
	ttl  time.Duration
	now  func() time.Time
}

// New returns a local backend for a context.
func New(name string, cfg *config.Local) (*Backend, error) {
	ttl := 8 * time.Hour
	if cfg.TTL != "" {
		d, err := time.ParseDuration(cfg.TTL)
		if err != nil {
			return nil, fmt.Errorf("local.ttl: %w", err)
		}
		ttl = d
	}
	return &Backend{name: name, cfg: *cfg, ttl: ttl, now: time.Now}, nil
}

func (b *Backend) signer() (ssh.Signer, error) {
	data, err := os.ReadFile(config.Expand(b.cfg.UserCAKey))
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

// Login checks the CA key is readable and opens a session.
func (b *Backend) Login(_ context.Context, persona string, _ backend.LoginOptions) (*backend.Session, error) {
	if _, err := b.signer(); err != nil {
		return nil, fmt.Errorf("reading CA key: %w", err)
	}
	name := "local"
	if u, err := user.Current(); err == nil {
		name = "local-" + u.Username
	}
	now := b.now()
	return &backend.Session{
		Context:     b.name,
		Persona:     persona,
		DisplayName: name,
		IssuedAt:    now,
		ExpiresAt:   now.Add(b.ttl),
	}, nil
}

// Sign issues a certificate valid until the session ends.
func (b *Backend) Sign(_ context.Context, s *backend.Session, req backend.SignRequest) (*ssh.Certificate, error) {
	now := b.now()
	if s.Expired(now) {
		return nil, backend.ErrSessionExpired
	}
	if len(req.Principals) == 0 {
		return nil, fmt.Errorf("%w: no principals requested", backend.ErrDenied)
	}
	if len(b.cfg.AllowedPrincipals) > 0 {
		for _, p := range req.Principals {
			if !slices.Contains(b.cfg.AllowedPrincipals, p) {
				return nil, fmt.Errorf("%w: principal %q is not allowed", backend.ErrDenied, p)
			}
		}
	}
	ca, err := b.signer()
	if err != nil {
		return nil, err
	}
	until := s.ExpiresAt
	if req.TTL > 0 && now.Add(req.TTL).Before(until) {
		until = now.Add(req.TTL)
	}
	var serial [8]byte
	if _, err := rand.Read(serial[:]); err != nil {
		return nil, err
	}
	cert := &ssh.Certificate{
		Key:             req.PublicKey,
		Serial:          binary.BigEndian.Uint64(serial[:]),
		CertType:        ssh.UserCert,
		KeyId:           s.DisplayName,
		ValidPrincipals: req.Principals,
		ValidAfter:      uint64(now.Add(-time.Minute).Unix()), //nolint:gosec // after 1970
		ValidBefore:     uint64(until.Unix()),                 //nolint:gosec // after 1970
		Permissions: ssh.Permissions{Extensions: map[string]string{
			"permit-pty":              "",
			"permit-port-forwarding":  "",
			"permit-agent-forwarding": "",
		}},
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		return nil, err
	}
	return cert, nil
}

// HostCAs reads the host CA public key file, if configured.
func (b *Backend) HostCAs(context.Context) ([]ssh.PublicKey, error) {
	if b.cfg.HostCAKey == "" {
		return nil, nil
	}
	data, err := os.ReadFile(config.Expand(b.cfg.HostCAKey))
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
		return nil, fmt.Errorf("%s holds no public key", b.cfg.HostCAKey)
	}
	return keys, nil
}

// Renew returns the session unchanged.
func (b *Backend) Renew(_ context.Context, s *backend.Session) (*backend.Session, error) {
	return s, nil
}

// Logout has nothing to revoke.
func (b *Backend) Logout(context.Context, *backend.Session) error { return nil }
