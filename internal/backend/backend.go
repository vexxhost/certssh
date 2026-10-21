// Package backend defines how certssh talks to a certificate authority.
package backend

import (
	"context"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	// ErrDenied means the CA refused to sign for the requested principals.
	ErrDenied = errors.New("permission denied")
	// ErrSessionExpired means the session can no longer be used and the
	// user has to log in again.
	ErrSessionExpired = errors.New("session expired")
)

// Session is the result of a login, persisted between commands and read by
// the agent.
type Session struct {
	Context     string    `json:"context"`
	Persona     string    `json:"persona"`
	Token       string    `json:"token,omitempty"`
	Accessor    string    `json:"accessor,omitempty"`
	DisplayName string    `json:"display_name"`
	Policies    []string  `json:"policies,omitempty"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Renewable   bool      `json:"renewable,omitempty"`
	// RenewedAt is the last successful renewal.
	RenewedAt time.Time `json:"renewed_at,omitzero"`
}

// Expired reports whether the session is expired at t, allowing a margin so
// a certificate is not requested with a token about to lapse.
func (s *Session) Expired(t time.Time) bool {
	if s == nil {
		return true
	}
	if s.ExpiresAt.IsZero() {
		return false
	}
	return !t.Add(10 * time.Second).Before(s.ExpiresAt)
}

// NeedsRenewal reports whether more than half the token's current lease has
// been used.
func (s *Session) NeedsRenewal(t time.Time) bool {
	if !s.Renewable || s.ExpiresAt.IsZero() {
		return false
	}
	start := s.IssuedAt
	if s.RenewedAt.After(start) {
		start = s.RenewedAt
	}
	return t.Sub(start) > s.ExpiresAt.Sub(start)/2
}

// Identity identifies a login; a new identity gets a new key.
func (s *Session) Identity() string {
	if s == nil {
		return ""
	}
	if s.Accessor != "" {
		return s.Accessor
	}
	return s.DisplayName + "@" + s.IssuedAt.UTC().Format(time.RFC3339Nano)
}

// LoginOptions carries what a login needs from the caller.
type LoginOptions struct {
	// Token is used by the token method; empty falls back to the
	// environment and the CLI token file.
	Token string
	// Out receives instructions for the user.
	Out io.Writer
	// OpenURL opens a URL in a browser; nil or NoBrowser only prints it.
	OpenURL   func(string) error
	NoBrowser bool
}

// SignRequest is a request for a user certificate.
type SignRequest struct {
	PublicKey  ssh.PublicKey
	Principals []string
	Role       string
	TTL        time.Duration
}

// Backend is a certificate authority.
type Backend interface {
	// Login opens a session for a persona.
	Login(ctx context.Context, persona string, opts LoginOptions) (*Session, error)
	// Sign issues a user certificate.
	Sign(ctx context.Context, s *Session, req SignRequest) (*ssh.Certificate, error)
	// HostCAs returns the public keys that sign host certificates.
	HostCAs(ctx context.Context) ([]ssh.PublicKey, error)
	// Renew extends the session; backends without renewal return it as is.
	Renew(ctx context.Context, s *Session) (*Session, error)
	// Logout revokes the session.
	Logout(ctx context.Context, s *Session) error
}
