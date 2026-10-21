package session

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vexxhost/certssh/internal/backend"
)

func TestStore(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "sessions")}
	if _, err := s.Load("ctx"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("got %v, want ErrNoSession", err)
	}
	in := &backend.Session{Context: "a/b c", Token: "secret", DisplayName: "alice", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.Save(in); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(s.Path("a/b c"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("session file mode %v, want 0600", fi.Mode().Perm())
	}
	if filepath.Dir(s.Path("a/b c")) != s.Dir {
		t.Fatal("context names must not escape the directory")
	}
	out, err := s.Load("a/b c")
	if err != nil || out.Token != "secret" {
		t.Fatalf("%+v %v", out, err)
	}
	if err := s.Delete("a/b c"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("a/b c"); err != nil {
		t.Fatalf("deleting twice: %v", err)
	}
}

func TestSessionTimes(t *testing.T) {
	now := time.Now()
	s := &backend.Session{IssuedAt: now, ExpiresAt: now.Add(time.Hour), Renewable: true}
	if s.Expired(now) || s.NeedsRenewal(now.Add(10*time.Minute)) || !s.NeedsRenewal(now.Add(31*time.Minute)) {
		t.Fatal("renewal threshold is half the lease")
	}
	if !s.Expired(now.Add(time.Hour - time.Second)) {
		t.Fatal("a session about to lapse counts as expired")
	}
	if (&backend.Session{}).Expired(now) {
		t.Fatal("a session without expiry never expires")
	}
}
