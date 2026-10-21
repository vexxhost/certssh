// Package session stores login sessions on disk, one file per context, so the
// CLI and the agent share them.
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/vexxhost/certssh/internal/backend"
)

// ErrNoSession means nobody has logged in to the context.
var ErrNoSession = errors.New("not logged in")

var safeName = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// Store keeps sessions under a directory.
type Store struct {
	Dir string
}

// Path returns the file holding a context's session.
func (s Store) Path(context string) string {
	return filepath.Join(s.Dir, safeName.ReplaceAllString(context, "_")+".json")
}

// Load reads a context's session.
func (s Store) Load(context string) (*backend.Session, error) {
	data, err := os.ReadFile(s.Path(context))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	var sess backend.Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("%s: %w", s.Path(context), err)
	}
	return &sess, nil
}

// ModTime returns when a context's session file last changed, or the zero
// time when there is none.
func (s Store) ModTime(context string) time.Time {
	fi, err := os.Stat(s.Path(context))
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

// Save writes a session readable only by the user.
func (s Store) Save(sess *backend.Session) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.Dir, ".session-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.Path(sess.Context))
}

// Delete removes a context's session.
func (s Store) Delete(context string) error {
	err := os.Remove(s.Path(context))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
