// Package backends opens the backend a context is configured for.
package backends

import (
	"fmt"

	"github.com/vexxhost/certssh/internal/backend"
	"github.com/vexxhost/certssh/internal/backend/local"
	"github.com/vexxhost/certssh/internal/backend/openbao"
	"github.com/vexxhost/certssh/internal/config"
)

// Open returns the backend for a context.
func Open(name string, c *config.Context) (backend.Backend, error) {
	switch c.BackendName() {
	case "openbao", "vault":
		return openbao.New(name, c)
	case "local":
		return local.New(name, c.Local)
	default:
		return nil, fmt.Errorf("unknown backend %q", c.Backend)
	}
}
