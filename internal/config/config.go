// Package config loads and saves certssh's configuration file and resolves
// the paths it uses.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/vexxhost/certssh/internal/profile"
)

// Personas a session can be opened as.
const (
	PersonaHuman = "human"
	PersonaAgent = "agent"
)

// Config is the whole configuration file.
type Config struct {
	Current  string              `yaml:"current,omitempty"`
	Contexts map[string]*Context `yaml:"contexts,omitempty"`
	Agent    Agent               `yaml:"agent,omitempty"`

	path string
}

// Context is one certificate authority and how to log in to it.
type Context struct {
	Backend    string            `yaml:"backend,omitempty"`
	Address    string            `yaml:"address,omitempty"`
	Namespace  string            `yaml:"namespace,omitempty"`
	CACert     string            `yaml:"ca_cert,omitempty"`
	Login      map[string]Login  `yaml:"login,omitempty"`
	CA         CA                `yaml:"ca,omitempty"`
	Roles      map[string]string `yaml:"roles,omitempty"`
	Principals string            `yaml:"principals,omitempty"`
	TTL        string            `yaml:"ttl,omitempty"`
	Profiles   Profiles          `yaml:"profiles,omitempty"`
	// HostCAPatterns limits which host names the host CA is trusted for.
	HostCAPatterns []string `yaml:"host_ca_patterns,omitempty"`
	Local          *Local   `yaml:"local,omitempty"`
}

// Login describes how a persona logs in.
type Login struct {
	Method string `yaml:"method,omitempty"`
	Mount  string `yaml:"mount,omitempty"`
	Role   string `yaml:"role,omitempty"`
	// Callback is the OIDC callback mode: client (a localhost listener),
	// direct or device (OpenBao polls; suited to unattended agents).
	Callback string `yaml:"callback,omitempty"`
	// ListenAddress is where the client-mode callback listens; it must
	// match a redirect URI allowed by the role.
	ListenAddress string `yaml:"listen_address,omitempty"`
}

// CA names the SSH secrets engine mounts.
type CA struct {
	User string `yaml:"user,omitempty"`
	Host string `yaml:"host,omitempty"`
}

// Profiles says where a context's site profile comes from.
type Profiles struct {
	Source string            `yaml:"source,omitempty"`
	Path   string            `yaml:"path,omitempty"`
	Inline []profile.Profile `yaml:"inline,omitempty"`
}

// Local configures the local backend, which signs with a CA key on disk.
type Local struct {
	UserCAKey         string   `yaml:"user_ca_key"`
	HostCAKey         string   `yaml:"host_ca_key,omitempty"`
	TTL               string   `yaml:"ttl,omitempty"`
	AllowedPrincipals []string `yaml:"allowed_principals,omitempty"`
}

// Agent configures the agent process.
type Agent struct {
	Socket string `yaml:"socket,omitempty"`
	// Upstream is another agent whose keys are offered alongside ours;
	// "none" disables the default of using SSH_AUTH_SOCK.
	Upstream string `yaml:"upstream,omitempty"`
	// UnknownHost is what is offered to a host that cannot be identified:
	// recent (the most recently used certificates), all, or none.
	UnknownHost    string `yaml:"unknown_host,omitempty"`
	AllowForwarded bool   `yaml:"allow_forwarded,omitempty"`
	// OfferUpstreamOnMatch also offers other keys to identified hosts,
	// after the certificate.
	OfferUpstreamOnMatch *bool  `yaml:"offer_upstream_on_match,omitempty"`
	Key                  string `yaml:"key,omitempty"`
}

// Dir returns certssh's configuration directory.
func Dir() string {
	if d := os.Getenv("CERTSSH_CONFIG_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "certssh")
	}
	return filepath.Join(home(), ".config", "certssh")
}

// StateDir returns where logs and caches go.
func StateDir() string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "certssh")
	}
	return filepath.Join(home(), ".local", "state", "certssh")
}

// DefaultSocket is the agent socket when none is configured.
func DefaultSocket() string {
	return filepath.Join(home(), ".certssh", "agent.sock")
}

// KnownHostsFile is the file the host CA line is written to.
func KnownHostsFile() string {
	return filepath.Join(home(), ".ssh", "known_hosts")
}

func home() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return h
}

// DefaultPath is the configuration file used when none is given.
func DefaultPath() string {
	return filepath.Join(Dir(), "config.yaml")
}

// Load reads the configuration file; a missing file is an empty config.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}
	c := &Config{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.path = path
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Path is the file this config was loaded from.
func (c *Config) Path() string { return c.path }

// Save writes the configuration file atomically.
func (c *Config) Save() error {
	if err := c.Validate(); err != nil {
		return err
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.path), ".config-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), c.path)
}

// Validate checks every context and the agent settings.
func (c *Config) Validate() error {
	for name, ctx := range c.Contexts {
		if err := ctx.validate(); err != nil {
			return fmt.Errorf("context %q: %w", name, err)
		}
	}
	if c.Current != "" && c.Contexts[c.Current] == nil {
		return fmt.Errorf("current context %q does not exist", c.Current)
	}
	switch c.Agent.UnknownHost {
	case "", "recent", "all", "none":
	default:
		return fmt.Errorf("agent.unknown_host must be recent, all or none")
	}
	switch c.Agent.Key {
	case "", "memory":
	default:
		return fmt.Errorf("agent.key %q is not supported yet (only memory)", c.Agent.Key)
	}
	return nil
}

func (ctx *Context) validate() error {
	switch ctx.BackendName() {
	case "openbao", "vault":
		if ctx.Address == "" {
			return errors.New("address is required")
		}
		u, err := url.Parse(ctx.Address)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("address %q must be an http(s) URL", ctx.Address)
		}
	case "local":
		if ctx.Local == nil || ctx.Local.UserCAKey == "" {
			return errors.New("local.user_ca_key is required for the local backend")
		}
	default:
		return fmt.Errorf("unknown backend %q", ctx.Backend)
	}
	switch ctx.Principals {
	case "", "one", "many":
	default:
		return errors.New("principals must be one or many")
	}
	if ctx.TTL != "" {
		if _, err := time.ParseDuration(ctx.TTL); err != nil {
			return fmt.Errorf("ttl: %w", err)
		}
	}
	for persona, l := range ctx.Login {
		switch l.Method {
		case "", "oidc", "token":
		default:
			return fmt.Errorf("login.%s.method %q is not supported", persona, l.Method)
		}
		switch l.Callback {
		case "", "client", "direct", "device":
		default:
			return fmt.Errorf("login.%s.callback must be client, direct or device", persona)
		}
	}
	switch ctx.Profiles.Source {
	case "", "inline":
		if ctx.Profiles.Path != "" && ctx.Profiles.Source == "inline" {
			return errors.New("profiles.path is only used with source file")
		}
	case "file":
		if ctx.Profiles.Path == "" {
			return errors.New("profiles.path is required with source file")
		}
	default:
		return fmt.Errorf("profiles.source %q is not supported yet (inline or file)", ctx.Profiles.Source)
	}
	return profile.Validate(ctx.Profiles.Inline)
}

// BackendName returns the backend, defaulting to openbao.
func (ctx *Context) BackendName() string {
	if ctx.Backend == "" {
		return "openbao"
	}
	return ctx.Backend
}

// LoginFor returns the login settings for a persona with defaults applied.
func (ctx *Context) LoginFor(persona string) Login {
	l := ctx.Login[persona]
	if l.Method == "" {
		l.Method = "oidc"
	}
	if l.Mount == "" {
		if l.Method == "token" {
			l.Mount = "token"
		} else {
			l.Mount = "oidc"
		}
	}
	if l.Callback == "" {
		if persona == PersonaAgent {
			l.Callback = "direct"
		} else {
			l.Callback = "client"
		}
	}
	if l.ListenAddress == "" {
		l.ListenAddress = "localhost:8250"
	}
	return l
}

// UserCA returns the user CA mount.
func (ctx *Context) UserCA() string {
	if ctx.CA.User == "" {
		return "ssh-client-signer"
	}
	return ctx.CA.User
}

// HostCA returns the host CA mount; "-" disables host CA trust.
func (ctx *Context) HostCA() string {
	if ctx.CA.Host == "" {
		return "ssh-host-signer"
	}
	return ctx.CA.Host
}

// RoleFor returns the signing role for a persona.
func (ctx *Context) RoleFor(persona string) string {
	if r := ctx.Roles[persona]; r != "" {
		return r
	}
	return persona
}

// ManyPrincipals reports whether one certificate may carry every principal.
func (ctx *Context) ManyPrincipals() bool { return ctx.Principals == "many" }

// LoadProfiles returns the context's profiles and host CA patterns.
func (ctx *Context) LoadProfiles() ([]profile.Profile, []string, error) {
	if ctx.Profiles.Source == "file" {
		doc, err := profile.Load(expand(ctx.Profiles.Path))
		if err != nil {
			return nil, nil, fmt.Errorf("profiles: %w", err)
		}
		patterns := ctx.HostCAPatterns
		if len(patterns) == 0 {
			patterns = doc.HostCAPatterns
		}
		return doc.Profiles, patterns, nil
	}
	return ctx.Profiles.Inline, ctx.HostCAPatterns, nil
}

// Names returns the context names, current first, then sorted.
func (c *Config) Names() []string {
	names := make([]string, 0, len(c.Contexts))
	for n := range c.Contexts {
		if n != c.Current {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if c.Contexts[c.Current] != nil {
		names = append([]string{c.Current}, names...)
	}
	return names
}

// Resolve returns the named context, or the current one when name is empty.
func (c *Config) Resolve(name string) (string, *Context, error) {
	if name == "" {
		name = c.Current
	}
	if name == "" {
		if len(c.Contexts) == 1 {
			for n, ctx := range c.Contexts {
				return n, ctx, nil
			}
		}
		return "", nil, errors.New("no context selected; run certssh login <address> first")
	}
	ctx := c.Contexts[name]
	if ctx == nil {
		return "", nil, fmt.Errorf("context %q does not exist", name)
	}
	return name, ctx, nil
}

// SocketPath returns the agent socket.
func (c *Config) SocketPath() string {
	if c.Agent.Socket != "" {
		return expand(c.Agent.Socket)
	}
	return DefaultSocket()
}

// OfferUpstream reports whether identified hosts are also offered other
// keys; it defaults to true.
func (a Agent) OfferUpstream() bool {
	return a.OfferUpstreamOnMatch == nil || *a.OfferUpstreamOnMatch
}

// UnknownHostPolicy returns agent.unknown_host, defaulting to recent.
func (a Agent) UnknownHostPolicy() string {
	if a.UnknownHost == "" {
		return "recent"
	}
	return a.UnknownHost
}

// Expand replaces a leading ~/ with the home directory.
func Expand(p string) string { return expand(p) }

func expand(p string) string {
	if p == "~" {
		return home()
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home(), p[2:])
	}
	return p
}
