// Package agent implements certssh's SSH agent. It holds one key per
// context, learns from OpenSSH's session-bind extension which host each
// connection is for, signs the matching certificate on demand, and offers
// keys added with ssh-add and keys from an upstream agent alongside.
package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"gopkg.in/yaml.v3"

	"github.com/vexxhost/certssh/internal/backend"
	"github.com/vexxhost/certssh/internal/backends"
	"github.com/vexxhost/certssh/internal/config"
	"github.com/vexxhost/certssh/internal/knownhosts"
	"github.com/vexxhost/certssh/internal/profile"
	"github.com/vexxhost/certssh/internal/session"
)

// Version is reported in status; set by the main package.
var Version = "dev"

// Options configures an Agent.
type Options struct {
	ConfigPath string
	Socket     string
	// Upstream overrides the configured upstream agent; "none" disables it.
	Upstream   string
	KnownHosts string
	Sessions   session.Store
	Logger     *slog.Logger
	// Open creates backends; tests replace it.
	Open func(name string, c *config.Context) (backend.Backend, error)
	Now  func() time.Time
}

// Agent is the running agent.
type Agent struct {
	opts       Options
	log        *slog.Logger
	knownHosts string
	now        func() time.Time

	mu       sync.RWMutex
	cfg      *config.Config
	contexts map[string]*contextState
	upstream string

	keyring agent.ExtendedAgent
	lockMu  sync.Mutex
	locked  bool

	signs atomic.Int64
	conns atomic.Uint64
}

// New loads the configuration and returns an agent ready to serve.
func New(opts Options) (*Agent, error) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.Open == nil {
		opts.Open = backends.Open
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.KnownHosts == "" {
		opts.KnownHosts = config.KnownHostsFile()
	}
	if opts.Sessions.Dir == "" {
		opts.Sessions = session.Store{Dir: filepath.Join(config.Dir(), "sessions")}
	}
	a := &Agent{
		opts:       opts,
		log:        opts.Logger,
		knownHosts: opts.KnownHosts,
		now:        opts.Now,
		contexts:   map[string]*contextState{},
		keyring:    agent.NewKeyring().(agent.ExtendedAgent),
	}
	if err := a.Reload(); err != nil {
		return nil, err
	}
	return a, nil
}

// Reload rereads the configuration. Contexts whose settings are unchanged
// keep their key and certificates.
func (a *Agent) Reload() error {
	cfg, err := config.Load(a.opts.ConfigPath)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	next := map[string]*contextState{}
	for name, c := range cfg.Contexts {
		if old := a.contexts[name]; old != nil && sameContext(old.cfg, c) {
			old.mu.Lock()
			old.sessionMod = time.Time{}
			old.hostCAs = nil
			old.mu.Unlock()
			next[name] = old
			continue
		}
		b, err := a.opts.Open(name, c)
		if err != nil {
			return fmt.Errorf("context %q: %w", name, err)
		}
		cs, err := newContextState(name, c, b, a.opts.Sessions)
		if err != nil {
			return fmt.Errorf("context %q: %w", name, err)
		}
		next[name] = cs
	}
	a.cfg, a.contexts = cfg, next
	a.upstream = a.resolveUpstream(cfg)
	return nil
}

func sameContext(a, b *config.Context) bool {
	ya, errA := yaml.Marshal(a)
	yb, errB := yaml.Marshal(b)
	if errA != nil || errB != nil || string(ya) != string(yb) {
		return false
	}
	pa, _, errA := a.LoadProfiles()
	pb, _, errB := b.LoadProfiles()
	return errA == nil && errB == nil && fmt.Sprint(pa) == fmt.Sprint(pb)
}

func (a *Agent) resolveUpstream(cfg *config.Config) string {
	up := a.opts.Upstream
	if up == "" {
		up = cfg.Agent.Upstream
	}
	if up == "" {
		up = os.Getenv("SSH_AUTH_SOCK")
	}
	if up == "none" || up == "" {
		return ""
	}
	up = config.Expand(up)
	if a.isOwnSocket(up) {
		return ""
	}
	return up
}

func (a *Agent) isOwnSocket(p string) bool {
	own := a.opts.Socket
	if own == "" {
		return false
	}
	if filepath.Clean(p) == filepath.Clean(own) {
		return true
	}
	fi1, err1 := os.Stat(p)
	fi2, err2 := os.Stat(own)
	return err1 == nil && err2 == nil && os.SameFile(fi1, fi2)
}

func (a *Agent) snapshot() (*config.Config, []*contextState, string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var list []*contextState
	for _, n := range a.cfg.Names() {
		list = append(list, a.contexts[n])
	}
	return a.cfg, list, a.upstream
}

func (a *Agent) caKeysFromKnownHosts(context string) []ssh.PublicKey {
	return knownhosts.CAKeys(a.knownHosts, context)
}

// Signs returns how many certificates the agent has requested from CAs.
func (a *Agent) Signs() int64 { return a.signs.Load() }

// Listen creates the agent socket, replacing a stale one but refusing to
// replace one another agent is serving.
func Listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err == nil {
		if c, err := dialUnix(path, time.Second); err == nil {
			_ = c.Close()
			return nil, fmt.Errorf("an agent is already listening on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

func dialUnix(path string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(context.Background(), "unix", path)
}

// certTime converts an OpenSSH certificate timestamp; "forever" maps to the
// largest time a Unix timestamp can hold.
func certTime(v uint64) time.Time {
	if v > math.MaxInt64 {
		v = math.MaxInt64
	}
	return time.Unix(int64(v), 0) //nolint:gosec // bounded above
}

// Serve accepts connections until the listener is closed.
func (a *Agent) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go a.handle(c)
	}
}

func (a *Agent) handle(c net.Conn) {
	cc := &conn{a: a, id: a.conns.Add(1)}
	defer cc.close()
	defer c.Close()
	if err := agent.ServeAgent(cc, c); !errors.Is(err, io.EOF) {
		a.log.Debug("agent connection ended", "conn", cc.id, "error", err)
	}
}

// HostPrincipalsExtension is a host-certificate extension listing, in order
// of preference and separated by commas, the user principals the host
// accepts. OpenSSH ignores extensions it does not know.
const HostPrincipalsExtension = "certssh-principals@vexxhost.com"

// resolution is what the agent decided about a connection's host.
type resolution struct {
	cs         *contextState
	principals []string
	// hinted are principals the host certificate lists, tried in order
	// one certificate at a time.
	hinted  []string
	profile string
	names   []string
	// identified means the host's names come from a host certificate
	// signed by the context's host CA, or from known_hosts.
	identified bool
	// reason explains the outcome for the debug log.
	reason string
}

// resolve works out which context and principals a bound host needs.
func (a *Agent) resolve(b Bind) resolution {
	_, contexts, _ := a.snapshot()
	certReason := "plain host key"
	if cert, ok := b.HostKey.(*ssh.Certificate); ok && cert.CertType == ssh.HostCert {
		certReason = "host certificate signed by a CA no context trusts (" + ssh.FingerprintSHA256(cert.SignatureKey) + ")"
		for _, cs := range contexts {
			if !signedBy(cert, a.hostCAKeys(cs)) {
				continue
			}
			if !certValid(cert, a.now()) {
				certReason = "host certificate from " + cs.name + "'s CA is invalid or expired"
				continue
			}
			names := cert.ValidPrincipals
			persona := cs.persona()
			if hinted := cs.hintedPrincipals(persona, cert); len(hinted) > 0 {
				return resolution{cs: cs, hinted: hinted, profile: "(host certificate)", names: names, identified: true,
					reason: "host certificate lists " + strings.Join(hinted, ",")}
			}
			principals, prof := cs.principalsFor(persona, names)
			if principals == nil {
				return resolution{cs: cs, names: names, reason: fmt.Sprintf(
					"host certificate from %s lists no principal for persona %s, and no profile matches %v", cs.name, persona, names)}
			}
			return resolution{cs: cs, principals: principals, profile: prof, names: names, identified: true,
				reason: "profile " + prof}
		}
	}
	key := b.HostKey
	if cert, ok := key.(*ssh.Certificate); ok {
		key = cert.Key
	}
	names := knownhosts.HostsFor(a.knownHosts, key)
	if len(names) == 0 {
		return resolution{reason: certReason + ", and the key is not in " + a.knownHosts}
	}
	for _, cs := range contexts {
		persona := cs.persona()
		if _, ok := profile.Match(cs.profiles, persona, names...); !ok {
			continue
		}
		if principals, prof := cs.principalsFor(persona, names); principals != nil {
			return resolution{cs: cs, principals: principals, profile: prof, names: names, identified: true,
				reason: "known_hosts name matches profile " + prof}
		}
	}
	return resolution{names: names, reason: fmt.Sprintf("%s; known_hosts names %v match no profile", certReason, names)}
}

func signedBy(cert *ssh.Certificate, cas []ssh.PublicKey) bool {
	want := cert.SignatureKey.Marshal()
	for _, k := range cas {
		if string(k.Marshal()) == string(want) {
			return true
		}
	}
	return false
}

// certValid checks the host certificate's signature and validity period.
func certValid(cert *ssh.Certificate, t time.Time) bool {
	if len(cert.ValidPrincipals) == 0 {
		return false
	}
	checker := ssh.CertChecker{Clock: func() time.Time { return t }}
	return checker.CheckCert(cert.ValidPrincipals[0], cert) == nil
}
