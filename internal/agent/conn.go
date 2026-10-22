package agent

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/vexxhost/certssh/internal/backend"
	"github.com/vexxhost/certssh/internal/session"
)

// recentLimit is how many cached certificates are offered to a host that
// cannot be identified, keeping well under sshd's MaxAuthTries.
const recentLimit = 3

var errLocked = errors.New("agent is locked")

// conn serves one client connection. OpenSSH opens one per ssh process, so
// the binds it records describe exactly one destination (plus hops when the
// agent is forwarded).
type conn struct {
	a  *Agent
	id uint64

	mu      sync.Mutex
	binds   []Bind
	up      agent.ExtendedAgent
	upConn  net.Conn
	upTried bool
}

var _ agent.ExtendedAgent = (*conn)(nil)

func (c *conn) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.upConn != nil {
		_ = c.upConn.Close()
	}
}

// upstream dials the upstream agent once per connection.
func (c *conn) upstream() agent.ExtendedAgent {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.upTried {
		return c.up
	}
	c.upTried = true
	_, _, path := c.a.snapshot()
	if path == "" || c.a.isOwnSocket(path) {
		return nil
	}
	nc, err := dialUnix(path, 2*time.Second)
	if err != nil {
		c.a.log.Debug("upstream agent unavailable", "socket", path, "error", err)
		return nil
	}
	c.upConn, c.up = nc, agent.NewClient(nc)
	return c.up
}

func (c *conn) state() (target *Bind, bound, forwarded bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.binds {
		forwarded = forwarded || c.binds[i].Forwarding
	}
	if n := len(c.binds); n > 0 {
		b := c.binds[n-1]
		return &b, true, forwarded
	}
	return nil, false, false
}

func (c *conn) isLocked() bool {
	c.a.lockMu.Lock()
	defer c.a.lockMu.Unlock()
	return c.a.locked
}

func certKey(e *certEntry) *agent.Key {
	exp := certTime(e.cert.ValidBefore).Format(time.RFC3339)
	return &agent.Key{
		Format:  e.cert.Type(),
		Blob:    e.cert.Marshal(),
		Comment: fmt.Sprintf("certssh:%s %s (expires %s)", e.context, strings.Join(e.principals, ","), exp),
	}
}

// List returns the keys to offer. For a host identified through its host
// certificate or known_hosts, that is the matching certificate first; for
// anything else, the user's own keys first.
func (c *conn) List() ([]*agent.Key, error) {
	if c.isLocked() {
		return nil, nil
	}
	cfg, contexts, _ := c.a.snapshot()
	target, bound, forwarded := c.state()
	certsAllowed := !forwarded || cfg.Agent.AllowForwarded

	others, err := c.otherKeys()
	if err != nil {
		return nil, err
	}

	if !bound {
		// ssh-add -l, or a client without session-bind: show everything we hold.
		c.a.log.Debug("key list requested without a session-bind (ssh-add, or ssh older than 8.9)", "conn", c.id)
		keys := others
		if certsAllowed {
			for _, cs := range contexts {
				for _, e := range cs.cached(c.a.now()) {
					keys = append(keys, certKey(e))
				}
			}
		}
		return keys, nil
	}

	res := c.a.resolve(*target)
	host := hostLabel(res.names, target.HostKey)
	if res.identified {
		c.a.log.Debug("host recognised", "conn", c.id, "host", host, "context", res.cs.name, "why", res.reason)
	} else {
		c.a.log.Debug("host not recognised", "conn", c.id, "host", host, "why", res.reason)
	}
	if res.identified && certsAllowed {
		var e *certEntry
		var err error
		if len(res.hinted) > 0 {
			e, err = c.a.ensureFirst(res.cs, res.hinted, host)
		} else {
			e, err = c.a.ensure(res.cs, res.principals, host)
		}
		switch {
		case err == nil:
			keys := []*agent.Key{certKey(e)}
			if cfg.Agent.OfferUpstream() {
				keys = append(keys, others...)
			}
			return keys, nil
		case errors.Is(err, session.ErrNoSession), errors.Is(err, backend.ErrSessionExpired):
			res.cs.warn(c.a, "no usable session; run certssh login", "host", host, "error", err)
		case errors.Is(err, backend.ErrDenied):
			c.a.log.Debug("not permitted", "context", res.cs.name, "host", host, "error", err)
		default:
			res.cs.warn(c.a, "signing failed", "host", host, "error", err)
		}
		return others, nil
	}

	keys := others
	if !certsAllowed {
		return keys, nil
	}
	var pool []*certEntry
	if res.cs != nil {
		pool = res.cs.cached(c.a.now())
	} else {
		for _, cs := range contexts {
			pool = append(pool, cs.cached(c.a.now())...)
		}
	}
	switch cfg.Agent.UnknownHostPolicy() {
	case "none":
		pool = nil
	case "recent":
		if len(pool) > recentLimit {
			pool = pool[:recentLimit]
		}
	}
	for _, e := range pool {
		keys = append(keys, certKey(e))
	}
	return keys, nil
}

// otherKeys are the keys added with ssh-add followed by the upstream agent's.
func (c *conn) otherKeys() ([]*agent.Key, error) {
	keys, err := c.a.keyring.List()
	if err != nil {
		return nil, err
	}
	if up := c.upstream(); up != nil {
		if upKeys, err := up.List(); err == nil {
			keys = append(keys, upKeys...)
		} else {
			c.a.log.Debug("listing upstream keys failed", "error", err)
		}
	}
	return keys, nil
}

func hostLabel(names []string, key ssh.PublicKey) string {
	if len(names) > 0 {
		return names[0]
	}
	if cert, ok := key.(*ssh.Certificate); ok {
		key = cert.Key
	}
	return ssh.FingerprintSHA256(key)
}

// findCert returns the held certificate whose blob matches.
func (c *conn) findCert(blob []byte) *certEntry {
	_, contexts, _ := c.a.snapshot()
	for _, cs := range contexts {
		cs.mu.Lock()
		for _, e := range cs.certs {
			if string(e.cert.Marshal()) == string(blob) {
				cs.mu.Unlock()
				return e
			}
		}
		cs.mu.Unlock()
	}
	return nil
}

func (c *conn) hasAdded(blob []byte) bool {
	keys, err := c.a.keyring.List()
	if err != nil {
		return false
	}
	for _, k := range keys {
		if string(k.Blob) == string(blob) {
			return true
		}
	}
	return false
}

// Sign signs with whichever store holds the key.
func (c *conn) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return c.SignWithFlags(key, data, 0)
}

// SignWithFlags signs with whichever store holds the key.
func (c *conn) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if c.isLocked() {
		return nil, errLocked
	}
	blob := key.Marshal()
	if e := c.findCert(blob); e != nil {
		cfg, _, _ := c.a.snapshot()
		if _, _, forwarded := c.state(); forwarded && !cfg.Agent.AllowForwarded {
			return nil, errors.New("refusing to sign for a forwarded connection")
		}
		return e.signer.Sign(rand.Reader, data)
	}
	if c.hasAdded(blob) {
		return c.a.keyring.SignWithFlags(key, data, flags)
	}
	if up := c.upstream(); up != nil {
		return up.SignWithFlags(key, data, flags)
	}
	return nil, errors.New("key not found")
}

func (c *conn) refuseRemote() error {
	if _, _, forwarded := c.state(); forwarded {
		return errors.New("not allowed over a forwarded agent connection")
	}
	return nil
}

// Add stores a key added with ssh-add in this agent.
func (c *conn) Add(key agent.AddedKey) error {
	if err := c.refuseRemote(); err != nil {
		return err
	}
	return c.a.keyring.Add(key)
}

// Remove removes an added key, drops a held certificate, or passes the
// request upstream for keys that live there.
func (c *conn) Remove(key ssh.PublicKey) error {
	if err := c.refuseRemote(); err != nil {
		return err
	}
	blob := key.Marshal()
	if e := c.findCert(blob); e != nil {
		c.a.dropCert(e)
		return nil
	}
	if c.hasAdded(blob) {
		return c.a.keyring.Remove(key)
	}
	if up := c.upstream(); up != nil {
		return up.Remove(key)
	}
	return errors.New("key not found")
}

// RemoveAll removes added keys and held certificates; certificates are
// signed again on next use. Upstream keys are left alone.
func (c *conn) RemoveAll() error {
	if err := c.refuseRemote(); err != nil {
		return err
	}
	_, contexts, _ := c.a.snapshot()
	for _, cs := range contexts {
		cs.mu.Lock()
		cs.certs = map[string]*certEntry{}
		cs.mu.Unlock()
	}
	return c.a.keyring.RemoveAll()
}

// Lock locks the whole agent.
func (c *conn) Lock(passphrase []byte) error {
	if err := c.refuseRemote(); err != nil {
		return err
	}
	c.a.lockMu.Lock()
	defer c.a.lockMu.Unlock()
	if c.a.locked {
		return errLocked
	}
	if err := c.a.keyring.Lock(passphrase); err != nil {
		return err
	}
	c.a.locked = true
	return nil
}

// Unlock unlocks the agent.
func (c *conn) Unlock(passphrase []byte) error {
	if err := c.refuseRemote(); err != nil {
		return err
	}
	c.a.lockMu.Lock()
	defer c.a.lockMu.Unlock()
	if !c.a.locked {
		return errors.New("agent is not locked")
	}
	if err := c.a.keyring.Unlock(passphrase); err != nil {
		return err
	}
	c.a.locked = false
	return nil
}

// Signers returns the added keys' signers.
func (c *conn) Signers() ([]ssh.Signer, error) {
	return c.a.keyring.Signers()
}

// Extension handles session-bind, certssh's control requests, and passes
// anything else upstream.
func (c *conn) Extension(name string, contents []byte) ([]byte, error) {
	switch name {
	case ExtensionSessionBind:
		b, err := parseBind(contents)
		if err != nil {
			c.a.log.Debug("rejecting session-bind", "conn", c.id, "error", err)
			return nil, err
		}
		c.a.log.Debug("session-bind", "conn", c.id, "host_key", describeKey(b.HostKey), "forwarding", b.Forwarding)
		c.mu.Lock()
		if len(c.binds) >= maxBinds {
			c.mu.Unlock()
			return nil, errors.New("too many session binds")
		}
		c.binds = append(c.binds, b)
		c.mu.Unlock()
		if up := c.upstream(); up != nil {
			// Keep the upstream agent's own destination constraints working.
			_, _ = up.Extension(name, contents)
		}
		return nil, nil
	case ExtensionStatus, ExtensionReload:
		if _, bound, _ := c.state(); bound {
			return nil, errors.New("control requests are only accepted from local clients")
		}
		return c.a.control(name)
	}
	if up := c.upstream(); up != nil {
		return up.Extension(name, contents)
	}
	return nil, agent.ErrExtensionUnsupported
}

func describeKey(k ssh.PublicKey) string {
	if cert, ok := k.(*ssh.Certificate); ok {
		return fmt.Sprintf("certificate %q for %v from CA %s", cert.KeyId, cert.ValidPrincipals, ssh.FingerprintSHA256(cert.SignatureKey))
	}
	return k.Type() + " " + ssh.FingerprintSHA256(k)
}

func (a *Agent) dropCert(e *certEntry) {
	_, contexts, _ := a.snapshot()
	for _, cs := range contexts {
		if cs.name != e.context {
			continue
		}
		cs.mu.Lock()
		delete(cs.certs, setKey(e.principals))
		cs.mu.Unlock()
	}
}
