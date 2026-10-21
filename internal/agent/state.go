package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/singleflight"

	"github.com/vexxhost/certssh/internal/backend"
	"github.com/vexxhost/certssh/internal/config"
	"github.com/vexxhost/certssh/internal/profile"
	"github.com/vexxhost/certssh/internal/session"
)

var randReader = rand.Reader

const (
	deniedFor    = 15 * time.Minute
	signTimeout  = 30 * time.Second
	hostCAMaxAge = time.Hour
	warnEvery    = time.Minute
)

// certEntry is a certificate the agent holds for one principal set.
type certEntry struct {
	context    string
	principals []string
	cert       *ssh.Certificate
	signer     ssh.Signer
	signed     time.Time
	lastUsed   time.Time
	lastHost   string
}

func (e *certEntry) validAt(t time.Time) bool {
	after := certTime(e.cert.ValidAfter)
	before := certTime(e.cert.ValidBefore)
	grace := before.Sub(after) / 10
	if grace < time.Minute {
		grace = time.Minute
	}
	return !t.Before(after) && t.Add(grace).Before(before)
}

type deniedEntry struct {
	until  time.Time
	reason string
}

// contextState is everything the agent keeps for one context: the session
// read from disk, the key generated for it, and the certificates signed so
// far.
type contextState struct {
	name     string
	cfg      *config.Context
	backend  backend.Backend
	profiles []profile.Profile
	store    session.Store

	mu         sync.Mutex
	session    *backend.Session
	sessionMod time.Time
	identity   string
	key        ssh.Signer
	certs      map[string]*certEntry
	denied     map[string]deniedEntry
	hostCAs    []ssh.PublicKey
	hostCAsAt  time.Time
	lastWarn   time.Time

	group singleflight.Group
}

func newContextState(name string, cfg *config.Context, b backend.Backend, store session.Store) (*contextState, error) {
	profiles, _, err := cfg.LoadProfiles()
	if err != nil {
		return nil, err
	}
	return &contextState{
		name:     name,
		cfg:      cfg,
		backend:  b,
		profiles: profiles,
		store:    store,
		certs:    map[string]*certEntry{},
		denied:   map[string]deniedEntry{},
	}, nil
}

func setKey(principals []string) string { return strings.Join(principals, ",") }

// loadSessionLocked rereads the session file when it changed. A new login
// gets a new key, and every certificate signed for the old one is dropped.
func (cs *contextState) loadSessionLocked() (*backend.Session, error) {
	mod := cs.store.ModTime(cs.name)
	if mod.IsZero() {
		cs.resetLocked()
		cs.session, cs.sessionMod = nil, time.Time{}
		return nil, session.ErrNoSession
	}
	if cs.session != nil && mod.Equal(cs.sessionMod) {
		return cs.session, nil
	}
	sess, err := cs.store.Load(cs.name)
	if err != nil {
		return nil, err
	}
	cs.session, cs.sessionMod = sess, mod
	if id := sess.Identity(); id != cs.identity {
		cs.resetLocked()
		cs.identity = id
	}
	return sess, nil
}

func (cs *contextState) resetLocked() {
	cs.identity = ""
	cs.key = nil
	cs.certs = map[string]*certEntry{}
	cs.denied = map[string]deniedEntry{}
}

func (cs *contextState) keyLocked() (ssh.Signer, error) {
	if cs.key != nil {
		return cs.key, nil
	}
	_, priv, err := ed25519.GenerateKey(randReader)
	if err != nil {
		return nil, err
	}
	k, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	cs.key = k
	return k, nil
}

// principalsFor returns the principals to request for a host, and the
// profile that matched, given the persona of the current session.
func (cs *contextState) principalsFor(persona string, names []string) ([]string, string) {
	if cs.cfg.ManyPrincipals() {
		seen := map[string]bool{}
		var all []string
		for _, p := range cs.profiles {
			if pr := p.PrincipalFor(persona); pr != "" && !seen[pr] {
				seen[pr] = true
				all = append(all, pr)
			}
		}
		sort.Strings(all)
		if len(all) == 0 {
			return nil, ""
		}
		return all, "*"
	}
	p, ok := profile.Match(cs.profiles, persona, names...)
	if !ok {
		return nil, ""
	}
	return []string{p.PrincipalFor(persona)}, p.Name
}

// hintedPrincipals returns the principals a host certificate lists, keeping
// only those the persona's principal_patterns allow.
func (cs *contextState) hintedPrincipals(persona string, cert *ssh.Certificate) []string {
	value := cert.Extensions[HostPrincipalsExtension]
	if value == "" {
		return nil
	}
	patterns := cs.cfg.PrincipalPatterns[persona]
	seen := map[string]bool{}
	var out []string
	for _, p := range strings.Split(value, ",") {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] || !matchesAny(p, patterns) {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func matchesAny(s string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if ok, _ := path.Match(p, s); ok {
			return true
		}
	}
	return false
}

// ensureFirst returns a certificate for the first candidate principal the CA
// will sign, moving on when one is refused. Refusals are remembered, so later
// connections skip straight to the principal that worked.
func (a *Agent) ensureFirst(cs *contextState, candidates []string, host string) (*certEntry, error) {
	var lastErr error
	for _, p := range candidates {
		e, err := a.ensure(cs, []string{p}, host)
		if err == nil {
			return e, nil
		}
		if !errors.Is(err, backend.ErrDenied) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// persona returns the persona of the current session, or human.
func (cs *contextState) persona() string {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if _, err := cs.loadSessionLocked(); err != nil || cs.session.Persona == "" {
		return config.PersonaHuman
	}
	return cs.session.Persona
}

// ensure returns a valid certificate for the principals, signing one when
// none is cached. Concurrent callers for the same principals share a single
// request to the CA.
func (a *Agent) ensure(cs *contextState, principals []string, host string) (*certEntry, error) {
	k := setKey(principals)
	now := a.now()
	cs.mu.Lock()
	sess, err := cs.loadSessionLocked()
	if e := cs.certs[k]; e != nil && e.validAt(now) {
		e.lastUsed, e.lastHost = now, host
		cs.mu.Unlock()
		return e, nil
	}
	if err != nil {
		cs.mu.Unlock()
		return nil, err
	}
	if d, ok := cs.denied[k]; ok && now.Before(d.until) {
		cs.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", backend.ErrDenied, d.reason)
	}
	identity := cs.identity
	key, err := cs.keyLocked()
	cs.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if sess.Expired(now) {
		return nil, backend.ErrSessionExpired
	}

	v, err, _ := cs.group.Do(identity+"|"+k, func() (any, error) {
		cs.mu.Lock()
		if e := cs.certs[k]; e != nil && e.validAt(a.now()) {
			cs.mu.Unlock()
			return e, nil
		}
		cs.mu.Unlock()
		return a.sign(cs, sess, key, identity, principals, host)
	})
	if err != nil {
		return nil, err
	}
	e := v.(*certEntry)
	cs.mu.Lock()
	e.lastUsed, e.lastHost = a.now(), host
	cs.mu.Unlock()
	return e, nil
}

func (a *Agent) sign(cs *contextState, sess *backend.Session, key ssh.Signer, identity string, principals []string, host string) (*certEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), signTimeout)
	defer cancel()
	if sess.NeedsRenewal(a.now()) {
		if renewed, err := cs.backend.Renew(ctx, sess); err == nil {
			if err := cs.store.Save(renewed); err == nil {
				sess = renewed
			}
		} else if errors.Is(err, backend.ErrSessionExpired) {
			return nil, err
		} else {
			a.log.Warn("renewing session failed", "context", cs.name, "error", err)
		}
	}
	var ttl time.Duration
	if cs.cfg.TTL != "" {
		ttl, _ = time.ParseDuration(cs.cfg.TTL)
	}
	persona := sess.Persona
	if persona == "" {
		persona = config.PersonaHuman
	}
	a.signs.Add(1)
	cert, err := cs.backend.Sign(ctx, sess, backend.SignRequest{
		PublicKey:  key.PublicKey(),
		Principals: principals,
		Role:       cs.cfg.RoleFor(persona),
		TTL:        ttl,
	})
	k := setKey(principals)
	if err != nil {
		if errors.Is(err, backend.ErrDenied) {
			cs.mu.Lock()
			cs.denied[k] = deniedEntry{until: a.now().Add(deniedFor), reason: err.Error()}
			cs.mu.Unlock()
			a.log.Info("CA refused to sign", "context", cs.name, "principals", k, "host", host, "error", err)
		}
		return nil, err
	}
	if string(cert.Key.Marshal()) != string(key.PublicKey().Marshal()) {
		return nil, errors.New("CA returned a certificate for a different key")
	}
	e := &certEntry{context: cs.name, principals: principals, cert: cert, signer: key, signed: a.now()}
	cs.mu.Lock()
	if cs.identity == identity {
		cs.certs[k] = e
		delete(cs.denied, k)
	}
	cs.mu.Unlock()
	a.log.Info("signed certificate", "context", cs.name, "principals", k, "serial", cert.Serial,
		"key_id", cert.KeyId, "valid_before", certTime(cert.ValidBefore).Format(time.RFC3339), "host", host)
	return e, nil
}

// hostCAKeys returns the keys that sign this context's host certificates:
// the @cert-authority lines in known_hosts, or else the CA itself.
func (a *Agent) hostCAKeys(cs *contextState) []ssh.PublicKey {
	cs.mu.Lock()
	if cs.hostCAs != nil && a.now().Sub(cs.hostCAsAt) < hostCAMaxAge {
		keys := cs.hostCAs
		cs.mu.Unlock()
		return keys
	}
	cs.mu.Unlock()
	keys := a.caKeysFromKnownHosts(cs.name)
	if len(keys) == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var err error
		keys, err = cs.backend.HostCAs(ctx)
		if err != nil {
			a.log.Debug("reading host CA failed", "context", cs.name, "error", err)
		}
	}
	if keys == nil {
		keys = []ssh.PublicKey{}
	}
	cs.mu.Lock()
	cs.hostCAs, cs.hostCAsAt = keys, a.now()
	cs.mu.Unlock()
	return keys
}

// cached returns valid certificates, most recently used first.
func (cs *contextState) cached(t time.Time) []*certEntry {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	var out []*certEntry
	for _, e := range cs.certs {
		if e.validAt(t) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].lastUsed.After(out[j].lastUsed) })
	return out
}

func (cs *contextState) warn(a *Agent, msg string, args ...any) {
	cs.mu.Lock()
	now := a.now()
	if now.Sub(cs.lastWarn) < warnEvery {
		cs.mu.Unlock()
		return
	}
	cs.lastWarn = now
	cs.mu.Unlock()
	a.log.Warn(msg, append([]any{"context", cs.name}, args...)...)
}
