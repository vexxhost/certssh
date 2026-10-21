package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"gopkg.in/yaml.v3"

	"github.com/vexxhost/certssh/internal/backend"
	"github.com/vexxhost/certssh/internal/backend/local"
	"github.com/vexxhost/certssh/internal/config"
	"github.com/vexxhost/certssh/internal/knownhosts"
	"github.com/vexxhost/certssh/internal/profile"
	"github.com/vexxhost/certssh/internal/session"
)

type env struct {
	t          *testing.T
	dir        string
	cfgPath    string
	socket     string
	knownHosts string
	store      session.Store
	userCA     ssh.Signer
	hostCA     ssh.Signer
	agent      *Agent
	listener   net.Listener
}

func newSigner(t *testing.T) (ssh.Signer, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, priv
}

// newEnv builds a config with a local CA and two allowed principals.
// Profiles: infra-* -> env:infra, public-* -> env:public, secret-* ->
// env:secret (refused by the CA).
func newEnv(t *testing.T, mutate func(*config.Config)) *env {
	t.Helper()
	// Unix socket paths are limited to ~104 bytes; t.TempDir() can exceed it.
	dir, err := os.MkdirTemp("", "certssh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	e := &env{t: t, dir: dir, cfgPath: filepath.Join(dir, "config.yaml"), socket: filepath.Join(dir, "agent.sock"),
		knownHosts: filepath.Join(dir, "known_hosts"), store: session.Store{Dir: filepath.Join(dir, "sessions")}}

	var userPriv ed25519.PrivateKey
	e.userCA, userPriv = newSigner(t)
	e.hostCA, _ = newSigner(t)
	block, err := ssh.MarshalPrivateKey(userPriv, "user-ca")
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "user_ca")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Current: "test",
		Contexts: map[string]*config.Context{"test": {
			Backend: "local",
			Local:   &config.Local{UserCAKey: caFile, TTL: "1h", AllowedPrincipals: []string{"env:infra", "env:public"}},
			Profiles: config.Profiles{Inline: []profile.Profile{
				{Name: "infra", Principal: "env:infra", AgentPrincipal: "agent:infra", Hosts: []string{"infra-*"}},
				{Name: "public", Principal: "env:public", Hosts: []string{"public-*"}},
				{Name: "secret", Principal: "env:secret", Hosts: []string{"secret-*"}},
			}},
		}},
	}
	if mutate != nil {
		mutate(cfg)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := knownhosts.Install(e.knownHosts, "test", nil, []ssh.PublicKey{e.hostCA.PublicKey()}); err != nil {
		t.Fatal(err)
	}
	e.login(config.PersonaHuman)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	e.agent, err = New(Options{ConfigPath: e.cfgPath, Socket: e.socket, Upstream: "none",
		KnownHosts: e.knownHosts, Sessions: e.store, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	e.listener, err = Listen(e.socket)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = e.agent.Serve(e.listener) }()
	t.Cleanup(func() { e.listener.Close() })
	return e
}

func (e *env) login(persona string) {
	e.t.Helper()
	cfg, err := config.Load(e.cfgPath)
	if err != nil {
		e.t.Fatal(err)
	}
	b, err := local.New("test", cfg.Contexts["test"].Local)
	if err != nil {
		e.t.Fatal(err)
	}
	sess, err := b.Login(nil, persona, backend.LoginOptions{}) //nolint:staticcheck // the local backend ignores the context
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.store.Save(sess); err != nil {
		e.t.Fatal(err)
	}
}

// server is a minimal SSH server that accepts certificates from the user CA
// carrying its required principal, and optionally one plain key.
type server struct {
	addr string
	mu   sync.Mutex
	// attempts records each public key offered, as "cert:<principals>" or
	// "key:<fingerprint>".
	attempts []string
}

func (s *server) tries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.attempts...)
}

func (e *env) server(names []string, principal string, plain ssh.PublicKey, withHostCert bool) (*server, ssh.Signer) {
	e.t.Helper()
	hostKey, _ := newSigner(e.t)
	hostSigner := hostKey
	if withHostCert {
		cert := &ssh.Certificate{Key: hostKey.PublicKey(), CertType: ssh.HostCert, KeyId: names[0],
			ValidPrincipals: names, ValidBefore: ssh.CertTimeInfinity}
		if err := cert.SignCert(rand.Reader, e.hostCA); err != nil {
			e.t.Fatal(err)
		}
		var err error
		if hostSigner, err = ssh.NewCertSigner(cert, hostKey); err != nil {
			e.t.Fatal(err)
		}
	}
	s := &server{}
	userCA := string(e.userCA.PublicKey().Marshal())
	checker := &ssh.CertChecker{}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if cert, ok := key.(*ssh.Certificate); ok {
			s.attempts = append(s.attempts, "cert:"+strings.Join(cert.ValidPrincipals, ","))
			if string(cert.SignatureKey.Marshal()) != userCA {
				return nil, errors.New("unknown CA")
			}
			if err := checker.CheckCert(principal, cert); err != nil {
				return nil, err
			}
			return &ssh.Permissions{}, nil
		}
		s.attempts = append(s.attempts, "key:"+ssh.FingerprintSHA256(key))
		if plain != nil && string(key.Marshal()) == string(plain.Marshal()) {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("not authorized")
	}}
	cfg.AddHostKey(hostSigner)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { l.Close() })
	s.addr = l.Addr().String()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go serveConn(c, cfg)
		}
	}()
	return s, hostKey
}

func serveConn(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		chn, reqs, err := ch.Accept()
		if err != nil {
			continue
		}
		go func() {
			for r := range reqs {
				if r.Type == "exec" {
					_ = r.Reply(true, nil)
					_, _ = chn.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{0}))
					chn.Close()
					return
				}
				_ = r.Reply(false, nil)
			}
		}()
	}
}

func requireSSH(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		if os.Getenv("REQUIRE_SSH") != "" {
			t.Fatal("ssh not found")
		}
		t.Skip("OpenSSH client not installed")
	}
}

// ssh runs the OpenSSH client against a server under a host name alias.
func (e *env) ssh(s *server, alias string) error {
	host, port, _ := net.SplitHostPort(s.addr)
	cmd := exec.Command("ssh", "-F", "/dev/null", "-p", port,
		"-o", "IdentityAgent="+e.socket, "-o", "IdentityFile=none",
		"-o", "UserKnownHostsFile="+e.knownHosts, "-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlias="+alias,
		"-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR",
		"user@"+host, "true")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

func TestOpenSSHGetsTheRightCertificatePerHost(t *testing.T) {
	requireSSH(t)
	e := newEnv(t, nil)
	infra, _ := e.server([]string{"infra-1"}, "env:infra", nil, true)
	public, _ := e.server([]string{"public-1"}, "env:public", nil, true)

	if err := e.ssh(infra, "infra-1"); err != nil {
		t.Fatalf("infra: %v", err)
	}
	if err := e.ssh(public, "public-1"); err != nil {
		t.Fatalf("public: %v", err)
	}
	if got := infra.tries(); len(got) != 1 || got[0] != "cert:env:infra" {
		t.Fatalf("infra saw %v, want exactly the env:infra certificate", got)
	}
	if got := public.tries(); len(got) != 1 || got[0] != "cert:env:public" {
		t.Fatalf("public saw %v, want exactly the env:public certificate", got)
	}
	if err := e.ssh(infra, "infra-1"); err != nil {
		t.Fatal(err)
	}
	if n := e.agent.Signs(); n != 2 {
		t.Fatalf("signed %d certificates, want 2 (the second infra login reuses the first)", n)
	}
	st := e.agent.Status()
	if len(st.Contexts) != 1 || len(st.Contexts[0].Certificates) != 2 || st.Contexts[0].Session == nil {
		t.Fatalf("status: %+v", st)
	}
}

func TestConcurrentConnectionsSignOnce(t *testing.T) {
	requireSSH(t)
	e := newEnv(t, nil)
	infra, _ := e.server([]string{"infra-1"}, "env:infra", nil, true)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- e.ssh(infra, "infra-1")
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := e.agent.Signs(); n != 1 {
		t.Fatalf("20 concurrent connections caused %d signings, want 1", n)
	}
}

func TestRefusedPrincipalIsNotRetried(t *testing.T) {
	requireSSH(t)
	e := newEnv(t, nil)
	secret, _ := e.server([]string{"secret-1"}, "env:secret", nil, true)
	if err := e.ssh(secret, "secret-1"); err == nil {
		t.Fatal("login succeeded without a permitted principal")
	}
	if err := e.ssh(secret, "secret-1"); err == nil {
		t.Fatal("second login succeeded")
	}
	if n := e.agent.Signs(); n != 1 {
		t.Fatalf("signed %d times, want 1 (the refusal is remembered)", n)
	}
	st := e.agent.Status()
	if len(st.Contexts[0].Denied) != 1 || st.Contexts[0].Denied[0].Principals != "env:secret" {
		t.Fatalf("denied: %+v", st.Contexts[0].Denied)
	}
}

func TestBareHostKeyResolvedThroughKnownHosts(t *testing.T) {
	requireSSH(t)
	e := newEnv(t, nil)
	srv, hostKey := e.server([]string{"infra-legacy"}, "env:infra", nil, false)
	f, err := os.OpenFile(e.knownHosts, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(f, "infra-legacy %s", ssh.MarshalAuthorizedKey(hostKey.PublicKey()))
	f.Close()
	if err := e.ssh(srv, "infra-legacy"); err != nil {
		t.Fatal(err)
	}
	if got := srv.tries(); len(got) != 1 || got[0] != "cert:env:infra" {
		t.Fatalf("saw %v", got)
	}
}

func TestOwnKeysStillWork(t *testing.T) {
	requireSSH(t)
	e := newEnv(t, nil)
	mine, priv := newSigner(t)
	ag, c, err := dial(e.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := ag.Add(agent.AddedKey{PrivateKey: priv, Comment: "mine"}); err != nil {
		t.Fatal(err)
	}

	// A host outside every CA, which knows only my key.
	github, hostKey := e.server([]string{"github.com"}, "", mine.PublicKey(), false)
	f, _ := os.OpenFile(e.knownHosts, os.O_APPEND|os.O_WRONLY, 0o600)
	fmt.Fprintf(f, "github.com %s", ssh.MarshalAuthorizedKey(hostKey.PublicKey()))
	f.Close()
	if err := e.ssh(github, "github.com"); err != nil {
		t.Fatal(err)
	}
	if n := e.agent.Signs(); n != 0 {
		t.Fatalf("signed %d certificates for a host outside the CA", n)
	}

	// A CA host that also still has my key: certificate first, my key after.
	infra, _ := e.server([]string{"infra-1"}, "env:public", mine.PublicKey(), true)
	if err := e.ssh(infra, "infra-1"); err != nil {
		t.Fatal(err)
	}
	got := infra.tries()
	if len(got) != 2 || got[0] != "cert:env:infra" || !strings.HasPrefix(got[1], "key:") {
		t.Fatalf("saw %v, want the certificate and then my key", got)
	}

	keys, err := ag.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("ssh-add -l shows %d keys, want my key and the certificate", len(keys))
	}
}

func TestLogoutDropsCertificatesAndNewLoginGetsNewKey(t *testing.T) {
	requireSSH(t)
	e := newEnv(t, nil)
	infra, _ := e.server([]string{"infra-1"}, "env:infra", nil, true)
	if err := e.ssh(infra, "infra-1"); err != nil {
		t.Fatal(err)
	}
	firstKey := e.agent.Status().Contexts[0].Key

	if err := e.store.Delete("test"); err != nil {
		t.Fatal(err)
	}
	if err := e.ssh(infra, "infra-1"); err == nil {
		t.Fatal("login succeeded after logout")
	}
	if st := e.agent.Status(); len(st.Contexts[0].Certificates) != 0 || st.Contexts[0].Session != nil {
		t.Fatalf("certificates survived logout: %+v", st.Contexts[0])
	}

	time.Sleep(10 * time.Millisecond) // a distinct issue time for the new session
	e.login(config.PersonaHuman)
	if err := e.ssh(infra, "infra-1"); err != nil {
		t.Fatal(err)
	}
	if k := e.agent.Status().Contexts[0].Key; k == firstKey || k == "" {
		t.Fatalf("new login reused key %s", k)
	}
}

func TestAgentPersonaUsesAgentPrincipal(t *testing.T) {
	requireSSH(t)
	e := newEnv(t, func(c *config.Config) {
		c.Contexts["test"].Local.AllowedPrincipals = []string{"agent:infra"}
	})
	e.login(config.PersonaAgent)
	infra, _ := e.server([]string{"infra-1"}, "agent:infra", nil, true)
	public, _ := e.server([]string{"public-1"}, "env:public", nil, true)
	if err := e.ssh(infra, "infra-1"); err != nil {
		t.Fatal(err)
	}
	if err := e.ssh(public, "public-1"); err == nil {
		t.Fatal("an agent session reached a host without an agent principal")
	}
	if n := e.agent.Signs(); n != 1 {
		t.Fatalf("signed %d, want 1", n)
	}
}

func TestManyPrincipalsInOneCertificate(t *testing.T) {
	requireSSH(t)
	e := newEnv(t, func(c *config.Config) {
		c.Contexts["test"].Principals = "many"
		c.Contexts["test"].Profiles.Inline = c.Contexts["test"].Profiles.Inline[:2]
	})
	infra, _ := e.server([]string{"infra-1"}, "env:infra", nil, true)
	other, _ := e.server([]string{"anything"}, "env:public", nil, true)
	if err := e.ssh(infra, "infra-1"); err != nil {
		t.Fatal(err)
	}
	if err := e.ssh(other, "anything"); err != nil {
		t.Fatal(err)
	}
	if got := other.tries(); len(got) != 1 || got[0] != "cert:env:infra,env:public" {
		t.Fatalf("saw %v", got)
	}
	if n := e.agent.Signs(); n != 1 {
		t.Fatalf("signed %d, want 1", n)
	}
}

// bindTo opens an agent connection and binds it to a host key.
func (e *env) bindTo(t *testing.T, host ssh.Signer, forwarding bool) (agent.ExtendedAgent, func()) {
	t.Helper()
	ag, c, err := dial(e.socket)
	if err != nil {
		t.Fatal(err)
	}
	req, err := MarshalBind(host, []byte("session-id"), forwarding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ag.Extension(ExtensionSessionBind, req); err != nil {
		t.Fatal(err)
	}
	return ag, func() { c.Close() }
}

func (e *env) hostCert(t *testing.T, names ...string) ssh.Signer {
	t.Helper()
	k, _ := newSigner(t)
	cert := &ssh.Certificate{Key: k.PublicKey(), CertType: ssh.HostCert, ValidPrincipals: names, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, e.hostCA); err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewCertSigner(cert, k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestForwardedConnectionsGetNoCertificates(t *testing.T) {
	e := newEnv(t, nil)
	ag, done := e.bindTo(t, e.hostCert(t, "infra-1"), true)
	defer done()
	keys, err := ag.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 || e.agent.Signs() != 0 {
		t.Fatalf("forwarded connection got %d keys, %d signings", len(keys), e.agent.Signs())
	}
	if err := ag.RemoveAll(); err == nil {
		t.Fatal("a forwarded connection could remove keys")
	}
}

func TestForwardingCanBeAllowed(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Agent.AllowForwarded = true })
	ag, done := e.bindTo(t, e.hostCert(t, "infra-1"), true)
	defer done()
	keys, err := ag.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want the infra certificate", len(keys))
	}
}

func TestHostCertificateFromAnotherCAIsNotTrusted(t *testing.T) {
	e := newEnv(t, nil)
	rogueCA, _ := newSigner(t)
	k, _ := newSigner(t)
	cert := &ssh.Certificate{Key: k.PublicKey(), CertType: ssh.HostCert, ValidPrincipals: []string{"infra-1"}, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, rogueCA); err != nil {
		t.Fatal(err)
	}
	rogue, _ := ssh.NewCertSigner(cert, k)
	ag, done := e.bindTo(t, rogue, false)
	defer done()
	keys, err := ag.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 || e.agent.Signs() != 0 {
		t.Fatalf("a host claiming infra-1 under a rogue CA got %d keys", len(keys))
	}
}

func TestBindWithBadSignatureIsRejected(t *testing.T) {
	e := newEnv(t, nil)
	ag, c, err := dial(e.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	host := e.hostCert(t, "infra-1")
	other, _ := newSigner(t)
	sig, _ := other.Sign(rand.Reader, []byte("session-id"))
	req := ssh.Marshal(struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}{host.PublicKey().Marshal(), []byte("session-id"), ssh.Marshal(sig), false})
	if _, err := ag.Extension(ExtensionSessionBind, req); err == nil {
		t.Fatal("bind with a signature from another key was accepted")
	}
}

func TestControlOnlyFromUnboundConnections(t *testing.T) {
	e := newEnv(t, nil)
	if _, err := QueryStatus(e.socket); err != nil {
		t.Fatal(err)
	}
	if err := RequestReload(e.socket); err != nil {
		t.Fatal(err)
	}
	ag, done := e.bindTo(t, e.hostCert(t, "infra-1"), false)
	defer done()
	if _, err := ag.Extension(ExtensionStatus, nil); err == nil {
		t.Fatal("status answered on a bound connection")
	}
}

func TestLockHidesEverything(t *testing.T) {
	e := newEnv(t, nil)
	ag, c, err := dial(e.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv := newSigner(t)
	if err := ag.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	if err := ag.Lock([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	b, done := e.bindTo(t, e.hostCert(t, "infra-1"), false)
	defer done()
	if keys, _ := b.List(); len(keys) != 0 || e.agent.Signs() != 0 {
		t.Fatalf("locked agent offered %d keys", len(keys))
	}
	if err := ag.Unlock([]byte("wrong")); err == nil {
		t.Fatal("unlocked with the wrong passphrase")
	}
	if err := ag.Unlock([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	if keys, _ := b.List(); len(keys) != 2 {
		t.Fatalf("after unlock got %d keys, want certificate and added key", len(keys))
	}
}

func TestUpstreamKeysAreOffered(t *testing.T) {
	requireSSH(t)
	e := newEnv(t, nil)
	upSock := filepath.Join(e.dir, "upstream.sock")
	ul, err := net.Listen("unix", upSock)
	if err != nil {
		t.Fatal(err)
	}
	defer ul.Close()
	upKeyring := agent.NewKeyring()
	mine, priv := newSigner(t)
	if err := upKeyring.Add(agent.AddedKey{PrivateKey: priv, Comment: "yubikey"}); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ul.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(upKeyring, c); c.Close() }()
		}
	}()
	e.agent.opts.Upstream = upSock
	if err := e.agent.Reload(); err != nil {
		t.Fatal(err)
	}

	srv, hostKey := e.server([]string{"git.example.com"}, "", mine.PublicKey(), false)
	f, _ := os.OpenFile(e.knownHosts, os.O_APPEND|os.O_WRONLY, 0o600)
	fmt.Fprintf(f, "git.example.com %s", ssh.MarshalAuthorizedKey(hostKey.PublicKey()))
	f.Close()
	if err := e.ssh(srv, "git.example.com"); err != nil {
		t.Fatalf("upstream key did not work through certssh: %v", err)
	}
}

func TestListenRefusesARunningAgent(t *testing.T) {
	e := newEnv(t, nil)
	if _, err := Listen(e.socket); err == nil {
		t.Fatal("second agent took over a live socket")
	}
	stale := filepath.Join(e.dir, "stale.sock")
	l, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	if ul, ok := l.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	l.Close()
	l2, err := Listen(stale)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	l2.Close()
}
