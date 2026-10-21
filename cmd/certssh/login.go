package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/vexxhost/certssh/internal/agent"
	"github.com/vexxhost/certssh/internal/backend"
	"github.com/vexxhost/certssh/internal/backends"
	"github.com/vexxhost/certssh/internal/config"
	"github.com/vexxhost/certssh/internal/knownhosts"
	"github.com/vexxhost/certssh/internal/profile"
	"github.com/vexxhost/certssh/internal/session"
)

func cmdLogin(g *globals, args []string) error {
	fs := newFlagSet(g, "login", "login [flags] [address]")
	var (
		contextName = fs.String("context", "", "context name (default: the address's host name, or the current context)")
		persona     = fs.String("as", config.PersonaHuman, "persona: human or agent")
		backendName = fs.String("backend", "", "backend for a new context: openbao, vault or local")
		method      = fs.String("method", "", "login method: oidc or token")
		mount       = fs.String("mount", "", "auth mount")
		role        = fs.String("role", "", "auth role (default: the mount's default_role)")
		callback    = fs.String("callback", "", "OIDC callback mode: client, direct or device")
		listen      = fs.String("listen", "", "address for the OIDC client callback (default localhost:8250)")
		token       = fs.String("token", "", "token for -method token (default BAO_TOKEN, VAULT_TOKEN or ~/.vault-token)")
		namespace   = fs.String("namespace", "", "namespace")
		caCert      = fs.String("ca-cert", "", "CA bundle to verify the server")
		userCA      = fs.String("user-ca", "", "SSH user CA mount (default ssh-client-signer)")
		hostCA      = fs.String("host-ca", "", "SSH host CA mount (default ssh-host-signer, - for none)")
		signRole    = fs.String("signing-role", "", "SSH signing role for this persona (default: the persona's name)")
		profiles    = fs.String("profiles", "", "site profile file")
		hostCAPats  = fs.String("host-ca-patterns", "", "comma-separated host patterns the host CA is trusted for (default: the profiles' hosts, or * without profiles)")
		noBrowser   = fs.Bool("no-browser", false, "print the login URL instead of opening a browser")
		noTrust     = fs.Bool("no-trust", false, "do not install the host CA in ~/.ssh/known_hosts")
	)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return errors.New("login takes at most one address")
	}
	if *persona != config.PersonaHuman && *persona != config.PersonaAgent {
		return fmt.Errorf("-as must be %s or %s", config.PersonaHuman, config.PersonaAgent)
	}

	cfg, err := g.load()
	if err != nil {
		return err
	}
	address := ""
	if len(pos) == 1 {
		address = pos[0]
	}
	name := *contextName
	if name == "" && address != "" {
		u, err := url.Parse(address)
		if err != nil || u.Hostname() == "" {
			return fmt.Errorf("invalid address %q", address)
		}
		name = u.Hostname()
	}
	if name == "" {
		name = cfg.Current
	}
	if name == "" {
		return errors.New("give the CA's address: certssh login https://openbao.example.com")
	}
	if cfg.Contexts == nil {
		cfg.Contexts = map[string]*config.Context{}
	}
	ctx := cfg.Contexts[name]
	if ctx == nil {
		if address == "" && *backendName != "local" {
			return fmt.Errorf("context %q does not exist; give its address", name)
		}
		ctx = &config.Context{}
		cfg.Contexts[name] = ctx
	}
	if address != "" {
		ctx.Address = address
	}
	set := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	set(&ctx.Backend, *backendName)
	set(&ctx.Namespace, *namespace)
	set(&ctx.CACert, *caCert)
	set(&ctx.CA.User, *userCA)
	set(&ctx.CA.Host, *hostCA)
	if *profiles != "" {
		ctx.Profiles = config.Profiles{Source: "file", Path: *profiles}
	}
	if *hostCAPats != "" {
		ctx.HostCAPatterns = strings.Split(*hostCAPats, ",")
	}
	if *signRole != "" {
		if ctx.Roles == nil {
			ctx.Roles = map[string]string{}
		}
		ctx.Roles[*persona] = *signRole
	}
	l := ctx.Login[*persona]
	set(&l.Method, *method)
	set(&l.Mount, *mount)
	set(&l.Role, *role)
	set(&l.Callback, *callback)
	set(&l.ListenAddress, *listen)
	if l != (config.Login{}) {
		if ctx.Login == nil {
			ctx.Login = map[string]config.Login{}
		}
		ctx.Login[*persona] = l
	}
	cfg.Current = name
	if err := cfg.Validate(); err != nil {
		return err
	}

	b, err := backends.Open(name, ctx)
	if err != nil {
		return err
	}
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sess, err := b.Login(sigCtx, *persona, backend.LoginOptions{
		Token: *token, Out: g.errOut, OpenURL: openBrowser, NoBrowser: *noBrowser,
	})
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	sess.Context = name
	// Only remember the context once a login has worked.
	if err := cfg.Save(); err != nil {
		return err
	}
	if err := g.store().Save(sess); err != nil {
		return err
	}
	fmt.Fprintf(g.out, "Logged in to %s as %s (%s%s)\n", name, sess.DisplayName, sess.Persona, expiry(sess))

	if !*noTrust {
		if err := trust(sigCtx, g, name, ctx, b); err != nil {
			fmt.Fprintf(g.errOut, "warning: trusting the host CA failed: %v\n", err)
		}
	}
	reportAgent(g, cfg)
	return nil
}

func expiry(s *backend.Session) string {
	if s.ExpiresAt.IsZero() {
		return ", no expiry"
	}
	return ", expires " + s.ExpiresAt.Local().Format("Jan 2 15:04")
}

// trust writes the host CA's @cert-authority line for a context.
func trust(ctx context.Context, g *globals, name string, c *config.Context, b backend.Backend) error {
	if c.BackendName() != "local" && c.HostCA() == "-" {
		return nil
	}
	tctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	keys, err := b.HostCAs(tctx)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil
	}
	profiles, patterns, err := c.LoadProfiles()
	if err != nil {
		return err
	}
	if len(patterns) == 0 {
		patterns = profile.KnownHostsPatterns(profiles)
	}
	if len(patterns) == 0 {
		// Hosts describe themselves through their certificates.
		patterns = []string{"*"}
	}
	file := config.KnownHostsFile()
	changed, err := knownhosts.Install(file, name, patterns, keys)
	if err != nil {
		return err
	}
	if changed {
		fps := ""
		for i, k := range keys {
			if i > 0 {
				fps += ", "
			}
			fps += ssh.FingerprintSHA256(k)
		}
		fmt.Fprintf(g.out, "Trusting host CA %s in %s\n", fps, tilde(file))
	}
	return nil
}

// reportAgent tells the agent to pick up changes and checks that ssh will
// talk to it.
func reportAgent(g *globals, cfg *config.Config) {
	socket := cfg.SocketPath()
	if err := agent.RequestReload(socket); err != nil {
		fmt.Fprintf(g.errOut, "\nThe certssh agent is not running. Start it with:\n\n    certssh agent install\n\n")
		return
	}
	if !sameSocket(os.Getenv("SSH_AUTH_SOCK"), socket) {
		fmt.Fprintf(g.errOut, "\nssh is not using the certssh agent yet. Add this to your shell profile:\n\n    export SSH_AUTH_SOCK=%s\n\n", tilde(socket))
	}
}

func cmdLogout(g *globals, args []string) error {
	fs := newFlagSet(g, "logout", "logout [-context name]")
	contextName := fs.String("context", "", "context (default: current)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	cfg, err := g.load()
	if err != nil {
		return err
	}
	name, ctx, err := cfg.Resolve(*contextName)
	if err != nil {
		return err
	}
	store := g.store()
	sess, err := store.Load(name)
	if errors.Is(err, session.ErrNoSession) {
		fmt.Fprintf(g.out, "Not logged in to %s\n", name)
		return nil
	}
	if err != nil {
		return err
	}
	if b, err := backends.Open(name, ctx); err == nil {
		lctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if err := b.Logout(lctx, sess); err != nil {
			fmt.Fprintf(g.errOut, "warning: revoking the token failed: %v\n", err)
		}
		cancel()
	}
	if err := store.Delete(name); err != nil {
		return err
	}
	_ = agent.RequestReload(cfg.SocketPath())
	fmt.Fprintf(g.out, "Logged out of %s\n", name)
	return nil
}

func cmdTrust(g *globals, args []string) error {
	fs := newFlagSet(g, "trust", "trust [-context name] [-remove]")
	contextName := fs.String("context", "", "context (default: current)")
	remove := fs.Bool("remove", false, "remove the context's host CA lines instead")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	cfg, err := g.load()
	if err != nil {
		return err
	}
	name, ctx, err := cfg.Resolve(*contextName)
	if err != nil {
		return err
	}
	if *remove {
		changed, err := knownhosts.Remove(config.KnownHostsFile(), name)
		if err == nil && changed {
			fmt.Fprintf(g.out, "Removed the host CA for %s from %s\n", name, tilde(config.KnownHostsFile()))
		}
		return err
	}
	b, err := backends.Open(name, ctx)
	if err != nil {
		return err
	}
	if err := trust(context.Background(), g, name, ctx, b); err != nil {
		return err
	}
	_ = agent.RequestReload(cfg.SocketPath())
	return nil
}
