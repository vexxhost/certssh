// Command certssh is an SSH agent and CLI for SSH certificate authorities in
// OpenBao and HashiCorp Vault.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vexxhost/certssh/internal/agent"
	"github.com/vexxhost/certssh/internal/config"
	"github.com/vexxhost/certssh/internal/session"
)

var version = "dev"

const usage = `certssh: SSH certificates from OpenBao or Vault, picked per host by an agent.

Usage:
  certssh [-config file] <command> [flags] [args]

Commands:
  login [address]    Log in to a CA (creates the context on first use)
  logout             Revoke the session and drop its certificates
  status             Show the agent, sessions and certificates
  agent              Run the agent in the foreground
  agent install      Run the agent as a user service (launchd or systemd)
  agent uninstall    Remove the user service
  trust              Trust the context's host CA in ~/.ssh/known_hosts
  contexts           List contexts
  use <context>      Select the current context
  which <host>       Show the context and principals the agent uses for a host
  version            Print the version

Run certssh <command> -h for a command's flags.
`

type globals struct {
	configPath string
	out        io.Writer
	errOut     io.Writer
}

func (g *globals) load() (*config.Config, error) {
	return config.Load(g.configPath)
}

func (g *globals) store() session.Store {
	return session.Store{Dir: filepath.Join(config.Dir(), "sessions")}
}

func main() {
	agent.Version = version
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "certssh:", err)
		os.Exit(1)
	}
}

func run(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("certssh", flag.ContinueOnError)
	fs.SetOutput(errOut)
	g := &globals{out: out, errOut: errOut}
	fs.StringVar(&g.configPath, "config", os.Getenv("CERTSSH_CONFIG"), "configuration file (default "+config.DefaultPath()+")")
	fs.Usage = func() { fmt.Fprint(errOut, usage) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return flag.ErrHelp
	}
	cmd, rest := rest[0], rest[1:]
	switch cmd {
	case "login":
		return cmdLogin(g, rest)
	case "logout":
		return cmdLogout(g, rest)
	case "status":
		return cmdStatus(g, rest)
	case "agent":
		if len(rest) > 0 && rest[0] == "install" {
			return cmdAgentInstall(g, rest[1:])
		}
		if len(rest) > 0 && rest[0] == "uninstall" {
			return cmdAgentUninstall(g, rest[1:])
		}
		return cmdAgent(g, rest)
	case "trust":
		return cmdTrust(g, rest)
	case "contexts":
		return cmdContexts(g, rest)
	case "use":
		return cmdUse(g, rest)
	case "which":
		return cmdWhich(g, rest)
	case "version", "-version", "--version":
		fmt.Fprintln(out, "certssh", version)
		return nil
	case "help", "-h", "--help":
		fs.Usage()
		return nil
	}
	return fmt.Errorf("unknown command %q (see certssh help)", cmd)
}

// parseInterspersed parses flags that may appear before or after positional
// arguments, the way people type "certssh login https://... -mount entra".
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		if args[0] == "--" {
			return append(positional, args[1:]...), nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

func newFlagSet(g *globals, name, synopsis string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(g.errOut)
	fs.Usage = func() {
		fmt.Fprintf(g.errOut, "Usage: certssh %s\n\n", synopsis)
		fs.PrintDefaults()
	}
	return fs
}

// sameSocket reports whether two socket paths name the same file.
func sameSocket(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	fa, errA := os.Stat(a)
	fb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(fa, fb)
}

func tilde(p string) string {
	h, err := os.UserHomeDir()
	if err == nil && h != "" && strings.HasPrefix(p, h+string(filepath.Separator)) {
		return "~" + p[len(h):]
	}
	return p
}
