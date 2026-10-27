package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/vexxhost/certssh/internal/agent"
	"github.com/vexxhost/certssh/internal/config"
	"github.com/vexxhost/certssh/internal/profile"
)

const hostKeyTimeout = 5 * time.Second

// cmdWhich shows what the agent would do for a host. It reads the host key
// the server presents, as ssh would, so host certificates that list their
// principals are taken into account; without the host key (with -offline,
// or when the host cannot be reached) it matches the name against profiles.
func cmdWhich(g *globals, args []string) error {
	fs := newFlagSet(g, "which", "which [-as persona] [-offline] <host>")
	persona := fs.String("as", "", "persona (default: the session's, or human)")
	offline := fs.Bool("offline", false, "match the name against profiles without connecting to the host")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("which takes one host name")
	}
	host := pos[0]
	if !*offline {
		key, err := fetchHostKey(host, hostKeyTimeout)
		if err == nil {
			a, err := agent.New(agent.Options{ConfigPath: g.configPath, Upstream: "none"})
			if err != nil {
				return err
			}
			return printExplanation(g.out, host, a.Explain(key, *persona))
		}
		fmt.Fprintf(g.errOut, "certssh: cannot read the host key of %s (%v); matching the name against profiles\n", host, err)
	}
	return whichByName(g, host, *persona)
}

func printExplanation(w io.Writer, host string, e agent.Explanation) error {
	switch {
	case !e.Recognised:
		return fmt.Errorf("%s is not recognised: %s", host, e.Reason)
	case len(e.Candidates) == 1:
		fmt.Fprintf(w, "%s: context %s, principal %s (listed in the host certificate)\n", host, e.Context, e.Candidates[0])
	case len(e.Candidates) > 1:
		fmt.Fprintf(w, "%s: context %s, principals %s (listed in the host certificate, tried in order)\n",
			host, e.Context, strings.Join(e.Candidates, ","))
	case e.Profile == "*":
		fmt.Fprintf(w, "%s: context %s (one certificate for %s)\n", host, e.Context, strings.Join(e.Principals, ","))
	default:
		fmt.Fprintf(w, "%s: context %s, profile %s, principal %s\n", host, e.Context, e.Profile, strings.Join(e.Principals, ","))
	}
	return nil
}

// whichByName resolves a host name the way the agent does when it only has
// names to go on.
func whichByName(g *globals, host, persona string) error {
	cfg, err := g.load()
	if err != nil {
		return err
	}
	store := g.store()
	for _, name := range cfg.Names() {
		ctx := cfg.Contexts[name]
		p := persona
		if p == "" {
			p = config.PersonaHuman
			if s, err := store.Load(name); err == nil && s.Persona != "" {
				p = s.Persona
			}
		}
		profiles, _, err := ctx.LoadProfiles()
		if err != nil {
			return fmt.Errorf("context %q: %w", name, err)
		}
		pr, ok := profile.Match(profiles, p, host)
		if !ok {
			continue
		}
		if ctx.ManyPrincipals() {
			var all []string
			for _, pr := range profiles {
				if v := pr.PrincipalFor(p); v != "" {
					all = append(all, v)
				}
			}
			fmt.Fprintf(g.out, "%s: context %s (one certificate for %s)\n", host, name, strings.Join(all, ","))
			return nil
		}
		fmt.Fprintf(g.out, "%s: context %s, profile %s, principal %s\n", host, name, pr.Name, pr.PrincipalFor(p))
		return nil
	}
	return fmt.Errorf("%s matches no profile", host)
}

// hostKeyAlgorithms prefers certificates, so a server that has a host
// certificate presents it.
var hostKeyAlgorithms = []string{
	ssh.CertAlgoED25519v01, ssh.CertAlgoECDSA256v01, ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA521v01,
	ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01,
	ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
}

var errGotHostKey = errors.New("host key received")

// fetchHostKey connects to host, using the address ssh would, and returns
// the key the server presents. It stops after key exchange.
func fetchHostKey(host string, timeout time.Duration) (ssh.PublicKey, error) {
	addr := sshAddress(host)
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	var key ssh.PublicKey
	_, _, _, err = ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:              "certssh",
		HostKeyAlgorithms: hostKeyAlgorithms,
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = k
			return errGotHostKey
		},
	})
	if key != nil {
		return key, nil
	}
	return nil, err
}

// sshAddress returns the address ssh connects to for host, following
// HostName and Port in the ssh config.
func sshAddress(host string) string {
	ctx, cancel := context.WithTimeout(context.Background(), hostKeyTimeout)
	defer cancel()
	// "--" keeps a host name starting with "-" from being read as an option.
	out, err := exec.CommandContext(ctx, "ssh", "-G", "--", host).Output() //nolint:gosec // fixed command, host is an argument

	if err != nil {
		return net.JoinHostPort(host, "22")
	}
	return parseSSHAddress(out, host)
}

func parseSSHAddress(out []byte, host string) string {
	hostname, port := host, "22"
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "hostname":
			hostname = strings.TrimSpace(value)
		case "port":
			port = strings.TrimSpace(value)
		}
	}
	return net.JoinHostPort(hostname, port)
}
