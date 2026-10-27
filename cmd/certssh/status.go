package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/vexxhost/certssh/internal/agent"
	"github.com/vexxhost/certssh/internal/session"
)

func cmdStatus(g *globals, args []string) error {
	fs := newFlagSet(g, "status", "status [-json]")
	asJSON := fs.Bool("json", false, "print the agent's status as JSON")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	cfg, err := g.load()
	if err != nil {
		return err
	}
	socket := cfg.SocketPath()
	st, err := agent.QueryStatus(socket)
	if *asJSON {
		if err != nil {
			return fmt.Errorf("agent at %s: %w", socket, err)
		}
		enc := json.NewEncoder(g.out)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}

	w := tabwriter.NewWriter(g.out, 0, 0, 2, ' ', 0)
	defer w.Flush()
	switch {
	case err == nil:
		fmt.Fprintf(w, "Agent\t%s (certssh %s)\n", tilde(socket), st.Version)
		if hint := agentHint(socket, cfg.Path()); hint == "" {
			fmt.Fprintf(w, "\tssh uses this agent\n")
		} else {
			_ = w.Flush()
			fmt.Fprintf(g.out, "\n%s\n", hint)
		}
		if st.Upstream != "" {
			fmt.Fprintf(w, "\tupstream agent %s\n", tilde(st.Upstream))
		}
		if st.AddedKeys > 0 {
			fmt.Fprintf(w, "\t%d key(s) added with ssh-add\n", st.AddedKeys)
		}
		if st.Locked {
			fmt.Fprintf(w, "\tlocked (ssh-add -X to unlock)\n")
		}
	case errors.Is(err, sshagent.ErrExtensionUnsupported):
		fmt.Fprintf(w, "Agent\t%s is another agent, not certssh\n", tilde(socket))
	default:
		fmt.Fprintf(w, "Agent\tnot running (certssh agent install)\n")
	}

	byName := map[string]agent.ContextStatus{}
	if st != nil {
		for _, c := range st.Contexts {
			byName[c.Name] = c
		}
	}
	store := g.store()
	now := time.Now()
	for _, name := range cfg.Names() {
		ctx := cfg.Contexts[name]
		fmt.Fprintln(w)
		current := ""
		if name == cfg.Current {
			current = " (current)"
		}
		fmt.Fprintf(w, "Context\t%s%s\t%s %s\n", name, current, ctx.BackendName(), ctx.Address)
		sess, serr := store.Load(name)
		switch {
		case errors.Is(serr, session.ErrNoSession):
			fmt.Fprintf(w, "Session\tnot logged in (certssh login -context %s)\n", name)
		case serr != nil:
			fmt.Fprintf(w, "Session\tunreadable: %v\n", serr)
		case sess.Expired(now):
			fmt.Fprintf(w, "Session\t%s, %s, expired (certssh login -context %s)\n", sess.DisplayName, sess.Persona, name)
		default:
			left := ""
			if !sess.ExpiresAt.IsZero() {
				left = fmt.Sprintf(", expires %s (in %s)", sess.ExpiresAt.Local().Format("15:04"), sess.ExpiresAt.Sub(now).Round(time.Minute))
			}
			fmt.Fprintf(w, "Session\t%s, %s%s\n", sess.DisplayName, sess.Persona, left)
		}
		c, ok := byName[name]
		if !ok {
			continue
		}
		if c.Key != "" {
			fmt.Fprintf(w, "Key\t%s\n", c.Key)
		}
		fmt.Fprintf(w, "Profiles\t%d\n", c.Profiles)
		if len(c.Certificates) > 0 {
			fmt.Fprintf(w, "Certificates\tPRINCIPALS\tSERIAL\tEXPIRES\tLAST USED\n")
			for _, cert := range c.Certificates {
				used := ""
				if !cert.LastUsed.IsZero() {
					used = fmt.Sprintf("%s, %s ago", cert.LastHost, now.Sub(cert.LastUsed).Round(time.Second))
				}
				fmt.Fprintf(w, "\t%s\t%#x\t%s\t%s\n", strings.Join(cert.Principals, ","), cert.Serial,
					cert.ValidBefore.Local().Format("15:04"), used)
			}
		}
		for _, d := range c.Denied {
			fmt.Fprintf(w, "Refused\t%s: %s (retry after %s)\n", d.Principals, d.Reason, d.RetryAfter.Local().Format("15:04"))
		}
	}
	if len(cfg.Contexts) == 0 {
		fmt.Fprintf(w, "\nNo contexts yet: certssh login https://openbao.example.com\n")
	}
	return nil
}

func cmdContexts(g *globals, args []string) error {
	fs := newFlagSet(g, "contexts", "contexts")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	cfg, err := g.load()
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(g.out, 0, 0, 2, ' ', 0)
	defer w.Flush()
	fmt.Fprintln(w, "\tNAME\tBACKEND\tADDRESS\tSESSION")
	store := g.store()
	for _, name := range cfg.Names() {
		ctx := cfg.Contexts[name]
		mark := ""
		if name == cfg.Current {
			mark = "*"
		}
		state := "not logged in"
		if s, err := store.Load(name); err == nil {
			state = s.DisplayName
			if s.Expired(time.Now()) {
				state += " (expired)"
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", mark, name, ctx.BackendName(), ctx.Address, state)
	}
	return nil
}

func cmdUse(g *globals, args []string) error {
	fs := newFlagSet(g, "use", "use <context>")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("use takes one context name")
	}
	cfg, err := g.load()
	if err != nil {
		return err
	}
	if cfg.Contexts[pos[0]] == nil {
		return fmt.Errorf("context %q does not exist", pos[0])
	}
	cfg.Current = pos[0]
	if err := cfg.Save(); err != nil {
		return err
	}
	_ = agent.RequestReload(cfg.SocketPath())
	fmt.Fprintf(g.out, "Using %s\n", pos[0])
	return nil
}
