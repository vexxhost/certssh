package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/vexxhost/certssh/internal/agent"
	"github.com/vexxhost/certssh/internal/config"
	"github.com/vexxhost/certssh/internal/service"
)

func cmdAgent(g *globals, args []string) error {
	fs := newFlagSet(g, "agent", "agent [-socket path] [-upstream path|none]")
	socket := fs.String("socket", "", "socket to listen on (default: agent.socket in the config, or ~/.certssh/agent.sock)")
	upstream := fs.String("upstream", "", "upstream agent socket, or none (default: agent.upstream, or SSH_AUTH_SOCK)")
	level := fs.String("log-level", "info", "log level: debug, info, warn or error")
	format := fs.String("log-format", "text", "log format: text or json")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*level)); err != nil {
		return fmt.Errorf("-log-level: %w", err)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var logger *slog.Logger
	switch *format {
	case "text":
		logger = slog.New(slog.NewTextHandler(g.errOut, opts))
	case "json":
		logger = slog.New(slog.NewJSONHandler(g.errOut, opts))
	default:
		return errors.New("-log-format must be text or json")
	}

	cfg, err := g.load()
	if err != nil {
		return err
	}
	path := *socket
	if path == "" {
		path = cfg.SocketPath()
	}
	a, err := agent.New(agent.Options{
		ConfigPath: cfg.Path(),
		Socket:     path,
		Upstream:   *upstream,
		Sessions:   g.store(),
		Logger:     logger,
	})
	if err != nil {
		return err
	}
	l, err := agent.Listen(path)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	st := a.Status()
	logger.Info("agent listening", "socket", path, "version", version, "contexts", len(st.Contexts), "upstream", st.Upstream)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for s := range sigs {
			if s == syscall.SIGHUP {
				if err := a.Reload(); err != nil {
					logger.Error("reload failed", "error", err)
				} else {
					logger.Info("configuration reloaded")
				}
				continue
			}
			logger.Info("shutting down", "signal", s.String())
			_ = l.Close()
			return
		}
	}()
	return a.Serve(l)
}

func cmdAgentInstall(g *globals, args []string) error {
	fs := newFlagSet(g, "agent install", "agent install [-print]")
	printOnly := fs.Bool("print", false, "print the service definition instead of installing it")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	cfg, err := g.load()
	if err != nil {
		return err
	}
	socket := cfg.SocketPath()
	exe, err := service.Executable()
	if err != nil {
		return err
	}
	argv := []string{exe}
	if g.configPath != "" {
		argv = append(argv, "-config", g.configPath)
	}
	argv = append(argv, "agent")
	svc, err := service.For(argv, socket, config.StateDir())
	if err != nil {
		return err
	}
	if *printOnly {
		fmt.Fprintf(g.out, "# %s\n%s", svc.Path, svc.Content)
		return nil
	}

	// Remember an existing agent so its keys stay available through ours.
	if cur := os.Getenv("SSH_AUTH_SOCK"); cfg.Agent.Upstream == "" && cur != "" && !sameSocket(cur, socket) && svc.RecordUpstream(cur) {
		cfg.Agent.Upstream = cur
		if err := cfg.Save(); err != nil {
			return err
		}
		fmt.Fprintf(g.out, "Keys from %s stay available through certssh (agent.upstream)\n", tilde(cur))
	}
	if err := svc.Install(); err != nil {
		return err
	}
	fmt.Fprintf(g.out, "Installed %s\n", tilde(svc.Path))
	if !sameSocket(os.Getenv("SSH_AUTH_SOCK"), socket) {
		fmt.Fprintf(g.out, "\nAdd this to your shell profile so ssh uses the agent:\n\n    export SSH_AUTH_SOCK=%s\n", tilde(socket))
		if hint := svc.EnvHint(); hint != "" {
			fmt.Fprintln(g.out, strings.TrimRight("\n"+hint, "\n"))
		}
	}
	return nil
}

func cmdAgentUninstall(g *globals, args []string) error {
	fs := newFlagSet(g, "agent uninstall", "agent uninstall")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	cfg, err := g.load()
	if err != nil {
		return err
	}
	svc, err := service.For(nil, cfg.SocketPath(), config.StateDir())
	if err != nil {
		return err
	}
	if err := svc.Uninstall(); err != nil {
		return err
	}
	fmt.Fprintf(g.out, "Removed %s\n", tilde(svc.Path))
	return nil
}
