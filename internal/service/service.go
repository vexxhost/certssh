// Package service installs the agent as a per-user service: a launchd agent
// on macOS and a systemd user unit on Linux.
package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Label names the service in launchd and systemd.
const (
	Label    = "com.github.vexxhost.certssh"
	UnitName = "certssh-agent.service"
)

// Service is a rendered service definition.
type Service struct {
	OS      string
	Path    string
	Content string
	// EnvFile is the systemd environment.d file setting SSH_AUTH_SOCK.
	EnvFile    string
	EnvContent string
	// LogFile receives the agent's log under launchd.
	LogFile string
	run     func(name string, args ...string) error
}

// Executable returns the path to run the agent from, preferring the name on
// PATH (a package manager's stable symlink) when it is the same binary.
func Executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if p, err := exec.LookPath("certssh"); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			a, errA := os.Stat(abs)
			b, errB := os.Stat(exe)
			if errA == nil && errB == nil && os.SameFile(a, b) {
				return abs, nil
			}
		}
	}
	return exe, nil
}

// For renders the service for this operating system.
func For(argv []string, socket, stateDir string) (*Service, error) {
	return forOS(runtime.GOOS, argv, socket, stateDir)
}

func forOS(goos string, argv []string, socket, stateDir string) (*Service, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	s := &Service{OS: goos, run: runCommand}
	switch goos {
	case "darwin":
		s.Path = filepath.Join(home, "Library", "LaunchAgents", Label+".plist")
		s.LogFile = filepath.Join(stateDir, "agent.log")
		s.Content = plist(argv, s.LogFile)
	case "linux":
		cfgHome := os.Getenv("XDG_CONFIG_HOME")
		if cfgHome == "" {
			cfgHome = filepath.Join(home, ".config")
		}
		s.Path = filepath.Join(cfgHome, "systemd", "user", UnitName)
		s.Content = unit(argv)
		s.EnvFile = filepath.Join(cfgHome, "environment.d", "50-certssh.conf")
		s.EnvContent = "SSH_AUTH_SOCK=" + socket + "\n"
	default:
		return nil, fmt.Errorf("installing a service is not supported on %s; run certssh agent from your session instead", goos)
	}
	return s, nil
}

func plist(argv []string, logFile string) string {
	var args bytes.Buffer
	for _, a := range argv {
		args.WriteString("\t\t<string>")
		_ = xml.EscapeText(&args, []byte(a))
		args.WriteString("</string>\n")
	}
	var lf bytes.Buffer
	_ = xml.EscapeText(&lf, []byte(logFile))
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + Label + `</string>
	<key>ProgramArguments</key>
	<array>
` + args.String() + `	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>StandardErrorPath</key>
	<string>` + lf.String() + `</string>
</dict>
</plist>
`
}

func unit(argv []string) string {
	quoted := make([]string, len(argv))
	for i, a := range argv {
		if strings.ContainsAny(a, " \t\"'\\$%") {
			a = strconv.Quote(strings.ReplaceAll(a, "%", "%%"))
		}
		quoted[i] = a
	}
	return `[Unit]
Description=certssh SSH agent
Documentation=https://github.com/vexxhost/certssh

[Service]
ExecStart=` + strings.Join(quoted, " ") + `
Restart=on-failure

[Install]
WantedBy=default.target
`
}

// RecordUpstream reports whether the current SSH_AUTH_SOCK should be saved
// as the upstream agent. On macOS launchd hands the agent the system
// agent's socket, whose path changes on every boot, so nothing is saved.
func (s *Service) RecordUpstream(string) bool { return s.OS == "linux" }

// EnvHint explains how non-shell programs get SSH_AUTH_SOCK.
func (s *Service) EnvHint() string {
	if s.OS == "linux" {
		return "Programs started by systemd --user pick it up from " + s.EnvFile + " after your next login."
	}
	return ""
}

// Install writes the definition and starts the service.
func (s *Service) Install() error {
	if err := writeFile(s.Path, s.Content); err != nil {
		return err
	}
	switch s.OS {
	case "darwin":
		if err := os.MkdirAll(filepath.Dir(s.LogFile), 0o700); err != nil {
			return err
		}
		domain := "gui/" + strconv.Itoa(os.Getuid())
		_ = s.run("launchctl", "bootout", domain, s.Path)
		return s.run("launchctl", "bootstrap", domain, s.Path)
	case "linux":
		if err := writeFile(s.EnvFile, s.EnvContent); err != nil {
			return err
		}
		if err := s.run("systemctl", "--user", "daemon-reload"); err != nil {
			return err
		}
		if err := s.run("systemctl", "--user", "enable", UnitName); err != nil {
			return err
		}
		return s.run("systemctl", "--user", "restart", UnitName)
	}
	return nil
}

// Uninstall stops the service and removes its files.
func (s *Service) Uninstall() error {
	switch s.OS {
	case "darwin":
		_ = s.run("launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid()), s.Path)
	case "linux":
		_ = s.run("systemctl", "--user", "disable", "--now", UnitName)
	}
	var errs []error
	for _, p := range []string{s.Path, s.EnvFile} {
		if p == "" {
			continue
		}
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if s.OS == "linux" {
		_ = s.run("systemctl", "--user", "daemon-reload")
	}
	return errors.Join(errs...)
}

func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o600)
}

func runCommand(name string, args ...string) error {
	out, err := exec.CommandContext(context.Background(), name, args...).CombinedOutput() //nolint:gosec // fixed launchctl/systemctl invocations
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}
