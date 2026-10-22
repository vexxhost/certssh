package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// sshAgent returns the agent socket ssh uses according to its configuration,
// and whether an IdentityAgent setting chose it (rather than SSH_AUTH_SOCK).
// An empty path means ssh uses no agent.
func sshAgent() (path string, fromConfig bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Any name works; Host * blocks apply to it.
	out, err := exec.CommandContext(ctx, "ssh", "-G", "certssh.invalid").Output()
	if err != nil {
		return os.Getenv("SSH_AUTH_SOCK"), false
	}
	return parseIdentityAgent(out, os.Getenv("SSH_AUTH_SOCK"))
}

func parseIdentityAgent(out []byte, env string) (string, bool) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok || !strings.EqualFold(key, "identityagent") {
			continue
		}
		switch value = strings.TrimSpace(value); value {
		case "SSH_AUTH_SOCK":
			return env, false
		case "none":
			return "", true
		default:
			return value, true
		}
	}
	return env, false
}

// agentHint explains what to change when ssh would not talk to the agent at
// socket; it returns "" when ssh already does.
func agentHint(socket, configFile string) string {
	path, fromConfig := sshAgent()
	if sameSocket(path, socket) {
		return ""
	}
	if !fromConfig {
		return fmt.Sprintf("ssh is not using the certssh agent. Add this to your shell profile:\n\n    export SSH_AUTH_SOCK=%s\n", tilde(socket))
	}
	if path == "" {
		return fmt.Sprintf("Your ssh config disables the agent (IdentityAgent none). To use certssh, set:\n\n    IdentityAgent %s\n", tilde(socket))
	}
	return fmt.Sprintf("Your ssh config sends agent requests to %[1]s (IdentityAgent), so ssh does not use certssh.\n"+
		"Point ssh at certssh and keep that agent's keys available through it:\n\n"+
		"    IdentityAgent %[2]s          # in ~/.ssh/config\n"+
		"    agent: {upstream: %[1]s}     # in %[3]s, then restart the agent\n",
		tilde(path), tilde(socket), tilde(configFile))
}
