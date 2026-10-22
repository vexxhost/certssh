package main

import "testing"

func TestParseIdentityAgent(t *testing.T) {
	cases := []struct {
		out        string
		path       string
		fromConfig bool
	}{
		{"user root\nidentityagent /home/a/.1password/agent.sock\n", "/home/a/.1password/agent.sock", true},
		{"identityagent SSH_AUTH_SOCK\n", "/run/env.sock", false},
		{"identityagent none\n", "", true},
		{"user root\nport 22\n", "/run/env.sock", false},
	}
	for _, c := range cases {
		path, fromConfig := parseIdentityAgent([]byte(c.out), "/run/env.sock")
		if path != c.path || fromConfig != c.fromConfig {
			t.Errorf("%q: got %q %v, want %q %v", c.out, path, fromConfig, c.path, c.fromConfig)
		}
	}
}
