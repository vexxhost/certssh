package service

import (
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	argv := []string{"/Users/a b/bin/certssh", "-config", "/tmp/c&d.yaml", "agent"}

	mac, err := forOS("darwin", argv, "/Users/a/.certssh/agent.sock", "/Users/a/.local/state/certssh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(mac.Path, "Library/LaunchAgents/"+Label+".plist") ||
		!strings.Contains(mac.Content, "<string>/Users/a b/bin/certssh</string>") ||
		!strings.Contains(mac.Content, "c&amp;d.yaml") || mac.RecordUpstream("x") {
		t.Fatalf("plist:\n%s", mac.Content)
	}

	linux, err := forOS("linux", argv, "/home/a/.certssh/agent.sock", "/home/a/.local/state/certssh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(linux.Content, `ExecStart="/Users/a b/bin/certssh" -config /tmp/c&d.yaml agent`) {
		t.Fatalf("unit:\n%s", linux.Content)
	}
	if linux.EnvContent != "SSH_AUTH_SOCK=/home/a/.certssh/agent.sock\n" || !linux.RecordUpstream("x") {
		t.Fatalf("env: %q", linux.EnvContent)
	}

	var ran []string
	linux.run = func(name string, args ...string) error {
		ran = append(ran, name+" "+strings.Join(args, " "))
		return nil
	}
	if err := linux.Install(); err != nil {
		t.Fatal(err)
	}
	if len(ran) != 3 || !strings.HasSuffix(ran[2], "restart "+UnitName) {
		t.Fatalf("commands: %v", ran)
	}
	if err := linux.Uninstall(); err != nil {
		t.Fatal(err)
	}

	if _, err := forOS("windows", argv, "", ""); err == nil {
		t.Fatal("windows should be refused")
	}
}
