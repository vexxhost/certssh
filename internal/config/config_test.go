package config

import (
	"path/filepath"
	"testing"

	"github.com/vexxhost/certssh/internal/profile"
)

func TestLoginDefaults(t *testing.T) {
	c := &Context{Address: "https://bao.example.com"}
	if l := c.LoginFor(PersonaHuman); l.Method != "oidc" || l.Mount != "oidc" || l.Callback != "client" || l.ListenAddress != "localhost:8250" {
		t.Fatalf("human: %+v", l)
	}
	if l := c.LoginFor(PersonaAgent); l.Callback != "direct" {
		t.Fatalf("agent: %+v", l)
	}
	c.Login = map[string]Login{PersonaHuman: {Method: "token"}}
	if l := c.LoginFor(PersonaHuman); l.Mount != "token" {
		t.Fatalf("token: %+v", l)
	}
	if c.UserCA() != "ssh-client-signer" || c.HostCA() != "ssh-host-signer" || c.RoleFor(PersonaAgent) != "agent" {
		t.Fatal("unexpected defaults")
	}
}

func TestValidate(t *testing.T) {
	bad := []*Context{
		{},
		{Address: "openbao.example.com"},
		{Backend: "local"},
		{Backend: "nope", Address: "https://x"},
		{Address: "https://x", Principals: "some"},
		{Address: "https://x", TTL: "soon"},
		{Address: "https://x", Login: map[string]Login{"human": {Method: "ldap"}}},
		{Address: "https://x", Login: map[string]Login{"human": {Callback: "magic"}}},
		{Address: "https://x", Profiles: Profiles{Source: "kv"}},
		{Address: "https://x", Profiles: Profiles{Source: "file"}},
		{Address: "https://x", Profiles: Profiles{Inline: []profile.Profile{{Name: "x"}}}},
	}
	for i, c := range bad {
		cfg := &Config{Contexts: map[string]*Context{"c": c}}
		if err := cfg.Validate(); err == nil {
			t.Errorf("case %d: expected an error", i)
		}
	}
	if err := (&Config{Current: "missing"}).Validate(); err == nil {
		t.Error("a missing current context must be rejected")
	}
	if err := (&Config{Agent: Agent{Key: "tpm"}}).Validate(); err == nil {
		t.Error("unsupported key backends must be rejected")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "config.yaml")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	c.Contexts = map[string]*Context{
		"b": {Address: "https://b.example.com"},
		"a": {Address: "https://a.example.com", Login: map[string]Login{"human": {Mount: "entra"}}},
	}
	c.Current = "b"
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Contexts["a"].LoginFor("human").Mount != "entra" {
		t.Fatal("login settings lost")
	}
	if names := got.Names(); len(names) != 2 || names[0] != "b" {
		t.Fatalf("current context must come first: %v", names)
	}
	if name, _, err := got.Resolve(""); err != nil || name != "b" {
		t.Fatalf("resolve: %v %v", name, err)
	}
}
