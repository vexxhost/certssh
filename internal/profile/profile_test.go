package profile

import (
	"reflect"
	"testing"
)

func TestMatchHost(t *testing.T) {
	patterns := []string{"yul2-public-*", "*.public.yul2.example.com", "10.102.2.0/24", "!yul2-public-bastion", "fd00::/64"}
	cases := map[string]bool{
		"yul2-public-kvm1":                  true,
		"YUL2-PUBLIC-KVM1":                  true,
		"kvm1.public.yul2.example.com":      true,
		"kvm1.public.yul2.example.com.":     true,
		"10.102.2.101":                      true,
		"10.102.3.1":                        false,
		"yul2-public-bastion":               false,
		"yul2-infra-ctl1":                   false,
		"fd00::1":                           true,
		"[fd00::1]":                         true,
		"::ffff:10.102.2.5":                 true,
		"yul2-public-[a]":                   true,
		"public.yul2.example.com":           false,
		"kvm1.public.yul2.example.com.evil": false,
	}
	for name, want := range cases {
		if got := MatchHost(name, patterns); got != want {
			t.Errorf("MatchHost(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestMatchHostQuestionMark(t *testing.T) {
	if !MatchHost("kvm1", []string{"kvm?"}) || MatchHost("kvm10", []string{"kvm?"}) {
		t.Fatal("? must match exactly one character")
	}
}

func TestMatchPersona(t *testing.T) {
	profiles := []Profile{
		{Name: "infra", Principal: "env:infra", AgentPrincipal: "agent:infra", Hosts: []string{"*-infra-*"}},
		{Name: "public", Principal: "env:public", Hosts: []string{"*-public-*"}},
	}
	if p, ok := Match(profiles, "human", "yul2-public-kvm1"); !ok || p.Name != "public" {
		t.Fatalf("human public: %v %v", p, ok)
	}
	if _, ok := Match(profiles, "agent", "yul2-public-kvm1"); ok {
		t.Fatal("agents have no principal for public")
	}
	if p, ok := Match(profiles, "agent", "nope", "yul2-infra-ctl1"); !ok || p.PrincipalFor("agent") != "agent:infra" {
		t.Fatalf("agent infra: %v %v", p, ok)
	}
}

func TestValidate(t *testing.T) {
	bad := [][]Profile{
		{{Name: "Bad Name", Principal: "p", Hosts: []string{"x"}}},
		{{Name: "a", Hosts: []string{"x"}}},
		{{Name: "a", Principal: "p"}},
		{{Name: "a", Principal: "p", Hosts: []string{"10.0.0.0/33"}}},
		{{Name: "a", Principal: "p", Hosts: []string{"x"}}, {Name: "a", Principal: "q", Hosts: []string{"y"}}},
	}
	for i, ps := range bad {
		if err := Validate(ps); err == nil {
			t.Errorf("case %d: expected an error", i)
		}
	}
	if err := Validate([]Profile{{Name: "ok", Principal: "p", Hosts: []string{"!x", "10.0.0.0/8", "*.example.com"}}}); err != nil {
		t.Fatal(err)
	}
}

func TestParse(t *testing.T) {
	doc, err := Parse([]byte(`
version: 1
host_ca_patterns: ["*.example.com"]
profiles:
  - name: infra
    principal: env:infra
    hosts: [infra-*]
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Profiles) != 1 || doc.HostCAPatterns[0] != "*.example.com" {
		t.Fatalf("%+v", doc)
	}
	if _, err := Parse([]byte("version: 2\nprofiles: []\n")); err == nil {
		t.Fatal("version 2 must be rejected")
	}
}

func TestKnownHostsPatterns(t *testing.T) {
	got := KnownHostsPatterns([]Profile{
		{Hosts: []string{"*.example.com", "10.102.0.0/16", "10.0.140.0/24", "10.1.2.3/32", "10.40.12.32/27", "!skip", "fd00::/64"}},
		{Hosts: []string{"*.example.com", "192.168.88.0/22"}},
	})
	want := []string{"*.example.com", "10.102.*", "10.0.140.*", "10.1.2.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
