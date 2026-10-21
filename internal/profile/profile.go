// Package profile maps host names to the SSH certificate principals needed to
// log in to them.
package profile

import (
	"fmt"
	"net/netip"
	"os"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Profile is one principal and the hosts that accept it.
type Profile struct {
	Name           string   `yaml:"name" json:"name"`
	Principal      string   `yaml:"principal" json:"principal"`
	AgentPrincipal string   `yaml:"agent_principal,omitempty" json:"agent_principal,omitempty"`
	Hosts          []string `yaml:"hosts" json:"hosts"`
}

// Document is a site profile as published by the CA operator.
type Document struct {
	Version        int       `yaml:"version"`
	HostCAPatterns []string  `yaml:"host_ca_patterns,omitempty"`
	Profiles       []Profile `yaml:"profiles"`
}

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// Validate checks that every profile has a usable name, principal and hosts.
func Validate(profiles []Profile) error {
	seen := map[string]bool{}
	for i, p := range profiles {
		if !namePattern.MatchString(p.Name) {
			return fmt.Errorf("profile %d: name %q must match %s", i, p.Name, namePattern)
		}
		if seen[p.Name] {
			return fmt.Errorf("profile %q is defined twice", p.Name)
		}
		seen[p.Name] = true
		if p.Principal == "" && p.AgentPrincipal == "" {
			return fmt.Errorf("profile %q has no principal", p.Name)
		}
		if len(p.Hosts) == 0 {
			return fmt.Errorf("profile %q has no hosts", p.Name)
		}
		for _, h := range p.Hosts {
			if err := validPattern(h); err != nil {
				return fmt.Errorf("profile %q: %w", p.Name, err)
			}
		}
	}
	return nil
}

func validPattern(h string) error {
	h = strings.TrimPrefix(h, "!")
	if h == "" {
		return fmt.Errorf("empty host pattern")
	}
	if strings.Contains(h, "/") {
		if _, err := netip.ParsePrefix(h); err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", h, err)
		}
		return nil
	}
	if _, err := path.Match(globToPath(h), ""); err != nil {
		return fmt.Errorf("invalid host pattern %q: %w", h, err)
	}
	return nil
}

// Load reads a site profile document from a YAML file.
func Load(file string) (*Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse decodes and validates a site profile document.
func Parse(data []byte) (*Document, error) {
	var doc Document
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Version != 0 && doc.Version != 1 {
		return nil, fmt.Errorf("unsupported profile version %d", doc.Version)
	}
	if err := Validate(doc.Profiles); err != nil {
		return nil, err
	}
	return &doc, nil
}

// PrincipalFor returns the principal this profile grants to a persona, or ""
// when the persona has no principal here.
func (p Profile) PrincipalFor(persona string) string {
	if persona == "agent" {
		return p.AgentPrincipal
	}
	return p.Principal
}

// Matches reports whether any of the names matches the profile's hosts.
func (p Profile) Matches(names ...string) bool {
	for _, n := range names {
		if MatchHost(n, p.Hosts) {
			return true
		}
	}
	return false
}

// Match returns the first profile whose hosts match any of the names and that
// grants the persona a principal.
func Match(profiles []Profile, persona string, names ...string) (Profile, bool) {
	for _, p := range profiles {
		if p.PrincipalFor(persona) != "" && p.Matches(names...) {
			return p, true
		}
	}
	return Profile{}, false
}

// MatchHost reports whether name matches the pattern list using ssh_config
// semantics: shell globs with * and ?, a leading ! negates and wins, and
// entries containing / are CIDRs matched against IP addresses.
func MatchHost(name string, patterns []string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	addr, addrErr := netip.ParseAddr(strings.Trim(name, "[]"))
	matched := false
	for _, pat := range patterns {
		neg := strings.HasPrefix(pat, "!")
		pat = strings.ToLower(strings.TrimPrefix(pat, "!"))
		var ok bool
		if strings.Contains(pat, "/") {
			if addrErr == nil {
				if prefix, err := netip.ParsePrefix(pat); err == nil {
					ok = prefix.Contains(addr.Unmap())
				}
			}
		} else {
			ok, _ = path.Match(globToPath(pat), name)
		}
		if ok && neg {
			return false
		}
		matched = matched || ok
	}
	return matched
}

// globToPath escapes the characters path.Match treats specially but
// ssh_config does not, so only * and ? are wildcards.
func globToPath(p string) string {
	r := strings.NewReplacer(`\`, `\\`, `[`, `\[`, `]`, `\]`)
	return r.Replace(p)
}

// KnownHostsPatterns turns profile hosts into patterns usable on a
// known_hosts @cert-authority line. CIDRs on octet boundaries become globs
// (10.102.0.0/16 becomes 10.102.*); other CIDRs and negations are dropped.
func KnownHostsPatterns(profiles []Profile) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, p := range profiles {
		for _, h := range p.Hosts {
			if strings.HasPrefix(h, "!") {
				continue
			}
			if !strings.Contains(h, "/") {
				add(h)
				continue
			}
			prefix, err := netip.ParsePrefix(h)
			if err != nil || !prefix.Addr().Is4() || prefix.Bits()%8 != 0 {
				continue
			}
			octets := strings.Split(prefix.Masked().Addr().String(), ".")
			n := prefix.Bits() / 8
			if n == 4 {
				add(prefix.Addr().String())
			} else if n > 0 {
				add(strings.Join(octets[:n], ".") + ".*")
			}
		}
	}
	return out
}
