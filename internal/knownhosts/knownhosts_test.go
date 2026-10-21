package knownhosts

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func key(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestInstallIsIdempotentAndScoped(t *testing.T) {
	file := filepath.Join(t.TempDir(), ".ssh", "known_hosts")
	plain := key(t)
	existing := "github.com " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(plain))) + "\n"
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	ca1, ca2, other := key(t), key(t), key(t)
	if changed, err := Install(file, "other", nil, []ssh.PublicKey{other}); err != nil || !changed {
		t.Fatalf("install other: %v %v", changed, err)
	}
	if changed, err := Install(file, "prod", []string{"*.example.com", "10.1.*"}, []ssh.PublicKey{ca1}); err != nil || !changed {
		t.Fatalf("first install: %v %v", changed, err)
	}
	if changed, err := Install(file, "prod", []string{"*.example.com", "10.1.*"}, []ssh.PublicKey{ca1}); err != nil || changed {
		t.Fatalf("second install should be a no-op: %v %v", changed, err)
	}
	if changed, err := Install(file, "prod", []string{"*.example.com"}, []ssh.PublicKey{ca2}); err != nil || !changed {
		t.Fatalf("rotation: %v %v", changed, err)
	}

	if got := CAKeys(file, "prod"); len(got) != 1 || string(got[0].Marshal()) != string(ca2.Marshal()) {
		t.Fatalf("prod keys after rotation: %v", got)
	}
	if got := CAKeys(file, "other"); len(got) != 1 {
		t.Fatalf("other context lost its line: %v", got)
	}
	data, _ := os.ReadFile(file)
	if !strings.HasPrefix(string(data), existing) {
		t.Fatalf("user entries changed:\n%s", data)
	}
	if fi, _ := os.Stat(file); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode changed to %v", fi.Mode().Perm())
	}

	if changed, err := Remove(file, "prod"); err != nil || !changed {
		t.Fatalf("remove: %v %v", changed, err)
	}
	if len(CAKeys(file, "prod")) != 0 || len(CAKeys(file, "other")) != 1 {
		t.Fatal("remove touched the wrong lines")
	}
}

func TestInstallRejectsBadPatterns(t *testing.T) {
	file := filepath.Join(t.TempDir(), "known_hosts")
	if _, err := Install(file, "x", []string{"a b"}, []ssh.PublicKey{key(t)}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestHostsFor(t *testing.T) {
	file := filepath.Join(t.TempDir(), "known_hosts")
	k, other := key(t), key(t)
	line := func(hosts string, k ssh.PublicKey) string {
		return hosts + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + "\n"
	}
	content := line("kvm1,10.0.0.1,[kvm1.example.com]:2222", k) +
		"garbage line\n" +
		line("|1|abc=|def=", k) +
		line("*.wild,!neg", k) +
		line("kvm2", other) +
		"@cert-authority * " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + "\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got := HostsFor(file, k)
	want := []string{"kvm1", "10.0.0.1", "kvm1.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if HostsFor(filepath.Join(t.TempDir(), "missing"), k) != nil {
		t.Fatal("missing file should yield nothing")
	}
}
