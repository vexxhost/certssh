// Package knownhosts manages certssh's @cert-authority lines in an OpenSSH
// known_hosts file and looks host keys up by fingerprint.
package knownhosts

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Comment tags the lines certssh owns for a context.
func Comment(context string) string { return "certssh:" + context }

// Install replaces the context's @cert-authority lines with one per key. It
// reports whether the file changed.
func Install(file, context string, patterns []string, keys []ssh.PublicKey) (bool, error) {
	if len(patterns) == 0 {
		patterns = []string{"*"}
	}
	for _, p := range patterns {
		if p == "" || strings.ContainsAny(p, " \t,") {
			return false, fmt.Errorf("invalid known_hosts pattern %q", p)
		}
	}
	old, err := os.ReadFile(file)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	kept := strip(old, context)
	var buf bytes.Buffer
	buf.Write(kept)
	if len(kept) > 0 && !bytes.HasSuffix(kept, []byte("\n")) {
		buf.WriteByte('\n')
	}
	for _, k := range keys {
		fmt.Fprintf(&buf, "@cert-authority %s %s %s\n", strings.Join(patterns, ","),
			strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))), Comment(context))
	}
	if bytes.Equal(buf.Bytes(), old) {
		return false, nil
	}
	return true, write(file, buf.Bytes())
}

// Remove deletes the context's lines.
func Remove(file, context string) (bool, error) {
	old, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	kept := strip(old, context)
	if bytes.Equal(kept, old) {
		return false, nil
	}
	return true, write(file, kept)
}

func strip(data []byte, context string) []byte {
	var out bytes.Buffer
	tag := Comment(context)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == "@cert-authority" && f[len(f)-1] == tag {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

func write(file string, data []byte) error {
	dir := filepath.Dir(file)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(file); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp, err := os.CreateTemp(dir, ".known_hosts-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), file)
}

// CAKeys returns the keys on the context's @cert-authority lines.
func CAKeys(file, context string) []ssh.PublicKey {
	var keys []ssh.PublicKey
	each(file, func(marker string, _ []string, key ssh.PublicKey, comment string) {
		if marker == "cert-authority" && comment == Comment(context) {
			keys = append(keys, key)
		}
	})
	return keys
}

// HostsFor returns the plain host names a key is recorded under. Hashed
// entries, wildcard patterns and negations are skipped.
func HostsFor(file string, key ssh.PublicKey) []string {
	want := key.Marshal()
	seen := map[string]bool{}
	var names []string
	each(file, func(marker string, hosts []string, k ssh.PublicKey, _ string) {
		if marker != "" || !bytes.Equal(k.Marshal(), want) {
			return
		}
		for _, h := range hosts {
			if strings.HasPrefix(h, "|") || strings.HasPrefix(h, "!") || strings.ContainsAny(h, "*?") {
				continue
			}
			if strings.HasPrefix(h, "[") {
				if host, _, err := net.SplitHostPort(h); err == nil {
					h = host
				}
			}
			if !seen[h] {
				seen[h] = true
				names = append(names, h)
			}
		}
	})
	return names
}

func each(file string, fn func(marker string, hosts []string, key ssh.PublicKey, comment string)) {
	data, err := os.ReadFile(file)
	if err != nil {
		return
	}
	for len(data) > 0 {
		marker, hosts, key, comment, rest, err := ssh.ParseKnownHosts(data)
		if err != nil {
			// Skip the offending line and carry on, like ssh does.
			i := bytes.IndexByte(data, '\n')
			if i < 0 {
				return
			}
			data = data[i+1:]
			continue
		}
		fn(marker, hosts, key, comment)
		data = rest
	}
}
