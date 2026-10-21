package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
)

// openBrowser opens a URL with $BROWSER, open (macOS) or xdg-open.
func openBrowser(url string) error {
	if b := os.Getenv("BROWSER"); b != "" {
		return exec.CommandContext(context.Background(), b, url).Start() //nolint:gosec // the user's own $BROWSER
	}
	switch runtime.GOOS {
	case "darwin":
		return exec.CommandContext(context.Background(), "open", url).Start() //nolint:gosec // URL from the configured CA
	case "linux", "freebsd", "openbsd", "netbsd":
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return errors.New("no display")
		}
		return exec.CommandContext(context.Background(), "xdg-open", url).Start() //nolint:gosec // URL from the configured CA
	}
	return errors.New("no browser opener for " + runtime.GOOS)
}
