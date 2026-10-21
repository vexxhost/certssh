package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/vexxhost/certssh/internal/session"
)

// Control extensions spoken between the certssh CLI and its agent.
const (
	ExtensionStatus = "certssh-status@vexxhost.com"
	ExtensionReload = "certssh-reload@vexxhost.com"
)

// agentSuccess is SSH_AGENT_SUCCESS; extension replies start with it.
const agentSuccess = 6

// Status describes the running agent.
type Status struct {
	Version   string          `json:"version"`
	Upstream  string          `json:"upstream,omitempty"`
	Locked    bool            `json:"locked"`
	AddedKeys int             `json:"added_keys"`
	Signs     int64           `json:"signs"`
	Contexts  []ContextStatus `json:"contexts"`
}

// ContextStatus describes one context.
type ContextStatus struct {
	Name         string         `json:"name"`
	Backend      string         `json:"backend"`
	Address      string         `json:"address,omitempty"`
	Session      *SessionStatus `json:"session,omitempty"`
	Key          string         `json:"key,omitempty"`
	Profiles     int            `json:"profiles"`
	Certificates []CertStatus   `json:"certificates,omitempty"`
	Denied       []DeniedStatus `json:"denied,omitempty"`
}

// SessionStatus describes a context's session.
type SessionStatus struct {
	DisplayName string    `json:"display_name"`
	Persona     string    `json:"persona"`
	ExpiresAt   time.Time `json:"expires_at,omitzero"`
	Expired     bool      `json:"expired"`
}

// CertStatus describes a held certificate.
type CertStatus struct {
	Principals  []string  `json:"principals"`
	Serial      uint64    `json:"serial"`
	KeyID       string    `json:"key_id"`
	ValidBefore time.Time `json:"valid_before"`
	Signed      time.Time `json:"signed"`
	LastUsed    time.Time `json:"last_used,omitzero"`
	LastHost    string    `json:"last_host,omitempty"`
}

// DeniedStatus is a principal set the CA refused recently.
type DeniedStatus struct {
	Principals string    `json:"principals"`
	Reason     string    `json:"reason"`
	RetryAfter time.Time `json:"retry_after"`
}

func (a *Agent) control(name string) ([]byte, error) {
	switch name {
	case ExtensionReload:
		if err := a.Reload(); err != nil {
			return nil, err
		}
		return nil, nil
	case ExtensionStatus:
		data, err := json.Marshal(a.Status())
		if err != nil {
			return nil, err
		}
		return append([]byte{agentSuccess}, data...), nil
	}
	return nil, agent.ErrExtensionUnsupported
}

// Status reports the agent's state.
func (a *Agent) Status() Status {
	_, contexts, upstream := a.snapshot()
	added, _ := a.keyring.List()
	a.lockMu.Lock()
	locked := a.locked
	a.lockMu.Unlock()
	st := Status{Version: Version, Upstream: upstream, Locked: locked, AddedKeys: len(added), Signs: a.Signs()}
	now := a.now()
	for _, cs := range contexts {
		cst := ContextStatus{Name: cs.name, Backend: cs.cfg.BackendName(), Address: cs.cfg.Address, Profiles: len(cs.profiles)}
		cs.mu.Lock()
		sess, err := cs.loadSessionLocked()
		if err == nil {
			cst.Session = &SessionStatus{DisplayName: sess.DisplayName, Persona: sess.Persona, ExpiresAt: sess.ExpiresAt, Expired: sess.Expired(now)}
		} else if !errors.Is(err, session.ErrNoSession) {
			cst.Session = &SessionStatus{DisplayName: "unreadable: " + err.Error(), Expired: true}
		}
		if cs.key != nil {
			cst.Key = ssh.FingerprintSHA256(cs.key.PublicKey())
		}
		for _, e := range cs.certs {
			if !e.validAt(now) {
				continue
			}
			cst.Certificates = append(cst.Certificates, CertStatus{
				Principals: e.principals, Serial: e.cert.Serial, KeyID: e.cert.KeyId,
				ValidBefore: certTime(e.cert.ValidBefore), Signed: e.signed,
				LastUsed: e.lastUsed, LastHost: e.lastHost,
			})
		}
		for k, d := range cs.denied {
			if now.Before(d.until) {
				cst.Denied = append(cst.Denied, DeniedStatus{Principals: k, Reason: d.reason, RetryAfter: d.until})
			}
		}
		cs.mu.Unlock()
		st.Contexts = append(st.Contexts, cst)
	}
	return st
}

func dial(socket string) (agent.ExtendedAgent, net.Conn, error) {
	c, err := dialUnix(socket, 2*time.Second)
	if err != nil {
		return nil, nil, err
	}
	return agent.NewClient(c), c, nil
}

// QueryStatus asks the agent at socket for its status. It fails with
// agent.ErrExtensionUnsupported when the socket belongs to another agent.
func QueryStatus(socket string) (*Status, error) {
	ag, c, err := dial(socket)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	res, err := ag.Extension(ExtensionStatus, nil)
	if err != nil {
		return nil, err
	}
	if len(res) == 0 || res[0] != agentSuccess {
		return nil, fmt.Errorf("unexpected status reply")
	}
	var st Status
	if err := json.Unmarshal(res[1:], &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// RequestReload tells the agent at socket to reread its configuration and
// sessions.
func RequestReload(socket string) error {
	ag, c, err := dial(socket)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = ag.Extension(ExtensionReload, nil)
	return err
}
