package agent

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// ExtensionSessionBind is sent by OpenSSH 8.9 and later after key exchange,
// before it asks the agent for keys.
const ExtensionSessionBind = "session-bind@openssh.com"

// maxBinds mirrors OpenSSH's limit on binds recorded per agent connection.
const maxBinds = 16

// Bind is a verified session-bind: the server the client is connected to.
type Bind struct {
	HostKey    ssh.PublicKey
	Forwarding bool
}

// parseBind decodes a session-bind request and checks that the host key
// signed the session ID, so a client cannot claim to be talking to a host it
// is not.
func parseBind(contents []byte) (Bind, error) {
	var msg struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}
	if err := ssh.Unmarshal(contents, &msg); err != nil {
		return Bind{}, fmt.Errorf("session-bind: %w", err)
	}
	key, err := ssh.ParsePublicKey(msg.HostKey)
	if err != nil {
		return Bind{}, fmt.Errorf("session-bind host key: %w", err)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(msg.Signature, &sig); err != nil {
		return Bind{}, fmt.Errorf("session-bind signature: %w", err)
	}
	if len(msg.SessionID) == 0 {
		return Bind{}, errors.New("session-bind: empty session ID")
	}
	if err := key.Verify(msg.SessionID, &sig); err != nil {
		return Bind{}, fmt.Errorf("session-bind signature does not verify: %w", err)
	}
	return Bind{HostKey: key, Forwarding: msg.Forwarding}, nil
}

// MarshalBind builds a session-bind request; it is used by tests and by
// anything that wants to act as an OpenSSH client towards the agent.
func MarshalBind(hostKey ssh.Signer, sessionID []byte, forwarding bool) ([]byte, error) {
	sig, err := hostKey.Sign(randReader, sessionID)
	if err != nil {
		return nil, err
	}
	return ssh.Marshal(struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}{hostKey.PublicKey().Marshal(), sessionID, ssh.Marshal(sig), forwarding}), nil
}
