# certssh

[![CI](https://github.com/vexxhost/certssh/actions/workflows/ci.yml/badge.svg)](https://github.com/vexxhost/certssh/actions/workflows/ci.yml)

An SSH agent for SSH certificate authorities in [OpenBao](https://openbao.org)
or HashiCorp Vault. Log in once, and plain `ssh`, `scp`, `rsync`, `git` and
`ansible-playbook` get the right short-lived certificate for every host. No
wrapper commands, no flags, no `~/.ssh/config` changes.

```console
$ certssh login https://openbao.example.com
Logged in to openbao.example.com as oidc-alice@example.com (human, expires Oct 21 17:04)
Trusting host CA SHA256:ShjL... in ~/.ssh/known_hosts

$ ssh web-1.prod.example.com          # the agent signs a prod certificate on first use
$ ssh db-3.staging.example.com        # and a staging one here
$ ansible-playbook -i inventory site.yml   # reuses both
```

## How it works

OpenBao and Vault sign SSH certificates well, and OpenSSH accepts them well,
but the step in between is left to you: sign a key, save the certificate, pick
the right one for each host, renew it. It gets worse when policy allows one
principal per certificate, which is a common way to scope access by
environment: someone who reaches twenty environments needs twenty
certificates, and offering them all trips sshd's `MaxAuthTries`.

Since OpenSSH 8.9, `ssh` tells the agent which server it is connected to
(the `session-bind@openssh.com` extension) before it asks for keys. When the
server presents a host certificate, that includes the host's names. certssh
uses this to:

1. check that the host certificate was signed by your CA's host CA, so only
   what your CA vouches for counts;
2. read the principals the host accepts from its certificate, or else match
   the host's names against your profiles (`*.prod.example.com` →
   `env:prod`);
3. sign a certificate for that principal if it does not hold a valid one
   (one request, however many connections are waiting);
4. offer only that certificate, followed by your other keys.

Hosts without a host certificate are recognised by the names recorded for
their key in `~/.ssh/known_hosts`.

## Which principal a host needs

The simplest setup needs no client configuration at all: put the principals
a host accepts in its host certificate, in the
`certssh-principals@vexxhost.com` extension, in order of preference:

```sh
bao write ssh-host-signer/sign/host - <<EOF
{"public_key": "$(cat /etc/ssh/ssh_host_ed25519_key.pub)", "cert_type": "host",
 "valid_principals": "web-1.prod.example.com",
 "extensions": {"certssh-principals@vexxhost.com": "env:prod,agent:prod"}}
EOF
```

The host role must allow the extension (`allowed_extensions`). OpenSSH
ignores extensions it does not know, so these certificates work with any
client. Whatever signs your host keys (Ansible, cloud-init, a bootstrap
script) already knows each host's environment, so the list stays current
without anything to distribute. certssh tries the listed principals in order
and remembers which ones the CA refused; `principal_patterns` skips the ones
a persona can never get.

For hosts whose certificates do not carry the list, or that have no host
certificate, a profile file maps host names to principals (see
[Configuration](#configuration)). When a certificate carries a list, it wins.

The private key is generated in memory at login and never written to disk;
certificates live as long as the CA allows. Logging in again replaces the
key, and `certssh logout` revokes the token and drops everything.

## Your own keys keep working

certssh is a complete agent. `ssh-add` stores keys in it, `ssh-add -l` lists
them next to the certificates, and `ssh` still reads the key files in
`~/.ssh`. Keys held by another agent (the OS agent, 1Password, Secretive, a
YubiKey agent) stay available through certssh's socket: it passes requests
for them upstream.

On a host it recognises, certssh offers the certificate first and your other
keys after it; set `agent.offer_upstream_on_match: false` to offer
certificates only. Hosts it does not recognise see your own keys first.

## Install

Download a release from
[GitHub](https://github.com/vexxhost/certssh/releases), or:

```sh
go install github.com/vexxhost/certssh/cmd/certssh@latest
```

Run the agent as a user service (launchd on macOS, systemd on Linux) and
point `SSH_AUTH_SOCK` at it:

```sh
certssh agent install
echo 'export SSH_AUTH_SOCK=~/.certssh/agent.sock' >> ~/.zshrc   # or ~/.bashrc
```

`certssh agent install` remembers the agent `SSH_AUTH_SOCK` pointed at before
(on Linux) so its keys stay available. On macOS the system agent is found
automatically.

## Logging in

```sh
certssh login https://openbao.example.com                 # OIDC in the browser
certssh login -mount entra https://openbao.example.com    # an OIDC mount not called "oidc"
certssh login -method token https://openbao.example.com   # BAO_TOKEN, VAULT_TOKEN or ~/.vault-token
certssh login -as agent                                   # an unattended agent, approved in a browser
```

The first login creates a *context* named after the server and saves the
flags you gave, so later logins need no arguments. `-context` names it
yourself; `certssh use` switches between several.

For people, the OIDC login uses a callback on `http://localhost:8250`, the
same one `bao login` uses. For automated agents (`-as agent`), certssh uses
OpenBao's `direct` or `device` callback modes: it prints a link for a person
to approve and waits up to ten minutes.

`certssh status` shows the agent, sessions, certificates and principals the
CA refused. `certssh which <host>` shows which profile a host name maps to.

## Configuration

`~/.config/certssh/config.yaml`; everything has a default.

```yaml
current: openbao.example.com
contexts:
  openbao.example.com:
    backend: openbao               # openbao, vault or local
    address: https://openbao.example.com
    login:
      human: {method: oidc, mount: entra}
      agent: {method: oidc, mount: agents, callback: direct}
    ca:
      user: ssh-client-signer      # SSH secrets engine signing user certificates
      host: ssh-host-signer        # and the one signing host certificates ("-" for none)
    roles:                         # signing role per persona (default: the persona's name)
      human: human
      agent: agent
    principals: one                # one certificate per principal, or "many" in one certificate
    principal_patterns:            # which listed principals each persona requests
      human: ["env:*"]
      agent: ["agent:*"]
    host_ca_patterns: ["*.example.com", "10.*"]   # where the host CA is trusted (default: profile hosts, or *)
    profiles:
      source: file                 # or inline (the default)
      path: ~/.config/certssh/example.yaml
agent:
  upstream: /run/user/1000/keyring/ssh   # another agent to pass through (default: SSH_AUTH_SOCK)
  unknown_host: recent             # what unrecognised hosts are offered: recent, all or none
  allow_forwarded: false           # sign for connections through a forwarded agent
```

A profile file maps host names to principals, for hosts whose certificates
do not list them:

```yaml
version: 1
profiles:
  - name: prod
    principal: env:prod
    agent_principal: agent:prod    # used by sessions logged in with -as agent
    hosts: ["*.prod.example.com", "10.10.0.0/16"]
  - name: staging
    principal: env:staging
    hosts: ["*.staging.example.com", "!bastion.staging.example.com"]
```

Hosts are `ssh_config`-style patterns (`*`, `?`, `!` to exclude) or CIDRs.
With `principals: many` every principal goes in one certificate and profiles
only bound what is requested.

## Ansible

Ansible runs `ssh`, which inherits `SSH_AUTH_SOCK`, so playbooks work with no
plugin or `ansible.cfg` change. With `forks: 100`, the first hundred
connections to an environment cause one signing request.

Because certssh trusts your host CA in `~/.ssh/known_hosts`, hosts with host
certificates no longer need `host_key_checking = False`.

## Setting up the CA

certssh needs an SSH secrets engine for user certificates, a role, and a
login. A host CA is optional but is what lets certssh recognise hosts by
name and removes host key prompts.

```sh
bao secrets enable -path=ssh-client-signer ssh
bao write ssh-client-signer/config/ca generate_signing_key=true key_type=ssh-ed25519
bao write ssh-client-signer/roles/human - <<'EOF'
{"key_type": "ca", "allow_user_certificates": true, "allowed_users": "env:prod,env:staging",
 "default_extensions": {"permit-pty": ""}, "allowed_extensions": "permit-pty",
 "ttl": "8h", "key_id_format": "{{token_display_name}}"}
EOF

bao secrets enable -path=ssh-host-signer ssh
bao write ssh-host-signer/config/ca generate_signing_key=true key_type=ssh-ed25519
bao write ssh-host-signer/roles/host key_type=ca allow_host_certificates=true \
  allowed_domains='*' allow_bare_domains=true allow_subdomains=true ttl=2160h \
  allowed_extensions=certssh-principals@vexxhost.com
```

Scope who may sign which principal with policies, for example:

```hcl
path "ssh-client-signer/sign/human" {
  capabilities        = ["create", "update"]
  required_parameters = ["valid_principals"]
  allowed_parameters  = { "valid_principals" = ["env:staging"], "*" = [] }
}
```

On hosts, trust the user CA, map principals to accounts, and install a host
certificate:

```
TrustedUserCAKeys /etc/ssh/user_ca.pub
AuthorizedPrincipalsFile /etc/ssh/principals/%u
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

To revoke certificates before they expire, see
[ssh-krl](https://github.com/vexxhost/ssh-krl).

## Security

- The private key exists only in the agent's memory.
- Session tokens are stored mode 0600 under `~/.config/certssh/sessions/`.
- A host's names and principal list are only trusted from a host
  certificate signed by the context's host CA (checked against the
  `@cert-authority` line), or from your own `known_hosts`. The `session-bind`
  signature proves the server holds that host key. Either way the CA's policy
  still decides what may be signed.
- Connections through a forwarded agent get no certificates and cannot add,
  remove or lock keys unless `allow_forwarded` is set.
- certssh requests exactly the principal a host needs and never sets
  `key_id` or critical options; what is allowed is up to the CA's policy.
- Every signing is logged by the agent with the host it was for.

## Development

```sh
go test ./...                                       # unit tests, plus OpenSSH tests if ssh is installed
BAO_BIN=$(command -v bao) go test ./...             # plus integration tests against an OpenBao dev server
BAO_BIN=$(command -v bao) ./test/e2e.sh             # OpenBao + real sshd + plain ssh through the agent
```

## License

Apache 2.0
