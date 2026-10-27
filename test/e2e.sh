#!/usr/bin/env bash
# End-to-end test: OpenBao signs host and user certificates, two real sshd
# servers trust them, and plain ssh gets the right certificate for each host
# from the certssh agent with nothing but SSH_AUTH_SOCK set.
#
# Requires: bao (or BAO_BIN), sshd, ssh, ssh-add, ssh-keygen, curl, jq, go.
# Runs unprivileged; sshd listens on high ports and logs in as the current user.
set -euo pipefail

BAO_BIN=${BAO_BIN:-bao}
SSHD_BIN=${SSHD_BIN:-$(command -v sshd || echo /usr/sbin/sshd)}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
PIDS=()

cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [ "${KEEP_WORK:-}" = "" ]; then rm -rf "$WORK"; else echo "work dir kept: $WORK"; fi
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  for f in "$WORK"/*.log; do echo "--- $f" >&2; tail -n 40 "$f" >&2; done
  exit 1
}

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

wait_http() {
  for _ in $(seq 1 100); do curl -fsS -o /dev/null "$1" 2>/dev/null && return 0; sleep 0.1; done
  fail "timed out waiting for $1"
}

BAO_PORT=$(free_port)
export BAO_ADDR="http://127.0.0.1:$BAO_PORT"
export BAO_TOKEN=e2e-root
USER_NAME=$(id -un)

echo "== building certssh"
(cd "$ROOT" && CGO_ENABLED=0 go build -o "$WORK/certssh" ./cmd/certssh)
certssh() { "$WORK/certssh" "$@"; }

# certssh keeps everything under HOME; give it a throwaway one (after the
# build, so Go's module cache stays where it was).
export HOME="$WORK/home"
mkdir -p "$HOME"
SOCK="$HOME/.certssh/agent.sock"

echo "== starting OpenBao dev server"
"$BAO_BIN" server -dev -dev-root-token-id="$BAO_TOKEN" \
  -dev-listen-address="127.0.0.1:$BAO_PORT" >"$WORK/bao.log" 2>&1 &
PIDS+=($!)
wait_http "$BAO_ADDR/v1/sys/health"
bao() { "$BAO_BIN" "$@"; }

echo "== configuring user and host CAs"
for m in ssh-client-signer ssh-host-signer; do
  bao secrets enable -path=$m ssh >/dev/null
  bao write -field=public_key $m/config/ca generate_signing_key=true key_type=ssh-ed25519 >"$WORK/$m.pub"
done
jq -n '{key_type: "ca", allow_user_certificates: true, allowed_users: "env:infra,env:public",
  default_extensions: {"permit-pty": ""}, allowed_extensions: "permit-pty", ttl: "1h",
  key_id_format: "{{token_display_name}}"}' | bao write ssh-client-signer/roles/human - >/dev/null
bao write ssh-host-signer/roles/host key_type=ca allow_host_certificates=true \
  allowed_domains='*' allow_bare_domains=true allow_subdomains=true ttl=24h \
  allowed_extensions=certssh-principals@vexxhost.com >/dev/null
bao policy write ssh-infra - >/dev/null <<'EOF'
path "ssh-client-signer/sign/human" {
  capabilities        = ["create", "update"]
  required_parameters = ["valid_principals"]
  allowed_parameters  = { "valid_principals" = ["env:infra"], "*" = [] }
}
EOF
USER_TOKEN=$(bao token create -display-name=alice -policy=ssh-infra -ttl=1h -field=token)

start_sshd() { # name principal [principals to list in the host certificate]
  local name=$1 principal=$2 listed=${3:-} port
  port=$(free_port)
  ssh-keygen -q -t ed25519 -N '' -f "$WORK/$name-host"
  jq -n --rawfile key "$WORK/$name-host.pub" --arg name "$name" --arg listed "$listed" \
    '{public_key: $key, cert_type: "host", valid_principals: $name}
     + (if $listed == "" then {} else {extensions: {"certssh-principals@vexxhost.com": $listed}} end)' \
    | bao write -field=signed_key ssh-host-signer/sign/host - >"$WORK/$name-host-cert.pub"
  echo "$principal" >"$WORK/$name-principals"
  cat >"$WORK/$name-sshd_config" <<EOF
Port $port
ListenAddress 127.0.0.1
HostKey $WORK/$name-host
HostCertificate $WORK/$name-host-cert.pub
PidFile $WORK/$name-sshd.pid
TrustedUserCAKeys $WORK/ssh-client-signer.pub
AuthorizedPrincipalsFile $WORK/$name-principals
AuthorizedKeysFile none
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
LogLevel VERBOSE
# The test opens 20 connections at once.
MaxStartups 100
EOF
  # OpenSSH 9.8+ penalises the readiness probe below (a connection without
  # authentication) and then refuses the parallel connections from 127.0.0.1.
  if "$SSHD_BIN" -t -f "$WORK/$name-sshd_config" -o PerSourcePenalties=no 2>/dev/null; then
    echo "PerSourcePenalties no" >>"$WORK/$name-sshd_config"
  fi
  "$SSHD_BIN" -D -e -f "$WORK/$name-sshd_config" >"$WORK/$name-sshd.log" 2>&1 &
  PIDS+=($!)
  for _ in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/"$port") 2>/dev/null && break; sleep 0.1; done
  echo "$port"
}

# infra-1's host certificate lists the principals it accepts, so it needs no
# profile; public-1 is found through the profile file.
echo "== starting sshd for infra-1 (env:infra, listed in its certificate) and public-1 (env:public)"
INFRA_PORT=$(start_sshd infra-1 env:infra env:infra)
PUBLIC_PORT=$(start_sshd public-1 env:public)

cat >"$WORK/profile.yaml" <<'EOF'
version: 1
profiles:
  - name: public
    principal: env:public
    hosts: [public-*]
EOF

echo "== starting the agent with no configuration"
certssh agent -upstream none -log-level debug >"$WORK/agent.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || fail "agent socket did not appear"

echo "== logging in (the agent picks the new context up)"
env -u BAO_TOKEN "$WORK/certssh" login -method token -token "$USER_TOKEN" -profiles "$WORK/profile.yaml" \
  -host-ca-patterns 'infra-*,public-*' "$BAO_ADDR" \
  >"$WORK/login.log" 2>&1 || fail "login failed"
grep -q "Logged in to 127.0.0.1 as token-alice" "$WORK/login.log" || fail "unexpected login output"
grep -q '^@cert-authority infra-\*,public-\* ssh-ed25519 .* certssh:127.0.0.1$' "$HOME/.ssh/known_hosts" \
  || fail "host CA not trusted in known_hosts"

# Plain ssh: only SSH_AUTH_SOCK points at certssh. Strict host key checking
# proves the host CA line works; no IdentityFile so only the agent is used.
plain_ssh() { # alias port
  SSH_AUTH_SOCK="$SOCK" ssh -F /dev/null -p "$2" -o IdentityFile=none \
    -o UserKnownHostsFile="$HOME/.ssh/known_hosts" -o GlobalKnownHostsFile=/dev/null \
    -o StrictHostKeyChecking=yes -o HostKeyAlias="$1" -o BatchMode=yes \
    -o ConnectTimeout=5 -o LogLevel=ERROR "$USER_NAME@127.0.0.1" true
}
signs() { certssh status -json | jq -r .signs; }

echo "== ssh to infra-1 gets the env:infra certificate its host certificate asks for"
plain_ssh infra-1 "$INFRA_PORT" || fail "ssh to infra-1 failed"
grep -q "Accepted publickey for $USER_NAME .*ED25519-CERT.*ID token-alice" "$WORK/infra-1-sshd.log" \
  || fail "infra-1 did not log the certificate login"
SSH_AUTH_SOCK="$SOCK" ssh-add -L | ssh-keygen -L -f - | grep -q 'env:infra' || fail "ssh-add -L does not show the certificate"

echo "== ssh to public-1 is refused by policy, and the refusal is remembered"
plain_ssh public-1 "$PUBLIC_PORT" && fail "public-1 accepted a principal the policy forbids"
plain_ssh public-1 "$PUBLIC_PORT" && fail "public-1 accepted on retry"
certssh status -json | jq -e '.contexts[0].denied[0].principals == "env:public"' >/dev/null || fail "refusal not reported"
[ "$(signs)" = 2 ] || fail "expected 2 signing requests so far, got $(signs)"

echo "== 20 parallel connections reuse the certificate"
pids=()
for _ in $(seq 1 20); do plain_ssh infra-1 "$INFRA_PORT" & pids+=($!); done
for p in "${pids[@]}"; do wait "$p" || fail "a parallel ssh failed"; done
[ "$(signs)" = 2 ] || fail "parallel connections caused new signing requests: $(signs)"

certssh status >"$WORK/status.txt" || fail "status failed"
grep -q 'env:infra' "$WORK/status.txt" || fail "status does not list the certificate"

echo "== logout revokes the token and drops the certificate"
certssh logout >/dev/null || fail "logout failed"
bao token lookup "$USER_TOKEN" >/dev/null 2>&1 && fail "token still valid after logout"
plain_ssh infra-1 "$INFRA_PORT" && fail "ssh worked after logout"
SSH_AUTH_SOCK="$SOCK" ssh-add -L >/dev/null 2>&1 && fail "agent still holds a certificate after logout"

echo "PASS"
