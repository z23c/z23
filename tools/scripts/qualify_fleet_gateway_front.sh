#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# qualify_fleet_gateway_front.sh — qualify ONE fleet-gateway SHA end to end.
#
# WHAT IT PROVES (through a throwaway-cert TLS front on loopback, byte for
# byte what production serves): fresh-checkout fetch plus pinned dependencies,
# exact running-image identity, OAuth discovery / DCR / PKCE / token exchange,
# initialize / tools.list / tools.call, steer_brief / steer_send /
# steer_evidence, missing / conflicting / unknown / wrong-scope / revoked
# credential refusals, ACME TLS-ALPN-01 passthrough to a site backend (raw
# splice for acme-tls/1, termination otherwise, clean refusal of malformed
# and truncated ClientHellos), revoke-cancel of queued work plus evidence readability
# under a fresh grant, restart persistence, bounded buffers and processes,
# and a clean credential-log scan.
#
# WHAT IT NEVER DOES: deploy anything, touch the operator's state, log a
# credential, or qualify a SHA it was not given. Pass means THIS sha, THESE
# image hashes, in the scratch worktree named below — never "main is fine".
# Deployment stays owner-authorized (see
# platform/deploy/fleet-gateway/README.md), and a stale candidate is refused:
# dirty closure, SHA mismatch, or reused image all fail LOUD before serving.
#
# USAGE (run under the scheduler; a full node build is heavy):
#   devbuild --wait bash tools/scripts/qualify_fleet_gateway_front.sh --sha <40-hex>
# (Never pipe the harness straight into tail: the pipe masks its exit code.
# Use bash pipefail + tee, e.g.
#   bash -c 'set -o pipefail; devbuild --wait bash tools/scripts/qualify_fleet_gateway_front.sh --sha <S> 2>&1 | tee <log>; echo "HARNESS-EXIT=${PIPESTATUS[0]}"')
#   devbuild --wait bash tools/scripts/qualify_fleet_gateway_front.sh --sha <40-hex> --skip-node-build
#     (--skip-node-build reuses NO node paths: OAuth-mint and grant-mint legs
#     are reported UNOBSERVED and the verdict is INCOMPLETE, never PASS.
#     Smoke only; the real qual for A's SHA always builds the node.)
#   --train <name>      scratch worktree ~/.z23/trains/<name> (default
#                       gw-qual-<shortsha>-<UTC-timestamp>: always a fresh
#                       lane; never the current checkout, never a reuse).
#   --allow-dirty       record the closure diff and continue as SMOKE only;
#                       the verdict can never be PASS.
#   --keep-worktree     leave the scratch worktree for inspection.
#
# EXIT: 0 PASS (full matrix, exact SHA), 2 INCOMPLETE (smoke/subset), 1 FAIL.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

SHA=""
TRAIN=""
SKIP_NODE=0
ALLOW_DIRTY=0
KEEP=0
while [ $# -gt 0 ]; do
    case "$1" in
    --sha) SHA="${2:-}"; shift 2 ;;
    --train) TRAIN="${2:-}"; shift 2 ;;
    --skip-node-build) SKIP_NODE=1; shift ;;
    --allow-dirty) ALLOW_DIRTY=1; shift ;;
    --keep-worktree) KEEP=1; shift ;;
    -h | --help) sed -n '2,30p' "$0"; exit 0 ;;
    *) printf 'qualify: unknown arg: %s\n' "$1" >&2; exit 1 ;;
    esac
done

for cmd in git openssl nc curl sha256sum cc; do
    command -v "$cmd" >/dev/null 2>&1 || {
        printf 'qualify: FAIL: missing tool: %s\n' "$cmd" >&2
        exit 1
    }
done

say() { printf 'qualify: %s\n' "$*"; }
fail() {
    printf 'qualify: FAIL: %s\n' "$*" >&2
    verdict="FAIL: $*"
}

PASS=0
FAILN=0
SKIPN=0
verdict=""
note() { printf 'qualify: [%-4s] %s\n' "$1" "$2"; }
ok() { PASS=$((PASS + 1)); note PASS "$1"; }
bad() { FAILN=$((FAILN + 1)); note FAIL "$1"; }
skip() { SKIPN=$((SKIPN + 1)); note SKIP "$1"; }

# ── 1. Fresh position: fetch, resolve, refuse dirt ────────────────────────
say "fetching origin (parent + pins must resolve from the network)"
git fetch origin main >&2 || {
    fail "git fetch origin main failed"
    printf 'verdict: %s (pass=%d fail=%d skip=%d)\n' "$verdict" "$PASS" "$FAILN" "$SKIPN"
    exit 1
}
# No default: the final run qualifies the SHA it is given and nothing else.
# An omitted --sha fails closed instead of blessing whatever HEAD is.
if [ -z "$SHA" ]; then fail "need --sha=<40-hex> (refusing to bless caller HEAD)"; fi
case "$SHA" in
????????????????????????????????????????) ;;
*) fail "sha is not 40-hex: $SHA"; ;;
esac
git cat-file -t "$SHA" >/dev/null 2>&1 || fail "sha not present even after fetch: $SHA"
SHORT="$(printf '%s' "$SHA" | cut -c1-12)"
# Fresh lane by default: a timestamped train can never reuse another run's
# worktree, build dir, or state. Pass --train explicitly only to debug a
# kept tree (reuse still requires exact SHA plus a clean closure).
[ -z "$TRAIN" ] && TRAIN="gw-qual-$SHORT-$(date -u +%Y%m%dT%H%M%SZ)"
WT="$HOME/.z23/trains/$TRAIN"

DIRT="$(git status --porcelain -- . ':!test-tmp' 2>/dev/null | grep -v '^??' || true)"
if [ -n "$DIRT" ]; then
    if [ "$ALLOW_DIRTY" -eq 1 ]; then
        skip "tracked closure dirty (recorded, SMOKE only): $(printf '%s' "$DIRT" | head -n 5 | tr '\n' ';')"
        SMOKE_ONLY=1
    else
        fail "tracked tree dirty; refusing (use --allow-dirty for smoke, or a clean checkout)"
    fi
else
    SMOKE_ONLY=0
fi
[ "$SKIP_NODE" -eq 1 ] && SMOKE_ONLY=1
say "target sha=$SHA train=$TRAIN smoke_only=$SMOKE_ONLY"

# ── 2. Isolated scratch worktree (never this checkout) ───────────────────
if [ -d "$WT" ]; then
    WHEAD="$(git -C "$WT" rev-parse HEAD 2>/dev/null || true)"
    WDIRT="$(git -C "$WT" status --porcelain 2>/dev/null | grep -v '^??' || true)"
    if [ "$WHEAD" != "$SHA" ] || [ -n "$WDIRT" ]; then
        fail "scratch worktree $WT is at $WHEAD (dirty=$([ -n "$WDIRT" ] && echo yes || echo no)); refusing another worker's tree"
    else
        say "reusing scratch worktree at exact sha"
    fi
else
    git worktree add --detach "$WT" "$SHA" >&2 || fail "worktree add failed"
fi
# Pinned dependencies: the repo-sanctioned prime (submodule pin + vendor).
# Prime copies vendored Tor archives from a sibling checkout when it can, and
# a sibling whose archives predate the current pin hands over bytes bound to
# the WRONG tor commit -- provenance then refuses, and a node linked anyway
# would be stamped from archives this SHA never pinned. Rebuild them inside
# the train from the pinned submodule instead of qualifying borrowed bytes.
if ! make -C "$WT" worktree-prime >&2 || ! make -C "$WT" check-tor-provenance >&2; then
    say "prime left Tor archives unbound to this SHA's pin; rebuilding them in the train"
    make -C "$WT" tor-full >&2 || fail "tor-full (pinned archives) failed"
    make -C "$WT" check-tor-provenance >&2 || fail "Tor archives still not bound to the pin"
    make -C "$WT" worktree-prime >&2 || fail "worktree-prime (pinned deps) failed"
fi
say "tor pin: $(git -C "$WT" submodule status vendor/tor 2>/dev/null || echo unknown)"

# ── 3. Build the exact images ─────────────────────────────────────────────
NJOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
make -C "$WT" -j"$NJOBS" fleet-gateway >&2 || fail "gateway build failed"
if [ "$SKIP_NODE" -eq 0 ]; then
    make -C "$WT" -j"$NJOBS" z23 >&2 || fail "node build failed"
else
    skip "node build skipped by flag (mint legs UNOBSERVED)"
fi
GW_BIN="$WT/build/bin/z23-fleet-gateway"
NODE_BIN="$WT/build/bin/z23"
# The front is exact-image cover too: compiled from the SHA tree with plain
# cc (like zcl_portfwd: no Makefile target, no new packages), then hashed.
FF_SRC="$WT/tools/zcl_fleet_front.c"
FF_BIN="$WT/build/bin/zcl-fleet-front"
FRONT_BIN="${QUAL_FRONT_BIN:-$FF_BIN}"
if [ -z "${QUAL_FRONT_BIN:-}" ]; then
    cc -O2 -Wall -Wextra -Werror -std=c2x -o "$FF_BIN" "$FF_SRC" -lssl -lcrypto >&2 \
        || fail "front build failed"
else
    skip "front from QUAL_FRONT_BIN, not the SHA tree (SMOKE only)"
    SMOKE_ONLY=1
fi
[ -x "$GW_BIN" ] || fail "gateway image missing: $GW_BIN"
[ -x "$FRONT_BIN" ] || fail "front image missing: $FRONT_BIN"
if [ "$SKIP_NODE" -eq 0 ]; then
    [ -x "$NODE_BIN" ] || fail "node image missing: $NODE_BIN"
fi
GW_SHA="$(sha256sum "$GW_BIN" | cut -d' ' -f1)"
FF_SHA="$(sha256sum "$FRONT_BIN" | cut -d' ' -f1)"
[ "$SKIP_NODE" -eq 0 ] && NODE_SHA="$(sha256sum "$NODE_BIN" | cut -d' ' -f1)"
say "image gateway sha256=$GW_SHA"
say "image front sha256=$FF_SHA"
[ "$SKIP_NODE" -eq 0 ] && say "image node sha256=$NODE_SHA"

# ── 4. Isolated runtime: state, gateway, throwaway-cert front ─────────────
T="$(mktemp -d "${TMPDIR:-/tmp}/gwqual.XXXXXX")"
ST="$T/state"
# The gateway mkdirs its own z23/dev/steer chain 0700, but the XDG base
# itself must exist first — without it every steer-dir leg fails server_error.
mkdir -p "$ST" || fail "cannot create isolated state base"
CERT="$T/cert.pem"
KEY="$T/key.pem"
GW_READY="$T/gw.ready"
GW_ERR="$T/gw.err"
FRONT_ERR="$T/front.err"
OWNER_KEY="qual-owner-$(openssl rand -hex 8)"
GW_PORT=""
FRONT_PORT=""
GW_PID=""
FRONT_PID=""
for p in 18443 18444 18445 18446 18447 18448 18449 18450; do
    nc -z 127.0.0.1 "$p" 2>/dev/null || {
        FRONT_PORT="$p"
        break
    }
done
[ -n "$FRONT_PORT" ] || fail "no free probe port for the front"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" \
    -days 1 -subj "/CN=127.0.0.1" 2>/dev/null || fail "throwaway cert failed"
chmod 600 "$KEY"
# NOTE: this throwaway key is test-only and isolated to $T (one day, never
# the operator's). The harness never prints it, posts it, or logs it.

cleanup() {
    [ -n "$FRONT_PID" ] && kill "$FRONT_PID" 2>/dev/null
    [ -n "${ACME_FRONT_PID:-}" ] && kill "$ACME_FRONT_PID" 2>/dev/null
    [ -n "${ACME_SITE_PID:-}" ] && kill "$ACME_SITE_PID" 2>/dev/null
    [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null
    wait 2>/dev/null
}
trap cleanup EXIT

spawn_gateway() {
    # Ephemeral port (0) unless a fixed one is passed: prints ready port=N.
    # The issuer is the front, exactly as a public deploy configures it, so
    # discovery and the 401 challenge name the URL a client actually used.
    FLEET_GW_ISSUER="https://127.0.0.1:$FRONT_PORT" \
    FLEET_GW_REDIRECT_ALLOW="https://client.test/cb https://client.example/api/oauth/auth_callback" \
    FLEET_GW_BIND=127.0.0.1 FLEET_GW_PORT="${1:-0}" FLEET_GW_NODE="$NODE_BIN" \
        FLEET_GW_OWNER_KEY="$OWNER_KEY" XDG_STATE_HOME="$ST" \
        "$GW_BIN" >"$GW_READY" 2>"$GW_ERR" &
    GW_PID=$!
    for _ in $(seq 1 50); do
        grep -q '^ready port=' "$GW_READY" 2>/dev/null && break
        kill -0 "$GW_PID" 2>/dev/null || break
        sleep 0.1
    done
    # The ready line is `ready port=%d node=%s`: take the leading digits
    # only. The gateway's exact bytes are frozen; the parse adapts here.
    GW_PORT="$(sed -n 's/^ready port=\([0-9][0-9]*\).*/\1/p' "$GW_READY" | head -n 1)"
    [ -n "$GW_PORT" ] || {
        fail "gateway did not report ready (see $GW_ERR)"
        return 1
    }
    [ "$(readlink "/proc/$GW_PID/exe")" = "$GW_BIN" ] || {
        fail "running gateway image is not $GW_BIN"
        return 1
    }
    say "gateway pid=$GW_PID port=$GW_PORT exe==image"
}

spawn_gateway || fail "initial gateway spawn failed"
"$FRONT_BIN" 127.0.0.1 "$FRONT_PORT" 127.0.0.1 "$GW_PORT" "$CERT" "$KEY" \
    2>"$FRONT_ERR" &
FRONT_PID=$!
sleep 1
kill -0 "$FRONT_PID" 2>/dev/null || fail "front died at startup (see $FRONT_ERR)"
grep -q '^fleet-front: listen' "$FRONT_ERR" 2>/dev/null \
    || fail "front startup line missing (see $FRONT_ERR)"
say "front pid=$FRONT_PID port=$FRONT_PORT image=$FF_SHA (throwaway cert, loopback only)"

# ── 5. Matrix THROUGH the front (curl -k: isolated throwaway cert) ────────
F="https://127.0.0.1:$FRONT_PORT"
have() { # have <name> <needle> <curl-args...>: body must contain needle
    name="$1"
    needle="$2"
    shift 2
    body="$(curl -sk -m 20 "$@" || true)"
    case "$body" in
    *"$needle"*) ok "$name" ;;
    *)
        bad "$name (missing [$needle] in [$(printf '%s' "$body" | head -c 200)])"
        ;;
    esac
}
code_is() { # code_is <name> <want-code> <curl-args...>
    name="$1"
    want="$2"
    shift 2
    got="$(curl -sk -m 20 -o /dev/null -w '%{http_code}' "$@" || true)"
    if [ "$got" = "$want" ]; then ok "$name (http $got)"; else bad "$name (want $want, got $got)"; fi
}

code_is "healthz direct (loopback, never proxied)" 200 "http://127.0.0.1:$GW_PORT/healthz"
have "healthz body" '"ok":true' "http://127.0.0.1:$GW_PORT/healthz"
have "discovery: protected-resource" '"scopes_supported"' "$F/.well-known/oauth-protected-resource"
have "discovery: path-suffixed protected-resource" '"resource":"'"$F"'/steer"' "$F/.well-known/oauth-protected-resource/steer"
have "discovery: auth-server" '"token_endpoint"' "$F/.well-known/oauth-authorization-server"
have "initialize negotiates" '"protocolVersion":"2025-06-18"' -X POST "$F/steer" \
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}'
have "tools.list verbs" '"name":"steer_send"' -X POST "$F/steer" \
    --data '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
have "unknown method typed" '"code":-32601' -X POST "$F/steer" \
    --data '{"jsonrpc":"2.0","id":3,"method":"nope"}'
have "bad json typed" '"code":-32700' -X POST "$F/steer" --data '{oops'
code_is "GET /steer is 405" 405 "$F/steer"
code_is "unknown path is 404" 404 "$F/nope"
have "missing credential refused pre-fork" '"code":-32001' -X POST "$F/steer" \
    --data '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"steer_brief","arguments":{}}}'
# A hosted tool client signs in only on a transport 401 carrying the RFC 9728
# challenge; a 200 wrapping -32001 never starts its OAuth flow.
code_is "missing credential is a 401 challenge" 401 -X POST "$F/steer" \
    --data '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"steer_brief","arguments":{}}}'
HDRS="$(curl -sk -m 20 -o /dev/null -D - -X POST "$F/steer" \
    --data '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"steer_brief","arguments":{}}}' |
    tr -d '\r' || true)"
case "$HDRS" in
*"WWW-Authenticate: Bearer "*"resource_metadata=\"$F/.well-known/oauth-protected-resource\""*)
    ok "challenge names the front's resource metadata" ;;
*) bad "challenge header (got [$(printf '%s' "$HDRS" | grep -i '^www-auth' | head -c 200)])" ;;
esac
# Fixed all-zero dummy tokens: never credentials, only refusal probes.
DUMMY_BEARER_1="Authorization: Bearer 00000000000000000000000000000001" # api-key-example-ok
DUMMY_BEARER_0="Authorization: Bearer 00000000000000000000000000000000" # api-key-example-ok
have "conflicting credentials refused" 'conflicting grants' -H "$DUMMY_BEARER_1" \
    -X POST "$F/steer" \
    --data '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"steer_brief","arguments":{"grant":"00000000000000000000000000000002"}}}'
# Bounded buffers: 1 MiB + 1 byte body must die before the node is forked.
head -c 1048577 /dev/zero | tr '\0' 'x' >"$T/big.bin"
code_is "oversize body refused (1 MiB cap)" 400 -X POST "$F/steer" \
    -H 'Content-Type: application/json' --data-binary "@$T/big.bin"
# DCR legs that need no node: register + bad-redirect refusal + approval form.
REG="$(curl -sk -m 20 -X POST "$F/oauth/register" --data '{"redirect_uris":["https://client.test/cb"]}' || true)"
CID="$(printf '%s' "$REG" | grep -o '"client_id":"[0-9a-f]*"' | head -n 1 | cut -d'"' -f4)"
if [ "${#CID}" -ge 16 ]; then ok "DCR mints client_id"; else bad "DCR client_id (got [$REG])"; fi
have "DCR bad redirect refused" 'invalid_redirect_uri' -X POST "$F/oauth/register" \
    --data '{"redirect_uris":["http://evil.test/cb"]}'
CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
have "authorize form (owner sign-in)" 'Z23 Fleet sign-in' \
    "$F/oauth/authorize?response_type=code&client_id=$CID&redirect_uri=https://client.test/cb&scope=brief%20send&state=xyz&code_challenge=$CHALLENGE&code_challenge_method=S256"
# Hosted-client shape: its callback URL, percent-encoded upper-case.
CREG="$(curl -sk -m 20 -X POST "$F/oauth/register" -H 'Content-Type: application/json' --data '{"client_name":"hosted","redirect_uris":["https://client.example/api/oauth/auth_callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}' || true)"
CCID="$(printf '%s' "$CREG" | grep -o '"client_id":"[0-9a-f]*"' | head -n 1 | cut -d'"' -f4)"
have "authorize form (hosted-client callback)" 'auth_callback' \
    "$F/oauth/authorize?response_type=code&client_id=$CCID&redirect_uri=https%3A%2F%2Fclient.example%2Fapi%2Foauth%2Fauth_callback&scope=brief+send+evidence&state=AbC-123_x&code_challenge=$CHALLENGE&code_challenge_method=S256&resource=$(printf '%s' "$F/steer" | sed 's|:|%3A|g; s|/|%2F|g')"
AUTH_FORM="response_type=code&client_id=$CID&redirect_uri=https://client.test/cb&scope=brief%20send&state=xyz&code_challenge=$CHALLENGE&code_challenge_method=S256"
fresh_csrf() {
    curl -sk -m 20 "$F/oauth/authorize?$AUTH_FORM" |
        sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p'
}
CSRF="$(fresh_csrf)"
[ -n "$CSRF" ] || bad "approval form supplies a CSRF nonce"
code_is "authorize wrong owner key is 403" 403 -X POST "$F/oauth/authorize" \
    -H "Origin: $F" --data "$AUTH_FORM&csrf=$CSRF&owner_key=wrong&approve=1"

if [ "$SKIP_NODE" -eq 0 ]; then
    # Full OAuth: approve (owner key) -> code -> token (RFC 7636 vector).
    CSRF="$(fresh_csrf)"
    LOC="$(curl -sk -m 20 -o /dev/null -D - -X POST "$F/oauth/authorize" \
        -H "Origin: $F" --data "$AUTH_FORM&csrf=$CSRF&owner_key=$OWNER_KEY&approve=1" |
        grep -i '^location:' | tr -d '\r' || true)"
    CODE="$(printf '%s' "$LOC" | grep -o 'code=[0-9a-f]*' | cut -d= -f2)"
    [ "${#CODE}" -ge 16 ] || bad "authorize code (got [$LOC])"
    have "token wrong verifier refused" 'invalid_grant' -X POST "$F/oauth/token" \
        --data "grant_type=authorization_code&code=$CODE&redirect_uri=https://client.test/cb&client_id=$CID&code_verifier=wrong"
    TOK="$(curl -sk -m 20 -X POST "$F/oauth/token" \
        --data "grant_type=authorization_code&code=$CODE&redirect_uri=https://client.test/cb&client_id=$CID&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" || true)"
    TOKEN="$(printf '%s' "$TOK" | grep -o '"access_token":"[0-9a-f]*"' | head -n 1 | cut -d'"' -f4)"
    if [ "${#TOKEN}" -ge 16 ]; then ok "token exchange (PKCE S256)"; else bad "token exchange (got [$TOK])"; fi
    if [ "${#TOKEN}" -ge 16 ] && ! printf '%s' "$TOK" | grep -q '"expires_in"'; then
        ok "OAuth token has no expiry"
    else
        bad "OAuth token has no expiry"
    fi
    have "token single-use" 'invalid_grant' -X POST "$F/oauth/token" \
        --data "grant_type=authorization_code&code=$CODE&redirect_uri=https://client.test/cb&client_id=$CID&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    have "Bearer token is a scoped grant" '"isError":false' -H "Authorization: Bearer $TOKEN" \
        -X POST "$F/steer" \
        --data '{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"steer_brief","arguments":{}}}'
    have "unknown Bearer refused" 'STEER_GRANT_UNKNOWN' -H "$DUMMY_BEARER_0" \
        -X POST "$F/steer" \
        --data '{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"steer_brief","arguments":{}}}'
    # Node-minted grant legs in the same isolated state root.
    MINT="$(XDG_STATE_HOME="$ST" "$NODE_BIN" fleet steer grant --action=mint --scopes=brief,send,evidence --label=qual-caller 2>/dev/null || true)"
    GID="$(printf '%s' "$MINT" | grep -o '"id":"[0-9a-f]*"' | head -n 1 | cut -d'"' -f4)"
    if [ "${#GID}" -ge 16 ]; then ok "node grant mint"; else bad "node grant mint (got [$(printf '%s' "$MINT" | head -c 200)])"; fi
    have "steer_brief via grant" '"isError":false' -X POST "$F/steer" \
        --data "{\"jsonrpc\":\"2.0\",\"id\":30,\"method\":\"tools/call\",\"params\":{\"name\":\"steer_brief\",\"arguments\":{\"grant\":\"$GID\"}}}"
    have "steer_send via grant" '"isError":false' -X POST "$F/steer" \
        --data "{\"jsonrpc\":\"2.0\",\"id\":31,\"method\":\"tools/call\",\"params\":{\"name\":\"steer_send\",\"arguments\":{\"grant\":\"$GID\",\"from\":\"qual-caller\",\"items\":[{\"to\":\"qual-agent\",\"body\":\"probe\",\"ref\":\"q-1\",\"idempotency_key\":\"qk-1\"}]}}}"
    have "steer_evidence via grant" '"isError":false' -X POST "$F/steer" \
        --data "{\"jsonrpc\":\"2.0\",\"id\":32,\"method\":\"tools/call\",\"params\":{\"name\":\"steer_evidence\",\"arguments\":{\"grant\":\"$GID\",\"type\":\"mail\",\"ref\":\"q-1\"}}}"
    MINT2="$(XDG_STATE_HOME="$ST" "$NODE_BIN" fleet steer grant --action=mint --scopes=brief 2>/dev/null || true)"
    GID2="$(printf '%s' "$MINT2" | grep -o '"id":"[0-9a-f]*"' | head -n 1 | cut -d'"' -f4)"
    have "wrong scope refused by node" 'STEER_GRANT_SCOPE' -X POST "$F/steer" \
        --data "{\"jsonrpc\":\"2.0\",\"id\":33,\"method\":\"tools/call\",\"params\":{\"name\":\"steer_send\",\"arguments\":{\"grant\":\"$GID2\",\"items\":[{\"to\":\"qual-agent\",\"body\":\"x\",\"ref\":\"r-s\",\"idempotency_key\":\"k-s\"}]}}}"
    XDG_STATE_HOME="$ST" "$NODE_BIN" fleet steer grant --action=revoke --id="$TOKEN" >/dev/null 2>&1 || true
    have "revoked Bearer refused" 'STEER_GRANT_REVOKED' -H "Authorization: Bearer $TOKEN" \
        -X POST "$F/steer" \
        --data '{"jsonrpc":"2.0","id":34,"method":"tools/call","params":{"name":"steer_brief","arguments":{}}}'
    # ed1612a02a revocation: killing the credential also best-effort cancels
    # the queued work it sent; the reply carries revoked:true plus the
    # cancelled count (observed here, not asserted: best-effort by contract).
    REV="$(XDG_STATE_HOME="$ST" "$NODE_BIN" fleet steer grant --action=revoke --id="$GID" 2>/dev/null || true)"
    case "$REV" in
    *'"revoked":true'*) ok "revoke kills credential" ;;
    *) bad "revoke reply (got [$(printf '%s' "$REV" | head -c 200)])" ;;
    esac
    say "revoke-cancel observed: $(printf '%s' "$REV" | grep -o '"cancelled":[0-9]*' | head -n 1)"
    # Completed history is never rewritten: a fresh least-privilege grant
    # still reads the q-1 evidence object (any state, never an error).
    MINT3="$(XDG_STATE_HOME="$ST" "$NODE_BIN" fleet steer grant --action=mint --scopes=brief,evidence 2>/dev/null || true)"
    GID3="$(printf '%s' "$MINT3" | grep -o '"id":"[0-9a-f]*"' | head -n 1 | cut -d'"' -f4)"
    have "evidence readable under fresh grant" '"isError":false' -X POST "$F/steer" \
        --data "{\"jsonrpc\":\"2.0\",\"id\":35,\"method\":\"tools/call\",\"params\":{\"name\":\"steer_evidence\",\"arguments\":{\"grant\":\"$GID3\",\"type\":\"mail\",\"ref\":\"q-1\"}}}"
else
    skip "OAuth mint legs UNOBSERVED (no node build)"
    skip "grant brief/send/evidence UNOBSERVED (no node build)"
    skip "scope/revoke refusals UNOBSERVED (no node build)"
fi

# ── 5b. ACME TLS-ALPN-01 passthrough (apex role: front with a site) ──────
# The node renews its certificate by answering acme-tls/1 itself, so a
# front placed before it must hand that handshake over untouched. The site
# here is a throwaway TLS server with its OWN name that negotiates
# acme-tls/1: seeing that name and that protocol can only mean the raw
# stream reached the backend; the front's name means it was terminated.
free_port() {
    for p in "$@"; do
        nc -z 127.0.0.1 "$p" 2>/dev/null || { printf '%s' "$p"; return 0; }
    done
    return 1
}
ACME_SITE_PORT="$(free_port 18461 18462 18463 18464 18465 || true)"
ACME_FRONT_PORT="$(free_port 18466 18467 18468 18469 18470 || true)"
ACME_SITE_PID=""
ACME_FRONT_PID=""
if [ -z "$ACME_SITE_PORT" ] || [ -z "$ACME_FRONT_PORT" ]; then
    bad "acme passthrough: no free probe ports"
else
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/site-key.pem" \
        -out "$T/site-cert.pem" -days 1 -subj "/CN=acme-backend.test" 2>/dev/null \
        || bad "acme passthrough: site cert"
    chmod 600 "$T/site-key.pem"
    openssl s_server -quiet -accept "127.0.0.1:$ACME_SITE_PORT" \
        -cert "$T/site-cert.pem" -key "$T/site-key.pem" -alpn acme-tls/1 -www \
        >"$T/site.log" 2>&1 &
    ACME_SITE_PID=$!
    "$FRONT_BIN" 127.0.0.1 "$ACME_FRONT_PORT" 127.0.0.1 "$GW_PORT" "$CERT" "$KEY" \
        "127.0.0.1:$ACME_SITE_PORT" 2>"$T/front-acme.err" &
    ACME_FRONT_PID=$!
    sleep 1
    hello() { # hello <extra s_client args...>: handshake summary lines
        timeout 15 openssl s_client -connect "127.0.0.1:$ACME_FRONT_PORT" \
            -servername qual.test "$@" </dev/null 2>&1 | grep -E '^subject=|ALPN' || true
    }
    OUT="$(hello -alpn acme-tls/1)"
    case "$OUT" in
    *acme-backend.test*"ALPN protocol: acme-tls/1"*) ok "acme-tls/1 reaches the site untouched" ;;
    *) bad "acme-tls/1 passthrough (got [$(printf '%s' "$OUT" | tr '\n' ';')])" ;;
    esac
    grep -q 'acme-tls/1 passthrough to site' "$T/front-acme.err" 2>/dev/null \
        && ok "front logged the passthrough" || bad "front passthrough log line missing"
    OUT="$(hello -alpn h2,http/1.1)"
    case "$OUT" in
    *"CN = 127.0.0.1"*) ok "ordinary ClientHello terminated by the front" ;;
    *) bad "ordinary termination (got [$(printf '%s' "$OUT" | tr '\n' ';')])" ;;
    esac
    have "terminated request still routes to the gateway" '"scopes_supported"' \
        "https://127.0.0.1:$ACME_FRONT_PORT/.well-known/oauth-protected-resource"
    # Hostile first records. probe_close prints "<bytes-back> <seconds-to-close>"
    # for one raw connection that sends the bytes and never closes its half.
    probe_close() {
        timeout 14 bash -c 'exec 3<>"/dev/tcp/127.0.0.1/$1"; printf "$2" >&3; s=$(date +%s); n=$(cat <&3 2>/dev/null | wc -c); echo "$n $(($(date +%s) - s))"' _ "$ACME_FRONT_PORT" "$1" || echo "timeout 14"
    }
    # Malformed: a record too short to hold the ClientHello it announces.
    # Refused at once, with no reply.
    set -- $(probe_close '\026\003\001\000\010\001\000\000\004\003\003\377\377')
    if [ "$1" = 0 ] && [ "$2" -lt 3 ]; then
        ok "malformed ClientHello refused cleanly (${2}s, 0 bytes)"
    else
        bad "malformed ClientHello (bytes=$1, ${2}s)"
    fi
    # Truncated: a valid header promising more than ever arrives. Refused at
    # the hello deadline, not held for the 120 s idle bound.
    set -- $(probe_close '\026\003\001\002\000\001\000')
    if [ "$1" = 0 ] && [ "$2" -lt 10 ]; then
        ok "truncated ClientHello refused at the deadline (${2}s, 0 bytes)"
    else
        bad "truncated ClientHello (bytes=$1, ${2}s)"
    fi
    kill -0 "$ACME_FRONT_PID" 2>/dev/null && ok "front survives hostile hellos" \
        || bad "front died on a hostile hello"
    kill "$ACME_FRONT_PID" "$ACME_SITE_PID" 2>/dev/null
    wait "$ACME_FRONT_PID" "$ACME_SITE_PID" 2>/dev/null
    ACME_FRONT_PID=""
    ACME_SITE_PID=""
fi

# ── 6. Restart persistence: same images, new pid, still serving ──────────
GW_SHA2="$(sha256sum "$GW_BIN" | cut -d' ' -f1)"
[ "$GW_SHA2" = "$GW_SHA" ] || fail "gateway image changed mid-qual"
FF_SHA2="$(sha256sum "$FRONT_BIN" | cut -d' ' -f1)"
[ "$FF_SHA2" = "$FF_SHA" ] || fail "front image changed mid-qual"
OLD_PID="$GW_PID"
kill "$GW_PID" 2>/dev/null
wait "$GW_PID" 2>/dev/null
GW_PID=""
sleep 1
spawn_gateway "$GW_PORT" || fail "gateway restart failed"
if [ -n "$GW_PID" ] && [ "$GW_PID" != "$OLD_PID" ]; then ok "restart: new pid $GW_PID (image identical)"; else bad "restart pid"; fi
have "post-restart initialize via front" 'z23-fleet-gateway' -X POST "$F/steer" \
    --data '{"jsonrpc":"2.0","id":90,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}'

# ── 7. No credential logging ───────────────────────────────────────────────
# Scanned: the gateway's stderr and the front's stderr (startup line only by
# construction). The throwaway cert/key files are never grepped (key
# material must not even enter a scan pipeline as a pattern).
if grep -q -F "$OWNER_KEY" "$FRONT_ERR" "$GW_ERR" 2>/dev/null; then
    bad "owner key present in a log"
else
    ok "owner key in no log"
fi
LEAK=0
for secret in "${TOKEN:-}" "${GID:-}" "${GID2:-}" "${GID3:-}" "${CID:-}" "${CODE:-}"; do
    [ -n "$secret" ] || continue
    if grep -q -F "$secret" "$FRONT_ERR" "$GW_ERR" 2>/dev/null; then LEAK=1; fi
done
if [ "$LEAK" -eq 1 ]; then bad "credential material present in a log"; else ok "grants/codes/tokens in no log"; fi

# ── 8. Verdict ─────────────────────────────────────────────────────────────
say "image gateway sha256=$GW_SHA"
say "image front sha256=$FF_SHA"
[ "$SKIP_NODE" -eq 0 ] && say "image node sha256=$NODE_SHA"
say "worktree $WT (sha $SHA)"
if [ "$FAILN" -gt 0 ]; then
    verdict="FAIL"
elif [ "$SMOKE_ONLY" -eq 1 ] || [ "$SKIPN" -gt 0 ]; then
    verdict="INCOMPLETE (smoke/subset; not a qualification)"
else
    verdict="PASS sha=$SHA gw=$GW_SHA front=$FF_SHA node=$NODE_SHA"
fi
printf 'verdict: %s (pass=%d fail=%d skip=%d)\n' "$verdict" "$PASS" "$FAILN" "$SKIPN"
if [ "$KEEP" -eq 0 ] && [ "$FAILN" -eq 0 ]; then
    git worktree remove --force "$WT" 2>/dev/null || say "worktree kept (remove refused): $WT"
    rm -rf "$T"
else
    say "kept: worktree $WT ; scratch $T"
fi
[ "$FAILN" -eq 0 ] && [ "$SMOKE_ONLY" -eq 0 ] && exit 0
[ "$FAILN" -eq 0 ] && exit 2
exit 1
