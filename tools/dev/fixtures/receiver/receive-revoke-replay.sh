#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
set -euo pipefail

if test "$#" -ne 2; then
    printf 'usage: %s z23-dev isolated-parent\n' "$0" >&2
    exit 2
fi
unit=$1
parent=$2
repo=$(cd "$(dirname "$unit")/../.." && pwd)
signer=$(git -C "$repo" config user.signingkey)
test -n "$signer"
root=$(mktemp -d "$parent/receive-replay.XXXXXX")
export XDG_STATE_HOME="$root/state"
ws="$root/ws"
mkdir -p "$ws/src"
git init -q "$ws"
printf '/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */\nint x(void) { return 0; }\n' > "$ws/src/x.c"
git -C "$ws" add src/x.c
git -C "$ws" -c user.name='Rhett Creighton' \
    -c user.email='2388024+RhettCreighton@users.noreply.github.com' \
    -c gpg.format=ssh -c user.signingkey="$signer" \
    -c commit.gpgsign=true commit -q -m 'Add isolated receiver fixture'
base_head=$(git -C "$ws" rev-parse HEAD)

grant1=$(
    "$unit" fleet steer grant \
        --input='{"action":"mint","scopes":"send","label":"fixture-sender","ttl_seconds":300}' |
        sed -n 's/.*"id":"\([0-9a-f]\{32\}\)".*/\1/p'
)
test "${#grant1}" -eq 32
body='muse-workspace: receiver\nmuse-scope: src/x.c\nmuse-gate: hex_codec\n\nImprove the clear error for failed display initialization.\n'
item='{"to":"fixture-box","body":"'"$body"'","ref":"display-error-1","idempotency_key":"display-error-1-key"}'
"$unit" fleet steer send --input='{"grant":"'"$grant1"'","from":"fixture-sender","items":['"$item"']}' > "$root/send-first.json"
"$unit" fleet steer send --input='{"grant":"'"$grant1"'","from":"fixture-sender","items":['"$item"']}' > "$root/send-retry.json"
grep -q '"duplicate":false' "$root/send-first.json"
grep -q '"duplicate":true' "$root/send-retry.json"

drive='{"action":"run","receiver":"fixture-box","workspace":"'"$ws"'","deadline_s":1,"wait_ms":50,"max_beats":1}'
"$unit" dev agent receive --input="$drive" > "$root/receive-first.json"
"$unit" dev agent queue --input='{"action":"status","json":true}' > "$root/queue-first.json"
grep -q '"admitted":1' "$root/receive-first.json"
grep -q '"queued_total":1' "$root/queue-first.json"

"$unit" dev agent receive --input="$drive" > "$root/receive-restart.json"
grep -q '"admitted":0' "$root/receive-restart.json"
revoke=$(
    "$unit" fleet steer grant --input='{"action":"revoke","id":"'"$grant1"'"}'
)
grep -q '"cancelled":1' <<<"$revoke"
"$unit" dev agent queue --input='{"action":"status","json":true}' > "$root/queue-cancelled.json"
grep -q '"queued_total":0' "$root/queue-cancelled.json"

set +e
refused=$("$unit" fleet steer send --input='{"grant":"'"$grant1"'","from":"fixture-sender","items":[{"to":"fixture-box","body":"'"$body"'","ref":"display-error-2","idempotency_key":"display-error-2-key"}]}' 2>&1)
refused_rc=$?
set -e
test "$refused_rc" -ne 0
grep -q 'STEER_GRANT_REVOKED' <<<"$refused"

grant2=$(
    "$unit" fleet steer grant \
        --input='{"action":"mint","scopes":"send","label":"fixture-sender","ttl_seconds":300}' |
        sed -n 's/.*"id":"\([0-9a-f]\{32\}\)".*/\1/p'
)
test "${#grant2}" -eq 32
item2='{"to":"fixture-box","body":"'"$body"'","ref":"display-error-1","idempotency_key":"display-error-1-new-grant"}'
"$unit" fleet steer send --input='{"grant":"'"$grant2"'","from":"fixture-sender","items":['"$item2"']}' > "$root/send-regrant.json"
"$unit" dev agent receive --input="$drive" > "$root/receive-regrant.json"
"$unit" dev agent queue --input='{"action":"status","json":true}' > "$root/queue-regrant.json"
"$unit" dev agent mail --input='{"action":"pull","from":"fixture-box","since":0}' > "$root/claims.json"
grep -q '"admitted":1' "$root/receive-regrant.json"
grep -q '"queued_total":1' "$root/queue-regrant.json"
test "$(grep -o '"kind":"claim"' "$root/claims.json" | wc -l)" -eq 2
test "$(grep -o 'queue_seq=1' "$root/claims.json" | wc -l)" -eq 2
test "$(grep -o 'src=[0-9a-f]\{16\}' "$root/claims.json" | sort -u | wc -l)" -eq 2

printf '/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */\nint x(void) { return 1; }\n' > "$ws/src/x.c"
"${CC:-cc}" -std=c23 -Wall -Wextra -Werror -pedantic -fsyntax-only "$ws/src/x.c"
dirty='{"to":"fixture-box","body":"'"$body"'","ref":"display-error-dirty","idempotency_key":"display-error-dirty-key"}'
"$unit" fleet steer send --input='{"grant":"'"$grant2"'","from":"fixture-sender","items":['"$dirty"']}' > "$root/send-dirty.json"
"$unit" dev agent receive --input="$drive" > "$root/receive-dirty.json"
"$unit" dev agent queue --input='{"action":"status","json":true}' > "$root/queue-dirty.json"
"$unit" dev agent mail --input='{"action":"pull","from":"fixture-box","since":0}' > "$root/claims-after-dirty.json"
grep -q '"refused":1' "$root/receive-dirty.json"
grep -q 'RECEIVE_WORKSPACE_DIRTY' "$root/claims-after-dirty.json"
grep -q '"queued_total":1' "$root/queue-dirty.json"
test ! -e "$XDG_STATE_HOME/z23/dev/receive/brief/display-error-dirty.brief"

git -C "$ws" add src/x.c
git -C "$ws" -c user.name='Rhett Creighton' \
    -c user.email='2388024+RhettCreighton@users.noreply.github.com' \
    -c gpg.format=ssh -c user.signingkey="$signer" \
    -c commit.gpgsign=true commit -q -m 'Change isolated receiver source'
stale_body='muse-workspace: receiver\nmuse-scope: src/x.c\nmuse-gate: hex_codec\nmuse-sha: '"$base_head"'\n\nReject the old source pin.\n'
stale='{"to":"fixture-box","body":"'"$stale_body"'","ref":"display-error-stale","idempotency_key":"display-error-stale-key"}'
"$unit" fleet steer send --input='{"grant":"'"$grant2"'","from":"fixture-sender","items":['"$stale"']}' > "$root/send-stale.json"
"$unit" dev agent receive --input="$drive" > "$root/receive-stale.json"
"$unit" dev agent queue --input='{"action":"status","json":true}' > "$root/queue-stale.json"
"$unit" dev agent mail --input='{"action":"pull","from":"fixture-box","since":0}' > "$root/claims-after-stale.json"
grep -q '"refused":1' "$root/receive-stale.json"
grep -q 'RECEIVE_WORKSPACE_SHA_MISMATCH' "$root/claims-after-stale.json"
grep -q '"queued_total":1' "$root/queue-stale.json"
test ! -e "$XDG_STATE_HOME/z23/dev/receive/brief/display-error-stale.brief"

printf 'PASS root=%s base_head=%s current_head=%s binary_sha256=%s\n' \
    "$root" "$base_head" "$(git -C "$ws" rev-parse HEAD)" \
    "$(sha256sum "$unit" | cut -d' ' -f1)"
printf 'utc=%s compiler=%s cpu=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    "$("${CC:-cc}" --version | sed -n '1p')" \
    "$(lscpu | sed -n 's/^Model name:[[:space:]]*//p' | sed -n '1p')"
sha256sum "$root"/send-first.json "$root"/send-retry.json \
    "$root"/receive-first.json "$root"/receive-restart.json \
    "$root"/queue-first.json "$root"/queue-cancelled.json \
    "$root"/receive-regrant.json "$root"/queue-regrant.json \
    "$root"/claims.json "$root"/receive-dirty.json \
    "$root"/queue-dirty.json "$root"/claims-after-dirty.json \
    "$root"/receive-stale.json "$root"/queue-stale.json \
    "$root"/claims-after-stale.json
