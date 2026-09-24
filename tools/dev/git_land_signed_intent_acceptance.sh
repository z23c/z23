#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
# Black-box RED witness: dev.land must not push a proven pair without a
# durable, signed publication intent and bundle attachment.
set -euo pipefail

bin=${1:-build/bin/z23-dev}
case "$bin" in /*) ;; *) bin="$(pwd)/$bin" ;; esac

fail()
{
    printf 'git-land-intent: RED %s\n' "$*" >&2
    printf 'git-land-intent: fixture=%s\n' "$fixture" >&2
    exit 1
}

fixture_root=$HOME/.cache
mkdir -p "$fixture_root"
fixture=$(mktemp -d "$fixture_root/z23-git-land-intent.XXXXXX")
work=$fixture/work
remote=$fixture/origin.git
hooks=$fixture/hooks
mkdir -p "$work" "$hooks"
git -C "$work" init -q --initial-branch=main
git -C "$work" config user.name 'Z23 Intent Fixture'
git -C "$work" config user.email fixture@example.invalid
ssh-keygen -q -t ed25519 -N '' -f "$fixture/signing_key"
printf 'fixture@example.invalid %s\n' "$(cat "$fixture/signing_key.pub")" \
    > "$fixture/allowed_signers"
git -C "$work" config gpg.format ssh
git -C "$work" config user.signingkey "$fixture/signing_key"
git -C "$work" config gpg.ssh.allowedSignersFile "$fixture/allowed_signers"
printf 'base\n' > "$work/source.txt"
git -C "$work" add source.txt
git -C "$work" commit -q -S -m base
base=$(git -C "$work" rev-parse HEAD)
git clone -q --bare "$work" "$remote"
git -C "$work" remote add origin "$remote"
git -C "$work" fetch -q origin main
printf 'candidate\n' > "$work/source.txt"
git -C "$work" commit -qam candidate -S
head=$(git -C "$work" rev-parse HEAD)
test "$(git -C "$work" log -1 --format=%G?)" = G ||
    fail 'fixture candidate is not a verified signed commit'

# The only remote is the fixture's local bare repository. This hook observes
# whether the lander attempts a push; the script never pushes the candidate.
cat > "$hooks/pre-push" <<EOF
#!/bin/sh
printf 'attempted\n' >> '$fixture/push-attempts'
exit 0
EOF
chmod 0755 "$hooks/pre-push"
export XDG_STATE_HOME="$fixture/state"
export ZCL_LAND_HOOKS_STUB_DIR="$hooks"
export ZCL_LAND_PROOF_STUB=running
"$bin" dev land submit --tip="$head" --worktree="$work" \
    > "$fixture/submit.json" || fail 'signed fixture submission failed'
"$bin" dev land step > "$fixture/prepare.json" ||
    fail 'fixture did not reach its prepared proof pair'
grep -Fq '"state":"started"' "$fixture/prepare.json" ||
    fail 'fixture did not reach the proof phase'

# PASS is a test-only proof observation. The candidate is still unqualified:
# no signed publication intent or attachment was supplied or stored.
export ZCL_LAND_PROOF_STUB=pass
"$bin" dev land step > "$fixture/no-intent.json" || true
observed=$(git --git-dir="$remote" rev-parse refs/heads/main)
if test "$observed" != "$base" || test -e "$fixture/push-attempts"; then
    fail "push attempted without intent: base=$base remote=$observed head=$head"
fi
grep -Fq '"code":"PUBLICATION_INTENT_REQUIRED"' \
    "$fixture/no-intent.json" ||
    fail 'missing intent did not produce PUBLICATION_INTENT_REQUIRED'
"$bin" dev land status > "$fixture/status.json"
grep -Fq "\"tip\":\"$head\"" "$fixture/status.json" ||
    fail 'refused work lost its exact candidate'
grep -Fq "\"base\":\"$base\"" "$fixture/status.json" ||
    fail 'refused work lost its exact expected base'
grep -Fq "\"local\":\"$head\"" "$fixture/status.json" ||
    fail 'refused work changed its proven head'
printf 'git-land-intent: PASS missing-intent pre-push refusal\n'

# The attach route must be present, but a dev proof stub is deliberately not
# a signed proof receipt. The test harness covers the positive signed route
# with its isolated ZCL_TESTING proof fixture.
"$bin" discover describe dev.land > "$fixture/land-schema.json"
grep -Fq 'attach seals' "$fixture/land-schema.json" ||
    fail 'dev.land attach is absent from the command contract'
"$bin" dev land attach --seq=1 > "$fixture/invalid-attach.json" || true
grep -Fq '"code":"UNKNOWN_ACTION"' "$fixture/invalid-attach.json" &&
    fail 'dev.land attach is not routed'
grep -Fq '"code":"PUBLICATION_PROOF_REQUIRED"' \
    "$fixture/invalid-attach.json" ||
    fail 'proof stub was accepted as a signed publication proof'
test "$(git --git-dir="$remote" rev-parse refs/heads/main)" = "$base" ||
    fail 'invalid intent changed the local fixture remote'
test ! -e "$fixture/push-attempts" ||
    fail 'invalid intent invoked the pre-push hook'
printf 'git-land-intent: PASS stub refused and remote unchanged; fixture=%s\n' "$fixture"
