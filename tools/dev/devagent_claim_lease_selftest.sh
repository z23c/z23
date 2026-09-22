#!/bin/sh
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
# Exercise lease takeover through the public dev command in disposable Git worktrees.
set -eu

bin=${1:-build/bin/z23-dev}
case $bin in /*) ;; *) bin="$(pwd)/$bin" ;; esac
fixture=$(mktemp -d "${TMPDIR:-/tmp}/z23-claim-lease.XXXXXX")
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
repo=$fixture/repo
other=$fixture/other
mkdir "$repo"
git -C "$repo" init -q
printf 'base\n' > "$repo/base.txt"
git -C "$repo" add base.txt
git -C "$repo" -c user.name='Z23 Test' -c user.email='z23-test@example.invalid' \
    -c commit.gpgsign=false commit -q -m base
git -C "$repo" worktree add -q -b other "$other"
ledger=$repo/.git/z23-agent-claims.jsonl

claim() {
    "$bin" dev agent claim --input="{\"cwd\":\"$1\",\"story\":\"lease-test\",\"files\":[\"engine/a.c\"]}"
}

# A well-formed expired lease becomes available and is removed atomically.
printf '{"ts":"old","expires_unix":1,"worktree":"%s","branch":"other","story":"stalled","files":["engine/a.c"]}\n' "$other" > "$ledger"
result=$(claim "$repo")
printf '%s\n' "$result" | grep -q '"status":"passed"'
printf '%s\n' "$result" | grep -q '"expired_reclaimed":1'
printf '%s\n' "$result" | grep -q '"expires_unix":'
if grep -q '"story":"stalled"' "$ledger"; then
    printf 'expired foreign lease survived claim\n' >&2
    exit 1
fi
result=$(claim "$other" || true)
printf '%s\n' "$result" | grep -q '"code":"CLAIM_OVERLAP"'
result=$(claim "$repo")
printf '%s\n' "$result" | grep -q '"live":1'
test "$(wc -l < "$ledger")" -eq 1

# A live lease and an old row without expiry still protect their owner.
future=$(($(date +%s) + 300))
printf '{"ts":"live","expires_unix":%s,"worktree":"%s","branch":"other","story":"live","files":["engine/a.c"]}\n' "$future" "$other" > "$ledger"
before=$(git hash-object "$ledger")
result=$(claim "$repo" || true)
printf '%s\n' "$result" | grep -q '"code":"CLAIM_OVERLAP"'
test "$before" = "$(git hash-object "$ledger")"

printf '{"ts":"legacy","worktree":"%s","branch":"other","story":"legacy","files":["engine/a.c"]}\n' "$other" > "$ledger"
result=$(claim "$repo" || true)
printf '%s\n' "$result" | grep -q '"code":"CLAIM_OVERLAP"'

printf '{"ts":"bad","expires_unix":"bad","worktree":"%s","branch":"other","story":"bad","files":["engine/a.c"]}\n' "$other" > "$ledger"
result=$(claim "$repo" || true)
printf '%s\n' "$result" | grep -q '"code":"CLAIM_OVERLAP"'

printf 'devagent_claim_lease: PASS\n'
