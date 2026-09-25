#!/bin/sh
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Probe exact local proof receipts named by signed landing projections.
set -eu

if [ "$#" -ne 4 ]; then
    printf 'usage: %s outcomes.jsonl tips.txt z23-dev checkout\n' "$0" >&2
    exit 2
fi

ledger=$1
tips=$2
unit=$3
checkout=$4
jsonq=$checkout/build/bin/jsonq
test -f "$ledger"
test -f "$tips"
test -x "$unit"
test -x "$jsonq"
count=0
available=0
mismatched=0

printf 'utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'compiler=%s\n' "$(cc --version | sed -n '1p')"
printf 'cpu=%s\n' "$(lscpu | sed -n 's/^Model name:[[:space:]]*//p' | sed -n '1p')"
sha256sum "$ledger" "$tips" "$unit" "$jsonq"

while IFS= read -r tip || [ -n "$tip" ]; do
    case "$tip" in ''|'#'*) continue ;; esac
    printf '%s\n' "$tip" | grep -Eq '^[0-9a-f]{40}$'
    count=$((count + 1))
    test "$count" -le 16
    row=$(rg -F -- '"remote_tip":"'"$tip"'"' "$ledger" || true)
    if [ -z "$row" ]; then
        printf 'MISSING_OBSERVATION tip=%s\n' "$tip" >&2
        exit 1
    fi
    if [ "$(printf '%s\n' "$row" | wc -l)" -ne 1 ]; then
        printf 'CONFLICTING_OBSERVATIONS tip=%s\n' "$tip" >&2
        exit 1
    fi
    field() { printf '%s\n' "$row" | "$jsonq" get "$1"; }
    workspace=$(field worktree)
    local_tip=$(field local)
    base=$(field base)
    expected=$(field publication_proof)
    printf '%s\n' "$workspace" | grep -Eq '^/[A-Za-z0-9_./-]+$'
    printf '%s\n' "$local_tip" | grep -Eq '^[0-9a-f]{40}$'
    printf '%s\n' "$base" | grep -Eq '^[0-9a-f]{40}$'
    printf '%s\n' "$expected" | grep -Eq '^[0-9a-f]{64}$'
    input='{"root":"'"$workspace"'","local_commit":"'"$local_tip"'","remote_base":"'"$base"'"}'
    response=$("$unit" dev proof status --input="$input")
    status=$(printf '%s\n' "$response" | "$jsonq" get data.status)
    receipt=$(printf '%s\n' "$response" | "$jsonq" get data.receipt_path)
    binding=UNAVAILABLE
    if [ "$status" = passed ] && [ -f "$receipt" ]; then
        actual=$(sha256sum "$receipt" | cut -d' ' -f1)
        if [ "$actual" = "$expected" ]; then
            binding=SHA_MATCH
            available=$((available + 1))
        else
            binding=SHA_MISMATCH
            mismatched=$((mismatched + 1))
        fi
    fi
    printf 'tip=%s status=%s local_proof_binding=%s\n' \
        "$tip" "$status" "$binding"
done < "$tips"

test "$count" -gt 0
printf 'LOCAL_PROOF_COVERAGE available=%s selected=%s authority=UNVERIFIED acceptance=UNVERIFIED\n' \
    "$available" "$count"
test "$mismatched" -eq 0
