#!/bin/sh
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Inspect signed landing projections without assigning acceptance authority.
set -eu

if [ "$#" -ne 4 ]; then
    printf 'usage: %s outcomes.jsonl tips.txt isolated-parent checkout\n' "$0" >&2
    exit 2
fi

ledger=$1
tips=$2
parent=$3
checkout=$4
jsonq=$checkout/build/bin/jsonq
test -f "$ledger"
test -f "$tips"
test -d "$parent"
test -x "$jsonq"
root=$(mktemp -d "$parent/land-receipts.XXXXXX")
count=0

printf 'utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'openssl=%s\n' "$(openssl version)"
printf 'compiler=%s\n' "$(cc --version | sed -n '1p')"
printf 'cpu=%s\n' "$(lscpu | sed -n 's/^Model name:[[:space:]]*//p' | sed -n '1p')"
sha256sum "$ledger" "$tips" "$jsonq"

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
    test "$(field remote_tip)" = "$tip"
    seq=$(field seq)
    target=$(field publication_target)
    proof=$(field publication_proof)
    bundle=$(field publication_bundle)
    base=$(field base)
    local_tip=$(field local)
    tree=$(field tree)
    proof_intent=$(field proof_intent)
    publication_signer=$(field publication_signer)
    publication_signature=$(field publication_signature)
    remote_source=$(field remote_source)
    remote_signer=$(field remote_signer)
    remote_signature=$(field remote_signature)
    if [ "$publication_signer" = "$remote_signer" ]; then
        signer_relation=same
    else
        signer_relation=different
    fi
    observed_tree=$(git -C "$checkout" rev-parse "$tip^{tree}")
    test "$tree" = "$observed_tree"
    test "$remote_source" = "$observed_tree"
    git -C "$checkout" merge-base --is-ancestor "$tip" origin/main

    dir=$root/$tip
    mkdir "$dir"
    printf '302a300506032b6570032100%s' "$publication_signer" |
        xxd -r -p > "$dir/publication-key.der"
    printf '%s' "$publication_signature" |
        xxd -r -p > "$dir/publication-signature.bin"
    printf 'zcl.dev_land.publication_intent.v1\noperator\nrefs/heads/main\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \
        "$seq" "$target" "$base" "$local_tip" "$tree" "$proof" \
        "$bundle" "$proof_intent" > "$dir/publication-message.txt"
    if ! openssl pkeyutl -verify -pubin -inkey "$dir/publication-key.der" \
        -keyform DER -rawin -in "$dir/publication-message.txt" \
        -sigfile "$dir/publication-signature.bin" > /dev/null; then
        printf 'INVALID_PUBLICATION_SIGNATURE tip=%s\n' "$tip" >&2
        exit 1
    fi

    printf '302a300506032b6570032100%s' "$remote_signer" |
        xxd -r -p > "$dir/remote-key.der"
    printf '%s' "$remote_signature" |
        xxd -r -p > "$dir/remote-signature.bin"
    printf 'zcl.dev_land.remote_receipt.v1\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \
        "$target" "$publication_signature" "$base" "$local_tip" \
        "$tree" "$tip" "$remote_source" > "$dir/remote-message.txt"
    if ! openssl pkeyutl -verify -pubin -inkey "$dir/remote-key.der" \
        -keyform DER -rawin -in "$dir/remote-message.txt" \
        -sigfile "$dir/remote-signature.bin" > /dev/null; then
        printf 'INVALID_REMOTE_SIGNATURE tip=%s\n' "$tip" >&2
        exit 1
    fi

    first=$(printf '%s' "$remote_signature" | cut -c1-2)
    rest=$(printf '%s' "$remote_signature" | cut -c3-)
    if [ "$first" = 00 ]; then first=ff; else first=00; fi
    printf '%s%s' "$first" "$rest" | xxd -r -p > "$dir/tampered.bin"
    if openssl pkeyutl -verify -pubin -inkey "$dir/remote-key.der" \
        -keyform DER -rawin -in "$dir/remote-message.txt" \
        -sigfile "$dir/tampered.bin" > /dev/null 2>&1; then
        printf 'tampered signature accepted for %s\n' "$tip" >&2
        exit 1
    fi
    { printf 'x'; tail -c +2 "$dir/remote-message.txt"; } > "$dir/tampered-message.txt"
    if openssl pkeyutl -verify -pubin -inkey "$dir/remote-key.der" \
        -keyform DER -rawin -in "$dir/tampered-message.txt" \
        -sigfile "$dir/remote-signature.bin" > /dev/null 2>&1; then
        printf 'tampered message accepted for %s\n' "$tip" >&2
        exit 1
    fi
    printf 'tip=%s publication_signature=VALID remote_signature=VALID signer_relation=%s signature_tamper=REJECTED message_tamper=REJECTED tree=PASS ancestry=PASS authority=UNVERIFIED acceptance=UNVERIFIED\n' "$tip" "$signer_relation"
    sha256sum "$dir/publication-message.txt" "$dir/remote-message.txt"
done < "$tips"

test "$count" -gt 0
printf 'CRYPTO_PASS count=%s root=%s authority=UNVERIFIED acceptance=UNVERIFIED\n' "$count" "$root"
