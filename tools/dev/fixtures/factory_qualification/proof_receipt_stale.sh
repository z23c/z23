#!/bin/sh
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Challenge an old signed proof receipt against a current exact-pair lookup.
set -eu

if [ "$#" -ne 4 ]; then
    printf 'usage: %s z23-dev signed-receipt isolated-parent checkout\n' "$0" >&2
    exit 2
fi

unit=$1
receipt=$2
parent=$3
checkout=$4
jsonq=$checkout/build/bin/jsonq
test -x "$unit"
test -x "$jsonq"
test -f "$receipt"
test -d "$parent"
test "$(wc -c < "$receipt")" -eq 760
name=$(basename "$receipt" .receipt)
local_tip=${name%%-*}
old_base=${name#*-}
current_base=$(git -C "$checkout" rev-parse origin/main)
for value in "$local_tip" "$old_base" "$current_base"; do
    printf '%s\n' "$value" | grep -Eq '^[0-9a-f]{40}$'
done
test "$old_base" != "$current_base"
root=$(mktemp -d "$parent/proof-stale.XXXXXX")

printf 'utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'compiler=%s\n' "$(cc --version | sed -n '1p')"
printf 'cpu=%s\n' "$(lscpu | sed -n 's/^Model name:[[:space:]]*//p' | sed -n '1p')"
printf 'local=%s old_base=%s current_base=%s\n' \
    "$local_tip" "$old_base" "$current_base"
sha256sum "$unit" "$receipt" "$jsonq"

dd if="$receipt" of="$root/body.bin" bs=664 count=1 status=none
dd if="$receipt" of="$root/pub.bin" bs=1 skip=664 count=32 status=none
dd if="$receipt" of="$root/signature.bin" bs=1 skip=696 count=64 status=none
printf '302a300506032b6570032100' | xxd -r -p > "$root/pub.der"
cat "$root/pub.bin" >> "$root/pub.der"
printf zcl.dev_proof_receipt.v2 > "$root/message.bin"
cat "$root/body.bin" >> "$root/message.bin"
openssl pkeyutl -verify -pubin -inkey "$root/pub.der" -keyform DER \
    -rawin -in "$root/message.bin" -sigfile "$root/signature.bin" > /dev/null
printf 'original_signature=VALID\n'

for variant in original stale corrupt truncated; do
    dir=$root/$variant/.cache/zcl-dev-proof/receipts
    mkdir -p "$dir"
    if [ "$variant" = stale ]; then
        lookup_base=$current_base
    else
        lookup_base=$old_base
    fi
    target=$dir/$local_tip-$lookup_base.receipt
    cp "$receipt" "$target"
    if [ "$variant" = corrupt ]; then
        chmod u+w "$target"
        byte=$(xxd -p -l 1 -s 759 "$target")
        if [ "$byte" = 00 ]; then byte=ff; else byte=00; fi
        printf '%s' "$byte" | xxd -r -p |
            dd of="$target" bs=1 seek=759 conv=notrunc status=none
    elif [ "$variant" = truncated ]; then
        dd if="$receipt" of="$target.tmp" bs=759 count=1 status=none
        mv "$target.tmp" "$target"
    fi
    input='{"root":"'"$root/$variant"'","local_commit":"'"$local_tip"'","remote_base":"'"$lookup_base"'"}'
    "$unit" dev proof status --input="$input" > "$root/$variant.json"
    status=$("$jsonq" get data.status < "$root/$variant.json")
    if [ "$variant" = original ]; then
        test "$status" = passed
    else
        test "$status" != passed
    fi
    printf 'variant=%s status=%s bytes=%s sha256=%s\n' "$variant" \
        "$status" "$(wc -c < "$target")" \
        "$(sha256sum "$target" | cut -d' ' -f1)"
done

sha256sum "$root"/original.json "$root"/stale.json \
    "$root"/corrupt.json "$root"/truncated.json
printf 'STALE_RECEIPT_REFUSED root=%s authority=current-local-only\n' "$root"
