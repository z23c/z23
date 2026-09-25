#!/bin/sh
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Verify one exact historical proof receipt on a consenting development peer.
set -eu

if [ "$#" -ne 2 ]; then
    printf 'usage: %s signed-receipt peer-alias\n' "$0" >&2
    exit 2
fi

receipt=$1
peer=$2
test -f "$receipt"
test "$(wc -c < "$receipt")" -eq 760
digest=$(sha256sum "$receipt" | cut -d' ' -f1)

remote='set -eu
d=$(mktemp -d)
trap "rm -rf $d" EXIT
cat > "$d/receipt"
test "$(wc -c < "$d/receipt")" -eq 760
test "$(sha256sum "$d/receipt" | cut -d" " -f1)" = "$1"
dd if="$d/receipt" of="$d/body" bs=664 count=1 status=none
dd if="$d/receipt" of="$d/pub" bs=1 skip=664 count=32 status=none
dd if="$d/receipt" of="$d/sig" bs=1 skip=696 count=64 status=none
printf 302a300506032b6570032100 | xxd -r -p > "$d/key.der"
cat "$d/pub" >> "$d/key.der"
printf zcl.dev_proof_receipt.v2 > "$d/message"
cat "$d/body" >> "$d/message"
openssl pkeyutl -verify -pubin -inkey "$d/key.der" -keyform DER \
    -rawin -in "$d/message" -sigfile "$d/sig" >/dev/null
printf "receipt_sha256=%s bytes=760 signature=VALID\\n" "$1"'

ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=5 \
    "$peer" "sh -c '$remote' sh '$digest'" < "$receipt"
