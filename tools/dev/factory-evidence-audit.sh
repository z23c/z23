#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Recompute source identity and check both reported receipt objects.
set -euo pipefail
if [[ $# != 3 ]]; then
    printf 'usage: %s REPORT PACKAGE_DIR BIN_DIR\n' "$0" >&2
    exit 2
fi
root=$(cd "$(dirname "$0")/../.." && pwd -P)
cd "$root"
report=$(realpath "$1")
package=$(realpath "$2")
bin_dir=$(realpath "$3")
field() { "$bin_dir/jsonq" get "$1" < "$report"; }
fail() { printf 'REFUSE %s\n' "$*" >&2; exit 1; }
[[ $(field ok) == true ]] || fail 'factory report is not successful'
pubkey=$(field package.publisher_pubkey)
sequence=$(field package.publisher_sequence)
"$bin_dir/zclassic23" -datadir="$(dirname "$report")/audit-datadir" \
    zcode package dev prepare --dir="$package" \
    --publisher_pubkey="$pubkey" --publisher_sequence="$sequence" \
    > "$(dirname "$report")/audit-prepare.json"
prepared="$(dirname "$report")/audit-prepare.json"
for key in package_root recipe_root; do
    actual=$("$bin_dir/jsonq" get "data.$key" < "$prepared")
    claimed=$(field "package.$key")
    [[ $actual == "$claimed" ]] || fail "$key stale: claimed=$claimed actual=$actual"
done
for profile in quick standard; do
    a=$(field "stores.a.receipt_$profile")
    b=$(field "stores.b.receipt_$profile")
    [[ $a == "$b" && $a =~ ^[0-9a-f]{64}$ ]] || fail "$profile receipt ids differ"
    dir_a="$(dirname "$report")/$(field stores.a.store)"
    dir_b="$(dirname "$report")/$(field stores.b.store)"
    file_a="$dir_a/zcode/receipts/$a"
    file_b="$dir_b/zcode/receipts/$b"
    [[ -f $file_a && -f $file_b ]] || fail "$profile receipt unavailable"
    cmp -s "$file_a" "$file_b" || fail "$profile receipt bytes differ"
    printf '%s receipt=%s sha256=%s\n' "$profile" "$a" \
        "$(sha256sum "$file_a" | cut -d' ' -f1)"
done
[[ $(field stores.a.reproduced) == true && \
   $(field stores.b.reproduced) == true ]] || fail 'reproduction absent'
printf 'PASS package_root=%s report_sha256=%s\n' \
    "$(field package.package_root)" "$(sha256sum "$report" | cut -d' ' -f1)"
