#!/bin/sh
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Qualify a compile-valid compiler-argument drift with exact output bytes.
set -eu

if [ "$#" -ne 2 ]; then
    printf 'usage: %s gcc-path isolated-parent\n' "$0" >&2
    exit 2
fi

compiler=$1
parent=$2
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/toolchain_drift.c
test -f "$fixture"
test -x "$compiler"
test -d "$parent"
root=$(mktemp -d "$parent/toolchain-drift.XXXXXX")

printf 'utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'compiler=%s\n' "$("$compiler" --version | sed -n '1p')"
printf 'cpu=%s\n' "$(lscpu | sed -n 's/^Model name:[[:space:]]*//p' | sed -n '1p')"
sha256sum "$compiler" "$fixture"

for mode in base extra; do
    for opt in 0 2; do
        if [ "$mode" = extra ]; then
            value=2
        else
            value=1
        fi
        binary="$root/$mode-O$opt"
        "$compiler" -std=c23 -Wall -Wextra -Werror -pedantic \
            -DZCL_FIXTURE_VALUE="$value" -O"$opt" "$fixture" -o "$binary"
        "$binary" > "$binary.out"
        test "$(cat "$binary.out")" = "$value"
        printf '%s O%s value=%s\n' "$mode" "$opt" "$value"
        sha256sum "$binary" "$binary.out"
    done
done
printf 'PASS root=%s\n' "$root"
