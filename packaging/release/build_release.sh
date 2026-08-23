#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# build_release.sh — pack stripped x86_64-linux node binaries + SHA256SUMS.
#
# A stranger must not compile 550K lines of C to run Z23. This script packages
# an already-built node (make && make tor-full) into a directory any node URL
# can later serve. It never invokes docker.
#
# Usage:
#   packaging/release/build_release.sh [--bin DIR] [--out DIR]
#   packaging/release/build_release.sh --selftest
#
# Default --bin is <repo>/build/bin; default --out is
# <repo>/build/release/z23-x86_64-linux. Requires z23 or zclassic23 in --bin.
# Honors the documented glibc/GLIBCXX floor (ci_symbol_floor_gate +
# check_c23_node_binary). Exit 0 on PASS, 1 on refusal.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FLOOR_GATE="$REPO_ROOT/tools/scripts/ci_symbol_floor_gate.sh"
NODE_AUDIT="$REPO_ROOT/tools/scripts/check_c23_node_binary.sh"

die() { printf 'build_release: REFUSE: %s\n' "$*" >&2; exit 1; }
say() { printf 'build_release: %s\n' "$*" >&2; }

assert_no_docker() {
    command -v docker >/dev/null 2>&1 || return 0
    # Presence is fine; invoking it is not. This script has no docker path.
    return 0
}

write_sha256sums() {
    local dir="$1"
    (
        cd "$dir" || exit 1
        # GNU sha256sum two-space format; sorted so the file is deterministic.
        sha256sum z23 zclassic23 | sort -k2 >SHA256SUMS
    ) || die "could not write SHA256SUMS in $dir"
}

package_from_bin() {
    local bin_dir="$1" out_dir="$2"
    local src=""
    [ -d "$bin_dir" ] || die "binary dir missing: $bin_dir"
    if [ -x "$bin_dir/z23" ]; then
        src="$bin_dir/z23"
    elif [ -x "$bin_dir/zclassic23" ]; then
        src="$bin_dir/zclassic23"
    else
        die "no z23/zclassic23 in $bin_dir — build first: make && make tor-full"
    fi
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64) ;;
        *) die "this packager produces x86_64-linux only (host is $(uname -s)-$(uname -m))" ;;
    esac
    command -v strip >/dev/null 2>&1 || die "strip(1) not found"
    [ -x "$FLOOR_GATE" ] || die "missing $FLOOR_GATE"
    [ -x "$NODE_AUDIT" ] || die "missing $NODE_AUDIT"

    mkdir -p "$out_dir"
    rm -f "$out_dir/z23" "$out_dir/zclassic23" "$out_dir/SHA256SUMS"
    strip --strip-unneeded -o "$out_dir/z23" "$src" || die "strip failed"
    chmod 755 "$out_dir/z23"
    cp -f -- "$out_dir/z23" "$out_dir/zclassic23"
    chmod 755 "$out_dir/zclassic23"
    write_sha256sums "$out_dir"

    ZCL_SYMBOL_FLOOR_BIN="$out_dir/z23" bash "$FLOOR_GATE" \
        || die "stripped z23 exceeds documented glibc/GLIBCXX symbol floor"
    ZCL_C23_MAX_GLIBC=GLIBC_2.38 bash "$NODE_AUDIT" "$out_dir/z23" \
        || die "stripped z23 failed the C23 node ABI audit"
    (cd "$out_dir" && sha256sum -c --strict SHA256SUMS >/dev/null) \
        || die "SHA256SUMS does not match packaged files"
    say "packed $out_dir (z23, zclassic23, SHA256SUMS)"
}

selftest() {
    local tmp rc
    tmp="$(mktemp -d /tmp/zcl-build-release-selftest.XXXXXX)" || die "mktemp failed"
    trap 'rm -rf "$tmp"' EXIT

    # Missing binaries refuse (subshell: die() must not kill the suite).
    mkdir -p "$tmp/empty"
    rc=0
    (package_from_bin "$tmp/empty" "$tmp/out") >/dev/null 2>"$tmp/missing.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: missing-bin must exit 1, got $rc"
    grep -q 'no z23/zclassic23' "$tmp/missing.err" \
        || die "selftest: missing-bin must name the refusal"

    # SHA256SUMS writer: two payload files, then sha256sum -c --strict.
    mkdir -p "$tmp/sums"
    printf 'alpha\n' >"$tmp/sums/z23"
    printf 'alpha\n' >"$tmp/sums/zclassic23"
    write_sha256sums "$tmp/sums"
    [ -s "$tmp/sums/SHA256SUMS" ] || die "selftest: SHA256SUMS empty"
    grep -q '  z23$' "$tmp/sums/SHA256SUMS" || die "selftest: SHA256SUMS missing z23"
    grep -q '  zclassic23$' "$tmp/sums/SHA256SUMS" \
        || die "selftest: SHA256SUMS missing zclassic23"
    (cd "$tmp/sums" && sha256sum -c --strict SHA256SUMS >/dev/null) \
        || die "selftest: SHA256SUMS must verify the files it names"
    printf 'tamper\n' >"$tmp/sums/z23"
    rc=0
    (cd "$tmp/sums" && sha256sum -c --strict SHA256SUMS >/dev/null 2>"$tmp/bad.err") || rc=$?
    [ "$rc" -ne 0 ] || die "selftest: tampered z23 must fail SHA256SUMS"
    say "selftest PASS"
    trap - EXIT
    rm -rf "$tmp"
}

BIN_DIR="$REPO_ROOT/build/bin"
OUT_DIR="$REPO_ROOT/build/release/z23-x86_64-linux"

while [ $# -gt 0 ]; do
    case "$1" in
        --selftest) selftest; exit 0 ;;
        --bin) [ $# -ge 2 ] || die "--bin needs a directory"; BIN_DIR="$2"; shift 2 ;;
        --out) [ $# -ge 2 ] || die "--out needs a directory"; OUT_DIR="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,18p' "$0"
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
done

assert_no_docker
package_from_bin "$BIN_DIR" "$OUT_DIR"
