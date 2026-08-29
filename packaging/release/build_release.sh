#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# build_release.sh — pack stripped x86_64-linux runtime binaries + SHA256SUMS.
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
# <repo>/build/release/z23-x86_64-linux. Requires z23 or zclassic23 and the
# confined zclassic23-package-verify worker in --bin.
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

# platform_supported / platform_refusal are split out from the call site so
# the refusal message can be selftested on any host, including the
# Linux-x86_64 host that is the only one that can ever reach this refusal
# for real: package_from_bin cannot be run to completion on an unsupported
# platform to observe its own message, because it also cannot produce a
# package there.
platform_supported() {
    case "$1" in
        Linux-x86_64) return 0 ;;
        *) return 1 ;;
    esac
}

platform_refusal() {
    local host="$1"
    cat >&2 <<EOF
build_release: REFUSE: this packager produces Linux-x86_64 runtime binaries only (host is $host).

Published today:
  - Linux-x86_64 (this script)

Not published yet:
  - macOS (any architecture)
  - Windows (any architecture)

What has to land first (docs/work/BOOTSTRAP_PLAN.md, "Order of work" item 3):
  - a working macOS build and a working Windows build of the node itself —
    neither exists in this tree yet, so there is nothing here to strip and
    package for those hosts
  - once a build exists, packaging it is the easy part: this script's
    per-file strip/audit/checksum steps are already platform-generic; only
    the platform gate above and the missing build are in the way
  - the installer (tools/scripts/install_z23.sh) and the domain-side
    checksum agreement do not need to change first — they already accept
    any node URL as a source and verify bytes independent of the mirror

Nothing was packaged. Build on a Linux-x86_64 host to produce a release
today.
EOF
}

write_sha256sums() {
    local dir="$1"
    # AGENT_CARD.md is a manifest member, not an optional extra: the card
    # tells a coding assistant which commands to run against the node, so
    # a tampered copy is an instruction-injection path into whatever agent
    # installs it, not merely stale prose. This list is an exact closed
    # set of four names -- never a glob -- because closedness is what
    # makes "sha256sum -c --strict SHA256SUMS" a complete statement about
    # every byte in the release directory, not a partial one.
    (
        cd "$dir" || exit 1
        # GNU sha256sum two-space format; sorted so the file is deterministic.
        sha256sum z23 zclassic23 zclassic23-package-verify AGENT_CARD.md \
            | sort -k2 >SHA256SUMS
    ) || die "could not write SHA256SUMS in $dir"
}

# AGENT_CARD.md tells a coding assistant which commands to run against
# this node. That makes it closer to executable content than to prose: a
# tampered card is an instruction-injection path into whatever agent
# installs it. It IS a SHA256SUMS member (see write_sha256sums above) and
# it is mandatory, not best-effort -- a release missing its card is a
# release that cannot honestly claim every shipped byte is checked, so
# packaging refuses rather than silently shipping three checksummed files
# and a fourth unchecked one.
#
# tools/scripts/install_z23.sh and tools/scripts/deploy_z23_release.sh
# currently hard-require SHA256SUMS to name exactly z23, zclassic23, and
# zclassic23-package-verify (three names, twice each, in independent
# checks). Both need a small, deliberately-still-closed-set
# update to accept AGENT_CARD.md as a fourth required name before a
# release built by this script can be installed or fleet-deployed. That
# change is out of scope for this file (another lane owns both).
copy_agent_card() {
    local out_dir="$1"
    [ -f "$SCRIPT_DIR/AGENT_CARD.md" ] \
        || die "missing $SCRIPT_DIR/AGENT_CARD.md -- required SHA256SUMS member"
    cp -f -- "$SCRIPT_DIR/AGENT_CARD.md" "$out_dir/AGENT_CARD.md"
}

# zclassic23 is required to exist as its own real, independently readable
# file (the legacy daemon name systemd starts and re-execs; see
# tools/scripts/deploy_z23_release.sh's exact-PID/exact-path qualification)
# and it is always byte-identical to z23, because both come from stripping
# the exact same source binary. A hardlink gives both names the same inode:
# every reader (sha256sum, install(1), a running process's argv[0]/
# /proc/self/exe) sees a completely ordinary regular file with the recorded
# bytes — nothing here is an alias or a symlink a verifier could be fooled
# by, so SHA256SUMS keeps its normal two independent lines and
# `sha256sum -c --strict` keeps verifying both names against real file
# content, not a shortcut. The only observable difference is storage: the
# release directory holds the payload once instead of twice, and (because
# GNU tar recognizes same-device/same-inode members and archives the second
# occurrence as a hardlink record instead of a second copy of the data)
# deploy_z23_release.sh's `tar | ssh | tar` fleet transfer sends the payload
# once per host instead of twice.
#
# This does NOT shrink the public curl|sh download: install_z23.sh fetches
# z23 and zclassic23 as two separate HTTP GETs, and a plain static file
# server streams full bytes for each URL regardless of whether the files
# share an inode on its filesystem — HTTP has no concept of a hardlink.
# Fixing that would require install_z23.sh itself to notice the two
# published digests already match and fetch once, which is out of scope
# here (another lane owns that file).
#
# ln can fail across filesystem boundaries or on filesystems without hard
# link support; a plain copy is always a correct fallback, never a silent
# loss of verification.
link_or_copy() {
    local src="$1" dst="$2"
    rm -f -- "$dst"
    ln -f -- "$src" "$dst" 2>/dev/null || cp -f -- "$src" "$dst"
}

package_from_bin() {
    local bin_dir="$1" out_dir="$2"
    local src="" verifier_src="$bin_dir/zclassic23-package-verify"
    [ -d "$bin_dir" ] || die "binary dir missing: $bin_dir"
    if [ -x "$bin_dir/z23" ]; then
        src="$bin_dir/z23"
    elif [ -x "$bin_dir/zclassic23" ]; then
        src="$bin_dir/zclassic23"
    else
        die "no z23/zclassic23 in $bin_dir — build first: make && make tor-full"
    fi
    [ -x "$verifier_src" ] \
        || die "no zclassic23-package-verify in $bin_dir — build first: make zclassic23-package-verify"
    platform_supported "$(uname -s)-$(uname -m)" \
        || { platform_refusal "$(uname -s)-$(uname -m)"; exit 1; }
    command -v strip >/dev/null 2>&1 || die "strip(1) not found"
    [ -x "$FLOOR_GATE" ] || die "missing $FLOOR_GATE"
    [ -x "$NODE_AUDIT" ] || die "missing $NODE_AUDIT"

    mkdir -p "$out_dir"
    rm -f "$out_dir/z23" "$out_dir/zclassic23" \
        "$out_dir/zclassic23-package-verify" "$out_dir/AGENT_CARD.md" \
        "$out_dir/SHA256SUMS"
    strip --strip-unneeded -o "$out_dir/z23" "$src" || die "strip failed"
    chmod 755 "$out_dir/z23"
    link_or_copy "$out_dir/z23" "$out_dir/zclassic23"
    chmod 755 "$out_dir/zclassic23"
    strip --strip-unneeded -o "$out_dir/zclassic23-package-verify" "$verifier_src" \
        || die "strip failed for zclassic23-package-verify"
    chmod 755 "$out_dir/zclassic23-package-verify"
    copy_agent_card "$out_dir"
    write_sha256sums "$out_dir"

    ZCL_SYMBOL_FLOOR_BIN="$out_dir/z23" bash "$FLOOR_GATE" \
        || die "stripped z23 exceeds documented glibc/GLIBCXX symbol floor"
    ZCL_C23_MAX_GLIBC=GLIBC_2.38 bash "$NODE_AUDIT" "$out_dir/z23" \
        || die "stripped z23 failed the C23 node ABI audit"
    (cd "$out_dir" && sha256sum -c --strict SHA256SUMS >/dev/null) \
        || die "SHA256SUMS does not match packaged files"

    say "packed $out_dir (z23, zclassic23, zclassic23-package-verify, SHA256SUMS, AGENT_CARD.md)"
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

    # A daemon without its confined reproduction worker is not a complete
    # runtime artifact set. This refusal occurs before strip/audit work.
    mkdir -p "$tmp/no-verifier"
    printf '#!/bin/sh\nexit 0\n' >"$tmp/no-verifier/z23"
    chmod 755 "$tmp/no-verifier/z23"
    rc=0
    (package_from_bin "$tmp/no-verifier" "$tmp/out") \
        >/dev/null 2>"$tmp/verifier.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: missing verifier must exit 1, got $rc"
    grep -q 'no zclassic23-package-verify' "$tmp/verifier.err" \
        || die "selftest: missing verifier must name the refusal"

    # An unsupported platform must refuse informatively, not just die. This
    # host is presumably the one supported platform (Linux-x86_64), so the
    # refusal path cannot be observed by actually running package_from_bin
    # here; test the message-generating function directly with a fake host
    # string instead — the same function package_from_bin calls for real.
    rc=0
    platform_supported "Darwin-arm64" && rc=1
    [ "$rc" -eq 0 ] || die "selftest: platform_supported must reject Darwin-arm64"
    platform_supported "Linux-x86_64" \
        || die "selftest: platform_supported must accept Linux-x86_64"
    platform_refusal "Darwin-arm64" >"$tmp/darwin.err" 2>&1 || true
    grep -q 'Linux-x86_64' "$tmp/darwin.err" \
        || die "selftest: platform refusal must name what IS published"
    grep -q 'macOS' "$tmp/darwin.err" \
        || die "selftest: platform refusal must name macOS as not yet published"
    grep -q 'Windows' "$tmp/darwin.err" \
        || die "selftest: platform refusal must name Windows as not yet published"
    grep -q 'BOOTSTRAP_PLAN' "$tmp/darwin.err" \
        || die "selftest: platform refusal must point at the plan for what lands first"
    grep -qi 'Darwin-arm64' "$tmp/darwin.err" \
        || die "selftest: platform refusal must name the actual host"

    # SHA256SUMS writer: the complete four-file manifest -- z23, zclassic23,
    # zclassic23-package-verify, AGENT_CARD.md -- then strict verification.
    # AGENT_CARD.md sits on the same footing as the binaries here: it is
    # the file a coding assistant reads to learn which commands to run
    # against the node, so it must fail exactly like a tampered binary
    # fails, not be treated as an afterthought.
    mkdir -p "$tmp/sums"
    printf 'alpha\n' >"$tmp/sums/z23"
    printf 'alpha\n' >"$tmp/sums/zclassic23"
    printf 'verifier\n' >"$tmp/sums/zclassic23-package-verify"
    printf 'card\n' >"$tmp/sums/AGENT_CARD.md"
    write_sha256sums "$tmp/sums"
    [ -s "$tmp/sums/SHA256SUMS" ] || die "selftest: SHA256SUMS empty"
    [ "$(wc -l <"$tmp/sums/SHA256SUMS")" -eq 4 ] \
        || die "selftest: SHA256SUMS must name exactly four files, not more or fewer"
    grep -q '  z23$' "$tmp/sums/SHA256SUMS" || die "selftest: SHA256SUMS missing z23"
    grep -q '  zclassic23$' "$tmp/sums/SHA256SUMS" \
        || die "selftest: SHA256SUMS missing zclassic23"
    grep -q '  zclassic23-package-verify$' "$tmp/sums/SHA256SUMS" \
        || die "selftest: SHA256SUMS missing zclassic23-package-verify"
    grep -q '  AGENT_CARD.md$' "$tmp/sums/SHA256SUMS" \
        || die "selftest: SHA256SUMS missing AGENT_CARD.md"
    (cd "$tmp/sums" && sha256sum -c --strict SHA256SUMS >/dev/null) \
        || die "selftest: SHA256SUMS must verify the files it names"
    printf 'tamper\n' >"$tmp/sums/z23"
    rc=0
    (cd "$tmp/sums" && sha256sum -c --strict SHA256SUMS >/dev/null 2>"$tmp/bad.err") || rc=$?
    [ "$rc" -ne 0 ] || die "selftest: tampered z23 must fail SHA256SUMS"
    printf 'alpha\n' >"$tmp/sums/z23"
    (cd "$tmp/sums" && sha256sum -c --strict SHA256SUMS >/dev/null) \
        || die "selftest: restored z23 must pass SHA256SUMS again"

    # AGENT_CARD.md tamper round-trip, proven explicitly and in both
    # directions (the coordinator asked to see both): this is the exact
    # property that makes it safe to ship the card at all. A single
    # mutated byte in the file an assistant reads for its own next
    # commands must be caught by --strict, and restoring the original
    # bytes must make the manifest pass again, the same as any binary.
    rc=0
    (cd "$tmp/sums" && sha256sum -c --strict SHA256SUMS >/dev/null 2>"$tmp/precard.err") \
        || rc=$?
    [ "$rc" -eq 0 ] || die "selftest: SHA256SUMS must pass before the card-tamper probe"
    printf 'TAMPERED-CARD-BYTES\n' >"$tmp/sums/AGENT_CARD.md"
    rc=0
    (cd "$tmp/sums" && sha256sum -c --strict SHA256SUMS \
        >"$tmp/card-tamper.out" 2>"$tmp/card-tamper.err") || rc=$?
    [ "$rc" -ne 0 ] || die "selftest: tampered AGENT_CARD.md must fail SHA256SUMS (direction 1 of 2)"
    grep -q 'AGENT_CARD.md: FAILED' "$tmp/card-tamper.out" \
        || die "selftest: SHA256SUMS failure must name AGENT_CARD.md, not just fail generically"
    printf 'card\n' >"$tmp/sums/AGENT_CARD.md"
    (cd "$tmp/sums" && sha256sum -c --strict SHA256SUMS >/dev/null) \
        || die "selftest: restored AGENT_CARD.md must pass SHA256SUMS again (direction 2 of 2)"

    # link_or_copy: zclassic23 must land as a real, independently readable,
    # correctly hashing file either way — the difference is only whether it
    # shares storage with z23 (same inode, so the release directory holds
    # the payload once and a tar transfer dedups it) or not.
    mkdir -p "$tmp/link"
    printf 'payload-bytes\n' >"$tmp/link/z23"
    link_or_copy "$tmp/link/z23" "$tmp/link/zclassic23"
    [ -f "$tmp/link/zclassic23" ] || die "selftest: link_or_copy produced no file"
    cmp -s "$tmp/link/z23" "$tmp/link/zclassic23" \
        || die "selftest: link_or_copy result has different bytes than the source"
    [ "$(sha256sum <"$tmp/link/z23" | awk '{print $1}')" \
        = "$(sha256sum <"$tmp/link/zclassic23" | awk '{print $1}')" ] \
        || die "selftest: link_or_copy result hashes differently than the source"
    if [ "$(stat -c %i "$tmp/link/z23")" = "$(stat -c %i "$tmp/link/zclassic23")" ]; then
        [ "$(stat -c %h "$tmp/link/z23")" -ge 2 ] \
            || die "selftest: same inode but link count did not increase"
    else
        say "selftest: link_or_copy fell back to a copy on this filesystem (still correct)"
    fi
    # Re-running write_sha256sums over a hardlinked pair must still record
    # independent, individually-verifiable lines for every one of the four
    # names — not a shortcut just because two of them share storage.
    printf 'verifier\n' >"$tmp/link/zclassic23-package-verify"
    printf 'card\n' >"$tmp/link/AGENT_CARD.md"
    write_sha256sums "$tmp/link"
    [ "$(wc -l <"$tmp/link/SHA256SUMS")" -eq 4 ] \
        || die "selftest: hardlinked pair did not still produce a four-line SHA256SUMS"
    (cd "$tmp/link" && sha256sum -c --strict SHA256SUMS >/dev/null) \
        || die "selftest: SHA256SUMS must verify a hardlinked pair too"

    # copy_agent_card: now a required, checksummed manifest member (see
    # write_sha256sums above), so it must FAIL CLOSED when the card is
    # missing rather than silently packaging three checksummed files and
    # skipping the fourth, and must copy the real bytes when present.
    mkdir -p "$tmp/card/nocard" "$tmp/card/withcard"
    rc=0
    ( SCRIPT_DIR="$tmp/card/nocard" copy_agent_card "$tmp/card/nocard" ) \
        >/dev/null 2>"$tmp/nocard.err" || rc=$?
    [ "$rc" -ne 0 ] || die "selftest: copy_agent_card must fail when the card is absent"
    grep -q 'AGENT_CARD.md' "$tmp/nocard.err" \
        || die "selftest: missing-card refusal must name the missing file"
    [ ! -e "$tmp/card/nocard/AGENT_CARD.md" ] \
        || die "selftest: copy_agent_card invented a file that was never there"
    mkdir -p "$tmp/card/srcdir"
    printf '# card\n' >"$tmp/card/srcdir/AGENT_CARD.md"
    ( SCRIPT_DIR="$tmp/card/srcdir" copy_agent_card "$tmp/card/withcard" )
    cmp -s "$tmp/card/srcdir/AGENT_CARD.md" "$tmp/card/withcard/AGENT_CARD.md" \
        || die "selftest: copy_agent_card did not copy the real card bytes"

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
