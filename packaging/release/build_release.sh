#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# build_release.sh — pack stripped runtime binaries + SHA256SUMS.
#
# A stranger must not compile 550K lines of C to run Z23. This script packages
# an already-built node (make && make tor-full) into a directory any node URL
# can later serve. It never invokes docker.
#
# Platforms, and the build that produces each:
#   linux-x86_64     make -j z23 zclassic23-package-verify zclassic23-acme
#                    make tor-full
#   windows-x86_64   VENDOR_TARGET=x86_64-w64-mingw32 \
#                        tools/scripts/build_vendor.sh
#                    make ZCL_TARGET=windows-x86_64 -j z23 zclassic23-acme
#                    (cross-linked on Linux with clang + the mingw-w64
#                     sysroot; see the Makefile's release-target block. There
#                     is no Windows zclassic23-package-verify on purpose --
#                     see release_binaries below.)
# macOS is NOT packaged here and cannot be: a Mach-O needs the macOS SDK,
# which no Linux host may redistribute. See docs/work/BOOTSTRAP_PLAN.md.
#
# Usage:
#   packaging/release/build_release.sh [--bin DIR] [--out DIR] [--platform P]
#   packaging/release/build_release.sh --selftest
#
# Default --bin is <repo>/build/bin; default --out is
# <repo>/build/release/z23-<platform>. Requires every member of that
# platform's set (release_binaries below) to be already built in --bin, all
# for the SAME platform. --platform asserts which one is expected and refuses
# a mismatch; without it the platform is read from the binary. The z23 and
# zclassic23 members are two names for one set of bytes and are produced here
# from the built node, so only the other members must pre-exist.
# Honors the documented glibc/GLIBCXX floor on Linux
# (ci_symbol_floor_gate) and the PE dependency audit on Windows, both through
# check_c23_node_binary. Exit 0 on PASS, 1 on refusal.
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

# What is packaged is decided by the BINARY, not by the machine running this
# script. That used to be the same question -- there was one build path and it
# ran natively -- and it stopped being the same question when the node started
# cross-building for Windows from a Linux host
# (make ZCL_TARGET=windows-x86_64 z23). A host-keyed gate would have refused a
# genuine Windows release for being produced on Linux, and, worse, would have
# handed a Windows release the Linux ELF/glibc audits, which pass vacuously on
# a PE. So: read the format, name the platform, and run that platform's audits.
#
# platform_of_binary echoes a release platform name, or nothing when the
# format is one this packager has no release contract for.
platform_of_binary() {
    local format
    command -v objdump >/dev/null 2>&1 || return 1
    format="$(objdump -f "$1" 2>/dev/null | sed -n 's/^.*file format //p' | head -1)"
    case "$format" in
        elf64-x86-64) printf 'linux-x86_64' ;;
        pei-x86-64) printf 'windows-x86_64' ;;
        *) return 1 ;;
    esac
}

# Split out from the call site so the refusal message can be selftested on any
# host: package_from_bin cannot be run to completion for an unsupported
# platform to observe its own message, because it also cannot produce a
# package there.
platform_supported() {
    case "$1" in
        linux-x86_64|windows-x86_64) return 0 ;;
        *) return 1 ;;
    esac
}

# The executable-name suffix for a platform. A Windows release member is
# z23.exe, not z23: a PE named without .exe is not runnable by the shell that
# installs it, and SHA256SUMS names exactly the files that ship.
platform_exe_suffix() {
    case "$1" in
        windows-x86_64) printf '.exe' ;;
        *) printf '' ;;
    esac
}

platform_strip() {
    case "$1" in
        windows-x86_64) printf 'x86_64-w64-mingw32-strip' ;;
        *) printf 'strip' ;;
    esac
}

# The EXACT closed set of executables a release for this platform ships, in
# the order they are produced. Closedness is the whole point -- it is what
# makes "sha256sum -c --strict SHA256SUMS" a complete statement about every
# byte in the release directory rather than a partial one -- so this is a
# written-out list per platform and NEVER a glob or a filter over what happens
# to be on disk. AGENT_CARD.md is added to every set by write_sha256sums.
#
# The sets differ by exactly one member, and for a stated reason:
# zclassic23-package-verify is the confined worker that compiles and executes
# downloaded package code. It is safe only because it confines each child with
# seccomp, Landlock and POSIX rlimits, and Windows has none of those in this
# tree. Shipping an unconfined binary under that name would be a false safety
# claim, so the Makefile refuses to build it for Windows and the Windows
# release does not carry it. The node itself is complete either way: the
# verifier is the C23 Commons reproduction worker, not part of the node.
release_binaries() {
    case "$1" in
        linux-x86_64)
            printf '%s\n' z23 zclassic23 zclassic23-package-verify zclassic23-acme
            ;;
        windows-x86_64)
            printf '%s\n' z23.exe zclassic23.exe zclassic23-acme.exe
            ;;
        *) return 1 ;;
    esac
}

platform_refusal() {
    local what="$1"
    cat >&2 <<EOF
build_release: REFUSE: no release contract for $what.

Packaged today:
  - linux-x86_64    (native build:  make z23 && make tor-full)
  - windows-x86_64  (cross build:   make ZCL_TARGET=windows-x86_64 z23)

Not packaged yet:
  - macOS (any architecture)

What has to land first for macOS (docs/work/BOOTSTRAP_PLAN.md, "Platform work"):
  - a Darwin build of the node produced on a Mac. The node already builds
    natively there (AGENTS.md, "Verified platform baseline"), but no Linux
    host can produce a Mach-O: it needs the macOS SDK, which is not
    redistributable, so there is nothing here to strip and package.
  - the per-file strip/audit/checksum steps below are already
    platform-generic; what a Mac worker has to run is written out in
    docs/work/BOOTSTRAP_PLAN.md.
  - the installer (tools/scripts/install_z23.sh) and the domain-side
    checksum agreement do not need to change first — they already accept
    any node URL as a source and verify bytes independent of the mirror

Nothing was packaged.
EOF
}

write_sha256sums() {
    local dir="$1" platform="${2:-linux-x86_64}"
    # AGENT_CARD.md is a manifest member, not an optional extra: the card
    # tells a coding assistant which commands to run against the node, so
    # a tampered copy is an instruction-injection path into whatever agent
    # installs it, not merely stale prose. zclassic23-acme is a manifest
    # member because it is the ONLY binary that can renew a certificate a
    # node obtains -- shipping a release that can get a certificate but
    # never installs the tool that renews it is exactly the silent-failure
    # bug this file exists to not reintroduce. The executable names come from
    # release_binaries above: an exact closed per-platform list, never a glob,
    # because closedness is what makes "sha256sum -c --strict SHA256SUMS" a
    # complete statement about every byte in the release directory rather than
    # a partial one. AGENT_CARD.md is on every platform's list.
    local members
    members="$(release_binaries "$platform")" \
        || die "no release member set for platform $platform"
    (
        cd "$dir" || exit 1
        # GNU sha256sum two-space format; sorted so the file is deterministic.
        # shellcheck disable=SC2086
        sha256sum $members AGENT_CARD.md | sort -k2 >SHA256SUMS
    ) || die "could not write SHA256SUMS in $dir"
}

# AGENT_CARD.md tells a coding assistant which commands to run against
# this node. That makes it closer to executable content than to prose: a
# tampered card is an instruction-injection path into whatever agent
# installs it. It IS a SHA256SUMS member (see write_sha256sums above) and
# it is mandatory, not best-effort -- a release missing its card is a
# release that cannot honestly claim every shipped byte is checked, so
# packaging refuses rather than silently shipping checksummed files and
# an unchecked one.
#
# tools/scripts/install_z23.sh and tools/scripts/deploy_z23_release.sh
# hard-require SHA256SUMS to name exactly z23, zclassic23,
# zclassic23-package-verify, zclassic23-acme, and AGENT_CARD.md (five
# names, in independent checks in each file). Keep all three in agreement:
# a name added or dropped here without the same change in both of those
# files reopens the exact "release member silently missing" bug class this
# script's own selftest below is built to catch.
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
    local bin_dir="$1" out_dir="$2" want_platform="${3-}"
    local src="" exe="" platform="" strip_tool="" members="" member="" source_name="" candidate=""
    [ -d "$bin_dir" ] || die "binary dir missing: $bin_dir"
    # The node name carries the platform's own executable suffix, so finding
    # the node also decides which suffix the whole member set uses. One
    # build/bin can hold BOTH a host node and a cross-built one -- that is the
    # normal state of a checkout that has produced two releases -- so with
    # --platform look only for that platform's name, and without it refuse an
    # ambiguous directory rather than pick one and be silently wrong.
    if [ -n "$want_platform" ]; then
        exe="$(platform_exe_suffix "$want_platform")"
        if [ -f "$bin_dir/z23$exe" ]; then
            src="$bin_dir/z23$exe"
        elif [ -f "$bin_dir/zclassic23$exe" ]; then
            src="$bin_dir/zclassic23$exe"
        else
            die "no z23$exe/zclassic23$exe in $bin_dir for $want_platform"
        fi
    else
        for candidate in z23 z23.exe zclassic23 zclassic23.exe; do
            [ -f "$bin_dir/$candidate" ] || continue
            case "$candidate" in *.exe) exe=".exe" ;; *) exe="" ;; esac
            if [ -n "$src" ]; then
                case "$src" in
                    *.exe) [ "$exe" = ".exe" ] || die "$bin_dir holds nodes for more than one platform — pass --platform" ;;
                    *) [ -z "$exe" ] || die "$bin_dir holds nodes for more than one platform — pass --platform" ;;
                esac
                continue
            fi
            src="$bin_dir/$candidate"
        done
        [ -n "$src" ] \
            || die "no z23/zclassic23 in $bin_dir — build first: make && make tor-full"
        case "$src" in *.exe) exe=".exe" ;; *) exe="" ;; esac
    fi
    # Ask the binary what it is. See platform_of_binary above for why this is
    # not `uname`.
    platform="$(platform_of_binary "$src")" || platform=""
    [ -n "$platform" ] \
        || { platform_refusal "the object format of $src"; exit 1; }
    platform_supported "$platform" \
        || { platform_refusal "$platform"; exit 1; }
    if [ -n "$want_platform" ] && [ "$want_platform" != "$platform" ]; then
        die "--platform $want_platform requested but $src is $platform"
    fi
    [ "$exe" = "$(platform_exe_suffix "$platform")" ] \
        || die "$src is $platform but is named with suffix '$exe'"

    members="$(release_binaries "$platform")" \
        || die "no release member set for platform $platform"
    # Every member except the z23/zclassic23 pair must already exist as a
    # built binary: this script strips and checksums, it never builds.
    for member in $members; do
        case "$member" in
            "z23$exe"|"zclassic23$exe") continue ;;
        esac
        source_name="${member%$exe}"
        [ -f "$bin_dir/$member" ] \
            || die "no $member in $bin_dir — build first: make $source_name"
    done

    strip_tool="$(platform_strip "$platform")"
    command -v "$strip_tool" >/dev/null 2>&1 || die "$strip_tool not found"
    [ -x "$FLOOR_GATE" ] || die "missing $FLOOR_GATE"
    [ -x "$NODE_AUDIT" ] || die "missing $NODE_AUDIT"

    mkdir -p "$out_dir"
    for member in $members; do rm -f "$out_dir/$member"; done
    rm -f "$out_dir/AGENT_CARD.md" "$out_dir/SHA256SUMS"
    "$strip_tool" --strip-unneeded -o "$out_dir/z23$exe" "$src" || die "strip failed"
    chmod 755 "$out_dir/z23$exe"
    link_or_copy "$out_dir/z23$exe" "$out_dir/zclassic23$exe"
    chmod 755 "$out_dir/zclassic23$exe"
    for member in $members; do
        case "$member" in
            "z23$exe"|"zclassic23$exe") continue ;;
        esac
        "$strip_tool" --strip-unneeded -o "$out_dir/$member" "$bin_dir/$member" \
            || die "strip failed for $member"
        chmod 755 "$out_dir/$member"
    done
    copy_agent_card "$out_dir"
    write_sha256sums "$out_dir" "$platform"

    # The glibc/GLIBCXX symbol floor is an ELF question and has no meaning for
    # a PE. Running it on one would not fail -- it would pass having graded
    # nothing, which is the shape of false green this repository keeps paying
    # for. check_c23_node_binary.sh below reads the artifact's own format and
    # applies that platform's dependency audit (Windows: system DLLs only), so
    # every platform is graded by something.
    case "$platform" in
        linux-x86_64)
            ZCL_SYMBOL_FLOOR_BIN="$out_dir/z23" bash "$FLOOR_GATE" \
                || die "stripped z23 exceeds documented glibc/GLIBCXX symbol floor"
            ZCL_C23_MAX_GLIBC=GLIBC_2.38 bash "$NODE_AUDIT" "$out_dir/z23" \
                || die "stripped z23 failed the C23 node ABI audit"
            ;;
        *)
            bash "$NODE_AUDIT" "$out_dir/z23$exe" \
                || die "stripped z23$exe failed the C23 node ABI audit"
            ;;
    esac
    (cd "$out_dir" && sha256sum -c --strict SHA256SUMS >/dev/null) \
        || die "SHA256SUMS does not match packaged files"

    say "packed $out_dir for $platform ($(printf '%s, ' $members)AGENT_CARD.md, SHA256SUMS)"
}

selftest() {
    local tmp rc name
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
    #
    # The stand-in node is a REAL executable of this platform, copied from
    # PATH, not a shell script: which members a release must carry is decided
    # per platform now, so the fixture has to be something platform_of_binary
    # can actually classify. A script would be refused for its format and this
    # case would stop grading what it says it grades.
    mkdir -p "$tmp/no-verifier"
    cp -f -- "$(command -v sha256sum)" "$tmp/no-verifier/z23"
    chmod 755 "$tmp/no-verifier/z23"
    rc=0
    (package_from_bin "$tmp/no-verifier" "$tmp/out") \
        >/dev/null 2>"$tmp/verifier.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: missing verifier must exit 1, got $rc"
    grep -q 'no zclassic23-package-verify' "$tmp/verifier.err" \
        || die "selftest: missing verifier must name the refusal"

    # A release without the certificate renewal worker is the exact bug this
    # task closes: a node that can obtain a certificate but ships with no
    # way to ever renew it. This refusal occurs before strip/audit work too.
    mkdir -p "$tmp/no-acme"
    cp -f -- "$(command -v sha256sum)" "$tmp/no-acme/z23"
    chmod 755 "$tmp/no-acme/z23"
    cp -f -- "$(command -v sha256sum)" "$tmp/no-acme/zclassic23-package-verify"
    chmod 755 "$tmp/no-acme/zclassic23-package-verify"
    rc=0
    (package_from_bin "$tmp/no-acme" "$tmp/out") \
        >/dev/null 2>"$tmp/acme.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: missing zclassic23-acme must exit 1, got $rc"
    grep -q 'no zclassic23-acme' "$tmp/acme.err" \
        || die "selftest: missing zclassic23-acme must name the refusal"

    # An unsupported platform must refuse informatively, not just die. The
    # refusal path cannot be observed by running package_from_bin for real
    # here -- this checkout has no Mach-O to hand it -- so exercise the same
    # two functions package_from_bin calls, directly.
    rc=0
    platform_supported "darwin-arm64" && rc=1
    [ "$rc" -eq 0 ] || die "selftest: platform_supported must reject darwin-arm64"
    platform_supported "linux-x86_64" \
        || die "selftest: platform_supported must accept linux-x86_64"
    platform_supported "windows-x86_64" \
        || die "selftest: platform_supported must accept windows-x86_64"
    platform_refusal "darwin-arm64" >"$tmp/darwin.err" 2>&1 || true
    grep -q 'linux-x86_64' "$tmp/darwin.err" \
        || die "selftest: platform refusal must name what IS packaged"
    grep -q 'windows-x86_64' "$tmp/darwin.err" \
        || die "selftest: platform refusal must name what IS packaged"
    grep -q 'macOS' "$tmp/darwin.err" \
        || die "selftest: platform refusal must name macOS as not yet packaged"
    grep -q 'BOOTSTRAP_PLAN' "$tmp/darwin.err" \
        || die "selftest: platform refusal must point at the plan for what lands first"
    grep -qi 'darwin-arm64' "$tmp/darwin.err" \
        || die "selftest: platform refusal must name the thing refused"

    # Naming a platform is not the same as recognising one. platform_of_binary
    # is what actually decides which audits a release gets, so grade it on
    # real files rather than on strings: the ELF this suite is running from
    # (any executable on PATH), and a PE built here if a cross toolchain is
    # present. A wrong answer here is the silent kind -- a PE graded by the
    # ELF/glibc branch passes having checked nothing.
    [ "$(platform_of_binary "$(command -v sha256sum)")" = "linux-x86_64" ] \
        || die "selftest: platform_of_binary must recognise a Linux ELF"
    rc=0
    platform_of_binary "$SCRIPT_DIR/build_release.sh" >/dev/null 2>&1 && rc=1
    [ "$rc" -eq 0 ] \
        || die "selftest: platform_of_binary must refuse a non-object file"
    if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
        printf 'int main(void){return 0;}\n' >"$tmp/pe.c"
        if x86_64-w64-mingw32-gcc -o "$tmp/pe.exe" "$tmp/pe.c" 2>/dev/null; then
            [ "$(platform_of_binary "$tmp/pe.exe")" = "windows-x86_64" ] \
                || die "selftest: platform_of_binary must recognise an x86-64 PE"
            [ "$(platform_exe_suffix "$(platform_of_binary "$tmp/pe.exe")")" = ".exe" ] \
                || die "selftest: a windows-x86_64 release must use the .exe suffix"
        fi
    else
        say "selftest: no mingw toolchain here; PE recognition UNOBSERVED (not a pass)"
    fi
    [ -z "$(platform_exe_suffix linux-x86_64)" ] \
        || die "selftest: a linux-x86_64 release must use no suffix"

    # The member sets are the manifest contract. Assert each one exactly --
    # a set that silently grew or shrank is a SHA256SUMS that stopped being a
    # complete statement about the release directory.
    [ "$(release_binaries linux-x86_64 | tr '\n' ' ')" \
        = "z23 zclassic23 zclassic23-package-verify zclassic23-acme " ] \
        || die "selftest: the linux-x86_64 member set changed"
    [ "$(release_binaries windows-x86_64 | tr '\n' ' ')" \
        = "z23.exe zclassic23.exe zclassic23-acme.exe " ] \
        || die "selftest: the windows-x86_64 member set changed"
    rc=0
    release_binaries darwin-arm64 >/dev/null 2>&1 && rc=1
    [ "$rc" -eq 0 ] \
        || die "selftest: release_binaries must have no set for an unpackaged platform"
    # Every member name must carry the platform's suffix, or SHA256SUMS names
    # files the platform cannot run.
    for name in $(release_binaries windows-x86_64); do
        case "$name" in *.exe) ;; *) die "selftest: Windows member $name lacks .exe" ;; esac
    done
    for name in $(release_binaries linux-x86_64); do
        case "$name" in *.exe) die "selftest: Linux member $name carries .exe" ;; esac
    done

    # SHA256SUMS writer: the complete five-file manifest -- z23, zclassic23,
    # zclassic23-package-verify, zclassic23-acme, AGENT_CARD.md -- then
    # strict verification. AGENT_CARD.md sits on the same footing as the
    # binaries here: it is the file a coding assistant reads to learn which
    # commands to run against the node, so it must fail exactly like a
    # tampered binary fails, not be treated as an afterthought.
    mkdir -p "$tmp/sums"
    printf 'alpha\n' >"$tmp/sums/z23"
    printf 'alpha\n' >"$tmp/sums/zclassic23"
    printf 'verifier\n' >"$tmp/sums/zclassic23-package-verify"
    printf 'acme\n' >"$tmp/sums/zclassic23-acme"
    printf 'card\n' >"$tmp/sums/AGENT_CARD.md"
    write_sha256sums "$tmp/sums"
    [ -s "$tmp/sums/SHA256SUMS" ] || die "selftest: SHA256SUMS empty"
    [ "$(wc -l <"$tmp/sums/SHA256SUMS")" -eq 5 ] \
        || die "selftest: SHA256SUMS must name exactly five files, not more or fewer"
    grep -q '  z23$' "$tmp/sums/SHA256SUMS" || die "selftest: SHA256SUMS missing z23"
    grep -q '  zclassic23$' "$tmp/sums/SHA256SUMS" \
        || die "selftest: SHA256SUMS missing zclassic23"
    grep -q '  zclassic23-package-verify$' "$tmp/sums/SHA256SUMS" \
        || die "selftest: SHA256SUMS missing zclassic23-package-verify"
    grep -q '  zclassic23-acme$' "$tmp/sums/SHA256SUMS" \
        || die "selftest: SHA256SUMS missing zclassic23-acme"
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
    # independent, individually-verifiable lines for every one of the five
    # names — not a shortcut just because two of them share storage.
    printf 'verifier\n' >"$tmp/link/zclassic23-package-verify"
    printf 'acme\n' >"$tmp/link/zclassic23-acme"
    printf 'card\n' >"$tmp/link/AGENT_CARD.md"
    write_sha256sums "$tmp/link"
    [ "$(wc -l <"$tmp/link/SHA256SUMS")" -eq 5 ] \
        || die "selftest: hardlinked pair did not still produce a five-line SHA256SUMS"
    (cd "$tmp/link" && sha256sum -c --strict SHA256SUMS >/dev/null) \
        || die "selftest: SHA256SUMS must verify a hardlinked pair too"

    # copy_agent_card: now a required, checksummed manifest member (see
    # write_sha256sums above), so it must FAIL CLOSED when the card is
    # missing rather than silently packaging the other checksummed files
    # and skipping this one, and must copy the real bytes when present.
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
OUT_DIR=""
WANT_PLATFORM=""

while [ $# -gt 0 ]; do
    case "$1" in
        --selftest) selftest; exit 0 ;;
        --bin) [ $# -ge 2 ] || die "--bin needs a directory"; BIN_DIR="$2"; shift 2 ;;
        --out) [ $# -ge 2 ] || die "--out needs a directory"; OUT_DIR="$2"; shift 2 ;;
        --platform)
            [ $# -ge 2 ] || die "--platform needs a name"
            WANT_PLATFORM="$2"
            platform_supported "$WANT_PLATFORM" \
                || { platform_refusal "$WANT_PLATFORM"; exit 1; }
            shift 2
            ;;
        -h|--help)
            sed -n '2,22p' "$0"
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
done

# --out defaults per platform, so packaging two targets from one checkout
# cannot silently overwrite the first with the second. The platform is read
# from the binary that is about to be packaged; package_from_bin repeats the
# read and is the authority, this only picks a directory name.
if [ -z "$OUT_DIR" ]; then
    default_platform="$WANT_PLATFORM"
    if [ -z "$default_platform" ]; then
        for candidate in z23 z23.exe zclassic23 zclassic23.exe; do
            [ -f "$BIN_DIR/$candidate" ] || continue
            default_platform="$(platform_of_binary "$BIN_DIR/$candidate")" \
                || default_platform=""
            [ -n "$default_platform" ] && break
        done
    fi
    [ -n "$default_platform" ] \
        || die "cannot tell what platform $BIN_DIR holds — pass --platform or --out"
    OUT_DIR="$REPO_ROOT/build/release/z23-$default_platform"
fi

assert_no_docker
package_from_bin "$BIN_DIR" "$OUT_DIR" "$WANT_PLATFORM"
