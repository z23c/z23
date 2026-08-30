#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_published_platforms.sh — every platform the install path CLAIMS must
# be one the release process actually produces.
#
# THE FAILURE THIS PREVENTS, precisely. A stranger runs
# `curl https://z23.sh | sh`. The shim names their machine, looks it up in its
# published table, and either refuses by name or fetches
# <origin>/bootstrap/<triple>/z23-bootstrap. A name in that table with nothing
# behind it does not degrade gracefully: it converts an honest, informative
# refusal into a 404 — or worse, into a digest check against a digest nobody
# ever wrote — on someone else's computer. Widening the claim is a one-word
# edit; producing the artifact is a toolchain, a second-stage installer and a
# service lifecycle. Nothing in the source stops the one-word edit, so this
# does.
#
# FOUR CLAIMS, FOUR AUTHORITIES:
#
#   packaging/install/install.sh        PUBLISHED_PLATFORMS + BOOT_* rows
#                                       -> what a POSIX machine may fetch
#   packaging/install/install.ps1       $BootPins keys
#                                       -> what a Windows machine may fetch
#   lib/install/src/front_door_platform.c  FD_PUBLISHED
#                                       -> what RUNTIME the bootstrap will
#                                          admit to publishing
#   packaging/release/build_release.sh  bootstrap_platforms/runtime_platforms
#                                       -> what is actually produced
#
# The cutter is the authority, and it is ASKED (--print-bootstrap-platforms,
# --print-runtime-platforms) rather than parsed, so this gate holds no second
# copy of the answer that could drift from the first.
#
# The two claim sets are deliberately allowed to DIFFER from each other: a
# bootstrap and a runtime are different artifacts, and a machine can honestly
# have one and not the other. What neither may do is exceed what the cutter
# produces. Subset, not equality — so narrowing a claim (the fail-closed
# direction) is always allowed and widening one is never allowed silently.
#
# It also holds the sentinel: every digest baked into a checked-in shim must
# be the all-zero "nothing is published" value. The release cutter writes real
# digests into COPIES (build_release.sh --front-door), never into the
# checkout, so a real digest appearing here means either a cut wrote where it
# must not or somebody pinned a release by hand without the cut.
#
# Status-carrying matches use `grep -q PATTERN FILE` with a file argument, not
# a pipeline, so nothing here can invert on SIGPIPE under pipefail.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Overridable so --selftest can point the same checks at mutated fixtures.
# A gate that has only ever been observed passing is not a gate.
PP_INSTALL_SH="${ZCL_PP_INSTALL_SH:-$REPO_ROOT/packaging/install/install.sh}"
PP_INSTALL_PS1="${ZCL_PP_INSTALL_PS1:-$REPO_ROOT/packaging/install/install.ps1}"
PP_FRONT_DOOR_C="${ZCL_PP_FRONT_DOOR_C:-$REPO_ROOT/lib/install/src/front_door_platform.c}"
PP_CUTTER="${ZCL_PP_CUTTER:-$REPO_ROOT/packaging/release/build_release.sh}"

FAIL=0
fail() { printf 'check-published-platforms: FAIL: %s\n' "$*" >&2; FAIL=1; }
note() { printf 'check-published-platforms: %s\n' "$*"; }

# ── reading each claim ────────────────────────────────────────────────────

# install.sh: PUBLISHED_PLATFORMS=" linux-x86_64 "
posix_claimed() {
    sed -n 's/^PUBLISHED_PLATFORMS="\(.*\)"[[:space:]]*$/\1/p' "$PP_INSTALL_SH" \
        | tr -s ' ' '\n' | sed '/^$/d'
}

# install.sh: the case arms that actually select a digest, which is what a
# fetch is decided by. A claim with no arm falls through to the refusal; an
# arm with no claim is a platform reachable by nothing but a stale comment.
posix_arms() {
    sed -n 's/^[[:space:]]*\([a-z0-9][a-z0-9_.-]*\))[[:space:]]*WANT=.*$/\1/p' \
        "$PP_INSTALL_SH"
}

# install.ps1: the keys of $BootPins. `@{}` yields nothing, which is a claim
# of no Windows platform at all.
windows_claimed() {
    sed -n "s/^[[:space:]]*['\"]\([a-z0-9][a-z0-9_.-]*\)['\"][[:space:]]*=[[:space:]]*['\"][0-9a-f]\{64\}['\"].*$/\1/p" \
        "$PP_INSTALL_PS1"
}


# install.sh: the cpu aliases the shim rewrites before it looks a platform up.
# Read from the shim rather than restated here, so this gate cannot hold a
# second copy of the fold table that drifts from the first. An arm is a FOLD
# when the value it assigns is not the alternative itself: `amd64) cpu=x86_64`
# folds amd64, while `x86_64) cpu=x86_64` is the identity and folds nothing.
cpu_fold_sources() {
    sed -n 's/^case "\$(uname -m)" in \(.*\) esac$/\1/p' "$PP_INSTALL_SH" \
        | tr ';' '\n' \
        | while IFS= read -r arm; do
            case "$arm" in
                *')'*cpu=*) ;;
                *) continue ;;
            esac
            pattern="${arm%%)*}"
            value="${arm#*cpu=}"
            value="${value%% *}"
            value="${value%\"}"; value="${value#\"}"
            printf '%s\n' "$pattern" | tr -d ' ' | tr '|' '\n' \
                | while IFS= read -r alt; do
                    [ -n "$alt" ] || continue
                    # The catch-all arm is a passthrough, not a fold.
                    [ "$alt" = "*" ] && continue
                    [ "$alt" = "$value" ] || printf '%s\n' "$alt"
                done
        done | sort -u
}
# front_door_platform.c: #define FD_PUBLISHED "linux-x86_64"
runtime_claimed() {
    sed -n 's/^#define[[:space:]]\+FD_PUBLISHED[[:space:]]\+"\(.*\)".*$/\1/p' \
        "$PP_FRONT_DOOR_C" | tr -s ' ' '\n' | sed '/^$/d'
}

in_set() {
    local want="$1" item
    shift
    for item in "$@"; do
        [ "$item" = "$want" ] && return 0
    done
    return 1
}

# ── the checks ────────────────────────────────────────────────────────────
run_checks() {
    local produced_boot produced_runtime claimed arms plat var
    FAIL=0

    [ -f "$PP_INSTALL_SH" ] || { fail "missing $PP_INSTALL_SH"; return 1; }
    [ -f "$PP_INSTALL_PS1" ] || { fail "missing $PP_INSTALL_PS1"; return 1; }
    [ -f "$PP_FRONT_DOOR_C" ] || { fail "missing $PP_FRONT_DOOR_C"; return 1; }
    [ -x "$PP_CUTTER" ] || [ -f "$PP_CUTTER" ] \
        || { fail "missing $PP_CUTTER"; return 1; }

    # Ask the cutter, do not re-derive. An empty answer is a broken cutter,
    # not "nothing is produced": fail rather than vacuously pass everything.
    produced_boot="$(bash "$PP_CUTTER" --print-bootstrap-platforms)" \
        || { fail "$PP_CUTTER --print-bootstrap-platforms failed"; return 1; }
    produced_runtime="$(bash "$PP_CUTTER" --print-runtime-platforms)" \
        || { fail "$PP_CUTTER --print-runtime-platforms failed"; return 1; }
    [ -n "$produced_boot" ] \
        || { fail "the cutter names no bootstrap platform at all"; return 1; }
    [ -n "$produced_runtime" ] \
        || { fail "the cutter names no runtime platform at all"; return 1; }

    # 1. Nothing the POSIX shim publishes may exceed what is produced.
    claimed="$(posix_claimed)"
    for plat in $claimed; do
        in_set "$plat" $produced_boot \
            || fail "install.sh publishes $plat, but the release cutter produces no z23-bootstrap for it (produced: $(echo $produced_boot))"
    done

    # 2. ...and each published platform must actually be selectable: a case
    #    arm that picks a digest, and the BOOT_* row that arm reads.
    arms="$(posix_arms)"
    for plat in $claimed; do
        in_set "$plat" $arms \
            || fail "install.sh publishes $plat but has no case arm selecting a digest for it"
        var="BOOT_$(printf '%s' "$plat" | tr 'a-z-' 'A-Z_')"
        grep -q "^$var=" "$PP_INSTALL_SH" \
            || fail "install.sh publishes $plat but has no $var= row"
    done

    # 3. ...and the reverse: an arm for a platform that is not published is a
    #    fetch path nothing announces and nothing tests.
    for plat in $arms; do
        in_set "$plat" $claimed \
            || fail "install.sh has a case arm for $plat, which PUBLISHED_PLATFORMS does not name"
    done

    # 4. The PowerShell shim, same rule.
    for plat in $(windows_claimed); do
        in_set "$plat" $produced_boot \
            || fail "install.ps1 publishes $plat, but the release cutter produces no z23-bootstrap for it"
    done

    # 5. The RUNTIME claim inside the bootstrap. A different question from the
    #    bootstrap set above — this is what the C23 program tells a user it
    #    can install — measured against what the cutter packages.
    for plat in $(runtime_claimed); do
        in_set "$plat" $produced_runtime \
            || fail "FD_PUBLISHED names $plat, but the release cutter packages no runtime for it (packaged: $(echo $produced_runtime))"
    done

    # 6. The sentinel stays the checked-in default. Real digests belong only
    #    in the copies the cutter publishes.
    while read -r line; do
        case "$line" in
            *'="$BOOT_ZERO"') ;;
            *=0000000000000000000000000000000000000000000000000000000000000000) ;;
            *) fail "install.sh has a non-sentinel baked digest checked in: $line" ;;
        esac
    done < <(grep '^BOOT_[A-Z0-9_]*=' "$PP_INSTALL_SH" | grep -v '^BOOT_ZERO=')
    grep -q '^BOOT_ZERO=0\{64\}$' "$PP_INSTALL_SH" \
        || fail "install.sh has no all-zero BOOT_ZERO sentinel to compare against"
    while read -r line; do
        case "$line" in
            *0000000000000000000000000000000000000000000000000000000000000000*) ;;
            *) fail "install.ps1 has a non-sentinel baked digest checked in: $line" ;;
        esac
    done < <(sed -n "/^[[:space:]]*['\"][a-z0-9][a-z0-9_.-]*['\"][[:space:]]*=[[:space:]]*['\"][0-9a-f]\{64\}['\"]/p" "$PP_INSTALL_PS1")

    # 7. Every produced platform must be spelled the way a real machine will
    #    name itself. The shims fold cpu aliases (amd64 -> x86_64) before they
    #    look a platform up, so a produced platform whose cpu is a fold SOURCE
    #    can never be matched by the machine it was built for: the shim
    #    rewrites the name first and then finds nothing.
    #
    #    Not hypothetical. The shims folded arm64 -> aarch64 while the cutter
    #    produced darwin-arm64, so publishing the Mac would have told every
    #    Mac "no runtime is published for darwin-aarch64" while shipping
    #    darwin-arm64 — a refusal naming a machine that does not exist, for a
    #    machine we do ship.
    #
    #    Checks 1-6 all ask whether a claim EXCEEDS what is produced. This is
    #    the other direction, and it is the one that was missing: whether what
    #    is produced is REACHABLE by the machine it is for.
    local folded cpu
    folded="$(cpu_fold_sources)"
    for plat in $produced_boot $produced_runtime; do
        for cpu in $folded; do
            if [ "${plat#*-}" = "$cpu" ]; then
                fail "the cutter produces $plat, but install.sh rewrites the cpu '$cpu' before looking a platform up, so no machine can ever match it"
            fi
        done
    done

    [ "$FAIL" -eq 0 ] || return 1
    return 0
}

# ── selftest ──────────────────────────────────────────────────────────────
# Each case mutates ONE input and asserts this gate goes red on it. A gate
# nobody has watched fail is a comment.
selftest() {
    local tmp rc
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl-published-platforms.XXXXXX")" \
        || { printf 'selftest: mktemp failed\n' >&2; exit 1; }
    trap 'rm -rf "$tmp"' EXIT

    cp -f -- "$PP_INSTALL_SH" "$tmp/install.sh"
    cp -f -- "$PP_INSTALL_PS1" "$tmp/install.ps1"
    cp -f -- "$PP_FRONT_DOOR_C" "$tmp/front_door_platform.c"

    # The gate runs in a subshell with the three claim files repointed at the
    # mutated copies; the cutter stays the real one, because the cutter is the
    # authority being measured against and mutating it would prove nothing.
    probe() {
        local expect="$1" what="$2"
        rc=0
        (
            PP_INSTALL_SH="$tmp/install.sh"
            PP_INSTALL_PS1="$tmp/install.ps1"
            PP_FRONT_DOOR_C="$tmp/front_door_platform.c"
            run_checks
        ) >"$tmp/probe.out" 2>"$tmp/probe.err" || rc=$?
        if [ "$expect" = pass ] && [ "$rc" -ne 0 ]; then
            printf 'selftest FAIL: %s should have passed:\n' "$what" >&2
            cat "$tmp/probe.err" >&2
            exit 1
        fi
        if [ "$expect" = fail ] && [ "$rc" -eq 0 ]; then
            printf 'selftest FAIL: %s should have been refused\n' "$what" >&2
            exit 1
        fi
    }

    # Baseline: the unmutated copies pass, or nothing below means anything.
    probe pass "the tree as checked in"

    # 1. A platform claimed with no bootstrap behind it.
    sed -i 's|^PUBLISHED_PLATFORMS=.*$|PUBLISHED_PLATFORMS=" linux-x86_64 darwin-aarch64 "|' \
        "$tmp/install.sh"
    probe fail "PUBLISHED_PLATFORMS naming an unproduced platform"
    grep -q 'publishes darwin-aarch64' "$tmp/probe.err" \
        || { printf 'selftest FAIL: the refusal must name the platform\n' >&2; exit 1; }
    cp -f -- "$PP_INSTALL_SH" "$tmp/install.sh"

    # 2. A claim with no case arm to select a digest.
    sed -i 's|^[[:space:]]*linux-x86_64) WANT=.*$|    never-matches) WANT="$BOOT_LINUX_X86_64" ;;|' \
        "$tmp/install.sh"
    probe fail "a published platform with no case arm"
    cp -f -- "$PP_INSTALL_SH" "$tmp/install.sh"

    # 3. A case arm for a platform nothing publishes.
    sed -i 's|^\([[:space:]]*\)linux-x86_64) WANT=\(.*\)$|\1linux-x86_64) WANT=\2\n\1darwin-aarch64) WANT="$BOOT_ZERO" ;;|' \
        "$tmp/install.sh"
    probe fail "a case arm for an unpublished platform"
    cp -f -- "$PP_INSTALL_SH" "$tmp/install.sh"

    # 4. A Windows row with no Windows bootstrap.
    sed -i "s|^[\$]BootPins = @{}\$|\$BootPins = @{\n    'windows-x86_64' = '$(printf '0%.0s' $(seq 64))'\n}|" \
        "$tmp/install.ps1"
    probe fail "an install.ps1 row for an unproduced platform"
    cp -f -- "$PP_INSTALL_PS1" "$tmp/install.ps1"

    # 5. A runtime claim the cutter does not package.
    sed -i 's|^#define[[:space:]]\+FD_PUBLISHED.*$|#define FD_PUBLISHED "linux-x86_64 darwin-aarch64"|' \
        "$tmp/front_door_platform.c"
    probe fail "FD_PUBLISHED naming an unpackaged runtime"
    cp -f -- "$PP_FRONT_DOOR_C" "$tmp/front_door_platform.c"

    # 6. A real digest checked in where the sentinel belongs.
    sed -i 's|^BOOT_LINUX_X86_64=.*$|BOOT_LINUX_X86_64=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef|' \
        "$tmp/install.sh"
    probe fail "a non-sentinel digest checked into install.sh"
    cp -f -- "$PP_INSTALL_SH" "$tmp/install.sh"


    # 7. The regression for the reachability direction: restore the arm64 fold
    #    the shims used to carry. The cutter produces darwin-arm64, so folding
    #    arm64 away makes that artifact unreachable by the only machines it is
    #    for. This mutation is the tree as it stood before the fold was
    #    removed, so this case is that bug, frozen.
    sed -i 's@^case "$(uname -m)" in .*@case "$(uname -m)" in x86_64|amd64) cpu=x86_64 ;; aarch64|arm64) cpu=aarch64 ;; *) cpu="$(uname -m)" ;; esac@' \
        "$tmp/install.sh"
    probe fail "a cpu fold that makes a produced platform unreachable"
    grep -q 'darwin-arm64' "$tmp/probe.err" \
        || { printf 'selftest FAIL: the refusal must name the unreachable platform\n' >&2; exit 1; }
    cp -f -- "$PP_INSTALL_SH" "$tmp/install.sh"
    # ...and everything is back to passing, so the mutations above were the
    # reason each case went red and not some residue of the one before.
    probe pass "the restored tree"

    printf 'check-published-platforms: selftest PASS (7 mutations refused)\n'
    trap - EXIT
    rm -rf "$tmp"
}

case "${1:-}" in
    --selftest) selftest; exit 0 ;;
    "") ;;
    *) printf 'check-published-platforms: unknown argument: %s\n' "$1" >&2; exit 2 ;;
esac

if run_checks; then
    note "PASS — install.sh publishes [$(posix_claimed | tr '\n' ' ')], install.ps1 publishes [$(windows_claimed | tr '\n' ' ')], FD_PUBLISHED runtimes [$(runtime_claimed | tr '\n' ' ')]; every one is produced by packaging/release/build_release.sh, and every checked-in digest is the sentinel."
    exit 0
fi
printf 'check-published-platforms: a front door claims a platform the release process does not produce.\n' >&2
printf '  Fix the claim, or produce the artifact — never the other way round.\n' >&2
printf '  See docs/work/BOOTSTRAP_PLAN.md, "Platform work".\n' >&2
exit 1
