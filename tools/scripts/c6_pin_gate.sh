#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# c6_pin_gate.sh — bind the MVP-C6 soak clock to an exact candidate,
# OFFLINE. No RPC, no node start, no write to the soak lane: the only
# things it touches are systemd's own view of the unit, the pinned file's
# bytes, and the kernel's handle on the running image.
#
# The gap it closes: soak_evidence.sh samples the live node's height,
# restarts, RSS and security posture, but a 168 h window is only worth
# something if every sample came from the SAME deliberately-chosen
# executable. The soak unit is pinned precisely so `make deploy` cannot
# re-baseline the clock (platform/deploy/examples/zclassic23-soak-node.service),
# and re-pinning it is a conscious restart. This gate is what makes that
# intent checkable before and after the swap:
#
#   tools/scripts/c6_pin_gate.sh                       # report the pin
#   tools/scripts/c6_pin_gate.sh --expect-binary-sha256=<hex> \
#                                --expect-source-prefix=<hex>
#
# With no expectation it REPORTS (verdict=REPORT): a truthful description
# of what the unit would exec and what it is execing now. With an
# expectation it BINDS (verdict=BOUND) and fails closed on every way the
# binding can be untrue — wrong bytes on disk, a source identity that is
# not the candidate's, a running image that is not the pinned bytes, an
# unobservable running image, a unit whose merged ExecStart points
# somewhere else, or a pin that lives inside a development checkout where
# an ordinary build would silently replace it.
#
# What it does NOT prove: that the candidate is correct, that the window
# has accrued, or that the node is healthy. Those are soak_evidence.sh's
# judge and the MVP gate. This answers exactly one question — which
# executable is the clock running on.
#
# Usage:
#   c6_pin_gate.sh [--expect-binary-sha256=<hex>] [--expect-source-prefix=<hex>]
#   c6_pin_gate.sh --selftest    # hermetic; fixture unit, fake binary, no systemd
#
# Env (test injection seams — the selftest needs no unit and no node):
#   ZCL_SOAK_UNIT        systemd unit name (default zclassic23-soak), the
#                        same seam soak_evidence.sh reads
#   ZCL_C6_SHOW_CMD      command printing `systemctl show` key=value lines
#   ZCL_C6_EXE_SHA_CMD   command printing the running image's sha256
#                        (default: sha256 of /proc/<MainPID>/exe)
#
# No python (banned), no jq — bash + sed + coreutils only, same rule as
# soak_evidence.sh, whose readers this script shares.

set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# The ONE reader per measurement — systemd properties, file and running-image
# digests all come from tools/scripts/lib/evidence_sources.sh so this gate and
# the hourly collector cannot disagree about the same host at the same instant.
. "$SCRIPT_DIR/lib/evidence_sources.sh"
SELF="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"

SOAK_UNIT="${ZCL_SOAK_UNIT:-zclassic23-soak}"

fail()
{
    printf 'c6-pin-gate: FAIL: %s\n' "$*" >&2
    exit 1
}

# ── pure decision ──────────────────────────────────────────────────────

# c6_verdict <pin_sha> <run_sha> <src_prefix> <exp_sha> <exp_src>
# Prints BOUND or REPORT. Exits 1 (through fail) on any untrue binding.
# Split out from the readers so the selftest can drive every rung without
# a systemd unit, and so the rules are readable in one place.
c6_verdict()
{
    local pin_sha="${1:-}" run_sha="${2:-}" src="${3:-}"
    local exp_sha="${4:-}" exp_src="${5:-}"

    [ -n "$pin_sha" ] || fail "pinned binary has no readable digest"
    [ -n "$src" ] || fail "pinned binary reports no source identity"

    [ -z "$exp_sha" ] || [ "$exp_sha" = "$pin_sha" ] ||
        fail "binary sha256 mismatch: pinned=$pin_sha expected=$exp_sha"
    [ -z "$exp_src" ] || [ "${src#"$exp_src"}" != "$src" ] ||
        fail "source identity mismatch: pinned=$src expected-prefix=$exp_src"

    # The running image is the only thing the window is actually judged
    # on: a swapped-but-not-restarted pin still serves the old bytes, and
    # a restarted-but-unswapped pin serves the old bytes too.
    if [ -n "$run_sha" ] && [ "$run_sha" != "$pin_sha" ]; then
        fail "running image is not the pinned bytes: running=$run_sha pinned=$pin_sha"
    fi

    if [ -n "$exp_sha" ] || [ -n "$exp_src" ]; then
        [ -n "$run_sha" ] ||
            fail "running image unobservable; an expectation cannot be proved against it"
        printf 'BOUND'
        return 0
    fi
    printf 'REPORT'
}

# ── readers ────────────────────────────────────────────────────────────

c6_show()
{
    if [ -n "${ZCL_C6_SHOW_CMD:-}" ]; then
        timeout "$ZCL_EVIDENCE_TIMEOUT_SEC" bash -c "$ZCL_C6_SHOW_CMD" 2>/dev/null || true
        return 0
    fi
    evidence_systemd_show "$SOAK_UNIT" ExecStart MainPID ActiveState NRestarts
}

c6_running_sha()
{
    local mainpid="${1:-}"
    if [ -n "${ZCL_C6_EXE_SHA_CMD:-}" ]; then
        timeout "$ZCL_EVIDENCE_TIMEOUT_SEC" bash -c "$ZCL_C6_EXE_SHA_CMD" 2>/dev/null || true
        return 0
    fi
    evidence_exe_sha256 "$mainpid"
}

# c6_source_prefix <version-line>: the identity inside "… (source <hex>)".
c6_source_prefix()
{
    case "${1:-}" in
        *"(source "*) local t="${1##*(source }"; printf '%s' "${t%%)*}" ;;
        *) printf '' ;;
    esac
}

# ── report ─────────────────────────────────────────────────────────────

cmd_report()
{
    local exp_sha="" exp_src=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --expect-binary-sha256=*) exp_sha="${1#*=}" ;;
            --expect-source-prefix=*) exp_src="${1#*=}" ;;
            *) fail "unknown argument: $1" ;;
        esac
        shift
    done

    local show exec_bin mainpid active
    show="$(c6_show)"
    [ -n "$show" ] || fail "unit unreadable: $SOAK_UNIT (no systemd properties)"

    exec_bin="$(evidence_unit_exec_bin "$show")"
    [ -n "$exec_bin" ] || fail "unit $SOAK_UNIT declares no ExecStart path"

    # A pin inside a development checkout is not a pin: an ordinary build
    # replaces those bytes and silently re-baselines the soak clock. The
    # unit is supposed to exec a private copy.
    case "$exec_bin" in
        "$REPO_ROOT"/*)
            fail "unit execs inside the checkout ($exec_bin); a build would re-baseline the clock" ;;
    esac

    mainpid="$(evidence_systemd_field "$show" MainPID)"
    active="$(evidence_systemd_field "$show" ActiveState)"

    [ -r "$exec_bin" ] || fail "pinned binary unreadable: $exec_bin (pin not yet swapped?)"
    [ -x "$exec_bin" ] || fail "pinned binary not executable: $exec_bin"

    local pin_sha version src_prefix
    pin_sha="$(evidence_sha256_file "$exec_bin")"
    version="$(timeout "$ZCL_EVIDENCE_TIMEOUT_SEC" "$exec_bin" --version 2>/dev/null | head -n1 || true)"
    src_prefix="$(c6_source_prefix "$version")"
    [ -n "$src_prefix" ] ||
        fail "pinned binary --version reports no source identity: ${version:-<none>}"

    local run_sha
    run_sha="$(c6_running_sha "$mainpid")"

    local verdict
    verdict="$(c6_verdict "$pin_sha" "$run_sha" "$src_prefix" "$exp_sha" "$exp_src")"

    # Forensics the verdict does not gate on: the merged unit text (every
    # drop-in included) and the datadir the clock accrues against. A
    # foreign datadir would seed the window from another node's chainstate.
    local unit_sha datadir anchors
    unit_sha="$(evidence_systemd_cat "$SOAK_UNIT" | evidence_sha256_stdin)"
    datadir="$(evidence_unit_exec_arg "$show" datadir)"
    if [ -n "$datadir" ] && [ -d "$datadir" ]; then
        anchors="present"
    elif [ -n "$datadir" ]; then
        anchors="absent(fresh-window)"
    else
        anchors=""
    fi

    printf '{"schema":"zcl.c6_pin_receipt.v1"'
    printf ',"unit":%s' "$(evidence_jstr "$SOAK_UNIT")"
    printf ',"active_state":%s' "$(evidence_jstr "$active")"
    printf ',"execstart_bin":%s' "$(evidence_jstr "$exec_bin")"
    printf ',"binary_sha256":%s' "$(evidence_jstr "$pin_sha")"
    printf ',"binary_source_prefix":%s' "$(evidence_jstr "$src_prefix")"
    printf ',"version_line":%s' "$(evidence_jstr "$version")"
    printf ',"mainpid":%s' "$(evidence_jnum "$mainpid")"
    printf ',"running_sha256":%s' "$(evidence_jstr "$run_sha")"
    printf ',"image_matches_pin":%s' \
        "$([ -n "$run_sha" ] && { [ "$run_sha" = "$pin_sha" ] && echo true || echo false; } || echo null)"
    printf ',"unit_config_sha256":%s' "$(evidence_jstr "$unit_sha")"
    printf ',"datadir":%s' "$(evidence_jstr "$datadir")"
    printf ',"datadir_state":%s' "$(evidence_jstr "$anchors")"
    printf ',"expected_binary_sha256":%s' "$(evidence_jstr "$exp_sha")"
    printf ',"expected_source_prefix":%s' "$(evidence_jstr "$exp_src")"
    printf ',"verdict":%s' "$(evidence_jstr "$verdict")"
    printf '}\n'
}

# ── selftest (hermetic; fixture unit text, fake binary, no systemd) ────

st_fail() { echo "selftest: FAIL $*" >&2; exit 1; }

# st_run <want_rc> <want_substr> <case> [args...]
# ZCL_C6_SHOW_CMD / ZCL_C6_EXE_SHA_CMD are already exported by the caller.
st_run()
{
    local want_rc="$1" want="$2" name="$3"
    shift 3
    local out rc
    set +e
    out="$(bash "$SELF" "$@" 2>&1)"
    rc=$?
    set -e
    [ "$rc" = "$want_rc" ] ||
        { printf '%s\n' "$out" >&2; st_fail "case=$name wanted rc=$want_rc got rc=$rc"; }
    grep -qF -- "$want" <<<"$out" ||
        { printf '%s\n' "$out" >&2; st_fail "case=$name wanted /$want/"; }
    echo "selftest: ok case=$name (rc=$rc)"
}

cmd_selftest()
{
    ST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/zcl-c6-pin-selftest.XXXXXX")"
    trap 'rm -rf "$ST_TMP"' EXIT

    local bin="$ST_TMP/zclassic23-soak" dd="$ST_TMP/datadir"
    printf '#!/bin/sh\necho "z23 v0.1.0 (source deadbeefcafe)"\n' > "$bin"
    chmod 0755 "$bin"
    mkdir -p "$dd"

    local pin_sha
    pin_sha="$(evidence_sha256_file "$bin")"
    [ -n "$pin_sha" ] || st_fail "fixture binary has no digest"

    local show="ExecStart={ path=$bin ; argv[]=$bin -datadir=$dd -rpcport=18242 ; ignore_errors=no }
MainPID=4242
ActiveState=active
NRestarts=0"

    export ZCL_C6_SHOW_CMD="printf '%s\\n' \"\$ZCL_C6_SHOW_FIXTURE\""
    export ZCL_C6_SHOW_FIXTURE="$show"
    export ZCL_C6_EXE_SHA_CMD="printf '%s\\n' $pin_sha"

    st_run 0 '"verdict":"REPORT"' report-no-expectation
    st_run 0 '"image_matches_pin":true' report-image-matches
    st_run 0 '"verdict":"BOUND"' bound-sha "--expect-binary-sha256=$pin_sha"
    st_run 0 '"verdict":"BOUND"' bound-source "--expect-source-prefix=deadbeef"
    st_run 1 'binary sha256 mismatch' wrong-sha \
        "--expect-binary-sha256=0000000000000000000000000000000000000000000000000000000000000000"
    st_run 1 'source identity mismatch' wrong-source "--expect-source-prefix=facefeed"
    st_run 1 'unknown argument' unknown-argument --expect-nothing=1

    # The running image is not the pinned bytes: a swapped pin that was
    # never restarted reads exactly like this, and it must never pass.
    ZCL_C6_EXE_SHA_CMD="printf '%s\\n' 1111111111111111111111111111111111111111111111111111111111111111" \
        st_run 1 'running image is not the pinned bytes' image-differs

    # Unobservable running image: a report may say so, an expectation may not.
    ZCL_C6_EXE_SHA_CMD="printf ''" \
        st_run 0 '"image_matches_pin":null' unobservable-report
    ZCL_C6_EXE_SHA_CMD="printf ''" \
        st_run 1 'running image unobservable' unobservable-expectation \
        "--expect-binary-sha256=$pin_sha"

    # A unit with no ExecStart, and an unreadable unit, are refusals — not
    # a cheerful receipt with empty fields.
    ZCL_C6_SHOW_FIXTURE="MainPID=0
ActiveState=inactive" st_run 1 'declares no ExecStart path' no-execstart
    ZCL_C6_SHOW_FIXTURE="" st_run 1 'unit unreadable' unit-unreadable

    # A pin inside the checkout is refused before it is even read: an
    # ordinary build replaces those bytes under the running clock.
    ZCL_C6_SHOW_FIXTURE="ExecStart={ path=$REPO_ROOT/build/bin/zclassic23 ; argv[]=$REPO_ROOT/build/bin/zclassic23 ; ignore_errors=no }
MainPID=0
ActiveState=inactive" st_run 1 'execs inside the checkout' pin-inside-checkout

    # A binary that cannot name its own source cannot anchor a window.
    printf '#!/bin/sh\necho "z23 v0.1.0"\n' > "$bin"
    st_run 1 'reports no source identity' no-source-identity

    echo "selftest: PASS"
}

case "${1:-}" in
    --selftest) shift; cmd_selftest "$@" ;;
    "") cmd_report ;;
    *) cmd_report "$@" ;;
esac
