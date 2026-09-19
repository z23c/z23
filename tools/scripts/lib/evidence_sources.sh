#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# evidence_sources.sh — the ONE implementation of every raw evidence reader
# the operator scripts use. Sourced, never executed.
#
# Why this file exists: the evidence-dimension audit found the same six
# measurements read six different ways across tools/scripts — peer count in
# lane_health.sh, VmRSS + systemd restart accounting in soak_evidence.sh,
# directory bytes in worktree_gc.sh (and again in first_build_timing.sh),
# typed-blocker enrichment in slo_page_if_stalled.sh. Each copy is a chance
# for two ledgers to disagree about the same host at the same instant, which
# is exactly the class of bug the architecture doctrine says to fix by
# DELETING a copy rather than by adding a reconciler. Every caller now reads
# through the functions below; adding a seventh reader means editing this
# file, and the diff shows every consumer it moves at once.
#
# Contract for every function here:
#   - NEVER raises. A missing pid, a dead unit, an unreadable directory, an
#     absent binary all print "" (or the documented empty form) and return 0.
#     Callers are collectors that must record a hole, not abort; `set -e` in
#     a caller must never be tripped by an absent measurement.
#   - Prints ONE line to stdout, nothing to stderr on the ordinary
#     absence paths.
#   - Bounded: every subprocess that touches the filesystem, systemd, or a
#     node is wrapped in `timeout`, so a 60 s collector cannot be wedged by
#     one slow reader.
#
# No python (banned), no jq — bash + sed + coreutils only, same rule as the
# scripts that source this.

# Idempotent source guard: several scripts source this both directly and
# transitively (lane_health.sh -> nothing, but slo_page_if_stalled.sh and
# node_slo_probe.sh may be chained by an operator wrapper).
if [ -n "${ZCL_EVIDENCE_SOURCES_SH_LOADED:-}" ]; then
    return 0 2>/dev/null || exit 0
fi
ZCL_EVIDENCE_SOURCES_SH_LOADED=1

# Bounded default for every external reader. Deliberately small: these are
# all sub-100 ms operations on a healthy box (measured: systemd show 9 ms,
# /proc read 1 ms, du -sb 1 ms, sha256 of a 22 MB binary 13 ms, node
# dumpstate 48 ms), so a reader that has not answered in 10 s is wedged and
# a hole in the ledger beats a stalled collector.
ZCL_EVIDENCE_TIMEOUT_SEC="${ZCL_EVIDENCE_TIMEOUT_SEC:-10}"

# ── JSON emission ──────────────────────────────────────────────────────
# One escaping implementation. Every evidence ledger in tools/scripts had
# its own copy of these three and they had already drifted (one escaped
# control characters, two did not).

# evidence_json_escape <s>: escape backslash and double-quote for a JSON
# string body. Also strips raw newlines/tabs/CRs, which would otherwise
# produce an unparseable line in a JSONL ledger.
evidence_json_escape() {
    printf '%s' "${1:-}" | tr '\n\r\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# evidence_jstr <s>: a complete JSON string literal, "" when empty.
evidence_jstr() { printf '"%s"' "$(evidence_json_escape "${1:-}")"; }

# evidence_jnum <v>: a JSON number when v is a bare (optionally negative)
# integer, JSON null otherwise. Never fabricates a 0 — "we did not measure
# it" and "we measured zero" are different facts and a monitor that
# conflates them is the reason this audit happened.
evidence_jnum() {
    local v="${1:-}"
    case "$v" in
        '' | null | -) printf 'null' ;;
        -*) case "${v#-}" in '' | *[!0-9]*) printf 'null' ;; *) printf '%s' "$v" ;; esac ;;
        *[!0-9]*) printf 'null' ;;
        *) printf '%s' "$v" ;;
    esac
}

# evidence_jbool <v>: JSON true/false for true/1/yes, null for anything
# else including empty. An unmeasured boolean must not read as false.
evidence_jbool() {
    case "${1:-}" in
        true | True | TRUE | 1 | yes) printf 'true' ;;
        false | False | FALSE | 0 | no) printf 'false' ;;
        *) printf 'null' ;;
    esac
}

# ── JSON extraction (read side) ────────────────────────────────────────

# evidence_json_int <json> <key>: first integer value for "key". "" when
# absent or non-integer.
evidence_json_int() {
    printf '%s' "${1:-}" |
        sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p" |
        head -n1
}

# evidence_json_str <json> <key>: first string value for "key". "" when
# absent. Does not handle escaped quotes inside the value — every field
# read through this is a node-emitted identifier (onion address, blocker
# id), none of which can contain one.
evidence_json_str() {
    printf '%s' "${1:-}" |
        sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" |
        head -n1
}

# evidence_json_bool <json> <key>: "true"/"false", "" when absent.
evidence_json_bool() {
    printf '%s' "${1:-}" |
        sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p" |
        head -n1
}

# ── peers ──────────────────────────────────────────────────────────────

# evidence_peer_count_from_json: stdin filter. Counts connected peers as
# the number of "addr" keys in a getpeerinfo response — the one definition
# this repo has ever used (moved here verbatim from lane_health.sh so the
# lane report and the SLO ledger can never disagree about peer count).
# Prints a bare integer; 0 on empty input, which for this reader is the
# truthful answer only when the RPC succeeded — callers gate on that.
evidence_peer_count_from_json() {
    grep -o '"addr"[[:space:]]*:' 2>/dev/null | wc -l | tr -d ' '
}

# ── process memory ─────────────────────────────────────────────────────

# evidence_rss_kb <pid>: VmRSS in kB from /proc/<pid>/status — the
# soak_harness-parity source (tools/soak/main.c rss_bytes_for parses
# exactly this line). "" for pid 0/empty/gone/unreadable.
evidence_rss_kb() {
    local pid="${1:-}"
    case "$pid" in '' | 0 | *[!0-9]*) printf ''; return 0 ;; esac
    [ -r "/proc/$pid/status" ] || { printf ''; return 0; }
    grep VmRSS "/proc/$pid/status" 2>/dev/null |
        sed -n 's/.*VmRSS:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*kB.*/\1/p' |
        head -n1
}

# evidence_exe_sha256 <pid>: sha256 of the RUNNING image —
# /proc/<pid>/exe, the kernel's own name for the execed bytes, never the
# pin path (a swapped pin the kernel has not execed yet still shows the
# old image, which is the truth the C6 window is judged on). "" for pid
# 0/empty/gone/unreadable.
evidence_exe_sha256() {
    local pid="${1:-}"
    case "$pid" in '' | 0 | *[!0-9]*) printf ''; return 0 ;; esac
    local digest
    # Open the kernel handle itself: resolving it to a pathname loses the
    # running inode when an installer replaces or unlinks that pathname.
    digest="$(timeout "$ZCL_EVIDENCE_TIMEOUT_SEC" sha256sum -- "/proc/$pid/exe" 2>/dev/null)" \
        || { printf ''; return 0; }
    printf '%s\n' "${digest%% *}"
}

# ── disk ───────────────────────────────────────────────────────────────

# evidence_dir_bytes <dir>: apparent-inclusive `du -sb` byte total, bounded.
# "" (not 0) when the directory is absent, unreadable, or du timed out —
# a datadir that "grew to 0 bytes" is a monitoring artefact, never a fact.
evidence_dir_bytes() {
    local d="${1:-}"
    [ -n "$d" ] && [ -d "$d" ] || { printf ''; return 0; }
    local out
    out="$(timeout "$ZCL_EVIDENCE_TIMEOUT_SEC" du -sb -- "$d" 2>/dev/null |
        awk 'NR==1{print $1}')" || true
    case "${out:-}" in '' | *[!0-9]*) printf '' ;; *) printf '%s' "$out" ;; esac
}

# ── systemd ────────────────────────────────────────────────────────────

# evidence_systemd_show <unit> <prop>...: raw `Prop=value` lines from
# `systemctl --user show`, bounded. "" when systemctl is absent or the
# call failed, which callers must treat as "unknown", not "unit stopped".
evidence_systemd_show() {
    local unit="${1:-}"; shift || true
    [ -n "$unit" ] || { printf ''; return 0; }
    command -v systemctl >/dev/null 2>&1 || { printf ''; return 0; }
    local args=() p
    for p in "$@"; do args+=(-p "$p"); done
    # ${a[@]+"${a[@]}"} rather than "${a[@]}": on bash before 4.4 an empty
    # array expanded under `set -u` is an unbound-variable ERROR, which
    # would turn "no properties requested" into a dead collector on any
    # host with an older bash.
    timeout "$ZCL_EVIDENCE_TIMEOUT_SEC" \
        systemctl --user show "$unit" ${args[@]+"${args[@]}"} 2>/dev/null || true
}

# evidence_systemd_field <show-output> <Prop>: the value of one Prop= line.
# Split from the fetch so a caller reads N properties with ONE systemctl
# round trip instead of N — at a 60 s cadence over several units the
# difference is the whole added cost of the sample.
evidence_systemd_field() {
    printf '%s\n' "${1:-}" | sed -n "s/^$2=\(.*\)$/\1/p" | head -n1
}

# evidence_systemd_cat <unit>: the unit file PLUS every drop-in, exactly as
# systemd merged them, with the `# /path/to/file` provenance headers.
# This is the input to the config-drift hash: ten drop-ins overriding
# ExecStart/WatchdogSec/OOMScoreAdjust are invisible in the tracked unit
# and visible here.
evidence_systemd_cat() {
    local unit="${1:-}"
    [ -n "$unit" ] || { printf ''; return 0; }
    command -v systemctl >/dev/null 2>&1 || { printf ''; return 0; }
    timeout "$ZCL_EVIDENCE_TIMEOUT_SEC" \
        systemctl --user cat "$unit" 2>/dev/null || true
}

# evidence_ts_to_epoch <systemd-timestamp>: epoch seconds, "" when the
# string is empty or unparseable (systemd prints "n/a" for a unit that has
# never been active — that must stay "" and not become epoch 0).
evidence_ts_to_epoch() {
    local s="${1:-}"
    case "$s" in '' | n/a | 'n/a') printf ''; return 0 ;; esac
    local v
    v="$(date -d "$s" +%s 2>/dev/null || true)"
    case "${v:-}" in '' | *[!0-9]*) printf '' ;; *) printf '%s' "$v" ;; esac
}

# evidence_unit_exec_bin <show-output>: the absolute path of the binary the
# unit will exec, parsed from the ExecStart property. systemd renders it as
#   { path=/x/y ; argv[]=/x/y --flag ; ... }
# and a drop-in that resets ExecStart changes exactly this. "" when absent.
evidence_unit_exec_bin() {
    printf '%s\n' "${1:-}" |
        sed -n 's/^ExecStart=.*[{;][[:space:]]*path=\([^ ;]*\).*/\1/p' |
        head -n1
}

# evidence_unit_exec_arg <show-output> <key>: the value of exactly one
# `-key=value` token in the argv[] segment of an ExecStart property.  The
# service contract deliberately forbids whitespace in these values; an
# absent or duplicated key prints "" so a collector can fall back without
# guessing which configured endpoint is authoritative.
evidence_unit_exec_arg() {
    local show="${1:-}" key="${2:-}" values="" count=""
    case "$key" in '' | *[!0-9A-Za-z_-]*) printf ''; return 0 ;; esac
    values="$(printf '%s\n' "$show" |
        sed -n 's/^ExecStart=.*argv\[\]=\([^;]*\);.*$/\1/p' |
        tr ' ' '\n' |
        sed -n "s/^-${key}=//p")"
    count="$(printf '%s\n' "$values" |
        awk 'NF { n++ } END { print n + 0 }')"
    [ "$count" = "1" ] || { printf ''; return 0; }
    printf '%s\n' "$values" | awk 'NF { print; exit }'
}

# ── hashing ────────────────────────────────────────────────────────────

# evidence_sha256_file <path>: lowercase hex digest, "" when unreadable.
# Used for BOTH the on-disk service binary and /proc/<pid>/exe: those two
# diverging is a binary swapped underneath a running node, which is the
# exact drift that happened on this host on 2026-07-28 and that no ledger
# recorded.
evidence_sha256_file() {
    local p="${1:-}"
    [ -n "$p" ] && [ -r "$p" ] || { printf ''; return 0; }
    timeout "$ZCL_EVIDENCE_TIMEOUT_SEC" sha256sum -- "$p" 2>/dev/null |
        awk 'NR==1{print $1}' || true
}

# evidence_sha256_stdin: lowercase hex digest of stdin, "" on empty input.
# Hashing the empty string to its well-known digest would make "systemctl
# cat failed" indistinguishable from "the unit is empty".
evidence_sha256_stdin() {
    local data; data="$(cat)"
    [ -n "$data" ] || { printf ''; return 0; }
    printf '%s' "$data" | sha256sum 2>/dev/null | awk 'NR==1{print $1}' || true
}

# ── node self-report ───────────────────────────────────────────────────

# evidence_node_dumpstate <bin> <subsystem> [datadir] [rpcport]: one typed
# dumpstate blob, single-line, bounded, NEVER fatal — "" on any
# absence/timeout/failure. This is the reader slo_page_if_stalled.sh's
# blocker enrichment already used; the SLO collector now uses the same one
# instead of inventing a second way to ask the node what is blocking it.
#
# Unlike every other function here the result is a NODE SELF-REPORT, not a
# client-viewpoint measurement. Callers must label it as such: a wedged
# node can answer this call with a stale or cheerful story, which is why
# reachability and height are still measured from outside.
evidence_node_dumpstate() {
    local bin="${1:-}" subsystem="${2:-}" datadir="${3:-}" rpcport="${4:-}"
    [ -n "$bin" ] && [ -n "$subsystem" ] || { printf ''; return 0; }
    [ -x "$bin" ] || { printf ''; return 0; }
    local args=()
    [ -n "$datadir" ] && args+=("-datadir=$datadir")
    [ -n "$rpcport" ] && args+=("-rpcport=$rpcport")
    # See evidence_systemd_show for why the array is expanded this way —
    # and here it matters on every call: slo_page_if_stalled.sh asks for a
    # blocker with no datadir and no rpcport, so `args` is routinely empty.
    local out
    out="$(timeout "$ZCL_EVIDENCE_TIMEOUT_SEC" "$bin" ${args[@]+"${args[@]}"} \
        dumpstate "$subsystem" 2>/dev/null || true)"
    printf '%s' "$out" | tr '\n\r\t' '   '
}

# ── ledger plumbing ────────────────────────────────────────────────────

# evidence_append_line <file> <line>: flock-serialized append with a
# BOUNDED wait and an EXPLICIT failure. `set -e` is suppressed inside an
# if/|| condition context, so without the explicit `|| exit 9` a missing or
# failing flock would silently degrade to an UNLOCKED append; without -w a
# stuck holder would block until the unit's TimeoutStartSec killed the run.
# Returns non-zero (and says why on stderr) only when the LEDGER could not
# be written — the one failure a collector must surface.
evidence_append_line() {
    local file="$1" line="$2" tag="${3:-evidence}" rc=0
    (
        flock -x -w 30 9 || exit 9
        printf '%s\n' "$line" >&9
    ) 9>>"$file" || rc=$?
    if [ "$rc" -ne 0 ]; then
        if [ "$rc" -eq 9 ]; then
            echo "$tag: FAIL could not acquire append lock on $file within 30s" >&2
        else
            echo "$tag: FAIL could not append to $file (rc=$rc)" >&2
        fi
        return 1
    fi
    return 0
}
