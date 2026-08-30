#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# intervention_ledger.sh — the record of every time a human or an agent
# touched a node, and of every change to a node that NOBODY claimed.
#
# WHY THIS EXISTS
# ---------------
# "The node ran N days with zero operator intervention" was, until this
# file, an UNFALSIFIABLE claim on this host. Nothing recorded interventions.
# The closest thing was soak_evidence.sh, which INFERS restarts once an hour
# from systemd NRestarts decreasing or ActiveEnterTimestamp jumping. That
# inference misses three whole classes of intervention:
#
#   1. A restart-and-restart-again inside one sampling hour looks like one
#      event, or like none.
#   2. A configuration edit that changes how the node runs but does not
#      restart it is completely invisible. On this host TEN systemd
#      drop-ins have accumulated over the tracked unit — four of them
#      resetting ExecStart, one disabling the hang watchdog (WatchdogSec=0),
#      one INVERTING the OOM protection (OOMScoreAdjust=200 over the
#      tracked -800). No ledger anywhere recorded any of them appearing.
#   3. A BINARY SWAP with no restart at all. That is not hypothetical: on
#      2026-07-28 ~/.local/bin/zclassic23-live was replaced at 11:10 and
#      the unit restarted at 11:12, an undocumented deploy that left the
#      build-identity drop-in claiming a commit 70 behind HEAD. NRestarts
#      inference cannot see the swap, only (maybe) the restart.
#
# So this collector records, per cycle, per watched unit:
#   (i)   every ActiveState transition, with InvocationID and the systemd
#         Result (the queryable form of the SERVICE_RESULT the unit's own
#         ExecStopPost writes) — invocation-level, so two restarts inside
#         one cycle are still two InvocationID values, not one delta;
#   (ii)  a sha256 of the unit AS SYSTEMD SEES IT — `systemctl cat`, which
#         includes every drop-in — so a config edit is an event even with
#         no restart;
#   (iii) a sha256 of the service binary on disk AND of /proc/<MainPID>/exe,
#         so a binary swap is an event even with no restart, and so a
#         binary swapped UNDERNEATH a running node (the two digests
#         diverging) is its own distinct event;
#   (iv)  an attribution: whether a human or agent DECLARED the touch via
#         `zcl-intervene "<reason>"` inside the attribution window. An
#         undeclared change is recorded as attribution "unattributed" —
#         which is the entire point. Unattributed changes are the ones that
#         falsify a zero-intervention claim.
#
# WHAT MAKES THE CLAIM FALSIFIABLE
# --------------------------------
# Two properties, both deliberate:
#   - The ledger is EVENT-driven, not sample-driven: a quiet node writes
#     nothing. That keeps the file small enough to never need rotation, so
#     the record is genuinely append-only and never truncated — no
#     generation of history is ever dropped, unlike the sampling ledgers
#     which must roll.
#   - Because a quiet node writes nothing, "no events" would otherwise be
#     indistinguishable from "the collector was dead the whole time". So a
#     HEARTBEAT line is written at most once per ZCL_INTERVENE_HEARTBEAT_SEC
#     (default daily) carrying the current digests. A window with neither
#     events nor heartbeats is NOT evidence of a quiet node; it is a gap,
#     and `summary` reports it as one.
#
# It is an OBSERVER. It never restarts, stops, reloads, enables, disables,
# or edits any unit, and it never writes inside any datadir.
#
# Usage:
#   intervention_ledger.sh [collect]        one detection cycle
#   intervention_ledger.sh declare <reason> record a declared intervention
#                                           (what `zcl-intervene` calls)
#   intervention_ledger.sh summary [since]  counts since epoch `since`
#                                           (default: all)
#   intervention_ledger.sh --selftest       hermetic; fixtures, no units
#
# Env (operator + test injection seams):
#   ZCL_INTERVENE_DIR         ledger dir
#                             (default ~/.local/state/zclassic23-intervention)
#   ZCL_INTERVENE_UNITS       space/comma separated units to watch
#                             (default: zclassic23.service)
#   ZCL_INTERVENE_WINDOW_SEC  attribution window (default 900)
#   ZCL_INTERVENE_HEARTBEAT_SEC
#                             max quiet period before a heartbeat line
#                             (default 86400)
#   ZCL_INTERVENE_SHOW_CMD    override the systemd property read;
#                             ZCL_INTERVENE_UNIT is exported to it
#   ZCL_INTERVENE_CAT_CMD     override `systemctl cat`; same export
#   ZCL_INTERVENE_RUNNING_EXE_CMD
#                             override the /proc/<pid>/exe digest read;
#                             ZCL_INTERVENE_PID is exported to it
#
# No python (banned), no jq — bash + sed + coreutils + flock only.

set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELF="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"

EVIDENCE_LIB="$SCRIPT_DIR/lib/evidence_sources.sh"
if [ ! -r "$EVIDENCE_LIB" ]; then
    echo "intervention-ledger: FATAL missing reader library $EVIDENCE_LIB" >&2
    exit 3
fi
# shellcheck source=lib/evidence_sources.sh
. "$EVIDENCE_LIB"

LEDGER_DIR="${ZCL_INTERVENE_DIR:-${HOME:-/root}/.local/state/zclassic23-intervention}"
LEDGER_FILE="$LEDGER_DIR/intervention-ledger.jsonl"
STATE_DIR="$LEDGER_DIR/state"
DECL_DIR="$LEDGER_DIR/declarations"
WINDOW_SEC="${ZCL_INTERVENE_WINDOW_SEC:-900}"
HEARTBEAT_SEC="${ZCL_INTERVENE_HEARTBEAT_SEC:-86400}"

# Watched units. Deliberately NOT auto-discovered: a collector that decides
# for itself what to watch quietly stops watching the thing you cared about
# the day its name changes.
UNITS_RAW="${ZCL_INTERVENE_UNITS:-zclassic23.service}"

units_list() { printf '%s' "$UNITS_RAW" | tr ',' ' '; }

# ── state ──────────────────────────────────────────────────────────────
# One file per unit per key. Tiny, greppable, and survives the ledger being
# archived — the detector's memory must not live in the artifact it writes.

state_path() { printf '%s/%s/%s' "$STATE_DIR" "$(printf '%s' "$1" | tr '/' '_')" "$2"; }

state_read() {
    local f; f="$(state_path "$1" "$2")"
    [ -f "$f" ] && cat "$f" 2>/dev/null || true
}

state_write() {
    local f; f="$(state_path "$1" "$2")"
    mkdir -p "$(dirname "$f")" 2>/dev/null || return 0
    printf '%s\n' "$3" > "$f.tmp" 2>/dev/null && mv -f "$f.tmp" "$f" 2>/dev/null
    return 0
}

# ── declarations ───────────────────────────────────────────────────────

# declare_intervention <reason>: record that a human or agent is about to
# touch (or just touched) something. Written BEFORE the detector sees the
# effect in the ordinary case, but the window is symmetric so a declaration
# filed immediately after still attributes.
cmd_declare() {
    local reason="${1:-}"
    if [ -z "$reason" ]; then
        echo "intervention-ledger: FAIL declare needs a reason — an unexplained declaration is not an attribution" >&2
        return 2
    fi
    mkdir -p "$DECL_DIR" "$LEDGER_DIR"
    local ts; ts="$(date +%s)"
    local id="$ts-$$"
    local who="${SUDO_USER:-${USER:-$(id -un 2>/dev/null || echo unknown)}}"
    # Provenance of the declaration itself: an agent-run declaration and a
    # human-at-a-terminal declaration are different evidence, and an
    # attribution nobody can trace back is barely better than none.
    local origin="local"
    [ -n "${SSH_CONNECTION:-}" ] && origin="ssh"
    [ -n "${ZCL_INTERVENE_ORIGIN:-}" ] && origin="$ZCL_INTERVENE_ORIGIN"
    local actor="${ZCL_INTERVENE_ACTOR:-$who}"

    printf '%s\n' "$reason" > "$DECL_DIR/$id" 2>/dev/null || true

    local line
    line="$(printf '{"ts":%s,"kind":"declared","declaration_id":%s,"actor":%s,"origin":%s,"reason":%s}' \
        "$ts" "$(evidence_jstr "$id")" "$(evidence_jstr "$actor")" \
        "$(evidence_jstr "$origin")" "$(evidence_jstr "$reason")")"
    evidence_append_line "$LEDGER_FILE" "$line" "intervention-ledger" || return 1
    echo "$line"
    return 0
}

# declaration_in_window <now>: id of the most recent declaration whose
# timestamp is within +/- WINDOW_SEC of now, "" when there is none.
# Symmetric because interventions get declared both before ("I am about to
# deploy") and after ("that was me"), and a one-sided window would label
# half of all honest declarations unattributed.
declaration_in_window() {
    local now="$1" best="" best_ts=0 f base ts
    [ -d "$DECL_DIR" ] || { printf ''; return 0; }
    for f in "$DECL_DIR"/*; do
        [ -f "$f" ] || continue
        base="$(basename "$f")"
        ts="${base%%-*}"
        case "$ts" in '' | *[!0-9]*) continue ;; esac
        local delta=$((now - ts))
        [ "$delta" -lt 0 ] && delta=$(( -delta ))
        [ "$delta" -le "$WINDOW_SEC" ] || continue
        if [ "$ts" -ge "$best_ts" ]; then best_ts="$ts"; best="$base"; fi
    done
    printf '%s' "$best"
}

declaration_reason() {
    local id="${1:-}"
    [ -n "$id" ] && [ -f "$DECL_DIR/$id" ] || { printf ''; return 0; }
    head -c 400 "$DECL_DIR/$id" 2>/dev/null || true
}

# prune_declarations <now>: drop claim files older than 30 days. The claim
# FILES are a working index for the window check; the permanent record of
# every declaration is the ledger line, which is never pruned.
prune_declarations() {
    # Split declaration: `local a=$1 b=$((a-1))` is not portable across
    # bash versions under `set -u` — some declare every name before
    # assigning any, so the arithmetic sees an unset `now`.
    local now="$1" f base ts cutoff
    cutoff=$((now - 2592000))
    [ -d "$DECL_DIR" ] || return 0
    for f in "$DECL_DIR"/*; do
        [ -f "$f" ] || continue
        base="$(basename "$f")"; ts="${base%%-*}"
        case "$ts" in '' | *[!0-9]*) continue ;; esac
        [ "$ts" -lt "$cutoff" ] && rm -f "$f" 2>/dev/null || true
    done
    return 0
}

# ── observation ────────────────────────────────────────────────────────

# observe_unit <unit>: one systemd round trip plus the three digests.
# Prints \x1f-separated:
#   1 active_state  2 sub_state  3 invocation_id  4 nrestarts
#   5 active_enter_ts(epoch)  6 result  7 exec_main_status  8 mainpid
#   9 exec_bin  10 unit_config_sha  11 binary_sha  12 running_binary_sha
observe_unit() {
    local unit="$1" show_out="" cat_out=""

    if [ -n "${ZCL_INTERVENE_SHOW_CMD:-}" ]; then
        show_out="$(ZCL_INTERVENE_UNIT="$unit" bash -c "$ZCL_INTERVENE_SHOW_CMD" 2>/dev/null || true)"
    else
        show_out="$(evidence_systemd_show "$unit" \
            ActiveState SubState InvocationID NRestarts ActiveEnterTimestamp \
            Result ExecMainStatus MainPID ExecStart)"
    fi

    local active_state sub_state invocation nrestarts aet result exec_status mainpid
    active_state="$(evidence_systemd_field "$show_out" ActiveState)"
    sub_state="$(evidence_systemd_field "$show_out" SubState)"
    invocation="$(evidence_systemd_field "$show_out" InvocationID)"
    nrestarts="$(evidence_systemd_field "$show_out" NRestarts)"
    aet="$(evidence_ts_to_epoch "$(evidence_systemd_field "$show_out" ActiveEnterTimestamp)")"
    result="$(evidence_systemd_field "$show_out" Result)"
    exec_status="$(evidence_systemd_field "$show_out" ExecMainStatus)"
    mainpid="$(evidence_systemd_field "$show_out" MainPID)"
    case "$nrestarts" in *[!0-9]*) nrestarts="" ;; esac
    case "$mainpid" in *[!0-9]*) mainpid="" ;; esac

    local exec_bin; exec_bin="$(evidence_unit_exec_bin "$show_out")"

    if [ -n "${ZCL_INTERVENE_CAT_CMD:-}" ]; then
        cat_out="$(ZCL_INTERVENE_UNIT="$unit" bash -c "$ZCL_INTERVENE_CAT_CMD" 2>/dev/null || true)"
    else
        cat_out="$(evidence_systemd_cat "$unit")"
    fi
    local unit_sha; unit_sha="$(printf '%s' "$cat_out" | evidence_sha256_stdin)"

    local bin_sha; bin_sha="$(evidence_sha256_file "$exec_bin")"

    local run_sha=""
    if [ -n "${ZCL_INTERVENE_RUNNING_EXE_CMD:-}" ]; then
        run_sha="$(ZCL_INTERVENE_PID="$mainpid" bash -c "$ZCL_INTERVENE_RUNNING_EXE_CMD" 2>/dev/null || true)"
    elif [ -n "$mainpid" ] && [ "$mainpid" != "0" ]; then
        run_sha="$(evidence_sha256_file "/proc/$mainpid/exe")"
    fi

    printf '%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s' \
        "$active_state" "$sub_state" "$invocation" "$nrestarts" "$aet" \
        "$result" "$exec_status" "$mainpid" "$exec_bin" \
        "$unit_sha" "$bin_sha" "$run_sha"
}

fld() { printf '%s' "$1" | cut -d $'\x1f' -f"$2"; }

# ── collect ────────────────────────────────────────────────────────────

EVENTS_THIS_RUN=0
UNATTRIBUTED_THIS_RUN=0

# emit_event <ts> <unit> <kind> <from> <to> <obs> <detail>
emit_event() {
    local ts="$1" unit="$2" kind="$3" from="$4" to="$5" obs="$6" detail="$7"
    local decl="" attribution reason=""
    case "$kind" in
        # Not operator actions, so not attributable: the first observation
        # of a unit, and the two RECOVERY edges. Marking these
        # "unattributed" would open every fresh install with a false
        # accusation and make the detector's own noise indistinguishable
        # from a real undeclared touch.
        baseline | observable | binary_running_converged)
            attribution="n/a"
            ;;
        *)
            decl="$(declaration_in_window "$ts")"
            if [ -n "$decl" ]; then
                attribution="attributed"; reason="$(declaration_reason "$decl")"
            else
                attribution="unattributed"
                UNATTRIBUTED_THIS_RUN=$((UNATTRIBUTED_THIS_RUN + 1))
            fi
            ;;
    esac
    EVENTS_THIS_RUN=$((EVENTS_THIS_RUN + 1))

    local line
    line="$(printf '{"ts":%s,"kind":%s,"unit":%s,"change":%s,"from":%s,"to":%s,"attribution":%s,"declaration_id":%s,"declared_reason":%s,"active_state":%s,"sub_state":%s,"invocation_id":%s,"service_result":%s,"exec_main_status":%s,"nrestarts":%s,"active_enter_ts":%s,"mainpid":%s,"exec_bin":%s,"unit_config_sha256":%s,"binary_sha256":%s,"running_binary_sha256":%s,"detail":%s}' \
        "$ts" "$(evidence_jstr "event")" "$(evidence_jstr "$unit")" \
        "$(evidence_jstr "$kind")" "$(evidence_jstr "$from")" "$(evidence_jstr "$to")" \
        "$(evidence_jstr "$attribution")" "$(evidence_jstr "$decl")" \
        "$(evidence_jstr "$reason")" \
        "$(evidence_jstr "$(fld "$obs" 1)")" "$(evidence_jstr "$(fld "$obs" 2)")" \
        "$(evidence_jstr "$(fld "$obs" 3)")" "$(evidence_jstr "$(fld "$obs" 6)")" \
        "$(evidence_jnum "$(fld "$obs" 7)")" "$(evidence_jnum "$(fld "$obs" 4)")" \
        "$(evidence_jnum "$(fld "$obs" 5)")" "$(evidence_jnum "$(fld "$obs" 8)")" \
        "$(evidence_jstr "$(fld "$obs" 9)")" "$(evidence_jstr "$(fld "$obs" 10)")" \
        "$(evidence_jstr "$(fld "$obs" 11)")" "$(evidence_jstr "$(fld "$obs" 12)")" \
        "$(evidence_jstr "$detail")")"
    evidence_append_line "$LEDGER_FILE" "$line" "intervention-ledger" || return 1
    echo "$line"
    if [ "$attribution" = "unattributed" ]; then
        echo "intervention-ledger: UNATTRIBUTED unit=$unit change=$kind from='$from' to='$to' — no zcl-intervene declaration within ${WINDOW_SEC}s. A zero-intervention claim covering this instant is FALSE." >&2
    fi
    return 0
}

cmd_collect() {
    mkdir -p "$LEDGER_DIR" "$STATE_DIR" "$DECL_DIR"
    local ts; ts="$(date +%s)"
    prune_declarations "$ts"

    local rc=0 unit obs
    for unit in $(units_list); do
        [ -n "$unit" ] || continue
        obs="$(observe_unit "$unit")"

        local active_state invocation nrestarts result unit_sha bin_sha run_sha exec_bin
        active_state="$(fld "$obs" 1)"
        invocation="$(fld "$obs" 3)"
        nrestarts="$(fld "$obs" 4)"
        result="$(fld "$obs" 6)"
        exec_bin="$(fld "$obs" 9)"
        unit_sha="$(fld "$obs" 10)"
        bin_sha="$(fld "$obs" 11)"
        run_sha="$(fld "$obs" 12)"

        # A completely empty observation means systemd could not be asked
        # at all. Recording that as "the unit went inactive and its binary
        # vanished" would manufacture four false interventions per cycle,
        # so it is its own event, once, and no state is overwritten.
        if [ -z "$active_state" ] && [ -z "$unit_sha" ] && [ -z "$bin_sha" ]; then
            if [ "$(state_read "$unit" observable)" != "0" ]; then
                emit_event "$ts" "$unit" "unobservable" "observable" "unobservable" \
                    "$obs" "systemctl could not be read — this is a gap in the record, not a quiet node" || rc=1
                state_write "$unit" observable 0
            fi
            continue
        fi
        [ "$(state_read "$unit" observable)" = "0" ] &&
            emit_event "$ts" "$unit" "observable" "unobservable" "observable" "$obs" \
                "systemd readable again" >/dev/null
        state_write "$unit" observable 1

        local prev_seen; prev_seen="$(state_read "$unit" seen)"
        if [ -z "$prev_seen" ]; then
            # First sight is a baseline, not an intervention. Recorded so
            # the ledger says where the digests started; anything that
            # differs from here on is a change with a known predecessor.
            emit_event "$ts" "$unit" "baseline" "" "$active_state" "$obs" \
                "first observation — establishes the digests every later comparison is against" || rc=1
        else
            local p_active p_inv p_nrest p_unit p_bin p_run p_exec
            p_active="$(state_read "$unit" active_state)"
            p_inv="$(state_read "$unit" invocation)"
            p_nrest="$(state_read "$unit" nrestarts)"
            p_unit="$(state_read "$unit" unit_sha)"
            p_bin="$(state_read "$unit" bin_sha)"
            p_run="$(state_read "$unit" run_sha)"
            p_exec="$(state_read "$unit" exec_bin)"

            # (i) every ActiveState transition, carrying InvocationID and
            #     the systemd Result — the queryable SERVICE_RESULT.
            [ "$active_state" != "$p_active" ] &&
                { emit_event "$ts" "$unit" "active_state" "$p_active" "$active_state" "$obs" \
                    "service_result=$result" || rc=1; }

            # A new InvocationID is a restart even when both samples read
            # "active" — this is what defeats the hourly NRestarts
            # inference: two restarts inside one cycle still produce a
            # different InvocationID than the one on record.
            [ -n "$invocation" ] && [ "$invocation" != "$p_inv" ] &&
                { emit_event "$ts" "$unit" "invocation" "$p_inv" "$invocation" "$obs" \
                    "unit was (re)started; service_result=$result nrestarts=$nrestarts" || rc=1; }

            # NRestarts DECREASING is the classic manual-restart signature
            # (systemd resets the counter on an explicit restart).
            if [ -n "$nrestarts" ] && [ -n "$p_nrest" ] && [ "$nrestarts" != "$p_nrest" ]; then
                local nkind="restart_counter"
                [ "$nrestarts" -lt "$p_nrest" ] && nkind="restart_counter_reset"
                emit_event "$ts" "$unit" "$nkind" "$p_nrest" "$nrestarts" "$obs" \
                    "NRestarts moved; a DECREASE means the counter was reset by an explicit restart" || rc=1
            fi

            # (ii) config drift: the unit AS MERGED, drop-ins included.
            [ -n "$unit_sha" ] && [ -n "$p_unit" ] && [ "$unit_sha" != "$p_unit" ] &&
                { emit_event "$ts" "$unit" "unit_config" "$p_unit" "$unit_sha" "$obs" \
                    "systemctl cat digest changed — a unit file or drop-in was added, edited, or removed" || rc=1; }

            [ -n "$exec_bin" ] && [ -n "$p_exec" ] && [ "$exec_bin" != "$p_exec" ] &&
                { emit_event "$ts" "$unit" "exec_start" "$p_exec" "$exec_bin" "$obs" \
                    "the unit now execs a different path" || rc=1; }

            # (iii) binary swap, WITH OR WITHOUT a restart.
            # Both digests must be non-empty to compare: an UNREADABLE
            # binary (deleted mid-deploy, permissions changed) must not be
            # reported as "the binary changed to nothing". Known gap —
            # the transition readable -> unreadable currently produces no
            # event of its own, only a silent skip until it comes back.
            [ -n "$bin_sha" ] && [ -n "$p_bin" ] && [ "$bin_sha" != "$p_bin" ] &&
                { emit_event "$ts" "$unit" "binary_swap" "$p_bin" "$bin_sha" "$obs" \
                    "the service binary on disk was replaced" || rc=1; }

            [ -n "$run_sha" ] && [ -n "$p_run" ] && [ "$run_sha" != "$p_run" ] &&
                { emit_event "$ts" "$unit" "running_binary" "$p_run" "$run_sha" "$obs" \
                    "the process is now running a different image" || rc=1; }
        fi

        # Standing condition, re-checked every cycle rather than only on
        # change: the on-disk binary and the running image disagreeing
        # means a deploy landed that the node has not picked up. That is
        # the 2026-07-28 shape exactly, and it can persist for days.
        local p_div; p_div="$(state_read "$unit" divergent)"
        if [ -n "$bin_sha" ] && [ -n "$run_sha" ] && [ "$bin_sha" != "$run_sha" ]; then
            if [ "$p_div" != "1" ]; then
                emit_event "$ts" "$unit" "binary_running_divergence" "$run_sha" "$bin_sha" "$obs" \
                    "on-disk binary != running image — a deploy landed that this process is not running" || rc=1
            fi
            state_write "$unit" divergent 1
        else
            [ "$p_div" = "1" ] &&
                { emit_event "$ts" "$unit" "binary_running_converged" "divergent" "converged" "$obs" \
                    "running image now matches the on-disk binary" || rc=1; }
            state_write "$unit" divergent 0
        fi

        state_write "$unit" seen 1
        state_write "$unit" active_state "$active_state"
        state_write "$unit" invocation "$invocation"
        state_write "$unit" nrestarts "$nrestarts"
        state_write "$unit" unit_sha "$unit_sha"
        state_write "$unit" bin_sha "$bin_sha"
        state_write "$unit" run_sha "$run_sha"
        state_write "$unit" exec_bin "$exec_bin"
    done

    # Heartbeat: proves the detector was ALIVE during a quiet stretch. See
    # the header — without it, "no events" and "collector dead" produce the
    # same ledger, and the zero-intervention claim becomes unfalsifiable
    # again by a different route.
    local last_hb; last_hb="$(state_read _global last_heartbeat)"
    case "$last_hb" in '' | *[!0-9]*) last_hb=0 ;; esac
    if [ "$EVENTS_THIS_RUN" -eq 0 ] && [ $((ts - last_hb)) -ge "$HEARTBEAT_SEC" ]; then
        local hb
        hb="$(printf '{"ts":%s,"kind":"heartbeat","units":%s,"window_sec":%s,"detail":%s}' \
            "$ts" "$(evidence_jstr "$UNITS_RAW")" "$WINDOW_SEC" \
            "$(evidence_jstr "detector alive, no change observed")")"
        evidence_append_line "$LEDGER_FILE" "$hb" "intervention-ledger" || rc=1
        echo "$hb"
        state_write _global last_heartbeat "$ts"
    fi
    [ "$EVENTS_THIS_RUN" -gt 0 ] && state_write _global last_heartbeat "$ts"

    echo "intervention-ledger: collect done file=$LEDGER_FILE units=$(units_list | wc -w) events=$EVENTS_THIS_RUN unattributed=$UNATTRIBUTED_THIS_RUN"
    return "$rc"
}

# ── summary ────────────────────────────────────────────────────────────

cmd_summary() {
    local since="${1:-0}"
    case "$since" in '' | *[!0-9]*) since=0 ;; esac
    if [ ! -f "$LEDGER_FILE" ]; then
        echo "intervention-ledger: NO LEDGER at $LEDGER_FILE — an absent ledger is NOT a zero-intervention proof"
        return 0
    fi
    awk -v since="$since" '
        function fld(line, key,   re, s) {
            re = "\"" key "\":\"[^\"]*\""
            if (match(line, re)) {
                s = substr(line, RSTART, RLENGTH)
                sub("\"" key "\":\"", "", s); sub("\"$", "", s)
                return s
            }
            return ""
        }
        {
            ts = 0
            if (match($0, /"ts":[0-9]+/)) { ts = substr($0, RSTART + 5, RLENGTH - 5) + 0 }
            if (ts < since) next
            if (first == 0 || ts < first) first = ts
            if (ts > last) last = ts
            k = fld($0, "kind")
            if (k == "heartbeat") { hb++; next }
            if (k == "declared")  { decl++; next }
            ch = fld($0, "change")
            n[ch]++
            events++
            if (fld($0, "attribution") == "unattributed") unattributed++
        }
        END {
            printf "intervention-ledger summary: window=[%d,%d] events=%d declared=%d heartbeats=%d unattributed=%d\n",
                first, last, events, decl, hb, unattributed
            for (k in n) printf "  change=%-28s count=%d\n", k, n[k]
            if (unattributed > 0)
                printf "VERDICT: zero-operator-intervention is FALSE for this window (%d unattributed change(s))\n", unattributed
            else if (events == 0 && hb == 0)
                printf "VERDICT: UNPROVEN — no events AND no heartbeats; the detector may not have been running\n"
            else
                printf "VERDICT: no unattributed change observed in this window\n"
        }
    ' "$LEDGER_FILE"
}

# ── selftest ───────────────────────────────────────────────────────────

st_fail() { echo "selftest: FAIL $*" >&2; exit 1; }

cmd_selftest() {
    ST_TMP="$(mktemp -d /tmp/zcl-intervention-selftest.XXXXXX)"
    trap 'rm -rf "$ST_TMP"' EXIT

    local BIN="$ST_TMP/fakebin"
    printf 'v1' > "$BIN"; chmod +x "$BIN"
    local RUNSHA_FILE="$ST_TMP/runsha"
    printf '%s' "$(evidence_sha256_file "$BIN")" > "$RUNSHA_FILE"

    # Fixture systemd. UNIT_STATE_FILE lets a case mutate what "systemctl"
    # reports between cycles without touching any real unit.
    local SHOWF="$ST_TMP/show" CATF="$ST_TMP/cat"
    write_show() {
        printf 'ActiveState=%s\nSubState=%s\nInvocationID=%s\nNRestarts=%s\nActiveEnterTimestamp=Tue 2026-07-28 11:12:00 UTC\nResult=%s\nExecMainStatus=0\nMainPID=4242\nExecStart={ path=%s ; argv[]=%s ; ignore_errors=no }\n' \
            "$1" "$2" "$3" "$4" "$5" "$BIN" "$BIN" > "$SHOWF"
    }
    write_show active running INV-AAA 0 success
    printf '# /etc/systemd/user/zclassic23.service\n[Service]\nExecStart=%s\n' "$BIN" > "$CATF"

    local ENVV=(
        "ZCL_INTERVENE_DIR=$ST_TMP/led"
        "ZCL_INTERVENE_UNITS=fake.service"
        "ZCL_INTERVENE_SHOW_CMD=cat $SHOWF"
        "ZCL_INTERVENE_CAT_CMD=cat $CATF"
        "ZCL_INTERVENE_RUNNING_EXE_CMD=cat $RUNSHA_FILE"
        "ZCL_INTERVENE_HEARTBEAT_SEC=100000"
    )
    local L="$ST_TMP/led/intervention-ledger.jsonl"

    # A) first cycle is a BASELINE, and it must not be counted as an
    #    unattributed intervention (or every fresh install would open with
    #    a false accusation).
    local out
    out="$(env "${ENVV[@]}" bash "$SELF" collect 2>&1)" || st_fail "case=baseline collect must exit 0"
    grep -q '"change":"baseline"' "$L" || { cat "$L" >&2; st_fail "case=baseline no baseline line"; }
    grep -q '"attribution":"n/a"' <<<"$(grep '"change":"baseline"' "$L")" \
        || { cat "$L" >&2; st_fail "case=baseline first sight must be attribution n/a, never unattributed"; }
    printf '%s' "$out" | grep -q 'events=1 unattributed=0' \
        || { printf '%s\n' "$out" >&2; st_fail "case=baseline must not count the baseline as unattributed"; }
    printf '%s' "$out" | grep -q 'UNATTRIBUTED' \
        && { printf '%s\n' "$out" >&2; st_fail "case=baseline must not shout UNATTRIBUTED on a first observation"; }
    grep -q '"binary_sha256":"[0-9a-f]\{64\}"' <<<"$(grep '"change":"baseline"' "$L")" \
        || { cat "$L" >&2; st_fail "case=baseline must record a real binary digest"; }
    grep -q '"unit_config_sha256":"[0-9a-f]\{64\}"' <<<"$(grep '"change":"baseline"' "$L")" \
        || { cat "$L" >&2; st_fail "case=baseline must record the merged unit+drop-in digest"; }
    echo "selftest: ok case=baseline"

    # B) NEGATIVE case — nothing changed: no event line at all. A detector
    #    that fires on a quiet node is noise and gets muted, which is how
    #    monitors die.
    local before after
    before="$(wc -l < "$L")"
    out="$(env "${ENVV[@]}" bash "$SELF" collect 2>&1)" || st_fail "case=quiet collect must exit 0"
    after="$(wc -l < "$L")"
    [ "$before" -eq "$after" ] || { cat "$L" >&2; st_fail "case=quiet a quiet cycle must append nothing (before=$before after=$after)"; }
    printf '%s' "$out" | grep -q 'events=0 unattributed=0' \
        || { printf '%s\n' "$out" >&2; st_fail "case=quiet must report zero events"; }
    echo "selftest: ok case=quiet"

    # C) POSITIVE case, the one that matters and that NRestarts inference
    #    cannot see: the binary is swapped on disk with NO restart —
    #    same InvocationID, same NRestarts, same ActiveState. This is the
    #    2026-07-28 shape. It must produce binary_swap AND, because the
    #    running image still hashes to the old bytes, a divergence event.
    printf 'v2-different-bytes' > "$BIN"
    out="$(env "${ENVV[@]}" bash "$SELF" collect 2>&1)" || st_fail "case=binary-swap collect must exit 0"
    grep -q '"change":"binary_swap"' "$L" || { cat "$L" >&2; st_fail "case=binary-swap not detected"; }
    grep -q '"change":"binary_running_divergence"' "$L" \
        || { cat "$L" >&2; st_fail "case=binary-swap divergence from the running image not detected"; }
    grep -q '"attribution":"unattributed"' <<<"$(grep '"change":"binary_swap"' "$L")" \
        || { cat "$L" >&2; st_fail "case=binary-swap an undeclared swap MUST be unattributed"; }
    grep -q '"invocation_id":"INV-AAA"' <<<"$(grep '"change":"binary_swap"' "$L")" \
        || { cat "$L" >&2; st_fail "case=binary-swap must record the invocation it happened under"; }
    printf '%s' "$out" | grep -q 'UNATTRIBUTED unit=fake.service change=binary_swap' \
        || { printf '%s\n' "$out" >&2; st_fail "case=binary-swap must say so on stderr"; }
    echo "selftest: ok case=binary-swap-without-restart"

    # D) config drift with no restart: a drop-in edit changes the
    #    `systemctl cat` digest and nothing else. This is the ten-drop-in
    #    shape (WatchdogSec=0, OOMScoreAdjust=200) that was invisible.
    printf '# /etc/systemd/user/zclassic23.service\n[Service]\nExecStart=%s\n# /etc/systemd/user/zclassic23.service.d/90-x.conf\n[Service]\nWatchdogSec=0\n' "$BIN" > "$CATF"
    out="$(env "${ENVV[@]}" bash "$SELF" collect 2>&1)" || st_fail "case=config-drift collect must exit 0"
    grep -q '"change":"unit_config"' "$L" || { cat "$L" >&2; st_fail "case=config-drift not detected"; }
    grep -q '"attribution":"unattributed"' <<<"$(grep '"change":"unit_config"' "$L")" \
        || { cat "$L" >&2; st_fail "case=config-drift an undeclared drop-in edit MUST be unattributed"; }
    echo "selftest: ok case=config-drift-without-restart"

    # E) a real restart: new InvocationID and an ActiveState transition,
    #    both recorded, carrying the systemd Result.
    write_show activating start-pre INV-BBB 0 success
    out="$(env "${ENVV[@]}" bash "$SELF" collect 2>&1)" || st_fail "case=restart collect must exit 0"
    grep -q '"change":"active_state","from":"active","to":"activating"' "$L" \
        || { cat "$L" >&2; st_fail "case=restart ActiveState transition not recorded"; }
    grep -q '"change":"invocation","from":"INV-AAA","to":"INV-BBB"' "$L" \
        || { cat "$L" >&2; st_fail "case=restart InvocationID change not recorded"; }
    grep -q '"service_result":"success"' <<<"$(grep '"change":"invocation"' "$L")" \
        || { cat "$L" >&2; st_fail "case=restart must carry the systemd Result"; }
    echo "selftest: ok case=restart-records-invocation-and-result"

    # F) NRestarts DECREASING — the manual-restart signature soak_evidence
    #    can only guess at hourly resolution.
    write_show active running INV-CCC 0 success
    env "${ENVV[@]}" bash "$SELF" collect >/dev/null 2>&1 || true
    write_show active running INV-CCC 5 success
    env "${ENVV[@]}" bash "$SELF" collect >/dev/null 2>&1 || true
    write_show active running INV-DDD 0 success
    out="$(env "${ENVV[@]}" bash "$SELF" collect 2>&1)" || st_fail "case=nrestarts-reset collect must exit 0"
    grep -q '"change":"restart_counter_reset","from":"5","to":"0"' "$L" \
        || { cat "$L" >&2; st_fail "case=nrestarts-reset counter reset not classified"; }
    echo "selftest: ok case=nrestarts-reset"

    # G) ATTRIBUTION — the same swap, declared first, is attributed and
    #    carries the reason. This is the whole contract of `zcl-intervene`.
    env "${ENVV[@]}" bash "$SELF" declare "deploying build 34155ae4f to canonical" >/dev/null 2>&1 \
        || st_fail "case=attributed declare must exit 0"
    printf 'v3-declared-swap' > "$BIN"
    printf '%s' "$(evidence_sha256_file "$BIN")" > "$RUNSHA_FILE"
    out="$(env "${ENVV[@]}" bash "$SELF" collect 2>&1)" || st_fail "case=attributed collect must exit 0"
    printf '%s' "$out" | grep -q '"change":"binary_swap".*"attribution":"attributed"' \
        || { printf '%s\n' "$out" >&2; st_fail "case=attributed a declared swap must attribute"; }
    printf '%s' "$out" | grep -q '"declared_reason":"deploying build 34155ae4f to canonical"' \
        || { printf '%s\n' "$out" >&2; st_fail "case=attributed must carry the declared reason"; }
    printf '%s' "$out" | grep -q 'unattributed=0' \
        || { printf '%s\n' "$out" >&2; st_fail "case=attributed must not count a declared change as unattributed"; }
    echo "selftest: ok case=declared-change-is-attributed"

    # H) a declaration that has AGED OUT does not attribute anything. An
    #    attribution window that never expires would let one old "yes that
    #    was me" launder every future change.
    (
        export ZCL_INTERVENE_DIR="$ST_TMP/led"
        rm -rf "$ST_TMP/led/declarations"
        mkdir -p "$ST_TMP/led/declarations"
        printf 'ancient\n' > "$ST_TMP/led/declarations/1000000000-1"
    )
    printf 'v4-after-window' > "$BIN"
    out="$(env "${ENVV[@]}" bash "$SELF" collect 2>&1)" || st_fail "case=stale-declaration collect must exit 0"
    printf '%s' "$out" | grep -q '"change":"binary_swap".*"attribution":"unattributed"' \
        || { printf '%s\n' "$out" >&2; st_fail "case=stale-declaration an expired declaration must not attribute"; }
    echo "selftest: ok case=stale-declaration-does-not-attribute"

    # I) summary VERDICTs: this ledger has unattributed changes, so the
    #    zero-intervention claim must come back FALSE; and an empty ledger
    #    must come back UNPROVEN rather than clean.
    out="$(env "${ENVV[@]}" bash "$SELF" summary 2>&1)"
    printf '%s' "$out" | grep -q 'VERDICT: zero-operator-intervention is FALSE' \
        || { printf '%s\n' "$out" >&2; st_fail "case=summary must report FALSE when unattributed changes exist"; }
    out="$(env "ZCL_INTERVENE_DIR=$ST_TMP/empty" bash "$SELF" summary 2>&1)"
    printf '%s' "$out" | grep -q 'NO LEDGER' \
        || { printf '%s\n' "$out" >&2; st_fail "case=summary an absent ledger must not read as proof"; }
    mkdir -p "$ST_TMP/empty"; : > "$ST_TMP/empty/intervention-ledger.jsonl"
    out="$(env "ZCL_INTERVENE_DIR=$ST_TMP/empty" bash "$SELF" summary 2>&1)"
    printf '%s' "$out" | grep -q 'VERDICT: UNPROVEN' \
        || { printf '%s\n' "$out" >&2; st_fail "case=summary an empty ledger must be UNPROVEN, not clean"; }
    echo "selftest: ok case=summary-verdicts"

    # J) systemd unreadable: ONE unobservable event, not a storm of false
    #    interventions, and the recorded digests are not clobbered.
    local bin_before; bin_before="$(cat "$ST_TMP/led/state/fake.service/bin_sha")"
    out="$(env "${ENVV[@]}" "ZCL_INTERVENE_SHOW_CMD=false" "ZCL_INTERVENE_CAT_CMD=false" \
        "ZCL_INTERVENE_RUNNING_EXE_CMD=false" bash "$SELF" collect 2>&1)" \
        || st_fail "case=unobservable collect must exit 0"
    printf '%s' "$out" | grep -q '"change":"unobservable"' \
        || { printf '%s\n' "$out" >&2; st_fail "case=unobservable must record the gap"; }
    printf '%s' "$out" | grep -q 'events=1' \
        || { printf '%s\n' "$out" >&2; st_fail "case=unobservable must emit exactly one event"; }
    out="$(env "${ENVV[@]}" "ZCL_INTERVENE_SHOW_CMD=false" "ZCL_INTERVENE_CAT_CMD=false" \
        "ZCL_INTERVENE_RUNNING_EXE_CMD=false" bash "$SELF" collect 2>&1)"
    printf '%s' "$out" | grep -q 'events=0' \
        || { printf '%s\n' "$out" >&2; st_fail "case=unobservable must not re-fire while still unreadable"; }
    [ "$(cat "$ST_TMP/led/state/fake.service/bin_sha")" = "$bin_before" ] \
        || st_fail "case=unobservable must not clobber the recorded digests"
    echo "selftest: ok case=unobservable-is-a-gap-not-an-event-storm"

    # K) declare with no reason is refused. An attribution with no
    #    explanation attributes nothing.
    if env "${ENVV[@]}" bash "$SELF" declare "" >/dev/null 2>&1; then
        st_fail "case=declare-needs-reason an empty reason must be refused"
    fi
    echo "selftest: ok case=declare-needs-reason"

    echo "selftest: PASS"
}

# ── dispatch ───────────────────────────────────────────────────────────

case "${1:-collect}" in
    collect)    shift || true; cmd_collect "$@" ;;
    declare)    shift; cmd_declare "$@" ;;
    summary)    shift; cmd_summary "$@" ;;
    --selftest) shift; cmd_selftest "$@" ;;
    *)
        echo "usage: intervention_ledger.sh [collect] | declare <reason> | summary [since_epoch] | --selftest" >&2
        exit 2
        ;;
esac
