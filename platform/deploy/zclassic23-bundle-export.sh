#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# zclassic23-bundle-export.sh — scheduled, verified consensus-state-bundle
# export + retention + optional off-disk copy for ONE datadir.
#
# Wraps the EXISTING TERMINAL `-export-consensus-bundle` verb
# (engine/composition/src/boot_export_consensus_bundle.c): reads the compiled SHA3 UTXO
# checkpoint, binds the shielded tip to THIS datadir's own validated
# header-committed hashFinalSaplingRoot at that height, and writes
# consensus-state-bundle-<height>.sqlite INTO <datadir>. That verb already
# self-verifies (seals the bundle, re-derives + compares the on-disk digest
# before/after any post-write hook and after publish rename — engine/composition/src/
# consensus_state_snapshot_export.c) and REFUSES loudly with a typed reason
# on anything short of a complete, checkpoint-content-provable datadir. This
# script never guesses past a REFUSED — it only surfaces it, and adds:
#   1. an INDEPENDENT re-hash of the produced file (defense in depth beyond
#      the exporter's own internal digest check)
#   2. bounded retention: newest ZCL_EXPORT_KEEP generations + one weekly
#      (>=7 days old) pin
#   3. a copy hook to a configurable secondary path — loud WARN, never
#      silent, when unset: a bundle living only on the source disk is not
#      a backup
#
# Usage:
#   zclassic23-bundle-export.sh <datadir>
#   zclassic23-bundle-export.sh --selftest
#
# Env:
#   ZCL_EXPORT_BINARY      path to the zclassic23 binary
#                          (default: <repo>/build/bin/zclassic23)
#   ZCL_EXPORT_KEEP        rolling generations to keep (default 3)
#   ZCL_EXPORT_SECONDARY   off-disk directory to copy the verified bundle
#                          into (default unset -> loud WARN, no copy)
#   ZCL_EXPORT_EXTRA_ARGS  extra zclassic23 flags, unquoted-split (test use
#                          only, e.g. "-nolegacyimport -allow-plaintext-wallet")
#
# Every run appends exactly one TERMINAL: EXPORTED|REFUSED|SKIPPED line to
# <datadir>/bundle-export-verdicts.log with height/sha3/size/duration.
# SKIPPED covers two non-failure states: (a) a concurrent run already holds
# this datadir's export lock, and (b) the compiled checkpoint hasn't moved
# since the last successful export, so the bundle filename already exists —
# the ordinary steady state on a nightly cadence, not an operational failure.
#
# NOT enabled by this script: deploy/zclassic23-bundle-export.{service,timer}
# ship alongside it, but installing/enabling the timer is an OPERATOR action.

set -uo pipefail  # not -e: every stage must fall through to the verdict
                   # line + correct exit code, never vanish silently.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log() { echo "bundle-export: $*" >&2; }

hash_bin=""
if openssl dgst -sha3-256 /dev/null >/dev/null 2>&1; then
    hash_bin() { openssl dgst -sha3-256 "$1" | awk '{print $NF}'; }
fi

write_verdict() {
    local dir="$1" status="$2" height="$3" sha3="$4" size="$5" dur="$6" reason="$7"
    printf '%s TERMINAL: %s height=%s sha3=%s size=%s duration_s=%s reason=%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$status" "$height" "$sha3" "$size" "$dur" \
        "$reason" >> "$dir/bundle-export-verdicts.log"
}

# retention <dir> <keep>: prune consensus-state-bundle-*.sqlite, keeping the
# newest <keep> generations plus the single most recent generation that is
# >=7 days old (the weekly pin). Files are matched newest-first (ls -1t).
retention() {
    local dir="$1" keep="$2" now weekly="" f mtime age i drop k
    local -a files=() keep_set=()
    while IFS= read -r f; do files+=("$f"); done \
        < <(ls -1t "$dir"/consensus-state-bundle-*.sqlite 2>/dev/null)
    [ "${#files[@]}" -eq 0 ] && return 0
    now="$(date +%s)"
    for ((i = 0; i < ${#files[@]} && i < keep; i++)); do keep_set+=("${files[$i]}"); done
    for ((i = keep; i < ${#files[@]}; i++)); do
        f="${files[$i]}"
        mtime="$(stat -c %Y -- "$f" 2>/dev/null || echo 0)"
        age=$(( (now - mtime) / 86400 ))
        if [ "$age" -ge 7 ]; then weekly="$f"; break; fi
    done
    [ -n "$weekly" ] && keep_set+=("$weekly")
    for f in "${files[@]}"; do
        drop=1
        for k in "${keep_set[@]}"; do [ "$f" = "$k" ] && drop=0 && break; done
        if [ "$drop" -eq 1 ]; then rm -f -- "$f"; log "retention: pruned $f"; fi
    done
}

secondary_copy() {
    local bundle="$1"
    if [ -z "${ZCL_EXPORT_SECONDARY:-}" ]; then
        log "WARN off-disk redundancy is NOT configured (ZCL_EXPORT_SECONDARY unset) — this bundle lives only on this disk"
        return 0
    fi
    mkdir -p -- "$ZCL_EXPORT_SECONDARY" || { log "FAIL cannot create secondary dir $ZCL_EXPORT_SECONDARY"; return 1; }
    cp -f -- "$bundle" "$ZCL_EXPORT_SECONDARY/" \
        && log "copied bundle to secondary: $ZCL_EXPORT_SECONDARY/$(basename -- "$bundle")" \
        || { log "FAIL copy to secondary failed: $ZCL_EXPORT_SECONDARY"; return 1; }
}

run_export() {
    local dir="$1" bin keep start dur out rc height digest coins bundle size recomputed
    bin="${ZCL_EXPORT_BINARY:-$REPO_ROOT/build/bin/zclassic23}"
    keep="${ZCL_EXPORT_KEEP:-3}"

    [ -d "$dir" ] || { log "REFUSED: datadir does not exist: $dir"; return 64; }
    [ -x "$bin" ] || { log "REFUSED: binary not executable: $bin"; return 64; }

    local lockfile="$dir/.bundle-export.lock"
    exec 9>>"$lockfile"
    if ! flock -n 9; then
        write_verdict "$dir" SKIPPED "" "" "" 0 "another export run holds $lockfile"
        log "SKIPPED: another export run holds the lock for $dir"
        return 0
    fi

    start="$(date +%s)"
    # shellcheck disable=SC2086
    out="$("$bin" -datadir="$dir" ${ZCL_EXPORT_EXTRA_ARGS:-} -export-consensus-bundle 2>&1)"
    rc=$?
    dur=$(( $(date +%s) - start ))

    if [ "$rc" -ne 0 ] || ! printf '%s' "$out" | grep -q '^EXPORTED:'; then
        local reason
        reason="$(printf '%s' "$out" | grep -oE 'REFUSED: -export-consensus-bundle: .*' | tail -1)"
        [ -n "$reason" ] || reason="non-zero exit ($rc) with no EXPORTED/REFUSED line"
        # The exporter refuses (engine/composition/src/consensus_state_snapshot_export.c
        # output_name_absent()) whenever consensus-state-bundle-<height>.sqlite
        # already exists in <dir> — the ordinary steady state between compiled
        # checkpoint rebakes on a nightly timer. That is idempotent success,
        # not an operational failure: page-worthy REFUSED is reserved for a
        # datadir that genuinely cannot export (missing header chain, zero
        # Sapling root, etc). Retention still runs so an older generation from
        # a prior checkpoint height gets pruned.
        if printf '%s' "$reason" | grep -q 'output name already exists'; then
            write_verdict "$dir" SKIPPED "" "" "" "$dur" "$reason (already exported for this checkpoint height)"
            log "SKIPPED: $reason (already exported for this checkpoint height)"
            retention "$dir" "$keep"
            return 0
        fi
        write_verdict "$dir" REFUSED "" "" "" "$dur" "$reason"
        log "$reason"
        return 1
    fi

    height="$(printf '%s' "$out" | grep -oE ' at h=[0-9]+' | head -1 | grep -oE '[0-9]+')"
    digest="$(printf '%s' "$out" | grep -oE 'digest=[0-9a-f]+' | head -1 | cut -d= -f2)"
    coins="$(printf '%s' "$out" | grep -oE 'coins=[0-9]+' | head -1 | cut -d= -f2)"
    bundle="$dir/consensus-state-bundle-$height.sqlite"
    if [ -z "$height" ] || [ -z "$digest" ] || [ ! -f "$bundle" ]; then
        write_verdict "$dir" REFUSED "$height" "$digest" "" "$dur" "EXPORTED line present but bundle artifact/fields unparseable"
        log "FAIL could not locate/parse the exported artifact"
        return 1
    fi
    size="$(stat -c %s -- "$bundle" 2>/dev/null || echo 0)"

    if [ -n "$hash_bin" ]; then
        recomputed="$(hash_bin "$bundle")"
        if [ "$recomputed" != "$digest" ]; then
            write_verdict "$dir" REFUSED "$height" "$digest" "$size" "$dur" \
                "independent re-hash MISMATCH exporter=$digest recomputed=$recomputed"
            log "FAIL independent re-hash mismatch — refusing to retain/copy $bundle"
            return 1
        fi
        log "independent re-hash CONFIRMED sha3-256=$recomputed"
    else
        log "WARN no sha3-256 tool available (openssl dgst -sha3-256) — skipping independent re-hash"
    fi

    write_verdict "$dir" EXPORTED "$height" "$digest" "$size" "$dur" "coins=$coins"
    log "EXPORTED height=$height sha3=$digest size=$size duration_s=$dur"
    retention "$dir" "$keep"
    secondary_copy "$bundle"
    return 0
}

cmd_selftest() {
    # tmp is intentionally NOT `local`: the EXIT trap below runs after this
    # function returns (bash EXIT traps are process-scoped, not
    # function-scoped), so a local would already be out of scope under `set
    # -u` by the time the trap fires.
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl-bundle-export-selftest.XXXXXX")"
    trap 'rm -rf "$tmp"' EXIT
    local bin="${ZCL_EXPORT_BINARY:-$REPO_ROOT/build/bin/zclassic23}"
    if [ -x "$bin" ]; then
        mkdir -p "$tmp/dd1"
        ZCL_EXPORT_BINARY="$bin" ZCL_EXPORT_EXTRA_ARGS="-nolegacyimport -allow-plaintext-wallet" \
            bash "$0" "$tmp/dd1" >"$tmp/run1.out" 2>&1
        [ "$?" -ne 0 ] || { cat "$tmp/run1.out"; echo "selftest: FAIL expected nonzero exit on fresh empty datadir" >&2; exit 1; }
        grep -q 'TERMINAL: REFUSED' "$tmp/dd1/bundle-export-verdicts.log" \
            || { cat "$tmp/dd1/bundle-export-verdicts.log"; echo "selftest: FAIL no REFUSED verdict line" >&2; exit 1; }
        echo "selftest: ok case=refused-on-unexportable-datadir"
    else
        echo "selftest: SKIP case=refused-on-unexportable-datadir (no built binary at $bin — run make build-only first)"
    fi

    mkdir -p "$tmp/dd2"
    for h in 1001 1002 1003 1004; do
        touch -d "-$((5 - (h - 1000))) days" "$tmp/dd2/consensus-state-bundle-$h.sqlite"
    done
    touch -d "-10 days" "$tmp/dd2/consensus-state-bundle-1000.sqlite"
    retention "$tmp/dd2" 3
    [ -f "$tmp/dd2/consensus-state-bundle-1004.sqlite" ] || { echo "selftest: FAIL newest generation pruned" >&2; exit 1; }
    [ -f "$tmp/dd2/consensus-state-bundle-1000.sqlite" ] || { echo "selftest: FAIL weekly (>=7d) pin pruned" >&2; exit 1; }
    [ ! -f "$tmp/dd2/consensus-state-bundle-1001.sqlite" ] || { echo "selftest: FAIL a non-kept generation survived" >&2; exit 1; }
    echo "selftest: ok case=retention-keep3-plus-weekly"

    mkdir -p "$tmp/dd3"; : > "$tmp/dd3/bundle.sqlite"
    unset ZCL_EXPORT_SECONDARY
    secondary_copy "$tmp/dd3/bundle.sqlite" 2>"$tmp/sec1.out"
    grep -q 'WARN off-disk redundancy is NOT configured' "$tmp/sec1.out" \
        || { cat "$tmp/sec1.out"; echo "selftest: FAIL missing loud WARN for unset secondary" >&2; exit 1; }
    ZCL_EXPORT_SECONDARY="$tmp/sec" secondary_copy "$tmp/dd3/bundle.sqlite" >/dev/null 2>&1
    [ -f "$tmp/sec/bundle.sqlite" ] || { echo "selftest: FAIL secondary copy did not land" >&2; exit 1; }
    echo "selftest: ok case=secondary-copy-warn-then-copy"

    echo "selftest: PASS"
}

main() {
    case "${1:-}" in
        --selftest) cmd_selftest ;;
        "" ) echo "usage: zclassic23-bundle-export.sh <datadir> | --selftest" >&2; exit 64 ;;
        * ) run_export "$1" ;;
    esac
}

main "$@"
