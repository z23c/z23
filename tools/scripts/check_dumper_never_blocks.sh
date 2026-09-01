#!/usr/bin/env bash
# Architecture gate — a dumpstate view never blocks behind the reducer.
#
# Program O0/O1: the diagnostic snapshot plane. A `*_dump_state_json` function
# runs on native/RPC threads while the reducer fold owns progress_store_tx_lock
# around bulk folds. A dumper that takes that lock BLOCKING — or runs a
# SELECT COUNT(*) over a multi-million-row stage log under it — queues the RPC
# worker behind the fold, so `dumpstate` / `status` disappears exactly when the
# node is busiest (the "RPC-dark under load" defect class). This gate proves no
# dumper reaches for a blocking primitive.
#
# WHAT IT SCANS: only the BODY of each `*_dump_state_json(...)` **or**
# `*_dump_state_fill(...)` function (from its signature down to the column-0 `}`
# that closes it — the project's function style). A blocking primitive used by a
# NON-dumper function in the same TU (a stage step, a service's background work)
# is legitimate and NOT flagged.
#
# WHY `_fill` IS IN SCOPE. The table-driven telemetry layer
# (util/telemetry_render.h) splits a dumper in two: a generic renderer emits the
# JSON, and a per-domain provider `<domain>_dump_state_fill()` collects the
# values into a typed snapshot. The collector is where the reads live, so it is
# where progress_store_tx_lock() and COUNT(*) would land — and it runs on the
# SAME RPC/native thread the old dumper ran on. Scanning only `_dump_state_json`
# would report PASS on a controller that does nothing while the risky code runs
# one call deeper. Both spellings are therefore scanned identically.
#
# THE MANIFEST (tools/scripts/dumper_blocking_primitives.tsv): rows of
# "<primitive>\t<ERE>". A dumper body that matches any ERE is a violation unless
# its (primitive, path) pair is in the ratchet baseline.
#
# THE BASELINE (tools/scripts/dumper_blocking_baseline.tsv): rows of
# "<primitive>\t<path>" for reviewed-but-not-yet-migrated dumpers. Goal: EMPTY.
# As each is migrated onto the published snapshot plane, delete its baseline row;
# a baseline row whose dumper no longer matches fails as stale (shrink it).
#
# Allowed (never flagged): progress_store_tx_trylock() — the non-blocking
# acquire a dumper uses to emit {"snapshot_status":"progress_store_busy"} for
# cold single-row detail; and the O(1) published counters (stage_log_rows_*,
# stage_cursor_rows_value, refold_from_anchor_target_cached).
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh
# shellcheck source=tools/lint/scan_exclusions.sh
. tools/lint/scan_exclusions.sh
# shellcheck source=tools/scripts/sh_str.sh
. tools/scripts/sh_str.sh

# ── `--selftest`: prove the gate still BITES ─────────────────────────────────
# A gate is only worth its exit status if someone has watched it fail. This
# runs the whole trip/recover matrix against a throwaway scan root, so it
# never plants a fixture into the real tree and never races another scan.
#
# Cases, in order:
#   1 clean sandbox                       -> 0
#   2 blocking call in a *_dump_state_fill -> 1   (the collector blind spot)
#   3 the same call in a NON-dumper fn     -> 0   (scope is still the body)
#   4 blocking call in a *_dump_state_json -> 1   (the original contract)
#   5 empty scan root                      -> 2   (anti-hollowness floor)
#   6 the REAL tree                        -> 0
if [ "${1:-}" = "--selftest" ]; then
    st_tmp="$(mktemp -d "${TMPDIR:-/tmp}/dumper_gate_selftest.XXXXXX")"
    trap 'rm -rf "$st_tmp"' EXIT
    st_root="$st_tmp/scanroot"
    mkdir -p "$st_root"
    : > "$st_tmp/empty_baseline.tsv"
    mkdir -p "$st_tmp/emptyroot"
    case "$0" in
        /*) st_self="$0" ;;
        *)  st_self="$PWD/${0#./}" ;;
    esac

    st_run() { # st_run <scan-root> -> prints output, sets st_rc
        set +e
        st_out="$(ZCL_DUMPER_BLOCKING_SCAN_ROOTS="$1" \
                  ZCL_DUMPER_BLOCKING_BASELINE="$st_tmp/empty_baseline.tsv" \
                  "$st_self" 2>&1)"
        st_rc=$?
        set -e
    }
    st_fail=0
    st_expect() { # st_expect <label> <want-rc> [<want-substring>]
        if [ "$st_rc" -ne "$2" ]; then
            echo "check_dumper_never_blocks --selftest: FAIL — $1: rc=$st_rc want=$2" >&2
            printf '%s\n' "$st_out" | sed 's/^/    | /' >&2
            st_fail=1
            return
        fi
        if [ -n "${3:-}" ] && str_lacks "$st_out" "$3"; then
            echo "check_dumper_never_blocks --selftest: FAIL — $1: output lacks '$3'" >&2
            printf '%s\n' "$st_out" | sed 's/^/    | /' >&2
            st_fail=1
            return
        fi
        echo "  ok  $1 (rc=$st_rc)"
    }

    # A compliant dumper: keeps the scan set non-empty through every case so a
    # recovered run proves "clean", not "scanned nothing".
    cat > "$st_root/clean_dumper.c" <<'ST_EOF'
bool clean_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!progress_store_tx_trylock()) { return true; }
    return true;
}
ST_EOF
    st_run "$st_root"; st_expect "1 clean sandbox" 0 "clean"

    cat > "$st_root/fill_provider.c" <<'ST_EOF'
bool runtime_dump_state_fill(struct runtime_snapshot *snap)
{
    progress_store_tx_lock();
    return true;
}
ST_EOF
    st_run "$st_root"
    st_expect "2 blocking call inside *_dump_state_fill" 1 "fill_provider.c"

    cat > "$st_root/fill_provider.c" <<'ST_EOF'
static void helper_that_may_block(void)
{
    progress_store_tx_lock();
}

bool runtime_dump_state_fill(struct runtime_snapshot *snap)
{
    (void)snap;
    return true;
}
ST_EOF
    st_run "$st_root"; st_expect "3 same call outside any dump body" 0 "clean"
    rm -f "$st_root/fill_provider.c"

    cat > "$st_root/json_dumper.c" <<'ST_EOF'
bool legacy_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    (void)out;
    stage_log_row_count("x");
    return true;
}
ST_EOF
    st_run "$st_root"
    st_expect "4 blocking call inside *_dump_state_json" 1 "json_dumper.c"
    rm -f "$st_root/json_dumper.c"

    st_run "$st_tmp/emptyroot"; st_expect "5 empty scan root is FATAL" 2 "FATAL"

    set +e
    st_out="$("$st_self" 2>&1)"; st_rc=$?
    set -e
    st_expect "6 real tree" 0 "clean"

    if [ "$st_fail" -ne 0 ]; then
        echo "check_dumper_never_blocks: --selftest FAILED" >&2
        exit 1
    fi
    echo "check_dumper_never_blocks: --selftest passed (6 cases)"
    exit 0
fi

MANIFEST="${ZCL_DUMPER_BLOCKING_MANIFEST:-tools/scripts/dumper_blocking_primitives.tsv}"
BASELINE="${ZCL_DUMPER_BLOCKING_BASELINE:-tools/scripts/dumper_blocking_baseline.tsv}"
SCAN_ROOTS_TEXT="${ZCL_DUMPER_BLOCKING_SCAN_ROOTS:-core engine contexts cognition platform}"
read -r -a SCAN_ROOTS <<< "$SCAN_ROOTS_TEXT"
[ -f "$BASELINE" ] || touch "$BASELINE"

if [ ! -r "$MANIFEST" ]; then
    echo "check_dumper_never_blocks: FATAL — manifest missing: $MANIFEST" >&2
    exit 2
fi
for root in "${SCAN_ROOTS[@]}"; do
    if [ ! -d "$root" ]; then
        echo "check_dumper_never_blocks: FATAL — scan root missing: $root" >&2
        exit 2
    fi
done

# ── Load the manifest: primitive -> ERE. ────────────────────────────────────
declare -a PRIMS ERES
manifest_count=0
while IFS=$'\t' read -r primitive ere extra; do
    case "$primitive" in ''|'#'*) continue ;; esac
    if [ -z "$ere" ] || [ -n "$extra" ]; then
        echo "check_dumper_never_blocks: FATAL — malformed manifest row: $primitive" >&2
        exit 2
    fi
    PRIMS+=("$primitive")
    ERES+=("$ere")
    manifest_count=$((manifest_count + 1))
done < "$MANIFEST"
if [ "$manifest_count" -eq 0 ]; then
    echo "check_dumper_never_blocks: FATAL — manifest contains no primitives" >&2
    exit 2
fi

# ── Load the baseline into a set keyed "primitive\tpath". ────────────────────
declare -A allowed
gate_load_list_file "$BASELINE" allowed baseline_count

# ── Find the dumper TUs (files defining at least one *_dump_state_json or
# *_dump_state_fill). ────────────────────────────────────────────────────────
#
# The two regexes below (the file finder and the awk body extractor) MUST stay
# in step: the finder decides which files are opened, the extractor decides
# which bytes inside them are judged. A definition whose spelling only one of
# them matches is scanned hollowly (file opened, zero bodies) or not at all.
#
# `static` is accepted because a provider may be file-local, and `void`/`int`
# because a fill collector returns nothing to render — only `_dump_state_json`
# is contractually `bool`. Widening the return type cannot hide a violation; it
# can only expose one.
#
# Both spellings use `[(]` rather than `\(`: awk's -v assignment eats one level
# of backslash escaping, so a `\(` written here would reach the regex engine as
# a bare `(` and abort with "Unmatched (". A bracket expression needs no escape
# in either engine.
DUMP_FN_ERE='^(static[[:space:]]+)?(bool|void|int)[[:space:]]+[A-Za-z_][A-Za-z0-9_]*_dump_state_(json|fill)[[:space:]]*[(]'
mapfile -t dumper_tus < <(
    grep -rlE "$DUMP_FN_ERE" \
        --include='*.c' "${LINT_GREP_EXCLUDE_ARGS[@]}" "${SCAN_ROOTS[@]}" \
    | grep -v '/test/' | sort)
gate_require_scanned "${#dumper_tus[@]}" 1 check_dumper_never_blocks \
    "no *_dump_state_json / *_dump_state_fill definitions found — was a shape dir renamed/moved?"

# Extract the concatenated bodies of every *_dump_state_json / *_dump_state_fill
# function in a file, each output line prefixed "<lineno>: " so a match reports a
# real source line. Capture starts at the signature line and ends at the
# column-0 `}` that closes the function (project function style); helper
# functions and code outside a dumper body are never emitted.
extract_dump_bodies() {
    awk -v fn_ere="$DUMP_FN_ERE" '
        $0 ~ fn_ere { cap = 1 }
        cap { printf "%d: %s\n", NR, $0 }
        cap && /^\}/ { cap = 0 }
    ' "$1"
}

declare -A seen
new_violations=()
scanned_bodies=0
for f in "${dumper_tus[@]}"; do
    bodies="$(extract_dump_bodies "$f")"
    [ -n "$bodies" ] && scanned_bodies=$((scanned_bodies + 1))
    for i in "${!PRIMS[@]}"; do
        prim="${PRIMS[$i]}"
        ere="${ERES[$i]}"
        set +e
        hits="$(printf '%s\n' "$bodies" | grep -nE -- "$ere")"
        grep_rc=$?
        set -e
        if [ "$grep_rc" -ge 2 ]; then
            echo "check_dumper_never_blocks: FATAL — grep failed for $prim (rc=$grep_rc)" >&2
            exit 2
        fi
        [ -z "$hits" ] && continue
        key="$prim"$'\t'"$f"
        if [ -n "${allowed[$key]+x}" ]; then
            seen[$key]=1
        else
            # Report the first offending source line for the message.
            srcline="$(printf '%s\n' "$bodies" | grep -nE -- "$ere" \
                        | head -n1 | sed 's/^[0-9]*:\([0-9]*\): .*/\1/')"
            new_violations+=("$prim in $f (dump body line ~$srcline)")
        fi
    done
done
gate_require_scanned "$scanned_bodies" 1 check_dumper_never_blocks \
    "extracted zero dumper bodies — the *_dump_state_json extractor drifted."

# ── Stale baseline rows: a (primitive,path) that no longer matches. ─────────
stale=()
for key in "${!allowed[@]}"; do
    if [ -z "${seen[$key]+x}" ]; then
        stale+=("$key")
    fi
done

if [ "${#new_violations[@]}" -gt 0 ] || [ "${#stale[@]}" -gt 0 ]; then
    if [ "${#new_violations[@]}" -gt 0 ]; then
        echo "check_dumper_never_blocks: FAIL — dumper reaches a blocking primitive"
        printf '  %s\n' "${new_violations[@]}"
        echo "  A *_dump_state_json must never take progress_store_tx_lock blocking"
        echo "  or run COUNT(*). Publish the value through the snapshot plane"
        echo "  (util/subsystem_snapshot.h / jobs/stage_log_rows.h) and read it"
        echo "  lock-free; use progress_store_tx_trylock only for cold single-row"
        echo "  detail, emitting {\"snapshot_status\":\"progress_store_busy\"}."
    fi
    if [ "${#stale[@]}" -gt 0 ]; then
        echo "check_dumper_never_blocks: FAIL — stale baseline row(s) (shrink the baseline)"
        printf '  %s\n' "${stale[@]}"
    fi
    exit 1
fi

echo "check_dumper_never_blocks: clean — $manifest_count primitive(s), ${#dumper_tus[@]} dumper TU(s), $baseline_count reviewed debt row(s), no new blocking dumpers"
