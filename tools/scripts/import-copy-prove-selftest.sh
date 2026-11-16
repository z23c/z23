#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Hermetic import/bundle driver-gate checks using fake node/RPC responses.
# No real node, datadir, network, importer or installer is exercised; the
# fixtures cover driver verdicts, not importer/installer correctness. Every
# fixture path is sandboxed and removed on exit.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$REPO/tools/scripts/import-copy-prove.sh"
SANDBOX="$(mktemp -d /tmp/zcl-import-copy-prove-selftest.XXXXXX)"
chmod 700 "$SANDBOX"

cleanup() { rm -rf "$SANDBOX"; }
trap cleanup EXIT

Z23_PORT_PROBE_SS=/bin/true; export Z23_PORT_PROBE_SS

FAKE_NODE="$SANDBOX/fake-zclassic23"
FAKE_RPC="$SANDBOX/fake-zcl-rpc"
SRC_FIXTURE="$SANDBOX/fixture-datadir"
CHAINSTATE_FIXTURE="$SANDBOX/fixture-chainstate"
ZD_FIXTURE="$SANDBOX/fixture-zclassicd-datadir"
IMPORT_BEHAVIOR_FILE="$SANDBOX/import-behavior"
INSTALL_BEHAVIOR_FILE="$SANDBOX/install-behavior"
HEADER_REFRESH_BEHAVIOR_FILE="$SANDBOX/header-refresh-behavior"
FAKE_BUNDLE="$SANDBOX/fixture-bundle.sqlite"
FAKE_RECEIPT="$SANDBOX/fixture-receipt.v1"

WEDGE=3176325
WEDGE_PLUS1=3176326

fail() {
    printf '[import-copy-prove-selftest] FAIL: %s\n' "$*" >&2
    [ -r "$OUTPUT" ] && sed 's/^/[selftest-output] /' "$OUTPUT" >&2
    exit 1
}

assert_rc() {
    local got="$1" want="$2" msg="$3"
    [ "$got" = "$want" ] || fail "$msg (expected rc=$want, got rc=$got)"
}

assert_contains() {
    grep -q -- "$2" "$1" || fail "$3 (missing '$2' in $1)"
}

# ── build the fixtures (once; each test overrides behavior via files) ──

cat > "$FAKE_NODE" <<'NODE_EOF'
#!/bin/sh
# Fake zclassic23 for the import-copy-prove hermetic selftest ONLY.
if [ "${1:-}" = "--importblockindex" ]; then
    # Header-refresh step (import mode): zclassic23 --importblockindex <src> [<target>]
    behavior="ok"
    [ -r "${FAKE_HEADER_REFRESH_BEHAVIOR_FILE:-}" ] && behavior="$(cat "$FAKE_HEADER_REFRESH_BEHAVIOR_FILE")"
    case "$behavior" in
        ok)
            target="${3:-}"
            if [ -n "$target" ]; then
                mkdir -p "$(dirname "$target")" 2>/dev/null || true
                : > "$target"
            fi
            echo "=== ZClassic Block-Index (header) Import ==="
            exit 0 ;;
        fail)
            echo "header-refresh fixture: forced failure" >&2
            exit 1 ;;
    esac
fi
datadir=""
import_arg=""
install_arg=""
operator_lane=""
for a in "$@"; do
    case "$a" in
        -datadir=*)                  datadir="${a#-datadir=}" ;;
        -import-complete-shielded=*)  import_arg="${a#-import-complete-shielded=}" ;;
        -install-consensus-bundle=*)  install_arg="${a#-install-consensus-bundle=}" ;;
        -operator-lane=*)             operator_lane="${a#-operator-lane=}" ;;
    esac
done
if [ -n "$import_arg" ]; then
    behavior="ok"
    [ -r "$FAKE_IMPORT_BEHAVIOR_FILE" ] && behavior="$(cat "$FAKE_IMPORT_BEHAVIOR_FILE")"
    case "$behavior" in
        ok)
            echo "IMPORT COMPLETE (committed=5): selftest fixture ok"
            # stderr mirrors the real LOG line carrying boundary=.
            echo "[shielded_import] INFO IMPORT COMPLETE: boundary=${FAKE_IMPORT_BOUNDARY:-3176325} — both cursors flipped, shielded history published" >&2
            exit 0 ;;
        ok_no_boundary)
            echo "IMPORT COMPLETE (committed=5): selftest fixture ok, no boundary line"
            exit 0 ;;
        fail)
            echo "IMPORT REFUSED — selftest fixture forced failure (wedge intact)" >&2
            exit 1 ;;
        missing)
            # Simulates an unmerged flag: the real argv loop ignores unknown
            # flags and just no-ops this one call (short-circuits rather than
            # falling through to a real long-running boot, purely for selftest
            # speed — the harness behavior proven is identical: no banner => FAIL).
            exit 0 ;;
    esac
fi
if [ -n "$install_arg" ]; then
    behavior="ok"
    [ -r "$FAKE_INSTALL_BEHAVIOR_FILE" ] && behavior="$(cat "$FAKE_INSTALL_BEHAVIOR_FILE")"
    case "$behavior" in
        ok)
            echo "INSTALLED: -install-consensus-bundle: selftest fixture ok"
            exit 0 ;;
        fail)
            echo "INSTALL REFUSED — selftest fixture forced failure" >&2
            exit 1 ;;
        missing)
            exit 0 ;;
    esac
fi
# Normal boot mode.
if [ "${FAKE_REQUIRE_CANONICAL_LANE:-0}" = "1" ] &&
   [ "$operator_lane" != "canonical" ]; then
    echo "identity conflict: persisted lane=canonical does not match runtime lane=${operator_lane:-unknown}" >&2
    exit 7
fi
mkdir -p "$datadir"
: > "$datadir/.cookie"
trap 'exit 0' TERM INT
while true; do sleep 1; done
NODE_EOF
chmod +x "$FAKE_NODE"

cat > "$FAKE_RPC" <<'RPC_EOF'
#!/bin/sh
# Fake zcl-rpc for the import-copy-prove hermetic selftest ONLY. Emits raw
# substrings the real driver's sed/grep patterns look for -- does not need to
# be a fully faithful JSON-RPC envelope.
method="$1"
params="${2:-}"
role="copy"
[ "$ZCL_DATADIR" = "${FAKE_ZD_DIR:-}" ] && role="zd"

case "$method" in
    getblockcount)
        if [ "$role" = "zd" ]; then
            printf '{"result":%s,"error":null,"id":1}\n' "${FAKE_ZD_TIP:-0}"
        else
            printf '{"result":%s,"error":null,"id":1}\n' "${FAKE_COPY_TIP:--1}"
        fi
        ;;
    getblockhash)
        table="${FAKE_COPY_HASHES:-}"
        [ "$role" = "zd" ] && table="${FAKE_ZD_HASHES:-}"
        hash=""
        [ -r "$table" ] && hash="$(awk -F: -v h="$params" '$1==h{print $2}' "$table")"
        printf '{"result":"%s","error":null,"id":1}\n' "$hash"
        ;;
    dbquery)
        cat "${FAKE_PROVENANCE_RESPONSE:-/dev/null}"
        ;;
    dumpstate)
        case "$params" in
            *blocker*)          cat "${FAKE_BLOCKER_RESPONSE:-/dev/null}" ;;
            *reducer_frontier*)
                if [ -n "${FAKE_FRONTIER_FIRST_RESPONSE:-}" ] &&
                   [ ! -e "${FAKE_FRONTIER_FIRST_SEEN_FILE:-/dev/null}" ]; then
                    cat "$FAKE_FRONTIER_FIRST_RESPONSE"
                    : > "$FAKE_FRONTIER_FIRST_SEEN_FILE"
                else
                    cat "${FAKE_FRONTIER_RESPONSE:-/dev/null}"
                fi
                ;;
            *sovereignty*)
                if [ -r "${FAKE_SOVEREIGNTY_RESPONSE:-}" ]; then
                    cat "$FAKE_SOVEREIGNTY_RESPONSE"
                else
                    echo '{"error":"unknown subsystem: sovereignty"}'
                fi
                ;;
            *) echo '{}' ;;
        esac
        ;;
    *) echo '{}' ;;
esac
RPC_EOF
chmod +x "$FAKE_RPC"

mkdir -p "$SRC_FIXTURE" "$CHAINSTATE_FIXTURE" "$ZD_FIXTURE"
: > "$SRC_FIXTURE/node.db"
: > "$CHAINSTATE_FIXTURE/CURRENT"
printf 'fake-bundle\n'  > "$FAKE_BUNDLE"
printf 'fake-receipt\n' > "$FAKE_RECEIPT"

BLOCKER_CLEAR="$SANDBOX/blocker-clear.json"
printf '{"active_count":0,"blockers":[]}' > "$BLOCKER_CLEAR"
BLOCKER_ANCHOR_GAP="$SANDBOX/blocker-anchor-gap.json"
printf '{"active_count":1,"blockers":[{"id":"utxo_apply.anchor_backfill_gap","class":"permanent"}]}' \
    > "$BLOCKER_ANCHOR_GAP"

FRONTIER_CONTINUOUS="$SANDBOX/frontier-continuous.json"
printf '{"hstar":%d,"coins_applied_height":%d}' "$((WEDGE + 5))" "$((WEDGE + 6))" \
    > "$FRONTIER_CONTINUOUS"
FRONTIER_GAP="$SANDBOX/frontier-gap.json"
printf '{"hstar":%d,"coins_applied_height":%d}' "$((WEDGE + 5))" "$((WEDGE + 9))" \
    > "$FRONTIER_GAP"

# bundle-mode provenance fixtures (progress_meta key rows).
PROVENANCE_BOTH="$SANDBOX/provenance-both.json"
printf '{"rows":[{"key":"coins_kv_migration_complete"},{"key":"coins_kv_self_folded"}]}' \
    > "$PROVENANCE_BOTH"
PROVENANCE_PARTIAL="$SANDBOX/provenance-partial.json"
printf '{"rows":[{"key":"coins_kv_migration_complete"}]}' > "$PROVENANCE_PARTIAL"

TIP=$((WEDGE + 5))
COPY_HASHES_MATCH="$SANDBOX/copy-hashes-match.txt"
{
    printf '%d:aaaa1111\n' "$WEDGE"
    printf '%d:bbbb2222\n' "$WEDGE_PLUS1"
    printf '%d:cccc3333\n' "$TIP"
} > "$COPY_HASHES_MATCH"
ZD_HASHES_MATCH="$SANDBOX/zd-hashes-match.txt"
cp "$COPY_HASHES_MATCH" "$ZD_HASHES_MATCH"

COPY_HASHES_MISMATCH="$SANDBOX/copy-hashes-mismatch.txt"
{
    printf '%d:aaaa1111\n' "$WEDGE"
    printf '%d:WRONGHASH\n' "$WEDGE_PLUS1"
    printf '%d:cccc3333\n' "$TIP"
} > "$COPY_HASHES_MISMATCH"

# run_script — import mode (the default). EXTRA_ARGS supplies per-test flags.
run_script() {
    local rc
    set +e
    env \
        ZCL_NODE_BIN="$FAKE_NODE" \
        ZCL_RPC_BIN="$FAKE_RPC" \
        FAKE_IMPORT_BEHAVIOR_FILE="$IMPORT_BEHAVIOR_FILE" \
        FAKE_INSTALL_BEHAVIOR_FILE="$INSTALL_BEHAVIOR_FILE" \
        FAKE_HEADER_REFRESH_BEHAVIOR_FILE="$HEADER_REFRESH_BEHAVIOR_FILE" \
        FAKE_REQUIRE_CANONICAL_LANE=1 \
        FAKE_IMPORT_BOUNDARY="${TEST_IMPORT_BOUNDARY:-$WEDGE}" \
        FAKE_ZD_DIR="$ZD_FIXTURE" \
        FAKE_COPY_TIP="$TIP" \
        FAKE_ZD_TIP="$((TIP + 100))" \
        FAKE_BLOCKER_RESPONSE="${TEST_BLOCKER_RESPONSE:-$BLOCKER_CLEAR}" \
        FAKE_FRONTIER_RESPONSE="${TEST_FRONTIER_RESPONSE:-$FRONTIER_CONTINUOUS}" \
        FAKE_FRONTIER_FIRST_RESPONSE="${TEST_FRONTIER_FIRST_RESPONSE:-}" \
        FAKE_FRONTIER_FIRST_SEEN_FILE="$COPY_DIR/.frontier-first-seen" \
        FAKE_PROVENANCE_RESPONSE="${TEST_PROVENANCE_RESPONSE:-$PROVENANCE_BOTH}" \
        FAKE_COPY_HASHES="${TEST_COPY_HASHES:-$COPY_HASHES_MATCH}" \
        FAKE_ZD_HASHES="$ZD_HASHES_MATCH" \
        ZCL_COPY_PROVE_CONTINUITY_RETRIES=2 \
        "$SCRIPT" --deadline=15 \
        --src="$SRC_FIXTURE" \
        --chainstate-src="$CHAINSTATE_FIXTURE" \
        --copy-dir="$COPY_DIR" \
        --zclassicd-datadir="$ZD_FIXTURE" \
        "${EXTRA_ARGS[@]}" \
        > "$OUTPUT" 2>&1
    rc=$?
    set -e
    echo "$rc"
}

fresh_copy_dir() {
    printf '%s/.zclassic-c23-COPY-%s-import' "$SANDBOX" "$(date +%s%N)"
}

# ============================================================================
# import mode (default)
# ============================================================================

test_dry_run_prints_plan_only() {
    OUTPUT="$SANDBOX/out-dryrun"
    COPY_DIR="$(fresh_copy_dir)"
    EXTRA_ARGS=(--dry-run)
    local rc; rc="$(run_script)"
    assert_rc "$rc" 0 "dry-run did not exit 0"
    assert_contains "$OUTPUT" "import-copy-prove plan  (mode=import)" "dry-run missing plan banner"
    assert_contains "$OUTPUT" "no filesystem or process action taken" "dry-run missing no-op notice"
    [ ! -e "$COPY_DIR" ] || fail "dry-run created a copy-dir on disk"
    printf '[import-copy-prove-selftest] PASS: --dry-run prints the plan and touches nothing\n'
}

test_refuses_non_copy_path() {
    OUTPUT="$SANDBOX/out-noncopy"
    COPY_DIR="$SANDBOX/not-marked-path"
    EXTRA_ARGS=(--dry-run)
    local rc; rc="$(run_script)"
    assert_rc "$rc" 2 "non-COPY --copy-dir was not refused"
    assert_contains "$OUTPUT" "must contain the '/.zclassic-c23-COPY-' marker" \
        "non-COPY refusal message missing"
    printf '[import-copy-prove-selftest] PASS: refuses a --copy-dir without the -COPY- marker\n'
}

test_refuses_preexisting_copy_dir() {
    OUTPUT="$SANDBOX/out-preexist"
    COPY_DIR="$(fresh_copy_dir)"
    mkdir -p "$COPY_DIR"
    EXTRA_ARGS=(--dry-run)
    local rc; rc="$(run_script)"
    assert_rc "$rc" 2 "pre-existing --copy-dir was not refused"
    assert_contains "$OUTPUT" "already exists, refusing to overwrite" \
        "pre-existing refusal message missing"
    rm -rf "$COPY_DIR"
    printf '[import-copy-prove-selftest] PASS: refuses a --copy-dir that already exists\n'
}

test_rejects_bad_mode() {
    OUTPUT="$SANDBOX/out-badmode"
    COPY_DIR="$(fresh_copy_dir)"
    EXTRA_ARGS=(--mode=promote --dry-run)
    local rc; rc="$(run_script)"
    assert_rc "$rc" 2 "an unknown --mode was not refused"
    assert_contains "$OUTPUT" "--mode must be 'import' or 'bundle'" "bad-mode refusal message missing"
    printf '[import-copy-prove-selftest] PASS: refuses an unknown --mode\n'
}

test_missing_importer_fails_fast() {
    OUTPUT="$SANDBOX/out-missing"
    COPY_DIR="$(fresh_copy_dir)"
    echo missing > "$IMPORT_BEHAVIOR_FILE"
    EXTRA_ARGS=(--expect-climb-past="$WEDGE")
    local rc; rc="$(run_script)"
    echo ok > "$IMPORT_BEHAVIOR_FILE"
    assert_rc "$rc" 1 "an unimplemented importer flag did not FAIL"
    assert_contains "$OUTPUT" "VERDICT: FAIL" "missing-importer run did not report FAIL"
    assert_contains "$OUTPUT" "did not report IMPORT COMPLETE" "missing-importer FAIL reason absent"
    printf '[import-copy-prove-selftest] PASS: an unmerged importer fails fast, not silently\n'
}

test_importer_explicit_refusal_fails() {
    OUTPUT="$SANDBOX/out-refused"
    COPY_DIR="$(fresh_copy_dir)"
    echo fail > "$IMPORT_BEHAVIOR_FILE"
    EXTRA_ARGS=(--expect-climb-past="$WEDGE")
    local rc; rc="$(run_script)"
    echo ok > "$IMPORT_BEHAVIOR_FILE"
    assert_rc "$rc" 1 "an explicit importer REFUSED did not FAIL"
    assert_contains "$OUTPUT" "VERDICT: FAIL" "importer refusal did not report FAIL"
    printf '[import-copy-prove-selftest] PASS: an explicit importer REFUSED fails the harness\n'
}

test_full_pass_all_gates_green() {
    OUTPUT="$SANDBOX/out-pass"
    COPY_DIR="$(fresh_copy_dir)"
    echo ok > "$IMPORT_BEHAVIOR_FILE"
    TEST_BLOCKER_RESPONSE="$BLOCKER_CLEAR"
    TEST_FRONTIER_RESPONSE="$FRONTIER_CONTINUOUS"
    TEST_COPY_HASHES="$COPY_HASHES_MATCH"
    EXTRA_ARGS=(--expect-climb-past="$WEDGE")
    local rc; rc="$(run_script)"
    unset TEST_BLOCKER_RESPONSE TEST_FRONTIER_RESPONSE TEST_COPY_HASHES
    assert_rc "$rc" 0 "the all-green fixture did not PASS"
    assert_contains "$OUTPUT" "VERDICT: PASS" "all-green fixture missing PASS verdict"
    assert_contains "$OUTPUT" "GATE (a) H\* climb:.*ok=1" "GATE (a) not reported ok"
    assert_contains "$OUTPUT" "GATE (b) continuity:.*ok=1" "GATE (b) not reported ok"
    assert_contains "$OUTPUT" "GATE (c) hash parity:.*ok=1" "GATE (c) not reported ok"
    assert_contains "$OUTPUT" "cleanup: graceful node shutdown complete" \
        "a green proof did not leave its candidate cleanly stopped"
    printf '[import-copy-prove-selftest] PASS: all three gates green yields overall PASS\n'
}

test_auto_parsed_boundary_passes() {
    OUTPUT="$SANDBOX/out-autoparse"
    COPY_DIR="$(fresh_copy_dir)"
    echo ok > "$IMPORT_BEHAVIOR_FILE"
    TEST_IMPORT_BOUNDARY="$WEDGE"
    TEST_BLOCKER_RESPONSE="$BLOCKER_CLEAR"
    TEST_FRONTIER_RESPONSE="$FRONTIER_CONTINUOUS"
    TEST_COPY_HASHES="$COPY_HASHES_MATCH"
    EXTRA_ARGS=()   # no --expect-climb-past: must auto-parse boundary=
    local rc; rc="$(run_script)"
    unset TEST_IMPORT_BOUNDARY TEST_BLOCKER_RESPONSE TEST_FRONTIER_RESPONSE TEST_COPY_HASHES
    assert_rc "$rc" 0 "auto-parsed boundary run did not PASS"
    assert_contains "$OUTPUT" "auto-parsed pre-import wedge height: boundary=$WEDGE" \
        "the boundary was not auto-parsed"
    assert_contains "$OUTPUT" "VERDICT: PASS" "auto-parse run missing PASS verdict"
    printf '[import-copy-prove-selftest] PASS: boundary= is auto-parsed when --expect-climb-past is omitted\n'
}

test_no_boundary_and_no_override_fails_blind() {
    OUTPUT="$SANDBOX/out-noboundary"
    COPY_DIR="$(fresh_copy_dir)"
    echo ok_no_boundary > "$IMPORT_BEHAVIOR_FILE"
    EXTRA_ARGS=()
    local rc; rc="$(run_script)"
    echo ok > "$IMPORT_BEHAVIOR_FILE"
    assert_rc "$rc" 1 "a missing boundary= with no override did not FAIL"
    assert_contains "$OUTPUT" "no 'boundary=<height>' could" "the blind-gate refusal reason is missing"
    printf '[import-copy-prove-selftest] PASS: a missing boundary= with no override refuses to gate blind\n'
}

test_blocker_still_present_fails_gate_a() {
    OUTPUT="$SANDBOX/out-blockerpresent"
    COPY_DIR="$(fresh_copy_dir)"
    echo ok > "$IMPORT_BEHAVIOR_FILE"
    TEST_BLOCKER_RESPONSE="$BLOCKER_ANCHOR_GAP"
    TEST_FRONTIER_RESPONSE="$FRONTIER_CONTINUOUS"
    TEST_COPY_HASHES="$COPY_HASHES_MATCH"
    EXTRA_ARGS=(--expect-climb-past="$WEDGE")
    local rc; rc="$(run_script)"
    unset TEST_BLOCKER_RESPONSE TEST_FRONTIER_RESPONSE TEST_COPY_HASHES
    assert_rc "$rc" 1 "a still-present anchor_backfill_gap blocker did not FAIL"
    assert_contains "$OUTPUT" "VERDICT: FAIL" "blocker-present fixture missing FAIL verdict"
    assert_contains "$OUTPUT" "GATE (a) H\* climb:.*ok=0" "GATE (a) did not report not-ok"
    printf '[import-copy-prove-selftest] PASS: a lingering blocker fails GATE (a) even though H* climbed\n'
}

test_continuity_gap_fails_gate_b() {
    OUTPUT="$SANDBOX/out-continuitygap"
    COPY_DIR="$(fresh_copy_dir)"
    echo ok > "$IMPORT_BEHAVIOR_FILE"
    TEST_BLOCKER_RESPONSE="$BLOCKER_CLEAR"
    TEST_FRONTIER_RESPONSE="$FRONTIER_GAP"
    TEST_COPY_HASHES="$COPY_HASHES_MATCH"
    EXTRA_ARGS=(--expect-climb-past="$WEDGE")
    local rc; rc="$(run_script)"
    unset TEST_BLOCKER_RESPONSE TEST_FRONTIER_RESPONSE TEST_COPY_HASHES
    assert_rc "$rc" 1 "a coins_applied/hstar continuity gap did not FAIL"
    assert_contains "$OUTPUT" "GATE (b) continuity:.*ok=0" "GATE (b) did not report not-ok"
    printf '[import-copy-prove-selftest] PASS: a continuity gap fails GATE (b)\n'
}

test_transient_continuity_publish_window_retries() {
    OUTPUT="$SANDBOX/out-continuity-race"
    COPY_DIR="$(fresh_copy_dir)"
    echo ok > "$IMPORT_BEHAVIOR_FILE"
    TEST_BLOCKER_RESPONSE="$BLOCKER_CLEAR"
    TEST_FRONTIER_FIRST_RESPONSE="$FRONTIER_GAP"
    TEST_FRONTIER_RESPONSE="$FRONTIER_CONTINUOUS"
    TEST_COPY_HASHES="$COPY_HASHES_MATCH"
    EXTRA_ARGS=(--expect-climb-past="$WEDGE")
    local rc; rc="$(run_script)"
    unset TEST_BLOCKER_RESPONSE TEST_FRONTIER_FIRST_RESPONSE TEST_FRONTIER_RESPONSE TEST_COPY_HASHES
    assert_rc "$rc" 0 "a transient reducer publish window did not retry to a coherent observation"
    assert_contains "$OUTPUT" "GATE (b) continuity:.*ok=1" \
        "GATE (b) did not recover after the transient publish window"
    printf '[import-copy-prove-selftest] PASS: a transient reducer publish window is retried without weakening continuity\n'
}

test_hash_mismatch_fails_gate_c() {
    OUTPUT="$SANDBOX/out-hashmismatch"
    COPY_DIR="$(fresh_copy_dir)"
    echo ok > "$IMPORT_BEHAVIOR_FILE"
    TEST_BLOCKER_RESPONSE="$BLOCKER_CLEAR"
    TEST_FRONTIER_RESPONSE="$FRONTIER_CONTINUOUS"
    TEST_COPY_HASHES="$COPY_HASHES_MISMATCH"
    EXTRA_ARGS=(--expect-climb-past="$WEDGE")
    local rc; rc="$(run_script)"
    unset TEST_BLOCKER_RESPONSE TEST_FRONTIER_RESPONSE TEST_COPY_HASHES
    assert_rc "$rc" 1 "a same-height hash mismatch vs zclassicd did not FAIL"
    assert_contains "$OUTPUT" "GATE (c) hash parity:.*ok=0" "GATE (c) did not report not-ok"
    assert_contains "$OUTPUT" "MISMATCH" "hash mismatch was not surfaced as evidence"
    printf '[import-copy-prove-selftest] PASS: a same-height hash mismatch fails GATE (c) (the missing-anchor signature)\n'
}

test_header_refresh_failure_fails_before_phase1() {
    OUTPUT="$SANDBOX/out-headerrefresh-fail"
    COPY_DIR="$(fresh_copy_dir)"
    echo ok > "$IMPORT_BEHAVIOR_FILE"
    echo fail > "$HEADER_REFRESH_BEHAVIOR_FILE"
    EXTRA_ARGS=(--expect-climb-past="$WEDGE")
    local rc; rc="$(run_script)"
    echo ok > "$HEADER_REFRESH_BEHAVIOR_FILE"
    assert_rc "$rc" 1 "a failed header-refresh (step 1b) did not FAIL the harness"
    assert_contains "$OUTPUT" "VERDICT: FAIL" "header-refresh failure did not report FAIL"
    assert_contains "$OUTPUT" "header-refresh (--importblockindex) failed" \
        "header-refresh FAIL reason absent"
    printf '[import-copy-prove-selftest] PASS: a failed header refresh fails fast, before phase 1 runs\n'
}

test_skip_header_refresh_bypasses_step() {
    OUTPUT="$SANDBOX/out-skip-headerrefresh"
    COPY_DIR="$(fresh_copy_dir)"
    echo ok > "$IMPORT_BEHAVIOR_FILE"
    echo fail > "$HEADER_REFRESH_BEHAVIOR_FILE"   # would FAIL the run if NOT skipped
    TEST_BLOCKER_RESPONSE="$BLOCKER_CLEAR"
    TEST_FRONTIER_RESPONSE="$FRONTIER_CONTINUOUS"
    TEST_COPY_HASHES="$COPY_HASHES_MATCH"
    EXTRA_ARGS=(--expect-climb-past="$WEDGE" --skip-header-refresh)
    local rc; rc="$(run_script)"
    echo ok > "$HEADER_REFRESH_BEHAVIOR_FILE"
    unset TEST_BLOCKER_RESPONSE TEST_FRONTIER_RESPONSE TEST_COPY_HASHES
    assert_rc "$rc" 0 "--skip-header-refresh did not bypass a forced header-refresh failure"
    assert_contains "$OUTPUT" "step 1b SKIPPED" "skip flag did not note the step was skipped"
    printf '[import-copy-prove-selftest] PASS: --skip-header-refresh bypasses step 1b\n'
}

test_stale_auto_reindex_request_is_cleared() {
    OUTPUT="$SANDBOX/out-staleautoreindex"
    COPY_DIR="$(fresh_copy_dir)"
    echo ok > "$IMPORT_BEHAVIOR_FILE"
    TEST_BLOCKER_RESPONSE="$BLOCKER_CLEAR"
    TEST_FRONTIER_RESPONSE="$FRONTIER_CONTINUOUS"
    TEST_COPY_HASHES="$COPY_HASHES_MATCH"
    printf '%d 2\n' "$WEDGE" > "$SRC_FIXTURE/auto_reindex_request"
    EXTRA_ARGS=(--expect-climb-past="$WEDGE" --clean-copy)
    local rc; rc="$(run_script)"
    rm -f "$SRC_FIXTURE/auto_reindex_request"
    unset TEST_BLOCKER_RESPONSE TEST_FRONTIER_RESPONSE TEST_COPY_HASHES
    assert_rc "$rc" 0 "a run with a stale auto_reindex_request in the source did not still PASS"
    assert_contains "$OUTPUT" "stale auto_reindex_request found in the copy — clearing before boot" \
        "the stale auto_reindex_request was not reported as cleared"
    [ ! -e "$COPY_DIR" ] || fail "--clean-copy did not delete the copy after the run"
    printf '[import-copy-prove-selftest] PASS: a stale auto_reindex_request carried in cp -a is cleared before the proving boot\n'
}

test_no_auto_reindex_request_is_a_documented_noop() {
    OUTPUT="$SANDBOX/out-noautoreindex"
    COPY_DIR="$(fresh_copy_dir)"
    echo ok > "$IMPORT_BEHAVIOR_FILE"
    TEST_BLOCKER_RESPONSE="$BLOCKER_CLEAR"
    TEST_FRONTIER_RESPONSE="$FRONTIER_CONTINUOUS"
    TEST_COPY_HASHES="$COPY_HASHES_MATCH"
    EXTRA_ARGS=(--expect-climb-past="$WEDGE")
    local rc; rc="$(run_script)"
    unset TEST_BLOCKER_RESPONSE TEST_FRONTIER_RESPONSE TEST_COPY_HASHES
    assert_rc "$rc" 0 "a clean run with no stale auto_reindex_request did not PASS"
    assert_contains "$OUTPUT" "no stale auto_reindex_request present — nothing to clear" \
        "the no-op case was not reported"
    printf '[import-copy-prove-selftest] PASS: no stale auto_reindex_request is a documented no-op\n'
}

test_skip_zclassicd_check_is_incomplete_not_pass() {
    OUTPUT="$SANDBOX/out-skipzd"
    COPY_DIR="$(fresh_copy_dir)"
    echo ok > "$IMPORT_BEHAVIOR_FILE"
    TEST_BLOCKER_RESPONSE="$BLOCKER_CLEAR"
    TEST_FRONTIER_RESPONSE="$FRONTIER_CONTINUOUS"
    EXTRA_ARGS=(--expect-climb-past="$WEDGE" --skip-zclassicd-check)
    local rc; rc="$(run_script)"
    unset TEST_BLOCKER_RESPONSE TEST_FRONTIER_RESPONSE
    assert_rc "$rc" 0 "--skip-zclassicd-check did not exit 0 with the other gates green"
    assert_contains "$OUTPUT" "PASS-INCOMPLETE" \
        "--skip-zclassicd-check did not label the verdict incomplete"
    printf '[import-copy-prove-selftest] PASS: --skip-zclassicd-check is labelled incomplete, never a bare PASS\n'
}

test_tail_peer_boots_with_addnode() {
    OUTPUT="$SANDBOX/out-tailpeer"
    COPY_DIR="$(fresh_copy_dir)"
    echo ok > "$IMPORT_BEHAVIOR_FILE"
    TEST_BLOCKER_RESPONSE="$BLOCKER_CLEAR"
    TEST_FRONTIER_RESPONSE="$FRONTIER_CONTINUOUS"
    TEST_COPY_HASHES="$COPY_HASHES_MATCH"
    EXTRA_ARGS=(--expect-climb-past="$WEDGE" --tail-peer=127.0.0.1:8034)
    local rc; rc="$(run_script)"
    unset TEST_BLOCKER_RESPONSE TEST_FRONTIER_RESPONSE TEST_COPY_HASHES
    assert_rc "$rc" 0 "an import run with --tail-peer did not PASS"
    assert_contains "$OUTPUT" "tail peer:.*-addnode=127.0.0.1:8034" "the tail peer was not reported in the plan"
    printf '[import-copy-prove-selftest] PASS: --tail-peer is honored (plan reports -addnode for tail bodies)\n'
}

# ============================================================================
# bundle mode (--mode=bundle)
# ============================================================================

# run_bundle — bundle mode. EXTRA_ARGS supplies per-test flags.
run_bundle() {
    local rc
    set +e
    env \
        ZCL_NODE_BIN="$FAKE_NODE" \
        ZCL_RPC_BIN="$FAKE_RPC" \
        FAKE_IMPORT_BEHAVIOR_FILE="$IMPORT_BEHAVIOR_FILE" \
        FAKE_INSTALL_BEHAVIOR_FILE="$INSTALL_BEHAVIOR_FILE" \
        FAKE_HEADER_REFRESH_BEHAVIOR_FILE="$HEADER_REFRESH_BEHAVIOR_FILE" \
        FAKE_ZD_DIR="$ZD_FIXTURE" \
        FAKE_COPY_TIP="$TIP" \
        FAKE_FRONTIER_RESPONSE="${TEST_FRONTIER_RESPONSE:-$FRONTIER_CONTINUOUS}" \
        FAKE_PROVENANCE_RESPONSE="${TEST_PROVENANCE_RESPONSE:-$PROVENANCE_BOTH}" \
        "$SCRIPT" --mode=bundle --deadline=15 \
        --src="$SRC_FIXTURE" \
        --copy-dir="$COPY_DIR" \
        --bundle="$FAKE_BUNDLE" \
        --receipt="$FAKE_RECEIPT" \
        "${EXTRA_ARGS[@]}" \
        > "$OUTPUT" 2>&1
    rc=$?
    set -e
    echo "$rc"
}

fresh_bundle_copy_dir() {
    printf '%s/.zclassic-c23-COPY-%s-bundle' "$SANDBOX" "$(date +%s%N)"
}

test_bundle_requires_bundle_and_receipt() {
    OUTPUT="$SANDBOX/out-bundle-req"
    COPY_DIR="$(fresh_bundle_copy_dir)"
    local rc
    set +e
    env ZCL_NODE_BIN="$FAKE_NODE" ZCL_RPC_BIN="$FAKE_RPC" \
        "$SCRIPT" --mode=bundle --src="$SRC_FIXTURE" --copy-dir="$COPY_DIR" \
        --expect-climb-past="$WEDGE" > "$OUTPUT" 2>&1
    rc=$?
    set -e
    assert_rc "$rc" 2 "bundle mode without --bundle/--receipt was not refused"
    assert_contains "$OUTPUT" "--bundle=PATH is required" "bundle-required message missing"
    printf '[import-copy-prove-selftest] PASS: bundle mode requires --bundle and --receipt\n'
}

test_bundle_requires_expect_climb_past() {
    OUTPUT="$SANDBOX/out-bundle-noclimb"
    COPY_DIR="$(fresh_bundle_copy_dir)"
    EXTRA_ARGS=()   # no --expect-climb-past
    local rc; rc="$(run_bundle)"
    assert_rc "$rc" 2 "bundle mode without --expect-climb-past was not refused"
    assert_contains "$OUTPUT" "expect-climb-past=H .*is required in --mode=bundle" \
        "bundle expect-climb-past-required message missing"
    printf '[import-copy-prove-selftest] PASS: bundle mode requires --expect-climb-past (no boundary= to parse)\n'
}

test_bundle_full_pass() {
    OUTPUT="$SANDBOX/out-bundle-pass"
    COPY_DIR="$(fresh_bundle_copy_dir)"
    echo ok > "$INSTALL_BEHAVIOR_FILE"
    TEST_FRONTIER_RESPONSE="$FRONTIER_CONTINUOUS"
    TEST_PROVENANCE_RESPONSE="$PROVENANCE_BOTH"
    EXTRA_ARGS=(--expect-climb-past="$WEDGE")
    local rc; rc="$(run_bundle)"
    unset TEST_FRONTIER_RESPONSE TEST_PROVENANCE_RESPONSE
    assert_rc "$rc" 0 "the all-green bundle fixture did not PASS"
    assert_contains "$OUTPUT" "VERDICT: PASS  (mode=bundle)" "bundle all-green missing PASS verdict"
    assert_contains "$OUTPUT" "G-SOV.3 provenance:.*present: 1" "G-SOV.3 provenance not reported present"
    [ -f "$COPY_DIR/consensus_state_replay_receipt.v1" ] || \
        fail "the replay receipt was not injected into the copy's datadir"
    printf '[import-copy-prove-selftest] PASS: bundle mode green path (install banner + climb + continuity + provenance) PASSes\n'
}

test_bundle_missing_install_banner_fails() {
    OUTPUT="$SANDBOX/out-bundle-missing"
    COPY_DIR="$(fresh_bundle_copy_dir)"
    echo missing > "$INSTALL_BEHAVIOR_FILE"
    EXTRA_ARGS=(--expect-climb-past="$WEDGE")
    local rc; rc="$(run_bundle)"
    echo ok > "$INSTALL_BEHAVIOR_FILE"
    assert_rc "$rc" 1 "a bundle install with no INSTALLED banner did not FAIL"
    assert_contains "$OUTPUT" "did not report INSTALLED" "bundle missing-banner FAIL reason absent"
    printf '[import-copy-prove-selftest] PASS: bundle mode fails closed when the INSTALLED banner is absent\n'
}

test_bundle_missing_provenance_fails_gsov3() {
    OUTPUT="$SANDBOX/out-bundle-prov"
    COPY_DIR="$(fresh_bundle_copy_dir)"
    echo ok > "$INSTALL_BEHAVIOR_FILE"
    TEST_FRONTIER_RESPONSE="$FRONTIER_CONTINUOUS"
    TEST_PROVENANCE_RESPONSE="$PROVENANCE_PARTIAL"   # only 1 of 2 markers
    EXTRA_ARGS=(--expect-climb-past="$WEDGE")
    local rc; rc="$(run_bundle)"
    unset TEST_FRONTIER_RESPONSE TEST_PROVENANCE_RESPONSE
    assert_rc "$rc" 1 "a bundle install missing a provenance marker did not FAIL G-SOV.3"
    assert_contains "$OUTPUT" "VERDICT: FAIL  (mode=bundle)" "partial-provenance run missing FAIL verdict"
    assert_contains "$OUTPUT" "G-SOV.3 provenance:.*present: 0" "G-SOV.3 did not report not-present"
    printf '[import-copy-prove-selftest] PASS: bundle mode fails G-SOV.3 when a provenance marker is missing (self_folded not proven)\n'
}

test_dead_sink_listener_fails_closed() {
    OUTPUT="$SANDBOX/out-sink-listening"; COPY_DIR="$(fresh_copy_dir)"
    EXTRA_ARGS=(--expect-climb-past="$WEDGE"); Z23_PORT_PROBE_SS=/bin/echo
    local rc; rc="$(run_script)"; Z23_PORT_PROBE_SS=/bin/true
    assert_rc "$rc" 2 "a listening dead sink was not refused"
    assert_contains "$OUTPUT" "dead -connect sink 39999 is LISTENING" \
        "the listening-sink refusal did not name its cause"
    printf '[import-copy-prove-selftest] PASS: a listening dead sink is refused, never dialled\n'
}

# ── import mode ──
test_dead_sink_listener_fails_closed
test_dry_run_prints_plan_only
test_refuses_non_copy_path
test_refuses_preexisting_copy_dir
test_rejects_bad_mode
test_missing_importer_fails_fast
test_importer_explicit_refusal_fails
test_full_pass_all_gates_green
test_auto_parsed_boundary_passes
test_no_boundary_and_no_override_fails_blind
test_blocker_still_present_fails_gate_a
test_continuity_gap_fails_gate_b
test_transient_continuity_publish_window_retries
test_hash_mismatch_fails_gate_c
test_header_refresh_failure_fails_before_phase1
test_skip_header_refresh_bypasses_step
test_stale_auto_reindex_request_is_cleared
test_no_auto_reindex_request_is_a_documented_noop
test_skip_zclassicd_check_is_incomplete_not_pass
test_tail_peer_boots_with_addnode
# ── bundle mode ──
test_bundle_requires_bundle_and_receipt
test_bundle_requires_expect_climb_past
test_bundle_full_pass
test_bundle_missing_install_banner_fails
test_bundle_missing_provenance_fails_gsov3
printf '[import-copy-prove-selftest] PASS: all import-copy-prove.sh driver-logic proofs (import + bundle modes)\n'
