#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# fresh-boot-weld-prove-selftest.sh — hermetic proof that
# tools/scripts/fresh-boot-weld-prove.sh's DRIVER computes the right verdict
# from a given set of boot outcomes, with NO real node binary, NO real chain
# state, and NO network ports opened for anything but a loopback fake. It
# fakes $ZCL_NODE_BIN with a tiny fixture script that emits exactly the log
# lines / marker files / dumpstate JSON the real driver greps and parses, and
# drives the real driver end-to-end against each fixture scenario.
#
# This exists for the same reason tools/scripts/import-copy-prove-selftest.sh
# does: the real weld (a zero-flag cold-boot bundle autodetect + install +
# fold-forward) cannot be exercised in CI/dev on demand (no from-scratch
# chain-binding relaxation merged yet at the time this was written — see the
# real driver's header). What CAN be proven hermetically, and what this
# proves, is that the DRIVER classifies each boot outcome (installed+climbed,
# tamper-refused, chain-binding-blocked, installed-but-frozen, a denylisted
# work dir) into the correct verdict and exit code — i.e. that the harness
# will gate correctly the moment a real weld runs. It does not (and cannot)
# prove anything about the weld/installer itself.
#
# All fixture paths live under a throwaway mktemp sandbox; nothing under
# $HOME or any real datadir is written (the one deliberate exception —
# proving the denylist refusal — only ever passes a --work-base string that
# is compared, never created or booted against).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$REPO/tools/scripts/fresh-boot-weld-prove.sh"
SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/zcl-fresh-boot-weld-selftest.XXXXXX")"
chmod 700 "$SANDBOX"

cleanup() { rm -rf "$SANDBOX"; }
trap cleanup EXIT

FAKE_NODE="$SANDBOX/fake-zclassic23"
GOOD_BUNDLE="$SANDBOX/fixture-bundle.sqlite"
CHECKPOINT=3056758

# ── DEADLINES IN THIS FILE ARE FIXTURE CONTROLS, NOT BUDGETS ──────────────
# Read this before touching any --deadline= / --negative-deadline= number
# below. Every VERDICT this selftest asserts is decided by an observation
# COUNT, never by a duration:
#
#   * install-and-climb  — the fake advances H* one height per OBSERVED
#     dumpstate, so the driver's 1st sample is the checkpoint and its 2nd is
#     above it. The driver takes MIN_SAMPLES=2 samples before its deadline is
#     even consulted, so PASS is reached in exactly two samples on any box.
#   * frozen-at-checkpoint / never-answers-RPC — the fixture is deliberately
#     STATIONARY, so the driver must exhaust its window to conclude. Here the
#     deadline is the fixture's control knob: it decides how long the selftest
#     RUNS, not what it decides. Making it bigger only makes the suite slower;
#     making it smaller cannot change the verdict, because MIN_SAMPLES
#     guarantees the samples happen first.
#   * tamper cases — decided by marker files the fake writes at boot.
#
# So: a slow or saturated box makes this script take LONGER and reach the
# SAME verdicts. Do not "fix" a failure here by raising a number — under this
# design a raised number cannot turn a red into a green, which means a red
# here is a real defect. If you ever find yourself wanting to raise one, the
# timing dependence has crept back in and that is the bug to fix.
SELFTEST_STARTED=$(date +%s)
loadavg_now() { cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo "unknown"; }
fail() {
    printf '[fresh-boot-weld-prove-selftest] FAIL: %s\n' "$*" >&2
    printf '[fresh-boot-weld-prove-selftest]   measured: %ss elapsed in this selftest so far; loadavg %s on %s cpus.\n' \
        "$(( $(date +%s) - SELFTEST_STARTED ))" "$(loadavg_now)" \
        "$(nproc 2>/dev/null || echo '?')" >&2
    printf '[fresh-boot-weld-prove-selftest]   NOTE: no assertion in this file is graded on elapsed time — every\n' >&2
    printf '[fresh-boot-weld-prove-selftest]   verdict comes from an observation count or a marker file. A busy box\n' >&2
    printf '[fresh-boot-weld-prove-selftest]   makes this SLOWER, not RED. Treat the failure above as a real defect\n' >&2
    printf '[fresh-boot-weld-prove-selftest]   in the driver, and do NOT raise a deadline to make it go away.\n' >&2
    [ -r "${OUTPUT:-}" ] && sed 's/^/[selftest-output] /' "$OUTPUT" >&2
    exit 1
}
assert_rc() {
    [ "$1" = "$2" ] || fail "$3 (expected rc=$2, got rc=$1)"
}
assert_contains() {
    grep -q -- "$2" "$1" || fail "$3 (missing '$2' in $1)"
}
assert_not_contains() {
    grep -q -- "$2" "$1" && fail "$3 (unexpectedly found '$2' in $1)" || true
}

# ── the one fake $ZCL_NODE_BIN, scenario-selected via FAKE_WELD_SCENARIO ────
cat > "$FAKE_NODE" <<'NODE_EOF'
#!/bin/sh
# Fake zclassic23 for the fresh-boot-weld-prove hermetic selftest ONLY.
#
# ── WHY THE H* SEQUENCE IS SAMPLE-DRIVEN AND NOT CLOCK-DRIVEN ──────────────
# This fixture used to publish H* from a `sleep 1; h=$((h+1))` loop in the
# BOOT path: it wrote H*=checkpoint, then one height per real second. The
# driver asserts it observed `first H*: <checkpoint>` exactly, so the driver's
# first successful dumpstate had to land inside a ONE-SECOND window after the
# boot path wrote the file. That is a wall-clock race, and it is the whole
# reason this selftest gave opposite verdicts on the same commit: FAILED at
# 48s inside a 32-worker suite run, PASSED at 64.0s standalone on the same
# tree and the same binary, with load the only variable. A busy box made the
# driver's first sample land at checkpoint+3, `seen_checkpoint` could then
# never become 1 (H* only ever moves up), and the driver correctly reported
# FAIL for a fixture that was working perfectly.
#
# The fix is not a bigger window. H* now advances by exactly one height per
# OBSERVED SAMPLE — an operation count, not a duration — so the sequence the
# driver sees is (checkpoint, checkpoint+1, checkpoint+2, …) on its 1st, 2nd,
# 3rd successful dumpstate no matter how long the machine takes between them.
# A 7200rpm box under full load sees exactly the same sequence a fast one
# does; only the wall time differs, and no assertion reads the wall time.
#
# The query path also SEEDS its own H* when the boot path has not written the
# file yet (same scenario table), so the boot/query interleaving cannot emit a
# transient -1 either. Nothing in this fixture sleeps to make an assertion
# true.
datadir=""
query=0
for a in "$@"; do
    case "$a" in
        -datadir=*) datadir="${a#-datadir=}" ;;
        dumpstate)  query=1 ;;
    esac
done

scenario="${FAKE_WELD_SCENARIO:-install_and_climb}"
cp_height="${FAKE_CHECKPOINT:-3056758}"

# The H* a scenario reports before/without any boot-path write. Keeping this
# in ONE place is what makes the query path independent of boot ordering.
scenario_seed_hstar() {
    case "$scenario" in
        install_and_climb|frozen_at_checkpoint|tamper_falsely_installed)
            printf '%s\n' "$cp_height" ;;
        *)  printf '%s\n' "-1" ;;
    esac
}

if [ "$query" = "1" ]; then
    if [ "$scenario" = "never_rpc" ]; then
        # Simulates an RPC that never binds: no output, non-zero exit.
        exit 1
    fi
    if [ -r "$datadir/fake_hstar" ]; then
        hstar="$(cat "$datadir/fake_hstar")"
    else
        hstar="$(scenario_seed_hstar)"
        [ -d "$datadir" ] && printf '%s\n' "$hstar" > "$datadir/fake_hstar"
    fi
    printf '{"hstar":%s,"network_tip":-1,"coins_applied_height":-1}\n' "$hstar"
    # Climb one height PER OBSERVED SAMPLE (see the header). Only the climbing
    # scenario advances; every other scenario is deliberately stationary.
    if [ "$scenario" = "install_and_climb" ] && [ -d "$datadir" ]; then
        case "$hstar" in
            ''|*[!0-9]*) : ;;                       # -1 / garbage: stay put
            *) printf '%s\n' "$((hstar + 1))" > "$datadir/fake_hstar" ;;
        esac
    fi
    exit 0
fi

# Boot mode: find the staged bundle (if any) under <datadir>/bundles/.
mkdir -p "$datadir"
bundle_path=""
for f in "$datadir"/bundles/*.sqlite; do
    [ -f "$f" ] && bundle_path="$f"
done

trap 'exit 0' TERM INT

case "$scenario" in
    install_and_climb)
        # H*=checkpoint at install; every subsequent height comes from the
        # query path, one per observed sample. No timed climb loop lives here.
        # Never move H* BACKWARDS: if a query already seeded (and advanced)
        # the file while this boot path was being scheduled, clobbering it
        # here would undo an observed climb and cost an extra sample — a
        # boot/query interleaving, i.e. exactly the kind of ordering-by-luck
        # this fixture exists to be free of.
        _prev=-1
        [ -r "$datadir/fake_hstar" ] && _prev="$(cat "$datadir/fake_hstar")"
        case "$_prev" in
            ''|*[!0-9]*) _prev=-1 ;;
        esac
        [ "$_prev" -lt "$cp_height" ] && echo "$cp_height" > "$datadir/fake_hstar"
        : > "$datadir/consensus-bundle-installed.marker"
        echo "[install_consensus_bundle] autodetected consensus bundle installed $bundle_path (H*=$cp_height)"
        while true; do sleep 1; done
        ;;
    refused_tamper)
        echo "-1" > "$datadir/fake_hstar"
        echo "[install_consensus_bundle] autodetected bundle $bundle_path did not install (marked .failed -> normal boot next time): bundle admission/validation failed: artifact digest mismatch"
        [ -n "$bundle_path" ] && : > "${bundle_path}.failed"
        while true; do sleep 1; done
        ;;
    chain_binding_blocked)
        echo "-1" > "$datadir/fake_hstar"
        echo "[install_consensus_bundle] autodetected bundle $bundle_path did not install (marked .failed -> normal boot next time): selected-chain binding failed (the bundle's height/hash is not on this node's validated header chain, or the node is not the open singleton): chain binding: selected frontier changed or is not durable"
        [ -n "$bundle_path" ] && : > "${bundle_path}.failed"
        while true; do sleep 1; done
        ;;
    frozen_at_checkpoint)
        echo "$cp_height" > "$datadir/fake_hstar"
        : > "$datadir/consensus-bundle-installed.marker"
        echo "[install_consensus_bundle] autodetected consensus bundle installed $bundle_path (H*=$cp_height)"
        while true; do sleep 1; done
        ;;
    tamper_falsely_installed)
        # A deliberate REGRESSION fixture: despite tamper, the fake installs
        # anyway. Proves the driver's PASS predicate genuinely checks the
        # marker + .failed absence, not merely "H* moved".
        echo "$cp_height" > "$datadir/fake_hstar"
        : > "$datadir/consensus-bundle-installed.marker"
        echo "[install_consensus_bundle] autodetected consensus bundle installed $bundle_path (H*=$cp_height) [SELFTEST REGRESSION FIXTURE]"
        while true; do sleep 1; done
        ;;
    never_rpc)
        # Simulates a node that never binds RPC in time.
        while true; do sleep 1; done
        ;;
    never_decides)
        # Boots and stays up, but never reaches a bundle-admission decision:
        # no installed marker, no .failed marker, no refusal line. This is
        # what a saturated or very slow box looks like from outside, and the
        # driver must call it INCONCLUSIVE rather than manufacture a FAIL.
        while true; do sleep 1; done
        ;;
esac
NODE_EOF
chmod +x "$FAKE_NODE"

# ── a fixture bundle that passes is_sqlite_bundle()'s magic-header check ───
printf 'SQLite format 3\000' > "$GOOD_BUNDLE"
dd if=/dev/zero bs=1 count=284 >> "$GOOD_BUNDLE" 2>/dev/null

run_script() {
    local rc
    set +e
    env ZCL_NODE_BIN="$FAKE_NODE" FAKE_CHECKPOINT="$CHECKPOINT" \
        FAKE_WELD_SCENARIO="${SCENARIO:-install_and_climb}" \
        "$SCRIPT" --checkpoint="$CHECKPOINT" --work-base="$SANDBOX" \
        "${EXTRA_ARGS[@]}" > "$OUTPUT" 2>&1
    rc=$?
    set -e
    echo "$rc"
}

# ============================================================================
test_no_bundle_found_skips() {
    OUTPUT="$SANDBOX/out-nobundle"
    EMPTY_HOME="$SANDBOX/empty-home-$$"
    mkdir -p "$EMPTY_HOME"
    local rc
    set +e
    env ZCL_NODE_BIN="$FAKE_NODE" HOME="$EMPTY_HOME" \
        "$SCRIPT" --work-base="$SANDBOX" > "$OUTPUT" 2>&1
    rc=$?
    set -e
    assert_rc "$rc" 0 "no-bundle-found did not exit 0 (SKIP)"
    assert_contains "$OUTPUT" "VERDICT: SKIP" "no-bundle-found missing SKIP verdict"
    printf '[fresh-boot-weld-prove-selftest] PASS: no bundle anywhere -> SKIP, exit 0\n'
}

test_explicit_bundle_discovery() {
    OUTPUT="$SANDBOX/out-explicit-negonly"
    SCENARIO=refused_tamper
    EXTRA_ARGS=(--bundle="$GOOD_BUNDLE" --negative-only --negative-deadline=15)
    local rc; rc="$(run_script)"
    assert_rc "$rc" 0 "--bundle=explicit path did not resolve/PASS"
    assert_contains "$OUTPUT" "bundle: $GOOD_BUNDLE" "explicit --bundle was not used"
    printf '[fresh-boot-weld-prove-selftest] PASS: --bundle=PATH is used verbatim\n'
}

test_negative_pass_tamper_refused() {
    OUTPUT="$SANDBOX/out-neg-pass"
    SCENARIO=refused_tamper
    EXTRA_ARGS=(--bundle="$GOOD_BUNDLE" --negative-only --negative-deadline=15)
    local rc; rc="$(run_script)"
    assert_rc "$rc" 0 "a cleanly-refused tamper did not PASS the negative leg"
    assert_contains "$OUTPUT" "NEGATIVE PASS" "negative leg missing PASS"
    assert_contains "$OUTPUT" "flipped 1 byte at offset" "byte-flip evidence missing (tamper may be a no-op)"
    assert_contains "$OUTPUT" "VERDICT: PASS" "negative-only run missing overall PASS verdict"
    printf '[fresh-boot-weld-prove-selftest] PASS: a cleanly-refused tamper -> NEGATIVE PASS\n'
}

test_negative_fails_if_marker_present() {
    OUTPUT="$SANDBOX/out-neg-fail-marker"
    SCENARIO=tamper_falsely_installed
    EXTRA_ARGS=(--bundle="$GOOD_BUNDLE" --negative-only --negative-deadline=15)
    local rc; rc="$(run_script)"
    assert_rc "$rc" 1 "a falsely-installed tamper did not FAIL the negative leg"
    assert_contains "$OUTPUT" "NEGATIVE FAIL" "negative leg missing FAIL for a falsely-installed tamper"
    printf '[fresh-boot-weld-prove-selftest] PASS: a falsely-installed tamper (regression fixture) -> NEGATIVE FAIL\n'
}

test_positive_pass_install_and_climb() {
    OUTPUT="$SANDBOX/out-pos-pass"
    SCENARIO=install_and_climb
    EXTRA_ARGS=(--bundle="$GOOD_BUNDLE" --positive-only --deadline=20)
    local rc; rc="$(run_script)"
    assert_rc "$rc" 0 "install-and-climb fixture did not PASS the positive leg"
    assert_contains "$OUTPUT" "first H\*: $CHECKPOINT" "did not observe H* land exactly at the checkpoint"
    assert_contains "$OUTPUT" "POSITIVE PASS" "positive leg missing PASS"
    assert_contains "$OUTPUT" "VERDICT: PASS" "positive-only run missing overall PASS verdict"
    printf '[fresh-boot-weld-prove-selftest] PASS: zero-flag install-then-climb fixture -> POSITIVE PASS\n'
}

test_positive_blocked_chain_binding() {
    OUTPUT="$SANDBOX/out-pos-blocked"
    SCENARIO=chain_binding_blocked
    EXTRA_ARGS=(--bundle="$GOOD_BUNDLE" --positive-only --deadline=8)
    local rc; rc="$(run_script)"
    assert_rc "$rc" 3 "a chain-binding refusal did not report BLOCKED (rc=3)"
    assert_contains "$OUTPUT" "BLOCKED-CHAIN-BINDING" "chain-binding refusal not distinguished from a generic FAIL"
    printf '[fresh-boot-weld-prove-selftest] PASS: chain-binding refusal -> honest BLOCKED, not FAIL or a false PASS\n'
}

test_positive_fails_frozen_at_checkpoint() {
    OUTPUT="$SANDBOX/out-pos-frozen"
    SCENARIO=frozen_at_checkpoint
    EXTRA_ARGS=(--bundle="$GOOD_BUNDLE" --positive-only --deadline=8)
    local rc; rc="$(run_script)"
    assert_rc "$rc" 1 "landed-but-never-climbed did not FAIL the positive leg"
    assert_contains "$OUTPUT" "NEVER moved" "frozen-at-checkpoint FAIL reason missing"
    # The FAIL must be justified by an observation COUNT, not by a duration:
    # "H* did not move across N samples" survives any machine speed, whereas
    # "H* did not climb within Ns" is a statement about the box.
    assert_contains "$OUTPUT" "samples=" "frozen FAIL does not report how many samples it based the verdict on"
    printf '[fresh-boot-weld-prove-selftest] PASS: installed but frozen at the checkpoint -> POSITIVE FAIL, justified by zero progress over N samples (gate is CLIMB, not booted)\n'
}

# ── the load-independence proof itself ────────────────────────────────────
# Model the worst possible box: one whose entire observation window has
# ALREADY expired before the first sample (--deadline=0). A healthy node must
# still PASS, because the driver's MIN_SAMPLES floor takes the two samples the
# predicate needs before it consults the clock at all. If someone reintroduces
# a "while [ now -lt deadline ]" that can skip the observation, this is the
# assertion that catches it — and it catches it deterministically, on a fast
# box, instead of waiting for a loaded one to flake.
test_positive_pass_survives_an_already_expired_deadline() {
    OUTPUT="$SANDBOX/out-pos-zero-deadline"
    SCENARIO=install_and_climb
    EXTRA_ARGS=(--bundle="$GOOD_BUNDLE" --positive-only --deadline=0)
    local rc; rc="$(run_script)"
    assert_rc "$rc" 0 "a healthy node FAILED with an already-expired window: the deadline is cutting off the observation the verdict needs (that is the load-sensitivity bug, not a slow box)"
    assert_contains "$OUTPUT" "POSITIVE PASS" "zero-deadline run missing PASS"
    assert_contains "$OUTPUT" "samples=2" "the driver did not take exactly the 2 samples its predicate needs"
    printf '[fresh-boot-weld-prove-selftest] PASS: an ALREADY-EXPIRED window still reaches POSITIVE PASS in 2 samples (verdict is count-graded, not clock-graded)\n'
}

# A node that boots and never reaches ANY bundle-admission decision is not
# evidence that a tamper was accepted — it is evidence the window closed
# first. That must read INCONCLUSIVE, visibly distinct from the NEGATIVE FAIL
# a genuinely-wrong decision earns, so nobody reads a saturated box as a
# broken refusal path.
test_negative_inconclusive_when_no_decision_reached() {
    OUTPUT="$SANDBOX/out-neg-inconclusive"
    SCENARIO=never_decides
    EXTRA_ARGS=(--bundle="$GOOD_BUNDLE" --negative-only --negative-deadline=5)
    local rc; rc="$(run_script)"
    assert_rc "$rc" 1 "a node that never decided was reported as a PASS"
    assert_contains "$OUTPUT" "NEGATIVE INCONCLUSIVE" "an undecided node was not distinguished from a wrong decision"
    assert_not_contains "$OUTPUT" "NEGATIVE FAIL" "an undecided node was graded FAIL — that grades the machine, not the refusal path"
    printf '[fresh-boot-weld-prove-selftest] PASS: node never reached an admission decision -> INCONCLUSIVE, never a false FAIL and never a PASS\n'
}

test_positive_inconclusive_when_rpc_never_answers() {
    OUTPUT="$SANDBOX/out-pos-norpc"
    SCENARIO=never_rpc
    EXTRA_ARGS=(--bundle="$GOOD_BUNDLE" --positive-only --deadline=6)
    local rc; rc="$(run_script)"
    assert_rc "$rc" 1 "a node that never answers RPC did not FAIL"
    assert_contains "$OUTPUT" "INCONCLUSIVE" "never-answers-RPC case missing INCONCLUSIVE diagnosis"
    printf '[fresh-boot-weld-prove-selftest] PASS: RPC never answering -> INCONCLUSIVE, not a false PASS\n'
}

test_denylist_refuses_live_datadir() {
    OUTPUT="$SANDBOX/out-denylist"
    SCENARIO=install_and_climb
    EXTRA_ARGS=(--bundle="$GOOD_BUNDLE" --negative-only --negative-deadline=5)
    local rc
    set +e
    env ZCL_NODE_BIN="$FAKE_NODE" FAKE_CHECKPOINT="$CHECKPOINT" \
        FAKE_WELD_SCENARIO="$SCENARIO" \
        "$SCRIPT" --checkpoint="$CHECKPOINT" --bundle="$GOOD_BUNDLE" \
        --negative-only --negative-deadline=5 \
        --work-base="$HOME/.zclassic" > "$OUTPUT" 2>&1
    rc=$?
    set -e
    assert_rc "$rc" 1 "a denylisted --work-base was not refused"
    assert_contains "$OUTPUT" "denylisted" "denylist refusal message missing"
    printf '[fresh-boot-weld-prove-selftest] PASS: a --work-base under a live datadir is refused, never booted against\n'
}

test_no_bundle_found_skips
test_explicit_bundle_discovery
test_negative_pass_tamper_refused
test_negative_fails_if_marker_present
test_positive_pass_install_and_climb
test_positive_pass_survives_an_already_expired_deadline
test_positive_blocked_chain_binding
test_positive_fails_frozen_at_checkpoint
test_positive_inconclusive_when_rpc_never_answers
test_negative_inconclusive_when_no_decision_reached
test_denylist_refuses_live_datadir

printf '[fresh-boot-weld-prove-selftest] ALL 11 HERMETIC ASSERTIONS PASSED (%ss elapsed, loadavg %s — reported, never asserted)\n' \
    "$(( $(date +%s) - SELFTEST_STARTED ))" "$(loadavg_now)"
