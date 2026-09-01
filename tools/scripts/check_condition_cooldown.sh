#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_condition_cooldown.sh — Gate E14: an external/network-dependent
# CRITICAL condition must not permanently latch (HARD).
#
# THE BUG CLASS (live 2026-07-13): sync_violation_lag and
# tip_wedged_resnapshot are CRITICAL conditions whose detect() depends on
# peer/network state (connman_max_peer_height / sync_monitor_connman).
# Both shipped with `cooldown_secs` unset (0 = the struct condition default).
# engine/modules/framework/src/condition.c's condition_cooldown_rearm() treats
# cooldown_secs == 0 as "legacy: latch permanently at max_attempts" — the
# CORRECT behavior for a genuinely local, deterministic-unrecoverable fault
# (disk full, corrupt local index), but WRONG for a condition whose only
# evidence is another node's state, which can recover on its own. The
# result: once max_attempts was reached, the remedy never ran again and the
# node paged an operator every ~3600s for 27h with zero further self-heal
# attempts. Fixed on main (1d317f4f6 / 62a7a0004) by giving both conditions
# `.cooldown_secs = 600` so condition.c re-arms the remedy on a bounded
# backoff instead of dead-ending at a human forever. See sync_violation_lag.c
# (search `.cooldown_secs = 600`) for the canonical fixed shape.
#
# THIS GATE makes the bug class unrepresentable: any FUTURE condition that
# is COND_CRITICAL and whose file calls a known peer/network/oracle-liveness
# primitive must also set cooldown_secs > 0, UNLESS it opts into the other
# documented anti-permanent-latch mechanism instead (see EXEMPTION below).
#
# --- detection rule ---
# For each *.c file in the scan dir that defines exactly one
# `static struct condition <var> = { ... };` registration literal (the
# repo-wide idiom — see framework/condition.h's `struct condition`):
#
#   1. severity  — `.severity = COND_CRITICAL` present in the file.
#   2. cooldown  — `.cooldown_secs = <N>` with N > 0. Absence (the struct's
#                  designated-initializer default) counts as 0 = "legacy
#                  permanent latch", matching condition.c's own doc comment
#                  ("cooldown_secs == 0 ... latch as before").
#   3. external  — the file calls one of the known external-liveness
#                  primitives (peer/connman height or count, or the
#                  zclassicd RPC oracle):
#                    connman_max_peer_height(   connman_get_node_count(
#                    sync_monitor_connman(      sync_monitor_max_peer_height(
#                    legacy_chain_rpc_*(
#                  These are the exact primitives sync_violation_lag.c and
#                  tip_wedged_resnapshot.c call from their detect() paths,
#                  and the only ones any current condition calls.
#
#   VIOLATION iff (1) AND (3) AND NOT (2), UNLESS EXEMPTION applies.
#
# --- EXEMPTION: `.progressing` (TL-1) ---
# framework/condition.h documents a second, independent anti-permanent-latch
# mechanism: a non-NULL `.progressing` callback lets condition.c RESET the
# attempt budget on confirmed durable forward progress, without ever
# reaching max_attempts. reducer_frontier_reconcile_light.c is COND_CRITICAL,
# calls connman_* from its detect() (a peer-lag gate), and has NO
# cooldown_secs — but it DOES set `.progressing`, so it can never
# permanently latch either; cooldown_secs would be redundant there. A file
# with a `.progressing = ` entry in its condition struct is exempt.
#
# Both mechanisms are legitimate; the gate simply requires a condition to
# use AT LEAST ONE of them once its detect() depends on state this process
# does not own.
#
# Exit codes: 0 clean; 2 on ANY failure — a real violation (offending
# condition(s) named on stderr) OR a hollow/empty scan (gate_require_scanned,
# fail-loud rather than a silent pass).
#
# --- self-test ---
# ZCL_CONDITION_COOLDOWN_SELFTEST=1 runs an internal fixture suite against
# an isolated tmp directory (ZCL_CONDITION_COOLDOWN_SCAN_DIR override) —
# it NEVER touches engine/conditions/src. It plants a cooldown-less CRITICAL
# fixture calling connman_max_peer_height(), asserts the gate exits 2 and
# names the offending condition, removes it, and asserts a clean rerun
# passes — plus sibling cases (cooldown-bearing pass, progressing-exempt
# pass, local-only-no-network pass, WARN-severity-ignored pass, hollow-scan
# fail-loud, recursive-selftest refusal). Wired into `make test` /
# `make test-parallel` via
# t_e14_condition_cooldown_gate() in tests/harness/src/test_make_lint_gates.c so
# it cannot silently rot.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

NETWORK_MARKER_RE='connman_max_peer_height\(|connman_get_node_count\(|sync_monitor_connman\(|sync_monitor_max_peer_height\(|legacy_chain_rpc_[A-Za-z_]*\('

# Extract the condition's reported name for the failure message:
#   1. a literal `.name = "..."` string
#   2. `.name = SOME_MACRO` resolved via `#define SOME_MACRO "value"` in the
#      same file
#   3. fall back to the filename stem
condition_name_for_file() {
    local f="$1"
    local lit
    lit=$(grep -oE '\.name[[:space:]]*=[[:space:]]*"[^"]*"' "$f" | head -1 \
          | sed -E 's/.*"([^"]*)".*/\1/') || true
    if [ -n "$lit" ]; then
        printf '%s\n' "$lit"
        return 0
    fi
    local macro
    macro=$(grep -oE '\.name[[:space:]]*=[[:space:]]*[A-Za-z_][A-Za-z0-9_]*' "$f" \
             | head -1 | sed -E 's/.*=[[:space:]]*//') || true
    if [ -n "$macro" ]; then
        local val
        val=$(grep -oE "#define[[:space:]]+${macro}[[:space:]]+\"[^\"]*\"" "$f" \
              | head -1 | sed -E 's/.*"([^"]*)".*/\1/') || true
        if [ -n "$val" ]; then
            printf '%s\n' "$val"
            return 0
        fi
    fi
    basename "$f" .c
}

main() {
    local scan_dir="${ZCL_CONDITION_COOLDOWN_SCAN_DIR:-engine/conditions/src}"
    local -a files
    mapfile -t files < <(find "$scan_dir" -maxdepth 1 -type f -name '*.c' 2>/dev/null | sort)

    # Fail-loud preflight (top-level call, not inside a subshell/command
    # substitution, so its exit 2 genuinely terminates the gate rather than
    # being swallowed as a captured subshell status).
    gate_require_scanned "${#files[@]}" 1 check_condition_cooldown \
        "no *.c under $scan_dir — scan dir renamed/moved/emptied?"

    local -a violations=()
    local f
    for f in "${files[@]}"; do
        # Only files that actually register a condition struct are in scope.
        grep -qE '^static struct condition [A-Za-z_][A-Za-z0-9_]* = \{[[:space:]]*$' "$f" \
            || continue

        grep -qE '\.severity[[:space:]]*=[[:space:]]*COND_CRITICAL\b' "$f" \
            || continue

        grep -qE "$NETWORK_MARKER_RE" "$f" || continue

        # EXEMPTION: a non-NULL .progressing callback is the documented
        # (TL-1) alternate anti-permanent-latch mechanism.
        grep -qE '\.progressing[[:space:]]*=[[:space:]]*[A-Za-z_]' "$f" && continue

        local cooldown
        cooldown=$(grep -oE '\.cooldown_secs[[:space:]]*=[[:space:]]*[0-9]+' "$f" \
                   | head -1 | grep -oE '[0-9]+$' || true)
        cooldown="${cooldown:-0}"
        [ "$cooldown" -gt 0 ] 2>/dev/null && continue

        violations+=("$f: $(condition_name_for_file "$f")")
    done

    if [ "${#violations[@]}" -eq 0 ]; then
        echo "check_condition_cooldown: OK — every network/oracle-dependent" \
             "CRITICAL condition in $scan_dir sets cooldown_secs > 0 or .progressing"
        exit 0
    fi

    echo "FAIL: CRITICAL condition(s) depend on external/network state but" >&2
    echo "      never re-arm — they will PERMANENTLY LATCH at max_attempts" >&2
    echo "      instead of retrying (the 2026-07-13 27h-page bug class):" >&2
    echo "" >&2
    local v
    for v in "${violations[@]}"; do
        echo "  $v" >&2
    done
    echo "" >&2
    echo "      Fix: add \`.cooldown_secs = <secs>\` (see sync_violation_lag.c" >&2
    echo "      for the canonical shape) so condition.c re-arms the remedy on" >&2
    echo "      a bounded backoff, OR wire a \`.progressing\` callback (TL-1," >&2
    echo "      framework/condition.h) if the condition already has a durable-" >&2
    echo "      progress signal that resets the attempt budget instead." >&2
    exit 2
}

# --------------------------------------------------------------------------
# Self-test: proves the gate FIRES (exit 2, names the offender) on a planted
# cooldown-less network-dependent CRITICAL fixture, and stays clean on every
# sibling case, entirely inside an isolated tmp dir.
# --------------------------------------------------------------------------
expect_rc() {
    local name="$1" want="$2" dir="$3"
    local rc=0
    local out_file
    out_file="$(mktemp)"
    # -u ZCL_..._SELFTEST: this invocation must run main(), never re-enter
    # selftest() — without clearing it, a caller that exported the selftest
    # var into its own environment (e.g. `env ZCL_..._SELFTEST=1 <this
    # script>`) would have every child invocation below inherit it and
    # recurse into selftest() forever.
    env -u ZCL_CONDITION_COOLDOWN_SELFTEST \
        ZCL_CONDITION_COOLDOWN_SCAN_DIR="$dir" "$SCRIPT_PATH" >"$out_file" 2>&1 \
        || rc=$?
    if [ "$rc" != "$want" ]; then
        echo "SELFTEST FAIL: $name — expected exit $want, got $rc"
        echo "  --- gate output ---"
        sed 's/^/  /' "$out_file"
        rm -f "$out_file"
        return 1
    fi
    rm -f "$out_file"
    return 0
}

write_condition_fixture() {
    # $1=path $2=severity $3=cooldown_line $4=extra_struct_line $5=body_marker
    local path="$1" severity="$2" cooldown_line="$3" extra="$4" marker="$5"
    cat > "$path" <<EOF
/* selftest fixture — not a real condition */
#include "framework/condition.h"

static bool detect_fixture(void)
{
    $marker
    return false;
}

static enum condition_remedy_result remedy_fixture(void)
{
    return COND_REMEDY_OK;
}

static bool witness_fixture(int64_t target_at_detect)
{
    (void)target_at_detect;
    return false;
}

static struct condition c_fixture = {
    .name = "selftest_fixture_condition",
    .severity = $severity,
    .poll_secs = 5,
    .backoff_secs = 60,
    .max_attempts = 1,
    $cooldown_line
    $extra
    .detect = detect_fixture,
    .remedy = remedy_fixture,
    .witness = witness_fixture,
    .witness_window_secs = 60,
};
EOF
}

selftest() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN

    local failures=0

    # Case 0: a child that accidentally inherits the self-test request must
    # fail before creating fixtures or spawning another child. Keep this
    # assertion independently bounded so a future regression in the guard
    # cannot recreate the process-chain incident that motivated it.
    local recursion_out recursion_rc=0
    recursion_out="$(mktemp)"
    if ! command -v timeout >/dev/null 2>&1; then
        echo "SELFTEST FAIL: timeout is required for the recursion-guard test"
        failures=$((failures + 1))
    else
        timeout --kill-after=0.1s 0.25s \
            env ZCL_CONDITION_COOLDOWN_SELFTEST=1 \
                "$SCRIPT_PATH" >"$recursion_out" 2>&1 || recursion_rc=$?
        if [ "$recursion_rc" != "2" ]; then
            echo "SELFTEST FAIL: recursive self-test expected exit 2, got $recursion_rc"
            failures=$((failures + 1))
        elif ! grep -q '^FAIL: check_condition_cooldown self-test recursion refused$' \
                "$recursion_out"; then
            echo "SELFTEST FAIL: recursive self-test refusal was not named"
            failures=$((failures + 1))
        fi
    fi
    rm -f "$recursion_out"

    # A permanent, never-removed filler file keeps the scan dir non-empty
    # across every case below (including after a fixture is deleted), so
    # a "clean pass" assertion never accidentally exercises the hollow-scan
    # floor (gate_require_scanned) instead of the real 0-violations path.
    cat > "$tmp/_keep.c" <<'EOF'
/* selftest filler — not a condition, keeps the scan dir non-empty. */
EOF

    # Case 1: network-dependent CRITICAL, NO cooldown_secs -> VIOLATION (exit 2).
    write_condition_fixture "$tmp/bad_fixture.c" "COND_CRITICAL" "" "" \
        "int p = connman_max_peer_height(cm);"
    expect_rc "network-dependent CRITICAL with no cooldown fires exit 2" 2 "$tmp" \
        || failures=$((failures + 1))
    # Assert the failure names the offending condition.
    local named_out
    named_out="$(env -u ZCL_CONDITION_COOLDOWN_SELFTEST \
        ZCL_CONDITION_COOLDOWN_SCAN_DIR="$tmp" "$SCRIPT_PATH" 2>&1 || true)"
    if ! printf '%s' "$named_out" | grep -q "selftest_fixture_condition"; then
        echo "SELFTEST FAIL: violation message does not name the offending condition"
        failures=$((failures + 1))
    fi
    rm -f "$tmp/bad_fixture.c"
    expect_rc "removing the fixture restores a clean pass" 0 "$tmp" \
        || failures=$((failures + 1))

    # Case 2: network-dependent CRITICAL WITH cooldown_secs > 0 -> pass.
    write_condition_fixture "$tmp/good_cooldown.c" "COND_CRITICAL" \
        ".cooldown_secs = 600," "" \
        "int p = sync_monitor_connman();"
    expect_rc "network-dependent CRITICAL with cooldown_secs passes" 0 "$tmp" \
        || failures=$((failures + 1))
    rm -f "$tmp/good_cooldown.c"

    # Case 3: network-dependent CRITICAL with NO cooldown but .progressing set
    # (TL-1 exemption, mirrors reducer_frontier_reconcile_light.c) -> pass.
    write_condition_fixture "$tmp/good_progressing.c" "COND_CRITICAL" "" \
        ".progressing = progressing_fixture," \
        "int n = connman_get_node_count(cm);"
    cat >> "$tmp/good_progressing.c" <<'EOF'
static bool progressing_fixture(int64_t target_at_detect)
{
    (void)target_at_detect;
    return false;
}
EOF
    expect_rc "network-dependent CRITICAL with .progressing exemption passes" \
        0 "$tmp" || failures=$((failures + 1))
    rm -f "$tmp/good_progressing.c"

    # Case 4: purely local CRITICAL (no network markers), no cooldown -> pass
    # (the legitimate legacy permanent-latch shape, e.g. disk_full_pause.c).
    write_condition_fixture "$tmp/local_only.c" "COND_CRITICAL" "" "" \
        "int d = 0; (void)d;"
    expect_rc "local-only CRITICAL with no network markers passes" 0 "$tmp" \
        || failures=$((failures + 1))
    rm -f "$tmp/local_only.c"

    # Case 5: network-dependent but COND_WARN (not CRITICAL) -> pass (severity
    # filter — only CRITICAL conditions are in scope for this gate).
    write_condition_fixture "$tmp/warn_network.c" "COND_WARN" "" "" \
        "int p = connman_max_peer_height(cm);"
    expect_rc "network-dependent COND_WARN is out of scope, passes" 0 "$tmp" \
        || failures=$((failures + 1))
    rm -f "$tmp/warn_network.c"

    # Case 6: hollow scan dir must be FATAL (exit 2), never a silent pass.
    local empty_dir="$tmp/empty"
    mkdir -p "$empty_dir"
    expect_rc "empty scan dir is fail-loud, not a hollow pass" 2 "$empty_dir" \
        || failures=$((failures + 1))

    if [ "$failures" -eq 0 ]; then
        echo "check_condition_cooldown: selftest OK (7/7 cases)"
        return 0
    fi
    echo "check_condition_cooldown: selftest FAILED ($failures case(s))"
    return 1
}

if [ "${ZCL_CONDITION_COOLDOWN_SELFTEST:-0}" = "1" ]; then
    if [ "${ZCL_CONDITION_COOLDOWN_SELFTEST_ACTIVE:-0}" = "1" ]; then
        echo "FAIL: check_condition_cooldown self-test recursion refused" >&2
        exit 2
    fi
    export ZCL_CONDITION_COOLDOWN_SELFTEST_ACTIVE=1
    selftest
else
    main
fi
