/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the oracle_policy module (engine/services/src/oracle_policy.c).
 *
 * oracle_policy is the gate that lets zclassicd-disagreement evidence
 * pause live chain extension. It is a lock-guarded singleton state
 * machine — NORMAL → HALTED (N distinct disagreement heights inside the
 * sliding window) or NORMAL → PANIC (a disagreement at or below the
 * evidence-prefix end height). chain_extension_allowed() is the yes/no
 * gate chain_advance consults before committing a new tip.
 *
 * Because the module is a process-global singleton, every test starts
 * from oracle_policy_reset_for_test() and then re-arms it with an
 * explicit oracle_policy_init() config so the thresholds are
 * deterministic and independent of the compile-time SHA3 windows. We
 * push the observation window wide (a large window_secs) so the few
 * rapid disagreements a test records all stay "live" regardless of
 * wall-clock granularity.
 *
 * Parallel-runner note: these tests mutate process-global singleton
 * state, so they must run inside a single test_oracle_policy() process
 * (which they do — the parallel runner forks one process per registered
 * test function). They do not touch SQLite, the network, or any other
 * test's globals.
 */

#include "test/test_core.h"
#include "services/oracle_policy.h"
#include "json/json.h"

#include <string.h>

/* Arm the policy from a clean slate with deterministic thresholds.
 *   - wide window so records do not age out mid-test
 *   - halt at `halt_at` distinct heights
 *   - PANIC for any disagreement height <= `prefix_end`
 * Heights strictly greater than prefix_end therefore drive HALT, not
 * PANIC, which is what the HALT-path tests want.
 *
 * NOTE: oracle_policy_init() only honours a *positive* prefix_end;
 * a value <= 0 falls back to the compile-time SHA3-window prefix end
 * (g_sha3_windows_count * SHA3_WINDOW_SIZE - 1, ~3.1M). So the HALT
 * tests pass a tiny positive prefix_end (e.g. 1) and use heights far
 * above it to stay on the HALT path; the PANIC test passes a prefix
 * end above its disagreement height. */
static void op_arm(int halt_at, int prefix_end)
{
    oracle_policy_reset_for_test();
    struct oracle_policy_config cfg = {
        .window_secs = 86400,           /* one day — nothing ages out */
        .halt_distinct_heights = halt_at,
        .evidence_prefix_end_height = prefix_end,
    };
    oracle_policy_init(&cfg);
}

/* Read one integer field out of a fresh dump_state_json snapshot. */
static int64_t op_dump_int(const char *field)
{
    struct json_value v;
    json_init(&v);
    int64_t got = -999999;        /* sentinel: field absent or dump failed */
    if (oracle_policy_dump_state_json(&v, NULL)) {
        const struct json_value *f = json_get(&v, field);
        if (f) got = json_get_int(f);
    }
    json_free(&v);
    return got;
}

/* Read the "state" string field out of dump_state_json into caller buf. */
static void op_dump_state_str(char *out, size_t n)
{
    struct json_value v;
    json_init(&v);
    out[0] = '\0';
    if (oracle_policy_dump_state_json(&v, NULL)) {
        const struct json_value *f = json_get(&v, "state");
        if (f) {
            const char *s = json_get_str(f);
            if (s) { strncpy(out, s, n - 1); out[n - 1] = '\0'; }
        }
    }
    json_free(&v);
}

/* ── 1. A fresh, armed policy starts NORMAL and allows extension ── */

static int t_starts_normal_allows(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: armed policy starts NORMAL and allows extension")
    {
        op_arm(3, 1);    /* tiny prefix_end → our test heights never PANIC */
        char st[16];
        op_dump_state_str(st, sizeof(st));

        ASSERT(oracle_policy_get_state() == OP_NORMAL);
        ASSERT(oracle_policy_chain_extension_allowed() == true);
        ASSERT_STR_EQ(st, "normal");
        ASSERT_EQ(op_dump_int("state_code"), (int64_t)OP_NORMAL);
        ASSERT_EQ(op_dump_int("total_disagree"), (int64_t)0);
        ASSERT_EQ(op_dump_int("total_halts"), (int64_t)0);
        ASSERT_EQ(op_dump_int("ring_count"), (int64_t)0);
    } TEST_END
    return failures;
}

/* ── 2. Below the distinct-height threshold stays NORMAL/allowed ── */

static int t_below_threshold_stays_allowed(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: disagreements below threshold keep extension allowed")
    {
        op_arm(3, 1);
        /* Two distinct heights with a 3-height HALT threshold: still
         * NORMAL. A repeat of an already-seen height must not count as
         * a new distinct height. */
        oracle_policy_record_disagreement(2000001, "a", "b");
        oracle_policy_record_disagreement(2000002, "a", "b");
        oracle_policy_record_disagreement(2000002, "a", "b"); /* dup */

        ASSERT(oracle_policy_get_state() == OP_NORMAL);
        ASSERT(oracle_policy_chain_extension_allowed() == true);
        ASSERT_EQ(op_dump_int("distinct_heights_in_window"), (int64_t)2);
        ASSERT_EQ(op_dump_int("total_disagree"), (int64_t)3);
        ASSERT_EQ(op_dump_int("total_halts"), (int64_t)0);
    } TEST_END
    return failures;
}

/* ── 3. Crossing the threshold transitions to HALTED and blocks ── */

static int t_threshold_halts_and_blocks(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: crossing distinct-height threshold HALTs (evidence-only; extension stays allowed)")
    {
        op_arm(3, 1);

        oracle_policy_record_disagreement(3000001, "a", "b");
        oracle_policy_record_disagreement(3000002, "a", "b");
        /* Still allowed right up to the boundary (2 < 3). */
        ASSERT(oracle_policy_chain_extension_allowed() == true);
        ASSERT(oracle_policy_get_state() == OP_NORMAL);

        /* Third distinct height crosses the threshold (3 >= 3). */
        oracle_policy_record_disagreement(3000003, "a", "b");
        ASSERT(oracle_policy_get_state() == OP_HALTED);
        /* Oracle disagreement is evidence-only — it drives the state
         * machine + events but NEVER gates chain extension. */
        ASSERT(oracle_policy_chain_extension_allowed() == true);

        /* dump_state_json must reflect the transition. */
        char st[16];
        op_dump_state_str(st, sizeof(st));
        ASSERT_STR_EQ(st, "halted");
        ASSERT_EQ(op_dump_int("state_code"), (int64_t)OP_HALTED);
        ASSERT_EQ(op_dump_int("total_halts"), (int64_t)1);
        ASSERT_EQ(op_dump_int("distinct_heights_in_window"), (int64_t)3);
    } TEST_END
    return failures;
}

/* ── 4. clear() restores NORMAL and re-allows extension ────────── */

static int t_clear_restores_allowed(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: clear() restores NORMAL and re-allows extension")
    {
        op_arm(3, 1);
        oracle_policy_record_disagreement(4000001, "a", "b");
        oracle_policy_record_disagreement(4000002, "a", "b");
        oracle_policy_record_disagreement(4000003, "a", "b");
        ASSERT(oracle_policy_get_state() == OP_HALTED);
        ASSERT(oracle_policy_chain_extension_allowed() == true);  /* evidence-only, never gates */

        oracle_policy_clear();

        ASSERT(oracle_policy_get_state() == OP_NORMAL);
        ASSERT(oracle_policy_chain_extension_allowed() == true);

        char st[16];
        op_dump_state_str(st, sizeof(st));
        ASSERT_STR_EQ(st, "normal");
        ASSERT_EQ(op_dump_int("state_code"), (int64_t)OP_NORMAL);
        /* clear() flushes the sliding window. */
        ASSERT_EQ(op_dump_int("ring_count"), (int64_t)0);
        ASSERT_EQ(op_dump_int("distinct_heights_in_window"), (int64_t)0);
        /* Lifetime counters survive a clear (operator observability). */
        ASSERT_EQ(op_dump_int("total_halts"), (int64_t)1);
    } TEST_END
    return failures;
}

/* ── 5. A disagreement at/under the evidence prefix triggers PANIC ── */

static int t_prefix_disagreement_panics(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: disagreement at evidence prefix PANICs (evidence-only; extension stays allowed)")
    {
        /* prefix_end = 100 → any height <= 100 is a prefix violation;
         * one such observation must PANIC immediately (no threshold). */
        op_arm(3, 100);

        ASSERT(oracle_policy_chain_extension_allowed() == true);
        oracle_policy_record_disagreement(50, "ours", "theirs");

        ASSERT(oracle_policy_get_state() == OP_PANIC);
        ASSERT(oracle_policy_chain_extension_allowed() == true);  /* evidence-only, never gates */

        char st[16];
        op_dump_state_str(st, sizeof(st));
        ASSERT_STR_EQ(st, "panic");
        ASSERT_EQ(op_dump_int("state_code"), (int64_t)OP_PANIC);
        ASSERT_EQ(op_dump_int("total_panics"), (int64_t)1);
        ASSERT_EQ(op_dump_int("total_halts"), (int64_t)0);

        /* clear() recovers from PANIC too. */
        oracle_policy_clear();
        ASSERT(oracle_policy_get_state() == OP_NORMAL);
        ASSERT(oracle_policy_chain_extension_allowed() == true);
    } TEST_END
    return failures;
}

/* ── 6. record_disagreement before init is a no-op (fail-safe) ──── */

static int t_record_before_init_noop(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: record_disagreement before init does not transition")
    {
        oracle_policy_reset_for_test();   /* leaves initialized=false */
        /* No oracle_policy_init() here. */
        oracle_policy_record_disagreement(5000001, "a", "b");
        oracle_policy_record_disagreement(5000002, "a", "b");
        oracle_policy_record_disagreement(5000003, "a", "b");

        /* Uninitialized policy must stay NORMAL/allowed and record
         * nothing — a missing init must never silently HALT the chain. */
        ASSERT(oracle_policy_get_state() == OP_NORMAL);
        ASSERT(oracle_policy_chain_extension_allowed() == true);
        ASSERT_EQ(op_dump_int("total_disagree"), (int64_t)0);
        ASSERT_EQ(op_dump_int("ring_count"), (int64_t)0);
    } TEST_END
    return failures;
}

/* ── Aggregator ─────────────────────────────────────────────────── */

int test_oracle_policy(void)
{
    printf("\n=== Oracle policy tests ===\n");
    int failures = 0;
    failures += t_starts_normal_allows();
    failures += t_below_threshold_stays_allowed();
    failures += t_threshold_halts_and_blocks();
    failures += t_clear_restores_allowed();
    failures += t_prefix_disagreement_panics();
    failures += t_record_before_init_noop();

    /* Leave the singleton in a clean, allowed state for any later test
     * group sharing this process. */
    oracle_policy_reset_for_test();
    return failures;
}
