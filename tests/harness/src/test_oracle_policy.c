/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the oracle_policy module (engine/services/src/oracle_policy.c).
 *
 * oracle_policy is a lock-guarded singleton state machine — NORMAL → HALTED
 * (N distinct disagreement heights inside the sliding window) or NORMAL →
 * PANIC (a disagreement at or below the evidence-prefix end height).
 *
 * Every test starts from oracle_policy_reset_for_test() and re-arms with an
 * explicit oracle_policy_init() config, with a wide window so records stay
 * live. The tests mutate process-global state and run in a single
 * test_oracle_policy() process; they touch no SQLite or network.
 */

#include "test/test_core.h"
#include "services/oracle_policy.h"
#include "json/json.h"
#include "chain/sha3_windows.h"
#include "event/event.h"
#include "platform/clock.h"

#include <stdatomic.h>
#include <stdint.h>
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

/* ── Mutation-sweep cases ───────────────────────────────────────────
 * A fake wall clock makes the sliding-window boundary exact, and observers
 * on the three policy events capture what each transition emitted. */

static _Atomic int64_t g_op_now_ms;

static int64_t op_fake_clock(void *self)
{
    (void)self;
    return atomic_load(&g_op_now_ms);
}

static void op_set_now(int64_t unix_secs)
{
    atomic_store(&g_op_now_ms, unix_secs * 1000);
}

struct op_ev {
    int n;
    uint32_t peer;
    char text[EVENT_PAYLOAD_SIZE + 1];
};
static struct op_ev g_op_ev[3];     /* panic, fork_suspected, chain_halted */

static void op_observer(enum event_type type, uint32_t peer_id,
                        const void *payload, uint32_t len, void *ctx)
{
    (void)ctx;
    struct op_ev *e = type == EV_ANCHOR_PANIC     ? &g_op_ev[0]
                    : type == EV_FORK_SUSPECTED   ? &g_op_ev[1]
                                                  : &g_op_ev[2];
    size_t n = len < EVENT_PAYLOAD_SIZE ? len : EVENT_PAYLOAD_SIZE;
    e->n++;
    e->peer = peer_id;
    if (payload) memcpy(e->text, payload, n);
    e->text[n] = '\0';
}

static void op_ev_reset(void)
{
    memset(g_op_ev, 0, sizeof(g_op_ev));
}

static bool op_ev_is(int slot, int n, const char *text)
{
    const struct op_ev *e = &g_op_ev[slot];
    bool ok = e->n == n && (n == 0 || (e->peer == 0 &&
                                       strcmp(e->text, text) == 0));
    if (!ok) printf("[event %d: n=%d peer=%u '%s'] ", slot, e->n, e->peer,
                    e->text);
    return ok;
}

/* The compile-time evidence-prefix end the policy derives when the config
 * names none. */
static int op_expected_default_prefix(void)
{
    if (g_sha3_windows_count == 0) return -1;
    return (int)(g_sha3_windows_count * SHA3_WINDOW_SIZE) - 1;
}

static void op_arm_cfg(int window, int halt_at, int prefix_end)
{
    oracle_policy_reset_for_test();
    op_ev_reset();
    struct oracle_policy_config cfg = {
        .window_secs = window,
        .halt_distinct_heights = halt_at,
        .evidence_prefix_end_height = prefix_end,
    };
    oracle_policy_init(&cfg);
}

static int t_default_config(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: init(NULL) takes 300 s window, halt at 3, compiled prefix")
    {
        op_set_now(1700000000);
        oracle_policy_reset_for_test();
        oracle_policy_init(NULL);
        ASSERT_EQ(op_dump_int("window_secs"), (int64_t)300);
        ASSERT_EQ(op_dump_int("halt_threshold"), (int64_t)3);
        ASSERT_EQ(op_dump_int("evidence_prefix_end_height"),
                  (int64_t)op_expected_default_prefix());
        ASSERT_EQ(op_dump_int("ring_count"), (int64_t)0);
    } TEST_END
    return failures;
}

static int t_default_config_2(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: a zero config falls back to the same defaults")
    {
        oracle_policy_reset_for_test();
        struct oracle_policy_config zero = {0};
        oracle_policy_init(&zero);
        ASSERT_EQ(op_dump_int("window_secs"), (int64_t)300);
        ASSERT_EQ(op_dump_int("halt_threshold"), (int64_t)3);
        ASSERT_EQ(op_dump_int("evidence_prefix_end_height"),
                  (int64_t)op_expected_default_prefix());
    } TEST_END
    return failures;
}

static int t_default_config_3(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: the smallest positive config values are honoured")
    {
        op_arm_cfg(1, 1, 1);
        ASSERT_EQ(op_dump_int("window_secs"), (int64_t)1);
        ASSERT_EQ(op_dump_int("halt_threshold"), (int64_t)1);
        ASSERT_EQ(op_dump_int("evidence_prefix_end_height"), (int64_t)1);
        op_set_now(1700000000);
        oracle_policy_record_disagreement(9000001, "a", "b");
        ASSERT(oracle_policy_get_state() == OP_HALTED);   /* 1 >= 1 */
    } TEST_END
    return failures;
}

static int t_default_window_boundary(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: default 300 s window keeps a record to exactly +300 s")
    {
        oracle_policy_reset_for_test();
        oracle_policy_init(NULL);
        op_set_now(1700000000);
        oracle_policy_record_disagreement(9100001, "a", "b");
        op_set_now(1700000000 + 299);
        ASSERT_EQ(op_dump_int("distinct_heights_in_window"), (int64_t)1);
        op_set_now(1700000000 + 300);
        ASSERT_EQ(op_dump_int("distinct_heights_in_window"), (int64_t)1);
        op_set_now(1700000000 + 301);
        ASSERT_EQ(op_dump_int("distinct_heights_in_window"), (int64_t)0);
        ASSERT_EQ(op_dump_int("ring_count"), (int64_t)1);   /* aged, not freed */
    } TEST_END
    return failures;
}

static int t_default_window_boundary_2(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: default halt threshold is 3 distinct heights")
    {
        oracle_policy_reset_for_test();
        oracle_policy_init(NULL);
        op_set_now(1700000000);
        oracle_policy_record_disagreement(9200001, "a", "b");
        oracle_policy_record_disagreement(9200002, "a", "b");
        ASSERT(oracle_policy_get_state() == OP_NORMAL);
        oracle_policy_record_disagreement(9200003, "a", "b");
        ASSERT(oracle_policy_get_state() == OP_HALTED);
    } TEST_END
    return failures;
}

static int t_default_prefix_boundary(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: default prefix end PANICs at the end height, not one above")
    {
        int pe = op_expected_default_prefix();
        if (pe < 0) { printf("(no compiled windows) "); }
        else {
            oracle_policy_reset_for_test();
            oracle_policy_init(NULL);
            op_set_now(1700000000);
            oracle_policy_record_disagreement(pe + 1, "a", "b");
            ASSERT(oracle_policy_get_state() == OP_NORMAL);
            oracle_policy_record_disagreement(pe, "a", "b");
            ASSERT(oracle_policy_get_state() == OP_PANIC);
        }
    } TEST_END
    return failures;
}

static int t_default_prefix_boundary_2(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: configured prefix end 100 PANICs at 100, not at 101")
    {
        op_arm_cfg(86400, 50, 100);
        op_set_now(1700000000);
        oracle_policy_record_disagreement(101, "a", "b");
        ASSERT(oracle_policy_get_state() == OP_NORMAL);
        ASSERT(op_ev_is(0, 0, ""));
        oracle_policy_record_disagreement(100, "a", "b");
        ASSERT(oracle_policy_get_state() == OP_PANIC);
    } TEST_END
    return failures;
}

static int t_ring_capacity(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: ring holds exactly 32 records and counts 32 distinct heights")
    {
        op_arm_cfg(86400, 1000, 1);
        op_set_now(1700000000);
        for (int i = 0; i < 31; i++)
            oracle_policy_record_disagreement(5000000 + i, "a", "b");
        ASSERT_EQ(op_dump_int("ring_count"), (int64_t)31);
        oracle_policy_record_disagreement(5000031, "a", "b");
        ASSERT_EQ(op_dump_int("ring_count"), (int64_t)32);
        ASSERT_EQ(op_dump_int("distinct_heights_in_window"), (int64_t)32);
        for (int i = 32; i < 40; i++)
            oracle_policy_record_disagreement(5000000 + i, "a", "b");
        ASSERT_EQ(op_dump_int("ring_count"), (int64_t)32);   /* wrapped */
        ASSERT_EQ(op_dump_int("distinct_heights_in_window"), (int64_t)32);
        ASSERT_EQ(op_dump_int("total_disagree"), (int64_t)40);
    } TEST_END
    return failures;
}

static int t_ring_capacity_2(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: a repeated height is one distinct height, even the first")
    {
        op_arm_cfg(86400, 5, 1);
        op_set_now(1700000000);
        oracle_policy_record_disagreement(5100001, "a", "b");
        oracle_policy_record_disagreement(5100001, "a", "b");
        ASSERT_EQ(op_dump_int("distinct_heights_in_window"), (int64_t)1);
        ASSERT_EQ(op_dump_int("ring_count"), (int64_t)2);
    } TEST_END
    return failures;
}

static int t_halt_window_and_events(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: a record exactly at the window edge counts toward HALT")
    {
        op_arm_cfg(10, 3, 1);
        op_set_now(1000);
        oracle_policy_record_disagreement(7000002, "a", "b");
        ASSERT(op_ev_is(0, 0, "") && op_ev_is(1, 0, "") && op_ev_is(2, 0, ""));
        op_set_now(1005);
        oracle_policy_record_disagreement(7000009, "a", "b");
        op_set_now(1010);                       /* cutoff 1000: first record live */
        oracle_policy_record_disagreement(7000005, "a", "b");
        ASSERT(oracle_policy_get_state() == OP_HALTED);
        ASSERT_EQ(op_dump_int("total_halts"), (int64_t)1);
        ASSERT(op_ev_is(1, 1, "distinct_heights=3 within_secs=10 "
                              "first_h=7000002 last_h=7000009"));
        ASSERT(op_ev_is(2, 1, "reason=fork_suspected distinct_heights=3"));
        ASSERT(op_ev_is(0, 0, ""));
    } TEST_END
    return failures;
}

static int t_halt_window_and_events_2(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: HALT with a wide window and a clock near zero")
    {
        op_arm_cfg(86400, 3, 1);
        op_set_now(100);                        /* cutoff negative */
        oracle_policy_record_disagreement(7100003, "a", "b");
        oracle_policy_record_disagreement(7100001, "a", "b");
        oracle_policy_record_disagreement(7100002, "a", "b");
        ASSERT(oracle_policy_get_state() == OP_HALTED);
        ASSERT(op_ev_is(1, 1, "distinct_heights=3 within_secs=86400 "
                              "first_h=7100001 last_h=7100003"));
        /* Already HALTED: a fourth distinct height does not re-fire. */
        oracle_policy_record_disagreement(7100004, "a", "b");
        ASSERT_EQ(op_dump_int("total_halts"), (int64_t)1);
        ASSERT(op_ev_is(1, 1, "distinct_heights=3 within_secs=86400 "
                              "first_h=7100001 last_h=7100003"));
        ASSERT(op_ev_is(2, 1, "reason=fork_suspected distinct_heights=3"));
    } TEST_END
    return failures;
}

static int t_halt_window_and_events_3(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: a record one second past the window does not count")
    {
        op_arm_cfg(10, 2, 1);
        op_set_now(1000);
        oracle_policy_record_disagreement(7200001, "a", "b");
        op_set_now(1011);                       /* cutoff 1001: first record aged */
        oracle_policy_record_disagreement(7200002, "a", "b");
        ASSERT(oracle_policy_get_state() == OP_NORMAL);
        ASSERT_EQ(op_dump_int("distinct_heights_in_window"), (int64_t)1);
    } TEST_END
    return failures;
}

static int t_panic_events_and_upgrade(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: PANIC emits the anchor_panic and chain_halted events")
    {
        op_arm_cfg(86400, 3, 100);
        op_set_now(1700000000);
        oracle_policy_record_disagreement(50, "ours", "theirs");
        ASSERT(op_ev_is(0, 1, "h=50 our=ours their=theirs"));
        ASSERT(op_ev_is(2, 1, "reason=anchor_panic distinct_heights=1"));
        ASSERT(op_ev_is(1, 0, ""));
        oracle_policy_record_disagreement(51, "ours", "theirs");   /* stays PANIC */
        ASSERT(op_ev_is(0, 1, "h=50 our=ours their=theirs"));
        ASSERT_EQ(op_dump_int("total_panics"), (int64_t)1);
        oracle_policy_clear();
        oracle_policy_record_disagreement(60, NULL, NULL);
        ASSERT(op_ev_is(0, 2, "h=60 our= their="));
        ASSERT_EQ(op_dump_int("total_panics"), (int64_t)2);
    } TEST_END
    return failures;
}

static int t_panic_events_and_upgrade_2(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: HALTED escalates to PANIC on a prefix disagreement")
    {
        op_arm_cfg(86400, 3, 100);
        op_set_now(1700000000);
        oracle_policy_record_disagreement(8000001, "a", "b");
        oracle_policy_record_disagreement(8000002, "a", "b");
        oracle_policy_record_disagreement(8000003, "a", "b");
        ASSERT(oracle_policy_get_state() == OP_HALTED);
        oracle_policy_record_disagreement(7, "a", "b");
        ASSERT(oracle_policy_get_state() == OP_PANIC);
        ASSERT_EQ(op_dump_int("total_halts"), (int64_t)1);
        ASSERT_EQ(op_dump_int("total_panics"), (int64_t)1);
    } TEST_END
    return failures;
}

static int t_last_fields_and_reset(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: dump reports the last disagreement height and time")
    {
        op_arm_cfg(86400, 3, 1);
        op_set_now(1234567);
        oracle_policy_record_disagreement(4242, "a", "b");
        ASSERT_EQ(op_dump_int("last_h"), (int64_t)4242);
        ASSERT_EQ(op_dump_int("last_unix"), (int64_t)1234567);
        ASSERT_EQ(op_dump_int("total_disagree"), (int64_t)1);
    } TEST_END
    return failures;
}

static int t_last_fields_and_reset_2(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: reset_for_test zeroes state, counters and last fields")
    {
        op_arm_cfg(86400, 3, 100);
        op_set_now(1700000000);
        for (int i = 0; i < 3; i++)
            oracle_policy_record_disagreement(8100001 + i, "a", "b");
        oracle_policy_clear();
        oracle_policy_record_disagreement(5, "a", "b");     /* PANIC */
        ASSERT(oracle_policy_get_state() == OP_PANIC);
        oracle_policy_reset_for_test();
        ASSERT(oracle_policy_get_state() == OP_NORMAL);
        ASSERT_EQ(op_dump_int("state_code"), (int64_t)OP_NORMAL);
        ASSERT_EQ(op_dump_int("total_disagree"), (int64_t)0);
        ASSERT_EQ(op_dump_int("total_halts"), (int64_t)0);
        ASSERT_EQ(op_dump_int("total_panics"), (int64_t)0);
        ASSERT_EQ(op_dump_int("last_h"), (int64_t)0);
        ASSERT_EQ(op_dump_int("last_unix"), (int64_t)0);
        ASSERT_EQ(op_dump_int("ring_count"), (int64_t)0);
    } TEST_END
    return failures;
}

static int t_last_fields_and_reset_3(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: clear() restarts the ring at slot 0")
    {
        op_arm_cfg(86400, 5, 1);
        op_set_now(1700000000);
        oracle_policy_record_disagreement(8200001, "a", "b");
        oracle_policy_clear();
        oracle_policy_record_disagreement(8200002, "a", "b");
        oracle_policy_record_disagreement(8200002, "a", "b");
        ASSERT_EQ(op_dump_int("ring_count"), (int64_t)2);
        ASSERT_EQ(op_dump_int("distinct_heights_in_window"), (int64_t)1);
    } TEST_END
    return failures;
}

static int t_names_dump_and_init_once(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: state names, unknown state and NULL dump target")
    {
        ASSERT_STR_EQ(oracle_policy_state_name(OP_NORMAL), "normal");
        ASSERT_STR_EQ(oracle_policy_state_name(OP_HALTED), "halted");
        ASSERT_STR_EQ(oracle_policy_state_name(OP_PANIC), "panic");
        ASSERT_STR_EQ(oracle_policy_state_name((enum oracle_policy_state)99),
                      "unknown");
        ASSERT(oracle_policy_dump_state_json(NULL, "k") == false);
        struct json_value v;
        json_init(&v);
        bool ok = oracle_policy_dump_state_json(&v, "k");
        json_free(&v);
        ASSERT(ok == true);
    } TEST_END
    return failures;
}

static int t_names_dump_and_init_once_2(void)
{
    int failures = 0;
    TEST_CASE("oracle_policy: a second init is ignored and leaves the lock usable")
    {
        op_arm_cfg(86400, 3, 1);
        struct oracle_policy_config other = {
            .window_secs = 5, .halt_distinct_heights = 1,
            .evidence_prefix_end_height = 99999999,
        };
        oracle_policy_init(&other);
        ASSERT_EQ(op_dump_int("window_secs"), (int64_t)86400);
        ASSERT_EQ(op_dump_int("halt_threshold"), (int64_t)3);
        ASSERT_EQ(op_dump_int("evidence_prefix_end_height"), (int64_t)1);
        op_set_now(1700000000);
        oracle_policy_record_disagreement(8300001, "a", "b");
        ASSERT(oracle_policy_get_state() == OP_NORMAL);
    } TEST_END
    return failures;
}

static int oracle_policy_sweep_tests(void)
{
    int failures = 0;
    failures += t_default_config();
    failures += t_default_config_2();
    failures += t_default_config_3();
    failures += t_default_window_boundary();
    failures += t_default_window_boundary_2();
    failures += t_default_prefix_boundary();
    failures += t_default_prefix_boundary_2();
    failures += t_ring_capacity();
    failures += t_ring_capacity_2();
    failures += t_halt_window_and_events();
    failures += t_halt_window_and_events_2();
    failures += t_halt_window_and_events_3();
    failures += t_panic_events_and_upgrade();
    failures += t_panic_events_and_upgrade_2();
    failures += t_last_fields_and_reset();
    failures += t_last_fields_and_reset_2();
    failures += t_last_fields_and_reset_3();
    failures += t_names_dump_and_init_once();
    failures += t_names_dump_and_init_once_2();
    return failures;
}

/* Run the sweep cases with the fake clock and the event observers armed. */
static int t_sweep_with_fixtures(void)
{
    static const clock_iface_t fake = {
        .now_monotonic_ns = op_fake_clock,
        .now_wall_ms = op_fake_clock,
    };
    int failures = 0;
    event_log_init();
    bool obs = event_observe(EV_ANCHOR_PANIC, op_observer, NULL) &&
               event_observe(EV_FORK_SUSPECTED, op_observer, NULL) &&
               event_observe(EV_CHAIN_HALTED, op_observer, NULL);
    TEST_CASE("oracle_policy: sweep event observers installed")
    {
        ASSERT(obs);
    } TEST_END
    if (obs) {
        const clock_iface_t *saved = clock_default();
        op_set_now(1700000000);
        clock_set_default(&fake);
        failures += oracle_policy_sweep_tests();
        clock_set_default(saved);
    }
    event_clear_observers(EV_ANCHOR_PANIC);
    event_clear_observers(EV_FORK_SUSPECTED);
    event_clear_observers(EV_CHAIN_HALTED);
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
    failures += t_sweep_with_fixtures();

    /* Leave the singleton clean and allowed for later groups. */
    oracle_policy_reset_for_test();
    return failures;
}
