/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for util/long_op.h (WS-2a).
 *
 * Cover:
 *   - begin + tick + end happy path (long_op_is_active toggles)
 *   - 100 tight-loop ticks emit at most one EV_LONG_OP_TICK (rate-limit)
 *   - nested / parallel begin: two scopes tracked simultaneously
 *   - long_op_is_active returns false after end()
 *   - dump_state_json shape
 */

#include "test/test_core.h"
#include "util/long_op.h"
#include "event/event.h"
#include "json/json.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static _Atomic int g_ev_begin;
static _Atomic int g_ev_tick;
static _Atomic int g_ev_end;

static void lo_observer(enum event_type type, uint32_t peer_id,
                        const void *payload, uint32_t payload_len,
                        void *ctx)
{
    (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    if (type == EV_LONG_OP_BEGIN) atomic_fetch_add(&g_ev_begin, 1);
    if (type == EV_LONG_OP_TICK)  atomic_fetch_add(&g_ev_tick,  1);
    if (type == EV_LONG_OP_END)   atomic_fetch_add(&g_ev_end,   1);
}

static void lo_install_observer(void)
{
    event_clear_observers(EV_LONG_OP_BEGIN);
    event_clear_observers(EV_LONG_OP_TICK);
    event_clear_observers(EV_LONG_OP_END);
    atomic_store(&g_ev_begin, 0);
    atomic_store(&g_ev_tick,  0);
    atomic_store(&g_ev_end,   0);
    event_observe(EV_LONG_OP_BEGIN, lo_observer, NULL);
    event_observe(EV_LONG_OP_TICK,  lo_observer, NULL);
    event_observe(EV_LONG_OP_END,   lo_observer, NULL);
}

#define LO_CHECK(name, expr) do { \
    printf("%s... ", (name));     \
    if ((expr)) printf("OK\n");   \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static int test_long_op_happy_path(void)
{
    int failures = 0;
    lo_install_observer();

    struct long_op_scope op;
    int64_t age = 0;

    /* Initially not active. */
    LO_CHECK("inactive before begin",
             !long_op_is_active(&age) && age == 0);

    long_op_begin(&op, "test.happy_path");
    LO_CHECK("EV_LONG_OP_BEGIN fired once",
             atomic_load(&g_ev_begin) == 1);
    LO_CHECK("active after begin (no tick yet)",
             long_op_is_active(&age));
    LO_CHECK("recent label set",
             long_op_recent_label() != NULL &&
             strcmp(long_op_recent_label(), "test.happy_path") == 0);

    long_op_tick(&op);
    LO_CHECK("active after tick",
             long_op_is_active(&age));

    long_op_end(&op);
    LO_CHECK("EV_LONG_OP_END fired once",
             atomic_load(&g_ev_end) == 1);
    LO_CHECK("inactive after end",
             !long_op_is_active(&age));
    LO_CHECK("recent label NULL after end",
             long_op_recent_label() == NULL);

    return failures;
}

static int test_long_op_tick_rate_limit(void)
{
    int failures = 0;
    lo_install_observer();

    struct long_op_scope op;
    long_op_begin(&op, "test.rate_limit");

    /* 100 ticks in tight loop. Each updates last_tick_us but only the
     * first one (which has prev = begin_us == now, so delta=0) sees
     * delta < 30s — none should emit beyond what the first begin
     * implies. With the implementation, the very first tick sees
     * prev=begin_us so delta is ~0us, which is < 30s, so NO emit.
     * Subsequent ticks see delta < 30s also. Expect 0 emits. */
    for (int i = 0; i < 100; i++) {
        long_op_tick(&op);
    }

    int ticks_emitted = atomic_load(&g_ev_tick);
    LO_CHECK("100 tight ticks emit <=1 EV_LONG_OP_TICK",
             ticks_emitted <= 1);

    long_op_end(&op);
    return failures;
}

static int test_long_op_parallel_scopes(void)
{
    int failures = 0;
    lo_install_observer();

    struct long_op_scope a, b;
    int64_t age = 0;

    long_op_begin(&a, "test.parallel.A");
    long_op_begin(&b, "test.parallel.B");
    LO_CHECK("two BEGIN events",
             atomic_load(&g_ev_begin) == 2);
    LO_CHECK("active with two scopes",
             long_op_is_active(&age));

    /* End A first; B should still keep things active. */
    long_op_end(&a);
    LO_CHECK("still active after A ends",
             long_op_is_active(&age));
    LO_CHECK("recent label is B",
             long_op_recent_label() != NULL &&
             strcmp(long_op_recent_label(), "test.parallel.B") == 0);

    long_op_end(&b);
    LO_CHECK("inactive after both end",
             !long_op_is_active(&age));
    LO_CHECK("two END events",
             atomic_load(&g_ev_end) == 2);

    return failures;
}

static int test_long_op_dump_state_json(void)
{
    int failures = 0;
    lo_install_observer();

    struct json_value dump = {0};
    long_op_dump_state_json(&dump, NULL);
    LO_CHECK("dump returns object with active_count=0 when empty",
             json_get_int(json_get(&dump, "active_count")) == 0);
    json_free(&dump);

    struct long_op_scope op;
    long_op_begin(&op, "test.dump_scope");
    long_op_tick(&op);

    struct json_value dump2 = {0};
    long_op_dump_state_json(&dump2, NULL);
    LO_CHECK("dump shows active_count=1",
             json_get_int(json_get(&dump2, "active_count")) == 1);
    const char *recent = json_get_str(json_get(&dump2, "recent_label"));
    LO_CHECK("dump shows recent_label",
             recent != NULL && strcmp(recent, "test.dump_scope") == 0);
    const struct json_value *scopes = json_get(&dump2, "scopes");
    LO_CHECK("dump.scopes is an array of size 1",
             scopes && json_size(scopes) == 1);
    json_free(&dump2);

    long_op_end(&op);
    return failures;
}

int test_long_op(void)
{
    int failures = 0;
    printf("[test_long_op] starting\n");
    /* Ensure the event log is alive — test_parallel runs each test
     * group in a child process with no init, so observers register
     * but event_emit() short-circuits on g_log.initialized==false
     * until we explicitly init. The sequential runner calls this
     * once early; we replicate that here so we work either way. */
    event_log_init();
    failures += test_long_op_happy_path();
    failures += test_long_op_tick_rate_limit();
    failures += test_long_op_parallel_scopes();
    failures += test_long_op_dump_state_json();
    printf("[test_long_op] %d failure(s)\n", failures);

    /* Cleanup observers so other tests aren't polluted. */
    event_clear_observers(EV_LONG_OP_BEGIN);
    event_clear_observers(EV_LONG_OP_TICK);
    event_clear_observers(EV_LONG_OP_END);

    return failures;
}
