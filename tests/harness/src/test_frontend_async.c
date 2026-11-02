/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_frontend_async — the frontend/Tor start runs on a tracked thread, off
 * the boot path.
 *
 * The start body is replaced through a ZCL_TESTING seam and held on a latch.
 * While held: boot_frontend_async_start has RETURNED (boot proceeds), the RPC
 * warm-up flag is still set so a dependent RPC answers -28, and the body has
 * not run. After release the body runs (it clears warm-up like rpc_http does)
 * and the RPC runs. A node stopped while the start is held joins the thread.
 * (A failing body keeps DEGRADED_SERVING; that path is unchanged code and is
 * not driven here because service_state has no test reset.) */

#include "test/test_core.h"
#include "config/boot_internal.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "platform/clock.h"
#include "util/thread_registry.h"
#include <stdatomic.h>
#include <stdio.h>

static atomic_int fa_ran;
static struct boot_svc_ctx fa_svc; /* zeroed: kernel never started */

static bool fa_ok_body(struct boot_svc_ctx *svc)
{
    (void)svc;
    atomic_store(&fa_ran, 1);
    set_rpc_warmup_finished(); /* what boot_rpc_http_start does after bind */
    return true;
}

static bool fa_actor(const struct json_value *params, bool help,
                     struct json_value *result)
{
    (void)params;
    (void)help;
    json_init(result);
    json_set_str(result, "ran");
    return true;
}

static int fa_check(bool ok, const char *what)
{
    if (ok)
        return 0;
    printf("frontend_async: FAIL (%s)\n", what);
    return 1;
}

static bool fa_run(const struct rpc_table *t, int64_t *code)
{
    struct json_value params, result;
    json_init(&params);
    json_set_array(&params);
    json_init(&result);
    bool ok = rpc_table_execute(t, "fa_dependent", &params, &result);
    const struct json_value *c = json_get(&result, "code");
    *code = (!ok && c) ? json_get_int(c) : 0;
    json_free(&params);
    json_free(&result);
    return ok;
}

static bool fa_wait_done(void)
{
    for (int i = 0; i < 10000; i++) {
        if (boot_frontend_async_done())
            return true;
        platform_sleep_ms(2); /* real-clock: waits on a real OS thread finishing */
    }
    return false;
}

static int fa_held_then_released(const struct rpc_table *t)
{
    int f = 0;
    int64_t code;
    set_rpc_warmup_started("frontend starting");
    atomic_store(&fa_ran, 0);
    boot_frontend_async_test_body(fa_ok_body);
    boot_frontend_async_test_hold(true);
    boot_frontend_async_start(&fa_svc);
    f += fa_check(!boot_frontend_async_done(), "start returned before body ran");
    f += fa_check(atomic_load(&fa_ran) == 0, "body held");
    f += fa_check(!fa_run(t, &code) && code == RPC_IN_WARMUP,
                  "dependent RPC answers -28 before ready");
    boot_frontend_async_test_hold(false);
    f += fa_check(fa_wait_done(), "thread completes after release");
    f += fa_check(atomic_load(&fa_ran) == 1, "body ran");
    f += fa_check(fa_run(t, &code), "dependent RPC runs after ready");
    boot_frontend_async_stop();
    return f;
}

static int fa_stop_while_held(void)
{
    int f = 0;
    set_rpc_warmup_started("frontend starting");
    atomic_store(&fa_ran, 0);
    boot_frontend_async_test_hold(true);
    boot_frontend_async_start(&fa_svc);
    boot_frontend_async_stop(); /* must release the latch and join */
    f += fa_check(boot_frontend_async_done(), "stop joined a finished thread");
    boot_frontend_async_test_hold(false);
    return f;
}


/* The READY gate: with the body held, the wait reports not done and the gate
 * built on it (what boot.c calls before BOOT_STAGE_READY and before the A/B
 * promote) cannot pass; after release both pass. */
static int fa_ready_gate(void)
{
    int f = 0;
    set_rpc_warmup_started("frontend starting");
    atomic_store(&fa_ran, 0);
    boot_frontend_async_test_body(fa_ok_body);
    boot_frontend_async_test_hold(true);
    boot_frontend_async_start(&fa_svc);
    f += fa_check(!boot_frontend_async_wait_done(60), "wait not done while held");
    f += fa_check(atomic_load(&fa_ran) == 0, "body still held after wait");
    boot_frontend_async_test_hold(false);
    f += fa_check(boot_frontend_async_wait_done(20000), "wait done after release");
    f += fa_check(atomic_load(&fa_ran) == 1, "body ran before wait returned");
    f += fa_check(boot_frontend_async_gate_ready("READY"), "gate passes after body");
    boot_frontend_async_stop();
    return f;
}

static atomic_int fa_tail_hold;
static atomic_int fa_promoted;

/* rpc_http bound, then the slow services behind it (explorer, package store)
 * are still starting. */
static bool fa_split_body(struct boot_svc_ctx *svc)
{
    (void)svc;
    set_rpc_warmup_finished();
    boot_frontend_async_note_rpc_bound();
    atomic_store(&fa_ran, 1);
    while (atomic_load(&fa_tail_hold))
        platform_sleep_ms(2);
    return true;
}

static void fa_promote(void)
{
    atomic_fetch_add(&fa_promoted, 1);
}

/* Serving (READY) waits for rpc_http's bind and NOT for the services started
 * behind it on the frontend thread; the A/B promote still waits for all of
 * them, and runs on the frontend thread, not the boot thread. */
static int fa_serving_before_tail(void)
{
    int f = 0;
    set_rpc_warmup_started("frontend starting");
    atomic_store(&fa_ran, 0);
    atomic_store(&fa_promoted, 0);
    atomic_store(&fa_tail_hold, 1);
    boot_frontend_async_test_body(fa_split_body);
    boot_frontend_async_start(&fa_svc);
    f += fa_check(boot_frontend_async_wait_serving(20000),
                  "serving once rpc bound, tail still starting");
    f += fa_check(atomic_load(&fa_ran) == 1, "rpc bound ran");
    f += fa_check(!boot_frontend_async_done(), "tail still running at serving");
    if (f == 0)
        f += fa_check(boot_frontend_async_gate_ready("READY"),
                      "READY gate passes before the tail finishes");
    boot_frontend_async_after_done(fa_promote);
    f += fa_check(atomic_load(&fa_promoted) == 0,
                  "promote waits for the whole frontend start");
    atomic_store(&fa_tail_hold, 0);
    f += fa_check(boot_frontend_async_wait_done(20000), "tail finishes");
    for (int i = 0; i < 1000 && atomic_load(&fa_promoted) == 0; i++)
        platform_sleep_ms(5);
    f += fa_check(atomic_load(&fa_promoted) == 1,
                  "promote ran once the frontend start finished");
    boot_frontend_async_after_done(fa_promote); /* already done: runs now */
    f += fa_check(atomic_load(&fa_promoted) == 2, "late promote runs inline");
    boot_frontend_async_stop();
    atomic_store(&fa_tail_hold, 0);
    return f;
}

/* A start that never binds rpc_http must not report serving: the gate holds
 * until the body is done (degraded). */
static int fa_unbound_waits_for_done(void)
{
    int f = 0;
    set_rpc_warmup_started("frontend starting");
    atomic_store(&fa_ran, 0);
    boot_frontend_async_test_body(fa_ok_body);
    boot_frontend_async_test_hold(true);
    boot_frontend_async_start(&fa_svc);
    f += fa_check(!boot_frontend_async_wait_serving(60),
                  "not serving while nothing is bound");
    boot_frontend_async_test_hold(false);
    f += fa_check(boot_frontend_async_wait_serving(20000),
                  "serving once the body finished");
    boot_frontend_async_stop();
    return f;
}

/* A shutdown request while the body is held ends the wait promptly with "not
 * done" (so READY and the promote are skipped), and touches nothing the thread
 * uses: the thread is still running, and stop still joins it. */
static int fa_shutdown_while_held(void)
{
    int f = 0;
    set_rpc_warmup_started("frontend starting");
    atomic_store(&fa_ran, 0);
    boot_frontend_async_test_hold(true);
    boot_frontend_async_start(&fa_svc);
    thread_registry_request_shutdown();
    int64_t t0 = clock_now_monotonic_ns();
    f += fa_check(!boot_frontend_async_wait_done(60000), "wait ends on shutdown");
    f += fa_check(!boot_frontend_async_gate_ready("READY"),
                  "gate refuses READY on shutdown");
    f += fa_check(clock_now_monotonic_ns() - t0 < 5000000000LL,
                  "wait returned promptly on shutdown");
    f += fa_check(!boot_frontend_async_done(), "thread still running, untouched");
    boot_frontend_async_stop(); /* joins the held thread */
    f += fa_check(boot_frontend_async_done(), "stop joined after shutdown wait");
    boot_frontend_async_test_hold(false);
    thread_registry_reset_for_test();
    return f;
}

int test_frontend_async(void)
{
    int failures = 0;
    struct rpc_table t;
    rpc_table_init(&t);
    const struct rpc_command cmd = { "control", "fa_dependent", fa_actor, true };
    failures += fa_check(rpc_table_append(&t, &cmd), "append");
    failures += fa_held_then_released(&t);
    failures += fa_stop_while_held();
    failures += fa_ready_gate();
    failures += fa_serving_before_tail();
    failures += fa_unbound_waits_for_done();
    failures += fa_shutdown_while_held();


    boot_frontend_async_test_body(NULL);
    set_rpc_warmup_finished();
    printf("frontend_async: %s\n", failures ? "FAIL" : "PASS");
    return failures;
}
