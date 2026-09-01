/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression tests for rpc_waitforheight's opt-in `provable` parameter.
 *
 * The default (provable=false) compares the target against
 * active_chain_height — the internal sync-window tip. provable=true compares
 * against reducer_frontier_provable_tip_cached() (H*), the same cached atomic
 * getblockcount and the P2P start_height serve externally. These two sources
 * legitimately differ (H* can sit BELOW the window tip mid-fold), so a caller
 * long-polling "synced to N" with provable=true sees only a height the node
 * will actually serve to getblockcount.
 *
 * Each case calls the handler with timeout_ms=0 (a single condition check, no
 * sleeping) so the assertions are deterministic and fast. With no progress.kv
 * open and no chain authority installed, active_chain_height returns
 * chain_active.height verbatim, which the fixture seeds directly. */

#include "test/test_core.h"

#include "controllers/blockchain_controller.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "storage/progress_store.h"
#include "validation/main_state.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/* Declared in blockchain_controller_internal.h (controller-private); the test
 * exercises the handler entry point directly. */
bool rpc_waitforheight(const struct json_value *params, bool help,
                       struct json_value *result);

#define WP_CHECK(name, expr) do {                                  \
    printf("waitforheight_provable: %s... ", (name));              \
    if (expr) { printf("OK\n"); }                                  \
    else { printf("FAIL\n"); failures++; }                         \
} while (0)

/* Build the params array [height, timeout_ms, provable]. timeout_ms=0 makes
 * the wait a one-shot probe (check the condition once, return immediately). */
static void make_params(struct json_value *arr, int64_t height,
                        int64_t timeout_ms, bool provable)
{
    json_set_array(arr);
    struct json_value v;

    json_init(&v); json_set_int(&v, height);     json_push_back(arr, &v); json_free(&v);
    json_init(&v); json_set_int(&v, timeout_ms); json_push_back(arr, &v); json_free(&v);
    json_init(&v); json_set_bool(&v, provable);  json_push_back(arr, &v); json_free(&v);
}

/* Read an int field out of a result object (0 if absent). */
static int64_t res_int(const struct json_value *res, const char *key)
{
    const struct json_value *v = json_get(res, key);
    return v ? json_get_int(v) : 0;
}

/* Read a bool field out of a result object (false if absent). */
static bool res_bool(const struct json_value *res, const char *key)
{
    const struct json_value *v = json_get(res, key);
    return v ? json_get_bool(v) : false;
}

/* Invoke the handler once with timeout 0; caller owns `res`. */
static void run_once(int64_t target, bool provable, struct json_value *res)
{
    struct json_value params;
    json_init(&params);
    make_params(&params, target, 0, provable);
    json_set_object(res);
    rpc_waitforheight(&params, false, res);
    json_free(&params);
}

int test_waitforheight_provable(void);
int test_waitforheight_provable(void)
{
    printf("\n=== waitforheight provable param ===\n");
    int failures = 0;

    test_reset_shared_globals();
    progress_store_close();

    struct main_state ms;
    main_state_init(&ms);

    /* Two intentionally DIFFERENT sources. The window tip sits above H*. */
    const int active_h   = REDUCER_FRONTIER_TRUSTED_ANCHOR + 50;  /* sync window */
    const int provable_h = REDUCER_FRONTIER_TRUSTED_ANCHOR + 10;  /* H* (lower) */
    ms.chain_active.height = active_h;
    reducer_frontier_provable_tip_set(provable_h);

    rpc_blockchain_set_state(&ms, NULL, NULL);

    /* Target between H* and the window tip: reached for the window, NOT for H*. */
    const int target = REDUCER_FRONTIER_TRUSTED_ANCHOR + 30;

    /* ── default (provable=false): tracks the window tip ─────────────── */
    {
        struct json_value res; json_init(&res);
        run_once(target, false, &res);
        WP_CHECK("default: provable flag echoed false", res_bool(&res, "provable") == false);
        WP_CHECK("default: height == active window tip",
                 res_int(&res, "height") == active_h);
        WP_CHECK("default: reached (window tip >= target)", res_bool(&res, "reached"));
        WP_CHECK("default: not timed_out (target already met)",
                 res_bool(&res, "timed_out") == false);
        json_free(&res);
    }

    /* ── provable=true: tracks H*, which is below the target ─────────── */
    {
        struct json_value res; json_init(&res);
        run_once(target, true, &res);
        WP_CHECK("provable: provable flag echoed true", res_bool(&res, "provable"));
        WP_CHECK("provable: height == H* (not the window tip)",
                 res_int(&res, "height") == provable_h);
        WP_CHECK("provable: NOT reached (H* < target)",
                 res_bool(&res, "reached") == false);
        WP_CHECK("provable: timed_out (one-shot probe, target unmet)",
                 res_bool(&res, "timed_out"));
        json_free(&res);
    }

    /* ── provable=true once H* advances to/above the target ──────────── */
    {
        reducer_frontier_provable_tip_set(target + 5);
        struct json_value res; json_init(&res);
        run_once(target, true, &res);
        WP_CHECK("provable advanced: height == new H*",
                 res_int(&res, "height") == target + 5);
        WP_CHECK("provable advanced: reached (H* >= target)",
                 res_bool(&res, "reached"));
        WP_CHECK("provable advanced: not timed_out",
                 res_bool(&res, "timed_out") == false);
        json_free(&res);
    }

    /* ── back-compat: omitting provable behaves exactly like false ───── */
    {
        struct json_value params; json_init(&params);
        json_set_array(&params);
        struct json_value v;
        json_init(&v); json_set_int(&v, target); json_push_back(&params, &v); json_free(&v);
        json_init(&v); json_set_int(&v, 0);      json_push_back(&params, &v); json_free(&v);
        struct json_value res; json_init(&res); json_set_object(&res);
        rpc_waitforheight(&params, false, &res);
        WP_CHECK("omitted provable: defaults to false", res_bool(&res, "provable") == false);
        WP_CHECK("omitted provable: tracks window tip",
                 res_int(&res, "height") == active_h);
        json_free(&params);
        json_free(&res);
    }

    /* Restore the cache to the init anchor so later test groups in the same
     * process (sequential runner) see the pristine default. The fork-parallel
     * runner isolates each group in its own process, so this is belt-and-braces. */
    reducer_frontier_provable_tip_set(REDUCER_FRONTIER_TRUSTED_ANCHOR);
    rpc_blockchain_set_state(NULL, NULL, NULL);
    main_state_free(&ms);
    test_reset_shared_globals();

    if (failures == 0)
        printf("waitforheight_provable: all cases passed\n");
    else
        printf("waitforheight_provable: %d failure(s)\n", failures);
    return failures;
}
