/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Long-poll "waitfor*" RPCs: waitforheight, waitforhalt, waitforblocker.
 *
 * These are ADDITIVE convenience methods that block the calling RPC worker
 * until a named condition becomes true, the per-call timeout elapses, or the
 * node is shutting down. They let an operator / orchestration script poll a
 * single state transition without a busy client-side spin loop.
 *
 * Design invariants (load-bearing):
 *   - SHUTDOWN-AWARE: every loop iteration checks
 *     thread_registry_shutdown_requested() and returns promptly when it flips
 *     true. A wait must NEVER block node exit.
 *   - NO BUSY-LOOP: ~200ms platform_sleep_ms between checks; never tight-spin.
 *   - BOUNDED: timeout_ms is clamped to [0, WAIT_RPC_MAX_MS]. On timeout the
 *     handler returns the CURRENT state with the target flag false rather than
 *     an error — the caller always gets a result object.
 *
 * NB the global per-request watchdog (ZCL_RPC_TIMEOUT_MS, default 10000ms,
 * engine/modules/rpc/include/rpc/rpc_timeout.h) closes the client socket once elapsed
 * time exceeds it. So WAIT_RPC_MAX_MS is hard-capped well below that. Raising
 * the wait past the cap requires also raising ZCL_RPC_TIMEOUT_MS, else the
 * watchdog kills the connection mid-poll and the caller sees a broken pipe
 * instead of the state result. */

#include "platform/time_compat.h"
#include "controllers/blockchain_controller.h"
#include "blockchain_controller_internal.h"
#include "controllers/strong_params.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "util/alerts.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/thread_registry.h"
#include "validation/main_state.h"

#include <stdbool.h>
#include <stdint.h>

/* Default wait when timeout_ms is omitted or <= 0. */
#define WAIT_RPC_DEFAULT_MS  30000
/* Hard cap. Must stay well under ZCL_RPC_TIMEOUT_MS (default 10000ms) so the
 * per-request watchdog does not tear down the connection mid-poll. */
#define WAIT_RPC_MAX_MS       9000
/* Poll cadence between condition checks. */
#define WAIT_RPC_POLL_MS       200

/* Clamp a caller-supplied timeout_ms into [0, WAIT_RPC_MAX_MS]. The RPC
 * handlers pass WAIT_RPC_DEFAULT_MS as the rpc_permit_int default, so an
 * OMITTED timeout_ms arrives here already as the default. An EXPLICIT 0 (or
 * negative) is honored as "no wait" — check the condition once and return the
 * current state immediately. This makes a 0-timeout call a cheap state probe
 * and keeps the native self-test fast. */
static int wait_clamp_timeout_ms(int64_t requested)
{
    int64_t ms = requested < 0 ? 0 : requested;
    if (ms > WAIT_RPC_MAX_MS)
        ms = WAIT_RPC_MAX_MS;
    return (int)ms;
}

/* Read the height this wait should compare against, fresh each loop iteration.
 *
 * Default (provable=false): active_chain_height — the INTERNAL sync-window /
 * lookahead tip, which can sit ABOVE H* by the pipeline depth. This is the
 * historical behavior every existing caller already depends on.
 *
 * provable=true: reducer_frontier_provable_tip_cached() — H*, the exact same
 * cached atomic getblockcount and the P2P start_height serve externally. An
 * operator long-polling "synced to height N" with provable=true therefore only
 * sees a height the node will actually serve to getblockcount, never a window
 * tip it would refuse to name. */
static int wait_height_source(const struct blockchain_context *ctx,
                              bool provable)
{
    if (provable)
        return (int)reducer_frontier_provable_tip_cached();
    return active_chain_height(&ctx->main_state->chain_active);
}

/* ── waitforheight ──────────────────────────────────────────────────
 *
 * Block until the chosen tip height >= `height`, then return. On
 * timeout/shutdown returns the current height with reached=false.
 *
 * By DEFAULT it tracks the active-chain window tip (back-compat). Pass
 * provable=true to instead track H* (reducer_frontier_provable_tip_cached) —
 * the provable tip getblockcount / P2P start_height serve externally — so a
 * long-poll observes only a height the node will actually serve. */
bool rpc_waitforheight(const struct json_value *params, bool help,
                       struct json_value *result)
{
    struct blockchain_context *ctx = blockchain_ctx();
    RPC_HELP(help, result,
        "waitforheight height ( timeout_ms provable )\n"
        "\nBlock until the chain height reaches `height`, the timeout\n"
        "(default 30000ms, capped at 9000ms) elapses, or the node shuts\n"
        "down. Always returns a result object.\n"
        "\nBy default tracks the active-chain (sync-window) tip. Set\n"
        "provable=true to track H* — the provable tip getblockcount and the\n"
        "P2P start_height serve externally — so the wait only completes at a\n"
        "height the node will actually serve to getblockcount.\n"
        "Result: { target, height, provable, reached, timed_out, shutdown }");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 3);
    int target = (int)rpc_require_int(&p, 0, "height");
    int64_t timeout_ms = rpc_permit_int(&p, 1, "timeout_ms", WAIT_RPC_DEFAULT_MS);
    bool provable = rpc_permit_bool(&p, 2, "provable", false);
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        LOG_FAIL("blockchain", "waitforheight: invalid params");
        return true;
    }
    if (!ctx->main_state) {
        json_set_str(result, "Not initialized");
        LOG_FAIL("blockchain", "waitforheight: main_state not initialized");
        return true;
    }

    int cap_ms = wait_clamp_timeout_ms(timeout_ms);
    int64_t start = platform_time_monotonic_ms();
    bool shutdown = false;
    bool timed_out = false;
    int height = wait_height_source(ctx, provable);

    for (;;) {
        height = wait_height_source(ctx, provable);
        if (height >= target)
            break;
        if (thread_registry_shutdown_requested()) {
            shutdown = true;
            break;
        }
        if (platform_time_monotonic_ms() - start >= cap_ms) {
            timed_out = true;
            break;
        }
        platform_sleep_ms(WAIT_RPC_POLL_MS);
    }

    json_set_object(result);
    json_push_kv_int(result, "target", target);
    json_push_kv_int(result, "height", height);
    json_push_kv_bool(result, "provable", provable);
    json_push_kv_bool(result, "reached", height >= target);
    json_push_kv_bool(result, "timed_out", timed_out);
    json_push_kv_bool(result, "shutdown", shutdown);
    return true;
}

/* ── waitforhalt ────────────────────────────────────────────────────
 *
 * Block until the operator-needed / halt latch is set
 * (alerts_operator_needed), then return. On timeout/shutdown returns
 * operator_needed=false. "A halt can never be silent" — this surfaces the
 * latch the moment it fires. */
bool rpc_waitforhalt(const struct json_value *params, bool help,
                     struct json_value *result)
{
    RPC_HELP(help, result,
        "waitforhalt ( timeout_ms )\n"
        "\nBlock until an operator-needed / halt latch is set, the timeout\n"
        "(default 30000ms, capped at 9000ms) elapses, or the node shuts\n"
        "down. Always returns a result object.\n"
        "Result: { operator_needed, detail, since_unix, timed_out, shutdown }");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 1);
    int64_t timeout_ms = rpc_permit_int(&p, 0, "timeout_ms", WAIT_RPC_DEFAULT_MS);
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        LOG_FAIL("blockchain", "waitforhalt: invalid params");
        return true;
    }

    int cap_ms = wait_clamp_timeout_ms(timeout_ms);
    int64_t start = platform_time_monotonic_ms();
    bool shutdown = false;
    bool timed_out = false;
    char detail[256];
    int64_t since_unix = 0;
    bool halted = false;

    for (;;) {
        detail[0] = '\0';
        since_unix = 0;
        halted = alerts_operator_needed(detail, sizeof(detail), &since_unix);
        if (halted)
            break;
        if (thread_registry_shutdown_requested()) {
            shutdown = true;
            break;
        }
        if (platform_time_monotonic_ms() - start >= cap_ms) {
            timed_out = true;
            break;
        }
        platform_sleep_ms(WAIT_RPC_POLL_MS);
    }

    json_set_object(result);
    json_push_kv_bool(result, "operator_needed", halted);
    json_push_kv_str(result, "detail", detail);
    json_push_kv_int(result, "since_unix", since_unix);
    json_push_kv_bool(result, "timed_out", timed_out);
    json_push_kv_bool(result, "shutdown", shutdown);
    return true;
}

/* Append the current blocker snapshot array to `result` under "blockers".
 * Returns the active count. Read-only — copies under the registry lock. */
static int wait_push_blocker_snapshot(struct json_value *result)
{
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    if (n < 0)
        n = 0;

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (int i = 0; i < n; i++) {
        struct json_value obj;
        json_init(&obj);
        json_set_object(&obj);
        json_push_kv_str(&obj, "id", snaps[i].id);
        json_push_kv_str(&obj, "owner_subsystem", snaps[i].owner_subsystem);
        json_push_kv_int(&obj, "class", snaps[i].class);
        json_push_kv_str(&obj, "class_name",
                         blocker_class_name((enum blocker_class)snaps[i].class));
        json_push_kv_int(&obj, "age_us", snaps[i].age_us);
        json_push_kv_int(&obj, "deadline_remaining_us",
                         snaps[i].deadline_remaining_us);
        json_push_kv_int(&obj, "retry_count", snaps[i].retry_count);
        json_push_kv_int(&obj, "retry_budget", snaps[i].retry_budget);
        json_push_kv_int(&obj, "fire_count", (int64_t)snaps[i].fire_count);
        json_push_kv_str(&obj, "reason", snaps[i].reason);
        json_push_back(&arr, &obj);
        json_free(&obj);
    }
    json_push_kv(result, "blockers", &arr);
    json_free(&arr);
    return n;
}

/* ── waitforblocker ─────────────────────────────────────────────────
 *
 * Block until at least one typed blocker is present
 * (blocker_count_active() > 0), then return a snapshot of all active
 * blockers. On timeout/shutdown returns the (possibly empty) current set. */
bool rpc_waitforblocker(const struct json_value *params, bool help,
                        struct json_value *result)
{
    RPC_HELP(help, result,
        "waitforblocker ( timeout_ms )\n"
        "\nBlock until at least one typed blocker is present, the timeout\n"
        "(default 30000ms, capped at 9000ms) elapses, or the node shuts\n"
        "down. Always returns a result object.\n"
        "Result: { active, blockers:[...], timed_out, shutdown }");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 1);
    int64_t timeout_ms = rpc_permit_int(&p, 0, "timeout_ms", WAIT_RPC_DEFAULT_MS);
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        LOG_FAIL("blockchain", "waitforblocker: invalid params");
        return true;
    }

    int cap_ms = wait_clamp_timeout_ms(timeout_ms);
    int64_t start = platform_time_monotonic_ms();
    bool shutdown = false;
    bool timed_out = false;

    for (;;) {
        if (blocker_count_active() > 0)
            break;
        if (thread_registry_shutdown_requested()) {
            shutdown = true;
            break;
        }
        if (platform_time_monotonic_ms() - start >= cap_ms) {
            timed_out = true;
            break;
        }
        platform_sleep_ms(WAIT_RPC_POLL_MS);
    }

    json_set_object(result);
    int active = wait_push_blocker_snapshot(result);
    json_push_kv_int(result, "active", active);
    json_push_kv_bool(result, "timed_out", timed_out);
    json_push_kv_bool(result, "shutdown", shutdown);
    return true;
}
