/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Bounded/cached front for agent_security_posture_collect(), used
 * exclusively by rpc_agent_summary() (event_agent_summary.c) -- split out
 * to its own file so that one keeps growing its own field list without
 * pushing the other file over its line-count ceiling (see
 * tools/file_size_policy.c).
 *
 * agent_security_posture_collect()'s bootstrap step
 * (chain_evidence_controller_snapshot, see chain_evidence_snapshot.c) issues
 * on the order of a dozen synchronous node_db reads per call -- fine for the
 * health heartbeat's own periodic tick, but rpc_agent_summary ("agent", and
 * its "status"/"summary"/"operatorsummary" aliases) is on the per-request
 * path event_agent_summary.c's header promises to keep cheap. Repeated
 * calls -- an operator polling `z23 status`, or a monitoring script
 * -- would otherwise redo the full read set every time, and each read is
 * subject to the shared node.db connection's multi-second busy_timeout, so
 * a request landing while that connection is merely contended (not flagged
 * as the rarer "long op") had no bound at all. Read-through with a short
 * wall-clock TTL bounds that: most calls in a burst are answered from
 * memory, and the very first call after a quiet stretch pays for one real
 * collection, not every collection.
 *
 * Disabled under ZCL_TESTING: several tests flip
 * agent_security_posture_test_override_review_required() and immediately
 * re-invoke this RPC expecting the override to apply to that very call; a
 * cache would serve the pre-override snapshot and break that contract.
 * Release binaries never define ZCL_TESTING.
 *
 * The cache-miss fallthrough below still calls
 * agent_security_posture_collect(out, NULL) directly, but that call is no
 * longer able to block this TTL's whole duration: it now tries the shared
 * node.db connection's own mutex non-blockingly before reading (see
 * posture_ndb_try_lock() in agent_security_posture.c) and, on contention,
 * returns the last-known-good (or labeled "posture_unavailable_busy")
 * snapshot immediately instead of queuing behind a writer's SQLITE_BUSY
 * retry. This TTL cache remains valuable for coalescing a burst of calls
 * into one real collection; it is no longer the only thing standing between
 * a contended connection and a stalled front door. */

#include "event_agent_summary_internal.h"

#include "controllers/agent_security_posture.h"
#include "controllers/sovereignty_controller.h"
#include "json/json.h"
#include "platform/time_compat.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define AGENT_SUMMARY_POSTURE_CACHE_TTL_MS 1500

#ifndef ZCL_TESTING
static pthread_mutex_t g_agent_posture_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static struct agent_security_posture g_agent_posture_cache;
static int64_t g_agent_posture_cache_captured_ms;
static bool g_agent_posture_cache_valid;
#endif

static bool agent_summary_posture_cache_load(struct agent_security_posture *out)
{
#ifdef ZCL_TESTING
    (void)out;
    return false;
#else
    bool ok;
    pthread_mutex_lock(&g_agent_posture_cache_lock);
    ok = g_agent_posture_cache_valid;
    if (ok) {
        int64_t now = platform_time_monotonic_ms();
        int64_t age = now > g_agent_posture_cache_captured_ms
            ? now - g_agent_posture_cache_captured_ms : 0;
        ok = age < AGENT_SUMMARY_POSTURE_CACHE_TTL_MS;
        if (ok) {
            *out = g_agent_posture_cache;
            out->served_from_cache = true;
            out->cache_age_ms = age;
        }
    }
    pthread_mutex_unlock(&g_agent_posture_cache_lock);
    return ok;
#endif
}

static void agent_summary_posture_cache_store(const struct agent_security_posture *p)
{
#ifndef ZCL_TESTING
    pthread_mutex_lock(&g_agent_posture_cache_lock);
    g_agent_posture_cache = *p;
    g_agent_posture_cache_captured_ms = platform_time_monotonic_ms();
    g_agent_posture_cache_valid = true;
    pthread_mutex_unlock(&g_agent_posture_cache_lock);
#else
    (void)p;
#endif
}

/* A cache hit still carries served_from_cache=true and an honest
 * cache_age_ms, same as agent_security_posture_collect()'s own db-busy
 * snapshot path, so the emitted zcl.security_posture.v1 body never claims a
 * live read it did not do. */
void agent_summary_posture_collect_bounded(struct agent_security_posture *out)
{
    if (agent_summary_posture_cache_load(out))
        return;
    agent_security_posture_collect(out, NULL);
    agent_summary_posture_cache_store(out);
}

/* ── Trust-tier bounded front (see event_agent_summary_internal.h) ──────
 *
 * sovereignty_dump_state_json() is itself non-blocking now (trylock over
 * progress_store_tx_lock, see sovereignty_controller.c) so this wrapper is
 * NOT standing between a caller and a lock the way agent_summary_posture_
 * collect_bounded's cache-miss fallthrough is; it exists purely to coalesce
 * a polling burst (an operator running `z23 status` in a loop, or a
 * monitoring script) into one dumper call plus one small JSON-tree walk
 * instead of repeating both on every request. Same TTL, same shape,
 * disabled under ZCL_TESTING for the identical override-visibility reason
 * documented on the posture cache above. */
#define AGENT_SUMMARY_TRUST_TIER_CACHE_TTL_MS 1500

#ifndef ZCL_TESTING
static pthread_mutex_t g_agent_trust_tier_cache_lock =
    PTHREAD_MUTEX_INITIALIZER;
static struct agent_trust_tier_snapshot g_agent_trust_tier_cache;
static int64_t g_agent_trust_tier_cache_captured_ms;
static bool g_agent_trust_tier_cache_valid;
#endif

static bool agent_summary_trust_tier_cache_load(
    struct agent_trust_tier_snapshot *out)
{
#ifdef ZCL_TESTING
    (void)out;
    return false;
#else
    bool ok;
    pthread_mutex_lock(&g_agent_trust_tier_cache_lock);
    ok = g_agent_trust_tier_cache_valid;
    if (ok) {
        int64_t now = platform_time_monotonic_ms();
        int64_t age = now > g_agent_trust_tier_cache_captured_ms
            ? now - g_agent_trust_tier_cache_captured_ms : 0;
        ok = age < AGENT_SUMMARY_TRUST_TIER_CACHE_TTL_MS;
        if (ok) {
            *out = g_agent_trust_tier_cache;
            out->served_from_cache = true;
            out->cache_age_ms = age;
        }
    }
    pthread_mutex_unlock(&g_agent_trust_tier_cache_lock);
    return ok;
#endif
}

static void agent_summary_trust_tier_cache_store(
    const struct agent_trust_tier_snapshot *p)
{
#ifndef ZCL_TESTING
    pthread_mutex_lock(&g_agent_trust_tier_cache_lock);
    g_agent_trust_tier_cache = *p;
    g_agent_trust_tier_cache_captured_ms = platform_time_monotonic_ms();
    g_agent_trust_tier_cache_valid = true;
    pthread_mutex_unlock(&g_agent_trust_tier_cache_lock);
#else
    (void)p;
#endif
}

static void trust_tier_str(char *dst, size_t cap, const char *src)
{
    if (!dst || cap == 0)
        return;
    snprintf(dst, cap, "%s", src ? src : "");
}

/* True (denied) unless the capability's "allowed" bit is present and true —
 * fails CLOSED on a missing/malformed sub-object rather than reporting a
 * denied capability as granted. `cap_key` is the sovereignty dumper's own
 * JSON key (k_sov_caps in sovereignty_controller.c) — note SYNC_CAP_MINE is
 * keyed "mine" there, matching the "mint" action name sovereignty_guard_
 * allow() logs, not a literal "mint" key. */
static bool trust_tier_cap_denied(const struct json_value *caps,
                                  const char *cap_key)
{
    const struct json_value *entry = caps ? json_get(caps, cap_key) : NULL;
    const struct json_value *allowed = entry ? json_get(entry, "allowed")
                                              : NULL;
    return !(allowed && json_get_bool(allowed));
}

static void agent_trust_tier_collect_fresh(
    struct agent_trust_tier_snapshot *out)
{
    struct json_value dump;
    json_init(&dump);
    sovereignty_dump_state_json(&dump, NULL);

    trust_tier_str(out->trust_mode, sizeof(out->trust_mode),
                   json_get_str(json_get(&dump, "trust_mode")));
    trust_tier_str(out->trust_state, sizeof(out->trust_state),
                   json_get_str(json_get(&dump, "trust_state")));
    trust_tier_str(out->durable_store_status,
                   sizeof(out->durable_store_status),
                   json_get_str(json_get(&dump, "durable_store_status")));

    const struct json_value *caps = json_get(&dump, "capabilities");
    out->mint_denied = trust_tier_cap_denied(caps, "mine");
    out->wallet_spend_denied = trust_tier_cap_denied(caps, "wallet_spend");
    out->export_bundle_denied = trust_tier_cap_denied(caps, "export_bundle");

    struct { bool denied; const char *name; } denied_caps[] = {
        { out->mint_denied, "mint" },
        { out->wallet_spend_denied, "wallet_spend" },
        { out->export_bundle_denied, "export_bundle" },
    };
    out->capabilities_denied[0] = '\0';
    size_t used = 0;
    for (size_t i = 0; i < sizeof(denied_caps) / sizeof(denied_caps[0]); i++) {
        if (!denied_caps[i].denied)
            continue;
        int n = snprintf(out->capabilities_denied + used,
                         sizeof(out->capabilities_denied) - used, "%s%s",
                         used ? "," : "", denied_caps[i].name);
        if (n > 0)
            used += (size_t)n;
    }

    json_free(&dump);
}

void agent_summary_trust_tier_collect_bounded(
    struct agent_trust_tier_snapshot *out)
{
    struct agent_trust_tier_snapshot empty = {0};
    if (!out)
        return;
    *out = empty;
    if (agent_summary_trust_tier_cache_load(out))
        return;
    agent_trust_tier_collect_fresh(out);
    agent_summary_trust_tier_cache_store(out);
}

void agent_push_trust_tier_json(struct json_value *out, const char *key)
{
    struct agent_trust_tier_snapshot tier;
    struct json_value tt = {0};

    if (!out)
        return;
    agent_summary_trust_tier_collect_bounded(&tier);
    json_set_object(&tt);
    json_push_kv_str(&tt, "schema", "zcl.trust_tier.v1");
    json_push_kv_str(&tt, "trust_mode", tier.trust_mode);
    json_push_kv_str(&tt, "trust_state", tier.trust_state);
    json_push_kv_str(&tt, "durable_store_status", tier.durable_store_status);
    json_push_kv_bool(&tt, "mint_denied", tier.mint_denied);
    json_push_kv_bool(&tt, "wallet_spend_denied", tier.wallet_spend_denied);
    json_push_kv_bool(&tt, "export_bundle_denied", tier.export_bundle_denied);
    json_push_kv_str(&tt, "capabilities_denied", tier.capabilities_denied);
    json_push_kv_bool(&tt, "served_from_cache", tier.served_from_cache);
    json_push_kv_int(&tt, "cache_age_ms", tier.cache_age_ms);
    json_push_kv(out, key && key[0] ? key : "trust_tier", &tt);
    json_free(&tt);
}
