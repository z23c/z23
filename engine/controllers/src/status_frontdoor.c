/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * status_frontdoor — single-round-trip operator status composition (Program
 * O2). See controllers/status_frontdoor.h for the contract and the "why".
 *
 * This dumper reaches ONLY non-blocking in-process sources:
 *   - reducer_frontier_provable_tip_cached() / _floor()  — plain atomics;
 *   - agent_peer_snapshot_collect()                       — trylock + seqlock
 *                                                           cache, never blocks;
 *   - blocker_dump_state_json()                           — in-memory registry.
 * It takes NO progress_store_tx_lock and runs no COUNT(*), so the front door
 * stays answerable exactly when the reducer owns the write lock (the "RPC-dark
 * under load" defect the old 12-call body created). check_dumper_never_blocks
 * enforces the no-blocking-primitive rule on this body. */

#include "controllers/status_frontdoor.h"
#include "controllers/status_native_helpers.h"
#include "controllers/network_controller.h"

#include "services/operator_peer_snapshot_service.h"
#include "jobs/reducer_frontier.h"
#include "util/blocker.h"
#include "platform/time_compat.h"

#include "json/json.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Append one member name to the running degraded[] list — a member whose
 * snapshot is stale, busy, or unavailable this composition. Kept a helper (not
 * inlined into the dumper body) so the dumper body stays small and readable;
 * check_dumper_never_blocks scans only the dumper body, and nothing here
 * touches a blocking primitive regardless. */
static void frontdoor_note_degraded(struct json_value *degraded,
                                    const char *member, const char *reason)
{
    struct json_value entry;
    json_init(&entry);
    json_set_object(&entry);
    json_push_kv_str(&entry, "member", member ? member : "unknown");
    json_push_kv_str(&entry, "reason", reason ? reason : "unavailable");
    json_push_back(degraded, &entry);
    json_free(&entry);
}

/* Compose the peer member (count/direction/height + its staleness label) and
 * return the degraded reason string, or NULL when the peer snapshot is fresh. */
static const char *frontdoor_push_peers(struct json_value *out)
{
    struct agent_peer_snapshot ps;
    agent_peer_snapshot_collect(&ps, rpc_net_get_connman());

    struct json_value conn;
    json_init(&conn);
    json_set_object(&conn);
    json_push_kv_bool(&conn, "available", ps.available);
    json_push_kv_bool(&conn, "stale", ps.stale);
    json_push_kv_int(&conn, "age_seconds", ps.age_seconds);
    json_push_kv_int(&conn, "total", (int64_t)ps.peer_count);
    json_push_kv_int(&conn, "inbound", (int64_t)ps.inbound_count);
    json_push_kv_int(&conn, "outbound", (int64_t)ps.outbound_count);
    json_push_kv_int(&conn, "ready", (int64_t)ps.ready_count);
    json_push_kv_int(&conn, "zcl23", (int64_t)ps.zclassic_c23_peer_count);
    json_push_kv_int(&conn, "magicbean", (int64_t)ps.magicbean_peer_count);
    json_push_kv_bool(&conn, "direction_known", ps.direction_known);
    json_push_kv_bool(&conn, "peer_best_height_known",
                      ps.peer_best_height_known);
    json_push_kv_int(&conn, "generation", (int64_t)ps.generation);
    json_push_kv_str(&conn, "warning_reason",
                     ps.warning_reason ? ps.warning_reason
                                       : (ps.available ? "ok" : "unavailable"));
    json_push_kv(out, "connections", &conn);
    json_free(&conn);

    /* Flat top-level scalars users depend on from the legacy body. */
    json_push_kv_int(out, "peers", (int64_t)ps.peer_count);
    if (ps.peer_best_height_known)
        json_push_kv_int(out, "max_peer_height", ps.peer_best_height);
    json_push_kv_bool(out, "max_peer_height_known", ps.peer_best_height_known);
    json_push_kv_str(out, "max_peer_height_trust",
                     "untrusted_peer_advertisement");

    if (!ps.available)
        return "peer_snapshot_unavailable";
    if (ps.stale)
        return "peer_snapshot_busy";
    return NULL;
}

/* Compose the blocker member from the in-memory registry (never a DB read) and
 * surface the dominant blocker + active count at the top level, matching the
 * legacy body's contract. */
static void frontdoor_push_blockers(struct json_value *out)
{
    struct json_value bl;
    json_init(&bl);
    json_set_object(&bl);
    (void)blocker_dump_state_json(&bl, NULL);

    const struct json_value *active = json_get(&bl, "active_count");
    int64_t active_count = active ? json_get_int(active) : 0;
    json_push_kv_int(out, "active_blocker_count", active_count);

    const struct json_value *entries = json_get(&bl, "blockers");
    const struct json_value *dominant =
        (entries && entries->type == JSON_ARR)
            ? status_dominant_blocker(entries)
            : NULL;
    struct json_value dom;
    json_init(&dom);
    if (dominant)
        json_copy(&dom, dominant);
    else
        json_set_null(&dom);
    json_push_kv(out, "dominant_blocker", &dom);
    json_free(&dom);

    json_push_kv(out, "blockers", &bl);
    json_free(&bl);
}

bool status_frontdoor_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    json_push_kv_str(out, "schema", "zcl.status_frontdoor.v1");
    json_push_kv_str(out, "execution_locus", "target_node");
    json_push_kv_int(out, "captured_us", platform_time_monotonic_us());

    struct json_value degraded;
    json_init(&degraded);
    json_set_array(&degraded);

    /* Provable tip (H*) — a plain atomic load; 0 before the first finalize.
     * `provable_tip_published` distinguishes a genuine 0 from "nothing folded
     * yet" so an IBD node never reads as a false at-tip. */
    int32_t provable_tip = reducer_frontier_provable_tip_cached();
    bool published = reducer_frontier_provable_tip_is_published();
    json_push_kv_int(out, "height", provable_tip);
    json_push_kv_int(out, "provable_tip", provable_tip);
    json_push_kv_bool(out, "provable_tip_published", published);
    json_push_kv_int(out, "reducer_floor", reducer_frontier_floor());

    /* Peers (trylock + cached; never blocks). */
    const char *peer_degraded = frontdoor_push_peers(out);
    if (peer_degraded)
        frontdoor_note_degraded(&degraded, "connections", peer_degraded);

    /* A conservative sync gap from the (untrusted) peer availability hint and
     * the provable tip; only meaningful when a peer height is known. */
    const struct json_value *mph_known = json_get(out, "max_peer_height_known");
    const struct json_value *mph = json_get(out, "max_peer_height");
    bool have_peer_height = mph_known && json_get_bool(mph_known) && mph &&
                            mph->type == JSON_INT;
    if (have_peer_height) {
        int64_t gap = json_get_int(mph) - (int64_t)provable_tip;
        json_push_kv_int(out, "sync_gap", gap > 0 ? gap : 0);
    }
    json_push_kv_bool(out, "sync_gap_known", have_peer_height);

    /* Blockers (in-memory registry). */
    frontdoor_push_blockers(out);

    /* Honest observability rollup: never a green ok over a dark member. */
    json_push_kv_bool(out, "all_members_fresh", json_size(&degraded) == 0);
    json_push_kv(out, "degraded", &degraded);
    json_free(&degraded);
    return true;
}
