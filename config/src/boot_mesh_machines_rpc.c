/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Unified fleet view RPC adapter. One `mesh_machines` document
 * (zcl.mesh.machines.v1) pairs, per pairing row:
 *   - durable evidence: the latest VERIFIED signed receipt from the
 *     schema-v77 observation store, with honest fresh/stale/never-seen
 *     staleness derived from `now` (a stale receipt is evidence of the
 *     past, never a claim of current reachability); and
 *   - live verdict: this call's bounded probe fan-out, merged by
 *     pairing_id, when the caller ran the refresh (the test hook passes a
 *     NULL live report and renders the durable evidence alone).
 * The refresh persists its verified terminal receipts through
 * boot_mesh_status_receipt_persist (the serialized db_service writer)
 * before the render reads the store, so the rendered evidence already
 * reflects what this call proved.
 * Fingerprints only — no raw public key crosses the surface. */

#include "config/boot_mesh_machines.h"

#include "config/runtime.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "models/mesh_machine_observation.h"
#include "models/mesh_pairing.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const struct json_value *rpc_input(const struct json_value *params)
{
    const struct json_value *first =
        params && json_size(params) ? json_at(params, 0) : NULL;
    return first && first->type == JSON_OBJ ? first : NULL;
}

static void rpc_error(struct json_value *result, const char *code,
                      const char *message)
{
    json_set_object(result);
    json_push_kv_bool(result, "ok", false);
    json_push_kv_str(result, "code", code);
    json_push_kv_str(result, "message", message);
}

static const char *mesh_pairing_state(const struct db_mesh_pairing *pairing,
                                      int64_t now)
{
    if (pairing->revoked_at != 0)
        return "revoked";
    return now < pairing->expires_at ? "active" : "expired";
}

static const struct mesh_machine_row *live_row_for(
    const struct mesh_machines_report *live, const char *pairing_id)
{
    if (!live || !live->records_observed || !pairing_id)
        return NULL;
    for (size_t i = 0; i < live->row_count; i++) {
        if (strcmp(live->rows[i].pairing_id, pairing_id) == 0)
            return &live->rows[i];
    }
    return NULL;
}

static void mesh_machine_json(struct json_value *array,
                              const struct db_mesh_machine_view *view,
                              int64_t now,
                              const struct mesh_machines_report *live,
                              bool *fresh_out)
{
    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    const char *pairing_state = mesh_pairing_state(&view->pairing, now);
    bool fresh = view->has_observation &&
                 strcmp(pairing_state, "active") == 0 &&
                 now < view->observation.expires_unix;
    char hex[65];
    json_push_kv_str(&item, "pairing_id", view->pairing.pairing_id);
    json_push_kv_str(&item, "pairing_state", pairing_state);
    boot_mesh_status_key_fingerprint("zcl.mesh.master.fingerprint.v1",
                                     view->pairing.peer_master_pubkey, hex);
    json_push_kv_str(&item, "peer_master_fingerprint", hex);
    boot_mesh_status_key_fingerprint("zcl.mesh.noise.fingerprint.v1",
                                     view->pairing.peer_noise_pubkey, hex);
    json_push_kv_str(&item, "peer_noise_fingerprint", hex);
    json_push_kv_str(&item, "observation_state",
                     !view->has_observation ? "unknown"
                                            : fresh ? "fresh" : "stale");
    if (view->has_observation) {
        json_push_kv_str(
            &item, "receipt_status",
            mesh_status_receipt_status_string(view->observation.status));
        json_push_kv_int(&item, "observed_unix",
                         view->observation.observed_unix);
        json_push_kv_int(&item, "expires_unix",
                         view->observation.expires_unix);
        json_push_kv_int(&item, "received_unix",
                         view->observation.received_unix);
        zcl_hex_encode(view->observation.receipt_root, 32, hex);
        json_push_kv_str(&item, "receipt_root", hex);
    }
    /* Live verdict from this call's probe, when one ran. Distinct from the
     * durable evidence above: a live timeout does not erase a fresh stored
     * receipt, and a stored fresh receipt never claims current online. */
    const struct mesh_machine_row *live_row =
        live_row_for(live, view->pairing.pairing_id);
    if (live_row && live_row->probed) {
        if (live_row->state == MESH_MACHINE_REFUSED) {
            char reachability[MESH_MACHINE_DETAIL_LEN + 16];
            snprintf(reachability, sizeof(reachability), "refused:%s",
                     live_row->detail);
            json_push_kv_str(&item, "live_reachability", reachability);
            json_push_kv_str(&item, "live_refusal_status", live_row->detail);
        } else {
            json_push_kv_str(&item, "live_reachability",
                             mesh_machine_state_string(live_row->state));
            if (live_row->detail[0])
                json_push_kv_str(&item, "live_detail", live_row->detail);
        }
        if (live_row->state == MESH_MACHINE_ONLINE) {
            json_push_kv_int(&item, "live_observed_unix",
                             (int64_t)live_row->observed_unix);
            zcl_hex_encode(live_row->responder_noise_fingerprint, 32, hex);
            json_push_kv_str(&item,
                             "live_responder_noise_fingerprint_sha3", hex);
        }
    }
    (void)json_push_back(array, &item);
    json_free(&item);
    *fresh_out = fresh;
}

void boot_mesh_machines_render(struct node_db *ndb, int64_t now,
                               const struct mesh_machines_report *live,
                               struct json_value *result)
{
    size_t capacity = MESH_MACHINES_VIEW_MAX;
    struct db_mesh_machine_view *views = zcl_calloc(
        capacity, sizeof(*views), "mesh_machines.views");
    if (!views || !ndb || now <= 0) {
        free(views);
        rpc_error(result, "OBSERVATION_UNAVAILABLE",
                  "the durable machine projection is unavailable");
        return;
    }
    struct db_mesh_pairing_counts pairing_counts;
    int count = db_mesh_machine_observation_list(ndb, views, capacity, now);
    if (count < 0 ||
        !db_mesh_pairing_count_states(ndb, now, &pairing_counts)) {
        free(views);
        rpc_error(result, "OBSERVATION_UNAVAILABLE",
                  "the durable pairing count is unavailable");
        return;
    }
    size_t shown = (size_t)count;
    bool truncated = pairing_counts.total > (int64_t)shown ||
                     (live && live->truncated);
    struct json_value machines;
    json_init(&machines);
    json_set_array(&machines);
    int64_t fresh = 0, stale = 0, unknown = 0;
    for (size_t i = 0; i < shown; i++) {
        bool is_fresh = false;
        mesh_machine_json(&machines, &views[i], now, live, &is_fresh);
        if (!views[i].has_observation)
            unknown++;
        else if (is_fresh)
            fresh++;
        else
            stale++;
    }
    free(views);
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "schema", "zcl.mesh.machines.v1");
    json_push_kv_int(result, "observed_at", now);
    json_push_kv_int(result, "total", pairing_counts.total);
    json_push_kv_int(result, "active", pairing_counts.active);
    json_push_kv_int(result, "returned", (int64_t)shown);
    json_push_kv_int(result, "returned_fresh", fresh);
    json_push_kv_int(result, "returned_stale", stale);
    json_push_kv_int(result, "returned_unknown", unknown);
    json_push_kv_bool(result, "truncated", truncated);
    if (live) {
        /* The live fan-out rollup; the pairing list itself was unreadable
         * iff records_observed is false, and the blocker says why. */
        json_push_kv_bool(result, "live_records_observed",
                          live->records_observed);
        if (!live->records_observed)
            json_push_kv_str(result, "live_blocker", live->blocker);
        int64_t probed = 0;
        for (size_t i = 0; i < live->row_count; i++)
            if (live->rows[i].probed)
                probed++;
        json_push_kv_int(result, "live_probed", probed);
        json_push_kv_int(result, "live_online", live->counts.online);
        json_push_kv_int(result, "live_refused", live->counts.refused);
        json_push_kv_int(result, "live_unreachable", live->counts.unreachable);
        json_push_kv_int(result, "live_timeout", live->counts.timeout);
        json_push_kv_int(result, "live_unknown",
                         live->counts.total - live->counts.online -
                             live->counts.refused - live->counts.unreachable -
                             live->counts.timeout - live->counts.expired -
                             live->counts.revoked);
    }
    json_push_kv(result, "machines", &machines);
    json_free(&machines);
}

static bool rpc_mesh_machines(const struct json_value *params, bool help,
                              struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "mesh_machines — every durable pairing with verified "
                     "evidence (fresh/stale/never-seen) plus this call's "
                     "bounded live probe verdict per row; probes up to 8 "
                     "actives with a collective 12 s budget; never dials");
        return true;
    }
    if (rpc_input(params)) {
        rpc_error(result, "INVALID_ARGUMENT",
                  "mesh_machines accepts no input");
        return true;
    }
    struct node_db *ndb = app_runtime_node_db();
    struct db_service *dbsvc = app_runtime_db_service();
    if (!ndb || !app_runtime_node_db_handle_open(ndb) || !dbsvc) {
        LOG_ERROR("net.mesh_machines",
                  "mesh_machines: node_db or db_service unavailable");
        rpc_error(result, "OBSERVATION_UNAVAILABLE",
                  "the durable machine projection is unavailable");
        return true;
    }
    struct mesh_machines_report *live =
        zcl_malloc(sizeof(*live), "mesh_machines.live");
    if (!live) {
        rpc_error(result, "UNAVAILABLE",
                  "could not allocate the fleet report");
        return true;
    }
    /* Refresh first: probes run, verified receipts persist, THEN the render
     * reads the store so the document already carries this call's proofs. */
    (void)boot_mesh_machines_refresh(ndb, dbsvc, live);
    boot_mesh_machines_render(ndb, (int64_t)platform_time_wall_time_t(),
                              live, result);
    free(live);
    return true;
}

void boot_mesh_machines_register_rpc(struct rpc_table *table)
{
    const struct rpc_command commands[] = {
        {"mesh", "mesh_machines", rpc_mesh_machines, true},
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
        rpc_table_must_append(table, &commands[i]);
}
