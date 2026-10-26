/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Snapshot-loader posture for bootstrapstatus. Kept separate from the network
 * controller so P2P readiness, fresh-node UX, and seed authority can evolve
 * independently without making one large endpoint file harder to review. */

#include "controllers/network_controller.h"

#include "controllers/diagnostics_internal.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static bool join_path(char *out, size_t out_sz, const char *dir,
                      const char *base)
{
    int n;

    if (!out || out_sz == 0 || !dir || !dir[0] || !base || !base[0])
        return false; // raw-return-ok:predicate-invalid-path
    n = snprintf(out, out_sz, "%s/%s", dir, base);
    return n > 0 && (size_t)n < out_sz;
}

/* Resolve the bundle path and probe the datadir for block_index.bin and the
 * bundle's .failed marker; the out-params keep their prior value (false)
 * whenever a probe does not run or fails. */
static void network_snapshot_loader_probe_paths(const char *datadir,
                                                const char *best_name,
                                                bool bundle_present,
                                                char *bundle_path,
                                                size_t bundle_path_sz,
                                                bool *bundle_path_ready,
                                                bool *block_index_present,
                                                bool *failed_marker)
{
    char failed_marker_path[1400] = {0};

    if (bundle_present)
        *bundle_path_ready = join_path(bundle_path, bundle_path_sz,
                                       datadir, best_name);

    if (datadir[0]) {
        char p[1200];
        if (join_path(p, sizeof(p), datadir, "block_index.bin"))
            *block_index_present = access(p, F_OK) == 0;
        if (*bundle_path_ready) {
            int n = snprintf(failed_marker_path,
                             sizeof(failed_marker_path),
                             "%s.failed", bundle_path);
            if (n > 0 && (size_t)n < sizeof(failed_marker_path))
                *failed_marker = access(failed_marker_path, F_OK) == 0;
        }
    }
}

/* Pick the recovery hint using the endpoint's precedence: datadir first,
 * then an active loader, then a bootable bundle, then a failed marker. */
static const char *network_snapshot_loader_recovery_hint(
    const char *datadir, bool loader_configured, bool bootable_bundle,
    bool bundle_present, bool failed_marker)
{
    if (!datadir[0])
        return "configure_datadir";
    if (loader_configured)
        return "loader_active";
    if (bootable_bundle)
        return "restart_with_load_snapshot_at_own_height";
    if (bundle_present && failed_marker)
        return "replace_failed_seed_snapshot";
    return "install_tip_seed_snapshot";
}

/* Progress-store and coins-KV facts reported under "authority". */
struct snapshot_loader_authority {
    bool progress_open;
    bool hstar_ok;
    bool applied_ok;
    bool applied_found;
    bool proven_authority;
    bool self_folded;
    bool coins_cover_hstar;
    bool self_derived;
    int32_t applied;
    int32_t hstar;
    int32_t served_floor;
    char self_reason[128];
};

/* Read the progress store and coins KV under the progress-store tx lock.
 * Fields stay at their caller-set defaults when the store is not open. */
static void network_snapshot_loader_probe_authority(
    struct snapshot_loader_authority *st)
{
    sqlite3 *pdb = progress_store_db();

    st->progress_open = pdb != NULL;
    if (pdb) {
        progress_store_tx_lock();
        st->applied_ok = coins_kv_get_applied_height(pdb, &st->applied,
                                                     &st->applied_found);
        st->proven_authority = coins_kv_is_proven_authority(pdb, NULL);
        st->self_folded = coins_kv_contains_refold_marker(pdb);
        st->hstar_ok = reducer_frontier_compute_hstar(pdb, &st->hstar,
                                                      &st->served_floor);
        if (st->hstar_ok) {
            st->coins_cover_hstar = st->applied_ok && st->applied_found &&
                st->applied >= st->hstar + 1;
            st->self_derived = coins_kv_tip_is_self_derived(
                pdb, st->hstar, st->self_reason,
                sizeof(st->self_reason));
            if (st->self_derived)
                snprintf(st->self_reason, sizeof(st->self_reason), "ok");
        } else {
            snprintf(st->self_reason, sizeof(st->self_reason),
                     "hstar_unavailable");
        }
        progress_store_tx_unlock();
    }
}

/* Emit the zcl.snapshot_loader_authority.v1 sub-object. */
static void network_snapshot_loader_push_authority(
    struct json_value *authority, const struct snapshot_loader_authority *st)
{
    json_push_kv_str(authority, "schema",
                     "zcl.snapshot_loader_authority.v1");
    json_push_kv_int(authority, "schema_version", 1);
    json_push_kv_bool(authority, "progress_store_open",
                      st->progress_open);
    json_push_kv_bool(authority, "hstar_available", st->hstar_ok);
    json_push_kv_int(authority, "hstar", st->hstar_ok ? st->hstar : -1);
    json_push_kv_int(authority, "served_floor",
                     st->hstar_ok ? st->served_floor : -1);
    json_push_kv_bool(authority, "coins_applied_height_readable",
                      st->applied_ok);
    json_push_kv_bool(authority, "coins_applied_height_present",
                      st->applied_found);
    json_push_kv_int(authority, "coins_applied_height",
                     st->applied_found ? st->applied : -1);
    json_push_kv_bool(authority, "coins_kv_proven_authority",
                      st->proven_authority);
    json_push_kv_bool(authority, "coins_cover_hstar",
                      st->coins_cover_hstar);
    json_push_kv_bool(authority, "fast_rebuild_authority_ready",
                      st->proven_authority && st->coins_cover_hstar);
    json_push_kv_bool(authority, "self_folded_marker", st->self_folded);
    json_push_kv_bool(authority, "self_derived_tip_static_checks",
                      st->self_derived);
    json_push_kv_str(authority, "self_derived_reason", st->self_reason);
    json_push_kv_str(authority, "authority_posture",
                     !st->progress_open ? "unknown_no_progress_store" :
                     !st->proven_authority ? "not_proven" :
                     st->self_folded ? "self_folded_marker_present" :
                     "proven_but_not_self_folded");
}

void network_push_snapshot_loader_status(struct json_value *result,
                                         const char *datadir_arg,
                                         const char *load_snapshot_at_own_height)
{
    const char *datadir = datadir_arg ? datadir_arg : "";
    const char *loader_path = load_snapshot_at_own_height
        ? load_snapshot_at_own_height : "";
    char best_name[256] = {0};
    char bundle_path[1200] = {0};
    int bundle_count = 0;
    long long seed_h = bundle_scan_seed_height(datadir, &bundle_count,
                                               best_name, sizeof(best_name));
    bool bundle_present = seed_h >= 0;
    bool block_index_present = false;
    bool failed_marker = false;
    bool loader_configured = loader_path[0] != '\0';
    bool bundle_path_ready = false;
    bool bootable_bundle = false;

    network_snapshot_loader_probe_paths(datadir, best_name, bundle_present,
                                        bundle_path, sizeof(bundle_path),
                                        &bundle_path_ready,
                                        &block_index_present,
                                        &failed_marker);
    bootable_bundle = bundle_present && block_index_present && !failed_marker;
    const char *recovery_hint = network_snapshot_loader_recovery_hint(
        datadir, loader_configured, bootable_bundle, bundle_present,
        failed_marker);

    struct json_value loader = {0};
    json_set_object(&loader);
    json_push_kv_str(&loader, "schema", "zcl.snapshot_loader.v1");
    json_push_kv_int(&loader, "schema_version", 1);
    json_push_kv_str(&loader, "datadir", datadir);
    json_push_kv_bool(&loader, "bundle_present", bundle_present);
    json_push_kv_int(&loader, "bundle_count", bundle_count);
    json_push_kv_int(&loader, "bundle_seed_height", seed_h);
    json_push_kv_str(&loader, "bundle_name", best_name);
    json_push_kv_str(&loader, "bundle_path",
                     bundle_path_ready ? bundle_path : "");
    json_push_kv_bool(&loader, "block_index_present",
                      block_index_present);
    json_push_kv_bool(&loader, "failed_marker", failed_marker);
    json_push_kv_bool(&loader, "bootable_bundle", bootable_bundle);
    json_push_kv_bool(&loader, "active_loader_configured",
                      loader_configured);
    json_push_kv_str(&loader, "active_loader_path", loader_path);
    json_push_kv_bool(&loader, "active_loader_matches_bundle",
                      loader_configured && bundle_path_ready &&
                      strcmp(loader_path, bundle_path) == 0);
    json_push_kv_str(&loader, "recovery_hint", recovery_hint);

    struct snapshot_loader_authority auth = {
        .applied = -1,
        .hstar = -1,
        .served_floor = -1,
        .self_reason = "progress_store_not_open",
    };

    network_snapshot_loader_probe_authority(&auth);

    struct json_value authority = {0};
    json_set_object(&authority);
    network_snapshot_loader_push_authority(&authority, &auth);
    json_push_kv(&loader, "authority", &authority);
    json_free(&authority);

    json_push_kv(result, "snapshot_loader", &loader);
    json_free(&loader);
}
