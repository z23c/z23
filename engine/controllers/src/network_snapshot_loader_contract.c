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

void network_push_snapshot_loader_status(struct json_value *result,
                                         const char *datadir_arg,
                                         const char *load_snapshot_at_own_height)
{
    const char *datadir = datadir_arg ? datadir_arg : "";
    const char *loader_path = load_snapshot_at_own_height
        ? load_snapshot_at_own_height : "";
    char best_name[256] = {0};
    char bundle_path[1200] = {0};
    char failed_marker_path[1400] = {0};
    int bundle_count = 0;
    long long seed_h = bundle_scan_seed_height(datadir, &bundle_count,
                                               best_name, sizeof(best_name));
    bool bundle_present = seed_h >= 0;
    bool block_index_present = false;
    bool failed_marker = false;
    bool loader_configured = loader_path[0] != '\0';
    bool bundle_path_ready = false;
    bool bootable_bundle = false;
    const char *recovery_hint = "install_tip_seed_snapshot";

    if (bundle_present)
        bundle_path_ready = join_path(bundle_path, sizeof(bundle_path),
                                      datadir, best_name);

    if (datadir[0]) {
        char p[1200];
        if (join_path(p, sizeof(p), datadir, "block_index.bin"))
            block_index_present = access(p, F_OK) == 0;
        if (bundle_path_ready) {
            int n = snprintf(failed_marker_path,
                             sizeof(failed_marker_path),
                             "%s.failed", bundle_path);
            if (n > 0 && (size_t)n < sizeof(failed_marker_path))
                failed_marker = access(failed_marker_path, F_OK) == 0;
        }
    }

    bootable_bundle = bundle_present && block_index_present && !failed_marker;

    if (!datadir[0])
        recovery_hint = "configure_datadir";
    else if (loader_configured)
        recovery_hint = "loader_active";
    else if (bootable_bundle)
        recovery_hint = "restart_with_load_snapshot_at_own_height";
    else if (bundle_present && failed_marker)
        recovery_hint = "replace_failed_seed_snapshot";

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

    sqlite3 *pdb = progress_store_db();
    bool progress_open = pdb != NULL;
    bool applied_found = false;
    bool applied_ok = false;
    bool proven_authority = false;
    bool self_folded = false;
    bool hstar_ok = false;
    bool coins_cover_hstar = false;
    bool self_derived = false;
    int32_t applied = -1;
    int32_t hstar = -1;
    int32_t served_floor = -1;
    char self_reason[128] = "progress_store_not_open";

    if (pdb) {
        progress_store_tx_lock();
        applied_ok = coins_kv_get_applied_height(pdb, &applied,
                                                 &applied_found);
        proven_authority = coins_kv_is_proven_authority(pdb, NULL);
        self_folded = coins_kv_contains_refold_marker(pdb);
        hstar_ok = reducer_frontier_compute_hstar(pdb, &hstar,
                                                  &served_floor);
        if (hstar_ok) {
            coins_cover_hstar = applied_ok && applied_found &&
                applied >= hstar + 1;
            self_derived = coins_kv_tip_is_self_derived(
                pdb, hstar, self_reason, sizeof(self_reason));
            if (self_derived)
                snprintf(self_reason, sizeof(self_reason), "ok");
        } else {
            snprintf(self_reason, sizeof(self_reason), "hstar_unavailable");
        }
        progress_store_tx_unlock();
    }

    struct json_value authority = {0};
    json_set_object(&authority);
    json_push_kv_str(&authority, "schema",
                     "zcl.snapshot_loader_authority.v1");
    json_push_kv_int(&authority, "schema_version", 1);
    json_push_kv_bool(&authority, "progress_store_open", progress_open);
    json_push_kv_bool(&authority, "hstar_available", hstar_ok);
    json_push_kv_int(&authority, "hstar", hstar_ok ? hstar : -1);
    json_push_kv_int(&authority, "served_floor",
                     hstar_ok ? served_floor : -1);
    json_push_kv_bool(&authority, "coins_applied_height_readable",
                      applied_ok);
    json_push_kv_bool(&authority, "coins_applied_height_present",
                      applied_found);
    json_push_kv_int(&authority, "coins_applied_height",
                     applied_found ? applied : -1);
    json_push_kv_bool(&authority, "coins_kv_proven_authority",
                      proven_authority);
    json_push_kv_bool(&authority, "coins_cover_hstar",
                      coins_cover_hstar);
    json_push_kv_bool(&authority, "fast_rebuild_authority_ready",
                      proven_authority && coins_cover_hstar);
    json_push_kv_bool(&authority, "self_folded_marker", self_folded);
    json_push_kv_bool(&authority, "self_derived_tip_static_checks",
                      self_derived);
    json_push_kv_str(&authority, "self_derived_reason", self_reason);
    json_push_kv_str(&authority, "authority_posture",
                     !progress_open ? "unknown_no_progress_store" :
                     !proven_authority ? "not_proven" :
                     self_folded ? "self_folded_marker_present" :
                     "proven_but_not_self_folded");
    json_push_kv(&loader, "authority", &authority);
    json_free(&authority);

    json_push_kv(result, "snapshot_loader", &loader);
    json_free(&loader);
}
