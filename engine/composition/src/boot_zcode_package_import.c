/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Render and import one complete signed package carrier. */

#include "config/boot_zcode_dht.h"
#include "base/hex.h"
#include "json/json.h"
#include "vcs/package_swarm_node.h"

void boot_zcode_package_download_render(
    struct json_value *result,
    const struct vcs_swarm_download_status *status)
{
    struct json_value download;
    json_init(&download);
    json_set_object(&download);
    json_push_kv_str(&download, "state",
                     vcs_swarm_download_state_string(status->state));
    if (status->rule)
        json_push_kv_str(&download, "rule", status->rule);
    json_push_kv_int(&download, "advertisers", status->advertisers);
    json_push_kv_int(&download, "inflight", status->inflight);
    json_push_kv_int(&download, "present_chunks", status->present_chunks);
    json_push_kv_int(&download, "total_chunks", status->total_chunks);
    json_push_kv_int(&download, "present_bytes",
                     (int64_t)status->present_bytes);
    json_push_kv_int(&download, "total_bytes",
                     (int64_t)status->total_bytes);
    json_push_kv_int(&download, "fetched_bytes",
                     (int64_t)status->fetched_bytes);
    json_push_kv_int(&download, "requested_bytes",
                     (int64_t)status->requested_bytes);
    json_push_kv_int(&download, "transferred_bytes",
                     (int64_t)status->transferred_bytes);
    json_push_kv_int(&download, "reused_bytes",
                     (int64_t)status->reused_bytes);
    json_push_kv_int(&download, "requested_objects",
                     status->requested_objects);
    json_push_kv_int(&download, "transferred_objects",
                     status->transferred_objects);
    json_push_kv_int(&download, "reused_objects", status->reused_objects);
    json_push_kv_int(&download, "maximum_package_bytes",
                     (int64_t)status->maximum_package_bytes);
    json_push_kv(result, "download", &download);
    json_free(&download);
}

void boot_zcode_package_import_render(struct vcs_swarm_engine *engine,
                                      const uint8_t transport_root[32],
                                      int fetch_result,
                                      struct json_value *result)
{
    char hex[65];
    zcl_hex_encode(transport_root, 32, hex);
    json_push_kv_str(result, "transport_root", hex);
    struct vcs_swarm_download_status status;
    if (engine && vcs_swarm_engine_download_status(
                      engine, transport_root, &status))
        boot_zcode_package_download_render(result, &status);
    if (!engine || fetch_result != VCS_SWARM_FETCH_ALREADY_COMPLETE)
        return;
    struct vcs_package_transport_import imported;
    enum vcs_package_transport_result rc =
        vcs_swarm_engine_import_transport(engine, transport_root, &imported);
    if (rc != VCS_PACKAGE_TRANSPORT_OK) {
        struct json_value *ok = (struct json_value *)json_get(result, "ok");
        if (ok) json_set_bool(ok, false);
        json_push_kv_str(result, "code", "PACKAGE_TRANSPORT_IMPORT");
        json_push_kv_str(result, "error",
                         vcs_package_transport_result_string(rc));
        return;
    }
    zcl_hex_encode(imported.package_root, 32, hex);
    json_push_kv_str(result, "package_root", hex);
    zcl_hex_encode(imported.recipe_root, 32, hex);
    json_push_kv_str(result, "recipe_root", hex);
    zcl_hex_encode(imported.release_id, 32, hex);
    json_push_kv_str(result, "release_id", hex);
    json_push_kv_int(result, "source_bytes", (int64_t)imported.source_bytes);
    json_push_kv_int(result, "source_chunks", imported.source_chunks);
    json_push_kv_int(result, "cas_objects_reused", imported.cas_objects_reused);
    json_push_kv_bool(result, "reconstructed", true);
}
