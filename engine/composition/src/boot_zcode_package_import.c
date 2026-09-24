/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Render and import one complete signed package carrier, and
 * finish a routed carrier fetch on the node's own clock. */

#include "config/boot_zcode_dht.h"
#include "base/hex.h"
#include "json/json.h"
#include "util/log_macros.h"
#include "vcs/package_swarm_node.h"
#include "vcs/package_transport.h"

#include <pthread.h>
#include <string.h>

#define PACKAGE_IMPORT_LOG "net.zcode_swarm"

/* Carriers a routed package fetch admitted but that were still moving
 * when the request returned. The swarm tick completes the transfer on
 * its own; without this table the inner package was reconstructed only
 * when a caller asked again, so a single fetch left the package root
 * untracked until the caller's next retry. One slot per possible
 * download: a full table falls back to reconstruct-on-next-request. */
#define PACKAGE_IMPORT_PENDING_MAX VCS_SWARM_MAX_DOWNLOADS

static pthread_mutex_t g_import_lock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t g_import_roots[PACKAGE_IMPORT_PENDING_MAX][32];
static size_t g_import_count;

static int import_pending_index(const uint8_t root[32])
{
    for (size_t i = 0; i < g_import_count; i++)
        if (memcmp(g_import_roots[i], root, 32) == 0)
            return (int)i;
    return -1;
}

static bool import_pending_arm(const uint8_t root[32])
{
    pthread_mutex_lock(&g_import_lock);
    bool armed = import_pending_index(root) >= 0;
    if (!armed && g_import_count < PACKAGE_IMPORT_PENDING_MAX) {
        memcpy(g_import_roots[g_import_count++], root, 32);
        armed = true;
    }
    pthread_mutex_unlock(&g_import_lock);
    return armed;
}

static void import_pending_disarm(const uint8_t root[32])
{
    pthread_mutex_lock(&g_import_lock);
    int index = import_pending_index(root);
    if (index >= 0) {
        g_import_count--;
        memmove(g_import_roots[index], g_import_roots[index + 1],
                (g_import_count - (size_t)index) * 32u);
    }
    pthread_mutex_unlock(&g_import_lock);
}

enum import_pending_step {
    IMPORT_PENDING_KEEP = 0,
    IMPORT_PENDING_DROPPED,
    IMPORT_PENDING_IMPORTED,
};

/* One armed carrier: keep while its download moves, reconstruct once it
 * is complete, drop it when the download ended any other way (the next
 * fetch request restarts it and names the failure). */
static enum import_pending_step import_pending_step(
    struct vcs_swarm_engine *engine, const uint8_t root[32])
{
    struct vcs_swarm_download_status status;
    if (!vcs_swarm_engine_download_status(engine, root, &status))
        return IMPORT_PENDING_DROPPED;
    if (status.state == VCS_SWARM_DL_WANT_MANIFEST ||
        status.state == VCS_SWARM_DL_CHUNKS)
        return IMPORT_PENDING_KEEP;
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    if (status.state != VCS_SWARM_DL_COMPLETE) {
        LOG_INFO(PACKAGE_IMPORT_LOG, "routed carrier %.16s ended %s: %s",
                 hex, vcs_swarm_download_state_string(status.state),
                 status.rule ? status.rule : "no rule");
        return IMPORT_PENDING_DROPPED;
    }
    struct vcs_package_transport_import imported;
    enum vcs_package_transport_result rc =
        vcs_swarm_engine_import_transport(engine, root, &imported);
    if (rc != VCS_PACKAGE_TRANSPORT_OK) {
        LOG_WARN(PACKAGE_IMPORT_LOG, "routed carrier %.16s refused: %s", hex,
                 vcs_package_transport_result_string(rc));
        return IMPORT_PENDING_DROPPED;
    }
    char package_hex[65];
    zcl_hex_encode(imported.package_root, 32, package_hex);
    LOG_INFO(PACKAGE_IMPORT_LOG, "routed carrier %.16s reconstructed %.16s",
             hex, package_hex);
    return IMPORT_PENDING_IMPORTED;
}

size_t boot_zcode_package_import_tick(struct vcs_swarm_engine *engine)
{
    if (!engine)
        return 0;
    uint8_t roots[PACKAGE_IMPORT_PENDING_MAX][32];
    pthread_mutex_lock(&g_import_lock);
    size_t count = g_import_count;
    memcpy(roots, g_import_roots, count * 32u);
    pthread_mutex_unlock(&g_import_lock);
    /* The table lock is never held across the engine: reconstruction
     * takes the engine lock and does store I/O. At most one
     * reconstruction per tick keeps the tick bounded; the rest wait one
     * second. */
    for (size_t i = 0; i < count; i++) {
        enum import_pending_step step = import_pending_step(engine, roots[i]);
        if (step == IMPORT_PENDING_KEEP)
            continue;
        import_pending_disarm(roots[i]);
        if (step == IMPORT_PENDING_IMPORTED)
            return 1;
    }
    return 0;
}

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
    if (engine && fetch_result == VCS_SWARM_FETCH_OK &&
        !import_pending_arm(transport_root))
        LOG_WARN(PACKAGE_IMPORT_LOG,
                 "routed carrier %.16s: pending-import table full; "
                 "reconstructed on the next fetch request", hex);
    if (!engine || fetch_result != VCS_SWARM_FETCH_ALREADY_COMPLETE)
        return;
    import_pending_disarm(transport_root);
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
