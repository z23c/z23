/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Read-only dumpstate snapshot of the node-global swarm engine. */

#include "vcs/package_swarm_status.h"

#include "vcs/package_swarm_node.h"

#include "base/hex.h"
#include "json/json.h"
#include "util/log_macros.h"

static void push_advertised(struct json_value *out,
                            struct vcs_swarm_engine *engine)
{
    struct vcs_swarm_advertised rows[VCS_SWARM_MAX_LOCAL_ANNOUNCES];
    size_t n = 0;
    if (engine)
        n = vcs_swarm_engine_advertised(engine, rows,
                                        VCS_SWARM_MAX_LOCAL_ANNOUNCES);
    json_push_kv_int(out, "advertised_count", (int64_t)n);
    struct json_value advertised = {0};
    json_set_array(&advertised);
    for (size_t i = 0; i < n; i++) {
        char hex[65];
        zcl_hex_encode(rows[i].root, 32, hex);
        struct json_value row = {0};
        json_set_object(&row);
        json_push_kv_str(&row, "root", hex);
        json_push_kv_int(&row, "advertisers",
                         (int64_t)rows[i].advertisers);
        json_push_back(&advertised, &row);
        json_free(&row);
    }
    json_push_kv(out, "advertised", &advertised);
    json_free(&advertised);
}

bool vcs_package_swarm_status_dump_state_json(struct json_value *out,
                                              const char *key)
{
    (void)key;
    if (!out)
        LOG_FAIL("zcode_swarm", "dump_state_json: out is NULL");
    json_set_object(out);

    struct vcs_swarm_engine *engine = vcs_swarm_engine_global();
    if (!engine) {
        json_push_kv_bool(out, "enabled", false);
        json_push_kv_bool(out, "present", false);
        json_push_kv_int(out, "peer_count", 0);
        json_push_kv_int(out, "active_downloads", 0);
        struct json_value peers = {0};
        json_set_array(&peers);
        json_push_kv(out, "peers", &peers);
        json_free(&peers);
        push_advertised(out, NULL);
        return true;
    }

    uint64_t ids[VCS_SWARM_MAX_PEERS];
    size_t peer_count = vcs_swarm_engine_peer_ids(
        engine, ids, VCS_SWARM_MAX_PEERS);
    size_t active = vcs_swarm_engine_active_downloads(engine);

    json_push_kv_bool(out, "enabled", true);
    json_push_kv_bool(out, "present", true);
    json_push_kv_int(out, "peer_count", (int64_t)peer_count);
    json_push_kv_int(out, "active_downloads", (int64_t)active);

    struct json_value peers = {0};
    json_set_array(&peers);
    for (size_t i = 0; i < peer_count; i++) {
        struct vcs_swarm_transfer xfer;
        uint64_t served = 0;
        uint64_t fetched = 0;
        if (vcs_swarm_engine_transfer_snapshot(engine, ids[i], &xfer)) {
            served = xfer.served;
            fetched = xfer.fetched;
        }
        struct json_value row = {0};
        json_set_object(&row);
        json_push_kv_int(&row, "peer_id", (int64_t)ids[i]);
        json_push_kv_int(&row, "served_bytes", (int64_t)served);
        json_push_kv_int(&row, "fetched_bytes", (int64_t)fetched);
        json_push_back(&peers, &row);
        json_free(&row);
    }
    json_push_kv(out, "peers", &peers);
    json_free(&peers);
    push_advertised(out, engine);
    return true;
}
