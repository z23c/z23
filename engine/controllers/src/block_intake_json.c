/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "controllers/block_intake_json.h"

#include "controllers/network_controller.h"
#include "json/json.h"
#include "net/msgprocessor.h"

#include <stdint.h>

void controller_json_set_block_intake_stats(struct json_value *obj)
{
    struct msg_block_intake_stats st;

    msg_processor_get_block_intake_stats(rpc_net_get_msg_processor(), &st);
    json_set_object(obj);
    json_push_kv_bool(obj, "running", st.running);
    json_push_kv_bool(obj, "stopping", st.stopping);
    json_push_kv_int(obj, "current_depth", (int64_t)st.current_depth);
    json_push_kv_int(obj, "capacity", (int64_t)st.capacity);
    json_push_kv_bool(obj, "saturated",
                      st.running && !st.stopping && st.capacity > 0 &&
                      st.current_depth >= st.capacity);
    json_push_kv_int(obj, "max_depth", (int64_t)st.max_depth);
    json_push_kv_int(obj, "enqueued", (int64_t)st.enqueued);
    json_push_kv_int(obj, "processed", (int64_t)st.processed);
    json_push_kv_int(obj, "accepted", (int64_t)st.accepted);
    json_push_kv_int(obj, "retryable", (int64_t)st.retryable);
    json_push_kv_int(obj, "rejected", (int64_t)st.rejected);
    json_push_kv_int(obj, "dropped", (int64_t)st.dropped);
    /* dropped/(dropped+enqueued) is the share of already-downloaded bodies
     * destroyed for want of a ring slot — the number that showed the getdata
     * window was wider than the absorber (measured 560 permille). Reported so
     * a reader does not have to do the division to see the bound is holding. */
    json_push_kv_int(obj, "dropped_permille_of_received",
                     (st.dropped + st.enqueued) > 0
                         ? (int64_t)((st.dropped * 1000u) /
                                     (st.dropped + st.enqueued))
                         : 0);
    json_push_kv_int(obj, "clone_failed", (int64_t)st.clone_failed);
    json_push_kv_int(obj, "spawn_failed", (int64_t)st.spawn_failed);
    json_push_kv_int(obj, "last_enqueue_unix", st.last_enqueue_unix);
    json_push_kv_int(obj, "last_process_unix", st.last_process_unix);
}

void controller_json_push_block_intake_stats(struct json_value *obj)
{
    struct json_value intake = {0};

    controller_json_set_block_intake_stats(&intake);
    json_push_kv(obj, "block_intake", &intake);
    json_free(&intake);
}

bool controller_block_intake_dump_state_json(struct json_value *out,
                                             const char *key)
{
    (void)key;
    controller_json_set_block_intake_stats(out);
    return true;
}
