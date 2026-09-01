/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * See sim/simnet_trace.h for the format and the "why not a live dumper"
 * rationale.
 */

#include "sim/simnet_trace.h"

#include "base/hex.h"
#include "coins/utxo_commitment.h"
#include "core/uint256.h"
#include "json/json.h"
#include "sim/simnet_cluster.h"
#include "util/log_macros.h"

#include <string.h>

bool simnet_trace_writer_open(struct simnet_trace_writer *w,
                              const char *path)
{
    if (!w || !path || !*path)
        return false;
    memset(w, 0, sizeof(*w));
    if (strlen(path) >= sizeof(w->path)) {
        LOG_FAIL("simnet.trace", "trace path too long: %s", path);
    }
    snprintf(w->path, sizeof(w->path), "%s", path);
    w->fp = fopen(path, "ab");
    if (!w->fp) {
        LOG_FAIL("simnet.trace", "failed to open trace file %s", path);
    }
    return true;
}

bool simnet_trace_writer_is_open(const struct simnet_trace_writer *w)
{
    return w && w->fp != NULL;
}

/* Fills `out` with one node's chain/coins/cluster snapshot. Returns false if
 * any simnet_cluster accessor fails for this node_id (still leaves *out a
 * valid, freeable JSON object reporting what it could). */
static bool simnet_trace_node_snapshot(struct json_value *out,
                                       struct simnet_cluster *cluster,
                                       size_t node_id, uint64_t seq,
                                       const char *event)
{
    json_set_object(out);
    json_push_kv_int(out, "seq", (int64_t)seq);
    json_push_kv_str(out, "event", event);
    json_push_kv_int(out, "node_id", (int64_t)node_id);

    struct uint256 tip;
    int32_t height = 0;
    struct utxo_commitment digest;
    bool have_tip = simnet_cluster_tip_hash(cluster, node_id, &tip);
    bool have_height = simnet_cluster_tip_height(cluster, node_id, &height);
    bool have_digest = simnet_cluster_coins_digest(cluster, node_id, &digest);

    struct json_value chain;
    json_init(&chain);
    json_set_object(&chain);
    json_push_kv_bool(&chain, "ok", have_tip && have_height);
    if (have_height)
        json_push_kv_int(&chain, "tip_height", height);
    if (have_tip) {
        char hex[65];
        uint256_get_hex(&tip, hex);
        json_push_kv_str(&chain, "tip_hash", hex);
    }
    json_push_kv(out, "chain", &chain);
    json_free(&chain);

    struct json_value coins;
    json_init(&coins);
    json_set_object(&coins);
    json_push_kv_bool(&coins, "ok", have_digest);
    if (have_digest) {
        char hex[2 * sizeof(digest.accumulator) + 1];
        zcl_hex_encode(digest.accumulator, sizeof(digest.accumulator), hex);
        json_push_kv_str(&coins, "commitment_hex", hex);
        json_push_kv_int(&coins, "utxo_count", (int64_t)digest.count);
    }
    json_push_kv(out, "coins", &coins);
    json_free(&coins);

    struct json_value clusterj;
    json_init(&clusterj);
    json_set_object(&clusterj);
    json_push_kv_int(&clusterj, "delivery_fingerprint",
                     (int64_t)simnet_cluster_delivery_fingerprint(cluster));
    json_push_kv_int(&clusterj, "byzantine_rejected",
                     (int64_t)simnet_cluster_byzantine_rejected(cluster));
    json_push_kv(out, "cluster", &clusterj);
    json_free(&clusterj);

    return have_tip && have_height && have_digest;
}

bool simnet_trace_write_event(struct simnet_trace_writer *w,
                              struct simnet_cluster *cluster,
                              size_t node_count, uint64_t seq,
                              const char *event)
{
    if (!w || !w->fp || !cluster || !event)
        return false;

    for (size_t i = 0; i < node_count; i++) {
        struct json_value line;
        json_init(&line);
        bool ok = simnet_trace_node_snapshot(&line, cluster, i, seq, event);

        char buf[1024];
        size_t need = json_write(&line, buf, sizeof(buf));
        json_free(&line);
        if (!ok || need >= sizeof(buf)) {
            LOG_FAIL("simnet.trace",
                     "snapshot failed or too long node=%zu event=%s ok=%d "
                     "need=%zu",
                     i, event, (int)ok, need);
        }
        if (fputs(buf, w->fp) < 0 || fputc('\n', w->fp) < 0)
            return false;
    }
    return fflush(w->fp) == 0;
}

void simnet_trace_writer_close(struct simnet_trace_writer *w)
{
    if (!w || !w->fp)
        return;
    fclose(w->fp);
    w->fp = NULL;
}
