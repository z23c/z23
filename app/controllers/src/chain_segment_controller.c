/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * chain_segment_controller — the ops surface over the sealed ROM segment
 * store (lib/storage/chain_segment). Two RPC actions:
 *
 *   sealsegments {first_height, count}  seal a height range from the node's
 *                                       on-disk block bodies into <datadir>/segments
 *   verifysegments {}                   full digest-verify every segment vs manifest
 *
 * plus the `chain_segments` dumpstate subsystem. The store organ itself is
 * pure; this controller supplies the disk-backed body source and the segments
 * directory. Fold read-path wiring and P2P re-fetch are a later wave.
 */

#include "controllers/chain_segment_controller.h"
#include "controllers/blockchain_controller.h"
#include "controllers/strong_params.h"
#include "blockchain_controller_internal.h"

#include "base/hex.h"
#include "chain/chain.h"
#include "core/serialize.h"
#include "json/json.h"
#include "primitives/block.h"
#include "storage/block_parse_cache.h"
#include "storage/chain_segment.h"
#include "storage/disk_block_io.h"
#include "rpc/server.h"
#include "util/file_tree_ops.h"
#include "util/log_macros.h"
#include "util/result.h"
#include "util/safe_alloc.h"
#include "util/util.h"
#include "validation/main_state.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void segments_dir(char *buf, size_t buflen)
{
    char datadir[2048];
    GetDataDir(true, datadir, sizeof(datadir));
    snprintf(buf, buflen, "%s/segments", datadir);
}

/* Disk-backed body source: raw serialized bytes of the block at `height`,
 * pulled from the active chain's persisted body. Fails (returns false) when the
 * height is not on the active chain, has no BLOCK_HAVE_DATA, or won't read —
 * which makes seal_range fail closed on that height. */
struct seal_body_ctx {
    struct main_state *ms;
    const char *datadir;
};

static bool seal_body_read(void *user, uint32_t height,
                           uint8_t **bytes, size_t *len)
{
    struct seal_body_ctx *c = user;
    *bytes = NULL; *len = 0;

    struct block_index *bi = active_chain_at(&c->ms->chain_active, (int)height);
    if (!bi || !bi->phashBlock ||
        !(block_index_status_load(bi) & BLOCK_HAVE_DATA))
        return false;

    struct block blk;
    block_init(&blk);
    if (!read_block_from_disk_index_pread(&blk, bi, c->datadir)) {
        block_free(&blk);
        return false;
    }

    struct byte_stream s;
    stream_init(&s, 4096);
    if (!block_serialize(&blk, &s) || s.size == 0) {
        stream_free(&s);
        block_free(&blk);
        return false;
    }

    uint8_t *copy = zcl_malloc(s.size, "chain_segment/body");
    if (copy) {
        memcpy(copy, s.data, s.size);
        *bytes = copy;
        *len = s.size;
    }
    stream_free(&s);
    block_free(&blk);
    return copy != NULL;
}

bool rpc_sealsegments(const struct json_value *params, bool help,
                      struct json_value *result)
{
    RPC_HELP(help, result,
             "sealsegments first_height count\n"
             "Seal a finalized block-body range into the immutable segment "
             "store under <datadir>/segments and rebuild the manifest.");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 2, 2);
    int64_t first = rpc_require_int(&p, 0, "first_height");
    int64_t count = rpc_require_int(&p, 1, "count");
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        LOG_FAIL("chain_segment", "sealsegments: invalid params");
    }
    if (first < 0 || count <= 0) {
        json_set_object(result);
        json_push_kv_str(result, "error", "first_height>=0 and count>0 required");
        LOG_FAIL("chain_segment", "sealsegments: first=%lld count=%lld",
                 (long long)first, (long long)count);
    }

    struct blockchain_context *ctx = blockchain_ctx();
    if (!ctx || !ctx->main_state || !ctx->datadir) {
        json_set_object(result);
        json_push_kv_str(result, "error", "node not initialized");
        LOG_FAIL("chain_segment", "sealsegments: main_state/datadir null");
    }

    char dir[2560];
    segments_dir(dir, sizeof(dir));
    struct zcl_result mk = zcl_mkdir_p(dir, 0755);
    if (!mk.ok) {
        json_set_object(result);
        json_push_kv_str(result, "error", "cannot create segments dir");
        LOG_FAIL("chain_segment", "sealsegments: mkdir %s: %s", dir, mk.message);
    }

    struct seal_body_ctx bctx = { .ms = ctx->main_state, .datadir = ctx->datadir };
    char err[256] = {0};
    enum cseg_status st = chain_segment_seal_range(dir, seal_body_read, &bctx,
                                                   (uint32_t)first,
                                                   (uint32_t)count, err, sizeof(err));

    json_set_object(result);
    json_push_kv_bool(result, "ok", st == CSEG_OK);
    json_push_kv_str(result, "status", cseg_status_str(st));
    json_push_kv_int(result, "first_height", first);
    json_push_kv_int(result, "count", count);
    if (st != CSEG_OK) {
        json_push_kv_str(result, "error", err);
        LOG_FAIL("chain_segment", "sealsegments: %s (%s)",
                 cseg_status_str(st), err);
    }
    return true;
}

bool rpc_verifysegments(const struct json_value *params, bool help,
                        struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
             "verifysegments\n"
             "Full digest-verify every sealed segment against the manifest.");

    char dir[2560];
    segments_dir(dir, sizeof(dir));

    struct chain_segment_stat stt;
    char err[256] = {0};
    enum cseg_status st = chain_segment_store_stat(dir, true, &stt, err, sizeof(err));

    json_set_object(result);
    json_push_kv_bool(result, "ok", st == CSEG_OK);
    json_push_kv_str(result, "status", cseg_status_str(st));
    json_push_kv_int(result, "segment_count", stt.segment_count);
    json_push_kv_int(result, "verified_count", stt.verified_count);
    if (stt.have_range) {
        json_push_kv_int(result, "min_height", stt.min_height);
        json_push_kv_int(result, "max_height", stt.max_height);
    }
    char root[65];
    zcl_hex_encode(stt.manifest_root, 32, root);
    json_push_kv_str(result, "manifest_root", root);
    if (st != CSEG_OK) {
        json_push_kv_str(result, "error", err);
        LOG_FAIL("chain_segment", "verifysegments: %s (%s)",
                 cseg_status_str(st), err);
    }
    return true;
}

bool chain_segment_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);

    char dir[2560];
    segments_dir(dir, sizeof(dir));
    json_push_kv_str(out, "segments_dir", dir);

    /* Fold read-source counters — proves the substrate is actually used:
     * how often block_parse_cache's miss path was served from a sealed
     * segment vs fell through to blk*.dat. Emitted unconditionally (before
     * the store-stat early return) because they describe the reader, not the
     * store. See storage/block_parse_cache.h. */
    uint64_t seg_hits = 0, blkdat_reads = 0;
    block_parse_cache_segment_read_stats(&seg_hits, &blkdat_reads);
    json_push_kv_int(out, "fold_reads_from_segment", (int64_t)seg_hits);
    json_push_kv_int(out, "fold_reads_from_blk_dat", (int64_t)blkdat_reads);
    uint64_t total_reads = seg_hits + blkdat_reads;
    json_push_kv_int(out, "fold_reads_total", (int64_t)total_reads);
    /* Ratio as a 0..10000 basis-points integer (json has no float pusher
     * here) so a dumpstate consumer can compute a percentage without
     * dividing by zero client-side. */
    int64_t hit_ratio_bp = total_reads
        ? (int64_t)((seg_hits * 10000ull) / total_reads) : 0;
    json_push_kv_int(out, "fold_reads_segment_hit_ratio_bp", hit_ratio_bp);

    /* Cheap dump: manifest summary + present-file check, no full re-hash. The
     * `verifysegments` action does the O(store) digest pass. */
    struct chain_segment_stat stt;
    char err[256] = {0};
    enum cseg_status st = chain_segment_store_stat(dir, false, &stt, err, sizeof(err));

    json_push_kv_str(out, "status", cseg_status_str(st));
    if (st != CSEG_OK) {
        json_push_kv_str(out, "error", err);
        return true;
    }
    json_push_kv_int(out, "segment_count", stt.segment_count);
    json_push_kv_int(out, "present_count", stt.verified_count);
    json_push_kv_bool(out, "full_verified", false);
    if (stt.have_range) {
        json_push_kv_int(out, "min_height", stt.min_height);
        json_push_kv_int(out, "max_height", stt.max_height);
    }
    char root[65];
    zcl_hex_encode(stt.manifest_root, 32, root);
    json_push_kv_str(out, "manifest_root", root);
    return true;
}

void register_chain_segment_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "control", "sealsegments",   rpc_sealsegments,   false },
        { "control", "verifysegments", rpc_verifysegments, true },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
