/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * OP_RETURN catalog RPC controller — see controllers/op_return_index_
 * controller.h. Read-only surface over the op_return_index projection
 * (engine/models/src/op_return_index.c); oprindex_rebuild is the only
 * mutating command, and it only ever deletes/resets a rebuildable
 * projection — never consensus state. Follows the anchor_controller.c
 * (ZANC) compose+return shape. */

#include "controllers/op_return_index_controller.h"
#include "models/op_return_index.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "encoding/utilstrencodings.h"
#include "util/log_macros.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ── Context ────────────────────────────────────────────────────── */

static struct node_db *g_oprindex_ndb = NULL;

void rpc_op_return_index_set_state(struct node_db *ndb)
{
    g_oprindex_ndb = ndb;
}

/* ── Input helpers (object-or-positional), mirroring anchor_controller.c */

static const char *oprindex_str_field(const struct json_value *params,
                                      size_t idx, const char *key)
{
    if (!params) return NULL;
    const struct json_value *p0 = json_size(params) > 0 ? json_at(params, 0)
                                                        : NULL;
    if (p0 && p0->type == JSON_OBJ) {
        const struct json_value *v = json_get(p0, key);
        return (v && v->type == JSON_STR) ? json_get_str(v) : NULL;
    }
    const struct json_value *v = json_size(params) > idx ? json_at(params, idx)
                                                         : NULL;
    return (v && v->type == JSON_STR) ? json_get_str(v) : NULL;
}

static int64_t oprindex_int_field(const struct json_value *params,
                                  size_t idx, const char *key, int64_t def)
{
    if (!params) return def;
    const struct json_value *p0 = json_size(params) > 0 ? json_at(params, 0)
                                                        : NULL;
    if (p0 && p0->type == JSON_OBJ) {
        const struct json_value *v = json_get(p0, key);
        if (!v) return def;
        if (v->type == JSON_INT) return json_get_int(v);
        if (v->type == JSON_STR) return strtoll(json_get_str(v), NULL, 10);
        return def;
    }
    const struct json_value *v = json_size(params) > idx ? json_at(params, idx)
                                                         : NULL;
    if (!v) return def;
    if (v->type == JSON_INT) return json_get_int(v);
    if (v->type == JSON_STR) return strtoll(json_get_str(v), NULL, 10);
    return def;
}

/* ── oprindex_status ────────────────────────────────────────────── */

static bool rpc_oprindex_status(const struct json_value *params, bool help,
                                struct json_value *result)
{
    (void)params;
    if (help) {
        json_set_str(result,
            "oprindex_status\n"
            "\nOP_RETURN catalog projection status: cursor height + running\n"
            "digest, the reducer's provable tip, total cataloged rows, and\n"
            "rows-by-known-tag counts (ZNAM/ZSLP/ZANC/other).\n");
        return true;
    }

    json_set_object(result);
    if (!g_oprindex_ndb || !g_oprindex_ndb->open) {
        json_push_kv_bool(result, "wired", false);
        return true;
    }
    json_push_kv_bool(result, "wired", true);

    struct op_return_index_cursor cur;
    memset(&cur, 0, sizeof(cur));
    cur.height = -1;
    bool have_cursor = op_return_index_get_cursor(g_oprindex_ndb, &cur);
    json_push_kv_str(result, "state_version",
                     op_return_index_state_version_name(
                         op_return_index_state_version(g_oprindex_ndb)));
    json_push_kv_int(result, "cursor_height", have_cursor ? cur.height : -1);
    char digest_hex[65] = {0};
    if (have_cursor) HexStr(cur.digest, 32, false, digest_hex,
                            sizeof(digest_hex));
    json_push_kv_str(result, "cursor_digest", digest_hex);
    /* The digest commits to [base_height, cursor_height] — report the range
     * beside it so no reader assumes a genesis-rooted catalog. */
    json_push_kv_int(result, "base_height",
                     have_cursor ? cur.base_height : -1);
    char base_hex[65] = {0};
    if (have_cursor) HexStr(cur.base_digest, 32, false, base_hex,
                            sizeof(base_hex));
    json_push_kv_str(result, "base_digest", base_hex);
    json_push_kv_bool(result, "partial_coverage",
                      have_cursor && cur.base_height > 0);
    json_push_kv_int(result, "provable_tip",
                     reducer_frontier_provable_tip_cached());

    int64_t total = op_return_index_count(g_oprindex_ndb);
    int64_t znam = op_return_index_count_by_tag_text(g_oprindex_ndb, "ZNAM");
    int64_t zslp = op_return_index_count_by_tag_text(g_oprindex_ndb, "SLP");
    int64_t zanc = op_return_index_count_by_tag_text(g_oprindex_ndb, "ZANC");
    int64_t other = total - znam - zslp - zanc;
    if (other < 0) other = 0;
    json_push_kv_int(result, "total_rows", total);
    json_push_kv_int(result, "znam_rows", znam);
    json_push_kv_int(result, "zslp_rows", zslp);
    json_push_kv_int(result, "zanc_rows", zanc);
    json_push_kv_int(result, "other_rows", other);
    return true;
}

/* ── oprindex_list ──────────────────────────────────────────────── */

#define OPRINDEX_LIST_CAP 100

static void row_to_json(const struct op_return_index_row *r,
                        struct json_value *obj)
{
    json_set_object(obj);
    char hex[65];
    HexStr(r->txid, 32, false, hex, sizeof(hex));
    json_push_kv_str(obj, "txid", hex);
    json_push_kv_int(obj, "vout_n", (int64_t)r->vout_n);
    json_push_kv_int(obj, "height", r->height);
    json_push_kv_str(obj, "tag_text", r->tag_text);
    char tag_hex[2 * OP_RETURN_INDEX_TAG_MAX + 1];
    HexStr(r->tag, r->tag_len, false, tag_hex, sizeof(tag_hex));
    json_push_kv_str(obj, "tag_hex", tag_hex);
    json_push_kv_int(obj, "payload_len", (int64_t)r->payload_len);
    HexStr(r->payload_sha3, 32, false, hex, sizeof(hex));
    json_push_kv_str(obj, "payload_sha3", hex);
}

static bool rpc_oprindex_list(const struct json_value *params, bool help,
                              struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "oprindex_list [{\"tag\":\"ZNAM\", \"height_min\":N, "
            "\"height_max\":N, \"limit\":N}]\n"
            "\nList cataloged OP_RETURN outputs, newest height first\n"
            "(limit<=100). tag filters on tag_text exactly (\"ZNAM\", "
            "\"SLP\", \"ZANC\", or a lowercase-hex tag for unrecognized "
            "lokad ids).\n");
        return true;
    }

    const char *tag = oprindex_str_field(params, 0, "tag");
    int64_t h_min = oprindex_int_field(params, 1, "height_min", 0);
    int64_t h_max = oprindex_int_field(params, 2, "height_max", INT32_MAX);
    int64_t limit = oprindex_int_field(params, 3, "limit", 20);
    if (limit < 1) limit = 1;
    if (limit > OPRINDEX_LIST_CAP) limit = OPRINDEX_LIST_CAP;
    if (h_min < 0) h_min = 0;
    if (h_max > INT32_MAX) h_max = INT32_MAX;
    if (h_max < h_min) h_max = h_min;

    struct op_return_index_row rows[OPRINDEX_LIST_CAP];
    int count = (g_oprindex_ndb && g_oprindex_ndb->open)
        ? op_return_index_query(g_oprindex_ndb, (int32_t)h_min,
                                (int32_t)h_max, tag, rows, (size_t)limit)
        : 0;

    json_set_object(result);
    json_push_kv_int(result, "limit", limit);
    json_push_kv_int(result, "height_min", h_min);
    json_push_kv_int(result, "height_max", h_max);
    struct json_value arr = {0};
    json_set_array(&arr);
    for (int i = 0; i < count; i++) {
        struct json_value e = {0};
        row_to_json(&rows[i], &e);
        json_push_back(&arr, &e);
        json_free(&e);
    }
    json_push_kv(result, "rows", &arr);
    json_push_kv_int(result, "count", count);
    json_free(&arr);
    return true;
}

/* ── oprindex_rebuild ───────────────────────────────────────────── */

static bool rpc_oprindex_rebuild(const struct json_value *params, bool help,
                                 struct json_value *result)
{
    (void)params;
    if (help) {
        json_set_str(result,
            "oprindex_rebuild\n"
            "\nDrop every op_return_index row and reset its cursor/digest\n"
            "to empty. The supervised backfill service "
            "(dumpstate op_return_index) re-derives the whole catalog from\n"
            "block bodies on its next ticks. Non-consensus projection —\n"
            "safe to run any time.\n");
        return true;
    }
    if (!g_oprindex_ndb || !g_oprindex_ndb->open) {
        json_set_str(result, "node.db not open");
        LOG_FAIL("op_return_index", "oprindex_rebuild: node.db not open");
    }
    bool ok = op_return_index_truncate(g_oprindex_ndb);
    json_set_object(result);
    json_push_kv_bool(result, "truncated", ok);
    if (!ok)
        json_push_kv_str(result, "note",
                         "op_return_index_truncate failed - see node.log");
    return ok;
}

/* ── Registration ───────────────────────────────────────────────── */

void register_op_return_index_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "oprindex", "oprindex_status",  rpc_oprindex_status,  true },
        { "oprindex", "oprindex_list",    rpc_oprindex_list,    true },
        { "oprindex", "oprindex_rebuild", rpc_oprindex_rebuild, false },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
