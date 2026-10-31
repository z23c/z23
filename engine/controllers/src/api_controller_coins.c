/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* GET /api/v1/coins/roots: boundary coin roots for cross-node comparison.
 *
 * Each entry is a block-bound record ("coin_root_v2", coins_kv.h): the hash of
 * the block at the boundary height and the SHA3 commitment of the coins set
 * after exactly that block. A record exists only when tip_finalize saw the
 * applied frontier equal to height + 1; boundaries finalized while utxo_apply
 * had run ahead, or skipped during catch-up, are not recorded and appear as
 * found=false. Rows of the older "mmb_utxo_root" store are never served.
 *
 * Roots are in internal byte order: the hex string lists the stored bytes
 * first to last, the order of the g_sha3_checkpoint.sha3_hash array. Block
 * hashes are in display order. A record whose block hash differs from the
 * active chain's block at that height (after a reorg) is returned with
 * on_active_chain=false and must not be compared; when the window holds no
 * block at that height the entry carries active_chain_unknown=true instead.
 *
 * Equal roots with equal block hashes show that two nodes hold the same coin
 * set after that block. They do not by themselves prove the set correct, and
 * this route cannot say how either node was built. */

#include "api_controller_coins.h"

#include "api_controller_internal.h"
#include "chain/mmr.h"
#include "controllers/agent_security_posture.h"
#include "core/uint256.h"
#include "encoding/utilstrencodings.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "validation/main_state.h"

#include <ctype.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COIN_ROOTS_SCHEMA "zcl.coin_roots.v1"
#define COIN_ROOTS_DEFAULT_COUNT 10
#define COIN_ROOTS_MAX_COUNT 100

#define COIN_ROOTS_400_HEADERS \
    "HTTP/1.1 400 Bad Request\r\n" \
    "Content-Type: application/json; charset=utf-8\r\n" \
    "Access-Control-Allow-Origin: *\r\n" \
    "Connection: close\r\n\r\n"

struct coin_roots_query {
    size_t count;
    bool has_height;
    int32_t height;
};

/* Value of `key` in the query string, or NULL. Keys match whole names. */
static const char *coin_roots_query_value(const char *query, const char *key)
{
    size_t klen = strlen(key);
    for (const char *p = query; p && *p;) {
        p++; /* skip '?' or '&' */
        if (strncmp(p, key, klen) == 0 && p[klen] == '=')
            return p + klen + 1;
        p = strchr(p, '&');
    }
    return NULL;
}

/* Strict decimal parse of a whole parameter value in [0, max]. */
static bool coin_roots_parse_number(const char *value, long max, long *out)
{
    char *end = NULL;
    if (!value || !isdigit((unsigned char)*value))
        return false;
    long v = strtol(value, &end, 10);
    if (!end || (*end != '\0' && *end != '&') || v < 0 || v > max)
        return false;
    *out = v;
    return true;
}

static const char *coin_roots_parse_query(const char *path,
                                          struct coin_roots_query *q)
{
    const char *query = strchr(path, '?');
    long v = 0;
    q->count = COIN_ROOTS_DEFAULT_COUNT;
    q->has_height = false;
    q->height = 0;
    const char *count = coin_roots_query_value(query, "count");
    if (count) {
        if (!coin_roots_parse_number(count, COIN_ROOTS_MAX_COUNT, &v) ||
            v < 1)
            return "count must be an integer from 1 to 100";
        q->count = (size_t)v;
    }
    const char *height = coin_roots_query_value(query, "height");
    if (height) {
        if (!coin_roots_parse_number(height, INT32_MAX, &v) ||
            v % MMR_COMMITMENT_INTERVAL != 0)
            return "height must be a non-negative multiple of 100";
        q->has_height = true;
        q->height = (int32_t)v;
    }
    return NULL;
}

/* Display-order hex of a stored internal-order block hash. */
static void coin_roots_hash_hex(const uint8_t hash[32], char hex[65])
{
    struct uint256 h;
    memcpy(h.data, hash, 32);
    uint256_get_hex(&h, hex);
}

/* Push the record's chain position: on_active_chain true or false, or
 * active_chain_unknown when the window holds no block at that height. */
static void coin_roots_push_chain_state(struct json_value *entry,
                                        struct main_state *ms, int32_t height,
                                        const uint8_t hash[32])
{
    const struct block_index *bi = active_chain_at(&ms->chain_active, height);
    if (!bi || !bi->phashBlock) {
        json_push_kv_bool(entry, "active_chain_unknown", true);
        return;
    }
    json_push_kv_bool(entry, "on_active_chain",
                      memcmp(bi->phashBlock->data, hash, 32) == 0);
}

/* Push one entry. False only on a store read error (never absence). */
static bool coin_roots_push_entry(struct json_value *roots, sqlite3 *db,
                                  struct main_state *ms, int32_t tip,
                                  int32_t height)
{
    uint8_t hash[32], root[32];
    bool found = false;
    struct json_value entry;
    json_init(&entry);
    json_set_object(&entry);
    json_push_kv_int(&entry, "height", height);
    if (height > tip) {
        json_push_kv_bool(&entry, "found", false);
        json_push_kv_bool(&entry, "above_tip", true);
    } else if (!coins_kv_boundary_record_get(db, height, hash, root, &found)) {
        LOG_WARN("api", "coin_roots: boundary record read failed h=%d",
                 (int)height);
        json_free(&entry);
        return false;
    } else {
        json_push_kv_bool(&entry, "found", found);
        if (found) {
            char hex[65];
            HexStr(root, 32, false, hex, sizeof(hex));
            json_push_kv_str(&entry, "root", hex);
            coin_roots_hash_hex(hash, hex);
            json_push_kv_str(&entry, "block_hash", hex);
            coin_roots_push_chain_state(&entry, ms, height, hash);
        }
    }
    json_push_back(roots, &entry);
    json_free(&entry);
    return true;
}

/* Newest boundaries at or below the tip, descending; or the one requested. */
static bool coin_roots_collect(struct json_value *roots, sqlite3 *db,
                               struct main_state *ms, int32_t tip,
                               const struct coin_roots_query *q)
{
    if (q->has_height)
        return coin_roots_push_entry(roots, db, ms, tip, q->height);
    int32_t top = tip - tip % MMR_COMMITMENT_INTERVAL;
    for (size_t i = 0; i < q->count && top > 0; i++) {
        if (!coin_roots_push_entry(roots, db, ms, tip, top))
            return false; // raw-return-ok:push_entry logged the failure
        top -= MMR_COMMITMENT_INTERVAL;
    }
    return true;
}

static void coin_roots_push_header(struct json_value *body, struct main_state *ms,
                                   int32_t tip)
{
    char hash_hex[65] = "";
    const struct block_index *bi = active_chain_at(&ms->chain_active, tip);
    struct agent_security_posture posture = {0};
    if (bi && bi->phashBlock)
        uint256_get_hex(bi->phashBlock, hash_hex);
    json_push_kv_str(body, "root_byte_order", "internal");
    json_push_kv_str(body, "hash_byte_order", "display");
    json_push_kv_int(body, "boundary_interval", MMR_COMMITMENT_INTERVAL);
    json_push_kv_int(body, "tip_height", tip);
    json_push_kv_str(body, "tip_hash", hash_hex);
    agent_security_posture_collect(&posture, api_node_db());
    json_push_kv_str(body, "full_history_validation_origin",
                     posture.full_history_validation_origin);
    json_push_kv_bool(body, "snapshot_utxo_sha3_verified",
                      posture.snapshot_utxo_sha3_verified);
    json_push_kv_str(body, "comparison_note",
                     "Equal roots at equal block_hash show that two nodes hold "
                     "the same coin set after that block. They do not prove the "
                     "set correct, and this route cannot say how a node was "
                     "built. Ignore entries with on_active_chain=false or "
                     "active_chain_unknown.");
}

size_t api_serve_coin_roots(const char *path, uint8_t *response,
                            size_t response_max)
{
    struct coin_roots_query q;
    const char *bad = coin_roots_parse_query(path, &q);
    if (bad)
        return api_json_error(response, response_max, COIN_ROOTS_400_HEADERS,
                              bad);

    sqlite3 *db = progress_store_db();
    struct main_state *ms = g_api_ctx.main_state;
    if (!db || !ms)
        return api_json_error(response, response_max, JSON_503_HEADERS,
                              "Progress store or chain state is not open; "
                              "coin roots are unavailable until the node "
                              "finishes opening them");
    if (!progress_store_tx_trylock())
        return api_json_error(response, response_max, JSON_503_HEADERS,
                              "Progress store is busy with a reducer batch; "
                              "retry shortly");

    int32_t tip = reducer_frontier_provable_tip_cached();
    struct json_value roots;
    json_init(&roots);
    json_set_array(&roots);
    bool ok = coin_roots_collect(&roots, db, ms, tip, &q);
    progress_store_tx_unlock();
    if (!ok) {
        json_free(&roots);
        return api_json_error(response, response_max, JSON_500_HEADERS,
                              "Coin root store read failed; the record is "
                              "unreadable, which is not the same as absent");
    }

    struct json_value body;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", COIN_ROOTS_SCHEMA);
    api_json_add_freshness(&body, "coin_root_boundaries", tip);
    coin_roots_push_header(&body, ms, tip);
    json_push_kv(&body, "roots", &roots);
    json_free(&roots);

    size_t n = api_json_ok(response, response_max, &body);
    json_free(&body);
    return n;
}
