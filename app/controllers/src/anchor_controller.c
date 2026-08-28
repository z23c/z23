/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Anchors (ZANC) RPC controller — anchor software/package digests into
 * the chain via OP_RETURN and verify a file/digest against the immutable
 * on-chain record. Follows the name_controller (ZNAM) compose+return shape:
 * with a wallet loaded, anchor_publish composes and broadcasts a tx carrying
 * the ZANC OP_RETURN; with no wallet it returns the OP_RETURN hex for manual
 * inclusion (the branch the unit tests exercise — no broadcast). */

#include "controllers/anchor_controller.h"
#include "controllers/strong_params.h"
#include "models/zanc.h"
#include "zanc/zanc.h"
#include "json/json.h"
#include "encoding/utilstrencodings.h"
#include "crypto/sha256.h"
#include "crypto/sha3.h"
#include "wallet/wallet.h"
#include "validation/txmempool.h"
#include "chain/chainparams.h"
#include "services/zslp_command_service.h"
#include "jobs/reducer_frontier.h"
#include "util/log_macros.h"

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

/* ── Context ────────────────────────────────────────────────────── */

static struct node_db *g_anchor_ndb = NULL;
static struct wallet *g_anchor_wallet = NULL;
static struct tx_mempool *g_anchor_mempool = NULL;
static struct main_state *g_anchor_main_state = NULL;
static struct coins_view_cache *g_anchor_coins_tip = NULL;

void rpc_anchor_set_state(struct node_db *ndb)
{
    g_anchor_ndb = ndb;
}

void rpc_anchor_set_wallet(struct wallet *w, struct tx_mempool *mp,
                           struct main_state *main_state,
                           struct coins_view_cache *coins_tip)
{
    g_anchor_wallet = w;
    g_anchor_mempool = mp;
    g_anchor_main_state = main_state;
    g_anchor_coins_tip = coins_tip;
}

/* ── Input helpers (object-or-positional) ───────────────────────── */

/* Read a string field: params[0] as a JSON object {key: ...} (the --input
 * form) if present, else the positional arg at idx. Returns NULL if absent. */
static const char *anchor_str_field(const struct json_value *params,
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

static int64_t anchor_int_field(const struct json_value *params,
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

/* "sha2"/"sha2-256"/"1" → SHA2, "sha3"/"sha3-256"/"2" → SHA3, else 0. */
static uint8_t parse_hash_type(const char *s)
{
    if (!s || !s[0]) return 0;
    if (strcmp(s, "sha2") == 0 || strcmp(s, "sha2-256") == 0 ||
        strcmp(s, "sha256") == 0 || strcmp(s, "1") == 0)
        return ZANC_HASH_SHA2_256;
    if (strcmp(s, "sha3") == 0 || strcmp(s, "sha3-256") == 0 ||
        strcmp(s, "2") == 0)
        return ZANC_HASH_SHA3_256;
    return 0;
}

/* ── Digest helpers ─────────────────────────────────────────────── */

/* SHA2-256 and SHA3-256 of a file, computed in one streaming pass. Reads
 * through an fd (race-free: the open image is hashed, not a re-resolved
 * path). Returns false and fills err on any I/O failure. */
static bool hash_fd(int fd, uint8_t sha2[32], uint8_t sha3[32])
{
    struct sha256_ctx c2;
    struct sha3_256_ctx c3;
    sha256_init(&c2);
    sha3_256_init(&c3);
    uint8_t buf[32768];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            sha256_write(&c2, buf, (size_t)n);
            sha3_256_write(&c3, buf, (size_t)n);
            continue;
        }
        if (n == 0) break;
        if (errno == EINTR) continue;
        return false;
    }
    sha256_finalize(&c2, sha2);
    sha3_256_finalize(&c3, sha3);
    return true;
}

static bool hash_file(const char *path, uint8_t sha2[32], uint8_t sha3[32])
{
    if (!path || !path[0]) return false;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        LOG_RETURN(false, "zanc", "hash_file: open %s failed: %s",
                   path, strerror(errno));
    bool ok = hash_fd(fd, sha2, sha3);
    close(fd);
    return ok;
}

/* SHA2-256 and SHA3-256 of the running executable via /proc/self/exe. */
static bool hash_self_exe(uint8_t sha2[32], uint8_t sha3[32])
{
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        LOG_RETURN(false, "zanc", "hash_self_exe: open failed: %s",
                   strerror(errno));
    bool ok = hash_fd(fd, sha2, sha3);
    close(fd);
    return ok;
}

static int64_t anchor_confirmations(int32_t anchor_height)
{
    int32_t tip = reducer_frontier_provable_tip_cached();
    if (tip < 0 || tip < anchor_height) return 0;
    return (int64_t)(tip - anchor_height + 1);
}

static void anchor_to_json(const struct zanc_anchor *a, struct json_value *obj)
{
    json_set_object(obj);
    char hex[65];
    HexStr(a->txid, 32, false, hex, sizeof(hex));
    json_push_kv_str(obj, "txid", hex);
    json_push_kv_int(obj, "height", a->height);
    json_push_kv_int(obj, "confirmations", anchor_confirmations(a->height));
    json_push_kv_int(obj, "hash_type", a->hash_type);
    json_push_kv_str(obj, "hash_type_name", zanc_hash_type_name(a->hash_type));
    HexStr(a->digest, 32, false, hex, sizeof(hex));
    json_push_kv_str(obj, "digest", hex);
    json_push_kv_str(obj, "label", a->label);
}

/* Emit a hit/miss verification record for one (hash_type,digest) pair. */
static void emit_lookup(uint8_t hash_type, const uint8_t digest[32],
                        struct json_value *obj)
{
    json_set_object(obj);
    json_push_kv_int(obj, "hash_type", hash_type);
    json_push_kv_str(obj, "hash_type_name", zanc_hash_type_name(hash_type));
    char hex[65];
    HexStr(digest, 32, false, hex, sizeof(hex));
    json_push_kv_str(obj, "digest", hex);

    struct zanc_anchor a;
    if (g_anchor_ndb && db_zanc_find_by_digest(g_anchor_ndb, hash_type,
                                               digest, &a)) {
        json_push_kv_bool(obj, "anchored", true);
        HexStr(a.txid, 32, false, hex, sizeof(hex));
        json_push_kv_str(obj, "txid", hex);
        json_push_kv_int(obj, "height", a.height);
        json_push_kv_int(obj, "confirmations", anchor_confirmations(a.height));
        json_push_kv_str(obj, "label", a.label);
    } else {
        json_push_kv_bool(obj, "anchored", false);
    }
}

/* ── anchor_publish ─────────────────────────────────────────────── */

static bool rpc_anchor_publish(const struct json_value *params, bool help,
                               struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "anchor_publish {\"file\":path | \"digest\":hex, "
            "\"hash_type\":\"sha3\"|\"sha2\", \"label\":\"name@version\"}\n"
            "\nAnchor a software/package digest into the chain via OP_RETURN.\n"
            "Give a file to hash, or a 64-hex-char digest. hash_type defaults\n"
            "to sha3. With no wallet loaded, returns the OP_RETURN hex.\n");
        return true;
    }

    const char *ht_str = anchor_str_field(params, 3, "hash_type");
    uint8_t hash_type = ht_str ? parse_hash_type(ht_str) : ZANC_HASH_SHA3_256;
    if (hash_type == 0) {
        json_set_str(result, "Invalid hash_type (use sha2 or sha3)");
        return false;
    }

    const char *label = anchor_str_field(params, 2, "label");
    if (label && !zanc_label_valid(label, strlen(label))) {
        json_set_str(result,
            "Invalid label (<=32 bytes, printable UTF-8)");
        return false;
    }

    uint8_t digest[32];
    const char *file = anchor_str_field(params, 0, "file");
    const char *digest_hex = anchor_str_field(params, 1, "digest");
    if (file) {
        uint8_t sha2[32], sha3[32];
        if (!hash_file(file, sha2, sha3)) {
            json_set_str(result, "Failed to read/hash file");
            return false;
        }
        memcpy(digest, hash_type == ZANC_HASH_SHA2_256 ? sha2 : sha3, 32);
    } else if (digest_hex) {
        if (strlen(digest_hex) != 64 || !IsHex(digest_hex) ||
            ParseHex(digest_hex, digest, sizeof(digest)) != 32) {
            json_set_str(result, "Invalid digest (need 64 hex chars)");
            return false;
        }
    } else {
        json_set_str(result, "Missing file or digest");
        return false;
    }

    uint8_t script[128];
    size_t script_len = zanc_build_anchor(script, sizeof(script), hash_type,
                                          digest, label);
    if (script_len == 0) {
        json_set_str(result, "Failed to build OP_RETURN script");
        return false;
    }

    char digest_out[65];
    HexStr(digest, 32, false, digest_out, sizeof(digest_out));

    if (g_anchor_wallet && g_anchor_mempool) {
        struct wallet_tx wtx;
        memset(&wtx, 0, sizeof(wtx));
        int64_t fee_paid = 0;
        const char *tx_error = NULL;
        if (!zslp_command_build_genesis_base_tx(g_anchor_wallet, &wtx,
                                                &fee_paid, &tx_error).ok) {
            json_set_str(result, tx_error ? tx_error :
                         "Failed to build transaction");
            return false;
        }
        struct wallet_tx_admission admission = {
            .mempool = g_anchor_mempool,
            .coins_tip = g_anchor_coins_tip,
            .main_state = g_anchor_main_state,
            .params = chain_params_get(),
        };
        struct zcl_result commit = zslp_command_commit_with_op_return(
            g_anchor_wallet, &wtx, &admission, script, script_len);
        if (!commit.ok) {
            json_set_str(result, commit.message);
            transaction_free(&wtx.tx);
            LOG_FAIL("zanc", "anchor_publish: commit failed (code=%d): %s",
                     commit.code, commit.message);
        }

        json_set_object(result);
        json_push_kv_str(result, "hash_type", zanc_hash_type_name(hash_type));
        json_push_kv_str(result, "digest", digest_out);
        json_push_kv_str(result, "label", label ? label : "");
        char txid_hex[65];
        uint256_get_hex(&wtx.tx.hash, txid_hex);
        json_push_kv_str(result, "txid", txid_hex);
        json_push_kv_int(result, "fee", fee_paid);
        json_push_kv_str(result, "status", "broadcast");
        return true;
    }

    json_set_object(result);
    json_push_kv_str(result, "hash_type", zanc_hash_type_name(hash_type));
    json_push_kv_str(result, "digest", digest_out);
    json_push_kv_str(result, "label", label ? label : "");
    char hex[257];
    HexStr(script, script_len, false, hex, sizeof(hex));
    json_push_kv_str(result, "op_return_hex", hex);
    json_push_kv_int(result, "op_return_size", (int64_t)script_len);
    json_push_kv_str(result, "status", "ready");
    json_push_kv_str(result, "note",
        "Wallet not loaded. Include this OP_RETURN as vout[0] manually.");
    return true;
}

/* ── anchor_verify ──────────────────────────────────────────────── */

static bool rpc_anchor_verify(const struct json_value *params, bool help,
                              struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "anchor_verify {\"file\":path | \"digest\":hex "
            "[, \"hash_type\":\"sha3\"|\"sha2\"]}\n"
            "\nRecompute a file's SHA2-256 and SHA3-256 (or take a digest) and\n"
            "report whether it is anchored on-chain, with txid/height/confs.\n");
        return true;
    }

    const char *file = anchor_str_field(params, 0, "file");
    const char *digest_hex = anchor_str_field(params, 1, "digest");
    const char *ht_str = anchor_str_field(params, 2, "hash_type");

    json_set_object(result);
    struct json_value matches = {0};
    json_set_array(&matches);
    bool any_anchored = false;

    if (file) {
        uint8_t sha2[32], sha3[32];
        if (!hash_file(file, sha2, sha3)) {
            json_free(&matches);
            json_set_str(result, "Failed to read/hash file");
            return false;
        }
        char hex[65];
        HexStr(sha2, 32, false, hex, sizeof(hex));
        json_push_kv_str(result, "sha2_256", hex);
        HexStr(sha3, 32, false, hex, sizeof(hex));
        json_push_kv_str(result, "sha3_256", hex);
        struct json_value m2 = {0}, m3 = {0};
        emit_lookup(ZANC_HASH_SHA2_256, sha2, &m2);
        emit_lookup(ZANC_HASH_SHA3_256, sha3, &m3);
        const struct json_value *a2 = json_get(&m2, "anchored");
        const struct json_value *a3 = json_get(&m3, "anchored");
        any_anchored = (a2 && json_get_bool(a2)) || (a3 && json_get_bool(a3));
        json_push_back(&matches, &m2);
        json_push_back(&matches, &m3);
        json_free(&m2);
        json_free(&m3);
    } else if (digest_hex) {
        uint8_t digest[32];
        if (strlen(digest_hex) != 64 || !IsHex(digest_hex) ||
            ParseHex(digest_hex, digest, sizeof(digest)) != 32) {
            json_free(&matches);
            json_set_str(result, "Invalid digest (need 64 hex chars)");
            return false;
        }
        uint8_t want = ht_str ? parse_hash_type(ht_str) : 0;
        for (uint8_t t = ZANC_HASH_SHA2_256; t <= ZANC_HASH_SHA3_256; t++) {
            if (want && t != want) continue;
            struct json_value m = {0};
            emit_lookup(t, digest, &m);
            const struct json_value *an = json_get(&m, "anchored");
            if (an && json_get_bool(an)) any_anchored = true;
            json_push_back(&matches, &m);
            json_free(&m);
        }
    } else {
        json_free(&matches);
        json_set_str(result, "Missing file or digest");
        return false;
    }

    json_push_kv_bool(result, "anchored", any_anchored);
    json_push_kv(result, "matches", &matches);
    json_free(&matches);
    return true;
}

/* ── anchor_list ────────────────────────────────────────────────── */

#define ANCHOR_LIST_CAP 100

static bool rpc_anchor_list(const struct json_value *params, bool help,
                            struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "anchor_list [{\"limit\":N}]\n"
            "\nList recent ZANC anchors, newest first (limit<=100).\n");
        return true;
    }

    int64_t limit = anchor_int_field(params, 0, "limit", 20);
    if (limit < 1) limit = 1;
    if (limit > ANCHOR_LIST_CAP) limit = ANCHOR_LIST_CAP;

    struct zanc_anchor rows[ANCHOR_LIST_CAP];
    int count = g_anchor_ndb ? db_zanc_list(g_anchor_ndb, rows, (size_t)limit)
                             : 0;

    json_set_object(result);
    json_push_kv_int(result, "limit", limit);
    struct json_value arr = {0};
    json_set_array(&arr);
    for (int i = 0; i < count; i++) {
        struct json_value e = {0};
        anchor_to_json(&rows[i], &e);
        json_push_back(&arr, &e);
        json_free(&e);
    }
    json_push_kv(result, "anchors", &arr);
    json_push_kv_int(result, "count", count);
    json_free(&arr);
    return true;
}

/* ── anchor_self ────────────────────────────────────────────────── */

static bool rpc_anchor_self(const struct json_value *params, bool help,
                            struct json_value *result)
{
    (void)params;
    if (help) {
        json_set_str(result,
            "anchor_self\n"
            "\nDigest the running binary (/proc/self/exe) with SHA2-256 and\n"
            "SHA3-256 and report whether it is anchored on-chain.\n");
        return true;
    }

    uint8_t sha2[32], sha3[32];
    if (!hash_self_exe(sha2, sha3)) {
        json_set_str(result, "Failed to digest running binary");
        return false;
    }

    json_set_object(result);
    char hex[65];
    HexStr(sha2, 32, false, hex, sizeof(hex));
    json_push_kv_str(result, "sha2_256", hex);
    HexStr(sha3, 32, false, hex, sizeof(hex));
    json_push_kv_str(result, "sha3_256", hex);

    struct json_value matches = {0};
    json_set_array(&matches);
    struct json_value m2 = {0}, m3 = {0};
    emit_lookup(ZANC_HASH_SHA2_256, sha2, &m2);
    emit_lookup(ZANC_HASH_SHA3_256, sha3, &m3);
    const struct json_value *a2 = json_get(&m2, "anchored");
    const struct json_value *a3 = json_get(&m3, "anchored");
    bool anchored = (a2 && json_get_bool(a2)) || (a3 && json_get_bool(a3));
    json_push_back(&matches, &m2);
    json_push_back(&matches, &m3);
    json_free(&m2);
    json_free(&m3);

    json_push_kv_bool(result, "anchored", anchored);
    json_push_kv(result, "matches", &matches);
    json_free(&matches);
    return true;
}

/* ── Registration ───────────────────────────────────────────────── */

void register_anchor_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "anchor", "anchor_publish", rpc_anchor_publish, true },
        { "anchor", "anchor_verify",  rpc_anchor_verify,  true },
        { "anchor", "anchor_list",    rpc_anchor_list,    true },
        { "anchor", "anchor_self",    rpc_anchor_self,    true },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
