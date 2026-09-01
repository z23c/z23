/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sovereign identity (ZID) RPC controller — anchor / rotate / revoke a
 * 32-byte ed25519 MASTER KEY on-chain through the `ZID\0` OP_RETURN
 * overlay, and resolve one key out of the zid_identities projection.
 *
 * This is the live-node half of `core identity *`
 * (tools/command/native_identity_command.c): the native command prefers
 * these RPCs so the node's own wallet composes and broadcasts, and falls
 * back to emitting op_return_hex itself when nothing answers.
 *
 * Compose+return shape, copied from anchor_controller.c: with a wallet
 * loaded the mutating commands build a base tx, attach the ZID
 * OP_RETURN and broadcast; with NO wallet they return the OP_RETURN hex
 * and status "ready" — that no-wallet branch is the one the unit tests
 * exercise, and nothing here broadcasts in a test.
 *
 * Ownership. rotate/revoke mutate a row that already exists, and
 * explorer_index_apply_zid_overlay will only fold such a mutation when
 * the confirming tx's first input pays the row's recorded
 * owner_address. So the base tx for those two is built with
 * zslp_command_build_owner_base_tx(owner_address) — the same proof,
 * constructed up front. A row with no recorded owner, or a wallet that
 * holds no spendable coin under it, fails closed with NOT_OWNER instead
 * of broadcasting a tx the projection would silently refuse. */

#include "controllers/identity_controller.h"
#include "models/zid_identity.h"
#include "zid/zid_anchor.h"
#include "json/json.h"
#include "encoding/utilstrencodings.h"
#include "wallet/wallet.h"
#include "validation/txmempool.h"
#include "chain/chainparams.h"
#include "services/zslp_command_service.h"
#include "jobs/reducer_frontier.h"
#include "util/log_macros.h"

#include <string.h>
#include <stdio.h>

/* ── Context ────────────────────────────────────────────────────── */

static struct node_db *g_identity_ndb = NULL;
static struct wallet *g_identity_wallet = NULL;
static struct tx_mempool *g_identity_mempool = NULL;
static struct main_state *g_identity_main_state = NULL;
static struct coins_view_cache *g_identity_coins_tip = NULL;

void rpc_identity_set_state(struct node_db *ndb)
{
    g_identity_ndb = ndb;
}

void rpc_identity_set_wallet(struct wallet *w, struct tx_mempool *mp,
                             struct main_state *main_state,
                             struct coins_view_cache *coins_tip)
{
    g_identity_wallet = w;
    g_identity_mempool = mp;
    g_identity_main_state = main_state;
    g_identity_coins_tip = coins_tip;
}

/* ── Input helpers (object-or-positional, anchor_controller shape) ── */

static const char *identity_str_field(const struct json_value *params,
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

/* Exactly 64 hex chars decoding to a non-zero 32-byte key. */
static bool identity_parse_key(const char *hex, uint8_t out[32])
{
    if (!hex || strlen(hex) != 64 || !IsHex(hex)) return false;
    if (ParseHex(hex, out, 32) != 32) return false;
    for (int i = 0; i < 32; i++)
        if (out[i]) return true;
    return false;
}

static void identity_row_json(const struct zid_identity *r,
                              struct json_value *obj)
{
    json_set_object(obj);
    char hex[65];
    HexStr(r->master_pubkey, 32, false, hex, sizeof(hex));
    json_push_kv_str(obj, "pubkey", hex);
    HexStr(r->anchor_txid, 32, false, hex, sizeof(hex));
    json_push_kv_str(obj, "anchor_txid", hex);
    json_push_kv_int(obj, "anchor_height", r->anchor_height);
    json_push_kv_int(obj, "updated_height", r->updated_height);
    json_push_kv_str(obj, "status", r->status);
    json_push_kv_str(obj, "source", r->source);
    json_push_kv_str(obj, "name", r->name);
    json_push_kv_str(obj, "owner_address", r->owner_address);
    if (r->has_successor) {
        HexStr(r->successor_pubkey, 32, false, hex, sizeof(hex));
        json_push_kv_str(obj, "successor", hex);
    }
    int32_t tip = reducer_frontier_provable_tip_cached();
    json_push_kv_int(obj, "confirmations",
                     (tip >= 0 && tip >= r->anchor_height)
                         ? (int64_t)(tip - r->anchor_height + 1) : 0);
}

/* Broadcast `script` inside a tx whose base is already built, or emit the
 * ready-to-include hex when no wallet is loaded. `owner_address` selects
 * the base-tx builder: NULL/"" → genesis base (a first anchor has no
 * owner to prove), else the owner-proof base. Fills `result` either way
 * and returns the RPC's bool. */
static bool identity_commit(const uint8_t *script, size_t script_len,
                            const char *owner_address,
                            struct json_value *result)
{
    if (!g_identity_wallet || !g_identity_mempool) {
        json_set_object(result);
        char hex[ZID_ANCHOR_SCRIPT_MAX * 2 + 2];
        HexStr(script, script_len, false, hex, sizeof(hex));
        json_push_kv_str(result, "op_return_hex", hex);
        json_push_kv_int(result, "op_return_size", (int64_t)script_len);
        json_push_kv_str(result, "status", "ready");
        json_push_kv_str(result, "note",
            "Wallet not loaded. Include this OP_RETURN as vout[0] manually.");
        return true;
    }

    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    int64_t fee_paid = 0;
    const char *tx_error = NULL;
    bool built;
    if (owner_address && owner_address[0])
        built = zslp_command_build_owner_base_tx(g_identity_wallet,
                                                 owner_address, &wtx,
                                                 &fee_paid, &tx_error).ok;
    else
        built = zslp_command_build_genesis_base_tx(g_identity_wallet, &wtx,
                                                   &fee_paid, &tx_error).ok;
    if (!built) {
        json_set_str(result, tx_error ? tx_error
                                      : "Failed to build transaction");
        return false;
    }

    struct wallet_tx_admission admission = {
        .mempool = g_identity_mempool,
        .coins_tip = g_identity_coins_tip,
        .main_state = g_identity_main_state,
        .params = chain_params_get(),
    };
    struct zcl_result commit = zslp_command_commit_with_op_return(
        g_identity_wallet, &wtx, &admission, script, script_len);
    if (!commit.ok) {
        json_set_str(result, commit.message);
        transaction_free(&wtx.tx);
        LOG_FAIL("zid", "identity commit failed (code=%d): %s",
                 commit.code, commit.message);
    }

    json_set_object(result);
    char txid_hex[65];
    uint256_get_hex(&wtx.tx.hash, txid_hex);
    json_push_kv_str(result, "txid", txid_hex);
    json_push_kv_int(result, "fee", fee_paid);
    json_push_kv_str(result, "status", "broadcast");
    return true;
}

/* ── identity_anchor ────────────────────────────────────────────── */

static bool rpc_identity_anchor(const struct json_value *params, bool help,
                                struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "identity_anchor {\"pubkey\":\"<64hex>\"}\n"
            "\nBind a 32-byte ed25519 master key to the chain via the ZID\n"
            "OP_RETURN overlay. With no wallet loaded, returns the\n"
            "OP_RETURN hex for manual inclusion.\n");
        return true;
    }

    uint8_t key[32];
    if (!identity_parse_key(identity_str_field(params, 0, "pubkey"), key)) {
        json_set_str(result,
            "Invalid pubkey (need 64 hex chars, not all-zero)");
        return false;
    }

    if (g_identity_ndb) {
        struct zid_identity prev;
        if (db_zid_identity_find(g_identity_ndb, key, &prev) &&
            strcmp(prev.status, ZID_IDENTITY_STATUS_ACTIVE) != 0) {
            json_set_str(result,
                "Key is already rotated or revoked — a dead key is never "
                "re-anchored");
            return false;
        }
    }

    uint8_t script[ZID_ANCHOR_SCRIPT_MAX];
    size_t script_len = zid_anchor_build_anchor(script, sizeof(script), key);
    if (script_len == 0) {
        json_set_str(result, "Failed to build ZID ANCHOR OP_RETURN");
        return false;
    }
    /* A first anchor has no prior owner to prove — genesis base tx. */
    return identity_commit(script, script_len, NULL, result);
}

/* ── identity_rotate ────────────────────────────────────────────── */

static bool rpc_identity_rotate(const struct json_value *params, bool help,
                                struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "identity_rotate {\"pubkey\":\"<64hex>\",\n"
            "                 \"new_pubkey\":\"<64hex>\"}\n"
            "\nSupersede an anchored master key with a successor. The tx's\n"
            "sole input is spent from the row's recorded owner address, so\n"
            "the projection accepts the rotation.\n");
        return true;
    }

    uint8_t old_key[32], new_key[32];
    if (!identity_parse_key(identity_str_field(params, 0, "pubkey"),
                            old_key) ||
        !identity_parse_key(identity_str_field(params, 1, "new_pubkey"),
                            new_key)) {
        json_set_str(result,
            "Invalid pubkey/new_pubkey (need 64 hex chars, not all-zero)");
        return false;
    }
    if (memcmp(old_key, new_key, 32) == 0) {
        json_set_str(result, "Self-rotation refused (pubkey == new_pubkey)");
        return false;
    }

    struct zid_identity prev;
    if (!g_identity_ndb ||
        !db_zid_identity_find(g_identity_ndb, old_key, &prev)) {
        json_set_str(result, "Key is not anchored on-chain");
        return false;
    }
    if (strcmp(prev.status, ZID_IDENTITY_STATUS_REVOKED) == 0) {
        json_set_str(result, "Key is revoked — a dead key is never rotated");
        return false;
    }
    if (prev.owner_address[0] == '\0' && g_identity_wallet) {
        json_set_str(result,
            "Row has no recorded owner address — ownership cannot be "
            "proven, so this identity is permanently immutable");
        return false;
    }

    uint8_t script[ZID_ANCHOR_SCRIPT_MAX];
    size_t script_len = zid_anchor_build_rotate(script, sizeof(script),
                                                old_key, new_key);
    if (script_len == 0) {
        json_set_str(result, "Failed to build ZID ROTATE OP_RETURN");
        return false;
    }
    return identity_commit(script, script_len, prev.owner_address, result);
}

/* ── identity_revoke ────────────────────────────────────────────── */

static bool rpc_identity_revoke(const struct json_value *params, bool help,
                                struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "identity_revoke {\"pubkey\":\"<64hex>\"}\n"
            "\nRetire an anchored master key with no successor. One-way:\n"
            "a revoked key is never resurrected by a later anchor.\n");
        return true;
    }

    uint8_t key[32];
    if (!identity_parse_key(identity_str_field(params, 0, "pubkey"), key)) {
        json_set_str(result,
            "Invalid pubkey (need 64 hex chars, not all-zero)");
        return false;
    }

    struct zid_identity prev;
    if (!g_identity_ndb || !db_zid_identity_find(g_identity_ndb, key, &prev)) {
        json_set_str(result, "Key is not anchored on-chain");
        return false;
    }
    if (strcmp(prev.status, ZID_IDENTITY_STATUS_REVOKED) == 0) {
        json_set_str(result, "Key is already revoked");
        return false;
    }
    if (prev.owner_address[0] == '\0' && g_identity_wallet) {
        json_set_str(result,
            "Row has no recorded owner address — ownership cannot be "
            "proven, so this identity is permanently immutable");
        return false;
    }

    uint8_t script[ZID_ANCHOR_SCRIPT_MAX];
    size_t script_len = zid_anchor_build_revoke(script, sizeof(script), key);
    if (script_len == 0) {
        json_set_str(result, "Failed to build ZID REVOKE OP_RETURN");
        return false;
    }
    return identity_commit(script, script_len, prev.owner_address, result);
}

/* ── identity_resolve ───────────────────────────────────────────── */

static bool rpc_identity_resolve(const struct json_value *params, bool help,
                                 struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "identity_resolve {\"pubkey\":\"<64hex\"} | {\"name\":\"<znam>\"}\n"
            "\nResolve one identity out of the zid_identities projection.\n");
        return true;
    }

    if (!g_identity_ndb) {
        json_set_str(result, "Identity projection unavailable");
        return false;
    }

    const char *pubkey_hex = identity_str_field(params, 0, "pubkey");
    const char *name = identity_str_field(params, 1, "name");
    struct zid_identity row;
    if (pubkey_hex && pubkey_hex[0]) {
        uint8_t key[32];
        if (!identity_parse_key(pubkey_hex, key)) {
            json_set_str(result,
                "Invalid pubkey (need 64 hex chars, not all-zero)");
            return false;
        }
        if (!db_zid_identity_find(g_identity_ndb, key, &row)) {
            json_set_str(result, "Key is not anchored on-chain");
            return false;
        }
    } else if (name && name[0]) {
        if (!db_zid_identity_find_by_name(g_identity_ndb, name, &row)) {
            json_set_str(result, "No identity anchored under that name");
            return false;
        }
    } else {
        json_set_str(result, "Missing pubkey or name");
        return false;
    }

    identity_row_json(&row, result);
    return true;
}

/* ── Registration ───────────────────────────────────────────────── */

void register_identity_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "identity", "identity_anchor",  rpc_identity_anchor,  true },
        { "identity", "identity_rotate",  rpc_identity_rotate,  true },
        { "identity", "identity_revoke",  rpc_identity_revoke,  true },
        { "identity", "identity_resolve", rpc_identity_resolve, true },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
    register_zid_intent_rpc_command(t);
}
