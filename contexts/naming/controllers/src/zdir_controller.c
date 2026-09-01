/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * On-chain node directory (ZDIR) RPC controller — the WRITE half of the
 * directory overlay. Announce a v3 onion hostname as a node, or retire one,
 * through a `ZDIR` OP_RETURN the whole network folds out of block history.
 *
 * Before this file existed the directory was read-only in the strictest
 * sense: zdir_build_register/zdir_build_deregister had no caller outside
 * their own tests, so the onion_directory projection could only ever be
 * empty on a network where nothing else published records, and peer
 * discovery leaned on the unsigned local-wallet scrape instead.
 *
 * This is the live-node half of `core zdir *`
 * (tools/command/native_zdir_command.c): the native command prefers these
 * RPCs so the node's own wallet composes and broadcasts, and falls back to
 * emitting op_return_hex itself when nothing answers.
 *
 * Compose+return shape, copied from identity_controller.c: with a wallet
 * loaded the commands build a base tx, attach the ZDIR OP_RETURN and
 * broadcast; with NO wallet they return the OP_RETURN hex and status
 * "ready" — that no-wallet branch is the one the unit tests exercise, and
 * nothing here broadcasts in a test.
 *
 * Ownership. Re-registering or deregistering mutates a row that already
 * exists, and explorer_index_apply_zdir_overlay will only fold such a
 * mutation when the confirming tx's first input pays the row's recorded
 * owner_address. So those build the base tx with
 * zslp_command_build_owner_base_tx(owner_address) — the same proof,
 * constructed up front. A FIRST registration of an unclaimed hostname has
 * no prior owner to prove and uses the genesis base tx. A row with no
 * recorded owner fails closed with NOT_OWNER instead of broadcasting a tx
 * the projection would silently refuse.
 *
 * NO TRANSFER. Command byte 3 is reserved for it and zdir_parse rejects it
 * on purpose; a parsed-but-unhandled command would be a silent stub.
 * Handing a hostname over is deregister-then-register.
 *
 * NEVER ON A TIMER. No boot path, no background service and no re-announce
 * cadence calls anything here. Every publication spends a real UTXO and
 * stays an explicit operator decision. */

#include "controllers/zdir_controller.h"
#include "models/onion_directory.h"
#include "net/onion_peer_merge.h"
#include "zdir/zdir.h"
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

static struct node_db *g_zdir_ndb = NULL;
static struct wallet *g_zdir_wallet = NULL;
static struct tx_mempool *g_zdir_mempool = NULL;
static struct main_state *g_zdir_main_state = NULL;
static struct coins_view_cache *g_zdir_coins_tip = NULL;

static void zdir_set_context(struct node_db *ndb, struct wallet *w,
                             struct tx_mempool *mp,
                             struct main_state *main_state,
                             struct coins_view_cache *coins_tip)
{
    g_zdir_ndb = ndb;
    g_zdir_wallet = w;
    g_zdir_mempool = mp;
    g_zdir_main_state = main_state;
    g_zdir_coins_tip = coins_tip;
}

/* ── Input helpers (object-or-positional, identity_controller shape) ── */

static const char *zdir_str_field(const struct json_value *params, size_t idx,
                                  const char *key)
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

/* Exactly 64 hex chars decoding to a non-zero 32-byte key. An all-zero key
 * is the unset sentinel, never an ed25519 point, and zdir_build refuses it
 * anyway — caught here so the refusal is named instead of a build failure. */
static bool zdir_parse_key(const char *hex, uint8_t out[ZDIR_PUBKEY_LEN])
{
    if (!hex || strlen(hex) != 64 || !IsHex(hex)) return false;
    if (ParseHex(hex, out, ZDIR_PUBKEY_LEN) != ZDIR_PUBKEY_LEN) return false;
    for (int i = 0; i < ZDIR_PUBKEY_LEN; i++)
        if (out[i]) return true;
    return false;
}

/* Broadcast `script` inside a tx whose base is already built, or emit the
 * ready-to-include hex when no wallet is loaded. `owner_address` selects the
 * base-tx builder: NULL/"" → genesis base (a first registration has no owner
 * to prove), else the owner-proof base. Fills `result` either way and returns
 * the RPC's bool. */
static bool zdir_commit(const uint8_t *script, size_t script_len,
                        const char *owner_address, struct json_value *result)
{
    if (!g_zdir_wallet || !g_zdir_mempool) {
        json_set_object(result);
        char hex[ZDIR_SCRIPT_MAX * 2 + 2];
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
        built = zslp_command_build_owner_base_tx(g_zdir_wallet, owner_address,
                                                 &wtx, &fee_paid,
                                                 &tx_error).ok;
    else
        built = zslp_command_build_genesis_base_tx(g_zdir_wallet, &wtx,
                                                   &fee_paid, &tx_error).ok;
    if (!built) {
        json_set_str(result, tx_error ? tx_error
                                      : "Failed to build transaction");
        return false;
    }

    struct wallet_tx_admission admission = {
        .mempool = g_zdir_mempool,
        .coins_tip = g_zdir_coins_tip,
        .main_state = g_zdir_main_state,
        .params = chain_params_get(),
    };
    struct zcl_result commit = zslp_command_commit_with_op_return(
        g_zdir_wallet, &wtx, &admission, script, script_len);
    if (!commit.ok) {
        json_set_str(result, commit.message);
        transaction_free(&wtx.tx);
        LOG_FAIL("zdir", "zdir commit failed (code=%d): %s",
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

/* Read the hostname argument, holding it to the ONE v3 onion rule the node
 * has. Returns NULL with `result` already filled on refusal. */
static const char *zdir_require_hostname(const struct json_value *params,
                                         struct json_value *result)
{
    const char *hostname = zdir_str_field(params, 0, "hostname");
    if (!hostname || !hostname[0]) {
        json_set_str(result, "Missing hostname");
        return NULL;
    }
    if (!onion_hostname_valid(hostname)) {
        json_set_str(result,
            "Invalid hostname (need a Tor v3 onion: 56 base32 chars + "
            "\".onion\")");
        return NULL;
    }
    return hostname;
}

/* ── zdir_register ──────────────────────────────────────────────── */

static bool rpc_zdir_register(const struct json_value *params, bool help,
                              struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "zdir_register {\"hostname\":\"<56 base32>.onion\",\n"
            "               \"pubkey\":\"<64hex, optional>\"}\n"
            "\nPublish this v3 onion hostname on-chain as a node, via the\n"
            "ZDIR OP_RETURN overlay. Every other node folds the record into\n"
            "its onion_directory projection and may dial the hostname. The\n"
            "optional pubkey binds the hostname to a ZID master key; the\n"
            "binding is a claim, not a proof. With no wallet loaded, returns\n"
            "the OP_RETURN hex for manual inclusion.\n");
        return true;
    }

    const char *hostname = zdir_require_hostname(params, result);
    if (!hostname)
        return false;

    const char *pubkey_hex = zdir_str_field(params, 1, "pubkey");
    uint8_t key[ZDIR_PUBKEY_LEN];
    bool have_key = pubkey_hex && pubkey_hex[0];
    if (have_key && !zdir_parse_key(pubkey_hex, key)) {
        json_set_str(result,
            "Invalid pubkey (need 64 hex chars, not all-zero) — omit it to "
            "register the hostname unbound");
        return false;
    }

    /* Pre-flight against the projection: a re-register of a hostname another
     * signer holds, or of a row that records no owner at all, is refused by
     * the fold — finding that out here costs nothing while broadcasting
     * costs a fee. An unclaimed hostname is the ordinary first-registration
     * case and has no owner to prove. */
    const char *owner = NULL;
    struct db_onion_directory prev;
    if (g_zdir_ndb && db_onion_directory_find(g_zdir_ndb, hostname, &prev)) {
        if (prev.owner_address[0] == '\0' && g_zdir_wallet) {
            json_set_str(result,
                "Row has no recorded owner address — ownership cannot be "
                "proven, so this hostname is permanently immutable");
            return false;
        }
        owner = prev.owner_address;
    }

    uint8_t script[ZDIR_SCRIPT_MAX];
    size_t script_len = zdir_build_register(script, sizeof(script), hostname,
                                            have_key ? key : NULL);
    if (script_len == 0) {
        json_set_str(result, "Failed to build ZDIR REGISTER OP_RETURN");
        return false;
    }
    return zdir_commit(script, script_len, owner, result);
}

/* ── zdir_deregister ────────────────────────────────────────────── */

static bool rpc_zdir_deregister(const struct json_value *params, bool help,
                                struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "zdir_deregister {\"hostname\":\"<56 base32>.onion\"}\n"
            "\nRetire a hostname this wallet registered. The row and its\n"
            "seniority stay on-chain as history; it just stops being dialed.\n"
            "The tx's sole input is spent from the row's recorded owner\n"
            "address, so the projection accepts the retirement. To hand a\n"
            "hostname to another operator, deregister it and let them\n"
            "register it — there is no transfer command.\n");
        return true;
    }

    const char *hostname = zdir_require_hostname(params, result);
    if (!hostname)
        return false;

    struct db_onion_directory prev;
    if (!g_zdir_ndb || !db_onion_directory_find(g_zdir_ndb, hostname, &prev)) {
        json_set_str(result, "Hostname is not registered on-chain");
        return false;
    }
    if (strcmp(prev.status, ONION_DIRECTORY_STATUS_RETIRED) == 0) {
        json_set_str(result,
            "Hostname is already retired — deregistering it again would "
            "spend a fee to say nothing");
        return false;
    }
    if (prev.owner_address[0] == '\0' && g_zdir_wallet) {
        json_set_str(result,
            "Row has no recorded owner address — ownership cannot be "
            "proven, so this hostname is permanently immutable");
        return false;
    }

    uint8_t script[ZDIR_SCRIPT_MAX];
    size_t script_len = zdir_build_deregister(script, sizeof(script),
                                              hostname);
    if (script_len == 0) {
        json_set_str(result, "Failed to build ZDIR DEREGISTER OP_RETURN");
        return false;
    }
    return zdir_commit(script, script_len, prev.owner_address, result);
}

/* ── zdir_resolve ───────────────────────────────────────────────── */

static bool rpc_zdir_resolve(const struct json_value *params, bool help,
                             struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "zdir_resolve {\"hostname\":\"<56 base32>.onion\"}\n"
            "\nRead one row out of the onion_directory projection: who\n"
            "registered this hostname, at what height, and whether it is\n"
            "still active. A row is a hint about where to look, never proof\n"
            "of who is there.\n");
        return true;
    }

    if (!g_zdir_ndb) {
        json_set_str(result, "Directory projection unavailable");
        return false;
    }
    const char *hostname = zdir_require_hostname(params, result);
    if (!hostname)
        return false;

    struct db_onion_directory row;
    if (!db_onion_directory_find(g_zdir_ndb, hostname, &row)) {
        json_set_str(result, "Hostname is not registered on-chain");
        return false;
    }

    json_set_object(result);
    json_push_kv_str(result, "hostname", row.hostname);
    char hex[65];
    HexStr(row.txid, 32, false, hex, sizeof(hex));
    json_push_kv_str(result, "txid", hex);
    json_push_kv_int(result, "height", row.height);
    json_push_kv_int(result, "updated_height", row.updated_height);
    json_push_kv_str(result, "status", row.status);
    json_push_kv_str(result, "owner_address", row.owner_address);
    if (row.has_pubkey) {
        HexStr(row.master_pubkey, 32, false, hex, sizeof(hex));
        json_push_kv_str(result, "pubkey", hex);
    } else {
        json_push_kv_str(result, "pubkey", "");
    }
    int32_t tip = reducer_frontier_provable_tip_cached();
    json_push_kv_int(result, "confirmations",
                     (tip >= 0 && tip >= row.height)
                         ? (int64_t)(tip - row.height + 1) : 0);
    return true;
}

/* ── Registration ───────────────────────────────────────────────── */

void register_zdir_rpc_commands(struct rpc_table *t, struct node_db *ndb,
                                struct wallet *w, struct tx_mempool *mp,
                                struct main_state *main_state,
                                struct coins_view_cache *coins_tip)
{
    zdir_set_context(ndb, w, mp, main_state, coins_tip);
    struct rpc_command cmds[] = {
        { "zdir", "zdir_register",   rpc_zdir_register,   true },
        { "zdir", "zdir_deregister", rpc_zdir_deregister, true },
        { "zdir", "zdir_resolve",    rpc_zdir_resolve,    true },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
    register_zdir_intent_rpc_command(t);
}
