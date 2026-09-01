/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Names RPC controller.
 *
 * Commands:
 *   name_register    — register a name on-chain via OP_RETURN
 *   name_update      — replace a name's primary target (owner-only)
 *   name_transfer    — hand ownership to a new owner (owner-only)
 *   name_renew       — extend the registration term (permissionless)
 *   name_set_record  — set an additional multi-coin address record
 *                      (owner-only)
 *   name_set_text    — set an arbitrary key/value text record
 *                      (owner-only)
 *   name_resolve     — look up a name's target
 *   name_list        — list all registered names
 *
 * "owner-only" above is enforced twice: this controller refuses to build
 * a mutation unless the wallet holds the current owner's private key
 * (zslp_command_build_owner_base_tx), and the ZNAM projection independently
 * re-derives the owner from the confirmed tx's first input and ignores any
 * mutation that doesn't match (contexts/explorer/models/src/explorer_index.c:apply_znam)
 * — the projection's check is authoritative; this controller's check is
 * just a fail-fast so a caller without the key gets a clean RPC error
 * instead of a broadcast tx the chain will silently drop. */

#include "controllers/name_controller.h"
#include "controllers/name_resolver.h"
#include "models/znam.h"
#include "api_controller_internal.h"
#include "json/json.h"
#include "rpc/server.h"
#include "models/database.h"
#include "wallet/wallet.h"
#include "chain/chainparams.h"
#include "validation/txmempool.h"
#include "services/zslp_command_service.h"
#include "encoding/utilstrencodings.h"
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "util/log_macros.h"

/* ── Context ────────────────────────────────────────────────────── */

static struct node_db *g_name_ndb = NULL;
static struct wallet *g_name_wallet = NULL;
static struct tx_mempool *g_name_mempool = NULL;
static struct main_state *g_name_main_state = NULL;
static struct coins_view_cache *g_name_coins_tip = NULL;

void rpc_name_set_state(struct node_db *ndb)
{
    g_name_ndb = ndb;
}

void rpc_name_set_wallet(struct wallet *w, struct tx_mempool *mp,
                         struct main_state *main_state,
                         struct coins_view_cache *coins_tip)
{
    g_name_wallet = w;
    g_name_mempool = mp;
    g_name_main_state = main_state;
    g_name_coins_tip = coins_tip;
}

/* Snapshot the boot-wired names runtime context (node.db + wallet path) so the
 * read-only HTML site controller and the shared REGISTER compose (both in
 * name_site_controller.c) reach the same handles the RPC surface uses — the
 * explorer_controller pattern (one boot-wired node.db, concurrent WAL
 * readers), not a second open. */
void name_controller_get_ctx(struct name_controller_ctx *out)
{
    if (!out) return;
    out->ndb = g_name_ndb;
    out->wallet = g_name_wallet;
    out->mempool = g_name_mempool;
    out->main_state = g_name_main_state;
    out->coins_tip = g_name_coins_tip;
}

/* ── Helper ─────────────────────────────────────────────────────── */

const char *znam_type_name(uint8_t t)
{
    switch (t) {
    case ZNAM_TYPE_ONION: return "onion";
    case ZNAM_TYPE_ZADDR: return "z-address";
    case ZNAM_TYPE_TADDR: return "t-address";
    case ZNAM_TYPE_BTC: return "bitcoin";
    case ZNAM_TYPE_LTC: return "litecoin";
    case ZNAM_TYPE_DOGE: return "dogecoin";
    case ZNAM_TYPE_CONTENT: return "content";
    default: return "unknown";
    }
}

/* parse_type moved to name_resolver.c as znam_type_from_name() — one
 * canonical parser, shared with the HTML site controller. */
#define parse_type znam_type_from_name

static void entry_to_json(const struct znam_entry *e, struct json_value *obj)
{
    json_set_object(obj);
    json_push_kv_str(obj, "name", e->name);
    json_push_kv_str(obj, "owner", e->owner_address);
    json_push_kv_int(obj, "target_type", e->target_type);
    json_push_kv_str(obj, "type", znam_type_name(e->target_type));
    json_push_kv_str(obj, "value", e->target_value);
    json_push_kv_int(obj, "reg_height", e->reg_height);
    json_push_kv_int(obj, "expiry_height", e->expiry_height);
    char hex[65];
    HexStr(e->reg_txid, 32, false, hex, sizeof(hex));
    json_push_kv_str(obj, "reg_txid", hex);
    HexStr(e->last_update_txid, 32, false, hex, sizeof(hex));
    json_push_kv_str(obj, "last_update_txid", hex);
}

#define ZNAM_API_LIST_LIMIT 100

static void append_name_verification(struct json_value *obj)
{
    struct json_value verification = {0};

    json_set_object(&verification);
    json_push_kv_str(&verification, "schema", "zcl.names.verification.v1");
    json_push_kv_str(&verification, "base_layer", "zclassic_l1");
    json_push_kv_str(&verification, "application_layer",
                     "zclassic23_application_layer");
    json_push_kv_str(&verification, "anchor", "confirmed_znam_op_return");
    json_push_kv_str(&verification, "projection", "znam_projection");
    json_push_kv_str(&verification, "mutation_authority",
                     "confirmed_chain_history");
    json_push_kv_str(&verification, "consensus_boundary",
                     "legacy_zclassic_consensus_unchanged");
    json_push_kv(obj, "zcl_verification", &verification);
    json_free(&verification);
}

static void append_name_crud_links(struct json_value *obj, const char *name)
{
    struct json_value links = {0};
    char self[256];

    json_set_object(&links);
    json_push_kv_str(&links, "collection", "/api/v1/names");
    json_push_kv_str(&links, "protocol", "/api/v1/protocols/znam");
    json_push_kv_str(&links, "create", "name_register");
    json_push_kv_str(&links, "read", "/api/v1/names/{name}");
    json_push_kv_str(&links, "service_directory",
                     "/api/v1/names/{name}/services");
    json_push_kv_str(&links, "update", "name_update");
    json_push_kv_str(&links, "delete", "not_supported_by_znam_v1");
    if (name && name[0]) {
        snprintf(self, sizeof(self), "/api/v1/names/%s", name);
        json_push_kv_str(&links, "self", self);
        snprintf(self, sizeof(self), "/api/v1/names/%s/services", name);
        json_push_kv_str(&links, "services", self);
    }
    json_push_kv(obj, "_links", &links);
    json_free(&links);
}

static void entry_to_show_json(const struct znam_entry *e,
                               struct json_value *obj)
{
    entry_to_json(e, obj);
    json_push_kv_str(obj, "schema", "zcl.names.show.v1");
    append_name_verification(obj);
    name_history_append_json(g_name_ndb, e, obj);
    append_name_crud_links(obj, e->name);
    api_name_append_records(g_name_ndb, e->name, obj);
}

/* ── name_resolve ───────────────────────────────────────────────── */

/* Resolution answers with a NAMED verdict, never a shared "Name not
 * found": absent, malformed, and registered-but-no-such-target are three
 * different situations with three different fixes, and
 * docs/spec/power-node-contract.md requires callers be able to tell them
 * apart. The whole taxonomy lives in name_resolver.c. */
static bool rpc_name_resolve(const struct json_value *params, bool help,
                             struct json_value *result)
{
    if (help || !params || json_size(params) < 1) {
        json_set_str(result, NAME_RESOLVE_RPC_HELP);
        return true;
    }

    const char *name = json_get_str(json_at(params, 0));
    const char *type_s = json_size(params) > 1
                       ? json_get_str(json_at(params, 1)) : NULL;
    struct name_resolution res;

    if (name_resolve_error_json(g_name_ndb, name, type_s, &res, result))
        return true;

    entry_to_show_json(&res.entry, result);
    json_push_kv_bool(result, "resolved", true);
    json_push_kv_str(result, "resolved_type", znam_type_name(res.matched_type));
    json_push_kv_str(result, "resolved_value", res.value);
    return true;
}

/* ── name_list ──────────────────────────────────────────────────── */

static bool name_index_to_json(const char *owner, struct json_value *result)
{
    struct json_value names = {0};
    struct znam_entry entries[ZNAM_API_LIST_LIMIT];
    bool owner_filter = owner && owner[0];
    int count = 0;

    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.names.index.v1");
    append_name_verification(result);
    append_name_crud_links(result, NULL);
    json_push_kv_int(result, "limit", ZNAM_API_LIST_LIMIT);
    json_push_kv_bool(result, "filtered", owner_filter);
    if (owner_filter)
        json_push_kv_str(result, "owner", owner);

    json_set_array(&names);
    if (g_name_ndb) {
        if (owner_filter)
            count = db_znam_list_by_owner(g_name_ndb, owner, entries, ZNAM_API_LIST_LIMIT);
        else
            count = db_znam_list(g_name_ndb, entries, ZNAM_API_LIST_LIMIT);
    }

    for (int i = 0; i < count; i++) {
        struct json_value e = {0};
        entry_to_json(&entries[i], &e);
        json_push_back(&names, &e);
        json_free(&e);
    }

    json_push_kv(result, "names", &names);
    json_push_kv_int(result, "count", count);
    json_free(&names);
    return true;
}

static bool rpc_name_list(const struct json_value *params, bool help,
                          struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "name_list [\"owner_address\"]\n"
            "\nList registered ZCL Names as zcl.names.index.v1, optionally filtered by owner.\n");
        return true;
    }

    const struct json_value *arg0 = params ? json_at(params, 0) : NULL;
    const char *owner = arg0 ? json_get_str(arg0) : NULL;
    return name_index_to_json(owner, result);
}

/* ── name_register ──────────────────────────────────────────────── */

static bool rpc_name_register(const struct json_value *params, bool help,
                              struct json_value *result)
{
    if (help || !params || json_size(params) < 3) {
        json_set_str(result,
            "name_register \"name\" \"type\" \"value\"\n"
            "\nRegister a ZCL Name on-chain via OP_RETURN transaction.\n"
            "\nArguments:\n"
            "1. name  (string) Name to register (1-63 chars, lowercase+hyphens)\n"
            "2. type  (string) Target type: onion, zaddr, taddr, btc, ltc, doge, content\n"
            "3. value (string) Target value (.onion, address, or content hash)\n"
            "\nNote: Requires wallet to create and broadcast the transaction.\n"
            "For now, returns the OP_RETURN hex that needs to be included\n"
            "in a transaction's first output.\n");
        return true;
    }

    const char *name = json_get_str(json_at(params, 0));
    const char *type_str = json_get_str(json_at(params, 1));
    const char *value = json_get_str(json_at(params, 2));

    if (!name || !type_str || !value) {
        json_set_str(result, "Missing arguments");
        return false;
    }

    if (!znam_validate_name(name)) {
        json_set_str(result, "Invalid name (1-63 chars, lowercase alphanumeric + hyphens)");
        return false;
    }

    uint8_t target_type = parse_type(type_str);
    if (target_type == 0) {
        json_set_str(result,
            "Invalid type (use: onion, zaddr, taddr, btc, ltc, doge, content)");
        return false;
    }

    /* Check if name already exists */
    struct znam_entry existing;
    if (g_name_ndb && db_znam_find(g_name_ndb, name, &existing)) {
        json_set_str(result, "Name already registered");
        return false;
    }

    /* Build the OP_RETURN script */
    uint8_t script[512];
    size_t script_len = znam_build_register(script, sizeof(script),
                                            name, target_type, value);
    if (script_len == 0) {
        json_set_str(result, "Failed to build OP_RETURN script");
        return false;
    }

    /* If wallet is available, build and broadcast the transaction via the
     * shared compose path (also used by the HTML register POST in
     * name_site_controller.c) so there is exactly one tx-compose routine. */
    if (g_name_wallet && g_name_mempool) {
        char txid_hex[65] = "";
        int64_t fee_paid = 0;
        char err[256] = "";
        if (!name_controller_compose_register(name, target_type, value,
                                              txid_hex, sizeof(txid_hex),
                                              &fee_paid, err, sizeof(err))) {
            json_set_str(result, err[0] ? err : "Failed to register name");
            LOG_FAIL("znam", "name_register: compose failed: %s",
                     err[0] ? err : "(no detail)");
        }

        json_set_object(result);
        json_push_kv_str(result, "name", name);
        json_push_kv_str(result, "type", znam_type_name(target_type));
        json_push_kv_str(result, "value", value);
        json_push_kv_str(result, "txid", txid_hex);
        json_push_kv_int(result, "fee", fee_paid);
        json_push_kv_str(result, "status", "broadcast");

        printf("znam: registered '%s' -> %s (txid: %s)\n",
               name, value, txid_hex);
        return true;
    }

    /* No wallet — return the OP_RETURN hex for manual inclusion */
    json_set_object(result);
    json_push_kv_str(result, "name", name);
    json_push_kv_str(result, "type", znam_type_name(target_type));
    json_push_kv_str(result, "value", value);

    char hex[1025];
    size_t hex_bytes = script_len < 512 ? script_len : 512;
    HexStr(script, hex_bytes, false, hex, sizeof(hex));
    json_push_kv_str(result, "op_return_hex", hex);
    json_push_kv_int(result, "op_return_size", (int64_t)script_len);
    json_push_kv_str(result, "status", "ready");
    json_push_kv_str(result, "note",
        "Wallet not loaded. Include this OP_RETURN as vout[0] manually.");

    return true;
}

/* ── name_update ────────────────────────────────────────────────── */

static bool rpc_name_update(const struct json_value *params, bool help,
                            struct json_value *result)
{
    if (help || !params || json_size(params) < 3) {
        json_set_str(result,
            "name_update \"name\" \"type\" \"value\"\n"
            "\nReplace a registered ZCL Name's primary target on-chain.\n"
            "\nArguments:\n"
            "1. name  (string) Name to update (must already be registered)\n"
            "2. type  (string) New target type: onion, zaddr, taddr, btc, ltc, doge, content\n"
            "3. value (string) New target value\n"
            "\nOnly the wallet holding the current owner's private key can\n"
            "broadcast an update that the name projection will accept.\n");
        return true;
    }

    const char *name = json_get_str(json_at(params, 0));
    const char *type_str = json_get_str(json_at(params, 1));
    const char *value = json_get_str(json_at(params, 2));

    if (!name || !type_str || !value) {
        json_set_str(result, "Missing arguments");
        return false;
    }
    if (!znam_validate_name(name)) {
        json_set_str(result, "Invalid name (1-63 chars, lowercase alphanumeric + hyphens)");
        return false;
    }
    uint8_t target_type = parse_type(type_str);
    if (target_type == 0) {
        json_set_str(result,
            "Invalid type (use: onion, zaddr, taddr, btc, ltc, doge, content)");
        return false;
    }
    /* znam_build_update() itself only checks the value fits the caller's
     * OP_RETURN buffer (512 bytes here), not ZNAM_VALUE_MAX — the parser
     * (contexts/naming/modules/znam/src/znam.c:znam_parse) is what actually enforces the
     * documented 128-byte cap on-chain. Reject early rather than build a
     * tx the projection will never accept. */
    if (strlen(value) > ZNAM_VALUE_MAX) {
        json_set_str(result, "Value too long (max 128 chars)");
        return false;
    }

    struct znam_entry existing;
    if (!g_name_ndb || !db_znam_find(g_name_ndb, name, &existing)) {
        json_set_str(result, "Name not found");
        return false;
    }

    uint8_t script[512];
    size_t script_len = znam_build_update(script, sizeof(script),
                                          name, target_type, value);
    if (script_len == 0) {
        json_set_str(result, "Failed to build OP_RETURN script");
        return false;
    }

    if (g_name_wallet && g_name_mempool) {
        struct wallet_tx wtx;
        memset(&wtx, 0, sizeof(wtx));
        int64_t fee_paid = 0;
        const char *tx_error = NULL;

        /* Coin-select from the CURRENT OWNER's own address so the tx's
         * vin[0] is provably the owner — the projection's authorization
         * check (fail-closed if the wallet doesn't hold that key or has
         * no funded coin there). */
        if (!zslp_command_build_owner_base_tx(g_name_wallet,
                                              existing.owner_address,
                                              &wtx, &fee_paid,
                                              &tx_error).ok) {
            json_set_str(result, tx_error ? tx_error : "Failed to build transaction");
            return false;
        }

        struct wallet_tx_admission admission = {
            .mempool = g_name_mempool,
            .coins_tip = g_name_coins_tip,
            .main_state = g_name_main_state,
            .params = chain_params_get(),
        };
        struct zcl_result commit = zslp_command_commit_with_op_return(
            g_name_wallet, &wtx, &admission, script, script_len);
        if (!commit.ok) {
            json_set_str(result, commit.message);
            transaction_free(&wtx.tx);
            LOG_FAIL("znam", "name_update: validated commit failed "
                             "(code=%d): %s", commit.code, commit.message);
        }

        json_set_object(result);
        json_push_kv_str(result, "name", name);
        json_push_kv_str(result, "type", znam_type_name(target_type));
        json_push_kv_str(result, "value", value);

        char txid_hex[65];
        uint256_get_hex(&wtx.tx.hash, txid_hex);
        json_push_kv_str(result, "txid", txid_hex);
        json_push_kv_int(result, "fee", fee_paid);
        json_push_kv_str(result, "status", "broadcast");

        printf("znam: updated '%s' -> %s (txid: %s)\n",
               name, value, txid_hex);
        return true;
    }

    json_set_object(result);
    json_push_kv_str(result, "name", name);
    json_push_kv_str(result, "type", znam_type_name(target_type));
    json_push_kv_str(result, "value", value);

    char hex[1025];
    size_t hex_bytes = script_len < 512 ? script_len : 512;
    HexStr(script, hex_bytes, false, hex, sizeof(hex));
    json_push_kv_str(result, "op_return_hex", hex);
    json_push_kv_int(result, "op_return_size", (int64_t)script_len);
    json_push_kv_str(result, "status", "ready");
    json_push_kv_str(result, "note",
        "Wallet not loaded. Include this OP_RETURN as vout[0]; the name "
        "projection accepts it only when vin[0] is signed by the current "
        "owner.");

    return true;
}

/* ── name_transfer ──────────────────────────────────────────────── */

/* Matches znam_parse's hardcoded new_owner cap (contexts/naming/modules/znam/src/znam.c);
 * there is no ZNAM_* constant for it because TRANSFER's target field is
 * a raw owner string, not a NAME/VALUE field. */
#define ZNAM_NEW_OWNER_MAX 63

static bool rpc_name_transfer(const struct json_value *params, bool help,
                              struct json_value *result)
{
    if (help || !params || json_size(params) < 2) {
        json_set_str(result,
            "name_transfer \"name\" \"new_owner\"\n"
            "\nTransfer ownership of a registered ZCL Name.\n"
            "\nArguments:\n"
            "1. name      (string) Name to transfer (must already be registered)\n"
            "2. new_owner (string) The new owner's address (1-63 chars)\n"
            "\nOnly the current owner can transfer a name; the ZNAM\n"
            "projection enforces this at apply time.\n");
        return true;
    }

    const char *name = json_get_str(json_at(params, 0));
    const char *new_owner = json_get_str(json_at(params, 1));

    if (!name || !new_owner) {
        json_set_str(result, "Missing arguments");
        return false;
    }
    if (!znam_validate_name(name)) {
        json_set_str(result, "Invalid name (1-63 chars, lowercase alphanumeric + hyphens)");
        return false;
    }
    size_t new_owner_len = strlen(new_owner);
    if (new_owner_len == 0 || new_owner_len > ZNAM_NEW_OWNER_MAX) {
        json_set_str(result, "Invalid new_owner (1-63 chars)");
        return false;
    }

    struct znam_entry existing;
    if (!g_name_ndb || !db_znam_find(g_name_ndb, name, &existing)) {
        json_set_str(result, "Name not found");
        return false;
    }

    uint8_t script[512];
    size_t script_len = znam_build_transfer(script, sizeof(script),
                                            name, new_owner);
    if (script_len == 0) {
        json_set_str(result, "Failed to build OP_RETURN script");
        return false;
    }

    if (g_name_wallet && g_name_mempool) {
        struct wallet_tx wtx;
        memset(&wtx, 0, sizeof(wtx));
        int64_t fee_paid = 0;
        const char *tx_error = NULL;

        if (!zslp_command_build_owner_base_tx(g_name_wallet,
                                              existing.owner_address,
                                              &wtx, &fee_paid,
                                              &tx_error).ok) {
            json_set_str(result, tx_error ? tx_error : "Failed to build transaction");
            return false;
        }

        struct wallet_tx_admission admission = {
            .mempool = g_name_mempool,
            .coins_tip = g_name_coins_tip,
            .main_state = g_name_main_state,
            .params = chain_params_get(),
        };
        struct zcl_result commit = zslp_command_commit_with_op_return(
            g_name_wallet, &wtx, &admission, script, script_len);
        if (!commit.ok) {
            json_set_str(result, commit.message);
            transaction_free(&wtx.tx);
            LOG_FAIL("znam", "name_transfer: validated commit failed "
                             "(code=%d): %s", commit.code, commit.message);
        }

        json_set_object(result);
        json_push_kv_str(result, "name", name);
        json_push_kv_str(result, "new_owner", new_owner);

        char txid_hex[65];
        uint256_get_hex(&wtx.tx.hash, txid_hex);
        json_push_kv_str(result, "txid", txid_hex);
        json_push_kv_int(result, "fee", fee_paid);
        json_push_kv_str(result, "status", "broadcast");

        printf("znam: transferred '%s' -> %s (txid: %s)\n",
               name, new_owner, txid_hex);
        return true;
    }

    json_set_object(result);
    json_push_kv_str(result, "name", name);
    json_push_kv_str(result, "new_owner", new_owner);

    char hex[1025];
    size_t hex_bytes = script_len < 512 ? script_len : 512;
    HexStr(script, hex_bytes, false, hex, sizeof(hex));
    json_push_kv_str(result, "op_return_hex", hex);
    json_push_kv_int(result, "op_return_size", (int64_t)script_len);
    json_push_kv_str(result, "status", "ready");
    json_push_kv_str(result, "note",
        "Wallet not loaded. Include this OP_RETURN as vout[0]; the name "
        "projection accepts it only when vin[0] is signed by the current "
        "owner.");

    return true;
}

/* ── name_renew ─────────────────────────────────────────────────── */

static bool rpc_name_renew(const struct json_value *params, bool help,
                           struct json_value *result)
{
    if (help || !params || json_size(params) < 1) {
        json_set_str(result,
            "name_renew \"name\"\n"
            "\nExtend a registered ZCL Name's registration term by one\n"
            "term (ZNAM_REGISTRATION_TERM_BLOCKS).\n"
            "\nArguments:\n"
            "1. name (string) Name to renew (must already be registered)\n"
            "\nRENEW is permissionless (ENS-style) — anyone may pay to\n"
            "extend a name's expiry; the projection performs no owner\n"
            "check on this command.\n");
        return true;
    }

    const char *name = json_get_str(json_at(params, 0));
    if (!name) {
        json_set_str(result, "Missing arguments");
        return false;
    }
    if (!znam_validate_name(name)) {
        json_set_str(result, "Invalid name (1-63 chars, lowercase alphanumeric + hyphens)");
        return false;
    }

    struct znam_entry existing;
    if (!g_name_ndb || !db_znam_find(g_name_ndb, name, &existing)) {
        json_set_str(result, "Name not found");
        return false;
    }

    uint8_t script[512];
    size_t script_len = znam_build_renew(script, sizeof(script), name);
    if (script_len == 0) {
        json_set_str(result, "Failed to build OP_RETURN script");
        return false;
    }

    if (g_name_wallet && g_name_mempool) {
        struct wallet_tx wtx;
        memset(&wtx, 0, sizeof(wtx));
        int64_t fee_paid = 0;
        const char *tx_error = NULL;

        /* RENEW is permissionless — any wallet funds may pay for it,
         * unlike the owner-restricted commands above. */
        if (!zslp_command_build_genesis_base_tx(g_name_wallet, &wtx,
                                                &fee_paid, &tx_error).ok) {
            json_set_str(result, tx_error ? tx_error : "Failed to build transaction");
            return false;
        }

        struct wallet_tx_admission admission = {
            .mempool = g_name_mempool,
            .coins_tip = g_name_coins_tip,
            .main_state = g_name_main_state,
            .params = chain_params_get(),
        };
        struct zcl_result commit = zslp_command_commit_with_op_return(
            g_name_wallet, &wtx, &admission, script, script_len);
        if (!commit.ok) {
            json_set_str(result, commit.message);
            transaction_free(&wtx.tx);
            LOG_FAIL("znam", "name_renew: validated commit failed "
                             "(code=%d): %s", commit.code, commit.message);
        }

        json_set_object(result);
        json_push_kv_str(result, "name", name);

        char txid_hex[65];
        uint256_get_hex(&wtx.tx.hash, txid_hex);
        json_push_kv_str(result, "txid", txid_hex);
        json_push_kv_int(result, "fee", fee_paid);
        json_push_kv_str(result, "status", "broadcast");

        printf("znam: renewed '%s' (txid: %s)\n", name, txid_hex);
        return true;
    }

    json_set_object(result);
    json_push_kv_str(result, "name", name);

    char hex[1025];
    size_t hex_bytes = script_len < 512 ? script_len : 512;
    HexStr(script, hex_bytes, false, hex, sizeof(hex));
    json_push_kv_str(result, "op_return_hex", hex);
    json_push_kv_int(result, "op_return_size", (int64_t)script_len);
    json_push_kv_str(result, "status", "ready");
    json_push_kv_str(result, "note",
        "Wallet not loaded. Include this OP_RETURN as vout[0] manually.");

    return true;
}

/* ── name_set_record ────────────────────────────────────────────── */

static bool rpc_name_set_record(const struct json_value *params, bool help,
                                struct json_value *result)
{
    if (help || !params || json_size(params) < 3) {
        json_set_str(result,
            "name_set_record \"name\" \"type\" \"value\"\n"
            "\nSet an additional multi-coin address record for a\n"
            "registered ZCL Name (ENS AddrResolver equivalent). Does not\n"
            "change the name's primary target — see name_update.\n"
            "\nArguments:\n"
            "1. name  (string) Name to update (must already be registered)\n"
            "2. type  (string) Coin type: onion, zaddr, taddr, btc, ltc, doge, content\n"
            "3. value (string) Address/value for that coin type\n"
            "\nOnly the wallet holding the current owner's private key can\n"
            "broadcast a record that the name projection will accept.\n");
        return true;
    }

    const char *name = json_get_str(json_at(params, 0));
    const char *type_str = json_get_str(json_at(params, 1));
    const char *value = json_get_str(json_at(params, 2));

    if (!name || !type_str || !value) {
        json_set_str(result, "Missing arguments");
        return false;
    }
    if (!znam_validate_name(name)) {
        json_set_str(result, "Invalid name (1-63 chars, lowercase alphanumeric + hyphens)");
        return false;
    }
    uint8_t target_type = parse_type(type_str);
    if (target_type == 0) {
        json_set_str(result,
            "Invalid type (use: onion, zaddr, taddr, btc, ltc, doge, content)");
        return false;
    }
    /* See the matching comment in rpc_name_update: the builder only
     * checks the OP_RETURN buffer size, not ZNAM_VALUE_MAX. */
    if (strlen(value) > ZNAM_VALUE_MAX) {
        json_set_str(result, "Value too long (max 128 chars)");
        return false;
    }

    struct znam_entry existing;
    if (!g_name_ndb || !db_znam_find(g_name_ndb, name, &existing)) {
        json_set_str(result, "Name not found");
        return false;
    }

    uint8_t script[512];
    size_t script_len = znam_build_set_record(script, sizeof(script),
                                              name, target_type, value);
    if (script_len == 0) {
        json_set_str(result, "Failed to build OP_RETURN script");
        return false;
    }

    if (g_name_wallet && g_name_mempool) {
        struct wallet_tx wtx;
        memset(&wtx, 0, sizeof(wtx));
        int64_t fee_paid = 0;
        const char *tx_error = NULL;

        if (!zslp_command_build_owner_base_tx(g_name_wallet,
                                              existing.owner_address,
                                              &wtx, &fee_paid,
                                              &tx_error).ok) {
            json_set_str(result, tx_error ? tx_error : "Failed to build transaction");
            return false;
        }

        struct wallet_tx_admission admission = {
            .mempool = g_name_mempool,
            .coins_tip = g_name_coins_tip,
            .main_state = g_name_main_state,
            .params = chain_params_get(),
        };
        struct zcl_result commit = zslp_command_commit_with_op_return(
            g_name_wallet, &wtx, &admission, script, script_len);
        if (!commit.ok) {
            json_set_str(result, commit.message);
            transaction_free(&wtx.tx);
            LOG_FAIL("znam", "name_set_record: validated commit failed "
                             "(code=%d): %s", commit.code, commit.message);
        }

        json_set_object(result);
        json_push_kv_str(result, "name", name);
        json_push_kv_str(result, "type", znam_type_name(target_type));
        json_push_kv_str(result, "value", value);

        char txid_hex[65];
        uint256_get_hex(&wtx.tx.hash, txid_hex);
        json_push_kv_str(result, "txid", txid_hex);
        json_push_kv_int(result, "fee", fee_paid);
        json_push_kv_str(result, "status", "broadcast");

        printf("znam: set_record '%s' %s -> %s (txid: %s)\n",
               name, type_str, value, txid_hex);
        return true;
    }

    json_set_object(result);
    json_push_kv_str(result, "name", name);
    json_push_kv_str(result, "type", znam_type_name(target_type));
    json_push_kv_str(result, "value", value);

    char hex[1025];
    size_t hex_bytes = script_len < 512 ? script_len : 512;
    HexStr(script, hex_bytes, false, hex, sizeof(hex));
    json_push_kv_str(result, "op_return_hex", hex);
    json_push_kv_int(result, "op_return_size", (int64_t)script_len);
    json_push_kv_str(result, "status", "ready");
    json_push_kv_str(result, "note",
        "Wallet not loaded. Include this OP_RETURN as vout[0]; the name "
        "projection accepts it only when vin[0] is signed by the current "
        "owner.");

    return true;
}

/* ── name_set_text ──────────────────────────────────────────────── */

static bool rpc_name_set_text(const struct json_value *params, bool help,
                              struct json_value *result)
{
    if (help || !params || json_size(params) < 2) {
        json_set_str(result,
            "name_set_text \"name\" \"key\" ( \"value\" )\n"
            "\nSet an arbitrary key-value text record for a registered\n"
            "ZCL Name (ENS TextResolver equivalent — email, url, avatar,\n"
            "...). Omitting value clears the key.\n"
            "\nArguments:\n"
            "1. name  (string) Name to update (must already be registered)\n"
            "2. key   (string) Record key (1-32 chars)\n"
            "3. value (string, optional) Record value (0-128 chars)\n"
            "\nOnly the wallet holding the current owner's private key can\n"
            "broadcast a record that the name projection will accept.\n");
        return true;
    }

    const char *name = json_get_str(json_at(params, 0));
    const char *key = json_get_str(json_at(params, 1));
    const struct json_value *arg2 = json_at(params, 2);
    const char *value = arg2 ? json_get_str(arg2) : NULL;
    if (!value)
        value = "";

    if (!name || !key) {
        json_set_str(result, "Missing arguments");
        return false;
    }
    if (!znam_validate_name(name)) {
        json_set_str(result, "Invalid name (1-63 chars, lowercase alphanumeric + hyphens)");
        return false;
    }

    struct znam_entry existing;
    if (!g_name_ndb || !db_znam_find(g_name_ndb, name, &existing)) {
        json_set_str(result, "Name not found");
        return false;
    }

    uint8_t script[512];
    size_t script_len = znam_build_set_text(script, sizeof(script), name, key, value);
    if (script_len == 0) {
        json_set_str(result,
            "Failed to build OP_RETURN script (key 1-32 chars, value 0-128 "
            "chars, and name+key+value together within the 223-byte "
            "standard OP_RETURN relay limit)");
        return false;
    }

    if (g_name_wallet && g_name_mempool) {
        struct wallet_tx wtx;
        memset(&wtx, 0, sizeof(wtx));
        int64_t fee_paid = 0;
        const char *tx_error = NULL;

        if (!zslp_command_build_owner_base_tx(g_name_wallet,
                                              existing.owner_address,
                                              &wtx, &fee_paid,
                                              &tx_error).ok) {
            json_set_str(result, tx_error ? tx_error : "Failed to build transaction");
            return false;
        }

        struct wallet_tx_admission admission = {
            .mempool = g_name_mempool,
            .coins_tip = g_name_coins_tip,
            .main_state = g_name_main_state,
            .params = chain_params_get(),
        };
        struct zcl_result commit = zslp_command_commit_with_op_return(
            g_name_wallet, &wtx, &admission, script, script_len);
        if (!commit.ok) {
            json_set_str(result, commit.message);
            transaction_free(&wtx.tx);
            LOG_FAIL("znam", "name_set_text: validated commit failed "
                             "(code=%d): %s", commit.code, commit.message);
        }

        json_set_object(result);
        json_push_kv_str(result, "name", name);
        json_push_kv_str(result, "key", key);
        json_push_kv_str(result, "value", value);

        char txid_hex[65];
        uint256_get_hex(&wtx.tx.hash, txid_hex);
        json_push_kv_str(result, "txid", txid_hex);
        json_push_kv_int(result, "fee", fee_paid);
        json_push_kv_str(result, "status", "broadcast");

        printf("znam: set_text '%s' %s -> %s (txid: %s)\n",
               name, key, value, txid_hex);
        return true;
    }

    json_set_object(result);
    json_push_kv_str(result, "name", name);
    json_push_kv_str(result, "key", key);
    json_push_kv_str(result, "value", value);

    char hex[1025];
    size_t hex_bytes = script_len < 512 ? script_len : 512;
    HexStr(script, hex_bytes, false, hex, sizeof(hex));
    json_push_kv_str(result, "op_return_hex", hex);
    json_push_kv_int(result, "op_return_size", (int64_t)script_len);
    json_push_kv_str(result, "status", "ready");
    json_push_kv_str(result, "note",
        "Wallet not loaded. Include this OP_RETURN as vout[0]; the name "
        "projection accepts it only when vin[0] is signed by the current "
        "owner.");

    return true;
}

/* name_records (has_many relationship read) is defined in
 * name_site_controller.c (file-size ceiling); declared in name_controller.h. */

/* ── REST API ───────────────────────────────────────────────────── */

bool api_name_list(struct json_value *result)
{
    return name_index_to_json(NULL, result);
}

bool rpc_name_resolve_api(const char *name, struct json_value *result)
{
    if (!name) LOG_FAIL("name", "rpc_name_resolve_api called with NULL name");
    if (!g_name_ndb) LOG_FAIL("name", "rpc_name_resolve_api: name database not initialized");
    struct znam_entry entry;
    if (!db_znam_find(g_name_ndb, name, &entry)) LOG_FAIL("name", "name '%s' not found in database", name);
    entry_to_show_json(&entry, result);
    return true;
}

bool api_name_service_directory(const char *name, struct json_value *result)
{
    struct json_value show = {0};
    const struct json_value *directory;
    char route[256];

    if (!name)
        LOG_FAIL("name", "api_name_service_directory called with NULL name");
    if (!result)
        LOG_FAIL("name", "api_name_service_directory called with NULL result");

    if (!rpc_name_resolve_api(name, &show)) {
        json_free(&show);
        return false;
    }

    directory = json_get(&show, "service_directory");
    if (!directory) {
        json_free(&show);
        LOG_FAIL("name", "service_directory missing for name '%s'", name);
    }

    json_copy(result, directory);
    json_push_kv_str(result, "name", name);
    snprintf(route, sizeof(route), "/api/v1/names/%s", name);
    json_push_kv_str(result, "name_route", route);
    snprintf(route, sizeof(route), "/api/v1/names/%s/services", name);
    json_push_kv_str(result, "self_route", route);
    json_push_kv_str(result, "operation_id",
                     "znam_names.resolve_service_directory");
    json_push_kv_str(result, "operation_route",
                     "/api/v1/service-operations/"
                     "znam_names.resolve_service_directory");
    json_push_kv_str(result, "parent_schema", "zcl.names.show.v1");
    json_push_kv_str(result, "next_action",
                     "use_records_then_run_runtime_probe_before_routing");
    json_free(&show);
    return true;
}
/* ── Registration ───────────────────────────────────────────────── */

void register_name_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "names", "name_register",   rpc_name_register,   true },
        { "names", "name_update",     rpc_name_update,     true },
        { "names", "name_transfer",   rpc_name_transfer,   true },
        { "names", "name_renew",      rpc_name_renew,      true },
        { "names", "name_set_record", rpc_name_set_record, true },
        { "names", "name_set_text",   rpc_name_set_text,   true },
        { "names", "name_resolve",    rpc_name_resolve,    true },
        { "names", "name_list",       rpc_name_list,       true },
        { "names", "name_records",    rpc_name_records,    true },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
    register_znam_intent_rpc_command(t);
}
