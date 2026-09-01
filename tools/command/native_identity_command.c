/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the `core identity` tree — the chain-rooted answer
 * to "whose master key is this, and is it still live?"
 * (docs/spec/sovereign-identity-layer.md).
 *
 * Reads (resolve/list) open <datadir>/node.db READONLY — the
 * core.storage.query.offline pattern — and answer straight out of the
 * zid_identities projection (engine/models/src/zid_identity.c), which is
 * fed from confirmed chain data by both identity feeds
 * (contexts/explorer/models/src/explorer_index_zid.c). So a stopped or copied datadir
 * answers exactly like a running one, with no RPC.
 *
 * Writes (anchor/rotate/revoke) require an explicit dev/prod custody scope.
 * They dispatch the dedicated zid_intent RPC in two phases: plan atomically
 * reserves the exact inputs plus maximum fee, and commit publishes only the
 * exact signed bytes stored in that durable plan. Public replies are a strict
 * receipt whitelist and never include keys, owners, addresses, or raw bytes.
 *
 * Pre-flight reads run against the projection BEFORE planning, so a
 * refusal is named and free rather than a spent fee: rotate/revoke need
 * an existing, non-revoked row; rotate needs old != new. */

#include "command/native_command.h"

#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/database.h"
#include "models/zid_identity.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZID_CMD_LIST_DEFAULT 25
#define ZID_CMD_LIST_CAP     100

/* ── small helpers ────────────────────────────────────────────────── */

static const char *zidc_input_str(const struct json_value *input,
                                  const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v ? json_get_str(v) : NULL;
}

static int64_t zidc_input_int(const struct json_value *input, const char *key,
                              int64_t def)
{
    const struct json_value *v = json_get(input, key);
    if (!v) return def;
    if (v->type == JSON_INT) return json_get_int(v);
    if (v->type == JSON_STR) {
        const char *s = json_get_str(v);
        return (s && s[0]) ? strtoll(s, NULL, 10) : def;
    }
    return def;
}

/* Explicit input.datadir wins, else the CLI's --datadir. */
static const char *zidc_datadir(const struct zcl_command_request *request)
{
    const char *dd = zidc_input_str(request->input, "datadir");
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

/* The read-only open lives in tools/command/native_node_db_ro.c; these
 * leaves call zcl_native_node_db_require_readonly directly.
 *
 * The one caller that still needs a local wrapper is the anchor preflight:
 * a missing node.db is NOT an error there, because anchoring a brand new
 * key on a host with no folded chain is a legitimate offline operation.
 * That is a decision about ABSENT only — an UNREADABLE node.db is still a
 * failure to look, and must not be silently treated as "the key has no
 * prior anchor". Returns the handle, or NULL with *fatal_out set when the
 * caller must refuse rather than proceed. */
static sqlite3 *zidc_open_db_preflight(const char *datadir,
                                       struct node_db *ndb_out,
                                       bool *fatal_out)
{
    sqlite3 *db = NULL;
    *fatal_out = false;
    enum zcl_node_db_ro_status st =
        zcl_native_node_db_open_readonly(datadir, &db, ndb_out, NULL, 0);
    if (st == ZCL_NODE_DB_RO_OK)
        return db;
    if (st != ZCL_NODE_DB_RO_ABSENT)
        *fatal_out = true;
    return NULL;  // raw-return-ok:optional-preflight-open
}

/* Exactly 64 hex chars decoding to a non-zero 32-byte key. */
static bool zidc_parse_key(const char *hex, uint8_t out[32])
{
    if (!hex || strlen(hex) != 64 || !IsHex(hex))
        return false;
    if (ParseHex(hex, out, 32) != 32)
        return false;
    for (int i = 0; i < 32; i++)
        if (out[i])
            return true;
    return false;   /* all-zero is the unset sentinel, never an identity */
}

static void zidc_row_json(const struct zid_identity *r,
                          struct json_value *obj)
{
    json_set_object(obj);
    char hex[65];
    HexStr(r->master_pubkey, 32, false, hex, sizeof(hex));
    json_push_kv_str(obj, "pubkey", hex);
    json_push_kv_str(obj, "name", r->name);
    HexStr(r->anchor_txid, 32, false, hex, sizeof(hex));
    json_push_kv_str(obj, "anchor_txid", hex);
    json_push_kv_int(obj, "anchor_height", r->anchor_height);
    json_push_kv_int(obj, "updated_height", r->updated_height);
    json_push_kv_str(obj, "status", r->status);
    if (r->has_successor) {
        HexStr(r->successor_pubkey, 32, false, hex, sizeof(hex));
        json_push_kv_str(obj, "successor", hex);
    } else {
        json_push_kv_str(obj, "successor", "");
    }
    json_push_kv_str(obj, "source", r->source);
    json_push_kv_str(obj, "owner_address", r->owner_address);
}

/* Resolve the datadir or fail the reply. */
static const char *zidc_require_datadir(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const char *path)
{
    const char *datadir = zidc_datadir(request);
    if (!datadir)
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given and no --datadir default",
                               path);
    return datadir;
}

/* Read --pubkey into `key`, failing the reply with a named code when it is
 * absent or malformed. */
static bool zidc_require_pubkey(const struct json_value *input,
                                const char *field,
                                struct zcl_command_reply *reply,
                                const char *path, uint8_t key[32])
{
    const char *hex = zidc_input_str(input, field);
    if (!hex || !hex[0]) {
        char msg[128];
        snprintf(msg, sizeof(msg),
                 "give --%s=<64 hex chars> (the ed25519 master public key)",
                 field);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               strcmp(field, "pubkey") == 0
                                   ? "MISSING_PUBKEY" : "MISSING_NEW_PUBKEY",
                               "normalize", false, false, msg, path);
        return false;
    }
    if (!zidc_parse_key(hex, key)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_PUBKEY_HEX",
                               "normalize", false, false,
                               "pubkey must be exactly 64 hex characters and "
                               "not all-zero — an all-zero key is the unset "
                               "sentinel, never a usable ed25519 point",
                               path);
        return false;
    }
    return true;
}

/* ── core.identity.resolve ────────────────────────────────────────── */

void zcl_native_handle_core_identity_resolve(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *path = "core.identity.resolve";

    const char *pubkey_hex = zidc_input_str(request->input, "pubkey");
    const char *name = zidc_input_str(request->input, "name");
    bool have_pubkey = pubkey_hex && pubkey_hex[0];
    bool have_name = name && name[0];
    if (!have_pubkey && !have_name) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_SELECTOR",
                               "normalize", false, false,
                               "give --pubkey=<64hex> or --name=<znam name> "
                               "— resolve needs exactly one selector", path);
        return;
    }
    if (have_pubkey && have_name) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "AMBIGUOUS_SELECTOR",
                               "normalize", false, false,
                               "give --pubkey OR --name, never both — they "
                               "can disagree and there is no rule for which "
                               "wins", path);
        return;
    }

    uint8_t key[32];
    if (have_pubkey && !zidc_parse_key(pubkey_hex, key)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_PUBKEY_HEX",
                               "normalize", false, false,
                               "pubkey must be exactly 64 hex characters and "
                               "not all-zero", path);
        return;
    }

    const char *datadir = zidc_require_datadir(request, reply, path);
    if (!datadir)
        return;
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!zcl_native_node_db_require_readonly(datadir, reply,
                                             "the identity projection",
                                             &db, &ndb))
        return;

    struct zid_identity row;
    bool found = have_pubkey ? db_zid_identity_find(&ndb, key, &row)
                             : db_zid_identity_find_by_name(&ndb, name, &row);
    zcl_native_node_db_close_readonly(&db, &ndb);

    if (!found) {
        if (have_pubkey)
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_FAILED,
                                   "KEY_NOT_ANCHORED", "execute", false,
                                   false,
                                   "this master key has no anchor on the "
                                   "chain this node has folded — it may be "
                                   "unanchored, or anchored above the "
                                   "node's current height", pubkey_hex);
        else
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_FAILED, "NAME_NOT_FOUND",
                                   "execute", false, false,
                                   "no ZNAM name anchors an identity under "
                                   "that name — check the spelling, or the "
                                   "name may set no `zid` text record",
                                   name);
        return;
    }

    struct json_value obj = {0};
    zidc_row_json(&row, &obj);
    json_copy(&reply->data, &obj);
    json_free(&obj);
    json_push_kv_str(&reply->data, "datadir", datadir);
    json_push_kv_bool(&reply->data, "found", true);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── core.identity.list ───────────────────────────────────────────── */

void zcl_native_handle_core_identity_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *path = "core.identity.list";

    int64_t limit = zidc_input_int(request->input, "limit",
                                   ZID_CMD_LIST_DEFAULT);
    int64_t offset = zidc_input_int(request->input, "offset", 0);
    if (limit < 1) limit = 1;
    if (limit > ZID_CMD_LIST_CAP) limit = ZID_CMD_LIST_CAP;
    if (offset < 0) offset = 0;

    const char *datadir = zidc_require_datadir(request, reply, path);
    if (!datadir)
        return;
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!zcl_native_node_db_require_readonly(datadir, reply,
                                             "the identity projection",
                                             &db, &ndb))
        return;

    struct zid_identity rows[ZID_CMD_LIST_CAP];
    int n = db_zid_identity_list(&ndb, rows, (int)limit, (int)offset);
    int64_t total = db_zid_identity_count(&ndb);
    int64_t active = db_zid_identity_count_by_status(
        &ndb, ZID_IDENTITY_STATUS_ACTIVE);
    int64_t rotated = db_zid_identity_count_by_status(
        &ndb, ZID_IDENTITY_STATUS_ROTATED);
    int64_t revoked = db_zid_identity_count_by_status(
        &ndb, ZID_IDENTITY_STATUS_REVOKED);
    zcl_native_node_db_close_readonly(&db, &ndb);

    json_push_kv_str(&reply->data, "datadir", datadir);
    json_push_kv_int(&reply->data, "limit", limit);
    json_push_kv_int(&reply->data, "offset", offset);
    json_push_kv_int(&reply->data, "total", total);
    json_push_kv_int(&reply->data, "active", active);
    json_push_kv_int(&reply->data, "rotated", rotated);
    json_push_kv_int(&reply->data, "revoked", revoked);

    struct json_value arr = {0};
    json_set_array(&arr);
    for (int i = 0; i < n; i++) {
        struct json_value e = {0};
        zidc_row_json(&rows[i], &e);
        json_push_back(&arr, &e);
        json_free(&e);
    }
    json_push_kv(&reply->data, "identities", &arr);
    json_free(&arr);
    json_push_kv_int(&reply->data, "count", n);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── core.identity.anchor ─────────────────────────────────────────── */

void zcl_native_handle_core_identity_anchor(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *path = "core.identity.anchor";
    if (json_get_bool_or(request->input, "confirm", false)) {
        zcl_native_overlay_intent_run(
            request, reply, "zid_intent", "anchor", false);
        return;
    }

    uint8_t key[32];
    if (!zidc_require_pubkey(request->input, "pubkey", reply, path, key))
        return;
    const char *pubkey_hex = zidc_input_str(request->input, "pubkey");

    /* Pre-flight: a dead or superseded key is never re-anchored, and
     * finding that out costs nothing while broadcasting costs a fee.
     * An ABSENT node.db is NOT fatal here — anchoring a brand new key on a
     * host with no folded chain is a legitimate offline operation. An
     * UNREADABLE one IS fatal: skipping the preflight because the lookup
     * failed would spend a fee re-anchoring a key that may already be
     * revoked, on the strength of a check that never ran. */
    const char *datadir = zidc_datadir(request);
    if (datadir) {
        struct node_db ndb;
        bool db_fatal = false;
        sqlite3 *db = zidc_open_db_preflight(datadir, &ndb, &db_fatal);
        if (db_fatal) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                "NODE_DB_UNREADABLE", "execute", true, false,
                "node.db is present at this datadir but would not open "
                "read-only, so the already-revoked pre-flight could not "
                "run — refusing rather than spending a fee on an unchecked "
                "anchor; check permissions, or pass a datadir you can read",
                datadir);
            return;
        }
        if (db) {
            struct zid_identity prev;
            memset(&prev, 0, sizeof(prev));
            bool dead = db_zid_identity_find(&ndb, key, &prev) &&
                        strcmp(prev.status,
                               ZID_IDENTITY_STATUS_ACTIVE) != 0;
            char status[ZID_IDENTITY_STATUS_MAX];
            snprintf(status, sizeof(status), "%s", prev.status);
            zcl_native_node_db_close_readonly(&db, &ndb);
            if (dead) {
                zcl_command_reply_fail(
                    reply, ZCL_COMMAND_STATUS_FAILED,
                    ZCL_COMMAND_EXIT_FAILED, "ALREADY_REVOKED", "execute",
                    false, false,
                    strcmp(status, ZID_IDENTITY_STATUS_REVOKED) == 0
                        ? "this key is revoked — a dead key is never "
                          "re-anchored; anchor a fresh key instead"
                        : "this key has already been rotated away — anchor "
                          "its successor, not the superseded key",
                    pubkey_hex);
                return;
            }
        }
    }

    zcl_native_overlay_intent_run(
        request, reply, "zid_intent", "anchor", true);
}

/* ── core.identity.rotate ─────────────────────────────────────────── */

void zcl_native_handle_core_identity_rotate(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *path = "core.identity.rotate";
    if (json_get_bool_or(request->input, "confirm", false)) {
        zcl_native_overlay_intent_run(
            request, reply, "zid_intent", "rotate", false);
        return;
    }

    uint8_t old_key[32], new_key[32];
    if (!zidc_require_pubkey(request->input, "pubkey", reply, path, old_key))
        return;
    if (!zidc_require_pubkey(request->input, "new_pubkey", reply, path,
                             new_key))
        return;
    const char *old_hex = zidc_input_str(request->input, "pubkey");

    if (memcmp(old_key, new_key, 32) == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "SELF_ROTATE",
                               "normalize", false, false,
                               "pubkey and new_pubkey are the same key — a "
                               "rotation to itself says nothing and the "
                               "overlay refuses it on both sides", old_hex);
        return;
    }

    const char *datadir = zidc_require_datadir(request, reply, path);
    if (!datadir)
        return;
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!zcl_native_node_db_require_readonly(datadir, reply,
                                             "the identity projection",
                                             &db, &ndb))
        return;
    struct zid_identity prev;
    bool found = db_zid_identity_find(&ndb, old_key, &prev);
    zcl_native_node_db_close_readonly(&db, &ndb);

    if (!found) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "KEY_NOT_ANCHORED",
                               "execute", false, false,
                               "the key you are rotating away from has no "
                               "anchor row — anchor it first with `core "
                               "identity anchor`", old_hex);
        return;
    }
    if (strcmp(prev.status, ZID_IDENTITY_STATUS_REVOKED) == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "ALREADY_REVOKED",
                               "execute", false, false,
                               "this key is revoked — a dead key is never "
                               "rotated; anchor a fresh key instead",
                               old_hex);
        return;
    }
    if (prev.owner_address[0] == '\0') {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "NOT_OWNER",
                               "execute", false, false,
                               "the anchor row records no owner address, so "
                               "no signer can ever prove ownership of it — "
                               "this identity is permanently immutable by "
                               "design", old_hex);
        return;
    }

    zcl_native_overlay_intent_run(
        request, reply, "zid_intent", "rotate", true);
}

/* ── core.identity.revoke ─────────────────────────────────────────── */

void zcl_native_handle_core_identity_revoke(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *path = "core.identity.revoke";
    if (json_get_bool_or(request->input, "confirm", false)) {
        zcl_native_overlay_intent_run(
            request, reply, "zid_intent", "revoke", false);
        return;
    }

    uint8_t key[32];
    if (!zidc_require_pubkey(request->input, "pubkey", reply, path, key))
        return;
    const char *pubkey_hex = zidc_input_str(request->input, "pubkey");

    const char *datadir = zidc_require_datadir(request, reply, path);
    if (!datadir)
        return;
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!zcl_native_node_db_require_readonly(datadir, reply,
                                             "the identity projection",
                                             &db, &ndb))
        return;
    struct zid_identity prev;
    bool found = db_zid_identity_find(&ndb, key, &prev);
    zcl_native_node_db_close_readonly(&db, &ndb);

    if (!found) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "KEY_NOT_ANCHORED",
                               "execute", false, false,
                               "this key has no anchor row — there is "
                               "nothing on-chain to revoke", pubkey_hex);
        return;
    }
    if (strcmp(prev.status, ZID_IDENTITY_STATUS_REVOKED) == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "ALREADY_REVOKED",
                               "execute", false, false,
                               "this key is already revoked — revoking it "
                               "again would spend a fee to say nothing",
                               pubkey_hex);
        return;
    }
    if (prev.owner_address[0] == '\0') {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "NOT_OWNER",
                               "execute", false, false,
                               "the anchor row records no owner address, so "
                               "no signer can ever prove ownership of it — "
                               "this identity is permanently immutable by "
                               "design", pubkey_hex);
        return;
    }

    zcl_native_overlay_intent_run(
        request, reply, "zid_intent", "revoke", true);
}
