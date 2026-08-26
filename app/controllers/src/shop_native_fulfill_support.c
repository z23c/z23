/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Guarded storage, identity, clock, and moderation helpers for fulfillment. */

#include "controllers/shop_native_fulfill_internal.h"
#include "controllers/shop_native_handler.h"

#include "base/cleanse.h"
#include "base/hex.h"
#include "controllers/native_handler_body.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "models/review_state.h"
#include "models/shop_fulfill.h"
#include "models/shop_want.h"
#include "platform/clock.h"
#include "services/market_moderation_service.h"
#include "services/market_moderation_view_service.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define SHF_TAG "native.app.shop.want.fulfill"

void shf_fail(struct zcl_command_reply *reply,
              enum zcl_command_status status,
              enum zcl_command_exit exit_code, const char *code,
              const char *phase, const char *message, const char *evidence)
{
    LOG_ERROR(SHF_TAG, "%s: %s (%s)", code, message,
              evidence && evidence[0] ? evidence : "-");
    zcl_command_reply_fail(reply, status, exit_code, code, phase, false,
                           false, message, evidence ? evidence : "");
}

const char *shf_datadir(const struct zcl_command_request *request)
{
    const char *dd = json_get_str(json_get(request->input, "datadir"));
    if (dd && dd[0]) return dd;
    dd = zcl_native_command_datadir();
    return dd && dd[0] ? dd : NULL;
}

static bool shf_hex32(const char *hex, uint8_t out[32])
{
    return hex && strlen(hex) == 64 && zcl_hex_decode_lower(hex, out, 32);
}

bool shf_nonzero(const uint8_t value[32])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++) any |= value[i];
    return any != 0;
}

bool shf_now(const struct zcl_command_request *request, int64_t *out,
             struct zcl_command_reply *reply)
{
    int64_t now = clock_now_wall_ms() / 1000;
    const struct json_value *value = json_get(request->input, "now_unix");
    if (value) {
#ifndef ZCL_TESTING
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_DENIED,
                 "NOW_OVERRIDE_FORBIDDEN", "validate",
                 "now_unix is test-only; release commands use the node's "
                 "wall clock for expiry and current-evidence decisions",
                 "remove now_unix");
        return false; // raw-return-ok:reply-already-carries-named-error
#else
        if (value->type != JSON_INT || json_get_int(value) <= 0) {
            shf_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INVALID, "BAD_NOW_UNIX", "validate",
                     "now_unix must be a positive integer", "now_unix");
            return false;
        }
        now = json_get_int(value);
#endif
    }
    *out = now;
    return true;
}

void shf_derive_pubkey(uint8_t pubkey[32], const uint8_t seed[32])
{
    uint8_t secret[32];
    ed25519_keypair(pubkey, secret, seed);
    memory_cleanse(secret, sizeof(secret));
}

bool shf_seller_secret(const struct zcl_command_request *request,
                       uint8_t out[32], struct zcl_command_reply *reply)
{
    const char *hex = json_get_str(json_get(request->input, "seller_secret"));
    if (!shf_hex32(hex, out)) {
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "BAD_SELLER_SECRET", "validate",
                 "seller_secret must be the 64-hex Ed25519 seed whose "
                 "derived key signs or withdraws this fulfillment",
                 "seller_secret");
        return false; // raw-return-ok:reply-already-carries-named-error
    }
    return true;
}

bool shf_required_id(const struct zcl_command_request *request,
                     const char *key, uint8_t out[32],
                     struct zcl_command_reply *reply)
{
    const char *hex = json_get_str(json_get(request->input, key));
    if (!shf_hex32(hex, out) || !shf_nonzero(out)) {
        char message[192];
        (void)snprintf(message, sizeof(message),
                       "%s must be a nonzero 64-hex SHA3 identifier", key);
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "BAD_FULFILLMENT_ID", "validate", message, key);
        return false; // raw-return-ok:reply-already-carries-named-error
    }
    return true;
}

bool shf_optional_id(const struct zcl_command_request *request,
                     const char *key, uint8_t out[32],
                     struct zcl_command_reply *reply)
{
    memset(out, 0, 32);
    const char *hex = json_get_str(json_get(request->input, key));
    if (!hex || !hex[0]) return true;
    if (!shf_hex32(hex, out) || !shf_nonzero(out)) {
        char message[192];
        (void)snprintf(message, sizeof(message),
                       "%s must be a nonzero 64-hex receipt id when present",
                       key);
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "BAD_RECEIPT_ID", "validate", message, key);
        return false; // raw-return-ok:reply-already-carries-named-error
    }
    return true;
}

static bool shf_require_node_db(const char *datadir, char path[1024],
                                struct zcl_command_reply *reply)
{
    if (!shop_internal_path_join(path, 1024, datadir, "node.db")) {
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "DATADIR_PATH_TOO_LONG", "normalize",
                 "datadir is too long to address node.db", datadir);
        return false; // raw-return-ok:reply-already-carries-named-error
    }
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        shf_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "FULFILL_STORE_NOT_INITIALISED", "open",
                 "no node.db at this datadir — boot the node once before "
                 "posting a fulfillment", path);
        return false; // raw-return-ok:reply-already-carries-named-error
    }
    return true;
}

static bool shf_tables_present(sqlite3 *db)
{
    static const char sql[] =
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN "
        "('shop_wants','shop_fulfills')";
    sqlite3_stmt *s = NULL;
    bool ok = sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s; // raw-controller-sql-ok
    if (ok && AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
        ok = sqlite3_column_int(s, 0) == 2;
    else
        ok = false;
    if (s) sqlite3_finalize(s);
    return ok;
}

bool shf_open_readonly(const char *datadir, sqlite3 **db,
                       struct node_db *ndb,
                       struct zcl_command_reply *reply)
{
    if (!zcl_native_node_db_require_readonly(datadir, reply,
                                             "the shop fulfillment board",
                                             db, ndb))
        return false; // raw-return-ok:reply-already-carries-named-error
    if (!shf_tables_present(*db)) {
        zcl_native_node_db_close_readonly(db, ndb);
        shf_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "FULFILL_STORE_NOT_MIGRATED", "open",
                 "this node.db predates schema v67 — boot the node once to "
                 "create shop_fulfills, then re-run the command", datadir);
        return false; // raw-return-ok:reply-already-carries-named-error
    }
    return true;
}

bool shf_open_write(const char *datadir, struct node_db *ndb,
                    struct zcl_command_reply *reply)
{
    char path[1024];
    if (!shf_require_node_db(datadir, path, reply))
        return false; // raw-return-ok:reply-already-carries-named-error
    memset(ndb, 0, sizeof(*ndb));
    if (!node_db_open_runtime(ndb, path, "shop.fulfill")) {
        shf_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "FULFILL_STORE_UNAVAILABLE", "open",
                 "node.db exists but could not be opened for fulfillments",
                 path);
        return false; // raw-return-ok:reply-already-carries-named-error
    }
    return true;
}

bool shf_resolve_profile(const struct zcl_command_request *request,
                         const char *datadir, int *profile_out,
                         struct zcl_command_reply *reply)
{
    bool ok = false;
    char err[160] = "";
    enum market_moderation_profile active =
        market_moderation_profile_load(datadir, NULL, &ok, err, sizeof(err));
    if (!ok) {
        shf_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "MODERATION_POLICY_UNREADABLE", "moderate",
                 "the node's moderation policy is unreadable; inspect "
                 "<datadir>/market/moderation.v1 before trusting this view",
                 err);
        return false;
    }
    const char *override =
        json_get_str_or(request->input, "profile", NULL);
    int profile = -1;
    if (!market_moderation_view_service_builtin()->resolve_profile(
            override, (int)active, &profile)) {
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "BAD_PROFILE", "validate",
                 "unknown moderation profile; use open, open-view, general, "
                 "or general-audience.v1", override ? override : "profile");
        return false;
    }
    *profile_out = profile;
    return true;
}

void zcl_native_handle_shop_want_fulfill_review(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *datadir = shf_datadir(request);
    if (!datadir) {
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_DATADIR", "normalize",
                 "no datadir given and no --datadir default", "datadir");
        return;
    }
    uint8_t fulfill_id[32];
    if (!shf_required_id(request, "fulfill_id", fulfill_id, reply)) return;
    const char *state_text =
        json_get_str(json_get(request->input, "review_state"));
    int state = market_review_state_from_string(state_text);
    if (state < 0) {
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "BAD_REVIEW_STATE", "validate",
                 "review_state must be unreviewed, reviewed_ok, or sensitive",
                 "review_state");
        return;
    }
    bool confirm = json_get_bool_or(request->input, "confirm", false);
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (confirm) {
        if (!shf_open_write(datadir, &ndb, reply)) return;
    } else if (!shf_open_readonly(datadir, &db, &ndb, reply)) {
        return;
    }
    struct shop_fulfill row;
    bool found = db_shop_fulfill_find(&ndb, fulfill_id, &row);
    if (!found) {
        if (confirm) node_db_close(&ndb);
        else zcl_native_node_db_close_readonly(&db, &ndb);
        shf_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "FULFILLMENT_NOT_FOUND", "execute",
                 "no fulfillment with this id is stored on this node",
                 "fulfill_id");
        return;
    }
    const char *previous = market_review_state_string(
        (enum market_review_state)row.review_state);
    bool changed = row.review_state != state;
    if (!confirm) {
        zcl_native_node_db_close_readonly(&db, &ndb);
        (void)json_push_kv_str(&reply->data, "mode", "plan");
        (void)json_push_kv_str(&reply->data, "current_review_state", previous);
        (void)json_push_kv_str(&reply->data, "requested_review_state",
                               state_text);
        (void)json_push_kv_str(&reply->data, "plan",
            "set this node's local curation mark; it changes visibility, "
            "never the signed wire, and is never gossiped");
        (void)json_push_kv_str(&reply->data, "commit_command",
            "re-run the identical command with confirm:true");
        return;
    }
    bool saved = !changed || db_shop_fulfill_set_review_state(
        &ndb, fulfill_id, state_text);
    node_db_close(&ndb);
    if (!saved) {
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                 "REVIEW_FAILED", "execute",
                 "the local fulfillment curation mark could not be stored",
                 "fulfill_id");
        return;
    }
    (void)json_push_kv_str(&reply->data, "mode", "commit");
    (void)json_push_kv_str(&reply->data, "review_state", state_text);
    (void)json_push_kv_str(&reply->data, "previous_review_state", previous);
    (void)json_push_kv_bool(&reply->data, "changed", changed);
    (void)json_push_kv_str(&reply->data, "moderation_note",
        "local-only view metadata; the signed claim is unchanged");
    reply->error.mutated = changed;
}
