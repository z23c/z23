/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `app shop want *` — slice D of docs/work/SHOP_COMMAND.md: buyer-posted
 * needs, the demand-side mirror of the signed offer. Five leaves:
 *
 *   post    (plan/commit) — build, seal, verify, and persist one signed
 *           shop_want.v1 on this node's board. The buyer's Ed25519 secret
 *           is supplied per call (the CLI has no wallet); the pubkey is
 *           re-derived and must match, so a wrong secret never seals.
 *   list    (read)        — the open board, moderation-filtered by the
 *           node's active community content moderation profile with the
 *           same visibility rule the market listing applies to offers
 *           (general-audience.v1 shows reviewed_ok only; open-view shows
 *           everything). Hidden wants are counted, never deleted.
 *   status  (read)        — one want in full: re-verified signature,
 *           open/expired/cancelled state, review mark, visibility.
 *   cancel  (plan/commit) — key-checked local cancellation: the presented
 *           secret must derive the row's buyer_pubkey. The row is kept
 *           (evidence); it leaves the open board.
 *   review  (plan/commit) — the node's own curation mark (the
 *           zmarket_review_set equivalent for the demand side):
 *           local-only, never gossiped, never part of the signed wire.
 *
 * A want is a signed, discoverable WANT advertisement with terms — amount
 * + objectively checkable criteria (+ optional spec hash) + expiry. It is
 * NOT an escrow and NOT a payment channel: no value moves or is promised
 * by posting; ZC23/ZCL value transfer stays simulation/plan-only. P2P
 * gossip relay of the signed wire and fulfillment/award are the named
 * follow-ups — the stored wire is already the relay-ready shape (the
 * zswap_ads projection's terms-reversed twin).
 *
 * Handlers compose existing primitives: the codec + AR projection
 * (models/shop_want.h, table shop_wants from migration v66), the
 * datadir-local moderation policy file and the pure visibility service
 * (services/market_moderation_*), and the CLI's guarded node.db openers.
 * Bound in config/commands/store.def. Tests: lib/test/src/test_shop_want.c.
 */
#include "controllers/shop_native_handler.h"
#include "controllers/shop_native_want_view.h"
#include "controllers/native_handler_body.h" /* json_get_bool_or/json_get_str_or */
#include "command/native_command.h"
#include "base/cleanse.h"
#include "base/hex.h"
#include "crypto/ed25519.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/database.h"
#include "models/shop_fulfill.h"
#include "models/shop_want.h"
#include "platform/clock.h"
#include "services/market_moderation_service.h"
#include "services/market_moderation_view_service.h"
#include "util/log_macros.h"
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#define SHW_TAG "native.app.shop.want"
/* The board page rendered by `list`: bounded so the reply stays inside
 * the registry LIST budget even at the criteria cap (16 rows x ~450 B
 * worst case vs the 8192-byte budget), with the criteria preview
 * truncated — the full text is one `status` call away. */
#define SHW_BOARD_PAGE 16u
#define SHW_TERMS_NOTE \
    "a want is declared terms inside a signed advertisement — not an " \
    "escrow, not a payment channel; posting moves and promises no value " \
    "(ZC23/ZCL transfer stays simulation/plan-only); fulfillment/award " \
    "and P2P relay of the signed wire are the follow-ups"

#define SHW_MODERATION_NOTE \
    "visibility is this node's own community content moderation view " \
    "filter: the active profile decides which locally stored wants the " \
    "board shows; a hidden want stays stored and its signed wire is " \
    "untouched — identical semantics to moderated market offers"

/* ── failures ───────────────────────────────────────────────────────── */
static void shw_fail(struct zcl_command_reply *reply,
                     enum zcl_command_status status,
                     enum zcl_command_exit exit_code, const char *code,
                     const char *phase, const char *message,
                     const char *evidence)
{
    LOG_ERROR(SHW_TAG, "%s: %s (%s)", code, message,
              evidence && evidence[0] ? evidence : "-");
    zcl_command_reply_fail(reply, status, exit_code, code, phase, false,
                           false, message, evidence ? evidence : "");
}

static const char *shw_datadir(const struct zcl_command_request *request)
{
    const char *dd = json_get_str(json_get(request->input, "datadir"));
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

/* Tests may pin time through input. Release commands refuse that override:
 * persisted stamps and lifetime checks use the node wall clock. Compile-time
 * twin of shf_now; no runtime environment valve exists. */
static bool shw_now(const struct zcl_command_request *request,
                    int64_t *now_out, struct zcl_command_reply *reply)
{
    int64_t now = clock_now_wall_ms() / 1000;
    const struct json_value *v = json_get(request->input, "now_unix");
    if (v) {
#ifndef ZCL_TESTING
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_DENIED,
                 "NOW_OVERRIDE_FORBIDDEN", "validate",
                 "now_unix is test-only; release commands use the node's "
                 "wall clock for expiry and board-evidence decisions",
                 "remove now_unix");
        return false; // raw-return-ok:shw_fail-already-logged-and-set-the-reply-error
#else
        if (v->type != JSON_INT || json_get_int(v) <= 0) {
            shw_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INVALID, "BAD_NOW_UNIX", "validate",
                     "now_unix must be a positive integer", "now_unix");
            return false;
        }
        now = json_get_int(v);
#endif
    }
    *now_out = now;
    return true;
}

/* A 64-hex input into 32 bytes. */
static bool shw_hex32(const char *hex, uint8_t out[32])
{
    return hex && strlen(hex) == 64 && zcl_hex_decode_lower(hex, out, 32);
}

/* Derive Ed25519 public key and cleanse the returned seed copy. */
static void shw_derive_pubkey(uint8_t pubkey[32], const uint8_t secret[32])
{
    uint8_t sk[32];
    ed25519_keypair(pubkey, sk, secret);
    memory_cleanse(sk, sizeof(sk));
}

/* The buyer secret: exactly 64 lower-hex of the 32-byte Ed25519 seed. */
static bool shw_buyer_secret(const struct zcl_command_request *request,
                             uint8_t secret[32],
                             struct zcl_command_reply *reply)
{
    const char *hex = json_get_str(json_get(request->input, "buyer_secret"));
    if (!shw_hex32(hex, secret)) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "BAD_BUYER_SECRET", "validate",
                 "buyer_secret must be the 64-hex Ed25519 seed whose "
                 "derived pubkey signs (post) or owns (cancel) the want",
                 "buyer_secret");
        return false;
    }
    return true;
}

static bool shw_want_id(const struct zcl_command_request *request,
                        uint8_t want_id[32], struct zcl_command_reply *reply)
{
    const char *hex = json_get_str(json_get(request->input, "want_id"));
    if (!shw_hex32(hex, want_id)) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "BAD_WANT_ID", "validate",
                 "want_id must be the 64-hex id printed by app shop want "
                 "post or list", "want_id");
        return false;
    }
    return true;
}

/* Resolve node.db; a write leaf never creates it on a mistyped datadir. */
static bool shw_require_node_db_path(const char *datadir, char db_path[1024],
                                     struct zcl_command_reply *reply)
{
    if (!shop_internal_path_join(db_path, 1024, datadir, "node.db")) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "DATADIR_PATH_TOO_LONG", "normalize",
                 "datadir path is too long to address node.db", datadir);
        return false;
    }
    struct stat st;
    if (stat(db_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        shw_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "WANT_STORE_NOT_INITIALISED", "open",
                 "no node.db at this datadir — boot the node once to "
                 "create it, then re-run the want command", db_path);
        return false;
    }
    return true;
}

/* Read-only open plus v66 table check; an old store is a named refusal. */
static bool shw_open_board_readonly(const char *datadir,
                                    struct sqlite3 **db,
                                    struct node_db *ndb,
                                    struct zcl_command_reply *reply)
{
    if (!zcl_native_node_db_require_readonly(datadir, reply,
                                             "the shop want board", db, ndb))
        return false;
    static const char *const sql =
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='shop_wants'";
    sqlite3_stmt *s = NULL;
    bool present = false;
    if (sqlite3_prepare_v2(*db, sql, -1, &s, NULL) == SQLITE_OK && s) { // raw-controller-sql-ok
        present = AR_STEP_ROW(s);
    }
    if (s)
        sqlite3_finalize(s);
    if (!present) {
        zcl_native_node_db_close_readonly(db, ndb);
        shw_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "WANT_STORE_NOT_MIGRATED", "open",
                 "this node.db predates schema v66 — boot the node once so "
                 "it migrates and creates the shop_wants table, then "
                 "re-run the command", datadir);
        return false;
    }
    return true;
}

/* Write open never mints node.db; runtime open applies pending migrations. */
static bool shw_open_board_write(const char *datadir, struct node_db *ndb,
                                 struct zcl_command_reply *reply)
{
    char db_path[1024];
    if (!shw_require_node_db_path(datadir, db_path, reply)) // raw-return-ok:shw_fail-already-logged-and-set-the-reply-error
        return false;
    memset(ndb, 0, sizeof(*ndb));
    if (!node_db_open_runtime(ndb, db_path, "shop.want")) {
        shw_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "WANT_STORE_UNAVAILABLE", "open",
                 "node.db exists but could not be opened for the want "
                 "board", db_path);
        return false;
    }
    return true;
}

/* Resolve the active moderation profile without widening on corrupt policy. */
static bool shw_resolve_profile(const struct zcl_command_request *request,
                                const char *datadir, int *profile_out,
                                const char **override_out,
                                struct zcl_command_reply *reply)
{
    bool ok = false;
    char err[160] = "";
    enum market_moderation_profile active =
        market_moderation_profile_load(datadir, NULL, &ok, err, sizeof(err));
    if (!ok) {
        shw_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "MODERATION_POLICY_UNREADABLE", "moderate",
                 "the node's moderation policy file exists but is not "
                 "readable — inspect <datadir>/market/moderation.v1 "
                 "before trusting any board view", err);
        return false;
    }
    const char *override =
        json_get_str_or(request->input, "profile", NULL);
    int profile = -1;
    struct zcl_hotswap_service_lease lease = {0};
    const struct market_moderation_view_service_v1 *view =
        zcl_hotswap_service_acquire(MARKET_MODERATION_VIEW_SERVICE_ID,
                                    &lease);
    if (!view)
        view = market_moderation_view_service_builtin();
    bool resolved = view->resolve_profile(override, (int)active, &profile);
    zcl_hotswap_service_release(&lease);
    if (!resolved) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "BAD_PROFILE", "validate",
                 "unknown moderation profile override — use \"open\", "
                 "\"open-view\", \"general\", or \"general-audience.v1\"",
                 override ? override : "profile");
        return false;
    }
    *profile_out = profile;
    *override_out = (override && override[0]) ? override : NULL;
    return true;
}

/* ── app shop want post (plan/commit) ───────────────────────────────── */
/* Parse, seal, and verify the want and its identity. */
static bool shw_build_want(const struct zcl_command_request *request,
                           int64_t now_unix, struct shop_want *row,
                           struct zcl_command_reply *reply)
{
    memset(row, 0, sizeof(*row));
    struct shop_want_v1 *w = &row->want;
    w->schema_version = SHOP_WANT_VERSION;

    const struct json_value *amount = json_get(request->input,
                                               "amount_zatoshi");
    if (!amount || amount->type != JSON_INT || json_get_int(amount) <= 0) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "BAD_AMOUNT", "validate",
                 "amount_zatoshi must be a positive integer — the declared "
                 "payment terms of the want", "amount_zatoshi");
        return false;
    }
    w->amount_zatoshi = (uint64_t)json_get_int(amount);

    const char *criteria = json_get_str(json_get(request->input, "criteria"));
    size_t criteria_len = criteria ? strlen(criteria) : 0;
    if (criteria_len == 0 || criteria_len > SHOP_WANT_CRITERIA_MAX) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "BAD_CRITERIA", "validate",
                 "criteria must be 1..1024 bytes of text naming the "
                 "objectively checkable terms the result must satisfy",
                 "criteria");
        return false;
    }
    memcpy(w->criteria, criteria, criteria_len);
    w->criteria_len = (uint16_t)criteria_len;

    const char *spec_hex = json_get_str_or(request->input, "spec_hash", NULL);
    if (spec_hex && spec_hex[0] &&
        !shw_hex32(spec_hex, w->spec_hash)) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "BAD_SPEC_HASH", "validate",
                 "spec_hash must be the 64-hex SHA3-256 of the external "
                 "specification document the criteria summarize",
                 "spec_hash");
        return false;
    }

    const struct json_value *issued = json_get(request->input, "issued_unix");
    if (issued && (issued->type != JSON_INT || json_get_int(issued) <= 0)) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "BAD_ISSUED_UNIX", "validate",
                 "issued_unix must be a positive integer", "issued_unix");
        return false;
    }
    w->issued_unix = issued ? json_get_int(issued) : now_unix;
    int64_t issued_skew = w->issued_unix > now_unix
        ? w->issued_unix - now_unix : now_unix - w->issued_unix;
    if (issued_skew > SHOP_WANT_ISSUED_SKEW_SECS) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "ISSUED_TIME_SKEW", "validate",
                 "a new want's issued_unix must be within 300 seconds of "
                 "the node clock; create a fresh plan with a fresh nonce",
                 "issued_unix");
        return false;
    }

    const struct json_value *expires = json_get(request->input,
                                                "expires_unix");
    if (!expires || expires->type != JSON_INT) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_EXPIRES", "validate",
                 "expires_unix is required — a want is a standing "
                 "advertisement with an explicit expiry (at most 30 days "
                 "past issued_unix)", "expires_unix");
        return false;
    }
    w->expires_unix = json_get_int(expires);

    const struct json_value *nonce = json_get(request->input, "nonce");
    if (nonce && (nonce->type != JSON_INT || json_get_int(nonce) <= 0)) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "BAD_NONCE", "validate",
                 "nonce must be a positive integer (it defaults to "
                 "issued_unix)", "nonce");
        return false;
    }
    w->nonce = (uint64_t)(nonce ? json_get_int(nonce) : w->issued_unix);

    if (w->expires_unix <= now_unix) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "WANT_ALREADY_EXPIRED", "validate",
                 "expires_unix is not in the future — posting a closed "
                 "advertisement would put a dead row on the board",
                 "expires_unix");
        return false;
    }
    if (w->expires_unix <= w->issued_unix) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "BAD_EXPIRY_ORDER", "validate",
                 "expires_unix must be after issued_unix", "expires_unix");
        return false;
    }
    int64_t lifetime_base = w->issued_unix < now_unix
        ? w->issued_unix : now_unix;
    if (w->expires_unix - lifetime_base > SHOP_WANT_MAX_LIFETIME_SECS) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "BAD_LIFETIME", "validate",
                 "a want expires at most 30 days after both issuance and "
                 "this node's clock — re-issue instead of extending",
                 "expires_unix");
        return false;
    }
    /* The secret enters only once the document is known-valid, so no
     * early return above can strand it uncleansed on the stack. */
    uint8_t secret[32];
    if (!shw_buyer_secret(request, secret, reply)) // raw-return-ok:shw_fail-already-logged-and-set-the-reply-error
        return false;
    shw_derive_pubkey(w->buyer_pubkey, secret);
    enum shop_want_error error = shop_want_seal(w, secret);
    memory_cleanse(secret, sizeof(secret));
    if (error != SHOP_WANT_OK) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "SEAL_FAILED", "sign",
                 "the want could not be signed",
                 shop_want_error_string(error));
        return false;
    }
    /* Belt and braces: nothing reaches the board unverified. */
    error = shop_want_verify(w);
    if (error != SHOP_WANT_OK ||
        shop_want_root(w, row->want_id) != SHOP_WANT_OK) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "VERIFY_FAILED", "sign",
                 "the freshly signed want failed its own verification",
                 shop_want_error_string(error));
        return false;
    }
    row->review_state = MARKET_REVIEW_UNREVIEWED;
    row->posted_unix = now_unix;
    return true;
}

void zcl_native_handle_shop_want_post(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = shw_datadir(request);
    if (!datadir) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_DATADIR", "normalize",
                 "no datadir given and no --datadir default", "datadir");
        return;
    }
    int64_t now_unix = 0;
    if (!shw_now(request, &now_unix, reply))
        return;
    struct shop_want row;
    if (!shw_build_want(request, now_unix, &row, reply))
        return;
    struct shop_want_view_result_v1 rendered_want;
    if (!zcl_shop_want_view_render(&row, now_unix, true, &rendered_want)) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "WANT_VIEW_FAILED", "render",
                 "the pure buyer-want view refused a freshly verified want",
                 "app.shop.want.view.v1");
        return;
    }

    char id_hex[65];
    zcl_hex_encode(row.want_id, 32, id_hex);

    if (!json_get_bool_or(request->input, "confirm", false)) {
        (void)json_push_kv_str(&reply->data, "mode", "plan");
        (void)json_push_kv_str(&reply->data, "datadir", datadir);
        struct json_value want;
        json_init(&want);
        json_set_object(&want);
        zcl_shop_want_view_push_json(&want, &rendered_want);
        (void)json_push_kv(&reply->data, "want", &want);
        json_free(&want);
        (void)json_push_kv_str(&reply->data, "terms_note", SHW_TERMS_NOTE);
        (void)json_push_kv_str(&reply->data, "commit_command",
            "re-run the identical command with \"confirm\":true added to "
            "the same input (buyer_secret is never echoed)");
        return;
    }

    struct node_db ndb;
    if (!shw_open_board_write(datadir, &ndb, reply))
        return;
    struct shop_want existing;
    bool already = db_shop_want_find(&ndb, row.want_id, &existing);
    bool saved = already || db_shop_want_save(&ndb, &row);
    node_db_close(&ndb);
    if (!saved) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                 "SAVE_FAILED", "execute",
                 "the verified want could not be persisted to the board",
                 id_hex);
        return;
    }

    (void)json_push_kv_str(&reply->data, "mode", "commit");
    (void)json_push_kv_str(&reply->data, "datadir", datadir);
    (void)json_push_kv_str(&reply->data, "want_id", id_hex);
    (void)json_push_kv_bool(&reply->data, "already_posted", already);
    struct json_value want;
    json_init(&want);
    json_set_object(&want);
    zcl_shop_want_view_push_json(&want, &rendered_want);
    (void)json_push_kv(&reply->data, "want", &want);
    json_free(&want);
    (void)json_push_kv_str(&reply->data, "terms_note", SHW_TERMS_NOTE);
    (void)json_push_kv_str(&reply->data, "moderation_note",
        SHW_MODERATION_NOTE);
    (void)json_push_kv_str(&reply->data, "board_note",
        "the want is on THIS node's board; under the default "
        "general-audience.v1 profile an unreviewed want is hidden from "
        "list until this node marks it reviewed_ok (app shop want review) "
        "— identical to a freshly ingested market offer");
    reply->error.mutated = !already;
}

/* ── app shop want list (read) ──────────────────────────────────────── */
void zcl_native_handle_shop_want_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = shw_datadir(request);
    if (!datadir) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_DATADIR", "normalize",
                 "no datadir given and no --datadir default", "datadir");
        return;
    }
    int64_t now_unix = 0;
    if (!shw_now(request, &now_unix, reply))
        return;
    int profile = -1;
    const char *override = NULL;
    if (!shw_resolve_profile(request, datadir, &profile, &override, reply))
        return;

    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!shw_open_board_readonly(datadir, &db, &ndb, reply))
        return;
    bool include_closed = json_get_bool_or(request->input, "all", false);
    /* The window (capped fetch) and the market fact (true match count)
     * are different numbers the moment the board outgrows the window;
     * reporting the window as the total tells buyers the market ended
     * at the cap. */
    int total = db_shop_want_count(&ndb, now_unix, include_closed);
    if (total < 0) {
        zcl_native_node_db_close_readonly(&db, &ndb);
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "WANT_COUNT_FAILED", "board",
                 "the store refused to count matching wants; no total is "
                 "reported rather than a wrong one",
                 "app.shop.want.list.v1");
        return;
    }
    struct shop_want rows[SHOP_WANT_QUERY_CAP];
    int count = db_shop_want_list(&ndb, now_unix, include_closed, rows,
                                  SHOP_WANT_QUERY_CAP);
    zcl_native_node_db_close_readonly(&db, &ndb);

    (void)json_push_kv_str(&reply->data, "datadir", datadir);
    (void)json_push_kv_int(&reply->data, "now_unix", now_unix);
    (void)json_push_kv_str(&reply->data, "profile",
        market_moderation_profile_string((enum market_moderation_profile)profile));
    (void)json_push_kv_bool(&reply->data, "profile_override",
                            override != NULL);
    (void)json_push_kv_bool(&reply->data, "include_closed", include_closed);

    struct zcl_hotswap_service_lease moderation_lease = {0};
    const struct market_moderation_view_service_v1 *view =
        zcl_hotswap_service_acquire(MARKET_MODERATION_VIEW_SERVICE_ID,
                                    &moderation_lease);
    if (!view)
        view = market_moderation_view_service_builtin();
    struct json_value wants;
    json_init(&wants);
    json_set_array(&wants);
    int64_t hidden = 0;
    size_t rendered = 0;
    for (int i = 0; i < count; i++) {
        struct market_moderation_decision_result_v1 decision;
        if (!view->decide(profile, rows[i].review_state, &decision) ||
            !decision.valid || !decision.visible) {
            hidden++;
            continue;
        }
        if (rendered >= SHW_BOARD_PAGE) {
            /* Past the page: counted in total, not rendered. */
            continue;
        }
        struct json_value entry;
        json_init(&entry);
        json_set_object(&entry);
        struct shop_want_view_result_v1 rendered_want;
        if (!zcl_shop_want_view_render(&rows[i], now_unix, false,
                                       &rendered_want)) {
            json_free(&entry);
            json_free(&wants);
            zcl_hotswap_service_release(&moderation_lease);
            shw_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INTERNAL, "WANT_VIEW_FAILED", "render",
                     "the pure buyer-want view refused a verified board row",
                     "app.shop.want.view.v1");
            return;
        }
        zcl_shop_want_view_push_json(&entry, &rendered_want);
        (void)json_push_back(&wants, &entry);
        json_free(&entry);
        rendered++;
    }
    zcl_hotswap_service_release(&moderation_lease);
    (void)json_push_kv(&reply->data, "wants", &wants);
    json_free(&wants);
    (void)json_push_kv_int(&reply->data, "rendered", (int64_t)rendered);
    (void)json_push_kv_int(&reply->data, "total_matching", total);
    /* The window is a fetch bound, not the market: say so when the
     * match set did not fit it, so readers know rows exist past the page. */
    (void)json_push_kv_bool(&reply->data, "window_capped",
                            total > count);
    (void)json_push_kv_int(&reply->data, "hidden_by_profile", hidden);
    (void)json_push_kv_str(&reply->data, "moderation_note",
        SHW_MODERATION_NOTE);
    (void)json_push_kv_str(&reply->data, "terms_note", SHW_TERMS_NOTE);
}

/* ── app shop want status (read) ────────────────────────────────────── */
void zcl_native_handle_shop_want_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = shw_datadir(request);
    if (!datadir) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_DATADIR", "normalize",
                 "no datadir given and no --datadir default", "datadir");
        return;
    }
    int64_t now_unix = 0;
    if (!shw_now(request, &now_unix, reply))
        return;
    uint8_t want_id[32];
    if (!shw_want_id(request, want_id, reply))
        return;
    int profile = -1;
    const char *override = NULL;
    if (!shw_resolve_profile(request, datadir, &profile, &override, reply))
        return;

    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!shw_open_board_readonly(datadir, &db, &ndb, reply))
        return;
    struct shop_want row;
    bool found = db_shop_want_find(&ndb, want_id, &row);
    int64_t fulfillment_count = found
        ? db_shop_fulfill_count_for_want(&ndb, want_id) : 0;
    zcl_native_node_db_close_readonly(&db, &ndb);
    if (!found) {
        char id_hex[65];
        zcl_hex_encode(want_id, 32, id_hex);
        shw_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "WANT_NOT_FOUND", "execute",
                 "no want with this id is stored on this node's board",
                 id_hex);
        return;
    }
    /* Re-verify stored signed-wire evidence at read time. */
    bool signature_valid = shop_want_verify(&row.want) == SHOP_WANT_OK;
    struct shop_want_view_result_v1 rendered_want;
    if (!zcl_shop_want_view_render(&row, now_unix, true, &rendered_want)) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "WANT_VIEW_FAILED", "render",
                 "the pure buyer-want view refused a verified stored row",
                 "app.shop.want.view.v1");
        return;
    }
    struct market_moderation_decision_result_v1 decision;
    struct zcl_hotswap_service_lease moderation_lease = {0};
    const struct market_moderation_view_service_v1 *moderation =
        zcl_hotswap_service_acquire(MARKET_MODERATION_VIEW_SERVICE_ID,
                                    &moderation_lease);
    if (!moderation)
        moderation = market_moderation_view_service_builtin();
    bool visible = moderation->decide(profile, row.review_state, &decision) &&
        decision.valid && decision.visible;
    zcl_hotswap_service_release(&moderation_lease);

    (void)json_push_kv_str(&reply->data, "datadir", datadir);
    (void)json_push_kv_int(&reply->data, "now_unix", now_unix);
    (void)json_push_kv_str(&reply->data, "state", rendered_want.state);
    (void)json_push_kv_bool(&reply->data, "signature_valid", signature_valid);
    (void)json_push_kv_int(&reply->data, "fulfillment_count", fulfillment_count);
    (void)json_push_kv_bool(&reply->data, "fulfillment_count_available",
                            fulfillment_count >= 0);
    struct json_value want;
    json_init(&want);
    json_set_object(&want);
    zcl_shop_want_view_push_json(&want, &rendered_want);
    (void)json_push_kv(&reply->data, "want", &want);
    json_free(&want);
    (void)json_push_kv_str(&reply->data, "profile",
        market_moderation_profile_string((enum market_moderation_profile)profile));
    (void)json_push_kv_bool(&reply->data, "visible_under_profile", visible);
    (void)json_push_kv_str(&reply->data, "moderation_note",
        SHW_MODERATION_NOTE);
    (void)json_push_kv_str(&reply->data, "terms_note", SHW_TERMS_NOTE);
}

/* ── app shop want cancel (plan/commit) ─────────────────────────────── */
void zcl_native_handle_shop_want_cancel(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = shw_datadir(request);
    if (!datadir) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_DATADIR", "normalize",
                 "no datadir given and no --datadir default", "datadir");
        return;
    }
    int64_t now_unix = 0;
    if (!shw_now(request, &now_unix, reply))
        return;
    uint8_t want_id[32];
    if (!shw_want_id(request, want_id, reply))
        return;
    uint8_t secret[32];
    if (!shw_buyer_secret(request, secret, reply))
        return;
    uint8_t buyer[32];
    shw_derive_pubkey(buyer, secret);
    memory_cleanse(secret, sizeof(secret));
    char id_hex[65];
    zcl_hex_encode(want_id, 32, id_hex);

    if (!json_get_bool_or(request->input, "confirm", false)) {
        /* Plan mode must be non-mutating: open the board read-only so the
         * runtime open (which runs migrations) never fires on a plan. */
        sqlite3 *db = NULL;
        struct node_db ndb;
        if (!shw_open_board_readonly(datadir, &db, &ndb, reply))
            return;
        struct shop_want row;
        bool found = db_shop_want_find(&ndb, want_id, &row);
        zcl_native_node_db_close_readonly(&db, &ndb);
        if (found && memcmp(buyer, row.want.buyer_pubkey, 32) != 0) {
            shw_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_DENIED,
                     "WRONG_BUYER_KEY", "custody",
                     "the presented buyer_secret derives a different pubkey "
                     "than the one that signed this want — only the posting "
                     "key can cancel it", id_hex);
            return;
        }
        (void)json_push_kv_str(&reply->data, "mode", "plan");
        (void)json_push_kv_str(&reply->data, "datadir", datadir);
        (void)json_push_kv_str(&reply->data, "want_id", id_hex);
        (void)json_push_kv_bool(&reply->data, "found", found);
        if (found) {
            struct shop_want_view_result_v1 rendered_want;
            if (!zcl_shop_want_view_render(&row, now_unix, true,
                                           &rendered_want)) {
                shw_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                         ZCL_COMMAND_EXIT_INTERNAL, "WANT_VIEW_FAILED",
                         "render", "the pure buyer-want view refused a "
                         "verified cancellation-plan row",
                         "app.shop.want.view.v1");
                return;
            }
            struct json_value want;
            json_init(&want);
            json_set_object(&want);
            zcl_shop_want_view_push_json(&want, &rendered_want);
            (void)json_push_kv(&reply->data, "want", &want);
            json_free(&want);
            (void)json_push_kv_bool(&reply->data, "already_cancelled",
                                    row.cancelled_unix > 0);
        }
        (void)json_push_kv_str(&reply->data, "plan",
            "mark this want cancelled on THIS node's board (the signed "
            "row is kept as evidence; it leaves the open board); "
            "cancellation is key-checked: the secret must derive the "
            "want's buyer pubkey");
        (void)json_push_kv_str(&reply->data, "commit_command",
            "re-run the identical command with \"confirm\":true added to "
            "the same input (buyer_secret is never echoed)");
        return;
    }

    struct node_db ndb;
    if (!shw_open_board_write(datadir, &ndb, reply))
        return;
    struct shop_want row;
    bool found = db_shop_want_find(&ndb, want_id, &row);
    if (found && memcmp(buyer, row.want.buyer_pubkey, 32) != 0) {
        node_db_close(&ndb);
        shw_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_DENIED,
                 "WRONG_BUYER_KEY", "custody",
                 "the presented buyer_secret derives a different pubkey "
                 "than the one that signed this want — only the posting "
                 "key can cancel it", id_hex);
        return;
    }
    if (!found) {
        node_db_close(&ndb);
        shw_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "WANT_NOT_FOUND", "execute",
                 "no want with this id is stored on this node's board",
                 id_hex);
        return;
    }
    bool already = row.cancelled_unix > 0;
    bool marked = already ||
                  db_shop_want_mark_cancelled(&ndb, want_id, now_unix);
    node_db_close(&ndb);
    if (!marked) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                 "CANCEL_FAILED", "execute",
                 "the cancellation could not be persisted", id_hex);
        return;
    }
    (void)json_push_kv_str(&reply->data, "mode", "commit");
    (void)json_push_kv_str(&reply->data, "datadir", datadir);
    (void)json_push_kv_str(&reply->data, "want_id", id_hex);
    (void)json_push_kv_bool(&reply->data, "cancelled", true);
    (void)json_push_kv_bool(&reply->data, "already_cancelled", already);
    (void)json_push_kv_str(&reply->data, "cancel_note",
        "cancellation is local and key-checked; the signed row stays "
        "stored as evidence and the want leaves the open board");
    reply->error.mutated = !already;
}

/* ── app shop want review (plan/commit) ─────────────────────────────── */
void zcl_native_handle_shop_want_review(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = shw_datadir(request);
    if (!datadir) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_DATADIR", "normalize",
                 "no datadir given and no --datadir default", "datadir");
        return;
    }
    uint8_t want_id[32];
    if (!shw_want_id(request, want_id, reply))
        return;
    const char *state_text =
        json_get_str(json_get(request->input, "review_state"));
    int state = market_review_state_from_string(state_text);
    if (state < 0) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "BAD_REVIEW_STATE", "validate",
                 "review_state must be one of \"unreviewed\", "
                 "\"reviewed_ok\", \"sensitive\"", "review_state");
        return;
    }
    char id_hex[65];
    zcl_hex_encode(want_id, 32, id_hex);

    if (!json_get_bool_or(request->input, "confirm", false)) {
        /* Plan mode must be non-mutating: open the board read-only so the
         * runtime open (which runs migrations) never fires on a plan. */
        sqlite3 *db = NULL;
        struct node_db ndb;
        if (!shw_open_board_readonly(datadir, &db, &ndb, reply))
            return;
        struct shop_want row;
        bool found = db_shop_want_find(&ndb, want_id, &row);
        zcl_native_node_db_close_readonly(&db, &ndb);
        if (!found) {
            shw_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                     "WANT_NOT_FOUND", "execute",
                     "no want with this id is stored on this node's board",
                     id_hex);
            return;
        }
        (void)json_push_kv_str(&reply->data, "mode", "plan");
        (void)json_push_kv_str(&reply->data, "datadir", datadir);
        (void)json_push_kv_str(&reply->data, "want_id", id_hex);
        (void)json_push_kv_str(&reply->data, "current_review_state",
            market_review_state_string((enum market_review_state)row.review_state));
        (void)json_push_kv_str(&reply->data, "requested_review_state",
                               state_text);
        (void)json_push_kv_str(&reply->data, "plan",
            "set this node's LOCAL curation mark on the want — identical "
            "semantics to zmarket_review_set on an offer: the mark decides "
            "visibility under the node's moderation profile; it is never "
            "gossiped, never part of the signed wire, and a hidden want "
            "stays stored");
        (void)json_push_kv_str(&reply->data, "commit_command",
            "re-run the identical command with \"confirm\":true added to "
            "the same input");
        return;
    }

    struct node_db ndb;
    if (!shw_open_board_write(datadir, &ndb, reply))
        return;
    struct shop_want row;
    bool found = db_shop_want_find(&ndb, want_id, &row);
    if (!found) {
        node_db_close(&ndb);
        shw_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "WANT_NOT_FOUND", "execute",
                 "no want with this id is stored on this node's board",
                 id_hex);
        return;
    }
    const char *previous =
        market_review_state_string((enum market_review_state)row.review_state);

    bool changed = row.review_state != state;
    bool set = !changed ||
               db_shop_want_set_review_state(&ndb, want_id, state_text);
    node_db_close(&ndb);
    if (!set) {
        shw_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                 "REVIEW_FAILED", "execute",
                 "the curation mark could not be persisted", id_hex);
        return;
    }
    (void)json_push_kv_str(&reply->data, "mode", "commit");
    (void)json_push_kv_str(&reply->data, "datadir", datadir);
    (void)json_push_kv_str(&reply->data, "want_id", id_hex);
    (void)json_push_kv_str(&reply->data, "review_state", state_text);
    (void)json_push_kv_str(&reply->data, "previous_review_state", previous);
    (void)json_push_kv_bool(&reply->data, "changed", changed);
    (void)json_push_kv_str(&reply->data, "moderation_note",
        SHW_MODERATION_NOTE);
    reply->error.mutated = changed;
}
