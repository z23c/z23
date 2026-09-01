/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `app shop want fulfill *` — Slice E supply-side fulfillment claims.
 * A seller signs an answer to one stored want, binding the direct SHA3 of
 * the delivered bytes, their content.v2 CAS manifest root, and optional
 * build/fuzz/benchmark receipts which this node re-verifies. No input boolean
 * can assert that work passed. No award, ZCL transfer, or ZC23 issuance exists
 * here; award/accept remains a separately owner-promoted follow-up.
 */

#include "controllers/shop_native_handler.h"
#include "base/bytes.h"
#include "controllers/shop_native_fulfill_internal.h"

#include "base/cleanse.h"
#include "base/hex.h"
#include "command/native_command.h"
#include "controllers/native_handler_body.h"
#include "crypto/ed25519.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "models/review_state.h"
#include "models/shop_fulfill.h"
#include "models/shop_want.h"
#include "services/shop_fulfill_evidence_service.h"
#include "services/shop_want_view_service.h"
#include "services/market_moderation_service.h"
#include "services/market_moderation_view_service.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SHF_PAGE 8u
#define SHF_TERMS_NOTE \
    "a fulfillment is a signed, CAS-bound work claim — not an award, " \
    "escrow, payment channel, or value transfer; ZC23/ZCL movement stays " \
    "simulation/plan-only and acceptance is outside this slice"

struct shf_evidence {
    struct shop_fulfill_artifact_fact artifact;
    struct shop_fulfill_receipt_fact receipts[3];
    bool claimed[3];
    bool verified[3];
};

static bool shf_want_open(struct node_db *ndb, const uint8_t want_id[32],
                          int64_t now, struct shop_want *out,
                          struct zcl_command_reply *reply)
{
    char hex[65];
    zcl_hex_encode(want_id, 32, hex);
    if (!db_shop_want_find(ndb, want_id, out)) {
        shf_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "WANT_NOT_FOUND", "validate",
                 "the named want is not stored on this node's board", hex);
        return false; // raw-return-ok:reply-already-carries-named-error
    }
    if (shop_want_verify(&out->want) != SHOP_WANT_OK) {
        shf_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "WANT_SIGNATURE_INVALID", "validate",
                 "the stored want no longer passes its signed-wire proof",
                 hex);
        return false; // raw-return-ok:reply-already-carries-named-error
    }
    if (out->cancelled_unix > 0 || out->want.expires_unix <= now) {
        shf_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "WANT_CLOSED", "validate",
                 "the want is cancelled or expired and cannot accept a new "
                 "fulfillment claim", hex);
        return false; // raw-return-ok:reply-already-carries-named-error
    }
    return true;
}

static bool shf_verify_evidence(struct node_db *ndb, const char *datadir,
                                const struct shop_fulfill_v1 *f, int64_t now,
                                struct shf_evidence *out)
{
    memset(out, 0, sizeof(*out));
    struct zcl_result artifact = shop_fulfill_artifact_verify(
        datadir, f->content_root, f->artifact_root, &out->artifact);
    bool ok = artifact.ok;
    const uint8_t *ids[3] = {f->build_receipt_id, f->fuzz_receipt_id,
                             f->bench_receipt_id};
    for (size_t i = 0; i < 3; i++) {
        out->claimed[i] = zcl_bytes_any_set(ids[i], 32);
        if (!out->claimed[i]) continue;
        struct zcl_result receipt = shop_fulfill_receipt_verify(
            ndb, datadir, ids[i], (enum shop_fulfill_receipt_kind)i,
            now, &out->receipts[i]);
        out->verified[i] = receipt.ok;
        ok = ok && out->verified[i];
    }
    return ok;
}

static void shf_push_evidence(struct json_value *into,
                              const struct shop_fulfill_v1 *f,
                              const struct shf_evidence *facts)
{
    (void)json_push_kv_bool(into, "artifact_verified",
                            facts->artifact.artifact_sha3_valid &&
                            facts->artifact.manifest_root_valid);
    (void)json_push_kv_int(into, "artifact_size_bytes",
                           (int64_t)facts->artifact.size_bytes);
    (void)json_push_kv_str(into, "artifact_evidence",
                           facts->artifact.reason);
    static const char *const names[3] = {
        "build_receipt", "fuzz_receipt", "bench_receipt"};
    const uint8_t *ids[3] = {f->build_receipt_id, f->fuzz_receipt_id,
                             f->bench_receipt_id};
    for (size_t i = 0; i < 3; i++) {
        if (!facts->claimed[i]) continue;
        char hex[65];
        zcl_hex_encode(ids[i], 32, hex);
        struct json_value receipt;
        json_init(&receipt);
        json_set_object(&receipt);
        (void)json_push_kv_str(&receipt, "receipt_id", hex);
        (void)json_push_kv_bool(&receipt, "verified_now",
                                facts->verified[i]);
        (void)json_push_kv_bool(&receipt, "artifact_binding_proven",
                                facts->receipts[i].artifact_binding_valid);
        (void)json_push_kv_str(&receipt, "reason",
                               facts->receipts[i].reason);
        if (facts->receipts[i].action_kind[0])
            (void)json_push_kv_str(&receipt, "action_kind",
                                   facts->receipts[i].action_kind);
        if (facts->receipts[i].signer_pubkey[0])
            (void)json_push_kv_str(&receipt, "signer_pubkey",
                                   facts->receipts[i].signer_pubkey);
        (void)json_push_kv(&into[0], names[i], &receipt);
        json_free(&receipt);
    }
}

static void shf_push_row(struct json_value *into,
                         const struct shop_fulfill *row, int64_t now,
                         const struct shf_evidence *facts)
{
    char hex[65];
    zcl_hex_encode(row->fulfill_id, 32, hex);
    (void)json_push_kv_str(into, "fulfill_id", hex);
    zcl_hex_encode(row->fulfill.want_id, 32, hex);
    (void)json_push_kv_str(into, "want_id", hex);
    zcl_hex_encode(row->fulfill.seller_pubkey, 32, hex);
    (void)json_push_kv_str(into, "seller_pubkey", hex);
    zcl_hex_encode(row->fulfill.artifact_root, 32, hex);
    (void)json_push_kv_str(into, "artifact_root", hex);
    zcl_hex_encode(row->fulfill.content_root, 32, hex);
    (void)json_push_kv_str(into, "content_root", hex);
    (void)json_push_kv_int(into, "issued_unix", row->fulfill.issued_unix);
    (void)json_push_kv_int(into, "expires_unix", row->fulfill.expires_unix);
    (void)json_push_kv_str(into, "state",
        row->withdrawn_unix > 0 ? "withdrawn" :
        row->fulfill.expires_unix <= now ? "expired" : "active");
    (void)json_push_kv_bool(into, "signature_valid",
        shop_fulfill_verify(&row->fulfill) == SHOP_FULFILL_OK);
    (void)json_push_kv_str(into, "review_state",
        market_review_state_string(
            (enum market_review_state)row->review_state));
    if (row->withdrawn_unix > 0)
        (void)json_push_kv_int(into, "withdrawn_unix", row->withdrawn_unix);
    if (facts) shf_push_evidence(into, &row->fulfill, facts);
}

static bool shf_build_row(const struct zcl_command_request *request,
                          int64_t now, struct shop_fulfill *row,
                          struct zcl_command_reply *reply)
{
    memset(row, 0, sizeof(*row));
    struct shop_fulfill_v1 *f = &row->fulfill;
    f->schema_version = SHOP_FULFILL_VERSION;
    if (!shf_required_id(request, "want_id", f->want_id, reply) ||
        !shf_required_id(request, "artifact_root", f->artifact_root, reply) ||
        !shf_required_id(request, "content_root", f->content_root, reply) ||
        !shf_optional_id(request, "build_receipt_id",
                         f->build_receipt_id, reply) ||
        !shf_optional_id(request, "fuzz_receipt_id",
                         f->fuzz_receipt_id, reply) ||
        !shf_optional_id(request, "bench_receipt_id",
                         f->bench_receipt_id, reply))
        return false;

    const struct json_value *issued = json_get(request->input, "issued_unix");
    if (!issued || issued->type != JSON_INT || json_get_int(issued) <= 0) {
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_ISSUED_UNIX", "validate",
                 "issued_unix is required so plan and commit sign identical "
                 "bytes; use the current Unix time", "issued_unix");
        return false;
    }
    f->issued_unix = json_get_int(issued);
    const struct json_value *expires = json_get(request->input,
                                                "expires_unix");
    if (!expires || expires->type != JSON_INT) {
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_EXPIRES", "validate",
                 "expires_unix is required for a fulfillment claim",
                 "expires_unix");
        return false;
    }
    f->expires_unix = json_get_int(expires);
    const struct json_value *nonce = json_get(request->input, "nonce");
    if (!nonce || nonce->type != JSON_INT || json_get_int(nonce) <= 0) {
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_NONCE", "validate",
                 "nonce is required so plan and commit sign identical bytes; "
                 "use a fresh positive integer per seller", "nonce");
        return false;
    }
    f->nonce = (uint64_t)json_get_int(nonce);
    if (f->expires_unix <= now || f->expires_unix <= f->issued_unix ||
        f->expires_unix - f->issued_unix >
            SHOP_FULFILL_MAX_LIFETIME_SECS) {
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "BAD_FULFILLMENT_WINDOW", "validate",
                 "fulfillment expiry must be future, after issue, and no "
                 "more than 30 days later", "expires_unix");
        return false;
    }
    uint8_t seed[32];
    if (!shf_seller_secret(request, seed, reply)) return false;
    shf_derive_pubkey(f->seller_pubkey, seed);
    enum shop_fulfill_error error = shop_fulfill_seal(f, seed);
    memory_cleanse(seed, sizeof(seed));
    if (error != SHOP_FULFILL_OK ||
        shop_fulfill_verify(f) != SHOP_FULFILL_OK ||
        shop_fulfill_root(f, row->fulfill_id) != SHOP_FULFILL_OK) {
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "FULFILLMENT_SEAL_FAILED", "sign",
                 "the signed fulfillment failed self-verification",
                 shop_fulfill_error_string(error));
        return false;
    }
    row->review_state = MARKET_REVIEW_UNREVIEWED;
    row->posted_unix = now;
    return true;
}

static bool shf_validate_claim(struct node_db *ndb, const char *datadir,
                               const struct shop_fulfill *row, int64_t now,
                               struct shf_evidence *facts,
                               struct zcl_command_reply *reply)
{
    struct shop_want want;
    if (!shf_want_open(ndb, row->fulfill.want_id, now, &want, reply))
        return false; // raw-return-ok:reply-already-carries-named-error
    if (row->fulfill.expires_unix > want.want.expires_unix) {
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "FULFILLMENT_OUTLIVES_WANT", "validate",
                 "a fulfillment claim cannot expire after its want",
                 "expires_unix");
        return false;
    }
    if (!shf_verify_evidence(ndb, datadir, &row->fulfill, now, facts)) {
        if (!facts->artifact.artifact_sha3_valid ||
            !facts->artifact.manifest_root_valid) {
            shf_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                     ZCL_COMMAND_EXIT_BLOCKED,
                     "FULFILLMENT_EVIDENCE_UNVERIFIED", "evidence",
                     "the content.v2 manifest and CAS bytes did not "
                     "re-verify; re-register the exact delivered bytes",
                     facts->artifact.reason);
            return false;
        }
        char evidence[256];
        (void)snprintf(evidence, sizeof(evidence),
                       "receipt_kind=unknown reason=unverified");
        for (size_t i = 0; i < 3; i++) {
            if (!facts->claimed[i] || facts->verified[i]) continue;
            const uint8_t *ids[3] = {row->fulfill.build_receipt_id,
                row->fulfill.fuzz_receipt_id, row->fulfill.bench_receipt_id};
            char id[65];
            zcl_hex_encode(ids[i], 32, id);
            (void)snprintf(evidence, sizeof(evidence),
                           "receipt_kind=%s receipt_id=%s reason=%s",
                           shop_fulfill_receipt_kind_name(
                               (enum shop_fulfill_receipt_kind)i),
                           id, facts->receipts[i].reason);
            break;
        }
        shf_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "FULFILLMENT_EVIDENCE_UNVERIFIED", "evidence",
                 "a claimed receipt failed node re-verification; remove the "
                 "reference or supply an admitted receipt of the named kind",
                 evidence);
        return false;
    }
    return true;
}

static bool shf_same_wire(const struct shop_fulfill *a,
                          const struct shop_fulfill *b)
{
    uint8_t aw[SHOP_FULFILL_WIRE_BYTES], bw[SHOP_FULFILL_WIRE_BYTES];
    return a && b &&
        shop_fulfill_encode(&a->fulfill, aw) == SHOP_FULFILL_OK &&
        shop_fulfill_encode(&b->fulfill, bw) == SHOP_FULFILL_OK &&
        memcmp(aw, bw, sizeof(aw)) == 0;
}

static bool shf_issued_fresh(const struct shop_fulfill *row, int64_t now,
                             struct zcl_command_reply *reply)
{
    int64_t issued = row->fulfill.issued_unix;
    int64_t skew = issued > now ? issued - now : now - issued;
    if (skew <= 300) return true;
    shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
             "ISSUED_TIME_SKEW", "validate",
             "a new fulfillment's issued_unix must be within 300 seconds "
             "of the node clock; create a fresh plan with a fresh nonce",
             "issued_unix");
    return false;
}

void zcl_native_handle_shop_want_fulfill_post(
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
    int64_t now = 0;
    if (!shf_now(request, &now, reply)) return;
    struct shop_fulfill row;
    if (!shf_build_row(request, now, &row, reply)) return;

    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!shf_open_readonly(datadir, &db, &ndb, reply)) return;
    struct shop_fulfill existing, replay;
    bool already = db_shop_fulfill_find(&ndb, row.fulfill_id, &existing);
    if (already && !shf_same_wire(&existing, &row)) {
        zcl_native_node_db_close_readonly(&db, &ndb);
        shf_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_DENIED,
                 "FULFILLMENT_ID_COLLISION", "replay",
                 "the stored row under this fulfillment id carries different "
                 "signed bytes; quarantine and inspect node.db", "fulfill_id");
        return;
    }
    struct shf_evidence facts;
    bool valid = already ||
        (shf_issued_fresh(&row, now, reply) &&
         shf_validate_claim(&ndb, datadir, &row, now, &facts, reply));
    bool nonce_replay = !already && valid &&
        db_shop_fulfill_find_seller_nonce(&ndb, row.fulfill.seller_pubkey,
                                          row.fulfill.nonce, &replay);
    zcl_native_node_db_close_readonly(&db, &ndb);
    if (!valid) return;
    if (nonce_replay) {
        shf_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_DENIED,
                 "FULFILL_NONCE_REPLAY", "replay",
                 "this seller already used the nonce for a different "
                 "fulfillment", "seller_pubkey+nonce");
        return;
    }

    if (!json_get_bool_or(request->input, "confirm", false)) {
        (void)json_push_kv_str(&reply->data, "mode", "plan");
        struct json_value claim;
        json_init(&claim);
        json_set_object(&claim);
        shf_push_row(&claim, &row, now, already ? NULL : &facts);
        (void)json_push_kv(&reply->data, "fulfillment", &claim);
        json_free(&claim);
        (void)json_push_kv_bool(&reply->data, "already_posted", already);
        (void)json_push_kv_str(&reply->data, "terms_note", SHF_TERMS_NOTE);
        (void)json_push_kv_str(&reply->data, "commit_command",
            "re-run with the exact same issued_unix and nonce plus "
            "\"confirm\":true; seller_secret is never echoed");
        return;
    }

    if (!shf_open_write(datadir, &ndb, reply)) return;
    already = db_shop_fulfill_find(&ndb, row.fulfill_id, &existing);
    if (already && !shf_same_wire(&existing, &row)) {
        node_db_close(&ndb);
        shf_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_DENIED,
                 "FULFILLMENT_ID_COLLISION", "replay",
                 "the stored row under this fulfillment id carries different "
                 "signed bytes; quarantine and inspect node.db", "fulfill_id");
        return;
    }
    if (!already) {
        if (!shf_issued_fresh(&row, now, reply) ||
            !shf_validate_claim(&ndb, datadir, &row, now, &facts, reply)) {
            node_db_close(&ndb);
            return;
        }
        nonce_replay = db_shop_fulfill_find_seller_nonce(
            &ndb, row.fulfill.seller_pubkey, row.fulfill.nonce, &replay);
        if (nonce_replay) {
            node_db_close(&ndb);
            shf_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                     ZCL_COMMAND_EXIT_DENIED, "FULFILL_NONCE_REPLAY",
                     "replay", "this seller already used the nonce for a "
                     "different fulfillment", "seller_pubkey+nonce");
            return;
        }
    }
    bool saved = already || db_shop_fulfill_save(&ndb, &row);
    node_db_close(&ndb);
    if (!saved) {
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                 "FULFILLMENT_SAVE_FAILED", "execute",
                 "the verified fulfillment could not be persisted", "node.db");
        return;
    }
    char id[65];
    zcl_hex_encode(row.fulfill_id, 32, id);
    (void)json_push_kv_str(&reply->data, "mode", "commit");
    (void)json_push_kv_str(&reply->data, "fulfill_id", id);
    (void)json_push_kv_bool(&reply->data, "already_posted", already);
    (void)json_push_kv_str(&reply->data, "terms_note", SHF_TERMS_NOTE);
    reply->error.mutated = !already;
}

void zcl_native_handle_shop_want_fulfill_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *datadir = shf_datadir(request);
    int64_t now = 0;
    uint8_t want_id[32];
    if (!datadir) {
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_DATADIR", "normalize",
                 "no datadir given and no --datadir default", "datadir");
        return;
    }
    if (!shf_now(request, &now, reply) ||
        !shf_required_id(request, "want_id", want_id, reply)) return;
    int profile = -1;
    if (!shf_resolve_profile(request, datadir, &profile, reply)) return;
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!shf_open_readonly(datadir, &db, &ndb, reply)) return;
    struct shop_want want;
    if (!db_shop_want_find(&ndb, want_id, &want)) {
        zcl_native_node_db_close_readonly(&db, &ndb);
        shf_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "WANT_NOT_FOUND", "execute",
                 "the named want is not stored on this node's board",
                 "want_id");
        return;
    }
    bool all = json_get_bool_or(request->input, "all", false);
    /* Window vs market fact, as on the want board: total_matching is the
     * uncapped match count, not however many rows fit the fetch cap. */
    int total = db_shop_fulfill_list_count_for_want(&ndb, want_id, now, all);
    if (total < 0) {
        zcl_native_node_db_close_readonly(&db, &ndb);
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "FULFILL_COUNT_FAILED", "execute",
                 "the store refused to count matching fulfillments; no "
                 "total is reported rather than a wrong one",
                 "app.shop.want.fulfill.list.v1");
        return;
    }
    struct shop_fulfill rows[SHOP_FULFILL_QUERY_CAP];
    int count = db_shop_fulfill_list_for_want(
        &ndb, want_id, now, all, rows, SHOP_FULFILL_QUERY_CAP);
    struct json_value list;
    json_init(&list);
    json_set_array(&list);
    size_t rendered = 0;
    int64_t hidden = 0;
    const struct market_moderation_view_service_v1 *view =
        market_moderation_view_service_builtin();
    for (int i = 0; i < count; i++) {
        struct market_moderation_decision_result_v1 decision;
        if (!view->decide(profile, rows[i].review_state, &decision) ||
            !decision.valid || !decision.visible) {
            hidden++;
            continue;
        }
        if (rendered >= SHF_PAGE) continue;
        struct shf_evidence facts;
        (void)shf_verify_evidence(&ndb, datadir, &rows[i].fulfill, now,
                                  &facts);
        struct json_value entry;
        json_init(&entry);
        json_set_object(&entry);
        shf_push_row(&entry, &rows[i], now, &facts);
        (void)json_push_back(&list, &entry);
        json_free(&entry);
        rendered++;
    }
    zcl_native_node_db_close_readonly(&db, &ndb);
    char want_hex[65];
    zcl_hex_encode(want_id, 32, want_hex);
    (void)json_push_kv_str(&reply->data, "want_id", want_hex);
    (void)json_push_kv_str(&reply->data, "profile",
        market_moderation_profile_string(
            (enum market_moderation_profile)profile));
    (void)json_push_kv_bool(&reply->data, "include_closed", all);
    (void)json_push_kv(&reply->data, "fulfillments", &list);
    json_free(&list);
    (void)json_push_kv_int(&reply->data, "rendered", (int64_t)rendered);
    (void)json_push_kv_int(&reply->data, "total_matching", total);
    /* Rows exist past the page whenever the match set outgrew the
     * fetch window — say so instead of letting the cap read as the end. */
    (void)json_push_kv_bool(&reply->data, "window_capped",
                            total > count);
    (void)json_push_kv_int(&reply->data, "hidden_by_profile", hidden);
    (void)json_push_kv_str(&reply->data, "facts_note",
        "signature, CAS bytes, and every claimed receipt are re-verified "
        "facts; receipt association is seller-signature-bound, not proof "
        "that a typed candidate/output root equals the raw artifact SHA3; "
        "signing identities never imply operator independence");
    (void)json_push_kv_str(&reply->data, "terms_note", SHF_TERMS_NOTE);
}

void zcl_native_handle_shop_want_fulfill_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *datadir = shf_datadir(request);
    int64_t now = 0;
    uint8_t fulfill_id[32];
    if (!datadir) {
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_DATADIR", "normalize",
                 "no datadir given and no --datadir default", "datadir");
        return;
    }
    if (!shf_now(request, &now, reply) ||
        !shf_required_id(request, "fulfill_id", fulfill_id, reply)) return;
    int profile = -1;
    if (!shf_resolve_profile(request, datadir, &profile, reply)) return;
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!shf_open_readonly(datadir, &db, &ndb, reply)) return;
    struct shop_fulfill row;
    if (!db_shop_fulfill_find(&ndb, fulfill_id, &row)) {
        zcl_native_node_db_close_readonly(&db, &ndb);
        shf_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "FULFILLMENT_NOT_FOUND", "execute",
                 "no fulfillment with this id is stored on this node",
                 "fulfill_id");
        return;
    }
    struct shf_evidence facts;
    bool evidence_valid = shf_verify_evidence(
        &ndb, datadir, &row.fulfill, now, &facts);
    struct market_moderation_decision_result_v1 decision;
    bool visible = market_moderation_view_service_builtin()->decide(
        profile, row.review_state, &decision) && decision.valid &&
        decision.visible;
    const struct shop_fulfill_status_view_input_v1 view_input = {
        .signature_valid =
            shop_fulfill_verify(&row.fulfill) == SHOP_FULFILL_OK,
        .evidence_valid = evidence_valid,
        .visible = visible,
        .withdrawn = row.withdrawn_unix > 0,
        .expired = row.fulfill.expires_unix <= now,
    };
    struct shop_fulfill_status_view_result_v1 view;
    struct zcl_hotswap_service_lease lease = {0};
    const struct shop_want_view_service_v1 *view_service =
        zcl_hotswap_service_acquire(SHOP_WANT_VIEW_SERVICE_ID, &lease);
    if (!view_service) view_service = shop_want_view_service_builtin();
    bool view_ok = view_service->render_fulfillment_status(&view_input,
                                                           &view);
    zcl_hotswap_service_release(&lease);
    zcl_native_node_db_close_readonly(&db, &ndb);
    if (!view_ok) {
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                 "FULFILLMENT_VIEW_FAILED", "render",
                 "the pure fulfillment status view refused verified facts",
                 "app.shop.want.fulfill.status");
        return;
    }
    struct json_value claim;
    json_init(&claim);
    json_set_object(&claim);
    shf_push_row(&claim, &row, now, &facts);
    (void)json_push_kv(&reply->data, "fulfillment", &claim);
    json_free(&claim);
    (void)json_push_kv_bool(&reply->data, "evidence_valid_now",
                            evidence_valid);
    (void)json_push_kv_str(&reply->data, "profile",
        market_moderation_profile_string(
            (enum market_moderation_profile)profile));
    (void)json_push_kv_bool(&reply->data, "visible_under_profile", visible);
    (void)json_push_kv_str(&reply->data, "readiness", view.readiness);
    (void)json_push_kv_str(&reply->data, "next_action", view.next_action);
    (void)json_push_kv_str(&reply->data, "terms_note", SHF_TERMS_NOTE);
}

void zcl_native_handle_shop_want_fulfill_withdraw(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *datadir = shf_datadir(request);
    int64_t now = 0;
    uint8_t fulfill_id[32], seed[32], seller[32];
    if (!datadir) {
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_DATADIR", "normalize",
                 "no datadir given and no --datadir default", "datadir");
        return;
    }
    if (!shf_now(request, &now, reply) ||
        !shf_required_id(request, "fulfill_id", fulfill_id, reply) ||
        !shf_seller_secret(request, seed, reply)) return;
    shf_derive_pubkey(seller, seed);
    memory_cleanse(seed, sizeof(seed));

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
    if (!found || memcmp(seller, row.fulfill.seller_pubkey, 32) != 0) {
        if (confirm) node_db_close(&ndb);
        else zcl_native_node_db_close_readonly(&db, &ndb);
        shf_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                 found ? ZCL_COMMAND_EXIT_DENIED : ZCL_COMMAND_EXIT_BLOCKED,
                 found ? "WRONG_SELLER_KEY" : "FULFILLMENT_NOT_FOUND",
                 found ? "custody" : "execute",
                 found ? "only the Ed25519 key that signed the fulfillment "
                         "may withdraw it"
                       : "no fulfillment with this id is stored on this node",
                 "fulfill_id");
        return;
    }
    bool already = row.withdrawn_unix > 0;
    if (!confirm) {
        zcl_native_node_db_close_readonly(&db, &ndb);
        (void)json_push_kv_str(&reply->data, "mode", "plan");
        (void)json_push_kv_bool(&reply->data, "already_withdrawn", already);
        (void)json_push_kv_str(&reply->data, "plan",
            "mark the claim withdrawn on this node while retaining its "
            "signed wire as evidence; no value moves");
        (void)json_push_kv_str(&reply->data, "commit_command",
            "re-run the identical command with \"confirm\":true added; "
            "seller_secret is never echoed");
        return;
    }
    bool marked = already ||
        db_shop_fulfill_mark_withdrawn(&ndb, fulfill_id, now);
    node_db_close(&ndb);
    if (!marked) {
        shf_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                 "WITHDRAW_FAILED", "execute",
                 "the fulfillment withdrawal could not be persisted",
                 "fulfill_id");
        return;
    }
    (void)json_push_kv_str(&reply->data, "mode", "commit");
    (void)json_push_kv_bool(&reply->data, "withdrawn", true);
    (void)json_push_kv_bool(&reply->data, "already_withdrawn", already);
    (void)json_push_kv_str(&reply->data, "terms_note", SHF_TERMS_NOTE);
    reply->error.mutated = !already;
}

/* ── Hot-swappable leaves ──────────────────────────────────────────────────
 * Read-only FULFILMENT projections: offers against a want, and one offer. Every mutating sibling in this file is
 * absent from the table; the loader refuses to re-point a leaf that is
 * missing from this file's row in config/hotswap_swappable.def. */
#if defined(ZCL_HOTSWAP_GEN) || defined(ZCL_HOTSWAP_MODULE_GEN)
#define ZCL_HOTSWAP_PROBE_LEAF "app.shop.want.fulfill.list"
#include "hotswap/hotswap_register.h"
ZCL_HOTSWAP_LEAVES_BEGIN(shop_fulfill)
ZCL_HOTSWAP_LEAF("app.shop.want.fulfill.list", zcl_native_handle_shop_want_fulfill_list)
ZCL_HOTSWAP_LEAF("app.shop.want.fulfill.status", zcl_native_handle_shop_want_fulfill_status)
ZCL_HOTSWAP_LEAVES_END(shop_fulfill)
#endif
