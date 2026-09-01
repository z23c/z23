/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the slice-10 `zcode badge` leaves plus the
 * contributor integration — SIMULATED ZCODE Badges (permanent
 * achievement evidence; SIMULATED ZSLP-based assets only: no real ZSLP
 * mint, no wallet call, no on-chain asset — the owner-reviewed real
 * issuance is slice 15 and is NOT built here):
 *
 *   zcode badge eligible       which badges one contributor qualifies
 *                              for RIGHT NOW, with the evidence facts;
 *                              unavailable types (popular-package,
 *                              rare-package-seeder) named honestly
 *   zcode badge plan           assemble one dedup-checked issuance batch
 *                              for one contributor (contributor + type +
 *                              period rows, evidence roots, policy id,
 *                              unique per-issuer sequences); the only
 *                              mutation is the persisted plan id
 *   zcode badge issue          commit a planned batch SIMULATED: re-
 *                              validates every row against CURRENT facts
 *                              and the CURRENT store, signs each badge
 *                              with the operator-held issuer key (the
 *                              secret never enters contexts/commons/modules/vcs — the handler
 *                              signs through a callback), persists the
 *                              signed badge wires, and writes the commit
 *                              record last. Idempotent: a replay is a
 *                              named duplicate, never a double-issue
 *   zcode contributor badges   the earned badges of one contributor —
 *                              PERMANENT: a later rank loss never
 *                              revokes them
 *
 * Truth discipline (unchanged from slices 3-9): durable wires under
 * <datadir>/zcode/badges are the only badge truth; the store is
 * replayed (and every badge signature re-verified) on every call, so a
 * one-shot CLI agrees with a node. Every rejection names the exact
 * failed rule. */

#include "base/hex.h"
#include "command/native_command.h"

#include "core/uint256.h"
#include "json/json.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "platform/time_compat.h"
#include "vcs/package_badge.h"
#include "vcs/package_badge_eligible.h"
#include "vcs/package_index.h"
#include "vcs/package_rank.h"
#include "vcs/package_reward.h"

#include <stdio.h>
#include <string.h>

/* Display page bound (the zcode list budget). */
#define ZB_PAGE_CAP 32u

/* ── small input helpers (the native_zcode_* pattern) ───────────────── */

static const char *zb_input_str(const struct json_value *input,
                                const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v ? json_get_str(v) : NULL;
}

static const char *zb_datadir(const struct zcl_command_request *request)
{
    const char *dd = zb_input_str(request->input, "datadir");
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

/* Resolve the datadir into <datadir>/zcode, or fail the reply. */
static bool zb_zcode_dir(const struct zcl_command_request *request,
                         struct zcl_command_reply *reply,
                         const char *command, char out[4400])
{
    const char *datadir = zb_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given (input datadir or --datadir)",
                               command);
        return false;
    }
    int n = snprintf(out, 4400, "%s/zcode", datadir);
    if (n < 0 || (size_t)n >= 4400) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "DATADIR_TOO_LONG",
                               "normalize", false, false,
                               "datadir path too long", datadir);
        return false;
    }
    return true;
}

static bool zb_pubkey_input(const struct zcl_command_request *request,
                            struct zcl_command_reply *reply,
                            uint8_t pubkey[33])
{
    const char *hex = zb_input_str(request->input, "pubkey");
    if (!hex || !zcl_hex_decode(hex, pubkey, 33)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_PUBKEY",
                               "normalize", false, false,
                               "pubkey must be a 66-hex compressed "
                               "secp256k1 contributor key",
                               hex ? hex : "");
        return false;
    }
    return true;
}

/* "Today": explicit civil `day` when given (pure window arithmetic);
 * the host clock only when omitted. */
static int64_t zb_today(const struct zcl_command_request *request)
{
    const struct json_value *dv = json_get(request->input, "day");
    if (dv)
        return json_get_int(dv);
    return vcs_rank_day_from_unix(platform_time_wall_unix());
}

/* The shared load: badge store + policy (best-effort) + index + ledger.
 * Any of index/ledger may be empty; the store is the badge truth. */
struct zb_ctx {
    char zcode_dir[4400];
    struct vcs_badge_store *store;
    struct vcs_badge_policy policy;
    bool policy_present;
    struct vcs_package_index *index;
    struct vcs_reward_ledger *ledger;
};

static bool zb_ctx_load(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply,
                        const char *command, struct zb_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    if (!zb_zcode_dir(request, reply, command, ctx->zcode_dir))
        return false;
    ctx->store = vcs_badge_store_load(ctx->zcode_dir);
    if (!ctx->store) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BADGE_STORE_LOAD",
                               "execute", false, false,
                               "the badge store could not be replayed",
                               ctx->zcode_dir);
        return false;
    }
    ctx->policy_present =
        vcs_badge_policy_load(ctx->zcode_dir, &ctx->policy);
    ctx->index = vcs_package_index_build(ctx->zcode_dir);
    if (!ctx->index) {
        vcs_badge_store_free(ctx->store);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "INDEX_LOAD",
                               "execute", false, false,
                               "the package index could not be rebuilt",
                               ctx->zcode_dir);
        return false;
    }
    ctx->ledger = vcs_reward_ledger_load(ctx->zcode_dir);
    if (!ctx->ledger) {
        vcs_package_index_free(ctx->index);
        vcs_badge_store_free(ctx->store);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "LEDGER_LOAD",
                               "execute", false, false,
                               "the reward ledger could not be replayed",
                               ctx->zcode_dir);
        return false;
    }
    return true;
}

static void zb_ctx_free(struct zb_ctx *ctx)
{
    if (ctx->ledger)
        vcs_reward_ledger_free(ctx->ledger);
    if (ctx->index)
        vcs_package_index_free(ctx->index);
    if (ctx->store)
        vcs_badge_store_free(ctx->store);
}

static void zb_push_period(struct json_value *row, int64_t first,
                           int64_t last)
{
    if (first == VCS_BADGE_PERIOD_NONE) {
        (void)json_push_kv_bool(row, "non_periodic", true);
        return;
    }
    (void)json_push_kv_int(row, "period_first_day", first);
    (void)json_push_kv_int(row, "period_last_day", last);
}

/* ── zcode badge eligible ───────────────────────────────────────────── */

void zcl_native_handle_zcode_badge_eligible(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    struct zb_ctx ctx;
    if (!zb_ctx_load(request, reply, "zcode.badge.eligible", &ctx))
        return;
    uint8_t pubkey[33];
    if (!zb_pubkey_input(request, reply, pubkey)) {
        zb_ctx_free(&ctx);
        return;
    }
    int64_t today = zb_today(request);

    struct vcs_badge_facts facts;
    vcs_badge_facts_build(pubkey, ctx.index, ctx.ledger, today, &facts);

    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    uint32_t eligible_count = 0, unavailable_count = 0,
             already_issued_count = 0;
    for (size_t i = 0; i < VCS_BADGE_TYPE_COUNT; i++) {
        enum vcs_badge_type type = (enum vcs_badge_type)i;
        struct vcs_badge_eval eval;
        if (!vcs_badge_evaluate(type, pubkey, &facts, today, &eval))
            continue;
        bool already =
            eval.available && eval.eligible && ctx.policy_present &&
            vcs_badge_store_dedup_hit(ctx.store, &ctx.policy, pubkey, type,
                                      eval.period_first, eval.period_last);
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "type", vcs_badge_type_string(type));
        (void)json_push_kv_bool(&row, "available", eval.available);
        (void)json_push_kv_bool(&row, "eligible", eval.eligible);
        (void)json_push_kv_str(&row, "detail", eval.detail);
        if (eval.eligible) {
            char hex[65];
            zb_push_period(&row, eval.period_first, eval.period_last);
            zcl_hex_encode(eval.evidence_root, 32, hex);
            (void)json_push_kv_str(&row, "evidence_root", hex);
            (void)json_push_kv_bool(&row, "already_issued", already);
        }
        (void)json_push_back(&rows, &row);
        json_free(&row);
        if (!eval.available)
            unavailable_count++;
        else if (eval.eligible) {
            eligible_count++;
            if (already)
                already_issued_count++;
        }
    }
    (void)json_push_kv(&reply->data, "badges", &rows);
    json_free(&rows);

    char pub_hex[67];
    zcl_hex_encode(pubkey, 33, pub_hex);
    (void)json_push_kv_str(&reply->data, "contributor", pub_hex);
    (void)json_push_kv_int(&reply->data, "day", today);
    (void)json_push_kv_int(&reply->data, "eligible_count",
                           (int64_t)eligible_count);
    (void)json_push_kv_int(&reply->data, "already_issued_count",
                           (int64_t)already_issued_count);
    (void)json_push_kv_int(&reply->data, "unavailable_count",
                           (int64_t)unavailable_count);
    (void)json_push_kv_bool(&reply->data, "policy_present",
                            ctx.policy_present);
    (void)json_push_kv_str(
        &reply->data, "honesty_note",
        "eligibility derives from existing facts only — the slice-8 "
        "reward ledger, the slice-9 rankings, the slice-3 publish "
        "history; popular-package and rare-package-seeder need P2P facts "
        "that arrive with slices 11-12 and are named unavailable, never "
        "faked; SIMULATED badges only (no real ZSLP asset — slice 15)");
    zb_ctx_free(&ctx);
}

/* ── zcode badge plan ───────────────────────────────────────────────── */

void zcl_native_handle_zcode_badge_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    struct zb_ctx ctx;
    if (!zb_ctx_load(request, reply, "zcode.badge.plan", &ctx))
        return;
    uint8_t pubkey[33];
    if (!zb_pubkey_input(request, reply, pubkey)) {
        zb_ctx_free(&ctx);
        return;
    }
    if (!ctx.policy_present) {
        zb_ctx_free(&ctx);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "NO_BADGE_POLICY", "normalize", false, false,
            "no badge policy configured: <datadir>/zcode/badge_policy "
            "must carry the 64-hex policy id (line 1) and the 66-hex "
            "issuer pubkey (line 2)",
            "badge_policy");
        return;
    }
    int64_t today = zb_today(request);

    struct vcs_badge_facts facts;
    vcs_badge_facts_build(pubkey, ctx.index, ctx.ledger, today, &facts);

    struct vcs_badge_plan plan;
    struct vcs_badge_plan_exclusion exclusions[VCS_BADGE_TYPE_COUNT];
    size_t exclusion_count = 0;
    if (!vcs_badge_plan_build(ctx.store, &ctx.policy, pubkey, &facts,
                              today, &plan, exclusions,
                              &exclusion_count)) {
        zb_ctx_free(&ctx);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "PLAN_BUILD",
                               "execute", false, false,
                               "the badge issuance batch could not be "
                               "assembled", "badge plan");
        return;
    }
    enum vcs_badge_plan_persist_error perr =
        vcs_badge_plan_persist(ctx.store, &plan);
    if (perr != VCS_BADGE_PLAN_PERSIST_OK &&
        perr != VCS_BADGE_PLAN_PERSIST_DUPLICATE) {
        zb_ctx_free(&ctx);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               perr == VCS_BADGE_PLAN_PERSIST_FULL
                                   ? "PLAN_STORE_FULL"
                                   : "PLAN_PERSIST_IO",
                               "execute", false, false,
                               perr == VCS_BADGE_PLAN_PERSIST_FULL
                                   ? "the plan store reached its bound"
                                   : "the plan wire could not be persisted",
                               "badges/plans");
        return;
    }

    char hex[67];
    zcl_hex_encode(plan.plan_id, 32, hex);
    (void)json_push_kv_str(&reply->data, "plan_id", hex);
    (void)json_push_kv_int(&reply->data, "planned_day",
                           (int64_t)plan.planned_day);
    (void)json_push_kv_bool(&reply->data, "already_persisted",
                            perr == VCS_BADGE_PLAN_PERSIST_DUPLICATE);
    (void)json_push_kv_int(&reply->data, "rows_planned",
                           (int64_t)plan.row_count);
    (void)json_push_kv_int(&reply->data, "rows_excluded",
                           (int64_t)exclusion_count);

    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < plan.row_count; i++) {
        const struct vcs_badge_plan_row *r = &plan.rows[i];
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        zcl_hex_encode(r->contributor, 33, hex);
        (void)json_push_kv_str(&row, "contributor", hex);
        (void)json_push_kv_str(&row, "type",
                               vcs_badge_type_string(r->type));
        zb_push_period(&row, r->period_first, r->period_last);
        zcl_hex_encode(r->evidence_root, 32, hex);
        (void)json_push_kv_str(&row, "evidence_root", hex);
        (void)json_push_kv_int(&row, "sequence", (int64_t)r->sequence);
        (void)json_push_back(&rows, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "rows", &rows);
    json_free(&rows);

    struct json_value excl;
    json_init(&excl);
    json_set_array(&excl);
    for (size_t i = 0; i < exclusion_count; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "type",
                               vcs_badge_type_string(exclusions[i].type));
        (void)json_push_kv_str(&row, "rule", exclusions[i].rule);
        (void)json_push_kv_str(&row, "detail", exclusions[i].detail);
        (void)json_push_back(&excl, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "exclusions", &excl);
    json_free(&excl);

    zcl_hex_encode(ctx.policy.policy_id, 32, hex);
    (void)json_push_kv_str(&reply->data, "policy_id", hex);
    (void)json_push_kv_bool(&reply->data, "simulated", true);
    (void)json_push_kv_str(
        &reply->data, "plan_note",
        "the ONLY mutation is the persisted plan id; nothing is issued "
        "here — zcode badge issue commits the batch SIMULATED (no real "
        "ZSLP asset; the owner-reviewed real issuance is slice 15). "
        "Dedup-checked: an already-issued badge for the same contributor "
        "+ achievement period is excluded with duplicate-badge");
    zb_ctx_free(&ctx);
}

/* ── zcode badge issue ──────────────────────────────────────────────── */

struct zb_sign_ctx {
    struct privkey secret;
};

/* The signer closure: the handler holds the operator key; contexts/commons/modules/vcs only
 * ever verifies. RFC6979 deterministic — a replay signs the identical
 * signature, so the identical badge wire dedups by id. */
static bool zb_sign_badge(struct vcs_badge *badge,
                          const uint8_t badge_id[32], void *ctx)
{
    struct zb_sign_ctx *c = ctx;
    struct uint256 hash;
    memcpy(hash.data, badge_id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(&c->secret, &hash, compact))
        return false;
    memcpy(badge->signature, compact + 1,
           VCS_PACKAGE_BADGE_SIGNATURE_BYTES);
    return true;
}

void zcl_native_handle_zcode_badge_issue(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    struct zb_ctx ctx;
    if (!zb_ctx_load(request, reply, "zcode.badge.issue", &ctx))
        return;
    if (!ctx.policy_present) {
        zb_ctx_free(&ctx);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "NO_BADGE_POLICY", "normalize", false, false,
            "no badge policy configured: <datadir>/zcode/badge_policy "
            "must carry the 64-hex policy id (line 1) and the 66-hex "
            "issuer pubkey (line 2)",
            "badge_policy");
        return;
    }
    uint8_t plan_id[32];
    const char *plan_hex = zb_input_str(request->input, "plan_id");
    if (!plan_hex || !zcl_hex_decode(plan_hex, plan_id, 32)) {
        zb_ctx_free(&ctx);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_PLAN_ID",
                               "normalize", false, false,
                               "plan_id must be a 64-hex badge issuance "
                               "plan id", plan_hex ? plan_hex : "");
        return;
    }
    const char *secret_hex = zb_input_str(request->input, "issuer_secret");
    struct zb_sign_ctx signer;
    memset(&signer, 0, sizeof(signer));
    if (!secret_hex ||
        !zcl_hex_decode(secret_hex, signer.secret.vch, 32)) {
        zb_ctx_free(&ctx);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_ISSUER_SECRET",
                               "normalize", false, false,
                               "issuer_secret must be the 64-hex issuer "
                               "secret key (SIMULATED issuance only)",
                               "issuer_secret");
        return;
    }
    signer.secret.fValid = true;
    signer.secret.fCompressed = true;
    struct pubkey issuer;
    pubkey_init(&issuer);
    if (!privkey_range_check(&signer.secret) ||
        !privkey_get_pubkey(&signer.secret, &issuer) ||
        issuer.size != COMPRESSED_PUBLIC_KEY_SIZE) {
        memset(&signer, 0, sizeof(signer));
        zb_ctx_free(&ctx);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_ISSUER_SECRET",
                               "normalize", false, false,
                               "issuer_secret is not a valid secp256k1 "
                               "secret key", "issuer_secret");
        return;
    }
    if (memcmp(issuer.vch, ctx.policy.issuer_pubkey, 33) != 0) {
        memset(&signer, 0, sizeof(signer));
        zb_ctx_free(&ctx);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "ISSUER_KEY_MISMATCH", "execute", false, false,
            "the issuer key is not the configured policy issuer: badges "
            "may only be issued by the key named in "
            "<datadir>/zcode/badge_policy",
            "badge_policy");
        return;
    }

    struct vcs_badge_issue_result result;
    char detail[256];
    enum vcs_badge_issue_error ierr =
        vcs_badge_issue(ctx.store, &ctx.policy, plan_id, ctx.index,
                        ctx.ledger, zb_sign_badge, &signer, &result,
                        detail, sizeof(detail));
    memset(&signer, 0, sizeof(signer));
    if (ierr != VCS_BADGE_ISSUE_OK) {
        const char *code = "ISSUE_FAILED";
        const char *message = "the badge batch could not be issued";
        bool idempotent = false;
        switch (ierr) {
        case VCS_BADGE_ISSUE_UNKNOWN_PLAN:
            code = "UNKNOWN_PLAN";
            message = "no persisted plan names this plan id";
            break;
        case VCS_BADGE_ISSUE_ALREADY_ISSUED:
            code = "ALREADY_ISSUED";
            message = "this plan was already issued: the commit record "
                      "exists, so re-issuing is a duplicate — never a "
                      "double-issue";
            idempotent = true;
            break;
        case VCS_BADGE_ISSUE_PLAN_CORRUPT:
            code = "PLAN_CORRUPT";
            message = "the plan wire is unreadable or commits a "
                      "different id";
            break;
        case VCS_BADGE_ISSUE_POLICY_MISMATCH:
            code = "POLICY_MISMATCH";
            message = "the plan's policy id or issuer key is not the "
                      "configured badge policy";
            break;
        case VCS_BADGE_ISSUE_STALE:
            code = "STALE_PLAN";
            message = "a planned row no longer matches current facts or "
                      "the current badge store (re-plan): the offending "
                      "row and rule are named in the evidence";
            break;
        case VCS_BADGE_ISSUE_SIGN:
            code = "SIGN_FAILURE";
            message = "the issuer signature could not be produced or "
                      "did not verify";
            break;
        case VCS_BADGE_ISSUE_IO:
            code = "ISSUE_IO";
            message = "a durable write failed mid-issue; the partial "
                      "state is resumable — re-issue the same plan id";
            break;
        case VCS_BADGE_ISSUE_OK: break;
        }
        char evidence[300];
        snprintf(evidence, sizeof(evidence), "%s%s%s",
                 detail[0] ? detail : "", detail[0] ? " plan=" : "",
                 plan_hex);
        zb_ctx_free(&ctx);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, code, "execute",
                               idempotent, false, message, evidence);
        return;
    }

    (void)json_push_kv_str(&reply->data, "plan_id", plan_hex);
    (void)json_push_kv_int(&reply->data, "issued_count",
                           (int64_t)result.issued_count);
    (void)json_push_kv_int(&reply->data, "replayed_count",
                           (int64_t)result.replayed_count);
    (void)json_push_kv_bool(&reply->data, "resumed", result.resumed);

    /* The issued badges (the commit record is the durable receipt). */
    uint8_t badge_ids[VCS_BADGE_MAX_PLAN_ROWS][32];
    size_t named = vcs_badge_commit_record_badges(
        ctx.store, plan_id, badge_ids, VCS_BADGE_MAX_PLAN_ROWS);
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    size_t rendered = named < ZB_PAGE_CAP ? named : ZB_PAGE_CAP;
    for (size_t i = 0; i < rendered; i++) {
        const struct vcs_badge *b =
            vcs_badge_store_find(ctx.store, badge_ids[i]);
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        char hex[67];
        zcl_hex_encode(badge_ids[i], 32, hex);
        (void)json_push_kv_str(&row, "badge_id", hex);
        if (b) {
            (void)json_push_kv_str(&row, "type",
                                   vcs_badge_type_string(
                                       (enum vcs_badge_type)b->type));
            zcl_hex_encode(b->recipient, 33, hex);
            (void)json_push_kv_str(&row, "recipient", hex);
            zb_push_period(&row, b->period_first_day,
                           b->period_last_day);
            (void)json_push_kv_int(&row, "sequence",
                                   (int64_t)b->sequence);
        }
        (void)json_push_back(&rows, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "badges", &rows);
    json_free(&rows);
    (void)json_push_kv_bool(&reply->data, "badges_truncated",
                            named > rendered);
    (void)json_push_kv_bool(&reply->data, "simulated", true);
    (void)json_push_kv_str(
        &reply->data, "issue_note",
        "SIMULATED issuance: signed badge records are durable under "
        "<datadir>/zcode/badges and PERMANENT (a later rank loss never "
        "revokes them); re-issuing this plan id is a named duplicate, "
        "never a double-issue; no real ZSLP asset exists (the "
        "owner-reviewed real issuance is slice 15)");
    zb_ctx_free(&ctx);
}

/* ── zcode contributor badges ───────────────────────────────────────── */

void zcl_native_handle_zcode_contributor_badges(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    struct zb_ctx ctx;
    if (!zb_ctx_load(request, reply, "zcode.contributor.badges", &ctx))
        return;
    uint8_t pubkey[33];
    if (!zb_pubkey_input(request, reply, pubkey)) {
        zb_ctx_free(&ctx);
        return;
    }

    size_t limit = 16;
    const struct json_value *lv = json_get(request->input, "limit");
    if (lv && json_get_int(lv) > 0)
        limit = (size_t)json_get_int(lv);
    if (limit > ZB_PAGE_CAP)
        limit = ZB_PAGE_CAP;
    size_t offset = 0;
    const struct json_value *ov = json_get(request->input, "offset");
    if (ov && json_get_int(ov) > 0)
        offset = (size_t)json_get_int(ov);

    /* Page by fetching the first (offset + limit) recognized badges in
     * issuance order and emitting the tail window. */
    size_t shown = 0;
    size_t total = 0;
    struct vcs_badge page[ZB_PAGE_CAP];
    if (ctx.policy_present) {
        total = vcs_badge_store_contributor_badges(
            ctx.store, &ctx.policy, pubkey, NULL, 0);
        size_t want = offset + limit;
        if (want > ZB_PAGE_CAP)
            want = ZB_PAGE_CAP;
        (void)vcs_badge_store_contributor_badges(ctx.store, &ctx.policy,
                                                 pubkey, page, want);
        size_t have = total < want ? total : want;
        shown = have > offset ? have - offset : 0;
        if (shown > 0)
            memmove(page, page + offset, shown * sizeof(*page));
    }

    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < shown; i++) {
        const struct vcs_badge *b = &page[i];
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        char hex[67];
        uint8_t id[32];
        if (vcs_badge_id(b, id) == VCS_BADGE_OK) {
            zcl_hex_encode(id, 32, hex);
            (void)json_push_kv_str(&row, "badge_id", hex);
        }
        (void)json_push_kv_str(&row, "type",
                               vcs_badge_type_string(
                                   (enum vcs_badge_type)b->type));
        zb_push_period(&row, b->period_first_day, b->period_last_day);
        zcl_hex_encode(b->evidence_root, 32, hex);
        (void)json_push_kv_str(&row, "evidence_root", hex);
        (void)json_push_kv_int(&row, "sequence", (int64_t)b->sequence);
        zcl_hex_encode(b->issuer_pubkey, 33, hex);
        (void)json_push_kv_str(&row, "issuer", hex);
        (void)json_push_kv_bool(&row, "permanent", true);
        (void)json_push_back(&rows, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "badges", &rows);
    json_free(&rows);

    char pub_hex[67];
    zcl_hex_encode(pubkey, 33, pub_hex);
    (void)json_push_kv_str(&reply->data, "contributor", pub_hex);
    (void)json_push_kv_int(&reply->data, "total_badges", (int64_t)total);
    (void)json_push_kv_int(&reply->data, "rendered", (int64_t)shown);
    (void)json_push_kv_bool(&reply->data, "items_truncated",
                            offset + shown < total);
    (void)json_push_kv_bool(&reply->data, "policy_present",
                            ctx.policy_present);
    if (!ctx.policy_present)
        (void)json_push_kv_str(
            &reply->data, "policy_note",
            "no badge policy configured (<datadir>/zcode/badge_policy): "
            "no badge can be recognized as earned");
    (void)json_push_kv_str(
        &reply->data, "permanence_note",
        "earned badges are PERMANENT historical evidence: losing a "
        "leaderboard position later never revokes them; SIMULATED "
        "ZSLP-based assets only (no real on-chain asset — slice 15)");
    zb_ctx_free(&ctx);
}
