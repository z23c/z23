/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: encrypted, idempotent Sapling and mixed-recipient vault intents. */

#include "controllers/vault_intent_private.h"

#include "base/serialize_le.h"
#include "controllers/vault_intent_controller.h"
#include "controllers/wallet_helpers.h"
#include "controllers/wallet_shielded_controller.h"
#include "coins/coins_view.h"
#include "core/amount.h"
#include "core/serialize.h"
#include "crypto/sha3.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/database.h"
#include "models/vault_intent.h"
#include "models/wallet_identity.h"
#include "models/wallet_metadata_crypto.h"
#include "platform/time_compat.h"
#include "primitives/transaction.h"
#include "services/wallet_money_service.h"
#include "services/agent_session_service.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include "validation/main_state.h"
#include "wallet/wallet.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#define VIP_EFFECTS_MAX 50
#define VIP_ADDR_MAX 127
#define VIP_TTL 600
#define VIP_APP_KIND "vault_multi"

enum vip_memo_kind { VIP_MEMO_NONE = 0, VIP_MEMO_TEXT = 1, VIP_MEMO_HEX = 2 };

struct vip_effect {
    char to[VIP_ADDR_MAX + 1];
    int64_t amount;
    enum vip_memo_kind memo_kind;
    uint16_t memo_len;
    uint8_t memo[1024];
};

struct vip_payload {
    enum vault_intent_route route;
    char from[VIP_ADDR_MAX + 1];
    struct vip_effect effects[VIP_EFFECTS_MAX];
    size_t effects_len;
    int64_t fee;
};

static void vip_error(struct json_value *out, const char *code,
                      const char *message)
{
    vault_intent_error_response(out, code, message);
}

bool vault_intent_private_requirements_current(
    struct wallet_rpc_context *ctx, const struct transaction *tx,
    struct json_value *result)
{
    if (!ctx || !ctx->coins_tip || !tx || !result) {
        vip_error(result, "SHIELDED_AUTHORITY_UNAVAILABLE",
                  "current shielded authority is unavailable");
        LOG_ERROR("vault_intent",
                  "private requirement preflight has incomplete context");
        return false;
    }
    enum coins_shielded_requirements_result verdict =
        coins_view_cache_check_shielded_requirements(ctx->coins_tip, tx);
    if (verdict == COINS_SHIELDED_REQUIREMENTS_OK)
        return true;
    if (verdict == COINS_SHIELDED_REQUIREMENTS_MISSING_ANCHOR) {
        vip_error(result, "WITNESS_RESCAN_REQUIRED",
                  "shielded witness anchor is not current; run z23 core "
                  "wallet rescan-witnesses before planning again");
        LOG_ERROR("vault_intent",
                  "private requirement preflight requires witness rescan");
        return false;
    }
    if (verdict == COINS_SHIELDED_REQUIREMENTS_HISTORY_INCOMPLETE) {
        vip_error(result, "SHIELDED_HISTORY_INCOMPLETE",
                  "canonical shielded anchor history is incomplete");
        LOG_ERROR("vault_intent",
                  "private requirement preflight found incomplete history");
        return false;
    }
    vip_error(result, "SHIELDED_AUTHORITY_UNAVAILABLE",
              "canonical shielded anchor authority is unreadable");
    LOG_ERROR("vault_intent",
              "private requirement preflight could not read authority");
    return false;
}

static void vip_hex(const uint8_t in[32], char out[65])
{
    HexStr(in, 32, false, out, 65);
}

static void vip_amount_text(int64_t amount, char out[32])
{
    (void)snprintf(out, 32, "%lld.%08lld",
                   (long long)(amount / COIN),
                   (long long)(amount % COIN));
}

static const char *vip_route_name(enum vault_intent_route route)
{
    switch (route) {
    case VAULT_INTENT_ROUTE_PRIVATE: return "private";
    case VAULT_INTENT_ROUTE_SHIELD: return "shield";
    case VAULT_INTENT_ROUTE_UNSHIELD: return "unshield";
    case VAULT_INTENT_ROUTE_MIXED: return "mixed";
    default: return "unsupported";
    }
}

static enum vault_intent_route vip_route_parse(const char *route)
{
    if (!route || strcmp(route, "private") == 0)
        return VAULT_INTENT_ROUTE_PRIVATE;
    if (strcmp(route, "shield") == 0)
        return VAULT_INTENT_ROUTE_SHIELD;
    if (strcmp(route, "unshield") == 0)
        return VAULT_INTENT_ROUTE_UNSHIELD;
    if (strcmp(route, "mixed") == 0)
        return VAULT_INTENT_ROUTE_MIXED;
    return 0;
}

static bool vip_effect_parse(const struct json_value *value,
                             struct vip_effect *out, int64_t *total,
                             size_t *transparent, size_t *shielded)
{
    const char *asset = value && value->type == JSON_OBJ
        ? json_get_str(json_get(value, "asset")) : NULL;
    const char *to = value && value->type == JSON_OBJ
        ? json_get_str(json_get(value, "to")) : NULL;
    const struct json_value *amount_value = value && value->type == JSON_OBJ
        ? json_get(value, "amount") : NULL;
    const char *amount = amount_value && amount_value->type == JSON_STR
        ? json_get_str(amount_value) : NULL;
    int64_t zats = 0;
    if (!asset || strcmp(asset, "ZCL") != 0 || !to || !to[0] ||
        strlen(to) > VIP_ADDR_MAX ||
        !vault_intent_parse_zcl_amount(amount, &zats) ||
        *total > INT64_MAX - zats)
        return false;

    bool is_z = wallet_addr_is_sapling(to);
    const char *memo_hex = json_get_str(json_get(value, "memo_hex"));
    const char *memo = json_get_str(json_get(value, "memo"));
    if (memo_hex && !memo_hex[0]) memo_hex = NULL;
    if (memo && !memo[0]) memo = NULL;
    if ((memo_hex || memo) && !is_z)
        return false;

    memset(out, 0, sizeof(*out));
    (void)snprintf(out->to, sizeof(out->to), "%s", to);
    out->amount = zats;
    if (memo_hex) {
        size_t n = strlen(memo_hex);
        if (n > 1024 || (n & 1u) != 0 || !IsHex(memo_hex))
            return false;
        out->memo_kind = VIP_MEMO_HEX;
        out->memo_len = (uint16_t)n;
        memcpy(out->memo, memo_hex, n);
    } else if (memo) {
        size_t n = strlen(memo);
        if (n > sizeof(out->memo))
            return false;
        out->memo_kind = VIP_MEMO_TEXT;
        out->memo_len = (uint16_t)n;
        memcpy(out->memo, memo, n);
    }
    *total += zats;
    if (is_z) (*shielded)++; else (*transparent)++;
    return true;
}

static bool vip_parse(const struct json_value *input, struct vip_payload *out,
                      int64_t *total, struct json_value *result)
{
    const char *from = json_get_str(json_get(input, "from"));
    const char *requested = json_get_str(json_get(input, "route"));
    enum vault_intent_route requested_route = vip_route_parse(requested);
    const struct json_value *effects = json_get(input, "effects");
    size_t count = effects && effects->type == JSON_ARR
        ? json_size(effects) : 0;
    if (!from || !from[0] || strlen(from) > VIP_ADDR_MAX) {
        vip_error(result, "FROM_REQUIRED", "from must name one wallet address");
        return false;
    }
    if (!requested_route) {
        vip_error(result, "UNSUPPORTED_ROUTE",
                  "route must be private, shield, unshield, mixed, or transparent");
        return false;
    }
    if (count == 0 || count > VIP_EFFECTS_MAX) {
        vip_error(result, "INVALID_EFFECTS", "effects must contain 1..50 entries");
        return false;
    }

    memset(out, 0, sizeof(*out));
    (void)snprintf(out->from, sizeof(out->from), "%s", from);
    size_t transparent = 0, shielded = 0;
    for (size_t i = 0; i < count; i++) {
        if (!vip_effect_parse(json_at(effects, i), &out->effects[i], total,
                              &transparent, &shielded)) {
            vip_error(result, "INVALID_EFFECT",
                      "each effect needs asset=ZCL, a valid address, an exact decimal-string amount, and a memo only for Sapling");
            return false;
        }
    }
    bool from_z = wallet_addr_is_sapling(from);
    enum vault_intent_route actual;
    if (transparent && shielded)
        actual = VAULT_INTENT_ROUTE_MIXED;
    else if (from_z && transparent)
        actual = VAULT_INTENT_ROUTE_UNSHIELD;
    else if (from_z)
        actual = VAULT_INTENT_ROUTE_PRIVATE;
    else if (shielded)
        actual = VAULT_INTENT_ROUTE_SHIELD;
    else
        actual = VAULT_INTENT_ROUTE_TRANSPARENT;
    if (actual == VAULT_INTENT_ROUTE_TRANSPARENT || actual != requested_route) {
        vip_error(result, "ROUTE_MISMATCH",
                  actual == VAULT_INTENT_ROUTE_TRANSPARENT
                      ? "transparent-only fan-out requires route=transparent"
                      : "route does not match the from/recipient pool shape");
        return false;
    }
    out->route = actual;
    out->effects_len = count;
    return true;
}

static bool vip_encode(const struct vip_payload *p, uint8_t *out, size_t cap,
                       size_t *out_len)
{
    struct byte_stream s;
    stream_init(&s, 1024);
    size_t from_len = strlen(p->from);
    bool ok = stream_write(&s, "VIP2", 4) &&
        stream_write_u8(&s, (uint8_t)p->route) &&
        stream_write_u8(&s, (uint8_t)from_len) &&
        stream_write(&s, p->from, from_len) &&
        stream_write_u8(&s, (uint8_t)p->effects_len) &&
        stream_write_i64_le(&s, p->fee);
    for (size_t i = 0; ok && i < p->effects_len; i++) {
        const struct vip_effect *e = &p->effects[i];
        size_t to_len = strlen(e->to);
        ok = stream_write_u8(&s, (uint8_t)to_len) &&
            stream_write(&s, e->to, to_len) &&
            stream_write_i64_le(&s, e->amount) &&
            stream_write_u8(&s, (uint8_t)e->memo_kind) &&
            stream_write_u16_le(&s, e->memo_len) &&
            stream_write(&s, e->memo, e->memo_len);
    }
    if (!ok || s.size > cap) {
        stream_free(&s);
        return false;
    }
    memcpy(out, s.data, s.size);
    *out_len = s.size;
    stream_free(&s);
    return true;
}

static bool vip_decode(const uint8_t *raw, size_t len, struct vip_payload *p)
{
    memset(p, 0, sizeof(*p));
    struct byte_stream s;
    stream_init_from_data(&s, raw, len);
    uint8_t magic[4], route = 0, from_len = 0, count = 0;
    bool ok = stream_read(&s, magic, 4) && memcmp(magic, "VIP2", 4) == 0 &&
        stream_read_u8(&s, &route) && route >= VAULT_INTENT_ROUTE_PRIVATE &&
        route <= VAULT_INTENT_ROUTE_MIXED &&
        route != VAULT_INTENT_ROUTE_TRANSPARENT &&
        stream_read_u8(&s, &from_len) && from_len > 0 &&
        from_len <= VIP_ADDR_MAX && stream_read(&s, p->from, from_len) &&
        stream_read_u8(&s, &count) && count > 0 && count <= VIP_EFFECTS_MAX &&
        stream_read_i64_le(&s, &p->fee);
    p->from[from_len] = '\0';
    p->route = (enum vault_intent_route)route;
    p->effects_len = count;
    for (size_t i = 0; ok && i < p->effects_len; i++) {
        struct vip_effect *e = &p->effects[i];
        uint8_t to_len = 0, memo_kind = 0;
        ok = stream_read_u8(&s, &to_len) && to_len > 0 &&
            to_len <= VIP_ADDR_MAX && stream_read(&s, e->to, to_len) &&
            stream_read_i64_le(&s, &e->amount) && e->amount > 0 &&
            MoneyRange(e->amount) && stream_read_u8(&s, &memo_kind) &&
            memo_kind <= VIP_MEMO_HEX &&
            stream_read_u16_le(&s, &e->memo_len) &&
            e->memo_len <= sizeof(e->memo) &&
            stream_read(&s, e->memo, e->memo_len);
        e->to[to_len] = '\0';
        e->memo_kind = (enum vip_memo_kind)memo_kind;
        ok = ok && ((e->memo_kind == VIP_MEMO_NONE && e->memo_len == 0) ||
                    (e->memo_kind != VIP_MEMO_NONE && e->memo_len > 0));
    }
    ok = ok && p->fee >= 0 && stream_remaining(&s) == 0;
    stream_free(&s);
    return ok;
}

static void vip_request_digest(const uint8_t *plain, size_t len,
                               const char *wallet_scope, uint8_t out[32])
{
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const uint8_t *)"vault-multi-request-v1", 22);
    sha3_256_write(&c, (const uint8_t *)wallet_scope, strlen(wallet_scope));
    sha3_256_write(&c, plain, len);
    sha3_256_finalize(&c, out);
}

static void vip_params(const struct vip_payload *p, struct json_value *params)
{
    json_set_array(params);
    struct json_value from;
    json_init(&from); json_set_str(&from, p->from);
    (void)json_push_back(params, &from); json_free(&from);
    struct json_value recipients;
    json_init(&recipients); json_set_array(&recipients);
    for (size_t i = 0; i < p->effects_len; i++) {
        const struct vip_effect *e = &p->effects[i];
        struct json_value recipient;
        json_init(&recipient); json_set_object(&recipient);
        char amount[32]; vip_amount_text(e->amount, amount);
        (void)json_push_kv_str(&recipient, "address", e->to);
        (void)json_push_kv_str(&recipient, "amount", amount);
        if (e->memo_kind != VIP_MEMO_NONE) {
            char memo[1025];
            memcpy(memo, e->memo, e->memo_len); memo[e->memo_len] = '\0';
            (void)json_push_kv_str(&recipient,
                e->memo_kind == VIP_MEMO_HEX ? "memo_hex" : "memo", memo);
            memory_cleanse(memo, sizeof(memo));
        }
        (void)json_push_back(&recipients, &recipient);
        json_free(&recipient);
    }
    (void)json_push_back(params, &recipients);
    json_free(&recipients);
}

static void vip_render_effects(const struct vip_payload *p,
                               struct json_value *result)
{
    struct json_value effects;
    json_init(&effects); json_set_array(&effects);
    for (size_t i = 0; i < p->effects_len; i++) {
        struct json_value effect;
        json_init(&effect); json_set_object(&effect);
        char amount[32]; vip_amount_text(p->effects[i].amount, amount);
        (void)json_push_kv_str(&effect, "asset", "ZCL");
        (void)json_push_kv_str(&effect, "to", p->effects[i].to);
        (void)json_push_kv_str(&effect, "amount", amount);
        (void)json_push_kv_bool(&effect, "memo_attached",
            p->effects[i].memo_kind != VIP_MEMO_NONE);
        (void)json_push_back(&effects, &effect); json_free(&effect);
    }
    (void)json_push_kv(result, "effects", &effects); json_free(&effects);
}

static void vip_render_plan_details(const struct vip_payload *p,
                                    const struct vault_intent_row *row,
                                    struct json_value *result)
{
    char digest[65], fee[32];
    vip_hex(row->digest, digest);
    vip_amount_text(p->fee, fee);
    (void)json_push_kv_str(result, "digest", digest);
    (void)json_push_kv_str(result, "fee", fee);
    (void)json_push_kv_int(result, "confirmation_policy", 6);
    (void)json_push_kv_str(result, "from", p->from);
    (void)json_push_kv_str(result, "route", vip_route_name(p->route));
    (void)json_push_kv_str(result, "privacy",
        p->route == VAULT_INTENT_ROUTE_PRIVATE
            ? "PRIVATE: Sapling recipients, values, memos, and graph are encrypted"
            : "MIXED POOLS: transparent legs are public; Sapling legs are encrypted");
    vip_render_effects(p, result);
}

static bool vip_refresh_money_for_reservation(
    struct wallet_rpc_context *ctx, const char *scope, int64_t reservation,
    const char *agent_session, int64_t session_reserve_floor,
    struct wallet_money_snapshot *money, struct json_value *result)
{
    memset(money, 0, sizeof(*money));
    struct zcl_result mr = wallet_money_snapshot_build(
        ctx->node_db, ctx->main_state, scope, money);
    if (!mr.ok || !money->complete || strcmp(money->status, "CURRENT") != 0) {
        vip_error(result, "MONEY_STATE_NOT_CURRENT",
                  mr.ok ? money->reason : mr.message);
        return false;
    }
    int64_t available = money->confirmed_zat >= money->intent_reserved_zat
        ? money->confirmed_zat - money->intent_reserved_zat : 0;
    int64_t agent_available = agent_session && agent_session[0]
        ? wallet_money_agent_available_for_floor(
            money, session_reserve_floor)
        : money->agent_available_zat;
    if (reservation > available ||
        (strcmp(scope, "dev") == 0 &&
         reservation > agent_available)) {
        vip_error(result, strcmp(scope, "dev") == 0
            ? "DEVELOPMENT_RESERVE_OR_LAB_CAP"
            : "INSUFFICIENT_CONFIRMED_FUNDS",
            "recipient value plus maximum fee exceeds current custody allocation");
        return false;
    }
    return true;
}

bool vault_intent_private_plan(const struct json_value *input,
                               struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    const char *scope = json_get_str(json_get(input, "wallet_scope"));
    const char *idem = json_get_str(json_get(input, "idempotency_key"));
    if (!wallet_money_scope_valid(scope)) {
        vip_error(result, "WALLET_SCOPE_REQUIRED",
                  "wallet_scope must explicitly be dev, prod, or test");
        return true;
    }
    if (!vault_intent_idempotency_key_valid(idem)) {
        vip_error(result, "IDEMPOTENCY_KEY_REQUIRED",
                  "idempotency_key must be 1..64 printable characters");
        return true;
    }
    if (!vault_intent_context_ready(ctx, result)) return true;
    (void)vault_intent_expire_due(
        ctx->node_db, (int64_t)platform_time_wall_time_t());

    struct vip_payload p;
    int64_t target = 0;
    if (!vip_parse(input, &p, &target, result)) return true;
    p.fee = wallet_default_fee(ctx->wallet);
    if (p.fee < 0 || target > INT64_MAX - p.fee) {
        vip_error(result, "FEE_INVALID", "wallet maximum fee is invalid");
        memory_cleanse(&p, sizeof(p));
        return true;
    }
    const char *agent_session =
        json_get_str(json_get(input, "_agent_session"));
    int64_t session_reserve_floor = VAULT_INTENT_DEV_RESERVE_FLOOR_ZAT;
    if (agent_session && agent_session[0]) {
        const char *recipients[VIP_EFFECTS_MAX];
        for (size_t i = 0; i < p.effects_len; i++)
            recipients[i] = p.effects[i].to;
        char why[64] = { 0 };
        if (!agent_session_service_plan_intent(
                agent_session, scope, target + p.fee, recipients,
                p.effects_len, &session_reserve_floor,
                why, sizeof(why))) {
            vip_error(result, why[0] ? why : "POLICY_STORE",
                      "bounded session refused the exact intent plan");
            memory_cleanse(&p, sizeof(p));
            return true;
        }
    }
    uint8_t plain[WALLET_METADATA_PLAINTEXT_MAX]; size_t plain_len = 0;
    if (!vip_encode(&p, plain, sizeof(plain), &plain_len)) {
        vip_error(result, "PLAN_TOO_LARGE",
                  "normalized recipients and memos exceed the encrypted plan budget");
        memory_cleanse(&p, sizeof(p));
        return true;
    }
    uint8_t request_digest[32];
    vip_request_digest(plain, plain_len, scope, request_digest);

    struct vault_intent_row existing;
    if (vault_intent_find_application_idempotency(
            ctx->node_db, scope, VIP_APP_KIND, idem, &existing)) {
        if (agent_session && agent_session[0] &&
            existing.agent_session_id[0] &&
            strcmp(existing.agent_session_id, agent_session) != 0) {
            memory_cleanse(plain, sizeof(plain));
            memory_cleanse(&p, sizeof(p));
            vip_error(result, "POLICY_INTENT_SESSION",
                      "that idempotency key is bound to another grant");
            return true;
        }
        bool same = existing.has_request_digest &&
            memcmp(existing.request_digest, request_digest, 32) == 0;
        memory_cleanse(plain, sizeof(plain));
        if (!same) {
            memory_cleanse(&p, sizeof(p));
            vip_error(result, "IDEMPOTENCY_CONFLICT",
                      "that idempotency key already names a different request");
            return true;
        }
        json_set_object(result); (void)json_push_kv_bool(result, "ok", true);
        vault_intent_render_row(ctx, result, &existing);
        vip_render_plan_details(&p, &existing, result);
        (void)json_push_kv_bool(result, "idempotent_plan", true);
        memory_cleanse(&p, sizeof(p));
        return true;
    }

    int64_t reservation = target + p.fee;
    struct wallet_money_snapshot money;
    if (!vip_refresh_money_for_reservation(
            ctx, scope, reservation, agent_session,
            session_reserve_floor, &money, result))
        goto plan_clean;

    /* Non-broadcast monetary preflight: prove the current source, witnesses,
     * keys, fee, recipients, and prover can build. The signed candidate is
     * discarded; commit later stores its own exact bytes before relay. */
    struct json_value params, prepare_result;
    json_init(&params); vip_params(&p, &params);
    json_init(&prepare_result);
    struct wallet_tx prepared; memset(&prepared, 0, sizeof(prepared));
    bool buildable = z_sendmany_prepare(&params, &prepared, &prepare_result);
    json_free(&params);
    if (!buildable) {
        const char *reason = json_get_str(&prepare_result);
        char why[256]; (void)snprintf(why, sizeof(why), "%s",
            reason && reason[0] ? reason : "z_sendmany preflight refused");
        json_free(&prepare_result);
        vip_error(result, "PRIVATE_BUILD_UNAVAILABLE", why);
        goto plan_clean;
    }
    json_free(&prepare_result);
    if (!vault_intent_private_requirements_current(
            ctx, &prepared.tx, result)) {
        transaction_free(&prepared.tx);
        goto plan_clean;
    }
    transaction_free(&prepared.tx);

    /* A real Sapling proof may take tens of seconds.  The tip, mempool, or a
     * concurrent reservation can change while it is built, so the pre-proof
     * money document is no longer eligible to bind a durable intent. Refresh
     * every authority after proof generation; only this post-proof snapshot
     * feeds identity, allocation, anchor, digest, and atomic reservation. */
    if (!vip_refresh_money_for_reservation(
            ctx, scope, reservation, agent_session,
            session_reserve_floor, &money, result))
        goto plan_clean;

    struct wallet_money_snapshot reserved_money;
    if (!wallet_money_snapshot_after_reservation(
            &money, reservation, &reserved_money)) {
        vip_error(result, "MONEY_STATE_NOT_CURRENT",
                  "current money snapshot cannot include this reservation");
        goto plan_clean;
    }
    struct vault_intent_row row; memset(&row, 0, sizeof(row));
    if (RAND_bytes(row.plan_id, 32) != 1) {
        vip_error(result, "RNG_FAILED", "could not mint plan id");
        goto plan_clean;
    }
    row.state = VAULT_INTENT_PLANNED; row.route = p.route;
    row.created_at = (int64_t)platform_time_wall_time_t();
    row.expires_at = row.created_at + VIP_TTL; row.updated_at = row.created_at;
    row.anchor_height = money.tip_height;
    memcpy(row.anchor_hash, money.tip_hash, 32);
    (void)snprintf(row.wallet_scope, sizeof(row.wallet_scope), "%s", scope);
    (void)snprintf(row.wallet_instance_id, sizeof(row.wallet_instance_id),
                   "%s", money.identity.wallet_instance_id);
    wallet_identity_genesis_hex(&money.identity, row.wallet_genesis);
    memcpy(row.snapshot_root, reserved_money.snapshot_root, 32);
    row.has_snapshot_root = true;
    row.recipient_value_zat = target; row.max_fee_zat = p.fee;
    row.reserved_zat = reservation;
    (void)snprintf(row.application_kind, sizeof(row.application_kind), "%s",
                   VIP_APP_KIND);
    (void)snprintf(row.idempotency_key, sizeof(row.idempotency_key), "%s", idem);
    memcpy(row.request_digest, request_digest, 32); row.has_request_digest = true;
    if (agent_session && agent_session[0])
        (void)snprintf(row.agent_session_id,
                       sizeof(row.agent_session_id), "%s", agent_session);
    vault_intent_digest_payload(plain, plain_len, &row, row.digest);
    bool encrypted = wallet_metadata_encrypt(ctx->node_db, row.plan_id, 32,
        plain, plain_len, row.encrypted_payload, sizeof(row.encrypted_payload),
        &row.encrypted_payload_len);
    /* The post-reservation root is a pure transform of the post-proof CURRENT
     * snapshot.  The database compares its reservation total and inserts this
     * exact row under one BEGIN IMMEDIATE, so no poll or second save is part
     * of correctness. */
    bool stored = encrypted && vault_intent_reserve_bound(
        ctx->node_db, &row, money.confirmed_zat,
        money.intent_reserved_zat);
    if (!stored) {
        if (vault_intent_find_application_idempotency(
                ctx->node_db, scope, VIP_APP_KIND, idem, &existing)) {
            bool same = existing.has_request_digest &&
                memcmp(existing.request_digest, request_digest, 32) == 0;
            if (!same) {
                vip_error(result, "IDEMPOTENCY_CONFLICT",
                          "that idempotency key already names a different request");
                goto plan_clean;
            }
            json_set_object(result);
            (void)json_push_kv_bool(result, "ok", true);
            vault_intent_render_row(ctx, result, &existing);
            vip_render_plan_details(&p, &existing, result);
            (void)json_push_kv_bool(result, "idempotent_plan", true);
            goto plan_clean;
        }
        vip_error(result, "PLAN_PERSIST_FAILED",
                  "plan was not reserved; retry the same idempotency_key");
        goto plan_clean;
    }
    json_set_object(result); (void)json_push_kv_bool(result, "ok", true);
    vault_intent_render_row(ctx, result, &row);
    vip_render_plan_details(&p, &row, result);
    (void)json_push_kv_bool(result, "idempotent_plan", false);

plan_clean:
    memory_cleanse(plain, sizeof(plain));
    memory_cleanse(&p, sizeof(p));
    return true;
}

bool vault_intent_private_build_prepared(
    struct wallet_rpc_context *ctx, const struct vault_intent_row *row,
    struct wallet_tx *wtx, struct json_value *result)
{
    uint8_t plain[WALLET_METADATA_PLAINTEXT_MAX]; size_t plain_len = 0;
    if (!wallet_metadata_decrypt(ctx->node_db, row->plan_id, 32,
            row->encrypted_payload, row->encrypted_payload_len,
            plain, sizeof(plain), &plain_len)) {
        vip_error(result, "PLAN_DECRYPT_FAILED",
                  "encrypted private plan failed authentication");
        return false;
    }
    uint8_t digest[32];
    vault_intent_digest_payload(plain, plain_len, row, digest);
    struct vip_payload p;
    bool valid = memcmp(digest, row->digest, 32) == 0 &&
        vip_decode(plain, plain_len, &p) && p.route == row->route &&
        p.fee == row->max_fee_zat &&
        wallet_default_fee(ctx->wallet) == p.fee;
    memory_cleanse(plain, sizeof(plain));
    if (!valid) {
        memory_cleanse(&p, sizeof(p));
        vip_error(result, "PLAN_TAMPERED",
                  "private plan, route, or maximum fee changed");
        return false;
    }
    struct json_value params, prepared_result;
    json_init(&params); vip_params(&p, &params);
    json_init(&prepared_result);
    bool built = z_sendmany_prepare(&params, wtx, &prepared_result);
    json_free(&params);
    if (!built) {
        const char *reason = json_get_str(&prepared_result);
        char why[256]; (void)snprintf(why, sizeof(why), "%s",
            reason && reason[0] ? reason : "private transaction build refused");
        json_free(&prepared_result);
        memory_cleanse(&p, sizeof(p));
        vip_error(result, "EXACT_BUILD_FAILED", why);
        return false;
    }
    json_free(&prepared_result);
    if (!vault_intent_private_requirements_current(ctx, &wtx->tx, result)) {
        transaction_free(&wtx->tx);
        memory_cleanse(&p, sizeof(p));
        return false;
    }
    struct byte_stream raw; stream_init(&raw, 2048);
    bool stored = transaction_serialize(&wtx->tx, &raw) &&
        raw.size <= VAULT_INTENT_RAW_MAX &&
        vault_intent_store_raw(ctx->node_db, row->plan_id, raw.data, raw.size) &&
        vault_intent_set_state(ctx->node_db, row->plan_id,
            VAULT_INTENT_PROVING, wtx->tx.hash.data, "",
            (int64_t)platform_time_wall_time_t());
    stream_free(&raw);
    memory_cleanse(&p, sizeof(p));
    if (!stored) {
        transaction_free(&wtx->tx);
        vip_error(result, "PRE_RELAY_DURABILITY_FAILED",
                  "signed private transaction could not be recorded");
        return false;
    }
    return true;
}
