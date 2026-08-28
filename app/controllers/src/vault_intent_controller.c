/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: durable exact-input planning and idempotent transparent commits. */

#include "controllers/vault_intent_controller.h"
#include "vault_intent_transparent_internal.h"
#include "controllers/vault_intent_private.h"
#include "controllers/vault_intent_publish.h"
#include "controllers/native_handler_body.h"
#include "controllers/sovereignty_controller.h"
#include "controllers/strong_params.h"
#include "controllers/sync_controller.h"
#include "controllers/wallet_helpers.h"
#include "base/serialize_le.h"
#include "core/serialize.h"
#include "core/amount.h"
#include "crypto/sha3.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/database.h"
#include "models/vault_intent.h"
#include "models/wallet_identity.h"
#include "models/wallet_metadata_crypto.h"
#include "net/connman.h"
#include "platform/time_compat.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "services/wallet_backup_service.h"
#include "services/agent_session_service.h"
#include "services/vault_intent_decision_service.h"
#include "services/wallet_money_service.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "wallet/wallet.h"
#include "wallet/wallet_canary.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VI_TTL 600
#define VI_PROVING_LEASE 300
#define VI_APP_KIND VAULT_INTENT_TRANSPARENT_APPLICATION

static void vi_error(struct json_value *out, const char *code, const char *msg)
{
    vault_intent_error_response(out, code, msg);
}

static bool vi_unhex(const char *s, uint8_t out[32])
{
    return s && strlen(s) == 64 && IsHex(s) && ParseHex(s, out, 32) == 32;
}

static bool vi_encode(const struct vi_payload *p, uint8_t *out, size_t cap,
                      size_t *out_len)
{
    struct byte_stream s;
    stream_init(&s, 1024);
    bool ok = stream_write(&s, "VIP1", 4) &&
        stream_write_u8(&s, VAULT_INTENT_ROUTE_TRANSPARENT) &&
        stream_write_u8(&s, (uint8_t)p->effects_len) &&
        stream_write_u16_le(&s, (uint16_t)p->inputs_len) &&
        stream_write_i64_le(&s, p->fee);
    for (size_t i = 0; ok && i < p->effects_len; i++) {
        size_t n = strlen(p->effects[i].to);
        ok = n > 0 && n <= VI_ADDR_MAX && stream_write_u8(&s, (uint8_t)n) &&
             stream_write(&s, p->effects[i].to, n) &&
             stream_write_i64_le(&s, p->effects[i].amount);
    }
    for (size_t i = 0; ok && i < p->inputs_len; i++)
        ok = stream_write(&s, p->inputs[i].txid, 32) &&
             stream_write_u32_le(&s, p->inputs[i].vout);
    if (!ok || s.size > cap) {
        stream_free(&s);
        LOG_FAIL("vault_intent", "canonical payload encode failed");
    }
    memcpy(out, s.data, s.size);
    *out_len = s.size;
    stream_free(&s);
    return true;
}

/* Bind retry identity to the caller's normalized request, before input
 * selection.  Exact selected inputs belong to the durable plan digest below;
 * putting them in this digest would make an otherwise identical retry depend
 * on transient coin-selection order. */
static void vi_request_digest(const struct vi_payload *p, const char *scope,
                              uint8_t out[32])
{
    uint8_t count = (uint8_t)p->effects_len;
    uint8_t fee_le[8];
    zcl_write_i64_le(fee_le, p->fee);
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    static const uint8_t domain[] = "vault-transparent-request-v1";
    sha3_256_write(&c, domain, sizeof(domain) - 1);
    sha3_256_write(&c, (const uint8_t *)scope, strlen(scope));
    sha3_256_write(&c, &count, sizeof(count));
    sha3_256_write(&c, fee_le, sizeof(fee_le));
    for (size_t i = 0; i < p->effects_len; i++) {
        uint8_t address_len = (uint8_t)strlen(p->effects[i].to);
        uint8_t amount_le[8];
        zcl_write_i64_le(amount_le, p->effects[i].amount);
        sha3_256_write(&c, &address_len, sizeof(address_len));
        sha3_256_write(&c, (const uint8_t *)p->effects[i].to, address_len);
        sha3_256_write(&c, amount_le, sizeof(amount_le));
    }
    sha3_256_finalize(&c, out);
}

static bool vi_render_idempotent(struct wallet_rpc_context *ctx,
                                 struct json_value *result,
                                 const struct vault_intent_row *row,
                                 const uint8_t request_digest[32],
                                 const struct vi_payload *payload)
{
    if (!row->has_request_digest ||
        memcmp(row->request_digest, request_digest, 32) != 0) {
        vi_error(result, "IDEMPOTENCY_CONFLICT",
                 "that idempotency key already names a different request");
        return true;
    }
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    vault_intent_render_row(ctx, result, row);
    vault_intent_transparent_render_plan(payload, row, result);
    json_push_kv_bool(result, "idempotent_plan", true);
    return true;
}

static bool vi_decode(const uint8_t *raw, size_t len, struct vi_payload *p)
{
    if (!raw || !p) LOG_FAIL("vault_intent", "decode: NULL argument");
    memset(p, 0, sizeof(*p));
    struct byte_stream s;
    stream_init_from_data(&s, raw, len);
    uint8_t magic[4], route = 0, ne = 0;
    uint16_t ni = 0;
    bool ok = stream_read(&s, magic, 4) && memcmp(magic, "VIP1", 4) == 0 &&
        stream_read_u8(&s, &route) && route == VAULT_INTENT_ROUTE_TRANSPARENT &&
        stream_read_u8(&s, &ne) && ne > 0 && ne <= VI_EFFECTS_MAX &&
        stream_read_u16_le(&s, &ni) && ni > 0 && ni <= VI_INPUTS_MAX &&
        stream_read_i64_le(&s, &p->fee);
    p->effects_len = ne; p->inputs_len = ni;
    for (size_t i = 0; ok && i < p->effects_len; i++) {
        uint8_t n = 0;
        ok = stream_read_u8(&s, &n) && n > 0 && n <= VI_ADDR_MAX &&
             stream_read(&s, p->effects[i].to, n) &&
             stream_read_i64_le(&s, &p->effects[i].amount);
        p->effects[i].to[n] = '\0';
    }
    for (size_t i = 0; ok && i < p->inputs_len; i++)
        ok = stream_read(&s, p->inputs[i].txid, 32) &&
             stream_read_u32_le(&s, &p->inputs[i].vout);
    ok = ok && stream_remaining(&s) == 0 && p->fee >= 0;
    stream_free(&s);
    if (!ok) LOG_FAIL("vault_intent", "canonical payload decode failed");
    return true;
}

static bool vi_context_ready(struct wallet_rpc_context *ctx,
                             struct json_value *out,
                             bool require_current_backup)
{
    if (!ctx || !ctx->wallet || !ctx->wallet_db || !ctx->node_db ||
        !ctx->mempool || !ctx->coins_tip || !ctx->main_state) {
        vi_error(out, "WALLET_UNAVAILABLE", "wallet persistence context is incomplete");
        return false;
    }
    if (!wallet_lock_encrypted_at_rest()) {
        vi_error(out, "WALLET_NOT_ENCRYPTED", "encrypt wallet keys and metadata before planning");
        return false;
    }
    if (!wallet_lock_is_unlocked()) {
        vi_error(out, "WALLET_LOCKED", "unlock the wallet through stdin before planning");
        return false;
    }
    sqlite3 *db = ctx->wallet_db->open ? ctx->wallet_db->db : NULL;
    struct wallet_persistence_health h = wallet_persistence_get_health(
        db, (int)ctx->wallet->keystore.num_keys);
    if (!h.open || !h.canary_ok || h.row_count < 0 || h.mismatch ||
        h.corrupt_rows > 0) {
        vi_error(out, "WALLET_PERSISTENCE_UNHEALTHY",
                 "wallet persistence health gate failed; inspect core wallet status");
        return false;
    }
    if (require_current_backup) {
        struct wallet_backup_status backup;
        wallet_backup_status_snapshot(&backup);
        int64_t now = (int64_t)platform_time_wall_time_t();
        size_t path_len = strlen(backup.last_encrypted_path);
        bool encrypted_backup = path_len > 4 &&
            strcmp(backup.last_encrypted_path + path_len - 4, ".enc") == 0;
        if (backup.last_encrypted_run_unix <= 0 ||
            now < backup.last_encrypted_run_unix ||
            now - backup.last_encrypted_run_unix > 86400 ||
            !encrypted_backup ||
            access(backup.last_encrypted_path, R_OK) != 0 ||
            backup.last_encrypted_tables_verified !=
                backup.wallet_table_count ||
            backup.last_encrypted_key_count != h.row_count) {
            vi_error(out, "ENCRYPTED_BACKUP_REQUIRED",
                     "a current-key encrypted, fully verified wallet backup under 24 hours old is required");
            return false;
        }
    }
    char why[96] = {0};
    if (!sovereignty_guard_allow("wallet_spend", why, sizeof(why))) {
        vi_error(out, "SOVEREIGNTY_GATE", why);
        return false;
    }
    return true;
}

bool vault_intent_context_ready(struct wallet_rpc_context *ctx,
                                struct json_value *out)
{ return vi_context_ready(ctx, out, true); }

static bool vi_effects(const struct json_value *input, struct vi_payload *p,
                       struct json_value *out)
{
    const char *route = json_get_str(json_get(input, "route"));
    if (!route) route = "private";
    if (strcmp(route, "transparent") != 0) {
        vi_error(out, strcmp(route, "private") == 0 ?
            "PRIVACY_ROUTE_UNAVAILABLE" : "UNSUPPORTED_ROUTE",
            "privacy is never downgraded; this build currently commits only explicit transparent plans");
        return false;
    }
    const struct json_value *effects = json_get(input, "effects");
    size_t effect_count = effects ? json_size(effects) : 0;
    if (!effects || effects->type != JSON_ARR || effect_count == 0 ||
        effect_count > VI_EFFECTS_MAX) {
        vi_error(out, "INVALID_EFFECTS", "effects must contain 1..50 entries");
        return false;
    }
    int64_t total = 0;
    p->effects_len = effect_count;
    for (size_t i = 0; i < effect_count; i++) {
        const struct json_value *e = json_at(effects, i);
        const char *asset = e ? json_get_str(json_get(e, "asset")) : NULL;
        const char *to = e ? json_get_str(json_get(e, "to")) : NULL;
        int64_t amount = 0;
        struct tx_destination dest;
        if (!e || e->type != JSON_OBJ || !asset || strcmp(asset, "ZCL") ||
            !to || strlen(to) > VI_ADDR_MAX ||
            !json_get(e, "amount") || json_get(e, "amount")->type != JSON_STR ||
            !vault_intent_parse_zcl_amount(
                json_get_str(json_get(e, "amount")), &amount) ||
            !wallet_decode_address(to, &dest) || // raw-return-ok:invalid recipient is reported below
            total > INT64_MAX - amount) {
            vi_error(out, "INVALID_EFFECT", "each effect needs asset=ZCL, a transparent address, and a decimal-string amount");
            return false; // raw-return-ok:invalid_effect_reported
        }
        snprintf(p->effects[i].to, sizeof(p->effects[i].to), "%s", to);
        p->effects[i].amount = amount;
        total += amount;
    }
    return true;
}

static bool rpc_vi_plan_checked(const struct json_value *params, bool help,
                                struct json_value *result,
                                bool backup_preflight_held)
{
    RPC_HELP(help, result,
             "vault_intent_plan {wallet_scope,route,effects,idempotency_key}\n");
    const struct json_value *input = json_at(params, 0);
    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    if (!input || input->type != JSON_OBJ) {
        vi_error(result, "INVALID_INPUT", "one intent object is required");
        return true;
    }
    const char *wallet_scope = json_get_str(json_get(input, "wallet_scope"));
    if (!wallet_money_scope_valid(wallet_scope)) {
        vi_error(result, "WALLET_SCOPE_REQUIRED",
                 "wallet_scope must explicitly be dev, prod, or test");
        return true;
    }
    const char *route = json_get_str(json_get(input, "route"));
    if (!route || strcmp(route, "transparent") != 0)
        return vault_intent_private_plan(input, result);
    const char *idem = json_get_str(json_get(input, "idempotency_key"));
    if (!vault_intent_idempotency_key_valid(idem)) {
        vi_error(result, "IDEMPOTENCY_KEY_REQUIRED",
                 "idempotency_key must be 1..64 printable characters");
        return true;
    }
    /* A fanout holds this full preflight while it mints durable self-custody
     * destinations. Re-running it after key generation made a long batch race
     * normal tip-finalize cursor movement and stranded the new keys. The plan
     * below still performs fresh money/input/tip binding and atomic reservation. Commit repeats the full
     * context/backup/sovereignty gate before any value can move. */
    if (!backup_preflight_held && !vi_context_ready(ctx, result, true)) return true;
    (void)vault_intent_expire_due(
        ctx->node_db, (int64_t)platform_time_wall_time_t());
    struct vi_payload p; memset(&p, 0, sizeof(p));
    if (!vi_effects(input, &p, result)) return true;
    int64_t target = 0;
    for (size_t i = 0; i < p.effects_len; i++) target += p.effects[i].amount;
    p.fee = wallet_default_fee(ctx->wallet);
    if (p.fee < 0 || target > INT64_MAX - p.fee) {
        vi_error(result, "FEE_INVALID", "wallet fee is invalid"); return true;
    }
    const char *agent_session =
        json_get_str(json_get(input, "_agent_session"));
    int64_t session_reserve_floor = VAULT_INTENT_DEV_RESERVE_FLOOR_ZAT;
    if (agent_session && agent_session[0]) {
        const char *recipients[VI_EFFECTS_MAX];
        for (size_t i = 0; i < p.effects_len; i++)
            recipients[i] = p.effects[i].to;
        char why[64] = { 0 };
        if (!agent_session_service_plan_intent(
                agent_session, wallet_scope, target + p.fee,
                recipients, p.effects_len, &session_reserve_floor,
                why, sizeof(why))) {
            vi_error(result, why[0] ? why : "POLICY_STORE",
                     "bounded session refused the exact intent plan");
            return true;
        }
    }
    uint8_t request_digest[32];
    vi_request_digest(&p, wallet_scope, request_digest);
    struct vault_intent_row existing;
    if (vault_intent_find_application_idempotency(
            ctx->node_db, wallet_scope, VI_APP_KIND, idem, &existing)) {
        if (agent_session && agent_session[0] &&
            existing.agent_session_id[0] &&
            strcmp(existing.agent_session_id, agent_session) != 0) {
            vi_error(result, "POLICY_INTENT_SESSION",
                     "that idempotency key is bound to another grant");
            return true;
        }
        return vi_render_idempotent(ctx, result, &existing, request_digest,
                                    &p);
    }
    struct wallet_money_snapshot money;
    struct zcl_result money_result = wallet_money_snapshot_build(
        ctx->node_db, ctx->main_state, wallet_scope, &money);
    struct vault_intent_plan_snapshot decision_snapshot = {
        .money_result_ok = money_result.ok,
        .money_complete = money_result.ok && money.complete,
        .money_current = money_result.ok && money.complete &&
            strcmp(money.status, "CURRENT") == 0,
        .development_scope = strcmp(wallet_scope, "dev") == 0,
        .target_zat = target,
        .fee_zat = p.fee,
        .confirmed_zat = money_result.ok ? money.confirmed_zat : 0,
        .already_reserved_zat = money_result.ok
            ? money.intent_reserved_zat : 0,
        .agent_available_zat = money_result.ok
            ? (agent_session && agent_session[0]
                ? wallet_money_agent_available_for_floor(
                    &money, session_reserve_floor)
                : money.agent_available_zat) : 0,
    };
    struct vault_intent_plan_decision decision;
    if (!vault_intent_plan_decide(&decision_snapshot, &decision)) {
        vi_error(result, "DECISION_CORE_INVALID",
                 "immutable planning snapshot was invalid");
        return true;
    }
    if (decision.code == VAULT_INTENT_DECISION_MONEY_NOT_CURRENT) {
        vi_error(result, "MONEY_STATE_NOT_CURRENT",
                 money_result.ok ? money.reason : money_result.message);
        return true;
    }
    if (decision.code != VAULT_INTENT_DECISION_ALLOW) {
        vi_error(result, vault_intent_decision_code_name(decision.code),
                 "recipient value plus maximum fee exceeds current custody allocation");
        return true;
    }
    int64_t reservation = decision.reservation_zat;
    struct coin_entry *avail = zcl_malloc(4096 * sizeof(*avail),
                                           "intent_available_coins");
    struct coin_entry chosen[VI_INPUTS_MAX];
    if (!avail) { vi_error(result, "OUT_OF_MEMORY", "coin inventory allocation failed"); return true; }
    size_t na = 0, nc = 0; int64_t value = 0;
    wallet_available_coins(ctx->wallet, avail, &na, 4096, true, false);
    bool funded = wallet_select_coins(ctx->wallet, avail, na, target + p.fee,
                                      chosen, &nc, VI_INPUTS_MAX, &value);
    if (!funded || nc == 0 || nc > VI_INPUTS_MAX) {
        free(avail);
        vi_error(result, "INSUFFICIENT_CONFIRMED_FUNDS", "confirmed transparent funds cannot satisfy effects and fee");
        return true;
    }
    p.inputs_len = nc;
    for (size_t i = 0; i < nc; i++) {
        memcpy(p.inputs[i].txid, chosen[i].wtx->tx.hash.data, 32);
        p.inputs[i].vout = (uint32_t)chosen[i].i;
    }
    free(avail);
    struct wallet_money_snapshot reserved_money;
    if (!wallet_money_snapshot_after_reservation(
            &money, reservation, &reserved_money)) {
        vi_error(result, "MONEY_STATE_NOT_CURRENT",
                 "current money snapshot cannot include this reservation");
        return true;
    }
    uint8_t plain[WALLET_METADATA_PLAINTEXT_MAX]; size_t plen = 0;
    if (!vi_encode(&p, plain, sizeof(plain), &plen)) {
        vi_error(result, "PLAN_ENCODING_FAILED", "could not encode exact plan"); return true;
    }
    struct vault_intent_row row; memset(&row, 0, sizeof(row));
    if (RAND_bytes(row.plan_id, 32) != 1) {
        memory_cleanse(plain, sizeof(plain));
        vi_error(result, "RNG_FAILED", "could not mint plan id"); return true;
    }
    row.state = VAULT_INTENT_PLANNED;
    row.route = VAULT_INTENT_ROUTE_TRANSPARENT;
    row.created_at = (int64_t)platform_time_wall_time_t();
    row.expires_at = row.created_at + VI_TTL;
    row.updated_at = row.created_at;
    row.anchor_height = money.tip_height;
    memcpy(row.anchor_hash, money.tip_hash, 32);
    snprintf(row.wallet_scope, sizeof(row.wallet_scope), "%s", wallet_scope);
    snprintf(row.wallet_instance_id, sizeof(row.wallet_instance_id), "%s",
             money.identity.wallet_instance_id);
    wallet_identity_genesis_hex(&money.identity, row.wallet_genesis);
    memcpy(row.snapshot_root, reserved_money.snapshot_root, 32);
    row.has_snapshot_root = true;
    row.recipient_value_zat = target;
    row.max_fee_zat = p.fee;
    row.reserved_zat = reservation;
    snprintf(row.application_kind, sizeof(row.application_kind), "%s",
             VI_APP_KIND);
    snprintf(row.idempotency_key, sizeof(row.idempotency_key), "%s", idem);
    memcpy(row.request_digest, request_digest, 32);
    row.has_request_digest = true;
    if (agent_session && agent_session[0])
        (void)snprintf(row.agent_session_id,
                       sizeof(row.agent_session_id), "%s", agent_session);
    vault_intent_digest_payload(plain, plen, &row, row.digest);
    bool encrypted = wallet_metadata_encrypt(ctx->node_db, row.plan_id, 32,
        plain, plen, row.encrypted_payload, sizeof(row.encrypted_payload),
        &row.encrypted_payload_len);
    bool stored = encrypted && vault_intent_reserve_bound(
        ctx->node_db, &row, money.confirmed_zat,
        money.intent_reserved_zat);
    memory_cleanse(plain, sizeof(plain));
    if (!stored) {
        /* A concurrent request with the same key can win the unique insert
         * after our first lookup.  Resolve that race as the same idempotent
         * plan, never as permission to create another reservation. */
        if (vault_intent_find_application_idempotency(
                ctx->node_db, wallet_scope, VI_APP_KIND, idem, &existing))
            return vi_render_idempotent(ctx, result, &existing,
                                        request_digest, &p);
        vi_error(result, "PLAN_PERSIST_FAILED",
                 "plan was not reserved; retry the same idempotency_key");
        return true;
    }
    json_set_object(result); json_push_kv_bool(result, "ok", true);
    vault_intent_render_row(ctx, result, &row);
    vault_intent_transparent_render_plan(&p, &row, result);
    json_push_kv_bool(result, "idempotent_plan", false);
    return true;
}

static bool rpc_vi_plan(const struct json_value *params, bool help,
                        struct json_value *result)
{ return rpc_vi_plan_checked(params, help, result, false); }

bool vault_intent_plan_transparent_fanout_continuation(
    const struct json_value *params, struct json_value *result)
{
    if (!params || params->type != JSON_ARR || !result)
        LOG_FAIL("vault_intent", "fanout continuation: invalid argument");
    return rpc_vi_plan_checked(params, false, result, true);
}

bool vault_intent_transparent_shape_matches(
    const struct vault_intent_row *row, size_t output_count,
    int64_t output_value_zat)
{
    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    if (!row || !ctx || !ctx->node_db || output_count == 0 ||
        output_count > VI_EFFECTS_MAX || output_value_zat <= 0 ||
        row->route != VAULT_INTENT_ROUTE_TRANSPARENT ||
        strcmp(row->application_kind, VI_APP_KIND) != 0)
        return false; // raw-return-ok:predicate
    uint8_t plain[WALLET_METADATA_PLAINTEXT_MAX]; size_t plain_len = 0;
    if (!wallet_metadata_decrypt(ctx->node_db, row->plan_id, 32,
            row->encrypted_payload, row->encrypted_payload_len,
            plain, sizeof(plain), &plain_len))
        return false; // raw-return-ok:predicate
    struct vi_payload payload;
    uint8_t digest[32];
    vault_intent_digest_payload(plain, plain_len, row, digest);
    bool matches = memcmp(digest, row->digest, 32) == 0 &&
        vi_decode(plain, plain_len, &payload) &&
        payload.effects_len == output_count;
    for (size_t i = 0; matches && i < payload.effects_len; i++)
        matches = payload.effects[i].amount == output_value_zat;
    memory_cleanse(plain, sizeof(plain));
    return matches;
}

static bool vi_build_prepared(struct wallet_rpc_context *ctx,
                              const struct vault_intent_row *row,
                              struct wallet_tx *wtx, struct json_value *result)
{
    uint8_t plain[WALLET_METADATA_PLAINTEXT_MAX]; size_t plen = 0;
    if (!wallet_metadata_decrypt(ctx->node_db, row->plan_id, 32,
            row->encrypted_payload, row->encrypted_payload_len,
            plain, sizeof(plain), &plen)) {
        vi_error(result, "PLAN_DECRYPT_FAILED", "encrypted plan failed authentication");
        return false;
    }
    uint8_t digest[32];
    vault_intent_digest_payload(plain, plen, row, digest);
    struct vi_payload p;
    bool valid = memcmp(digest, row->digest, 32) == 0 && vi_decode(plain, plen, &p);
    memory_cleanse(plain, sizeof(plain));
    if (!valid) { vi_error(result, "PLAN_TAMPERED", "plan digest or payload changed"); return false; }
    struct coin_entry *avail = zcl_malloc(4096 * sizeof(*avail),
                                           "intent_commit_coins");
    struct coin_entry selected[VI_INPUTS_MAX];
    struct tx_out outputs[VI_EFFECTS_MAX];
    if (!avail) { vi_error(result, "OUT_OF_MEMORY", "commit inventory allocation failed"); return false; }
    size_t na = 0;
    wallet_available_coins(ctx->wallet, avail, &na, 4096, true, false);
    bool found_all = true;
    for (size_t i = 0; i < p.inputs_len; i++) {
        bool found = false;
        for (size_t j = 0; j < na; j++) {
            if (avail[j].i == p.inputs[i].vout &&
                memcmp(avail[j].wtx->tx.hash.data, p.inputs[i].txid, 32) == 0) {
                selected[i] = avail[j]; found = true; break;
            }
        }
        if (!found) { found_all = false; break; }
    }
    free(avail);
    if (!found_all) { vi_error(result, "INPUT_CONFLICT", "an exact input is no longer confirmed and spendable"); return false; }
    for (size_t i = 0; i < p.effects_len; i++) {
        struct tx_destination dest; memset(&outputs[i], 0, sizeof(outputs[i]));
        if (!wallet_decode_address(p.effects[i].to, &dest)) {
            vi_error(result, "RECIPIENT_REVALIDATION_FAILED", "planned recipient no longer decodes");
            return false; // raw-return-ok:recipient_revalidation_reported
        }
        outputs[i].value = p.effects[i].amount;
        script_for_destination(&outputs[i].script_pub_key, &dest);
    }
    int64_t fee = 0; const char *why = NULL;
    if (!wallet_create_transaction_selected(ctx->wallet, selected, p.inputs_len,
            outputs, p.effects_len, wtx, &fee, &why) || fee != p.fee) {
        vi_error(result, "EXACT_BUILD_FAILED", why ? why : "fee changed since planning"); return false;
    }
    /* wallet_create_transaction_selected() can consume only a keypool entry
     * whose private key was durably flushed before it became eligible.  No
     * new key material is created here, so a full all-key re-encryption is
     * neither a durability boundary nor part of the plan hot path.  The new
     * wallet transaction itself is persisted before relay by
     * wallet_persist_commit_before_relay(). */
    struct byte_stream s; stream_init(&s, 1024);
    bool saved = transaction_serialize(&wtx->tx, &s) &&
        s.size <= VAULT_INTENT_RAW_MAX &&
        vault_intent_store_raw(ctx->node_db, row->plan_id, s.data, s.size) &&
        vault_intent_set_state(ctx->node_db, row->plan_id,
            VAULT_INTENT_PROVING, wtx->tx.hash.data, "",
            (int64_t)platform_time_wall_time_t());
    stream_free(&s);
    if (!saved) {
        transaction_free(&wtx->tx);
        vi_error(result, "PRE_RELAY_DURABILITY_FAILED", "signed transaction could not be recorded"); return false;
    }
    return true;
}

bool vault_intent_commit_input(const struct json_value *in,
                               struct json_value *result)
{
    const char *hex = in ? json_get_str(json_get(in, "plan_id")) : NULL;
    const char *wallet_scope = in
        ? json_get_str(json_get(in, "wallet_scope")) : NULL;
    uint8_t id[32];
    if (!in || !wallet_money_scope_valid(wallet_scope) ||
        !json_get_bool_or(in, "confirm", false) || !vi_unhex(hex, id)) {
        vi_error(result, "CONFIRM_REQUIRED",
                 "wallet_scope, plan_id, and confirm:true are required");
        return true;
    }
    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    if (!vault_intent_context_ready(ctx, result)) return true;
    int64_t now = (int64_t)platform_time_wall_time_t();
    vault_intent_expire_due(ctx->node_db, now);
    struct vault_intent_row row;
    if (!vault_intent_find(ctx->node_db, id, &row)) {
        vi_error(result, "PLAN_NOT_FOUND", "no durable plan has that id"); return true;
    }
    if (!row.wallet_scope[0] || strcmp(row.wallet_scope, wallet_scope) != 0) {
        vi_error(result, row.wallet_scope[0] ? "WALLET_SCOPE_MISMATCH"
                                            : "LEGACY_PLAN_UNBOUND",
                 "the plan is not bound to the explicitly targeted wallet scope");
        return true;
    }
    if (row.state >= VAULT_INTENT_MEMPOOL_ACCEPTED &&
        row.state <= VAULT_INTENT_FINALIZED) {
        if (row.state == VAULT_INTENT_MEMPOOL_ACCEPTED &&
            !vault_intent_republish_durable(ctx, id, now, result))
            return true;
        (void)vault_intent_find(ctx->node_db, id, &row);
        json_set_object(result); json_push_kv_bool(result, "ok", true);
        vault_intent_render_row(ctx, result, &row); json_push_kv_bool(result, "idempotent_replay", true); return true;
    }
    const bool prepared_retry = vault_intent_prepared_retry_allowed(
        &row, vault_intent_has_raw(ctx->node_db, id));
    if (!prepared_retry &&
        (row.state == VAULT_INTENT_EXPIRED || row.expires_at <= now)) {
        vi_error(result, "PLAN_EXPIRED", "the ten-minute plan lifetime elapsed"); return true;
    }
    struct wallet_money_snapshot money;
    struct zcl_result money_result = wallet_money_snapshot_build(
        ctx->node_db, ctx->main_state, wallet_scope, &money);
    char genesis[65];
    wallet_identity_genesis_hex(&money.identity, genesis);
    if (!money_result.ok || !money.complete ||
        strcmp(money.status, "CURRENT") != 0) {
        vi_error(result, "MONEY_STATE_NOT_CURRENT",
                 money_result.ok ? money.reason : money_result.message);
        return true;
    }
    if (strcmp(row.wallet_instance_id,
               money.identity.wallet_instance_id) != 0 ||
        strcmp(row.wallet_genesis, genesis) != 0) {
        (void)vault_intent_set_state(ctx->node_db, id,
            VAULT_INTENT_CONFLICTED, NULL, "WALLET_IDENTITY_CHANGED", now);
        vi_error(result, "WALLET_IDENTITY_CHANGED",
                 "wallet instance or network no longer matches the plan");
        return true;
    }
    if (!prepared_retry && (!vault_intent_anchor_current(ctx, &row) ||
        memcmp(row.snapshot_root, money.snapshot_root, 32) != 0)) {
        (void)vault_intent_set_state(ctx->node_db, id,
            VAULT_INTENT_CONFLICTED, NULL, "MONEY_SNAPSHOT_CHANGED", now);
        vi_error(result, "MONEY_SNAPSHOT_CHANGED",
                 "tip, mempool, balance, or reservation state changed; create a fresh plan");
        return true;
    }
    if (row.state == VAULT_INTENT_PROVING &&
        !vault_intent_has_raw(ctx->node_db, id)) {
        if (now - row.updated_at < VI_PROVING_LEASE) {
            vi_error(result, "COMMIT_BUSY",
                     "another commit is preparing the signed transaction");
            return true;
        }
        if (!vault_intent_reclaim_proving(ctx->node_db, id,
                                          now - VI_PROVING_LEASE, now) ||
            !vault_intent_claim_commit(ctx->node_db, id, now)) {
            vi_error(result, "COMMIT_BUSY",
                     "the expired proving lease could not be reclaimed");
            return true;
        }
        row.state = VAULT_INTENT_PROVING;
        row.updated_at = now;
    }
    if (row.state == VAULT_INTENT_PLANNED &&
        !vault_intent_claim_commit(ctx->node_db, id, now)) {
        vi_error(result, "COMMIT_BUSY", "another commit claimed this plan"); return true;
    }
    if (row.state != VAULT_INTENT_PLANNED && row.state != VAULT_INTENT_PROVING) {
        vi_error(result, "PLAN_NOT_COMMITTABLE", vault_intent_state_name(row.state)); return true;
    }
    uint8_t *raw = zcl_malloc(VAULT_INTENT_RAW_MAX, "intent_raw_tx");
    if (!raw) { vi_error(result, "OUT_OF_MEMORY", "raw transaction allocation failed"); return true; }
    size_t raw_len = 0; struct wallet_tx wtx; memset(&wtx, 0, sizeof(wtx));
    if (vault_intent_load_raw(ctx->node_db, id, raw, VAULT_INTENT_RAW_MAX,
                              &raw_len)) {
        struct byte_stream s; stream_init_from_data(&s, raw, raw_len);
        bool ok = transaction_deserialize(&wtx.tx, &s) && stream_remaining(&s) == 0;
        stream_free(&s);
        if (!ok) { free(raw); transaction_free(&wtx.tx); vi_error(result, "RAW_TX_CORRUPT", "prepared transaction failed to decode"); return true; }
        wtx.time_received = now; wtx.from_me = true; wtx.used = true;
    } else if (row.route == VAULT_INTENT_ROUTE_TRANSPARENT
                   ? !vi_build_prepared(ctx, &row, &wtx, result)
                   : !vault_intent_private_build_prepared(
                         ctx, &row, &wtx, result)) {
        free(raw);
        const char *code = json_get_str(json_get(result, "code"));
        if (code && strcmp(code, "INPUT_CONFLICT") == 0)
            (void)vault_intent_set_state(ctx->node_db, id,
                VAULT_INTENT_CONFLICTED, NULL, "INPUT_CONFLICT", now);
        else
            /* The proving claim owns no broadcast bytes yet. A failed exact
             * build must become terminal immediately: leaving it PROVING for
             * the five-minute crash lease makes a known failure look busy and
             * keeps its reservation needlessly locked. */
            (void)vault_intent_set_state(ctx->node_db, id,
                VAULT_INTENT_FAILED, NULL,
                code && code[0] ? code : "EXACT_BUILD_FAILED", now);
        return true;
    }
    free(raw);
    if (!vault_intent_publish_prepared(ctx, id, &wtx, now, result)) { transaction_free(&wtx.tx); return true; }
    transaction_free(&wtx.tx);
    vault_intent_find(ctx->node_db, id, &row);
    json_set_object(result); json_push_kv_bool(result, "ok", true);
    vault_intent_render_row(ctx, result, &row); json_push_kv_bool(result, "idempotent_replay", false);
    return true;
}

static bool rpc_vi_commit(const struct json_value *params, bool help,
                          struct json_value *result)
{
    RPC_HELP(help, result,
             "vault_intent_commit {wallet_scope,plan_id,confirm:true}\n");
    return vault_intent_commit_input(json_at(params, 0), result);
}

static bool rpc_vi_status(const struct json_value *params, bool help,
                          struct json_value *result)
{
    RPC_HELP(help, result, "vault_intent_status {plan_id}\n");
    const struct json_value *in = json_at(params, 0);
    const char *hex = in ? json_get_str(json_get(in, "plan_id")) : NULL;
    uint8_t id[32]; struct vault_intent_row row; struct node_db *ndb = wallet_rpc_node_db();
    if (!vi_unhex(hex, id) || !ndb || !vault_intent_find(ndb, id, &row)) {
        vi_error(result, "PLAN_NOT_FOUND", "no durable plan has that id"); return true;
    }
    vault_intent_expire_due(ndb, (int64_t)platform_time_wall_time_t());
    vault_intent_find(ndb, id, &row);
    vault_intent_refresh_state(wallet_rpc_context_current(), &row,
                               (int64_t)platform_time_wall_time_t());
    json_set_object(result); json_push_kv_bool(result, "ok", true);
    vault_intent_render_row(wallet_rpc_context_current(), result, &row);
    return true;
}

static bool rpc_vi_list(const struct json_value *params, bool help,
                        struct json_value *result)
{
    (void)params; RPC_HELP(help, result, "vault_intent_list\n");
    struct node_db *ndb = wallet_rpc_node_db();
    if (!ndb) { vi_error(result, "DATABASE_UNAVAILABLE", "node.db is unavailable"); return true; }
    vault_intent_expire_due(ndb, (int64_t)platform_time_wall_time_t());
    struct vault_intent_row *rows = zcl_calloc(
        100, sizeof(*rows), "vault intent RPC list rows");
    if (!rows) {
        vi_error(result, "ALLOCATION_FAILED",
                 "vault intent list workspace allocation failed");
        return true;
    }
    int n = vault_intent_list(ndb, rows, 100);
    if (n < 0) {
        free(rows);
        vi_error(result, "DATABASE_READ_FAILED",
                 "vault intent list could not be read");
        return true;
    }
    for (int i = 0; i < n; i++)
        vault_intent_refresh_state(wallet_rpc_context_current(), &rows[i],
                                   (int64_t)platform_time_wall_time_t());
    json_set_object(result); json_push_kv_bool(result, "ok", true);
    struct json_value items; json_init(&items); json_set_array(&items);
    for (int i = 0; i < n; i++) {
        struct json_value item; json_init(&item); json_set_object(&item);
        vault_intent_render_row(wallet_rpc_context_current(), &item,
                                &rows[i]);
        json_push_back(&items, &item); json_free(&item);
    }
    json_push_kv(result, "intents", &items); json_free(&items);
    free(rows);
    json_push_kv_int(result, "count", n); return true;
}

void register_vault_intent_rpc_commands(struct rpc_table *t)
{
    const struct rpc_command cmds[] = {
        { "wallet", "vault_intent_plan", rpc_vi_plan, false },
        { "wallet", "vault_intent_fanout_plan",
          vault_intent_fanout_plan_rpc, false },
        { "wallet", "vault_intent_commit", rpc_vi_commit, false },
        { "wallet", "vault_intent_status", rpc_vi_status, false },
        { "wallet", "vault_intent_list", rpc_vi_list, false },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
    register_vault_intent_async_rpc_commands(t);
}
