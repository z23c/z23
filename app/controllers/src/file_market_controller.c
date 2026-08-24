/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Market RPC controller: file sharing marketplace commands.
 *
 * Commands:
 *   zmarket_list    — list available files on the network
 *   zmarket_offer   — announce a file for sale
 *   zmarket_buy     — initiate purchase of a file
 *   zmarket_status  — show active downloads/uploads */

#include "platform/time_compat.h"
#include "base/hex.h"
#include "controllers/file_market_controller.h"
#include "controllers/network_controller.h"
#include "controllers/wallet_helpers.h"
#include "controllers/wallet_shielded_controller.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "net/file_market.h"
#include "net/msgprocessor.h"
#include "net/rom_seed.h"
#include "net/tor_integration.h"
#include "util/util.h"
#include "encoding/utilstrencodings.h"
#include "util/log_macros.h"
#include "json/json.h"
#include "rpc/server.h"
#include "models/database.h"
#include "models/file_offer.h"
#include "models/market_content.h"
#include "services/file_market_content_service.h"
#include "services/file_market_purchase_service.h"
#include "services/market_moderation_service.h"
#include "services/market_moderation_view_service.h"
#include "hotswap/hotswap_service.h"
#include "validation/main_state.h"
#include "wallet/wallet.h"
#include "config/runtime.h"
#include "crypto/sha3.h"
#include "views/format_helpers.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ── Context ────────────────────────────────────────────────────── */

static struct node_db *g_market_ndb = NULL;
static char g_market_datadir[1024] = "";

void rpc_market_set_state(struct node_db *ndb)
{
    g_market_ndb = ndb;
    /* Bind the per-node moderation context to the same store: the
     * datadir derives from the node.db path (<datadir>/node.db). */
    g_market_datadir[0] = '\0';
    if (ndb && ndb->path[0]) {
        snprintf(g_market_datadir, sizeof(g_market_datadir), "%s", ndb->path);
        char *slash = strrchr(g_market_datadir, '/');
        if (slash)
            *slash = '\0';
        else
            g_market_datadir[0] = '\0';
    }
    market_moderation_set_context(
        ndb, g_market_datadir[0] ? g_market_datadir : NULL);
}

/* ── zmarket_list ───────────────────────────────────────────────── */

/* The listing view filter: every cached offer is annotated with its
 * LOCAL review_state; the active per-node profile decides visibility.
 * Protocol validity, hosting, and trading are unaffected — a hidden
 * offer is still stored, served, and tradable. */
static bool market_list_json(const char *profile_override,
                             struct json_value *result)
{
    int active = market_moderation_active_profile();
    struct zcl_hotswap_service_lease moderation_lease = {0};
    const struct market_moderation_view_service_v1 *moderation_view =
        zcl_hotswap_service_acquire(MARKET_MODERATION_VIEW_SERVICE_ID, &moderation_lease);
    if (!moderation_view) moderation_view = market_moderation_view_service_builtin();
    int profile = -1;
    if (!moderation_view->resolve_profile(profile_override, active, &profile)) {
        zcl_hotswap_service_release(&moderation_lease);
        json_set_str(result,
            "unknown market moderation profile override — use \"open\", "
            "\"open-view\", \"general\", or \"general-audience.v1\"");
        return false;
    }
    json_set_object(result);
    json_push_kv_str(result, "profile",
        market_moderation_profile_string((enum market_moderation_profile)profile));
    json_push_kv_bool(result, "profile_override",
                      profile_override != NULL && profile_override[0]);
    struct file_offer offers[FILE_MARKET_MAX_OFFERS];
    int count = file_market_get_offers(offers, FILE_MARKET_MAX_OFFERS);
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    int64_t hidden = 0;
    for (int i = 0; i < count; i++) {
        int review = market_moderation_review_state_for_root(
            offers[i].root_hash);
        struct market_moderation_decision_result_v1 decision;
        if (!moderation_view->decide(profile, review, &decision) ||
            !decision.valid || !decision.visible) {
            hidden++;
            continue;
        }
        struct json_value entry = {0};
        json_set_object(&entry);

        char hex[65];
        HexStr(offers[i].root_hash, 32, false, hex, sizeof(hex));
        json_push_kv_str(&entry, "root_hash", hex);
        json_push_kv_str(&entry, "filename", offers[i].filename);
        json_push_kv_str(&entry, "review_state",
                         market_review_state_string(
                             (enum market_review_state)review));
        json_push_kv_int(&entry, "size_bytes", (int64_t)offers[i].size_bytes);

        double size_mb = offers[i].size_bytes / (1024.0 * 1024.0);
        json_push_kv_real(&entry, "size_mb", size_mb);

        json_push_kv_int(&entry, "num_chunks", offers[i].num_chunks);
        json_push_kv_int(&entry, "price_per_mb_zat", offers[i].price_per_mb);

        /* Price in ZCL */
        double price_zcl = offers[i].price_per_mb / 100000000.0;
        json_push_kv_real(&entry, "price_per_mb_zcl", price_zcl);

        int64_t total_zat = 0;
        if (file_market_offer_total_zat(&offers[i], &total_zat)) {
            json_push_kv_int(&entry, "total_cost_zat", total_zat);
            json_push_kv_real(&entry, "total_cost_zcl",
                              total_zat / 100000000.0);
        } else if (offers[i].price_per_mb == 0) {
            json_push_kv_int(&entry, "total_cost_zat", 0);
            json_push_kv_real(&entry, "total_cost_zcl", 0.0);
        }

        json_push_kv_int(&entry, "peer_port", offers[i].peer_port);
        json_push_kv_int(&entry, "ttl", offers[i].ttl);
        json_push_kv_int(&entry, "last_seen", offers[i].last_seen);
        json_push_kv_bool(&entry, "authenticated",
                          file_offer_auth_version_supported(
                              offers[i].auth_version));
        if (file_offer_auth_version_supported(offers[i].auth_version)) {
            char offer_hex[65];
            HexStr(offers[i].offer_id, 32, false,
                   offer_hex, sizeof(offer_hex));
            json_push_kv_str(&entry, "offer_id", offer_hex);
            json_push_kv_int(&entry, "expires_unix",
                             offers[i].expires_unix);
        }

        json_push_back(&rows, &entry);
        json_free(&entry);
    }

    json_push_kv(result, "offers", &rows);
    json_free(&rows);
    json_push_kv_int(result, "offer_count", count - hidden);
    json_push_kv_int(result, "hidden_count", hidden);
    zcl_hotswap_service_release(&moderation_lease);
    return true;
}

/* Accepts [profile] or [{"profile":"open"}] — both the native bridge and
 * ad-hoc RPC callers get the explicit per-request view override. */
static const char *market_list_profile_param(const struct json_value *params,
                                             char *err, size_t err_len)
{
    if (!params || json_size(params) < 1)
        return NULL;
    const struct json_value *arg0 = json_at(params, 0);
    if (!arg0)
        return NULL;
    if (arg0->type == JSON_STR)
        return json_get_str(arg0);
    if (arg0->type == JSON_OBJ) {
        const struct json_value *p = json_get(arg0, "profile");
        if (p && p->type == JSON_STR)
            return json_get_str(p);
        if (!p) {
            snprintf(err, err_len,
                     "first argument object only accepts the \"profile\" key");
            return NULL;
        }
    }
    snprintf(err, err_len,
             "profile override must be a string or an object with a "
             "\"profile\" string");
    return NULL;
}

static bool rpc_zmarket_list(const struct json_value *params, bool help,
                             struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "zmarket_list [profile]\n"
            "\nList files available on the ZCL Market network through the\n"
            "node's own listing-visibility profile (local moderation).\n"
            "\nArguments:\n"
            "1. profile   (string, optional) \"open\"/\"open-view\" shows every\n"
            "             ingested offer; default is the node's active profile.\n"
            "\nResult: object {offers: [...each annotated review_state...],\n"
            "  offer_count, hidden_count, profile}. Hidden offers stay stored\n"
            "and tradable; filtering is view-only.\n");
        return true;
    }
    char err[128] = {0};
    const char *profile = market_list_profile_param(params, err, sizeof(err));
    if (err[0]) {
        json_set_str(result, err);
        return false;
    }
    return market_list_json(profile, result);
}

/* ── zmarket_offer ──────────────────────────────────────────────── */

static bool rpc_zmarket_offer(const struct json_value *params, bool help,
                              struct json_value *result)
{
    if (help || !params || json_size(params) < 2) {
        json_set_str(result,
            "zmarket_offer \"filepath\" price_per_mb_zat [\"z_addr\"]\n"
            "\nContained legacy endpoint: it does not create an offer.\n"
            "\nArguments:\n"
            "1. filepath         (string, required) Path to file to share\n"
            "2. price_per_mb_zat (number, required) Price per MB in zatoshis\n"
            "3. z_addr           (string, optional) Payment z-address\n"
            "\nUse romseed_register for verified free artifacts. Signed paid "
            "offers use the typed native command `app market offer`.\n");
        return true;
    }

    /* Parse arguments */
    const struct json_value *arg0 = json_at(params, 0);
    const struct json_value *arg1 = json_at(params, 1);
    if (!arg0 || !arg1) {
        json_set_str(result, "Missing required arguments");
        return false;
    }

    (void)arg0;
    (void)arg1;

    /* This compatibility RPC never hashed the file manifest and never
     * announced an authenticated origin. The working paid-offer path is the
     * typed native leaf `app market offer` (plan/commit over
     * zmarket_offer_publish); free recovery artifacts use romseed_register. */
    json_set_str(result,
        "zmarket_offer is contained: use the typed native command "
        "`app market offer` for signed paid offers, or romseed_register for "
        "verified free recovery artifacts");
    return false;
}

/* ── zmarket_buy ────────────────────────────────────────────────── */

static bool rpc_zmarket_buy(const struct json_value *params, bool help,
                            struct json_value *result)
{
    if (help || !params || json_size(params) < 1) {
        json_set_str(result,
            "zmarket_buy \"root_hash\" [\"output_path\"]\n"
            "\nContained legacy endpoint: it cannot spend or download.\n"
            "\nArguments:\n"
            "1. root_hash   (string, required) SHA3 hash of file offer\n"
            "2. output_path (string, optional) Where to save the file\n"
            "\nThe typed market-purchase plan/commit service is not "
            "available yet.\n");
        return true;
    }
    (void)params;
    json_set_str(result,
        "zmarket_buy is contained: exact payment verification and paid-file "
        "unlock are not wired; no download session or wallet action started");
    return false;
}

/* ── durable typed purchase payment ─────────────────────────────── */

static const char *market_purchase_code(const struct zcl_result *r)
{
    if (!r) return "PURCHASE_REFUSED";
    switch (r->code) {
    case -3:  return "MONEY_STATE_NOT_CURRENT";
    case -7:  return "IDEMPOTENCY_CONFLICT";
    case -10: return "CUSTODY_ALLOCATION_EXCEEDED";
    case -43: return "COMMIT_UNCERTAIN";
    case -45: return "MONEY_SNAPSHOT_CHANGED";
    case -46: return "OFFER_CONTRACT_CHANGED";
    case -47: return "COMMIT_BUSY";
    case -48: return "COMMIT_STATE_UNCERTAIN";
    case -60: return "DESTINATION_INVALID";
    case -61: return "DOWNLOAD_BINDING_CONFLICT";
    case -62: return "DESTINATION_CONFLICT";
    case -67: return "MANIFEST_VERIFICATION_FAILED";
    case -69: return "DESTINATION_CONFLICT";
    case -75: return "STAGING_VERIFICATION_FAILED";
    case -76: return "DELIVERY_NOT_READY";
    case -78: return "ONION_DELIVERY_UNAVAILABLE";
    default:  return "PURCHASE_REFUSED";
    }
}

static bool market_purchase_refuse(struct json_value *result,
                                   struct zcl_result r)
{
    json_set_object(result);
    json_push_kv_bool(result, "ok", false);
    json_push_kv_str(result, "code", market_purchase_code(&r));
    json_push_kv_str(result, "message", r.message);
    return true;
}

static void market_purchase_amount(int64_t zat, char out[32])
{
    (void)snprintf(out, 32, "%lld.%08lld",
                   (long long)(zat / 100000000LL),
                   (long long)(zat >= 0 ? zat % 100000000LL
                                        : -(zat % 100000000LL)));
}

static bool market_purchase_render(const struct market_purchase_view *view,
                                   struct json_value *result)
{
    if (!view || !result) return false;
    char plan[65], offer[65], buyer[65], txid[65], claim[65];
    char amount[32], fee[32], reserved[32];
    zcl_hex_encode(view->plan_id, 32, plan);
    zcl_hex_encode(view->offer_id, 32, offer);
    zcl_hex_encode(view->buyer_pubkey, 32, buyer);
    market_purchase_amount(view->amount_zat, amount);
    market_purchase_amount(view->maximum_fee_zat, fee);
    market_purchase_amount(view->reserved_zat, reserved);
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "schema", "zcl.market_purchase.v1");
    json_push_kv_str(result, "plan_id", plan);
    json_push_kv_str(result, "offer_id", offer);
    json_push_kv_str(result, "buyer_pubkey", buyer);
    json_push_kv_str(result, "wallet_scope", view->wallet_scope);
    json_push_kv_str(result, "state", view->state);
    json_push_kv_int(result, "chunk_start", view->chunk_start);
    json_push_kv_int(result, "chunks_paid", view->chunks_paid);
    json_push_kv_str(result, "amount_zcl", amount);
    json_push_kv_int(result, "amount_zat", view->amount_zat);
    json_push_kv_str(result, "maximum_fee_zcl", fee);
    json_push_kv_int(result, "maximum_fee_zat", view->maximum_fee_zat);
    json_push_kv_str(result, "reserved_zcl", reserved);
    json_push_kv_int(result, "reserved_zat", view->reserved_zat);
    json_push_kv_int(result, "expires_at", view->expires_at);
    json_push_kv_bool(result, "idempotent_replay",
                      view->idempotent_replay);
    if (view->has_txid) {
        zcl_hex_encode(view->txid, 32, txid);
        json_push_kv_str(result, "txid", txid);
    }
    if (view->has_claim) {
        zcl_hex_encode(view->claim_id, 32, claim);
        json_push_kv_str(result, "claim_id", claim);
    }
    json_push_kv_bool(result, "payment_notification_queued",
                      view->payment_notification_queued);
    if (view->has_download) {
        json_push_kv_str(result, "download_state", view->download_state);
        json_push_kv_int(result, "chunks_received", view->chunks_received);
        json_push_kv_int(result, "num_chunks", view->num_chunks);
        json_push_kv_int(result, "bytes_received",
                         (int64_t)view->bytes_received);
        json_push_kv_int(result, "size_bytes", (int64_t)view->size_bytes);
        json_push_kv_bool(result, "destination_published",
                          view->destination_published);
    }
    return true;
}

static struct zcl_result market_purchase_money(
    void *opaque, const char *scope, struct wallet_money_snapshot *out)
{
    struct wallet_rpc_context *ctx = opaque;
    return wallet_money_snapshot_build(ctx ? ctx->node_db : NULL,
                                       ctx ? ctx->main_state : NULL,
                                       scope, out);
}

static struct zcl_result market_purchase_source_owned(
    void *opaque, const char *source)
{
    struct wallet_rpc_context *ctx = opaque;
    if (!ctx || !ctx->wallet || !source || !source[0])
        return ZCL_ERR(-1, "wallet and source address are required");
    if (wallet_addr_is_sapling(source)) {
        uint8_t d[11], pk_d[32];
        if (!sapling_decode_payment_address(source, d, pk_d) ||
            !sapling_keystore_find_by_address(
                &ctx->wallet->sapling_keys, d, pk_d))
            return ZCL_ERR(-2, "source address is not a wallet spending key");
        return ZCL_OK;
    }
    struct tx_destination dest;
    if (!wallet_decode_address(source, &dest))
        return ZCL_ERR(-3, "source address is invalid for the active network");
    bool owned = (dest.type == DEST_KEY_ID &&
                  keystore_have_key(&ctx->wallet->keystore, &dest.id.key)) ||
                 (dest.type == DEST_SCRIPT_ID &&
                  keystore_have_cscript(&ctx->wallet->keystore,
                                         &dest.id.script.hash));
    return owned ? ZCL_OK
                 : ZCL_ERR(-4, "source address is not a wallet spending key");
}

static struct zcl_result market_purchase_send(
    void *opaque, const char *source, const char *seller, int64_t amount_zat,
    const uint8_t memo[FILE_MARKET_PAYMENT_MEMO_BYTES], uint8_t txid_out[32])
{
    (void)opaque;
    char amount[32], memo_hex[FILE_MARKET_PAYMENT_MEMO_BYTES * 2 + 1];
    market_purchase_amount(amount_zat, amount);
    zcl_hex_encode(memo, FILE_MARKET_PAYMENT_MEMO_BYTES, memo_hex);
    struct json_value params = {0}, recipients = {0}, recipient = {0};
    json_set_array(&params);
    struct json_value from = {0};
    json_set_str(&from, source);
    json_push_back(&params, &from);
    json_free(&from);
    json_set_array(&recipients);
    json_set_object(&recipient);
    json_push_kv_str(&recipient, "address", seller);
    json_push_kv_str(&recipient, "amount", amount);
    json_push_kv_str(&recipient, "memo_hex", memo_hex);
    json_push_back(&recipients, &recipient);
    json_push_back(&params, &recipients);
    struct json_value sent = {0};
    bool ok = rpc_z_sendmany(&params, false, &sent);
    const char *answer = json_get_str(&sent);
    /* z_sendmany returns display-order hex (uint256_get_hex); vault and
     * market rows key internal byte order — set_hex reverses back. */
    struct uint256 parsed;
    bool exact = ok && answer && strlen(answer) == 64;
    if (exact) uint256_set_hex(&parsed, answer);
    if (exact) memcpy(txid_out, parsed.data, 32);
    char reason[192];
    (void)snprintf(reason, sizeof(reason), "%s",
                   answer && answer[0] ? answer
                                       : "wallet refused exact market payment");
    json_free(&sent);
    json_free(&recipient);
    json_free(&recipients);
    json_free(&params);
    return exact ? ZCL_OK : ZCL_ERR(-1, "%s", reason);
}

static bool market_purchase_notify(void *opaque,
                                   const struct file_payment *payment)
{
    struct msg_processor *mp = opaque;
    struct byte_stream wire;
    stream_init(&wire, FILE_MARKET_PAYMENT_WIRE_BYTES);
    bool encoded = mp && file_payment_serialize(payment, &wire) &&
                   wire.size == FILE_MARKET_PAYMENT_WIRE_BYTES;
    if (encoded)
        msg_processor_flood_message(mp, MSG_FILE_PAY, wire.data, wire.size);
    stream_free(&wire);
    return encoded;
}

static struct zcl_result market_purchase_runtime(
    struct market_purchase_runtime *runtime, bool money)
{
    if (!runtime) return ZCL_ERR(-1, "purchase runtime output is required");
    memset(runtime, 0, sizeof(*runtime));
    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    runtime->node_db = ctx ? ctx->node_db : NULL;
    runtime->now_unix = (int64_t)platform_time_wall_time_t();
    /* The fetch transport owes nothing to the money runtime — wire it
     * before the !money early return or retrieve can never run. */
    runtime->fetch = market_purchase_fetch_endpoint;
    runtime->fetch_onion = market_purchase_fetch_onion_endpoint;
    runtime->onion_transport_ready = tor_integration_is_ready();
    if (!money) return runtime->node_db && runtime->node_db->open
        ? ZCL_OK : ZCL_ERR(-2, "market database is unavailable");
    if (!ctx || !ctx->wallet || !ctx->main_state || !ctx->node_db ||
        !ctx->node_db->open)
        return ZCL_ERR(-3, "wallet, chain, and market database are required");
    struct block_index *tip = active_chain_tip(&ctx->main_state->chain_active);
    if (!tip) return ZCL_ERR(-4, "active chain tip is unavailable");
    runtime->read_money = market_purchase_money;
    runtime->money_ctx = ctx;
    runtime->check_source = market_purchase_source_owned;
    runtime->source_ctx = ctx;
    runtime->send = market_purchase_send;
    runtime->send_ctx = ctx;
    runtime->notify = market_purchase_notify;
    runtime->notify_ctx = rpc_net_get_msg_processor();
    runtime->tip_height = tip->nHeight;
    memcpy(runtime->tip_hash, tip->hashBlock.data, 32);
    runtime->maximum_fee_zat = ctx->wallet->default_fee;
    return ZCL_OK;
}

static bool rpc_zmarket_purchase_plan(const struct json_value *params,
                                      bool help,
                                      struct json_value *result)
{
    if (help) {
        json_set_str(result, "zmarket_purchase_plan {wallet_scope,offer_id,source_address,chunk_start,chunks_paid,idempotency_key}\n");
        return true;
    }
    const struct json_value *in = json_at(params, 0);
    const char *scope = in ? json_get_str(json_get(in, "wallet_scope")) : NULL;
    const char *offer = in ? json_get_str(json_get(in, "offer_id")) : NULL;
    const char *source = in ? json_get_str(json_get(in, "source_address")) : NULL;
    const char *key = in ? json_get_str(json_get(in, "idempotency_key")) : NULL;
    const struct json_value *start_value = in
        ? json_get(in, "chunk_start") : NULL;
    const struct json_value *count_value = in
        ? json_get(in, "chunks_paid") : NULL;
    int64_t start = start_value && start_value->type == JSON_INT
        ? json_get_int(start_value) : -1;
    int64_t count = count_value && count_value->type == JSON_INT
        ? json_get_int(count_value) : 0;
    struct market_purchase_request request = {0};
    if (!in || in->type != JSON_OBJ || !scope || !offer || !source || !key ||
        strlen(scope) >= sizeof(request.wallet_scope) ||
        strlen(source) > MARKET_PURCHASE_SOURCE_MAX ||
        strlen(key) >= sizeof(request.idempotency_key) ||
        !zcl_hex_decode(offer, request.offer_id, 32) || start < 0 ||
        start > UINT32_MAX || count <= 0 || count > UINT32_MAX)
        return market_purchase_refuse(result,
            ZCL_ERR(-1, "complete exact purchase-plan input is required"));
    (void)snprintf(request.wallet_scope, sizeof(request.wallet_scope), "%s",
                   scope);
    (void)snprintf(request.source_address, sizeof(request.source_address),
                   "%s", source);
    (void)snprintf(request.idempotency_key, sizeof(request.idempotency_key),
                   "%s", key);
    request.chunk_start = (uint32_t)start;
    request.chunks_paid = (uint32_t)count;
    struct market_purchase_runtime runtime;
    struct zcl_result ready = market_purchase_runtime(&runtime, true);
    if (!ready.ok) return market_purchase_refuse(result, ready);
    struct market_purchase_view view;
    struct zcl_result planned = market_purchase_plan(&runtime, &request, &view);
    return planned.ok ? market_purchase_render(&view, result)
                      : market_purchase_refuse(result, planned);
}

static bool rpc_zmarket_purchase_commit(const struct json_value *params,
                                        bool help,
                                        struct json_value *result)
{
    if (help) {
        json_set_str(result, "zmarket_purchase_commit {wallet_scope,plan_id}\n");
        return true;
    }
    const struct json_value *in = json_at(params, 0);
    const char *scope = in ? json_get_str(json_get(in, "wallet_scope")) : NULL;
    const char *plan = in ? json_get_str(json_get(in, "plan_id")) : NULL;
    uint8_t plan_id[32];
    if (!scope || !zcl_hex_decode(plan, plan_id, 32))
        return market_purchase_refuse(result,
            ZCL_ERR(-1, "wallet_scope and exact plan_id are required"));
    struct market_purchase_runtime runtime;
    struct zcl_result ready = market_purchase_runtime(&runtime, true);
    if (!ready.ok) return market_purchase_refuse(result, ready);
    struct market_purchase_view view;
    struct zcl_result committed = market_purchase_commit(
        &runtime, scope, plan_id, &view);
    return committed.ok ? market_purchase_render(&view, result)
                        : market_purchase_refuse(result, committed);
}

static bool rpc_zmarket_purchase_status(const struct json_value *params,
                                        bool help,
                                        struct json_value *result)
{
    if (help) {
        json_set_str(result, "zmarket_purchase_status {plan_id}\n");
        return true;
    }
    const struct json_value *in = json_at(params, 0);
    const char *plan = in ? json_get_str(json_get(in, "plan_id")) : NULL;
    uint8_t plan_id[32];
    if (!zcl_hex_decode(plan, plan_id, 32))
        return market_purchase_refuse(result,
            ZCL_ERR(-1, "exact plan_id is required"));
    struct market_purchase_runtime runtime;
    struct zcl_result ready = market_purchase_runtime(&runtime, false);
    if (!ready.ok) return market_purchase_refuse(result, ready);
    struct market_purchase_view view;
    struct zcl_result found = market_purchase_status(
        &runtime, plan_id, &view);
    return found.ok ? market_purchase_render(&view, result)
                    : market_purchase_refuse(result, found);
}

static bool rpc_zmarket_purchase_retrieve(const struct json_value *params,
                                          bool help,
                                          struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "zmarket_purchase_retrieve {plan_id,destination_path}\n");
        return true;
    }
    const struct json_value *in = json_at(params, 0);
    const char *plan = in ? json_get_str(json_get(in, "plan_id")) : NULL;
    const char *destination = in
        ? json_get_str(json_get(in, "destination_path")) : NULL;
    uint8_t plan_id[32];
    if (!zcl_hex_decode(plan, plan_id, 32) || !destination ||
        !destination[0])
        return market_purchase_refuse(result,
            ZCL_ERR(-1, "exact plan_id and private destination are required"));
    struct market_purchase_runtime runtime;
    struct zcl_result ready = market_purchase_runtime(&runtime, false);
    if (!ready.ok) return market_purchase_refuse(result, ready);
    struct market_purchase_view view;
    struct zcl_result fetched = market_purchase_retrieve(
        &runtime, plan_id, destination, &view);
    return fetched.ok ? market_purchase_render(&view, result)
                      : market_purchase_refuse(result, fetched);
}

/* ── zmarket_status ─────────────────────────────────────────────── */

static bool rpc_zmarket_status(const struct json_value *params, bool help,
                               struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "zmarket_status\n"
            "\nShow ZCL Market status: offer count, active downloads.\n");
        return true;
    }
    (void)params;

    json_set_object(result);
    json_push_kv_int(result, "offers_cached", file_market_count());

    /* DB count */
    if (g_market_ndb) {
        struct file_offer db_offers[FILE_MARKET_MAX_OFFERS];
        int db_count = db_file_offer_list(g_market_ndb, db_offers,
                                          FILE_MARKET_MAX_OFFERS);
        json_push_kv_int(result, "offers_persisted", db_count);
    }

    return true;
}

/* ── private paid-content registry ───────────────────────────────── */

static bool market_content_index_json(struct json_value *result)
{
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.market_contents.index.v1");
    struct json_value rows = {0};
    json_set_array(&rows);
    if (g_market_ndb && g_market_ndb->open) {
        struct market_content_public_record content[FILE_MARKET_MAX_OFFERS];
        int count = db_market_content_list(g_market_ndb, content,
                                           FILE_MARKET_MAX_OFFERS);
        for (int i = 0; i < count; i++) {
            struct json_value row = {0};
            json_set_object(&row);
            char offer_hex[65], root_hex[65];
            HexStr(content[i].offer_id, 32, false,
                   offer_hex, sizeof(offer_hex));
            HexStr(content[i].root_hash, 32, false,
                   root_hex, sizeof(root_hex));
            json_push_kv_str(&row, "offer_id", offer_hex);
            json_push_kv_str(&row, "root_hash", root_hex);
            json_push_kv_int(&row, "size_bytes",
                             (int64_t)content[i].size_bytes);
            json_push_kv_int(&row, "num_chunks", content[i].num_chunks);
            json_push_kv_int(&row, "registered_at",
                             content[i].registered_at);
            json_push_back(&rows, &row);
            json_free(&row);
        }
    }
    json_push_kv(result, "contents", &rows);
    json_free(&rows);
    return true;
}

static bool rpc_zmarket_content_list(const struct json_value *params,
                                     bool help,
                                     struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "zmarket_content_list\n\nList owner-registered paid content "
            "without revealing private filesystem paths.\n");
        return true;
    }
    (void)params;
    return market_content_index_json(result);
}

static bool rpc_zmarket_content_register(const struct json_value *params,
                                         bool help,
                                         struct json_value *result)
{
    if (help || !params || json_size(params) < 2) {
        json_set_str(result,
            "zmarket_content_register \"offer_id\" \"content_path\"\n"
            "\nBind exact local bytes to an authenticated paid offer. "
            "The private path is never returned.\n");
        return true;
    }
    const char *offer_hex = json_get_str(json_at(params, 0));
    const char *content_path = json_get_str(json_at(params, 1));
    uint8_t offer_id[32];
    if (!offer_hex || strlen(offer_hex) != 64 || !IsHex(offer_hex) ||
        ParseHex(offer_hex, offer_id, sizeof(offer_id)) != 32 ||
        !content_path || !content_path[0]) {
        json_set_str(result,
                     "offer_id must be 64 hex characters and content_path is required");
        return false;
    }
    if (!g_market_ndb || !g_market_ndb->open) {
        json_set_str(result, "market database is unavailable");
        return false;
    }

    struct market_content_public_record registered;
    struct zcl_result saved = file_market_content_register(
        g_market_ndb, offer_id, content_path,
        (int64_t)platform_time_wall_time_t(), &registered);
    if (!saved.ok) {
        json_set_str(result, saved.message);
        return false;
    }

    char saved_offer_hex[65], root_hex[65];
    HexStr(registered.offer_id, 32, false,
           saved_offer_hex, sizeof(saved_offer_hex));
    HexStr(registered.root_hash, 32, false,
           root_hex, sizeof(root_hex));
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.market_content.v1");
    json_push_kv_str(result, "status", "registered");
    json_push_kv_str(result, "offer_id", saved_offer_hex);
    json_push_kv_str(result, "root_hash", root_hex);
    json_push_kv_int(result, "size_bytes", (int64_t)registered.size_bytes);
    json_push_kv_int(result, "num_chunks", registered.num_chunks);
    json_push_kv_int(result, "registered_at", registered.registered_at);
    return true;
}

/* ── romseed_register ───────────────────────────────────────────────
 *
 * Explicitly (re)register a ROM/sync artifact by basename inside the datadir.
 * Registration re-computes every digest from the bytes on disk (never a
 * sidecar); a corrupt / mis-named / out-of-band file is refused. */
static bool rpc_romseed_register(const struct json_value *params, bool help,
                                 struct json_value *result)
{
    if (help || !params || json_size(params) < 1) {
        json_set_str(result,
            "romseed_register \"filename\"\n"
            "\n(Re)register a ROM/sync artifact for free P2P seeding.\n"
            "\nArguments:\n"
            "1. filename (string, required) Basename inside the datadir, e.g.\n"
            "             consensus-state-bundle-<height>.sqlite\n"
            "\nRegistration re-derives whole-file + per-chunk digests from disk\n"
            "and refuses a corrupt / mis-named file. Result: the artifact.\n");
        return true;
    }

    const struct json_value *arg0 = json_at(params, 0);
    const char *filename = arg0 ? json_get_str(arg0) : NULL;
    if (!filename || !filename[0]) {
        json_set_str(result, "Missing filename");
        return false;
    }

    char datadir[1024];
    GetDataDir(true, datadir, sizeof(datadir));

    struct rom_artifact art;
    enum rom_register_result rr =
        rom_seed_register(datadir, filename, NULL, &art);

    json_set_object(result);
    json_push_kv_str(result, "filename", filename);
    json_push_kv_int(result, "result_code", (int)rr);
    if (rr == ROM_REG_OK) {
        char hex[65];
        HexStr(art.chunk_root, 32, false, hex, sizeof(hex));
        json_push_kv_str(result, "status", "registered");
        json_push_kv_str(result, "digest", hex);
        json_push_kv_int(result, "size_bytes", (int64_t)art.size_bytes);
        json_push_kv_int(result, "chunk_size", (int64_t)art.chunk_size);
        json_push_kv_int(result, "chunks", (int64_t)art.num_chunks);

        /* Announce it as a price-0 offer so peers can discover + fetch it. */
        struct file_offer offer;
        uint8_t zero_ip[16] = {0};
        if (rom_seed_build_offer(&art, zero_ip, 0, &offer))
            file_market_add_offer(&offer);
    } else {
        json_push_kv_str(result, "status", "refused");
    }
    return true;
}

/* ── romseed_list ───────────────────────────────────────────────────── */

static bool rpc_romseed_list(const struct json_value *params, bool help,
                             struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "romseed_list\n"
            "\nList ROM/sync artifacts registered for free P2P seeding.\n"
            "\nResult: array of {kind, filename, digest, size_bytes, chunks}.\n");
        return true;
    }
    (void)params;

    json_set_array(result);
    struct rom_artifact arts[ROM_SEED_MAX_ARTIFACTS];
    int n = rom_seed_list(arts, ROM_SEED_MAX_ARTIFACTS);
    for (int i = 0; i < n; i++) {
        struct json_value entry = {0};
        json_set_object(&entry);
        char hex[65];
        HexStr(arts[i].chunk_root, 32, false, hex, sizeof(hex));
        json_push_kv_str(&entry, "kind",
            arts[i].kind == ROM_ARTIFACT_CONSENSUS_BUNDLE ? "consensus_bundle" :
            arts[i].kind == ROM_ARTIFACT_HEADER_SEED ? "header_seed" : "unknown");
        json_push_kv_str(&entry, "filename", arts[i].filename);
        json_push_kv_str(&entry, "digest", hex);
        json_push_kv_int(&entry, "size_bytes", (int64_t)arts[i].size_bytes);
        json_push_kv_int(&entry, "chunk_size", (int64_t)arts[i].chunk_size);
        json_push_kv_int(&entry, "chunks", (int64_t)arts[i].num_chunks);
        json_push_kv_bool(&entry, "free", true);
        json_push_back(result, &entry);
        json_free(&entry);
    }
    return true;
}

/* ── REST API ───────────────────────────────────────────────────── */

bool api_market_list_profile(const char *profile_override,
                             struct json_value *result)
{
    return market_list_json(profile_override, result);
}

bool api_market_list(struct json_value *result)
{
    return market_list_json(NULL, result);
}

bool api_market_content_list(struct json_value *result)
{
    return market_content_index_json(result);
}

/* ── Per-node listing moderation (view filter only) ─────────────── */

static bool rpc_zmarket_moderation_status(const struct json_value *params,
                                          bool help,
                                          struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "zmarket_moderation_status\n"
            "\nThe node's own marketplace listing-visibility posture: active\n"
            "profile, available immutable profiles, and local review_state\n"
            "counts. Moderation filters listing views only; it never deletes\n"
            "or bans — hidden offers stay stored, served, and tradable.\n");
        return true;
    }
    (void)params;

    enum market_moderation_profile active =
        market_moderation_active_profile();
    json_set_object(result);
    json_push_kv_str(result, "active_profile",
                     market_moderation_profile_string(active));
    struct json_value profiles;
    json_init(&profiles);
    json_set_array(&profiles);
    for (int i = 0; i < MARKET_MODERATION_PROFILE_COUNT; i++) {
        struct json_value p;
        json_init(&p);
        json_set_str(&p, market_moderation_profile_string(
                             (enum market_moderation_profile)i));
        json_push_back(&profiles, &p);
        json_free(&p);
    }
    json_push_kv(result, "available_profiles", &profiles);
    json_free(&profiles);

    int64_t counts[MARKET_REVIEW_STATE_COUNT] = {0, 0, 0};
    struct zcl_result counted = market_moderation_review_counts(counts);
    struct json_value by_state;
    json_init(&by_state);
    json_set_object(&by_state);
    for (int i = 0; i < MARKET_REVIEW_STATE_COUNT; i++)
        json_push_kv_int(&by_state,
                         market_review_state_string(
                             (enum market_review_state)i),
                         counted.ok ? counts[i] : 0);
    json_push_kv(result, "review_counts", &by_state);
    json_free(&by_state);
    json_push_kv_bool(result, "review_counts_live", counted.ok);
    json_push_kv_int(result, "offers_cached", file_market_count());
    json_push_kv_str(result, "policy_file", MARKET_MODERATION_POLICY_FILE);
    json_push_kv_bool(result, "view_filter_only", true);
    return true;
}

static bool rpc_zmarket_moderation_profile_show(
    const struct json_value *params, bool help, struct json_value *result)
{
    if (help || !params || json_size(params) < 1) {
        json_set_str(result,
            "zmarket_moderation_profile_show \"profile\"\n"
            "\nDescribe one immutable named listing-visibility profile:\n"
            "what it shows, what it hides, and whether it is active here.\n"
            "\nArguments:\n"
            "1. profile   (string, required) \"general-audience.v1\" or "
            "\"open-view\"\n");
        return true;
    }
    const struct json_value *arg0 = json_at(params, 0);
    const char *name =
        arg0 && arg0->type == JSON_STR ? json_get_str(arg0) : NULL;
    int profile = market_moderation_profile_from_string(name);
    if (profile < 0) {
        json_set_str(result,
            "unknown market moderation profile — available: "
            "general-audience.v1, open-view");
        return false;
    }
    struct zcl_hotswap_service_lease lease = {0};
    const struct market_moderation_view_service_v1 *service = zcl_hotswap_service_acquire(MARKET_MODERATION_VIEW_SERVICE_ID, &lease);
    if (!service) service = market_moderation_view_service_builtin();
    struct market_moderation_profile_result_v1 rendered;
    if (!service->render_profile(profile, &rendered) || !rendered.valid) {
        zcl_hotswap_service_release(&lease);
        json_set_str(result, "market moderation profile rendering failed");
        return false;
    }
    json_set_object(result);
    json_push_kv_str(result, "profile", rendered.profile);
    json_push_kv_bool(result, "immutable", true);
    json_push_kv_bool(result, "active", (int)market_moderation_active_profile() == profile);
    json_push_kv_str(result, "shows", rendered.shows);
    json_push_kv_str(result, "hides", rendered.hides);
    json_push_kv_str(result, "policy_file", MARKET_MODERATION_POLICY_FILE);
    zcl_hotswap_service_release(&lease);
    return true;
}

static void market_profile_plan_token(const char *active_name,
                                      const char *target_name,
                                      uint8_t out[32])
{
    struct sha3_256_ctx sha;
    static const char domain[] = "zcl.market.moderation.plan.v1";
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, (const uint8_t *)active_name,
                   strlen(active_name) + 1u);
    sha3_256_write(&sha, (const uint8_t *)target_name,
                   strlen(target_name) + 1u);
    sha3_256_finalize(&sha, out);
}

static bool rpc_zmarket_moderation_profile_set(
    const struct json_value *params, bool help, struct json_value *result)
{
    if (help || !params || json_size(params) < 2) {
        json_set_str(result,
            "zmarket_moderation_profile_set \"profile\" \"mode\" "
            "[\"plan_token\"]\n"
            "\nSet the node's own listing-visibility profile, persisted to\n"
            "<datadir>/market/moderation.v1. Exact two-step: mode \"plan\"\n"
            "mints a plan_token bound to the current active profile and the\n"
            "target; mode \"commit\" requires that token (STALE_PLAN if the\n"
            "active profile moved in between). Local view filtering only.\n"
            "\nArguments:\n"
            "1. profile   (string, required) \"general-audience.v1\" or "
            "\"open-view\"\n"
            "2. mode      (string, required) \"plan\" or \"commit\"\n"
            "3. plan_token (string, required for commit) 64-hex plan token\n");
        return true;
    }
    const struct json_value *arg0 = json_at(params, 0);
    const struct json_value *arg1 = json_at(params, 1);
    const char *name =
        arg0 && arg0->type == JSON_STR ? json_get_str(arg0) : NULL;
    const char *mode =
        arg1 && arg1->type == JSON_STR ? json_get_str(arg1) : NULL;
    int profile = market_moderation_profile_from_string(name);
    if (profile < 0) {
        json_set_str(result,
            "unknown market moderation profile — available: "
            "general-audience.v1, open-view");
        return false;
    }
    if (!mode || (strcmp(mode, "plan") != 0 && strcmp(mode, "commit") != 0)) {
        json_set_str(result, "mode must be \"plan\" or \"commit\"");
        return false;
    }

    const char *active_name = market_moderation_profile_string(
        market_moderation_active_profile());
    uint8_t token[32];
    market_profile_plan_token(active_name, name, token);

    bool committed = false;
    if (strcmp(mode, "commit") == 0) {
        const struct json_value *arg2 = json_at(params, 2);
        const char *hex =
            arg2 && arg2->type == JSON_STR ? json_get_str(arg2) : NULL;
        uint8_t supplied[32], difference = 0;
        if (!hex || strlen(hex) != 64 ||
            !zcl_hex_decode_lower(hex, supplied, 32)) {
            json_set_str(result,
                "INVALID_PLAN_TOKEN: commit requires the canonical 64-hex "
                "plan_token minted by mode \"plan\"");
            return false;
        }
        for (size_t i = 0; i < 32; i++)
            difference |= supplied[i] ^ token[i];
        if (difference) {
            json_set_str(result,
                "STALE_PLAN: the active moderation profile moved after the "
                "plan was minted — re-plan and commit again");
            return false;
        }
        struct zcl_result set = market_moderation_set_active_profile(
            (enum market_moderation_profile)profile);
        if (!set.ok) {
            char message[300];
            snprintf(message, sizeof(message), "POLICY_REFUSED: %s",
                     set.message[0] ? set.message : "profile save failed");
            json_set_str(result, message);
            return false;
        }
        committed = true;
    }

    char token_hex[65];
    zcl_hex_encode(token, 32, token_hex);
    json_set_object(result);
    json_push_kv_str(result, "mode", mode);
    json_push_kv_bool(result, "committed", committed);
    json_push_kv_str(result, "plan_token", token_hex);
    json_push_kv_str(result, "profile", name);
    json_push_kv_str(result, "previous_profile", active_name);
    json_push_kv_str(result, "policy_file", MARKET_MODERATION_POLICY_FILE);
    return true;
}

static bool rpc_zmarket_review_set(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    if (help || !params || json_size(params) < 2) {
        json_set_str(result,
            "zmarket_review_set \"offer_id\" \"review_state\"\n"
            "\nThe node's OWN curation mark on one signed offer: sets the\n"
            "local-only review_state (unreviewed / reviewed_ok / sensitive).\n"
            "Never gossiped, never in the signed wire, never a deletion —\n"
            "the offer stays stored, served, and tradable; only the local\n"
            "listing view changes. One audit log line is written per mark.\n"
            "\nArguments:\n"
            "1. offer_id     (string, required) 64-hex signed offer id\n"
            "2. review_state (string, required) unreviewed | reviewed_ok | "
            "sensitive\n");
        return true;
    }
    if (!g_market_ndb || !g_market_ndb->open) {
        json_set_str(result,
            "NODE_UNAVAILABLE: the market store is not open on this node");
        return false;
    }
    const struct json_value *arg0 = json_at(params, 0);
    const struct json_value *arg1 = json_at(params, 1);
    const char *id_hex =
        arg0 && arg0->type == JSON_STR ? json_get_str(arg0) : NULL;
    const char *state_text =
        arg1 && arg1->type == JSON_STR ? json_get_str(arg1) : NULL;
    uint8_t offer_id[32];
    if (!id_hex || strlen(id_hex) != 64 ||
        !zcl_hex_decode_lower(id_hex, offer_id, 32)) {
        json_set_str(result,
            "INVALID_OFFER_ID: offer_id must be the 64-hex signed offer id");
        return false;
    }
    int state = market_review_state_from_string(state_text);
    if (state < 0) {
        json_set_str(result,
            "INVALID_REVIEW_STATE: use unreviewed, reviewed_ok, or "
            "sensitive");
        return false;
    }

    struct file_offer offer;
    if (!db_file_offer_find_by_id(g_market_ndb, offer_id, &offer)) {
        json_set_str(result,
            "OFFER_NOT_FOUND: no signed offer with that offer_id is stored "
            "on this node");
        return false;
    }
    char previous[16] = {0};
    const char *previous_state =
        db_file_offer_get_review_state(g_market_ndb, offer.root_hash,
                                       previous, sizeof(previous))
            ? previous : "unreviewed";
    struct zcl_result marked = market_moderation_set_review_state(
        offer_id, (enum market_review_state)state);
    if (!marked.ok) {
        char message[300];
        snprintf(message, sizeof(message), "REVIEW_REFUSED: %s",
                 marked.message[0] ? marked.message
                                   : "the mark could not persist");
        json_set_str(result, message);
        return false;
    }
    /* Local curation audit trail: one line per mark, node.log only. */
    LOG_INFO("market",
             "moderation review set: offer_id=%s review_state=%s previous=%s",
             id_hex, market_review_state_string(
                         (enum market_review_state)state),
             previous_state);

    json_set_object(result);
    json_push_kv_str(result, "status", "marked");
    json_push_kv_str(result, "offer_id", id_hex);
    json_push_kv_str(result, "review_state",
                     market_review_state_string(
                         (enum market_review_state)state));
    json_push_kv_str(result, "previous_review_state", previous_state);
    json_push_kv_bool(result, "local_only", true);
    json_push_kv_bool(result, "gossiped", false);
    return true;
}

/* ── Registration ───────────────────────────────────────────────── */

void register_market_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "market", "zmarket_list",   rpc_zmarket_list,   true },
        { "market", "zmarket_offer",  rpc_zmarket_offer,  true },
        { "market", "zmarket_buy",    rpc_zmarket_buy,    true },
        { "market", "zmarket_status", rpc_zmarket_status, true },
        { "market", "zmarket_content_list",
          rpc_zmarket_content_list, true },
        { "market", "zmarket_content_register",
          rpc_zmarket_content_register, true },
        { "market", "zmarket_purchase_plan",
          rpc_zmarket_purchase_plan, false },
        { "market", "zmarket_purchase_commit",
          rpc_zmarket_purchase_commit, false },
        { "market", "zmarket_purchase_status",
          rpc_zmarket_purchase_status, true },
        { "market", "zmarket_purchase_retrieve",
          rpc_zmarket_purchase_retrieve, false },
        { "market", "romseed_register", rpc_romseed_register, true },
        { "market", "romseed_list",     rpc_romseed_list,     true },
        { "market", "zmarket_moderation_status",
          rpc_zmarket_moderation_status, true },
        { "market", "zmarket_moderation_profile_show",
          rpc_zmarket_moderation_profile_show, true },
        { "market", "zmarket_moderation_profile_set",
          rpc_zmarket_moderation_profile_set, false },
        { "market", "zmarket_review_set", rpc_zmarket_review_set, false },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
    register_market_offer_rpc_commands(t);
}
