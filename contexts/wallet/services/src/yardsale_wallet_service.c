/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the yardsale wallet glue — shared helpers plus the seller side
 * (arm / disarm / status). The buy half lives in
 * yardsale_wallet_service_buy.c (E1 file-size split, the
 * wallet_controller_*.c idiom). See services/yardsale_wallet_service.h
 * for the contract. Key hygiene lives here: wallet keys are fetched at
 * commit time only, used in stack copies cleansed with memory_cleanse,
 * and never reach the plan row, the DB, or the logs. */

#include "services/yardsale_wallet_service.h"
#include "services/yardsale_wallet_internal.h"

#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "keys/pubkey.h"
#include "script/script.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "zslp/slp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define YW_TAG "yardsale_wallet"

/* ── ceremony port (wired by the RPC controller / tests) ───────────── */

static struct yardsale_wallet_ceremony_port g_yw_port;
static bool g_yw_port_set;

void yardsale_wallet_set_ceremony_port(
    const struct yardsale_wallet_ceremony_port *port)
{
    if (port) {
        g_yw_port = *port;
        g_yw_port_set = true;
    } else {
        memset(&g_yw_port, 0, sizeof(g_yw_port));
        g_yw_port_set = false;
    }
}

const struct yardsale_wallet_ceremony_port *yw_ceremony_port(void)
{
    return g_yw_port_set ? &g_yw_port : NULL;
}

/* ── status names ────────────────────────────────────────────────── */

const char *yardsale_wallet_status_code(int status)
{
    switch ((enum yardsale_wallet_status)status) {
    case YARDSALE_WALLET_OK: return "OK";
    case YARDSALE_WALLET_ERR_ARGS: return "INVALID_ARGUMENTS";
    case YARDSALE_WALLET_ERR_DB: return "DATABASE_UNAVAILABLE";
    case YARDSALE_WALLET_ERR_AD_UNKNOWN: return "AD_UNKNOWN";
    case YARDSALE_WALLET_ERR_INPUT_NOT_OWNED: return "INPUT_NOT_OWNED";
    case YARDSALE_WALLET_ERR_TOKEN_MISMATCH: return "TOKEN_MISMATCH";
    case YARDSALE_WALLET_ERR_SCRIPT_TYPE: return "SCRIPT_TYPE_NOT_P2PKH";
    case YARDSALE_WALLET_ERR_KEY_MISSING: return "KEY_MISSING";
    case YARDSALE_WALLET_ERR_ADDRESS: return "ADDRESS_DERIVATION_FAILED";
    case YARDSALE_WALLET_ERR_FEE: return "FEE_INVALID";
    case YARDSALE_WALLET_ERR_INSUFFICIENT: return "INSUFFICIENT_CONFIRMED_FUNDS";
    case YARDSALE_WALLET_ERR_INPUT_CONFLICT: return "INPUT_CONFLICT";
    case YARDSALE_WALLET_ERR_PLAN_NOT_FOUND: return "PLAN_NOT_FOUND";
    case YARDSALE_WALLET_ERR_PLAN_EXPIRED: return "PLAN_EXPIRED";
    case YARDSALE_WALLET_ERR_PLAN_CONFLICT: return "PLAN_CONFLICT";
    case YARDSALE_WALLET_ERR_CEREMONY: return "CEREMONY_REFUSED";
    case YARDSALE_WALLET_ERR_INTERNAL: return "INTERNAL";
    }
    return "UNKNOWN";
}

enum yardsale_wallet_status yw_fail(struct json_value *out,
                                    enum yardsale_wallet_status status,
                                    const char *message)
{
    const char *code = yardsale_wallet_status_code(status);
    LOG_ERROR(YW_TAG, "%s: %s", code, message ? message : "");
    if (out) {
        json_set_object(out);
        json_push_kv_bool(out, "ok", false);
        json_push_kv_str(out, "code", code);
        json_push_kv_str(out, "message", message ? message : code);
    }
    return status;
}

/* ── request / plan identity ─────────────────────────────────────── */

static void yw_request_hash(const char *kind, const uint8_t *a,
                            size_t a_len, const uint8_t *b, size_t b_len,
                            uint8_t out[32])
{
    static const char domain[] = "zcl.yardsale.request.v1";
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const uint8_t *)domain, sizeof(domain) - 1);
    sha3_256_write(&ctx, (const uint8_t *)kind, strlen(kind));
    sha3_256_write(&ctx, a, a_len);
    if (b && b_len)
        sha3_256_write(&ctx, b, b_len);
    sha3_256_finalize(&ctx, out);
}

void yw_plan_identity(struct yw_plan *p, const char *kind,
                      const uint8_t *a, size_t a_len,
                      const uint8_t *b, size_t b_len)
{
    static const char plan_domain[] = "zcl.yardsale.plan.v1";
    uint8_t request[32];
    struct sha3_256_ctx ctx;
    yw_request_hash(kind, a, a_len, b, b_len, request);
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const uint8_t *)plan_domain,
                   sizeof(plan_domain) - 1);
    sha3_256_write(&ctx, request, 32);
    uint8_t root[32];
    sha3_256_finalize(&ctx, root);
    zcl_hex_encode(request, 32, p->request_hex);
    zcl_hex_encode(root, 32, p->plan_root_hex);
}

void yw_terms_digest(const uint8_t *bytes, size_t len, char out[65])
{
    static const char domain[] = "zcl.yardsale.terms.v1";
    uint8_t root[32];
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const uint8_t *)domain, sizeof(domain) - 1);
    sha3_256_write(&ctx, bytes, len);
    sha3_256_finalize(&ctx, root);
    zcl_hex_encode(root, 32, out);
}

/* ── canonical payload parse (the zswap_assembly.c layout, LE ints) ── */

struct yw_reader {
    const uint8_t *p;
    size_t len;
    size_t off;
};

static bool yw_rd(struct yw_reader *r, void *dst, size_t n)
{
    if (r->off + n > r->len)
        return false;
    memcpy(dst, r->p + r->off, n);
    r->off += n;
    return true;
}

static struct zcl_result yw_rd_input(struct yw_reader *r,
                                     struct zswap_swap_input *in)
{
    memset(in, 0, sizeof(*in));
    uint8_t script_len = 0;
    uint64_t value = 0;
    uint8_t le[8];
    if (!yw_rd(r, in->txid, 32) || !yw_rd(r, le, 4))
        return ZCL_ERR(-1, "truncated swap input");
    in->vout = zcl_read_u32_le(le);
    if (!yw_rd(r, le, 8))
        return ZCL_ERR(-1, "truncated swap input value");
    value = zcl_read_u64_le(le);
    if (value > INT64_MAX)
        return ZCL_ERR(-2, "swap input value overflows the money range");
    in->value_sats = (int64_t)value;
    if (!yw_rd(r, &script_len, 1) || script_len == 0 ||
        script_len > ZSWAP_MAX_INPUT_SCRIPT_BYTES)
        return ZCL_ERR(-3, "bad swap input script length");
    in->script_len = script_len;
    if (!yw_rd(r, in->script_pub_key, script_len))
        return ZCL_ERR(-1, "truncated swap input script");
    return ZCL_OK;
}

struct zcl_result yw_parse_seller_payload(const uint8_t *raw, size_t len,
                                          uint8_t ad_root[32],
                                          struct zswap_seller_accept *out)
{
    struct yw_reader r = { raw, len, 0 };
    memset(out, 0, sizeof(*out));
    uint8_t le[8];
    if (!yw_rd(&r, ad_root, 32))
        return ZCL_ERR(-1, "truncated payload ad root");
    struct zcl_result ri = yw_rd_input(&r, &out->token_input);
    if (!ri.ok)
        return ri;
    if (!yw_rd(&r, out->zcl_recv_address, ZSWAP_ADDRESS_FIELD_BYTES) ||
        !yw_rd(&r, out->change_address, ZSWAP_ADDRESS_FIELD_BYTES) ||
        !yw_rd(&r, le, 8))
        return ZCL_ERR(-1, "truncated seller payload");
    uint64_t deadline = zcl_read_u64_le(le);
    if (deadline > INT64_MAX)
        return ZCL_ERR(-2, "seller deadline overflows the time range");
    out->deadline_unix = (int64_t)deadline;
    if (r.off != r.len)
        return ZCL_ERR(-4, "trailing bytes after the seller payload");
    if (zswap_seller_accept_validate(out) != ZSWAP_ASSEMBLY_OK)
        return ZCL_ERR(-5, "seller payload failed validation");
    return ZCL_OK;
}

static bool yw_outpoint_lt(const struct zswap_swap_input *a,
                           const struct zswap_swap_input *b)
{
    int c = memcmp(a->txid, b->txid, 32);
    if (c != 0)
        return c < 0;
    return a->vout < b->vout;
}

struct zcl_result yw_parse_buyer_payload(const uint8_t *raw, size_t len,
                                         uint8_t ad_root[32],
                                         struct zswap_buyer_accept *out)
{
    struct yw_reader r = { raw, len, 0 };
    memset(out, 0, sizeof(*out));
    uint8_t n = 0;
    uint8_t le[8];
    if (!yw_rd(&r, ad_root, 32) || !yw_rd(&r, &n, 1) || n == 0 ||
        n > ZSWAP_MAX_BUYER_INPUTS)
        return ZCL_ERR(-1, "truncated buyer payload or bad input count");
    out->num_inputs = n;
    for (size_t i = 0; i < n; i++) {
        struct zcl_result ri = yw_rd_input(&r, &out->inputs[i]);
        if (!ri.ok)
            return ri;
        if (i > 0 && !yw_outpoint_lt(&out->inputs[i - 1], &out->inputs[i]))
            return ZCL_ERR(-3, "buyer inputs out of canonical order or "
                               "a duplicate outpoint");
    }
    uint64_t deadline = 0;
    if (!yw_rd(&r, out->token_recv_address, ZSWAP_ADDRESS_FIELD_BYTES) ||
        !yw_rd(&r, out->change_address, ZSWAP_ADDRESS_FIELD_BYTES) ||
        !yw_rd(&r, le, 8))
        return ZCL_ERR(-1, "truncated buyer payload");
    out->fee_sats = zcl_read_u64_le(le);
    if (!yw_rd(&r, le, 8))
        return ZCL_ERR(-1, "truncated buyer deadline");
    deadline = zcl_read_u64_le(le);
    if (deadline > INT64_MAX)
        return ZCL_ERR(-2, "buyer deadline overflows the time range");
    out->deadline_unix = (int64_t)deadline;
    if (r.off != r.len)
        return ZCL_ERR(-4, "trailing bytes after the buyer payload");
    if (zswap_buyer_accept_validate(out) != ZSWAP_ASSEMBLY_OK)
        return ZCL_ERR(-5, "buyer payload failed validation");
    return ZCL_OK;
}

struct zcl_result yw_payload_decode(const char *hex, uint8_t *raw,
                                    size_t raw_cap, size_t *raw_len)
{
    size_t hex_len = hex ? strlen(hex) : 0;
    if (hex_len == 0 || (hex_len & 1u) != 0 || hex_len / 2 > raw_cap)
        return ZCL_ERR(-1, "bad payload hex length");
    if (!zcl_hex_decode_lower(hex, raw, hex_len / 2))
        return ZCL_ERR(-2, "payload is not lowercase hex");
    *raw_len = hex_len / 2;
    return ZCL_OK;
}

/* ── wallet helpers ──────────────────────────────────────────────── */

void yw_script_key_id(const uint8_t *script, struct key_id *out)
{
    memcpy(out->id.data, script + 3, 20);
}

struct zcl_result yw_find_coin(struct wallet *w, const uint8_t txid[32],
                               uint32_t vout, bool include_slp,
                               struct coin_entry *coin, bool *seen)
{
    struct coin_entry *coins = zcl_malloc(
        YW_COIN_CAP * sizeof(*coins), "yardsale_wallet_coins");
    if (!coins) {
        LOG_ERROR(YW_TAG, "coin inventory allocation failed");
        return ZCL_ERR(-10, "coin inventory allocation failed");
    }
    size_t n = 0;
    wallet_available_coins_ex(w, coins, &n, YW_COIN_CAP, true, false,
                              include_slp);
    bool found = false;
    *seen = false;
    for (size_t i = 0; i < n; i++) {
        if (memcmp(coins[i].wtx->tx.hash.data, txid, 32) != 0 ||
            coins[i].i != vout)
            continue;
        *seen = true;
        if (coins[i].spendable && coins[i].solvable) {
            *coin = coins[i];
            found = true;
        }
        break;
    }
    free(coins);
    return found ? ZCL_OK
                 : ZCL_ERR(-11, "outpoint is not a confirmed spendable "
                                "wallet coin");
}

int64_t yw_available_ordinary(struct wallet *w)
{
    struct coin_entry *coins = zcl_malloc(
        YW_COIN_CAP * sizeof(*coins), "yardsale_wallet_balance");
    if (!coins) {
        LOG_ERROR(YW_TAG, "balance inventory allocation failed");
        return 0;
    }
    size_t n = 0;
    wallet_available_coins(w, coins, &n, YW_COIN_CAP, true, false);
    int64_t total = 0;
    for (size_t i = 0; i < n; i++) {
        const struct tx_out *o = &coins[i].wtx->tx.vout[coins[i].i];
        if (o->value > 0 && total <= INT64_MAX - o->value)
            total += o->value;
    }
    free(coins);
    return total;
}

struct zcl_result yw_live_ad(const uint8_t ad_root[32], int64_t now_unix,
                             struct zswap_yardsale_ad *out)
{
    if (!zswap_yardsale_find(ad_root, out))
        return ZCL_ERR(-20, "no remembered sign with that root");
    if (zswap_quote_validate_at(&out->quote, now_unix) != ZSWAP_QUOTE_OK)
        return ZCL_ERR(-21, "the sign is outside its validity window");
    return ZCL_OK;
}

/* ── rendering ───────────────────────────────────────────────────── */

void yw_render_plan_head(struct json_value *out, const char *kind,
                         const char plan_root_hex[65],
                         const char request_hex[65], int64_t expires_unix)
{
    json_push_kv_bool(out, "ok", true);
    json_push_kv_str(out, "kind", kind);
    json_push_kv_str(out, "plan_root", plan_root_hex);
    json_push_kv_str(out, "request_hash", request_hex);
    json_push_kv_int(out, "plan_expires_unix", expires_unix);
}

void yw_render_seller_terms(struct json_value *out,
                            const struct zswap_seller_accept *terms,
                            const struct zswap_yardsale_ad *ad)
{
    char hex[65];
    struct json_value t;
    json_init(&t);
    json_set_object(&t);
    zcl_hex_encode(terms->token_input.txid, 32, hex);
    json_push_kv_str(&t, "token_txid", hex);
    json_push_kv_int(&t, "token_vout", terms->token_input.vout);
    json_push_kv_int(&t, "token_input_sats", terms->token_input.value_sats);
    if (ad) {
        zcl_hex_encode(ad->quote.token_id, 32, hex);
        json_push_kv_str(&t, "token_id", hex);
        json_push_kv_int(&t, "token_amount",
                         (int64_t)ad->quote.token_amount);
        json_push_kv_int(&t, "zcl_amount_sats",
                         (int64_t)ad->quote.zcl_amount);
    }
    json_push_kv_str(&t, "zcl_recv_address", terms->zcl_recv_address);
    json_push_kv_str(&t, "change_address", terms->change_address);
    json_push_kv_int(&t, "deadline_unix", terms->deadline_unix);
    json_push_kv(out, "terms", &t);
    json_free(&t);
}

void yw_render_buyer_terms(struct json_value *out,
                           const struct zswap_buyer_accept *buyer,
                           const struct zswap_yardsale_ad *ad)
{
    char hex[65];
    struct json_value t;
    json_init(&t);
    json_set_object(&t);
    if (ad) {
        zcl_hex_encode(ad->quote.token_id, 32, hex);
        json_push_kv_str(&t, "token_id", hex);
        json_push_kv_int(&t, "token_amount",
                         (int64_t)ad->quote.token_amount);
        json_push_kv_int(&t, "price_sats", (int64_t)ad->quote.zcl_amount);
    }
    json_push_kv_int(&t, "fee_sats", (int64_t)buyer->fee_sats);
    json_push_kv_str(&t, "token_recv_address", buyer->token_recv_address);
    json_push_kv_str(&t, "change_address", buyer->change_address);
    json_push_kv_int(&t, "deadline_unix", buyer->deadline_unix);
    struct json_value inputs;
    json_init(&inputs);
    json_set_array(&inputs);
    int64_t total = 0;
    for (size_t i = 0; i < buyer->num_inputs; i++) {
        struct json_value in;
        json_init(&in);
        json_set_object(&in);
        zcl_hex_encode(buyer->inputs[i].txid, 32, hex);
        json_push_kv_str(&in, "txid", hex);
        json_push_kv_int(&in, "vout", buyer->inputs[i].vout);
        json_push_kv_int(&in, "value_sats", buyer->inputs[i].value_sats);
        json_push_back(&inputs, &in);
        json_free(&in);
        total += buyer->inputs[i].value_sats;
    }
    json_push_kv(&t, "inputs", &inputs);
    json_free(&inputs);
    json_push_kv_int(&t, "input_total_sats", total);
    json_push_kv(out, "terms", &t);
    json_free(&t);
}

/* ── plan row plumbing ───────────────────────────────────────────── */

struct zcl_result yw_plan_store(struct yw_plan *p, struct node_db *ndb,
                                const char *kind, const char *payload_hex,
                                int64_t now_unix)
{
    memset(&p->row, 0, sizeof(p->row));
    snprintf(p->row.plan_root, sizeof(p->row.plan_root), "%s",
             p->plan_root_hex);
    snprintf(p->row.kind, sizeof(p->row.kind), "%s", kind);
    snprintf(p->row.request_hash, sizeof(p->row.request_hash), "%s",
             p->request_hex);
    snprintf(p->row.payload_hex, sizeof(p->row.payload_hex), "%s",
             payload_hex);
    p->row.result[0] = '\0';
    snprintf(p->row.state, sizeof(p->row.state), "%s",
             YARDSALE_PLAN_STATE_PLANNED);
    p->row.created_at = now_unix;
    p->row.expires_unix = now_unix + YARDSALE_WALLET_PLAN_TTL_SECS;
    if (!db_yardsale_plan_save(ndb, &p->row))
        return ZCL_ERR(-30, "the plan ledger refused the save");
    return ZCL_OK;
}

struct zcl_result yw_plan_mark(struct yw_plan *p, struct node_db *ndb,
                               const char *state, const char *result)
{
    snprintf(p->row.state, sizeof(p->row.state), "%s", state);
    snprintf(p->row.result, sizeof(p->row.result), "%s",
             result ? result : "");
    if (!db_yardsale_plan_save(ndb, &p->row))
        return ZCL_ERR(-31, "the plan ledger refused the state change");
    return ZCL_OK;
}

/* ── arm: build the exact seller terms from the wallet ───────────── */

static enum yardsale_wallet_status yw_build_seller_terms(
    struct wallet *w, const struct zswap_yardsale_ad *ad,
    const uint8_t token_txid[32], uint32_t token_vout,
    struct zswap_seller_accept *terms, struct json_value *out)
{
    struct coin_entry coin;
    bool seen = false;
    memset(&coin, 0, sizeof(coin));
    if (!yw_find_coin(w, token_txid, token_vout, true, &coin, &seen).ok) {
        return yw_fail(out, YARDSALE_WALLET_ERR_INPUT_NOT_OWNED,
            seen ? "the token outpoint is a wallet coin but is not "
                   "confirmed-spendable"
                 : "the token outpoint is not a confirmed wallet coin — "
                   "the seller profile was left unconfigured");
    }
    const struct tx_out *txout = &coin.wtx->tx.vout[token_vout];
    if (!script_is_p2pkh(&txout->script_pub_key)) {
        return yw_fail(out, YARDSALE_WALLET_ERR_SCRIPT_TYPE,
            "the token input's script is not P2PKH — the ceremony signs "
            "P2PKH inputs only");
    }
    struct slp_output_metadata meta;
    memset(&meta, 0, sizeof(meta));
    if (!slp_classify_tx_output(&coin.wtx->tx, token_vout, &meta) ||
        meta.role != SLP_OUTPUT_TOKEN ||
        memcmp(meta.token_id, ad->quote.token_id, 32) != 0 ||
        meta.amount != ad->quote.token_amount) {
        return yw_fail(out, YARDSALE_WALLET_ERR_TOKEN_MISMATCH,
            "the named coin does not hold exactly the sign's token_amount "
            "of the sign's token — arming with it would burn the "
            "remainder under the SLP overlay");
    }

    memset(terms, 0, sizeof(*terms));
    memcpy(terms->token_input.txid, token_txid, 32);
    terms->token_input.vout = token_vout;
    terms->token_input.value_sats = txout->value;
    terms->token_input.script_len = (uint16_t)txout->script_pub_key.size;
    memcpy(terms->token_input.script_pub_key, txout->script_pub_key.data,
           txout->script_pub_key.size);
    if (!wallet_get_new_address(w, terms->zcl_recv_address,
                                sizeof(terms->zcl_recv_address)) ||
        !wallet_get_new_change_address(w, terms->change_address,
                                       sizeof(terms->change_address))) {
        return yw_fail(out, YARDSALE_WALLET_ERR_ADDRESS,
            "the wallet could not derive the ZCL receive/change addresses");
    }
    terms->deadline_unix = ad->quote.expires_unix;
    if (zswap_seller_accept_validate(terms) != ZSWAP_ASSEMBLY_OK)
        return yw_fail(out, YARDSALE_WALLET_ERR_ARGS,
            "the assembled seller terms failed validation");
    return YARDSALE_WALLET_OK;
}

/* ── seller arm ──────────────────────────────────────────────────── */

enum yardsale_wallet_status yardsale_wallet_seller_arm(
    struct wallet *w, struct node_db *ndb,
    const uint8_t token_txid[32], uint32_t token_vout,
    const uint8_t ad_root[32], bool confirm, int64_t now_unix,
    struct json_value *out)
{
    if (!w || !token_txid || !ad_root || now_unix <= 0 || !out)
        return yw_fail(out, YARDSALE_WALLET_ERR_ARGS,
                       "wallet, token outpoint, sign root, and time are "
                       "required");
    if (!ndb || !ndb->open)
        return yw_fail(out, YARDSALE_WALLET_ERR_DB,
                       "node.db is unavailable — the plan ledger cannot "
                       "persist");

    struct yw_plan p;
    memset(&p, 0, sizeof(p));
    uint8_t fields[36];
    zcl_write_u32_le(fields + 32, token_vout);
    memcpy(fields, token_txid, 32);
    yw_plan_identity(&p, YARDSALE_PLAN_KIND_ARM, fields, sizeof(fields),
                     ad_root, 32);
    p.exists = db_yardsale_plan_find_by_request(ndb, p.request_hex, &p.row);

    /* Idempotent replay of a committed arm — never a second configure. */
    if (p.exists &&
        strcmp(p.row.state, YARDSALE_PLAN_STATE_COMMITTED) == 0) {
        uint8_t raw[YW_PAYLOAD_RAW_MAX];
        size_t raw_len = 0;
        uint8_t root[32];
        struct zswap_seller_accept terms;
        struct zswap_yardsale_ad ad;
        bool have_terms =
            yw_payload_decode(p.row.payload_hex, raw, sizeof(raw),
                              &raw_len).ok &&
            yw_parse_seller_payload(raw, raw_len, root, &terms).ok;
        json_set_object(out);
        yw_render_plan_head(out, YARDSALE_PLAN_KIND_ARM, p.plan_root_hex,
                            p.request_hex, p.row.expires_unix);
        json_push_kv_str(out, "stage", "committed");
        json_push_kv_bool(out, "committed", true);
        json_push_kv_bool(out, "idempotent_replay", true);
        json_push_kv_str(out, "result", p.row.result);
        if (have_terms)
            yw_render_seller_terms(out, &terms,
                                   yw_live_ad(root, now_unix, &ad).ok
                                       ? &ad : NULL);
        return YARDSALE_WALLET_OK;
    }

    if (confirm) {
        if (!p.exists)
            return yw_fail(out, YARDSALE_WALLET_ERR_PLAN_NOT_FOUND,
                           "no plan names this request — run without "
                           "confirm first and inspect the exact terms");
        if (now_unix >= p.row.expires_unix) {
            if (!yw_plan_mark(&p, ndb, YARDSALE_PLAN_STATE_EXPIRED,
                              NULL).ok)
                return yw_fail(out, YARDSALE_WALLET_ERR_DB,
                               "the plan ledger could not record the "
                               "expiry");
            return yw_fail(out, YARDSALE_WALLET_ERR_PLAN_EXPIRED,
                           "the plan lifetime elapsed — the seller "
                           "profile was NOT configured");
        }

        /* Commit from the STORED exact payload, never a re-plan. */
        uint8_t raw[YW_PAYLOAD_RAW_MAX];
        size_t raw_len = 0;
        uint8_t root[32];
        struct zswap_seller_accept terms;
        if (!yw_payload_decode(p.row.payload_hex, raw, sizeof(raw),
                               &raw_len).ok ||
            !yw_parse_seller_payload(raw, raw_len, root, &terms).ok)
            return yw_fail(out, YARDSALE_WALLET_ERR_INTERNAL,
                           "the stored plan payload failed to parse");

        struct zswap_yardsale_ad ad;
        if (!yw_live_ad(root, now_unix, &ad).ok)
            return yw_fail(out, YARDSALE_WALLET_ERR_AD_UNKNOWN,
                           "the sign expired or left this node's yardsale "
                           "— the ceremony is dead and the profile was "
                           "not configured");

        /* The coin must still be exactly what the plan proved. */
        struct coin_entry coin;
        bool seen = false;
        memset(&coin, 0, sizeof(coin));
        if (!yw_find_coin(w, terms.token_input.txid,
                          terms.token_input.vout, true, &coin, &seen).ok)
            return yw_fail(out, YARDSALE_WALLET_ERR_INPUT_CONFLICT,
                           "the planned token input is no longer a "
                           "confirmed spendable wallet coin");
        const struct tx_out *txout =
            &coin.wtx->tx.vout[terms.token_input.vout];
        if (txout->value != terms.token_input.value_sats ||
            txout->script_pub_key.size != terms.token_input.script_len ||
            memcmp(txout->script_pub_key.data,
                   terms.token_input.script_pub_key,
                   terms.token_input.script_len) != 0)
            return yw_fail(out, YARDSALE_WALLET_ERR_INPUT_CONFLICT,
                           "the planned token input changed since "
                           "planning");
        struct slp_output_metadata meta;
        memset(&meta, 0, sizeof(meta));
        if (!slp_classify_tx_output(&coin.wtx->tx, terms.token_input.vout,
                                    &meta) ||
            meta.role != SLP_OUTPUT_TOKEN ||
            memcmp(meta.token_id, ad.quote.token_id, 32) != 0 ||
            meta.amount != ad.quote.token_amount)
            return yw_fail(out, YARDSALE_WALLET_ERR_TOKEN_MISMATCH,
                           "the planned token input no longer holds the "
                           "sign's exact token amount");

        struct key_id kid;
        struct privkey key;
        memset(&key, 0, sizeof(key));
        yw_script_key_id(terms.token_input.script_pub_key, &kid);
        if (!wallet_dump_key(w, &kid, &key))
            return yw_fail(out, YARDSALE_WALLET_ERR_KEY_MISSING,
                           "the wallet holds no key for the planned token "
                           "input");
        const struct yardsale_wallet_ceremony_port *port =
            yw_ceremony_port();
        if (!port) {
            memory_cleanse(&key, sizeof(key));
            return yw_fail(out, YARDSALE_WALLET_ERR_INTERNAL,
                           "the ceremony port is unwired — the seller "
                           "profile was NOT configured");
        }
        port->seller_profile_configure(&terms, &key);
        memory_cleanse(&key, sizeof(key));

        if (!yw_plan_mark(&p, ndb, YARDSALE_PLAN_STATE_COMMITTED,
                          "armed").ok) {
            /* The profile is armed but the ledger did not record it —
             * fail loudly so the operator disarms or retries. */
            return yw_fail(out, YARDSALE_WALLET_ERR_DB,
                           "the profile is armed but the plan ledger "
                           "could not record the commit");
        }
        uint8_t ser[YW_PAYLOAD_RAW_MAX];
        size_t ser_len = 0;
        char digest[65] = { 0 };
        if (zswap_seller_accept_serialize(&terms, ser, sizeof(ser),
                                          &ser_len) == ZSWAP_ASSEMBLY_OK)
            yw_terms_digest(ser, ser_len, digest);
        json_set_object(out);
        yw_render_plan_head(out, YARDSALE_PLAN_KIND_ARM, p.plan_root_hex,
                            p.request_hex, p.row.expires_unix);
        json_push_kv_str(out, "stage", "committed");
        json_push_kv_bool(out, "committed", true);
        json_push_kv_bool(out, "idempotent_replay", false);
        json_push_kv_str(out, "result", "armed");
        json_push_kv_bool(out, "profile_configured", true);
        if (digest[0])
            json_push_kv_str(out, "terms_digest", digest);
        yw_render_seller_terms(out, &terms, &ad);
        return YARDSALE_WALLET_OK;
    }

    /* Plan stage: an unexpired PLANNED row is the same plan — return it
     * unchanged (no fresh addresses, no fresh selection). */
    if (p.exists &&
        strcmp(p.row.state, YARDSALE_PLAN_STATE_PLANNED) == 0 &&
        now_unix < p.row.expires_unix) {
        uint8_t raw[YW_PAYLOAD_RAW_MAX];
        size_t raw_len = 0;
        uint8_t root[32];
        struct zswap_seller_accept terms;
        if (!yw_payload_decode(p.row.payload_hex, raw, sizeof(raw),
                               &raw_len).ok ||
            !yw_parse_seller_payload(raw, raw_len, root, &terms).ok)
            return yw_fail(out, YARDSALE_WALLET_ERR_INTERNAL,
                           "the stored plan payload failed to parse");
        struct zswap_yardsale_ad ad;
        json_set_object(out);
        yw_render_plan_head(out, YARDSALE_PLAN_KIND_ARM, p.plan_root_hex,
                            p.request_hex, p.row.expires_unix);
        json_push_kv_str(out, "stage", "plan");
        json_push_kv_bool(out, "committed", false);
        yw_render_seller_terms(out, &terms,
                               yw_live_ad(root, now_unix, &ad).ok
                                   ? &ad : NULL);
        json_push_kv_str(out, "confirm_hint",
                         "re-run with \"confirm\":true before "
                         "plan_expires_unix to arm the seller profile");
        return YARDSALE_WALLET_OK;
    }

    /* Fresh plan (first request, or an expired row being re-planned). */
    struct zswap_yardsale_ad ad;
    if (!yw_live_ad(ad_root, now_unix, &ad).ok)
        return yw_fail(out, YARDSALE_WALLET_ERR_AD_UNKNOWN,
                       "no live sign with that root in this node's "
                       "yardsale");
    struct zswap_seller_accept terms;
    enum yardsale_wallet_status st =
        yw_build_seller_terms(w, &ad, token_txid, token_vout, &terms, out);
    if (st != YARDSALE_WALLET_OK)
        return st;

    uint8_t ser[YW_PAYLOAD_RAW_MAX];
    size_t ser_len = 0;
    if (zswap_seller_accept_serialize(&terms, ser, sizeof(ser),
                                      &ser_len) != ZSWAP_ASSEMBLY_OK)
        return yw_fail(out, YARDSALE_WALLET_ERR_INTERNAL,
                       "the seller terms failed canonical serialization");
    uint8_t raw[YW_PAYLOAD_RAW_MAX];
    if (32 + ser_len > sizeof(raw))
        return yw_fail(out, YARDSALE_WALLET_ERR_INTERNAL,
                       "the plan payload exceeds its bound");
    memcpy(raw, ad_root, 32);
    memcpy(raw + 32, ser, ser_len);
    char payload_hex[YARDSALE_PLAN_PAYLOAD_HEX_MAX];
    zcl_hex_encode(raw, 32 + ser_len, payload_hex);
    if (!yw_plan_store(&p, ndb, YARDSALE_PLAN_KIND_ARM, payload_hex,
                       now_unix).ok)
        return yw_fail(out, YARDSALE_WALLET_ERR_DB,
                       "the plan ledger could not persist the plan");

    json_set_object(out);
    yw_render_plan_head(out, YARDSALE_PLAN_KIND_ARM, p.plan_root_hex,
                        p.request_hex, p.row.expires_unix);
    json_push_kv_str(out, "stage", "plan");
    json_push_kv_bool(out, "committed", false);
    yw_render_seller_terms(out, &terms, &ad);
    json_push_kv_str(out, "confirm_hint",
                     "re-run with \"confirm\":true before "
                     "plan_expires_unix to arm the seller profile");
    return YARDSALE_WALLET_OK;
}

/* ── seller disarm / status ──────────────────────────────────────── */

enum yardsale_wallet_status yardsale_wallet_seller_disarm(
    struct json_value *out)
{
    if (!out)
        return yw_fail(out, YARDSALE_WALLET_ERR_ARGS,
                       "an output body is required");
    const struct yardsale_wallet_ceremony_port *port = yw_ceremony_port();
    bool was = port && port->seller_profile_configured();
    if (port)
        port->seller_profile_clear(); /* cleanses the retained key */
    json_set_object(out);
    json_push_kv_bool(out, "ok", true);
    json_push_kv_bool(out, "was_configured", was);
    json_push_kv_bool(out, "configured", false);
    json_push_kv_str(out, "result",
                     was ? "disarmed" : "already_disarmed");
    return YARDSALE_WALLET_OK;
}

enum yardsale_wallet_status yardsale_wallet_seller_status(
    int64_t now_unix, struct json_value *out)
{
    if (!out)
        return yw_fail(out, YARDSALE_WALLET_ERR_ARGS,
                       "an output body is required");
    struct zswap_seller_accept terms;
    const struct yardsale_wallet_ceremony_port *port = yw_ceremony_port();
    bool configured = port && port->seller_profile_snapshot(&terms);
    json_set_object(out);
    json_push_kv_bool(out, "ok", true);
    json_push_kv_bool(out, "configured", configured);
    json_push_kv_int(out, "pending_buys",
                     port ? port->pending_count(now_unix) : 0);
    if (configured) {
        uint8_t ser[512];
        size_t ser_len = 0;
        char digest[65] = { 0 };
        if (zswap_seller_accept_serialize(&terms, ser, sizeof(ser),
                                          &ser_len) == ZSWAP_ASSEMBLY_OK)
            yw_terms_digest(ser, ser_len, digest);
        if (digest[0])
            json_push_kv_str(out, "terms_digest", digest);
        int64_t remaining = terms.deadline_unix - now_unix;
        json_push_kv_int(out, "deadline_unix", terms.deadline_unix);
        json_push_kv_int(out, "deadline_remaining_secs",
                         remaining > 0 ? remaining : 0);
        yw_render_seller_terms(out, &terms, NULL);
    }
    /* The key is process memory and is never rendered. */
    return YARDSALE_WALLET_OK;
}
