/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the Yardsale web mount's plan-gated buy route.
 *
 * Split out of yardsale_site_controller.c for the E1 file-size ceiling.
 * A form POST without confirm=true resolves the exact accept terms and
 * stores them as a PLANNED db_yardsale_plan row; confirm=true arms money
 * only against a byte-identical, unexpired stored plan. WIFs live only in
 * the request body and are cleansed with it. Shared page plumbing comes
 * from controllers/yardsale_site_internal.h. */

#include "controllers/yardsale_site_internal.h"

#include "chain/chainparams.h"
#include "config/runtime.h"
#include "controllers/yardsale_controller.h"
#include "keys/key_io.h"
#include "models/database.h"
#include "models/yardsale_plan.h"
#include "models/zswap_ad.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "zswap/zswap_assembly.h"

#include <errno.h>
#include <stdlib.h>

/* Locate the three colons of "txid:vout:value:scripthex" and bound the
 * txid width and the vout and value field widths. */
static bool parse_input_bounds(const char *text, const char **c1,
                               const char **c2, const char **c3)
{
    /* The script is last (hex has no colons), the txid first. */
    const char *a = strchr(text, ':');
    const char *b = a ? strchr(a + 1, ':') : NULL;
    const char *c = b ? strchr(b + 1, ':') : NULL;
    if (!c || c == b + 1)
        return false; /* raw-return-ok:form-refusal-named-by-caller */
    if ((size_t)(a - text) != 64 ||
        (size_t)(b - a - 1) >= 16 || (size_t)(c - b - 1) >= 32)
        return false; /* raw-return-ok:form-refusal-named-by-caller */
    *c1 = a;
    *c2 = b;
    *c3 = c;
    return true;
}

/* Strict decimal parse of the vout and value fields and their ranges. */
static bool parse_input_numbers(const char *vout_s, const char *value_s,
                                unsigned long *vout,
                                unsigned long long *value)
{
    char *end = NULL;
    errno = 0;
    *vout = strtoul(vout_s, &end, 10);
    if (errno != 0 || !end || *end != '\0')
        return false; /* raw-return-ok:form-refusal-named-by-caller */
    errno = 0;
    *value = strtoull(value_s, &end, 10);
    if (errno != 0 || !end || *end != '\0')
        return false; /* raw-return-ok:form-refusal-named-by-caller */
    if (*vout > UINT32_MAX || *value == 0 || *value > INT64_MAX)
        return false; /* raw-return-ok:form-refusal-named-by-caller */
    return true;
}

/* Parse one "txid:vout:value:scripthex" form field. */
static bool parse_input_field(const char *text, struct zswap_swap_input *in)
{
    memset(in, 0, sizeof(*in));
    char txid_hex[65], script_hex[2 * ZSWAP_MAX_INPUT_SCRIPT_BYTES + 1];
    unsigned long vout;
    unsigned long long value;
    const char *c1 = NULL, *c2 = NULL, *c3 = NULL;
    if (!parse_input_bounds(text, &c1, &c2, &c3))
        return false; /* raw-return-ok:form-refusal-named-by-caller */
    memcpy(txid_hex, text, 64);
    txid_hex[64] = 0;
    char vout_s[16], value_s[32];
    memcpy(vout_s, c1 + 1, (size_t)(c2 - c1 - 1));
    vout_s[c2 - c1 - 1] = 0;
    memcpy(value_s, c2 + 1, (size_t)(c3 - c2 - 1));
    value_s[c3 - c2 - 1] = 0;
    size_t script_hex_len = strlen(c3 + 1);
    if (script_hex_len == 0 || script_hex_len % 2 != 0 ||
        script_hex_len > 2 * ZSWAP_MAX_INPUT_SCRIPT_BYTES)
        return false;
    memcpy(script_hex, c3 + 1, script_hex_len + 1);
    if (!parse_input_numbers(vout_s, value_s, &vout, &value))
        return false; /* raw-return-ok:form-refusal-named-by-caller */
    if (!zcl_hex_decode_lower(txid_hex, in->txid, 32))
        return false; /* raw-return-ok:form-refusal-named-by-caller */
    size_t script_len = script_hex_len / 2;
    if (!zcl_hex_decode_lower(script_hex, in->script_pub_key, script_len))
        return false; /* raw-return-ok:form-refusal-named-by-caller */
    in->vout = (uint32_t)vout;
    in->value_sats = (int64_t)value;
    in->script_len = (uint16_t)script_len;
    return true;
}

/* ── web-buy plan identity (mirrors yardsale_wallet_service.c under a
 * controller-distinct domain, so form plans can never collide with the
 * CLI wallet service's rows for the same sign) ───────────────────── */

static void webbuy_identity(const uint8_t ad_root[32],
                            const uint8_t *ser, size_t ser_len,
                            char request_hex[65], char plan_root_hex[65])
{
    static const char req_domain[] = "zcl.yardsale.webbuy.request.v1";
    static const char plan_domain[] = "zcl.yardsale.webbuy.plan.v1";
    uint8_t request[32], plan_root[32];
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const uint8_t *)req_domain,
                   sizeof(req_domain) - 1);
    sha3_256_write(&ctx, ad_root, 32);
    sha3_256_write(&ctx, ser, ser_len);
    sha3_256_finalize(&ctx, request);
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const uint8_t *)plan_domain,
                   sizeof(plan_domain) - 1);
    sha3_256_write(&ctx, request, 32);
    sha3_256_finalize(&ctx, plan_root);
    zcl_hex_encode(request, 32, request_hex);
    zcl_hex_encode(plan_root, 32, plan_root_hex);
}

/* payload = ad_root(32) || canonical serialized accept — the exact planned
 * terms, no key material — matching the wallet service's payload contract. */
static bool webbuy_payload(const uint8_t ad_root[32],
                           const uint8_t *ser, size_t ser_len,
                           char payload_hex[YARDSALE_PLAN_PAYLOAD_HEX_MAX])
{
    if (32 + ser_len > YARDSALE_PLAN_PAYLOAD_HEX_MAX / 2 - 1)
        return false;
    uint8_t raw[YARDSALE_PLAN_PAYLOAD_HEX_MAX / 2];
    memcpy(raw, ad_root, 32);
    memcpy(raw + 32, ser, ser_len);
    zcl_hex_encode(raw, 32 + ser_len, payload_hex);
    return true;
}

static void webbuy_plan_row(struct db_yardsale_plan *row,
                            const char request_hex[65],
                            const char plan_root_hex[65],
                            const char payload_hex[], int64_t expires_unix,
                            int64_t created_at)
{
    memset(row, 0, sizeof(*row));
    snprintf(row->plan_root, sizeof(row->plan_root), "%s", plan_root_hex);
    snprintf(row->kind, sizeof(row->kind), "%s", YARDSALE_PLAN_KIND_BUY);
    snprintf(row->request_hash, sizeof(row->request_hash), "%s",
             request_hex);
    snprintf(row->payload_hex, sizeof(row->payload_hex), "%s", payload_hex);
    snprintf(row->state, sizeof(row->state), "%s",
             YARDSALE_PLAN_STATE_PLANNED);
    row->expires_unix = expires_unix;
    row->created_at = created_at;
}

static size_t yardsale_render_buy_plan_page(
    const struct db_yardsale_plan *plan, const uint8_t root[32],
    const struct zswap_buyer_accept *buyer, bool committed,
    uint8_t *response, size_t response_max)
{
    uint64_t total_sats = 0;
    for (size_t i = 0; i < buyer->num_inputs; i++)
        total_sats += (uint64_t)buyer->inputs[i].value_sats;
    char root_short[24];
    hex_short(root, 32, 8, root_short, sizeof(root_short));
    char page[3072];
    int n = snprintf(page, sizeof(page),
        "<!doctype html><html><head><title>%s</title>"
        "<style>" YARDSALE_PAGE_STYLE "</style></head><body>"
        "<h1>%s</h1>"
        "<p>These exact terms are saved in this node's plan store "
        "(<code>%s</code>) until <code>%lld</code>:</p>"
        "<table>"
        "<tr><th>sign root</th><td>%s&hellip;</td></tr>"
        "<tr><th>token recipient</th><td>%s</td></tr>"
        "<tr><th>change address</th><td>%s</td></tr>"
        "<tr><th>ZCL inputs</th><td>%zu totalling %llu sats</td></tr>"
        "<tr><th>fee</th><td>%llu sats</td></tr>"
        "<tr><th>plan request hash</th><td>%s</td></tr>"
        "</table>"
        "%s"
        "<p><a href='/yardsale'>Back to the yard</a></p>"
        "</body></html>",
        committed ? "accept already out" : "accept planned",
        committed ? "Your accept is already pinned on the door"
                  : "Accept planned — nothing armed yet",
        plan->state,
        (long long)plan->expires_unix,
        root_short,
        buyer->token_recv_address, buyer->change_address,
        (size_t)buyer->num_inputs, (unsigned long long)total_sats,
        (unsigned long long)buyer->fee_sats, plan->request_hash,
        committed
            ? "<p>The <code>zswap_accept.v1</code> built from these "
              "terms already gossiped toward the seller; this node "
              "verifies and broadcasts when his partial returns. "
              "Re-submitting the same form changes nothing.</p>"
            : "<p><strong>No money moves yet.</strong> Re-submit this "
              "same form with one extra field <code>confirm=true</code> "
              "to arm your inputs and flood the accept toward the "
              "seller. Any changed term gets a different plan instead."
              "</p>");
    if (n < 0)
        return 0;
    if ((size_t)n >= sizeof(page))
        n = (int)sizeof(page) - 1;
    return yardsale_http_response("200 OK", "text/html; charset=utf-8",
                                  (const uint8_t *)page, (size_t)n,
                                  response, response_max);
}

/* One resolved web-buy request: the form fields, the terms they name and
 * the ledger state carried between the readers, steps and renderers. */
struct buy_post {
    char root_hex[80];
    char token_recv[ZSWAP_ADDRESS_FIELD_BYTES];
    char change[ZSWAP_ADDRESS_FIELD_BYTES];
    char fee_s[24];
    bool confirm;
    uint8_t root[32];
    uint64_t fee;
    struct zswap_buyer_accept buyer;
    struct privkey keys[ZSWAP_MAX_BUYER_INPUTS];
    struct node_db *ndb;
    struct zswap_yardsale_ad ad;
    struct db_yardsale_plan plan;
    bool have_plan;
    bool arm_now;
    bool already_begun;
    bool expire_save_failed;
    bool commit_save_failed;
    int64_t now;
    size_t ser_len;
    uint8_t ser[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    char request_hex[65];
    char plan_root_hex[65];
    char payload_hex[YARDSALE_PLAN_PAYLOAD_HEX_MAX];
    enum yardsale_error result;
    size_t wire_len;
    uint8_t wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
};

static const char buy_plan_expired_msg[] =
    "these planned terms expired — submit without confirm to plan again";

static const char *buy_read_required(const char *form, size_t body_len,
                                     struct buy_post *bp)
{
    if (!web_form_field(form, body_len, "root", bp->root_hex,
                        sizeof(bp->root_hex)) ||
        !web_form_field(form, body_len, "token_recv", bp->token_recv,
                        sizeof(bp->token_recv)) ||
        !web_form_field(form, body_len, "change", bp->change,
                        sizeof(bp->change)) ||
        !web_form_field(form, body_len, "fee", bp->fee_s,
                        sizeof(bp->fee_s)))
        return "root, token_recv, change, and fee are required";
    return NULL;
}

static const char *buy_read_confirm(const char *form, size_t body_len,
                                    struct buy_post *bp, const char *bad)
{
    /* Plan-first money on the form path too: without confirm=true this
     * only persists the exact planned terms; confirm=true arms money but
     * only against a stored PLANNED row whose terms match byte-for-byte. */
    char confirm_s[8];
    if (!bad && web_form_field(form, body_len, "confirm", confirm_s,
                                 sizeof(confirm_s))) {
        if (strcmp(confirm_s, "true") == 0 || strcmp(confirm_s, "1") == 0)
            bp->confirm = true;
        else
            bad = "confirm must be \"true\" to arm money";
    }
    return bad;
}

static const char *buy_decode_root(struct buy_post *bp, const char *bad)
{
    if (!bad && !zcl_hex_decode_lower(bp->root_hex, bp->root, 32))
        bad = "root must be 64 lowercase hex characters";
    return bad;
}

/* One in<i>/key<i> pair: an empty pair is skipped, a complete pair is
 * parsed and its WIF decoded into the next input slot. */
static const char *buy_read_input_slot(const char *form, size_t body_len,
                                       size_t i,
                                       const unsigned char *sec_pfx,
                                       size_t sec_pfx_len,
                                       struct buy_post *bp)
{
    char fname[8], kname[8], in_s[640] = {0}, wif_s[128] = {0};
    snprintf(fname, sizeof(fname), "in%zu", i);
    snprintf(kname, sizeof(kname), "key%zu", i);
    bool have_in = web_form_field(form, body_len, fname, in_s,
                                    sizeof(in_s)) && in_s[0];
    bool have_key = web_form_field(form, body_len, kname, wif_s,
                                     sizeof(wif_s)) && wif_s[0];
    if (!have_in && !have_key)
        return NULL;
    const char *bad = NULL;
    size_t n = bp->buyer.num_inputs;
    if (have_in != have_key)
        bad = "every input needs its WIF, and every WIF its input";
    else if (!parse_input_field(in_s, &bp->buyer.inputs[n]))
        bad = "an input is not txid:vout:value:scripthex";
    else if (!decode_secret(wif_s, sec_pfx, sec_pfx_len, &bp->keys[n]))
        bad = "a WIF did not decode";
    else
        bp->buyer.num_inputs++;
    memory_cleanse(wif_s, sizeof(wif_s));
    return bad;
}

static const char *buy_read_inputs(const char *form, size_t body_len,
                                   struct buy_post *bp, const char *bad)
{
    /* Up to four inputs via in1..in4 / key1..key4 (the web form's v1
     * convenience bound; the controller API takes the full 16). */
    const struct chain_params *cp = chain_params_get();
    size_t sec_pfx_len = 0;
    const unsigned char *sec_pfx =
        chain_params_base58_prefix(cp, B58_SECRET_KEY, &sec_pfx_len);
    for (size_t i = 1; i <= 4 && !bad; i++)
        bad = buy_read_input_slot(form, body_len, i, sec_pfx, sec_pfx_len,
                                  bp);
    return bad;
}

static const char *buy_read_fee(struct buy_post *bp, const char *bad)
{
    if (bad)
        return bad;
    if (bp->buyer.num_inputs == 0)
        bad = "at least one ZCL input is required";
    char *end = NULL;
    errno = 0;
    bp->fee = strtoull(bp->fee_s, &end, 10);
    if (errno != 0 || !end || *end != '\0' || bp->fee == 0)
        bad = "fee must be positive sats";
    return bad;
}

static const char *buy_check_store(struct buy_post *bp, const char *bad)
{
    /* The ledger gates every arm. A missing plan store refuses rather
     * than falling back to the old one-shot behavior. */
    bp->ndb = app_runtime_node_db();
    if (!bad && (!bp->ndb || !bp->ndb->open))
        bad = "the web-buy plan store is unavailable — nothing was "
              "planned or armed";
    return bad;
}

static const char *buy_read_request(const char *form, size_t body_len,
                                    struct buy_post *bp)
{
    const char *bad = buy_read_required(form, body_len, bp);
    bad = buy_read_confirm(form, body_len, bp, bad);
    bad = buy_decode_root(bp, bad);
    bad = buy_read_inputs(form, body_len, bp, bad);
    bad = buy_read_fee(bp, bad);
    return buy_check_store(bp, bad);
}

static void buy_apply_terms(struct buy_post *bp)
{
    snprintf(bp->buyer.token_recv_address,
             sizeof(bp->buyer.token_recv_address), "%s", bp->token_recv);
    snprintf(bp->buyer.change_address, sizeof(bp->buyer.change_address),
             "%s", bp->change);
    bp->buyer.fee_sats = bp->fee;
}

static const char *buy_plan_renew(struct buy_post *bp)
{
    webbuy_plan_row(&bp->plan, bp->request_hex, bp->plan_root_hex,
                    bp->payload_hex, bp->ad.quote.expires_unix, bp->now);
    if (!db_yardsale_plan_save(bp->ndb, &bp->plan))
        return "renewing the planned accept failed";
    return NULL;
}

static const char *buy_plan_expire(struct buy_post *bp)
{
    snprintf(bp->plan.state, sizeof(bp->plan.state), "%s",
             YARDSALE_PLAN_STATE_EXPIRED);
    if (!db_yardsale_plan_save(bp->ndb, &bp->plan))
        bp->expire_save_failed = true;
    return buy_plan_expired_msg;
}

static const char *buy_plan_claim(struct buy_post *bp)
{
    enum db_yardsale_plan_claim_result claim =
        db_yardsale_plan_claim(bp->ndb, &bp->plan, bp->now);
    if (claim == DB_YARDSALE_PLAN_CLAIMED) {
        bp->arm_now = true;
        return NULL;
    }
    if (claim == DB_YARDSALE_PLAN_CLAIM_REFUSED)
        return "these terms are already being armed or "
               "changed state — inspect before retrying";
    return "the plan ledger could not claim these "
           "terms — nothing was armed";
}

/* A stored row already names these exact terms: replay, renew, refuse,
 * expire or arm it according to its state and the confirm flag. */
static const char *buy_plan_existing(struct buy_post *bp)
{
    if (strcmp(bp->plan.state, YARDSALE_PLAN_STATE_COMMITTED) == 0) {
        bp->already_begun = true;
        return NULL;
    }
    if (!bp->confirm &&
        (strcmp(bp->plan.state, YARDSALE_PLAN_STATE_EXPIRED) == 0 ||
         bp->now > bp->plan.expires_unix))
        return buy_plan_renew(bp);
    if (!bp->confirm)
        return NULL; /* plain re-inspection of live terms */
    if (strcmp(bp->plan.state, YARDSALE_PLAN_STATE_PLANNED) != 0)
        return buy_plan_expired_msg;
    if (bp->now > bp->plan.expires_unix)
        return buy_plan_expire(bp);
    return buy_plan_claim(bp);
}

static const char *buy_plan_new(struct buy_post *bp)
{
    webbuy_plan_row(&bp->plan, bp->request_hex, bp->plan_root_hex,
                    bp->payload_hex, bp->ad.quote.expires_unix, bp->now);
    if (!db_yardsale_plan_save(bp->ndb, &bp->plan)) {
        memset(&bp->plan, 0, sizeof(bp->plan));
        return "saving the planned accept failed";
    }
    return NULL;
}

/* Terms and ledger resolution use only public bytes. */
static const char *buy_resolve_plan(struct buy_post *bp, const char *bad)
{
    if (bad)
        return bad;
    if (!zswap_yardsale_find(bp->root, &bp->ad))
        return "that sign is not in this node's yardsale";
    bp->buyer.deadline_unix = bp->ad.quote.expires_unix;
    if (zswap_buyer_accept_serialize(&bp->buyer, bp->ser, sizeof(bp->ser),
                                     &bp->ser_len) != ZSWAP_ASSEMBLY_OK)
        return "the accept terms did not serialize";
    webbuy_identity(bp->root, bp->ser, bp->ser_len, bp->request_hex,
                    bp->plan_root_hex);
    if (!webbuy_payload(bp->root, bp->ser, bp->ser_len, bp->payload_hex))
        return "the planned accept outgrew the plan payload";
    bp->have_plan = db_yardsale_plan_find_by_request(bp->ndb,
                                                     bp->request_hex,
                                                     &bp->plan);
    if (bp->have_plan && strcmp(bp->plan.payload_hex, bp->payload_hex) != 0)
        return "a different accept already claims this plan "
               "hash — start over with fresh terms";
    if (bp->have_plan)
        return buy_plan_existing(bp);
    if (bp->confirm)
        return "no plan names these exact terms — submit "
               "without confirm first and inspect them";
    return buy_plan_new(bp);
}

static const char *buy_arm_ceremony(struct buy_post *bp)
{
    bp->result = yardsale_buyer_begin(&bp->ad.quote, &bp->buyer, bp->keys,
                                      bp->buyer.num_inputs, bp->now,
                                      bp->wire, sizeof(bp->wire),
                                      &bp->wire_len);
    if (bp->result == YARDSALE_OK && bp->have_plan) {
        snprintf(bp->plan.state, sizeof(bp->plan.state), "%s",
                 YARDSALE_PLAN_STATE_COMMITTED);
        snprintf(bp->plan.result, sizeof(bp->plan.result), "begun");
        if (!db_yardsale_plan_save(bp->ndb, &bp->plan)) {
            bp->commit_save_failed = true;
            return "the accept left the node but its durable outcome is "
                   "uncertain — automatic replay is blocked";
        }
    } else if (bp->result != YARDSALE_OK) {
        snprintf(bp->plan.state, sizeof(bp->plan.state), "%s",
                 YARDSALE_PLAN_STATE_PLANNED);
        bp->plan.result[0] = '\0';
        if (!db_yardsale_plan_save(bp->ndb, &bp->plan))
            return "the ceremony refused and the plan could not be "
                   "released — inspect before retrying";
    }
    return NULL;
}

static size_t buy_success_page(const struct buy_post *bp, uint8_t *response,
                               size_t response_max)
{
    char page[2048];
    int n = snprintf(page, sizeof(page),
        "<!doctype html><html><head><title>accept out</title>"
        "<style>" YARDSALE_PAGE_STYLE "</style></head><body>"
        "<h1>Accept pinned on the seller's door</h1>"
        "<p>Your <code>zswap_accept.v1</code> (%zu bytes) is gossiping "
        "toward the seller. When his <code>zswap_partial.v1</code> "
        "returns, this node verifies every term of the sign, signs your "
        "inputs, and broadcasts the swap — check <code>z23 "
        "status</code> or the logs for the settlement. If the sign "
        "expires first, the ceremony dies with it and nothing was "
        "lost.</p><p><a href='/yardsale'>Back to the yard</a></p>"
        "</body></html>", bp->wire_len);
    if (n < 0)
        return 0;
    return yardsale_http_response("200 OK", "text/html; charset=utf-8",
                                  (const uint8_t *)page, (size_t)n,
                                  response, response_max);
}

/* ── POST /yardsale/buy — plan-first on the web form too ─────────── */
/* A form POST without confirm=true resolves the exact accept terms
 * (canonical zswap serialization under the live ad) and stores them as a
 * PLANNED db_yardsale_plan row under a controller-distinct request hash;
 * the reply renders those terms and says money arms only after
 * confirm=true. The confirm POST must reproduce terms whose stored row is
 * still PLANNED and unexpired — changed terms plan anew instead of arming,
 * COMMITTED rows replay idempotently without a second begin(), and there
 * is no arm path that bypasses the ledger. WIFs stay in the request body
 * only: they are cleansed with it and never persisted or echoed. */

size_t yardsale_site_handle_buy_post(const uint8_t *body, size_t body_len,
                                       uint8_t *response,
                                       size_t response_max)
{
    /* The body is form text; bound it before scanning. */
    if (!body || body_len == 0 || body_len > 16384)
        return yardsale_error_page("400 Bad Request", "400 Bad Request",
            "missing or oversized form body", response, response_max);

    char *form = zcl_malloc(body_len + 1, "yardsale buy form");
    if (!form)
        LOG_RETURN(0, "yardsale", "buy POST: form copy allocation failed");
    memcpy(form, body, body_len);
    form[body_len] = 0;

    struct buy_post bp;
    memset(&bp, 0, sizeof(bp));
    bp.result = YARDSALE_ERR_NULL;
    const char *bad = buy_read_request(form, body_len, &bp);
    if (!bad)
        buy_apply_terms(&bp);

    /* Terms and ledger resolution use only public bytes; the private keys
     * stay live solely for the phase-2 ceremony below. */
    bp.now = (int64_t)platform_time_wall_time_t();
    bad = buy_resolve_plan(&bp, bad);
    if (bp.expire_save_failed)
        LOG_ERR("yardsale",
                "web-buy expiry save failed");
    if (!bad && bp.arm_now)
        bad = buy_arm_ceremony(&bp);
    if (bp.commit_save_failed)
        LOG_ERR("yardsale",
                "armed accept remains ARMING after commit save failed");
    memory_cleanse(bp.keys, sizeof(bp.keys));
    memory_cleanse(form, body_len); /* raw body holds the WIF strings */
    free(form);

    if (bad)
        return yardsale_error_page("400 Bad Request", "400 Bad Request",
                                   bad, response, response_max);
    if (bp.already_begun || !bp.arm_now)
        return yardsale_render_buy_plan_page(&bp.plan, bp.root, &bp.buyer,
                                             bp.already_begun,
                                             response, response_max);
    if (bp.result != YARDSALE_OK)
        return yardsale_error_page("502 Bad Gateway",
                                   "the accept never left the yard",
                                   yardsale_error_string(bp.result),
                                   response, response_max);
    return buy_success_page(&bp, response, response_max);
}

/* ── POST /yardsale/accept — the seller endpoint ─────────────────── */
