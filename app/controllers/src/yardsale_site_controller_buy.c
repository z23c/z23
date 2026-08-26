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

/* Parse one "txid:vout:value:scripthex" form field. */
static bool parse_input_field(const char *text, struct zswap_swap_input *in)
{
    memset(in, 0, sizeof(*in));
    char txid_hex[65], script_hex[2 * ZSWAP_MAX_INPUT_SCRIPT_BYTES + 1];
    unsigned long vout;
    unsigned long long value;
    /* The script is last (hex has no colons), the txid first. */
    const char *c1 = strchr(text, ':');
    const char *c2 = c1 ? strchr(c1 + 1, ':') : NULL;
    const char *c3 = c2 ? strchr(c2 + 1, ':') : NULL;
    if (!c3 || c3 == c2 + 1)
        return false;
    size_t txid_len = (size_t)(c1 - text);
    if (txid_len != 64 ||
        (size_t)(c2 - c1 - 1) >= 16 || (size_t)(c3 - c2 - 1) >= 32)
        return false;
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
    char *end = NULL;
    errno = 0;
    vout = strtoul(vout_s, &end, 10);
    if (errno != 0 || !end || *end != '\0')
        return false;
    errno = 0;
    value = strtoull(value_s, &end, 10);
    if (errno != 0 || !end || *end != '\0')
        return false;
    if (vout > UINT32_MAX || value == 0 || value > INT64_MAX)
        return false;
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

    char root_hex[80], token_recv[ZSWAP_ADDRESS_FIELD_BYTES],
         change[ZSWAP_ADDRESS_FIELD_BYTES], fee_s[24];
    const char *bad = NULL;
    struct zswap_buyer_accept buyer;
    memset(&buyer, 0, sizeof(buyer));
    struct privkey keys[ZSWAP_MAX_BUYER_INPUTS];
    memset(keys, 0, sizeof(keys));

    if (!web_form_field(form, body_len, "root", root_hex,
                          sizeof(root_hex)) ||
        !web_form_field(form, body_len, "token_recv", token_recv,
                          sizeof(token_recv)) ||
        !web_form_field(form, body_len, "change", change,
                          sizeof(change)) ||
        !web_form_field(form, body_len, "fee", fee_s, sizeof(fee_s)))
        bad = "root, token_recv, change, and fee are required";

    /* Plan-first money on the form path too: without confirm=true this
     * only persists the exact planned terms; confirm=true arms money but
     * only against a stored PLANNED row whose terms match byte-for-byte. */
    char confirm_s[8];
    bool confirm = false;
    if (!bad && web_form_field(form, body_len, "confirm", confirm_s,
                                 sizeof(confirm_s))) {
        if (strcmp(confirm_s, "true") == 0 || strcmp(confirm_s, "1") == 0)
            confirm = true;
        else
            bad = "confirm must be \"true\" to arm money";
    }

    uint8_t root[32];
    if (!bad && !zcl_hex_decode_lower(root_hex, root, 32))
        bad = "root must be 64 lowercase hex characters";

    /* Up to four inputs via in1..in4 / key1..key4 (the web form's v1
     * convenience bound; the controller API takes the full 16). */
    const struct chain_params *cp = chain_params_get();
    size_t sec_pfx_len = 0;
    const unsigned char *sec_pfx =
        chain_params_base58_prefix(cp, B58_SECRET_KEY, &sec_pfx_len);
    for (size_t i = 1; i <= 4 && !bad; i++) {
        char fname[8], kname[8], in_s[640] = {0}, wif_s[128] = {0};
        snprintf(fname, sizeof(fname), "in%zu", i);
        snprintf(kname, sizeof(kname), "key%zu", i);
        bool have_in = web_form_field(form, body_len, fname, in_s,
                                        sizeof(in_s)) && in_s[0];
        bool have_key = web_form_field(form, body_len, kname, wif_s,
                                         sizeof(wif_s)) && wif_s[0];
        if (!have_in && !have_key)
            continue;
        if (have_in != have_key) {
            memory_cleanse(wif_s, sizeof(wif_s));
            bad = "every input needs its WIF, and every WIF its input";
            break;
        }
        struct zswap_swap_input *in = &buyer.inputs[buyer.num_inputs];
        if (!parse_input_field(in_s, in)) {
            memory_cleanse(wif_s, sizeof(wif_s));
            bad = "an input is not txid:vout:value:scripthex";
            break;
        }
        if (!decode_secret(wif_s, sec_pfx, sec_pfx_len,
                           &keys[buyer.num_inputs])) {
            bad = "a WIF did not decode";
            memory_cleanse(wif_s, sizeof(wif_s));
            break;
        }
        memory_cleanse(wif_s, sizeof(wif_s));
        buyer.num_inputs++;
    }

    uint64_t fee = 0;
    if (!bad) {
        if (buyer.num_inputs == 0)
            bad = "at least one ZCL input is required";
        char *end = NULL;
        errno = 0;
        fee = strtoull(fee_s, &end, 10);
        if (errno != 0 || !end || *end != '\0' || fee == 0)
            bad = "fee must be positive sats";
    }

    /* The ledger gates every arm. A missing plan store refuses rather
     * than falling back to the old one-shot behavior. */
    struct node_db *ndb = app_runtime_node_db();
    if (!bad && (!ndb || !ndb->open))
        bad = "the web-buy plan store is unavailable — nothing was "
              "planned or armed";

    struct db_yardsale_plan plan;
    bool have_plan = false;
    if (!bad) {
        snprintf(buyer.token_recv_address,
                 sizeof(buyer.token_recv_address), "%s", token_recv);
        snprintf(buyer.change_address, sizeof(buyer.change_address),
                 "%s", change);
        buyer.fee_sats = fee;
    }

    /* Terms and ledger resolution use only public bytes; the private keys
     * stay live solely for the phase-2 ceremony below. */
    bool arm_now = false;
    bool already_begun = false;
    size_t ser_len = 0;
    uint8_t ser[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    struct zswap_yardsale_ad ad;
    int64_t now = (int64_t)platform_time_wall_time_t();
    if (!bad) {
        if (!zswap_yardsale_find(root, &ad)) {
            bad = "that sign is not in this node's yardsale";
        } else {
            buyer.deadline_unix = ad.quote.expires_unix;
            if (zswap_buyer_accept_serialize(&buyer, ser, sizeof(ser),
                                             &ser_len) !=
                ZSWAP_ASSEMBLY_OK) {
                bad = "the accept terms did not serialize";
            } else {
                char request_hex[65], plan_root_hex[65];
                char payload_hex[YARDSALE_PLAN_PAYLOAD_HEX_MAX];
                webbuy_identity(root, ser, ser_len, request_hex,
                                plan_root_hex);
                if (!webbuy_payload(root, ser, ser_len, payload_hex))
                    bad = "the planned accept outgrew the plan payload";
                else
                    have_plan = db_yardsale_plan_find_by_request(
                        ndb, request_hex, &plan);
                if (!bad && have_plan &&
                    strcmp(plan.payload_hex, payload_hex) != 0)
                    bad = "a different accept already claims this plan "
                          "hash — start over with fresh terms";

                if (!bad && have_plan) {
                    if (strcmp(plan.state, YARDSALE_PLAN_STATE_COMMITTED)
                        == 0)
                        already_begun = true;
                    else if (!confirm &&
                             (strcmp(plan.state,
                                     YARDSALE_PLAN_STATE_EXPIRED) == 0 ||
                              now > plan.expires_unix)) {
                        webbuy_plan_row(&plan, request_hex, plan_root_hex,
                                        payload_hex, ad.quote.expires_unix,
                                        now);
                        if (!db_yardsale_plan_save(ndb, &plan))
                            bad = "renewing the planned accept failed";
                    } else if (!confirm)
                        ; /* plain re-inspection of live terms */
                    else if (strcmp(plan.state,
                                    YARDSALE_PLAN_STATE_PLANNED) != 0)
                        bad = "these planned terms expired — submit "
                              "without confirm to plan again";
                    else if (now > plan.expires_unix) {
                        snprintf(plan.state, sizeof(plan.state), "%s",
                                 YARDSALE_PLAN_STATE_EXPIRED);
                        if (!db_yardsale_plan_save(ndb, &plan))
                            LOG_ERR("yardsale",
                                    "web-buy expiry save failed");
                        bad = "these planned terms expired — submit "
                              "without confirm to plan again";
                    } else {
                        enum db_yardsale_plan_claim_result claim =
                            db_yardsale_plan_claim(ndb, &plan, now);
                        if (claim == DB_YARDSALE_PLAN_CLAIMED)
                            arm_now = true;
                        else if (claim == DB_YARDSALE_PLAN_CLAIM_REFUSED)
                            bad = "these terms are already being armed or "
                                  "changed state — inspect before retrying";
                        else
                            bad = "the plan ledger could not claim these "
                                  "terms — nothing was armed";
                    }
                } else if (!bad && confirm && !have_plan) {
                    bad = "no plan names these exact terms — submit "
                          "without confirm first and inspect them";
                }
                if (!bad && !have_plan) {
                    webbuy_plan_row(&plan, request_hex, plan_root_hex,
                                    payload_hex, ad.quote.expires_unix,
                                    now);
                    if (!db_yardsale_plan_save(ndb, &plan)) {
                        bad = "saving the planned accept failed";
                        memset(&plan, 0, sizeof(plan));
                    }
                }
            }
        }
    }

    size_t wire_len = 0;
    enum yardsale_error result = YARDSALE_ERR_NULL;
    uint8_t wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    if (!bad && arm_now) {
        result = yardsale_buyer_begin(&ad.quote, &buyer, keys,
                                      buyer.num_inputs, now,
                                      wire, sizeof(wire), &wire_len);
        if (result == YARDSALE_OK && have_plan) {
            snprintf(plan.state, sizeof(plan.state), "%s",
                     YARDSALE_PLAN_STATE_COMMITTED);
            snprintf(plan.result, sizeof(plan.result), "begun");
            if (!db_yardsale_plan_save(ndb, &plan)) {
                LOG_ERR("yardsale",
                        "armed accept remains ARMING after commit save failed");
                bad = "the accept left the node but its durable outcome is "
                      "uncertain — automatic replay is blocked";
            }
        } else if (result != YARDSALE_OK) {
            snprintf(plan.state, sizeof(plan.state), "%s",
                     YARDSALE_PLAN_STATE_PLANNED);
            plan.result[0] = '\0';
            if (!db_yardsale_plan_save(ndb, &plan))
                bad = "the ceremony refused and the plan could not be "
                      "released — inspect before retrying";
        }
    }
    memory_cleanse(keys, sizeof(keys));
    memory_cleanse(form, body_len); /* raw body holds the WIF strings */
    free(form);

    if (bad)
        return yardsale_error_page("400 Bad Request", "400 Bad Request",
                                   bad, response, response_max);
    if (already_begun || !arm_now)
        return yardsale_render_buy_plan_page(&plan, root, &buyer,
                                             already_begun,
                                             response, response_max);
    if (result != YARDSALE_OK)
        return yardsale_error_page("502 Bad Gateway",
                                   "the accept never left the yard",
                                   yardsale_error_string(result),
                                   response, response_max);

    char page[2048];
    int n = snprintf(page, sizeof(page),
        "<!doctype html><html><head><title>accept out</title>"
        "<style>" YARDSALE_PAGE_STYLE "</style></head><body>"
        "<h1>Accept pinned on the seller's door</h1>"
        "<p>Your <code>zswap_accept.v1</code> (%zu bytes) is gossiping "
        "toward the seller. When his <code>zswap_partial.v1</code> "
        "returns, this node verifies every term of the sign, signs your "
        "inputs, and broadcasts the swap — check <code>zclassic23 "
        "status</code> or the logs for the settlement. If the sign "
        "expires first, the ceremony dies with it and nothing was "
        "lost.</p><p><a href='/yardsale'>Back to the yard</a></p>"
        "</body></html>", wire_len);
    if (n < 0)
        return 0;
    return yardsale_http_response("200 OK", "text/html; charset=utf-8",
                                  (const uint8_t *)page, (size_t)n,
                                  response, response_max);
}

/* ── POST /yardsale/accept — the seller endpoint ─────────────────── */
