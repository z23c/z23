/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the Yardsale app's /yardsale web mount — see
 * controllers/yardsale_site_controller.h for the route table and the
 * no-session/no-CSRF rationale. Renders straight off the zswap_ads
 * rebuildable projection; mutating routes drive the ceremony controller. */

#include "controllers/yardsale_site_controller.h"
#include "controllers/yardsale_site_internal.h"

#include "base/hex.h"
#include "config/runtime.h"
#include "controllers/yardsale_controller.h"
#include "models/database.h"
#include "models/zswap_ad.h"
#include "net/onion_service.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/template.h"
#include "znam/znam.h"
#include "zswap/zswap_ceremony.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── GET /yardsale — the yard ────────────────────────────────────── */

/* Defined just below the index renderer; appends the "Known sellers"
 * section at `off` and returns the byte count it wrote. */
static size_t yardsale_render_known_sellers(struct node_db *ndb, int64_t now,
                                            uint8_t *out, size_t out_cap,
                                            size_t off);

static size_t yardsale_render_index(struct node_db *ndb, int64_t now,
                                    uint8_t *out, size_t out_cap)
{
    struct zswap_yardsale_ad ads[ZSWAP_YARDSALE_QUERY_CAP];
    int count = db_zswap_ad_list_live(ndb, now, ads,
                                      ZSWAP_YARDSALE_QUERY_CAP);

    size_t off = 0;
    int n = snprintf((char *)out, out_cap,
        "<!doctype html><html><head><title>ZClassic Yardsale</title>"
        "<style>" YARDSALE_PAGE_STYLE "</style></head><body>"
        "<h1>The Yardsale</h1>"
        "<p>Signed for-sale-by-owner signs this node remembers, best unit "
        "price first. Every sign is Ed25519-sealed by its seller and "
        "relayed byte-identically; buying is a direct two-message ceremony "
        "with the seller — there is no counterparty in the middle.</p>"
        "<table><tr><th>sign</th><th>token</th><th>amount</th>"
        "<th>price (sats)</th><th>seller</th><th>expires</th>"
        "<th>seen</th></tr>");
    if (n > 0)
        off = (size_t)n;

    for (int i = 0; i < count && off < out_cap - 512; i++) {
        const struct zswap_yardsale_ad *ad = &ads[i];
        char root_hex[65], root_short[40], token_short[40], seller_short[40];
        zcl_hex_encode(ad->quote_root, 32, root_hex);
        hex_short(ad->quote_root, 32, 8, root_short, sizeof(root_short));
        hex_short(ad->quote.token_id, 32, 8, token_short,
                  sizeof(token_short));
        hex_short(ad->quote.seller_pubkey, 32, 8, seller_short,
                  sizeof(seller_short));
        n = snprintf((char *)out + off, out_cap - off,
            "<tr><td><a href='/yardsale/ad/%s'>%s</a></td><td>%s</td>"
            "<td>%llu</td><td>%llu</td><td>%s</td>"
            "<td>%llds</td><td>%llu</td></tr>",
            root_hex, root_short, token_short,
            (unsigned long long)ad->quote.token_amount,
            (unsigned long long)ad->quote.zcl_amount,
            seller_short,
            (long long)(ad->quote.expires_unix - now),
            (unsigned long long)ad->seen_count);
        if (n < 0)
            break;
        off += (size_t)n;
    }
    if (count == 0)
        off += (size_t)snprintf((char *)out + off, out_cap - off,
            "<tr><td colspan='7'>no live signs — the yard is empty"
            " — pin your own sign: `z23 discover help yardsale` "
            "(seller commands)</td></tr>");
    int closed = snprintf((char *)out + off, out_cap - off, "</table>");
    if (closed > 0)
        off += (size_t)closed;
    off += yardsale_render_known_sellers(ndb, now, out, out_cap, off);
    snprintf((char *)out + off, out_cap - off,
        "<p><a href='/'>Home</a></p></body></html>");
    return strlen((const char *)out);
}

/* ── Known sellers (peer-directory read, discovery hints only) ───────
 *
 * Fresh peer_directory rows whose apps advertisement names the yardsale
 * App, rendered as links to their /yardsale mounts. These are discovery
 * HINTS — a row says where to look, never who is there (the directory
 * contract in net/onion_service.h) — and every rendered value passes
 * html_escape on top of the directory's own read-time re-validation. The
 * empty state is honest: gossip carries the ads with or without this
 * section. */

#define YARDSALE_KNOWN_SELLERS_CAP 50

static size_t yardsale_render_known_sellers(struct node_db *ndb, int64_t now,
                                            uint8_t *out, size_t out_cap,
                                            size_t off)
{
    size_t start = off;
    int n = snprintf((char *)out + off, out_cap - off,
        "<h2>Known sellers</h2>");
    if (n > 0)
        off += (size_t)n;

    struct onion_directory_app_peer peers[YARDSALE_KNOWN_SELLERS_CAP];
    int n_peers = onion_directory_app_peers_db(ndb->db, "yardsale", now,
                                               peers,
                                               YARDSALE_KNOWN_SELLERS_CAP);

    int shown = 0;
    for (int i = 0; i < n_peers && off + 768 < out_cap; i++) {
        /* The ZNAM label join that already exists for directory rows: a
         * name is a label for an address, never a substitute, so the raw
         * .onion the buyer would dial is always shown beside it. */
        char name[ZNAM_NAME_MAX + 1];
        name[0] = '\0';
        (void)onion_directory_name_for_db(ndb->db, peers[i].onion,
                                          name, sizeof(name));
        char esc_onion[384], esc_name[256], esc_apps[1600];
        html_escape(esc_onion, sizeof(esc_onion), peers[i].onion);
        html_escape(esc_name, sizeof(esc_name), name);
        html_escape(esc_apps, sizeof(esc_apps), peers[i].apps);
        bool named = name[0] != '\0';
        n = snprintf((char *)out + off, out_cap - off,
            "<div class='seller'><a href='http://%s/yardsale'>%s</a>"
            "<div class='desc'>%s &middot; serves: %s</div></div>",
            esc_onion, named ? esc_name : esc_onion,
            named ? esc_onion : "this node",
            esc_apps);
        if (n < 0)
            break;
        off += (size_t)n;
        shown++;
    }

    if (shown == 0) {
        n = snprintf((char *)out + off, out_cap - off,
            "<p>no sellers discovered yet &mdash; ads still propagate "
            "by gossip.</p>");
        if (n > 0)
            off += (size_t)n;
    }
    return off - start;
}

/* ── GET /yardsale/ad/<root> — one sign + the buy form ───────────── */

static size_t yardsale_render_ad(struct node_db *ndb, int64_t now,
                                 const char *root_hex,
                                 uint8_t *out, size_t out_cap)
{
    uint8_t root[32];
    if (!zcl_hex_decode_lower(root_hex, root, 32))
        return yardsale_error_page("400 Bad Request", "400 Bad Request",
            "the sign root must be 64 lowercase hex characters",
            out, out_cap);

    struct zswap_yardsale_ad ad;
    if (!db_zswap_ad_find(ndb, root, &ad) ||
        ad.quote.expires_unix <= now)
        return yardsale_error_page("404 Not Found", "404 Not Found",
            "no live sign with that root", out, out_cap);

    char token_hex[65], seller_hex[65];
    zcl_hex_encode(ad.quote.token_id, 32, token_hex);
    zcl_hex_encode(ad.quote.seller_pubkey, 32, seller_hex);

    int n = snprintf((char *)out, out_cap,
        "<!doctype html><html><head><title>Yardsale sign %s</title>"
        "<style>" YARDSALE_PAGE_STYLE "</style></head><body>"
        "<h1>Sign <code>%.16s...</code></h1>"
        "<table>"
        "<tr><th>token</th><td><code>%s</code></td></tr>"
        "<tr><th>amount for sale</th><td>%llu base units</td></tr>"
        "<tr><th>price</th><td>%llu sats ZCL (whole amount)</td></tr>"
        "<tr><th>seller</th><td><code>%s</code></td></tr>"
        "<tr><th>valid</th><td>%lld &rarr; %lld (%llds left)</td></tr>"
        "</table>"
        "<h2>Buy it</h2>"
        "<p>Your node builds a <code>zswap_accept.v1</code> from the fields "
        "below and gossips it to the seller. No signatures cross the wire "
        "until the seller's partial answer returns and your node verifies "
        "every term of the sign byte-for-byte; walking away at any point "
        "leaves no transaction and no loss. Input txids are node-internal "
        "byte order, hex.</p>"
        "<form method='POST' action='/yardsale/buy'>"
        "<input type='hidden' name='root' value='%s'>"
        "<label>ZCL input 1: txid:vout:value:scripthex</label>"
        "<input name='in1'>"
        "<label>ZCL input 2 (optional)</label><input name='in2'>"
        "<label>ZCL input 3 (optional)</label><input name='in3'>"
        "<label>ZCL input 4 (optional)</label><input name='in4'>"
        "<label>WIF for input 1</label><input name='key1'>"
        "<label>WIF for input 2</label><input name='key2'>"
        "<label>WIF for input 3</label><input name='key3'>"
        "<label>WIF for input 4</label><input name='key4'>"
        "<label>token receive address</label><input name='token_recv'>"
        "<label>change address</label><input name='change'>"
        "<label>fee (sats)</label><input name='fee'>"
        "<p><button type='submit'>Pin the accept on the seller's "
        "door</button></p>"
        "</form>"
        "<p><a href='/yardsale'>Back to the yard</a></p></body></html>",
        root_hex, root_hex, token_hex,
        (unsigned long long)ad.quote.token_amount,
        (unsigned long long)ad.quote.zcl_amount, seller_hex,
        (long long)ad.quote.issued_unix, (long long)ad.quote.expires_unix,
        (long long)(ad.quote.expires_unix - now), root_hex);
    if (n < 0 || (size_t)n >= out_cap)
        return 0;
    return (size_t)n;
}


static size_t yardsale_handle_accept_post(const uint8_t *body,
                                          size_t body_len,
                                          uint8_t *response,
                                          size_t response_max)
{
    if (!body || body_len == 0 || body_len > ZSWAP_ACCEPT_WIRE_MAX_BYTES)
        return yardsale_error_page("400 Bad Request", "400 Bad Request",
            "the body must be one zswap_accept.v1 wire",
            response, response_max);

    uint8_t partial[ZSWAP_PARTIAL_WIRE_MAX_BYTES];
    size_t partial_len = 0;
    int64_t now = (int64_t)platform_time_wall_time_t();
    enum yardsale_error e = yardsale_seller_handle_accept_wire(
        body, body_len, now, partial, sizeof(partial), &partial_len);
    if (e != YARDSALE_OK)
        return yardsale_error_page("422 Unprocessable Content",
                                   "the accept was refused",
                                   yardsale_error_string(e),
                                   response, response_max);
    return yardsale_http_response("200 OK", "engine/application/octet-stream",
                                  partial, partial_len,
                                  response, response_max);
}

/* ── The mount ───────────────────────────────────────────────────── */

size_t yardsale_site_handle_request(const char *method, const char *path,
                                    const uint8_t *body, size_t body_len,
                                    uint8_t *response, size_t response_max)
{
    if (!method || !path || !response || response_max < 1024)
        return 0;

    const char *query = strchr(path, '?');
    size_t path_len = query ? (size_t)(query - path) : strlen(path);
    char clean[256];
    if (path_len == 0 || path_len >= sizeof(clean))
        return yardsale_error_page("400 Bad Request", "400 Bad Request",
            "path too long", response, response_max);
    memcpy(clean, path, path_len);
    clean[path_len] = 0;

    if (strncmp(clean, "/yardsale", 9) != 0 ||
        (clean[9] != 0 && clean[9] != '/'))
        return 0;

    if (strcmp(method, "POST") == 0) {
        if (strcmp(clean, "/yardsale/buy") == 0)
            return yardsale_site_handle_buy_post(body, body_len, response,
                                            response_max);
        if (strcmp(clean, "/yardsale/accept") == 0)
            return yardsale_handle_accept_post(body, body_len, response,
                                               response_max);
        return yardsale_error_page("404 Not Found", "404 Not Found",
            "no such yardsale action", response, response_max);
    }
    if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0)
        return yardsale_error_page("405 Method Not Allowed",
            "405 Method Not Allowed", "GET, HEAD or POST only",
            response, response_max);

    /* Read-only pages need the zswap_ads projection. */
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !ndb->open) {
        LOG_WARN("yardsale", "public Yardsale requested while node.db is "
                 "unavailable");
        return 0; /* the dispatcher serves its own 503 */
    }

    int64_t now = (int64_t)platform_time_wall_time_t();
    uint8_t *rendered = zcl_malloc(response_max, "yardsale page");
    if (!rendered)
        LOG_RETURN(0, "yardsale", "response allocation failed");

    size_t rendered_len = 0;
    if (clean[9] == 0 || strcmp(clean, "/yardsale/") == 0) {
        rendered_len = yardsale_render_index(ndb, now, rendered,
                                             response_max);
    } else if (strncmp(clean, "/yardsale/ad/", 13) == 0 &&
               strlen(clean + 13) == 64) {
        rendered_len = yardsale_render_ad(ndb, now, clean + 13, rendered,
                                          response_max);
    } else {
        free(rendered);
        return yardsale_error_page("404 Not Found", "404 Not Found",
            "no such yardsale page", response, response_max);
    }

    size_t response_len = 0;
    if (rendered_len > 0)
        response_len = yardsale_http_response(
            "200 OK", "text/html; charset=utf-8", rendered, rendered_len,
            response, response_max);
    free(rendered);
    if (response_len == 0)
        return yardsale_error_page("404 Not Found", "404 Not Found",
            "no such yardsale page", response, response_max);
    return response_len;
}
