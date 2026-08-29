/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Blog controller — static file server + ZSLP node registry. */

#include "controllers/blog_controller.h"
#include "models/database.h"
#include "models/onion_announcement.h"
#include "models/onion_directory.h"
#include "models/wallet_tx.h"
#include "net/onion_peer_merge.h"
#include "zslp/slp.h"
#include "script/op_return_push.h"
#include "primitives/transaction.h"
#include "core/uint256.h"
#include "core/serialize.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "platform/safe_root_read.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

/* Last discovery pass's per-source contribution, published through
 * blog_onion_discovery_counts(). Diagnostic only — nothing branches on these.
 * They exist so the wallet scrape can be RETIRED WITH EVIDENCE (a measured
 * zero contribution over real datadirs) instead of by assertion; peer
 * discovery is liveness-critical and deleting a source on a design argument is
 * how a node ends up with none. Written by the two source functions on the
 * discovery thread, read by tests and diagnostics. */
static _Atomic int g_last_chain_rows;
static _Atomic int g_last_wallet_rows;
static _Atomic int g_last_rejected;

/* ── Static file server ─────────────────────────────────────── */

static const char *content_type_for(const char *path)
{
    const char *ext = strrchr(path, '.');
    if (!ext) return "text/html; charset=utf-8";
    if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0)
        return "text/html; charset=utf-8";
    if (strcmp(ext, ".css") == 0) return "text/css";
    if (strcmp(ext, ".js") == 0) return "application/javascript";
    if (strcmp(ext, ".png") == 0) return "image/png";
    if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0)
        return "image/jpeg";
    if (strcmp(ext, ".svg") == 0) return "image/svg+xml";
    if (strcmp(ext, ".json") == 0) return "application/json";
    if (strcmp(ext, ".xml") == 0) return "application/xml";
    if (strcmp(ext, ".txt") == 0) return "text/plain";
    if (strcmp(ext, ".ico") == 0) return "image/x-icon";
    return "application/octet-stream";
}

/* Sanitize path: no .., no absolute paths, no control characters */
static bool safe_path(const char *path)
{
    if (!path || path[0] == '\0') return false;
    if (strstr(path, "..")) return false;
    if (path[0] == '/' && path[1] == '/') return false;
    for (size_t i = 0; path[i]; i++) {
        unsigned char c = (unsigned char)path[i];
        if (c < 0x20 && c != '\t') return false;  /* reject control chars */
    }
    return true;
}

static size_t http_response(char *out, size_t out_len,
                             int status, const char *content_type,
                             const char *body, size_t body_len)
{
    const char *status_text = (status == 200) ? "OK" :
                              (status == 404) ? "Not Found" :
                              (status == 403) ? "Forbidden" : "Error";
    int hdr_len = snprintf(out, out_len,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        status, status_text, content_type, body_len);
    if (hdr_len < 0 || (size_t)hdr_len + body_len > out_len)
        return 0;
    memcpy(out + hdr_len, body, body_len);
    return (size_t)hdr_len + body_len;
}

size_t blog_serve(const char *datadir, const char *path,
                  char *out, size_t out_len)
{
    if (!path || !out || out_len < 256) return 0;
    if (!datadir) {
        const char *body =
            "<html><head><style>body{background:#0a0a0a;color:#e0e0e0;"
            "font-family:monospace;text-align:center;padding:80px 20px}"
            "</style></head><body><h1>404 Not Found</h1>"
            "<p><a href='/' style='color:#00ff88'>Return home</a></p>"
            "</body></html>";
        return http_response(out, out_len, 404, "text/html",
                             body, strlen(body));
    }

    /* Default to index.html */
    const char *rel = path;
    if (rel[0] == '/') rel++;
    if (rel[0] == '\0') rel = "index.html";

    if (!safe_path(rel)) {
        const char *body =
            "<html><head><style>body{background:#0a0a0a;color:#e0e0e0;"
            "font-family:monospace;text-align:center;padding:80px 20px}"
            "</style></head><body><h1>403 Forbidden</h1>"
            "<p><a href='/' style='color:#00ff88'>Return home</a></p>"
            "</body></html>";
        return http_response(out, out_len, 403, "text/html",
                             body, strlen(body));
    }

    /* The platform seam opens each component without following links/reparse
     * points and reads from the same pinned leaf handle.  This avoids both the
     * check/reopen race and Windows' lack of realpath(3). */
    char blog_root[1024];
    int root_n = snprintf(blog_root, sizeof(blog_root), "%s/blog", datadir);
    if (root_n < 0 || (size_t)root_n >= sizeof(blog_root)) return 0;
    size_t max_body = (out_len > 512) ? out_len - 512 : 0;
    uint8_t *body_data = NULL;
    size_t nread = 0;
    enum platform_safe_root_read_result read_result = platform_safe_root_read(
        blog_root, rel, max_body, &body_data, &nread);
    char rel_html[1024];
    const char *served_rel = rel;
    if (read_result == PLATFORM_SAFE_ROOT_READ_NOT_FOUND) {
        int rel_n = snprintf(rel_html, sizeof(rel_html), "%s.html", rel);
        if (rel_n >= 0 && (size_t)rel_n < sizeof(rel_html)) {
            read_result = platform_safe_root_read(blog_root, rel_html, max_body,
                                                  &body_data, &nread);
            if (read_result == PLATFORM_SAFE_ROOT_READ_OK) served_rel = rel_html;
        }
    }
    if (read_result == PLATFORM_SAFE_ROOT_READ_NOT_FOUND) {
        const char *body =
            "<html><head><style>body{background:#0a0a0a;color:#e0e0e0;"
            "font-family:monospace;text-align:center;padding:80px 20px}"
            "</style></head><body><h1>404 Not Found</h1>"
            "<p><a href='/' style='color:#00ff88'>Return home</a></p>"
            "</body></html>";
        return http_response(out, out_len, 404, "text/html",
                             body, strlen(body));
    }
    if (read_result == PLATFORM_SAFE_ROOT_READ_FORBIDDEN) {
        const char *body =
            "<html><head><style>body{background:#0a0a0a;color:#e0e0e0;"
            "font-family:monospace;text-align:center;padding:80px 20px}"
            "</style></head><body><h1>403 Forbidden</h1>"
            "<p><a href='/' style='color:#00ff88'>Return home</a></p>"
            "</body></html>";
        return http_response(out, out_len, 403, "text/html",
                             body, strlen(body));
    }
    if (read_result != PLATFORM_SAFE_ROOT_READ_OK) {
        const char *msg = "<h1>500 File too large</h1>";
        return http_response(out, out_len, 500, "text/html",
                             msg, strlen(msg));
    }

    size_t result = http_response(out, out_len, 200,
                                   content_type_for(served_rel),
                                   (const char *)body_data, nread);
    free(body_data);
    return result;
}

/* ── ZSLP Node Registry ────────────────────────────────────── */

size_t blog_build_node_registry_genesis(uint8_t *out, size_t out_len)
{
    return slp_build_genesis(out, out_len,
        "ZCL23NODES",                /* ticker */
        "ZClassic23 Node Registry",  /* name */
        "",                           /* document_url */
        NULL,                         /* document_hash */
        0,                            /* decimals */
        2,                            /* mint_baton_vout */
        1);                           /* initial_quantity */
}

size_t blog_build_node_announce(uint8_t *out, size_t out_len,
                                 const uint8_t token_id[32],
                                 const char *onion_hostname)
{
    /* Encode .onion hostname as a SEND with quantity=1.
     * The hostname is stored in the OP_RETURN after the SLP data
     * as an additional push. This is non-standard SLP but allows
     * any node to parse it by reading past the SLP fields. */
    struct uint256 tid;
    memcpy(tid.data, token_id, 32);
    uint64_t qty = 1;
    size_t slp_len = slp_build_send(out, out_len, &tid, &qty, 1);
    if (slp_len == 0 || !onion_hostname) return slp_len;

    /* Append hostname as additional pushdata */
    size_t hlen = strlen(onion_hostname);
    if (slp_len + 1 + hlen > out_len) return slp_len;
    out[slp_len] = (uint8_t)hlen;
    memcpy(out + slp_len + 1, onion_hostname, hlen);
    return slp_len + 1 + hlen;
}

/* SOURCE 2 of 2 — the WALLET SCRAPE. Deliberately still wired.
 *
 * This reads db_wallet_tx_recent_raw(): it can only ever see transactions
 * ALREADY IN THE LOCAL WALLET TABLE, and it recovers a hostname by parsing a
 * zero-token_id ZSLP SEND and skipping push fields until something ends in
 * ".onion". That is a scrape of your own wallet, not a protocol — a node with
 * an empty wallet learns nothing here, and no node ever sees another node's
 * announcement this way. Source 1 (the ZDIR chain projection, below) is the
 * real replacement.
 *
 * It stays for now because peer discovery is liveness-critical and a source is
 * only ever RETIRED WITH EVIDENCE, never on the strength of a better design:
 * it is the only source on a node whose datadir predates the onion_directory
 * table. Retire it when `ops state --subsystem=onion_directory` shows
 * active_rows > 0 on a real datadir and the counters published by
 * blog_onion_discovery_counts() show the wallet source contributing nothing
 * the chain source did not already supply. */
static int blog_discover_onion_peers_wallet(const char *datadir,
                                            struct onion_peer *out, size_t max)
{
    if (!datadir || !out || max == 0) return 0;

    char db_path[1024];
    snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);

    struct node_db ndb;
    struct db_wallet_tx_raw_view rows[256];
    if (max > sizeof(rows) / sizeof(rows[0]))
        max = sizeof(rows) / sizeof(rows[0]);

    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open_existing_runtime(&ndb, db_path,
                                       "blog.onion_discovery_wallet"))
        return 0;

    int found = 0;
    int row_count = db_wallet_tx_recent_raw(&ndb, rows, max);
    for (int ri = 0; ri < row_count && found < (int)max; ++ri) {
        const uint8_t *raw = rows[ri].raw_tx;
        int raw_len = (int)rows[ri].raw_tx_len;
        int height = rows[ri].block_height;
        if (!raw || raw_len < 10) {
            db_wallet_tx_raw_view_free(&rows[ri]);
            continue;
        }

        /* Deserialize transaction */
        struct transaction tx;
        transaction_init(&tx);
        struct byte_stream bs;
        stream_init_from_data(&bs, raw, (size_t)raw_len);
        if (!transaction_deserialize(&tx, &bs)) {
            transaction_free(&tx);
            db_wallet_tx_raw_view_free(&rows[ri]);
            continue;
        }

        /* Check vout[0] for OP_RETURN with SLP */
        if (tx.num_vout < 1 || tx.vout[0].script_pub_key.size < 10 ||
            tx.vout[0].script_pub_key.data[0] != 0x6a) {
            transaction_free(&tx);
            db_wallet_tx_raw_view_free(&rows[ri]);
            continue;
        }

        struct slp_message msg;
        if (!slp_parse(tx.vout[0].script_pub_key.data,
                       tx.vout[0].script_pub_key.size, &msg) ||
            msg.type != SLP_TX_SEND) {
            transaction_free(&tx);
            db_wallet_tx_raw_view_free(&rows[ri]);
            continue;
        }

        /* Skip SLP fields to find .onion hostname after them */
        const uint8_t *p = tx.vout[0].script_pub_key.data + 1; /* skip OP_RETURN */
        const uint8_t *end = tx.vout[0].script_pub_key.data +
                              tx.vout[0].script_pub_key.size;
        const uint8_t *data;
        size_t len;

        /* Skip: lokad_id, token_type, "SEND", token_id — read_push refuses a
         * NULL cursor, so a failed field short-circuits the rest. */
        for (int i = 0; i < 4; i++)
            p = read_push(p, end, &data, &len);
        /* Skip output quantities */
        for (int i = 0; i < 19 && p; i++) {
            const uint8_t *saved = p;
            p = read_push(p, end, &data, &len);
            if (!p || len != 8) { p = saved; break; }
        }

        /* Remaining data: [1 byte length][hostname] */
        if (p && p < end) {
            size_t hlen = (size_t)*p++;
            if (hlen > 0 && hlen < 63 && p + hlen <= end &&
                hlen > 6 && memcmp(p + hlen - 6, ".onion", 6) == 0) {
                memcpy(out[found].hostname, p, hlen);
                out[found].hostname[hlen] = '\0';
                out[found].height = height;
                found++;
            }
        }
        transaction_free(&tx);
        db_wallet_tx_raw_view_free(&rows[ri]);
    }

    node_db_close(&ndb);
    atomic_store(&g_last_wallet_rows, found);
    return found;
}

/* ── The chain-fed directory source ─────────────────────────── */

/* SOURCE 1 of 2 — the REAL chain projection.
 *
 * Reads onion_directory: one row per v3 onion hostname that a confirmed ZDIR
 * OP_RETURN registered, folded out of BLOCK HISTORY by
 * app/models/src/explorer_index_zdir.c during the ordinary genesis-ascending
 * index walk. No wallet involvement: a node with an empty wallet sees every
 * other node's announcement, which is the whole point.
 *
 * Read-only and bounded — a LIMIT-ed SELECT over an indexed (status, height)
 * page, no network call and no clock read. Every hostname is re-validated with
 * onion_hostname_valid before it leaves this function; the row was validated at
 * parse and at save too, and it is checked again here because the value is
 * about to be dialed. */
int blog_discover_onion_peers_chain(const char *datadir,
                                    struct onion_peer *out, size_t max)
{
    if (!datadir || !out || max == 0) return 0;

    char db_path[1024];
    snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open_existing_runtime(&ndb, db_path,
                                       "blog.onion_discovery_chain"))
        LOG_RETURN(0, "blog", "discover_onion_peers_chain: cannot open %s",
                   db_path);

    struct db_onion_directory rows[64];
    size_t want = max;
    if (want > sizeof(rows) / sizeof(rows[0]))
        want = sizeof(rows) / sizeof(rows[0]);

    memset(rows, 0, sizeof(rows));
    int row_count = db_onion_directory_list_active(&ndb, rows, (int)want, 0);
    node_db_close(&ndb);

    int found = 0;
    for (int i = 0; i < row_count && (size_t)found < max; i++) {
        if (!onion_hostname_valid(rows[i].hostname))
            continue;   /* refuse, never sanitize — see the model header */
        snprintf(out[found].hostname, sizeof(out[found].hostname), "%.*s",
                 (int)sizeof(out[found].hostname) - 1,
                 rows[i].hostname);
        out[found].height = rows[i].height;
        found++;
    }
    atomic_store(&g_last_chain_rows, found);
    return found;
}

/* onion_peers_collect's signed-source signature takes an opaque ctx; the chain
 * source takes a datadir. One adapter, no second copy of the merge. */
static int blog_chain_peer_source(void *ctx, struct onion_peer *out,
                                  size_t max)
{
    return blog_discover_onion_peers_chain((const char *)ctx, out, max);
}

void blog_onion_discovery_counts(int *out_chain, int *out_wallet,
                                 int *out_rejected)
{
    if (out_chain)    *out_chain    = atomic_load(&g_last_chain_rows);
    if (out_wallet)   *out_wallet   = atomic_load(&g_last_wallet_rows);
    if (out_rejected) *out_rejected = atomic_load(&g_last_rejected);
}

/* BOTH sources, chain first, merged by the ONE merge the node has
 * (onion_peers_collect, net/onion_peer_merge.h) — which is also what applies
 * onion_hostname_valid and de-duplicates a host that advertised through both.
 *
 * ADD, never replace, and never STARVE: the wallet scrape keeps running
 * alongside the chain projection, neither source can remove a candidate the
 * other found, and — the part that "never replace" alone did not buy —
 * onion_peers_collect asks the scrape first into at most half the slate, so a
 * chain projection with more rows than the slate is wide cannot consume all of
 * it and leave the scrape uninvoked. Consuming all the capacity is the same
 * outage as removing a source. An empty wallet still leaves the whole slate to
 * the chain. This function can only ever grow the peer set handed to connman; a
 * poisoned or squatted directory row costs one wasted connection attempt and
 * nothing else. */
int blog_discover_onion_peers(const char *datadir,
                              struct onion_peer *out, size_t max)
{
    if (!datadir || !out || max == 0) return 0;

    atomic_store(&g_last_chain_rows, 0);
    atomic_store(&g_last_wallet_rows, 0);

    /* The collect port hands the source an opaque void* ctx; the datadir is a
     * const char*. A union keeps that a type pun and not a cast that discards
     * const — the callee only ever reads it back through .cs. */
    union { const char *cs; void *v; } ctx = { .cs = datadir };

    int rejected = 0;
    int kept = onion_peers_collect(out, max, blog_chain_peer_source, ctx.v,
                                   blog_discover_onion_peers_wallet, datadir,
                                   &rejected);
    atomic_store(&g_last_rejected, rejected);

    /* The attribution line that lets the wallet source be retired with
     * evidence rather than by argument. */
    if (kept > 0 || rejected > 0)
        LOG_INFO("blog", "onion discovery: kept=%d chain=%d wallet=%d"
                 " malformed_dropped=%d", kept,
                 atomic_load(&g_last_chain_rows),
                 atomic_load(&g_last_wallet_rows), rejected);
    return kept;
}

/* ── Auto-announce .onion address on-chain ─────────────────── */

bool blog_auto_announce_onion(const char *datadir, const char *onion_address)
{
    struct node_db ndb;
    struct db_onion_announcement ann;
    if (!datadir || !onion_address || onion_address[0] == '\0')
        LOG_FAIL("blog", "auto_announce_onion: missing datadir or onion_address");

    char db_path[1024];
    snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);

    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open_runtime(&ndb, db_path, "blog.auto_announce"))
        LOG_FAIL("blog", "auto_announce_onion: failed to open db at %s", db_path);

    if (db_onion_announcement_exists(&ndb, onion_address)) {
        node_db_close(&ndb);
        LOG_FAIL("blog", "auto_announce_onion: announcement already exists for %s", onion_address);
    }

    /* Build the ZSLP SEND script with .onion hostname.
     * Use a zero token_id (node registry not yet on-chain). */
    uint8_t token_id[32];
    memset(token_id, 0, sizeof(token_id));

    uint8_t script[256];
    size_t slen = blog_build_node_announce(script, sizeof(script),
                                            token_id, onion_address);
    if (slen == 0) {
        node_db_close(&ndb);
        LOG_FAIL("blog", "auto_announce_onion: failed to build node announce script for %s", onion_address);
    }

    memset(&ann, 0, sizeof(ann));
    snprintf(ann.onion_address, sizeof(ann.onion_address), "%s", onion_address);
    {
        size_t off = 0;
        for (size_t i = 0; i < slen && off + 2 < sizeof(ann.script_hex); i++)
            off += (size_t)snprintf(ann.script_hex + off,
                                    sizeof(ann.script_hex) - off,
                                    "%02x", script[i]);
    }

    bool ok = db_onion_announcement_save(&ndb, &ann);
    node_db_close(&ndb);
    return ok;
}
