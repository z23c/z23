/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer secondary-page VIEWS: tokens, token detail, HODL wave, event
 * log, names, market, swaps, messages, and the shared projection-status page.
 * Controllers parse the request, pass the datadir, and delegate page assembly
 * here. */

#include "platform/time_compat.h"
#include "views/explorer_pages_view.h"
#include "controllers/explorer_internal.h"
#include "models/hodl_wave.h"
#include "services/hodl_history_service.h"
#include "encoding/utilstrencodings.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/template.h"
#include "views/format_helpers.h"

#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Param validation helper defined in the explorer controller
 * (explorer_controller.c). Forward-declared here so the token-detail
 * view can reject non-printable token-id params before touching the DB. */
bool explorer_param_is_printable_ascii(const char *s);

/* ── Shared projection-status page ────────────────────────── */

size_t explorer_view_loading_placeholder(uint8_t *r, size_t max,
                                          const char *title,
                                          const char *accent,
                                          const char *subtitle)
{
    size_t off = 0;
    APPEND(off, r, max,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n"
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<link rel='stylesheet' href='/explorer/style.css'>"
        "</head><body>" EXPLORER_NAV
        "<div style='max-width:900px;margin:50px auto;color:#ccc'>"
        "<h1 style='font-size:36px;color:%s'>%s</h1>"
        "<p style='font-size:20px;color:#888'>%s</p>"
        "<p style='font-size:16px;color:#777'>The node is still serving "
        "verified chain data; this projection is catching up in the "
        "background.</p>"
        "<div style='display:flex;gap:12px;flex-wrap:wrap;margin-top:22px'>"
        "<a href='/explorer' style='display:inline-block;background:#33ff99;"
        "color:#07130d;padding:10px 14px;border-radius:6px;font-weight:700;"
        "text-decoration:none'>Open blocks</a>"
        "<a href='/api/v1/status' style='display:inline-block;border:1px solid #333;"
        "color:#ddd;padding:10px 14px;border-radius:6px;text-decoration:none'>"
        "Open node status JSON</a>"
        "</div>"
        "</div>" EXPLORER_FOOTER,
        accent, title, subtitle);
    return off;
}

/* ── Shared error-page emitter ────────────────────────────────── */

size_t explorer_emit_error_page(uint8_t *out, size_t max,
                                 int http_status,
                                 const char *title,
                                 const char *message)
{
    if (!out || max < 1) return 0;

    const char *status_line = NULL;
    switch (http_status) {
        case 404: status_line = "HTTP/1.1 404 Not Found"; break;
        case 500: status_line = "HTTP/1.1 500 Internal Server Error"; break;
        case 503: status_line = "HTTP/1.1 503 Service Unavailable"; break;
        default: status_line = "HTTP/1.1 500 Internal Server Error"; break;
    }

    size_t off = 0;
    APPEND(off, out, max,
        "%s\r\nContent-Type: text/html; charset=utf-8\r\n"
        "Connection: close\r\n\r\n"
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<link rel='stylesheet' href='/explorer/style.css'>"
        "</head><body>" EXPLORER_NAV
        "<div style='max-width:900px;margin:50px auto;color:#ccc'>"
        "<h1>%s</h1>"
        "<p>%s</p>"
        "<div style='margin-top:20px'>"
        "<a href='/explorer' style='display:inline-block;background:#33ff99;"
        "color:#07130d;padding:10px 14px;border-radius:6px;font-weight:700;"
        "text-decoration:none'>Back to Explorer</a>"
        "</div></div>" EXPLORER_FOOTER,
        status_line,
        title ? title : "Error",
        message ? message : "An error occurred");
    return off;
}

/* Reverse a 64-char big-endian hex txid/token-id into display byte order
 * and lowercase it. out must be >= 65 bytes. Returns false (out empty) if
 * the input isn't exactly 64 hex chars. */
static bool explorer_reverse_hex_lower(const char *hex_in, char *out)
{
    out[0] = '\0';
    if (!hex_in || strlen(hex_in) != 64) return false;
    for (int k = 0; k < 32; k++) {
        out[k*2]     = hex_in[62 - k*2];
        out[k*2 + 1] = hex_in[63 - k*2];
    }
    out[64] = '\0';
    for (int k = 0; k < 64; k++)
        if (out[k] >= 'A' && out[k] <= 'F')
            out[k] += 32;
    return true;
}

/* ── ZSLP Tokens Page ─────────────────────────────────────── */

size_t explorer_view_tokens(const char *datadir, uint8_t *r, size_t max)
{
    if (!datadir || !r) return 0;

    sqlite3 *db = NULL;
    if (!explorer_open_readonly_db(datadir, &db)) {
        LOG_ERR("explorer", "explorer_view_tokens: failed to open db");
        return explorer_emit_error_page(r, max, 500, "Database Error", "Failed to open block index");
    }
    size_t off = 0;

    APPEND(off, r, max, EXPLORER_HEADER("ZSLP Tokens"));
    off += explorer_emit_nav((char *)r + off, max - off, "tokens");

    /* Count tokens and transfers */
    struct explorer_token_stats token_stats = {0};
    explorer_query_token_stats(db, &token_stats);
    int64_t token_count = token_stats.token_count;
    int64_t xfer_count = token_stats.transfer_count;

    APPEND(off, r, max,
        "<h1>ZSLP Tokens</h1>"
        "<div class='stats-row'>"
        "<div class='stat'><div class='num'>%" PRId64 "</div><div class='lbl'>Tokens Created</div></div>"
        "<div class='stat'><div class='num'>%" PRId64 "</div><div class='lbl'>Token Transfers</div></div>"
        "</div>"
        "<p style='color:#aaa;font-size:16px'>"
        "Simple Ledger Protocol (ZSLP) tokens on the ZClassic blockchain.</p>",
        token_count, xfer_count);

    /* Token list from SQLite */
    APPEND(off, r, max,
        "<h2>All Tokens (%" PRId64 ")</h2>"
        "<table><tr><th>Ticker</th><th>Name</th><th>Decimals</th>"
        "<th>Supply</th><th>Block</th></tr>",
        token_count);
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT ticker, name, decimals, total_minted, genesis_height, hex(token_id)"
                " FROM zslp_tokens ORDER BY genesis_height LIMIT 100",
                -1, &s, NULL) == SQLITE_OK) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW && off + 512 < max) {
                const char *ticker = (const char *)sqlite3_column_text(s, 0);
                const char *name = (const char *)sqlite3_column_text(s, 1);
                int dec = sqlite3_column_int(s, 2);
                int64_t minted = sqlite3_column_int64(s, 3);
                int height = sqlite3_column_int(s, 4);
                const char *tid_hex = (const char *)sqlite3_column_text(s, 5);

                char safe_ticker[128] = "", safe_name[256] = "";
                html_escape(safe_ticker, sizeof(safe_ticker), ticker ? ticker : "");
                html_escape(safe_name, sizeof(safe_name), name ? name : "");

                /* Format supply with decimals */
                char supply[64];
                if (dec > 0 && dec <= 8) {
                    int64_t divisor = zcl_pow10(dec);
                    snprintf(supply, sizeof(supply), "%" PRId64 ".%0*" PRId64,
                             minted / divisor, dec, minted % divisor);
                } else {
                    snprintf(supply, sizeof(supply), "%" PRId64, minted);
                }

                /* Build linkable token ID (reverse byte order for display) */
                char tid_link[65] = "";
                explorer_reverse_hex_lower(tid_hex, tid_link);

                APPEND(off, r, max,
                    "<tr><td style='font-size:18px'>"
                    "<a href='/explorer/token/%s' style='color:#ff99ff;font-weight:700'>%s</a></td>"
                    "<td>%s</td>"
                    "<td>%d</td>"
                    "<td class='amount'>%s</td>"
                    "<td><a href='/explorer/block/%d'>%d</a></td></tr>",
                    tid_link, safe_ticker[0] ? safe_ticker : "(none)",
                    safe_name, dec, supply, height, height);
            }
            sqlite3_finalize(s);
        }
    }
    APPEND(off, r, max, "</table>");

    /* Recent transfers */
    APPEND(off, r, max,
        "<h2>Recent Transfers</h2>"
        "<table><tr><th>Block</th><th>Type</th><th>Token</th>"
        "<th>Amount</th></tr>");
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT x.block_height, x.tx_type, x.amount, t.ticker, t.decimals "
                "FROM zslp_transfers x "
                "LEFT JOIN zslp_tokens t ON x.token_id = t.token_id "
                "ORDER BY x.block_height DESC LIMIT 50",
                -1, &s, NULL) == SQLITE_OK) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW && off + 256 < max) {
                int height = sqlite3_column_int(s, 0);
                int tx_type = sqlite3_column_int(s, 1);
                int64_t amount = sqlite3_column_int64(s, 2);
                const char *ticker = (const char *)sqlite3_column_text(s, 3);
                int dec = sqlite3_column_int(s, 4);

                const char *type_str = tx_type == 1 ? "GENESIS" :
                                       tx_type == 2 ? "MINT" :
                                       tx_type == 3 ? "SEND" : "?";
                const char *type_class = tx_type == 1 ? "tag-cb" :
                                         tx_type == 2 ? "tag-shielded" : "tag-slp";

                char amt[64];
                if (dec > 0 && dec <= 8) {
                    int64_t divisor = zcl_pow10(dec);
                    snprintf(amt, sizeof(amt), "%" PRId64 ".%0*" PRId64,
                             amount / divisor, dec, amount % divisor);
                } else {
                    snprintf(amt, sizeof(amt), "%" PRId64, amount);
                }

                char safe_ticker[64] = "";
                html_escape(safe_ticker, sizeof(safe_ticker), ticker ? ticker : "");

                APPEND(off, r, max,
                    "<tr><td><a href='/explorer/block/%d'>%d</a></td>"
                    "<td><span class='tag %s'>%s</span></td>"
                    "<td style='color:#ff99ff'>%s</td>"
                    "<td class='amount'>%s</td></tr>",
                    height, height, type_class, type_str,
                    safe_ticker[0] ? safe_ticker : "?", amt);
            }
            sqlite3_finalize(s);
        }
    }
    APPEND(off, r, max, "</table>");

    /* About section */
    APPEND(off, r, max,
        "<h2>About ZSLP</h2>"
        "<div class='card'>"
        "<p style='font-size:16px;line-height:1.8'>"
        "ZSLP (ZClassic Simple Ledger Protocol) enables custom tokens on the ZClassic blockchain. "
        "Based on the SLP specification, tokens are encoded in "
        "OP_RETURN outputs with no consensus changes required.</p>"
        "<div class='grid' style='margin-top:12px'>"
        "<div class='label'>GENESIS</div><div class='val'>Create a new token (ticker, name, supply, decimals)</div>"
        "<div class='label'>SEND</div><div class='val'>Transfer tokens between addresses</div>"
        "<div class='label'>MINT</div><div class='val'>Create additional supply (if baton exists)</div>"
        "<div class='label'>Token ID</div><div class='val'>The GENESIS transaction hash uniquely identifies each token</div>"
        "<div class='label'>Lokad ID</div><div class='val'><code>SLP\\x00</code> (0x534c5000) in OP_RETURN</div>"
        "</div></div>");

    APPEND(off, r, max, EXPLORER_FOOTER);

    sqlite3_close(db);
    return off;
}

/* ── ZSLP Token Detail Page ────────────────────────────────── */

size_t explorer_view_token_detail(const char *token_id_hex,
                                   const char *datadir,
                                   uint8_t *r, size_t max)
{
    if (!zcl_is_hex_string(token_id_hex, 64) || !datadir ||
        !explorer_param_is_printable_ascii(token_id_hex))
        return 0;

    /* Open our own SQLite connection (called from HTTPS thread) */
    sqlite3 *db = NULL;
    if (!explorer_open_readonly_db(datadir, &db)) {
        LOG_ERR("explorer", "explorer_view_token_detail: failed to open db");
        return explorer_emit_error_page(r, max, 500, "Database Error", "Failed to open block index");
    }
    /* Parse hex token ID — try direct first, then reversed byte order */
    uint8_t token_id[32];
    uint8_t token_id_rev[32];
    if (ParseHex(token_id_hex, token_id, 32) != 32) {
        sqlite3_close(db);
        return 0;
    }
    for (int i = 0; i < 32; i++)
        token_id_rev[31 - i] = token_id[i];

    /* Look up token — try both byte orders */
    char ticker[64] = "", name[128] = "", doc_url[256] = "";
    int decimals = 0, genesis_height = 0;
    int64_t total_minted = 0;
    bool found = false;

    /* Try direct byte order first, then reversed */
    const uint8_t *lookup_id = token_id;
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT ticker, name, decimals, document_url, genesis_height, total_minted "
                "FROM zslp_tokens WHERE token_id = ?",
                -1, &s, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(s, 1, token_id, 32, SQLITE_STATIC);
            bool have_row = (AR_STEP_ROW_READONLY(s) == SQLITE_ROW);
            if (!have_row) {
                /* Try reversed */
                sqlite3_reset(s);
                sqlite3_bind_blob(s, 1, token_id_rev, 32, SQLITE_STATIC);
                if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                    have_row = true;
                    lookup_id = token_id_rev;
                }
            }
            /* Only read columns when a row is actually current: with no
             * SQLITE_ROW the column accessors return NULL/garbage. */
            if (have_row && sqlite3_column_text(s, 0)) {
                const char *t = (const char *)sqlite3_column_text(s, 0);
                const char *n = (const char *)sqlite3_column_text(s, 1);
                const char *u = (const char *)sqlite3_column_text(s, 3);
                if (t) snprintf(ticker, sizeof(ticker), "%s", t);
                if (n) snprintf(name, sizeof(name), "%s", n);
                if (u) snprintf(doc_url, sizeof(doc_url), "%s", u);
                decimals = sqlite3_column_int(s, 2);
                genesis_height = sqlite3_column_int(s, 4);
                total_minted = sqlite3_column_int64(s, 5);
                found = true;
            }
            sqlite3_finalize(s);
        }
    }

    if (!found) {
        sqlite3_close(db);
        char msg[256];
        snprintf(msg, sizeof(msg), "No ZSLP token with ID: <code>%s</code>", token_id_hex ? token_id_hex : "");
        return explorer_emit_error_page(r, max, 404, "Token Not Found", msg);
    }

    size_t off = 0;
    char safe_ticker[128], safe_name[256], safe_url[512];
    html_escape(safe_ticker, sizeof(safe_ticker), ticker);
    html_escape(safe_name, sizeof(safe_name), name);
    html_escape(safe_url, sizeof(safe_url), doc_url);

    char supply[64];
    if (decimals > 0 && decimals <= 8) {
        int64_t divisor = zcl_pow10(decimals);
        snprintf(supply, sizeof(supply), "%" PRId64 ".%0*" PRId64,
                 total_minted / divisor, decimals, total_minted % divisor);
    } else {
        snprintf(supply, sizeof(supply), "%" PRId64, total_minted);
    }

    /* Count transfers for this token */
    int64_t xfer_count = 0;
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT count(*) FROM zslp_transfers WHERE token_id = ?",
                -1, &s, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(s, 1, lookup_id, 32, SQLITE_STATIC);
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
                xfer_count = sqlite3_column_int64(s, 0);
            sqlite3_finalize(s);
        }
    }

    APPEND(off, r, max, EXPLORER_HEADER("Token"));
    off += explorer_emit_nav((char *)r + off, max - off, "tokens");

    /* Token header */
    APPEND(off, r, max,
        "<h1 style='color:#ff99ff'>%s</h1>"
        "<h2>%s</h2>"
        "<div class='card'><div class='grid'>"
        "<div class='label'>Token ID</div><div class='val hash' style='font-size:13px'>%s</div>"
        "<div class='label'>Ticker</div><div class='val' style='color:#ff99ff;font-weight:700;font-size:20px'>%s</div>"
        "<div class='label'>Name</div><div class='val'>%s</div>"
        "<div class='label'>Decimals</div><div class='val'>%d</div>"
        "<div class='label'>Total Supply</div><div class='val amount' style='font-size:20px'>%s</div>"
        "<div class='label'>Genesis Block</div><div class='val'><a href='/explorer/block/%d'>%d</a></div>"
        "<div class='label'>Genesis TX</div><div class='val hash'><a href='/explorer/tx/%s'>%s</a></div>"
        "<div class='label'>Transfers</div><div class='val'>%" PRId64 "</div>",
        safe_ticker[0] ? safe_ticker : "(unnamed)",
        safe_name[0] ? safe_name : "ZSLP Token",
        token_id_hex,
        safe_ticker[0] ? safe_ticker : "(none)",
        safe_name, decimals, supply,
        genesis_height, genesis_height,
        token_id_hex, token_id_hex,
        xfer_count);

    if (safe_url[0])
        APPEND(off, r, max,
            "<div class='label'>Document URL</div><div class='val'>%s</div>",
            safe_url);

    APPEND(off, r, max, "</div></div>");

    /* Transfer history */
    APPEND(off, r, max,
        "<h2>Transfer History (%" PRId64 ")</h2>"
        "<table><tr><th>Block</th><th>Type</th><th>Amount</th></tr>",
        xfer_count);
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT block_height, tx_type, amount, hex(txid) "
                "FROM zslp_transfers WHERE token_id = ? "
                "ORDER BY block_height DESC LIMIT 100",
                -1, &s, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(s, 1, lookup_id, 32, SQLITE_STATIC);
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW && off + 512 < max) {
                int height = sqlite3_column_int(s, 0);
                int tx_type = sqlite3_column_int(s, 1);
                int64_t amount = sqlite3_column_int64(s, 2);
                const char *txid_hex = (const char *)sqlite3_column_text(s, 3);

                const char *type_str = tx_type == 1 ? "GENESIS" :
                                       tx_type == 2 ? "MINT" :
                                       tx_type == 3 ? "SEND" : "?";
                const char *type_class = tx_type == 1 ? "tag-cb" :
                                         tx_type == 2 ? "tag-shielded" : "tag-slp";

                char amt[64];
                if (decimals > 0 && decimals <= 8) {
                    int64_t divisor = zcl_pow10(decimals);
                    snprintf(amt, sizeof(amt), "%" PRId64 ".%0*" PRId64,
                             amount / divisor, decimals, amount % divisor);
                } else {
                    snprintf(amt, sizeof(amt), "%" PRId64, amount);
                }

                /* Reverse txid for display */
                char txid_disp[65] = "";
                explorer_reverse_hex_lower(txid_hex, txid_disp);
                char short_tx[18];
                snprintf(short_tx, sizeof(short_tx), "%.8s...%.4s",
                         txid_disp, txid_disp + 60);

                APPEND(off, r, max,
                    "<tr><td><a href='/explorer/block/%d'>%d</a></td>"
                    "<td><span class='tag %s'>%s</span></td>"
                    "<td class='amount'>%s</td></tr>",
                    height, height, type_class, type_str, amt);
            }
            sqlite3_finalize(s);
        }
    }
    APPEND(off, r, max, "</table>");

    APPEND(off, r, max, EXPLORER_FOOTER);
    sqlite3_close(db);
    return off;
}

/* ── Event Log Page ───────────────────────────────────────── */

size_t explorer_view_events(uint8_t *r, size_t max)
{
    size_t off = 0;
    char *response = (char *)r;

    APPEND(off, response, max, EXPLORER_HEADER("Event Log — Z23"));
    off += explorer_emit_nav(response + off, max - off, "events");

    APPEND(off, response, max,
        "<div class='content'>"
        "<h1>Event Log</h1>"
        "<p style='color:#888'>Live node events from the ring buffer.</p>"
        "<div style='margin:10px 0'>"
        "<label style='color:#aaa'>Show: </label>"
        "<select id='ev-count' style='background:#1a1a2e;color:#eee;border:1px solid #333;"
        "padding:4px 8px;border-radius:4px'>"
        "<option value='50'>50</option>"
        "<option value='100' selected>100</option>"
        "<option value='500'>500</option>"
        "<option value='2000'>2000</option>"
        "</select>"
        "<label style='color:#aaa;margin-left:16px'>Filter: </label>"
        "<input id='ev-filter' placeholder='type, peer, or data...' "
        "style='background:#1a1a2e;color:#eee;border:1px solid #333;"
        "padding:4px 8px;border-radius:4px;width:200px'>"
        "<span id='ev-status' style='color:#555;margin-left:16px;font-size:13px'>"
        "loading...</span>"
        "</div>"
        "<table class='block-table' style='font-size:13px'>"
        "<thead><tr>"
        "<th style='width:60px'>Seq</th>"
        "<th style='width:170px'>Time</th>"
        "<th style='width:180px'>Type</th>"
        "<th style='width:60px'>Peer</th>"
        "<th>Data</th>"
        "</tr></thead>"
        "<tbody id='ev-body'></tbody></table></div>");

    APPEND(off, response, max,
        "<script>"
        "const tbody=document.getElementById('ev-body'),"
        "sel=document.getElementById('ev-count'),"
        "flt=document.getElementById('ev-filter'),"
        "sts=document.getElementById('ev-status');"
        "function fmt(ts){"
        "const d=new Date(ts/1000);"
        "return d.toISOString().replace('T',' ').replace('Z','')}"
        "function cls(t){"
        "if(t.startsWith('val.'))return'color:#ff6b6b';"
        "if(t.startsWith('sync.'))return'color:#ffd93d';"
        "if(t.startsWith('peer.'))return'color:#6bcb77';"
        "if(t.startsWith('tcp.'))return'color:#4d96ff';"
        "if(t.startsWith('snap.'))return'color:#ff922b';"
        "if(t.startsWith('chain.'))return'color:#cc5de8';"
        "if(t.startsWith('tx.'))return'color:#66d9e8';"
        "if(t.startsWith('sys.'))return'color:#ff8787';"
        "return'color:#aaa'}"
        "function esc(s){const d=document.createElement('div');"
        "d.textContent=s;return d.innerHTML}"
        "async function refresh(){"
        "try{"
        "const r=await fetch('/api/events?count='+sel.value);"
        "const evs=await r.json();"
        "const f=flt.value.toLowerCase();"
        "let html='';"
        "for(let i=evs.length-1;i>=0;i--){"
        "const e=evs[i];"
        "if(f&&!(e.type+' '+e.peer+' '+e.data).toLowerCase().includes(f))continue;"
        "html+='<tr><td>'+e.seq+'</td>"
        "<td>'+fmt(e.ts)+'</td>"
        "<td style=\"'+cls(e.type)+'\">'+esc(e.type)+'</td>"
        "<td>'+(e.peer||'')+'</td>"
        "<td style=\"font-family:monospace;font-size:12px;word-break:break-all\">"
        "'+esc(e.data)+'</td></tr>'}"
        "tbody.innerHTML=html;"
        "sts.textContent=evs.length+' events ('+new Date().toLocaleTimeString()+')';"
        "}catch(e){sts.textContent='Error: '+e.message}}"
        "refresh();"
        "setInterval(refresh,3000);"
        "sel.onchange=refresh;"
        "flt.oninput=refresh;"
        "</script>");

    APPEND(off, response, max, EXPLORER_FOOTER);
    return off;
}

/* ── Names Page ──────────────────────────────────────────── */

size_t explorer_view_names(uint8_t *r, size_t max)
{
    size_t off = 0;
    char *response = (char *)r;

    APPEND(off, response, max, EXPLORER_HEADER("ZCL Names — Z23"));
    off += explorer_emit_nav(response + off, max - off, "names");

    APPEND(off, response, max,
        "<div class='content'>"
        "<h1>ZCL Names</h1>"
        "<p style='color:#888'>On-chain name registry (ZNAM protocol). "
        "Names map to .onion addresses, z-addresses, t-addresses, "
        "and multi-coin records.</p>"
        "<div style='margin:12px 0;display:flex;gap:8px;align-items:center'>"
        "<input id='name-search' placeholder='Resolve a name...' "
        "style='background:#1a1a2e;color:#eee;border:1px solid #333;"
        "padding:6px 12px;border-radius:4px;width:200px;font-size:14px'>"
        "<button onclick='resolve()' style='background:#33ff99;color:#000;"
        "border:none;padding:6px 16px;border-radius:4px;font-weight:600;"
        "cursor:pointer'>Resolve</button>"
        "<span id='resolve-result' style='color:#888;font-size:13px'></span>"
        "</div>"
        "<table class='block-table'>"
        "<thead><tr>"
        "<th>Name</th>"
        "<th>Type</th>"
        "<th>Target</th>"
        "<th>Owner</th>"
        "<th>Height</th>"
        "</tr></thead>"
        "<tbody id='names-body'><tr><td colspan='5' style='color:#555'>"
        "Loading...</td></tr></tbody></table></div>"
        "<script>"
        "function esc(s){const d=document.createElement('div');"
        "d.textContent=s==null?'':String(s);return d.innerHTML}"
        "async function load(){"
        "try{"
        "const r=await fetch('/api/names');"
        "const names=await r.json();"
        "const tb=document.getElementById('names-body');"
        "if(!names.length){tb.innerHTML='<tr><td colspan=5 style=\"color:#555\">"
        "No names registered yet</td></tr>';return}"
        "let h='';"
        "for(const n of names){"
        "h+='<tr><td style=\"color:#33ff99;font-weight:600\">'+esc(n.name)+'</td>"
        "<td>'+esc(n.type)+'</td>"
        "<td style=\"font-family:monospace;font-size:12px;word-break:break-all\">"
        "'+esc(n.value)+'</td>"
        "<td style=\"font-family:monospace;font-size:11px\">'+esc((n.owner||'').slice(0,16))+'...</td>"
        "<td>'+esc(n.reg_height)+'</td></tr>'}"
        "tb.innerHTML=h"
        "}catch(e){document.getElementById('names-body').innerHTML="
        "'<tr><td colspan=5 style=\"color:#f66\">Error: '+esc(e.message)+'</td></tr>'}}"
        "load();"
        "async function resolve(){"
        "const n=document.getElementById('name-search').value.trim();"
        "const rs=document.getElementById('resolve-result');"
        "if(!n){rs.textContent='Enter a name';return}"
        "try{"
        "const r=await fetch('/api/name/'+encodeURIComponent(n));"
        "if(!r.ok){rs.innerHTML='<span style=\"color:#f66\">Not found</span>';return}"
        "const d=await r.json();"
        "rs.innerHTML='<span style=\"color:#33ff99\">'+esc(d.name)+'</span> &rarr; "
        "<span style=\"font-family:monospace;font-size:12px\">'+esc(d.value)+'</span> "
        "('+esc(d.type)+')';"
        "}catch(e){rs.textContent='Error: '+e.message}}"
        "document.getElementById('name-search').addEventListener('keyup',"
        "function(e){if(e.key==='Enter')resolve()});"
        "</script>");

    APPEND(off, response, max, EXPLORER_FOOTER);
    return off;
}

/* ── Market Page ─────────────────────────────────────────── */

size_t explorer_view_market(uint8_t *r, size_t max)
{
    size_t off = 0;
    char *response = (char *)r;

    APPEND(off, response, max, EXPLORER_HEADER("ZCL Market — Z23"));
    off += explorer_emit_nav(response + off, max - off, "market");

    APPEND(off, response, max,
        "<div class='content'>"
        "<h1>ZCL Market</h1>"
        "<p style='color:#888'>Decentralized file marketplace. "
        "Seeders announce files, downloaders pay in shielded ZCL per chunk.</p>"
        "<table class='block-table'>"
        "<thead><tr>"
        "<th>Filename</th>"
        "<th>Size</th>"
        "<th>Price/MB</th>"
        "<th>Chunks</th>"
        "<th>Last Seen</th>"
        "</tr></thead>"
        "<tbody id='market-body'><tr><td colspan='5' style='color:#555'>"
        "Loading...</td></tr></tbody></table></div>"
        "<script>"
        "function esc(s){const d=document.createElement('div');"
        "d.textContent=s==null?'':String(s);return d.innerHTML}"
        "async function load(){"
        "try{"
        "const r=await fetch('/api/market');"
        "const files=await r.json();"
        "const tb=document.getElementById('market-body');"
        "if(!files.length){tb.innerHTML='<tr><td colspan=5 style=\"color:#555\">"
        "No files available</td></tr>';return}"
        "let h='';"
        "for(const f of files){"
        "const sz=f.size_mb?f.size_mb.toFixed(1)+' MB':Math.round(f.size_bytes/1024)+' KB';"
        "const pr=f.price_per_mb_zcl?f.price_per_mb_zcl.toFixed(4)+' ZCL':'free';"
        "const t=f.last_seen?new Date(f.last_seen*1000).toLocaleString():'—';"
        "h+='<tr><td style=\"color:#33ff99\">'+esc(f.filename)+'</td>"
        "<td>'+sz+'</td><td>'+pr+'</td>"
        "<td>'+esc(f.num_chunks)+'</td><td>'+t+'</td></tr>'}"
        "tb.innerHTML=h"
        "}catch(e){document.getElementById('market-body').innerHTML="
        "'<tr><td colspan=5 style=\"color:#f66\">Error: '+esc(e.message)+'</td></tr>'}}"
        "load();setInterval(load,10000)"
        "</script>");

    APPEND(off, response, max, EXPLORER_FOOTER);
    return off;
}

/* ── Swaps Page ──────────────────────────────────────────── */

size_t explorer_view_swaps(uint8_t *r, size_t max)
{
    size_t off = 0;
    char *response = (char *)r;

    APPEND(off, response, max, EXPLORER_HEADER("Atomic Swaps — Z23"));
    off += explorer_emit_nav(response + off, max - off, "swaps");

    APPEND(off, response, max,
        "<div class='content'>"
        "<h1>Atomic Swaps</h1>"
        "<p style='color:#888'>HTLC cross-chain contracts (dcrdex-compatible). "
        "Supports ZCL, BTC, LTC, DOGE.</p>"
        "<div style='margin:10px 0'>"
        "<span id='chains' style='color:#555'>Loading chains...</span></div>"
        "<table class='block-table'>"
        "<thead><tr>"
        "<th>Swap ID</th>"
        "<th>Chain</th>"
        "<th>Role</th>"
        "<th>State</th>"
        "<th>Amount</th>"
        "<th>Locktime</th>"
        "<th>P2SH Address</th>"
        "</tr></thead>"
        "<tbody id='swaps-body'><tr><td colspan='7' style='color:#555'>"
        "Loading...</td></tr></tbody></table></div>"
        "<script>"
        "function esc(s){const d=document.createElement('div');"
        "d.textContent=s==null?'':String(s);return d.innerHTML}"
        "async function load(){"
        "try{"
        "const[sr,cr]=await Promise.all(["
        "fetch('/api/swaps'),fetch('/api/swap_chains')]);"
        "const swaps=(await sr.json()).swaps||[];"
        "const chains=await cr.json();"
        "document.getElementById('chains').innerHTML="
        "'Supported: '+chains.map(c=>"
        "'<span style=\"color:#33ff99;margin-right:8px\">'+esc(c.ticker)+'</span>').join('');"
        "const tb=document.getElementById('swaps-body');"
        "if(!swaps.length){tb.innerHTML='<tr><td colspan=7 style=\"color:#555\">"
        "No swaps yet</td></tr>';return}"
        "let h='';"
        "for(const s of swaps){"
        "const st=s.state==='pending'?'color:#ffd93d':s.state==='funded'?'color:#6bcb77':"
        "s.state==='redeemed'?'color:#33ff99':'color:#888';"
        "h+='<tr><td style=\"font-family:monospace;font-size:11px\">"
        "'+esc((s.swap_id||'').slice(0,12))+'...</td>"
        "<td style=\"font-weight:600\">'+esc(s.chain)+'</td>"
        "<td>'+esc(s.role)+'</td>"
        "<td style=\"'+st+'\">'+esc(s.state)+'</td>"
        "<td>'+esc(s.amount)+' '+esc(s.chain)+'</td>"
        "<td>'+esc(s.locktime)+' blocks</td>"
        "<td style=\"font-family:monospace;font-size:11px\">"
        "'+esc((s.p2sh_address||'').slice(0,16))+'...</td></tr>'}"
        "tb.innerHTML=h"
        "}catch(e){document.getElementById('swaps-body').innerHTML="
        "'<tr><td colspan=7 style=\"color:#f66\">Error: '+esc(e.message)+'</td></tr>'}}"
        "load()"
        "</script>");

    APPEND(off, response, max, EXPLORER_FOOTER);
    return off;
}

/* ── Messages Page ───────────────────────────────────────── */

size_t explorer_view_messages(uint8_t *r, size_t max)
{
    size_t off = 0;
    char *response = (char *)r;

    APPEND(off, response, max, EXPLORER_HEADER("Messages — Z23"));
    off += explorer_emit_nav(response + off, max - off, NULL);

    APPEND(off, response, max,
        "<div class='content'>"
        "<h1>Messages</h1>"
        "<p style='color:#888'>P2P encrypted messaging (ZMSG protocol). "
        "Send messages to peers by ID or by ZCL Name.</p>"
        "<table class='block-table'>"
        "<thead><tr>"
        "<th>Direction</th>"
        "<th>Channel</th>"
        "<th>From/To</th>"
        "<th>Message</th>"
        "<th>Time</th>"
        "</tr></thead>"
        "<tbody id='msg-body'><tr><td colspan='5' style='color:#555'>"
        "Loading...</td></tr></tbody></table></div>"
        "<script>"
        "function esc(s){const d=document.createElement('div');"
        "d.textContent=s==null?'':String(s);return d.innerHTML}"
        "async function load(){"
        "try{"
        "const r=await fetch('/api/messages');"
        "const msgs=await r.json();"
        "const tb=document.getElementById('msg-body');"
        "if(!msgs.length){tb.innerHTML='<tr><td colspan=5 style=\"color:#555\">"
        "No messages yet</td></tr>';return}"
        "let h='';"
        "for(const m of msgs){"
        "const dir=m.direction==='outbound'?"
        "'<span style=\"color:#4d96ff\">&#x2191; sent</span>':"
        "'<span style=\"color:#6bcb77\">&#x2193; received</span>';"
        "const who=m.direction==='outbound'?m.recipient:m.sender;"
        "const body=(m.body||'').length>80?(m.body||'').slice(0,80)+'...':(m.body||'');"
        "const t=new Date(m.timestamp*1000).toLocaleString();"
        "h+='<tr><td>'+dir+'</td>"
        "<td>'+esc(m.channel)+'</td>"
        "<td style=\"font-size:12px\">'+esc(who)+'</td>"
        "<td>'+esc(body)+'</td>"
        "<td style=\"font-size:12px;color:#888\">'+t+'</td></tr>'}"
        "tb.innerHTML=h"
        "}catch(e){document.getElementById('msg-body').innerHTML="
        "'<tr><td colspan=5 style=\"color:#f66\">Error: '+esc(e.message)+'</td></tr>'}}"
        "load();setInterval(load,5000)"
        "</script>");

    APPEND(off, response, max, EXPLORER_FOOTER);
    return off;
}
