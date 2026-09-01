/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Names onion-gateway views. See views/name_gateway_view.h for the
 * rendering rule — the one thing in this file that must not be relaxed. */

#include "views/name_gateway_view.h"
#include "views/name_view.h"
#include "views/site_layout.h"
#include "controllers/name_gateway_controller.h"
#include "util/template.h"      /* html_escape */
#include "util/log_macros.h"
#include "base/safe_alloc.h"

#include <stdio.h>
#include <string.h>

/* Bytes held back at the end of the page buffer for the closing chrome,
 * and at the front of the response buffer for the status/header block. */
#define GW_TAIL_RESERVE   1024u
#define GW_HEADER_RESERVE 640u

/* The relayed frame's box. Emitted as one small <style> in the body rather
 * than a style="" attribute so the rule set is readable in one place; the
 * page links the shared stylesheet (site_emit_head css=NULL) instead of
 * inlining 13 KB of it, because the onion listener's whole response buffer
 * is 64 KiB and the relayed document needs that room. */
#define GW_FRAME_CSS \
    "<style>.zrelay{width:100%;height:70vh;border:1px solid #444;" \
    "background:#fff;display:block}</style>"

/* Every response from this file carries the same hardening. default-src
 * 'none' is inherited by the srcdoc document, so the relayed content
 * cannot fetch, script, submit, or frame anything either. */
#define GW_SECURITY_HEADERS \
    "Content-Security-Policy: default-src 'none'; style-src 'self' " \
    "'unsafe-inline'; frame-src 'self'; form-action 'none'; " \
    "base-uri 'none'; frame-ancestors 'none'\r\n" \
    "X-Content-Type-Options: nosniff\r\n" \
    "Referrer-Policy: no-referrer\r\n" \
    "Cache-Control: no-store\r\n" \
    "X-ZCL-Relay: third-party-content-not-vouched-for\r\n"

static size_t gw_wrap(const char *status, const char *body, size_t body_len,
                      uint8_t *resp, size_t max)
{
    int hn = snprintf((char *)resp, max,
        "HTTP/1.1 %s\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        GW_SECURITY_HEADERS
        "Connection: close\r\n\r\n",
        status, body_len);
    if (hn <= 0 || (size_t)hn >= max) return 0;
    if ((size_t)hn + body_len > max) return 0;
    memcpy(resp + hn, body, body_len);
    return (size_t)hn + body_len;
}

/* The banner that must survive whatever the far side sends. It is emitted
 * before the iframe and cannot be reached from inside it. */
static size_t gw_emit_notice(char *buf, size_t max, const char *safe_name,
                             const char *safe_host)
{
    size_t off = 0;
    SITE_APPEND(off, buf, max,
        "<div class='card'>"
        "<h1>%s</h1>"
        "<p><span class='pill pill-warn'>relayed</span> "
        "This node fetched the page below from <span class='mono'>%s</span> "
        "on your behalf and is showing it to you. <b>It is somebody else's "
        "content. This node does not vouch for it, did not check it, and "
        "has no relationship with whoever published it.</b></p>"
        "<p class='meta'>The frame below is sandboxed: no scripts, no "
        "forms, no network access, no access to this page. Nothing you "
        "type into it reaches anyone. Only this banner and the navigation "
        "above it come from this node.</p>"
        "</div>",
        safe_name, safe_host);
    return off;
}

/* Append the relayed bytes as srcdoc-safe entities. Control characters are
 * dropped (they are a parser-confusion tool, never content), and the five
 * HTML-significant characters are escaped so the parent parser cannot be
 * walked out of the attribute. Stops at `limit`; sets *fit_all. */
static size_t gw_escape_append(char *buf, size_t off, size_t limit,
                               const uint8_t *body, size_t body_len,
                               bool *fit_all)
{
    if (fit_all) *fit_all = true;
    for (size_t i = 0; i < body_len; i++) {
        unsigned char c = body[i];
        const char *esc = NULL;
        size_t elen = 1;
        if (c == 0) continue;
        if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') continue;
        if (c == 0x7f) continue;
        switch (c) {
        case '<':  esc = "&lt;";   elen = 4; break;
        case '>':  esc = "&gt;";   elen = 4; break;
        case '&':  esc = "&amp;";  elen = 5; break;
        case '"':  esc = "&quot;"; elen = 6; break;
        case '\'': esc = "&#39;";  elen = 5; break;
        default: break;
        }
        if (off + elen >= limit) {
            if (fit_all) *fit_all = false;
            break;
        }
        if (esc) { memcpy(buf + off, esc, elen); off += elen; }
        else     { buf[off++] = (char)c; }
    }
    buf[off] = '\0';
    return off;
}

size_t name_gateway_view_page(const char *name, const char *host,
                              const uint8_t *body, size_t body_len,
                              int upstream_status, bool truncated,
                              size_t upstream_bytes,
                              uint8_t *resp, size_t max)
{
    char safe_name[128], safe_host[128];
    char *page;
    size_t page_cap, off, limit, out;
    bool fit_all = true;
    int n;

    if (!resp || max <= GW_HEADER_RESERVE + GW_TAIL_RESERVE) return 0;
    page_cap = max - GW_HEADER_RESERVE;
    page = zcl_malloc(page_cap, "name_gateway_page");
    if (!page) {
        LOG_WARN("name.gateway", "page buffer alloc failed (%zu)", page_cap);
        return 0;
    }

    html_escape(safe_name, sizeof(safe_name), name ? name : "");
    html_escape(safe_host, sizeof(safe_host), host ? host : "");

    off = site_emit_head(page, page_cap, safe_name, NULL, NULL);
    off += site_emit_global_nav(page + off, page_cap - off, "names");
    SITE_APPEND(off, page, page_cap, "%s", GW_FRAME_CSS);
    off += gw_emit_notice(page + off, page_cap - off, safe_name, safe_host);
    SITE_APPEND(off, page, page_cap,
        "<main id='content'>"
        "<iframe class='zrelay' title='Relayed third-party content' "
        "referrerpolicy='no-referrer' sandbox='' srcdoc=\"");

    limit = page_cap - GW_TAIL_RESERVE;
    off = gw_escape_append(page, off, limit, body, body_len, &fit_all);

    SITE_APPEND(off, page, page_cap, "\"></iframe>");
    SITE_APPEND(off, page, page_cap,
        "<p class='meta'>Relayed %zu of %zu byte%s from "
        "<span class='mono'>%s</span> (upstream HTTP %d).%s%s</p>"
        "<p><a href='/names/%s'>What is this name?</a> &middot; "
        "<a href='http://%s/'>Open <span class='mono'>%s</span> directly</a> "
        "(needs a Tor-capable browser) &middot; "
        "<a href='/names'>&larr; all names</a></p>",
        body_len, upstream_bytes ? upstream_bytes : body_len,
        body_len == 1 ? "" : "s", safe_host, upstream_status,
        truncated ? " The page was longer than this node's relay cap and "
                    "was cut short." : "",
        fit_all ? "" : " It was also cut to fit this node's response "
                       "buffer.",
        safe_name, safe_host, safe_host);
    n = name_view_body_end(page + off, page_cap - off);
    if (n > 0) off += (size_t)n;

    out = gw_wrap("200 OK", page, off, resp, max);
    free(page);
    return out;
}

size_t name_gateway_view_unavailable(const char *name, const char *target,
                                     const char *code, const char *message,
                                     const char *http_status,
                                     uint8_t *resp, size_t max)
{
    char body[8192];
    char safe_name[128], safe_target[300], safe_code[64], safe_msg[600];
    size_t off = 0;
    char host[NAME_GATEWAY_HOST_MAX];
    bool dialable;
    int n;

    if (!resp || max == 0) return 0;
    html_escape(safe_name, sizeof(safe_name), name ? name : "");
    html_escape(safe_target, sizeof(safe_target), target ? target : "");
    html_escape(safe_code, sizeof(safe_code), code ? code : "GATEWAY_ERROR");
    html_escape(safe_msg, sizeof(safe_msg), message ? message : "");

    dialable = name_gateway_host_from_target(target, host, sizeof(host));

    off = site_emit_head(body, sizeof(body), safe_name, NULL, "measure");
    off += site_emit_global_nav(body + off, sizeof(body) - off, "names");
    SITE_APPEND(off, body, sizeof(body),
        "<main id='content'>"
        "<h1>%s</h1>"
        "<div class='card'>"
        "<h3>Not relayed <span class='pill pill-warn'>%s</span></h3>"
        "<p>%s</p>"
        "<div class='kv'><b>target</b><span class='val mono'>%s</span></div>",
        safe_name, safe_code, safe_msg, safe_target);
    if (dialable) {
        char safe_host[128];
        html_escape(safe_host, sizeof(safe_host), host);
        SITE_APPEND(off, body, sizeof(body),
            "<p><a href='http://%s/'>Open <span class='mono'>%s</span> "
            "directly</a> — needs a Tor-capable browser.</p>", safe_host,
            safe_host);
    }
    SITE_APPEND(off, body, sizeof(body),
        "<p><a href='/names/%s'>See this name's on-chain record</a> &middot; "
        "<a href='/names'>&larr; all names</a></p></div>", safe_name);
    n = name_view_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;

    return gw_wrap(http_status && http_status[0] ? http_status : "502 Bad Gateway",
                   body, off, resp, max);
}
