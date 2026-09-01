/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: render escaped, proof-oriented HTML for the public Blog resource. */

#include "views/blog_post_view.h"

#include "base/hex.h"
#include "views/format_helpers.h"
#include "views/site_css.h"
#include "views/site_layout.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

struct blog_view_sink {
    char *out;
    size_t capacity;
    size_t used;
    bool ok;
};

static void sink_bytes(struct blog_view_sink *sink,
                       const char *bytes, size_t len)
{
    if (!sink->ok || len > sink->capacity - sink->used - 1) {
        sink->ok = false;
        return;
    }
    memcpy(sink->out + sink->used, bytes, len);
    sink->used += len;
    sink->out[sink->used] = 0;
}

static void sink_literal(struct blog_view_sink *sink, const char *text)
{
    sink_bytes(sink, text, strlen(text));
}

static void sink_format(struct blog_view_sink *sink, const char *fmt, ...)
{
    if (!sink->ok)
        return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(sink->out + sink->used,
                      sink->capacity - sink->used, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sink->capacity - sink->used) {
        sink->ok = false;
        return;
    }
    sink->used += (size_t)n;
}

static void sink_html(struct blog_view_sink *sink, const char *text)
{
    for (const unsigned char *p = (const unsigned char *)text;
         sink->ok && *p; p++) {
        switch (*p) {
        case '&': sink_literal(sink, "&amp;"); break;
        case '<': sink_literal(sink, "&lt;"); break;
        case '>': sink_literal(sink, "&gt;"); break;
        case '"': sink_literal(sink, "&quot;"); break;
        case '\'': sink_literal(sink, "&#39;"); break;
        default: sink_bytes(sink, (const char *)p, 1); break;
        }
    }
}

static const char *view_status_name(enum blog_publication_status status)
{
    switch (status) {
    case BLOG_PUBLICATION_CONFIRMED: return "projection-confirmed";
    case BLOG_PUBLICATION_ORPHANED: return "orphaned";
    case BLOG_PUBLICATION_UNRESOLVED:
    default: return "unresolved";
    }
}

static void blog_document_open(struct blog_view_sink *sink,
                               const char *title)
{
    sink_literal(sink,
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<style>");
    /* The shared design system (contexts/explorer/views/src/site.css), inlined — one
     * round trip over the onion, zero external assets. */
    sink_literal(sink, site_css);
    /* Blog-specific components layered on the shared tokens. */
    sink_literal(sink,
        ".shell{position:relative;width:100%;margin:0 auto}"
        ".gradient{background:linear-gradient(92deg,var(--ink) 10%,var(--accent) 54%,var(--violet));"
        "-webkit-background-clip:text;background-clip:text;color:transparent}"
        ".hero{display:grid;grid-template-columns:minmax(0,1fr) 220px;gap:32px;align-items:end}"
        ".stat{border:1px solid var(--border);border-radius:var(--r-lg);padding:20px;background:var(--panel)}"
        ".stat strong{display:block;font-size:2.2rem;line-height:1;color:var(--ok)}"
        ".stat span{display:block;margin-top:8px;color:var(--muted);font-size:13px}"
        ".section-head{display:flex;justify-content:space-between;gap:20px;align-items:end;margin-bottom:18px}"
        ".section-head h2{margin:0;border-bottom:none;padding-bottom:0}"
        ".arrow{display:grid;place-items:center;width:36px;height:36px;border:1px solid var(--border);"
        "border-radius:50%;color:var(--accent)}"
        ".empty{padding:40px;border:1px dashed var(--border-strong);border-radius:var(--r-lg);"
        "text-align:center;background:var(--panel)}"
        ".article-wrap{width:min(820px,100%);margin:32px auto}"
        ".article-meta{display:flex;flex-wrap:wrap;gap:8px 16px;padding-bottom:20px;"
        "border-bottom:1px solid var(--border)}"
        ".badge{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--border);"
        "border-radius:999px;background:var(--panel-2);padding:4px 10px;color:var(--ink-dim);font-size:12px}"
        ".post-card{display:grid;grid-template-columns:1fr auto;gap:16px;align-items:center}"
        ".hero h1{font-size:clamp(2rem,6vw,3.6rem);letter-spacing:-.03em;line-height:1.05}"
        ".article h1{font-size:clamp(1.8rem,5vw,3rem);letter-spacing:-.025em}"
        "@media(max-width:720px){.hero{grid-template-columns:1fr;gap:20px}"
        ".section-head{flex-direction:column;align-items:start}}"
        "</style><title>");
    sink_html(sink, title);
    sink_literal(sink, "</title></head><body><a class='skip' href='#content'>Skip to content</a>");
}

static void blog_nav(struct blog_view_sink *sink, const char *back_name)
{
    /* Global site nav (shared with explorer/names/store) with Blog active. */
    size_t nav_len = site_emit_global_nav(
        sink->out + sink->used, sink->capacity - sink->used, "blog");
    sink->used += nav_len;
    sink_literal(sink, "<div class='shell'>");
    if (back_name && back_name[0]) {
        sink_literal(sink, "<p><a class='pill pill-info' href='/blog/");
        sink_html(sink, back_name);
        sink_literal(sink, "' aria-label='Back to author blog'>← @");
        sink_html(sink, back_name);
        sink_literal(sink, "</a></p>");
    } else {
        sink_literal(sink, "<p><span class='pill pill-ok'>local sovereign view</span></p>");
    }
}

size_t blog_post_index_view_render(const struct blog_post_index_page *page,
                                   uint8_t *out, size_t out_capacity)
{
    if (!page || !out || out_capacity < 2)
        return 0;
    struct blog_view_sink sink = {
        .out = (char *)out,
        .capacity = out_capacity,
        .used = 0,
        .ok = true,
    };
    sink.out[0] = 0;
    blog_document_open(&sink, page->blog_name[0]
        ? "ZNAM Blog — Z23" : "Z23 Journal");
    blog_nav(&sink, NULL);
    sink_literal(&sink, "<header class='hero'><div><p class='eyebrow'>Wallet-signed publishing demo</p><h1><span class='gradient'>");
    if (page->blog_name[0]) {
        sink_literal(&sink, "Writing by @");
        sink_html(&sink, page->blog_name);
    } else {
        sink_literal(&sink, "Ideas with cryptographic provenance.");
    }
    sink_literal(&sink, "</span></h1><p class='lede'>Portable, verifiable writing rendered directly by a C23 full node. "
                        "Wallet keys establish authorship; ZNAM provides the human identity.</p>"
                        "<div class='chips'><span class='chip'>C23 native</span><span class='chip'>secp256k1 signed</span>"
                        "<span class='chip'>ZNAM named</span><span class='chip'>onion available</span></div></div>"
                        "<aside class='stat' aria-label='Local post count'><strong>");
    sink_format(&sink, "%d", page->count);
    sink_literal(&sink, "</strong><span>canonical post routes in this local view</span></aside></header>"
                        "<main id='content'><div class='section-head'><div><p class='eyebrow'>Local collection</p>"
                        "<h2>Latest accepted events</h2></div><span class='meta'>/blog · clearnet + onion</span></div>");
    if (page->count == 0) {
        sink_literal(&sink, "<div class='empty'><h2>No posts on this node yet</h2>"
                            "<p class='muted'>A verified signed event will appear here after local import.</p></div>");
    } else {
        sink_literal(&sink, "<section class='feed' aria-label='Blog posts'>");
    }
    for (int i = 0; i < page->count && sink.ok; i++) {
        const struct db_blog_post_summary *post = &page->posts[i];
        char when[40];
        zcl_format_time(when, sizeof(when), post->event_created_at);
        sink_literal(&sink, "<a class='post-card' href='/blog/");
        sink_html(&sink, post->blog_name);
        sink_literal(&sink, "/");
        sink_html(&sink, post->slug);
        sink_literal(&sink, "'><article><span class='identity'>@");
        sink_html(&sink, post->blog_name);
        sink_literal(&sink, "</span><h3>");
        sink_html(&sink, post->title);
        sink_format(&sink, "</h3><p class='meta'>sequence %llu · ",
                    (unsigned long long)post->sequence);
        sink_html(&sink, when[0] ? when : "time unavailable");
        sink_literal(&sink, "</p></article><span class='arrow' aria-hidden='true'>→</span></a>");
    }
    if (page->count > 0)
        sink_literal(&sink, "</section>");
    sink_literal(&sink,
        "</main><footer>Content is locally stored and independently verifiable; network anti-entropy remains a separate availability proof. "
        "Mounted at <code>/blog</code> on zclnet.net and participating node onions.</footer></div></body></html>");
    if (!sink.ok) {
        out[0] = 0;
        return 0;
    }
    return sink.used;
}

size_t blog_post_view_render(const struct blog_post_page *page,
                             uint8_t *out, size_t out_capacity)
{
    if (!page || !out || out_capacity < 2)
        return 0;
    struct blog_view_sink sink = {
        .out = (char *)out,
        .capacity = out_capacity,
        .used = 0,
        .ok = true,
    };
    sink.out[0] = 0;
    char event_hex[65], when[40];
    zcl_hex_encode(page->post.event_id, 32, event_hex);
    zcl_format_time(when, sizeof(when), page->post.event_created_at);
    blog_document_open(&sink, page->post.title);
    blog_nav(&sink, page->post.blog_name);
    sink_literal(&sink, "<main id='content' class='article-wrap'><article class='article'><header>"
                        "<p class='eyebrow'>Signed entry · @");
    sink_html(&sink, page->post.blog_name);
    sink_literal(&sink, "</p><h1><span class='gradient'>");
    sink_html(&sink, page->post.title);
    sink_literal(&sink, "</span></h1><div class='article-meta'><span class='badge'>sequence ");
    sink_format(&sink, "%llu", (unsigned long long)page->post.sequence);
    sink_literal(&sink, "</span><time class='badge'>");
    sink_html(&sink, when[0] ? when : "time unavailable");
    sink_literal(&sink, "</time><span class='badge'>author <code>");
    sink_html(&sink, page->post.author_address);
    sink_literal(&sink, "</code></span></div></header><div class='article-body'><pre>");
    sink_html(&sink, page->post.body);
    sink_literal(&sink, "</pre></div><section class='proof' aria-labelledby='proof-title'>"
                        "<p class='eyebrow'>Verification receipt</p><h2 id='proof-title'>What this node can prove</h2>"
                        "<div class='proof-grid'><div class='proof-item'><div class='proof-label good'>"
                        "<span class='status-dot'></span>Signature verified</div>"
                        "<p>The canonical event ID and secp256k1 signature were recomputed for this read.</p></div>"
                        "<div class='proof-item'><div class='proof-label pending-label'><span class='status-dot'></span>"
                        "ZNAM admission observed</div><p>The signer matched this node’s mutable ZNAM projection at import. "
                        "Historical owner-epoch chain proof is still pending.</p></div>");
    if (!page->has_receipt) {
        sink_literal(&sink,
            "<div class='proof-item'><div class='proof-label pending-label'><span class='status-dot'></span>"
            "Chain anchor unresolved</div><p>No fresh exact-script projection match is currently available.</p></div>");
    } else {
        char txid_hex[65], znam_txid_hex[65], observed_when[40];
        zcl_hex_encode(page->receipt.txid, 32, txid_hex);
        zcl_hex_encode(page->receipt.znam_reg_txid, 32, znam_txid_hex);
        zcl_format_time(observed_when, sizeof(observed_when),
                        page->receipt.observed_at);
        sink_format(&sink, "<div class='proof-item'><div class='proof-label %s'>"
                    "<span class='status-dot'></span>Chain %s</div><p>Height %lld · observed ",
                    page->receipt.status == BLOG_PUBLICATION_CONFIRMED
                        ? "good" : "pending-label",
                    view_status_name(page->receipt.status),
                    (long long)page->receipt.block_height);
        sink_html(&sink, observed_when[0] ? observed_when : "time unavailable");
        sink_format(&sink, "<br><code class='hash'>%s</code><br>ZNAM observation <code class='hash'>%s</code></p></div>",
                    txid_hex, znam_txid_hex);
    }
    sink_format(&sink,
        "<div class='proof-item'><div class='proof-label %s'><span class='status-dot'></span>"
        "Served frontier</div><p>served-frontier proof: %s. H* + active-slot/body verification is required.</p></div>"
        "<div class='proof-item'><div class='proof-label %s'><span class='status-dot'></span>"
        "Content %s</div><p>The signed article body is %s on this node; anchoring alone does not provide it.</p></div>"
        "</div><p class='meta' style='margin:18px 0 0'>Event <code class='hash'>%s</code></p>"
        "</section></article></main><footer>Projection evidence is deliberately separated from consensus finality.</footer>"
        "</div></body></html>",
        page->served_frontier_proven ? "good" : "pending-label",
        page->served_frontier_proven ? "proven" : "pending",
        page->content_available ? "good" : "pending-label",
        page->content_available ? "available" : "unavailable",
        page->content_available ? "available" : "unavailable",
        event_hex);
    if (!sink.ok) {
        out[0] = 0;
        return 0;
    }
    return sink.used;
}
