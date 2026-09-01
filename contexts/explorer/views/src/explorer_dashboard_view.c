/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer dashboard VIEW: the /explorer landing page. Renders the
 * four-stat header row and the "Latest Blocks" table in two modes (RPC-proxy
 * and native-chain). The controller parses the request, fetches the data,
 * packs it into the view structs, and delegates the entire HTML/HTTP assembly
 * here. The per-row buffer-bound truncation guards live inside the emit loops. */

#include "platform/time_compat.h"
#include "views/explorer_dashboard_view.h"
#include "controllers/explorer_internal.h"
#include "views/format_helpers.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ── Headline chain-card grid ─────────────────────────────────
 *
 * A responsive, self-contained card grid of the highest-value live stats.
 * Class prefix .chaincard so the inline <style> can't collide with the
 * shared header CSS. Every number is either pulled from the view struct or
 * derived purely from the tip (supply/cap/halving via the consensus-exact
 * helpers in explorer_internal.h), so it is correct by construction. */
static size_t emit_chaincard_grid(uint8_t *r, size_t max, size_t off,
        int tip, double difficulty, int64_t mempool_count,
        int64_t mempool_bytes, int64_t tip_time, double recent_interval)
{
    int64_t mined = zcl_total_supply_zatoshi(tip);
    int64_t cap   = zcl_max_supply_zatoshi();
    double  pct   = cap > 0 ? (double)mined / (double)cap * 100.0 : 0.0;

    char supply_str[24], cap_str[24], solrate_str[32], mp_str[24];
    char bu_str[24], nh_str[24], age_str[40], int_str[32], ht_str[24];
    format_with_commas(ht_str, sizeof(ht_str), tip);
    format_with_commas(supply_str, sizeof(supply_str), mined / 100000000LL);
    format_with_commas(cap_str, sizeof(cap_str), cap / 100000000LL);
    explorer_format_solrate(solrate_str, sizeof(solrate_str),
                            explorer_solrate_from_diff(difficulty, tip));
    format_with_commas(mp_str, sizeof(mp_str), mempool_count);

    int next_h = explorer_next_halving_height(tip);
    int blocks_until = next_h - tip;
    if (blocks_until < 0) blocks_until = 0;
    format_with_commas(bu_str, sizeof(bu_str), blocks_until);
    format_with_commas(nh_str, sizeof(nh_str), next_h);

    int64_t now_w = (int64_t)platform_time_wall_time_t();
    int64_t age = (tip_time > 0 && now_w > tip_time) ? now_w - tip_time : 0;
    if (age <= 0)        snprintf(age_str, sizeof(age_str), "just now");
    else if (age < 3600) snprintf(age_str, sizeof(age_str), "%lldm %llds",
                                  (long long)(age / 60), (long long)(age % 60));
    else                 snprintf(age_str, sizeof(age_str), "%lldh %lldm",
                                  (long long)(age / 3600),
                                  (long long)((age % 3600) / 60));

    if (recent_interval > 0)
        snprintf(int_str, sizeof(int_str), "%.0f s", recent_interval);
    else
        snprintf(int_str, sizeof(int_str), "%d s", explorer_target_spacing(tip));

    APPEND(off, r, max,
        "<style>"
        ".chaincard-grid{display:grid;"
        "grid-template-columns:repeat(auto-fit,minmax(190px,1fr));"
        "gap:12px;margin:16px 0}"
        ".chaincard{background:#111418;border:1px solid #242832;border-radius:8px;"
        "padding:14px 16px}"
        ".chaincard .cv{font-family:ui-monospace,Menlo,monospace;font-size:22px;"
        "font-weight:700;color:#4db8ff;letter-spacing:-.5px}"
        ".chaincard .cl{color:#888;font-size:12px;margin-top:4px;"
        "text-transform:uppercase;letter-spacing:.5px}"
        ".chaincard .cs{color:#666;font-size:12px;margin-top:2px}"
        "</style>"
        "<div class='chaincard-grid'>"
        "<div class='chaincard'><div class='cv'>%s</div>"
        "<div class='cl'>Circulating Supply</div>"
        "<div class='cs'>%.2f%% of %s ZCL cap</div></div>"
        "<div class='chaincard'><div class='cv'>%s</div>"
        "<div class='cl'>Network Solve Rate</div>"
        "<div class='cs'>difficulty %.2f</div></div>"
        "<div class='chaincard'><div class='cv'>%s</div>"
        "<div class='cl'>Blocks to Next Halving</div>"
        "<div class='cs'>at block %s</div></div>"
        "<div class='chaincard'><div class='cv'>%s</div>"
        "<div class='cl'>Avg Block Interval</div>"
        "<div class='cs'>target %ds</div></div>"
        "<div class='chaincard'><div class='cv'>%s</div>"
        "<div class='cl'>Mempool Txs</div>"
        "<div class='cs'>%.1f KB</div></div>"
        "<div class='chaincard'><div class='cv'>%s</div>"
        "<div class='cl'>Chain Tip Age</div>"
        "<div class='cs'>block %s</div></div>"
        "</div>",
        supply_str, pct, cap_str,
        solrate_str, difficulty,
        bu_str, nh_str,
        int_str, explorer_target_spacing(tip),
        mp_str, (double)mempool_bytes / 1024.0,
        age_str, ht_str);
    return off;
}

static size_t emit_bootstrap_peer_band(uint8_t *r, size_t max, size_t off,
        const struct explorer_dashboard_network_view *n)
{
    const char *state =
        (n && n->zclassic23_nodes_seen >= 2) ? "Ready" : "Searching";
    const char *tone =
        (n && n->zclassic23_nodes_seen >= 2) ? "bootstrap-ready" :
                                               "bootstrap-watch";
    size_t peers = n ? n->peer_count : 0;
    size_t z23 = n ? n->zclassic23_peers : 0;
    size_t z23_nodes = n ? n->zclassic23_nodes_seen : 0;
    size_t legacy = n ? n->magicbean_peers : 0;

    APPEND(off, r, max,
        "<style>"
        ".bootstrap-band{display:grid;grid-template-columns:1.4fr repeat(3,1fr);"
        "gap:10px;margin:14px 0 18px;align-items:stretch}"
        ".bootstrap-band .bb{background:#111418;border:1px solid #242832;"
        "border-radius:8px;padding:12px 14px}"
        ".bootstrap-band .bb-title{color:#888;font-size:12px;"
        "text-transform:uppercase;letter-spacing:.5px}"
        ".bootstrap-band .bb-value{font-family:ui-monospace,Menlo,monospace;"
        "font-size:21px;font-weight:700;color:#e8e8e8;margin-top:4px}"
        ".bootstrap-band .bb-note{color:#777;font-size:12px;margin-top:3px}"
        ".bootstrap-band .bootstrap-ready .bb-value{color:#33ff99}"
        ".bootstrap-band .bootstrap-watch .bb-value{color:#ffcc66}"
        "@media(max-width:760px){.bootstrap-band{grid-template-columns:1fr 1fr}"
        ".bootstrap-band .bb-main{grid-column:1/-1}}"
        "</style>"
        "<div class='bootstrap-band'>"
        "<div class='bb bb-main %s'><div class='bb-title'>Z23 Bootstrap</div>"
        "<div class='bb-value'>%s</div>"
        "<div class='bb-note'>verified live peer handshakes</div></div>"
        "<div class='bb'><div class='bb-title'>Connected Peers</div>"
        "<div class='bb-value'>%zu</div><div class='bb-note'>handshakes now</div></div>"
        "<div class='bb bootstrap-ready'><div class='bb-title'>Z23 Nodes</div>"
        "<div class='bb-value'>%zu</div><div class='bb-note'>this node + %zu peer%s</div></div>"
        "<div class='bb'><div class='bb-title'>Legacy Peers</div>"
        "<div class='bb-value'>%zu</div><div class='bb-note'>MagicBean-compatible</div></div>"
        "</div>",
        tone, state, peers, z23_nodes, z23, z23 == 1 ? "" : "s", legacy);
    return off;
}

/* ── Dashboard (RPC proxy mode) ───────────────────────────── */

size_t explorer_dashboard_view_rpc(uint8_t *r, size_t max,
                                   const struct explorer_dashboard_rpc_view *v)
{
    size_t off = 0;

    APPEND(off, r, max, EXPLORER_HEADER("Dashboard"));
    off += explorer_emit_nav((char *)r + off, max - off, "blocks");

    char ht_fmt[32];
    format_with_commas(ht_fmt, sizeof(ht_fmt), v->tip);
    APPEND(off, r, max,
        "<div class='stats-row'>"
        "<div class='stat'><div class='num'>%s</div><div class='lbl'>Block Height</div></div>"
        "<div class='stat'><div class='num'>%.2f</div><div class='lbl'>Difficulty</div></div>"
        "<div class='stat'><div class='num'>%" PRId64 "</div><div class='lbl'>Mempool Txs</div></div>"
        "<div class='stat'><div class='num'>%.1f KB</div><div class='lbl'>Mempool Size</div></div>"
        "</div>",
        ht_fmt, v->difficulty, v->mempool_count, (double)v->mempool_bytes / 1024.0);

    off = emit_chaincard_grid(r, max, off, v->tip, v->difficulty,
                              v->mempool_count, v->mempool_bytes,
                              v->tip_time, v->recent_avg_interval);
    off = emit_bootstrap_peer_band(r, max, off, &v->network);

    /* Latest blocks */
    APPEND(off, r, max,
        "<h2>Latest Blocks</h2>"
        "<table><tr><th>Height</th><th>Hash</th><th>Time</th>"
        "<th>Txs</th><th>Difficulty</th></tr>");

    for (int i = 0; i < v->row_count && off + 600 < max; i++) {
        const struct explorer_dashboard_rpc_row *row = &v->rows[i];
        APPEND(off, r, max,
            "<tr><td><a href='/explorer/block/%d'><b>%d</b></a></td>"
            "<td class='hash'><a href='/explorer/block/%s'>%s</a></td>"
            "<td>%s<br><small style='color:#666'>%s</small></td>"
            "<td>%d</td><td>%.2f</td></tr>",
            row->height, row->height, row->hash, row->short_hash,
            row->ago, row->ts, row->tx_count, row->difficulty);
    }

    APPEND(off, r, max, "</table>" EXPLORER_FOOTER);
    return off;
}

/* ── Dashboard (native chain mode) ───────────────────────── */

size_t explorer_dashboard_view_native(uint8_t *r, size_t max,
                                      const struct explorer_dashboard_native_view *v)
{
    size_t off = 0;

    APPEND(off, r, max, EXPLORER_HEADER("Dashboard"));
    off += explorer_emit_nav((char *)r + off, max - off, "blocks");

    char ht_fmt[32];
    format_with_commas(ht_fmt, sizeof(ht_fmt), v->tip);
    APPEND(off, r, max,
        "<div class='stats-row'>"
        "<div class='stat'><div class='num'>%s</div><div class='lbl'>Block Height</div></div>"
        "<div class='stat'><div class='num'>%.2f</div><div class='lbl'>Difficulty</div></div>"
        "<div class='stat'><div class='num'>%zu</div><div class='lbl'>Mempool Txs</div></div>"
        "<div class='stat'><div class='num'>%.1f KB</div><div class='lbl'>Mempool Size</div></div>"
        "</div>",
        ht_fmt, v->difficulty, v->mempool_count, (double)v->mempool_bytes / 1024.0);

    /* Headline card grid only on page 0 (the landing dashboard); on older
     * pages the "recent interval" / shown rows aren't the chain tip. */
    if (v->page == 0)
        off = emit_chaincard_grid(r, max, off, v->tip, v->difficulty,
                                  (int64_t)v->mempool_count,
                                  (int64_t)v->mempool_bytes,
                                  v->tip_time, v->recent_avg_interval);
    if (v->page == 0)
        off = emit_bootstrap_peer_band(r, max, off, &v->network);

    APPEND(off, r, max,
        "<h2>Latest Blocks</h2>"
        "<table><tr><th>Height</th><th>Hash</th><th>Time</th>"
        "<th>Txs</th><th>Difficulty</th><th>Shielded</th></tr>");

    for (int i = 0; i < v->row_count; i++) {
        const struct explorer_dashboard_native_row *row = &v->rows[i];
        APPEND(off, r, max,
            "<tr><td><a href='/explorer/block/%d'>%s</a></td>"
            "<td class='hash'><a href='/explorer/block/%s'>%s</a></td>"
            "<td>%s</td><td>%u</td><td>%.4f</td><td class='amount'>%s</td></tr>",
            row->height, row->h_fmt, row->hash, row->short_hash,
            row->ts, row->ntx, row->difficulty, row->sapling);

        if (off + 512 >= max) break;
    }

    APPEND(off, r, max, "</table>");

    /* Pagination */
    APPEND(off, r, max, "<div class='pager'>");
    if (v->page > 0)
        APPEND(off, r, max, "<a href='/explorer?page=%d'>&larr; Newer</a>", v->page - 1);
    if (v->end_height > 0)
        APPEND(off, r, max, "<a href='/explorer?page=%d'>Older &rarr;</a>", v->page + 1);
    APPEND(off, r, max, "</div>");

    APPEND(off, r, max, EXPLORER_FOOTER);
    return off;
}
