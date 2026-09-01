/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer HODL-wave VIEW — page assembly.
 *
 * This TU owns the HODL-wave page's HTML/CSS templates, the page view-model,
 * and the public entry point explorer_view_hodl(). The rest of the page group
 * lives beside it (see views/explorer_pages_hodl_internal.h):
 *   - explorer_pages_hodl_snapshot.c verified-snapshot cache + bg refresh
 *   - explorer_pages_hodl_rows.c     survival-row time-series model
 *   - explorer_pages_hodl_chart.c    SVG chart emitters
 * The other explorer secondary pages (tokens, token detail, event log, names,
 * market, swaps, messages, loading placeholder) live in explorer_pages_view.c.
 * explorer_view_hodl is declared in views/explorer_pages_view.h. */

#include "platform/time_compat.h"
#include "views/explorer_pages_view.h"
#include "views/explorer_pages_hodl_internal.h"
#include "controllers/explorer_internal.h"
#include "models/hodl_wave.h"
#include "util/safe_alloc.h"
#include "util/template.h"
#include "views/format_helpers.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── HODL Wave Page ────────────────────────────────────────── */

static const char HODL_VIEW_CSS_BASE[] =
    ".hodl-page{max-width:1160px;margin:0 auto 10px;padding-bottom:4px;}"
    ".hodl-hero{display:flex;justify-content:space-between;gap:22px;"
    "align-items:flex-end;text-align:left;margin:14px auto 18px;"
    "padding:22px 0 18px;border-bottom:1px solid #26313a;}"
    ".hodl-kicker{color:#9bddff;font-size:13px;font-weight:760;"
    "text-transform:uppercase;letter-spacing:0;margin:0 0 8px;}"
    ".hodl-title{color:#f5f7fa;font-family:-apple-system,'Segoe UI',Roboto,"
    "Helvetica,Arial,sans-serif;font-size:40px;font-weight:820;line-height:1.08;"
    "letter-spacing:0;margin:0;max-width:920px;overflow-wrap:break-word;}"
    ".hodl-subtitle{font-size:15px;color:#a9b4bf;margin:9px 0 0;"
    "max-width:760px;line-height:1.55;}"
    ".hodl-hero-badge{flex:0 0 auto;color:#f3d18a;background:#161713;"
    "border:1px solid #3b3320;border-radius:8px;padding:9px 12px;"
    "font-size:13px;font-weight:720;white-space:nowrap;"
    "box-shadow:0 10px 24px rgba(0,0,0,.18);}"
    ".hodl-panel{margin:18px auto;padding:18px;background:#10151a;"
    "border:1px solid #24303a;border-radius:8px;color:#a3adb8;"
    "box-shadow:0 18px 42px rgba(0,0,0,.20);}"
    ".hodl-panel h2{color:#e1e8ee;margin-top:0;border-bottom-color:#242e37;}"
    ".hodl-chart-wrap{max-width:1160px;margin:18px auto;padding:16px;"
    "background:linear-gradient(180deg,#0f1519 0,#090d11 100%);"
    "border:1px solid #2a3741;border-radius:8px;"
    "box-shadow:0 14px 34px rgba(0,0,0,.20);position:relative;"
    "contain:layout paint;isolation:isolate;}"
    ".hodl-chart-head{display:flex;justify-content:space-between;gap:16px;"
    "align-items:flex-start;margin:2px 2px 10px;}"
    ".hodl-chart-title{color:#e1e8ee;margin:0 0 6px;font-size:25px;"
    "line-height:1.2;font-weight:780;letter-spacing:0;}"
    ".hodl-chart-subtitle{margin:0;color:#9aa8b5;font-size:14px;"
    "line-height:1.45;}"
    ".hodl-chart-meta{color:#68717d;font-size:13px;white-space:nowrap;"
    "padding-top:4px;}"
    ".hodl-legend{display:flex;flex-wrap:wrap;gap:12px 22px;"
    "margin:12px 2px 14px;color:#d5dbe3;font-size:13px;}"
    ".hodl-legend-item{display:inline-flex;align-items:center;gap:8px;}"
    ".hodl-legend-swatch{display:inline-block;width:26px;height:4px;"
    "border-radius:999px;}"
    ".hodl-current-strip{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));"
    "gap:10px;margin:0 2px 14px;}"
    ".hodl-current-chip{min-width:0;background:#0b1014;border:1px solid #26343f;"
    "border-left:3px solid var(--c);border-radius:8px;padding:9px 10px;}"
    ".hodl-current-chip span{display:block;color:#9aa8b5;font-size:12px;"
    "line-height:1.2;}"
    ".hodl-current-chip strong{display:block;color:#f2f7f4;font-size:18px;"
    "line-height:1.2;margin-top:3px;font-variant-numeric:tabular-nums;}"
    ".hodl-chart-canvas{overflow-x:auto;-webkit-overflow-scrolling:touch;"
    "touch-action:pan-x pan-y;scrollbar-color:#33414d #0b0f13;"
    "padding-bottom:4px;}"
    ".hodl-chart-canvas::-webkit-scrollbar{height:10px;}"
    ".hodl-chart-canvas::-webkit-scrollbar-track{background:#0b0f13;}"
    ".hodl-chart-canvas::-webkit-scrollbar-thumb{background:#30414e;"
    "border-radius:999px;border:2px solid #0b0f13;}"
    ".hodl-chart-wrap:focus-within{border-color:#365365;"
    "box-shadow:0 18px 46px rgba(0,0,0,.28),0 0 0 1px rgba(98,199,255,.16);}";

static const char HODL_VIEW_CSS_DETAIL[] =
    ".hodl-wave-interactive{position:relative;}"
    ".hodl-svg{width:100%;min-width:0;height:auto;background:transparent;"
    "border:0;border-radius:0;display:block;}"
    ".hodl-survival-svg{min-width:820px;}.hodl-age-svg{min-width:720px;}"
    ".hodl-axis-title{fill:#758290;font-size:11px;font-weight:680;"
    "letter-spacing:0;text-transform:uppercase;}"
    ".hodl-end-label{font-family:-apple-system,'Segoe UI',Roboto,sans-serif;"
    "font-weight:760;paint-order:stroke;stroke:#071016;stroke-width:3px;"
    "stroke-linejoin:round;}"
    ".hodl-series-line{mix-blend-mode:screen;}"
    ".hodl-hover-dot{filter:drop-shadow(0 0 4px rgba(255,255,255,.28));}"
    ".hodl-age-bar{transition:opacity .12s ease,stroke-width .12s ease,"
    "filter .12s ease;}"
    ".hodl-age-hit{cursor:crosshair;}"
    ".hodl-age-hit:focus{outline:none;}"
    ".hodl-stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));"
    "gap:16px;margin-top:18px;}"
    ".hodl-stats .stat{min-width:0;}"
    ".hodl-stats .num{font-size:30px;overflow-wrap:anywhere;"
    "word-break:break-word;}"
    ".hodl-table-wrap{max-width:1000px;margin:18px auto;overflow-x:auto;"
    "background:#0d1218;border:1px solid #22303a;border-radius:8px;}"
    ".hodl-table{min-width:660px;margin:0;}"
    ".hodl-table td,.hodl-table th{white-space:nowrap;}"
    ".hodl-age-key{display:inline-block;width:11px;height:11px;"
    "border-radius:2px;margin-right:8px;}"
    ".hodl-source{max-width:900px;margin:18px auto;color:#9aa3ad;"
    "font-size:16px;line-height:1.7;}"
    "@media (max-width:900px){.hodl-hero{display:block;}.hodl-hero-badge{"
    "display:inline-block;margin-top:12px;}.hodl-title{font-size:36px;}"
    ".hodl-stats{grid-template-columns:repeat(2,minmax(0,1fr));}}"
    "@media (max-width:560px){.hodl-page{max-width:none;}.hodl-hero{"
    "margin:14px auto 10px;padding:12px 0 10px;}.hodl-title{font-size:29px;"
    "line-height:1.14;}"
    ".hodl-subtitle{font-size:15px;}.hodl-panel{padding:12px;}"
    ".hodl-stats{grid-template-columns:1fr;gap:10px;}"
    ".hodl-stats .num{font-size:26px;}.hodl-chart-wrap{margin:14px -10px;"
    "padding:10px;border-left:0;border-right:0;border-radius:0;}"
    ".hodl-chart-head{display:block;margin:0 0 10px;}"
    ".hodl-chart-title{font-size:22px;}.hodl-chart-meta{margin-top:6px;}"
    ".hodl-legend{gap:10px 14px;margin:10px 0 12px;font-size:12px;}"
    ".hodl-current-strip{grid-template-columns:repeat(2,minmax(0,1fr));"
    "gap:8px;margin:0 0 12px;}"
    ".hodl-current-chip{padding:8px 9px;}.hodl-current-chip strong{font-size:16px;}"
    ".hodl-x-tick{display:none;}"
    ".hodl-survival-svg{min-width:660px;}.hodl-age-svg{min-width:620px;}"
    ".hodl-table{min-width:620px;}}"
    "@media (max-width:420px){.hodl-title{font-size:27px;}"
    ".hodl-survival-svg{min-width:620px;}.hodl-age-svg{min-width:590px;}}";

static const char HODL_PAGE_OPEN_TEMPLATE[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Cache-Control: no-store\r\n"
    "Connection: close\r\n\r\n"
    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>HODL Wave</title>"
    "<link rel='icon' type='image/png' href='/explorer/favicon.png'>"
    "<link rel='stylesheet' href='/explorer/style.css'>"
    "<style>{{{css_base}}}{{{css_detail}}}</style>"
    "</head><body>";

static const char HODL_DEGRADED_TEMPLATE[] =
    "<section class='hodl-panel'>"
    "<h1>HODL Wave</h1>"
    "<p>Degraded: {{status}}.</p>"
    "</section></main>";

static const char HODL_WARMING_TEMPLATE[] =
    "<section class='hodl-panel'>"
    "<h1>HODL Wave</h1>"
    "<p>{{status}}.</p>"
    "</section></main>";

static const char HODL_HERO_TEMPLATE[] =
    "<section class='hodl-hero'>"
    "<div>"
    "<div class='hodl-kicker'>HODL Wave</div>"
    "<h1 class='hodl-title'>"
    "{{older_pct}}% held over 1 year"
    "</h1>"
    "<p class='hodl-subtitle'>{{hero_subject}} - {{snapshot_label}} at "
    "block {{tip_height}}</p>"
    "</div>"
    "<div class='hodl-hero-badge'>Transparent UTXO age</div>"
    "</section>";

static const char HODL_STATS_TEMPLATE[] =
    "<div class='stats-row hodl-stats'>"
    "<div class='stat'><div class='num'>{{total_value}}</div>"
    "<div class='lbl'>{{value_label}}</div></div>"
    "<div class='stat'><div class='num'>{{older_value}}</div>"
    "<div class='lbl'>Older than 1 year</div></div>"
    "<div class='stat'><div class='num'>{{total_count}}</div>"
    "<div class='lbl'>UTXOs counted</div></div>"
    "<div class='stat'><div class='num'>{{skipped_rows}}</div>"
    "<div class='lbl'>Rows skipped</div></div>"
    "</div>";

static const char HODL_TABLE_ROW_TEMPLATE[] =
    "<tr><td><span class='hodl-age-key' style='background:{{{color}}}'>"
    "</span>{{{age}}}</td><td>{{count}}</td><td>{{value}} ZCL</td>"
    "<td>{{share}}%</td></tr>";

struct hodl_page_model {
    char older_pct[32];
    char tip_height[32];
    char total_value[64];
    char older_value[64];
    char total_count[32];
    char skipped_rows[32];
    char hero_subject[80];
    char snapshot_label[96];
    char value_label[96];
};

static size_t hodl_append_template(size_t *off, uint8_t *r, size_t max,
                                   const char *tmpl,
                                   const struct template_var *vars,
                                   size_t var_count)
{
    size_t added = 0;
    if (!off || !r || !tmpl || *off >= max)
        return 0;
    added = template_render(tmpl, vars, var_count,
                            (char *)r + *off, max - *off);
    *off += added;
    return added;
}

static void hodl_page_model_init(struct hodl_page_model *m,
                                 const struct hodl_wave_snapshot *hodl,
                                 double older_pct, bool cached_snapshot)
{
    if (!m || !hodl)
        return;
    snprintf(m->older_pct, sizeof(m->older_pct), "%.3f", older_pct);
    snprintf(m->tip_height, sizeof(m->tip_height), "%" PRId64,
             hodl->tip_height);
    zcl_format_zcl(m->total_value, sizeof(m->total_value), hodl->total_value);
    zcl_format_zcl(m->older_value, sizeof(m->older_value),
                   hodl->older_than_1y_value);
    snprintf(m->total_count, sizeof(m->total_count), "%" PRId64,
             hodl->total_count);
    snprintf(m->skipped_rows, sizeof(m->skipped_rows), "%" PRId64,
             hodl->skipped_rows);
    if (cached_snapshot) {
        snprintf(m->hero_subject, sizeof(m->hero_subject),
                 "Transparent UTXO value");
        snprintf(m->snapshot_label, sizeof(m->snapshot_label),
                 "verified cached snapshot");
        snprintf(m->value_label, sizeof(m->value_label),
                 "Transparent UTXO value");
    } else {
        snprintf(m->hero_subject, sizeof(m->hero_subject),
                 "Transparent UTXO value");
        snprintf(m->snapshot_label, sizeof(m->snapshot_label),
                 "current verified snapshot");
        snprintf(m->value_label, sizeof(m->value_label),
                 "Current transparent UTXO value");
    }
}

size_t explorer_view_hodl(const char *datadir, uint8_t *r, size_t max)
{
    sqlite3 *db = NULL;
    size_t off = 0;

    if (!datadir || !explorer_open_readonly_db(datadir, &db)) {
        APPEND(off, r, max, EXPLORER_HEADER("HODL Wave"));
        off += explorer_emit_nav((char *)r + off, max - off, "hodl");
        APPEND(off, r, max,
            "<div style='max-width:900px;margin:40px auto;color:#ccc'>"
            "<h1>HODL Wave</h1>"
            "<p>Database unavailable. This page will not publish cached HODL data.</p>"
            "</div>" EXPLORER_FOOTER);
        return off;
    }

    /* HODL is public chain data, so publish it at the same H* frontier served
     * by getblockcount/getblockhash. The projection DB can be one reducer
     * stage ahead during a tip-finalize hole; those rows are skipped until H*
     * advances instead of being advertised as the live explorer tip. */
    int64_t block_tip =
        sql_query_i64(db, "SELECT COALESCE(MAX(height),0) FROM blocks");
    int64_t utxo_tip = sql_query_i64(db, "SELECT COALESCE(MAX(height),0) FROM utxos");
    int64_t index_tip = block_tip > utxo_tip ? block_tip : utxo_tip;
    int64_t tip = hodl_view_cap_to_served_tip(index_tip);

    struct hodl_wave_snapshot hodl;
    char datadir_key[HODL_VIEW_CACHE_DATADIR_MAX];
    char tip_hash[HODL_VIEW_CACHE_HASH_MAX];
    char cached_hash[HODL_VIEW_CACHE_HASH_MAX];
    bool cacheable = hodl_view_datadir_key(datadir, datadir_key);
    bool cached_snapshot = false;
    bool warming_snapshot = false;
    hodl_view_tip_hash(db, tip, tip_hash);
    bool ok = cacheable &&
        hodl_view_cache_get_verified(db, datadir_key, tip, &hodl,
                                     &cached_snapshot);
    if (!ok && cacheable) {
        ok = hodl_view_disk_cache_load_verified(datadir, db, tip, &hodl,
                                                cached_hash,
                                                &cached_snapshot);
        if (ok)
            hodl_view_cache_put(datadir_key, hodl.tip_height, cached_hash,
                                &hodl);
    }
    if (ok && cached_snapshot && cacheable)
        (void)hodl_view_refresh_start(datadir, datadir_key, tip, tip_hash);
    if (!ok && cacheable && !hodl_view_allow_sync_scan(datadir)) {
        hodl_view_snapshot_base(&hodl, tip);
        snprintf(hodl.status, sizeof(hodl.status),
                 "Building the verified HODL snapshot in the background");
        warming_snapshot = true;
        (void)hodl_view_refresh_start(datadir, datadir_key, tip, tip_hash);
    } else if (!ok) {
        ok = hodl_wave_scan_current_utxos(db, tip, &hodl);
        if (ok && cacheable) {
            hodl_view_cache_put(datadir_key, tip, tip_hash, &hodl);
            hodl_view_disk_cache_save(datadir, tip, tip_hash, &hodl);
        }
    }
    sqlite3_close(db);

    struct template_var open_vars[] = {
        { "css_base", HODL_VIEW_CSS_BASE },
        { "css_detail", HODL_VIEW_CSS_DETAIL },
    };
    hodl_append_template(&off, r, max, HODL_PAGE_OPEN_TEMPLATE,
                         open_vars, sizeof(open_vars) / sizeof(open_vars[0]));
    off += explorer_emit_nav((char *)r + off, max - off, "hodl");
    APPEND(off, r, max, "<main class='hodl-page'>");

    if (!ok) {
        struct template_var degraded_vars[] = {
            { "status", hodl.status },
        };
        hodl_append_template(&off, r, max,
                             warming_snapshot ? HODL_WARMING_TEMPLATE :
                             HODL_DEGRADED_TEMPLATE,
                             degraded_vars,
                             sizeof(degraded_vars) /
                             sizeof(degraded_vars[0]));
        APPEND(off, r, max, EXPLORER_FOOTER);
        return off;
    }

    double older_pct = hodl_wave_older_than_1y_percent(&hodl);
    struct hodl_page_model page_model;
    memset(&page_model, 0, sizeof(page_model));
    hodl_page_model_init(&page_model, &hodl, older_pct, cached_snapshot);

    struct template_var hero_vars[] = {
        { "older_pct", page_model.older_pct },
        { "hero_subject", page_model.hero_subject },
        { "snapshot_label", page_model.snapshot_label },
        { "tip_height", page_model.tip_height },
    };
    hodl_append_template(&off, r, max, HODL_HERO_TEMPLATE,
                         hero_vars, sizeof(hero_vars) / sizeof(hero_vars[0]));
    if (cacheable)
        hodl_emit_survival_chart(&off, r, max, datadir, datadir_key, &hodl);
    hodl_emit_age_distribution_chart(&off, r, max, &hodl, cached_snapshot);

    struct template_var stats_vars[] = {
        { "total_value", page_model.total_value },
        { "value_label", page_model.value_label },
        { "older_value", page_model.older_value },
        { "total_count", page_model.total_count },
        { "skipped_rows", page_model.skipped_rows },
    };
    hodl_append_template(&off, r, max, HODL_STATS_TEMPLATE,
                         stats_vars,
                         sizeof(stats_vars) / sizeof(stats_vars[0]));

    APPEND(off, r, max,
        "<div class='hodl-table-wrap'>"
        "<table class='txlist hodl-table'>"
        "<tr><th>Age</th><th>UTXOs</th><th>Value</th><th>Share</th></tr>");
    for (int b = 0; b < HODL_WAVE_BUCKETS; b++) {
        char val_fmt[64];
        char count_fmt[32];
        char pct_fmt[32];
        zcl_format_zcl(val_fmt, sizeof(val_fmt), hodl.buckets[b].value);
        double pct = hodl.total_value > 0
            ? (double)hodl.buckets[b].value / (double)hodl.total_value * 100.0 : 0.0;
        snprintf(count_fmt, sizeof(count_fmt), "%" PRId64,
                 hodl.buckets[b].count);
        snprintf(pct_fmt, sizeof(pct_fmt), "%.3f", pct);
        struct template_var row_vars[] = {
            { "color", hodl.buckets[b].color },
            { "age", hodl.buckets[b].html_label },
            { "count", count_fmt },
            { "value", val_fmt },
            { "share", pct_fmt },
        };
        hodl_append_template(&off, r, max, HODL_TABLE_ROW_TEMPLATE,
                             row_vars,
                             sizeof(row_vars) / sizeof(row_vars[0]));
    }
    APPEND(off, r, max, "</table></div>");
    APPEND(off, r, max,
        "<p class='hodl-source'>"
        "Source: %s. Metric: UTXO age distribution."
        "</p></main>" EXPLORER_FOOTER,
        cached_snapshot ? "verified cached transparent UTXO set" :
                          "current transparent UTXO set");
    return off;
}
