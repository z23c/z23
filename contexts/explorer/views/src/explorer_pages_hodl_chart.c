/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer HODL-wave VIEW — SVG chart emitters.
 *
 * Part of the HODL-wave page split (see views/explorer_pages_hodl_internal.h):
 * this TU owns the two interactive SVG charts — the survival wave over time and
 * the current age-distribution bars — plus their scaling helpers. The page
 * assembly lives in explorer_pages_hodl.c; the snapshot cache in
 * explorer_pages_hodl_snapshot.c; the survival-row model in
 * explorer_pages_hodl_rows.c. */

#include "views/explorer_pages_hodl_internal.h"
#include "controllers/explorer_internal.h"
#include "models/hodl_wave.h"
#include "util/safe_alloc.h"
#include "views/format_helpers.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int hodl_survival_x(const struct hodl_survival_row *row,
                           int pl, int pw, int64_t h_min, int64_t h_max)
{
    if (!row || h_max <= h_min)
        return pl;
    return pl + (int)((double)(row->height - h_min) /
                      (double)(h_max - h_min) * pw);
}

static int hodl_survival_y(const struct hodl_survival_row *row,
                           int threshold, int pt, int ph)
{
    int pct = row ? row->pct_x1000[threshold] : 0;
    if (pct < 0)
        pct = 0;
    if (pct > 100000)
        pct = 100000;
    return pt + ph - (int)((double)pct / 100000.0 * ph);
}

void hodl_emit_survival_chart(size_t *off, uint8_t *r, size_t max,
                              const char *datadir,
                              const char *datadir_key,
                              const struct hodl_wave_snapshot *hodl)
{
    sqlite3 *db = NULL;
    struct hodl_survival_row *rows = NULL;
    struct hodl_survival_row *fallback_rows = NULL;
    int n = 0;
    char tip_hash[HODL_VIEW_CACHE_HASH_MAX];
    bool history_backed = false;
    bool have_history_rows = false;
    bool have_fallback_rows = false;

    if (!off || !r || !datadir || !datadir_key || !hodl)
        return;
    rows = zcl_calloc(HODL_SURVIVAL_MAX_ROWS, sizeof(*rows),
                      "hodl_survival_rows");
    if (!rows)
        return;
    if (!explorer_open_readonly_db(datadir, &db)) {
        free(rows);
        return;
    }
    hodl_view_tip_hash(db, hodl->tip_height, tip_hash);
    have_history_rows = hodl_load_history_wave_rows(db, hodl, rows, &n);
    if (have_history_rows && hodl_history_wave_rows_graphable(rows, n)) {
        history_backed = true;
        hodl_survival_cache_put(datadir_key, hodl->tip_height, tip_hash,
                                rows, n, true);
    } else {
        history_backed = false;
        fallback_rows = zcl_calloc(HODL_SURVIVAL_MAX_ROWS,
                                   sizeof(*fallback_rows),
                                   "hodl_survival_fallback_rows");
        if (fallback_rows) {
            bool cached_history = false;
            int fallback_n = 0;
            have_fallback_rows =
                hodl_survival_cache_get(datadir_key, hodl->tip_height,
                                        tip_hash, fallback_rows, &fallback_n,
                                        &cached_history) && !cached_history;
            if (!have_fallback_rows &&
                hodl_build_survival_rows(db, hodl, fallback_rows,
                                         &fallback_n)) {
                hodl_survival_cache_put(datadir_key, hodl->tip_height,
                                        tip_hash, fallback_rows,
                                        fallback_n, false);
                have_fallback_rows = true;
            }
            if (have_fallback_rows) {
                memcpy(rows, fallback_rows,
                       (size_t)fallback_n * sizeof(*fallback_rows));
                n = fallback_n;
            }
            free(fallback_rows);
        }
        if (!have_fallback_rows && !have_history_rows)
            n = 0;
        if (!have_fallback_rows && have_history_rows)
            history_backed = true;
    }
    sqlite3_close(db);

    if (n < 2) {
        free(rows);
        return;
    }

    int W = 1000;
    int H = 410;
    int pl = 72;
    int pr = 134;
    int pt = 26;
    int pb = 74;
    int pw = W - pl - pr;
    int ph = H - pt - pb;
    int64_t h_min = rows[0].height;
    int64_t h_max = rows[n - 1].height;
    if (h_max <= h_min)
        h_max = h_min + 1;

    char sample_meta[96];
    snprintf(sample_meta, sizeof(sample_meta), "%d %s samples", n,
             history_backed ? "verified" : "cohort");
    const char *chart_title = history_backed
        ? "Historical HODL wave"
        : "HODL wave over time";
    const char *chart_subtitle = history_backed
        ? "Share of transparent UTXO value alive at each sample and older than each threshold"
        : "Current unspent transparent value grouped by the age each coin would have at past dates";
    const char *chart_source = history_backed
        ? "historical UTXO snapshots"
        : "current surviving transparent UTXO set while history backfills";

    APPEND(*off, r, max,
        "<section id='hodl-survival-wrap' "
        "class='hodl-chart-wrap hodl-wave-interactive'>"
        "<div class='hodl-chart-head'><div>"
        "<h2 class='hodl-chart-title'>%s</h2>"
        "<p class='hodl-chart-subtitle'>%s</p></div>"
        "<div class='hodl-chart-meta'>%s</div></div>"
        "<div class='hodl-legend' aria-label='Holding thresholds'>",
        chart_title, chart_subtitle, sample_meta);

    for (int t = 0; t < HODL_SURVIVAL_THRESHOLDS; t++) {
        APPEND(*off, r, max,
            "<span class='hodl-legend-item'><span class='hodl-legend-swatch' "
            "style='background:%s'></span>%s</span>",
            HODL_THRESHOLDS[t].color, HODL_THRESHOLDS[t].label);
    }

    APPEND(*off, r, max, "</div><div class='hodl-current-strip'>");
    for (int t = 0; t < HODL_SURVIVAL_THRESHOLDS; t++) {
        double pct = (double)rows[n - 1].pct_x1000[t] / 1000.0;
        APPEND(*off, r, max,
            "<div class='hodl-current-chip' style='--c:%s'>"
            "<span>%s current</span><strong>%.1f%%</strong></div>",
            HODL_THRESHOLDS[t].color, HODL_THRESHOLDS[t].label, pct);
    }

    APPEND(*off, r, max,
        "</div><div id='hodl-survival-canvas' class='hodl-chart-canvas'>"
        "<svg id='hodl-survival-wave' viewBox='0 0 %d %d' "
        "class='hodl-svg hodl-survival-svg' tabindex='0' role='img' "
        "aria-label='HODL Wave over time for 6 month, 1 year, 2 year, "
        "and 5 year holding thresholds.' style='outline:none'>"
        "<defs>"
        "<linearGradient id='hodl-survival-bg' x1='0' y1='0' x2='0' y2='1'>"
        "<stop offset='0%%' stop-color='#15212a'/>"
        "<stop offset='100%%' stop-color='#071117'/>"
        "</linearGradient>"
        "<linearGradient id='hodl-survival-area' x1='0' y1='0' x2='0' y2='1'>"
        "<stop offset='0%%' stop-color='#35d07f' stop-opacity='0.24'/>"
        "<stop offset='72%%' stop-color='#35d07f' stop-opacity='0.08'/>"
        "<stop offset='100%%' stop-color='#35d07f' stop-opacity='0.01'/>"
        "</linearGradient>"
        "<filter id='hodl-line-glow' x='-4%%' y='-8%%' width='108%%' height='116%%'>"
        "<feGaussianBlur stdDeviation='0.75' result='blur'/>"
        "<feMerge><feMergeNode in='blur'/><feMergeNode in='SourceGraphic'/></feMerge>"
        "</filter>"
        "</defs>",
        W, H);

    APPEND(*off, r, max,
        "<rect x='%d' y='%d' width='%d' height='%d' rx='7' "
        "fill='url(#hodl-survival-bg)' stroke='#314655'/>",
        pl, pt, pw, ph);
    APPEND(*off, r, max,
        "<text class='hodl-axis-title' x='%d' y='%d' "
        "text-anchor='middle'>Share of transparent value</text>"
        "<text class='hodl-axis-title' x='%d' y='%d' "
        "text-anchor='middle'>Block height</text>",
        pl + pw / 2, pt - 9, pl + pw / 2, pt + ph + 48);

    for (int g = 0; g <= 4; g++) {
        int pct = g * 25;
        int y = pt + ph - ph * g / 4;
        APPEND(*off, r, max,
            "<line x1='%d' y1='%d' x2='%d' y2='%d' stroke='#253642' "
            "opacity='0.56'/>"
            "<text x='%d' y='%d' fill='#8d96a0' font-size='12' "
            "text-anchor='end'>%d%%</text>",
            pl, y, pl + pw, y, pl - 8, y + 4, pct);
    }

    for (int g = 0; g <= 4; g++) {
        int64_t hval = h_min + (h_max - h_min) * g / 4;
        int x = pl + pw * g / 4;
        time_t tt = (time_t)hodl_estimated_block_time(hval);
        struct tm tm_;
        char dbuf[16];
        gmtime_r(&tt, &tm_);
        strftime(dbuf, sizeof(dbuf), "%Y-%m", &tm_);
        APPEND(*off, r, max,
            "<line x1='%d' y1='%d' x2='%d' y2='%d' stroke='#1b2b35' "
            "opacity='0.46'/>"
            "<text class='hodl-x-tick' x='%d' y='%d' fill='#8d96a0' font-size='12' "
            "text-anchor='middle'>%s</text>",
            x, pt, x, pt + ph, x, pt + ph + 20, dbuf);
    }

    APPEND(*off, r, max,
        "<path d='M%d,%d", hodl_survival_x(&rows[0], pl, pw, h_min, h_max),
        pt + ph);
    for (int i = 0; i < n; i++) {
        int x = hodl_survival_x(&rows[i], pl, pw, h_min, h_max);
        int y = hodl_survival_y(&rows[i], 1, pt, ph);
        APPEND(*off, r, max, " L%d,%d", x, y);
    }
    APPEND(*off, r, max, " L%d,%d Z' fill='url(#hodl-survival-area)'/>",
           hodl_survival_x(&rows[n - 1], pl, pw, h_min, h_max), pt + ph);

    for (int t = 0; t < HODL_SURVIVAL_THRESHOLDS; t++) {
        APPEND(*off, r, max,
            "<polyline fill='none' stroke='%s' stroke-width='%d' "
            "stroke-linejoin='round' stroke-linecap='round' opacity='0.96' "
            "filter='url(#hodl-line-glow)' class='hodl-series-line' "
            "vector-effect='non-scaling-stroke' points='",
            HODL_THRESHOLDS[t].color, t == 1 ? 4 : 3);
        for (int i = 0; i < n; i++) {
            int x = hodl_survival_x(&rows[i], pl, pw, h_min, h_max);
            int y = hodl_survival_y(&rows[i], t, pt, ph);
            APPEND(*off, r, max, "%s%d,%d", i ? " " : "", x, y);
        }
        APPEND(*off, r, max, "'/>");
    }

    for (int t = 0; t < HODL_SURVIVAL_THRESHOLDS; t++) {
        int x = hodl_survival_x(&rows[n - 1], pl, pw, h_min, h_max);
        int y = hodl_survival_y(&rows[n - 1], t, pt, ph);
        APPEND(*off, r, max,
            "<circle class='hodl-hover-dot' cx='%d' cy='%d' r='%d' fill='%s' stroke='#071015' "
            "stroke-width='2'/>",
            x, y, t == 1 ? 5 : 4, HODL_THRESHOLDS[t].color);
    }

    int label_y[HODL_SURVIVAL_THRESHOLDS];
    int label_x = pl + pw + 14;
    int label_top = pt + 12;
    int label_bottom = pt + ph - 8;
    int last_y = label_top - 17;
    for (int t = 0; t < HODL_SURVIVAL_THRESHOLDS; t++) {
        int y = hodl_survival_y(&rows[n - 1], t, pt, ph);
        if (y < last_y + 17)
            y = last_y + 17;
        label_y[t] = y;
        last_y = y;
    }
    if (last_y > label_bottom) {
        int shift = last_y - label_bottom;
        for (int t = 0; t < HODL_SURVIVAL_THRESHOLDS; t++) {
            label_y[t] -= shift;
            if (label_y[t] < label_top)
                label_y[t] = label_top;
        }
    }
    for (int t = 0; t < HODL_SURVIVAL_THRESHOLDS; t++) {
        int x = hodl_survival_x(&rows[n - 1], pl, pw, h_min, h_max);
        int y = hodl_survival_y(&rows[n - 1], t, pt, ph);
        double pct = (double)rows[n - 1].pct_x1000[t] / 1000.0;
        APPEND(*off, r, max,
            "<path d='M%d,%d L%d,%d L%d,%d' fill='none' stroke='%s' "
            "stroke-width='1.2' opacity='0.68'/>"
            "<text class='hodl-end-label' x='%d' y='%d' fill='%s' "
            "font-size='12'>%s %.1f%%</text>",
            x + 6, y, label_x - 8, label_y[t], label_x - 2, label_y[t],
            HODL_THRESHOLDS[t].color,
            label_x, label_y[t] + 4, HODL_THRESHOLDS[t].color,
            HODL_THRESHOLDS[t].label, pct);
    }

    APPEND(*off, r, max,
        "<line id='hodl-survival-xhair' x1='0' y1='%d' x2='0' y2='%d' "
        "stroke='#f5f7fa' stroke-dasharray='2,4' stroke-width='1' "
        "opacity='0.62' style='display:none;pointer-events:none'/>",
        pt, pt + ph);
    for (int t = 0; t < HODL_SURVIVAL_THRESHOLDS; t++) {
        APPEND(*off, r, max,
            "<circle id='hodl-survival-dot-%d' class='hodl-hover-dot' "
            "cx='0' cy='0' r='4' "
            "fill='%s' stroke='#050505' stroke-width='1' "
            "style='display:none;pointer-events:none'/>",
            t, HODL_THRESHOLDS[t].color);
    }
    APPEND(*off, r, max,
        "<g id='hodl-survival-tip' style='display:none;pointer-events:none'>"
        "<rect id='hodl-survival-tip-bg' x='0' y='0' width='330' "
        "height='150' rx='8' fill='#060b10' stroke='#6ee7b7' opacity='0.97'/>"
        "<text id='hodl-survival-date' x='12' y='22' fill='#fff' "
        "font-size='13'>-</text>"
        "<text id='hodl-survival-total' x='12' y='43' fill='#aaa' "
        "font-size='12'>-</text>"
        "<text id='hodl-survival-h' x='12' y='62' fill='#666' "
        "font-size='11'>-</text>");
    for (int t = 0; t < HODL_SURVIVAL_THRESHOLDS; t++) {
        int y = 86 + t * 17;
        APPEND(*off, r, max,
            "<rect x='12' y='%d' width='10' height='10' rx='2' fill='%s'/>"
            "<text id='hodl-survival-row-%d' x='30' y='%d' fill='#ddd' "
            "font-size='12'>-</text>",
            y - 9, HODL_THRESHOLDS[t].color, t, y);
    }
    APPEND(*off, r, max,
        "</g>"
        "<text x='%d' y='%d' fill='#566371' font-size='11' "
        "text-anchor='end'>"
        "Source: %s</text>"
        "</svg></div></section>"
        "<script>(function(){"
        "var data=[",
        W - 30, H - 21, chart_source);
    for (int i = 0; i < n; i++) {
        APPEND(*off, r, max,
            "%s[%" PRId64 ",%" PRId64 ",%" PRId64,
            i ? "," : "", rows[i].height, rows[i].time, rows[i].total_zat);
        for (int t = 0; t < HODL_SURVIVAL_THRESHOLDS; t++)
            APPEND(*off, r, max, ",%d", rows[i].pct_x1000[t]);
        for (int t = 0; t < HODL_SURVIVAL_THRESHOLDS; t++)
            APPEND(*off, r, max, ",%" PRId64, rows[i].older_zat[t]);
        APPEND(*off, r, max, "]");
    }
    APPEND(*off, r, max, "];var series=[");
    for (int t = 0; t < HODL_SURVIVAL_THRESHOLDS; t++) {
        APPEND(*off, r, max, "%s['%s','%s']",
               t ? "," : "", HODL_THRESHOLDS[t].label,
               HODL_THRESHOLDS[t].color);
    }
    APPEND(*off, r, max,
        "];var W=%d,pl=%d,pr=%d,pt=%d,pb=%d,ph=%d,pw=W-pl-pr;"
        "var hmin=%" PRId64 ",hmax=%" PRId64 ";"
        "var svg=document.getElementById('hodl-survival-wave');"
        "var wrap=document.getElementById('hodl-survival-canvas');"
        "var xhair=document.getElementById('hodl-survival-xhair');"
        "var tip=document.getElementById('hodl-survival-tip');"
        "var tipBg=document.getElementById('hodl-survival-tip-bg');"
        "var td=document.getElementById('hodl-survival-date');"
        "var tt=document.getElementById('hodl-survival-total');"
        "var th=document.getElementById('hodl-survival-h');"
        "var dots=series.map(function(_,i){return document.getElementById('hodl-survival-dot-'+i);});"
        "var rows=series.map(function(_,i){return document.getElementById('hodl-survival-row-'+i);});"
        "var TIPW=330,TIPH=150,cur=-1;"
        "tipBg.setAttribute('width',TIPW);tipBg.setAttribute('height',TIPH);"
        "function fmtZcl(z){var v=z/1e8;if(v>=1e6)return(v/1e6).toFixed(2)+'M';"
        "if(v>=1e3)return(v/1e3).toFixed(2)+'k';return v.toFixed(2);}"
        "function fmtDate(t){return new Date(t*1000).toISOString().slice(0,10);}"
        "function maybeScrollLatest(){if(!wrap||!window.matchMedia)return;"
        "if(wrap.scrollWidth>wrap.clientWidth+16&&"
        "window.matchMedia('(max-width: 640px)').matches)"
        "wrap.scrollLeft=wrap.scrollWidth;}"
        "function hide(){xhair.style.display='none';tip.style.display='none';"
        "dots.forEach(function(d){if(d)d.style.display='none';});}"
        "function pickNearest(svgX){var frac=(svgX-pl)/pw;"
        "var target=hmin+frac*(hmax-hmin);var lo=0,hi=data.length-1;"
        "while(lo<hi){var m=(lo+hi)>>1;if(data[m][0]<target)lo=m+1;else hi=m;}"
        "if(lo>0&&Math.abs(data[lo-1][0]-target)<Math.abs(data[lo][0]-target))lo--;"
        "return lo;}"
        "function yFor(p){return Math.round(pt+ph-(p/100000)*ph);}"
        "function render(svgX){if(svgX<pl)svgX=pl;if(svgX>W-pr)svgX=W-pr;"
        "var i=pickNearest(svgX);cur=i;var row=data[i];"
        "var x=Math.round(pl+(row[0]-hmin)/(hmax-hmin)*pw);"
        "xhair.setAttribute('x1',x);xhair.setAttribute('x2',x);"
        "xhair.style.display='';"
        "for(var s=0;s<series.length;s++){var y=yFor(row[3+s]);"
        "if(dots[s]){dots[s].setAttribute('cx',x);dots[s].setAttribute('cy',y);"
        "dots[s].style.display='';}}"
        "var tx=x+14;if(tx+TIPW>W-pr)tx=x-TIPW-14;if(tx<pl)tx=pl;"
        "var ty=pt+12;if(ty+TIPH>pt+ph)ty=pt+ph-TIPH;"
        "tip.setAttribute('transform','translate('+tx+','+ty+')');"
        "tip.style.display='';td.textContent=fmtDate(row[1]);"
        "tt.textContent='Current surviving total then: '+fmtZcl(row[2])+' ZCL';"
        "th.textContent='Block '+row[0].toLocaleString();"
        "for(var s=0;s<series.length;s++){var p=row[3+s]/1000;"
        "var z=row[3+series.length+s];"
        "rows[s].textContent=series[s][0]+': '+p.toFixed(2)+'%%, '+fmtZcl(z)+' ZCL';}"
        "}"
        "var pend=null,raf=0;"
        "function sched(x){pend=x;if(!raf)raf=requestAnimationFrame(function(){"
        "raf=0;if(pend!=null)render(pend);});}"
        "function pt2svg(clientX){var rc=svg.getBoundingClientRect();"
        "return (clientX-rc.left)*(W/rc.width);}"
        "svg.addEventListener('mousemove',function(e){var sx=pt2svg(e.clientX);"
        "if(sx<pl||sx>W-pr){hide();return;}sched(sx);});"
        "svg.addEventListener('mouseleave',hide);"
        "function onTouch(e){if(!e.touches[0])return;var sx=pt2svg(e.touches[0].clientX);"
        "if(sx>=pl&&sx<=W-pr)sched(sx);}"
        "svg.addEventListener('touchstart',onTouch,{passive:true});"
        "svg.addEventListener('touchmove',onTouch,{passive:true});"
        "svg.addEventListener('touchend',hide);svg.addEventListener('touchcancel',hide);"
        "svg.addEventListener('focus',function(){render(W-pr);});"
        "svg.addEventListener('blur',hide);"
        "svg.addEventListener('keydown',function(e){var k=e.key,i=cur<0?data.length-1:cur;"
        "if(k==='ArrowLeft')i=Math.max(0,i-1);else if(k==='ArrowRight')i=Math.min(data.length-1,i+1);"
        "else if(k==='Home')i=0;else if(k==='End')i=data.length-1;"
        "else if(k==='Escape'){hide();return;}else return;e.preventDefault();"
        "render(pl+(data[i][0]-hmin)/(hmax-hmin)*pw);});"
        "requestAnimationFrame(maybeScrollLatest);"
        "})();</script>",
        W, pl, pr, pt, pb, ph, h_min, h_max);

    free(rows);
}

void hodl_emit_age_distribution_chart(size_t *off, uint8_t *r,
                                      size_t max,
                                      const struct hodl_wave_snapshot *h,
                                      bool cached_snapshot)
{
    if (!off || !r || !h)
        return;

    int selected = 0;
    for (int i = 1; i < HODL_WAVE_BUCKETS; i++) {
        if (h->buckets[i].value > h->buckets[selected].value)
            selected = i;
    }

    int W = 1000;
    int H = 408;
    APPEND(*off, r, max,
        "<section id='hodl-age-wrap' class='hodl-chart-wrap hodl-wave-interactive'>"
        "<div class='hodl-chart-head'><div>"
        "<h2 class='hodl-chart-title'>Unspent transparent value by age</h2>"
        "<p class='hodl-chart-subtitle'>Current transparent UTXO value distribution.</p>"
        "</div></div>"
        "<div id='hodl-age-canvas' class='hodl-chart-canvas'>"
        "<svg id='hodl-age-wave' viewBox='0 0 %d %d' class='hodl-svg hodl-age-svg' "
        "tabindex='0' role='img' "
        "aria-label='Interactive unspent transparent value by age. "
        "Use mouse, touch, or arrow keys to inspect each age band.'>"
        "<defs>"
        "<linearGradient id='hodl-age-bg' x1='0' y1='0' x2='0' y2='1'>"
        "<stop offset='0%%' stop-color='#15212a'/>"
        "<stop offset='100%%' stop-color='#071117'/>"
        "</linearGradient>"
        "<linearGradient id='hodl-age-glow' x1='0' y1='0' x2='0' y2='1'>"
        "<stop offset='0%%' stop-color='#35d07f' stop-opacity='0.18'/>"
        "<stop offset='100%%' stop-color='#35d07f' stop-opacity='0.02'/>"
        "</linearGradient>"
        "</defs>",
        W, H);

    int x0 = 76, y0 = 304, chart_w = 850, chart_h = 230;
    APPEND(*off, r, max,
        "<rect x='%d' y='%d' width='%d' height='%d' rx='7' "
        "fill='url(#hodl-age-bg)' stroke='#314655'/>",
        x0, y0 - chart_h, chart_w, chart_h);
    APPEND(*off, r, max,
        "<text class='hodl-axis-title' x='%d' y='%d' "
        "text-anchor='middle'>Share of transparent value</text>",
        x0 + chart_w / 2, y0 - chart_h - 31);
    for (int g = 0; g <= 4; g++) {
        int y = y0 - chart_h * g / 4;
        APPEND(*off, r, max,
            "<line x1='%d' y1='%d' x2='%d' y2='%d' stroke='#253642' "
            "opacity='0.56'/>"
            "<text x='%d' y='%d' fill='#8d96a0' font-size='12' "
            "text-anchor='end'>%d%%</text>",
            x0, y, x0 + chart_w, y, x0 - 8, y + 4, g * 25);
    }

    int bar_gap = 10;
    int bar_w = (chart_w - bar_gap * (HODL_WAVE_BUCKETS - 1)) /
                HODL_WAVE_BUCKETS;
    int threshold_x = x0 + 6 * (bar_w + bar_gap) - bar_gap / 2;
    APPEND(*off, r, max,
        "<rect x='%d' y='%d' width='%d' height='%d' fill='#35d07f' "
        "opacity='0.055'/>"
        "<line x1='%d' y1='%d' x2='%d' y2='%d' stroke='#35d07f' "
        "stroke-width='1.2' stroke-dasharray='4,4' opacity='0.72'/>"
        "<text x='%d' y='%d' fill='#8fffc3' font-size='11' "
        "text-anchor='middle'>1 year+</text>",
        threshold_x, y0 - chart_h, x0 + chart_w - threshold_x, chart_h,
        threshold_x, y0 - chart_h, threshold_x, y0,
        threshold_x, y0 - chart_h - 8);

    APPEND(*off, r, max,
        "<path d='M%d,%d", x0, y0);
    for (int b = 0; b < HODL_WAVE_BUCKETS; b++) {
        double pct = h->total_value > 0
            ? (double)h->buckets[b].value / (double)h->total_value * 100.0
            : 0.0;
        int bh = (int)(pct / 100.0 * chart_h);
        int x = x0 + b * (bar_w + bar_gap) + bar_w / 2;
        int y = y0 - bh;
        APPEND(*off, r, max, " L%d,%d", x, y);
    }
    APPEND(*off, r, max,
        " L%d,%d Z' fill='url(#hodl-age-glow)' stroke='#35d07f' "
        "stroke-width='1' opacity='0.72'/>",
        x0 + chart_w, y0);

    for (int b = 0; b < HODL_WAVE_BUCKETS; b++) {
        double pct = h->total_value > 0
            ? (double)h->buckets[b].value / (double)h->total_value * 100.0
            : 0.0;
        int bh = (int)(pct / 100.0 * chart_h);
        int draw_h = bh > 3 ? bh : 3;
        int x = x0 + b * (bar_w + bar_gap);
        int y = y0 - draw_h;
        char val_fmt[64];
        zcl_format_zcl(val_fmt, sizeof(val_fmt), h->buckets[b].value);
        APPEND(*off, r, max,
            "<rect id='hodl-age-bar-%d' class='hodl-age-bar' "
            "x='%d' y='%d' width='%d' height='%d' fill='%s' rx='4' "
            "opacity='%s' stroke='%s' stroke-width='%d'/>"
            "<rect class='hodl-age-hit' data-i='%d' tabindex='-1' "
            "x='%d' y='%d' width='%d' height='%d' fill='transparent' "
            "aria-label='%s: %.3f%%, %s ZCL, %" PRId64 " UTXOs'>"
            "<title>%s: %.3f%%, %s ZCL, %" PRId64 " UTXOs</title>"
            "</rect>"
            "<text x='%d' y='%d' fill='#aaa' font-size='11' "
            "text-anchor='middle' transform='rotate(-35,%d,%d)'>%s</text>",
            b, x, y, bar_w, draw_h, h->buckets[b].color,
            b == selected ? "1" : "0.82",
            b == selected ? "#fff" : h->buckets[b].color,
            b == selected ? 2 : 1,
            b, x, y0 - chart_h, bar_w, chart_h,
            h->buckets[b].html_label, pct, val_fmt, h->buckets[b].count,
            h->buckets[b].html_label, pct, val_fmt, h->buckets[b].count,
            x + bar_w / 2, y0 + 26, x + bar_w / 2, y0 + 26,
            h->buckets[b].html_label);
        if (pct >= 1.0 || b == selected) {
            APPEND(*off, r, max,
                "<text x='%d' y='%d' fill='#eee' font-size='12' "
                "text-anchor='middle'>%.2f%%</text>",
                x + bar_w / 2, y - 6, pct);
        }
    }

    APPEND(*off, r, max,
        "<g id='hodl-age-tip' style='display:none;pointer-events:none'>"
        "<rect id='hodl-age-tip-bg' x='0' y='0' width='300' height='102' "
        "rx='8' fill='#060b10' stroke='#6ee7b7' opacity='0.97'/>"
        "<text id='hodl-age-tip-title' x='20' y='29' fill='#fff' "
        "font-size='18'>-</text>"
        "<text id='hodl-age-tip-pct' x='20' y='54' fill='#33ff99' "
        "font-size='18' font-weight='700'>-</text>"
        "<text id='hodl-age-tip-value' x='20' y='75' fill='#bbb' "
        "font-size='13'>-</text>"
        "<text id='hodl-age-tip-count' x='20' y='93' fill='#8d96a0' "
        "font-size='12'>-</text>"
        "</g>"
        "<text x='%d' y='%d' fill='#4d5662' font-size='11' text-anchor='end'>"
        "Source: %s</text></svg></div></section>"
        "<script>(function(){"
        "var svg=document.getElementById('hodl-age-wave');"
        "if(!svg)return;"
        "var wrap=document.getElementById('hodl-age-canvas');"
        "var data=[",
        W - 30, H - 17,
        cached_snapshot ? "verified cached transparent UTXO set" :
                          "current transparent UTXO set");
    for (int b = 0; b < HODL_WAVE_BUCKETS; b++) {
        double pct = h->total_value > 0
            ? (double)h->buckets[b].value / (double)h->total_value * 100.0
            : 0.0;
        APPEND(*off, r, max,
            "%s{label:'%s',pct:%d,value:%" PRId64 ",count:%" PRId64 "}",
            b ? "," : "", h->buckets[b].label, (int)(pct * 1000.0),
            h->buckets[b].value, h->buckets[b].count);
    }
    APPEND(*off, r, max,
        "];"
        "var selected=%d;"
        "var tip=document.getElementById('hodl-age-tip');"
        "var title=document.getElementById('hodl-age-tip-title');"
        "var pct=document.getElementById('hodl-age-tip-pct');"
        "var value=document.getElementById('hodl-age-tip-value');"
        "var count=document.getElementById('hodl-age-tip-count');"
        "function fmtZcl(z){var v=z/1e8;"
        "if(v>=1e6)return(v/1e6).toFixed(3)+'M ZCL';"
        "if(v>=1e3)return(v/1e3).toFixed(3)+'k ZCL';"
        "return v.toFixed(8)+' ZCL';}"
        "function fmtCount(n){return n.toLocaleString()+' UTXOs';}"
        "function maybeScrollSelected(){if(!wrap||!window.matchMedia)return;"
        "if(wrap.scrollWidth>wrap.clientWidth+16&&selected>=data.length/2&&"
        "window.matchMedia('(max-width: 640px)').matches)"
        "wrap.scrollLeft=wrap.scrollWidth;}"
        "function setBar(i,on){var b=document.getElementById('hodl-age-bar-'+i);"
        "if(!b)return;b.setAttribute('opacity',on?'1':'0.82');"
        "b.setAttribute('stroke',on?'#fff':b.getAttribute('fill'));"
        "b.setAttribute('stroke-width',on?'2':'1');}"
        "function render(i){if(i<0)i=0;if(i>=data.length)i=data.length-1;"
        "setBar(selected,false);selected=i;setBar(selected,true);"
        "var d=data[i];title.textContent=d.label;"
        "pct.textContent=(d.pct/1000).toFixed(3)+'%% of transparent value';"
        "value.textContent=fmtZcl(d.value);"
        "count.textContent=fmtCount(d.count);"
        "var x=i<4?620:150;tip.setAttribute('transform','translate('+x+',76)');"
        "tip.style.display='';}"
        "function hide(){tip.style.display='none';}"
        "svg.querySelectorAll('.hodl-age-hit').forEach(function(el){"
        "el.addEventListener('mouseenter',function(){render(+el.dataset.i);});"
        "el.addEventListener('mousemove',function(){render(+el.dataset.i);});"
        "el.addEventListener('touchstart',function(e){render(+el.dataset.i);"
        "},{passive:true});"
        "el.addEventListener('touchmove',function(e){render(+el.dataset.i);"
        "},{passive:true});"
        "});"
        "svg.addEventListener('mouseleave',hide);"
        "svg.addEventListener('touchend',hide);svg.addEventListener('touchcancel',hide);"
        "svg.addEventListener('focus',function(){render(selected);});"
        "svg.addEventListener('blur',hide);"
        "svg.addEventListener('keydown',function(e){"
        "var k=e.key,i=selected;"
        "if(k==='ArrowLeft')i--;else if(k==='ArrowRight')i++;"
        "else if(k==='Home')i=0;else if(k==='End')i=data.length-1;"
        "else if(k==='Escape'){hide();return;}"
        "else return;e.preventDefault();render(i);});"
        "hide();"
        "requestAnimationFrame(maybeScrollSelected);"
        "})();</script>",
        selected);
}
