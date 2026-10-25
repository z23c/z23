/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet history-page view: timeline transaction cards and the shielded
 * notes section for /wallet/history. The controller fetches rows through
 * the wallet_view port; this file owns the HTML fragments. */

#include "views/wallet_view_history_view.h"
#include "controllers/explorer_internal.h"   /* APPEND */
#include "views/wallet_templates_gen.h"
#include "views/format_helpers.h"
#include "util/template.h"

#include <stdio.h>
#include <string.h>

/* Controller helpers; forward-declared so the view does not include a
 * controller-internal header. Resolve at link time. html_escape comes
 * from util/template.h. */
void wv_txid_short(const char *txid, char *out, size_t max);
void wv_txid_lower(const char *txid, char *out, size_t max);
void wv_format_relative_time(int64_t timestamp, char *out, size_t max);
void wv_format_time(int64_t timestamp, char *out, size_t max);

/* Per-row helpers for wv_render_history_cards; each owns one step of a
 * history card so the render loop itself stays flat. */
static bool history_row_is_ghost(int64_t wallet_output, int64_t wallet_input,
                                 int h, int from_me)
{
    return wallet_output == 0 && wallet_input == 0 && h == 0 && !from_me;
}

static int64_t history_row_display_value(bool is_recv, int64_t wallet_output,
                                         int64_t wallet_input)
{
    if (is_recv)
        return wallet_output;
    if (wallet_input > 0) {
        int64_t display_val = wallet_input - wallet_output;
        if (display_val < 0) display_val = 0;
        return display_val;
    }
    return wallet_output;
}

static bool history_row_is_shield_op(int from_me, int64_t wallet_output,
                                     int64_t wallet_input,
                                     int64_t display_val)
{
    return from_me && wallet_output == 0 && wallet_input == 0 &&
           display_val == 0;
}

static int history_row_confs(int tip, int h)
{
    int confs = (tip > 0 && h > 0) ? (tip - h + 1) : 0;
    if (confs < 0) confs = 0;
    return confs;
}

static void history_format_height_commas(int h, char *h_fmt,
                                         size_t h_fmt_size)
{
    char tmp[20];
    int tl = snprintf(tmp, sizeof(tmp), "%d", h);
    int ci = 0, ti = 0;
    int digits_left = tl;
    for (int di = 0; di < tl && ci < (int)h_fmt_size-1; di++) {
        h_fmt[ci++] = tmp[ti++];
        digits_left--;
        if (digits_left > 0 && digits_left % 3 == 0)
            h_fmt[ci++] = ',';
    }
    h_fmt[ci] = '\0';
}

static void history_render_conf_html(int h, int confs, const char *h_fmt,
                                     char *conf_html, size_t conf_size)
{
    if (h > 0) {
        char confs_s[16];
        snprintf(confs_s, sizeof(confs_s), "%d", confs);
        struct template_var cv[] = {
            { "block", h_fmt }, { "confs", confs_s }
        };
        template_render(TMPL_CONF_CONFIRMED, cv, 2,
            conf_html, conf_size);
    } else {
        template_render(TMPL_CONF_PENDING, NULL, 0,
            conf_html, conf_size);
    }
}

static size_t history_render_shield_card(uint8_t *r, size_t max, size_t off,
                                         const char *esc_lower, int64_t fee,
                                         const char *esc_ts,
                                         const char *esc_rel)
{
    char fee_s[32] = "";
    if (fee > 0)
        zcl_format_zcl_short(fee_s, sizeof(fee_s), fee);

    struct template_var sv[] = {
        { "txid",      esc_lower },
        { "fee",       fee_s },
        { "timestamp", esc_ts },
        { "rel_time",  esc_rel },
    };
    return off + template_render(TMPL_HISTORY_SHIELD, sv, 4,
        (char *)r + off, max - off);
}

static size_t history_render_tx_card(uint8_t *r, size_t max, size_t off,
                                     bool is_recv, const char *esc_lower,
                                     const char *amt_s, const char *esc_ts,
                                     const char *esc_rel,
                                     const char *conf_html)
{
    struct template_var tv[] = {
        { "txid",        esc_lower },
        { "color",       is_recv ? "#34d399" : "#f87171" },
        { "amount_class", is_recv ? "recv" : "send" },
        { "sign",        is_recv ? "+" : "-" },
        { "amount",      amt_s },
        { "pill_class",  is_recv ? "pill-t" : "pill-send" },
        { "pill_label",  is_recv ? "Received" : "Sent" },
        { "timestamp",   esc_ts },
        { "rel_time",    esc_rel },
        { "conf_html",   conf_html },
    };
    return off + template_render(TMPL_HISTORY_CARD, tv, 10,
        (char *)r + off, max - off);
}

void wv_render_history_cards(uint8_t *r, size_t max, size_t *off_io,
                             const struct wallet_view_ledger_row *rows, int n,
                             int tip)
{
    size_t off = *off_io;

    for (int i = 0; rows && i < n && off + 600 < max; i++) {
        const char *txid = rows[i].txid;
        int h = rows[i].height;
        int64_t btime = rows[i].block_time;
        int from_me = rows[i].from_me;
        int64_t fee = rows[i].fee;
        int64_t wallet_output = rows[i].wallet_output;
        int64_t wallet_input = rows[i].wallet_input;
        if (!txid) continue;
        /* Skip ghost entries (no data AND not a send we initiated) */
        if (history_row_is_ghost(wallet_output, wallet_input, h, from_me))
            continue;

        bool is_recv = (from_me == 0);
        int64_t display_val =
            history_row_display_value(is_recv, wallet_output, wallet_input);
        bool is_shield_op =
            history_row_is_shield_op(from_me, wallet_output, wallet_input,
                                     display_val);
        if (display_val == 0 && !is_shield_op) continue;

        char short_tx[18], lower_tx[65], rel_time[48], ts[32];
        wv_txid_short(txid, short_tx, sizeof(short_tx));
        wv_txid_lower(txid, lower_tx, sizeof(lower_tx));
        wv_format_relative_time(btime, rel_time, sizeof(rel_time));
        wv_format_time(btime, ts, sizeof(ts));

        char esc_short[64], esc_lower[256], esc_rel[96], esc_ts[64];
        html_escape(esc_short, sizeof(esc_short), short_tx);
        html_escape(esc_lower, sizeof(esc_lower), lower_tx);
        html_escape(esc_rel, sizeof(esc_rel), rel_time);
        html_escape(esc_ts, sizeof(esc_ts), ts);

        int confs = history_row_confs(tip, h);

        /* Format height with commas */
        char h_fmt[20];
        history_format_height_commas(h, h_fmt, sizeof(h_fmt));

        char conf_html[256] = "";
        history_render_conf_html(h, confs, h_fmt, conf_html,
                                 sizeof(conf_html));

        char amt_s[32];
        zcl_format_zcl_short(amt_s, sizeof(amt_s), display_val);

        if (is_shield_op) {
            off = history_render_shield_card(r, max, off, esc_lower, fee,
                                             esc_ts, esc_rel);
        } else {
            off = history_render_tx_card(r, max, off, is_recv, esc_lower,
                                         amt_s, esc_ts, esc_rel, conf_html);
        }
    }

    *off_io = off;
}

void wv_render_history_notes(uint8_t *r, size_t max, size_t *off_io,
                             const struct wallet_view_note_row *notes, int n)
{
    size_t off = *off_io;
    bool header_shown = false;

    for (int i = 0; notes && i < n && off + 600 < max; i++) {
        int64_t val = notes[i].value;
        const char *addr = notes[i].address;
        int64_t ntime = notes[i].block_time;

        if (!header_shown) {
            APPEND(off, r, max,
                "<div class='section-header' style='margin-top:16px'>"
                "<span>&#x1F512; Shielded Notes</span></div>");
            header_shown = true;
        }

        char amt_s[32];
        zcl_format_zcl_short(amt_s, sizeof(amt_s), val);
        char rel[48], esc_rel[96];
        wv_format_relative_time(ntime, rel, sizeof(rel));
        html_escape(esc_rel, sizeof(esc_rel), rel);

        char addr_short[24] = "";
        if (addr && strlen(addr) > 12)
            snprintf(addr_short, sizeof(addr_short),
                "%.8s...%.4s", addr, addr + strlen(addr) - 4);

        bool is_mine = (addr && addr[0]);

        APPEND(off, r, max,
            "<div class='tx-card' style='border-left-color:#a78bfa'>"
            "<div style='display:flex;justify-content:space-between;"
            "align-items:baseline'>"
            "<span class='tx-amount recv'>+%s ZCL</span>"
            "<span class='pill pill-z'>%s</span></div>"
            "<div class='tx-meta'>"
            "<span style='color:#888;font-size:13px'>%s</span>"
            "<span class='tx-time'>%s</span>"
            "</div></div>",
            amt_s,
            is_mine ? "my z-addr" : "external",
            addr_short,
            esc_rel);
    }

    *off_io = off;
}

size_t wv_render_tx_outputs(char *out, size_t outmax,
                            const struct wallet_view_tx_output *outs, int n)
{
    size_t os = 0;
    bool header_shown = false;

    for (int i = 0; outs && i < n && os + 300 < outmax; i++) {
        if (!header_shown) {
            int hn = snprintf(out + os, outmax - os, "<h3>Wallet Outputs</h3>");
            if (hn > 0) os += (size_t)hn;
            header_shown = true;
        }
        int vout = outs[i].vout;
        int64_t val = outs[i].value;
        int rn = snprintf(out + os, outmax - os,
            "<div class='utxo-row'>"
            "<span class='mono' style='color:#888'>:%d</span>"
            "<span class='zcl'>%.8f ZCL</span>"
            "</div>",
            vout, (double)val / 1e8);
        if (rn > 0) os += (size_t)rn;
    }
    out[os] = '\0';
    return os;
}
