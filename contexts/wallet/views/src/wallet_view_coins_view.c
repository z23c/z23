/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet coins-page view: builds the transparent UTXO table rows, the
 * shielded-note <tr> rows, and the token-table <tr> rows for /wallet/coins.
 * The controller fetches rows through the wallet_view port; this file owns
 * the HTML fragments. */

#include "views/wallet_view_coins_view.h"
#include "views/format_helpers.h"
#include "util/template.h"

#include <stdio.h>
#include <string.h>

/* Defined in the wallet view controller helpers; forward-declared here so
 * the view does not depend on a controller-internal header (the symbols
 * resolve at link time). html_escape comes from util/template.h. */
void wv_txid_short(const char *hex, char *out, size_t out_max);
void wv_txid_lower(const char *hex, char *out, size_t out_max);

size_t wv_render_coin_rows(char *out, size_t outmax,
                           const struct wallet_view_coin *coins, int n,
                           int tip, int64_t *out_total, int *out_count)
{
    size_t ur = 0;
    int64_t t_total = 0;
    int t_count = 0;

    for (int i = 0; coins && i < n && ur + 500 < outmax; i++) {
        const char *txid = coins[i].txid;
        int vout = coins[i].vout;
        int64_t val = coins[i].value;
        int h = coins[i].height;
        const char *stype = coins[i].type;

        char short_tx[18], lower_tx[65];
        wv_txid_short(txid, short_tx, sizeof(short_tx));
        wv_txid_lower(txid, lower_tx, sizeof(lower_tx));

        int confs = (tip > 0 && h > 0) ? (tip - h + 1) : 0;
        if (confs < 0) confs = 0;

        int nn = snprintf(out + ur, outmax - ur,
            "<tr>"
            "<td><a href='/explorer/tx/%s' class='hash'>"
            "%s:%d</a></td>"
            "<td><span class='pill pill-%s' style='font-size:13px'>"
            "%s</span></td>"
            "<td class='zcl'>%.8f</td>",
            lower_tx, short_tx, vout,
            stype && stype[0] == 'C' ? "pending" : "t",
            stype ? stype : "Standard",
            (double)val / 1e8);
        if (nn > 0) ur += (size_t)nn;
        if (h > 0)
            nn = snprintf(out + ur, outmax - ur,
                "<td>%d</td><td>%d</td>", h, confs);
        else
            nn = snprintf(out + ur, outmax - ur,
                "<td><span class='pill pill-pending'>Pending</span></td>"
                "<td><span class='pill pill-pending'>Pending</span></td>");
        if (nn > 0) ur += (size_t)nn;
        nn = snprintf(out + ur, outmax - ur, "</tr>");
        if (nn > 0) ur += (size_t)nn;
        t_total += val;
        t_count++;
    }
    out[ur] = '\0';
    if (out_total) *out_total = t_total;
    if (out_count) *out_count = t_count;
    return ur;
}

size_t wv_render_note_rows(char *out, size_t outmax,
                           const struct wallet_view_note_group *groups, int n)
{
    size_t nr = 0;

    for (int i = 0; groups && i < n && nr + 400 < outmax; i++) {
        int64_t val = groups[i].value;
        const char *addr = groups[i].address;
        int cnt = groups[i].count;
        int min_h = groups[i].min_height;
        int max_h = groups[i].max_height;
        char short_addr[18] = "\xe2\x80\x94";
        if (addr && addr[0] && strlen(addr) > 3)
            wv_txid_short(addr + 3, short_addr, sizeof(short_addr));
        int nn = snprintf(out + nr, outmax - nr,
            "<tr>"
            "<td class='zcl'>%.8f</td>"
            "<td class='hash' style='color:#a78bfa'>zs1%s</td>"
            "<td>%d</td>",
            (double)val / 1e8, short_addr, cnt);
        if (nn > 0) nr += (size_t)nn;
        if (min_h > 0) {
            if (min_h == max_h)
                nn = snprintf(out + nr, outmax - nr,
                    "<td>%d</td>", min_h);
            else
                nn = snprintf(out + nr, outmax - nr,
                    "<td>%d\xe2\x80\x93%d</td>", min_h, max_h);
        } else {
            nn = snprintf(out + nr, outmax - nr,
                "<td><span class='pill pill-pending'>Pending</span></td>");
        }
        if (nn > 0) nr += (size_t)nn;
        nn = snprintf(out + nr, outmax - nr, "</tr>");
        if (nn > 0) nr += (size_t)nn;
    }
    out[nr] = '\0';
    return nr;
}

size_t wv_render_token_rows(char *out, size_t outmax,
                            const struct wallet_view_token_balance *tokens,
                            int n)
{
    size_t tr_off = 0;

    for (int i = 0; tokens && i < n; i++) {
        const char *ticker = tokens[i].ticker;
        const char *name = tokens[i].name;
        int decimals = tokens[i].decimals;
        int64_t bal = tokens[i].balance;
        char esc_ticker[64] = "", esc_name[128] = "";
        if (ticker && ticker[0]) html_escape(esc_ticker, sizeof(esc_ticker), ticker);
        if (name && name[0]) html_escape(esc_name, sizeof(esc_name), name);
        double disp = (double)bal / (double)zcl_pow10(decimals);
        int nn = snprintf(out + tr_off, outmax - tr_off,
            "<tr><td><span class='pill pill-z'>%s</span></td>"
            "<td>%s</td>"
            "<td class='zcl' style='color:#a78bfa'>%.*f</td></tr>",
            esc_ticker[0] ? esc_ticker : "\xe2\x80\x94",
            esc_name[0] ? esc_name : "\xe2\x80\x94",
            decimals, disp);
        if (nn > 0) tr_off += (size_t)nn;
    }
    out[tr_off] = '\0';
    return tr_off;
}
