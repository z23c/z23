/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet dashboard-page view: the "Tokens" card and the "Recent
 * transactions" list for /wallet. The controller fetches rows through the
 * wallet_view port; this file owns the HTML fragments. */

#include "views/wallet_view_dashboard_view.h"
#include "views/wallet_templates_gen.h"
#include "views/format_helpers.h"
#include "util/template.h"

#include <stdio.h>
#include <string.h>

/* Controller helpers; forward-declared (resolve at link time).
 * html_escape comes from util/template.h. */
void wv_txid_lower(const char *txid, char *out, size_t max);
void wv_format_relative_time(int64_t timestamp, char *out, size_t max);

size_t wv_render_dashboard_tokens(char *out, size_t outmax,
                                  const struct wallet_view_token_balance *tokens,
                                  int n)
{
    size_t toff = 0;
    int tok_count = 0;

    for (int i = 0; tokens && i < n && toff + 300 < outmax; i++) {
        const char *ticker = tokens[i].ticker;
        int decimals = tokens[i].decimals;
        int64_t bal = tokens[i].balance;
        if (!ticker || !ticker[0] || bal <= 0) continue;
        if (tok_count == 0)
            toff += (size_t)snprintf(out + toff, outmax - toff,
                "<div style='margin:12px 0'>"
                "<div class='section-header'>"
                "<span>Tokens</span>"
                "<a href='/wallet/coins'>View all</a></div>");
        double div = (double)zcl_pow10(decimals);
        char esc_tk[32];
        html_escape(esc_tk, sizeof(esc_tk), ticker);
        toff += (size_t)snprintf(out + toff, outmax - toff,
            "<div class='tx-row'>"
            "<div><span class='pill pill-z'>%s</span></div>"
            "<div style='text-align:right;color:#a78bfa;"
            "font-family:\"JetBrains Mono\",monospace;"
            "font-weight:700'>%.*f</div></div>",
            esc_tk, decimals, (double)bal / div);
        tok_count++;
    }
    if (tok_count > 0)
        snprintf(out + toff, outmax - toff, "</div>");
    return strlen(out);
}

/* Render one ledger row of the "Recent transactions" list into `out`
 * (size `outmax`). Returns true when the row was rendered (zero-value
 * entries and rows without a txid are skipped); `*out_added` receives the
 * bytes written. */
static bool wv_render_one_tx_row(char *out, size_t outmax,
                                 const struct wallet_view_ledger_row *row,
                                 int tip, size_t *out_added)
{
    const char *txid = row->txid;
    int height = row->height;
    int64_t btime = row->block_time;
    int from_me = row->from_me;
    int64_t wallet_output = row->wallet_output;
    int64_t wallet_input = row->wallet_input;
    if (!txid) return false;
    int64_t display_amount = wallet_output;
    if (from_me && wallet_input > 0) {
        display_amount = wallet_input - wallet_output;
        if (display_amount < 0) display_amount = 0;
    }
    if (display_amount == 0) return false; /* skip zero-value entries */

    bool is_recv = (from_me == 0);
    char rel_time[48], esc_rel[96];
    wv_format_relative_time(btime, rel_time, sizeof(rel_time));
    html_escape(esc_rel, sizeof(esc_rel), rel_time);
    char lower_tx[65];
    wv_txid_lower(txid, lower_tx, sizeof(lower_tx));
    int confs = (tip > 0 && height > 0) ? (tip - height + 1) : 0;
    char amt[32];
    zcl_format_zcl_short(amt, sizeof(amt), display_amount);
    char conf_str[32] = "";
    /* Show time, not conf count */
    (void)confs;
    char link[80];
    snprintf(link, sizeof(link), "/wallet/tx/%s", lower_tx);

    struct template_var tv[] = {
        { "link",            link },
        { "direction_class", is_recv ? "recv" : "send" },
        { "sign",            is_recv ? "+" : "-" },
        { "amount",          amt },
        { "time_style",      "" },
        { "time_label",      esc_rel },
        { "conf_label",      conf_str },
    };
    *out_added = template_render(TMPL_TX_ROW, tv, 7, out, outmax);
    return true;
}

/* Render one shielded note row of the "Recent transactions" list into
 * `out` (size `outmax`). Returns the bytes written. */
static size_t wv_render_one_note_row(char *out, size_t outmax,
                                     int64_t value, int height, int tip)
{
    int nc = (tip > 0 && height > 0) ? (tip - height + 1) : 0;
    if (nc < 0) nc = 0;
    char amt[32];
    zcl_format_zcl_short(amt, sizeof(amt), value);
    char nc_str[32] = "";
    (void)nc;

    struct template_var tv[] = {
        { "link",            "/wallet/coins" },
        { "direction_class", "recv" },
        { "sign",            "+" },
        { "amount",          amt },
        { "time_style",      " style='color:#a78bfa'" },
        { "time_label",      "&#x1F512; Private" },
        { "conf_label",      nc_str },
    };
    return template_render(TMPL_TX_ROW, tv, 7, out, outmax);
}

/* Render the empty-state message shown when no recent entry was listed. */
static void wv_render_recent_empty_state(char *out, size_t outmax,
                                         int64_t total_balance)
{
    snprintf(out, outmax,
        "<div class='empty-state'>%s</div>",
        total_balance > 0 ? "Transaction history syncing..."
                          : "No transactions yet");
}

size_t wv_render_dashboard_recent(char *out, size_t outmax,
                                  const struct wallet_view_ledger_row *rows,
                                  int n_rows,
                                  const struct wallet_view_note_row *notes,
                                  int n_notes,
                                  int tip, int64_t total_balance)
{
    size_t txoff = 0;
    int tx_shown = 0;

    for (int i = 0; rows && i < n_rows &&
                    txoff + 512 < outmax && tx_shown < 5; i++) {
        size_t added = 0;
        if (wv_render_one_tx_row(out + txoff, outmax - txoff,
                                 &rows[i], tip, &added)) {
            txoff += added;
            tx_shown++;
        }
    }

    /* Shielded notes */
    if (tx_shown < 5) {
        for (int i = 0; notes && i < n_notes && tx_shown < 5 &&
                        txoff + 512 < outmax; i++) {
            txoff += wv_render_one_note_row(out + txoff, outmax - txoff,
                                            notes[i].value, notes[i].height,
                                            tip);
            tx_shown++;
        }
    }

    if (tx_shown == 0)
        wv_render_recent_empty_state(out, outmax, total_balance);
    return strlen(out);
}
