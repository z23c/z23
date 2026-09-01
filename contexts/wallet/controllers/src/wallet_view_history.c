/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "controllers/wallet_view_internal.h"
#include "controllers/wallet_controller.h"
#include "views/wallet_view_history_view.h"
#include "util/log_macros.h"

enum history_filter_mode {
    HISTORY_FILTER_ALL = 0,
    HISTORY_FILTER_SENT = 1,
    HISTORY_FILTER_RECV = 2,
};

static enum history_filter_mode history_filter_parse(const char *filter)
{
    if (filter && strcmp(filter, "sent") == 0)
        return HISTORY_FILTER_SENT;
    if (filter && strcmp(filter, "recv") == 0)
        return HISTORY_FILTER_RECV;
    return HISTORY_FILTER_ALL;
}

static const char *history_filter_name(enum history_filter_mode mode)
{
    switch (mode) {
    case HISTORY_FILTER_SENT: return "sent";
    case HISTORY_FILTER_RECV: return "recv";
    default: return "all";
    }
}

static int history_filter_restrict(enum history_filter_mode mode)
{
    return mode == HISTORY_FILTER_ALL ? 0 : 1;
}

static int history_filter_from_me(enum history_filter_mode mode)
{
    return mode == HISTORY_FILTER_SENT ? 1 : 0;
}

static int history_query_count(sqlite3 *db, enum history_filter_mode mode,
                               const char *search_hex)
{
    return wv_count_ledger_rows(db, history_filter_restrict(mode),
                                history_filter_from_me(mode), search_hex);
}

/* ── History (/wallet/history) ──────────────────────────────── */

size_t serve_history(uint8_t *r, size_t max, int page,
                            const char *filter, const char *search) {
    sqlite3 *db = wv_open_db();
    if (!db) {
        size_t off = wv_emit_header(r, max, "History — Z23", "/wallet/history");
        off += template_render(TMPL_LOADING, NULL, 0,
            (char *)r + off, max - off);
        wv_emit_footer(r, max, &off);
        return off;
    }

    int tip = wv_effective_tip(db);
    int per_page = 50;

    size_t off = wv_emit_header(r, max, "History — Z23", "/wallet/history");

    enum history_filter_mode filter_mode = history_filter_parse(filter);

    /* Search by txid prefix */
    char safe_search[65] = "";
    if (search && search[0]) {
        size_t si = 0;
        for (size_t i = 0; search[i] && si < 64; i++) {
            char c = search[i];
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                (c >= 'A' && c <= 'F'))
                safe_search[si++] = c;
        }
        safe_search[si] = '\0';
    }

    int tx_count = history_query_count(db, filter_mode, safe_search);

    int total_pages = (tx_count + per_page - 1) / per_page;
    if (page >= total_pages && total_pages > 0) page = total_pages - 1;

    /* Filter tabs with counts */
    const char *f = history_filter_name(filter_mode);
    int c_all = history_query_count(db, HISTORY_FILTER_ALL, NULL);
    int c_sent = history_query_count(db, HISTORY_FILTER_SENT, NULL);
    int c_recv = history_query_count(db, HISTORY_FILTER_RECV, NULL);
    {
        char ca[16], cs[16], cr[16], cnt[16], pg[16], pgs[16];
        snprintf(ca, sizeof(ca), "%d", c_all);
        snprintf(cs, sizeof(cs), "%d", c_sent);
        snprintf(cr, sizeof(cr), "%d", c_recv);
        snprintf(cnt, sizeof(cnt), "%d", tx_count);
        snprintf(pg, sizeof(pg), "%d", page + 1);
        snprintf(pgs, sizeof(pgs), "%d", total_pages > 0 ? total_pages : 1);
        bool is_all = (strcmp(f, "all") == 0 || !filter);
        struct template_var hv[] = {
            { "all_active",   is_all ? "active" : "" },
            { "sent_active",  strcmp(f, "sent") == 0 ? "active" : "" },
            { "recv_active",  strcmp(f, "recv") == 0 ? "active" : "" },
            { "c_all",        ca },
            { "c_sent",       cs },
            { "c_recv",       cr },
            { "search",       safe_search },
            { "filter",       f },
            { "count",        cnt },
            { "count_plural", tx_count == 1 ? "" : "s" },
            { "page",         pg },
            { "pages",        pgs },
        };
        off += template_render(TMPL_HISTORY_HEADER, hv, 12,
            (char *)r + off, max - off);
    }

    /* Timeline view (tx-cards). Fetch the page of ledger rows via the
     * port, then render the cards via the history view. */
    {
        struct wallet_view_ledger_row rows[64];
        int n_rows = wv_list_ledger_rows(db, rows,
            sizeof(rows) / sizeof(rows[0]),
            true, history_filter_restrict(filter_mode),
            history_filter_from_me(filter_mode), safe_search,
            per_page, page * per_page);
        wv_render_history_cards(r, max, &off, rows, n_rows, tip);
    }

    /* Shielded note activity — show recent note deposits */
    if (page == 0 && (strcmp(f, "all") == 0 || strcmp(f, "recv") == 0)) {
        struct wallet_view_note_row notes[10];
        int n_notes = wv_list_recent_notes(db, notes,
            sizeof(notes) / sizeof(notes[0]), true, 0);
        wv_render_history_notes(r, max, &off, notes, n_notes);
    }

    /* Pagination (preserve filter + search) */
    if (total_pages > 1) {
        char newer[256] = "", older[256] = "";
        const char *qs = safe_search[0] ? safe_search : "";
        const char *qp = safe_search[0] ? "&amp;q=" : "";
        if (page > 0)
            snprintf(newer, sizeof(newer),
                "<a href='/wallet/history?page=%d&amp;filter=%s%s%s'>"
                "&larr; Newer</a>", page - 1, f, qp, qs);
        if (page < total_pages - 1)
            snprintf(older, sizeof(older),
                "<a href='/wallet/history?page=%d&amp;filter=%s%s%s'>"
                "Older &rarr;</a>", page + 1, f, qp, qs);
        struct template_var pv[] = {
            { "newer_link", newer },
            { "older_link", older },
        };
        off += template_render(TMPL_PAGINATION, pv, 2,
            (char *)r + off, max - off);
    }

    wv_emit_footer(r, max, &off);
    sqlite3_close(db);
    return off;
}

/* ── Coins (/wallet/coins) — Full UTXO audit view ──────────── */

/* ── Transaction Detail (/wallet/tx/:txid) ──────────────────── */

size_t serve_tx_detail(uint8_t *r, size_t max, const char *txid_hex) {
    sqlite3 *db = wv_open_db();
    if (!db) {
        size_t off = wv_emit_header(r, max, "Transaction — Z23", "/wallet/history");
        off += template_render(TMPL_LOADING, NULL, 0,
            (char *)r + off, max - off);
        wv_emit_footer(r, max, &off);
        return off;
    }

    int tip = wv_effective_tip(db);
    size_t off = wv_emit_header(r, max, "Transaction — Z23", "/wallet/history");

    /* Sanitize txid: only hex chars, max 64 */
    char safe_txid[65] = "";
    {
        size_t si = 0;
        for (size_t i = 0; txid_hex && txid_hex[i] && si < 64; i++) {
            char c = txid_hex[i];
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                (c >= 'A' && c <= 'F'))
                safe_txid[si++] = c;
        }
        safe_txid[si] = '\0';
    }

    if (strlen(safe_txid) < 64) {
        off += template_render(TMPL_TX_INVALID, NULL, 0,
            (char *)r + off, max - off);
        wv_emit_footer(r, max, &off);
        sqlite3_close(db);
        return off;
    }

    /* Convert to uppercase for BLOB comparison */
    char upper_txid[65];
    for (int i = 0; i < 64; i++)
        upper_txid[i] = (safe_txid[i] >= 'a' && safe_txid[i] <= 'f')
            ? (char)(safe_txid[i] - 32) : safe_txid[i];
    upper_txid[64] = '\0';

    /* Lookup wallet transaction */
    int block_height = 0, from_me = 0;
    int64_t fee = 0, btime = 0;

    struct wallet_view_tx_header hdr = {0};
    bool found = wv_lookup_tx_header(db, upper_txid, &hdr);
    if (found) {
        block_height = hdr.block_height;
        from_me = hdr.from_me;
        fee = hdr.fee;
        btime = hdr.block_time;
    }

    if (!found) {
        off += template_render(TMPL_TX_NOT_FOUND, NULL, 0,
            (char *)r + off, max - off);
        wv_emit_footer(r, max, &off);
        sqlite3_close(db);
        return off;
    }

    int confs = (tip > 0 && block_height > 0) ? (tip - block_height + 1) : 0;
    if (confs < 0) confs = 0;
    bool is_recv = (from_me == 0);
    int conf_pct = confs >= 6 ? 100 : (confs * 100 / 6);

    char rel_time[48], abs_time[32];
    wv_format_relative_time(btime, rel_time, sizeof(rel_time));
    wv_format_time(btime, abs_time, sizeof(abs_time));

    char esc_rel[96], esc_abs[64];
    html_escape(esc_rel, sizeof(esc_rel), rel_time);
    html_escape(esc_abs, sizeof(esc_abs), abs_time);

    /* Fee row (only for outgoing with fee) */
    char fee_row[128] = "";
    if (fee > 0 && !is_recv)
        snprintf(fee_row, sizeof(fee_row),
            "<div class='lbl'>Fee</div>"
            "<div class='val zcl'>%.8f ZCL</div>",
            (double)fee / 1e8);

    /* Pre-render wallet outputs (fetch via port, render via view) */
    char outputs_section[4096];
    {
        struct wallet_view_tx_output outs[64];
        int n_outs = wv_list_tx_outputs(db, upper_txid, outs,
            sizeof(outs) / sizeof(outs[0]));
        wv_render_tx_outputs(outputs_section, sizeof(outputs_section),
            outs, n_outs);
    }

    /* Format template variables */
    char confs_s[16], conf_pct_s[8], block_h_s[16];
    snprintf(confs_s, sizeof(confs_s), "%d", confs);
    snprintf(conf_pct_s, sizeof(conf_pct_s), "%d", conf_pct);
    snprintf(block_h_s, sizeof(block_h_s), "%d", block_height);

    struct template_var vars[] = {
        { "parent_href",     "/wallet/history" },
        { "parent_label",    "History" },
        { "current",         "Transaction" },
        { "pill_class",      is_recv ? "pill-t" : "pill-pending" },
        { "direction",       is_recv ? "Received" : "Sent" },
        { "color",           is_recv ? "#34d399" : "#f87171" },
        { "heading",         is_recv ? "Incoming Transaction"
                                     : "Outgoing Transaction" },
        { "rel_time",        esc_rel },
        { "abs_time",        esc_abs },
        { "confs",           confs_s },
        { "conf_plural",     confs == 1 ? "" : "s" },
        { "conf_status",     confs >= 6 ? "Confirmed" : "Pending" },
        { "conf_pct",        conf_pct_s },
        { "conf_color",      confs >= 6 ? "#34d399"
                             : confs >= 1 ? "#fbbf24" : "#f87171" },
        { "txid",            safe_txid },
        { "block_height",    block_h_s },
        { "fee_row",         fee_row },
        { "outputs_section", outputs_section },
    };
    off += template_render(TMPL_TX_DETAIL, vars,
        sizeof(vars) / sizeof(vars[0]), (char *)r + off, max - off);

    wv_emit_footer(r, max, &off);
    sqlite3_close(db);
    return off;
}

/* ── Node / Command Center (/wallet/node) ───────────────────── */
