/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "platform/time_compat.h"
#include "controllers/wallet_view_internal.h"
#include "controllers/wallet_controller.h"
#include "views/wallet_view_dashboard_view.h"
#include "sync/sync_state.h"
#include "util/log_macros.h"

/* ── Dashboard (/wallet) ────────────────────────────────────── */

static size_t render_loading_page(uint8_t *r, size_t max) {
    size_t off = wv_emit_header(r, max, "Z23 Wallet", "/wallet");
    off += template_render(TMPL_LOADING, NULL, 0,
        (char *)r + off, max - off);
    wv_emit_footer(r, max, &off);
    return off;
}

/* If a shield operation is pending, adjust displayed balances.
 * The blockchain hasn't confirmed yet, but the user expects to see
 * the funds moving from public -> private immediately. */
static void apply_pending_shield_to_display(int64_t *transparent,
    int64_t *shielded) {
    if (g_shield_pending_amount > 0 && g_shield_pending_since > 0) {
        int64_t pending = g_shield_pending_amount;
        if (pending > *transparent) pending = *transparent;
        *transparent -= pending;
        *shielded += pending;
    }
}

/* Map internal state names to user-friendly labels */
static const char *sync_label_for_state(bool synced,
    const char *sync_raw) {
    static const struct {
        const char *match;
        const char *label;
    } labels[] = {
        { "download", "Syncing blocks..." },
        { "header",   "Syncing headers..." },
        { "connect",  "Connecting..." },
        { "idle",     "Ready" },
        { "scan",     "Scanning..." },
    };
    if (synced)
        return "Synced";
    for (size_t i = 0; i < sizeof(labels) / sizeof(labels[0]); i++)
        if (strstr(sync_raw, labels[i].match))
            return labels[i].label;
    return "Syncing...";
}

/* Sync badge CSS class */
static const char *sync_class_for_state(bool synced,
    const char *sync_raw) {
    if (synced)
        return "pill-synced";
    return strstr(sync_raw, "idle") ? "pill-ready" : "pill-syncing";
}

/* Format balance with minimal decimals */
static void format_balance_display(char *buf, size_t buflen,
    int64_t total_balance) {
    double bal_f = (double)total_balance / (double)ZATOSHI_PER_ZCL;
    if (total_balance == 0)
        snprintf(buf, buflen, "0.00");
    else if (total_balance % 1000000 == 0)
        snprintf(buf, buflen, "%.2f", bal_f);
    else if (total_balance % 10000 == 0)
        snprintf(buf, buflen, "%.4f", bal_f);
    else
        snprintf(buf, buflen, "%.8f", bal_f);
}

/* Privacy percentage */
static int privacy_percent(int64_t shielded, int64_t total_balance) {
    if (total_balance > 0)
        return (int)(100 * shielded / total_balance);
    return 0;
}

static const char *privacy_meter_color(int pct) {
    return pct == 100 ? "#34d399" :
           pct >= 50  ? "#a78bfa" :
           pct > 0    ? "#fbbf24" : "#f87171";
}

/* Breakdown text — contextual based on privacy state */
static void format_breakdown_html(char *breakdown, size_t buflen,
    int pct, int64_t transparent, int64_t shielded,
    bool synced, const char *sync_raw) {
    if (pct >= 95 && shielded > 0 && transparent > 0) {
        /* Nearly all private — don't clutter with dust amounts */
        snprintf(breakdown, buflen,
            "<span style='color:#34d399'>&#x1F512; Funds shielded</span>");
    } else if (transparent > 0 && shielded > 0) {
        char t_fmt[32], s_fmt[32];
        zcl_format_zcl_short(t_fmt, sizeof(t_fmt), transparent);
        zcl_format_zcl_short(s_fmt, sizeof(s_fmt), shielded);
        snprintf(breakdown, buflen,
            "%s public + %s private", t_fmt, s_fmt);
    } else if (shielded > 0) {
        snprintf(breakdown, buflen,
            "<span style='color:#34d399'>&#x1F512; All funds private</span>");
    } else if (transparent > 0) {
        char t_fmt[32];
        zcl_format_zcl_short(t_fmt, sizeof(t_fmt), transparent);
        snprintf(breakdown, buflen, "%s public", t_fmt);
    }
    /* Append sync note if still syncing */
    if (!synced && !strstr(sync_raw, "idle")) {
        size_t blen = strlen(breakdown);
        snprintf(breakdown + blen, buflen - blen,
            "</span></div>"
            "<div class='sync-note'>"
            "Syncing &mdash; balance updating</div>"
            "<div style='display:none'><span>");
    }
}

/* Privacy card (nudge / pending / done) */
static void render_privacy_card(char *privacy_buf, size_t buflen,
    int64_t transparent) {
    int shield_st = wv_shield_check_status();
    if (shield_st == 1) {
        char el_s[16];
        snprintf(el_s, sizeof(el_s), "%d",
            (int)(platform_time_wall_time_t() - g_shield_pending_since));
        struct template_var pv[] = { { "elapsed", el_s } };
        template_render(TMPL_SHIELD_PENDING, pv, 1,
            privacy_buf, buflen);
    } else if (shield_st == 2) {
        /* Shield op completed — show what happened honestly */
        char amt_s[32];
        zcl_format_zcl(amt_s, sizeof(amt_s), g_shield_pending_amount);
        const char *msg = (transparent <= 0)
            ? "Moved to z-address. Not linkable to your transparent address."
            : "Moved to z-address. Transparent balance remains — shield to complete.";
        struct template_var dv[] = {
            { "amount", amt_s }, { "message", msg }
        };
        size_t dlen = template_render(TMPL_SHIELD_DONE, dv, 2,
            privacy_buf, buflen);
        /* If there's STILL shieldable balance, also show the nudge */
        if (transparent > (int64_t)(FEE_ZCL * ZATOSHI_PER_ZCL + 1) &&
            dlen < buflen - 256) {
            char t_fmt[32];
            zcl_format_zcl(t_fmt, sizeof(t_fmt), transparent);
            struct template_var pv[] = { { "amount", t_fmt } };
            template_render(TMPL_PRIVACY_NUDGE, pv, 1,
                privacy_buf + dlen, buflen - dlen);
        }
    } else if (transparent > (int64_t)(FEE_ZCL * ZATOSHI_PER_ZCL + 1)) {
        /* Only show nudge if transparent balance exceeds fee.
         * Amounts at or below the min-relay fee cannot pay a shield. */
        char t_fmt[32];
        zcl_format_zcl(t_fmt, sizeof(t_fmt), transparent);
        struct template_var pv[] = { { "amount", t_fmt } };
        template_render(TMPL_PRIVACY_NUDGE, pv, 1,
            privacy_buf, buflen);
    }
}

/* Token cards — fetch top-5 held tokens via the port, render via
 * the dashboard view. */
static void render_token_cards(sqlite3 *db, char *token_buf,
    size_t buflen) {
    struct wallet_view_token_balance tokens[5];
    int n_tokens = wv_list_token_cards(db, tokens,
        sizeof(tokens) / sizeof(tokens[0]));
    wv_render_dashboard_tokens(token_buf, buflen,
        tokens, n_tokens);
}

/* Recent transactions — fetch recent ledger rows + shielded notes
 * via the port, render via the dashboard view (which caps at 5
 * total and falls back to the empty-state). */
static void render_recent_transactions(sqlite3 *db, char *tx_buf,
    size_t buflen, int tip, int64_t total_balance) {
    struct wallet_view_ledger_row rows[20];
    int n_rows = wv_list_ledger_rows(db, rows,
        sizeof(rows) / sizeof(rows[0]),
        false, 0, 0, NULL, 0, 0);
    struct wallet_view_note_row notes[5];
    int n_notes = wv_list_recent_notes(db, notes,
        sizeof(notes) / sizeof(notes[0]), false, 5);
    wv_render_dashboard_recent(tx_buf, buflen,
        rows, n_rows, notes, n_notes, tip, total_balance);
}

/* Backup warning */
static void render_backup_warning(char *backup_buf, size_t buflen,
    int64_t total_balance) {
    if (total_balance > 0 && g_wv_datadir) {
        char bk_path[1024];
        snprintf(bk_path, sizeof(bk_path), "%s/wallet.backup", g_wv_datadir);
        if (access(bk_path, F_OK) != 0) {
            struct template_var bv[] = { { "address", PRIMARY_ADDR } };
            template_render(TMPL_BACKUP_WARNING, bv, 1,
                backup_buf, buflen);
        }
    }
}

/* Node status strip (compact, replaces old Power Node card) */
static void render_node_status_strip(sqlite3 *db, char *node_strip,
    size_t buflen, bool synced, const char *sync_raw, int tip) {
    int peers = wv_query_int(db, "SELECT count(*) FROM peers");
    bool is_ready = synced || strstr(sync_raw, "idle");
    const char *node_status = synced ? "Synced" :
                              strstr(sync_raw, "idle") ? "Ready" : "Syncing";
    const char *node_color = is_ready ? "#34d399" : "#fbbf24";
    char peers_str[16], height_str[16];
    snprintf(peers_str, sizeof(peers_str), "%d", peers);
    snprintf(height_str, sizeof(height_str), "%d", tip);

    struct template_var nv[] = {
        { "peers",        peers_str },
        { "height",       height_str },
        { "status",       node_status },
        { "status_color", node_color },
    };
    template_render(TMPL_NODE_STATUS_STRIP, nv, 4,
        node_strip, buflen);
}

size_t serve_dashboard(uint8_t *r, size_t max) {
    sqlite3 *db = wv_open_db();
    if (!db) {
        return render_loading_page(r, max);
    }

    int tip = wv_effective_tip(db);
    sqlite3_close(db);

    /* Sync wallet from zclassicd before displaying balance.
     * This ensures the dashboard never shows stale data.
     * Only sync when explicitly enabled (live mode, not tests). */
    if (g_sync_enabled)
        wv_sync_wallet_from_zclassicd();

    db = wv_open_db();
    if (!db) {
        return render_loading_page(r, max);
    }

    /* Ground-truth transparent balance (P2PKH + P2SH change addresses) */
    int t_utxos = 0;
    int64_t transparent = wv_query_ground_truth_balance(db, &t_utxos);

    /* Shielded: verified notes minus spent nullifiers */
    int z_notes = 0;
    int64_t shielded = wv_query_shielded_balance(db, &z_notes);

    apply_pending_shield_to_display(&transparent, &shielded);

    int64_t total_balance = transparent + shielded;

    const char *sync_raw = sync_state_name(sync_get_state());
    bool synced = (sync_get_state() == SYNC_AT_TIP);

    const char *sync_label = sync_label_for_state(synced, sync_raw);

    const char *sync_class = sync_class_for_state(synced, sync_raw);

    char bal_str[32];
    format_balance_display(bal_str, sizeof(bal_str), total_balance);

    int pct = privacy_percent(shielded, total_balance);
    const char *pct_color = privacy_meter_color(pct);
    char pct_str[12];
    snprintf(pct_str, sizeof(pct_str), "%d", pct);

    char breakdown[256] = "";
    format_breakdown_html(breakdown, sizeof(breakdown),
        pct, transparent, shielded, synced, sync_raw);

    char privacy_buf[512] = "";
    render_privacy_card(privacy_buf, sizeof(privacy_buf), transparent);

    char token_buf[2048] = "";
    render_token_cards(db, token_buf, sizeof(token_buf));

    char tx_buf[4096] = "";
    render_recent_transactions(db, tx_buf, sizeof(tx_buf),
        tip, total_balance);

    char backup_buf[512] = "";
    render_backup_warning(backup_buf, sizeof(backup_buf), total_balance);

    char node_strip[512] = "";
    render_node_status_strip(db, node_strip, sizeof(node_strip),
        synced, sync_raw, tip);

    /* Render full dashboard via TMPL_DASHBOARD */
    size_t off = wv_emit_header(r, max, "Z23 Wallet", "/wallet");

    /* Only show "Details" link when there's something to shield */
    const char *details_link = (transparent > (int64_t)(FEE_ZCL * ZATOSHI_PER_ZCL + 1))
        ? "<a href='/wallet/shield' style='color:#888;font-size:14px'>Shield</a>"
        : "";

    struct template_var vars[] = {
        { "sync_class",     sync_class },
        { "sync_label",     sync_label },
        { "balance",        bal_str },
        { "pct_color",      pct_color },
        { "pct",            pct_str },
        { "breakdown",      breakdown },
        { "details_link",   details_link },
        { "privacy_card",   privacy_buf },
        { "token_cards",    token_buf },
        { "recent_txs",     tx_buf },
        { "backup_warning", backup_buf },
        { "node_strip",     node_strip },
    };
    off += template_render(TMPL_DASHBOARD, vars, 12,
        (char *)r + off, max - off);

    /* Dashboard live-update JS */
    APPEND(off, r, max,
        "<script>"
        "function fmt(z){var v=z/1e8;if(z===0)return'0.00';"
        "if(z%%1000000===0)return v.toFixed(2);"
        "if(z%%10000===0)return v.toFixed(4);return v.toFixed(8);}"
        "window._dashUpdate=function(d){"
        "var b=document.getElementById('bal');"
        "if(b){var n=fmt(d.balance+d.shielded)+' ZCL';"
        "if(b.textContent!==n){b.textContent=n;}}"
        "var s=document.getElementById('sync');"
        "if(s){var st=d.sync==='at_tip'?'Synced':"
        "d.sync==='idle'?'Ready':"
        "d.sync.indexOf('download')>=0?'Syncing blocks...':"
        "d.sync.indexOf('header')>=0?'Syncing headers...':"
        "d.sync.indexOf('connect')>=0?'Connecting...':"
        "d.sync.indexOf('scan')>=0?'Scanning...':"
        "d.sync;"
        "s.textContent=st;"
        "s.className='pill sync-badge '+"
        "(d.sync==='at_tip'?'pill-synced':"
        "d.sync==='idle'?'pill-ready':'pill-syncing');}"
        "var sn=document.querySelector('.sync-note');"
        "if(sn){if(d.sync==='at_tip')sn.style.display='none';"
        "else sn.style.display='';}"
        "var bd=document.getElementById('breakdown');"
        "if(bd){if(d.balance>0&&d.shielded>0)"
        "bd.textContent=fmt(d.balance)+' public + '+fmt(d.shielded)+' private';"
        "else if(d.shielded>0)bd.textContent='All funds private';"
        "else if(d.balance>0)bd.textContent=fmt(d.balance)+' public';"
        "else bd.textContent='';}"
        "var lk=document.getElementById('lock');"
        "if(lk){var tot=d.balance+d.shielded;"
        "var pct=tot>0?Math.round(100*d.shielded/tot):0;"
        "lk.style.width=pct+'%%';"
        "var c=pct===100?'#34d399':pct>=50?'#a78bfa':"
        "pct>0?'#fbbf24':'#f87171';"
        "lk.style.background=c;}"
        "var pm=document.getElementById('privacy-meter');"
        "if(pm){var pl=pm.querySelector('span');"
        "if(pl){var tot2=d.balance+d.shielded;"
        "var p2=tot2>0?Math.round(100*d.shielded/tot2):0;"
        "pl.textContent=p2+'%% private';}}};"
        "</script>");

    /* Pre-fill status bar so it's not blank on load */
    APPEND(off, r, max,
        "<script>document.addEventListener('DOMContentLoaded',function(){"
        "var h=document.getElementById('sb-h');"
        "if(h)h.textContent='Block %d';});</script>", tip);

    wv_emit_footer(r, max, &off);
    sqlite3_close(db);
    return off;
}

static struct {
    int height;
    int64_t balance, shielded, speed_bal;
    int t_utxos, z_notes;
} pulse_cache;

size_t serve_pulse(uint8_t *r, size_t max) {
    sqlite3 *db = wv_open_db();
    int height = 0, peers = 0, mempool = 0;
    int64_t balance = 0, shielded = 0, speed_bal = 0;
    int t_utxos = 0, z_notes = 0;

    /* Check if a pending shield operation completed */
    if (g_shield_opid[0]) {
        int ss = wv_shield_check_status();
        if (ss == 2 || ss == -1)
            g_balance_dirty = 1; /* shield done — force recompute */
    }

    if (db) {
        height = wv_effective_tip(db);
        peers = wv_query_int(db,  "SELECT count(*) FROM peers");
        mempool = wv_query_int(db, "SELECT count(*) FROM mempool_entries");

        if (g_balance_dirty) {
            /* Wallet changed — sync from zclassicd then recompute */
            sqlite3_close(db);
            wv_sync_wallet_from_zclassicd();
            db = wv_open_db();
            if (!db) return 0;
        }

        if (height != pulse_cache.height || pulse_cache.height == 0 ||
            g_balance_dirty) {
            g_balance_dirty = 0;
            /* Recompute balances */
            balance = wv_query_ground_truth_balance(db, &t_utxos);
            shielded = wv_query_shielded_balance(db, &z_notes);
            speed_bal = wv_query_speed_balance(db);

            pulse_cache.height = height;
            pulse_cache.balance = balance;
            pulse_cache.shielded = shielded;
            pulse_cache.speed_bal = speed_bal;
            pulse_cache.t_utxos = t_utxos;
            pulse_cache.z_notes = z_notes;
        } else {
            /* Same height — serve cached balances, only refresh peers/mempool */
            balance = pulse_cache.balance;
            shielded = pulse_cache.shielded;
            speed_bal = pulse_cache.speed_bal;
            t_utxos = pulse_cache.t_utxos;
            z_notes = pulse_cache.z_notes;
        }
        sqlite3_close(db);
    }

    /* Adjust pulse balances for pending shield operation */
    if (g_shield_pending_amount > 0 && g_shield_pending_since > 0) {
        int64_t pending = g_shield_pending_amount;
        if (pending > balance) pending = balance;
        balance -= pending;
        shielded += pending;
    }

    const char *sync = sync_state_name(sync_get_state());

    struct wv_pulse p = {
        .height = height, .balance = balance, .shielded = shielded,
        .speed_balance = speed_bal, .t_utxos = t_utxos, .z_notes = z_notes,
        .peers = peers, .mempool = mempool
    };
    snprintf(p.sync, sizeof(p.sync), "%s", sync ? sync : "idle");
    return wv_render_pulse(r, max, &p);
}

/* ── Send Review (/wallet/send/review POST) ─────────────────── */
/* Intermediate confirmation step: show details before executing. */
