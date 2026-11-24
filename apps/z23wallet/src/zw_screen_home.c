/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Home, as beta13 draws it: the sync row (quiet pill when synced,
 * a coloured banner otherwise, the Connect card before the node answers),
 * the Summary group (private-balance hero with auto-fitting amount, Total,
 * qualifier/helper, Send/Receive, the amber fix-it card, the unconfirmed
 * warning) and the Address Balances group (pill, elided address, right-
 * aligned amount per address). Groups stack under 820 px of content. */
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "zw.h"

#define DOT "\xE2\x97\x8F"
#define NBSP "\xC2\xA0"
#define MID "\xC2\xB7"
#define DASH "\xE2\x80\x94"
#define ELLIPSIS "\xE2\x80\xA6"

enum hero_state { HERO_UNAVAILABLE, HERO_WARMING, HERO_SYNCED };

static bool known(const struct zw_model *m) { return m->have_wallet && m->wallet.known; }

static enum hero_state hero_state(const struct zw_model *m, int64_t now_s)
{
    if (!known(m)) return HERO_UNAVAILABLE;
    if (m->conn != ZW_CONN_ONLINE || !zw_model_synced(m, now_s)) return HERO_WARMING;
    return HERO_SYNCED;
}

static bool empty_wallet(const struct zw_model *m) { return known(m) && m->wallet.total == 0; }

/* ---- table source: home.balances ---- */

static size_t bal_rows(void *ctx)
{
    const struct zw_model *m = ctx;
    if (!m->bal) return m->conn == ZW_CONN_ONLINE ? 1u : 0u; /* "Loading..." */
    return m->bal->n + (m->bal->more ? 1u : 0u);
}

static const char *pill_label(uint8_t kind)
{
    return kind == ZW_ADDR_PUBLIC ? "PUBLIC" : kind == ZW_ADDR_SPROUT ? "Private (legacy)" : "Private";
}

static bool bal_cell(void *ctx, size_t row, size_t col, char *buf, size_t cap, enum gui_style *style)
{
    const struct zw_model *m = ctx;
    if (!m->bal || row >= m->bal->n) {
        if (col == 0 && !m->bal) snprintf(buf, cap, "Loading...");
        else if (col == 0) snprintf(buf, cap, "+%zu more", m->bal->more);
        else buf[0] = 0;
        *style = GS_MUTED;
        return true;
    }
    const struct zw_bal_row *r = &m->bal->rows[row];
    if (col == 0) {
        snprintf(buf, cap, "%s\t%s", pill_label(r->kind), r->addr);
        *style = r->kind == ZW_ADDR_PUBLIC ? GS_PILL_PUBLIC : GS_PILL_PRIVATE;
    } else {
        zw_amount_format_net(r->zat, buf, cap, m->testnet);
        *style = r->unconfirmed ? GS_WARN_TEXT : GS_AMOUNT_MONO;
    }
    return true;
}

void zw_home_sources(struct gui_ui *ui, const struct zw_model *m)
{
    static struct gui_table_source src = { "home.balances", bal_rows, bal_cell, NULL, NULL };
    src.ctx = (void *)m;
    gui_ui_table_source(ui, &src);
}

bool zw_home_row_address(const struct zw_model *m, int64_t row, char *buf, size_t cap)
{
    buf[0] = 0;
    if (!m->bal || row < 0 || (size_t)row >= m->bal->n) return false;
    snprintf(buf, cap, "%s", m->bal->rows[row].addr);
    return true;
}

/* ---- tree ---- */

static void sync_row(struct gui_tree *t, const struct zw_model *m)
{
    enum zw_sync s = zw_sync_classify(m, m->now_s);
    if (m->conn != ZW_CONN_ONLINE) {
        zw_screen_connect_build(t, m);
        return;
    }
    if (s == ZW_SYNC_SYNCED || s == ZW_SYNC_LOCAL) {
        gui_box(t, "h_syncrow", GUI_ROW, GS_BODY);
        gui_attr(t, GUI_A_PAD, 6);
        gui_attr(t, GUI_A_H, 51); /* beta13: the Summary border sits 80 below the page top */
        gui_attr(t, GUI_A_ALIGN, GUI_ALIGN_CENTER);
        gui_text_bind(t, "h_pill", GS_SYNC_PILL, "home.pill");
        gui_end(t);
        return;
    }
    gui_box(t, "h_banner", GUI_ROW, s == ZW_SYNC_CONNECTING ? GS_BANNER_CONNECTING : GS_BANNER_SYNCING);
    gui_attr(t, GUI_A_PAD, 10);
    gui_attr(t, GUI_A_GAP, 10);
    gui_attr(t, GUI_A_ALIGN, GUI_ALIGN_CENTER);
    gui_text_bind(t, "h_banner_text", s == ZW_SYNC_CONNECTING ? GS_BANNER_CONNECTING : GS_BANNER_SYNCING,
                  "home.banner");
    gui_flag(t, GUI_F_WRAP);
    gui_attr(t, GUI_A_GROW, 1);
    if (s == ZW_SYNC_SYNCING || s == ZW_SYNC_FINDING) {
        gui_progress(t, "h_sync_bar", "home.sync_progress");
        gui_attr(t, GUI_A_W, 200);
    }
    gui_end(t);
}

static void hero(struct gui_tree *t, const struct zw_model *m)
{
    enum hero_state hs = hero_state(m, m->now_s);
    gui_box(t, "h_hero", GUI_COL, GS_HERO_CARD);
    gui_attr(t, GUI_A_PAD, 16);
    gui_attr(t, GUI_A_GAP, 4);
    gui_text(t, "h_hero_caption", GS_HERO_CAPTION, "PRIVATE BALANCE");
    gui_text_bind(t, "h_hero_amount", hs == HERO_SYNCED ? GS_HERO_AMOUNT_OK : GS_HERO_AMOUNT_WARM, "home.private");
    gui_flag(t, GUI_F_SELECTABLE);
    gui_text_bind(t, "h_hero_total", GS_HERO_TOTAL, "home.total");
    if (hs != HERO_SYNCED) {
        gui_text_bind(t, "h_hero_qualifier", GS_HERO_NOTE, "home.qualifier");
        gui_flag(t, GUI_F_WRAP);
    }
    if (empty_wallet(m)) {
        gui_text(t, "h_hero_helper", GS_MUTED, "Your private balance " DASH " receive ZCL to get started.");
        gui_flag(t, GUI_F_WRAP);
    }
    gui_end(t);
}

static void quick_actions(struct gui_tree *t, const struct zw_model *m)
{
    bool swap = empty_wallet(m); /* total 0: Receive becomes primary and default */
    gui_box(t, "h_actions", GUI_ROW, GS_BODY);
    gui_attr(t, GUI_A_GAP, 8);
    gui_button(t, "h_send", swap ? GS_BUTTON_SECONDARY : GS_BUTTON_PRIMARY, "Send", "home.send");
    gui_attr(t, GUI_A_GROW, 1);
    gui_attr(t, GUI_A_H, 50);
    if (!swap) gui_flag(t, GUI_F_DEFAULT);
    gui_button(t, "h_receive", swap ? GS_BUTTON_PRIMARY : GS_BUTTON_SECONDARY, "Receive", "home.receive");
    gui_attr(t, GUI_A_GROW, 1);
    gui_attr(t, GUI_A_H, 50);
    if (swap) gui_flag(t, GUI_F_DEFAULT);
    gui_end(t);
}

static void summary(struct gui_tree *t, const struct zw_model *m)
{
    zw_group_begin(t, "h_summary", "Summary", 26, 17, !m->narrow); /* stacked: natural height */
    hero(t, m);
    quick_actions(t, m);
    if (known(m) && m->wallet.publicf > 10) {
        gui_box(t, "h_fixit", GUI_COL, GS_CARD_AMBER);
        gui_attr(t, GUI_A_PAD, 12);
        gui_attr(t, GUI_A_GAP, 8);
        gui_text_bind(t, "h_fixit_text", GS_AMBER_TEXT, "home.fixit");
        gui_flag(t, GUI_F_WRAP);
        gui_box(t, "h_fixit_row", GUI_ROW, GS_BODY);
        gui_button(t, "h_shield", GS_BUTTON_AMBER, "Shield my funds", "home.shield");
        gui_end(t);
        gui_end(t);
    }
    if (m->bal && m->bal->any_unconfirmed)
        gui_text(t, "h_unconfirmed", GS_WARN_TEXT, "Some transactions are not yet confirmed");
    gui_spacer(t, 1);
    zw_group_end(t, 25, 12);
}

static void balances(struct gui_tree *t)
{
    static const struct gui_column cols[2] = { { "Address", 0, false, false },
                                               { "Amount", GUI_COL_FIT, true, false } };
    zw_group_begin(t, "h_addrs", "Address Balances", 15, 14, true);
    gui_table(t, "h_balances", "home.balances", cols, 2);
    gui_attr(t, GUI_A_GROW, 1);
    zw_group_end(t, 15, 15);
}

void zw_screen_home_build(struct gui_tree *t, const struct zw_model *m)
{
    sync_row(t, m);
    gui_box(t, "h_groups", m->narrow ? GUI_COL : GUI_ROW, GS_BODY);
    gui_attr(t, GUI_A_GROW, 1);
    gui_attr(t, GUI_A_GAP, 7);
    summary(t, m);
    balances(t);
    gui_end(t);
}

/* ---- bound text ---- */

struct sync_view { enum zw_sync s; int64_t tip_age; char h[32], age[32]; };

static void pill_text(const struct sync_view *v, char *t, size_t cap)
{
    if (v->s == ZW_SYNC_LOCAL) snprintf(t, cap, DOT " Local test network " MID " block %s", v->h);
    else if (v->tip_age >= 0)
        snprintf(t, cap, DOT NBSP NBSP "Synced  " MID "  block %s  " MID "  last block %s ago", v->h, v->age);
    else snprintf(t, cap, DOT NBSP NBSP "Synced  " MID "  block %s", v->h);
}

static void peerless_text(const struct zw_model *m, const struct sync_view *v, char *t, size_t cap)
{
    char tail[160] = "";
    if (v->tip_age >= 0) snprintf(tail, sizeof(tail), "\nYour wallet is at block %s (newest block %s old).", v->h, v->age);
    snprintf(t, cap, "%s%s", m->peerless_polls >= 36
             ? "Still no connection to the ZClassic network " DASH " please check your internet connection and firewall."
             : "Connecting to the ZClassic network" ELLIPSIS " no peers yet", tail);
}

/* The exact beta13 banner strings (pages section B). */
static void banner_text(const struct zw_model *m, const struct sync_view *v, char *t, size_t cap)
{
    bool behind = v->tip_age > 3600;
    switch (v->s) {
    case ZW_SYNC_SYNCING:
        snprintf(t, cap, "Syncing blockchain\nValidated block %s%s%s%s", v->h, behind ? " " MID " " : "",
                 behind ? v->age : "", behind ? " behind" : "");
        break;
    case ZW_SYNC_FINDING: snprintf(t, cap, "Syncing blockchain " DASH " finding the latest blocks" ELLIPSIS); break;
    case ZW_SYNC_STALE:
        snprintf(t, cap, "Waiting for new blocks\nLast block %s ago " DASH " if this stays, check your "
                 "computer's date and time", v->age);
        break;
    case ZW_SYNC_PEERLESS: peerless_text(m, v, t, cap); break;
    case ZW_SYNC_SKEW:
        snprintf(t, cap, "Your computer's date or time looks wrong\nWallet is up to date at block %s, but block "
                 "times look off. Please correct the clock in your system settings.", v->h);
        break;
    default: snprintf(t, cap, "Connecting to your ZClassic node" ELLIPSIS); break;
    }
}

static void sync_texts(const struct zw_model *m, struct gui_ui *ui, int64_t now_s)
{
    char t[400];
    struct sync_view v = { .s = zw_sync_classify(m, now_s) };
    v.tip_age = m->chain.tiptime > 0 ? now_s - m->chain.tiptime : -1;
    zw_fmt_int(m->chain.blocks, v.h, sizeof(v.h));
    zw_fmt_age(v.tip_age, v.age, sizeof(v.age));
    pill_text(&v, t, sizeof(t));
    gui_ui_set(ui, "home.pill", t);
    banner_text(m, &v, t, sizeof(t));
    gui_ui_set(ui, "home.banner", t);
    snprintf(t, sizeof(t), "%d", (int)m->chain.progress_permille);
    gui_ui_set(ui, "home.sync_progress", v.s == ZW_SYNC_FINDING ? "" : t);
}

static void updated_at(int64_t when, char *buf, size_t cap)
{
    static const char *const mon[12] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
                                         "Nov", "Dec" };
    time_t tt = (time_t)when;
    struct tm tmv;
#if defined(_WIN32)
    bool ok = localtime_s(&tmv, &tt) == 0;
#else
    bool ok = localtime_r(&tt, &tmv) != NULL;
#endif
    if (!ok || when <= 0) { snprintf(buf, cap, "Updating" ELLIPSIS " not final yet"); return; }
    int h12 = tmv.tm_hour % 12 ? tmv.tm_hour % 12 : 12;
    snprintf(buf, cap, "Last updated %s %d, %d:%02d %s " MID " refreshing", mon[tmv.tm_mon % 12], tmv.tm_mday, h12,
             tmv.tm_min, tmv.tm_hour < 12 ? "AM" : "PM");
}

static void hero_texts(const struct zw_model *m, struct gui_ui *ui, int64_t now_s)
{
    char a[64], t[200];
    enum hero_state hs = hero_state(m, now_s);
    if (hs == HERO_UNAVAILABLE) {
        gui_ui_set(ui, "home.private", DASH);
        gui_ui_set(ui, "home.total", "Balance unavailable until the node is connected");
        gui_ui_set(ui, "home.qualifier", "Your funds are not affected. The balance is shown once the wallet is "
                   "connected to its node.");
        return;
    }
    zw_amount_format_net(m->wallet.spendable, a, sizeof(a), m->testnet);
    gui_ui_set(ui, "home.private", a);
    zw_amount_format_net(m->wallet.total, a, sizeof(a), m->testnet);
    snprintf(t, sizeof(t), "Total: %s", a);
    gui_ui_set(ui, "home.total", t);
    if (m->conn == ZW_CONN_ONLINE) snprintf(t, sizeof(t), "Updating" ELLIPSIS " not final yet");
    else updated_at(m->last_update_s, t, sizeof(t));
    gui_ui_set(ui, "home.qualifier", t);
}

void zw_home_publish(const struct zw_model *m, struct gui_ui *ui, int64_t now_s)
{
    char a[64], t[200];
    sync_texts(m, ui, now_s);
    hero_texts(m, ui, now_s);
    zw_amount_format_net(m->wallet.publicf, a, sizeof(a), m->testnet);
    snprintf(t, sizeof(t), "%s is PUBLIC and visible to everyone.", a);
    gui_ui_set(ui, "home.fixit", t);
}
