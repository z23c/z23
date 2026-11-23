/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the Connect, Home and Node screens, built in C against the same
 * widget API the later markup parser targets. Text is bound by key; only
 * the structure (which cards exist) depends on the model. */
#include <string.h>

#include "zw.h"

const struct zw_action_entry zw_screen_connect_actions[] = {
    { "connect.retry" }, { "connect.copy" }, { NULL } };
const struct zw_action_entry zw_screen_home_actions[] = { { "home.refresh" }, { NULL } };
const struct zw_action_entry zw_screen_node_actions[] = { { "node.copy" }, { NULL } };

static void label_row(struct gui_tree *t, const char *id, const char *label, const char *bind,
                      enum gui_style value_style)
{
    char rid[32], lid[32], vid[32];
    snprintf(rid, sizeof(rid), "%s_row", id);
    snprintf(lid, sizeof(lid), "%s_lbl", id);
    snprintf(vid, sizeof(vid), "%s_val", id);
    gui_box(t, rid, GUI_ROW, GS_BODY);
    gui_attr(t, GUI_A_ALIGN, GUI_ALIGN_CENTER);
    gui_text(t, lid, GS_MUTED, label);
    gui_spacer(t, 1);
    gui_text_bind(t, vid, value_style, bind);
    gui_end(t);
}

void zw_screen_connect_build(struct gui_tree *t, const struct zw_model *m)
{
    gui_text(t, "c_title", GS_TITLE, "Connect to your node");
    gui_box(t, "c_card", GUI_COL, GS_CARD);
    gui_attr(t, GUI_A_PAD, 18);
    gui_attr(t, GUI_A_GAP, 14);
    gui_text_bind(t, "c_text", GS_BODY, "connect.text");
    gui_flag(t, GUI_F_WRAP);
    if (m->conn == ZW_CONN_WARMING && m->warm_percent >= 0) {
        gui_progress(t, "c_progress", "connect.progress");
    }
    gui_box(t, "c_btns", GUI_ROW, GS_BODY);
    gui_attr(t, GUI_A_GAP, 10);
    gui_button(t, "c_retry", GS_BUTTON_PRIMARY, "Retry now", "connect.retry");
    gui_button(t, "c_copy", GS_BUTTON, "Copy the path list", "connect.copy");
    gui_end(t);
    gui_end(t);
}

void zw_screen_home_build(struct gui_tree *t, const struct zw_model *m)
{
    const struct zw_wallet *w = &m->wallet;
    bool k = m->have_wallet && w->known;
    gui_text(t, "h_title", GS_TITLE, "Home");
    gui_box(t, "h_hero", GUI_COL, GS_CARD);
    gui_attr(t, GUI_A_PAD, 18);
    gui_attr(t, GUI_A_GAP, 6);
    gui_text(t, "h_hero_lbl", GS_MUTED, "Private balance (shielded)");
    gui_text_bind(t, "h_hero_val", k && w->spendable >= INT64_C(100000000000000) ? GS_AMOUNT : GS_HERO,
                  "home.private");
    gui_box(t, "h_badge_row", GUI_ROW, GS_BODY);
    gui_attr(t, GUI_A_ALIGN, GUI_ALIGN_START);
    gui_text(t, "h_badge", GS_BADGE_PRIVATE, "PRIVATE");
    gui_end(t);
    gui_end(t);
    gui_box(t, "h_lines", GUI_COL, GS_CARD);
    gui_attr(t, GUI_A_PAD, 16);
    gui_attr(t, GUI_A_GAP, 10);
    label_row(t, "h_shielded", "Shielded", "home.private", GS_AMOUNT);
    label_row(t, "h_public", "Transparent", "home.transparent", GS_AMOUNT);
    label_row(t, "h_total", "Total", "home.total", GS_AMOUNT);
    gui_end(t);
    if (k && w->pending > 0) {
        gui_text_bind(t, "h_pending", GS_MUTED, "home.pending");
        gui_flag(t, GUI_F_WRAP);
    }
    if (k && w->publicf > 0) {
        gui_box(t, "h_public_card", GUI_COL, GS_CARD_WARN);
        gui_attr(t, GUI_A_PAD, 14);
        gui_attr(t, GUI_A_GAP, 8);
        gui_text_bind(t, "h_public_warn", GS_BODY, "home.public_warn");
        gui_flag(t, GUI_F_WRAP);
        gui_box(t, "h_shield_row", GUI_ROW, GS_BODY);
        gui_attr(t, GUI_A_GAP, 10);
        gui_button(t, "h_shield", GS_BUTTON, "Shield my funds", "home.shield");
        gui_flag(t, GUI_F_DISABLED);
        gui_text(t, "h_shield_why", GS_MUTED, "Sending arrives in a later update.");
        gui_end(t);
        gui_end(t);
    }
    if (k && !w->current) {
        gui_text_bind(t, "h_sync", GS_MUTED, "home.sync_note");
        gui_flag(t, GUI_F_WRAP);
    }
    if (m->have_wallet && !w->send_allowed && w->reason[0]) {
        gui_text_bind(t, "h_blocked", GS_MUTED, "home.blocked");
        gui_flag(t, GUI_F_WRAP);
    }
    if (m->conn != ZW_CONN_ONLINE) gui_text_bind(t, "h_updated", GS_MUTED, "home.updated");
    gui_box(t, "h_btns", GUI_ROW, GS_BODY);
    gui_button(t, "h_refresh", GS_BUTTON_PRIMARY, "Refresh", "home.refresh");
    gui_end(t);
}

void zw_screen_node_build(struct gui_tree *t, const struct zw_model *m)
{
    gui_text(t, "n_title", GS_TITLE, "Node");
    gui_box(t, "n_card", GUI_COL, GS_CARD);
    gui_attr(t, GUI_A_PAD, 18);
    gui_attr(t, GUI_A_GAP, 10);
    static const struct { const char *id, *bind; } rows[] = {
        { "n_blocks", "node.blocks" }, { "n_headers", "node.headers" },
        { "n_peers", "node.peers" }, { "n_version", "node.version" },
        { "n_network", "node.network" }, { "n_datadir", "node.datadir" },
        { "n_port", "node.port" }, { "n_profile", "node.profile" },
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        gui_text_bind(t, rows[i].id, i < 3 ? GS_AMOUNT : GS_BODY, rows[i].bind);
        gui_flag(t, GUI_F_ELLIPSIS);
    }
    gui_end(t);
    if (m->have_net && m->net.connections == 0) gui_text_bind(t, "n_hint", GS_MUTED, "node.hint");
    gui_box(t, "n_btns", GUI_ROW, GS_BODY);
    gui_button(t, "n_copy", GS_BUTTON, "Copy diagnostics", "node.copy");
    gui_end(t);
}
