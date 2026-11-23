/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Advanced (beta13's node-stats page, formerly "Node"): the node
 * line naming its kind and port, Connections, Block height, Network
 * solution rate, the P2P line and the diagnostics copy button. */
#include <stdio.h>
#include <string.h>

#include "zw.h"

#define MID "\xC2\xB7"
#define DASH "\xE2\x80\x94"

static void label_row(struct gui_tree *t, const char *id, const char *label, const char *bind)
{
    char rid[GUI_ID_MAX], lid[GUI_ID_MAX], vid[GUI_ID_MAX];
    snprintf(rid, sizeof(rid), "%.24s_row", id);
    snprintf(lid, sizeof(lid), "%.24s_lbl", id);
    snprintf(vid, sizeof(vid), "%.24s_val", id);
    gui_box(t, rid, GUI_ROW, GS_BODY);
    gui_attr(t, GUI_A_ALIGN, GUI_ALIGN_CENTER);
    if (label[0] == '@') gui_text_bind(t, lid, GS_MUTED, label + 1);
    else gui_text(t, lid, GS_MUTED, label);
    gui_spacer(t, 1);
    gui_text_bind(t, vid, GS_AMOUNT, bind);
    gui_end(t);
}

void zw_screen_advanced_build(struct gui_tree *t, const struct zw_model *m)
{
    (void)m;
    zw_group_begin(t, "a_node", "Node", 26, 17, true);
    gui_text_bind(t, "a_nodeline", GS_BODY, "adv.node");
    gui_flag(t, GUI_F_ELLIPSIS);
    label_row(t, "a_conn", "Connections", "adv.connections");
    label_row(t, "a_height", "@adv.height_label", "adv.height");
    label_row(t, "a_solps", "Network solution rate", "adv.solps");
    gui_text_bind(t, "a_p2p", GS_MUTED, "adv.p2p");
    gui_text_bind(t, "a_datadir", GS_MUTED, "adv.datadir");
    gui_flag(t, GUI_F_ELLIPSIS);
    gui_box(t, "a_btns", GUI_ROW, GS_BODY);
    gui_button(t, "a_copy", GS_BUTTON_SECONDARY, "Copy diagnostics", "node.copy");
    gui_end(t);
    gui_spacer(t, 1);
    zw_group_end(t, 25, 12);
}

static void p2p_text(const struct zw_model *m, int64_t peers, struct gui_ui *ui)
{
    char t[200];
    unsigned p2p = m->testnet ? 18033u : 8033u;
    if (m->have_net && m->net.inbound >= 0)
        snprintf(t, sizeof(t), "P2P: ON " MID " port %u " MID " %lld peers (%lld inbound)", p2p,
                 (long long)m->net.connections, (long long)m->net.inbound);
    else
        snprintf(t, sizeof(t), "P2P: ON " MID " port %u " MID " %lld peers", p2p, (long long)peers);
    gui_ui_set(ui, "adv.p2p", m->have_net || m->have_info ? t : "");
}

static void solps_text(const struct zw_model *m, struct gui_ui *ui)
{
    char t[64], b[40];
    if (m->have_info && m->info.has_solps) {
        zw_fmt_int(m->info.solps, b, sizeof(b));
        snprintf(t, sizeof(t), "%s Sol/s", b);
    } else {
        snprintf(t, sizeof(t), DASH);
    }
    gui_ui_set(ui, "adv.solps", t);
}

void zw_advanced_publish(const struct zw_model *m, struct gui_ui *ui)
{
    char t[600], a[40];
    zw_node_line(m, t, sizeof(t));
    gui_ui_set(ui, "adv.node", t);
    int64_t peers = m->have_info ? m->info.connections : m->net.connections;
    zw_fmt_int(peers, a, sizeof(a));
    gui_ui_set(ui, "adv.connections", m->have_info || m->have_net ? a : "Loading...");
    bool syncing = m->have_chain && m->chain.blocks + 2 < m->chain.headers;
    gui_ui_set(ui, "adv.height_label", !m->have_chain ? "Starting\xE2\x80\xA6" : syncing ? "Block height (syncing)"
                                                                                   : "Validated block");
    zw_fmt_int(m->chain.blocks, a, sizeof(a));
    gui_ui_set(ui, "adv.height", m->have_chain ? a : "Loading...");
    solps_text(m, ui);
    p2p_text(m, peers, ui);
    snprintf(t, sizeof(t), "Data folder: %s", m->datadir);
    gui_ui_set(ui, "adv.datadir", m->datadir[0] ? t : "");
}
