/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: window shell: left nav rail, the screen body and a bottom status
 * bar. Node-dependent screens give way to the Connect panel while the node
 * can't be read; a refused node keeps showing the last values. */
#include <string.h>

#include "zw.h"

static const struct { const char *id, *label, *action; } k_screens[ZW_SCREEN_COUNT] = {
    { "nav_home", "Home", "nav.home" },
    { "nav_node", "Node", "nav.node" },
};

static bool show_connect(const struct zw_model *m)
{
    if (m->conn == ZW_CONN_ONLINE) return false;
    return !(m->conn == ZW_CONN_REFUSED && (m->have_wallet || m->have_chain));
}

void zw_shell_build(struct gui_tree *t, const struct zw_model *m, size_t screen)
{
    gui_tree_begin(t);
    gui_box(t, "root", GUI_COL, GS_SCREEN);
    gui_box(t, "body", GUI_ROW, GS_SCREEN);
    gui_attr(t, GUI_A_GROW, 1);
    gui_box(t, "nav", GUI_COL, GS_NAV);
    gui_attr(t, GUI_A_PAD, 12);
    gui_attr(t, GUI_A_GAP, 6);
    gui_attr(t, GUI_A_W, 190);
    gui_text(t, "brand", GS_TITLE, "Z23 Wallet");
    gui_spacer(t, 0);
    gui_attr(t, GUI_A_H, 10);
    for (size_t i = 0; i < ZW_SCREEN_COUNT; i++)
        gui_button(t, k_screens[i].id, i == screen ? GS_NAV_ACTIVE : GS_NAV, k_screens[i].label,
                   k_screens[i].action);
    gui_end(t);
    gui_box(t, "main", GUI_COL, GS_SCREEN);
    gui_attr(t, GUI_A_PAD, 22);
    gui_attr(t, GUI_A_GAP, 14);
    gui_attr(t, GUI_A_GROW, 1);
    if (show_connect(m)) zw_screen_connect_build(t, m);
    else if (screen == ZW_SCREEN_NODE) zw_screen_node_build(t, m);
    else zw_screen_home_build(t, m);
    gui_end(t);
    gui_end(t);
    gui_box(t, "statusbar", GUI_ROW, GS_STATUS);
    gui_attr(t, GUI_A_PAD, 10);
    gui_attr(t, GUI_A_GAP, 12);
    gui_text_bind(t, "status_text", GS_STATUS, "status.text");
    gui_spacer(t, 1);
    if (m->chain.chain[0] && (!strcmp(m->chain.chain, "test") || !strcmp(m->chain.chain, "regtest")))
        gui_text_bind(t, "status_badge", GS_BADGE_PUBLIC, "status.badge");
    gui_end(t);
    gui_end(t);
}
