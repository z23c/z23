/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the window shell, as beta13 lays it out: menu bar (File, Edit,
 * Help) with drop-down menus, the navigation rail (screens from
 * zw_screens.def, Advanced pinned to the bottom behind the gear), the page,
 * and the status bar (transient message left; node label and a 16x16
 * status icon right). Also the group-box helpers every screen uses. */
#include <stdio.h>
#include <string.h>

#include "zw.h"

const struct zw_screen_row zw_screens[ZW_SCREEN_COUNT] = {
#define ZW_SCREEN(id, name, label, build) { name, label, build },
#include "zw_screens.def"
#undef ZW_SCREEN
};

size_t zw_screen_by_name(const char *name)
{
    for (size_t i = 0; i < ZW_SCREEN_COUNT; i++)
        if (!strcmp(zw_screens[i].name, name)) return i;
    return ZW_SCREEN_COUNT;
}

/* ---- group box: title in the border, then an inset body column ---- */

void zw_group_begin(struct gui_tree *t, const char *id, const char *title, int inset_x, int inset_top, bool grow)
{
    char sub[GUI_ID_MAX];
    gui_box(t, id, GUI_COL, GS_GROUP);
    if (grow) gui_attr(t, GUI_A_GROW, 1);
    snprintf(sub, sizeof(sub), "%.24s_title", id);
    gui_text(t, sub, GS_GROUP_TITLE, title);
    snprintf(sub, sizeof(sub), "%.24s_row", id);
    gui_box(t, sub, GUI_ROW, GS_BODY);
    gui_attr(t, GUI_A_GROW, 1);
    gui_spacer(t, 0);
    gui_attr(t, GUI_A_W, inset_x);
    snprintf(sub, sizeof(sub), "%.24s_body", id);
    gui_box(t, sub, GUI_COL, GS_BODY);
    gui_attr(t, GUI_A_GROW, 1);
    gui_attr(t, GUI_A_GAP, 6);
    gui_spacer(t, 0);
    gui_attr(t, GUI_A_H, inset_top - 6);
}

void zw_group_end(struct gui_tree *t, int inset_right, int inset_bottom)
{
    gui_spacer(t, 0);
    gui_attr(t, GUI_A_H, inset_bottom - 6);
    gui_end(t); /* body */
    gui_spacer(t, 0);
    gui_attr(t, GUI_A_W, inset_right);
    gui_end(t); /* row */
    gui_end(t); /* group */
}

/* The shared placeholder body the three later screens start from. */
void zw_screen_soon(struct gui_tree *t, const char *prefix, const char *title, const char *body)
{
    char id[GUI_ID_MAX];
    snprintf(id, sizeof(id), "%s_group", prefix);
    zw_group_begin(t, id, title, 26, 17, true);
    snprintf(id, sizeof(id), "%s_soon", prefix);
    gui_text(t, id, GS_MUTED, body);
    gui_flag(t, GUI_F_WRAP);
    gui_spacer(t, 1);
    zw_group_end(t, 25, 12);
}

/* ---- menu bar and menus ---- */

static void menu_item(struct gui_tree *t, const char *id, const char *label, const char *action, bool enabled)
{
    gui_button(t, id, GS_MENU_ITEM, label, action);
    if (!enabled) gui_flag(t, GUI_F_DISABLED);
}

static void menubar(struct gui_tree *t)
{
    gui_box(t, "menubar", GUI_ROW, GS_MENUBAR);
    gui_attr(t, GUI_A_H, 31);
    gui_attr(t, GUI_A_GAP, 2);
    gui_attr(t, GUI_A_ALIGN, GUI_ALIGN_CENTER);
    gui_spacer(t, 0);
    gui_attr(t, GUI_A_W, 2);
    static const char *const ids[3] = { "menu_file", "menu_edit", "menu_help" };
    static const char *const labels[3] = { "File", "Edit", "Help" };
    static const char *const acts[3] = { "menu.file", "menu.edit", "menu.help" };
    for (int i = 0; i < 3; i++) {
        gui_button(t, ids[i], GS_MENUBAR_ITEM, labels[i], acts[i]);
        gui_attr(t, GUI_A_H, 25);
    }
    gui_end(t);
}

static void menu_popup(struct gui_tree *t, const struct zw_model *m)
{
    char label[96];
    switch (m->menu) {
    case ZW_MENU_FILE:
        gui_dialog(t, "menu_file_pop", "", "menu.close");
        menu_item(t, "mf_uri", "Pay zclassic URI\xE2\x80\xA6 (coming)", "menu.none", false);
        menu_item(t, "mf_backup", "Back up my wallet\xE2\x80\xA6 (coming)", "menu.none", false);
        menu_item(t, "mf_export", "Export transactions (coming)", "menu.none", false);
        menu_item(t, "mf_import", "Import private key (coming)", "menu.none", false);
        menu_item(t, "mf_exit", "Exit", "app.exit", true);
        gui_end(t);
        break;
    case ZW_MENU_EDIT:
        gui_dialog(t, "menu_edit_pop", "", "menu.close");
        menu_item(t, "me_book", "Address book (coming)", "menu.none", false);
        menu_item(t, "me_settings", "Settings\xE2\x80\xA6 (coming)", "menu.none", false);
        gui_end(t);
        break;
    case ZW_MENU_HELP:
        gui_dialog(t, "menu_help_pop", "", "menu.close");
        menu_item(t, "mh_about", "About", "help.about", true);
        gui_end(t);
        break;
    case ZW_MENU_ROW:
        gui_dialog(t, "h_balances_pop", "", "menu.close");
        menu_item(t, "mr_copy", "Copy address", "row.copy", true);
        char addr[100] = "";
        zw_home_row_address(m, m->menu_row, addr, sizeof(addr));
        snprintf(label, sizeof(label), "Send from %.40s...", addr);
        menu_item(t, "mr_send", label, "row.send", true);
        gui_end(t);
        break;
    default: break;
    }
}

static void about_dialog(struct gui_tree *t)
{
    gui_dialog(t, "about", "About Z23 Wallet", "about.close");
    gui_attr(t, GUI_A_W, 460);
    gui_text(t, "about_what", GS_BODY, "Z23 Wallet \xE2\x80\x94 a lightweight wallet window for ZClassic (ZCL)");
    gui_flag(t, GUI_F_WRAP);
    gui_text_bind(t, "about_version", GS_MUTED, "about.version");
    gui_text_bind(t, "about_node", GS_MUTED, "about.node");
    gui_box(t, "about_btns", GUI_ROW, GS_BODY);
    gui_spacer(t, 1);
    gui_button(t, "about_ok", GS_BUTTON_PRIMARY, "OK", "about.close");
    gui_flag(t, GUI_F_DEFAULT);
    gui_end(t);
    gui_end(t);
}

/* ---- rail ---- */

static void rail(struct gui_tree *t, size_t screen)
{
    gui_box(t, "rail", GUI_COL, GS_RAIL);
    gui_attr(t, GUI_A_W, 168);
    gui_attr(t, GUI_A_PAD, 8);
    gui_attr(t, GUI_A_GAP, 6);
    gui_spacer(t, 0);
    gui_attr(t, GUI_A_H, 2); /* 8 pad + 2 + 6 gap: the first item sits 16 below the top */
    for (size_t i = 0; i < ZW_SCREEN_COUNT; i++) {
        char id[GUI_ID_MAX], act[GUI_ID_MAX];
        bool adv = i == ZW_SCREEN_ADVANCED, on = i == screen;
        snprintf(id, sizeof(id), "nav_%s", zw_screens[i].name);
        snprintf(act, sizeof(act), "nav.%s", zw_screens[i].name);
        if (adv) gui_spacer(t, 1);
        gui_button(t, id, adv ? (on ? GS_NAV_ADV_ACTIVE : GS_NAV_ADV) : (on ? GS_NAV_ITEM_ACTIVE : GS_NAV_ITEM),
                   zw_screens[i].label, act);
        gui_attr(t, GUI_A_W, 152);
        gui_attr(t, GUI_A_H, adv ? 42 : 48);
    }
    gui_spacer(t, 0);
    gui_attr(t, GUI_A_H, 2);
    gui_end(t);
}

/* ---- status bar ---- */

static enum gui_style status_icon(const struct zw_model *m)
{
    if (m->conn != ZW_CONN_ONLINE) return m->conn == ZW_CONN_STARTING ? GS_ICON_WARN : GS_ICON_CRIT;
    bool peerless = m->have_net ? m->net.connections == 0 : m->have_info && m->info.connections == 0;
    return peerless ? GS_ICON_WARN : GS_ICON_OK;
}

static void statusbar(struct gui_tree *t, const struct zw_model *m)
{
    gui_box(t, "statusbar", GUI_ROW, GS_STATUSBAR);
    gui_attr(t, GUI_A_H, 30);
    gui_attr(t, GUI_A_ALIGN, GUI_ALIGN_CENTER);
    gui_attr(t, GUI_A_GAP, 8);
    gui_spacer(t, 0);
    gui_attr(t, GUI_A_W, 2);
    if (m->msg[0]) gui_text_bind(t, "status_msg", GS_STATUS_MSG, "status.msg");
    gui_spacer(t, 1);
    gui_text_bind(t, "status_label", GS_STATUS_LABEL, "status.label");
    gui_box(t, "status_icon", GUI_COL, status_icon(m));
    gui_attr(t, GUI_A_W, 16);
    gui_attr(t, GUI_A_H, 16);
    gui_end(t);
    gui_spacer(t, 0);
    gui_attr(t, GUI_A_W, 2);
    gui_end(t);
}

void zw_shell_build(struct gui_tree *t, const struct zw_model *m, size_t screen)
{
    if (screen >= ZW_SCREEN_COUNT) screen = ZW_SCREEN_HOME;
    gui_tree_begin(t);
    gui_box(t, "root", GUI_COL, GS_SCREEN);
    menubar(t);
    gui_box(t, "body", GUI_ROW, GS_SCREEN);
    gui_attr(t, GUI_A_GROW, 1);
    rail(t, screen);
    gui_box(t, "page", GUI_COL, GS_PAGE);
    gui_attr(t, GUI_A_GROW, 1);
    gui_attr(t, GUI_A_PAD, 12);
    gui_attr(t, GUI_A_GAP, 8);
    zw_screens[screen].build(t, m);
    gui_end(t);
    gui_end(t);
    statusbar(t, m);
    menu_popup(t, m);
    if (m->about_open) about_dialog(t);
    gui_end(t);
}

/* ---- bound text: status bar and About ---- */

static void status_label(const struct zw_model *m, int64_t now_s, char *buf, size_t cap)
{
    char h[32];
    zw_fmt_int(m->chain.blocks, h, sizeof(h));
    switch (m->conn) {
    case ZW_CONN_ONLINE: break;
    case ZW_CONN_STARTING: snprintf(buf, cap, "Looking for your node\xE2\x80\xA6"); return;
    case ZW_CONN_WARMING: snprintf(buf, cap, "Starting node"); return;
    case ZW_CONN_NOT_FOUND: case ZW_CONN_REFUSED: snprintf(buf, cap, "No Connection"); return;
    default: snprintf(buf, cap, "Connection needs attention"); return;
    }
    if (!m->have_chain) { snprintf(buf, cap, "Connected"); return; }
    switch (zw_sync_classify(m, now_s)) {
    case ZW_SYNC_SYNCING: snprintf(buf, cap, "Syncing (%lld)", (long long)m->chain.blocks); break;
    case ZW_SYNC_FINDING: snprintf(buf, cap, "Syncing (block %lld)", (long long)m->chain.blocks); break;
    case ZW_SYNC_PEERLESS: snprintf(buf, cap, "No peers (block %s)", h); break;
    case ZW_SYNC_LOCAL: snprintf(buf, cap, "Local test network (block %s)", h); break;
    case ZW_SYNC_STALE: snprintf(buf, cap, "Waiting for new blocks (%s)", h); break;
    default:
        if (m->testnet) snprintf(buf, cap, "Connected (testnet:%lld)", (long long)m->chain.blocks);
        else snprintf(buf, cap, "Connected (%s)", h);
        break;
    }
}

void zw_shell_publish(const struct zw_model *m, struct gui_ui *ui, int64_t now_s)
{
    char t[300], ver[48];
    status_label(m, now_s, t, sizeof(t));
    gui_ui_set(ui, "status.label", t);
    gui_ui_set(ui, "status.msg", m->msg);
    gui_ui_set(ui, "about.version", "Version " ZW_VERSION " (" ZW_RELEASE_DATE ")");
    if (m->conn != ZW_CONN_ONLINE) {
        snprintf(t, sizeof(t), "Node: not connected yet");
    } else if (!strcmp(zw_node_kind(m), "zclassicd")) {
        zw_version_decode(m->have_info && m->info.version ? m->info.version : m->net.version, ver, sizeof(ver));
        snprintf(t, sizeof(t), "Node (zclassicd): %s at 127.0.0.1:%u (read only)", ver, (unsigned)m->port);
    } else {
        snprintf(t, sizeof(t), "Node (Z23): %s at 127.0.0.1:%u", m->net.subversion[0] ? m->net.subversion : "Z23",
                 (unsigned)m->port);
    }
    gui_ui_set(ui, "about.node", t);
}

void zw_model_publish(const struct zw_model *m, struct gui_ui *ui, int64_t now_s)
{
    char t[1600];
    zw_shell_publish(m, ui, now_s);
    zw_connect_text(m, t, sizeof(t));
    gui_ui_set(ui, "connect.text", t);
    char pm[16] = "";
    if (m->conn == ZW_CONN_WARMING && m->warm_percent >= 0) snprintf(pm, sizeof(pm), "%d", m->warm_percent * 10);
    gui_ui_set(ui, "connect.progress", pm);
    zw_home_publish(m, ui, now_s);
    zw_advanced_publish(m, ui);
}
