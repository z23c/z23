/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the Connect card shown at the top of Home until the node answers:
 * STARTING ("Looking for your node..."), NOT_FOUND (every searched folder
 * with its reason, never an empty list), REFUSED (host:port), AUTH (names
 * the credential source, never its value), WARMING and BAD_REPLY. Wording
 * names the node kind the user asked for. */
#include <stdio.h>
#include <string.h>

#include "zw.h"

#define DASH "\xE2\x80\x94"
#define ELLIPSIS "\xE2\x80\xA6"

static const char *wanted(const struct zw_model *m)
{
    switch (m->requested) {
    case ZW_PROFILE_ZCLASSICD: return "a ZClassic node (zclassicd)";
    case ZW_PROFILE_Z23: return "a Z23 node";
    default: return "a Z23 node or a ZClassic node (zclassicd)";
    }
}

static void not_found_text(const struct zw_model *m, char *buf, size_t cap)
{
    size_t o = (size_t)snprintf(buf, cap, "Couldn't find %s on this computer.\n", wanted(m));
    if (m->report.ntried == 0 && o < cap)
        o += (size_t)snprintf(buf + o, cap - o, "No folder could be searched.\n");
    for (size_t i = 0; i < m->report.ntried && o < cap; i++)
        o += (size_t)snprintf(buf + o, cap - o, "%s " DASH " %s\n", m->report.tried[i].path,
                              m->report.tried[i].reason);
    if (o < cap)
        snprintf(buf + o, cap - o, "Start your node, or run z23-wallet --datadir=<folder>.");
}

static void auth_text(const struct zw_model *m, char *buf, size_t cap)
{
    if (m->cred_src == ZW_CRED_CONF && m->conf_path[0])
        snprintf(buf, cap, "Your node refused the login in %s.", m->conf_path);
    else
        snprintf(buf, cap, "Your node refused this wallet's login. The .cookie in %s may belong to another "
                 "node; check --datadir.", m->datadir[0] ? m->datadir : "the data folder");
}

void zw_connect_text(const struct zw_model *m, char *buf, size_t cap)
{
    switch (m->conn) {
    case ZW_CONN_STARTING: snprintf(buf, cap, "Looking for your node" ELLIPSIS); break;
    case ZW_CONN_NOT_FOUND: not_found_text(m, buf, cap); break;
    case ZW_CONN_REFUSED:
        snprintf(buf, cap, "Your node at 127.0.0.1:%u isn't answering. Retrying in %u s.", (unsigned)m->port,
                 zw_backoff_s(m->fail_count));
        break;
    case ZW_CONN_WARMING: snprintf(buf, cap, "Your node is starting: %s", m->conn_msg); break;
    case ZW_CONN_AUTH: auth_text(m, buf, cap); break;
    case ZW_CONN_ONLINE: buf[0] = 0; break;
    default:
        snprintf(buf, cap, "Your node sent a reply this wallet doesn't understand (%s). Check that "
                 "z23-wallet and the node are from the same release.", m->conn_msg);
        break;
    }
}

void zw_screen_connect_build(struct gui_tree *t, const struct zw_model *m)
{
    gui_box(t, "c_card", GUI_COL, GS_CARD);
    gui_attr(t, GUI_A_PAD, 16);
    gui_attr(t, GUI_A_GAP, 12);
    gui_text_bind(t, "c_text", GS_BODY, "connect.text");
    gui_flag(t, GUI_F_WRAP);
    if (m->conn == ZW_CONN_WARMING && m->warm_percent >= 0) gui_progress(t, "c_progress", "connect.progress");
    if (m->conn != ZW_CONN_STARTING) {
        gui_box(t, "c_btns", GUI_ROW, GS_BODY);
        gui_attr(t, GUI_A_GAP, 8);
        gui_button(t, "c_retry", GS_BUTTON_PRIMARY, "Try again", "connect.retry");
        gui_flag(t, GUI_F_DEFAULT);
        gui_button(t, "c_copy", GS_BUTTON, "Copy details", "connect.copy");
        gui_end(t);
    }
    gui_end(t);
}
