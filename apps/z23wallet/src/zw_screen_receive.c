/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the Receive screen. Shows one private address the wallet already
 * holds so another person can pay it. Does not create an address, open a
 * socket, or draw a code. */
#include "zw.h"
#include "zw_send.h"

static const char *listed_sapling(const struct zw_balances *list)
{
    if (!list) return NULL;
    for (size_t i = 0; i < list->n; i++) {
        const char *addr = list->rows[i].addr;
        if (list->rows[i].kind == ZW_ADDR_SAPLING &&
            zw_addr_check(addr) == ZW_AT_SAPLING)
            return addr;
    }
    return NULL;
}

const char *zw_receive_address(const struct zw_model *m)
{
    const char *listed;
    if (!m || m->conn != ZW_CONN_ONLINE) return NULL;
    if (zw_addr_check(m->rcv.fresh_z) == ZW_AT_SAPLING) return m->rcv.fresh_z;
    listed = listed_sapling(m->rcv.list);
    return listed ? listed : listed_sapling(m->bal);
}

static const char *receive_note(const struct zw_model *m, const char *addr)
{
    if (addr)
        return "Share this private address. A payment to it does not reveal your other funds.";
    if (!m || m->conn != ZW_CONN_ONLINE)
        return "Connect to your node to see a receive address.";
    if (!m->bal && !m->rcv.list && m->rcv.fresh_z[0] == '\0')
        return "Looking up your receive address.";
    return "This wallet has no private receive address yet.";
}

void zw_receive_publish(const struct zw_model *m, struct gui_ui *ui)
{
    const char *addr = zw_receive_address(m);
    if (!ui) return;
    gui_ui_set(ui, "receive.address", addr ? addr : "");
    gui_ui_set(ui, "receive.note", receive_note(m, addr));
}

void zw_screen_receive_build(struct gui_tree *t, const struct zw_model *m)
{
    (void)m;
    zw_group_begin(t, "r_group", "Receive", 26, 17, true);
    gui_text_bind(t, "r_note", GS_MUTED, "receive.note");
    gui_flag(t, GUI_F_WRAP);
    gui_text_bind(t, "r_address", GS_AMOUNT_MONO, "receive.address");
    gui_flag(t, GUI_F_WRAP | GUI_F_SELECTABLE | GUI_F_FOCUSABLE);
    gui_spacer(t, 1);
    zw_group_end(t, 25, 12);
}
