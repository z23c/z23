/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Prepare beta13's Shield my funds form from the connected wallet's own addresses. */
#include "zw_send.h"
#include <string.h>

const char *zw_shield_source(const struct zw_balances *bal)
{
    const struct zw_bal_row *confirmed = NULL, *shown = NULL;
    if (!bal) return NULL;
    for (size_t i = 0; i < bal->n; ++i) {
        const struct zw_bal_row *r = &bal->rows[i];
        if (r->kind != ZW_ADDR_PUBLIC || !zw_addr_is_t(r->addr)) continue;
        if (!shown || r->zat > shown->zat) shown = r;
        if (r->confirmed_zat > 0 && (!confirmed || r->confirmed_zat > confirmed->confirmed_zat))
            confirmed = r;
    }
    if (!shown || shown->zat <= 10) return NULL; /* Qt tests > 0.0000001 ZCL. */
    return confirmed ? confirmed->addr : shown->addr;
}

static const char *shield_target(const struct zw_receive *rc, const char *issued)
{
    if (issued) return issued;
    for (size_t i = 0; i < rc->list->n; ++i) {
        const char *addr = rc->list->rows[i].addr;
        if (zw_addr_check(addr) == ZW_AT_SAPLING) return addr;
    }
    return rc->fresh_z;
}

static bool payment_occupied(const struct zw_send *s)
{
    if (s->pend.active || s->locked_out || s->dlg != ZW_DLG_NONE) return true;
    for (size_t i = 0; i < s->shown; ++i) {
        const struct zw_rcpt *r = &s->form.to[i];
        if (r->addr[0] || r->amount[0] || r->memo[0]) return true;
    }
    return false;
}

enum zw_shield_choice zw_send_home_shield(struct zw_send *s, const struct zw_send_env *env, const char *issued)
{
    const struct zw_model *m = env->m;
    if (!s || m->conn != ZW_CONN_ONLINE || !m->bal || m->rcv.creating)
        return ZW_SHIELD_WAIT;
    if (payment_occupied(s)) return ZW_SHIELD_BUSY;
    const char *from = zw_shield_source(m->bal);
    if (!from) return ZW_SHIELD_EMPTY;
    if (!m->rcv.list) return ZW_SHIELD_READ;
    const char *to = shield_target(&m->rcv, issued);
    if (!to[0]) return ZW_SHIELD_CREATE;
    if (zw_addr_check(to) != ZW_AT_SAPLING) return ZW_SHIELD_WAIT;
    zw_send_clear_form(s, env->ui);
    zw_send_prefill_from(s, from);
    zw_copy(s->form.to[0].addr, sizeof(s->form.to[0].addr), to);
    zw_send_seed(env->ui, "s_addr1", to, ZW_PAY_TO_MAX);
    s->max_on = s->shield_draft = true;
    return ZW_SHIELD_READY;
}
