/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the Send page state (beta13 sendtab.cpp): the fields are mirrored
 * after every event and the view (badge, pay-from list and default,
 * available-to-send, totals, field borders, memo buttons, look-alike
 * warnings, "Send all") is derived from them and the model. The actions
 * and send results are in zw_send_act.c. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/safe_alloc.h"
#include "zw_send.h"

struct zw_send *zw_send_new(void)
{
    struct zw_send *s = zcl_calloc(1, sizeof(*s), "zw_send");
    if (!s) return NULL;
    s->shown = 1;
    s->form.n = 1;
    s->form.fee = ZW_DEFAULT_FEE;
    return s;
}

void zw_send_free(struct zw_send *s)
{
    if (!s) return;
    zw_sender_free(s->runner);
    free(s);
}

const struct zw_send_plan *zw_send_form(const struct zw_send *s) { return &s->form; }
bool zw_send_busy(const struct zw_send *s) { return s->runner && !zw_sender_finished(s->runner); }

const char *zw_send_dialog_title(const struct zw_send *s)
{
    if (s->dlg == ZW_DLG_CONFIRM) return zw_send_confirm_title(s->pending_cat);
    if (s->dlg == ZW_DLG_DESHIELD) return "De-shield to a public address?";
    if (s->dlg == ZW_DLG_MEMO) return "Memo";
    return s->dlg == ZW_DLG_NONE ? "" : s->dlg_title;
}

void zw_send_prefill_from(struct zw_send *s, const char *addr)
{
    snprintf(s->form.from, sizeof(s->form.from), "%s", addr);
    s->from_user = true;
}

static void field_id(char *buf, size_t cap, const char *kind, size_t i)
{
    snprintf(buf, cap, "s_%s%zu", kind, i + 1);
}

/* ---- model facts ---- */

static const struct zw_bal_row *row_of(const struct zw_model *m, const char *addr)
{
    for (size_t i = 0; m->bal && i < m->bal->n; i++)
        if (!strcmp(m->bal->rows[i].addr, addr)) return &m->bal->rows[i];
    return NULL;
}

/* spendableOrFallback: the confirmed spendable part once the unspent lists
 * are loaded, else the displayed total. */
static int64_t spendable_of(const struct zw_model *m, const char *addr)
{
    const struct zw_bal_row *r = row_of(m, addr);
    return r ? r->confirmed_zat : 0;
}

/* setDefaultPayFrom: the z-address with the most, else the t-address with the most. */
static void default_from(struct zw_send *s, const struct zw_model *m)
{
    const struct zw_bal_row *best = NULL;
    for (int pass = 0; pass < 2 && !best; pass++)
        for (size_t i = 0; m->bal && i < m->bal->n; i++) {
            const struct zw_bal_row *r = &m->bal->rows[i];
            if (r->addr[0] != (pass ? 't' : 'z')) continue;
            if (!best || r->zat > best->zat) best = r;
        }
    if (!best && m->bal && m->bal->n) best = &m->bal->rows[0];
    snprintf(s->form.from, sizeof(s->form.from), "%s", best ? best->addr : "");
}

/* ---- mirroring the fields ---- */

static void read_fields(struct zw_send *s, struct gui_ui *ui)
{
    char id[GUI_ID_MAX];
    for (size_t i = 0; i < s->shown; i++) {
        field_id(id, sizeof(id), "addr", i);
        if (!gui_ui_input_text(ui, id, s->form.to[i].addr, sizeof(s->form.to[i].addr))) s->form.to[i].addr[0] = 0;
        field_id(id, sizeof(id), "amt", i);
        if (!gui_ui_input_text(ui, id, s->form.to[i].amount, sizeof(s->form.to[i].amount)))
            s->form.to[i].amount[0] = 0;
    }
    s->form.n = s->shown;
}

/* recomputeMaxIfChecked: spendable minus the other amounts and the fee. */
static void apply_max(struct zw_send *s, const struct zw_send_env *env)
{
    if (!s->max_on) return;
    int64_t others = s->form.fee;
    for (size_t i = 1; i < s->form.n; i++) {
        int64_t z;
        if (zw_amount_text(s->form.to[i].amount, &z) == ZW_AMT_OK) others += z;
    }
    int64_t max = spendable_of(env->m, s->form.from) - others;
    char d[40];
    zw_decimal(max < 0 ? 0 : max, d, sizeof(d));
    if (strcmp(d, s->form.to[0].amount)) {
        gui_ui_input_set(env->ui, "s_amt1", d);
        zw_copy(s->form.to[0].amount, sizeof(s->form.to[0].amount), d);
    }
}

/* ---- the view ---- */

static void elide_middle(const char *a, char *out, size_t cap)
{
    size_t n = strlen(a);
    if (n <= 34) snprintf(out, cap, "%s", a);
    else snprintf(out, cap, "%.16s\xE2\x80\xA6%s", a, a + n - 16);
}

static void view_from(struct zw_send *s, const struct zw_model *m, struct zw_send_view *v)
{
    char d[40], el[64];
    for (size_t i = 0; m->bal && i < m->bal->n; i++) {
        const struct zw_bal_row *r = &m->bal->rows[i];
        if (v->nfrom == ZW_FROM_ITEMS) { v->from_more++; continue; }
        zw_decimal(r->zat, d, sizeof(d));
        elide_middle(r->addr, el, sizeof(el));
        snprintf(v->from_items[v->nfrom], sizeof(v->from_items[0]), "%s(%s %s)", el, d, m->testnet ? "ZCT" : "ZCL");
        snprintf(s->from_addr[v->nfrom], sizeof(s->from_addr[0]), "%s", r->addr);
        if (!strcmp(r->addr, s->form.from)) snprintf(v->from_label, sizeof(v->from_label), "%s", v->from_items[v->nfrom]);
        v->nfrom++;
    }
    if (!v->from_label[0] && s->form.from[0]) elide_middle(s->form.from, v->from_label, sizeof(v->from_label));
}

static void view_avail(const struct zw_send *s, const struct zw_model *m, struct zw_send_view *v)
{
    const struct zw_bal_row *r = row_of(m, s->form.from);
    int64_t spend = r ? r->confirmed_zat : 0, pending = r ? r->zat - r->confirmed_zat : 0;
    char a[48], p[48];
    zw_amount_format_net(spend, a, sizeof(a), m->testnet);
    if (pending > 0) {
        zw_amount_format_net(pending, p, sizeof(p), m->testnet);
        snprintf(v->avail, sizeof(v->avail), "%s (+%s confirming)", a, p);
    } else {
        snprintf(v->avail, sizeof(v->avail), "%s", a);
    }
}

static void view_lookalike(const struct zw_model *m, const char *addr, char *out, size_t cap)
{
    out[0] = 0;
    for (size_t i = 0; m->bal && i < m->bal->n && !out[0]; i++)
        if (zw_addr_lookalike(addr, m->bal->rows[i].addr))
            snprintf(out, cap, "Check this address: it starts and ends like your address %s but is a different "
                     "address.", m->bal->rows[i].addr);
}

static void view_recipient(const struct zw_send *s, const struct zw_model *m, size_t i, struct zw_send_view *v)
{
    const struct zw_rcpt *r = &s->form.to[i];
    const char *a;
    size_t n = zw_trimmed(r->addr, &a);
    char addr[ZW_ADDR_MAX];
    snprintf(addr, sizeof(addr), "%.*s", (int)(n < sizeof(addr) ? n : sizeof(addr) - 1), a);
    v->addr_state[i] = !n ? ZW_FIELD_EMPTY : zw_addr_check(addr) != ZW_AT_INVALID ? ZW_FIELD_VALID : ZW_FIELD_INVALID;
    int64_t z;
    enum zw_amt k = zw_amount_text(r->amount, &z);
    v->amt_state[i] = k == ZW_AMT_EMPTY ? ZW_FIELD_EMPTY : k == ZW_AMT_OK ? ZW_FIELD_VALID : ZW_FIELD_INVALID;
    v->memo_on[i] = addr[0] == 'z';
    snprintf(v->memo_preview[i], sizeof(v->memo_preview[i]), "%s", r->memo);
    if (strlen(r->memo) >= sizeof(v->memo_preview[i]))
        memcpy(v->memo_preview[i] + sizeof(v->memo_preview[i]) - 4, "...", 4);
    if (n) view_lookalike(m, addr, v->look[i], sizeof(v->look[i]));
}

static uint32_t fnv(uint32_t h, const void *p, size_t n)
{
    const unsigned char *b = p;
    for (size_t i = 0; i < n; i++) h = (h ^ b[i]) * 16777619u;
    return h;
}

static uint32_t compute_key(const struct zw_send *s)
{
    uint32_t h = fnv(2166136261u, &s->view, sizeof(s->view));
    uint8_t flags[4] = { (uint8_t)s->dlg, s->reveal_open, s->details_open, (uint8_t)s->memo_for };
    h = fnv(h, flags, sizeof(flags));
    h = fnv(h, s->dlg_title, strlen(s->dlg_title));
    h = fnv(h, s->dlg_body, strlen(s->dlg_body));
    h = fnv(h, s->card_txid, strlen(s->card_txid));
    return fnv(h, s->dlg_detail, strlen(s->dlg_detail));
}

static void make_view(struct zw_send *s, const struct zw_model *m)
{
    struct zw_send_view *v = &s->view;
    memset(v, 0, sizeof(*v));
    enum gui_style bs;
    snprintf(v->badge, sizeof(v->badge), "%s", zw_send_badge(&s->form, &bs));
    v->badge_style = (uint8_t)bs;
    view_from(s, m, v);
    view_avail(s, m, v);
    zw_send_totals(&s->form, m->testnet, v->totals, sizeof(v->totals));
    zw_decimal(s->form.fee, v->fee, sizeof(v->fee));
    v->nrcpt = (uint8_t)s->shown;
    for (size_t i = 0; i < s->shown; i++) view_recipient(s, m, i, v);
    v->max_on = s->max_on;
    v->from_open = s->from_open;
    v->can_add = s->shown < ZW_SEND_RCPT_MAX;
    v->card = s->card;
    v->connected = m->conn == ZW_CONN_ONLINE;
    s->key = compute_key(s);
}

uint32_t zw_send_structure_key(const struct zw_send *s) { return s ? s->key : 0; }

/* Set a field's text before or without its node (a read-only field, or an
 * editor that opens on a value). */
void zw_send_seed(struct gui_ui *ui, const char *id, const char *text, size_t cap)
{
    struct gui_input_state *st = gui_ui_input_find(ui, id, true, cap);
    size_t l = strlen(text);
    if (!st || l > st->cap || (st->len == l && !memcmp(st->buf, text, l))) return;
    memcpy(st->buf, text, l + 1);
    st->len = st->caret = st->anchor = l;
    gui_ui_mark_node(ui, id);
}

bool zw_send_sync(struct zw_send *s, const struct zw_send_env *env)
{
    if (!s) return false;
    uint32_t old = s->key;
    s->pend.active = zw_send_busy(s);
    if (s->clear_shield || (s->shield_draft && env->m->bal && !row_of(env->m, s->form.from))) {
        zw_send_clear_form(s, env->ui);
        s->from_user = false;
    }
    read_fields(s, env->ui);
    if (s->from_user && env->m->bal && !row_of(env->m, s->form.from)) s->from_user = false;
    if (!s->from_user) default_from(s, env->m);
    apply_max(s, env);
    char fee[40];
    zw_decimal(s->form.fee, fee, sizeof(fee));
    zw_send_seed(env->ui, "s_fee", fee, ZW_AMOUNT_TEXT - 6);
    if (s->fail_pending && s->dlg == ZW_DLG_NONE) zw_send_show_failure(s, env->ui);
    make_view(s, env->m);
    return s->key != old;
}
