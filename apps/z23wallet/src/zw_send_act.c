/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the Send page's actions and send results (beta13 sendButton,
 * confirmTx, cancelButton, memoButtonClicked, showSendSuccess and the
 * executeTransaction callbacks). Every path that sends goes through
 * commit(), which only runs from the confirm dialog (or the de-shield
 * acknowledgement after it) and closes that dialog before it does anything
 * else. Nothing is sent when any validation fails. */
#if defined(_WIN32)
#include <windows.h>
#include <shellapi.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zw_send.h"

#define PARAMS_CAP 8192

static const char k_not_connected[] =
    "Sending needs the ZClassic node, and the wallet is not connected to it yet. If the status bar says it is "
    "starting, wait until it shows that the wallet is connected, then try again. If it says there is a problem, "
    "use the \"Try again\" button on the Home page.";

static void say(struct zw_send_out *out, const char *msg, uint32_t ms)
{
    zw_copy(out->msg, sizeof(out->msg), msg);
    out->msg_set = true;
    out->msg_ms = ms;
}

static void open_dlg(struct zw_send *s, enum zw_send_dlg d, const char *title, const char *body)
{
    s->dlg = d;
    snprintf(s->dlg_title, sizeof(s->dlg_title), "%s", title);
    snprintf(s->dlg_body, sizeof(s->dlg_body), "%s", body);
    s->dlg_detail[0] = 0;
}

static void close_dlg(struct zw_send *s)
{
    s->dlg = ZW_DLG_NONE;
    s->reveal_open = s->details_open = false;
    s->dlg_title[0] = s->dlg_body[0] = s->dlg_detail[0] = 0;
}

void zw_send_cancel_review(struct zw_send *s)
{
    if (!s) return;
    if (s->shield_draft) s->clear_shield = true;
    if (s->dlg != ZW_DLG_SYNC_GATE && s->dlg != ZW_DLG_CONFIRM && s->dlg != ZW_DLG_DESHIELD) return;
    close_dlg(s);
    memset(&s->pending, 0, sizeof(s->pending));
    s->pending_look[0] = 0;
}

static int64_t peers_of(const struct zw_model *m)
{
    return m->have_net ? m->net.connections : m->have_info ? m->info.connections : 0;
}

static bool local_net(const struct zw_model *m)
{
    return !strcmp(m->chain.chain, "regtest") || zw_sync_classify(m, m->now_s) == ZW_SYNC_LOCAL;
}

static bool is_syncing(const struct zw_model *m, int64_t now_s)
{
    if (!zw_model_synced(m, now_s)) return true;
    return m->profile == ZW_PROFILE_Z23 && m->have_wallet && m->wallet.known && !m->wallet.current;
}

static struct zw_funds funds_of(const struct zw_model *m, const char *addr)
{
    struct zw_funds f = { .known = false };
    for (size_t i = 0; m->bal && i < m->bal->n; i++)
        if (!strcmp(m->bal->rows[i].addr, addr)) {
            f.known = true;
            f.displayed = m->bal->rows[i].zat;
            f.confirmed = m->bal->rows[i].confirmed_zat;
        }
    return f;
}

/* removeExtraAddresses: one empty recipient, fee reset, Send all off. */
void zw_send_clear_form(struct zw_send *s, struct gui_ui *ui)
{
    char id[GUI_ID_MAX];
    for (size_t i = 0; i < ZW_SEND_RCPT_MAX; i++) {
        snprintf(id, sizeof(id), "s_addr%zu", i + 1);
        gui_ui_input_clear(ui, id);
        snprintf(id, sizeof(id), "s_amt%zu", i + 1);
        gui_ui_input_clear(ui, id);
        memset(&s->form.to[i], 0, sizeof(s->form.to[i]));
    }
    s->shield_draft = s->clear_shield = false;
    s->shown = s->form.n = 1;
    s->form.fee = ZW_DEFAULT_FEE;
    s->max_on = false;
}

/* ---- review, gate, confirm, commit ---- */

static void gate_text(const struct zw_model *m, int64_t now_s, char *buf, size_t cap)
{
    if (peers_of(m) == 0 && !local_net(m))
        snprintf(buf, cap, "Your wallet is not connected to any peers yet, so it cannot tell whether its balance "
                 "is current and this transaction could fail.\n\nSend anyway?");
    else if (m->last_update_s && now_s - m->last_update_s > 60)
        snprintf(buf, cap, "Your wallet hasn't reported sync progress recently. Your balance may be up to date, "
                 "or syncing may have paused.\n\nSend anyway?");
    else
        snprintf(buf, cap, "Your wallet is still catching up with the network, so your balance may be incomplete "
                 "and this transaction could fail.\n\nSend anyway?");
}

static void pending_lookalike(struct zw_send *s, const struct zw_model *m)
{
    s->pending_look[0] = 0;
    for (size_t i = 0; i < s->pending.n && !s->pending_look[0]; i++) {
        const char *a;
        size_t n = zw_trimmed(s->pending.to[i].addr, &a);
        char addr[ZW_ADDR_MAX];
        snprintf(addr, sizeof(addr), "%.*s", (int)(n < sizeof(addr) ? n : sizeof(addr) - 1), a);
        for (size_t k = 0; m->bal && k < m->bal->n && !s->pending_look[0]; k++)
            if (zw_addr_lookalike(addr, m->bal->rows[k].addr))
                snprintf(s->pending_look, sizeof(s->pending_look), "Check recipient %zu: it starts and ends like "
                         "your address %s but is a different address.", i + 1, m->bal->rows[k].addr);
    }
}

static void open_confirm(struct zw_send *s, const struct zw_send_env *env)
{
    s->pending = s->form;
    s->pending_cat = zw_send_category(&s->pending);
    pending_lookalike(s, env->m);
    close_dlg(s);
    s->dlg = ZW_DLG_CONFIRM;
    gui_ui_focus(env->ui, "sc_cancel"); /* never the send button */
}

static bool validate_form(struct zw_send *s, const struct zw_send_env *env)
{
    char err[400];
    struct zw_funds f = funds_of(env->m, s->form.from);
    if (zw_send_validate(&s->form, &f, is_syncing(env->m, env->now_s), env->m->testnet, err, sizeof(err)))
        return true;
    open_dlg(s, ZW_DLG_ERROR, "Transaction Error", err);
    gui_ui_focus(env->ui, "se_ok");
    return false;
}

static void review(struct zw_send *s, const struct zw_send_env *env)
{
    char body[600];
    s->from_open = false;
    if (env->m->conn != ZW_CONN_ONLINE) {
        open_dlg(s, ZW_DLG_INFO, "Not connected yet", k_not_connected);
    } else if (zw_send_busy(s)) {
        open_dlg(s, ZW_DLG_INFO, "A payment is still being sent",
                 "Wait until the payment in progress has finished (the status bar shows how it is going), then "
                 "send the next one.");
    } else if (!s->form.from[0]) {
        open_dlg(s, ZW_DLG_INFO, "Nothing to send from yet",
                 "There is no \"Pay from\" address available yet. ZClassic is still starting or loading your "
                 "wallet. Wait until the status bar shows that the wallet is connected and your balance has "
                 "appeared, then try again.");
    } else if (validate_form(s, env)) {
        if (is_syncing(env->m, env->now_s)) {
            gate_text(env->m, env->now_s, body, sizeof(body));
            open_dlg(s, ZW_DLG_SYNC_GATE, "Wallet still syncing", body);
            gui_ui_focus(env->ui, "sg_no");
            return;
        }
        open_confirm(s, env);
        return;
    }
    if (s->dlg == ZW_DLG_INFO) gui_ui_focus(env->ui, "se_ok");
}

static void commit(struct zw_send *s, const struct zw_send_env *env, struct zw_send_out *out)
{
    close_dlg(s); /* first: a repeated activation finds no confirm dialog */
    char key[ZW_SEND_KEY_MAX];
    char *keyed = malloc(PARAMS_CAP), *plain = malloc(PARAMS_CAP);
    bool ok = keyed && plain && zw_flow_new_key(key) && zw_send_params(&s->pending, key, keyed, PARAMS_CAP) &&
              zw_send_params(&s->pending, NULL, plain, PARAMS_CAP);
    if (ok) {
        zw_sender_free(s->runner);
        s->runner = zw_sender_start(env->win, env->o, env->m, keyed, plain);
        ok = s->runner != NULL;
    }
    free(keyed);
    free(plain);
    memset(key, 0, sizeof(key));
    memset(&s->pending, 0, sizeof(s->pending));
    if (!ok) {
        open_dlg(s, ZW_DLG_ERROR, "Couldn't send", "The wallet could not prepare this payment (out of memory or "
                 "no secure random numbers). Nothing was sent.");
        return;
    }
    zw_log("send: confirmed by the user; sending");
    zw_send_clear_form(s, env->ui);
    s->card = false;
    say(out, ZW_TXT_SENDING, 0);
}

/* ---- memo dialog ---- */

static void open_memo(struct zw_send *s, const struct zw_send_env *env, size_t i)
{
    const char *a;
    zw_trimmed(s->form.to[i].addr, &a);
    if (a[0] != 'z') {
        char body[400];
        snprintf(body, sizeof(body), "The memo field can only be used with a z-address.\n%.128s\ndoesn't look like "
                 "a z-address", s->form.to[i].addr);
        open_dlg(s, ZW_DLG_ERROR, "Memos can only be used with z-addresses", body);
        gui_ui_focus(env->ui, "se_ok");
        return;
    }
    close_dlg(s);
    s->dlg = ZW_DLG_MEMO;
    s->memo_for = i;
    s->pending_look[0] = 0;
    /* The editor opens on the current memo; its node exists only after the
     * rebuild, so the field state is seeded directly. */
    gui_ui_input_clear(env->ui, "s_memo_edit");
    zw_send_seed(env->ui, "s_memo_edit", s->form.to[i].memo, ZW_MEMO_MAX);
    gui_ui_focus(env->ui, "s_memo_edit");
}

static void memo_ok(struct zw_send *s, const struct zw_send_env *env)
{
    char text[ZW_MEMO_MAX + 1];
    if (!gui_ui_input_text(env->ui, "s_memo_edit", text, sizeof(text))) text[0] = 0;
    if (strlen(text) > ZW_MEMO_MAX) return; /* Ok is disabled above 512 bytes */
    snprintf(s->form.to[s->memo_for].memo, sizeof(s->form.to[0].memo), "%s", text);
    gui_ui_input_clear(env->ui, "s_memo_edit");
    close_dlg(s);
}

/* fnAddReplyTo: the pay-from z-address, else the first Sapling address. */
static void memo_reply(struct zw_send *s, const struct zw_send_env *env)
{
    char reply[ZW_ADDR_MAX] = "", text[ZW_MEMO_MAX + 1], next[ZW_MEMO_MAX + 160];
    if (zw_addr_is_z(s->form.from)) snprintf(reply, sizeof(reply), "%s", s->form.from);
    for (size_t i = 0; !reply[0] && env->m->bal && i < env->m->bal->n; i++)
        if (env->m->bal->rows[i].kind == ZW_ADDR_SAPLING) snprintf(reply, sizeof(reply), "%s", env->m->bal->rows[i].addr);
    if (!reply[0]) return;
    if (!gui_ui_input_text(env->ui, "s_memo_edit", text, sizeof(text))) text[0] = 0;
    size_t tl = strlen(text), rl = strlen(reply);
    if (tl >= rl && !strcmp(text + tl - rl, reply)) return;
    snprintf(next, sizeof(next), "%s\nReply to:\n%s", text, reply);
    gui_ui_input_set(env->ui, "s_memo_edit", next);
}

/* ---- results of the runner ---- */

void zw_send_show_failure(struct zw_send *s, struct gui_ui *ui)
{
    char detail[700];
    if (s->st.opid[0]) snprintf(detail, sizeof(detail), "Operation id: %s\n\n%s", s->st.opid, s->st.raw);
    else snprintf(detail, sizeof(detail), "%s", s->st.raw);
    open_dlg(s, ZW_DLG_FAILED, "Couldn't send", zw_flow_humane(s->st.text));
    snprintf(s->dlg_detail, sizeof(s->dlg_detail), "%s", detail);
    s->fail_pending = false;
    gui_ui_focus(ui, "sf_ok");
}

static void sent_card(struct zw_send *s, const struct zw_model *m)
{
    s->card = true;
    snprintf(s->card_txid, sizeof(s->card_txid), "%s", s->st.txid);
    if (local_net(m)) {
        snprintf(s->card_title, sizeof(s->card_title), "Transaction created");
        snprintf(s->card_text, sizeof(s->card_text), "Transaction created on the local test network");
        snprintf(s->card_info, sizeof(s->card_info), "It will confirm when a block is mined.");
    } else if (peers_of(m) == 0) {
        snprintf(s->card_title, sizeof(s->card_title), "Transaction created");
        snprintf(s->card_text, sizeof(s->card_text), "Transaction created, but not sent to the network yet");
        snprintf(s->card_info, sizeof(s->card_info), "Your node accepted the transaction, but it is not connected to "
                 "any peers right now, so nobody else has seen it. It will be broadcast when the node reconnects "
                 "(keep ZClassic open). Your funds are not lost.");
    } else {
        snprintf(s->card_title, sizeof(s->card_title), "Sent! Your ZCL is on its way");
        snprintf(s->card_text, sizeof(s->card_text), "Sent! Your ZCL is on its way");
        snprintf(s->card_info, sizeof(s->card_info), "Your node accepted the transaction and is sharing it with the "
                 "network. It will show as confirmed in your Activity list in a few minutes.");
    }
}

void zw_send_wake(struct zw_send *s, const struct zw_send_env *env, struct zw_send_out *out)
{
    if (!s || !s->runner || !zw_sender_poll(s->runner, &s->st)) return;
    char msg[160];
    out->dirty = true;
    switch (s->st.phase) {
    case ZW_SP_SENT:
        snprintf(msg, sizeof(msg), "Tx submitted (right click to copy) txid: %s", s->st.txid);
        say(out, msg, 0);
        sent_card(s, env->m);
        out->refresh = true;
        break;
    case ZW_SP_FAILED:
        say(out, "Transaction couldn't be sent", 15000);
        s->fail_pending = true; /* shown now, or as soon as the open dialog closes */
        if (s->dlg == ZW_DLG_NONE) zw_send_show_failure(s, env->ui);
        break;
    default:
        say(out, s->st.text, 0);
        break;
    }
}

/* ---- explorer link ---- */

static void open_explorer(const struct zw_send *s, const struct zw_send_env *env, struct zw_send_out *out)
{
    char url[160];
    snprintf(url, sizeof(url), "https://explorer.zcl.zelcore.io/tx/%s", s->card_txid);
#if defined(_WIN32)
    wchar_t w[160];
    for (size_t i = 0; i < sizeof(w) / sizeof(w[0]); i++) {
        w[i] = (wchar_t)(unsigned char)url[i];
        if (!url[i]) break;
    }
    if ((INT_PTR)ShellExecuteW(NULL, L"open", w, NULL, NULL, SW_SHOWNORMAL) > 32) return;
#endif
    bool ok = gui_clipboard_set_text(env->win, url, strlen(url));
    say(out, ok ? "Explorer link copied to clipboard" : "Couldn't copy. Try again.", 3000);
}

/* ---- dispatch ---- */

static size_t index_of(const char *name, const char *prefix, size_t limit)
{
    size_t n = strlen(prefix);
    if (strncmp(name, prefix, n)) return limit;
    char *end;
    unsigned long v = strtoul(name + n, &end, 10);
    return *end || v < 1 || v > limit ? limit : (size_t)v - 1;
}

/* The steps that lead to a send; each acts only from its own dialog. */
static bool act_steps(struct zw_send *s, const struct zw_send_env *env, const char *a, struct zw_send_out *out)
{
    if (!strcmp(a, "send.confirm.go") && s->dlg == ZW_DLG_CONFIRM) {
        if (s->pending_cat != ZW_CAT_DESHIELD) { commit(s, env, out); return true; }
        s->dlg = ZW_DLG_DESHIELD;
        gui_ui_focus(env->ui, "sd_no");
    } else if (!strcmp(a, "send.deshield.yes") && s->dlg == ZW_DLG_DESHIELD) {
        commit(s, env, out);
    } else if (!strcmp(a, "send.gate.yes") && s->dlg == ZW_DLG_SYNC_GATE) {
        close_dlg(s);
        if (validate_form(s, env)) open_confirm(s, env);
    } else if (!strcmp(a, "send.discard.yes") && s->dlg == ZW_DLG_DISCARD) {
        zw_send_clear_form(s, env->ui);
        close_dlg(s);
    } else {
        return false;
    }
    return true;
}

static bool act_memo(struct zw_send *s, const struct zw_send_env *env, const char *a)
{
    bool memo = s->dlg == ZW_DLG_MEMO;
    if (!strcmp(a, "send.memo.ok") && memo) {
        memo_ok(s, env);
    } else if (!strcmp(a, "send.memo.reply") && memo) {
        if (s->reply_warned) memo_reply(s, env);
        else s->reveal_open = true; /* "Reveal your address to the recipient?" first */
    } else if (!strcmp(a, "send.reveal.yes") && s->reveal_open) {
        s->reveal_open = false;
        s->reply_warned = true;
        memo_reply(s, env);
    } else if (!strcmp(a, "send.reveal.no")) {
        s->reveal_open = false;
    } else {
        return false;
    }
    return true;
}

static bool act_close(struct zw_send *s, const struct zw_send_env *env, const char *a)
{
    if (!strcmp(a, "send.fail.details")) {
        s->details_open = !s->details_open;
        return true;
    }
    if (strcmp(a, "send.close") && strncmp(a, "send.close.", 11)) return false;
    if (s->dlg == ZW_DLG_MEMO) gui_ui_input_clear(env->ui, "s_memo_edit");
    if (s->dlg == ZW_DLG_DESHIELD || s->dlg == ZW_DLG_CONFIRM) memset(&s->pending, 0, sizeof(s->pending));
    close_dlg(s);
    return true;
}

static bool act_card(struct zw_send *s, const struct zw_send_env *env, const char *a, struct zw_send_out *out)
{
    if (!strcmp(a, "send.card.copy")) {
        bool ok = gui_clipboard_set_text(env->win, s->card_txid, strlen(s->card_txid));
        say(out, ok ? "Copied to clipboard" : "Couldn't copy. Try again.", 3000);
    } else if (!strcmp(a, "send.card.explorer")) {
        open_explorer(s, env, out);
    } else if (!strcmp(a, "send.card.close")) {
        s->card = false;
    } else {
        return false;
    }
    return true;
}

/* cancelButton: typed input asks first (default No); an empty form clears. */
static void cancel(struct zw_send *s, const struct zw_send_env *env)
{
    if (s->form.to[0].addr[0] || s->form.to[0].amount[0]) {
        open_dlg(s, ZW_DLG_DISCARD, "Discard this payment?", "Your typed recipients and amounts will be cleared.");
        gui_ui_focus(env->ui, "sx_no");
    } else {
        zw_send_clear_form(s, env->ui);
    }
}

static bool act_from(struct zw_send *s, const char *a)
{
    size_t i;
    if (!strcmp(a, "send.from")) s->from_open = !s->from_open;
    else if (!strcmp(a, "send.from.close")) s->from_open = false;
    else if ((i = index_of(a, "send.from.", ZW_FROM_ITEMS)) < ZW_FROM_ITEMS && s->from_addr[i][0]) {
        zw_send_prefill_from(s, s->from_addr[i]);
        s->from_open = false;
    } else {
        return false;
    }
    return true;
}

static void act_page(struct zw_send *s, const struct zw_send_env *env, const char *a, struct zw_send_out *out)
{
    size_t i;
    if (!strcmp(a, "send.review")) review(s, env);
    else if (!strcmp(a, "send.cancel")) cancel(s, env);
    else if (act_from(s, a)) return;
    else if (!strcmp(a, "send.max")) s->max_on = !s->max_on;
    else if (!strcmp(a, "send.add") && s->shown < ZW_SEND_RCPT_MAX) {
        char id[GUI_ID_MAX];
        snprintf(id, sizeof(id), "s_addr%zu", ++s->shown);
        gui_ui_focus(env->ui, id);
    } else if ((i = index_of(a, "send.memo.", ZW_SEND_RCPT_MAX)) < ZW_SEND_RCPT_MAX) open_memo(s, env, i);
    else if (index_of(a, "send.book.", ZW_SEND_RCPT_MAX) < ZW_SEND_RCPT_MAX)
        say(out, "The address book opens in a later version.", 3000);
}

void zw_send_action(struct zw_send *s, const struct zw_send_env *env, const char *name, struct zw_send_out *out)
{
    memset(out, 0, sizeof(*out));
    if (!s) return;
    out->dirty = true;
    if (act_steps(s, env, name, out) || act_memo(s, env, name) || act_close(s, env, name) ||
        act_card(s, env, name, out))
        return;
    if (s->dlg != ZW_DLG_NONE) return; /* the page is behind a modal dialog */
    act_page(s, env, name, out);
}
