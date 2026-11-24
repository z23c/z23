/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the Send screen's widgets, as beta13 lays out its Send tab: the
 * privacy badge, "Pay from" (address combo and "Available to send"), "Send
 * To" with one box per recipient (Pay to, Address Book, Amount, ZCL, Send
 * all, Add private note, the memo preview), Add Recipient, the read-only
 * network fee, the totals line and Review and send / Cancel; then the
 * success card and whichever modal dialog is open (Transaction Error, the
 * syncing gate, the confirm dialog, the de-shield acknowledgement, Memo,
 * Discard, Couldn't send). Addresses are shown whole wherever the user
 * verifies them. Built from zw_send_view only, so the structure key covers
 * everything drawn here. */
#include <stdio.h>
#include <string.h>

#include "gui/dialog.h"
#include "zw_send.h"

void zw_screen_send_build(struct gui_tree *t, const struct zw_model *m)
{
    if (m->send) zw_send_build(t, m, m->send);
    else zw_screen_soon(t, "s", "Send", "Sending is not available: the wallet ran out of memory at start.");
}

static enum gui_style field_style(uint8_t state)
{
    return state == ZW_FIELD_VALID ? GS_INPUT_VALID : state == ZW_FIELD_INVALID ? GS_INPUT_INVALID : GS_INPUT;
}

static void label(struct gui_tree *t, const char *id, const char *text, int w)
{
    gui_text(t, id, GS_BODY, text);
    if (w) gui_attr(t, GUI_A_W, w);
}

static void row_begin(struct gui_tree *t, const char *id)
{
    gui_box(t, id, GUI_ROW, GS_BODY);
    gui_attr(t, GUI_A_GAP, 8);
    gui_attr(t, GUI_A_ALIGN, GUI_ALIGN_CENTER);
}

/* ---- the page ---- */

static void pay_from(struct gui_tree *t, const struct zw_send_view *v)
{
    zw_group_begin(t, "s_payfrom", "Pay from", 18, 14, false);
    row_begin(t, "s_from_row");
    gui_button(t, "s_from", GS_BUTTON_SECONDARY, v->nfrom ? v->from_label : "No address holds a balance yet",
               "send.from");
    gui_attr(t, GUI_A_GROW, 1);
    gui_attr(t, GUI_A_H, 34);
    if (!v->nfrom) gui_flag(t, GUI_F_DISABLED);
    gui_end(t);
    row_begin(t, "s_avail_row");
    label(t, "s_avail_lbl", "Available to send", 0);
    gui_text(t, "s_avail", GS_AMOUNT, v->avail);
    gui_spacer(t, 1);
    gui_end(t);
    zw_group_end(t, 18, 10);
}

static void recipient_first_row(struct gui_tree *t, const struct zw_send_view *v, size_t i)
{
    char id[GUI_ID_MAX], act[GUI_ID_MAX];
    snprintf(id, sizeof(id), "s_r%zu_to", i + 1);
    row_begin(t, id);
    snprintf(id, sizeof(id), "s_r%zu_tol", i + 1);
    label(t, id, "Pay to", 70);
    snprintf(id, sizeof(id), "s_addr%zu", i + 1);
    gui_input(t, id, GUI_IN_ADDRESS, "", "Paste a z-address (private) or t-address (public)", ZW_ADDR_MAX - 1);
    gui_last_style(t, field_style(v->addr_state[i]));
    gui_attr(t, GUI_A_GROW, 1);
    snprintf(id, sizeof(id), "s_book%zu", i + 1);
    snprintf(act, sizeof(act), "send.book.%zu", i + 1);
    gui_button(t, id, GS_BUTTON_SECONDARY, "Address Book", act);
    gui_attr(t, GUI_A_H, 34);
    gui_end(t);
    if (v->look[i][0]) {
        snprintf(id, sizeof(id), "s_r%zu_look", i + 1);
        gui_text(t, id, GS_WARN_TEXT, v->look[i]);
        gui_flag(t, GUI_F_WRAP);
    }
}

static void recipient_second_row(struct gui_tree *t, const struct zw_send_view *v, size_t i)
{
    char id[GUI_ID_MAX], act[GUI_ID_MAX];
    snprintf(id, sizeof(id), "s_r%zu_amt", i + 1);
    row_begin(t, id);
    snprintf(id, sizeof(id), "s_r%zu_amtl", i + 1);
    label(t, id, "Amount", 70);
    snprintf(id, sizeof(id), "s_amt%zu", i + 1);
    gui_input(t, id, GUI_IN_AMOUNT, "", "0.00", ZW_AMOUNT_TEXT - 6);
    gui_last_style(t, field_style(v->amt_state[i]));
    gui_attr(t, GUI_A_W, 200);
    if (i == 0 && v->max_on) gui_flag(t, GUI_F_DISABLED); /* read-only while Send all is on */
    snprintf(id, sizeof(id), "s_r%zu_unit", i + 1);
    label(t, id, "ZCL", 0);
    gui_spacer(t, 1);
    if (i == 0) {
        gui_button(t, "s_max1", v->max_on ? GS_BUTTON_PRIMARY : GS_BUTTON_SECONDARY, "Send all", "send.max");
        gui_attr(t, GUI_A_H, 34);
    }
    snprintf(id, sizeof(id), "s_memo%zu", i + 1);
    snprintf(act, sizeof(act), "send.memo.%zu", i + 1);
    gui_button(t, id, GS_BUTTON_SECONDARY, "Add private note", act);
    gui_attr(t, GUI_A_H, 34);
    if (!v->memo_on[i]) gui_flag(t, GUI_F_DISABLED);
    gui_end(t);
    if (v->memo_preview[i][0]) {
        snprintf(id, sizeof(id), "s_r%zu_memo", i + 1);
        gui_text(t, id, GS_BODY, v->memo_preview[i]);
        gui_flag(t, GUI_F_WRAP);
    }
}

static void send_to(struct gui_tree *t, const struct zw_send_view *v)
{
    char id[GUI_ID_MAX], title[24];
    zw_group_begin(t, "s_sendto", "Send To", 18, 14, false);
    for (size_t i = 0; i < v->nrcpt; i++) {
        snprintf(id, sizeof(id), "s_r%zu", i + 1);
        snprintf(title, sizeof(title), "Recipient %zu", i + 1);
        zw_group_begin(t, id, title, 14, 12, false);
        recipient_first_row(t, v, i);
        recipient_second_row(t, v, i);
        zw_group_end(t, 14, 8);
    }
    row_begin(t, "s_add_row");
    gui_button(t, "s_add", GS_BUTTON_SECONDARY, "Add Recipient", "send.add");
    gui_attr(t, GUI_A_H, 34);
    if (!v->can_add) gui_flag(t, GUI_F_DISABLED);
    gui_spacer(t, 1);
    gui_end(t);
    zw_group_end(t, 18, 10);
}

static void fee_and_buttons(struct gui_tree *t, const struct zw_send_view *v)
{
    row_begin(t, "s_fee_row");
    label(t, "s_fee_lbl", "Network fee", 0);
    /* Read-only (custom fees are off): zw_send_sync keeps its text. */
    gui_input(t, "s_fee", GUI_IN_AMOUNT, "", "", ZW_AMOUNT_TEXT - 6);
    gui_attr(t, GUI_A_W, 120);
    gui_flag(t, GUI_F_DISABLED);
    label(t, "s_fee_unit", "ZCL", 0);
    gui_spacer(t, 1);
    gui_end(t);
    gui_text(t, "s_totals", GS_BODY, v->totals);
    row_begin(t, "s_btns");
    gui_spacer(t, 1);
    gui_button(t, "s_review", GS_BUTTON_PRIMARY, "Review and send", "send.review");
    gui_attr(t, GUI_A_H, 38);
    gui_attr(t, GUI_A_W, 170);
    gui_flag(t, GUI_F_DEFAULT); /* opens the checks and the confirm dialog; never sends */
    gui_button(t, "s_cancel", GS_BUTTON_SECONDARY, "Cancel", "send.cancel");
    gui_attr(t, GUI_A_H, 38);
    gui_attr(t, GUI_A_W, 110);
    gui_end(t);
}

static void sent_card(struct gui_tree *t, const struct zw_send *s, const struct zw_model *m)
{
    gui_box(t, "s_card", GUI_COL, GS_CARD);
    gui_attr(t, GUI_A_PAD, 12);
    gui_attr(t, GUI_A_GAP, 6);
    gui_text(t, "s_card_text", GS_TITLE, s->card_text);
    gui_text(t, "s_card_info", GS_MUTED, s->card_info);
    gui_flag(t, GUI_F_WRAP);
    row_begin(t, "s_card_btns");
    gui_spacer(t, 1);
    gui_button(t, "s_card_copy", GS_BUTTON_SECONDARY, "Copy txid", "send.card.copy");
    gui_attr(t, GUI_A_H, 32);
    if (!m->testnet) { /* there is no testnet explorer */
        gui_button(t, "s_card_view", GS_BUTTON_SECONDARY, "View on explorer", "send.card.explorer");
        gui_attr(t, GUI_A_H, 32);
    }
    gui_button(t, "s_card_close", GS_BUTTON_SECONDARY, "Close", "send.card.close");
    gui_attr(t, GUI_A_H, 32);
    gui_end(t);
    gui_end(t);
}

static void from_popup(struct gui_tree *t, const struct zw_send_view *v)
{
    char id[GUI_ID_MAX], act[GUI_ID_MAX], more[64];
    gui_dialog(t, "s_from_pop", "", "send.from.close");
    for (size_t i = 0; i < v->nfrom; i++) {
        snprintf(id, sizeof(id), "s_from_i%zu", i + 1);
        snprintf(act, sizeof(act), "send.from.%zu", i + 1);
        gui_button(t, id, GS_MENU_ITEM, v->from_items[i], act);
    }
    if (v->from_more) {
        snprintf(more, sizeof(more), "\xE2\x80\xA6 and %u more addresses", (unsigned)v->from_more);
        gui_button(t, "s_from_more", GS_MENU_ITEM, more, "send.from.close");
        gui_flag(t, GUI_F_DISABLED);
    }
    gui_end(t);
}

/* ---- dialogs ---- */

/* fnSplitAddressForWrap: a z-address in two halves; nothing is cut. */
static void split_addr(const char *a, char *out, size_t cap)
{
    size_t n = strlen(a);
    if (a[0] != 'z') snprintf(out, cap, "%s", a);
    else snprintf(out, cap, "%.*s\n%s", (int)(n / 2), a, a + n / 2);
}

static void amount_row(struct gui_tree *t, const char *id, const char *left, const char *right, enum gui_style st)
{
    char sub[GUI_ID_MAX];
    gui_box(t, id, GUI_ROW, GS_GROUP);
    gui_attr(t, GUI_A_GAP, 12);
    snprintf(sub, sizeof(sub), "%.24s_a", id);
    gui_text(t, sub, st, left);
    gui_attr(t, GUI_A_GROW, 1);
    gui_flag(t, GUI_F_WRAP | GUI_F_SELECTABLE);
    snprintf(sub, sizeof(sub), "%.24s_v", id);
    gui_text(t, sub, st, right);
    gui_flag(t, GUI_F_RIGHT);
    gui_end(t);
}

static void confirm_rows(struct gui_tree *t, const struct zw_send *s, const struct zw_model *m)
{
    char id[GUI_ID_MAX], addr[2 * ZW_ADDR_MAX], amt[48];
    int64_t total = s->pending.fee;
    for (size_t i = 0; i < s->pending.n; i++) {
        const char *a, *mm;
        size_t n = zw_trimmed(s->pending.to[i].addr, &a), ml = zw_trimmed(s->pending.to[i].memo, &mm);
        char trimmed[ZW_ADDR_MAX];
        snprintf(trimmed, sizeof(trimmed), "%.*s", (int)(n < sizeof(trimmed) ? n : sizeof(trimmed) - 1), a);
        int64_t z = 0;
        zw_amount_text(s->pending.to[i].amount, &z);
        total += z;
        split_addr(trimmed, addr, sizeof(addr));
        zw_money(z, m->testnet, amt, sizeof(amt));
        snprintf(id, sizeof(id), "sc_to%zu", i + 1);
        amount_row(t, id, addr, amt, GS_BODY);
        if (trimmed[0] == 'z' && ml) {
            snprintf(id, sizeof(id), "sc_memo%zu", i + 1);
            gui_text(t, id, GS_MUTED, s->pending.to[i].memo);
            gui_flag(t, GUI_F_WRAP | GUI_F_SELECTABLE);
        }
    }
    zw_money(s->pending.fee, m->testnet, amt, sizeof(amt));
    amount_row(t, "sc_fee", "Miner Fee", amt, GS_BODY);
    zw_money(total, m->testnet, amt, sizeof(amt));
    amount_row(t, "sc_total", "Total", amt, GS_AMOUNT);
}

static void confirm_warnings(struct gui_tree *t, const struct zw_send *s, const struct zw_model *m)
{
    int64_t peers = m->have_net ? m->net.connections : m->info.connections;
    bool local = !strcmp(m->chain.chain, "regtest") || zw_sync_classify(m, m->now_s) == ZW_SYNC_LOCAL;
    if (peers == 0 && !local) {
        gui_text(t, "sc_nopeers", GS_WARN_TEXT, "zclassicd doesn't seem to have any peers. You might not be "
                 "connected to the internet, so this Transaction might not work.");
        gui_flag(t, GUI_F_WRAP);
    }
    if (!zw_model_synced(m, m->now_s)) {
        gui_text(t, "sc_syncing", GS_WARN_TEXT, "You are sending a transaction while your node is still syncing. "
                 "This may not work.");
        gui_flag(t, GUI_F_WRAP);
    }
    if (s->pending_cat == ZW_CAT_DESHIELD) {
        gui_text(t, "sc_public", GS_WARN_TEXT, "DE-SHIELD: you are moving funds from a PRIVATE (shielded) address "
                 "to a PUBLIC transparent address. The amount, the recipient, AND the link back to your shielded "
                 "sender become permanently visible to everyone on the blockchain.");
        gui_flag(t, GUI_F_WRAP);
    } else if (s->pending_cat == ZW_CAT_PUBLIC) {
        gui_text(t, "sc_public", GS_AMBER_TEXT, "This transaction is PUBLIC: the amount and recipient will be "
                 "permanently visible to everyone on the blockchain.");
        gui_flag(t, GUI_F_WRAP);
    }
    if (s->pending.from[0] == 't') { /* beta13 shields such change by default; this version does not yet */
        gui_text(t, "sc_change", GS_AMBER_TEXT, "Any change from this transparent address goes back to a PUBLIC "
                 "transparent address: automatic shielding of change is not in this version yet.");
        gui_flag(t, GUI_F_WRAP);
    }
    if (s->pending_look[0]) {
        gui_text(t, "sc_look", GS_WARN_TEXT, s->pending_look);
        gui_flag(t, GUI_F_WRAP);
    }
}

static void confirm_dialog(struct gui_tree *t, const struct zw_send *s, const struct zw_model *m)
{
    static const char *const badges[4] = { "PRIVATE  z \xE2\x86\x92 z", "SHIELDING  t \xE2\x86\x92 z",
                                           "DE-SHIELD  z \xE2\x86\x92 t", "PUBLIC  t \xE2\x86\x92 t" };
    static const enum gui_style tones[4] = { GS_BADGE_PRIVATE, GS_DIALOG, GS_BADGE_DANGER, GS_BADGE_PUBLIC };
    char from[2 * ZW_ADDR_MAX], amount[64], send[96];
    int64_t sum = 0;
    zw_send_amounts(&s->pending, &sum);
    zw_money(sum, m->testnet, amount, sizeof(amount));
    snprintf(send, sizeof(send), "Send %s", amount);
    gui_dialog_open(t, "s_conf", zw_send_confirm_title(s->pending_cat), "send.close", 620);
    gui_text(t, "sc_badge", tones[s->pending_cat], badges[s->pending_cat]);
    zw_group_begin(t, "sc_from", "From", 12, 12, false);
    split_addr(s->pending.from, from, sizeof(from));
    gui_text(t, "sc_from_addr", GS_BODY, from);
    gui_flag(t, GUI_F_WRAP | GUI_F_SELECTABLE);
    zw_group_end(t, 12, 8);
    zw_group_begin(t, "sc_tobox", "To", 12, 12, false);
    confirm_rows(t, s, m);
    zw_group_end(t, 12, 8);
    confirm_warnings(t, s, m);
    const struct gui_dialog_button b[2] = {
        { "sc_cancel", "Cancel", "send.close", GS_BUTTON_SECONDARY, true, false },
        { "sc_send", send, "send.confirm.go", s->pending_cat == ZW_CAT_DESHIELD ? GS_BUTTON_DANGER : GS_BUTTON_PRIMARY,
          false, false },
    };
    gui_dialog_buttons(t, "sc_btns", b, 2);
    gui_dialog_close(t);
}

static void memo_dialog(struct gui_tree *t, const struct zw_send *s)
{
    gui_dialog_open(t, "s_memo", "Memo", "send.close.memo", 560);
    gui_text(t, "sm_label", GS_DIALOG, "Memo");
    gui_input(t, "s_memo_edit", GUI_IN_MEMO, "", "", ZW_MEMO_MAX);
    gui_attr(t, GUI_A_H, 120);
    const struct gui_dialog_button b[3] = {
        { "sm_reply", "Include Reply Address", "send.memo.reply", GS_BUTTON_SECONDARY, false, false },
        { "sm_ok", "OK", "send.memo.ok", GS_BUTTON_PRIMARY, false, false },
        { "sm_cancel", "Cancel", "send.close.memo", GS_BUTTON_SECONDARY, false, false },
    };
    gui_dialog_buttons(t, "sm_btns", b, 3);
    gui_dialog_close(t);
    if (!s->reveal_open) return;
    const struct gui_dialog_button r[2] = {
        { "sr_yes", "Yes", "send.reveal.yes", GS_BUTTON_SECONDARY, false, false },
        { "sr_no", "No", "send.reveal.no", GS_BUTTON_SECONDARY, true, false },
    };
    gui_msgbox(t, "s_reveal", "Reveal your address to the recipient?",
               "Including a reply address writes your own z-address into the encrypted memo. Only the recipient "
               "can read it, but it reveals your identity to them and lets them link this payment to your "
               "shielded address.\n\nInclude your reply address anyway?", NULL, r, 2, "send.reveal.no", 480);
}

static void yes_no(struct gui_tree *t, const struct zw_send *s, const char *id, const char *yes_id, const char *no_id,
                   const char *yes_act, enum gui_style yes_style)
{
    const struct gui_dialog_button b[2] = {
        { yes_id, "Yes", yes_act, yes_style, false, false },
        { no_id, "No", "send.close", GS_BUTTON_SECONDARY, true, false },
    };
    gui_msgbox(t, id, s->dlg_title, s->dlg_body, NULL, b, 2, "send.close", 480);
}

static void failed_dialog(struct gui_tree *t, const struct zw_send *s)
{
    const struct gui_dialog_button b[2] = {
        { "sf_det", s->details_open ? "Hide Details..." : "Show Details...", "send.fail.details",
          GS_BUTTON_SECONDARY, false, false },
        { "sf_ok", "OK", "send.close", GS_BUTTON_PRIMARY, true, false },
    };
    gui_msgbox(t, "s_fail", s->dlg_title, s->dlg_body, s->details_open ? s->dlg_detail : NULL, b, 2, "send.close",
               520);
}

static void dialogs(struct gui_tree *t, const struct zw_send *s, const struct zw_model *m)
{
    static const char deshield_body[] =
        "This send moves funds OUT of your private (shielded) balance onto a PUBLIC transparent address. The "
        "amount, the recipient, and the link back to your shielded sender will be permanently visible on the "
        "blockchain.\n\nThis cannot be undone. De-shield anyway?";
    const struct gui_dialog_button ok[1] = { { "se_ok", "OK", "send.close", GS_BUTTON_PRIMARY, true, false } };
    const struct gui_dialog_button ack[2] = {
        { "sd_yes", "Yes", "send.deshield.yes", GS_BUTTON_DANGER, false, false },
        { "sd_no", "No", "send.close", GS_BUTTON_SECONDARY, true, false },
    };
    switch (s->dlg) {
    case ZW_DLG_ERROR: case ZW_DLG_INFO:
        gui_msgbox(t, "s_err", s->dlg_title, s->dlg_body, NULL, ok, 1, "send.close", 480);
        break;
    case ZW_DLG_SYNC_GATE: yes_no(t, s, "s_gate", "sg_yes", "sg_no", "send.gate.yes", GS_BUTTON_AMBER); break;
    case ZW_DLG_DISCARD: yes_no(t, s, "s_disc", "sx_yes", "sx_no", "send.discard.yes", GS_BUTTON_SECONDARY); break;
    case ZW_DLG_CONFIRM: confirm_dialog(t, s, m); break;
    case ZW_DLG_DESHIELD:
        gui_msgbox(t, "s_desh", "De-shield to a public address?", deshield_body, NULL, ack, 2, "send.close", 480);
        break;
    case ZW_DLG_MEMO: memo_dialog(t, s); break;
    case ZW_DLG_FAILED: failed_dialog(t, s); break;
    default: break;
    }
}

void zw_send_build(struct gui_tree *t, const struct zw_model *m, const struct zw_send *s)
{
    const struct zw_send_view *v = &s->view;
    gui_box(t, "s_page", GUI_COL, GS_PAGE);
    gui_attr(t, GUI_A_GROW, 1);
    gui_attr(t, GUI_A_GAP, 8);
    if (v->card) sent_card(t, s, m);
    gui_text(t, "s_badge", (enum gui_style)v->badge_style, v->badge);
    pay_from(t, v);
    send_to(t, v);
    fee_and_buttons(t, v);
    gui_spacer(t, 1);
    if (v->from_open && v->nfrom) from_popup(t, v);
    dialogs(t, s, m);
    gui_end(t);
}
