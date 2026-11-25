/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the Send page of z23-wallet, ZclWallet beta13 sendtab.cpp parity.
 * zw_send_plan.c is the pure plan (address checksums, amount text, the four
 * privacy categories, doSendTxValidations, z_sendmany params);
 * zw_send_flow.c is the pure send-flow verdict (beta13 sendflow.h);
 * zw_q_send.c is the background send runner; zw_send_ui.c and
 * zw_screen_send.c are the page state, its actions and its widgets.
 * Amounts are integer zatoshi end to end; nothing here uses floating point. */
#ifndef ZW_SEND_H
#define ZW_SEND_H

#include "zw.h"

#define ZW_SEND_RCPT_MAX 3     /* recipient boxes the page shows (no scrolling page) */
#define ZW_MEMO_MAX 512        /* memo bytes (UTF-8), beta13's memo dialog limit */
#define ZW_ADDR_MAX 128        /* address field bytes; a valid address is at most 95 */
#define ZW_PAY_TO_MAX ZW_ADDR_MAX
#define ZW_AMOUNT_TEXT 24      /* [0-9]{0,8}.[0-9]{0,8} plus slack */
#define ZW_DEFAULT_FEE INT64_C(10000) /* Settings::getMinerFee(): 0.0001 ZCL */
#define ZW_SEND_KEY_MAX 40     /* "zq-" + 32 base62 + NUL */
#define ZW_LOOKALIKE_EDGE 5    /* first and last characters compared */

/* ---- addresses (Settings::isValidAddress) ---- */
enum zw_addr_type { ZW_AT_INVALID, ZW_AT_SAPLING, ZW_AT_SPROUT, ZW_AT_TRANSPARENT };
enum zw_addr_type zw_addr_check(const char *addr);
bool zw_addr_is_z(const char *addr); /* valid and a z-address (Sapling or Sprout) */
bool zw_addr_is_t(const char *addr); /* valid and transparent */
void zw_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
/* Same first and last ZW_LOOKALIKE_EDGE characters as known, different middle. */
bool zw_addr_lookalike(const char *addr, const char *known);

/* ---- amount text: the [0-9]{0,8}\.?[0-9]{0,8} validator of beta13 ---- */
enum zw_amt { ZW_AMT_EMPTY, ZW_AMT_ZERO, ZW_AMT_OK, ZW_AMT_BAD };
enum zw_amt zw_amount_text(const char *s, int64_t *zat);
/* Settings::getDecimalString: 8 decimals, trailing zeros and "." stripped. */
void zw_decimal(int64_t zat, char *buf, size_t cap);
/* getZCLDisplayFormat: the decimal string and " ZCL" (" ZCT" on testnet). */
void zw_money(int64_t zat, bool testnet, char *buf, size_t cap);

/* ---- the plan of one send ---- */
enum zw_send_cat { ZW_CAT_PRIVATE, ZW_CAT_SHIELDING, ZW_CAT_DESHIELD, ZW_CAT_PUBLIC };
struct zw_rcpt {
    char addr[ZW_ADDR_MAX];
    char amount[ZW_AMOUNT_TEXT];
    char memo[ZW_MEMO_MAX + 1];
};
struct zw_send_plan {
    char from[ZW_ADDR_MAX];
    size_t n;
    struct zw_rcpt to[ZW_SEND_RCPT_MAX];
    int64_t fee;
};
/* Balance of the from-address: displayed is the minconf=0 total, confirmed the
 * confirmed spendable part; known is false when the address has no row. */
struct zw_funds { bool known; int64_t displayed, confirmed; };

/* Bounded string copy: at most cap - 1 bytes, always terminated. */
void zw_copy(char *dst, size_t cap, const char *src);
/* QString::trimmed of a field: leading/trailing white space (UTF-8 aware). */
size_t zw_trimmed(const char *s, const char **start);
/* sendCategoryOf: any recipient that is not a valid z-address makes it public. */
enum zw_send_cat zw_send_category(const struct zw_send_plan *p);
/* doSendTxValidations, in beta13's order. False with the first message. */
bool zw_send_validate(const struct zw_send_plan *p, const struct zw_funds *f, bool syncing, bool testnet,
                      char *err, size_t cap);
/* Sum of the recipients' amounts (zatoshi); false when one is not a number. */
bool zw_send_amounts(const struct zw_send_plan *p, int64_t *sum);
/* z_sendmany params as beta13 sends them: [from,[{address,amount,memo}]] and,
 * with a key, minconf 1, the fee and the idempotency key appended. */
bool zw_send_params(const struct zw_send_plan *p, const char *key, char *out, size_t cap);
/* The memo of recipient i as hex of its trimmed UTF-8; empty when none is sent. */
bool zw_memo_hex(const struct zw_rcpt *r, char *out, size_t cap);
/* "You'll send A + F fee = T", or "" when no amount is entered. */
void zw_send_totals(const struct zw_send_plan *p, bool testnet, char *buf, size_t cap);
/* The live privacy badge; style is the colour token for it. */
const char *zw_send_badge(const struct zw_send_plan *p, enum gui_style *style);
/* Confirm-dialog title per category. */
const char *zw_send_confirm_title(enum zw_send_cat c);

/* ---- send flow verdicts (beta13 sendflow.h) ---- */
#define ZW_TXT_SENDING "Sending... your wallet is building the transaction (private sends can take up to a minute)."
#define ZW_TXT_UNKNOWN "Outcome unknown: the wallet will not send again; checking"
enum zw_call_class { ZW_CALL_DEFINITIVE, ZW_CALL_KEY_UNSUPPORTED, ZW_CALL_AMBIGUOUS };
enum zw_flow_state { ZW_FLOW_SENDING, ZW_FLOW_SENT, ZW_FLOW_UNKNOWN, ZW_FLOW_EXPIRED, ZW_FLOW_FAILED,
                     ZW_FLOW_LOST };
struct zw_queue_entry { bool present, has_last_error; char status[16], txid[80], error[256]; };
struct zw_journal_entry { bool present; char state[24], txid[80]; };
struct zw_verdict { enum zw_flow_state state; char txid[80]; char text[400]; };

/* Classify a failed z_sendmany call. first: no earlier attempt was made. */
enum zw_call_class zw_flow_classify(enum zw_err err, const struct zw_rpc_error *e, bool keyed, bool first,
                                    char *msg, size_t cap);
bool zw_flow_queue_find(const struct json_value *reply, const char *opid, struct zw_queue_entry *q);
bool zw_flow_journal_find(const struct json_value *reply, const char *opid, struct zw_journal_entry *j);
bool zw_flow_needs_journal(bool keyed, const struct zw_queue_entry *q, bool unknown);
void zw_flow_resolve(bool keyed, const struct zw_queue_entry *q, bool journal_known,
                     const struct zw_journal_entry *j, struct zw_verdict *v);
/* A keyed Z23 z_sendmany answers {"state","txid","replayed"}. */
void zw_flow_z23_state(const struct json_value *body, struct zw_verdict *v);
/* humaneSendError: a plain headline for a raw node error. */
const char *zw_flow_humane(const char *raw);
bool zw_flow_is_flow_text(const char *s);
const char *zw_flow_text(enum zw_flow_state s); /* the fixed text of a state */
const char *zw_flow_gave_up_text(void);
const char *zw_flow_old_node_text(void);
void zw_flow_retry_refused(const char *reason, char *buf, size_t cap);
/* "zq-" + 32 characters of [A-Za-z0-9] from the system CSPRNG. */
bool zw_flow_new_key(char out[ZW_SEND_KEY_MAX]);
uint32_t zw_flow_retry_delay_ms(int attempt, uint32_t base_ms);
#define ZW_SEND_MAX_ATTEMPTS 40

/* ---- background runner: one send, its retries and its status polling ---- */
enum zw_send_phase { ZW_SP_SUBMITTING, ZW_SP_PROGRESS, ZW_SP_SENT, ZW_SP_FAILED };
struct zw_send_status {
    enum zw_send_phase phase;
    uint32_t seq;
    char opid[128], txid[80], text[400], raw[400];
};
struct zw_sender_timing { uint32_t retry_base_ms, poll_ms, legacy_deadline_ms, z23_deadline_ms, poll_limit_ms; };
struct zw_sender;
/* params_keyed carries the key; params_plain is the form for a node that does
 * not take one. The runner owns copies of both. */
struct zw_sender *zw_sender_start(struct gui_window *win, const struct zw_options *o, const struct zw_model *m,
                                  const char *params_keyed, const char *params_plain);
/* Copies the latest status; true when it changed since the last call. */
bool zw_sender_poll(struct zw_sender *s, struct zw_send_status *out);
bool zw_sender_finished(struct zw_sender *s);
void zw_sender_free(struct zw_sender *s); /* aborts the request in flight and joins */
void zw_sender_set_timing(const struct zw_sender_timing *t); /* tests */

/* ---- page state and actions (UI thread only) ---- */
#define ZW_FROM_ITEMS 16 /* pay-from choices listed; the rest are counted */
enum zw_field { ZW_FIELD_EMPTY, ZW_FIELD_VALID, ZW_FIELD_INVALID };
enum zw_send_dlg { ZW_DLG_NONE, ZW_DLG_ERROR, ZW_DLG_INFO, ZW_DLG_SYNC_GATE, ZW_DLG_CONFIRM, ZW_DLG_DESHIELD,
                   ZW_DLG_MEMO, ZW_DLG_DISCARD, ZW_DLG_FAILED };
/* Everything the page shows, derived from the fields and the model by
 * zw_send_sync. It is plain data: its bytes are the page's structure key. */
struct zw_send_view {
    char badge[160], from_label[160], avail[128], totals[160], fee[24];
    uint8_t badge_style, nrcpt, max_on, from_open, can_add, card, connected;
    uint8_t addr_state[ZW_SEND_RCPT_MAX], amt_state[ZW_SEND_RCPT_MAX], memo_on[ZW_SEND_RCPT_MAX];
    char memo_preview[ZW_SEND_RCPT_MAX][96];
    char look[ZW_SEND_RCPT_MAX][160];
    uint16_t nfrom, from_more;
    char from_items[ZW_FROM_ITEMS][160];
};
struct zw_send {
    struct zw_send_plan form;   /* mirror of the page's fields */
    size_t shown;               /* recipient boxes on the page */
    bool from_user, from_open, max_on, reveal_open, reply_warned, details_open, fail_pending;
    enum zw_send_dlg dlg;
    bool shield_draft;
    size_t memo_for;
    char dlg_title[96], dlg_body[1200], dlg_detail[700];
    struct zw_send_plan pending; /* the plan the confirm dialog shows and commits */
    enum zw_send_cat pending_cat;
    char pending_look[400];
    bool review_bound;
    uint32_t review_generation;
    enum zw_profile review_profile;
    uint16_t review_port;
    char review_datadir[ZW_PATH];
    struct zw_sender *runner;
    struct zw_send_status st;
    struct { bool active; } pend; /* mirrors the current runner for Home's occupancy check */
    bool locked_out;              /* this Send implementation has no record-store lock */
    bool card;
    char card_title[64], card_text[96], card_info[320], card_txid[80];
    char from_addr[ZW_FROM_ITEMS][100];
    struct zw_send_view view;
    uint32_t key;
};
struct zw_send *zw_send_new(void);
void zw_send_cancel_review(struct zw_send *s, struct gui_ui *ui);
bool zw_send_review_current(const struct zw_send *s, const struct zw_model *m);
void zw_send_free(struct zw_send *s);
struct zw_send_env {
    struct gui_window *win;
    struct gui_ui *ui;
    struct zw_model *m;
    const struct zw_options *o;
    int64_t now_s;
};
/* What the app does after a send action or status change. */
struct zw_send_out {
    bool dirty;
    bool refresh; /* a send went out: refetch balances */
    bool msg_set;
    uint32_t msg_ms; /* 0: the message stays */
    char msg[120];
};
/* Mirror the page's fields into the state; true when the page must rebuild. */
bool zw_send_sync(struct zw_send *s, const struct zw_send_env *env);
void zw_send_action(struct zw_send *s, const struct zw_send_env *env, const char *name, struct zw_send_out *out);
void zw_send_wake(struct zw_send *s, const struct zw_send_env *env, struct zw_send_out *out);
void zw_send_show_failure(struct zw_send *s, struct gui_ui *ui); /* the "Couldn't send" box */
void zw_send_seed(struct gui_ui *ui, const char *id, const char *text, size_t cap);
/* Home's "Send from <address>": preselect the pay-from address. */
void zw_send_prefill_from(struct zw_send *s, const char *addr);
enum zw_shield_choice { ZW_SHIELD_READY, ZW_SHIELD_EMPTY, ZW_SHIELD_WAIT, ZW_SHIELD_READ, ZW_SHIELD_CREATE, ZW_SHIELD_BUSY };
const char *zw_shield_source(const struct zw_balances *bal);
enum zw_shield_choice zw_send_home_shield(struct zw_send *s, const struct zw_send_env *env, const char *issued);
void zw_send_clear_form(struct zw_send *s, struct gui_ui *ui);
uint32_t zw_send_structure_key(const struct zw_send *s);
void zw_send_build(struct gui_tree *t, const struct zw_model *m, const struct zw_send *s);
/* Test hooks: the plan the page would confirm, and the dialog shown. */
const struct zw_send_plan *zw_send_form(const struct zw_send *s);
const char *zw_send_dialog_title(const struct zw_send *s);
bool zw_send_busy(const struct zw_send *s);

#endif
