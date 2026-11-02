/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "wallet_screens.h"
#include "base/cleanse.h"
#include "json/json.h"
#include "payment_code.h"
#include "wallet_view.h"
#include "zutf8/zutf8.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OUT_CAP 65536u
#define PAGES_MAX 64u
#define TXID_MAX (WALLET_TXID_LEN + 1u)
#define MEMO_MAX 1025u /* 512 bytes of text, or 512 bytes as hex, and the NUL */
#define NOTE_MAX 192u
#define WALLET_COPIED_NOTE "Address copied. It clears in 1 minute."
#define WALLET_COPY_FAILED_NOTE "Could not copy the address."
#define MAX_UNIX 253402300799LL
#define MACHINES_MAX 64u
#define CHUNK_MAX 280u
#define CHUNKS_MAX 8u
#define TOKEN_MAX 16u

enum direction { DIR_UNKNOWN, DIR_SENT, DIR_RECEIVED, DIR_INTERNAL };
/* What the node reports in fully_shielded: true, false, or null (or nothing) when the wallet cannot tell. */
enum shield { SHIELD_UNKNOWN, SHIELD_FULL, SHIELD_PART };
enum status { STATUS_UNKNOWN, STATUS_CONFIRMED, STATUS_PENDING };
/* What the node says about private payments in a history page: complete, hidden because a locked wallet holds no viewing
 * key, or nothing usable. Only a page that says "ok" is the whole history. */
enum history_state { HIST_UNSAID, HIST_OK, HIST_HIDDEN };
enum kind { K_SUMMARY, K_FLEET, K_LATEST, K_NEW, K_HISTORY, K_DETAIL, K_COUNT };

struct entry {
    enum direction direction;
    enum shield shield;
    enum status status;
    bool amount_known, time_known, memo_present;
    uint64_t amount_zat;
    int64_t time;
    char txid[TXID_MAX]; /* empty when the node gave none that is a transaction id */
};

/* Everything a wallet screen holds that is wiped when the owner leaves. */
struct data {
    bool funds_loaded, fleet_loaded, funds_fresh, fleet_fresh, node_silent;
    uint64_t summary_at, fleet_at, requested_at;
    struct wallet_view view;
    char fleet[WALLET_TEXT_MAX];
    bool address_pending, has_amount, no_receive;
    uint64_t amount_zat;
    enum zapp_pay_network network;
    char address[ZAPP_PAY_ADDRESS_MAX], code[ZAPP_RECEIVE_CODE_MAX], note[NOTE_MAX], scan_note[NOTE_MAX];
    bool history_pending, history_failed, has_more;
    enum history_state history_state;
    unsigned page, detail;
    size_t rows;
    char cursor[PAGES_MAX][WALLET_CURSOR_MAX], next[WALLET_CURSOR_MAX];
    struct entry entry[WALLET_PAGE_ROWS];
    bool detail_pending, detail_failed, memo_loaded, memo_hex, memo_over;
    char memo[MEMO_MAX];
};

struct job {
    struct wallet_env env;
    char op[12], arg[WALLET_CURSOR_MAX];
    unsigned epoch;
    enum kind kind;
};
struct flight { bool running, queued; struct job next; };

static struct {
    pthread_mutex_t lock;
    struct wallet_env env;
    bool ready, secure, blocked, held;
    uint64_t held_at; /* when the pause kept the protection */
    unsigned held_ticks; /* settle calls since then */
    char why[96]; /* what the refused protection could not do, for the notice shown instead of the wallet */
    unsigned epoch, version, dropped;
    enum wallet_page page;
    struct data d;
    struct flight flight[K_COUNT];
} st = {.lock = PTHREAD_MUTEX_INITIALIZER};

/* ---- small helpers ---- */

/* The protection a pause kept goes only after this long and this many ticks, so a stalled UI thread cannot
 * release it before a screen without wallet data has been drawn. */
enum { WALLET_SETTLE_MS = 250, WALLET_SETTLE_TICKS = 2 };

static void touch(void) { ++st.version; }
static void copy(char *dst, size_t cap, const char *src) { snprintf(dst, cap, "%s", src); }
static uint64_t now(void) { return st.env.now_ms ? st.env.now_ms(st.env.ctx) : 0; }
/* The JSON object in command output: at its start, or on the first line that begins with a brace. */
static const char *json_start(const char *text)
{
    const char *at = !text ? NULL : text[0] == '{' ? text : strstr(text, "\n{");
    return at && at[0] == '\n' ? at + 1 : at;
}
/* The data object of a successful reply, or NULL. */
static const struct json_value *data_of(const struct json_value *root)
{
    const struct json_value *ok = json_get(root, "ok"), *data = json_get(root, "data");
    return ok && ok->type == JSON_BOOL && json_get_bool(ok) && data && data->type == JSON_OBJ ? data : NULL;
}
/* The member of the given type, or NULL when it is missing or of another type. */
static const struct json_value *typed(const struct json_value *object, const char *key, enum json_type type)
{
    const struct json_value *value = json_get(object, key);
    return value && value->type == type ? value : NULL;
}
static const char *text_of(const struct json_value *object, const char *key)
{
    const struct json_value *value = typed(object, key, JSON_STR);
    return value ? json_get_str(value) : NULL;
}
static bool is(const char *text, const char *want) { return text && !strcmp(text, want); }
/* Frees a parsed reply after overwriting the text in it. */
static void drop_tree(struct json_value *root)
{
    json_cleanse_strings(root);
    json_free(root);
}

/* ---- text from other people ---- */

/* The visible form of the character at in: itself, or its code point or byte in angle brackets. */
static size_t visible_token(const char *in, size_t len, char tok[TOKEN_MAX])
{
    uint32_t cp = 0;
    size_t used = 0;
    if (zutf8_decode_n(in, len, &cp, &used) != ZUTF8_OK) {
        snprintf(tok, TOKEN_MAX, "<x%02X>", (unsigned)(unsigned char)in[0]);
        return 1;
    }
    if (zapp_pay_cp_hidden(cp)) snprintf(tok, TOKEN_MAX, "<U+%04X>", (unsigned)cp);
    else { memcpy(tok, in, used); tok[used] = '\0'; }
    return used;
}

/* ---- items ---- */

static struct wallet_item *add(struct wallet_screen *s, enum wallet_item_kind kind, enum wallet_action action, const char *text)
{
    if (s->count >= WALLET_ITEMS_MAX) return NULL;
    struct wallet_item *item = &s->items[s->count++];
    memset(item, 0, sizeof(*item));
    item->kind = kind;
    item->action = action;
    copy(item->text, sizeof(item->text), text);
    return item;
}
static void line(struct wallet_screen *s, const char *text) { (void)add(s, WALLET_ITEM_TEXT, WALLET_ACT_NONE, text); }
static void note(struct wallet_screen *s, const char *text) { (void)add(s, WALLET_ITEM_NOTE, WALLET_ACT_NONE, text); }
static void button(struct wallet_screen *s, enum wallet_action action, const char *text) { (void)add(s, WALLET_ITEM_BUTTON, action, text); }
/* The title of a page. When another window has been drawing over the app and taps were dropped, the reason follows it. */
static void title(struct wallet_screen *s, const char *text)
{
    (void)add(s, WALLET_ITEM_TITLE, WALLET_ACT_NONE, text);
    if (st.dropped) note(s, "Another app is drawing over this screen, so your taps were ignored. Turn off screen dimmers and overlays, then tap again.");
}

/* A memo in items of their own kind, every hazardous character shown as its code point. What does not
 * fit in the items allowed says so. */
static void memo_items(struct wallet_screen *s, const char *raw)
{
    char chunk[CHUNK_MAX + TOKEN_MAX], tok[TOKEN_MAX];
    size_t used = 0, items = 0, len = strlen(raw);
    for (size_t at = 0; at < len;) {
        size_t n = visible_token(raw + at, len - at, tok), tok_len = strlen(tok);
        if (used + tok_len > CHUNK_MAX) {
            (void)add(s, WALLET_ITEM_MEMO, WALLET_ACT_NONE, chunk);
            used = 0;
            if (++items == CHUNKS_MAX) { note(s, "The memo is longer than this screen shows."); return; }
        }
        memcpy(chunk + used, tok, tok_len + 1);
        used += tok_len;
        at += n;
    }
    if (used) { chunk[used] = '\0'; (void)add(s, WALLET_ITEM_MEMO, WALLET_ACT_NONE, chunk); }
}

/* What the node reported, in the order the owner asks: spendable now, what is arriving, waiting, public and maturing, then
 * how current it is. */
static void funds_lines(struct wallet_screen *s, const struct data *d)
{
    line(s, "Balance");
    (void)add(s, WALLET_ITEM_AMOUNT, WALLET_ACT_NONE, d->view.balance);
    if (d->view.pending[0]) line(s, d->view.pending);
    if (d->view.unready_line[0]) line(s, d->view.unready_line);
    if (d->view.total_line[0]) line(s, d->view.total_line);
    if (d->view.public_line[0]) line(s, d->view.public_line);
    if (d->view.immature_line[0]) line(s, d->view.immature_line);
    if (d->funds_fresh) line(s, d->view.sync);
    else note(s, "Last read more than 30 seconds ago, so these amounts and the sync state may be out of date. Check that your node is running.");
    if (!d->view.known) note(s, "The wallet could not be read. Check that your node is running, then open this screen again.");
    if (d->view.send[0]) note(s, d->view.send);
}

/* A node that gave no answer. A process known to run is starting or busy: Start would only be refused, so the owner is told to
 * wait. Otherwise it is stopped, or not answering when the app cannot tell, and Start is offered. */
static void silent_node_items(struct wallet_screen *s)
{
    if (st.env.node_running && st.env.node_running(st.env.ctx)) {
        line(s, "Waiting for your node. It is running and shows your balance as soon as it answers; after a restart that takes a few minutes.");
        return;
    }
    line(s, st.env.node_running ? "Node stopped. Start it to see your funds." : "The node is not answering. Start it to see your funds.");
    button(s, WALLET_ACT_START_NODE, "Start node");
}
static void funds_items(struct wallet_screen *s)
{
    const struct data *d = &st.d;
    title(s, "Wallet");
    if (d->scan_note[0]) note(s, d->scan_note);
    if (!d->funds_loaded) line(s, "Loading…");
    else if (d->node_silent) silent_node_items(s);
    else funds_lines(s, d);
    if (d->fleet_loaded && !d->node_silent) line(s, d->fleet_fresh ? d->fleet : WALLET_FLEET_UNCHECKED);
    button(s, WALLET_ACT_RECEIVE, "Receive");
    button(s, WALLET_ACT_SEND, d->scan_note[0] ? "Scan again" : "Send");
    button(s, WALLET_ACT_HISTORY, "History");
    button(s, WALLET_ACT_BACK, "Home");
}

static void receive_items(struct wallet_screen *s)
{
    const struct data *d = &st.d;
    char grouped[ZAPP_PAY_ADDRESS_MAX * 2], text[WALLET_TEXT_MAX];
    title(s, "Receive");
    bool shown = d->address[0] && wallet_view_group_address(d->address, grouped, sizeof(grouped));
    if (shown) {
        (void)add(s, WALLET_ITEM_QR, WALLET_ACT_NONE, d->code);
        (void)add(s, WALLET_ITEM_ADDRESS, WALLET_ACT_NONE, grouped);
        button(s, WALLET_ACT_COPY_ADDRESS, "Copy address");
        if (d->has_amount && zapp_zat_format(d->amount_zat, grouped, sizeof(grouped))) {
            snprintf(text, sizeof(text), "Asking for %s ZCL", grouped);
            line(s, text);
        }
    } else if (d->address_pending) line(s, "Loading the address…");
    if (!d->no_receive) button(s, WALLET_ACT_NEW_ADDRESS, "New address");
    if (d->note[0]) note(s, d->note);
    (void)add(s, WALLET_ITEM_INPUT, WALLET_ACT_NONE, "Amount in ZCL (optional)");
    button(s, WALLET_ACT_SET_AMOUNT, "Set amount");
    button(s, WALLET_ACT_BACK, "Back");
}

/* ---- history ---- */

static const char *direction_label(enum direction direction)
{
    return direction == DIR_SENT ? "Sent" : direction == DIR_RECEIVED ? "Received" :
           direction == DIR_INTERNAL ? "Moved inside your wallet" : "Direction unknown";
}
/* What the entry says about privacy, or "" when the node makes no claim. Only the node's fully_shielded says: true
 * when every input and output of the transaction is shielded, false when any is transparent. A payment from a
 * private balance to a public address, or from a public sender to a private one, is not private in either direction. */
static const char *pool_label(const struct entry *e)
{
    return e->shield == SHIELD_FULL ? "Private" : e->shield == SHIELD_PART ? "Public" : "";
}
static const char *state_label(enum status status)
{
    return status == STATUS_CONFIRMED ? "Confirmed" : status == STATUS_PENDING ? "Pending" : "State unknown";
}
static void amount_label(const struct entry *e, char *out, size_t cap)
{
    char zcl[32];
    if (e->amount_known && zapp_zat_format(e->amount_zat, zcl, sizeof(zcl))) snprintf(out, cap, "%s ZCL", zcl);
    else copy(out, cap, "Amount unknown");
}
/* The date of a Unix time as UTC "YYYY-MM-DD", and with the time of day when full. */
static void date_label(const struct entry *e, bool full, char *out, size_t cap)
{
    if (!e->time_known) { copy(out, cap, "Date unknown"); return; }
    int64_t days = e->time / 86400 + 719468, secs = e->time % 86400;
    int64_t era = days / 146097, doe = days - era * 146097;
    int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100), mp = (5 * doy + 2) / 153;
    int64_t day = doy - (153 * mp + 2) / 5 + 1, month = mp < 10 ? mp + 3 : mp - 9;
    int64_t year = yoe + era * 400 + (month <= 2 ? 1 : 0);
    if (full) snprintf(out, cap, "%04lld-%02lld-%02lld %02lld:%02lld UTC", (long long)year, (long long)month, (long long)day, (long long)(secs / 3600), (long long)(secs % 3600 / 60));
    else snprintf(out, cap, "%04lld-%02lld-%02lld", (long long)year, (long long)month, (long long)day);
}
static void row_text(const struct entry *e, char *out, size_t cap)
{
    char amount[48], date[32];
    amount_label(e, amount, sizeof(amount));
    date_label(e, false, date, sizeof(date));
    const char *pool = pool_label(e);
    snprintf(out, cap, "%s\n%s%s%s · %s · %s", amount, direction_label(e->direction), pool[0] ? " · " : "", pool, state_label(e->status), date);
}

/* The sentence for a first page with no rows. "No transactions yet." only when the node says it is current. */
static const char *empty_history_text(const struct data *d)
{
    if (!d->funds_loaded || !d->view.known) return "None found so far.";
    if (d->view.scanning) return "None found so far. The wallet is still scanning the chain.";
    return d->view.current ? "No transactions yet." : "None found so far. The node is not up to date.";
}
/* The line above the rows: loading, a failure, what the node says is missing from the list, or why it is empty. An
 * empty list is never called empty unless the node says it holds every payment. */
static void history_status(struct wallet_screen *s, const struct data *d)
{
    if (d->history_pending) { line(s, "Loading…"); return; }
    if (d->history_failed) { note(s, "History could not be read. Check that your node is running, then open History again."); return; }
    if (d->history_state == HIST_HIDDEN) {
        note(s, "Private payments are hidden while the wallet is locked. Only public ones are listed.");
        return;
    }
    if (d->history_state != HIST_OK) {
        note(s, "The node did not say whether this list is complete, so private payments may be missing.");
        return;
    }
    if (!d->rows) line(s, d->page ? "No older transactions." : empty_history_text(d));
}

static void history_items(struct wallet_screen *s)
{
    const struct data *d = &st.d;
    char text[WALLET_TEXT_MAX];
    title(s, "History");
    history_status(s, d);
    for (size_t i = 0; i < d->rows; ++i) {
        row_text(&d->entry[i], text, sizeof(text));
        struct wallet_item *item = add(s, WALLET_ITEM_BUTTON, WALLET_ACT_DETAIL, text);
        if (item) item->arg = (unsigned)i;
    }
    if (d->page) button(s, WALLET_ACT_NEWER, "Newer");
    if (d->has_more && d->page + 1 < PAGES_MAX) button(s, WALLET_ACT_OLDER, "Older");
    else if (d->has_more) note(s, "Older transactions are not listed here.");
    button(s, WALLET_ACT_BACK, "Back");
}

static void detail_memo_items(struct wallet_screen *s, const struct data *d)
{
    line(s, "Memo, written by the sender");
    if (d->detail_pending) line(s, "Loading…");
    else if (d->detail_failed) note(s, "The memo could not be read. Check that your node is running, then open this transaction again.");
    else if (!d->memo_loaded) note(s, "The wallet reports a memo but gave none.");
    else {
        if (d->memo_hex) line(s, "Not text, so shown as hexadecimal");
        memo_items(s, d->memo);
        if (d->memo_over) note(s, "The memo was longer than the 512 bytes the wallet keeps, so it is cut.");
    }
}

static void detail_items(struct wallet_screen *s)
{
    const struct data *d = &st.d;
    const struct entry *e = &d->entry[d->detail < d->rows ? d->detail : 0];
    char text[WALLET_TEXT_MAX];
    title(s, direction_label(e->direction));
    line(s, e->shield == SHIELD_PART ? "Public: at least one amount or address in this payment is visible to everyone." :
            e->shield == SHIELD_FULL ? "Private" : "The node does not say whether every part of this payment was private.");
    amount_label(e, text, sizeof(text));
    (void)add(s, WALLET_ITEM_AMOUNT, WALLET_ACT_NONE, text);
    line(s, state_label(e->status));
    date_label(e, true, text, sizeof(text));
    line(s, text);
    line(s, "Transaction id");
    line(s, e->txid[0] ? e->txid : "unknown");
    if (e->memo_present) detail_memo_items(s, d);
    button(s, WALLET_ACT_BACK, "Back");
}

unsigned wallet_screens_snapshot(struct wallet_screen *out)
{
    unsigned version;
    pthread_mutex_lock(&st.lock);
    out->page = st.page;
    out->count = 0;
    if (st.blocked) {
        (void)add(out, WALLET_ITEM_TITLE, WALLET_ACT_NONE, "Wallet");
        char notice[WALLET_TEXT_MAX];
        snprintf(notice, sizeof(notice), "The wallet is not shown because this phone would not let the app %s.",
                 st.why[0] ? st.why : "protect the screen");
        note(out, notice);
        button(out, WALLET_ACT_BACK, "Home");
    } else if (st.page == WALLET_PAGE_FUNDS) funds_items(out);
    else if (st.page == WALLET_PAGE_RECEIVE) receive_items(out);
    else if (st.page == WALLET_PAGE_HISTORY) history_items(out);
    else if (st.page == WALLET_PAGE_DETAIL) detail_items(out);
    version = st.version;
    pthread_mutex_unlock(&st.lock);
    return version;
}

/* ---- replies ---- */

/* silent: the node did not answer at all, as opposed to answering with an error of its own. */
static void apply_summary(bool ok, bool silent, const char *json)
{
    st.d.funds_loaded = true;
    st.d.funds_fresh = true;
    st.d.node_silent = !ok && silent;
    st.d.summary_at = now();
    if (!ok || !json) json = "";
    (void)wallet_view_from_summary(json, &st.d.view);
}

enum how { HOW_INVALID, HOW_UNKNOWN, HOW_AGREES, HOW_AHEAD, HOW_APART };
/* The agreement a machine row names, by the words the node uses. A machine one or more blocks behind on this
 * chain agrees with it; one ahead of this node has not been compared and counts as neither agreeing nor apart. */
static enum how how_of(const char *how)
{
    if (is(how, "agrees") || is(how, "machine_behind")) return HOW_AGREES;
    if (is(how, "phone_behind")) return HOW_AHEAD;
    if (is(how, "disagree")) return HOW_APART;
    return is(how, "unknown") ? HOW_UNKNOWN : HOW_INVALID;
}
/* Counts the machines by agreement. False when they are not exactly the typed list: a machine that is not
 * connected is "unknown", and every agreement is one the node names. */
static bool count_machines(const struct json_value *list, int *connected, int *agrees, int *apart)
{
    *connected = *agrees = *apart = 0;
    for (size_t i = 0; i < json_size(list); ++i) {
        const struct json_value *m = json_at(list, i);
        const struct json_value *up = typed(m, "connected", JSON_BOOL);
        enum how how = how_of(text_of(m, "agreement"));
        if (!m || m->type != JSON_OBJ || !up || !typed(m, "name", JSON_STR) || how == HOW_INVALID) return false;
        if (!json_get_bool(up)) { if (how != HOW_UNKNOWN) return false; continue; }
        ++*connected;
        if (how == HOW_AGREES) ++*agrees;
        else if (how == HOW_APART) ++*apart;
    }
    return true;
}
/* Whether the reply is exactly the typed fleet status; the counts of machines are returned. */
static bool fleet_shape(const struct json_value *data, int *connected, int *agrees, int *apart)
{
    const struct json_value *list = typed(data, "machines", JSON_ARR), *total = typed(data, "machines_total", JSON_INT);
    const struct json_value *up = typed(data, "machines_connected", JSON_INT);
    if (!is(text_of(data, "schema"), "zcl.fleet_status.v1") || !list || !total || !up || !typed(data, "member", JSON_BOOL) ||
        !typed(data, "refuses_send", JSON_BOOL) || !text_of(data, "verdict") || !typed(data, "local_tip", JSON_INT) ||
        json_size(list) > MACHINES_MAX || json_get_int(total) != (int64_t)json_size(list) ||
        !count_machines(list, connected, agrees, apart) || json_get_int(up) != *connected) return false;
    return true;
}
/* The fleet line, or false when the reply is not exactly the typed shape and the fleet counts as not checked.
 * "Sending waits" is worded from the node's own refuses_send, and only a disagreement the machines show can
 * come with it; a verdict the machines do not bear out is not shown. */
static bool fleet_text(const struct json_value *data, char *out, size_t cap)
{
    int connected, agrees, apart;
    if (!fleet_shape(data, &connected, &agrees, &apart)) return false;
    const char *verdict = text_of(data, "verdict");
    bool member = json_get_bool(typed(data, "member", JSON_BOOL)), refuses = json_get_bool(typed(data, "refuses_send", JSON_BOOL));
    if (!member) return false;
    if (is(verdict, "agree") && agrees > 0 && apart == 0 && !refuses) {
        if (agrees == 1) copy(out, cap, "1 fleet machine agrees");
        else snprintf(out, cap, "%d fleet machines agree", agrees);
        return true;
    }
    if (is(verdict, "disagree") && apart > 0) {
        snprintf(out, cap, refuses ? "%d of %d fleet machines disagree: sending waits until they agree" :
                 "%d of %d fleet machines last reported another chain at a lower height: sending is not held back", apart, connected);
        return true;
    }
    return false;
}
static void apply_fleet(bool ok, const char *json)
{
    struct json_value root;
    const struct json_value *data;
    json_init(&root);
    st.d.fleet_loaded = st.d.fleet_fresh = true;
    st.d.fleet_at = now();
    if (!(ok && json && json_read(&root, json, strlen(json)) && (data = data_of(&root)) && fleet_text(data, st.d.fleet, sizeof(st.d.fleet))))
        copy(st.d.fleet, sizeof(st.d.fleet), WALLET_FLEET_UNCHECKED);
    drop_tree(&root);
}

/* The network whose private address this is, or false for anything else, a public address included. */
static bool private_network(const char *address, enum zapp_pay_network *network)
{
    struct zapp_payment parsed;
    for (int n = ZAPP_PAY_MAINNET; n <= ZAPP_PAY_REGTEST; ++n) {
        if (zapp_payment_parse(address, strlen(address), (enum zapp_pay_network)n, &parsed) == ZAPP_PAY_OK && parsed.kind == ZAPP_PAY_PRIVATE) {
            *network = (enum zapp_pay_network)n;
            return true;
        }
    }
    return false;
}
/* The code for the address and amount, kept only when the parser reads it back as the same payment. */
static void rebuild_code(void)
{
    struct zapp_payment got;
    struct data *d = &st.d;
    d->code[0] = '\0';
    if (zapp_payment_receive_code(d->address, d->has_amount, d->amount_zat, d->code, sizeof(d->code)) &&
        zapp_payment_parse(d->code, strlen(d->code), d->network, &got) == ZAPP_PAY_OK && !strcmp(got.address, d->address) &&
        got.has_amount == d->has_amount && (!d->has_amount || got.amount_zat == d->amount_zat)) return;
    memory_cleanse(d->address, sizeof(d->address));
    memory_cleanse(d->code, sizeof(d->code));
    copy(d->note, sizeof(d->note), "A code could not be made for this address. Tap New address.");
}

static void show_address(const char *address)
{
    st.d.note[0] = '\0';
    if (!private_network(address, &st.d.network)) copy(st.d.note, sizeof(st.d.note), "The wallet returned an address that is not private, so it is not shown. Tap New address.");
    else {
        copy(st.d.address, sizeof(st.d.address), address);
        rebuild_code();
    }
}
/* A reply that names an address: {"address":"zs1..."}. latest may answer null when the wallet has none. */
static void apply_address(bool ok, bool missing, bool latest, const char *json)
{
    struct json_value root;
    const struct json_value *data;
    const char *address = NULL;
    st.d.address_pending = false;
    json_init(&root);
    data = ok && json && json_read(&root, json, strlen(json)) ? data_of(&root) : NULL;
    address = text_of(data, "address");
    if (address && address[0] && strlen(address) < sizeof(st.d.address)) show_address(address);
    else if (data && latest && typed(data, "address", JSON_NULL)) copy(st.d.note, sizeof(st.d.note), "This wallet has no receive address yet. Tap New address.");
    else if (latest && missing) copy(st.d.note, sizeof(st.d.note), "This node cannot report its latest address yet. Tap New address to make one.");
    else if (latest) copy(st.d.note, sizeof(st.d.note), "The latest address could not be read. Check that your node is running, or tap New address.");
    else if (missing) {
        st.d.no_receive = true;
        copy(st.d.note, sizeof(st.d.note), "This build cannot make a new address.");
    } else copy(st.d.note, sizeof(st.d.note), "No address was made. Check that your node is running.");
    drop_tree(&root);
}

static enum direction read_direction(const char *text)
{
    return is(text, "sent") ? DIR_SENT : is(text, "received") ? DIR_RECEIVED : is(text, "internal") ? DIR_INTERNAL : DIR_UNKNOWN;
}
static void read_entry(const struct json_value *row, struct entry *e)
{
    const struct json_value *amount = typed(row, "amount_zat", JSON_INT), *time = typed(row, "time", JSON_INT);
    const struct json_value *memo = typed(row, "memo_present", JSON_BOOL), *shielded = typed(row, "fully_shielded", JSON_BOOL);
    const char *status = text_of(row, "status"), *txid = text_of(row, "txid");
    memset(e, 0, sizeof(*e));
    e->direction = read_direction(text_of(row, "direction"));
    e->status = is(status, "confirmed") ? STATUS_CONFIRMED : is(status, "pending") ? STATUS_PENDING : STATUS_UNKNOWN;
    if (amount && json_get_int(amount) >= 0 && (uint64_t)json_get_int(amount) <= ZAPP_PAY_MAX_ZAT) {
        e->amount_known = true;
        e->amount_zat = (uint64_t)json_get_int(amount);
    }
    if (time && json_get_int(time) > 0 && json_get_int(time) <= MAX_UNIX) {
        e->time_known = true;
        e->time = json_get_int(time);
    }
    if (wallet_txid_valid(txid)) copy(e->txid, sizeof(e->txid), txid);
    e->memo_present = memo && json_get_bool(memo);
    e->shield = !shielded ? SHIELD_UNKNOWN : json_get_bool(shielded) ? SHIELD_FULL : SHIELD_PART;
}
/* Reads the page. False when the reply is not exactly the typed frame, which is an error and not an empty wallet. */
static enum history_state read_history_state(const struct json_value *data)
{
    const char *state = text_of(data, "shielded_state");
    return is(state, "ok") ? HIST_OK : is(state, "keys_unavailable") ? HIST_HIDDEN : HIST_UNSAID;
}
static bool read_page(const struct json_value *data)
{
    const struct json_value *entries = typed(data, "entries", JSON_ARR), *count = typed(data, "count", JSON_INT);
    const struct json_value *next = json_get(data, "next_cursor");
    if (!is(text_of(data, "schema"), "zcl.wallet_history.v1") || !entries || !count || !next ||
        json_get_int(count) != (int64_t)json_size(entries) || json_size(entries) > WALLET_PAGE_ROWS) return false;
    if (next->type != JSON_NULL && !(next->type == JSON_STR && wallet_cursor_valid(json_get_str(next)))) return false;
    for (size_t i = 0; i < json_size(entries); ++i) if (json_at(entries, i)->type != JSON_OBJ) return false;
    for (size_t i = 0; i < json_size(entries); ++i) read_entry(json_at(entries, i), &st.d.entry[i]);
    st.d.history_state = read_history_state(data);
    st.d.rows = json_size(entries);
    st.d.has_more = next->type == JSON_STR;
    if (st.d.has_more) copy(st.d.next, sizeof(st.d.next), json_get_str(next));
    return true;
}
static void apply_history(bool ok, const char *json)
{
    struct json_value root;
    const struct json_value *data;
    st.d.history_pending = false;
    st.d.history_state = HIST_UNSAID;
    st.d.rows = 0;
    st.d.has_more = false;
    json_init(&root);
    data = ok && json && json_read(&root, json, strlen(json)) ? data_of(&root) : NULL;
    st.d.history_failed = !data || !read_page(data);
    if (st.d.history_failed) { st.d.rows = 0; st.d.has_more = false; }
    drop_tree(&root);
}

enum memo_read { MEMO_NONE, MEMO_OK, MEMO_BAD };
/* The memo of a detail: text, or hexadecimal when it is not text. Neither member is no memo; both, or one
 * that is of another type or not hexadecimal, is a memo that cannot be read. */
static enum memo_read memo_from(const struct json_value *entry)
{
    const char *text = text_of(entry, "memo"), *hex = text_of(entry, "memo_hex");
    size_t n, limit;
    if (!json_get(entry, "memo") && !json_get(entry, "memo_hex")) return MEMO_NONE;
    if (text && !hex) n = strlen(text);
    else if (hex && !text) {
        n = strlen(hex);
        if (n % 2 || !wallet_hex_valid(hex, n)) return MEMO_BAD;
    } else return MEMO_BAD;
    st.d.memo_hex = hex != NULL;
    limit = st.d.memo_hex ? 1024u : 512u;
    st.d.memo_over = n > limit;
    snprintf(st.d.memo, sizeof(st.d.memo), "%.*s", (int)(n < limit ? n : limit), text ? text : hex);
    return MEMO_OK;
}
static void apply_detail(bool ok, const char *json)
{
    struct json_value root;
    const struct json_value *data, *entry;
    const struct entry *row = &st.d.entry[st.d.detail < st.d.rows ? st.d.detail : 0];
    st.d.detail_pending = false;
    json_init(&root);
    data = ok && json && json_read(&root, json, strlen(json)) ? data_of(&root) : NULL;
    entry = typed(data, "entry", JSON_OBJ);
    enum memo_read memo = MEMO_NONE;
    st.d.detail_failed = !entry || !is(text_of(data, "schema"), "zcl.wallet_history.v1") || !is(text_of(entry, "txid"), row->txid);
    if (!st.d.detail_failed) memo = memo_from(entry);
    st.d.detail_failed = st.d.detail_failed || memo == MEMO_BAD;
    st.d.memo_loaded = memo == MEMO_OK;
    drop_tree(&root);
}

/* ---- commands ---- */

struct reply { bool ok, missing, silent; const char *json; };

static void apply(const struct job *j, const struct reply *r)
{
    if (!strcmp(j->op, "summary")) apply_summary(r->ok, r->silent, r->json);
    else if (!strcmp(j->op, "fleet")) apply_fleet(r->ok, r->json);
    else if (!strcmp(j->op, "history")) apply_history(r->ok, r->json);
    else if (!strcmp(j->op, "detail")) apply_detail(r->ok, r->json);
    else apply_address(r->ok, r->missing, !strcmp(j->op, "latest"), r->json);
}

static void finish(const struct job *j, const struct reply *r)
{
    bool live;
    pthread_mutex_lock(&st.lock);
    live = st.ready && j->epoch == st.epoch;
    if (live) { apply(j, r); touch(); }
    pthread_mutex_unlock(&st.lock);
    if (live && j->env.changed) j->env.changed(j->env.ctx);
}

static void run_job(const struct job *j)
{
    char *out = calloc(1, OUT_CAP);
    struct reply r = {0};
    r.ok = out && j->env.run && j->env.run(j->env.ctx, j->op, j->arg, out, OUT_CAP);
    r.missing = out && !r.ok && strstr(out, "UNKNOWN_COMMAND");
    r.silent = out && !r.ok && (strstr(out, "NODE_UNAVAILABLE") || strstr(out, "The command timed out."));
    r.json = json_start(out ? out : "");
    finish(j, &r);
    if (out) memory_cleanse(out, OUT_CAP);
    free(out);
}
static void *job_main(void *opaque)
{
    struct job *j = opaque;
    for (;;) {
        run_job(j);
        pthread_mutex_lock(&st.lock);
        struct flight *f = &st.flight[j->kind];
        if (f->queued) {
            *j = f->next;
            f->queued = false;
            memory_cleanse(&f->next, sizeof(f->next));
            pthread_mutex_unlock(&st.lock);
            continue;
        }
        f->running = false;
        pthread_mutex_unlock(&st.lock);
        break;
    }
    memory_cleanse(j, sizeof(*j));
    free(j);
    return NULL;
}
/* Starts the workers submit asked for. */
static void dispatch(struct job *jobs, size_t count)
{
    static const struct reply failed = {0};
    for (size_t i = 0; i < count; ++i) {
        struct job *heap = jobs[i].env.async ? malloc(sizeof(*heap)) : NULL;
        pthread_t thread;
        if (!jobs[i].env.async) { run_job(&jobs[i]); continue; }
        if (heap) {
            *heap = jobs[i];
            if (pthread_create(&thread, NULL, job_main, heap) == 0) { pthread_detach(thread); continue; }
            memory_cleanse(heap, sizeof(*heap));
            free(heap);
        }
        finish(&jobs[i], &failed);
        pthread_mutex_lock(&st.lock);
        st.flight[jobs[i].kind].running = false;
        pthread_mutex_unlock(&st.lock);
    }
    memory_cleanse(jobs, count * sizeof(*jobs));
}
/* Caller holds the lock. Asks for a command: one that is running keeps going and the newest request waits
 * behind it; a request that creates an address is refused while one is being made. False when refused. */
static bool submit(struct job *jobs, size_t *count, enum kind kind, const char *op, const char *arg)
{
    struct job j;
    memset(&j, 0, sizeof(j));
    j.env = st.env;
    copy(j.op, sizeof(j.op), op);
    copy(j.arg, sizeof(j.arg), arg);
    j.epoch = st.epoch;
    j.kind = kind;
    struct flight *f = &st.flight[kind];
    bool sync = !st.env.async, refused = !sync && f->running && kind == K_NEW;
    if (!refused && !sync && f->running) { f->next = j; f->queued = true; }
    else if (!refused) { f->running = !sync; jobs[(*count)++] = j; }
    memory_cleanse(&j, sizeof(j));
    return !refused;
}

/* ---- navigation ---- */

static void wipe(void) { memory_cleanse(&st.d, sizeof(st.d)); }
static void drop_queued(void)
{
    for (int k = 0; k < K_COUNT; ++k) { st.flight[k].queued = false; memory_cleanse(&st.flight[k].next, sizeof(st.flight[k].next)); }
}
/* Caller holds the lock. Replaces the screen and starts the commands it needs. */
static size_t enter(enum wallet_page page, struct job *jobs)
{
    size_t count = 0;
    st.dropped = 0;
    bool keep_amount = page == WALLET_PAGE_RECEIVE && st.page == WALLET_PAGE_RECEIVE && st.d.has_amount;
    uint64_t amount = st.d.amount_zat;
    wipe();
    ++st.epoch;
    st.page = page;
    if (keep_amount) { st.d.has_amount = true; st.d.amount_zat = amount; }
    if (page == WALLET_PAGE_FUNDS) {
        st.d.requested_at = now();
        (void)submit(jobs, &count, K_SUMMARY, "summary", "");
        (void)submit(jobs, &count, K_FLEET, "fleet", "");
    }
    if (page == WALLET_PAGE_RECEIVE) { st.d.address_pending = true; (void)submit(jobs, &count, K_LATEST, "latest", ""); }
    if (page == WALLET_PAGE_HISTORY) {
        st.d.history_pending = true;
        (void)submit(jobs, &count, K_HISTORY, "history", "");
        (void)submit(jobs, &count, K_SUMMARY, "summary", "");
    }
    touch();
    return count;
}

bool wallet_screens_init(const struct wallet_env *env)
{
    if (!env || !env->secure || !env->run || !env->now_ms) return false;
    pthread_mutex_lock(&st.lock);
    memset(&st.d, 0, sizeof(st.d));
    drop_queued();
    st.env = *env;
    st.ready = true; st.secure = false; st.blocked = false;
    st.page = WALLET_PAGE_NONE;
    ++st.epoch; touch();
    pthread_mutex_unlock(&st.lock);
    return true;
}

static void leave_locked(bool keep_protection)
{
    st.held = keep_protection && st.secure;
    st.held_at = st.held ? now() : 0;
    st.held_ticks = 0;
    ++st.epoch;
    wipe();
    drop_queued();
    st.page = WALLET_PAGE_NONE;
    st.blocked = false;
    if (st.secure && !keep_protection) (void)st.env.secure(st.env.ctx, false);
    if (!keep_protection) st.secure = false;
    touch();
}
void wallet_screens_close(void)
{
    pthread_mutex_lock(&st.lock);
    if (st.ready) leave_locked(false);
    pthread_mutex_unlock(&st.lock);
}
void wallet_screens_pause(void)
{
    pthread_mutex_lock(&st.lock);
    if (st.ready) leave_locked(true);
    pthread_mutex_unlock(&st.lock);
}
void wallet_screens_shutdown(void)
{
    pthread_mutex_lock(&st.lock);
    if (st.ready) leave_locked(false);
    st.ready = false;
    memset(&st.env, 0, sizeof(st.env));
    pthread_mutex_unlock(&st.lock);
}

bool wallet_screens_open(enum wallet_page page)
{
    struct job jobs[2];
    size_t count = 0;
    pthread_mutex_lock(&st.lock);
    if (!st.ready || page == WALLET_PAGE_NONE) { pthread_mutex_unlock(&st.lock); return false; }
    if (!st.secure) {
        st.secure = st.env.secure(st.env.ctx, true);
        st.blocked = !st.secure;
        st.why[0] = '\0';
        if (st.blocked && st.env.refusal) {
            const char *words = st.env.refusal(st.env.ctx);
            if (words) copy(st.why, sizeof(st.why), words);
        }
        if (st.blocked) (void)st.env.secure(st.env.ctx, false);
    }
    if (st.blocked) { ++st.epoch; wipe(); st.page = page; touch(); }
    else count = enter(page, jobs);
    bool shown = !st.blocked;
    pthread_mutex_unlock(&st.lock);
    dispatch(jobs, count);
    return shown;
}

bool wallet_screens_back(void)
{
    struct job jobs[2];
    size_t count = 0;
    bool moved = true;
    pthread_mutex_lock(&st.lock);
    if (!st.ready || st.blocked || st.page == WALLET_PAGE_NONE || st.page == WALLET_PAGE_FUNDS) moved = false;
    else if (st.page == WALLET_PAGE_DETAIL) {
        ++st.epoch;
        st.page = WALLET_PAGE_HISTORY;
        st.d.detail_pending = st.d.detail_failed = st.d.memo_loaded = st.d.memo_hex = st.d.memo_over = false;
        memory_cleanse(st.d.memo, sizeof(st.d.memo));
        touch();
    } else count = enter(WALLET_PAGE_FUNDS, jobs);
    pthread_mutex_unlock(&st.lock);
    dispatch(jobs, count);
    return moved;
}

/* Caller holds the lock. Shows the history page whose cursor is stored, and asks for it. */
static size_t history_page(unsigned page, struct job *jobs)
{
    size_t count = 0;
    ++st.epoch;
    st.d.page = page;
    st.d.history_pending = true;
    st.d.history_failed = false;
    st.d.rows = 0;
    st.d.has_more = false;
    memory_cleanse(st.d.entry, sizeof(st.d.entry));
    (void)submit(jobs, &count, K_HISTORY, "history", st.d.cursor[page]);
    touch();
    return count;
}
static size_t older(struct job *jobs)
{
    copy(st.d.cursor[st.d.page + 1], sizeof(st.d.cursor[0]), st.d.next);
    return history_page(st.d.page + 1, jobs);
}
static size_t open_detail(unsigned row, struct job *jobs)
{
    size_t count = 0;
    st.d.detail = row;
    st.page = WALLET_PAGE_DETAIL;
    st.d.detail_pending = st.d.entry[row].memo_present && st.d.entry[row].txid[0];
    st.d.detail_failed = st.d.entry[row].memo_present && !st.d.entry[row].txid[0];
    if (st.d.detail_pending) (void)submit(jobs, &count, K_DETAIL, "detail", st.d.entry[row].txid);
    touch();
    return count;
}
/* New address: drops the shown one and asks for a fresh one, unless one is already being made. */
static size_t new_address(struct job *jobs)
{
    size_t count = 0;
    if (st.d.no_receive) return 0;
    ++st.epoch;
    if (!submit(jobs, &count, K_NEW, "receive", "")) { --st.epoch; return 0; }
    memory_cleanse(st.d.address, sizeof(st.d.address));
    memory_cleanse(st.d.code, sizeof(st.d.code));
    st.d.note[0] = '\0';
    st.d.address_pending = true;
    touch();
    return count;
}

/* Copy address: the clipboard gets the bare address, never the grouped text. The reply is a note on the screen. */
static void copy_address(void)
{
    char address[ZAPP_PAY_ADDRESS_MAX];
    if (!st.d.address[0]) return;
    copy(address, sizeof(address), st.d.address);
    bool ok = st.env.copy_address && st.env.copy_address(st.env.ctx, address);
    memory_cleanse(address, sizeof(address));
    copy(st.d.note, sizeof(st.d.note), ok ? WALLET_COPIED_NOTE : WALLET_COPY_FAILED_NOTE);
    touch();
}

/* The jobs a tap on the Funds page starts, or WALLET_SEND for Send. */
static size_t from_funds(enum wallet_action action, struct job *jobs, enum wallet_outcome *outcome)
{
    if (action == WALLET_ACT_RECEIVE) return enter(WALLET_PAGE_RECEIVE, jobs);
    if (action == WALLET_ACT_HISTORY) return enter(WALLET_PAGE_HISTORY, jobs);
    if (action == WALLET_ACT_SEND) *outcome = WALLET_SEND;
    if (action == WALLET_ACT_START_NODE) *outcome = WALLET_START_NODE;
    return 0;
}
/* The jobs a tap on the History page starts. */
static size_t from_history(enum wallet_action action, unsigned arg, struct job *jobs)
{
    if (action == WALLET_ACT_OLDER && st.d.has_more && st.d.page + 1 < PAGES_MAX) return older(jobs);
    if (action == WALLET_ACT_NEWER && st.d.page) return history_page(st.d.page - 1, jobs);
    if (action == WALLET_ACT_DETAIL && arg < st.d.rows) return open_detail(arg, jobs);
    return 0;
}

enum wallet_outcome wallet_screens_activate(enum wallet_action action, unsigned arg)
{
    struct job jobs[2];
    size_t count = 0;
    enum wallet_outcome outcome = WALLET_STAY;
    pthread_mutex_lock(&st.lock);
    if (st.dropped && action != WALLET_ACT_BACK) { st.dropped = 0; touch(); }
    if (st.ready && !st.blocked) {
        if (st.page == WALLET_PAGE_FUNDS) count = from_funds(action, jobs, &outcome);
        else if (st.page == WALLET_PAGE_RECEIVE && action == WALLET_ACT_NEW_ADDRESS) count = new_address(jobs);
        else if (st.page == WALLET_PAGE_RECEIVE && action == WALLET_ACT_COPY_ADDRESS) copy_address();
        else if (st.page == WALLET_PAGE_HISTORY) count = from_history(action, arg, jobs);
    }
    pthread_mutex_unlock(&st.lock);
    dispatch(jobs, count);
    if (action == WALLET_ACT_BACK && !wallet_screens_back()) outcome = WALLET_LEAVE;
    return outcome;
}

bool wallet_screens_set_amount(const char *text)
{
    uint64_t zat = 0;
    bool ok = false, blank = true;
    pthread_mutex_lock(&st.lock);
    for (const char *c = text ? text : ""; *c; ++c) if (*c != ' ') blank = false;
    if (st.ready && !st.blocked && st.page == WALLET_PAGE_RECEIVE && text) {
        st.dropped = 0;
        st.d.note[0] = '\0';
        if (blank) { st.d.has_amount = false; ok = true; }
        else if (zapp_zat_parse(text, &zat) && zat > 0) { st.d.has_amount = true; st.d.amount_zat = zat; ok = true; }
        else copy(st.d.note, sizeof(st.d.note), "Enter an amount above zero in ZCL, with up to 8 decimals.");
        if (ok && st.d.address[0]) rebuild_code();
        touch();
    }
    pthread_mutex_unlock(&st.lock);
    return ok;
}

void wallet_screens_scan_notice(const char *text)
{
    pthread_mutex_lock(&st.lock);
    if (st.ready && !st.blocked && st.page == WALLET_PAGE_FUNDS && text) {
        copy(st.d.scan_note, sizeof(st.d.scan_note), text);
        touch();
    }
    pthread_mutex_unlock(&st.lock);
}

void wallet_screens_dropped(unsigned taps)
{
    pthread_mutex_lock(&st.lock);
    if (st.ready && !st.blocked && taps && st.dropped < 1000u) { st.dropped += taps; touch(); }
    pthread_mutex_unlock(&st.lock);
}

void wallet_screens_tick(void)
{
    struct job jobs[2];
    size_t count = 0;
    pthread_mutex_lock(&st.lock);
    if (st.ready && !st.blocked && st.page == WALLET_PAGE_FUNDS) {
        uint64_t t = now();
        bool funds = st.d.funds_loaded && t - st.d.summary_at <= WALLET_STALE_MS;
        bool fleet = st.d.fleet_loaded && t - st.d.fleet_at <= WALLET_STALE_MS;
        if (funds != st.d.funds_fresh || fleet != st.d.fleet_fresh) { st.d.funds_fresh = funds; st.d.fleet_fresh = fleet; touch(); }
        if (t - st.d.requested_at >= WALLET_REFRESH_MS) {
            st.d.requested_at = t;
            (void)submit(jobs, &count, K_SUMMARY, "summary", "");
            (void)submit(jobs, &count, K_FLEET, "fleet", "");
        }
    }
    pthread_mutex_unlock(&st.lock);
    dispatch(jobs, count);
}

/* The caller has drawn a screen without wallet data since the pause. */
void wallet_screens_settle(void)
{
    pthread_mutex_lock(&st.lock);
    if (st.ready && st.held && st.page == WALLET_PAGE_NONE) {
        if (st.held_ticks < WALLET_SETTLE_TICKS) ++st.held_ticks;
        if (st.held_ticks >= WALLET_SETTLE_TICKS && now() - st.held_at >= WALLET_SETTLE_MS) leave_locked(false);
    }
    pthread_mutex_unlock(&st.lock);
}

bool wallet_screens_active(void)
{
    pthread_mutex_lock(&st.lock);
    bool active = st.ready && st.page != WALLET_PAGE_NONE;
    pthread_mutex_unlock(&st.lock);
    return active;
}

bool wallet_screens_residue(const void *bytes, size_t len)
{
    const unsigned char *all = (const unsigned char *)&st, *want = bytes;
    bool found = false;
    pthread_mutex_lock(&st.lock);
    for (size_t i = 0; len && !found && i + len <= sizeof(st); ++i) found = !memcmp(all + i, want, len);
    pthread_mutex_unlock(&st.lock);
    return found;
}
