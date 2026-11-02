/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "wallet_view.h"
#include "json/json.h"
#include "payment_code.h"
#include <stdio.h>
#include <string.h>

#define WALLET_VIEW_SCHEMA "zcl.wallet_summary.v1"
#define WALLET_VIEW_ZAT_PER_ZCL 100000000LL
#define WALLET_VIEW_MAX_ZAT 2100000000000000LL /* 21000000 ZCL: no amount above this is real */
#define WALLET_VIEW_ADDRESS_MAX 256
#define WALLET_VIEW_GROUP 4
#define WALLET_VIEW_AMOUNT_MAX 18 /* "21000000.00000000", the longest amount read_zat admits, with its NUL */

#define TEXT_BALANCE_UNKNOWN "Balance unknown"
#define TEXT_PENDING_UNKNOWN "Pending amount unknown"
#define TEXT_PUBLIC_UNKNOWN "Public amount unknown"
#define TEXT_IMMATURE_UNKNOWN "Maturing amount unknown"
#define TEXT_UNREADY_UNKNOWN "Funds received but not spendable yet: amount unknown"
#define TEXT_HIDDEN "Your private balance is hidden because the wallet is locked"
#define TEXT_SYNC_UNKNOWN "Sync state unknown"
#define TEXT_SYNC_LOCKED "The wallet is locked, so private amounts are not shown"
#define TEXT_SEND_UNAVAILABLE "Sending is unavailable until the wallet state loads."
#define TEXT_SEND_RELEASE "Sending is paused until your phone has checked the latest blocks on its own."
#define TEXT_SEND_STORE "Sending is paused because the wallet cannot save its progress right now."
#define TEXT_SEND_UNKNOWN "Sending is paused for a reason this app does not recognize."

/* The fields of a well-formed reply. Every one is validated before any line is rendered. The
 * reason points into the parsed tree, so the summary is rendered before that tree is freed. */
/* How an optional amount arrived: not at all, as null (unreadable), as a valid amount, or malformed. */
enum presence { P_ABSENT, P_NULL, P_VALUE, P_BAD };

struct summary {
    bool hidden; /* shielded_state is keys_unavailable: no private amount is known */
    enum presence unready_state, total_state;
    int64_t unready;
    int64_t total;
    int64_t spendable;
    int64_t pending;
    int64_t pending_notes;
    int64_t pending_confirmations;
    int64_t public_zat;
    int64_t immature;
    int64_t tip;
    int64_t header;
    int64_t scanned;
    int64_t blocks_behind;
    bool current;
    bool send_allowed;
    const char *send_reason;
};

static void put(char *dst, size_t cap, const char *src)
{
    snprintf(dst, cap, "%s", src);
}

/* Exact eight-decimal form of a zatoshi amount, integer arithmetic only. */
static bool format_full(int64_t zat, char *out, size_t cap)
{
    if (zat < 0) return false;
    int n = snprintf(out, cap, "%lld.%08lld", (long long)(zat / WALLET_VIEW_ZAT_PER_ZCL),
                     (long long)(zat % WALLET_VIEW_ZAT_PER_ZCL));
    return n > 0 && (size_t)n < cap;
}

static bool read_int(const struct json_value *data, const char *key, int64_t *out)
{
    const struct json_value *v = json_get(data, key);
    if (!v || v->type != JSON_INT) return false;
    *out = json_get_int(v);
    return true;
}

static bool read_count(const struct json_value *data, const char *key, int64_t *out)
{
    return read_int(data, key, out) && *out >= 0;
}

static bool read_flag(const struct json_value *data, const char *key, bool *out)
{
    const struct json_value *v = json_get(data, key);
    if (!v || v->type != JSON_BOOL) return false;
    *out = json_get_bool(v);
    return true;
}

/* A zatoshi count at most 21000000 ZCL whose eight-decimal string must agree with it exactly. */
static bool read_zat(const struct json_value *data, const char *zat_key, const char *str_key,
                     int64_t *zat)
{
    char want[32];
    const struct json_value *str = json_get(data, str_key);
    if (!str || str->type != JSON_STR) return false;
    return read_count(data, zat_key, zat) && *zat <= WALLET_VIEW_MAX_ZAT &&
           format_full(*zat, want, sizeof(want)) && !strcmp(json_get_str(str), want);
}

/* An amount that may be missing or null: null is unreadable, missing is not reported, and anything else must be valid. */
static enum presence read_optional_zat(const struct json_value *data, const char *zat_key, const char *str_key,
                                       int64_t *zat)
{
    const struct json_value *z = json_get(data, zat_key), *str = json_get(data, str_key);
    if (!z && !str) return P_ABSENT;
    if (z && str && z->type == JSON_NULL && str->type == JSON_NULL) return P_NULL;
    return read_zat(data, zat_key, str_key, zat) ? P_VALUE : P_BAD;
}

/* shielded_state: "ok", or "keys_unavailable" when a locked wallet holds no viewing key. A node that does not say
 * has amounts that are checked one by one. */
static bool parse_state(const struct json_value *data, struct summary *s)
{
    const struct json_value *state = json_get(data, "shielded_state");
    s->hidden = false;
    if (!state) return true;
    if (state->type != JSON_STR) return false;
    s->hidden = !strcmp(json_get_str(state), "keys_unavailable");
    return s->hidden || !strcmp(json_get_str(state), "ok");
}

static bool parse_public(const struct json_value *data, struct summary *s)
{
    return read_zat(data, "public_zat", "public", &s->public_zat) &&
           read_zat(data, "immature_zat", "immature", &s->immature);
}

static bool parse_private(const struct json_value *data, struct summary *s)
{
    s->unready_state = read_optional_zat(data, "unready_zat", "unready", &s->unready);
    s->total_state = read_optional_zat(data, "spendable_total_zat", "spendable_total", &s->total);
    return read_zat(data, "spendable_zat", "spendable", &s->spendable) &&
           /* The node's spendable is the largest per-key sum, so it never exceeds the total. */
           !(s->total_state == P_VALUE && s->spendable > s->total) &&
           read_zat(data, "pending_zat", "pending", &s->pending) &&
           read_count(data, "pending_notes", &s->pending_notes) &&
           read_count(data, "pending_min_confirmations_needed", &s->pending_confirmations) &&
           s->unready_state != P_BAD && s->total_state != P_BAD;
}

static bool parse_amounts(const struct json_value *data, struct summary *s)
{
    return parse_public(data, s) && (s->hidden || parse_private(data, s));
}

/* The height the wallet has scanned to; null when it has scanned nothing it can name, which counts as behind. */
static bool read_scanned(const struct json_value *data, struct summary *s)
{
    const struct json_value *v = json_get(data, "scanned_through_height");
    if (v && v->type == JSON_NULL) { s->scanned = -1; return true; }
    return read_int(data, "scanned_through_height", &s->scanned);
}

static bool parse_chain(const struct json_value *data, struct summary *s)
{
    return read_int(data, "tip_height", &s->tip) && read_int(data, "header_height", &s->header) &&
           read_scanned(data, s) &&
           read_count(data, "blocks_behind", &s->blocks_behind) &&
           read_flag(data, "current", &s->current) && (!s->current || s->tip >= 0);
}

/* locked is read but not shown. send_allowed may be true while locked, because sending unlocks
 * after device authentication, so the send line follows send_allowed alone. */
static bool parse_keystore(const struct json_value *data)
{
    bool locked = false, encrypted = false;
    int64_t keys = 0;
    return read_flag(data, "locked", &locked) && read_flag(data, "encrypted", &encrypted) &&
           read_count(data, "shielded_keys", &keys);
}

static bool parse_send(const struct json_value *data, struct summary *s)
{
    const struct json_value *reason = json_get(data, "send_blocked_reason");
    if (!reason || reason->type != JSON_STR) return false;
    s->send_reason = json_get_str(reason);
    return read_flag(data, "send_allowed", &s->send_allowed);
}

static bool parse_summary(const struct json_value *data, struct summary *s)
{
    const struct json_value *schema = json_get(data, "schema");
    return schema && schema->type == JSON_STR &&
           !strcmp(json_get_str(schema), WALLET_VIEW_SCHEMA) && parse_state(data, s) && parse_amounts(data, s) &&
           parse_chain(data, s) && parse_keystore(data) &&
           parse_send(data, s);
}

static bool parse_reply(const struct json_value *root, struct summary *s)
{
    const struct json_value *ok = json_get(root, "ok");
    const struct json_value *data = json_get(root, "data");
    return ok && ok->type == JSON_BOOL && json_get_bool(ok) && data && data->type == JSON_OBJ &&
           parse_summary(data, s);
}

static void set_unknown(struct wallet_view *out)
{
    memset(out, 0, sizeof(*out));
    put(out->balance, sizeof(out->balance), TEXT_BALANCE_UNKNOWN);
    put(out->pending, sizeof(out->pending), TEXT_PENDING_UNKNOWN);
    put(out->public_line, sizeof(out->public_line), TEXT_PUBLIC_UNKNOWN);
    put(out->immature_line, sizeof(out->immature_line), TEXT_IMMATURE_UNKNOWN);
    put(out->unready_line, sizeof(out->unready_line), TEXT_UNREADY_UNKNOWN);
    put(out->sync, sizeof(out->sync), TEXT_SYNC_UNKNOWN);
    put(out->send, sizeof(out->send), TEXT_SEND_UNAVAILABLE);
}

/* An amount without trailing zeros, as every other amount on the screens is written. */
static bool amount_text(int64_t zat, char *out, size_t cap)
{
    return zat >= 0 && zapp_zat_format((uint64_t)zat, out, cap);
}

static void render_balance(const struct summary *s, struct wallet_view *out)
{
    char amount[32];
    if (s->hidden) { put(out->balance, sizeof(out->balance), TEXT_HIDDEN); return; }
    /* The headline is everything spendable, across all keys; spendable is what one payment can use. */
    bool whole = s->total_state == P_VALUE;
    if (!amount_text(whole ? s->total : s->spendable, amount, sizeof(amount))) return;
    snprintf(out->balance, sizeof(out->balance), "%s ZCL", amount);
}

/* pending_min_confirmations_needed is when the first pending note arrives, not the rest. A single note arrives
 * whole at that time, so only then is the whole amount said to arrive in it. */
static void render_pending(const struct summary *s, struct wallet_view *out)
{
    char amount[WALLET_VIEW_AMOUNT_MAX];
    out->pending[0] = '\0';
    if (s->hidden || s->pending == 0 || !zapp_zat_format((uint64_t)s->pending, amount, sizeof(amount))) return;
    const char *unit = s->pending_confirmations == 1 ? "" : "s";
    if (s->pending_notes == 1 && s->pending_confirmations > 0)
        snprintf(out->pending, sizeof(out->pending), "%s ZCL arriving in %lld confirmation%s", amount,
                 (long long)s->pending_confirmations, unit);
    else if (s->pending_notes > 1 && s->pending_confirmations > 0)
        snprintf(out->pending, sizeof(out->pending), "%s ZCL pending in %lld payments. The next arrives in %lld confirmation%s.",
                 amount, (long long)s->pending_notes, (long long)s->pending_confirmations, unit);
    else
        snprintf(out->pending, sizeof(out->pending), "%s ZCL pending", amount);
}

/* Confirmed funds that a send would refuse until the wallet catches up (a missing or stale witness), and the most one
 * payment can use when that is less than the total spendable. Unready funds are not added to the spendable amount. */
static void render_unready(const struct summary *s, struct wallet_view *out)
{
    char amount[32];
    out->unready_line[0] = '\0';
    out->total_line[0] = '\0';
    if (s->hidden) return;
    if (s->unready_state == P_NULL) put(out->unready_line, sizeof(out->unready_line), TEXT_UNREADY_UNKNOWN);
    else if (s->unready_state == P_VALUE && s->unready > 0 && amount_text(s->unready, amount, sizeof(amount)))
        snprintf(out->unready_line, sizeof(out->unready_line), "%s ZCL received, not spendable yet", amount);
    if (s->total_state == P_VALUE && s->total > s->spendable && amount_text(s->spendable, amount, sizeof(amount)))
        snprintf(out->total_line, sizeof(out->total_line), "You can send up to %s ZCL at once, fee included", amount);
}

static void render_immature(const struct summary *s, struct wallet_view *out)
{
    char amount[32];
    out->immature_line[0] = '\0';
    if (s->immature == 0 || !amount_text(s->immature, amount, sizeof(amount))) return;
    snprintf(out->immature_line, sizeof(out->immature_line), "%s ZCL of mined coins maturing, not yet spendable", amount);
}

static void render_public(const struct summary *s, struct wallet_view *out)
{
    char amount[32];
    out->public_line[0] = '\0';
    if (s->public_zat == 0 || !zapp_zat_format((uint64_t)s->public_zat, amount, sizeof(amount))) return;
    snprintf(out->public_line, sizeof(out->public_line), "%s ZCL public: visible to everyone, not part of the spendable amount", amount);
}

/* Up to date only at zero blocks behind. A gap of one or more blocks says so, whatever current
 * says, so a stale balance is never shown as confirmed. */
static void render_sync(const struct summary *s, struct wallet_view *out)
{
    if (s->blocks_behind > 1)
        snprintf(out->sync, sizeof(out->sync), "Catching up, %lld blocks behind: amounts may change",
                 (long long)s->blocks_behind);
    else if (s->blocks_behind == 1)
        put(out->sync, sizeof(out->sync), "Catching up, 1 block behind: amounts may change");
    else if (s->current)
        snprintf(out->sync, sizeof(out->sync), "Up to date at block %lld", (long long)s->tip);
    else if (s->hidden)
        put(out->sync, sizeof(out->sync), TEXT_SYNC_LOCKED);
    else
        put(out->sync, sizeof(out->sync), "Catching up: amounts may change");
}

/* The guard reports "release_assisted" alone or with a ": why" suffix. */
static bool is_release_assisted(const char *reason)
{
    size_t n = strlen("release_assisted");
    return !strncmp(reason, "release_assisted", n) && (reason[n] == '\0' || reason[n] == ':');
}

static const char *send_sentence(const char *reason)
{
    if (!strcmp(reason, "progress_store_unavailable")) return TEXT_SEND_STORE;
    if (is_release_assisted(reason)) return TEXT_SEND_RELEASE;
    return TEXT_SEND_UNKNOWN;
}

static void render_send(const struct summary *s, struct wallet_view *out)
{
    out->send[0] = '\0';
    if (!s->send_allowed) put(out->send, sizeof(out->send), send_sentence(s->send_reason));
}

static void render_known(const struct summary *s, struct wallet_view *out)
{
    out->known = true;
    render_balance(s, out);
    render_pending(s, out);
    render_unready(s, out);
    render_public(s, out);
    render_immature(s, out);
    out->scanning = s->blocks_behind > 0 || s->scanned < s->header;
    out->current = s->current;
    render_sync(s, out);
    render_send(s, out);
    out->send_allowed = s->send_allowed;
}

bool wallet_view_from_summary(const char *json, struct wallet_view *out)
{
    struct json_value root = {0};
    struct summary s = {0};
    if (!out) return false;
    set_unknown(out);
    if (!json || !json_read(&root, json, strlen(json))) return false;
    bool ok = parse_reply(&root, &s);
    if (ok) render_known(&s, out);
    json_cleanse_strings(&root);
    json_free(&root);
    return ok;
}

static bool is_printable_address(const char *address, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (address[i] <= 0x20 || address[i] >= 0x7f) return false;
    return true;
}

/* The length of the bech32 prefix with its separator ("zs1", "zregtestsapling1"), kept whole as the first group, or 0
 * when the address has none. The prefix is two or more lowercase letters, then the last '1'. */
static size_t prefix_length(const char *address, size_t n)
{
    size_t sep = 0;
    for (size_t i = 0; i < n; i++)
        if (address[i] == '1') sep = i;
    if (sep < 2 || sep + 1 >= n) return 0;
    for (size_t i = 0; i < sep; i++)
        if (address[i] < 'a' || address[i] > 'z') return 0;
    return sep + 1;
}

/* The length of address when it is a displayable address of at most WALLET_VIEW_ADDRESS_MAX bytes, otherwise 0. */
static size_t displayable_length(const char *address)
{
    size_t n = 0;
    while (n <= WALLET_VIEW_ADDRESS_MAX && address[n]) n++;
    return n > 0 && n <= WALLET_VIEW_ADDRESS_MAX && is_printable_address(address, n) ? n : 0;
}

bool wallet_view_group_address(const char *address, char *out, size_t cap)
{
    if (out && cap) out[0] = '\0';
    if (!address || !out || !cap) return false;
    size_t n = displayable_length(address);
    if (n == 0) return false;
    size_t head = prefix_length(address, n), rest = n - head;
    size_t spaces = (rest ? (rest - 1) / WALLET_VIEW_GROUP : 0) + (head && rest ? 1 : 0);
    if (n + spaces + 1 > cap) return false;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        if (i && i >= head && (i - head) % WALLET_VIEW_GROUP == 0) out[o++] = ' ';
        out[o++] = address[i];
    }
    out[o] = '\0';
    return true;
}
