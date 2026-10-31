/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "wallet_view.h"
#include "json/json.h"
#include <stdio.h>
#include <string.h>

#define WALLET_VIEW_SCHEMA "zcl.wallet_summary.v1"
#define WALLET_VIEW_ZAT_PER_ZCL 100000000LL
#define WALLET_VIEW_MAX_ZAT 2100000000000000LL /* 21000000 ZCL: no amount above this is real */
#define WALLET_VIEW_ADDRESS_MAX 256
#define WALLET_VIEW_GROUP 4

#define TEXT_BALANCE_UNKNOWN "Balance unknown"
#define TEXT_PENDING_UNKNOWN "Pending amount unknown"
#define TEXT_PUBLIC_UNKNOWN "Public amount unknown"
#define TEXT_SYNC_UNKNOWN "Sync state unknown"
#define TEXT_SEND_UNAVAILABLE "Sending is unavailable until the wallet state loads."
#define TEXT_SEND_RELEASE "Sending is paused until this node verifies the chain tip itself."
#define TEXT_SEND_STORE "Sending is paused because this node's progress store is not open."
#define TEXT_SEND_UNKNOWN "Sending is paused for a reason this app does not recognize."

/* The fields of a well-formed reply. Every one is validated before any line is rendered. The
 * reason points into the parsed tree, so the summary is rendered before that tree is freed. */
struct summary {
    int64_t spendable;
    int64_t pending;
    int64_t pending_notes;
    int64_t pending_confirmations;
    int64_t public_zat;
    int64_t tip;
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

/* The same amount with trailing zeros dropped: 50000000 reads "0.5", 100000000 reads "1". */
static bool format_short(int64_t zat, char *out, size_t cap)
{
    char full[32];
    if (!format_full(zat, full, sizeof(full))) return false;
    char *dot = strchr(full, '.');
    char *end = full + strlen(full);
    while (end > dot + 1 && end[-1] == '0') *--end = '\0';
    if (end == dot + 1) *dot = '\0';
    put(out, cap, full);
    return true;
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

static bool parse_amounts(const struct json_value *data, struct summary *s)
{
    int64_t immature = 0;
    return read_zat(data, "spendable_zat", "spendable", &s->spendable) &&
           read_zat(data, "pending_zat", "pending", &s->pending) &&
           read_zat(data, "public_zat", "public", &s->public_zat) &&
           read_zat(data, "immature_zat", "immature", &immature);
}

static bool parse_pending(const struct json_value *data, struct summary *s)
{
    return read_count(data, "pending_notes", &s->pending_notes) &&
           read_count(data, "pending_min_confirmations_needed", &s->pending_confirmations);
}

static bool parse_chain(const struct json_value *data, struct summary *s)
{
    int64_t header = 0, scanned = 0;
    return read_int(data, "tip_height", &s->tip) && read_int(data, "header_height", &header) &&
           read_int(data, "scanned_through_height", &scanned) &&
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
           !strcmp(json_get_str(schema), WALLET_VIEW_SCHEMA) && parse_amounts(data, s) &&
           parse_pending(data, s) && parse_chain(data, s) && parse_keystore(data) &&
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
    put(out->sync, sizeof(out->sync), TEXT_SYNC_UNKNOWN);
    put(out->send, sizeof(out->send), TEXT_SEND_UNAVAILABLE);
}

static void render_balance(const struct summary *s, struct wallet_view *out)
{
    char amount[32];
    if (!format_full(s->spendable, amount, sizeof(amount))) return;
    snprintf(out->balance, sizeof(out->balance), "%s ZCL", amount);
}

static void render_pending(const struct summary *s, struct wallet_view *out)
{
    char amount[32];
    out->pending[0] = '\0';
    if (s->pending == 0 || !format_short(s->pending, amount, sizeof(amount))) return;
    if (s->pending_notes > 0 && s->pending_confirmations > 0)
        snprintf(out->pending, sizeof(out->pending), "%s ZCL arriving, %lld more confirmation%s",
                 amount, (long long)s->pending_confirmations,
                 s->pending_confirmations == 1 ? "" : "s");
    else
        snprintf(out->pending, sizeof(out->pending), "%s ZCL arriving", amount);
}

static void render_public(const struct summary *s, struct wallet_view *out)
{
    char amount[32];
    out->public_line[0] = '\0';
    if (s->public_zat == 0 || !format_short(s->public_zat, amount, sizeof(amount))) return;
    snprintf(out->public_line, sizeof(out->public_line), "%s ZCL public", amount);
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
    render_public(s, out);
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
    json_free(&root);
    return ok;
}

static bool is_printable_address(const char *address, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (address[i] <= 0x20 || address[i] >= 0x7f) return false;
    return true;
}

bool wallet_view_group_address(const char *address, char *out, size_t cap)
{
    if (out && cap) out[0] = '\0';
    if (!address || !out || !cap) return false;
    size_t n = 0;
    while (n <= WALLET_VIEW_ADDRESS_MAX && address[n]) n++;
    if (n == 0 || n > WALLET_VIEW_ADDRESS_MAX || !is_printable_address(address, n)) return false;
    size_t spaces = (n - 1) / WALLET_VIEW_GROUP;
    if (n + spaces + 1 > cap) return false;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        if (i && i % WALLET_VIEW_GROUP == 0) out[o++] = ' ';
        out[o++] = address[i];
    }
    out[o] = '\0';
    return true;
}
