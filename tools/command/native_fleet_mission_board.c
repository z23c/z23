/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: `fleet.mission.board`, a kanban for lead developers. It projects
 * three durable sources into seven columns and holds no state of its own:
 *   BACKLOG / BUILDING  the dev agent queue (queued / running rows)
 *   PROVING / LANDED / FAILED  the dev land queue and its outcomes
 *   CLAIMED / REVIEW  the steer outbox (bodies starting CLAIM / READY)
 * Read-only by construction: the queue and land readers resolve the existing
 * state root, create nothing and take no lock (land rewrites by atomic
 * rename, so a plain read sees a whole file). The steer outbox is read with
 * fopen("rb"), only its last 2 MiB and at most its last 4096 rows, and no
 * mail cursor is ever advanced. A bad row is skipped and counted. */

#include "command/native_command.h"

#include "base/safe_alloc.h"
#include "command/native_dev_land_read.h"
#include "command/native_devagent_queue_read.h"
#include "command/native_fleet.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MB_HOURS_DEFAULT 24
#define MB_HOURS_MAX 168
#define MB_LIMIT_DEFAULT 12
#define MB_LIMIT_MAX 32
#define MB_CARD_MAX 46
#define MB_TAIL_BYTES (2u * 1024u * 1024u)
#define MB_ROWS_MAX 4096u
#define MB_KEY_MAX 128
#define MB_BOX_W 30
#define MB_TEXT_W 26
#define MB_SCREEN_CAP (24u * 1024u)
#define MB_NO_STEER "steer bus not on this host"

enum mb_col_id {
    MB_BACKLOG, MB_CLAIMED, MB_BUILDING, MB_REVIEW, MB_PROVING, MB_LANDED,
    MB_FAILED, MB_COLS
};

static const char *const mb_names[MB_COLS] = {
    "BACKLOG", "CLAIMED", "BUILDING", "REVIEW", "PROVING", "LANDED", "FAILED"};

struct mb_col {
    size_t total, shown;
    char cards[MB_LIMIT_MAX][MB_CARD_MAX + 1];
};

struct mb_board {
    struct mb_col col[MB_COLS];
    long long now, window;
    size_t limit, skipped;
    bool steer_bus;
};

/* ── card text ─────────────────────────────────────────────────────────── */

/* One printable ASCII line of at most MB_CARD_MAX characters. */
static void mb_fit(char *out, const char *text)
{
    size_t n = strnlen(text, MB_CARD_MAX + 1);
    size_t keep = n > MB_CARD_MAX ? MB_CARD_MAX - 3 : n;
    for (size_t i = 0; i < keep; i++) {
        unsigned char c = (unsigned char)text[i];
        out[i] = (c >= 0x20 && c < 0x7f) ? (char)c : (c < 0x80 ? ' ' : '?');
    }
    if (n > MB_CARD_MAX)
        memcpy(out + keep, "...", 4);
    else
        out[keep] = '\0';
}

static void mb_add(struct mb_board *b, enum mb_col_id id, const char *text)
{
    struct mb_col *c = &b->col[id];
    c->total++;
    if (c->shown < b->limit)
        mb_fit(c->cards[c->shown++], text);
}

static void mb_age(char out[16], long long now, long long then)
{
    long long d = now - then;
    if (then <= 0)
        out[0] = '\0';
    else if (d < 60)
        (void)snprintf(out, 16, "%llds", d < 0 ? 0 : d);
    else if (d < 3600)
        (void)snprintf(out, 16, "%lldm", d / 60);
    else if (d < 172800)
        (void)snprintf(out, 16, "%lldh", d / 3600);
    else
        (void)snprintf(out, 16, "%lldd", d / 86400);
}

/* ── time ──────────────────────────────────────────────────────────────── */

static long long mb_days_from_civil(long long y, long long m, long long d)
{
    long long era, yoe, doy;
    y -= m <= 2 ? 1 : 0;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    return era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
}

static bool mb_ts_shape_ok(const char *ts)
{
    static const char pat[] = "dddd-dd-ddTdd:dd:ddZ";
    if (strlen(ts) != sizeof(pat) - 1)
        return false;
    for (size_t i = 0; pat[i]; i++) {
        bool ok = pat[i] == 'd' ? (ts[i] >= '0' && ts[i] <= '9')
                                : ts[i] == pat[i];
        if (!ok)
            return false;
    }
    return true;
}

static long long mb_num(const char *s, size_t n)
{
    long long v = 0;
    for (size_t i = 0; i < n; i++)
        v = v * 10 + (s[i] - '0');
    return v;
}

/* Unix seconds of "YYYY-MM-DDTHH:MM:SSZ", or 0 when it is anything else. */
static long long mb_ts_unix(const char *ts)
{
    long long mo, d;
    if (!ts || !mb_ts_shape_ok(ts))
        return 0;
    mo = mb_num(ts + 5, 2);
    d = mb_num(ts + 8, 2);
    if (mo < 1 || mo > 12 || d < 1 || d > 31)
        return 0;
    return mb_days_from_civil(mb_num(ts, 4), mo, d) * 86400 +
           mb_num(ts + 11, 2) * 3600 + mb_num(ts + 14, 2) * 60 +
           mb_num(ts + 17, 2);
}

static bool mb_in_window(const struct mb_board *b, long long t)
{
    return t > 0 && b->now - t <= b->window;
}

/* ── queue columns ─────────────────────────────────────────────────────── */

static void mb_card_queued(struct mb_board *b, const struct zcl_dvq_row_view *r)
{
    char age[16], text[256];
    mb_age(age, b->now, mb_ts_unix(r->ts));
    (void)snprintf(text, sizeof(text), "%s %s %s", r->name, r->kind, age);
    mb_add(b, MB_BACKLOG, text);
}

static void mb_card_running(struct mb_board *b, const struct zcl_dvq_row_view *r)
{
    char age[16], text[256];
    mb_age(age, b->now, r->started > 0 ? r->started : mb_ts_unix(r->ts));
    (void)snprintf(text, sizeof(text), "%s %s a%lld %s", r->name,
                   r->engine[0] ? r->engine : "-", r->attempt, age);
    mb_add(b, MB_BUILDING, text);
}

static void mb_fill_queue(struct mb_board *b)
{
    struct zcl_dvq_row_view *rows = NULL;
    size_t n = 0, skipped = 0;
    if (!zcl_devagent_queue_rows_read(&rows, &n, &skipped)) {
        mb_add(b, MB_BACKLOG, "queue unreadable");
        mb_add(b, MB_BUILDING, "queue unreadable");
        return;
    }
    b->skipped += skipped;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(rows[i].state, "queued") == 0)
            mb_card_queued(b, &rows[i]);
        else if (strcmp(rows[i].state, "running") == 0)
            mb_card_running(b, &rows[i]);
    }
    free(rows);
}

/* ── land columns ──────────────────────────────────────────────────────── */

static void mb_card_proving(struct mb_board *b, const struct zcl_dl_row_view *r)
{
    char text[256];
    if (strcmp(r->state, "inflight") == 0 && r->phase[0])
        (void)snprintf(text, sizeof(text), "#%lld %.8s run:%s", r->seq,
                       r->tip12, r->phase);
    else
        (void)snprintf(text, sizeof(text), "#%lld %.8s %s", r->seq, r->tip12,
                       r->state);
    mb_add(b, MB_PROVING, text);
}

static void mb_card_outcome(struct mb_board *b, const struct zcl_dl_row_view *r,
                            long long t)
{
    char age[16], text[256];
    mb_age(age, b->now, t);
    if (strcmp(r->state, "landed") == 0) {
        (void)snprintf(text, sizeof(text), "#%lld %.8s landed %s", r->seq,
                       r->tip12, age);
        mb_add(b, MB_LANDED, text);
    } else {
        (void)snprintf(text, sizeof(text), "#%lld %.8s %s %s", r->seq, r->tip12,
                       r->dimension[0] ? r->dimension : "?", age);
        mb_add(b, MB_FAILED, text);
    }
}

static void mb_fill_land(struct mb_board *b)
{
    struct zcl_dl_row_view *rows = NULL;
    size_t n = 0, skipped = 0;
    if (!zcl_dev_land_rows_read(&rows, &n, &skipped)) {
        mb_add(b, MB_PROVING, "land unreadable");
        return;
    }
    b->skipped += skipped;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(rows[i].state, "queued") == 0 ||
            strcmp(rows[i].state, "inflight") == 0)
            mb_card_proving(b, &rows[i]);
    }
    for (size_t i = n; i-- > 0;) { /* outcomes, newest first */
        long long t = rows[i].landed_at > 0 ? rows[i].landed_at : mb_ts_unix(rows[i].ts);
        bool done = strcmp(rows[i].state, "landed") == 0 ||
                    strcmp(rows[i].state, "failed") == 0;
        if (done && mb_in_window(b, t))
            mb_card_outcome(b, &rows[i], t);
    }
    free(rows);
}

/* ── steer columns (the outbox, read only) ─────────────────────────────── */

struct mb_tail {
    char *text;
    size_t len;
    bool present;
};

static bool mb_outbox_path(char *path, size_t cap)
{
    char root[4096];
    if (!platform_state_root_existing(root, sizeof(root)))
        return false;
    return snprintf(path, cap, "%s/mail/outbox.jsonl", root) < (int)cap;
}

/* The last MB_TAIL_BYTES of the file, minus a first line the cut split. */
static bool mb_tail_read(const char *path, struct mb_tail *t)
{
    FILE *f = fopen(path, "rb");
    long size;
    size_t start = 0, got, skip = 0;
    memset(t, 0, sizeof(*t));
    if (!f)
        return false;
    if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0) {
        (void)fclose(f);
        return false;
    }
    if ((size_t)size > MB_TAIL_BYTES)
        start = (size_t)size - MB_TAIL_BYTES;
    t->text = (char *)zcl_malloc(MB_TAIL_BYTES + 1, "fleet.mission.tail");
    if (!t->text || fseek(f, (long)start, SEEK_SET) != 0) {
        (void)fclose(f);
        return false;
    }
    got = fread(t->text, 1, MB_TAIL_BYTES, f);
    (void)fclose(f);
    t->text[got] = '\0';
    if (start > 0) {
        char *nl = memchr(t->text, '\n', got);
        skip = nl ? (size_t)(nl - t->text) + 1 : got;
    }
    memmove(t->text, t->text + skip, got - skip + 1);
    t->len = got - skip;
    t->present = true;
    return true;
}

/* NUL-terminate each line; keep pointers to the last MB_ROWS_MAX of them. */
static size_t mb_tail_lines(char *text, size_t len, char **ring)
{
    size_t count = 0;
    for (char *line = text; line < text + len;) {
        char *end = memchr(line, '\n', (size_t)(text + len - line));
        char *next = end ? end + 1 : text + len;
        if (end)
            *end = '\0';
        if (line[0])
            ring[count++ % MB_ROWS_MAX] = line;
        line = next;
    }
    return count;
}

static const char *mb_str(const struct json_value *doc, const char *key)
{
    const struct json_value *v = json_get(doc, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

struct mb_keys {
    char (*key)[MB_KEY_MAX];
    size_t n;
};

/* True when this (from, ref or first 48 body chars) was already seen. */
static bool mb_claim_seen(struct mb_keys *k, const char *from, const char *ref,
                          const char *body)
{
    char key[MB_KEY_MAX];
    if (ref[0])
        (void)snprintf(key, sizeof(key), "%.63s|%.63s", from, ref);
    else
        (void)snprintf(key, sizeof(key), "%.63s|%.48s", from, body);
    for (size_t i = 0; i < k->n; i++) {
        if (strcmp(k->key[i], key) == 0)
            return true;
    }
    if (k->n < MB_ROWS_MAX)
        memcpy(k->key[k->n++], key, sizeof(key));
    return false;
}

static void mb_steer_row(struct mb_board *b, struct mb_keys *k,
                         const struct json_value *doc)
{
    const char *body = mb_str(doc, "body"), *from = mb_str(doc, "from");
    char text[1024];
    if (!mb_in_window(b, mb_ts_unix(mb_str(doc, "ts"))))
        return;
    (void)snprintf(text, sizeof(text), "%.64s: %s", from[0] ? from : "?", body);
    if (strncmp(body, "READY", 5) == 0)
        mb_add(b, MB_REVIEW, text);
    else if (strncmp(body, "CLAIM", 5) == 0 &&
             !mb_claim_seen(k, from, mb_str(doc, "ref"), body))
        mb_add(b, MB_CLAIMED, text);
}

static void mb_steer_rows(struct mb_board *b, char **ring, size_t count)
{
    struct mb_keys k = {0};
    size_t use = count < MB_ROWS_MAX ? count : MB_ROWS_MAX;
    k.key = (char (*)[MB_KEY_MAX])zcl_malloc((size_t)MB_ROWS_MAX * MB_KEY_MAX,
                                             "fleet.mission.keys");
    if (!k.key) {
        b->skipped += use;
        return;
    }
    for (size_t i = 0; i < use; i++) { /* newest first */
        const char *line = ring[(count - 1 - i) % MB_ROWS_MAX];
        struct json_value doc;
        json_init(&doc);
        if (json_read(&doc, line, strlen(line)) && doc.type == JSON_OBJ &&
            json_get(&doc, "body"))
            mb_steer_row(b, &k, &doc);
        else
            b->skipped++;
        json_free(&doc);
    }
    free(k.key);
}

static void mb_fill_steer(struct mb_board *b)
{
    char path[4096 + 32];
    struct mb_tail t = {0};
    char **ring;
    if (!mb_outbox_path(path, sizeof(path)) || !mb_tail_read(path, &t)) {
        free(t.text);
        b->steer_bus = false;
        (void)snprintf(b->col[MB_CLAIMED].cards[0], MB_CARD_MAX + 1, "%s", MB_NO_STEER);
        (void)snprintf(b->col[MB_REVIEW].cards[0], MB_CARD_MAX + 1, "%s", MB_NO_STEER);
        b->col[MB_CLAIMED].shown = b->col[MB_REVIEW].shown = 1;
        return;
    }
    b->steer_bus = true;
    ring = (char **)zcl_malloc(MB_ROWS_MAX * sizeof(*ring), "fleet.mission.ring");
    if (ring) {
        size_t count = mb_tail_lines(t.text, t.len, ring);
        mb_steer_rows(b, ring, count);
    }
    free(ring);
    free(t.text);
}

/* ── screen ────────────────────────────────────────────────────────────── */

struct mb_sb {
    char *p;
    size_t len, cap;
    bool overflow;
};

static void mb_cat(struct mb_sb *s, const char *text)
{
    size_t n = strlen(text);
    if (s->len + n + 1 > s->cap) {
        s->overflow = true;
        return;
    }
    memcpy(s->p + s->len, text, n + 1);
    s->len += n;
}

static void mb_rule(struct mb_sb *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        mb_cat(s, "\xe2\x94\x80"); /* U+2500 */
}

static size_t mb_overflow(const struct mb_col *c)
{
    return c->total > c->shown ? c->total - c->shown : 0;
}

static size_t mb_body_lines(const struct mb_col *c)
{
    size_t n = c->shown + (mb_overflow(c) ? 1 : 0);
    return n ? n : 1;
}

static void mb_box_top(struct mb_sb *s, enum mb_col_id id, const struct mb_board *b)
{
    char title[48];
    int w = snprintf(title, sizeof(title), "%s %zu", mb_names[id],
                     b->col[id].total);
    mb_cat(s, "\xe2\x94\x8c\xe2\x94\x80 "); /* corner, rule, space */
    mb_cat(s, title);
    mb_cat(s, " ");
    mb_rule(s, (MB_BOX_W - 2) - (size_t)w - 3);
    mb_cat(s, "\xe2\x94\x90"); /* U+2510 */
}

/* The text of body line k of one column ("" past its end). */
static void mb_cell(char *out, const struct mb_col *c, size_t k)
{
    out[0] = '\0';
    if (k < c->shown)
        (void)snprintf(out, 64, "%s", c->cards[k]);
    else if (k == c->shown && mb_overflow(c))
        (void)snprintf(out, 64, "+%zu more", mb_overflow(c));
    else if (k == 0 && c->shown == 0)
        (void)snprintf(out, 64, "(none)");
    if (strlen(out) > MB_TEXT_W)
        memcpy(out + MB_TEXT_W - 3, "...", 4);
}

static void mb_box_line(struct mb_sb *s, const struct mb_col *c, size_t k)
{
    char cell[64], pad[MB_TEXT_W + 1];
    mb_cell(cell, c, k);
    (void)snprintf(pad, sizeof(pad), "%-*s", MB_TEXT_W, cell);
    mb_cat(s, "\xe2\x94\x82 "); /* U+2502 */
    mb_cat(s, pad);
    mb_cat(s, " \xe2\x94\x82");
}

static void mb_band(struct mb_sb *s, const struct mb_board *b, int first,
                    int last)
{
    size_t body = 1;
    for (int i = first; i <= last; i++)
        if (mb_body_lines(&b->col[i]) > body)
            body = mb_body_lines(&b->col[i]);
    for (int i = first; i <= last; i++)
        mb_box_top(s, (enum mb_col_id)i, b);
    mb_cat(s, "\n");
    for (size_t k = 0; k < body; k++) {
        for (int i = first; i <= last; i++)
            mb_box_line(s, &b->col[i], k);
        mb_cat(s, "\n");
    }
    for (int i = first; i <= last; i++) {
        mb_cat(s, "\xe2\x94\x94"); /* U+2514 */
        mb_rule(s, MB_BOX_W - 2);
        mb_cat(s, "\xe2\x94\x98"); /* U+2518 */
    }
    mb_cat(s, "\n");
}

static void mb_header(struct mb_sb *s, const struct mb_board *b, long long hours)
{
    char line[256];
    (void)snprintf(line, sizeof(line),
                   "FLEET MISSION BOARD  window %lldh  up to %zu per column\n",
                   hours, b->limit);
    mb_cat(s, line);
    for (int i = 0; i < MB_COLS; i++) {
        (void)snprintf(line, sizeof(line), "%s%s %zu", i ? "  |  " : "",
                       mb_names[i], b->col[i].total);
        mb_cat(s, line);
    }
    mb_cat(s, "\n\n");
}

static bool mb_screen(const struct mb_board *b, long long hours, char *buf)
{
    struct mb_sb s = {buf, 0, MB_SCREEN_CAP, false};
    mb_header(&s, b, hours);
    mb_band(&s, b, 0, 3);
    mb_band(&s, b, 4, 6);
    if (b->skipped) {
        char line[96];
        (void)snprintf(line, sizeof(line), "%zu malformed rows skipped\n",
                       b->skipped);
        mb_cat(&s, line);
    }
    return !s.overflow;
}

/* ── reply ─────────────────────────────────────────────────────────────── */

static bool mb_col_json(struct json_value *arr, const struct mb_board *b, int id)
{
    const struct mb_col *c = &b->col[id];
    struct json_value o, cards, s;
    bool ok;
    json_init(&o);
    json_init(&cards);
    json_init(&s);
    json_set_object(&o);
    json_set_array(&cards);
    ok = true;
    for (size_t i = 0; ok && i < c->shown; i++) {
        json_set_str(&s, c->cards[i]);
        ok = json_push_back(&cards, &s);
    }
    ok = ok && json_push_kv_str(&o, "name", mb_names[id]) &&
         json_push_kv_int(&o, "count", (int64_t)c->total) &&
         json_push_kv_int(&o, "shown", (int64_t)c->shown) &&
         json_push_kv_int(&o, "overflow", (int64_t)mb_overflow(c)) &&
         json_push_kv(&o, "cards", &cards) && json_push_back(arr, &o);
    json_free(&s);
    json_free(&cards);
    json_free(&o);
    return ok;
}

static bool mb_emit_columns(struct zcl_command_reply *reply,
                            const struct mb_board *b)
{
    struct json_value cols, counts;
    bool ok = true;
    json_init(&cols);
    json_init(&counts);
    json_set_array(&cols);
    json_set_object(&counts);
    for (int i = 0; ok && i < MB_COLS; i++)
        ok = mb_col_json(&cols, b, i) &&
             json_push_kv_int(&counts, mb_names[i], (int64_t)b->col[i].total);
    ok = ok && json_push_kv(&reply->data, "columns", &cols) &&
         json_push_kv(&reply->data, "counts", &counts);
    json_free(&cols);
    json_free(&counts);
    return ok;
}

static bool mb_emit(struct zcl_command_reply *reply, const struct mb_board *b,
                    long long hours)
{
    char *screen = (char *)zcl_malloc(MB_SCREEN_CAP, "fleet.mission.screen");
    bool ok = screen && mb_screen(b, hours, screen);
    ok = ok && json_push_kv_str(&reply->data, "leaf", "fleet.mission.board") &&
         json_push_kv_int(&reply->data, "hours", hours) &&
         json_push_kv_int(&reply->data, "limit", (int64_t)b->limit) &&
         json_push_kv_bool(&reply->data, "steer_bus", b->steer_bus) &&
         json_push_kv_int(&reply->data, "skipped", (int64_t)b->skipped) &&
         mb_emit_columns(reply, b) &&
         json_push_kv_str(&reply->data, "screen", screen);
    free(screen);
    return ok;
}

/* ── inputs ────────────────────────────────────────────────────────────── */

/* An integer key (JSON number or digit string); absent means the default. */
static bool mb_int(const struct zcl_command_request *req, const char *key,
                   long long def, long long lo, long long hi, long long *out)
{
    const struct json_value *v = req->input ? json_get(req->input, key) : NULL;
    long long x = def;
    if (v && v->type == JSON_INT) {
        x = json_get_int(v);
    } else if (v && v->type == JSON_STR && json_get_str(v)[0]) {
        char *end = NULL;
        errno = 0;
        x = strtoll(json_get_str(v), &end, 10);
        if (errno != 0 || *end != '\0')
            return false;
    } else if (v) {
        return false;
    }
    *out = x;
    return x >= lo && x <= hi;
}

void zcl_native_handle_fleet_mission_board(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    long long hours = 0, limit = 0;
    struct mb_board *b;
    if (!request || !reply)
        return;
    if (!mb_int(request, "hours", MB_HOURS_DEFAULT, 1, MB_HOURS_MAX, &hours) ||
        !mb_int(request, "limit", MB_LIMIT_DEFAULT, 1, MB_LIMIT_MAX, &limit)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "BAD_INPUT", "execute",
                               false, false,
                               "hours is 1..168 and limit is 1..32",
                               "fleet.mission.board input");
        return;
    }
    b = (struct mb_board *)zcl_calloc(1, sizeof(*b), "fleet.mission.board");
    if (!b)
        return;
    b->now = (long long)platform_time_wall_unix();
    b->window = hours * 3600;
    b->limit = (size_t)limit;
    mb_fill_queue(b);
    mb_fill_land(b);
    mb_fill_steer(b);
    if (mb_emit(reply, b, hours)) {
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = 0;
    } else {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "MISSION_BOARD_FAILED",
                               "execute", false, false,
                               "the board could not be assembled",
                               "allocation or screen bound");
    }
    free(b);
}
