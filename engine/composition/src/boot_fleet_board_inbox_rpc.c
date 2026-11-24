/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The board's per-agent read views on the `fleet_board` RPC:
 * `inbox` (rows that answer this agent's posts, or mail addressed to it),
 * `inbox_wait` (the same, held open until a row arrives) and `delivery`
 * (what each peer answered when this box pushed it a post).
 *
 * They are views over the one signed store and assert nothing. Visibility
 * is the list op's: the same local, operator-authenticated method, the same
 * rows. Nothing here writes a post, and `inbox_wait` is bounded on every
 * side: one call waits at most FLEET_BOARD_WAIT_SLICE_MS, at most
 * FLEET_BOARD_WAIT_SLOTS calls wait in the node at once (one per agent
 * label), and a waiter holds no lock and no statement while it sleeps — it
 * watches the store's arrival counter and reads again only when that moved. */

#include "boot_fleet_board_rpc_internal.h"
#include "config/boot_fleet_board.h"

#include "base/hex.h"
#include "json/json.h"
#include "models/fleet_board_delivery.h"
#include "models/fleet_board_inbox.h"
#include "models/fleet_board_post.h"
#include "platform/time_compat.h"
#include "util/sync.h"
#include "util/thread_registry.h"

#include <stdio.h>
#include <string.h>

/* ── input ─────────────────────────────────────────────────────────────── */

struct fb_inbox_in {
    char agent[FLEET_BOARD_AGENT_MAX + 1];
    struct fleet_board_inbox_query q;
    unsigned rows_max;
    unsigned text_max;
};

/* Labels are descriptive, never identity; the alphabet keeps the next
 * command copy-pasteable into a shell without quoting. */
static bool fb_inbox_agent_ok(const char *agent)
{
    size_t n = strnlen(agent, FLEET_BOARD_AGENT_MAX + 1);
    if (n == 0 || n > FLEET_BOARD_AGENT_MAX)
        return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)agent[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                  c == '.' || c == ':' || c == '@';
        if (!ok)
            return false;
    }
    return true;
}

static bool fb_inbox_bounded(const struct json_value *in, const char *key,
                             int64_t lo, int64_t hi, int64_t fallback,
                             int64_t *out)
{
    const struct json_value *v = json_get(in, key);
    *out = fallback;
    if (!v || v->type == JSON_NULL)
        return true;
    if (v->type != JSON_INT || json_get_int(v) < lo || json_get_int(v) > hi)
        return false;
    *out = json_get_int(v);
    return true;
}

static bool fb_inbox_ref(const struct json_value *in, struct json_value *result,
                         struct fleet_board_inbox_query *q)
{
    const char *ref = fb_str(in, "ref", NULL);
    if (!ref)
        return true;
    if (!fleet_board_id_from_hex(ref, q->ref)) {
        fb_error(result, "BAD_REF", "ref is the 64-character id of the post "
                 "whose replies to read; take it from fleet board list or show");
        return false;
    }
    q->ref_set = true;
    return true;
}

static bool fb_inbox_parse(const struct json_value *in, struct json_value *result,
                           struct fb_inbox_in *out)
{
    memset(out, 0, sizeof(*out));
    const char *agent = fb_str(in, "agent", "");
    if (!fb_inbox_agent_ok(agent)) {
        fb_error(result, "BAD_AGENT", "agent is required: the label you post "
                 "under, 1..64 of A-Z a-z 0-9 - _ . : @ (e.g. --agent=lane-a)");
        return false;
    }
    (void)snprintf(out->agent, sizeof(out->agent), "%s", agent);
    int64_t after, rows, text;
    if (!fb_inbox_bounded(in, "after", 0, INT64_MAX, 0, &after) ||
        !fb_inbox_bounded(in, "limit", 1, FLEET_BOARD_INBOX_ROWS_MAX,
                          FLEET_BOARD_INBOX_ROWS_DEFAULT, &rows) ||
        !fb_inbox_bounded(in, "text_max", 0, FLEET_BOARD_TEXT_MAX,
                          FLEET_BOARD_INBOX_TEXT_DEFAULT, &text)) {
        fb_error(result, "BAD_INBOX_INPUT", "after is an arrival number >= 0 "
                 "(next_after of the last reply), limit is 1..64 rows "
                 "(default 20) and text_max is 0..2048 bytes (default 160)");
        return false;
    }
    out->q.agent = out->agent;
    out->q.after = after;
    out->q.limit = FLEET_BOARD_INBOX_SCAN_MAX;
    out->rows_max = (unsigned)rows;
    out->text_max = (unsigned)text;
    return fb_inbox_ref(in, result, &out->q);
}

/* ── one page ──────────────────────────────────────────────────────────── */

struct fb_inbox_page {
    const struct fb_inbox_in *in;
    struct json_value rows;
    unsigned got;
    unsigned candidates;
    bool full;
    bool ok;
};

/* Whether a mail-receipt note names this reader in its `to`. */
static bool fb_inbox_mail_to(const struct db_fleet_board_post *row,
                             const char *agent)
{
    struct json_value mail;
    json_init(&mail);
    bool to_me = json_read(&mail, row->post.text, row->post.text_len) &&
                 mail.type == JSON_OBJ &&
                 strcmp(json_get_str(json_get(&mail, "to")), agent) == 0;
    json_free(&mail);
    return to_me;
}

/* Why this candidate concerns the reader, or NULL when it does not. */
static const char *fb_inbox_why(const struct fb_inbox_page *p,
                                const struct db_fleet_board_post *row)
{
    if (p->in->q.ref_set)
        return "thread";
    if (strcmp(row->post.receipt, FLEET_BOARD_MAIL_RECEIPT) == 0)
        return fb_inbox_mail_to(row, p->in->agent) ? "mail" : NULL;
    return "reply";
}

/* Cut to at most `max` bytes without splitting a UTF-8 sequence. */
static size_t fb_inbox_cut(const char *text, size_t len, size_t max)
{
    if (len <= max)
        return len;
    size_t n = max;
    while (n > 0 && ((unsigned char)text[n] & 0xC0u) == 0x80u)
        n--;
    return n;
}

static bool fb_inbox_text(struct json_value *item, const struct db_fleet_board_post *row,
                          unsigned text_max)
{
    char text[FLEET_BOARD_TEXT_MAX + 1];
    size_t len = fb_inbox_cut(row->post.text, row->post.text_len, text_max);
    memcpy(text, row->post.text, len);
    text[len] = '\0';
    bool ok = json_push_kv_str(item, "text", text);
    if (len < row->post.text_len)
        ok = ok && json_push_kv_int(item, "text_len", row->post.text_len);
    return ok;
}

static bool fb_inbox_row(struct json_value *item, const struct db_fleet_board_post *row,
                         const char *why, unsigned text_max)
{
    char id[65];
    fleet_board_id_to_hex(row->post.id, id);
    bool ok = json_push_kv_int(item, "arrival", row->arrival) &&
              json_push_kv_str(item, "id", id) &&
              json_push_kv_str(item, "why", why) &&
              json_push_kv_str(item, "kind", fleet_board_kind_name(row->post.kind)) &&
              json_push_kv_str(item, "agent", row->post.agent) &&
              json_push_kv_int(item, "created_at", (int64_t)row->post.created_at);
    /* A row that reached this store long after it was signed says so: a
     * backlog somewhere upstream is otherwise invisible. */
    int64_t late = row->received_at - (int64_t)row->post.created_at;
    if (late > FLEET_BOARD_INBOX_LATE_S)
        ok = ok && json_push_kv_int(item, "late_s", late);
    return ok && fb_inbox_text(item, row, text_max);
}

static bool fb_inbox_visit(const struct db_fleet_board_post *row, void *ctx)
{
    struct fb_inbox_page *p = ctx;
    p->candidates++;
    const char *why = fb_inbox_why(p, row);
    if (!why)
        return true;
    if (p->got >= p->in->rows_max) {
        p->full = true;
        return false;
    }
    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    p->ok = p->ok && fb_inbox_row(&item, row, why, p->in->text_max) &&
            json_push_back(&p->rows, &item);
    json_free(&item);
    p->got++;
    return p->ok;
}

/* Read one page. False only when the store could not be read. */
static bool fb_inbox_read(struct node_db *ndb, const struct fb_inbox_in *in,
                          int64_t now, struct fb_inbox_page *p, int64_t *next)
{
    memset(p, 0, sizeof(*p));
    p->in = in;
    p->ok = true;
    json_init(&p->rows);
    json_set_array(&p->rows);
    int visited = db_fleet_board_inbox_scan(ndb, now, &in->q, fb_inbox_visit,
                                            p, next);
    return visited >= 0;
}

static bool fb_inbox_next(struct json_value *result, const struct fb_inbox_in *in,
                          int64_t next)
{
    char cmd[256], ref[80] = "";
    if (in->q.ref_set) {
        char hex[65];
        fleet_board_id_to_hex(in->q.ref, hex);
        (void)snprintf(ref, sizeof(ref), " --ref=%s", hex);
    }
    (void)snprintf(cmd, sizeof(cmd), "z23 fleet board wait --agent=%s --after=%lld%s",
                   in->agent, (long long)next, ref);
    bool ok = json_push_kv_str(result, "next", cmd);
    (void)snprintf(cmd, sizeof(cmd), "z23 fleet board inbox --agent=%s --after=%lld%s",
                   in->agent, (long long)next, ref);
    return ok && json_push_kv_str(result, "next_read", cmd);
}

static bool fb_inbox_render(struct json_value *result, const struct fb_inbox_in *in,
                            struct fb_inbox_page *p, int64_t next)
{
    bool has_more = p->full || p->candidates >= in->q.limit;
    json_set_object(result);
    bool ok = json_push_kv_bool(result, "ok", true) &&
              json_push_kv_str(result, "agent", in->agent) &&
              json_push_kv(result, "rows", &p->rows) &&
              json_push_kv_int(result, "returned", p->got) &&
              json_push_kv_int(result, "next_after", next) &&
              json_push_kv_bool(result, "has_more", has_more);
    return ok && fb_inbox_next(result, in, next);
}

/* One page into `result`; *rows_out is how many rows it carries. */
static void fb_inbox_page(struct node_db *ndb, const struct fb_inbox_in *in,
                          int64_t now, struct json_value *result,
                          unsigned *rows_out, int64_t *next_out)
{
    struct fb_inbox_page p;
    int64_t next = in->q.after;
    *rows_out = 0;
    *next_out = next;
    if (!fb_inbox_read(ndb, in, now, &p, &next)) {
        json_free(&p.rows);
        fb_error(result, "BOARD_READ_FAILED",
                 "the inbox could not be read; nothing was consumed, try again");
        return;
    }
    if (!p.ok || !fb_inbox_render(result, in, &p, next)) {
        json_free(&p.rows);
        fb_error(result, "BOARD_ALLOC_FAILED", "the inbox page could not be built");
        return;
    }
    json_free(&p.rows);
    *rows_out = p.got;
    *next_out = next;
}

void fb_op_inbox(struct node_db *ndb, const struct json_value *in,
                 struct json_value *result, int64_t now)
{
    struct fb_inbox_in parsed;
    unsigned rows;
    int64_t next;
    if (fb_inbox_parse(in, result, &parsed))
        fb_inbox_page(ndb, &parsed, now, result, &rows, &next);
}

/* ── the bounded wait ──────────────────────────────────────────────────── */

static zcl_mutex_t g_wait_lock;
static zcl_once_t g_wait_once = ZCL_ONCE_INIT;
static struct {
    bool used;
    char agent[FLEET_BOARD_AGENT_MAX + 1];
} g_wait_slots[FLEET_BOARD_WAIT_SLOTS];

static void fb_wait_lock_init(void)
{
    zcl_mutex_init(&g_wait_lock);
}

/* A free slot, or -1 with *same_agent saying which cap refused. */
static int fb_wait_acquire(const char *agent, bool *same_agent)
{
    int slot = -1;
    *same_agent = false;
    (void)zcl_once_call(&g_wait_once, fb_wait_lock_init);
    zcl_mutex_lock(&g_wait_lock);
    for (int i = 0; i < FLEET_BOARD_WAIT_SLOTS; i++) {
        if (g_wait_slots[i].used && !strcmp(g_wait_slots[i].agent, agent))
            *same_agent = true;
        else if (!g_wait_slots[i].used && slot < 0)
            slot = i;
    }
    if (*same_agent)
        slot = -1;
    if (slot >= 0) {
        g_wait_slots[slot].used = true;
        (void)snprintf(g_wait_slots[slot].agent, sizeof(g_wait_slots[slot].agent),
                       "%s", agent);
    }
    zcl_mutex_unlock(&g_wait_lock);
    return slot;
}

static void fb_wait_release(int slot)
{
    zcl_mutex_lock(&g_wait_lock);
    g_wait_slots[slot].used = false;
    g_wait_slots[slot].agent[0] = '\0';
    zcl_mutex_unlock(&g_wait_lock);
}

static void fb_wait_busy(struct json_value *result, bool same_agent)
{
    char msg[320];
    (void)snprintf(msg, sizeof(msg),
                   "%s; this call returned at once and consumed nothing. Read "
                   "with fleet board inbox, or retry the wait in %d ms",
                   same_agent ? "this agent already has a wait open in the node "
                                "(1 per agent)"
                              : "the node already holds its 2 open waits",
                   FLEET_BOARD_WAIT_RETRY_MS);
    fb_error(result, "WAIT_BUSY", msg);
    (void)json_push_kv_int(result, "retry_after_ms", FLEET_BOARD_WAIT_RETRY_MS);
    (void)json_push_kv_int(result, "wait_slots", FLEET_BOARD_WAIT_SLOTS);
}

/* Sleep until the arrival counter moves past `seen`, the deadline passes or
 * the node is stopping. True when the counter moved. */
static bool fb_wait_arrival(uint64_t seen, int64_t deadline_ms)
{
    for (;;) {
        if (db_fleet_board_arrival_generation() != seen)
            return true;
        int64_t left = deadline_ms - platform_time_monotonic_ms();
        if (left <= 0 || thread_registry_shutdown_requested())
            return false;
        platform_sleep_ms((int)(left < FLEET_BOARD_WAIT_TICK_MS
                                    ? left : FLEET_BOARD_WAIT_TICK_MS));
    }
}

static void fb_wait_loop(struct node_db *ndb, struct fb_inbox_in *in,
                         int64_t deadline_ms, struct json_value *result)
{
    int64_t start = platform_time_monotonic_ms();
    for (;;) {
        uint64_t seen = db_fleet_board_arrival_generation();
        unsigned rows = 0;
        int64_t next = in->q.after;
        json_free(result);
        json_init(result);
        fb_inbox_page(ndb, in, (int64_t)platform_time_wall_time_t(), result,
                      &rows, &next);
        if (rows > 0 || !json_get_bool(json_get(result, "ok")))
            break;
        in->q.after = next; /* nothing matched up to here: never read again */
        if (!fb_wait_arrival(seen, deadline_ms)) {
            (void)json_push_kv_bool(result, "timed_out", true);
            break;
        }
    }
    (void)json_push_kv_int(result, "waited_ms", platform_time_monotonic_ms() - start);
}

void fb_op_inbox_wait(struct node_db *ndb, const struct json_value *in,
                      struct json_value *result, int64_t now)
{
    (void)now;
    struct fb_inbox_in parsed;
    int64_t slice;
    if (!fb_inbox_parse(in, result, &parsed))
        return;
    if (!fb_inbox_bounded(in, "timeout_ms", 0, FLEET_BOARD_WAIT_SLICE_MS,
                          FLEET_BOARD_WAIT_SLICE_MS, &slice)) {
        fb_error(result, "BAD_TIMEOUT", "one node-side wait is 0..5000 ms; "
                 "the CLI's fleet board wait chains them up to 60 s");
        return;
    }
    bool same_agent = false;
    int slot = fb_wait_acquire(parsed.agent, &same_agent);
    if (slot < 0) {
        fb_wait_busy(result, same_agent);
        return;
    }
    fb_wait_loop(ndb, &parsed, platform_time_monotonic_ms() + slice, result);
    fb_wait_release(slot);
}

/* ── delivery ──────────────────────────────────────────────────────────── */

static bool fb_delivery_row(struct json_value *peers,
                            const struct db_fleet_board_delivery *d,
                            int64_t counts[FLEET_BOARD_DELIVERY_VERDICTS])
{
    char peer[65];
    zcl_hex_encode(d->peer, 32, peer);
    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    bool ok = json_push_kv_str(&item, "peer", peer) &&
              json_push_kv_str(&item, "verdict",
                               fleet_board_delivery_verdict_name(d->verdict)) &&
              (!d->reason[0] || json_push_kv_str(&item, "reason", d->reason)) &&
              json_push_kv_int(&item, "at", d->at) &&
              json_push_back(peers, &item);
    json_free(&item);
    if (d->verdict >= 0 && d->verdict < FLEET_BOARD_DELIVERY_VERDICTS)
        counts[d->verdict]++;
    return ok;
}

static bool fb_delivery_counts(struct json_value *result,
                               const int64_t counts[FLEET_BOARD_DELIVERY_VERDICTS])
{
    struct json_value c;
    json_init(&c);
    json_set_object(&c);
    bool ok = true;
    for (int64_t v = 0; v < FLEET_BOARD_DELIVERY_VERDICTS; v++)
        ok = ok && json_push_kv_int(&c, fleet_board_delivery_verdict_name(v),
                                    counts[v]);
    ok = ok && json_push_kv(result, "counts", &c);
    json_free(&c);
    return ok;
}

static const char *fb_delivery_note(bool held, uint8_t scope, int n)
{
    if (!held)
        return "this node does not hold the post; delivery is recorded by the "
               "node that signed and pushed it";
    if (scope != FLEET_BOARD_SCOPE_FLEET)
        return "public posts travel by announce and fetch, which carry no "
               "per-peer receipt; fleet board show on the peer is the check";
    if (n == 0)
        return "no peer has answered a push of this post yet (or its answers "
               "aged out of the newest 4096); the paired pull still carries "
               "it within 15 s of a peer asking";
    return "stored and held mean the peer has it; deferred is retried by the "
           "paired pull; refused names why the peer will not keep it";
}

static bool fb_delivery_render(struct json_value *result, const char *id,
                               const struct db_fleet_board_post *post, bool held,
                               const struct db_fleet_board_delivery *rows, int n)
{
    int64_t counts[FLEET_BOARD_DELIVERY_VERDICTS] = {0};
    struct json_value peers;
    json_init(&peers);
    json_set_array(&peers);
    bool ok = true;
    for (int i = 0; ok && i < n; i++)
        ok = fb_delivery_row(&peers, &rows[i], counts);
    json_set_object(result);
    ok = ok && json_push_kv_bool(result, "ok", true) &&
         json_push_kv_str(result, "id", id) &&
         json_push_kv_bool(result, "held_here", held) &&
         (!held || json_push_kv_str(result, "scope",
                                    fleet_board_scope_name(post->post.scope))) &&
         json_push_kv(result, "peers", &peers) &&
         fb_delivery_counts(result, counts) &&
         json_push_kv_str(result, "note",
                          fb_delivery_note(held, post->post.scope, n));
    json_free(&peers);
    return ok;
}

void fb_op_delivery(struct node_db *ndb, const struct json_value *in,
                    struct json_value *result)
{
    const char *id = fb_str(in, "id", "");
    uint8_t post_id[32];
    if (!fleet_board_id_from_hex(id, post_id)) {
        fb_error(result, "BAD_ID", "usage: fleet board delivery <id>, the "
                 "64-character post id fleet board post printed");
        return;
    }
    struct db_fleet_board_post post;
    memset(&post, 0, sizeof(post));
    enum fleet_board_lookup_status found =
        db_fleet_board_post_lookup_checked(ndb, post_id, &post);
    struct db_fleet_board_delivery rows[FLEET_BOARD_DELIVERY_PEERS_MAX];
    int n = db_fleet_board_delivery_for_post(ndb, post_id, rows,
                                             FLEET_BOARD_DELIVERY_PEERS_MAX);
    if (found == FLEET_BOARD_LOOKUP_ERROR || n < 0) {
        fb_error(result, "BOARD_READ_FAILED",
                 "the post or its delivery record could not be read; try again");
        return;
    }
    if (!fb_delivery_render(result, id, &post, found == FLEET_BOARD_LOOKUP_FOUND,
                            rows, n))
        fb_error(result, "BOARD_ALLOC_FAILED", "the delivery reply could not be built");
}

bool fb_dispatch_views(struct node_db *ndb, const char *op,
                       const struct json_value *in, struct json_value *result,
                       int64_t now)
{
    if (strcmp(op, "inbox") == 0)
        fb_op_inbox(ndb, in, result, now);
    else if (strcmp(op, "inbox_wait") == 0)
        fb_op_inbox_wait(ndb, in, result, now);
    else if (strcmp(op, "delivery") == 0)
        fb_op_delivery(ndb, in, result);
    else
        return false;
    return true;
}
