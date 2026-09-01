// one-result-type-ok:passive-reader-and-bridge — this file owns no
// fallible service surface beyond event_log_append (already wrapped by
// the shared primitive) and node_db KV get/set (already wrapped by the
// blessed raw-sql-ok KV primitive in models/database.h); every failure
// path here degrades to "skip this call, try again next tick" and logs
// via LOG_WARN, matching the established pattern in
// consensus_reject_index.c and the small event-log projections.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Blocker History — see services/blocker_history.h for the full design
 * rationale. Two halves in one file (small enough to keep together,
 * like consensus_reject_index.c pairs its observer with its ring):
 *
 *   1. The bridge: an EV_OPERATOR_NEEDED (in-memory bus, event/event.h)
 *      observer that durably appends an EV_OPERATOR_ALERT copy to the
 *      shared event log (storage/event_log.h) so an operator page
 *      survives restart.
 *   2. The reader: an incremental cursor-driven fold of EV_OPERATOR_ALERT
 *      events into a fixed-capacity in-memory aggregate table, plus the
 *      dumpstate JSON surface.
 */

#include "services/blocker_history.h"

#include "config/runtime.h"
#include "core/utiltime.h"
#include "event/event.h"
#include "json/json.h"
#include "models/database.h"
#include "storage/event_log.h"
#include "storage/event_log_singleton.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/log_macros.h"

/* Durable cursor key in node.db's node_state KV table (the blessed
 * raw-sql-ok:kv-state-primitive path — see models/database.h). */
#define BLOCKER_HISTORY_CURSOR_KEY "blocker_history.cursor"

/* Bridge payload cap: EVENT_PAYLOAD_SIZE (256, event/event.h) for the
 * original EV_OPERATOR_NEEDED payload plus a "ts=<unix> " prefix. */
#define BLOCKER_HISTORY_BRIDGE_BUF 320

/* ── Module state (the aggregate table) ─────────────────────────────── */

struct bh_state {
    pthread_mutex_t             lock;
    struct blocker_history_row  rows[BLOCKER_HISTORY_CAP];
    size_t                      row_count;
    uint64_t                    total_events;      /* EV_OPERATOR_ALERT
                                                      * events visited,
                                                      * lifetime */
    uint64_t                    unparsed_events;
    uint64_t                    overflow_dropped;
};

static struct bh_state g_bh = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

static _Atomic bool g_bridge_registered = false;

/* ── Bridge (writer side) ─────────────────────────────────────────── */

static void bh_bridge_observer(enum event_type type, uint32_t peer_id,
                               const void *payload, uint32_t payload_len,
                               void *ctx)
{
    (void)peer_id; (void)ctx;
    if (type != EV_OPERATOR_NEEDED)
        return;

    /* NULL-tolerant per event_log_singleton's own contract: "not wired
     * yet" during early boot is best-effort-skip, not an error. */
    event_log_t *log = event_log_singleton();
    if (!log)
        return;

    char buf[BLOCKER_HISTORY_BRIDGE_BUF];
    const char *p = payload ? (const char *)payload : "";
    int n = snprintf(buf, sizeof(buf), "ts=%lld %.*s",
                     (long long)GetTime(), (int)payload_len, p);
    if (n <= 0)
        return;
    size_t len = (size_t)n < sizeof(buf) ? (size_t)n : sizeof(buf) - 1;

    if (event_log_append(log, EV_OPERATOR_ALERT, buf, len) == UINT64_MAX)
        LOG_WARN("blocker_history",
                 "[blocker_history] durable bridge append failed — "
                 "an operator page did not reach the durable history");
}

void blocker_history_bridge_register(void)
{
    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_bridge_registered, &expected,
                                        true))
        return; /* already registered — idempotent */
    event_observe(EV_OPERATOR_NEEDED, bh_bridge_observer, NULL);
}

void blocker_history_bridge_unregister_for_test(void)
{
    event_clear_observers(EV_OPERATOR_NEEDED);
    atomic_store(&g_bridge_registered, false);
}

/* ── Id extraction ───────────────────────────────────────────────── */

/* Find `key` in `body` and copy the token that follows (up to the next
 * space or end of string) into `out`. Returns false if `key` is absent
 * or the token is empty. */
static bool bh_token_after(const char *body, const char *key,
                           char *out, size_t out_cap)
{
    const char *p = strstr(body, key);
    if (!p) return false;
    p += strlen(key);
    const char *end = p;
    while (*end && *end != ' ') end++;
    size_t len = (size_t)(end - p);
    if (len == 0) return false;
    if (len >= out_cap) len = out_cap - 1;
    memcpy(out, p, len);
    out[len] = '\0';
    return true;
}

struct bh_fixed_rule {
    const char *prefix;
    const char *id;
};

/* Fixed literal-prefix rows for emit sites whose payload carries no
 * key=token at all. `coin_backfill` deliberately coarsens away the
 * per-height suffix (see header rationale) rather than let one noisy
 * stage evict every other blocker's history from the table. */
static const struct bh_fixed_rule BH_FIXED_RULES[] = {
    { "coin_backfill h=",                     "coin_backfill" },
    { "script_validate prevout_unresolved",   "script_validate.prevout_unresolved" },
    { "proof_validate internal_error",        "proof_validate.internal_error" },
    { "reducer_frontier script_undetermined", "reducer_frontier.script_undetermined" },
};
#define BH_NUM_FIXED_RULES \
    (sizeof(BH_FIXED_RULES) / sizeof(BH_FIXED_RULES[0]))

/* Parses one EV_OPERATOR_ALERT payload. `*ts_out` gets the bridge's
 * `ts=<unix>` prefix (falls back to "now" if absent/malformed — a
 * defensive floor, not the expected production path). `id_out` gets the
 * extracted blocker/condition id (priority: blocker= > check= >
 * condition= > fixed-prefix table). `reason_out` gets the payload body
 * (post-ts-prefix), bounded copy, always filled regardless of id-parse
 * outcome. Returns true iff an id was extracted. */
static bool bh_parse_payload(const void *payload, size_t len,
                             int64_t *ts_out, char *id_out, size_t id_cap,
                             char *reason_out, size_t reason_cap)
{
    if (!payload || len == 0 || !ts_out || !id_out || id_cap == 0 ||
        !reason_out || reason_cap == 0)
        return false;

    char buf[BLOCKER_HISTORY_BRIDGE_BUF];
    size_t n = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;
    memcpy(buf, payload, n);
    buf[n] = '\0';

    const char *body = buf;
    int64_t ts = GetTime();
    if (strncmp(buf, "ts=", 3) == 0) {
        char *end = NULL;
        long long v = strtoll(buf + 3, &end, 10);
        if (end != buf + 3 && *end == ' ') {
            ts = (int64_t)v;
            body = end + 1;
        }
    }
    *ts_out = ts;
    size_t reason_len = strlen(body);
    if (reason_len >= reason_cap)
        reason_len = reason_cap - 1;
    memcpy(reason_out, body, reason_len);
    reason_out[reason_len] = '\0';

    if (bh_token_after(body, "blocker=",   id_out, id_cap)) return true;
    if (bh_token_after(body, "check=",     id_out, id_cap)) return true;
    if (bh_token_after(body, "condition=", id_out, id_cap)) return true;

    for (size_t i = 0; i < BH_NUM_FIXED_RULES; i++) {
        size_t plen = strlen(BH_FIXED_RULES[i].prefix);
        if (strncmp(body, BH_FIXED_RULES[i].prefix, plen) == 0) {
            snprintf(id_out, id_cap, "%s", BH_FIXED_RULES[i].id);
            return true;
        }
    }
    return false;
}

/* ── Aggregate fold (lock held) ──────────────────────────────────── */

static void bh_fold_locked(const char *id, int64_t ts_unix,
                           const char *reason)
{
    for (size_t i = 0; i < g_bh.row_count; i++) {
        if (strcmp(g_bh.rows[i].id, id) == 0) {
            g_bh.rows[i].fire_count++;
            g_bh.rows[i].last_seen_unix = ts_unix;
            snprintf(g_bh.rows[i].last_reason,
                     sizeof(g_bh.rows[i].last_reason), "%s", reason);
            return;
        }
    }
    if (g_bh.row_count >= BLOCKER_HISTORY_CAP) {
        g_bh.overflow_dropped++;
        return;
    }
    struct blocker_history_row *row = &g_bh.rows[g_bh.row_count++];
    snprintf(row->id, sizeof(row->id), "%s", id);
    row->fire_count = 1;
    row->first_seen_unix = ts_unix;
    row->last_seen_unix = ts_unix;
    snprintf(row->last_reason, sizeof(row->last_reason), "%s", reason);
}

/* ── Reader / aggregator ─────────────────────────────────────────── */

struct bh_stream_ctx {
    uint64_t next_offset;
    int      visited; /* EV_OPERATOR_ALERT events visited THIS call */
};

static bool bh_catchup_cb(uint64_t offset, enum event_log_type type,
                          const void *payload, size_t len, void *user)
{
    struct bh_stream_ctx *ctx = user;
    ctx->next_offset = offset + EVENT_LOG_FRAME_OVERHEAD + (uint64_t)len;

    if (type != EV_OPERATOR_ALERT)
        return true; /* shared log — every other producer's events pass
                       * through untouched; the cursor still advances. */

    ctx->visited++;

    int64_t ts = 0;
    char id[BLOCKER_HISTORY_ID_MAX];
    char reason[BLOCKER_HISTORY_REASON_MAX];
    bool parsed = bh_parse_payload(payload, len, &ts, id, sizeof(id),
                                   reason, sizeof(reason));

    pthread_mutex_lock(&g_bh.lock);
    g_bh.total_events++;
    if (parsed)
        bh_fold_locked(id, ts, reason);
    else
        g_bh.unparsed_events++;
    pthread_mutex_unlock(&g_bh.lock);
    return true;
}

int blocker_history_catch_up_ex(event_log_t *log, struct node_db *ndb)
{
    if (!log)
        LOG_ERR("blocker_history",
                "[blocker_history] catch_up called with NULL event log");

    int64_t cursor = 0;
    if (ndb && ndb->open) {
        int64_t c = 0;
        if (node_db_state_get_int(ndb, BLOCKER_HISTORY_CURSOR_KEY, &c) &&
            c >= 0)
            cursor = c;
    }

    struct bh_stream_ctx ctx = {
        .next_offset = (uint64_t)cursor,
        .visited = 0,
    };
    if (event_log_stream(log, (uint64_t)cursor, bh_catchup_cb, &ctx) != 0)
        LOG_ERR("blocker_history",
               "[blocker_history] event_log_stream failed from cursor=%lld",
               (long long)cursor);

    if (ndb && ndb->open && ctx.next_offset != (uint64_t)cursor) {
        if (!node_db_state_set_int(ndb, BLOCKER_HISTORY_CURSOR_KEY,
                                   (int64_t)ctx.next_offset))
            LOG_WARN("blocker_history",
                     "[blocker_history] failed to persist cursor=%llu — "
                     "next catch_up will rescan from the stale cursor",
                     (unsigned long long)ctx.next_offset);
    }
    return ctx.visited;
}

int blocker_history_catch_up(void)
{
    event_log_t *log = event_log_singleton();
    if (!log)
        return -1; // raw-return-ok:not-wired-yet — early boot / unit-test
                    // process with no event log singleton is the expected,
                    // benign idle case (matches event_log_singleton.h's own
                    // "NULL means not wired yet" contract), not an error.
    return blocker_history_catch_up_ex(log, app_runtime_node_db());
}

uint64_t blocker_history_scan_visits_total(void)
{
    pthread_mutex_lock(&g_bh.lock);
    uint64_t v = g_bh.total_events;
    pthread_mutex_unlock(&g_bh.lock);
    return v;
}

void blocker_history_reset_for_test(void)
{
    pthread_mutex_lock(&g_bh.lock);
    memset(g_bh.rows, 0, sizeof(g_bh.rows));
    g_bh.row_count = 0;
    g_bh.total_events = 0;
    g_bh.unparsed_events = 0;
    g_bh.overflow_dropped = 0;
    pthread_mutex_unlock(&g_bh.lock);
}

/* ── Dumper ──────────────────────────────────────────────────────── */

static int bh_cmp_fire_count_desc(const void *a, const void *b)
{
    const struct blocker_history_row *ra = a;
    const struct blocker_history_row *rb = b;
    if (ra->fire_count > rb->fire_count) return -1; // raw-return-ok:qsort-comparator-sort-order
    if (ra->fire_count < rb->fire_count) return 1;
    return 0;
}

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
bool blocker_history_dump_state_json(struct json_value *out, const char *key)
{
    if (!out)
        return false;
    json_set_object(out);

    (void)blocker_history_catch_up();

    struct blocker_history_row snapshot[BLOCKER_HISTORY_CAP];
    size_t n;
    uint64_t total, unparsed, overflow;
    pthread_mutex_lock(&g_bh.lock);
    n = g_bh.row_count;
    memcpy(snapshot, g_bh.rows, n * sizeof(*snapshot));
    total = g_bh.total_events;
    unparsed = g_bh.unparsed_events;
    overflow = g_bh.overflow_dropped;
    pthread_mutex_unlock(&g_bh.lock);

    qsort(snapshot, n, sizeof(*snapshot), bh_cmp_fire_count_desc);

    json_push_kv_int(out, "total_events", (int64_t)total);
    json_push_kv_int(out, "unparsed_events", (int64_t)unparsed);
    json_push_kv_int(out, "overflow_dropped", (int64_t)overflow);
    json_push_kv_int(out, "distinct_ids", (int64_t)n);
    json_push_kv_int(out, "capacity", (int64_t)BLOCKER_HISTORY_CAP);

    size_t want = 10;
    if (key && *key) {
        long v = strtol(key, NULL, 10);
        if (v > 0)
            want = (size_t)v;
    }
    if (want > BLOCKER_HISTORY_CAP)
        want = BLOCKER_HISTORY_CAP;
    if (want > n)
        want = n;

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < want; i++) {
        struct json_value child;
        json_init(&child);
        json_set_object(&child);
        json_push_kv_str(&child, "id", snapshot[i].id);
        json_push_kv_int(&child, "fire_count",
                         (int64_t)snapshot[i].fire_count);
        json_push_kv_int(&child, "first_seen_unix",
                         snapshot[i].first_seen_unix);
        json_push_kv_int(&child, "last_seen_unix",
                         snapshot[i].last_seen_unix);
        json_push_kv_str(&child, "last_reason", snapshot[i].last_reason);
        json_push_back(&arr, &child);
        json_free(&child);
    }
    json_push_kv(out, "top", &arr);
    json_free(&arr);
    return true;
}
