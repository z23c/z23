// one-result-type-ok:running-flag-getter — the sole remaining legacy
// export, consensus_reject_index_running, is a mutex-guarded read of the
// service's running flag with no failure path (struct zcl_result would
// always report OK). Every fallible surface in this file
// (consensus_reject_index_start, consensus_reject_index_lookup) already
// returns zcl_result.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Consensus Reject Index — see header for rationale.
 *
 * Subscribes to EV_CONSENSUS_REJECT_TX and EV_CONSENSUS_REJECT_BLOCK
 * and stores the last N entries in a fixed-size ring. Parsing
 * strategy: the
 * event payload is a printf'd C string of the shape
 *
 *     "hash=<64hex> reason=<name> dos=<N>"
 *
 * which is emitted by check_block.c and check_transaction.c. We parse it with
 * a sscanf-shaped manual scan (no sscanf — the reason field may contain any
 * non-space ASCII, and we want a bounded copy not a %s overflow).
 *
 * The ring uses a power-of-two capacity so write-head advancement
 * is a cheap AND. Lookups walk backwards from the newest write to
 * the oldest slot so "most recent match wins".
 */

#include "services/consensus_reject_index.h"

#include "encoding/utilstrencodings.h"
#include "event/event.h"
#include "json/json.h"
#include "platform/time_compat.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "util/log_macros.h"
#include "util/result.h"
#include "util/safe_alloc.h"

/* ── Module state ───────────────────────────────────────────── */

struct cri_state {
    pthread_mutex_t  lock;
    bool             running;
    struct cri_entry *ring;
    size_t           capacity;     /* power of two, 0 if not running */
    size_t           mask;         /* capacity - 1 */
    size_t           count;        /* entries present (≤ capacity)  */
    size_t           write_pos;    /* next slot to write            */
    uint64_t         total;        /* lifetime counter (never decreases) */
};

static struct cri_state g_cri = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

/* ── Helpers ────────────────────────────────────────────────── */

static int64_t cri_now_us(void)
{
    return platform_time_realtime_us();
}

/* Parse exactly 64 hex chars into out[32]. Matches the encoding
 * direction of `uint256_get_hex`, which writes bytes in reverse
 * (Bitcoin display order) so that the left-most hex character is
 * the most-significant byte of the integer. Returns true on success. */
static bool parse_hex256(const char *s, size_t len, struct uint256 *out)
{
    if (len < 64) return false;
    for (int i = 0; i < 32; i++) {
        signed char hi = HexDigit(s[2 * i]);
        signed char lo = HexDigit(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out->data[31 - i] = (uint8_t)(((unsigned)hi << 4) | (unsigned)lo);
    }
    return true;
}

/* Round cap up to the next power of two, clamped to [8, CRI_MAX_CAPACITY]. */
static size_t round_pow2(size_t cap)
{
    if (cap < 8) cap = 8;
    if (cap > CRI_MAX_CAPACITY) cap = CRI_MAX_CAPACITY;
    size_t p = 8;
    while (p < cap) p <<= 1;
    return p;
}

/* ── Ring write (mutex held) ────────────────────────────────── */

static void cri_write_locked(const struct cri_entry *e)
{
    struct cri_entry *slot = &g_cri.ring[g_cri.write_pos & g_cri.mask];
    *slot = *e;
    g_cri.write_pos++;
    if (g_cri.count < g_cri.capacity) g_cri.count++;
    g_cri.total++;
}

/* ── Payload parser ─────────────────────────────────────────── */

/* Fills `out` from a payload of the shape
 *   "hash=<64hex> reason=<name> dos=<N>"
 *
 * Any field missing or malformed → returns false and `out` is
 * left in an indeterminate state. Whitespace between fields is
 * a single space (matches event_emitf output). The reason field
 * ends at the next space. Extra fields after `dos=N` are ignored. */
static bool cri_parse_payload(const void *payload, size_t len,
                               enum cri_kind kind,
                               struct cri_entry *out)
{
    if (!payload || len == 0) return false;
    const char *p = (const char *)payload;
    const char *end = p + len;

    /* hash=<64hex> */
    if ((size_t)(end - p) < 5 + 64) return false;
    if (memcmp(p, "hash=", 5) != 0) return false;
    p += 5;
    if (!parse_hex256(p, (size_t)(end - p), &out->hash)) return false;
    p += 64;
    if (p >= end || *p != ' ') return false;
    p++;

    /* reason=<name> */
    if ((size_t)(end - p) < 7) return false;
    if (memcmp(p, "reason=", 7) != 0) return false;
    p += 7;
    const char *r_start = p;
    while (p < end && *p != ' ') p++;
    size_t r_len = (size_t)(p - r_start);
    if (r_len == 0) return false;
    if (r_len >= CRI_REASON_MAX) r_len = CRI_REASON_MAX - 1;
    memcpy(out->reason, r_start, r_len);
    out->reason[r_len] = '\0';
    if (p >= end || *p != ' ') return false;
    p++;

    /* dos=<N>  — accept digits until end or space. */
    if ((size_t)(end - p) < 4) return false;
    if (memcmp(p, "dos=", 4) != 0) return false;
    p += 4;
    int dos = 0;
    bool any = false;
    while (p < end && *p >= '0' && *p <= '9') {
        dos = dos * 10 + (*p - '0');
        p++; any = true;
    }
    if (!any) return false;
    out->dos = dos;
    out->kind = kind;
    out->ts_us = cri_now_us();
    return true;
}

/* ── Event observer ─────────────────────────────────────────── */

static void cri_observer(enum event_type type, uint32_t peer_id,
                          const void *payload, uint32_t payload_len,
                          void *ctx)
{
    (void)peer_id; (void)ctx;
    enum cri_kind kind;
    if (type == EV_CONSENSUS_REJECT_TX)         kind = CRI_KIND_TX;
    else if (type == EV_CONSENSUS_REJECT_BLOCK) kind = CRI_KIND_BLOCK;
    else return;

    struct cri_entry entry;
    memset(&entry, 0, sizeof(entry));
    if (!cri_parse_payload(payload, payload_len, kind, &entry))
        return;

    pthread_mutex_lock(&g_cri.lock);
    if (g_cri.running) cri_write_locked(&entry);
    pthread_mutex_unlock(&g_cri.lock);
}

/* ── Lifecycle ──────────────────────────────────────────────── */

struct zcl_result consensus_reject_index_start(size_t capacity)
{
    pthread_mutex_lock(&g_cri.lock);
    if (g_cri.running) {
        pthread_mutex_unlock(&g_cri.lock);
        return ZCL_OK;
    }
    size_t cap = capacity == 0 ? CRI_DEFAULT_CAPACITY : round_pow2(capacity);
    struct cri_entry *ring = zcl_calloc(cap, sizeof(*ring), "cri ring buffer");
    if (!ring) {
        pthread_mutex_unlock(&g_cri.lock);
        return ZCL_ERR(-1, "calloc failed for ring capacity %zu", cap);
    }
    g_cri.ring       = ring;
    g_cri.capacity   = cap;
    g_cri.mask       = cap - 1;
    g_cri.count      = 0;
    g_cri.write_pos  = 0;
    g_cri.total      = 0;
    g_cri.running    = true;
    pthread_mutex_unlock(&g_cri.lock);

    /* Register observers OUTSIDE the lock so the event system can't
     * re-enter us while we hold our own mutex. */
    event_observe(EV_CONSENSUS_REJECT_TX,    cri_observer, NULL);
    event_observe(EV_CONSENSUS_REJECT_BLOCK, cri_observer, NULL);
    return ZCL_OK;
}

void consensus_reject_index_stop(void)
{
    /* Drop observers first so no more writes race with free(). */
    event_clear_observers(EV_CONSENSUS_REJECT_TX);
    event_clear_observers(EV_CONSENSUS_REJECT_BLOCK);

    pthread_mutex_lock(&g_cri.lock);
    free(g_cri.ring);
    g_cri.ring      = NULL;
    g_cri.capacity  = 0;
    g_cri.mask      = 0;
    g_cri.count     = 0;
    g_cri.write_pos = 0;
    g_cri.total     = 0;
    g_cri.running   = false;
    pthread_mutex_unlock(&g_cri.lock);
}

bool consensus_reject_index_running(void)
{
    pthread_mutex_lock(&g_cri.lock);
    bool r = g_cri.running;
    pthread_mutex_unlock(&g_cri.lock);
    return r;
}

void consensus_reject_index_clear(void)
{
    pthread_mutex_lock(&g_cri.lock);
    if (g_cri.running && g_cri.ring) {
        memset(g_cri.ring, 0, g_cri.capacity * sizeof(*g_cri.ring));
        g_cri.count     = 0;
        g_cri.write_pos = 0;
        g_cri.total     = 0;
    }
    pthread_mutex_unlock(&g_cri.lock);
}

/* ── Queries ────────────────────────────────────────────────── */

uint64_t consensus_reject_index_total(void)
{
    pthread_mutex_lock(&g_cri.lock);
    uint64_t t = g_cri.total;
    pthread_mutex_unlock(&g_cri.lock);
    return t;
}

size_t consensus_reject_index_count(void)
{
    pthread_mutex_lock(&g_cri.lock);
    size_t c = g_cri.count;
    pthread_mutex_unlock(&g_cri.lock);
    return c;
}

size_t consensus_reject_index_capacity(void)
{
    pthread_mutex_lock(&g_cri.lock);
    size_t c = g_cri.capacity;
    pthread_mutex_unlock(&g_cri.lock);
    return c;
}

struct zcl_result consensus_reject_index_lookup(const struct uint256 *hash,
                                                 const enum cri_kind *kind,
                                                 struct cri_entry *out)
{
    if (!hash || !out) {
        LOG_WARN("consensus_reject",
                 "lookup called with null hash or out pointer");
        return ZCL_ERR(-1,
                       "consensus_reject_index_lookup: null hash or out pointer");
    }
    bool found = false;
    pthread_mutex_lock(&g_cri.lock);
    if (g_cri.running && g_cri.count > 0) {
        /* Walk backwards from write head: newest match wins. */
        for (size_t i = 0; i < g_cri.count; i++) {
            size_t idx = (g_cri.write_pos - 1 - i) & g_cri.mask;
            const struct cri_entry *e = &g_cri.ring[idx];
            if (!uint256_eq(&e->hash, hash)) continue;
            if (kind && *kind != e->kind) continue;
            *out = *e;
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_cri.lock);
    if (!found) {
        char hex[65];
        uint256_get_hex(hash, hex);
        return ZCL_ERR(-2,
                       "consensus_reject_index_lookup: no match for hash=%s",
                       hex);
    }
    return ZCL_OK;
}

size_t consensus_reject_index_recent(struct cri_entry *out, size_t cap)
{
    if (!out || cap == 0) return 0;
    size_t n = 0;
    pthread_mutex_lock(&g_cri.lock);
    if (g_cri.running && g_cri.count > 0) {
        size_t limit = g_cri.count < cap ? g_cri.count : cap;
        for (size_t i = 0; i < limit; i++) {
            size_t idx = (g_cri.write_pos - 1 - i) & g_cri.mask;
            out[n++] = g_cri.ring[idx];
        }
    }
    pthread_mutex_unlock(&g_cri.lock);
    return n;
}

void consensus_reject_index_record(const struct cri_entry *e)
{
    if (!e) return;
    pthread_mutex_lock(&g_cri.lock);
    if (g_cri.running) cri_write_locked(e);
    pthread_mutex_unlock(&g_cri.lock);
}

static const char *cri_kind_name(enum cri_kind k)
{
    return k == CRI_KIND_BLOCK ? "block" : "tx";
}

/* Cap on entries returned by the dumper — independent of the ring's own
 * (up to CRI_MAX_CAPACITY) capacity, so this function's stack frame stays
 * small regardless of how the service was started. */
#define CRI_DUMP_MAX_RECENT 64

/* See CLAUDE.md "Adding state introspection". Reentrant-safe: every field
 * read goes through the existing mutex-guarded accessors. `key`, if given,
 * is parsed as the max number of recent entries to return (default 20,
 * clamped to CRI_DUMP_MAX_RECENT); NULL uses the default. */
bool consensus_reject_index_dump_state_json(struct json_value *out,
                                            const char *key)
{
    if (!out)
        return false;
    json_set_object(out);

    bool running = consensus_reject_index_running();
    json_push_kv_bool(out, "running", running);
    json_push_kv_int(out, "total", (int64_t)consensus_reject_index_total());
    json_push_kv_int(out, "count", (int64_t)consensus_reject_index_count());
    json_push_kv_int(out, "capacity",
                     (int64_t)consensus_reject_index_capacity());

    size_t want = 20;
    if (key && *key) {
        long v = strtol(key, NULL, 10);
        if (v > 0)
            want = (size_t)v;
    }
    if (want > CRI_DUMP_MAX_RECENT)
        want = CRI_DUMP_MAX_RECENT;

    struct cri_entry entries[CRI_DUMP_MAX_RECENT];
    size_t n = want > 0 ? consensus_reject_index_recent(entries, want) : 0;

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < n; i++) {
        char hex[65];
        uint256_get_hex(&entries[i].hash, hex);
        struct json_value child;
        json_init(&child);
        json_set_object(&child);
        json_push_kv_str(&child, "hash", hex);
        json_push_kv_str(&child, "kind", cri_kind_name(entries[i].kind));
        json_push_kv_int(&child, "dos", (int64_t)entries[i].dos);
        json_push_kv_int(&child, "ts_us", entries[i].ts_us);
        json_push_kv_str(&child, "reason", entries[i].reason);
        json_push_back(&arr, &child);
        json_free(&child);
    }
    json_push_kv(out, "recent", &arr);
    json_free(&arr);
    return true;
}
