/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * body_coverage — see storage/body_coverage.h for the design. This file
 * is the pure range algebra, the bounded scan, progress_meta persistence,
 * the gap-fill scheduler, and the global singleton + diagnostics dumper. */

#include "storage/body_coverage.h"
#include "storage/progress_store.h"
#include "json/json.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/sync.h"

#include <string.h>
#include <stdlib.h>

/* ── Lifecycle ──────────────────────────────────────────────────── */

void body_coverage_init(struct body_coverage_map *m)
{
    if (!m)
        return;
    m->ranges = NULL;
    m->count = 0;
    m->cap = 0;
}

void body_coverage_free(struct body_coverage_map *m)
{
    if (!m)
        return;
    free(m->ranges);
    m->ranges = NULL;
    m->count = 0;
    m->cap = 0;
}

void body_coverage_reset(struct body_coverage_map *m)
{
    if (!m)
        return;
    m->count = 0;
}

/* Grow to hold at least `need` ranges. Doubles. Returns false on OOM. */
static bool bc_ensure_cap(struct body_coverage_map *m, size_t need)
{
    if (m->cap >= need)
        return true;
    size_t ncap = m->cap ? m->cap : 8;
    while (ncap < need)
        ncap *= 2;
    struct bc_range *nr =
        zcl_realloc(m->ranges, ncap * sizeof(*nr), "body_coverage_ranges");
    if (!nr)
        LOG_FAIL("body_coverage", "grow to %zu ranges failed", ncap);
    m->ranges = nr;
    m->cap = ncap;
    return true;
}

/* ── Pure range algebra ─────────────────────────────────────────── */

bool body_coverage_insert(struct body_coverage_map *m, int64_t lo, int64_t hi)
{
    if (!m)
        return false;
    if (lo < 0 || lo > hi)
        return true; /* no-op: benign empty/invalid insert */

    /* First range not entirely to the left of [lo-1, ...]: i.e. the first
     * range whose hi >= lo-1 (touching or overlapping on the left edge). */
    size_t start = 0;
    while (start < m->count && m->ranges[start].hi < lo - 1)
        start++;

    /* Absorb every following range that starts within [.., hi+1] (touching
     * or overlapping on the right edge). Because the map is sorted and
     * disjoint, these are contiguous starting at `start`. */
    int64_t new_lo = lo;
    int64_t new_hi = hi;
    size_t end = start;
    while (end < m->count && m->ranges[end].lo <= hi + 1) {
        if (m->ranges[end].lo < new_lo)
            new_lo = m->ranges[end].lo;
        if (m->ranges[end].hi > new_hi)
            new_hi = m->ranges[end].hi;
        end++;
    }

    size_t absorbed = end - start;
    if (absorbed == 1) {
        /* Common path: exactly one range absorbed (or extended). */
        m->ranges[start].lo = new_lo;
        m->ranges[start].hi = new_hi;
        return true;
    }

    if (absorbed == 0) {
        /* Pure insert of a new disjoint range at `start`. */
        if (!bc_ensure_cap(m, m->count + 1))
            return false;
        memmove(&m->ranges[start + 1], &m->ranges[start],
                (m->count - start) * sizeof(m->ranges[0]));
        m->ranges[start].lo = new_lo;
        m->ranges[start].hi = new_hi;
        m->count++;
        return true;
    }

    /* absorbed >= 2: collapse [start, end) into one merged range. */
    m->ranges[start].lo = new_lo;
    m->ranges[start].hi = new_hi;
    size_t tail = m->count - end;
    if (tail > 0)
        memmove(&m->ranges[start + 1], &m->ranges[end],
                tail * sizeof(m->ranges[0]));
    m->count -= (absorbed - 1);
    return true;
}

bool body_coverage_remove(struct body_coverage_map *m, int64_t lo, int64_t hi)
{
    if (!m)
        return false;
    if (lo < 0 || lo > hi || m->count == 0)
        return true;

    /* Rebuild into a scratch buffer: correctness over cleverness. A single
     * removal can split at most one range, so count+1 is the worst case. */
    struct bc_range *scratch =
        zcl_malloc((m->count + 1) * sizeof(*scratch), "body_coverage_remove");
    if (!scratch)
        LOG_FAIL("body_coverage", "remove scratch alloc failed");

    size_t n = 0;
    for (size_t i = 0; i < m->count; i++) {
        struct bc_range r = m->ranges[i];
        if (r.hi < lo || r.lo > hi) {
            scratch[n++] = r; /* untouched */
            continue;
        }
        /* Overlaps [lo, hi]. Keep the left remnant [r.lo, lo-1] and the
         * right remnant [hi+1, r.hi] if non-empty. */
        if (r.lo < lo) {
            scratch[n].lo = r.lo;
            scratch[n].hi = lo - 1;
            n++;
        }
        if (r.hi > hi) {
            scratch[n].lo = hi + 1;
            scratch[n].hi = r.hi;
            n++;
        }
    }

    if (n > m->cap) {
        if (!bc_ensure_cap(m, n)) {
            free(scratch);
            return false;
        }
    }
    memcpy(m->ranges, scratch, n * sizeof(*scratch));
    m->count = n;
    free(scratch);
    return true;
}

bool body_coverage_contains(const struct body_coverage_map *m, int64_t h)
{
    if (!m || h < 0)
        return false;
    /* Binary search: ranges are sorted, disjoint, non-adjacent. */
    size_t lo = 0, hi = m->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (m->ranges[mid].hi < h)
            lo = mid + 1;
        else if (m->ranges[mid].lo > h)
            hi = mid;
        else
            return true;
    }
    return false;
}

bool body_coverage_find_first_hole(const struct body_coverage_map *m,
                                   int64_t from, int64_t to,
                                   struct bc_range *out)
{
    if (!out || !m || from < 0 || from > to)
        return false;

    int64_t cursor = from;
    for (size_t i = 0; i < m->count && cursor <= to; i++) {
        const struct bc_range *r = &m->ranges[i];
        if (r->hi < cursor)
            continue; /* range entirely below the cursor */
        if (r->lo > to)
            break;    /* remaining ranges are all above the window */
        if (r->lo > cursor) {
            /* Hole [cursor, min(r->lo-1, to)]. */
            out->lo = cursor;
            out->hi = r->lo - 1 < to ? r->lo - 1 : to;
            return true;
        }
        /* r covers cursor — advance past it. */
        if (r->hi + 1 > cursor)
            cursor = r->hi + 1;
    }
    if (cursor <= to) {
        out->lo = cursor;
        out->hi = to;
        return true;
    }
    return false;
}

int64_t body_coverage_total_covered(const struct body_coverage_map *m)
{
    if (!m)
        return 0;
    int64_t total = 0;
    for (size_t i = 0; i < m->count; i++)
        total += m->ranges[i].hi - m->ranges[i].lo + 1;
    return total;
}

int64_t body_coverage_covered_in_window(const struct body_coverage_map *m,
                                        int64_t lo, int64_t hi)
{
    if (!m || lo < 0 || lo > hi)
        return 0;
    int64_t total = 0;
    for (size_t i = 0; i < m->count; i++) {
        int64_t rlo = m->ranges[i].lo;
        int64_t rhi = m->ranges[i].hi;
        if (rhi < lo)
            continue;
        if (rlo > hi)
            break; /* sorted: nothing further can overlap */
        if (rlo < lo)
            rlo = lo;
        if (rhi > hi)
            rhi = hi;
        total += rhi - rlo + 1;
    }
    return total;
}

bool body_coverage_union_into(struct body_coverage_map *dst,
                              const struct body_coverage_map *src)
{
    if (!dst || !src)
        LOG_FAIL("body_coverage", "union_into: null dst or src");
    for (size_t i = 0; i < src->count; i++) {
        if (!body_coverage_insert(dst, src->ranges[i].lo, src->ranges[i].hi))
            LOG_FAIL("body_coverage", "union_into: insert %zu failed", i);
    }
    return true;
}

size_t body_coverage_range_count(const struct body_coverage_map *m)
{
    return m ? m->count : 0;
}

int64_t body_coverage_max_covered(const struct body_coverage_map *m)
{
    if (!m || m->count == 0)
        return -1;
    return m->ranges[m->count - 1].hi;
}

/* ── Bounded-scan builder ───────────────────────────────────────── */

size_t body_coverage_scan_window(struct body_coverage_map *m,
                                  int64_t lo, int64_t hi,
                                  bool (*have_data)(int64_t h, void *ctx),
                                  void *ctx)
{
    if (!m || !have_data || lo < 0 || lo > hi)
        return 0;
    size_t inserted = 0;
    /* Coalesce contiguous have-data runs into one insert to keep the map
     * minimal and the scan O(window) inserts-amortized. */
    int64_t run_lo = -1;
    for (int64_t h = lo; h <= hi; h++) {
        if (have_data(h, ctx)) {
            if (run_lo < 0)
                run_lo = h;
        } else if (run_lo >= 0) {
            if (body_coverage_insert(m, run_lo, h - 1))
                inserted += (size_t)(h - run_lo);
            run_lo = -1;
        }
    }
    if (run_lo >= 0 && body_coverage_insert(m, run_lo, hi))
        inserted += (size_t)(hi - run_lo + 1);
    return inserted;
}

/* ── Persistence (progress_meta blob) ───────────────────────────── */

/* Blob layout (native byte order, matching the progress_meta idiom used by
 * legacy_attach_tip_height): [u32 magic][u32 version][u32 count][count * {
 * i64 lo, i64 hi }]. */
#define BC_BLOB_MAGIC   0x42434f56u /* "BCOV" */
#define BC_BLOB_VERSION 1u

bool body_coverage_save_key(const struct body_coverage_map *m,
                            struct sqlite3 *db, const char *key)
{
    if (!m || !db || !key)
        LOG_FAIL("body_coverage", "save: null map, db or key");

    size_t n = m->count;
    if (n > BODY_COVERAGE_PERSIST_MAX_RANGES) {
        LOG_WARN("body_coverage",
                 "persist truncated: %zu ranges > cap %u (keeping lowest)",
                 n, (unsigned)BODY_COVERAGE_PERSIST_MAX_RANGES);
        n = BODY_COVERAGE_PERSIST_MAX_RANGES;
    }

    size_t hdr = 3 * sizeof(uint32_t);
    size_t body = n * 2 * sizeof(int64_t);
    size_t total = hdr + body;
    uint8_t *buf = zcl_malloc(total, "body_coverage_save");
    if (!buf)
        LOG_FAIL("body_coverage", "save: alloc %zu failed", total);

    uint32_t magic = BC_BLOB_MAGIC, ver = BC_BLOB_VERSION, cnt = (uint32_t)n;
    memcpy(buf + 0, &magic, sizeof(magic));
    memcpy(buf + 4, &ver, sizeof(ver));
    memcpy(buf + 8, &cnt, sizeof(cnt));
    size_t off = hdr;
    for (size_t i = 0; i < n; i++) {
        memcpy(buf + off, &m->ranges[i].lo, sizeof(int64_t));
        off += sizeof(int64_t);
        memcpy(buf + off, &m->ranges[i].hi, sizeof(int64_t));
        off += sizeof(int64_t);
    }

    bool ok = progress_meta_set(db, key, buf, total);
    free(buf);
    if (!ok)
        LOG_FAIL("body_coverage", "save: progress_meta_set failed");
    return true;
}

bool body_coverage_load_key(struct body_coverage_map *m,
                            struct sqlite3 *db, const char *key)
{
    if (!m || !db || !key)
        LOG_FAIL("body_coverage", "load: null map, db or key");
    body_coverage_reset(m);

    size_t blob_len = 0;
    bool found = false;
    if (!progress_meta_get(db, key, NULL, 0,
                           &blob_len, &found))
        LOG_FAIL("body_coverage", "load: progress_meta_get(len) failed");
    if (!found)
        return true; /* fresh datadir: no coverage yet */

    size_t hdr = 3 * sizeof(uint32_t);
    if (blob_len < hdr)
        LOG_FAIL("body_coverage", "load: blob too small (%zu)", blob_len);

    uint8_t *buf = zcl_malloc(blob_len, "body_coverage_load");
    if (!buf)
        LOG_FAIL("body_coverage", "load: alloc %zu failed", blob_len);
    size_t got = 0;
    bool found2 = false;
    if (!progress_meta_get(db, key, buf, blob_len,
                           &got, &found2) || !found2 || got != blob_len) {
        free(buf);
        LOG_FAIL("body_coverage", "load: progress_meta_get(read) short/failed");
    }

    uint32_t magic = 0, ver = 0, cnt = 0;
    memcpy(&magic, buf + 0, sizeof(magic));
    memcpy(&ver, buf + 4, sizeof(ver));
    memcpy(&cnt, buf + 8, sizeof(cnt));
    if (magic != BC_BLOB_MAGIC || ver != BC_BLOB_VERSION) {
        free(buf);
        LOG_FAIL("body_coverage", "load: bad magic/version %08x/%u",
                 magic, ver);
    }
    size_t need = hdr + (size_t)cnt * 2 * sizeof(int64_t);
    if (need != blob_len) {
        free(buf);
        LOG_FAIL("body_coverage", "load: length mismatch cnt=%u len=%zu",
                 cnt, blob_len);
    }

    /* Re-insert every range: insert enforces the sorted/disjoint invariant,
     * so even a resaved-then-mutated blob loads to a normalized map. */
    size_t off = hdr;
    for (uint32_t i = 0; i < cnt; i++) {
        int64_t lo = 0, hi = 0;
        memcpy(&lo, buf + off, sizeof(int64_t));
        off += sizeof(int64_t);
        memcpy(&hi, buf + off, sizeof(int64_t));
        off += sizeof(int64_t);
        if (!body_coverage_insert(m, lo, hi)) {
            free(buf);
            body_coverage_reset(m);
            LOG_FAIL("body_coverage", "load: insert failed at %u", i);
        }
    }
    free(buf);
    return true;
}

bool body_coverage_save(const struct body_coverage_map *m, struct sqlite3 *db)
{
    return body_coverage_save_key(m, db, BODY_COVERAGE_META_KEY);
}

bool body_coverage_load(struct body_coverage_map *m, struct sqlite3 *db)
{
    return body_coverage_load_key(m, db, BODY_COVERAGE_META_KEY);
}

/* ── Gap-fill scheduler ─────────────────────────────────────────── */

void body_coverage_scheduler_init(struct body_coverage_scheduler *s)
{
    if (!s)
        return;
    memset(s, 0, sizeof(*s));
    s->needed_lo = -1;
    s->needed_hi = -1;
    s->last_total_covered = -1;
}

bool body_coverage_scheduler_plan(struct body_coverage_scheduler *s,
                                   const struct body_coverage_map *map,
                                   int64_t needed_lo, int64_t needed_hi,
                                   int64_t now_unix,
                                   struct bc_range *out_hole)
{
    if (!s || !map)
        return false;

    s->plans++;
    s->needed_lo = needed_lo;
    s->needed_hi = needed_hi;

    /* Fill rate: covered-heights delta over wall time since the last plan. */
    int64_t total = body_coverage_total_covered(map);
    if (s->last_total_covered >= 0 && s->last_plan_unix > 0 &&
        now_unix > s->last_plan_unix) {
        int64_t dcov = total - s->last_total_covered;
        if (dcov < 0)
            dcov = 0; /* prune shrank coverage; not a fill */
        s->fill_rate_per_sec =
            (double)dcov / (double)(now_unix - s->last_plan_unix);
    }
    s->last_total_covered = total;
    s->last_plan_unix = now_unix;

    struct bc_range hole;
    if (needed_lo < 0 || needed_lo > needed_hi ||
        !body_coverage_find_first_hole(map, needed_lo, needed_hi, &hole)) {
        /* Needed range fully covered — no work, and any prior no-source
         * latch is stale (the range resolved). */
        s->has_active_hole = false;
        body_coverage_scheduler_clear_no_source(s);
        return false;
    }

    s->active_hole = hole;
    s->has_active_hole = true;
    s->holes_seen++;
    if (out_hole)
        *out_hole = hole;
    return true;
}

void body_coverage_scheduler_mark_enqueued(struct body_coverage_scheduler *s)
{
    if (!s)
        return;
    /* Work was handed to the download manager — a source exists this pass. */
    body_coverage_scheduler_clear_no_source(s);
}

void body_coverage_scheduler_mark_no_source(struct body_coverage_scheduler *s,
                                            int64_t now_unix)
{
    if (!s)
        return;
    if (!s->blocked_no_source) {
        s->blocked_no_source = true;
        s->blocked_since_unix = now_unix;
        s->no_source_fires++;
    }
}

void body_coverage_scheduler_clear_no_source(struct body_coverage_scheduler *s)
{
    if (!s)
        return;
    s->blocked_no_source = false;
    s->blocked_since_unix = 0;
}

/* ── Global singleton + diagnostics ─────────────────────────────── */

static struct body_coverage_map       g_bc_map;
static struct body_coverage_scheduler g_bc_sched;
static zcl_mutex_t                     g_bc_lock;
static bool                            g_bc_inited = false;

static void bc_global_init_once(void)
{
    if (g_bc_inited)
        return;
    zcl_mutex_init(&g_bc_lock);
    body_coverage_init(&g_bc_map);
    body_coverage_scheduler_init(&g_bc_sched);
    g_bc_inited = true;
}

struct body_coverage_map *body_coverage_global_map(void)
{
    bc_global_init_once();
    return &g_bc_map;
}

struct body_coverage_scheduler *body_coverage_global_scheduler(void)
{
    bc_global_init_once();
    return &g_bc_sched;
}

void body_coverage_global_lock(void)
{
    bc_global_init_once();
    zcl_mutex_lock(&g_bc_lock);
}

void body_coverage_global_unlock(void)
{
    if (!g_bc_inited)
        return;
    zcl_mutex_unlock(&g_bc_lock);
}

/* Cap on ranges/holes emitted into the dump so `dumpstate body_coverage`
 * stays bounded regardless of fragmentation. */
#define BC_DUMP_MAX_RANGES 32
#define BC_DUMP_MAX_HOLES  32

bool body_coverage_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    body_coverage_global_lock();
    const struct body_coverage_map *m = &g_bc_map;
    const struct body_coverage_scheduler *s = &g_bc_sched;

    json_push_kv_int(out, "total_covered", body_coverage_total_covered(m));
    json_push_kv_int(out, "range_count", (int64_t)m->count);
    json_push_kv_int(out, "max_covered", body_coverage_max_covered(m));

    /* First few covered ranges (the coverage shape). */
    struct json_value ranges;
    json_init(&ranges);
    json_set_array(&ranges);
    size_t rn = m->count < BC_DUMP_MAX_RANGES ? m->count : BC_DUMP_MAX_RANGES;
    for (size_t i = 0; i < rn; i++) {
        struct json_value it;
        json_init(&it);
        json_set_object(&it);
        json_push_kv_int(&it, "lo", m->ranges[i].lo);
        json_push_kv_int(&it, "hi", m->ranges[i].hi);
        json_push_back(&ranges, &it);
        json_free(&it);
    }
    json_push_kv(out, "ranges", &ranges);
    json_free(&ranges);
    json_push_kv_bool(out, "ranges_truncated", m->count > rn);

    /* Scheduler view: needed range, active hole, holes within it, rate,
     * blocker. */
    struct json_value sched;
    json_init(&sched);
    json_set_object(&sched);
    json_push_kv_int(&sched, "needed_lo", s->needed_lo);
    json_push_kv_int(&sched, "needed_hi", s->needed_hi);
    json_push_kv_bool(&sched, "has_active_hole", s->has_active_hole);
    if (s->has_active_hole) {
        json_push_kv_int(&sched, "active_hole_lo", s->active_hole.lo);
        json_push_kv_int(&sched, "active_hole_hi", s->active_hole.hi);
    }
    json_push_kv_int(&sched, "fill_rate_per_sec",
                     (int64_t)(s->fill_rate_per_sec + 0.5));
    json_push_kv_int(&sched, "plans", (int64_t)s->plans);
    json_push_kv_int(&sched, "holes_seen", (int64_t)s->holes_seen);
    json_push_kv_bool(&sched, "blocked_no_source", s->blocked_no_source);
    json_push_kv_str(&sched, "blocker_id",
                     s->blocked_no_source ? BODY_COVERAGE_NO_SOURCE_BLOCKER
                                          : "");
    json_push_kv_int(&sched, "blocked_since_unix", s->blocked_since_unix);
    json_push_kv_int(&sched, "no_source_fires", (int64_t)s->no_source_fires);

    /* Enumerate the holes inside the needed window (bounded). */
    struct json_value holes;
    json_init(&holes);
    json_set_array(&holes);
    size_t emitted = 0;
    if (s->needed_lo >= 0 && s->needed_lo <= s->needed_hi) {
        int64_t cursor = s->needed_lo;
        while (emitted < BC_DUMP_MAX_HOLES) {
            struct bc_range hole;
            if (!body_coverage_find_first_hole(m, cursor, s->needed_hi, &hole))
                break;
            struct json_value it;
            json_init(&it);
            json_set_object(&it);
            json_push_kv_int(&it, "lo", hole.lo);
            json_push_kv_int(&it, "hi", hole.hi);
            json_push_back(&holes, &it);
            json_free(&it);
            emitted++;
            if (hole.hi >= s->needed_hi)
                break;
            cursor = hole.hi + 1;
        }
    }
    json_push_kv(&sched, "holes", &holes);
    json_free(&holes);

    json_push_kv(out, "scheduler", &sched);
    json_free(&sched);

    body_coverage_global_unlock();
    return true;
}
