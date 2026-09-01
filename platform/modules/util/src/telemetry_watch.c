/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * telemetry_watch — the change feed's ring and its diff.
 * Contract, invariants and the missed-window-vs-quiet-period argument:
 * util/telemetry_watch.h. Read that header before changing anything here.
 *
 * THE ONE RULE THIS FILE ENFORCES. Three outcomes must be distinguishable by
 * a reader who has only the reply in front of them:
 *
 *   nothing happened       count 0, gap false, dropped 0
 *   I missed some          count >= 1, gap true, dropped > 0
 *   the feed restarted     epoch_changed true
 *
 * All three are decided in telemetry_watch_read() and nowhere else, so no
 * caller can produce a fourth, ambiguous shape. In particular a GAP always
 * comes back with at least one record: `gap` can only be raised while the ring
 * holds something, and the read then starts AT the oldest held record, so the
 * batch is non-empty by construction rather than by care.
 *
 * WHY A MUTEX AND NOT A SEQLOCK. Publishing writes a ~700-byte slot and
 * reading copies up to sixteen of them; a lock-free publication would need a
 * per-slot generation dance to keep a reader from copying a torn record, and
 * getting that wrong shows up as a corrupt field NAME in an operator's feed.
 * The critical section is a bounded memcpy with no I/O, no allocation and no
 * call-out, on a path that runs at most a few times a second, so the honest
 * trade is a plain mutex. Nothing here can block behind the reducer.
 */

#include "util/telemetry_watch.h"

#include "base/log_macros.h"

#include <pthread.h>
#include <string.h>
#include <unistd.h>

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* Ring state. `g_seq` is the LAST sequence assigned (0 = nothing published
 * yet), `g_held` the number of slots occupied, so the sequences currently
 * addressable are [g_seq - g_held + 1, g_seq]. Deriving the window from two
 * counters rather than storing head/tail indices is what makes the gap
 * arithmetic below a subtraction instead of a modular case analysis. */
static struct telemetry_watch_record g_ring[TELEMETRY_WATCH_RING_CAP];
static uint64_t g_epoch;
static uint64_t g_seq;
static size_t g_held;
static uint64_t g_published_total;
/* Bumped on every epoch mint. Folded into the epoch so two restarts inside
 * one wall-clock second still differ — without it a fast restart looks like a
 * stall, which is the exact confusion the epoch exists to remove. */
static uint64_t g_generation;

/* Mint an epoch. Caller holds the lock.
 *
 * The value only has to be DIFFERENT across restarts of this feed, never
 * ordered and never meaningful, so it mixes the three things that cannot all
 * repeat: the wall clock, this process's pid, and a per-mint counter. The
 * shifts keep each contribution in its own bits rather than letting a small
 * generation cancel a small clock difference. */
static void watch_mint_epoch_locked(void)
{
    g_generation++;
    int64_t now = telemetry_now_unix();
    uint64_t clock_bits = (now > 0) ? (uint64_t)now : 0u;
    uint64_t pid_bits = (uint64_t)(uint32_t)getpid();
    g_epoch = (clock_bits << 24) ^ (pid_bits << 8) ^ g_generation;
    if (g_epoch == 0)
        g_epoch = g_generation; /* 0 is the caller's "I did not check" value */
}

void telemetry_watch_init(void)
{
    pthread_mutex_lock(&g_lock);
    if (g_epoch == 0)
        watch_mint_epoch_locked();
    pthread_mutex_unlock(&g_lock);
}

void telemetry_watch_restart(void)
{
    pthread_mutex_lock(&g_lock);
    memset(g_ring, 0, sizeof g_ring);
    g_seq = 0;
    g_held = 0;
    g_published_total = 0;
    watch_mint_epoch_locked();
    pthread_mutex_unlock(&g_lock);
}

uint64_t telemetry_watch_epoch(void)
{
    pthread_mutex_lock(&g_lock);
    if (g_epoch == 0)
        watch_mint_epoch_locked();
    uint64_t e = g_epoch;
    pthread_mutex_unlock(&g_lock);
    return e;
}

uint64_t telemetry_watch_last_sequence(void)
{
    pthread_mutex_lock(&g_lock);
    uint64_t s = g_seq;
    pthread_mutex_unlock(&g_lock);
    return s;
}

uint64_t telemetry_watch_published_total(void)
{
    pthread_mutex_lock(&g_lock);
    uint64_t t = g_published_total;
    pthread_mutex_unlock(&g_lock);
    return t;
}

uint64_t telemetry_watch_publish(const struct telemetry_watch_record *rec)
{
    if (!rec)
        LOG_RETURN(0, "telemetry_watch", "publish: record is NULL");

    pthread_mutex_lock(&g_lock);
    if (g_epoch == 0)
        watch_mint_epoch_locked();
    g_seq++;
    struct telemetry_watch_record *slot =
        &g_ring[(size_t)((g_seq - 1) % TELEMETRY_WATCH_RING_CAP)];
    *slot = *rec;
    slot->sequence = g_seq;
    /* A STORED record never carries a drop count: what was lost depends on
     * where the reader is, not on when the record was written. */
    slot->dropped_count = 0;
    if (g_held < TELEMETRY_WATCH_RING_CAP)
        g_held++;
    g_published_total++;
    uint64_t assigned = g_seq;
    pthread_mutex_unlock(&g_lock);
    return assigned;
}

/* Which static token explains this batch. One function so a shape and its
 * explanation can never disagree; the flags are already set when it runs. */
static const char *watch_reason(const struct telemetry_watch_batch *b)
{
    if (b->gap && b->epoch_changed)
        return "feed_restarted_and_the_resume_fell_behind_the_ring";
    if (b->epoch_changed)
        return "feed_restarted_since_this_cursor_was_issued";
    if (b->gap)
        return "resume_fell_behind_the_ring";
    if (b->since_ahead)
        return "cursor_is_ahead_of_the_feed";
    if (b->more)
        return "batch_capped_more_changes_are_waiting";
    if (b->count == 0)
        return "no_change_recorded_after_this_sequence";
    return "every_change_after_this_sequence_delivered";
}

bool telemetry_watch_read(uint64_t since, uint64_t since_epoch,
                          size_t max_records,
                          struct telemetry_watch_batch *out)
{
    if (!out)
        LOG_FAIL("telemetry_watch", "read: out batch is NULL");
    memset(out, 0, sizeof *out);
    out->since = since;

    /* A gapped batch must never be empty, so a request for zero records is
     * not honoured as zero — it is raised to one. Clamped at the top for the
     * caller's own buffer. */
    if (max_records == 0)
        max_records = 1;
    if (max_records > TELEMETRY_WATCH_BATCH_MAX)
        max_records = TELEMETRY_WATCH_BATCH_MAX;

    pthread_mutex_lock(&g_lock);
    if (g_epoch == 0)
        watch_mint_epoch_locked();

    out->epoch = g_epoch;
    out->last_sequence = g_seq;
    out->oldest_sequence = g_held ? (g_seq - (uint64_t)g_held + 1u) : 0u;
    out->published_total = g_published_total;

    uint64_t effective = since;
    if (since_epoch != 0 && since_epoch != g_epoch) {
        /* The cursor was minted by a feed that no longer exists. It addresses
         * nothing here, so it is dropped rather than applied to sequences it
         * was never about — and the caller is told, because silently serving
         * "everything after 41" out of a fresh feed is how a restart gets
         * mistaken for a quiet period. */
        out->epoch_changed = true;
        effective = 0;
    }
    if (effective > g_seq) {
        out->since_ahead = true;
        effective = g_seq;
    }

    uint64_t first = effective + 1u;
    if (g_held > 0 && first < out->oldest_sequence) {
        out->gap = true;
        out->dropped_count = out->oldest_sequence - first;
        first = out->oldest_sequence;
    }

    for (uint64_t s = first; s <= g_seq && out->count < max_records; s++) {
        out->records[out->count] =
            g_ring[(size_t)((s - 1) % TELEMETRY_WATCH_RING_CAP)];
        out->count++;
    }

    if (out->count > 0) {
        out->next_since = out->records[out->count - 1].sequence;
        out->more = out->next_since < g_seq;
        /* Stamp the loss on the first record too: an agent that consumes the
         * array one entry at a time must see the gap without also having to
         * parse the envelope it arrived in. */
        out->records[0].dropped_count = out->dropped_count;
    } else {
        out->next_since = effective;
    }
    pthread_mutex_unlock(&g_lock);

    out->reason = watch_reason(out);
    return true;
}

/* ── the diff ────────────────────────────────────────────────────────────
 * Generic over any domain schema: every name it produces is a descriptor
 * row's own `key`, so this file spells no field name and a table that gains a
 * row is diffed with no edit here. */

static const struct telemetry_leaf_meta *watch_meta(const void *snap,
                                                    const struct telemetry_leaf *lf)
{
    return (const struct telemetry_leaf_meta *)(const void *)
        ((const char *)snap + lf->meta_off);
}

/* Did this leaf's OBSERVABLE state move? Presence first: a leaf that went from
 * PRESENT to UNAVAILABLE is a change an operator must see, and comparing only
 * the stale value bytes behind it would hide that completely. */
static bool watch_leaf_changed(const struct telemetry_leaf *lf,
                               const void *prev, const void *cur)
{
    const struct telemetry_leaf_meta *pm = watch_meta(prev, lf);
    const struct telemetry_leaf_meta *cm = watch_meta(cur, lf);
    if (pm->presence != cm->presence)
        return true;
    if (cm->presence != TELEMETRY_PRESENT)
        return false; /* two unreadable samples are not a change */

    const char *pv = (const char *)prev + lf->value_off;
    const char *cv = (const char *)cur + lf->value_off;
    switch (lf->ctype) {
    case TLC_I64:
        return memcmp(pv, cv, sizeof(int64_t)) != 0;
    case TLC_BOOL:
        return memcmp(pv, cv, sizeof(bool)) != 0;
    case TLC_TEXT:
        return strncmp(pv, cv, (size_t)TELEMETRY_TEXT_MAX) != 0;
    }
    return false;
}

size_t telemetry_watch_diff(const struct telemetry_domain_schema *schema,
                            const void *prev, const void *cur,
                            struct telemetry_watch_record *rec)
{
    if (!schema || !prev || !cur || !rec)
        LOG_RETURN(0, "telemetry_watch", "diff: a required argument is NULL");

    rec->changed_count = 0;
    rec->changed_total = 0;
    rec->changed_truncated = false;
    memset(rec->changed_fields, 0, sizeof rec->changed_fields);

    for (size_t i = 0; i < schema->leaf_count; i++) {
        const struct telemetry_leaf *lf = &schema->leaves[i];
        if (strcmp(lf->group, TELEMETRY_WATCH_SELF_GROUP) == 0)
            continue; /* describes the sample, not the node — see the header */
        if (!watch_leaf_changed(lf, prev, cur))
            continue;
        rec->changed_total++;
        if (rec->changed_count < TELEMETRY_WATCH_FIELDS_MAX) {
            char *dst = rec->changed_fields[rec->changed_count];
            size_t n = strlen(lf->key);
            if (n >= TELEMETRY_WATCH_FIELD_MAX)
                n = TELEMETRY_WATCH_FIELD_MAX - 1;
            memcpy(dst, lf->key, n);
            dst[n] = '\0';
            rec->changed_count++;
        } else {
            rec->changed_truncated = true;
        }
    }
    return rec->changed_total;
}
