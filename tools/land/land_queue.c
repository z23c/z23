/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The replay and the four write paths described in land_queue.h.
 *
 * Replay is the only place queue state is ever computed. A write appends a
 * frame and then applies that one frame to the in-memory replay, so the two
 * can never drift: there is no code that sets a state without a frame on
 * disk saying so.
 */

#include "land_queue.h"

#include "base/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

struct gate_row {
    uint64_t seq;
    struct land_gate_run run;
};

struct land_queue {
    struct zcl_chainlog *log;
    struct land_entry *entries;
    size_t entry_count;
    size_t entry_cap;
    struct gate_row *gates;
    size_t gate_count;
    size_t gate_cap;
};

const char *land_status_label(enum land_status s)
{
    switch (s) {
    case LAND_OK:                   return "ok";
    case LAND_ERR_ARGUMENT:         return "argument";
    case LAND_ERR_LOG:              return "log";
    case LAND_ERR_ENCODE:           return "encode";
    case LAND_ERR_UNKNOWN_SEQ:      return "unknown-submission";
    case LAND_ERR_ALREADY_FINAL:    return "already-final";
    case LAND_ERR_NO_GATE_RUN:      return "no-gate-run";
    case LAND_ERR_GATE_NOT_GREEN:   return "gate-not-green";
    case LAND_ERR_GATE_NOT_STRESSED:return "gate-skipped-groups";
    case LAND_ERR_GATE_UNIDENTIFIED:return "gate-tree-unidentified";
    }
    return "unknown";
}

/* ── growth ───────────────────────────────────────────────────────────── */

/* One growth routine for both arrays. Written once rather than twice
 * because two copies differing only in an element type is exactly the shape
 * where one of them later gets a fix the other does not. */
static bool reserve(void **items, size_t *cap, size_t want, size_t elem,
                    const char *label)
{
    if (want <= *cap)
        return true;
    size_t next = *cap ? *cap * 2 : 16;
    while (next < want)
        next *= 2;
    void *grown = zcl_realloc(*items, next * elem, label);
    if (!grown)
        return false;
    *items = grown;
    *cap = next;
    return true;
}

static bool entries_reserve(struct land_queue *q, size_t want)
{
    return reserve((void **)&q->entries, &q->entry_cap, want,
                   sizeof *q->entries, "land_queue_entries");
}

static bool gates_reserve(struct land_queue *q, size_t want)
{
    return reserve((void **)&q->gates, &q->gate_cap, want, sizeof *q->gates,
                   "land_queue_gates");
}

/* ── lookups ──────────────────────────────────────────────────────────── */

static struct land_entry *entry_by_seq(struct land_queue *q, uint64_t seq)
{
    for (size_t i = 0; i < q->entry_count; i++)
        if (q->entries[i].seq == seq)
            return &q->entries[i];
    return NULL;
}

static const struct gate_row *gate_by_seq(const struct land_queue *q,
                                          uint64_t seq)
{
    for (size_t i = 0; i < q->gate_count; i++)
        if (q->gates[i].seq == seq)
            return &q->gates[i];
    return NULL;
}

static bool gate_contains(const struct land_gate_run *g, uint64_t seq)
{
    for (uint32_t i = 0; i < g->member_count; i++)
        if (g->member_seq[i] == seq)
            return true;
    return false;
}

enum land_status land_queue_check_landable(const struct land_queue *q,
                                           uint64_t submit_seq,
                                           uint64_t gate_run_seq)
{
    if (!q || submit_seq == 0)
        return LAND_ERR_ARGUMENT;
    /* Order matters for the diagnosis a person reads. "You never ran a gate"
     * and "the gate you ran was red" are different conversations. */
    if (gate_run_seq == 0)
        return LAND_ERR_NO_GATE_RUN;
    const struct gate_row *row = gate_by_seq(q, gate_run_seq);
    if (!row || !gate_contains(&row->run, submit_seq))
        return LAND_ERR_NO_GATE_RUN;
    if (row->run.outcome != LAND_GATE_GREEN)
        return LAND_ERR_GATE_NOT_GREEN;
    if (!row->run.stress)
        return LAND_ERR_GATE_NOT_STRESSED;
    /* An all-zero gate identity is the value "nobody can say which tree this
     * was". A landing behind one is a pass no second machine can check, so
     * it is refused here rather than published as something it is not. */
    static const uint8_t no_gate[LAND_GATE_ID_BYTES] = { 0 };
    if (memcmp(row->run.gate_id, no_gate, LAND_GATE_ID_BYTES) == 0)
        return LAND_ERR_GATE_UNIDENTIFIED;
    return LAND_OK;
}

/* ── applying one frame to the replay ─────────────────────────────────── */

static bool apply_submit(struct land_queue *q, uint64_t seq,
                         const struct land_submit *s)
{
    if (!entries_reserve(q, q->entry_count + 1))
        return false;
    struct land_entry *e = &q->entries[q->entry_count++];
    memset(e, 0, sizeof *e);
    e->seq = seq;
    e->submit = *s;
    e->state = LAND_STATE_QUEUED;
    e->landing_backed = true; /* nothing has claimed a landing yet */
    return true;
}

/* "How far down the queue am I, and how big is the batch I am in" — the
 * answer to "why is it not done yet". Derived, never stored, so it can never
 * disagree with the frames. O(n) over a queue that is at most a few hundred
 * entries deep, and it runs only when something actually changed. */
static void refresh_positions(struct land_queue *q)
{
    uint32_t ahead = 0;
    for (size_t i = 0; i < q->entry_count; i++) {
        struct land_entry *e = &q->entries[i];
        if (e->state == LAND_STATE_QUEUED) {
            e->ahead = ahead;
            ahead++;
        } else {
            e->ahead = 0;
        }
    }
}

static bool apply_gate_run(struct land_queue *q, uint64_t seq,
                           const struct land_gate_run *g)
{
    if (!gates_reserve(q, q->gate_count + 1))
        return false;
    struct gate_row *row = &q->gates[q->gate_count++];
    row->seq = seq;
    row->run = *g;
    for (uint32_t i = 0; i < g->member_count; i++) {
        struct land_entry *e = entry_by_seq(q, g->member_seq[i]);
        if (!e)
            continue; /* a member naming nothing is caught by the writer */
        e->gate_runs++;
        e->gate_run_seq = seq;
        e->batch_size = g->member_count;
        memcpy(e->gate_id, g->gate_id, LAND_GATE_ID_BYTES);
        e->gate_stress = g->stress;
        /* A settled submission is not dragged back into GATING by a later
         * batch that happened to re-include it. */
        if (e->state == LAND_STATE_QUEUED)
            e->state = LAND_STATE_GATING;
    }
    return true;
}

static void apply_verdict(struct land_queue *q, const struct land_verdict *v)
{
    struct land_entry *e = entry_by_seq(q, v->submit_seq);
    if (!e)
        return; /* a verdict for nothing; the writer refuses to create one */
    e->state = v->state;
    e->has_verdict = true;
    e->verdict = *v;
    if (v->state == LAND_STATE_LANDED)
        e->landing_backed =
            land_queue_check_landable(q, v->submit_seq, v->gate_run_seq) ==
            LAND_OK;

    /* The verdict's content address. Taken from the gate run the verdict
     * NAMES rather than from whatever ran most recently, so the digest is
     * about the run that actually decided this submission. A verdict with no
     * gate run behind it (a merge conflict, an abandoned batch) still gets a
     * digest, over an all-zero gate identity — which is the honest value: it
     * says "nothing gated this", and it will never match a digest produced
     * by a run that did. */
    const struct gate_row *row =
        v->gate_run_seq ? gate_by_seq(q, v->gate_run_seq) : NULL;
    static const uint8_t no_gate[LAND_GATE_ID_BYTES] = { 0 };
    land_verdict_digest(v->head, v->integration,
                        row ? row->run.gate_id : no_gate, v->state,
                        row ? row->run.stress : false, e->digest);
    e->has_digest = true;
}

/* ── open / replay / close ────────────────────────────────────────────── */

struct land_queue *land_queue_open(const char *path,
                                   struct zcl_chainlog_report *report)
{
    if (!path || !report)
        return NULL;

    uint8_t stream[32];
    land_stream_id(stream);
    struct zcl_chainlog *log = zcl_chainlog_open(path, stream, report);
    if (!log)
        return NULL;

    struct land_queue *q = zcl_calloc(1, sizeof *q, "land_queue");
    if (!q) {
        zcl_chainlog_close(log);
        report->status = ZCL_CHAINLOG_IO;
        return NULL;
    }
    q->log = log;

    uint64_t total = zcl_chainlog_count(log);
    for (uint64_t seq = 1; seq <= total; seq++) {
        uint8_t buf[ZCL_CHAINLOG_PAYLOAD_MAX];
        size_t len = 0;
        uint32_t kind = 0;
        enum zcl_chainlog_status rs =
            zcl_chainlog_read(log, seq, &kind, buf, sizeof buf, &len);
        if (rs != ZCL_CHAINLOG_OK) {
            report->status = rs;
            report->first_bad_seq = seq;
            land_queue_close(q);
            return NULL;
        }
        bool ok = true;
        if (kind == LAND_KIND_SUBMIT) {
            struct land_submit s;
            ok = land_submit_decode(buf, len, &s) && apply_submit(q, seq, &s);
        } else if (kind == LAND_KIND_GATE_RUN) {
            struct land_gate_run g;
            ok = land_gate_run_decode(buf, len, &g) &&
                 apply_gate_run(q, seq, &g);
        } else if (kind == LAND_KIND_VERDICT) {
            struct land_verdict v;
            ok = land_verdict_decode(buf, len, &v);
            if (ok)
                apply_verdict(q, &v);
        } else {
            /* An unknown kind is a log this build does not understand.
             * Skipping it would mean reporting a state derived from a subset
             * of the history while claiming to have read all of it. */
            ok = false;
        }
        if (!ok) {
            report->status = ZCL_CHAINLOG_FORMAT;
            report->first_bad_seq = seq;
            land_queue_close(q);
            return NULL;
        }
    }
    refresh_positions(q);
    return q;
}

void land_queue_close(struct land_queue *q)
{
    if (!q)
        return;
    if (q->log)
        zcl_chainlog_close(q->log);
    free(q->entries);
    free(q->gates);
    free(q);
}

size_t land_queue_count(const struct land_queue *q)
{
    return q ? q->entry_count : 0;
}

const struct land_entry *land_queue_at(const struct land_queue *q, size_t i)
{
    if (!q || i >= q->entry_count)
        return NULL;
    return &q->entries[i];
}

const struct land_entry *land_queue_find_seq(const struct land_queue *q,
                                             uint64_t seq)
{
    if (!q)
        return NULL;
    for (size_t i = 0; i < q->entry_count; i++)
        if (q->entries[i].seq == seq)
            return &q->entries[i];
    return NULL;
}

const struct land_entry *land_queue_find_branch(const struct land_queue *q,
                                                const char *branch)
{
    if (!q || !branch)
        return NULL;
    const struct land_entry *found = NULL;
    for (size_t i = 0; i < q->entry_count; i++)
        if (strcmp(q->entries[i].submit.branch, branch) == 0)
            found = &q->entries[i]; /* keep walking: the last wins */
    return found;
}

void land_queue_metrics(const struct land_queue *q, struct land_metrics *m)
{
    if (!m)
        return;
    memset(m, 0, sizeof *m);
    if (!q)
        return;
    m->submissions = q->entry_count;
    for (size_t i = 0; i < q->entry_count; i++) {
        const struct land_entry *e = &q->entries[i];
        switch (e->state) {
        case LAND_STATE_QUEUED:  m->queued++; break;
        case LAND_STATE_GATING:  m->gating++; break;
        case LAND_STATE_LANDED:  m->landed++; break;
        case LAND_STATE_REFUSED: m->refused++; break;
        case LAND_STATE_TIMEOUT: m->timed_out++; break;
        }
        if (!e->landing_backed) {
            m->unbacked_landings++;
            if (m->first_unbacked_seq == 0)
                m->first_unbacked_seq = e->seq;
        }
    }
    m->gate_runs = q->gate_count;
    for (size_t i = 0; i < q->gate_count; i++)
        if (q->gates[i].run.outcome == LAND_GATE_GREEN)
            m->gate_runs_green++;
}

/* ── writes ───────────────────────────────────────────────────────────── */

enum land_status land_queue_submit(struct land_queue *q,
                                   const struct land_submit *s,
                                   uint64_t *out_seq)
{
    if (!q || !s)
        return LAND_ERR_ARGUMENT;
    uint8_t buf[ZCL_CHAINLOG_PAYLOAD_MAX];
    size_t n = land_submit_encode(s, buf, sizeof buf);
    if (n == 0)
        return LAND_ERR_ENCODE;
    uint64_t seq = 0;
    if (zcl_chainlog_append(q->log, LAND_KIND_SUBMIT, buf, n, &seq, NULL) !=
        ZCL_CHAINLOG_OK)
        return LAND_ERR_LOG;
    if (!apply_submit(q, seq, s))
        return LAND_ERR_LOG; /* durable on disk; only the replay ran short */
    refresh_positions(q);
    if (out_seq)
        *out_seq = seq;
    return LAND_OK;
}

enum land_status land_queue_gate_run(struct land_queue *q,
                                     const struct land_gate_run *g,
                                     uint64_t *out_seq)
{
    if (!q || !g)
        return LAND_ERR_ARGUMENT;
    /* A gate run naming a submission nobody made is a receipt about
     * nothing. Refuse before it reaches disk. */
    for (uint32_t i = 0; i < g->member_count; i++)
        if (!entry_by_seq(q, g->member_seq[i]))
            return LAND_ERR_UNKNOWN_SEQ;
    uint8_t buf[ZCL_CHAINLOG_PAYLOAD_MAX];
    size_t n = land_gate_run_encode(g, buf, sizeof buf);
    if (n == 0)
        return LAND_ERR_ENCODE;
    uint64_t seq = 0;
    if (zcl_chainlog_append(q->log, LAND_KIND_GATE_RUN, buf, n, &seq, NULL) !=
        ZCL_CHAINLOG_OK)
        return LAND_ERR_LOG;
    if (!apply_gate_run(q, seq, g))
        return LAND_ERR_LOG;
    refresh_positions(q);
    if (out_seq)
        *out_seq = seq;
    return LAND_OK;
}

enum land_status land_queue_verdict(struct land_queue *q,
                                    const struct land_verdict *v,
                                    uint64_t *out_seq)
{
    if (!q || !v)
        return LAND_ERR_ARGUMENT;
    struct land_entry *e = entry_by_seq(q, v->submit_seq);
    if (!e)
        return LAND_ERR_UNKNOWN_SEQ;
    if (e->has_verdict)
        return LAND_ERR_ALREADY_FINAL;

    /* THE SEAM. Everything above this line is bookkeeping; this is the rule
     * the whole design rests on. A landing must name a gate run that really
     * happened, really passed, really covered this submission, and really
     * ran its groups. Nothing here can be satisfied by intent. */
    if (v->state == LAND_STATE_LANDED) {
        enum land_status backing =
            land_queue_check_landable(q, v->submit_seq, v->gate_run_seq);
        if (backing != LAND_OK)
            return backing;
    }

    uint8_t buf[ZCL_CHAINLOG_PAYLOAD_MAX];
    size_t n = land_verdict_encode(v, buf, sizeof buf);
    if (n == 0)
        return LAND_ERR_ENCODE;
    uint64_t seq = 0;
    if (zcl_chainlog_append(q->log, LAND_KIND_VERDICT, buf, n, &seq, NULL) !=
        ZCL_CHAINLOG_OK)
        return LAND_ERR_LOG;
    apply_verdict(q, v);
    refresh_positions(q);
    if (out_seq)
        *out_seq = seq;
    return LAND_OK;
}
