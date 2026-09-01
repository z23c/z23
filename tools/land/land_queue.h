/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * land_queue — the landing queue, which is a replay of its own chainlog.
 *
 * WHAT PROBLEM THIS SOLVES
 * ------------------------
 * Measured on this tree: `ZCL_STRESS_TESTS=1 make pre-push-ci` costs 15-25
 * minutes, has no cache, and every agent ran it serially before every push.
 * Four machines doing that independently means four full gate runs to land
 * four commits, plus a race at the end that frequently sends one of them
 * back to re-merge and re-gate. The cost is not the push. It is the gating,
 * multiplied by the number of agents, plus the racing.
 *
 * The fix is not a faster gate. It is running the gate ONCE for N
 * submissions. A batch of five costs one gate run instead of five, so gate
 * runs per landed commit falls from 1.0 to 0.2, and no agent waits for it.
 *
 * THE QUEUE HAS NO SEPARATE STATE FILE
 * ------------------------------------
 * There is no sidecar database that could disagree with the receipts. The
 * chainlog IS the queue: every state a caller can observe is derived by
 * replaying the frames. That gives three properties for free —
 *
 *   * a restart is invisible (the state was never in RAM to begin with),
 *   * a receipt can never contradict the queue,
 *   * two submitters cannot corrupt it, because engine/modules/chainlog opens its file
 *     under an exclusive whole-file lock that WAITS. The second submitter
 *     blocks in open() and appends after the first, rather than interleaving
 *     with it.
 *
 * WHAT THIS DELIBERATELY WILL NOT DO
 * ----------------------------------
 * It does not push. tools/lint/check_no_unattended_publish.sh is a hard gate
 * with a closed allowlist, and it is right: a background loop that can move
 * `main` moves it for every checkout that fast-forwards from it, with nobody
 * reviewing what went out. So the lander does everything up to the push —
 * merge, gate, order, bisect, record — and leaves a ready-to-push
 * integration branch that a person publishes with one command. The 20
 * minutes an agent loses is the gating and the racing; both are gone. The
 * push, which is seconds, stays a deliberate human act.
 */

#ifndef ZCL_LAND_QUEUE_H
#define ZCL_LAND_QUEUE_H

#include "land_record.h"

#include "chainlog/chainlog.h"

/* Every way a queue write can refuse. There is no generic failure: the
 * lander has to be able to tell a person which rule stopped it. */
enum land_status {
    LAND_OK = 0,
    LAND_ERR_ARGUMENT,          /* a NULL, or a field over its bound */
    LAND_ERR_LOG,               /* the chainlog said no */
    LAND_ERR_ENCODE,            /* the record has no canonical encoding */
    LAND_ERR_UNKNOWN_SEQ,       /* a verdict for a submission nobody made */
    LAND_ERR_ALREADY_FINAL,     /* a second verdict for a settled submission */
    LAND_ERR_NO_GATE_RUN,       /* LANDED, but no gate run contains it */
    LAND_ERR_GATE_NOT_GREEN,    /* LANDED, but that gate run was red */
    LAND_ERR_GATE_NOT_STRESSED, /* LANDED, but that run skipped its groups */
    LAND_ERR_GATE_UNIDENTIFIED  /* LANDED, but nobody can say WHICH tree */
};

const char *land_status_label(enum land_status s);

struct land_entry {
    uint64_t seq;                  /* the SUBMIT frame's chainlog seq */
    struct land_submit submit;
    enum land_state state;
    uint64_t gate_run_seq;         /* the most recent run containing it */
    uint32_t gate_runs;            /* how many runs it has been through */
    bool has_verdict;
    struct land_verdict verdict;   /* meaningful only when has_verdict */

    /* WHAT IT IS WAITING ON. A queue that can only say PENDING makes the
     * asker think, and making the asker think is the cost this whole thing
     * exists to remove. So every live state carries the one number that
     * answers "why is it not done yet":
     *   QUEUED  -> `ahead` submissions the lander will take before it
     *   GATING  -> it is inside gate run `gate_run_seq`, which is proving
     *              `batch_size` submissions at once
     * Both are derived from the log by replay, so reading them costs a file
     * read and no gate, no build, and no network. */
    uint32_t ahead;
    uint32_t batch_size;

    /* The gating tree's identity and whether its groups were enabled,
     * carried from the most recent gate run that contained this submission.
     * These are what make the verdict digest below reproducible. */
    uint8_t gate_id[LAND_GATE_ID_BYTES];
    bool gate_stress;

    /* The content address of the verdict — see land_verdict_digest(). Set
     * only once a verdict exists, because there is no digest for a decision
     * nobody has made. A receiver on another machine recomputes this from
     * (head, integration, gate_id, state, stress) and compares. */
    bool has_digest;
    uint8_t digest[LAND_DIGEST_BYTES];
    /* False when a LANDED verdict in the log is NOT backed by a green,
     * stress-enabled gate run naming this submission. The writer refuses to
     * create one; this exists so an auditor reading a log written by
     * something else can still catch it. Replay reports it, and never
     * silently repairs it: rewriting the entry would destroy the evidence
     * that the log was altered, which is the whole point of a chainlog. */
    bool landing_backed;
};

struct land_metrics {
    uint64_t submissions;
    uint64_t queued;
    uint64_t gating;
    uint64_t landed;
    uint64_t refused;
    uint64_t timed_out;
    uint64_t gate_runs;
    uint64_t gate_runs_green;
    uint64_t unbacked_landings;   /* must be 0 in a sound log */
    uint64_t first_unbacked_seq;  /* 0 when sound */
};

struct land_queue;

/* Open (creating when absent) and replay. `report` is required and is filled
 * even when this returns NULL, so a caller can always say WHY. */
struct land_queue *land_queue_open(const char *path,
                                   struct zcl_chainlog_report *report);
void land_queue_close(struct land_queue *q);

size_t land_queue_count(const struct land_queue *q);
const struct land_entry *land_queue_at(const struct land_queue *q, size_t i);
const struct land_entry *land_queue_find_seq(const struct land_queue *q,
                                             uint64_t seq);
/* The MOST RECENT submission of a branch. A branch refused once and
 * resubmitted has two entries; status answers about the live one. */
const struct land_entry *land_queue_find_branch(const struct land_queue *q,
                                                const char *branch);
void land_queue_metrics(const struct land_queue *q, struct land_metrics *m);

/* Append a submission. Returns immediately after the chainlog's two fsyncs:
 * no gate, no build, no wait. */
enum land_status land_queue_submit(struct land_queue *q,
                                   const struct land_submit *s,
                                   uint64_t *out_seq);

/* Record one gate run over one integration branch and the exact submissions
 * that were in it. Every member must name a real submission. */
enum land_status land_queue_gate_run(struct land_queue *q,
                                     const struct land_gate_run *g,
                                     uint64_t *out_seq);

/* Record a verdict. THE FAIL-CLOSED SEAM: a LANDED verdict is refused unless
 * v->gate_run_seq names a gate run that (a) exists, (b) was GREEN, (c) ran
 * with the stress groups enabled, (d) listed v->submit_seq as a member, and
 * (e) carries a non-zero gate identity.
 *
 * (e) is there for the receiver, not for the runner. A landing whose gating
 * tree cannot be named produces a verdict digest nobody else can reproduce,
 * which is precisely the "trust me, it passed" receipt this design exists to
 * remove. Refusing an unidentifiable pass costs one resubmission; accepting
 * one costs the property that makes a verdict worth sending anywhere.
 *
 * REFUSED and TIMEOUT carry none of these requirements — refusing work that
 * was never gated is always sound, landing it never is. */
enum land_status land_queue_verdict(struct land_queue *q,
                                    const struct land_verdict *v,
                                    uint64_t *out_seq);

/* The same four checks, without writing. The lander asks this before it
 * merges anything, and the test group asks it directly. */
enum land_status land_queue_check_landable(const struct land_queue *q,
                                           uint64_t submit_seq,
                                           uint64_t gate_run_seq);

#endif /* ZCL_LAND_QUEUE_H */
