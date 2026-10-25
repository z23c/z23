/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the dev.land queue row and the few host helpers that the land
 *          train module (native_dev_land_train.c) and the objectives
 *          snapshot (native_dev_land_objectives.c) share with the landing
 *          service (native_dev_land.c). Nothing outside those three files
 *          includes this header. */

#ifndef ZCL_NATIVE_DEV_LAND_INTERNAL_H
#define ZCL_NATIVE_DEV_LAND_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>

#include "command/native_command.h"

/* Bounded budgets shared with the train module. */
#define DL_LOG_CAP   (2u * 1024u * 1024u)
#define DL_NOTE_MAX  512u

/* Attempt ceiling for a host-load retry (a source-identity race or a
 * timeout). A real red dimension is terminal on the first attempt. */
#define DL_ATTEMPT_MAX 3

/* Wall-clock ceiling for the git actions step performs. */
#define DL_GIT_TIMEOUT_MS  (10 * 60 * 1000)

struct dl_dirs {
    char root[4096];
    char land[4096];
    char logs[4096];
    char wt[4096];
};

/* state:   queued | inflight | landed | failed | conflict | cancelled
 * phase:   "" | rebase | prebuild | prove | push  (meaningful when
 *          inflight). A legacy "regen" phase persisted by an older binary
 *          still loads; nothing writes it. The queue never amends a tip:
 *          `local` is the rebased row as submitted, and every downstream
 *          step proves and pushes exactly it. */
struct dl_failure_identity {
    char root[4096], attempt[144], request[65], archive[65];
};
struct dl_row {
    long long seq;
    long long priority_seq;
    char ts[64];
    char tip[80];
    char worktree[4096];
    char note[DL_NOTE_MAX + 1];
    char state[16];
    char phase[16];
    long long attempt;
    long long started;
    /* Unix seconds at which the outcome writer recorded state "landed"; 0 for
     * every other row. `ts` is the SUBMIT time and `started` the proof start,
     * so only this says when the train landed. */
    long long landed_at;
    /* First native terminal-recording observation, not child exit/fsync.
     * 0 unknown (including legacy). Consumer owns clock/window validation. */
    long long terminal_recorded_at;
    char base[80];
    char local[80];
    char tree[80];
    char proof_intent[176];
    /* Optional host-local retained proof identity, never verdict authority. */
    struct dl_failure_identity failed_proof;
    long long predecessor_seq;
    char predecessor_local[80], predecessor_base[80], predecessor_tree[80];
    char predecessor_intent[176];
    /* Signed Git landing intent, bound to the exact proven pair. The bundle
     * lives under land/ and its digest is checked again before dispatch. */
    char publication_target[65];
    char publication_proof[65];
    char publication_bundle[65];
    char publication_signer[65];
    char publication_signature[129];
    char remote_tip[65];
    char remote_source[65];
    char remote_signer[65];
    char remote_signature[129];
    char pushed[80];
    char dimension[48];
    char log_path[4096];
    /* Keep the complete bounded worktree-dependency refusal, including its
     * repair command, rather than truncating the upstream 1024-byte text. */
    char detail[1024];
    /* A possible send without durable diagnostics forbids another send.
     * Remote observation remains authoritative, including after a crash. */
    bool push_diagnostic_pending;
    long long fence_peer;
    bool publication_hold;
    /* The origin main this queued row was last replayed onto by the
     * queued-row conflict precheck, so a fresh step process does not
     * replay it again until main moves. A cache, never authority: absence, empty or a fitting
     * non-SHA string only means "not checked yet". */
    char prechecked[80];
    /* Uncertain precheck answers against `uncertain_main`; at
     * DL_PRECHECK_TRIES the check leaves the row alone until main moves.
     * Also a cache: absence, empty or a fitting non-SHA string
     * means "no answers yet". */
    char uncertain_main[80];
    long long uncertain_tries;
    /* Set once the producer-stale recovery has been spent for this row until
     * main moves. Written before the recovery runs; independent of dimension.
     * Optional on disk: an older row loads as "not tried". */
    long long producer_recovered;
    /* Digest of the last phase mail posted for this row (state, phase,
     * attempt, tip, dimension, note, detail, log); 0 means nothing posted.
     * Optional on disk: an older row loads as 0, an older binary ignores
     * the key. A cache that only decides whether a repeat row is mailed. */
    long long phase_mail;
    /* Land trains (native_dev_land_train.c). train_solo: a red train
     * released this row, so it never forms or joins a train again. Optional
     * on disk. train_commit: while the row rides in a train, its own commit
     * in the stacked history; "" otherwise. */
    long long train_solo;
    char train_commit[80];
};

/* ── the objectives snapshot (native_dev_land_objectives.c) ───────────── */

/* Append one zcl.objectives_snapshot.v1 line to <land>/objectives.jsonl for a
 * row dl_record_outcome has just appended to outcomes.jsonl in state
 * "landed". `fresh` is false for a replayed or already-recorded row, which
 * writes nothing. Best effort: a failure is logged to the row's attempt log
 * and never changes the outcome, the push or the reply. */
void dl_objectives_snapshot(const struct dl_dirs *d, const struct dl_row *r,
                            bool fresh);

/* ── host helpers the train module calls (native_dev_land.c) ───────────── */

/* Append one complete line to `path` (O_APPEND, full-write loop). */
bool dl_append_row(const char *path, const char *line, size_t len);

/* The rows each stamp their log; these are the land leaf's own primitives. */
void dl_fail(struct zcl_command_reply *reply, const char *code,
             const char *phase, const char *msg, const char *evidence);
void dl_log(const struct dl_row *row, const char *text);
void dl_log_path(const struct dl_dirs *d, struct dl_row *row);
void dl_step_reply(struct zcl_command_reply *reply, const struct dl_row *row,
                   const char *state);
bool dl_commit_or_report(const struct dl_dirs *d, struct dl_row *row,
                         bool terminal, struct zcl_command_reply *reply,
                         const char *intended_state);
bool dl_stubbed(void);
bool dl_sha_ok(const char *s);
int dl_git(const char *dir, const char *const *args, char *out, size_t cap,
           int timeout_ms);
int dl_rebase(const struct dl_dirs *d, struct dl_row *row,
              const char *observed_main, char *why, size_t why_cap);
bool dl_push_identity_ok(const struct dl_dirs *d, const struct dl_row *row);
void dl_publication_clear(struct dl_row *r);
bool dl_proof_intent_bind(const struct dl_dirs *d, struct dl_row *row);
bool dl_wt_proof_deps_ensure(const struct dl_dirs *d, const struct dl_row *r,
                             bool stubbed, char *why, size_t why_cap);
int dl_lint_candidate(const struct dl_dirs *d, struct dl_row *row);
bool dl_queued_precedes(const struct dl_row *row, const struct dl_row *best);
int dl_rows_lock(const char *landdir);
void dl_unlock(int fd);
bool dl_load_rows(const char *qpath, struct dl_row **rows_out, size_t *n_out,
                  char *why, size_t why_cap);
bool dl_rewrite_rows(const char *landdir, const char *qpath,
                     const struct dl_row *rows, size_t n);
bool dl_history_read(const char *path,
                     bool (*visit)(const struct dl_row *, void *),
                     void *context, char *why, size_t why_cap);
/* Seal one bound member under its own bundle and signed landing intent
 * (its own seq; `head`'s target and proof digest); an already sealed
 * member is verified again. */
bool dl_train_seal_member(const struct dl_dirs *d, const struct dl_row *head,
                          struct dl_row *member);

/* ── land trains (native_dev_land_train.c) ─────────────────────────────── */

struct json_value;

/* dl_proof_intent_bind, preceded by the train when ZCL_LAND_TRAIN_WIDTH is
 * on and queued rows can be stacked onto the prepared head; *members is the
 * count bound to the head's pair (0: the head proves alone). */
bool dl_train_intent_bind(const struct dl_dirs *d, struct dl_row *row,
                          size_t *members);
/* The row heads a formed train (train_commit and the stacked proof_intent
 * persist together); false for every plain row, which no train code reads
 * the queue or the outcome history for. */
bool dl_train_formed(const struct dl_row *row);
/* A failed train proof is no verdict on the head alone: requeue the head
 * and release its members, all marked to prove alone. False: not a train. */
bool dl_train_fallback(const struct dl_dirs *d, struct dl_row *row,
                       const char *detail, struct zcl_command_reply *reply);
/* A superseded pair can never publish: release the rows bound to it. */
void dl_train_unbind(const struct dl_dirs *d, const char *intent,
                     long long head, bool solo);
/* Every row bound to a formed train's pair is live, unchanged and sealed;
 * a strict no-op (true, nothing read) for a row that heads no train. */
bool dl_train_gate(const struct dl_dirs *d, struct dl_row *row,
                   struct zcl_command_reply *reply);
/* Refuse (reply set, true) a queued row that rides in a live train. */
bool dl_train_refuse_bound(const struct dl_dirs *d, const struct dl_row *rows,
                           size_t n, const struct dl_row *member,
                           const char *stage, struct zcl_command_reply *reply);
/* dl_rebase for a row's own turn: first clears a binding it no longer has. */
int dl_train_rebase(const struct dl_dirs *d, struct dl_row *row,
                    const char *observed_main, char *why, size_t why_cap);
/* Add the queued rows riding in the in-flight row's pair to its status. */
void dl_train_status(struct json_value *inflight, const struct dl_row *rows,
                     size_t n);

#endif
