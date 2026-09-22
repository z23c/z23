/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * muse_run_restore — the candidate fold one Muse run publishes, and the
 * return of the workspace to its pinned base once that fold is durable.
 *
 * WHY A RUN RESTORES. A run refuses before the turn unless the workspace
 * is measurably clean, because baseline dirt could satisfy the non-empty
 * diff a pass requires. A run that leaves its own change behind therefore
 * makes the NEXT claimed task on the same workspace refuse before a token
 * is spent. So once the verdict and evidence are written, the run puts
 * the workspace back — but only what it can prove it has a durable copy
 * of.
 *
 * WHAT MUST HOLD BEFORE ANYTHING IS TOUCHED. The pre-state was measured
 * clean (so every path now dirty is this run's); HEAD still names the
 * pinned base; the published artifact exists, its bytes hash to the name
 * it was published under, and a fresh fold of the workspace reproduces
 * those bytes exactly; every untracked path it names is a regular file
 * named by the scope audit, copied under the rundir, and the copy hashes
 * to the recorded content hash; and the tracked half reverse-applies
 * cleanly (`git apply -R --check`). Any miss refuses with a reason and
 * changes nothing — the next run's pre-state refusal stays the backstop.
 *
 * WHAT IS TOUCHED. Only the tracked half of the artifact, reversed; the
 * index for those paths, back to HEAD; and the untracked files the
 * artifact names. Ignored files are never listed by the fold and are
 * never touched. HEAD never moves: no commit, stash, reset of HEAD, or
 * branch change. A workspace that is not measurably clean afterwards
 * reports restored=false. Once the tree measures clean at base, the
 * index stat cache is refreshed so a stat-only reader agrees it is
 * clean; a refresh failure reports incomplete, never half-undone.
 */
#ifndef ZCL_SERVICES_MUSE_RUN_RESTORE_H
#define ZCL_SERVICES_MUSE_RUN_RESTORE_H

#include <stdbool.h>
#include <stddef.h>

/* Bound on one fold, and on the artifact that publishes it. A fold that
 * reaches the bound may be truncated and is never restored from. */
#define MUSE_FOLD_MAX (256u * 1024u)

/* Bound on one named fold failure. */
#define MUSE_FOLD_NOTE_MAX 256

/* The post-run change set as one text: `git diff HEAD` plus one
 * "?? <path> <content-hash>" line per untracked path, and its 40-hex
 * git hash in hex_out. *fold_out is heap text the caller frees, or NULL
 * when git failed (hex_out then reads "none"). The rundir hosts one
 * transient tempfile.
 *
 * EVERY FAILURE NAMES ITSELF. `why` (bounded by why_cap, always
 * terminated, "" on success) says WHICH step broke: the tracked-diff
 * capture, the tempfile, or the hash. That distinction is not cosmetic.
 * On 2026-09-19 this call failed in production and the run reported only
 * candidate "none". Which step broke, and why, is STILL not known, and
 * cannot be recovered: nothing captured it. That is the whole argument
 * for this parameter — a refusal nobody can diagnose is one that gets
 * retried at full price instead of repaired. The three notes each name
 * the call and its exit status, so the next occurrence is readable from
 * the evidence alone. `why` may be NULL. */
bool muse_candidate_fold(const char *workspace, const char *rundir,
    char *hex_out, size_t hex_cap, char **fold_out, char *why,
    size_t why_cap);

struct muse_restore_in {
    const char *workspace;
    const char *rundir;
    const char *base;           /* pinned pre-turn HEAD, 40-hex */
    const char *candidate;      /* fold hash, 40-hex */
    const char *candidate_file; /* "candidate-<hex>.diff" under rundir */
    bool pre_clean;             /* pre-state measured AND clean */
};

/* Returns true only when the workspace is measurably clean at base
 * afterwards. reason always says what happened, either way.
 *
 * REFUSED IS NOT HALF-UNDONE. `half_undone` (always written when
 * non-NULL) is true only when the undo had already TOUCHED the workspace
 * and then could not settle it at base: the tree holds neither the
 * change nor the base, and no artifact anywhere describes what it does
 * hold. It stays false for every refusal made before the first byte is
 * changed — those leave the change exactly where the turn left it, which
 * is recoverable, because the change is still the change. Both states
 * block the next claimed task; only one of them has lost information.
 * One boolean for both would tell the operator that a workspace it can
 * inspect and a workspace it cannot are the same thing. */
bool muse_restore_workspace(const struct muse_restore_in *in, char *reason,
    size_t reason_cap, bool *half_undone);

#endif /* ZCL_SERVICES_MUSE_RUN_RESTORE_H */
