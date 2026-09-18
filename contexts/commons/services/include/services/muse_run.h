/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the Z23 worker link from a claimed queue row to a Muse coding
 * turn and back to a reap-compatible result. A's worker loop owns claim,
 * retry, and reap; this module owns the Muse session/turn/cancel, the
 * model interaction, the named gate execution, and the structured result.
 * One task in, one receipt plus one evidence file out; A's reap turns
 * those into the outcome row under the SAME ref.
 *
 * THE LAW (borrowed from engine_verdict.h): THE MODEL PROPOSES. THE GATE
 * DECIDES. A Muse "completed" is never a pass; only the named registered
 * group, read through its own SUITE VERDICT line, plus a measured worktree
 * diff, can pass. Anything unreadable is a refusal, never a pass.
 *
 * THE SAME LAW OVER SCOPE: THE SCOPE IS PROVEN BY MEASURED OUTPUT, not
 * only by the approval mode. Handing the scope to the session as its
 * single allow prefix under approval_mode "denyUnmatched" binds only the
 * moment the model ASKS; it proves nothing about the workspace
 * afterwards. So the run measures the change set itself, through the same
 * `git status --porcelain` seam the diff count already uses, and every
 * path it names must be inside the declared scope or the run fails
 * closed. The workspace must also be clean BEFORE the turn: pre-existing
 * dirt would otherwise satisfy the non-empty diff a pass requires, so a
 * dirty workspace is refused before a single token is spent. `build/` is
 * gitignored, so an already-built workspace is still clean.
 *
 * THE PRE-TURN HEAD IS PINNED. The change-set audit only proves anything
 * while the commit it is measured against holds still: a model that
 * COMMITS its work leaves a clean porcelain tree, and an audit of that
 * tree measures nothing while reporting everything in order. So HEAD is
 * read before the turn and read again after it, before the gate runs, and
 * a HEAD that moved — or either read that failed — fails the run closed.
 *
 * THE GATE'S PROCESS IS PART OF THE GATE. A runner that dies, is killed
 * on its deadline, or exits non-zero can still leave a captured log whose
 * last SUITE VERDICT line says everything passed. The log is only read
 * when the process exited normally with status 0 inside its deadline, so
 * a passing-looking log out of a failed process refuses.
 *
 * AN UNMEASURABLE OUTPUT IS A REFUSAL, NEVER A PASS. If either
 * enumeration cannot be measured — the porcelain capture fails to spawn,
 * exits non-zero, times out, fills its bound (the capture helper discards
 * the overrun and still reports the child's exit status, so a full buffer
 * proves nothing), or names a row the parser cannot read — the run fails
 * closed. It is never read as "clean" or as "nothing outside scope", and
 * the evidence records which of the two it was: a measured count, or -1
 * with measured=false.
 *
 * CLOSED VERDICTS (match the fleet predicate: only "pass" with rc 0
 * completes; everything else stays incomplete): pass, failed, timeout,
 * cancelled, refused. Lowercase verbs, honest rc: pass carries 0,
 * every other verb carries 1. Detail (engine name, reason, gate line)
 * rides the evidence file, never the verdict string.
 *
 * RESTART RULE: if the SAME ref (name+attempt) already owns a receipt
 * with a terminal verdict in the run directory, no Muse turn starts and
 * the call reports the earlier verdict with rc 0. The queue's own state
 * (locks, outcome rows) is A's business and is never read here.
 *
 * STDOUT CONTRACT: the two trailing lines
 *   ref=<seq>/<name>/<attempt> verdict=<v> tokens=<n> files=<n> wall_ms=<n>
 *   rc=<N>
 * are the run.out mechanism A's launcher captures; rc is 0 iff pass.
 */
#ifndef ZCL_SERVICES_MUSE_RUN_H
#define ZCL_SERVICES_MUSE_RUN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MUSE_RUN_ERROR_MAX 256
#define MUSE_RUN_NAME_MAX 80
#define MUSE_RUN_WORKER_MAX 64
#define MUSE_RUN_PATH_MAX 4096
#define MUSE_RUN_SCOPE_MAX 512
#define MUSE_RUN_GATE_MAX 128
#define MUSE_RUN_MODEL_MAX 128
#define MUSE_RUN_ID_MAX 64
#define MUSE_RUN_VERDICT_MAX 16
#define MUSE_RUN_REASON_MAX 256
/* Bounded JSON array bodies for the scope audit's measured path lists:
 * one run's change set can never write without limit. The honest total
 * always rides beside the list, so a truncated array stays visible. */
#define MUSE_RUN_CHANGED_LIST_MAX 4096
#define MUSE_RUN_SCOPE_LIST_MAX 1024
/* A brief is model input, not a ledger: bounded so one row cannot spend
 * without limit before the turn even starts. */
#define MUSE_RUN_PROMPT_MAX (256u * 1024u)

struct muse_run_ref {
    long long seq;
    char name[MUSE_RUN_NAME_MAX];
    long long attempt;
};

/* All bounds are at-most-N: reaching exactly N completes, consuming
 * beyond N refuses. Non-positive selects the module defaults. */
struct muse_run_budgets {
    int64_t turn_timeout_ms;
    int gate_timeout_ms;
    uint64_t max_total_tokens;
};

struct muse_run_task {
    struct muse_run_ref ref;
    /* A's worker identity, echoed into the evidence; "" = unattributed.
     * Non-empty must match [A-Za-z0-9_.-]{1,64}, never "." or "..". */
    char worker[MUSE_RUN_WORKER_MAX];
    /* Claimed worktree the turn may touch. */
    char workspace[MUSE_RUN_PATH_MAX];
    /* Repo-relative allow prefix inside the workspace (no leading '/',
     * no ".."). */
    char scope[MUSE_RUN_SCOPE_MAX];
    /* Registered group that judges the diff. */
    char gate[MUSE_RUN_GATE_MAX];
    /* Requested model; "" takes the server default. Both the request
     * and the resolution are recorded, so a substitution is visible. */
    char model[MUSE_RUN_MODEL_MAX];
    /* Caller-owned NUL-terminated brief; bounded by MUSE_RUN_PROMPT_MAX. */
    const char *prompt;
    /* Executor-owned evidence dir: receipt.json + muse.json land here. */
    char rundir[MUSE_RUN_PATH_MAX];
    struct muse_run_budgets budgets;
    /* True when the caller holds the claim (A's worker): the receipt
     * pre-check and the receipt write are skipped — the caller's
     * claim.json is the at-most-once guarantee, and the caller's
     * receipt is canonical. Evidence (muse.json, candidate artifact,
     * admission) is still written. */
    bool caller_holds_claim;
};

/* Everything the result row needs: ref, attempt, worker, provider/model,
 * session/turn/command IDs, terminal, source/diff identity, gate and
 * evidence, input/output/total tokens, wall time, files changed. */
struct muse_run_result {
    struct muse_run_ref ref;
    char worker[MUSE_RUN_WORKER_MAX];
    char provider[MUSE_RUN_ID_MAX];
    char model_requested[MUSE_RUN_MODEL_MAX];
    char model_resolved[MUSE_RUN_MODEL_MAX];
    char session[MUSE_RUN_ID_MAX];
    char turn[MUSE_RUN_ID_MAX];
    char start_command[MUSE_RUN_ID_MAX];
    char turn_command[MUSE_RUN_ID_MAX];
    /* Turn terminal as the host reported it: completed, cancelled, or
     * "none" when no terminal record folded. */
    char terminal[32];
    /* Raw engine verdict name (NO-CHANGE, FAIL, ...): detail for the
     * evidence file; the receipt verdict stays a closed verb. */
    char engine[32];
    char verdict[MUSE_RUN_VERDICT_MAX];
    /* Process exit code: 0 iff pass, the value A's run.out scan reads. */
    int rc;
    /* 40-hex HEAD before the turn, or "none" when unmeasurable. */
    char base[MUSE_RUN_ID_MAX];
    /* The same identity re-read AFTER the turn, or "none" when it could
     * not be read. A model that COMMITS its work leaves a clean porcelain
     * tree, so the change-set audit measures nothing at all and would see
     * a spotless run; only these two identities catch it. head_measured
     * is true only when both were read and agree, and an unread identity
     * is never the same answer as a match. */
    char head_observed[MUSE_RUN_ID_MAX];
    bool head_measured;
    /* 40-hex SHA-1 over the post-run change set (porcelain + content
     * hashes), or "none" when unmeasurable. Empty diff hashes
     * deterministically; identity never implies judgement. */
    char candidate[MUSE_RUN_ID_MAX];
    /* Artifact filename under the rundir holding the folded change set
     * ("candidate-<hex>.diff"), or "" when there is nothing to name.
     * Written atomically: a kill can never leave a partial file for a
     * gate to accept. */
    char candidate_file[192];
    /* The worker-run session from the caller's claim identity (""
     * when the caller supplies none): provenance beside the MSP ids. */
    char worker_session[MUSE_RUN_ID_MAX];
    char gate[MUSE_RUN_GATE_MAX];
    /* Mail-safe gate token, "<group>:<ran>/<failed>". */
    char gate_evidence[192];
    /* Last SUITE VERDICT line, verbatim (evidence file only). */
    char gate_verdict[512];
    long long gate_ms;
    long long gate_ran;
    long long gate_failed;
    bool gate_present;
    /* What the gate's PROCESS did, kept apart from what its log SAID. A
     * captured log holding a passing verdict line proves nothing when the
     * process that wrote it was killed on its deadline or exited
     * non-zero, so the log is only ever read when gate_normal is true:
     * an observed normal exit with status 0, inside the deadline, over a
     * log that did not fill its bound. gate_exit is that normal exit
     * status, or 128+signal for a signalled child, and -1 when no
     * trustworthy status was obtained — which is never the same answer as
     * a measured 0. gate_spawn names the outcome for the evidence. */
    bool gate_normal;
    int gate_exit;
    char gate_spawn[64];
    /* The gate BUILD, kept apart from the gate run. The runner is rebuilt
     * from the candidate tree before the group runs, so the verdict binds
     * three identities: the candidate (source), gate_runner (SHA3-256 hex
     * of the exact runner bytes the build left and the gate then ran) and
     * the gate reading. build_spawn names what the build process did
     * ("none" until attempted), build_ms is its wall time (-1 until
     * measured), and gate_runner stays "none" unless the build finished
     * normally and the runner was read in full. */
    char build_spawn[64];
    long long build_ms;
    char gate_runner[65];
    unsigned long long input_tokens;
    unsigned long long output_tokens;
    unsigned long long total_tokens;
    unsigned long long cached_input_tokens; /* see muse_turn_outcome */
    unsigned long long billed_tokens;       /* what the cap was charged */
    long long duration_ms;
    long long wall_ms;
    long long files_changed;
    bool prior_unresolved;
    /* --- the scope audit: the permission proven by measured output -----
     * scope_pre_clean is the workspace BEFORE the turn; false means the
     * run refused without spending a token, because baseline dirt must
     * never be able to count toward success. scope_changed and
     * scope_outside are measured AFTER the turn. Each list is a bounded
     * JSON array body (already escaped) and may hold fewer elements than
     * its *_count, which is always the honest total. */
    /* Whether each enumeration was MEASURED at all. False is unmeasurable
     * and refuses; it is never the same answer as a measured clean tree,
     * and the matching *_count stays -1 so no reader can confuse them. */
    bool scope_pre_measured;
    bool scope_changed_measured;
    bool scope_pre_clean;
    long long scope_pre_count;
    long long scope_changed_count;
    long long scope_outside_count;
    char scope_pre[MUSE_RUN_SCOPE_LIST_MAX];
    char scope_changed[MUSE_RUN_CHANGED_LIST_MAX];
    char scope_outside[MUSE_RUN_SCOPE_LIST_MAX];
    char reason[MUSE_RUN_REASON_MAX];
    /* Whether the workspace was returned to `base` after the verdict and
     * evidence were written (services/muse_run_restore.h). True only when
     * the candidate artifact was verified as a durable copy of the change
     * AND the workspace measured clean at base afterwards. False keeps
     * the change in place, and the next run's pre-state refusal stays
     * the fail-closed backstop. The reason says which, either way. */
    bool workspace_restored;
    char workspace_restore[MUSE_RUN_REASON_MAX];
};

/* Runs one task to a terminal verdict: restart pre-check, one bounded
 * Muse turn in the workspace, the named gate over the measured diff,
 * receipt.json + muse.json in the rundir, and the trailing rc lines on
 * stdout. Returns the process exit code (0 iff pass) and fills *out;
 * err carries the reason when the run itself breaks down (as opposed
 * to judging fail). Never starts a turn for an already-recorded ref. */
int muse_run_task(const struct muse_run_task *task,
    struct muse_run_result *out, char err[MUSE_RUN_ERROR_MAX]);

/* Leaf compat: the composed kind=muse task file. The queue: header is
 * accepted and ignored (claim state is A's); worker defaults to "cli".
 * Same run, same receipt, same stdout contract. */
int muse_run_task_file(const char *taskpath,
    const struct muse_run_budgets *budgets, char err[MUSE_RUN_ERROR_MAX]);

#ifdef ZCL_TESTING
#include <sys/types.h>
/* Test seam: same run, but the transport is caller-spawned (a scripted
 * host). The run owns the session afterwards, including close. Mirrors
 * muse_session_attach. */
int muse_run_task_on_transport(const struct muse_run_task *task,
    pid_t child, int to_fd, int from_fd, struct muse_run_result *out,
    char err[MUSE_RUN_ERROR_MAX]);
#endif

#endif /* ZCL_SERVICES_MUSE_RUN_H */
