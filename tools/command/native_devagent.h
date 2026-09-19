/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Pure, testable primitives behind the dev.agent.* command surface —
 *          checkout-root resolution, SUITE VERDICT parsing, and the
 *          deterministic single-line source mutation used by
 *          dev.agent.mutate. Kept separate from the handlers so a registered
 *          test group can prove them without spawning a build. */

#ifndef ZCL_NATIVE_DEVAGENT_H
#define ZCL_NATIVE_DEVAGENT_H

#include <stdbool.h>
#include <stddef.h>

/* ── SUITE VERDICT ────────────────────────────────────────────────────────
 * test_parallel prints exactly one machine-greppable verdict line:
 *
 *   SUITE VERDICT mode=cold groups_total=N groups_ran=N groups_cached=N
 *     groups_gated=N groups_failed=N self_skips=N env_unobserved=N toolkey=..
 *
 * `groups_ran` is the field that separates "the group passed" from "nothing
 * executed and the runner still printed ALL TESTS PASSED". Every consumer of
 * a test run must read it, so it is parsed once, here. */
#define ZCL_DEVAGENT_MODE_MAX    16
#define ZCL_DEVAGENT_TOOLKEY_MAX 32

struct zcl_devagent_verdict {
    bool present;               /* a SUITE VERDICT line was found at all */
    char mode[ZCL_DEVAGENT_MODE_MAX];       /* "cold" | "cached" */
    char toolkey[ZCL_DEVAGENT_TOOLKEY_MAX];
    long long groups_total;
    long long groups_ran;
    long long groups_cached;
    long long groups_gated;
    long long groups_failed;
    long long self_skips;
    long long env_unobserved;
    bool hotswap;               /* the run executed a hot-swapped module */
};

/* Parse the LAST `SUITE VERDICT` line in `text`. `out` is always initialized;
 * returns out->present. Missing numeric fields stay -1 so an absent field can
 * never be mistaken for a zero. */
bool zcl_devagent_verdict_parse(const char *text,
                                struct zcl_devagent_verdict *out);

/* ── closed completion vocabulary ─────────────────────────────────────────
 * Only an explicit "pass"/"PASS" verdict with a clean exit completes a
 * queue directive: "pass" is the long-standing explicit allowlist entry and
 * "PASS" is what the tree's own receipt producers emit. Anything else —
 * fail words, "completed", unknown strings, case variants, a missing
 * verdict — stays incomplete no matter what rc says, and a pass claim
 * contradicted by a nonzero exit does not complete either. rc == 0 alone
 * is never completion evidence. One shared predicate so the claim refusal,
 * the worker gate, and the gateway evidence paths cannot drift apart. */
bool zcl_devagent_closed_pass(const char *verdict, long long rc);

/* ── the one directive-name grammar ───────────────────────────────────────
 * A queue row is a directory named by its name, and a steer directive names
 * the row it is meant to become. So both must accept exactly the same
 * strings: [A-Za-z0-9_.-], 1..64 bytes, never "." or "..", never empty.
 * A '/' is off the alphabet, so a path-shaped name cannot escape the run
 * directory and cannot reach a second segment.
 *
 * One shared predicate because the two ends drifted once: fleet.steer.send
 * accepted a ref that dev.agent.queue then refused with BAD_INPUT, which
 * wrote mail describing work that could never be dispatched. Anything that
 * names queue work validates here, so that gap cannot reopen. */
#define ZCL_DEVAGENT_NAME_MAX 64u

bool zcl_devagent_name_ok(const char *name);

/* ── resident dev worker ──────────────────────────────────────────────────
 * The dev-only loop that consumes dev.agent.queue continuously. One active
 * job per worker; the queue stays the only ledger (claim/running/outcome
 * rows), mail carries result copies, receipts judge runs. The MODEL
 * EXECUTION SEAM is wkr_executor_fn: the production binary wires "no
 * executor yet" until C's muse_session drops in; tests wire fixtures. A
 * worker terminal of "completed" is never success by itself — only the
 * closed predicate over the gated receipt advances completion. */

/* Bounded drive options. Strings are NUL-terminated on entry; over-long
 * values are refused by the leaf before the drive starts. */
struct wkr_drive_opts {
    char worker[56];      /* resident worker identity, required */
    char session[56];     /* this worker run, required */
    char model[160];      /* model id hint for the executor, may be empty */
    long long deadline_s; /* stop claiming after this many seconds */
    long long idle_start_s; /* first idle wait on an empty queue */
    long long idle_limit_s; /* stop after this much consecutive idle */
    long long max_jobs;   /* stop after this many jobs (0 = deadline only) */
    long long time_cap_s; /* wall clock per executor run */
    long long cpu_s;      /* RLIMIT_CPU per executor run */
    long long mem_mb;     /* RLIMIT_AS per executor run */
    long long token_cap;  /* token budget handed to the executor */
    bool timed_idle_only; /* skip the queue watch and sleep the backoff;
                           * the leaf never sets it, tests prove the
                           * fallback with it */
};

/* One claimed unit of work. task is executor-ready text; rundir owns
 * claim.json, receipt.json, run.out and the executor result file. */
struct wkr_job {
    char rundir[4096];
    char name[80];
    char kind[16];
    long long attempt;
    long long seq;
    char task[8192];
    char model[160];
    long long token_cap;
    long long time_cap_s;
};

/* Worst-case JSON growth of one byte: a control byte escapes to \u00XX.
 * A buffer holding the escaped form of an N-byte field is N * this. */
#define WKR_JSON_ESCAPE_WORST 6u

/* Executor outcome. terminal is the executor's own word ("completed" is
 * NOT success); candidate names the produced diff/artifact for the gate. */
struct wkr_result {
    char terminal[32];
    long long rc;
    char candidate[192];
    char evidence[2048];
    long long tokens_used;
    long long wall_ms;
};

/* Model execution seam. True when the executor ran and filled res (even
 * on executor failure); false when no executor is wired. Production
 * C muse_session integration replaces the wired function, never the
 * loop around it. */
typedef bool (*wkr_executor_fn)(const struct wkr_job *job,
                                struct wkr_result *res);

/* Drive the loop until the deadline, idle limit, or job cap. Returns
 * jobs processed (>= 0), or -1 when the worker lock or state root
 * refuses. Single worker per queue: a second concurrent drive refuses. */
long long zcl_devagent_worker_drive(const struct wkr_drive_opts *opts,
                                    wkr_executor_fn exec);

/* Production executor stub: wired until C's muse_session arrives. Always
 * returns false so a job is never executed without a real executor. */
bool zcl_devagent_worker_no_executor(const struct wkr_job *job,
                                     struct wkr_result *res);

/* Production Muse executor (C): adapts one claimed job to one bounded
 * muse_run_task and maps the structured result back. Declared here
 * beside the seam it implements; defined in
 * tools/command/native_devagent_muse_executor.c. */
bool zcl_devagent_worker_muse_executor(const struct wkr_job *job,
                                       struct wkr_result *res);

/* ── one executor run: caps, confinement, outcome ─────────────────────────
 * native_devagent_worker_run.c. The worker loop owns the queue, receipts
 * and mail; this unit owns the one bounded executor run beneath it, so the
 * POSIX fork backend and the Windows confined backend share ONE cap
 * computation, ONE result record, ONE result parse, ONE gate, and ONE
 * outcome mapping — a timeout, a crash, an ENOMEM or a failing executor
 * therefore reaches the receipt through the same fields on every host.
 *
 * POSIX: fork, RLIMIT_CPU = cpu_s, RLIMIT_AS = memory_bytes, wall SIGKILL.
 * Windows: the same image re-entered as a restricted low-integrity child
 * in a kill-on-close job carrying memory_bytes (job-wide commit), cpu_s
 * (job-wide user time) and WKR_ACTIVE_PROCESS_CAP; the parent keeps the
 * wall clock and kills the whole job. The child image's own entry picks
 * the executor (the production binary passes the Muse executor, as the
 * leaf does); the drive's exec pointer is not carried across the
 * process boundary. See docs/WINDOWS.md for what Windows does and does
 * not enforce relative to POSIX. */

#define WKR_ACTIVE_PROCESS_CAP 64u
#define WKR_CHILD_FLAG "--z23-internal-agent-worker-child"
#define WKR_JOB_FILE "executor_job.json"

/* The caps one run is held to, derived once from the drive options. A
 * zero field means "not capped" (POSIX keeps that meaning); Windows
 * refuses to launch unless every field is nonzero. */
struct wkr_caps {
    unsigned long long memory_bytes; /* mem_mb MiB: RLIMIT_AS / job memory */
    long long cpu_s;                 /* RLIMIT_CPU / job user time */
    long long wall_s;                /* parent wall clock, both hosts */
    unsigned active_processes;       /* Windows job only */
};

/* Fill caps from opts. True only when every cap is nonzero — the
 * precondition for a Windows launch. */
bool zcl_devagent_worker_caps(const struct wkr_drive_opts *opts,
                              struct wkr_caps *caps);

/* What the parent observed. status: 1 ran, 0 wall timeout (killed), -1
 * launch/wait failure. signaled: the child died by signal (POSIX), by an
 * exception or fast-fail exit, or by the job CPU cap (Windows). */
struct wkr_spawn_out {
    int status;
    long long wall_ms;
    bool signaled;
};

/* The receipt-facing mapping, shared by both backends. When gate is true
 * the caller parses the result file and gates it; otherwise rc, terminal
 * and note are the outcome and no receipt is written. */
struct wkr_outcome {
    long long rc;
    const char *terminal;
    const char *note;
    bool gate;
};

void zcl_devagent_worker_outcome(const struct wkr_spawn_out *out,
                                 bool terminating, struct wkr_outcome *o);

/* Child side, both hosts: run exec on job, write executor_result.json
 * under job->rundir, and return the process exit code (the executor rc
 * clipped to 0..125; 125 no executor; 126 record failure). */
int zcl_devagent_worker_child_record(const struct wkr_job *job,
                                     wkr_executor_fn exec);

/* Parse executor_result.json under rundir. False when absent/unusable. */
bool zcl_devagent_worker_parse_result(const char *rundir,
                                      struct wkr_result *res);

/* The required gate. Writes the verdict and returns the receipt rc (0 only
 * on pass). */
long long zcl_devagent_worker_gate(const struct wkr_job *job,
                                   const struct wkr_result *res,
                                   char *verdict, size_t cap);

/* Bounded small-file helpers the worker and its child share. */
bool zcl_devagent_worker_read_file(const char *path, char *out, size_t cap);
bool zcl_devagent_worker_write_atomic(const char *path, const char *text,
                                      size_t len);
bool zcl_devagent_worker_json_escape(const char *in, char *out, size_t cap);
bool zcl_devagent_worker_file_exists(const char *path);

/* The job handed across the Windows process boundary, as WKR_JOB_FILE in
 * the run dir: every wkr_job field but rundir (the child takes that from
 * its argv) plus the memory cap the child verifies its job against. */
bool zcl_devagent_worker_job_store(const struct wkr_job *job,
                                   unsigned long long memory_bytes);
bool zcl_devagent_worker_job_load(const char *rundir, struct wkr_job *job,
                                  unsigned long long *memory_bytes);

/* The workspace a Muse brief names ("muse-workspace: <abs>" in the header
 * block of job->task), admitted as a write root only when it is an
 * absolute, existing directory with no ".." segment, is not a filesystem
 * or drive root, and holds a ".git" entry (a checkout or worktree). False
 * leaves out empty. */
bool zcl_devagent_worker_task_workspace(const char *task, char *out,
                                        size_t cap);

/* The explicit child environment: a fixed allowlist of path/system
 * variables copied from this process, plus TEMP and TMP pointed at the run
 * dir. Nothing else crosses — no credential, token or key variable. Fills
 * up to cap entries of storage[i] (each WKR_ENV_ENTRY_MAX bytes) and the
 * NULL-terminated ptrs (cap + 1 slots). Returns the entry count, -1 on
 * overflow. */
#define WKR_ENV_ENTRY_MAX 4096u
#define WKR_ENV_MAX 20u
int zcl_devagent_worker_child_env(const char *rundir,
                                  char storage[][WKR_ENV_ENTRY_MAX],
                                  const char **ptrs, size_t cap);

/* Windows backend: run job under the confinement described above and
 * report exactly like the POSIX fork backend. terminating is the worker's
 * shutdown flag, polled between wait slices. On a non-Windows host, or when
 * the backend cannot arm, status is -1 and nothing ran. */
struct wkr_spawn_out zcl_devagent_worker_spawn_confined(
    const struct wkr_drive_opts *opts, const struct wkr_job *job,
    const volatile int *terminating);

/* Windows child entry (WKR_CHILD_FLAG <rundir>): load the job, refuse
 * unless this process is confined, run exec, record. Returns the process
 * exit code; a non-Windows host returns 2 without running anything. */
int zcl_devagent_worker_child_main(const char *rundir, wkr_executor_fn exec);

/* ── resident mail receiver ───────────────────────────────────────────────
 * The dev-only loop that turns a directive arriving in this box's agent
 * mail into a dev.agent.queue row and answers the sender under the same
 * ref. It never executes anything: dev.agent.worker's own resident loop
 * runs the job and posts the result. Admission is the EXISTING fleet.steer
 * grant store, read by the binding the row carries
 * (zcl_fleet_steer_grant_binding_live): the sender's name in a row is a
 * claim, and what is checked is that the grant carrying that name is the
 * one that stamped this row. A row with no stamp is unattributable and
 * refused. That binds a row to a credential, not to a peer key. A row that
 * crossed hosts on the signed fleet board is admitted instead on the board
 * signer its own node verified plus a peer grant for that enrolled box
 * (zcl_devagent_boardmail_admit below). */

/* Bounded drive options. `receiver` is this box's mail identity, and
 * `workspace` is the ONE workspace this receiver was started against — the
 * operator names it, never a sender. Empty means "no workspace configured",
 * and a directive naming a workspace selector is then refused rather than
 * resolved against a guess. */
struct rcv_drive_opts {
    char receiver[56];
    char workspace[1024];
    long long deadline_s; /* stop beating after this many seconds */
    long long wait_ms;    /* idle ceiling for one mail-watch wait */
    long long max_beats;  /* stop after this many beats (0 = deadline only) */
};

/* ── one workspace's observed identity ────────────────────────────────────
 * What the receiver can learn about a workspace from FILES ALONE — no git
 * spawn, no shell, so a beat can never block on a subprocess. Every field
 * is evidence; the policy that turns it into an admission or a refusal
 * lives in the receive leaf.
 *
 * `dirty` is git's own stat shortcut over the index: type, size, exec bit
 * and mtime seconds per tracked path, plus any unmerged stage. It catches a
 * modified, deleted or retyped tracked path without hashing a byte, and it
 * deliberately does NOT see an untracked file, an already-staged change, or
 * a rewrite inside the index's own second that preserves the size. That is
 * why it is the receiver's cheap EARLY refusal and muse_run's own
 * `git status` stays the authoritative pre-state gate. -1 means the
 * pre-state could not be read at all, which fails closed. */
#define ZCL_DEVAGENT_WS_PATH_MAX 1024u
#define ZCL_DEVAGENT_WS_NAMES_MAX 256u

struct rcv_workspace {
    char root[ZCL_DEVAGENT_WS_PATH_MAX]; /* realpath of the asked-for dir */
    char head[41];   /* HEAD commit, 40 lowercase hex, or "" when unresolved */
    char tree[65];   /* SHA3-256 over the index's (mode, path, object id)
                      * rows in index order — the staged tree's identity,
                      * equal on two boxes holding the same staged content.
                      * NOT tools/dev/source-identity.sh's source_id_sha256
                      * and not z23-dev agentbuild's either; those hash the
                      * built source set, this hashes the index. "" when the
                      * index was not walked. */
    char dirty_names[ZCL_DEVAGENT_WS_NAMES_MAX]; /* first few, comma-joined */
    long long dirty;  /* -1 unreadable/unscanned, 0 clean, else path count */
    long long tracked; /* index entries walked */
    bool directory;   /* the asked-for path is an existing directory */
    bool resolved;    /* realpath() resolved it; `root` is that canonical
                       * path, with "." and ".." collapsed and every
                       * symlinked component followed */
    bool checkout;    /* a git directory resolved for THIS worktree */
};

/* Observe `dir` without changing it. `scan_tracked` also walks the git
 * index for the tree id and the tracked-path pre-state; false skips that
 * walk and leaves dirty = -1 and tree = "". `root` is the CANONICAL path
 * whenever realpath() resolved it, so every caller works from the one real
 * directory rather than from the spelling it was handed. Returns false
 * only on a bad argument or an over-long path; an absent, unresolvable, or
 * non-checkout directory is reported through the fields, because the
 * caller — not this observer — decides what to refuse. */
bool zcl_devagent_workspace_observe(const char *dir, bool scan_tracked,
                                    struct rcv_workspace *out);

/* What one drive (or one read-only survey) observed. Counts only; no row
 * content ever leaves the loop. */
struct rcv_beat_stats {
    long long beats;
    long long seen;          /* directives addressed to this receiver */
    long long admitted;      /* newly queued refs */
    long long reconciled;    /* known refs whose stored brief matched */
    long long refused;        /* typed refusals, conflicts included */
    long long already;        /* rows this receiver had already answered */
    long long intake_failed;  /* beats whose mail pull did not answer */
    long long board_in;       /* rows carried in from the fleet board */
    long long board_out;      /* rows posted to the fleet board */
    long long board_deferred; /* carriage or admission waiting on the node */
};

/* ── board-carried mail (native_devagent_boardmail.c) ─────────────────────
 * The receiver's carriage between enrolled boxes over the signed FLEET
 * board, through this box's own node RPC. Both steps are no-ops on a box
 * with no enrolled peer, and in a dry (status) beat. */
struct zcl_boardmail_ctx {
    const char *receiver; /* this box's receiver name == its roster name */
    const char *recvdir;  /* <state>/receive: the carriage cursors */
    const char *maildir;  /* <state>/mail: outbox in, inbox.<box> out */
    bool dry;
};

/* Before intake: page this node's fleet posts and append each carried row
 * addressed here (or answering a row this box sent) to inbox.<box>.jsonl
 * with "board_post" and "board_signer". */
void zcl_devagent_boardmail_import(const struct zcl_boardmail_ctx *c,
                                   struct rcv_beat_stats *st);

/* After the answers: post outbox rows bound for another enrolled box, and
 * rows answering a directive that came from one, as FLEET notes. */
void zcl_devagent_boardmail_export(const struct zcl_boardmail_ctx *c,
                                   struct rcv_beat_stats *st);

/* True when `to` is a verified roster box other than this one. */
bool zcl_devagent_boardmail_remote(const char *to);

/* The longest mail row line (without its newline) the board carries: the
 * signed text ceiling of one fleet note (FLEET_BOARD_TEXT_MAX). A row bound
 * for another box that would not fit is refused where it is sent. */
#define ZCL_BOARDMAIL_TEXT_MAX 2048u

/* One pulled row carrying board fields, borrowed for one call. */
struct zcl_boardmail_row {
    long long seq;
    const char *ts, *from, *to, *kind, *body, *ref, *sender_binding;
    const char *board_post, *board_signer;
};

enum zcl_boardmail_verdict {
    ZCL_BOARDMAIL_ADMIT,
    ZCL_BOARDMAIL_REFUSE, /* final: answer and mark the row */
    ZCL_BOARDMAIL_DEFER,  /* the node did not answer: no marker, retry */
};

struct zcl_boardmail_decision {
    enum zcl_boardmail_verdict verdict;
    const char *code;  /* RECEIVE_PEER_*, NULL on admit */
    char detail[64];   /* the reason, or the admitting box on admit */
};

/* Admit a board-carried row: both fields 64 hex (UNSIGNED), this node shows
 * the unexpired post (POST_MISSING defers, POST_GONE refuses) carrying
 * exactly this row signed by board_signer (POST_MISMATCH), that signer is
 * an enrolled box other than `receiver` (UNENROLLED), and a live peer grant
 * carries row->from for that box (UNGRANTED). */
void zcl_devagent_boardmail_admit(const struct zcl_boardmail_row *row,
                                  const char *receiver,
                                  struct zcl_boardmail_decision *d);

/* Drive the resident loop until SIGTERM, the deadline, or the beat cap.
 * Returns beats completed (>= 0), or -1 when the singleton lock or the
 * state root refuses. Single instance: a second concurrent drive refuses
 * immediately and never waits. `st` may be NULL. */
long long zcl_devagent_receive_drive(const struct rcv_drive_opts *opts,
                                     struct rcv_beat_stats *st);

/* Decide what one beat would decide for every directive from the start of
 * the mail history (a survey ignores the resident's intake cursor and pages
 * through the whole history), and write and post nothing.
 * This is what the status action reports; it creates no directory, no
 * brief, no queue row, no marker and no mail. `workspace` is the same
 * operator-named workspace the resident runs with: a survey that is not
 * told it decides exactly as an unconfigured receiver would, because
 * guessing the resident's configuration would make status a fiction.
 * Returns beats surveyed (1), or -1 on a bad receiver name or an
 * unresolvable state root. */
long long zcl_devagent_receive_survey(const char *receiver,
                                      const char *workspace,
                                      struct rcv_beat_stats *st);

/* ── single-line source mutation ──────────────────────────────────────────
 * One deterministic edit to one line, chosen by the first applicable rule in
 * a left-to-right scan of the line's CODE regions (string literals, character
 * literals and trailing `//` comments are skipped). A line whose first
 * non-blank character starts a comment is refused outright: from one line
 * alone a block-comment interior is indistinguishable from code. */
#define ZCL_DEVAGENT_RULE_MAX  24
#define ZCL_DEVAGENT_TOKEN_MAX 24

struct zcl_devagent_mutation {
    char rule[ZCL_DEVAGENT_RULE_MAX];   /* e.g. "eq_to_ne" */
    char before[ZCL_DEVAGENT_TOKEN_MAX];
    char after[ZCL_DEVAGENT_TOKEN_MAX];
    size_t column;                      /* 1-based column of the edit */
};

/* Write the mutated form of `line` (which must NOT contain a newline) into
 * `out`. Returns false and leaves `out`/`m` zeroed when no rule applies —
 * that is a refusal the caller must report, never a silent no-op. */
bool zcl_devagent_mutate_line(const char *line, struct zcl_devagent_mutation *m,
                              char *out, size_t out_cap);

/* ── checkout root ────────────────────────────────────────────────────────
 * Walk up from `start` (NULL = current directory) until a directory carries
 * all three checkout markers. Returns false when none does — the caller must
 * then say so rather than guessing a root and writing somewhere else. */
bool zcl_devagent_checkout_root(const char *start, char *out, size_t out_cap);

/* ── bounded process helpers ──────────────────────────────────────────────
 * Not pure: these spawn (never through a shell) and are shared by the
 * dev.agent.* handlers. Both run from `root` and restore the caller's
 * directory before returning. A negative return is a launch failure. */
int zcl_devagent_run_make(const char *root, const char *target, int timeout_ms);

/* Run build/bin/test_parallel with one already-formed selector
 * ("--exact=x" / "--only=x") and --no-cache. `out` is always initialized; a
 * run whose transcript overflowed the capture buffer sets *truncated and
 * leaves out->present false rather than parsing a partial transcript. */
int zcl_devagent_run_group(const char *root, const char *selector,
                           int timeout_ms, struct zcl_devagent_verdict *out,
                           bool *truncated);

#endif /* ZCL_NATIVE_DEVAGENT_H */
