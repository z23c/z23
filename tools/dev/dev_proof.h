/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Exact commit/base proof scheduling and status interface. */

#ifndef ZCL_TOOLS_DEV_PROOF_H
#define ZCL_TOOLS_DEV_PROOF_H

#include "dev_proof_receipt.h"
#include "vcs/build_action.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Can a proof started in cgroup `self` (the unified path, "/a/b") under the
 * cgroup v2 mount `mount` run the test dimension's memory-limit leg?
 * QUALIFIED when an ancestor delegates the memory controller and is
 * writable by this uid; UNQUALIFIED when none is; UNKNOWN when there is no
 * hierarchy to read. Read-only. The proof worker refuses UNQUALIFIED before
 * it starts instead of after its test accounting. */
enum zcl_dev_proof_memory_scope {
    ZCL_DEV_PROOF_MEMORY_SCOPE_UNKNOWN = 0,
    ZCL_DEV_PROOF_MEMORY_SCOPE_QUALIFIED,
    ZCL_DEV_PROOF_MEMORY_SCOPE_UNQUALIFIED,
};
enum zcl_dev_proof_memory_scope zcl_dev_proof_memory_scope_verdict(
    const char *mount, const char *self);
/* Match complete candidate source identity to the compiler-injected identity
 * of the code computing proof policy. The production caller supplies the
 * pure clientversion getter, never an environment or request field. */
bool zcl_dev_proof_producer_source_qualified(const char *candidate_source,
    const char *producer_source, char *why, size_t why_len);

/* Compiled-in lint-dimension allowances until this checkout has measured
 * its own. Publishable proofs use the full landing allowance everywhere;
 * the default remains available to non-publication feedback callers. */
#define PROOF_LINT_DEFAULT_MS 600000
/* A publishable proof runs `make lint` plus check-windows-acceptance in
 * one invocation, inside a fresh generation whose object tree has never
 * compiled the ~47 one-shot standalone tools check-standalone-tools-link
 * links. It runs alongside the test dimension on purpose: three measured
 * landing-shaped proofs on a 32-core box under concurrent lane traffic
 * (2026-09-06) put all 202 gates at 373 s, 507 s and 670 s of wall time
 * against 188-230 s for the tests, so lint is always the longer of the two
 * and running it first would simply add the test dimension to every
 * landing. The cold check-standalone-tools-link inside those generations
 * was 118 s, 120 s and 636 s -- the last of them the whole lint run's
 * single largest item. Thirty minutes is about 2.6x the slowest total
 * observed, and a budget only ends a step that has ALSO gone silent for
 * PROOF_NO_PROGRESS_MS, which a run printing a gate line every few seconds
 * does not. The proof writes its measured wall time into the phases file
 * as lint_wall_ms beside the lint_targets line, so the next reader
 * replaces this number rather than trusting it. */
#define PROOF_LINT_LANDING_MS 1800000

/* The pre-fork build step: everything EITHER dimension can build, built once
 * before both start. A lane proof builds the helper executables the test
 * dimension execs; a landing proof additionally builds every target its full
 * gate set can build, which is dominated by the ~47 one-shot standalone
 * tools check-standalone-tools-link links -- 118 s, 120 s and 636 s in the
 * three measured landing-shaped generations above. That work is moved, not
 * new: it used to run inside the lint dimension, concurrently with the test
 * dimension reading the same binaries. The landing allowance matches the
 * lint one for that reason, and the step writes its measured wall into the
 * phases file as `step=prefork` so the next reader replaces the number. */
#define PROOF_PREFORK_DEFAULT_MS 120000
#define PROOF_PREFORK_LANDING_MS 1800000
/* make, --no-print-directory, -jN, the 8 helper targets, proof-lint-prebuild
 * and the NULL terminator: 13 slots, exactly. */
#define PROOF_PREFORK_ARGV_CAP 13u
/* Every BUILD row is a conservative upper bound on distinct helper targets.
 * Derive it from the same platform-qualified catalog the selector reads;
 * duplicate and already-provided targets still disappear during argv fill. */
enum {
    ZCL_DEV_PROOF_TEST_BUILD_NEED_ROWS = 0
#define ZCL_TEST_GROUP_NEED(id_, kind_, value_)
#define ZCL_TEST_GROUP_BUILD_NEED(id_, value_, target_) + 1
#include "test_group_host_needs.def"
#undef ZCL_TEST_GROUP_BUILD_NEED
#undef ZCL_TEST_GROUP_NEED
};
/* make, --no-print-directory, -jN, bounded targets and NULL terminator. */
#define PROOF_TEST_NEEDS_ARGV_CAP (ZCL_DEV_PROOF_TEST_BUILD_NEED_ROWS + 4u)

/* Room for the `host_gated=` line of the test-selection note: every group the
 * universal selector left out because this tree cannot meet its declared host
 * need, spelled `<group>:<kind>:<value>` and comma-joined. Overflowing this
 * refuses the selection rather than writing a truncated explanation. */
#define PROOF_HOST_GATED_MAX 4096u

enum zcl_dev_proof_state {
    ZCL_DEV_PROOF_STATE_INVALID = -1,
    ZCL_DEV_PROOF_STATE_MISSING = 0,
    ZCL_DEV_PROOF_STATE_RUNNING,
    ZCL_DEV_PROOF_STATE_PASSED,
    ZCL_DEV_PROOF_STATE_FAILED,
    /* Producer qualification refused before candidate tests: no verdict. */
    ZCL_DEV_PROOF_STATE_NO_VERDICT,
};

struct zcl_dev_proof_status {
    enum zcl_dev_proof_state state;
    char root[4096];
    char local_commit[65];
    char remote_base[65];
    char receipt_path[4096];
    char log_dir[4096];
    char detail[256];
    /* A settled failure's evidence digest: the failing step, its first
     * FAIL or compiler-error lines with repo-relative paths, and a
     * `logs:` pointer at the attempt. Empty when the record has none. */
    char evidence[1280];
    int64_t started_unix;
    int64_t eta_ms;
    int64_t worker_id;
    /* Seconds since the still-queued request was written and no worker
     * claimed it (claiming renames the request into its attempt dir, so a
     * present request means an unstarted one). 0 when no request is
     * queued. This is the honest liveness number behind
     * resident_proof_request_queued: state RUNNING is a claim about a
     * worker, and an unclaimed request has none. */
    int64_t request_age_s;
    bool receipt_reused;
};

struct zcl_dev_proof_child_action_inputs_v1 {
    const char *source_sha256_hex;
    const char *source_cas_sha3_hex;
    uint8_t toolchain_capsule_root[32];
    uint8_t flags_root[32];
    uint8_t environment_root[32];
    uint8_t build_graph_root[32];
    const char *selector;
    uint32_t selected;
};

/* What a proof was run under, in four roots. None of them contains this
 * checkout's location, so the same tree at two absolute paths -- on this box
 * or on another with the same toolchain -- produces the same four values,
 * which is what lets one box read another's receipt.
 *
 *   compiler     the toolchain capsule root: driver and backend bytes,
 *                assembler version, sysroot and ABI aggregates, target probe.
 *   flags        the compiler command and every flag the build plan passes.
 *   environment  the variables that reach the compiler without going through
 *                a flag (header/library redirection, SDK root, build clock).
 *   build_graph  which objects, response files and products the plan links.
 */
struct zcl_dev_proof_build_identity_v1 {
    uint8_t compiler[32];
    uint8_t flags[32];
    uint8_t environment[32];
    uint8_t build_graph[32];
};

/* Derive that identity for one checkout. This is the only derivation of
 * these four roots in the tree: the receipt's compiler_root/flags_root/
 * environment_root/build_graph_root and the warm-start donor seal both come
 * from this call, so the two can never disagree. Reads
 * <repo_root>/build/dev-loop/restart.env and captures the toolchain capsule;
 * false means one of those was unavailable and no root was produced. `why`
 * (may be NULL) receives the exact cause -- for example
 * "restart_env_missing:<path> (make dev-bin)" when a fresh worktree never
 * ran the generator that writes that file. Defined on POSIX hosts, like the
 * rest of the proof worker. */
bool zcl_dev_proof_build_identity_v1_capture(
    const char *repo_root, struct zcl_dev_proof_build_identity_v1 *out,
    char *why, size_t why_len);

/* Compare the executed plan with the requested flags and dependency graph,
 * and bind its local BASE_GENERATION to that tree's sealed mutation token.
 * A relocation may change the token, never the other plan inputs. */
bool zcl_dev_proof_build_plan_verify(
    const char *root, const struct zcl_dev_proof_build_identity_v1 *expected,
    const char *expected_mutation, char *why, size_t why_len);

/* One captured base..local changed set. Heap-resident: the row ceiling is a
 * landing-batch ceiling (thousands of paths), which must never sit in a stack
 * frame. `files` holds `count` pointers into `bytes`; release both together.
 * `structural_path` is the first added, deleted or type-changed row (a
 * pointer into `bytes`, NULL when every row is a content change) and
 * `structural_count` how many such rows there are. No old depfile can hold an
 * edge for a formerly absent path, so such a set is never narrowed: the proof
 * runs its full closure instead. */
struct zcl_dev_proof_changed_set {
    char *bytes;
    const char **files;
    size_t count;
    /* Owned second half of files allocation, populated only from validated
     * non-D Git rows. NULL means no status authority: query every file. */
    const char **current_files;
    size_t current_count;
    const char *structural_path;
    size_t structural_count;
};

#if defined(ZCL_TESTING)
struct zcl_devloop_plan;
bool zcl_dev_proof_test_changed_set_close(const char *root,
    const struct zcl_dev_proof_changed_set *set,
    struct zcl_devloop_plan *plan, const char **reason);
#endif

/* Capture the exact base..local changed set the proof worker plans against.
 *
 * `repo_root` must be a git worktree already checked out to exactly `local`
 * (a live worktree a concurrent step can still rebase is the wrong thing to
 * pass — the generation copy `worktree_exact()` already pinned is the
 * right one; passing the shared source worktree here reopens the same
 * source-identity TOCTOU the generation checkpoint exists to close). Any
 * such worktree resolves `base` and `local` from the shared object
 * database, so a private git worktree sharing the same .git works exactly
 * like the original checkout for `merge-base`/`diff`.
 *
 * The list is written to `scratch_path` by git and read whole, so no fixed
 * capture buffer can silently shorten it; over-ceiling and unreadable captures
 * refuse with a typed reason naming the observed count. An unknown status, an
 * unsafe path or a short list refuses too. An added, deleted or type-changed
 * row is kept and marked in `structural_path`, never refused: it widens the
 * proof to the full closure. `persist_path` (may be NULL) receives the
 * newline-separated record. On success the caller owns `*out` until
 * zcl_dev_proof_changed_set_release(). */
bool zcl_dev_proof_changed_set_capture(const char *repo_root, const char *base,
                                       const char *local,
                                       const char *scratch_path,
                                       const char *persist_path,
                                       struct zcl_dev_proof_changed_set *out,
                                       char *why, size_t why_len);
void zcl_dev_proof_changed_set_release(struct zcl_dev_proof_changed_set *set);

/* One base..local test selection, exactly what the proof worker would run.
 * `groups` is the caller's buffer for the comma-separated exact selector,
 * `gated` receives the host-gated list a universal selection left out.
 * `reason` is a static spelling of why the set is this wide. */
struct zcl_dev_proof_range_selection {
    char *groups;
    size_t groups_size;
    uint32_t count;
    size_t files;
    bool universal;
    const char *reason;
    char detail[160];
    char gated[PROOF_HOST_GATED_MAX];
};
size_t zcl_dev_proof_select_groups_capacity(void);
bool zcl_dev_proof_select_range(const char *root, const char *base,
                                const char *local,
                                struct zcl_dev_proof_range_selection *out,
                                char *why, size_t why_len);

const char *zcl_dev_proof_state_name(enum zcl_dev_proof_state state);
/* Admit a completed cycle only when its schema, canonical action inputs, and
 * one independently derived fixed-width root per selected proof dimension
 * exactly match. Duplicate critical JSON keys are always inadmissible. */
bool zcl_dev_proof_cycle_reuse_admissible(
    const char *body, size_t body_len, const char *source_cas,
    const char *proof_inputs_sha3,
    const struct zcl_dev_proof_dimension
        dimensions[ZCL_DEV_PROOF_DIMENSIONS]);
/* Derive the existing zcl.build_action.v1 identity for one local proof child.
 * This has no durable task, queue, worker, signing, or admission authority. */
bool zcl_dev_proof_child_action_v1(
    const struct zcl_dev_proof_child_action_inputs_v1 *inputs,
    enum zcl_dev_proof_dimension_id dimension,
    struct vcs_build_action_v1 *action, uint8_t action_root[32]);
/* d8f84411e makes generation dependencies independent clones or copies. */
#define ZCL_DEV_PROOF_MATERIALIZER_CLONES 1
/* Testing seam: materialize one generation dependency with an independent
 * inode, preserving mode and mtime. No proof, lease, or admission authority. */
bool zcl_dev_proof_dependency_materialize(const char *source,
                                          const char *target);
/* Sweep both of this checkout's generation pools (the disk pool beside the
 * checkout, and this host's RAM root when it offers one) for finished
 * generations and remove them, bounded and lease-aware exactly like the
 * reap the proof already runs on its own hot path -- this is the same
 * policy invoked explicitly, not a second one. `removed_out`/`bytes_out`
 * (either may be NULL) report what was actually deleted so a caller (the
 * landing leaf, at attempt end or the next submit) can log it. Returns
 * false only when neither pool path could even be computed from
 * `repo_root`; finding nothing to remove is success, not a refusal. */
bool zcl_dev_proof_generation_pool_sweep(const char *repo_root,
                                         size_t *removed_out,
                                         uint64_t *bytes_out, char *why,
                                         size_t why_len);
bool zcl_dev_proof_resolve_pair(const char *repo_root,
                                const char *requested_local,
                                const char *requested_base,
                                char local_commit[65],
                                char remote_base[65],
                                char *why, size_t why_len);
bool zcl_dev_proof_status_read(const char *repo_root,
                               const char *local_commit,
                               const char *remote_base,
                               struct zcl_dev_proof_status *out);
bool zcl_dev_proof_ensure(const char *repo_root,
                          const char *local_commit,
                          const char *remote_base,
                          struct zcl_dev_proof_status *out);
/* Explicitly queue another full proof after a settled failure. Requires no
 * pending request/live worker, preserves the prior attempt's failure and
 * logs, and refuses passed pairs. Scheduling grants no receipt authority. */
bool zcl_dev_proof_retry(const char *repo_root,
                         const char *local_commit,
                         const char *remote_base,
                         struct zcl_dev_proof_status *out);
/* The settled `.failed` record of this exact pair: true with its path when
 * one exists and is readable. Evidence only; it grants no receipt. */
bool zcl_dev_proof_failure_path(const char *repo_root,
                                const char *local_commit,
                                const char *remote_base, char *out,
                                size_t out_len);
/* Scheduling exclusion shared by foreground and resident edit/commit workers.
 * Returns 1 with an owned descriptor, 0 busy, -1 refusal. Across fork the
 * parent closes its copy without unlocking; the child releases after work. */
int zcl_dev_proof_execution_acquire(const char *root, int *guard,
                                    char *why, size_t why_len);
void zcl_dev_proof_execution_release(int guard);
/* Foreground execution of only the explicit pair in an unarmed checkout.
 * Existing watcher state refuses admission; no watcher state is created.
 * A bounded child owns both guards through worker/lease cleanup. Requester
 * cancellation settles that child; requester hard death leaves its guards
 * owned. Hard death of the guard-owning worker is qualified by the
 * impact_composition acceptance (worker SIGKILL frees guards, preserves
 * evidence, admits no completion): the kernel releases both guards, the
 * pair returns to MISSING with its consumed request preserved in the dead
 * attempt, retry refuses until a failure settles, and requeue plus any
 * eligible worker continue under the existing lease rules.
 * Returns 1 when settled (inspect status, never infer PASS), 0 busy, -1
 * invalid/unavailable. Existing failed attempts require explicit retry. */
int zcl_dev_proof_step(const char *root, const char *local, const char *base,
                        struct zcl_dev_proof_status *out);
/* A caller-supplied observation that the pair's base is no longer the
 * remote tip. SUPERSEDED is the only answer that acts: the foreground
 * requester then cancels its worker exactly as a SIGTERM would, so every
 * running step's process group gets TERM, 100 ms, then KILL, and the pair
 * settles as a cancelled failure that can never read as PASS. UNKNOWN
 * (no answer, timeout, unreadable output) and CURRENT never cancel and
 * never admit anything. */
enum zcl_dev_proof_base_observation {
    ZCL_DEV_PROOF_BASE_UNKNOWN = 0,
    ZCL_DEV_PROOF_BASE_CURRENT = 1,
    ZCL_DEV_PROOF_BASE_SUPERSEDED = 2,
};
struct zcl_dev_proof_base_probe {
    enum zcl_dev_proof_base_observation (*observe)(void *ctx);
    void *ctx;
    int interval_ms; /* <= 0 selects ZCL_DEV_PROOF_BASE_PROBE_MS */
};
#define ZCL_DEV_PROOF_BASE_PROBE_MS 30000
/* zcl_dev_proof_step with the base watched while the foreground worker
 * runs. `probe` may be NULL (identical to zcl_dev_proof_step). When the
 * probe cancelled the worker, `*superseded` is set and out->detail keeps
 * the settled pair's own failure text. */
int zcl_dev_proof_step_watched(const char *root, const char *local,
                               const char *base,
                               const struct zcl_dev_proof_base_probe *probe,
                               struct zcl_dev_proof_status *out,
                               bool *superseded);
/* Settled failure texts that record an interruption of the run (a step
 * cancelled by the requester, or a run cancelled between steps) rather than
 * a verdict on the candidate. They are still failures and never PASS; a
 * lander may re-run the same pair, a bounded number of times. The budget's
 * own no_progress and hard_ceiling kills are verdicts, not interruptions. */
#define ZCL_DEV_PROOF_INTERRUPTED_PREFIX "proof_interrupted_"
/* run_step_why()'s spelling for a step ended by ZCL_DEV_PROOF_KILL_CANCELLED. */
#define ZCL_DEV_PROOF_STEP_CANCELLED_PREFIX "child_proof_cancelled_"
/* Header-inline so the lander reads the same predicate the proof worker
 * writes against without a link dependency on dev_proof.c. */
static inline bool zcl_dev_proof_failure_interrupted(const char *detail)
{
    static const char step[] = ZCL_DEV_PROOF_STEP_CANCELLED_PREFIX;
    static const char run[] = ZCL_DEV_PROOF_INTERRUPTED_PREFIX;
    return detail && (strncmp(detail, step, sizeof(step) - 1) == 0 ||
                      strncmp(detail, run, sizeof(run) - 1) == 0);
}
#if defined(ZCL_TESTING) && !defined(_WIN32)
/* The requester's wait loop over an already-forked worker, for tests. */
int zcl_dev_proof_test_foreground_wait(
    int worker_pid, const struct zcl_dev_proof_base_probe *probe,
    bool *superseded);
/* Run one stub child as dimension `id` of a fresh attempt for the exact
 * pair under `repo_root` and settle its failure exactly as a proof worker
 * does. True when the child failed and its failure was settled. */
bool zcl_dev_proof_test_settle_child(const char *repo_root, const char *local,
                                     const char *base,
                                     enum zcl_dev_proof_dimension_id id,
                                     const char *const argv[], char *why,
                                     size_t why_len);
#endif
/* Notifications publish immutable requests. All consumers share execution
 * exclusion; queue claim remains separately locked and bounded. */
bool zcl_dev_proof_queue_has_pending(const char *repo_root);
int zcl_dev_proof_queue_run_next(const char *repo_root,
                                 char *why, size_t why_len);
bool zcl_dev_proof_wait(const char *repo_root,
                        const char *local_commit,
                        const char *remote_base,
                        int timeout_ms,
                        struct zcl_dev_proof_status *out);

/* The routed-group preflight account: what one batch probe of the whole
 * required set reported. would_reuse + must_run == groups always. It is
 * advisory and never execution authority: the test dimension runs every
 * selected group cold until a separate-uid verifier qualifies, so
 * would_reuse only measures what reuse could save. Declared
 * unconditionally: the proof worker fills it in production, the seam below
 * exposes its parser to tests. */
struct zcl_dev_proof_preflight {
    uint32_t groups;
    uint32_t would_reuse;
    uint32_t must_run;
    uint32_t uncacheable;
};

/* The five capsule arguments a runner child takes (write vs use plus the
 * four sealed bindings). Storage travels with the struct so the argv
 * pointers stay valid through the spawn; the worker fills one on its
 * stack for the advisory preflight, the seam below exposes the same
 * builder to tests. Declared unconditionally so every compilation of
 * dev_proof.c sees the same layout; only the seam function is test-gated. */
struct zcl_dev_proof_capsule_argv {
    char capsule[192];
    char sid[96];
    char mid[96];
    char cas[96];
    char graph[96];
    const char *argv[6];
};

/* Bytes the queued CHECK worker hashes into one component proof key.
 * Production leaves `active` false and binds these pointers to the
 * receipt, helper root, and depfile root it already sealed. A null
 * pointer for one of those fields is an incomplete closure. */
struct zcl_dev_proof_check_inputs {
    bool active;
    const char *unit;
    const uint8_t *source_cas;
    const uint8_t *dependency;
    const uint8_t *harness;
    const uint8_t *flags;
    const uint8_t *environment;
    const uint8_t *build_graph;
    const uint8_t *toolchain;
    const uint8_t *policy;
    const uint8_t *changed;
};

#if defined(ZCL_TESTING)
struct vcs_component_proof_key_v1;
struct vcs_proof_receiver;
struct vcs_proof_candidate_domain;
struct vcs_proof_reuse_policy;

/* What one call of the queued CHECK dimension did. `test_children` counts
 * test steps whose child process was actually forked. */
struct zcl_dev_proof_check_result {
    bool ok;
    uint32_t test_children;
    uint32_t selected;
    uint32_t ran;
    uint32_t reused;
    uint32_t failed;
    uint32_t skipped;
    uint8_t receipt_root[32];
    char why[160];
    bool log_present;
    /* Set when any of receiver, domain, or policy was null and the
     * worker replaced all three. `derived_policy_root` is the closure's
     * policy field. `derived_author` is the box signer copied into that
     * domain. `authority_trust` is the root-pinned verifier loader's
     * token, or verifier_unqualified when a key loaded and was not
     * adopted. `authority_local_signer` is that domain's
     * has_local_signer bit, not a second copy of `authority_derived`. */
    bool authority_derived;
    bool authority_local_signer;
    uint8_t derived_policy_root[32];
    uint8_t derived_author[32];
    char authority_trust[64];
};

/* The same derivation dp_worker_dimensions_run uses. Tests issue tickets
 * for this key; they do not pass the key back into the dimension. */
bool zcl_dev_proof_check_closure_derive(
    const struct zcl_dev_proof_check_inputs *in,
    struct vcs_component_proof_key_v1 *key);

/* Enter the queued CHECK dimension from the worker state it already has:
 * sealed bytes, optional receiver, and the test child it would exec.
 * Does not accept a key, change, or obligation. A null receiver, domain,
 * or policy is derived from the closure and this attempt's signer, then
 * checked against that closure. It does not skip while no separate-uid
 * verifier is qualified. */
bool zcl_dev_proof_check_dimensions(
    const struct zcl_dev_proof_check_inputs *in, const char *logs_dir,
    const char *root, const char *generation_binary, uint32_t selected,
    const struct vcs_proof_receiver *receiver,
    const struct vcs_proof_candidate_domain *domain,
    const struct vcs_proof_reuse_policy *policy,
    struct zcl_dev_proof_check_result *out);

/* Watcher admission fixture: a held execution guard must preserve pending
 * edit work without forking a worker or arming a watcher. */
bool zcl_dev_proof_test_edit_busy(const char *root);
bool zcl_dev_proof_test_edit_lifetime(const char *root);
/* The generation's exact required/optional dependency policy and copy path.
 * Missing optional inputs succeed only if the generation also lacks them;
 * a stale generation copy, unsafe source, or inspection/copy error refuses. */
bool zcl_dev_proof_test_generation_dependency(const char *root,
                                              const char *generation,
                                              const char *dependency,
                                              char *why, size_t why_len);
/* Seam for the selection regression: the same builder the proof worker uses,
 * so a test can prove a universal plan selects the whole catalog without
 * running a proof cycle. `root` is the tree the runner would exec in, and the
 * one the declared host needs are asked of; `gated_out` receives the same
 * `host_gated=` list the selection note carries. */
struct zcl_devloop_plan;
bool zcl_dev_proof_test_build_test_selector(
    const struct zcl_devloop_plan *plan, const char *root, bool inventory_only,
    char *out, size_t out_size, uint32_t *count_out, char *gated_out,
    size_t gated_size);
/* Seam for the structural-change widening: plan `set`'s files, apply the
 * same widening the proof worker applies after its plan closes, and build
 * the selector. `*universal_out` says whether the plan was widened to the
 * full closure. */
bool zcl_dev_proof_test_changed_set_selector(
    const struct zcl_dev_proof_changed_set *set, const char *root, char *out,
    size_t out_size, uint32_t *count_out, bool *universal_out,
    char *gated_out, size_t gated_size);
/* Seam for the preflight parser: the exact reader the proof worker uses to
 * turn the runner's --cache-probe-only output into the account above, so a
 * test can prove the counts (and the summary self-check) without driving a
 * proof cycle or spawning a runner. */
bool zcl_dev_proof_test_preflight_parse(const char *bytes, size_t len,
                                        struct zcl_dev_proof_preflight *out);
/* Seam for the preflight's empty-store skip: the exact decision the proof
 * worker makes before spawning the probe. True means the store provably
 * holds no verdict, the spawn is skipped, and phases_path received
 * `test_preflight=advisory skipped reason=empty_verdict_store`; false means
 * the probe runs as before. */
bool zcl_dev_proof_test_preflight_skip(const char *store_root,
                                       const char *phases_path);
/* Seam for the fail-closed test dimension: the exact runner argv the proof
 * worker launches. It carries the runner's explicit cold mode, so a test
 * can prove no cached verdict is admitted without spawning a runner.
 * Returns the argc written (argv NULL-terminated), or 0 on bad input or a
 * too-small argv_cap. */
size_t zcl_dev_proof_test_dimension_argv(const char *binary, const char *only,
                                         const char **argv, size_t argv_cap);
/* Seam for the test-dimension accounting: the exact reader that turns the
 * runner's SUITE VERDICT line into the receipt's test counts. `dim->selected`
 * is the input; it refuses a log with any failed, skipped, unobserved or
 * cached (reused) group. */
bool zcl_dev_proof_test_log_account(const char *path,
                                    struct zcl_dev_proof_dimension *dim);
/* Seam for the host-size decision: true when a host with `available_cpus`
 * finishes the test child before starting lint. */
bool zcl_dev_proof_test_lint_waits_for_tests(uint32_t available_cpus);
/* Seam for the lint/test launch: starts test_argv, then holds lint_argv. With
 * finish_tests_first the test child ends first; otherwise lint starts when the
 * test log carries ZCL_TEST_EXCLUSIVE_PASS_DONE, the test child ends, or
 * hold_max_ms passes. Both are then waited for. Logs land in logs_dir. rcs[0]
 * is lint's exit, rcs[1] the test's; `hold` names why lint started. */
bool zcl_dev_proof_dimensions_run_for_test(const char *logs_dir,
                                           const char *const lint_argv[],
                                           const char *const test_argv[],
                                           int64_t hold_max_ms,
                                           bool finish_tests_first,
                                           int rcs[2], char *hold,
                                           size_t hold_size);
/* Seam for the capsule argv builder: the exact flags the worker hands the
 * advisory preflight (write=true), and the use form (write=false) a
 * qualified reuse path would hand a consumer, so a test can prove both
 * forms carry the same bindings without driving a proof cycle. The proof's
 * test dimension takes neither while it runs cold. Returns 5 with
 * argv[0..4] set and argv[5] NULL, or 0 on any bad input or argv_cap < 6. */
int zcl_dev_proof_test_capsule_argv(bool write, const char *capsule_path,
                                    const char *source_id,
                                    const char *mutation_id,
                                    const char *source_cas,
                                    const char *graph_root,
                                    const char **argv, size_t argv_cap);
/* Seam for the stress-env regression: the exact call the test dimension
 * makes right before it launches its runner, so a test can prove
 * ZCL_STRESS_TESTS lands in this process's own environ (and therefore in
 * every execvp()'d test child) without driving a full proof cycle. */
bool zcl_dev_proof_test_stress_env_prepare(char *why, size_t why_len);
/* Seam onto the per-proof observation/testcache store environment the worker
 * arms before the test dimension: prepare lands both knobs pointing at
 * per-pair directories under <state>; restore removes them again. */
bool zcl_dev_proof_test_observation_env_prepare(const char *state,
                                                const char *key,
                                                char *why, size_t why_len);
bool zcl_dev_proof_test_observation_env_restore(const char *state,
                                                const char *key);
/* Exercise the proof worker's actual runtime admission before it forks. */
bool zcl_dev_proof_test_clang_runtime_check(char *why, size_t why_len);
const char *zcl_dev_proof_test_clang_runtime_path(void);
/* Seam for the warm-status-line regression: the exact reader
 * `dev proof status`/`dev proof wait` uses to turn one warm-start sidecar
 * into the single line a developer reads beside an admitted receipt, so a
 * test can prove "warm-start from donor <id>" / "cold: <typed reason>"
 * against a fixture sidecar without driving a full proof cycle. */
bool zcl_dev_proof_test_warm_status_line(const char *warmstart_path,
                                         char *out, size_t out_len);
/* Text-only reader classes: 0 warm status, 1 running marker, 2 lease,
 * 3 request, 4 failure record, 5 settled-worker running marker. */
bool zcl_dev_proof_test_text_reader(const char *path, unsigned reader);
/* Seam for the landing-lint regression: the same argv, fallback budget, and
 * recorded target list the proof worker uses for the lint dimension, so a
 * test can prove every root runs the whole gate set plus Windows
 * acceptance, without driving a make or a proof cycle. */
bool zcl_dev_proof_test_lint_argv(const char *root, const char *jobs,
                                  const char **argv, size_t argv_cap,
                                  size_t *argc_out, int64_t *fallback_ms,
                                  const char **targets_out);
/* Same environment normalization performed before any proof child runs. */
bool zcl_dev_proof_test_prepare_environment(void);
/* Seam for compile-cache isolation: runs the worker's compile-store step for
 * the proof state directory `state` and pair `key`, then writes to `store`
 * the zcc store a compile started from this process would now use. */
bool zcl_dev_proof_test_compile_store(const char *state, const char *key,
                                      char *store, size_t store_len);
/* Removes what zcl_dev_proof_test_compile_store() opened. */
bool zcl_dev_proof_test_compile_store_close(const char *state,
                                            const char *key);
/* Seam for the shared admitted-executable set: the one table both the lint
 * and the test dimension materialize into a generation. Writes at most
 * `cap` source/target pairs, relative to the submitting checkout and the
 * generation respectively, and returns how many it wrote (0 if `cap` is
 * too small). */
size_t zcl_dev_proof_test_admitted_executables(const char **sources,
                                               const char **targets,
                                               size_t cap);
/* Seam for the generation-hooks regression: the exact reconfiguration
 * generation_prepare() applies after copying build/githooks into a fresh
 * generation, so a test can prove a generation whose worktree config still
 * names the submitting checkout's hooks gets pointed at its own copy,
 * without driving a full proof cycle. */
bool zcl_dev_proof_test_generation_hooks_configure(const char *generation,
                                                   char *why, size_t why_len);
/* Exact dependency materialization used by generation_prepare. No proof,
 * lease or publication authority; POSIX-only like the generation worker. */
bool zcl_dev_proof_test_generation_dependencies(const char *root,
                                                const char *generation,
                                                char *why, size_t why_len);
/* Seam for the generated-docs freshness precheck: the exact read-only
 * verification generation_prepare() runs inside the sealed generation
 * before any expensive dimension starts, so a test can prove a stale
 * generated file refuses fast with its typed name without driving a
 * full proof cycle. */
bool zcl_dev_proof_test_generation_docs_fresh(const char *generation,
                                              char *why, size_t why_len);
/* Seam for the overlapped form proof_worker() runs: start the same checkers
 * with a `timeout_ms` deadline, spend `overlap_ms` as the proof's own steps
 * would, then settle them against the verdict those steps reached
 * (`later_ok`, or the refusal `later_why`) exactly as proof_worker() does.
 * Returns the final verdict with its reason in `why`. */
bool zcl_dev_proof_test_docs_fresh_overlapped(const char *generation,
                                              int64_t timeout_ms,
                                              int64_t overlap_ms,
                                              bool later_ok,
                                              const char *later_why,
                                              char *why, size_t why_len);
/* How the proof that used a generation settled, for the retire seam. */
enum zcl_dev_proof_retire_verdict {
    ZCL_DEV_PROOF_RETIRE_PASSED = 0,
    ZCL_DEV_PROOF_RETIRE_FAILED,
    ZCL_DEV_PROOF_RETIRE_INTERRUPTED,
    ZCL_DEV_PROOF_RETIRE_NO_VERDICT,
};
/* Seam for the retirement proof_worker() runs on `generation` (a worktree
 * of `repo_root`) once its proof settles: `verdict` is how it settled, and
 * `donor_eligible` stands in an eligible donor verdict for the real
 * same-uid refusal. Writes the outcome name (removed, removed_failed,
 * kept_interrupted, kept_no_verdict, kept_donor, kept_not_clean, remove_failed,
 * kept_invalid) and returns true only when the generation was removed. */
bool zcl_dev_proof_test_generation_retire(
    const char *repo_root, const char *generation,
    enum zcl_dev_proof_retire_verdict verdict, bool donor_eligible,
    char *outcome, size_t outcome_len);
/* Seam for the checkout generation_prepare() runs:
 `generation` is where
 * the pair's worktree of `repo_root` at commit `local` lives. A directory
 * already there is reused, except one whose worktree registration git has
 * deleted (an earlier retire that failed on the tree), which is cleared and
 * checked out fresh. False names the refusal in `why`. */
bool zcl_dev_proof_test_generation_checkout(const char *repo_root,
                                            const char *generation,
                                            const char *local, char *why,
                                            size_t why_len);
/* Name dp_donor_trust_verdict() returns for `path`: a path this uid owns,
 * or one lstat cannot see, is donor_untrusted_same_uid. A path another uid
 * owns stays donor_verifier_unqualified until a separate verifier is
 * qualified. Does not accept that donor or install a verifier. */
const char *zcl_dev_proof_test_donor_trust_name(const char *path);
/* Canonical submitting-checkout preparation, without a proof lease or receipt. */
bool zcl_dev_proof_test_preflight_prepare(const char *root, const char *local,
                                         const char *producer_source,
                                         const char *log_path,
                                         char *why, size_t why_len);
bool zcl_dev_proof_test_original_plan_prepare(const char *root,
                                              const char *local,
                                              const char *log_path,
                                              char *why, size_t why_len);
/* Seam for the lint-target split: true when a recorded target list is the
 * whole gate set rather than the fast subset. */
bool zcl_dev_proof_test_lint_targets_are_full(const char *targets);
/* Seam for the pre-fork build step: the exact make argv the proof runs ONCE,
 * alone, before it forks its lint and test dimensions. A test uses it to
 * prove that everything either dimension can build is built here, so no
 * target is left for both children to link at the same time in the one
 * generation worktree. Writes a NULL-terminated argv and returns false when
 * `argv_cap` is too small. */
bool zcl_dev_proof_test_prefork_argv(const char *jobs, bool lint_full,
                                     const char **argv, size_t argv_cap);
/* Seam for the test-needs build step: the exact make argv the proof runs in
 * its generation, before the fork, for the Make targets that the selected
 * groups (`groups`, the comma-separated exact selector) declare as
 * ZCL_HOST_NEED_BUILD needs, each named once. `*targets` gets how many
 * targets the argv names; 0 means no selected group needs a build, and the
 * proof runs no step. Returns false -- a refusal -- for an unregistered group,
 * a malformed need row, or an argv that does not fit `argv_cap`. */
bool zcl_dev_proof_test_needs_argv(const char *jobs, const char *groups,
                                   const char **argv, size_t argv_cap,
                                   size_t *targets);
/* Seam for the docs-tools build step: the exact make argv generation_prepare()
 * runs inside the sealed generation before the docs-fresh verification, so a
 * test can prove the freshness gate's checker binaries are provisioned
 * without driving a full proof cycle. Writes a NULL-terminated argv and
 * returns false when `argv_cap` is too small. */
bool zcl_dev_proof_test_docs_tools_argv(const char *jobs, const char **argv,
                                        size_t argv_cap);
#endif

/* True when a BUILD need is already provided for every test-selected proof:
 * `target` is a prefork helper, or `value` is an admitted executable path.
 * The test-needs argv leaves those out. */
bool zcl_dev_proof_need_already_provided(const char *target, const char *value);

/* Warm-start survey types. Inert data, declared unconditionally so every
 * compilation of dev_proof.c sees the same layout; only the seam
 * functions below are macro-gated. */
enum zcl_dev_proof_warm_seed_class {
    ZCL_DEV_PROOF_WARM_SKIP = 0,
    ZCL_DEV_PROOF_WARM_LINK,
    ZCL_DEV_PROOF_WARM_COPY,
};

struct zcl_dev_proof_warm_candidate {
    char tag[33];
    char path[PATH_MAX];
    char local[65];
    int64_t completed;
    int64_t touched;
    bool head_ok;
    bool live;
};

/* files_linked counts every seeded file: hard-linked outputs plus the
 * copied wrapper. The sidecar reports the same number. */
struct zcl_dev_proof_warm_stats {
    uint64_t files_linked;
    uint64_t bytes_linked;
};

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
/* The landing step-lock share a resident proof worker performs before it
 * claims a queued request, against a caller named lock file and window.
 * Preparation holds that lock exclusively for a whole `dev land step`, and a
 * once-per-loop non-blocking attempt could be starved by a keeper stepping in
 * a loop; 1 acquired, 0 still held when the window ran out, -1 the lock file
 * is unusable. Exposed so the group measures what the window buys. */
int zcl_dev_proof_landing_step_share(const char *step_path, int wait_ms);
/* Warm-start test seam. The harness proves the donor policy and the
 * link/copy decision against fixture trees; the dev binary compiles the
 * same seam. A release build sees none of it. POSIX-only, like the
 * warm-start machinery itself. */
/* Generation-pool hygiene seams, aimed at a fixture pool instead of this
 * host's. `parent` is the pool directory and `in_use` the one generation
 * that must never be taken ("" for none); both counters are INCREMENTED,
 * never reset, exactly as the internal reaps report.
 *
 * The first is the age reap generation_prepare() runs after it has taken
 * its generation -- the pass that reclaims an abandoned lane's sole
 * complete generation. The second is the pressure pass it runs BEFORE it
 * reserves RAM, told what the pool has free and what the reservation
 * needs, so a test can simulate a full pool without one. Neither grants
 * any proof, lease, or admission authority; both are advisory hygiene. */
void zcl_dev_proof_test_generation_pool_reap(const char *repo_root,
                                             const char *parent,
                                             const char *in_use,
                                             size_t *removed_out,
                                             uint64_t *bytes_out);
void zcl_dev_proof_test_pool_pressure_reap(const char *repo_root,
                                           const char *parent,
                                           const char *in_use,
                                           uint64_t free_bytes,
                                           uint64_t need_bytes,
                                           const char *phases,
                                           size_t *removed_out,
                                           uint64_t *bytes_out);
/* The pool name a proof of `local` from checkout `root` (canonical, as
 * the proof resolves it) gives its generation. */
void zcl_dev_proof_test_generation_tag(const char *root, const char *local,
                                       char tag[33]);
bool zcl_dev_proof_warm_tag(const char *name);
/* The ZCL_DEV_PROOF_WARM=0/"off"/"no" opt-out, exposed so the harness
 * proves the cold-forcing switch it gates on. */
bool zcl_dev_proof_warm_disabled(void);
enum zcl_dev_proof_warm_seed_class zcl_dev_proof_warm_classify(
    const char *rel, bool is_reg);
int zcl_dev_proof_warm_pick(const struct zcl_dev_proof_warm_candidate *c,
                            size_t n);
/* `identity` seals what the donor was built under: the same four roots the
 * receipt records (dev_proof_receipt.h), from the same capture call. A
 * marker without a matching identity on read is refused, so the harness
 * proves the invalidation directly rather than only through the private
 * warm_marker_read() it gates. */
bool zcl_dev_proof_warm_marker_write(
    const char *generation, const char *root, const char *local,
    const char *base, int64_t completed,
    const struct zcl_dev_proof_build_identity_v1 *identity);
bool zcl_dev_proof_warm_marker_read(
    const char *generation, char root[PATH_MAX], char local[65],
    char base[65], int64_t *completed,
    struct zcl_dev_proof_build_identity_v1 *identity);
/* Seed donor_build into gen_build (object and depfile outputs linked or
 * privately copied under the host's donor-isolation policy,
 * dependency room files and the wrapper copied, everything else skipped)
 * and repair the timestamp graph so exactly `changed` (relative to gen_src)
 * reads newer than the seeds. `copy_wrapper` is the caller gate production
 * computes from the bootstrap-inputs diff: false leaves bin/zcc behind and
 * must leave every other seedable file, room copies included, untouched. */
bool zcl_dev_proof_warm_seed_and_retime(const char *donor_build,
                                        const char *gen_build,
                                        const char *gen_src,
                                        bool copy_wrapper,
                                        const char *const *changed,
                                        size_t nchanged,
                                        struct zcl_dev_proof_warm_stats *stats);
#endif /* ZCL_DEV_BUILD || ZCL_TESTING */

#endif
