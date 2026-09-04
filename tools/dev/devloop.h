/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_TOOLS_DEVLOOP_H
#define ZCL_TOOLS_DEVLOOP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZCL_DEVLOOP_MAX_FILES 256
#define ZCL_DEVLOOP_PATH_MAX 1024
#define ZCL_DEVLOOP_OUTPUT_MAX 65536
#define ZCL_DEVLOOP_RESTART_SOURCE_MAX 32
/* A graph plan can legitimately reach hundreds of registered proof owners
 * through a central header. Retain a measured 512-group envelope while the
 * per-path accumulator remains separate; overflow still refuses.
 * The rendered command document has an independent byte ceiling. */
#define ZCL_DEVLOOP_MAX_PLAN_GROUPS 512
#define ZCL_DEVLOOP_GROUP_MAX 64
/* Union across every dimension: the path floor plus the closure additions,
 * so a full path set and a full closure set both fit without either evicting
 * the other. Not a raised cap — it is the sum of the two that already exist. */
#define ZCL_DEVLOOP_MAX_PLAN_SELECTIONS (ZCL_DEVLOOP_MAX_PLAN_GROUPS * 2)
/* The intermediate file a selection came through. Repo-relative; the longest
 * tracked path is well under this. */
#define ZCL_DEVLOOP_VIA_MAX 160
/* Byte ceiling the composed plan DOCUMENT renders into, independent of how
 * large a buffer the caller happens to hand us.
 *
 * The plan is served by the `dev.test.plan` native leaf, which declares
 * ZCL_COMMAND_LIST_BUDGET (8192) for the WHOLE zcl.result.v1 envelope, and the
 * registry hard-fails the reply (RESPONSE_BUDGET_EXCEEDED, empty document)
 * rather than truncating it. The envelope around `data` measured 340 bytes on
 * this tree; 512 is the rounded-up reserve. Writing past this number does not
 * produce a longer reply, it produces NO reply — which is why the renderer
 * abridges the explanation list against this ceiling instead of against the
 * caller's 16 KB stack buffer.
 *
 * Pinned mechanically: test_impact_composition asserts the leaf's declared
 * budget still covers this number, so raising one without the other fails. */
#define ZCL_DEVLOOP_PLAN_WIRE_MAX 7680
#define ZCL_DEVLOOP_FIRST_ERROR_MAX 512
#define ZCL_DEVLOOP_CYCLE_JSON_MAX 8192
#define ZCL_DEVLOOP_WATCH_LOCK_REL ".cache/zcl-dev-watch.lock"

/* ── the three dependency dimensions a plan is the UNION of ─────────────
 *
 * They are unioned, never intersected: a group named by any one of them is in
 * the plan. They exist as separate names for two reasons — so a reader can be
 * told WHICH one put a given test in the plan, and so incompleteness can be
 * reported per dimension instead of collapsing into one boolean that means
 * "something, somewhere, might be missing".
 *
 * OPAQUE   the hand-authored mappings in agent_impact_rules.def for artifacts
 *          NO graph can reach: X-macro registries, lint gates, docs, lint
 *          baselines, unit files — plus the hardcoded consensus-surface
 *          prefixes. These are human judgement about which proof covers which
 *          behaviour and are not derivable from any index; that is exactly why
 *          they are labelled, so a reader knows no graph could have found them.
 * SEMANTIC the call-graph blast radius: the changed file's own rule match plus
 *          the rules matched by every file in its reverse-caller closure.
 * INCLUDE  the compiler-depfile blast radius: the rules matched by every
 *          translation unit that reads the changed file. This is the dimension
 *          that answers a macro-only header or an X-macro table, which have no
 *          call edges and therefore no SEMANTIC radius at all. */
enum zcl_devloop_dim {
    ZCL_DEVLOOP_DIM_OPAQUE = 0,
    ZCL_DEVLOOP_DIM_SEMANTIC,
    ZCL_DEVLOOP_DIM_INCLUDE,
    ZCL_DEVLOOP_DIM__COUNT
};

/* Per-dimension completeness. The PRESERVE/FAIL-CLOSED split lives here:
 * whatever a dimension found is always kept (INCOMPLETE never means EMPTY),
 * and the verdict rides alongside so a caller that needs completeness can
 * refuse while a caller that just wants tests to run still gets them. */
enum zcl_devloop_dim_status {
    ZCL_DEVLOOP_DIM_COMPLETE = 0,   /* ran to completion; the answer is whole */
    ZCL_DEVLOOP_DIM_INCOMPLETE,     /* a bound fired; partial evidence RETAINED */
    ZCL_DEVLOOP_DIM_UNAVAILABLE,    /* the dimension's source is absent */
    ZCL_DEVLOOP_DIM_NOT_APPLICABLE  /* the file is outside this dimension's
                                     * universe — nothing to find, and that is
                                     * a complete answer, not a missing one */
};

struct zcl_devloop_dim_state {
    enum zcl_devloop_dim_status status;
    /* Stable label naming WHY, "" when COMPLETE. Deliberately shares wording
     * with testcache_reason_label() ("closure-truncated", "no-include-graph")
     * so the plan and the result cache never describe the same incompleteness
     * with two different words. */
    const char *reason;
};

/* One selected proof group and the evidence that selected it. */
struct zcl_devloop_selection {
    char group[ZCL_DEVLOOP_GROUP_MAX];
    /* The file whose rule match named this group: the changed file itself for
     * OPAQUE and for a direct SEMANTIC match, otherwise the intermediate the
     * closure walk reached. Never empty. */
    char via[ZCL_DEVLOOP_VIA_MAX];
    enum zcl_devloop_dim dim;
};

/* Stable names for the JSON surface and for report text. */
const char *zcl_devloop_dim_name(enum zcl_devloop_dim dim);
const char *zcl_devloop_dim_status_name(enum zcl_devloop_dim_status status);
/* Stable progressive reactor vocabulary. `detail` retains the legacy
 * compiler/probe/proof substage; the return value is the event humans and
 * agents schedule against. */
const char *zcl_devloop_progress_phase(const char *status,
                                       const char *detail);

/* Bind downstream resident receipts to the immutable edit epoch currently
 * owned by the watcher thread. Empty clears the context; standalone callers
 * naturally emit no edit_epoch field. */
bool zcl_devloop_event_edit_epoch_set(const char *edit_epoch);
const char *zcl_devloop_event_edit_epoch(void);

enum zcl_devloop_state_lookup {
    ZCL_DEVLOOP_STATE_INVALID = -1,
    ZCL_DEVLOOP_STATE_ABSENT = 0,
    ZCL_DEVLOOP_STATE_FOUND = 1
};

enum zcl_devloop_action {
    ZCL_DEVLOOP_CHECK = 0,
    ZCL_DEVLOOP_HOTSWAP,
    ZCL_DEVLOOP_RELOAD,
};

/* Publication intent is an explicit caller decision.  Persistent watchers use
 * VERIFY_ONLY by default; only an operator-invoked apply/auto path may select
 * APPLY.  Keeping this separate from the file-classification action prevents a
 * consensus/reload classification from bypassing watcher containment. */
enum zcl_devloop_publish_mode {
    ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY = 0,
    ZCL_DEVLOOP_PUBLISH_APPLY,
};

struct zcl_devloop_plan {
    enum zcl_devloop_action action;
    const char *action_name;
    const char *reason;
    const char *probe_tool;
    const char *proof_group;
    char proof_group_storage[64];
    bool consensus_risk;
    bool docs_only;
    /* True iff any changed file lives under the SEALED consensus core (core/
     * — the surface core/MANIFEST.sha3 pins). Sealed files are always
     * consensus_risk too (heaviest proof), and the fast loop structurally
     * REFUSES to auto-publish them unless the owner unseal token is present.
     * See zcl_devloop_path_is_sealed_core() / zcl_devloop_refusal_json(). */
    bool sealed_core;
    size_t file_count;

    /* ── proof-group sets (F3: path floor + symbol-closure additions) ──
     * proof_group above stays the PRIMARY route (path-derived, consensus-safe).
     * These sets are ADDITIVE reporting only — nothing here changes proof_group.
     *
     * path_groups: the union of every shared-impact-rule group matched by the
     * changed files themselves (the path-glob FLOOR). Deterministic insertion
     * order; proof_group is normally path_groups[0] (or the consensus override).
     *
     * closure_groups: groups reached ONLY through the blast radius — every
     * file in the changed set's reverse-caller closure (SEMANTIC) and every
     * translation unit that reads it (INCLUDE), each mapped through the SAME
     * shared impact rules, minus anything already in path_groups. Populated by
     * zcl_devloop_plan_add_closure(); empty until then.
     *
     * A BOUND FIRING NO LONGER EMPTIES THIS SET. A partial walk is real
     * evidence and every group it found is kept; what a bound changes is the
     * per-dimension completeness verdict in `dims` below, which is what a
     * caller needing PROOF must read. The old behaviour discarded the
     * evidence AND let the caller believe the remainder was sufficient —
     * fail-closed by design, fail-open in effect. */
    char path_groups[ZCL_DEVLOOP_MAX_PLAN_GROUPS][ZCL_DEVLOOP_GROUP_MAX];
    size_t path_groups_len;
    char closure_groups[ZCL_DEVLOOP_MAX_PLAN_GROUPS][ZCL_DEVLOOP_GROUP_MAX];
    size_t closure_groups_len;
    bool closure_attempted;   /* zcl_devloop_plan_add_closure() ran */
    bool closure_snapshot;    /* resident used existing graph + current bytes */
    /* Back-compat boolean: true iff an applicable SEMANTIC or INCLUDE
     * dimension is INCOMPLETE/UNAVAILABLE. NOT_APPLICABLE is sufficient. It
     * no longer implies closure_groups is empty — read `dims`. */
    bool closure_truncated;

    /* ── C5: why every selected group is here ── */
    struct zcl_devloop_selection selections[ZCL_DEVLOOP_MAX_PLAN_SELECTIONS];
    size_t selections_len;
    bool selections_truncated;   /* the selection ledger itself overflowed */

    /* ── C4: per-dimension completeness, indexed by enum zcl_devloop_dim ── */
    struct zcl_devloop_dim_state dims[ZCL_DEVLOOP_DIM__COUNT];
};

/* Is this plan admissible as PROOF that a change is covered?
 *
 * TRUE only when every dimension is COMPLETE or NOT_APPLICABLE. An INCOMPLETE
 * or UNAVAILABLE dimension means the union may be missing a group nobody can
 * name, so any consumer that would treat the plan as sufficient evidence —
 * proof reuse, test-cache admission, an "is this change proven" gate — must
 * refuse. This is deliberately the same standard tests/harness/src/testcache.c
 * already applies to its own closure (TESTCACHE_R_TRUNCATED /
 * TESTCACHE_R_NO_INCLUDE_GRAPH => UNCACHEABLE, and an UNCACHEABLE group always
 * runs), and *out_reason receives the same label vocabulary so the two never
 * describe one incompleteness with two different words. They cannot share a
 * symbol: testcache is a test-binary-only module and is never linked into the
 * node, so the shared thing is the vocabulary and the test that pins them.
 *
 * `out_reason` (may be NULL) receives the first refusing dimension's reason,
 * or "" when admissible. Never NULL-terminated garbage; always a literal. */
bool zcl_devloop_plan_proof_admissible(const struct zcl_devloop_plan *plan,
                                       const char **out_reason);

struct zcl_devloop_process_result {
    int exit_code;
    int term_signal;
    bool timed_out;
    bool cancelled;
    int64_t elapsed_ms;
    int64_t startup_us;
    int64_t body_us;
    int64_t first_output_us;
    char output[ZCL_DEVLOOP_OUTPUT_MAX];
    size_t output_len;
    bool output_truncated;
};

/* One resident-authority module build. The authority is the long-lived
 * zclassic23-dev watcher; only the compiler and linker are child processes.
 * Make, a shell, and a throwaway CLI are absent from the edit path. */
struct zcl_devloop_hotswap_build_receipt {
    char source_tu[256];
    char artifact_path[4096];
    /* SHA-256 of the exact compiler-produced relocatable object.  This is
     * distinct from the linked candidate module root below and survives an
     * exact-input cache hit. */
    char candidate_object_sha256[65];
    char artifact_sha256[65];
    char artifact_cache_key[65];
    int64_t plan_load_us;
    int64_t compile_us;
    int64_t link_us;
    int64_t publish_us;
    int64_t total_us;
    bool plan_cache_hit;
    bool artifact_cache_hit;
    uint32_t dependency_count;
    uint32_t compiler_processes;
    uint32_t linker_processes;
};

/* Build exactly one compiled-allowlist source TU under the cached action plan
 * written by the authoritative Make configuration. A warm build snapshots
 * the previous compiler depfile and re-stats after compilation. A cold build
 * discovers the closure, then verifies it with a second compile in the same
 * action; any dependency mutation or expansion refuses publication. No shell
 * or Make process is launched. */
bool zcl_devloop_hotswap_build(
    const char *repo_root, const char *source_tu,
    struct zcl_devloop_hotswap_build_receipt *receipt,
    struct zcl_devloop_process_result *process,
    char *why, size_t why_len);

/* Pure fallback diagnosis for one resident hot-swap receipt. `why_not_live`
 * preserves the exact bounded refusal; `next_command` names one deterministic
 * action instead of the old generic "repair the refusal" instruction. */
void zcl_devloop_hotswap_guidance(
    const char *status, const char *phase, const char *why,
    char *why_not_live, size_t why_not_live_size,
    char *next_command, size_t next_command_size);
struct json_value;
bool zcl_devloop_hotswap_response_error(
    const struct json_value *response, char *out, size_t out_size);

/* One non-LTO process-restart candidate produced directly by the resident
 * watcher from Make's frozen action plan. This is a candidate command-runtime
 * proof, never release/deployment authority and never a live-node restart. */
struct zcl_devloop_restart_build_receipt {
    char artifact_path[4096];
    char artifact_sha256[65];
    char artifact_cache_key[65];
    char source_cas_sha3[65];
    char probe[64];
    int64_t plan_load_us;
    int64_t compile_us;
    int64_t compile_startup_us;
    int64_t compile_body_us;
    int64_t link_us;
    int64_t link_startup_us;
    int64_t link_body_us;
    int64_t probe_us;
    int64_t probe_startup_us;
    int64_t probe_body_us;
    int64_t total_us;
    uint32_t changed_sources;
    uint32_t compiler_processes;
    uint32_t linker_processes;
    uint32_t complete_graph_linker_processes;
    uint32_t probe_processes;
    uint32_t source_guard_captures;
    bool plan_cache_hit;
    bool artifact_cache_hit;
    bool source_identity_overlay;
    bool candidate_probe_passed;
};

/* Exact affected-proof execution against a test binary linked from the same
 * changed source bytes as the process candidate. A green exit alone is not
 * proof: the receipt is complete only when the runner's summary accounts for
 * every selected group as a fresh execution or a verified content-addressed
 * PASS, with zero failures or self-skips. */
struct zcl_devloop_restart_proof_receipt {
    char artifact_path[4096];
    char artifact_sha256[65];
    char artifact_cache_key[65];
    char source_cas_sha3[65];
    char groups[4096];
    char groups_sha256[65];
    char deferred_groups[4096];
    char deferred_groups_sha256[65];
    char priority_group[128];
    char priority_reason[64];
    int64_t selection_us;
    int64_t compile_us;
    int64_t compile_startup_us;
    int64_t compile_body_us;
    int64_t link_us;
    int64_t link_startup_us;
    int64_t link_body_us;
    int64_t test_us;
    int64_t test_startup_us;
    int64_t test_body_us;
    int64_t priority_test_us;
    int64_t total_us;
    uint32_t group_count;
    uint32_t deferred_group_count;
    uint32_t groups_ran;
    uint32_t groups_cached;
    uint32_t groups_failed;
    uint32_t self_skips;
    uint32_t compiler_processes;
    uint32_t linker_processes;
    uint32_t complete_graph_linker_processes;
    uint32_t test_processes;
    uint32_t source_guard_captures;
    bool artifact_cache_hit;
    bool source_identity_overlay;
    bool bounded_proof_deferred;
    bool immediate_proof_complete;
    bool integration_proof_deferred;
    bool proof_complete;
};

bool zcl_devloop_restart_build(
    const char *repo_root, const char *const *source_tus, size_t source_count,
    struct zcl_devloop_restart_build_receipt *receipt,
    struct zcl_devloop_process_result *process,
    char *why, size_t why_len);

bool zcl_devloop_restart_prove(
    const char *repo_root, const char *const *source_tus, size_t source_count,
    const struct zcl_devloop_plan *plan,
    struct zcl_devloop_restart_proof_receipt *receipt,
    struct zcl_devloop_process_result *process,
    char *why, size_t why_len);

/* Save-cycle tier: executes every selected group except exact integration-only
 * groups. If a reverse-caller closure exceeds the resident bound, it executes
 * the complete explicit path floor and hash-binds the broader closure into the
 * deferred set. proof_complete remains false until every deferred group runs. */
bool zcl_devloop_restart_prove_immediate(
    const char *repo_root, const char *const *source_tus, size_t source_count,
    const struct zcl_devloop_plan *plan,
    struct zcl_devloop_restart_proof_receipt *receipt,
    struct zcl_devloop_process_result *process,
    char *why, size_t why_len);

enum zcl_devloop_restart_event_result {
    ZCL_DEVLOOP_RESTART_EVENT_ERROR = -1,
    ZCL_DEVLOOP_RESTART_EVENT_NOT_APPLICABLE = 0,
    ZCL_DEVLOOP_RESTART_EVENT_FINAL = 1,
    ZCL_DEVLOOP_RESTART_EVENT_CANCELLED = 2,
    ZCL_DEVLOOP_RESTART_EVENT_PROOF_PENDING = 3,
    ZCL_DEVLOOP_RESTART_EVENT_FALLBACK_PENDING = 4,
};

/* Try the resident process-candidate lane for a bounded set of changed C TUs.
 * The result distinguishes final failures from green affected feedback and
 * from resident-cap fallbacks that still require conservative proof. */
int zcl_devloop_restart_event(const char *repo_root,
                              const char *const *source_tus,
                              size_t source_count,
                              enum zcl_devloop_publish_mode publish_mode);

/* Continue a green owner-bound story into exact affected proof without
 * rebuilding or re-probing the runtime candidate. This is deliberately an
 * asynchronous post-reflex lane: STORY_GREEN is already observable before
 * this function compiles/links the isolated test candidate. */
int zcl_devloop_restart_story_prove_event(
    const char *repo_root, const char *const *source_tus,
    size_t source_count, enum zcl_devloop_publish_mode publish_mode);

/* Try the resident fast lane for one watcher epoch. Returns 0 when the file
 * is not a hot-swap island (caller must use the conservative path), 1 when a
 * machine-readable pass/refusal receipt was emitted and persisted, and -1 on
 * an internal receipt-publication failure. APPLY is honored only here; the
 * caller must downgrade every non-island edit to VERIFY_ONLY. */
int zcl_devloop_hotswap_event(const char *repo_root, const char *source_tu,
                              enum zcl_devloop_publish_mode publish_mode);

/* Admit one debounced edit batch only when every path maps to the exact same
 * island owner. The owner is compiled once and one generation is published;
 * a cross-island or public-contract batch returns 0 for DEV_RESTART. */
int zcl_devloop_hotswap_batch_event(
    const char *repo_root, const char *const *paths, size_t path_count,
    enum zcl_devloop_publish_mode publish_mode);

/* Development-only capsule lane for an exact module-ABI fallback. The
 * resident parent never loads the candidate; a disposable sandboxed child
 * loads it, executes its owner-bound story, reports one bounded observation,
 * and exits. */
int zcl_devloop_hotfork_batch_event(
    const char *repo_root, const char *const *paths, size_t path_count,
    enum zcl_devloop_publish_mode publish_mode);
struct zcl_hotfork_capsule_v1;
bool zcl_devloop_hotfork_descriptor_validate(
    const char *source_tu, const char *candidate_object_root,
    const struct zcl_hotfork_capsule_v1 *capsule);
bool zcl_devloop_hotfork_registry_validate(void);

/* Complete current source identity: byte inventory plus the ABA mutation
 * token. Shared by the watcher/cycle and focused native execution so neither
 * can admit an artifact built from a superseded checkout. */
struct dev_source_record {
    char source_id[65];
    char mutation_id[65];
    /* Native, content-addressed identity for the public C23 source roots.
     * A CAS-only capture derives source_id/mutation_id as domain-separated
     * SHA-256 records for isolated resident candidates. A full capture
     * overwrites those two fields with publication-authoritative v2 values. */
    char cas_root_sha3[65];
    uint32_t cas_files_total;
    uint32_t cas_files_read;
    uint32_t cas_nodes_hashed;
    uint64_t cas_bytes_total;
    uint64_t cas_bytes_read;
    int64_t cas_elapsed_us;
    bool cas_present;
};

/* Refresh the persistent native source Merkle tree and attach its SHA3 root
 * and measured work to `out`. Project/source publication authority is not
 * changed by this shadow capture. */
bool zcl_dev_source_cas_capture(const char *repo_root,
                                struct dev_source_record *out);
bool zcl_dev_source_identity_capture(const char *repo_root,
                                     struct dev_source_record *out,
                                     char *why, size_t why_len);
/* Classify a failed source-identity child process into one specific evidence
 * token (timeout, signal, nonzero exit, truncated output) rather than the
 * single undifferentiated source_identity_command_failed. Exposed so tests
 * can drive the mapping directly without paying for a real 30s+ capture. */
bool zcl_dev_source_identity_classify_failure(
    const struct zcl_devloop_process_result *result, char *why,
    size_t why_len);
/* Whether a source-identity failure token names a transient, load-shaped
 * condition (timeout/signal/truncation) worth retrying the capture for, as
 * opposed to a deterministic content or tool-path defect. */
bool zcl_dev_source_identity_failure_retryable(const char *why);
bool zcl_dev_source_identity_verify(const char *repo_root,
                                    const struct dev_source_record *expected,
                                    char *why, size_t why_len);
/* Post-proof/preflight CAS: verifies inventory + ABA mutation metadata without
 * a full byte rehash. Admission may compare it with a dev/test executable's
 * publication-verified build receipt; publication/release authority remains
 * the full portable byte identity. */
bool zcl_dev_source_mutation_verify(const char *repo_root,
                                    const struct dev_source_record *expected,
                                    char *why, size_t why_len);

enum zcl_dev_source_admission {
    ZCL_DEV_SOURCE_ADMISSION_ERROR = -1,
    ZCL_DEV_SOURCE_ADMISSION_STALE = 0,
    ZCL_DEV_SOURCE_ADMISSION_BUILD_MUTATION = 1,
    ZCL_DEV_SOURCE_ADMISSION_FULL_BYTES = 2
};

/* Admit one already-open dev/test executable against the current checkout.
 * The common path compares its publication-verified source+mutation receipt
 * with a bounded current mutation CAS. A receipt mismatch falls back to full
 * byte capture, preserving safe edit/revert and copied-checkout reuse. */
enum zcl_dev_source_admission zcl_dev_executable_source_admit(
    const char *repo_root, int executable_fd, const char *display_path,
    struct dev_source_record *out, char *why, size_t why_len);
bool zcl_dev_executable_source_record_read(
    const char *repo_root, int executable_fd, const char *display_path,
    struct dev_source_record *out, char *why, size_t why_len);
const char *zcl_dev_source_admission_name(
    enum zcl_dev_source_admission admission);

bool zcl_devloop_is_method(const char *method);
int zcl_devloop_cli_main(const char **args, int nargs);
int zcl_devloop_watch_worker_main(uintptr_t inherited, const char *root,
                                  const char *mode, const char image_sha256[65]);

bool zcl_devloop_plan_files(const char *const *files, size_t file_count,
                            struct zcl_devloop_plan *out);
size_t zcl_devloop_plan_json(const char *const *files, size_t file_count,
                             char *out, size_t out_sz);

/* Augment `plan` (already produced by zcl_devloop_plan_files for the same
 * `files`) with blast-radius-derived proof groups across BOTH graph
 * dimensions. For applicable source shapes, opens the codeindex at
 * `repo_root` and computes
 *   SEMANTIC — codeindex_impact_closure(): the reverse-caller file set, and
 *   INCLUDE  — codeindex_reverse_includes(): every translation unit whose
 *              compiler depfile lists a changed file,
 * A dimension structurally unable to contain an edge for the changed shape
 * is NOT_APPLICABLE and does not open/query the index. Maps each reached file
 * through the SAME shared impact rules the path floor
 * uses, and fills plan->closure_groups with the groups NOT already in
 * plan->path_groups. The primary proof_group route is left untouched.
 *
 * PRESERVE, then FAIL CLOSED. Whatever a dimension found is always kept — a
 * bound firing marks that dimension INCOMPLETE and never empties the group set.
 * An index that will not open marks both graph dimensions UNAVAILABLE. Either
 * way the plan still runs the tests it found; what changes is
 * zcl_devloop_plan_proof_admissible(), which then refuses.
 *
 * Sets closure_attempted=true and fills plan->dims + plan->selections.
 * Returns true unless an argument is invalid. */
bool zcl_devloop_plan_add_closure(const char *repo_root,
                                  const char *const *files, size_t file_count,
                                  struct zcl_devloop_plan *plan);
bool zcl_devloop_plan_add_closure_snapshot(
    const char *repo_root, const char *const *files, size_t file_count,
    struct zcl_devloop_plan *plan);

/* Like zcl_devloop_plan_json but also runs the symbol closure at `repo_root`
 * and emits the additional "path_groups", "closure_groups", and
 * "closure_truncated" fields. Returns bytes written, or 0 on overflow/bad
 * args. */
size_t zcl_devloop_plan_json_closure(const char *repo_root,
                                     const char *const *files,
                                     size_t file_count, char *out,
                                     size_t out_sz);

/* True iff the persistent watcher should react to a change at `path`
 * (repo-relative): a .c/.h/.def/.md/.mk/.service source or the Makefile,
 * excluding editor temp files, build/, .git/, and — critically — the
 * transient `_*fixture*` lint/shape-gate fixtures that
 * test_make_lint_gates.c writes under app/, lib/, and domain/ then deletes.
 * Reacting to those fixtures fires a phantom reload cycle on every
 * test-suite run (they no longer exist by the time the cycle rebuilds), so
 * the watcher must ignore them. Pure: no I/O. Shared by the watcher and its
 * unit test. */
bool zcl_devloop_path_is_relevant(const char *path);

/* Accumulated C translation units whose source bytes have diverged from the
 * resident restart base during this watcher lifetime. Service-private header
 * edits map to their one island owner. Overflow fails closed so a later
 * restart cannot silently link stale base objects. */
struct zcl_devloop_restart_source_set {
    char sources[ZCL_DEVLOOP_RESTART_SOURCE_MAX][ZCL_DEVLOOP_PATH_MAX];
    size_t count;
    bool overflow;
};

bool zcl_devloop_restart_source_set_add(
    struct zcl_devloop_restart_source_set *set,
    const char *const *paths, size_t path_count);

/* True iff `path` is under the sealed consensus core (the `core/` prefix —
 * the exact surface `core/MANIFEST.sha3` seals). Broader than the
 * consensus-risk prefix list: it covers ALL of core/ (incl. core/math). */
bool zcl_devloop_path_is_sealed_core(const char *path);

/* True iff an owner-minted one-shot unseal token (`.core-unseal-token`, the
 * file `make core-unseal` writes) is present at `repo_root`. READ-ONLY: this
 * never mints or consumes the token — `make core-seal` is the sole consumer,
 * so one unseal authorizes one LANDED COMMIT, not one dev-cycle. */
bool zcl_devloop_unseal_token_present(const char *repo_root);

/* Build the structured sealed-core refusal envelope (a zcl.dev_cycle.v1
 * document with status "refused") into `out`. `files` lists the full changed
 * set; the envelope's "paths" array carries only the sealed-core members that
 * triggered the refusal. Returns the byte count, or 0 on overflow/bad args.
 * Sealed != frozen: the envelope always names the elevated procedure. */
size_t zcl_devloop_refusal_json(const char *const *files, size_t file_count,
                                char *out, size_t out_sz);

size_t zcl_devloop_menu_json(const char *path, char *out, size_t out_sz);
size_t zcl_devloop_menu_search_json(const char *query,
                                    char *out, size_t out_sz);

bool zcl_devloop_process_run(const char *cwd,
                             const char *const argv[],
                             int timeout_ms,
                             struct zcl_devloop_process_result *out);
/* Test fixtures include intentionally large stack frames. Raise only the
 * test child's soft stack limit to its inherited hard limit before exec. */
bool zcl_devloop_process_run_test(const char *cwd,
                                  const char *const argv[], int timeout_ms,
                                  struct zcl_devloop_process_result *out);
/* Execute the already-open regular executable at `exec_fd`. The caller owns
 * and closes the fd after return. This pins one inode across identity query +
 * execution even when a stable build/bin alias is atomically republished. */
bool zcl_devloop_process_run_fd(const char *cwd, int exec_fd,
                                const char *const argv[], int timeout_ms,
                                struct zcl_devloop_process_result *out);
/* Async-signal-safe cancellation owned by the resident watcher. A request
 * terminates the active bounded child process group; clear only when the
 * watcher begins a new ownership lifetime. */
void zcl_devloop_process_cancel_request(void);
void zcl_devloop_process_cancel_clear(void);
bool zcl_devloop_process_cancel_requested(void);
typedef bool (*zcl_devloop_process_cancel_poll_fn)(void *opaque);
void zcl_devloop_process_cancel_poll_set(
    zcl_devloop_process_cancel_poll_fn poll_fn, void *opaque);
void zcl_devloop_process_cancel_poll_clear(void);
#if defined(ZCL_TESTING) && !defined(_WIN32)
/* Deterministic process-backed KAT for exact-commit scheduling priority. */
bool zcl_devloop_watch_commit_preemption_selftest(void);
#endif
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
bool zcl_devloop_deterministic_compile_failure(
    const struct zcl_devloop_process_result *result,
    char out[ZCL_DEVLOOP_FIRST_ERROR_MAX]);
#endif

/* Launch the generation-neutral initial ZVCS baseline. POSIX uses a detached
 * double-fork/setsid grandchild. Until a qualified native detached-process
 * seam exists, Windows runs synchronously to preserve VCS state isolation.
 * Completion is appended to <repo_root>/.zvcs/bootstrap.log. Returns true iff
 * work started successfully (the detached baseline may still have failed; check
 * .zvcs/bootstrap.log or the next vcs_devloop_anchor_cycle() call). Dev-only
 * (tools/dev/devloop_baseline.c); a release build never links this. */
bool zcl_devloop_baseline_launch(const char *repo_root);

int zcl_devloop_run_cycle(const char *repo_root,
                          const char *const *files,
                          size_t file_count);
int zcl_devloop_run_cycle_mode(const char *repo_root,
                               const char *const *files,
                               size_t file_count,
                               enum zcl_devloop_publish_mode publish_mode);
bool zcl_devloop_publish_mode_applies(
    enum zcl_devloop_publish_mode publish_mode);
/* True only for a completed conservative source-wide verify cycle. A
 * deferred, superseded, rejected, probe-only, or publication cycle is never
 * reusable proof. Kept public so the receipt contract has a tiny KAT. */
bool zcl_devloop_cycle_proof_complete(const char *status, const char *phase);
const char *zcl_devloop_publish_mode_name(
    enum zcl_devloop_publish_mode publish_mode);
enum zcl_devloop_publish_mode zcl_devloop_default_watch_publish_mode(void);
bool zcl_devloop_publication_target_port_supported(int rpc_port);
/* Stable watcher-status vocabulary shared by the native status/ensure
 * surface and its tests. The returned next action is deliberately the same
 * idempotent command whether it starts a watcher or reports an existing one. */
const char *zcl_devloop_watcher_freshness(bool active, bool source_ready,
                                          bool runtime_ready);
const char *zcl_devloop_watcher_next_action(
    bool active, bool source_ready, bool runtime_ready,
    enum zcl_devloop_publish_mode publish_mode);
/* Pure path builder shared by the native watcher's flock acquisition and its
 * regression tests.  repo_root must already identify the worktree whose lane
 * is being watched; distinct worktrees consequently receive distinct locks. */
bool zcl_devloop_watch_lock_path(const char *repo_root,
                                 char *out, size_t out_sz);
/* Content/directory-entry mutations wake the loop. Metadata-only access-time
 * changes from compilers and indexers do not constitute a source save. */
bool zcl_devloop_watch_event_is_mutation(uint32_t inotify_mask);
bool zcl_devloop_watch_dir_is_ignored(const char *name);
/* Canonical-worktree identity and SHA3-sealed cycle state.  Readers never
 * create state. ABSENT is an honest empty result; INVALID must fail closed. */
bool zcl_devloop_workspace_id(const char *repo_root, char out[65]);
bool zcl_devloop_workspace_resolve(const char *repo_root, char out_id[65],
                                   char *out_dir, size_t out_dir_len);
bool zcl_devloop_workspace_state_dir(const char *repo_root,
                                     char *out, size_t out_len);
bool zcl_devloop_cycle_state_write(const char *repo_root,
                                   const char *cycle_json, size_t cycle_len,
                                   char *why, size_t why_len);
/* Volatile bounded reflex stream. The watcher resets it from the durable
 * journal's latest epoch, publishes without fsync/storage acknowledgement,
 * then persists the same reserved epoch asynchronously. It is an observation
 * cache only; the sealed append-only journal remains evidence authority. */
bool zcl_devloop_cycle_stream_reset(const char *repo_root,
                                    int64_t durable_epoch,
                                    char *why, size_t why_len);
bool zcl_devloop_cycle_stream_publish(const char *repo_root,
                                      const char *cycle_json,
                                      size_t cycle_len, int64_t *epoch_out,
                                      char *why, size_t why_len);
/* Seal every volatile event through `through_epoch` in epoch order. Producers
 * call this only after the action-changing event is visible; storage latency
 * therefore cannot delay reflex feedback. */
bool zcl_devloop_cycle_stream_flush_through(const char *repo_root,
                                            int64_t through_epoch,
                                            char *why, size_t why_len);
bool zcl_devloop_cycle_state_write_epoch(const char *repo_root,
                                         int64_t reserved_epoch,
                                         const char *cycle_json,
                                         size_t cycle_len,
                                         char *why, size_t why_len);
enum zcl_devloop_state_lookup zcl_devloop_cycle_state_read(
    const char *repo_root, char *out, size_t out_len, size_t *len_out,
    int64_t *epoch_out, char *why, size_t why_len);
/* Read the first sealed event strictly newer than after_epoch. Unlike the
 * latest-value compatibility surface above, this never skips an available
 * intermediate event. A missing link in an otherwise newer journal is
 * INVALID, not permission to jump ahead. */
enum zcl_devloop_state_lookup zcl_devloop_cycle_state_read_after(
    const char *repo_root, int64_t after_epoch, char *out, size_t out_len,
    size_t *len_out, int64_t *epoch_out, char *why, size_t why_len);

/* Wait for the first exact event after `after_epoch`. The directory watch is
 * armed before the first read, closing the check/sleep race; producers wake it
 * through the bounded volatile ring. On timeout, epoch_out retains the exact
 * caller anchor so recovery evidence cannot regress to zero. */
enum zcl_devloop_state_lookup zcl_devloop_cycle_state_wait_after(
    const char *repo_root, int64_t after_epoch, int timeout_ms,
    char *out, size_t out_len, size_t *len_out, int64_t *epoch_out,
    char *why, size_t why_len);
int zcl_devloop_watch(const char *repo_root);
int zcl_devloop_watch_mode(const char *repo_root,
                           enum zcl_devloop_publish_mode publish_mode);
typedef bool (*zcl_devloop_stop_predicate)(void *opaque);
int zcl_devloop_watch_mode_until(const char *repo_root,
    enum zcl_devloop_publish_mode publish_mode,
    zcl_devloop_stop_predicate stop, void *opaque);
int zcl_devloop_print_status(void);
int zcl_devloop_run_sim(const char *repo_root);
int zcl_devloop_app_describe(const char *repo_root, const char *app_id);
int zcl_devloop_app_plan(const char *repo_root, const char *app_id,
                         const char *resource);
int zcl_devloop_app_simulate(const char *app_id, uint64_t seed);

/* Release-safe bounded JSON buffer producers backing both the stdout print
 * wrappers above and the Wave 2.2 registry dev handlers. Return bytes written,
 * or 0 on invalid arguments / overflow. */
size_t zcl_devloop_app_describe_json(const char *repo_root, const char *app_id,
                                     char *out, size_t out_sz);
size_t zcl_devloop_app_plan_json(const char *repo_root, const char *app_id,
                                 const char *resource, char *out, size_t out_sz);
size_t zcl_devloop_app_simulate_json(const char *app_id, uint64_t seed,
                                     char *out, size_t out_sz);

/* ── Wave 3.2 native activation engine — dev-lane wiring ───────────────
 *
 * The implementation remains testable while all public callers are hard-
 * contained. A future complete publication transaction may decide whether to
 * drive the native transactional activation
 * engine (tools/dev/dev_activation.h: dev_activation_run() /
 * dev_activation_activate_generation()) or keep shelling out to the proven
 * backend or a replacement. The three helpers below are pure (no process
 * exec, no disk I/O beyond getenv()) glue used to build/interpret its request and
 * result -- see docs/work/HOTSWAP.md "Transactional reload: native engine".
 *
 * Guarded the same way dev_activation.h's own entry points are
 * (ZCL_DEV_BUILD || ZCL_TESTING): a release build sees no declaration at
 * all, and the hermetic ZCL_TESTING harness can unit-test the pure builders
 * directly (no fake ops vtable needed -- they never call one). */
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
#include <limits.h>

#include "dev_activation.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* True iff ZCL_DEV_NATIVE_ACTIVATION selects the retained native engine in
 * code paths that already possess internal test authority. This runtime
 * selector is NOT activation authority: public watcher/apply entrypoints
 * refuse before consulting it, and deploy-dev-lane.sh accepts machinery tests
 * only through its inherited-FD, fixture-bound self-test capability. */
bool dev_activation_native_enabled(void);

/* Caller-owned storage backing a struct dev_activation_request built by
 * dev_activation_request_from_cycle() below -- the struct's string fields
 * point directly into these buffers (and, for repo_root/build_commit, into
 * the caller's own arguments), so `out` must outlive any use of out->req. */
struct dev_activation_cycle_request {
    struct dev_activation_request req;
    char artifact_path[PATH_MAX];
    char gen_root[PATH_MAX];
    char datadir[PATH_MAX];
};

/* Build *out from the dev lane's fixed constants -- the exact values
 * tools/dev/deploy-dev-lane.sh hard-codes (GEN_ROOT defaulting to
 * ~/.local/lib/zclassic23-dev, DEV_DATADIR ~/.zclassic-c23-dev, UNIT
 * zcl23-dev.service, DEV_RPCPORT 18252, build_type "fast") plus the
 * fast-lane artifact at <repo_root>/build/bin/zclassic23-dev. Pure: reads
 * only HOME and ZCL_DEV_GENERATION_ROOT, never touches disk beyond that and
 * never spawns a process. `repo_root` and display-only `build_commit` are
 * stored by pointer (not copied) and must outlive `out`; `build_commit` may
 * be "" but not NULL. It is never a preflight or activation decision input.
 * The caller binds req.source_identity separately before activation. Returns
 * false, leaving *out unusable, iff HOME is unset/empty or an argument is
 * NULL/oversized. */
bool dev_activation_request_from_cycle(const char *repo_root,
                                       const char *build_commit,
                                       struct dev_activation_cycle_request *out);

/* Outcome of a completed dev_activation_result, mapped into the shape
 * finish_cycle()/the vcs.vcs.revert reply need: pass/fail plus a short
 * human-readable failure capsule and the candidate's generation hex (the
 * ZVCS auto-anchor's generation binding -- see devloop_cycle.c:finish_cycle
 * and vcs.h's generation_sha256). */
struct dev_activation_cycle_outcome {
    bool ok;
    char capsule[256];
    char generation_hex[65];
};

/* Pure: maps `r` into `out`. `r` NULL => *out zeroed (ok=false). */
void dev_activation_map_result(const struct dev_activation_result *r,
                               struct dev_activation_cycle_outcome *out);

/* Testable wrapper over devloop_cycle.c's static distill_first_error(): scan
 * [out, out+len) FORWARD for the first actionable line — a compiler
 * diagnostic (contains ": error:") or a test failure (contains "FAIL",
 * "Assertion", or "EXPECT") — and copy it (newline stripped, bounded by
 * dstcap, always NUL-terminated) into dst. Returns true iff one was found.
 * Backs the dense output_capsule "first_error=" prefix. Pure: no I/O. */
bool zcl_devloop_distill_first_error(const char *out, size_t len,
                                     char *dst, size_t dstcap);
#endif /* ZCL_DEV_BUILD || ZCL_TESTING */

#ifdef __cplusplus
}
#endif

#endif /* ZCL_TOOLS_DEVLOOP_H */
