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

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

enum zcl_dev_proof_state {
    ZCL_DEV_PROOF_STATE_INVALID = -1,
    ZCL_DEV_PROOF_STATE_MISSING = 0,
    ZCL_DEV_PROOF_STATE_RUNNING,
    ZCL_DEV_PROOF_STATE_PASSED,
    ZCL_DEV_PROOF_STATE_FAILED,
};

struct zcl_dev_proof_status {
    enum zcl_dev_proof_state state;
    char local_commit[65];
    char remote_base[65];
    char receipt_path[4096];
    char log_dir[4096];
    char detail[256];
    int64_t started_unix;
    int64_t eta_ms;
    int64_t worker_id;
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

/* One captured base..local changed set. Heap-resident: the row ceiling is a
 * landing-batch ceiling (thousands of paths), which must never sit in a stack
 * frame. `files` holds `count` pointers into `bytes`; release both together. */
struct zcl_dev_proof_changed_set {
    char *bytes;
    const char **files;
    size_t count;
};

/* Capture the exact base..local changed set the proof worker plans against.
 *
 * The list is written to `scratch_path` by git and read whole, so no fixed
 * capture buffer can silently shorten it; over-ceiling and unreadable captures
 * refuse with a typed reason naming the observed count. `persist_path` (may be
 * NULL) receives the newline-separated record. On success the caller owns
 * `*out` until zcl_dev_proof_changed_set_release(). */
bool zcl_dev_proof_changed_set_capture(const char *repo_root, const char *base,
                                       const char *local,
                                       const char *scratch_path,
                                       const char *persist_path,
                                       struct zcl_dev_proof_changed_set *out,
                                       char *why, size_t why_len);
void zcl_dev_proof_changed_set_release(struct zcl_dev_proof_changed_set *set);

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
/* Testing seam: materialize one generation dependency the way the proof does
 * — link() inside one filesystem, a faithful mode-preserving copy across
 * one. No proof, lease, or admission authority. */
bool zcl_dev_proof_dependency_materialize(const char *source,
                                          const char *target);
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
/* The singleton development watcher owns this queue. Notifications only
 * publish immutable pair requests; the resident owner claims and executes at
 * most one leased attempt at a time. */
bool zcl_dev_proof_queue_has_pending(const char *repo_root);
int zcl_dev_proof_queue_run_next(const char *repo_root,
                                 char *why, size_t why_len);
bool zcl_dev_proof_wait(const char *repo_root,
                        const char *local_commit,
                        const char *remote_base,
                        int timeout_ms,
                        struct zcl_dev_proof_status *out);

#if defined(ZCL_TESTING)
/* Seam for the selection regression: the same builder the proof worker uses,
 * so a test can prove a universal plan selects the whole catalog without
 * running a proof cycle. */
struct zcl_devloop_plan;
bool zcl_dev_proof_test_build_test_selector(
    const struct zcl_devloop_plan *plan, bool inventory_only,
    char *out, size_t out_size, uint32_t *count_out);
/* Seam for the stress-env regression: the exact call the test dimension
 * makes right before it launches its runner, so a test can prove
 * ZCL_STRESS_TESTS lands in this process's own environ (and therefore in
 * every execvp()'d test child) without driving a full proof cycle. */
bool zcl_dev_proof_test_stress_env_prepare(char *why, size_t why_len);
#endif

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
/* Warm-start test seam. The harness proves the donor policy and the
 * link/copy decision against fixture trees; the dev binary compiles the
 * same seam. A release build sees none of it. POSIX-only, like the
 * warm-start machinery itself. */
bool zcl_dev_proof_warm_tag(const char *name);
/* The ZCL_DEV_PROOF_WARM=0/"off"/"no" opt-out, exposed so the harness
 * proves the cold-forcing switch it gates on. */
bool zcl_dev_proof_warm_disabled(void);
enum zcl_dev_proof_warm_seed_class zcl_dev_proof_warm_classify(
    const char *rel, bool is_reg);
int zcl_dev_proof_warm_pick(const struct zcl_dev_proof_warm_candidate *c,
                            size_t n);
bool zcl_dev_proof_warm_marker_write(const char *generation,
                                     const char *root, const char *local,
                                     const char *base, int64_t completed);
bool zcl_dev_proof_warm_marker_read(const char *generation,
                                    char root[PATH_MAX], char local[65],
                                    char base[65], int64_t *completed);
/* Seed donor_build into gen_build (object and depfile outputs linked,
 * wrapper copied, everything else skipped) and repair the timestamp graph
 * so exactly `changed` (relative to gen_src) reads newer than the seeds.
 * The wrapper copy is unconditional here; production gates it on the
 * bootstrap-inputs diff. */
bool zcl_dev_proof_warm_seed_and_retime(const char *donor_build,
                                        const char *gen_build,
                                        const char *gen_src,
                                        const char *const *changed,
                                        size_t nchanged,
                                        struct zcl_dev_proof_warm_stats *stats);
#endif /* ZCL_DEV_BUILD || ZCL_TESTING */

#endif
