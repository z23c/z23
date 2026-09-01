/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The closed S4 benchmark/reproduction executor — confined fixed-
 *          action runs whose observations feed the landed S3 admission path.
 *
 * THE CONTRACT OF THIS SERVICE: a benchmark is an OBSERVATION, never truth.
 * The executor runs ONLY the registry fixed actions
 * (vcs/build_action.h: c23.benchmark.v1 and c23.benchmark.reproduce.v1) —
 * never a free-form command, never a downloaded script. Every input object
 * (study, task, candidate, method, environment policy, workload payload,
 * original result) is loaded from the workspace CAS with a rederived-root
 * agreement check; a root that is not in CAS is a refusal, never a fetch.
 *
 * Confinement: before any run the executor re-proves the host confinement
 * backend with a canary self-check in the escape-suite tradition (a granted
 * file opens, /etc/passwd is EACCES, socket() and execve() die by SIGSYS)
 * and REFUSES to run when the check fails. The run itself executes in a
 * forked child inside the os_sandbox session-child profile: no_new_privs,
 * rlimits parsed from the kind's fixed resource policy (CPU seconds,
 * address space, nproc=1, bounded file size, no core dumps), Landlock with
 * no usable filesystem (the payload arrives in memory across fork; samples
 * leave over a pre-opened pipe), and the seccomp session deny-list with
 * W^X (socket/exec/clone/mount/ptrace all kill the child).
 *
 * Crash discipline: the finished evidence wire enters CAS ONLY through the
 * S3 confirm:true commit. A crashed/timed-out child leaves nothing behind:
 * auxiliary objects (manifest, sample payload, evidence, profile) are
 * composed and stored only after a successful run, and they are inert —
 * addressed by content, bound to no projection row. Retrying the exact
 * produced wire re-plans/re-commits idempotently by the S3 plan identity.
 *
 * Deterministic envelope: run twice with the same recipe-derived inputs,
 * action sequence, method, and `now`, and the composed result wire is
 * identical except the time fields and the evidence root (the sample
 * payload carrier); method, hardware-profile, and raw-sample manifest
 * roots are stable. */

#ifndef ZCL_SERVICES_ZCODE_BENCHMARK_EXECUTOR_H
#define ZCL_SERVICES_ZCODE_BENCHMARK_EXECUTOR_H

#include "base/result.h"
#include "models/database.h"
#include "services/zcode_science_service.h"
#include "vcs/build_action.h"
#include "vcs/zcode_benchmark_receipt.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_science.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Test/embedding hooks. A NULL hooks pointer (or a NULL field) selects the
 * real default: the canary escape-suite self-check over os_sandbox. A
 * sandbox_selfcheck hook returning a non-ok result must make the executor
 * REFUSE before any run or CAS write — that refusal is a required proof. */
struct zcode_benchmark_executor_hooks {
    struct zcl_result (*sandbox_selfcheck)(const char *bench_dir);
};

struct zcode_benchmark_execute_request {
    const char *workspace;             /* CAS root (repo_root of .zvcs)   */
    /* Benchmark-run identity (all four required for c23.benchmark.v1). */
    const char *study_root_hex;
    const char *task_root_hex;
    const char *candidate_root_hex;
    const char *method_root_hex;
    /* Reproduction runs: the v1 result wire root being reproduced. When
     * non-NULL the run is a reproduction (kind must then be
     * c23.benchmark.reproduce.v1); study/task/candidate roots are taken
     * from the original wire and the four fields above are ignored except
     * method_root_hex (the method is re-pinned exactly). */
    const char *original_result_root_hex;
    const char *action_kind; /* NULL -> VCS_BUILD_ACTION_KIND_BENCHMARK_V1 */
    uint64_t action_sequence;         /* >= 1; a reproduction must re-use
                                         the original run's sequence so the
                                         canonical action root agrees */
    uint64_t challenge_block_height;  /* >= 1 */
    uint8_t challenge_block_hash[32]; /* nonzero */
    uint64_t result_sequence;         /* >= 1 */
    /* Reproduction runs only. */
    uint8_t reproducer_pubkey[32];    /* nonzero for reproduction runs */
    uint64_t reproduction_sequence;   /* >= 1 for reproduction runs */
    int64_t now;                      /* the declared observation time */
    bool confirm;                     /* admit with confirm:true */
    const struct zcode_benchmark_executor_hooks *hooks;
};

/* The artifacts one successful run composed. Everything here is
 * deterministic given the request except the sample payload (and the
 * evidence/result roots that carry it). */
struct zcode_benchmark_run_out {
    bool is_reproduction;
    /* Benchmark runs: the v2 observation + aux wires (method/profile are
     * the exact CAS wires plan/commit store and re-validate). */
    struct vcs_zcode_benchmark_result_v2 result;
    uint8_t result_wire[VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES];
    size_t result_wire_len;
    uint8_t method_wire[VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES];
    uint8_t profile_wire[VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES];
    struct vcs_build_action_v1 action;
    uint8_t result_root[32];
    /* Reproduction runs: the reproduced v1 wire (stored to CAS addressed
     * by its v1 root — the landed S1 comparator binds v1 roots) and the
     * reproduction.v1 wire that goes through plan/commit. */
    struct vcs_zcode_benchmark_result_v1 reproduced;
    uint8_t reproduced_wire[VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES];
    uint8_t reproduced_root[32];
    struct vcs_zcode_reproduction_v1 reproduction;
    uint8_t reproduction_wire[VCS_ZCODE_REPRODUCTION_WIRE_BYTES];
    uint8_t reproduction_root[32];
    uint8_t verdict; /* enum vcs_zcode_reproduction_verdict */
    /* Shared run facts. */
    struct vcs_zcode_benchmark_evidence_v1 evidence;
    uint8_t manifest_root[32];
    uint8_t sample_payload_root[32];
    uint8_t evidence_root[32];
    uint8_t hardware_profile_root[32];
};

struct zcode_benchmark_execute_out {
    struct zcode_benchmark_run_out run;
    struct zcode_science_plan_out plan;
    struct zcode_science_commit_out commit;
    bool committed; /* false when confirm was not given: plan only */
};

/* Run + admit in one call (the native command's shape). `ndb` is the
 * open node database the S3 plan ledger and projection live in. Every
 * refusal names its rule in the result message. */
struct zcl_result zcode_benchmark_execute(
    struct node_db *ndb, const struct zcode_benchmark_execute_request *req,
    struct zcode_benchmark_execute_out *out);

/* Stage 1 — the confined run: loads and cross-checks every CAS input,
 * captures the hardware profile, enforces the study's environment policy,
 * runs the fixed action in confinement, composes the result + aux objects,
 * and stores the AUXILIARY objects (manifest, sample payload, evidence,
 * profile, and for reproductions the reproduced v1 wire) to CAS. Stores NO
 * finished evidence wire and touches NO database. */
struct zcl_result zcode_benchmark_executor_run(
    const struct zcode_benchmark_execute_request *req,
    struct zcode_benchmark_run_out *out);

/* Stage 2 — admission: hands exactly the run artifacts to the landed S3
 * work.plan / work.commit path. confirm:false persists only the exact
 * expiring plan; confirm:true commits (idempotent by plan identity). */
struct zcl_result zcode_benchmark_executor_admit(
    struct node_db *ndb, const char *workspace,
    const struct zcode_benchmark_run_out *run, bool confirm, int64_t now,
    struct zcode_benchmark_execute_out *out);

/* Receipt verification: re-loads the result wire addressed by
 * result_root_hex plus every artifact it transitively binds (method,
 * profile, manifest, sample payload, evidence) from the workspace CAS and
 * re-derives every root and cross-reference. A tampered sample payload,
 * manifest, or profile file fails its root agreement and the whole receipt
 * is rejected — never silently kept. */
struct zcl_result zcode_benchmark_executor_verify_receipt(
    const char *workspace, const char *result_root_hex);

/* The default canary self-check (also what a NULL hooks pointer runs).
 * Exposed so tests can extend the escape-suite pattern directly. */
struct zcl_result zcode_benchmark_executor_sandbox_selfcheck(
    const char *bench_dir);

#endif /* ZCL_SERVICES_ZCODE_BENCHMARK_EXECUTOR_H */
