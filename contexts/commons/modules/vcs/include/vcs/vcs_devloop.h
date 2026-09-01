/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs_devloop — the dev-loop <-> ZVCS glue: turns one green
 * `zcl.dev_cycle.v1` verdict (tools/dev/devloop_cycle.c:finish_cycle()) into
 * one auto-anchored ZVCS commit binding the source tree to the verdict and
 * the binary generation it produced.
 *
 * FAIL-OPEN BY DESIGN: this is called from the hot dev-loop path on every
 * green cycle. A ZVCS failure here must never fail the cycle or crash the
 * loop — every path returns a populated result instead of using the
 * process-terminating LOG_FAIL/LOG_ERR/LOG_NULL macros. The one exception
 * that gets a distinct, loud status is a sealed-path refusal
 * (VCS_DEVLOOP_ANCHOR_REFUSED): the dev-loop publish has ALREADY happened by
 * this point in the pipeline (this hook runs after finish_cycle's own
 * publish/hotswap step), so a refusal here is advisory only, not a block —
 * the seal check is moved earlier, before publish. */

#ifndef ZCL_VCS_DEVLOOP_H
#define ZCL_VCS_DEVLOOP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "vcs/zcode_dht_record.h"

/* The subset of a dev-cycle verdict this glue needs, deliberately narrow —
 * every field is something tools/dev/devloop_cycle.c:finish_cycle() already
 * has in scope or can read from state it already touches (the
 * zcl.agent_dev_deploy.v1 deploy-state file for a reload cycle, or the
 * hotswap load report's artifact_sha256 for a hotswap cycle).
 *
 * generation_hex, when non-empty, MUST be exactly 64 lowercase/uppercase hex
 * characters (a raw SHA-256 digest) — the binary identity this cycle
 * produced. An unparsable non-empty value is treated as absent (the commit
 * still lands, with an all-zero generation_sha256) rather than failing the
 * anchor. */
struct vcs_devloop_verdict {
    uint32_t    verdict_status;  /* 0 = passed; any other value = not passed */
    const char *phase;           /* e.g. "resident_commit", "transactional_reload" */
    int64_t     elapsed_ms;
    const char *generation_hex;  /* 64 hex chars, or NULL/empty if unknown */
    const char *agent_id;        /* from ZCL_AGENT_ID, or NULL/empty */
    const char *session_id;      /* from ZCL_SESSION_ID, or NULL/empty */
    const char *task_ref;        /* from ZCL_TASK_REF, or NULL/empty */
    /* A fresh repository has no stat cache or object baseline and can require
     * thousands of durable writes. When true, queue that generation-neutral
     * baseline out of band and return DEFERRED instead of blocking the edit
     * verdict. Existing repositories still anchor synchronously. */
    bool        defer_initial_snapshot;
    /* Only a complete source-wide VERIFY proof may enqueue publication.
     * These exact identities are captured before proof and rechecked by the
     * resident dev authority; queueing never grants acceptance or network,
     * package, wallet, or Git authority. */
    bool        proof_complete;
    const char *proof_scope;
    const char *source_identity_hex;
    const char *source_cas_hex;
};

enum vcs_devloop_anchor_status {
    VCS_DEVLOOP_ANCHOR_OK      = 0,  /* committed; out->commit_id is valid */
    VCS_DEVLOOP_ANCHOR_ERROR   = 1,  /* vcs failure; fail-open, see out->error */
    VCS_DEVLOOP_ANCHOR_REFUSED = 2,  /* sealed-path change refused (advisory) */
    VCS_DEVLOOP_ANCHOR_DEFERRED = 3, /* generation-neutral baseline queued */
};

enum vcs_devloop_publication_status {
    VCS_DEVLOOP_PUBLICATION_NONE = 0,
    VCS_DEVLOOP_PUBLICATION_QUEUED = 1,
    VCS_DEVLOOP_PUBLICATION_ERROR = 2,
};

#define VCS_DEVLOOP_PUBLICATION_JOB_VERSION 1u

struct vcs_devloop_publication_job {
    uint32_t version;
    uint8_t vcs_commit_root[32];
    uint8_t source_tree_root[32];
    uint8_t proof_receipt_root[32];
    uint8_t source_identity_sha256[32];
    uint8_t source_cas_sha3[32];
    uint8_t generation_sha256[32];
    uint8_t parent_workspace_root[32];
};

enum vcs_devloop_publication_phase {
    VCS_DEVLOOP_PUBLICATION_PHASE_WAITING_ACCEPTANCE = 1,
    VCS_DEVLOOP_PUBLICATION_PHASE_ACCEPTED_LANE_BOUND = 2,
    VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY = 3,
    VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED = 4,
    VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED = 5,
    VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED = 6,
    VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED = 7,
    VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED = 8,
    VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED = 9,
};

#define VCS_DEVLOOP_PUBLICATION_RECEIPT_VERSION 1u

/* Local scheduling evidence only. Signed releases, workspace manifests,
 * provider announcements and storage ACKs remain authoritative in their
 * existing protocols; future phases bind those roots through artifact_root. */
struct vcs_devloop_publication_receipt {
    uint32_t version;
    enum vcs_devloop_publication_phase phase;
    uint8_t job_root[32];
    uint8_t predecessor_receipt_root[32];
    uint8_t artifact_root[32];
    uint64_t bytes_scanned;
    uint32_t new_chunks;
    uint32_t reused_chunks;
    uint16_t providers;
    uint16_t storage_acks;
};

struct vcs_devloop_anchor_result {
    enum vcs_devloop_anchor_status status;
    uint8_t commit_id[32];  /* valid iff status == VCS_DEVLOOP_ANCHOR_OK */
    char    error[256];     /* human-readable detail iff status != OK */
    /* True iff status == VCS_DEVLOOP_ANCHOR_DEFERRED because no baseline is
     * running yet (durable history is absent and no other cycle holds
     * .zvcs/bootstrap.lock). contexts/commons/modules/vcs never launches anything to fill this
     * in — it is a pure SELECT-only check (open/flock, no fork/exec) — so
     * the CALLER decides how to run the baseline: synchronously via
     * vcs_devloop_run_initial_baseline() below, or detached (see
     * tools/dev/devloop_baseline.c for the dev-loop's double-fork
     * launcher). When false and status == DEFERRED, a baseline started by
     * some earlier caller is already in flight; this cycle just stays
     * unanchored until it finishes. */
    bool    baseline_needed;
    enum vcs_devloop_publication_status publication_status;
    uint8_t proof_receipt_root[32];
    uint8_t publication_job_root[32];
    int64_t publication_enqueue_us;
    bool publication_reused;
    char publication_error[256];
};

/* Result of binding one already-PROVEN ZCODE candidate to the existing
 * publication queue from its retained candidate workspace.  No source files
 * are copied or applied: the destination re-captures the exact candidate
 * tree, imports and independently verifies the accepted-work authority
 * bundle, then advances the ordinary publication job to the accepted lane. */
struct vcs_devloop_accepted_candidate_result {
    bool ok;
    bool reused;
    uint8_t source_tree_root[32];
    uint8_t vcs_commit_root[32];
    uint8_t proof_receipt_root[32];
    uint8_t publication_job_root[32];
    uint8_t publication_progress_root[32];
    uint32_t imported_objects;
    uint32_t imported_work_receipts;
    char error[256];
};

/* Anchor one green dev-loop cycle: open (creating if absent) the ZVCS repo
 * rooted at repo_root, and take a snapshot bound to *v. Never aborts the
 * calling process. `out` is always fully populated (memset first) — check
 * out->status rather than a boolean return. Safe to call from the hot
 * dev-loop path: the object store dedupes unchanged files, so steady-state
 * cost tracks the change set. Callers that set defer_initial_snapshot get a
 * DEFERRED result instead of paying the first-snapshot cost inline; check
 * out->baseline_needed to see whether THIS call is the one that should
 * launch/run the baseline (see vcs_devloop_run_initial_baseline below) or
 * whether one is already in flight. contexts/commons/modules/vcs itself never spawns a process
 * to do this — see docs/work/HOTSWAP.md and the ZVCS-sovereignty lint gate
 * (contexts/commons/modules/vcs is release-linkable and must stay process-spawn free). */
void vcs_devloop_anchor_cycle(const char *repo_root,
                              const struct vcs_devloop_verdict *v,
                              struct vcs_devloop_anchor_result *out);

/* Turn an existing accepted-work root into an ordinary dev.publication job
 * without changing the authoritative source workspace.  authority_workspace
 * owns the accepted proof chain; candidate_workspace owns the already-created
 * exact candidate files.  Both source captures and the full authority bundle
 * are independently checked against expected_source_root before queueing.
 * Restart-safe: an existing same-source job is reused only when the normal
 * accepted-work advancement independently accepts this exact root. */
void vcs_devloop_publication_bind_accepted_candidate(
    const char *authority_workspace, const char *candidate_workspace,
    const uint8_t accepted_work_root[32],
    const uint8_t expected_source_root[32], int64_t now_unix,
    struct vcs_devloop_accepted_candidate_result *out);

/* Run the generation-neutral initial ZVCS baseline SYNCHRONOUSLY: take the
 * .zvcs/bootstrap.lock flock singleton (open()/flock() only — no process
 * spawned), and if acquired, take one snapshot binding a
 * phase="bootstrap_baseline" verdict, then release the lock. If the lock is
 * already held by another caller, returns immediately with
 * VCS_DEVLOOP_ANCHOR_DEFERRED and baseline_needed=false (someone else is
 * already running it). This is the same work the old in-process double-fork
 * detach used to do in its grandchild; callers that want that off the
 * foreground path (e.g. the interactive dev loop) are responsible for
 * detaching it themselves — see tools/dev/devloop_baseline.c, which is
 * ZCL_DEV_BUILD-only and lives outside contexts/commons/modules/vcs precisely so contexts/commons/modules/vcs can stay
 * process-spawn free (the ZVCS-sovereignty lint gate). `out` is always
 * fully populated. */
void vcs_devloop_run_initial_baseline(const char *repo_root,
                                      struct vcs_devloop_anchor_result *out);

/* Decode exactly 64 hex characters (either case) into 32 bytes. Returns
 * false — and leaves *out unmodified — on a wrong length or any non-hex
 * character; never crashes on a malformed or NULL input. */
bool vcs_devloop_hex32_decode(const char *hex, uint8_t out[32]);

/* Bounded restart-safe publication queue readers. Loading recomputes the
 * VCS object address; queue membership means an fsync-complete append exists.
 * Requeue is idempotent for an exact immutable job root. */
bool vcs_devloop_publication_job_load(
    const char *repo_root, const uint8_t job_root[32],
    struct vcs_devloop_publication_job *out);
bool vcs_devloop_publication_job_is_queued(
    const char *repo_root, const uint8_t job_root[32]);
bool vcs_devloop_publication_job_requeue(
    const char *repo_root, const uint8_t job_root[32], bool *reused_out);

/* Load the latest append-only scheduler receipt for one job. False means no
 * receipt or a corrupt/over-budget progress log. The advance operation is an
 * idempotent worker step and never grants human-acceptance authority. */
bool vcs_devloop_publication_progress_load(
    const char *repo_root, const uint8_t job_root[32],
    struct vcs_devloop_publication_receipt *out,
    uint8_t receipt_root_out[32]);
bool vcs_devloop_publication_receipt_load(
    const char *repo_root, const uint8_t receipt_root[32],
    struct vcs_devloop_publication_receipt *out);
bool vcs_devloop_publication_advance_waiting_acceptance(
    const char *repo_root, const uint8_t job_root[32],
    uint8_t receipt_root_out[32], bool *reused_out);
bool vcs_devloop_publication_advance_proven_work(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t accepted_work_root[32], int64_t now_unix,
    uint8_t receipt_root_out[32], bool *reused_out);
bool vcs_devloop_publication_advance_package_mapping(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t mapping_set_root[32], uint64_t bytes_scanned,
    uint32_t new_chunks, uint32_t reused_chunks,
    uint8_t receipt_root_out[32], bool *reused_out);
bool vcs_devloop_publication_advance_release(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t mapping_set_root[32], const uint8_t release_root[32],
    uint8_t receipt_root_out[32], bool *reused_out);
bool vcs_devloop_publication_advance_passport(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t mapping_set_root[32], const uint8_t release_root[32],
    const uint8_t passport_root[32], uint8_t receipt_root_out[32],
    bool *reused_out);
bool vcs_devloop_publication_advance_workspace(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t mapping_set_root[32], const uint8_t release_root[32],
    const uint8_t passport_root[32], const uint8_t workspace_root[32],
    uint8_t receipt_root_out[32], bool *reused_out);

#define VCS_DEVLOOP_PUBLICATION_ACK_MIN 2u
#define VCS_DEVLOOP_PUBLICATION_ACK_MAX 16u

struct vcs_devloop_publication_ack_target {
    char namespace_name[VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES];
    uint8_t transport_root[32];
    uint8_t source_root[32];
    uint16_t existing_acks;
    bool already_acknowledged;
    bool already_reproduced;
};

/* Persist one exact signed PROVIDER wire and append its canonical record root
 * only after re-verifying the job's signed workspace -> release chain and
 * proving that the record addresses that release's content.v2 package root.
 * This records network evidence; it does not perform or authorize network IO. */
bool vcs_devloop_publication_advance_provider(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t *record_wire, size_t record_wire_len,
    const struct vcs_zcode_dht_record_verify_context *verify,
    uint8_t receipt_root_out[32], bool *reused_out);

/* Resolve a provider-announced job to the exact DHT selector needed for
 * STORAGE_ACK discovery. The stored PROVIDER wire (including ordinary
 * historical expiry), signed release chain and content.v2 package root are
 * all reloaded and reverified first. Current ACK wires are verified later. */
bool vcs_devloop_publication_storage_ack_target(
    const char *repo_root, const uint8_t job_root[32],
    const struct vcs_zcode_dht_record_verify_context *verify,
    struct vcs_devloop_publication_ack_target *out);

/* Bind a bounded, provider/group-distinct set of existing signed STORAGE_ACK
 * wires to the exact release package behind a provider-announced job. The
 * DHT records remain authoritative; this is a rebuildable scheduler receipt
 * and performs no network or wallet action. */
bool vcs_devloop_publication_advance_storage_acks(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t *const record_wires[], const size_t record_wire_lengths[],
    size_t record_count,
    const struct vcs_zcode_dht_record_verify_context *verify,
    uint8_t receipt_root_out[32], bool *reused_out);

/* Resolve a storage-acknowledged publication to its exact source/package
 * selector, then bind one current SOURCE_REPRODUCTION_ACK only when its
 * signer and declared owner group are distinct from the publishing provider
 * and every accepted storage witness. This proves signed source
 * reconstruction; the record format intentionally makes no physical-host
 * claim. */
bool vcs_devloop_publication_source_reproduction_target(
    const char *repo_root, const uint8_t job_root[32],
    const struct vcs_zcode_dht_record_verify_context *verify,
    struct vcs_devloop_publication_ack_target *out);
bool vcs_devloop_publication_advance_source_reproduction_ack(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t *record_wire, size_t record_wire_len,
    const struct vcs_zcode_dht_record_verify_context *verify,
    uint8_t receipt_root_out[32], bool *reused_out);

#endif /* ZCL_VCS_DEVLOOP_H */
