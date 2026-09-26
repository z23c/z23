/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Executor-keyed attachment of a duplicate fixed compile request to
 * one already-qualified physical result, with its own signed receipt. */

#ifndef ZCL_SERVICES_BUILD_FABRIC_ATTACH_H
#define ZCL_SERVICES_BUILD_FABRIC_ATTACH_H

#include "base/result.h"
#include "models/build_fabric.h"

#include <stdbool.h>
#include <stdint.h>

struct vcs_package_store;

/* The executor key commits to the exact bytes a trusted BUILD-stage executor
 * consumes: the fixed action kind, target, resource policy, declared outputs,
 * the RECOMPUTED fixed flags/environment roots (a stale declared root refuses
 * with "executor-fixed-descriptor-stale"), the action's proof-policy root,
 * the current host's compiler driver/backend/ASSEMBLER FILE BYTES (never the
 * assembler --version string the toolchain capsule binds), and the exact .i
 * payload bytes. The key is also a CAS object id: the worker publishes a
 * self-describing record at that address after each successful physical
 * compile, and a later eligible request attaches instead of recompiling. */
#define BUILD_FABRIC_EXECUTOR_KEY_DOMAIN "zcl.build_executor_key.v1"
#define BUILD_FABRIC_EXECUTOR_TOOLCHAIN_DOMAIN "zcl.build_executor_toolchain.v1"

/* An attached receipt carries no process lease; its lease slot names the
 * executor key it attached to (64 lowercase hex, satisfying the model's
 * lease_id shape) so the binding is self-describing in the durable ledger. */

enum build_fabric_attach_disposition {
    BUILD_FABRIC_ATTACH_MISS = 0, /* no qualified donor; caller compiles */
    BUILD_FABRIC_ATTACH_HIT,      /* output restored, receipt signed */
    BUILD_FABRIC_ATTACH_REFUSED,  /* named refusal in report.refusal */
};

struct build_fabric_attach_report {
    enum build_fabric_attach_disposition disposition;
    char refusal[BUILD_FABRIC_ERROR_MAX + 1];
    char executor_key[BUILD_FABRIC_ID_HEX + 1];
    char donor_action_id[BUILD_FABRIC_ID_HEX + 1];
    char donor_receipt_id[BUILD_FABRIC_ID_HEX + 1];
    char requester_receipt_id[BUILD_FABRIC_ID_HEX + 1];
    /* Requester-action-bound copy of the output bytes in CAS. The canonical
     * action/receipt output root stays the donor's physical root. */
    char output_copy_sha3[BUILD_FABRIC_ID_HEX + 1];
    uint64_t restored_bytes;
    int64_t attach_wall_us;
    uint64_t compiler_processes; /* always 0: attachment never compiles */
};

const char *build_fabric_attach_disposition_string(
    enum build_fabric_attach_disposition disposition);

/* Composition primitives, exposed so tests and future executors can reason
 * about exact key inputs without a host probe. */
void build_fabric_executor_toolchain_root(
    const uint8_t driver_sha3[32], const uint8_t backend_sha3[32],
    const uint8_t assembler_sha3[32], uint8_t out[32]);
void build_fabric_executor_key_from_parts(
    const char *kind, const char *target, const char *resource_policy,
    const char *declared_outputs, const uint8_t flags_root[32],
    const uint8_t environment_root[32], const uint8_t proof_policy_root[32],
    const uint8_t toolchain_bytes_root[32], const uint8_t input_bytes_root[32],
    uint8_t out_key[32]);

/* Hash the current host's resolved compiler driver, backend, and assembler
 * FILE BYTES (the capsule's assembler identity is only its --version string)
 * and compose the executor toolchain-bytes root. */
struct zcl_result build_fabric_executor_host_tool_hashes(
    uint8_t driver_sha3[32], uint8_t backend_sha3[32],
    uint8_t assembler_sha3[32]);

/* Full key derivation for one planned action: recomputes the fixed
 * flags/environment roots for the action kind and refuses a stale declared
 * root, hashes the current tool bytes, and binds the exact input bytes. */
struct zcl_result build_fabric_executor_key_compose(
    const struct db_build_action *action, const uint8_t input_bytes_root[32],
    uint8_t out_key[32]);

/* Idempotently store the self-describing executor-key record in the workspace
 * CAS at object id == key. Called by the confined worker right after the
 * physical observation lands. */
struct zcl_result build_fabric_executor_key_publish(
    const char *workspace, const struct db_build_job *job,
    const struct db_build_action *action, const uint8_t input_bytes_root[32]);

/* Best-effort publish for the confined worker: logs a failure and returns
 * void so the caller adds no branch to its pinned complexity budget. */
void build_fabric_executor_key_publish_logged(
    const char *workspace, const struct db_build_job *job,
    const struct db_build_action *action, const uint8_t input_bytes_root[32]);

/* Attach an eligible duplicate compile request to the qualified physical
 * result of an earlier request WITHOUT re-running the compiler. The
 * requester's own action advances to CACHE_HIT and a SEPARATE signed receipt
 * (requester action/job/worker ids, donor observation root) is persisted.
 * Reproduction (independent-verification) requests carry a distinct profile
 * and are refused by name ("attach-refused-independent-run-required"); a
 * missing executor-key record or donor is a clean MISS, never an error. */
struct zcl_result build_fabric_attach(
    struct node_db *ndb, const char *workspace, struct vcs_package_store *store,
    const struct db_build_job *req_job, const struct db_build_action *req_action,
    const uint8_t signer_secret[32], const uint8_t signer_pubkey[32],
    struct db_build_receipt *out_receipt,
    struct build_fabric_attach_report *out_report);

#endif /* ZCL_SERVICES_BUILD_FABRIC_ATTACH_H */
