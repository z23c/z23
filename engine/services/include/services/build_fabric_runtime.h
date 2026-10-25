/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Supervision for equal-node requester and executor roles. */

#ifndef ZCL_SERVICES_BUILD_FABRIC_RUNTIME_H
#define ZCL_SERVICES_BUILD_FABRIC_RUNTIME_H

#include "base/result.h"

#include <stdbool.h>
#include <stdint.h>

struct node_db;
struct db_build_action;
struct db_build_receipt;
struct build_fabric_attach_report;
struct build_fabric_host_accounting;
struct build_fabric_proof_context;

struct zcl_result build_fabric_runtime_register(bool worker_enabled,
                                                const char *datadir);

struct json_value;
/* True once the worker thread has finished identity, toolchain capture and
 * enroll (acquire); until then the local worker declines all work exactly as
 * a disabled one does. */
bool build_fabric_runtime_worker_ready(void);

bool build_fabric_dump_state_json(struct json_value *out, const char *key);

/* The worker loop's two work steps, callable with an explicit proof context
 * (NULL: no proof state). attach_step peeks at the next queued plain compile
 * and runs build_fabric_attach, the reuse authority; when attach decided and
 * proof is set it also computes the feedback-only ticket decision for the
 * same key and counts the pair. It never changes the attach outcome.
 * execute_step runs the claimed action, admits its receipt, and then issues
 * and publishes a proof ticket; an issuance refusal is counted and logged
 * but never fails the executed, admitted result. */
/* Worker start's proof state: the context build_fabric_proof_context_open
 * returns, or NULL (logged) when it refuses. It never refuses the worker:
 * the caller starts on its identity checks alone, with or without proof. */
struct build_fabric_proof_context *build_fabric_runtime_proof_open(
    struct node_db *ndb, const char *datadir, const char *worker_id,
    const uint8_t seed[32]);
struct zcl_result build_fabric_runtime_attach_step(
    struct node_db *ndb, const char *workspace,
    const uint8_t signer_secret[32], const uint8_t signer_pubkey[32],
    struct build_fabric_proof_context *proof,
    struct db_build_receipt *receipt,
    struct build_fabric_attach_report *report);
struct zcl_result build_fabric_runtime_execute_step(
    struct node_db *ndb, const char *workspace, const char *datadir,
    const struct db_build_action *action, const char *lease_id,
    const uint8_t signer_secret[32], const uint8_t signer_pubkey[32],
    struct build_fabric_proof_context *proof,
    struct db_build_receipt *receipt,
    struct build_fabric_host_accounting *accounting);

#ifdef ZCL_TESTING
#include "services/subordinate_work_admission.h"
#include "services/build_fabric_attach.h"

/* The register call's synchronous worker half (paths only, no capture), the
 * worker thread's enroll step, and read-backs; the thread itself cannot run
 * in a test binary. */
struct zcl_result build_fabric_runtime_prepare_worker_for_test(
    const char *datadir);
bool build_fabric_runtime_enroll_step_for_test(struct node_db *ndb);
bool build_fabric_runtime_worker_enabled_for_test(void);
const char *build_fabric_runtime_local_worker_id_for_test(void);

/* Run exactly the worker loop's admission step — observe, decide, publish the
 * standing reason, count and log a refusal — without the thread, lease or
 * claim. That block is the only writer of the reported admission status, and
 * the loop itself cannot be run in a test binary: it exits only on the
 * process-wide shutdown flag, latches its start one-shot, and caches the
 * node_db past a fixture's teardown. This calls the same function the loop
 * calls, so a test drives the production decision rather than a copy of it.
 *
 * It executes no work. A test using this qualifies the refusal and recovery
 * path, NOT the running worker. */
enum subordinate_work_refusal build_fabric_worker_admission_step_for_test(
    bool running, bool persistence_ready, struct node_db *ndb);

struct zcl_result build_fabric_runtime_try_attach_queued_for_test(
    struct node_db *ndb, const char *workspace,
    const uint8_t signer_secret[32], const uint8_t signer_pubkey[32],
    struct db_build_receipt *receipt,
    struct build_fabric_attach_report *report);
#endif

#endif /* ZCL_SERVICES_BUILD_FABRIC_RUNTIME_H */
