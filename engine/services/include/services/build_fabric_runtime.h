/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Supervision for equal-node requester and executor roles. */

#ifndef ZCL_SERVICES_BUILD_FABRIC_RUNTIME_H
#define ZCL_SERVICES_BUILD_FABRIC_RUNTIME_H

#include "base/result.h"

#include <stdbool.h>

struct zcl_result build_fabric_runtime_register(bool worker_enabled,
                                                const char *datadir);

struct json_value;
bool build_fabric_dump_state_json(struct json_value *out, const char *key);

#ifdef ZCL_TESTING
#include "services/subordinate_work_admission.h"

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
#endif

#endif /* ZCL_SERVICES_BUILD_FABRIC_RUNTIME_H */
