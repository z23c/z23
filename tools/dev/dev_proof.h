/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Exact commit/base proof scheduling and status interface. */

#ifndef ZCL_TOOLS_DEV_PROOF_H
#define ZCL_TOOLS_DEV_PROOF_H

#include "dev_proof_receipt.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
    char detail[256];
    int64_t started_unix;
    int64_t eta_ms;
    int64_t worker_id;
    bool receipt_reused;
};

const char *zcl_dev_proof_state_name(enum zcl_dev_proof_state state);
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
bool zcl_dev_proof_wait(const char *repo_root,
                        const char *local_commit,
                        const char *remote_base,
                        int timeout_ms,
                        struct zcl_dev_proof_status *out);

#endif
