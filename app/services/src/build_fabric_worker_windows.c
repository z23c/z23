/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: fail-closed Windows boundary for unqualified package execution. */

#include "services/build_fabric_worker.h"

#if defined(_WIN32)
#include <string.h>

struct zcl_result build_fabric_worker_execute(
    struct node_db *ndb, const char *workspace, const char *datadir,
    const char *action_id, const char *lease_id,
    const uint8_t signer_secret[32], const uint8_t signer_pubkey[32],
    struct db_build_receipt *out_receipt,
    struct build_fabric_worker_feedback *out_feedback)
{
    (void)ndb;
    (void)workspace;
    (void)datadir;
    (void)action_id;
    (void)lease_id;
    (void)signer_secret;
    (void)signer_pubkey;
    if (out_receipt) memset(out_receipt, 0, sizeof(*out_receipt));
    if (out_feedback) memset(out_feedback, 0, sizeof(*out_feedback));
    return ZCL_ERR(
        -1,
        "windows-build-fabric-execution-refused: restricted-token Job Object "
        "low-integrity/AppContainer resource-limit network-denial sandbox "
        "qualification is not complete");
}
#endif
