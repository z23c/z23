/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: One confined, content-addressed ZBuild V1 worker dispatch. */

#ifndef ZCL_SERVICES_BUILD_FABRIC_WORKER_H
#define ZCL_SERVICES_BUILD_FABRIC_WORKER_H

#include "base/result.h"
#include "models/build_fabric.h"
#include "services/build_fabric_worker_feedback.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Execute one already-claimed action. The caller owns lease acquisition;
 * this path rechecks it at start, verification, and signed publication. */
struct zcl_result build_fabric_worker_execute(
    struct node_db *ndb, const char *workspace_root, const char *datadir,
    const char *action_id,
    const char *lease_id, const uint8_t signer_secret[32],
    const uint8_t signer_pubkey[32], struct db_build_receipt *out_receipt,
    struct build_fabric_worker_feedback *out_feedback);

/* Load or atomically create the operator-owned local worker key. The returned
 * row is suitable for explicit -buildworker self-approval. A host that
 * cannot capture a gcc toolchain capsule (vcs_toolchain_capsule_v1_capture,
 * ELF/glibc-specific) cannot execute c23.compile/.test/.fuzz/.package and
 * this returns a named error instead of an approvable row that would
 * advertise capability it cannot honor. */
struct zcl_result build_fabric_worker_identity_load(
    const char *datadir, struct db_build_worker *worker,
    uint8_t signer_secret[32], uint8_t signer_pubkey[32]);

#ifdef ZCL_TESTING
/* Test seam: the honest capabilities-or-refusal decision, driven by a
 * caller-supplied outcome rather than the real toolchain probe, so tests
 * can exercise the refusal path on a host (e.g. this repo's own Linux CI)
 * where vcs_toolchain_capsule_v1_capture() always succeeds. Mirrors
 * the "force the outcome, run the real decision code" shape of
 * os_proc_mem_set_override() / platform_clock_set_source(). */
struct zcl_result build_fabric_worker_capabilities_for_test(
    bool have_toolchain, char *out, size_t out_len);
#endif

#endif /* ZCL_SERVICES_BUILD_FABRIC_WORKER_H */
