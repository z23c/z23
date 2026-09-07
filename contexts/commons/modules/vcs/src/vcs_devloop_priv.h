/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs_devloop_priv — the publication state machine's shared shape and
 * internal seams, between vcs_devloop.c (job queue, receipt codec, and
 * artifact-chain reconstruction) and vcs_devloop_publication.c (the
 * advance_* entry points that walk the chain forward one phase at a
 * time). NOT a public header: nothing outside contexts/commons/modules/vcs/src/
 * includes this, and the concrete struct publication_artifact_chain shape
 * stays invisible to every caller of vcs/vcs_devloop.h. */

#ifndef ZCL_VCS_VCS_DEVLOOP_PRIV_H
#define ZCL_VCS_VCS_DEVLOOP_PRIV_H

#include "vcs/vcs_devloop.h"
#include "vcs/package_mapping.h"
#include "vcs/package_release.h"
#include "vcs/zcode_dht_record.h"
#include "platform/process_lock.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Fixed wire sizes and the ack-set magic shared by the receipt codec
 * (vcs_devloop.c) and the ack-set assembly it stores for
 * (vcs_devloop_publication.c). */
#define VCS_DEV_PUBLICATION_RECEIPT_WIRE_BYTES 132u
#define VCS_DEV_PUBLICATION_ACK_SET_HEADER_BYTES 16u
extern const uint8_t publication_ack_set_magic[8];

/* One receipt chain, resolved back from the latest receipt to the
 * mapping-ready root. vcs_devloop.c builds it; vcs_devloop_publication.c's
 * advance_* steps read it to decide what phase comes next. */
struct publication_artifact_chain {
    bool mapping_ready;
    bool release_published;
    bool passport_published;
    bool workspace_published;
    bool provider_announced;
    bool storage_acknowledged;
    bool source_reproduced;
    struct vcs_devloop_publication_receipt mapping;
    struct vcs_devloop_publication_receipt release;
    struct vcs_devloop_publication_receipt passport;
    struct vcs_devloop_publication_receipt workspace;
    struct vcs_devloop_publication_receipt provider;
    struct vcs_devloop_publication_receipt storage_ack;
    struct vcs_devloop_publication_receipt source_reproduction;
};

/* ── defined in vcs_devloop.c, called from vcs_devloop_publication.c ─── */

bool publication_artifact_chain_load(
    const char *repo_root,
    const struct vcs_devloop_publication_receipt *latest,
    struct publication_artifact_chain *out);

bool publication_mapping_valid(
    const char *repo_root, const struct vcs_devloop_publication_job *job,
    const uint8_t mapping_set_root[32],
    struct vcs_package_mapping_set *set_out);

bool publication_accepted_work_valid(
    const char *repo_root,
    const struct vcs_devloop_publication_job *job,
    const uint8_t accepted_work_root[32], int64_t now_unix);

bool publication_provider_wire_store(
    const char *repo_root, const struct vcs_package_release *release,
    const uint8_t *record_wire, size_t record_wire_len,
    const struct vcs_zcode_dht_record_verify_context *verify,
    uint8_t record_root_out[32]);

bool publication_storage_ack_set_store(
    const char *repo_root, const struct vcs_package_release *release,
    const uint8_t *const record_wires[], const size_t record_wire_lengths[],
    size_t record_count,
    const struct vcs_zcode_dht_record_verify_context *verify,
    uint8_t ack_set_root_out[32]);

bool publication_record_load_persisted(
    const char *repo_root, const uint8_t root[32],
    const struct vcs_zcode_dht_record_verify_context *verify,
    struct vcs_zcode_dht_record *record);

bool publication_receipt_serialize(
    const struct vcs_devloop_publication_receipt *receipt,
    uint8_t wire[VCS_DEV_PUBLICATION_RECEIPT_WIRE_BYTES]);

bool publication_queue_path(const char *repo_root, const char *name,
                            char *out, size_t out_size);

bool publication_queue_lock_acquire(struct platform_process_lock *lock,
                                    const char *lock_path);

/* ── defined in vcs_devloop_publication.c, called from vcs_devloop.c ─── */

bool publication_receipt_phase_known(
    enum vcs_devloop_publication_phase phase);

bool publication_provider_stored_write_verified(
    const char *repo_root, const uint8_t record_root[32],
    const uint8_t *record_wire, size_t record_wire_len,
    const struct vcs_zcode_dht_record_verify_context *verify);

bool publication_storage_ack_record_ingest(
    const char *repo_root, const struct vcs_package_release *release,
    const struct vcs_zcode_dht_record_verify_context *verify,
    const uint8_t *record_wire, size_t record_wire_len,
    uint8_t providers[][32], uint8_t groups[][32], size_t i,
    uint8_t root_out[32]);

bool publication_enqueue_proof_basis_valid(
    const struct vcs_devloop_verdict *verdict, uint8_t source_identity[32],
    uint8_t source_cas[32]);

#endif /* ZCL_VCS_VCS_DEVLOOP_PRIV_H */
