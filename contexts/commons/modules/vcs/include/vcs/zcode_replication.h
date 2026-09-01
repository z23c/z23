/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded, explicitly declared replication accounting. */
#ifndef ZCL_VCS_ZCODE_REPLICATION_H
#define ZCL_VCS_ZCODE_REPLICATION_H

#include "vcs/zcode_dht_record.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_REPLICATION_TARGET 8u
#define VCS_ZCODE_REPLICATION_DURABLE_ACKS 5u
#define VCS_ZCODE_REPLICATION_DURABLE_GROUPS 3u
#define VCS_ZCODE_REPLICATION_MAX_RECORDS_PER_KIND 64u
#define VCS_ZCODE_REPLICATION_MAX_EVIDENCE \
  (2u * VCS_ZCODE_REPLICATION_MAX_RECORDS_PER_KIND)

struct vcs_zcode_replication_status {
  size_t provider_hints;
  size_t authenticated_providers;
  size_t valid_acks;
  size_t locally_revalidated_acks;
  size_t declared_owner_groups;
  size_t expired_acks;
  size_t conflicted_records;
  bool provider_evidence_complete;
  bool ack_evidence_complete;
  bool local_cache_only;
  bool partial;
  bool durable;
};

struct vcs_zcode_replication_evidence {
  const struct vcs_zcode_dht_record *records;
  size_t count;
  const uint8_t (*authenticated_node_ids)[32];
  size_t authenticated_count;
  uint8_t local_node_id[32];
  bool local_possession_current;
  bool provider_evidence_complete;
  bool ack_evidence_complete;
  bool local_cache_only;
};

/* Records must already have passed signature/network authorization. Provider
 * IDs and owner-group declarations are de-duplicated. `durable` means only
 * five live ACKs across three declared groups; it is never proof of separate
 * operators, machines or failure domains. */
void vcs_zcode_replication_evaluate(
    const struct vcs_zcode_dht_record *records, size_t count,
    const char *namespace_name, const uint8_t transport_root[32],
    uint64_t now_unix, struct vcs_zcode_replication_status *out);

/* Distributed evaluator. Remote ACKs remain signed claims; only an ACK whose
 * provider is local_node_id and whose package proof is current contributes to
 * locally_revalidated_acks. Conflicted stream slots are retained in the input
 * but excluded from usable counts. Partial evidence can never be durable. */
void vcs_zcode_replication_evaluate_evidence(
    const struct vcs_zcode_replication_evidence *evidence,
    const char *namespace_name, const uint8_t transport_root[32],
    uint64_t now_unix, struct vcs_zcode_replication_status *out);

bool vcs_zcode_replication_record_conflicted(
    const struct vcs_zcode_dht_record *records, size_t count, size_t index);

#endif
