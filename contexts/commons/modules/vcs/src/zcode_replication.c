/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Evaluate bounded signed provider and storage-ACK evidence. */
#include "vcs/zcode_replication.h"

#include <string.h>

bool vcs_zcode_replication_record_conflicted(
    const struct vcs_zcode_dht_record *records, size_t count, size_t index) {
  return vcs_zcode_dht_record_conflicted_at(records, count, index);
}

static bool record_matches(const struct vcs_zcode_dht_record *record,
                           const char *namespace_name,
                           const uint8_t transport_root[32]) {
  return strcmp(record->namespace_name, namespace_name) == 0 &&
         memcmp(record->transport_root, transport_root, 32) == 0;
}

static bool seen32(const uint8_t values[][32], size_t count,
                   const uint8_t value[32]) {
  for (size_t i = 0; i < count; i++)
    if (memcmp(values[i], value, 32) == 0)
      return true;
  return false;
}

/* Marks each bounded record as conflicted and totals them in out. */
static void mark_conflicted_records(
    const struct vcs_zcode_replication_evidence *evidence,
    size_t bounded_count, bool conflicted[],
    struct vcs_zcode_replication_status *out) {
  for (size_t i = 0; i < bounded_count; i++) {
    conflicted[i] = vcs_zcode_replication_record_conflicted(
        evidence->records, bounded_count, i);
    out->conflicted_records += conflicted[i];
  }
}

/* True when a newer, unconflicted record with the same namespace, root and
 * stream supersedes this one. */
static bool record_superseded_by_newer(
    const struct vcs_zcode_replication_evidence *evidence,
    size_t bounded_count, const bool conflicted[], const char *namespace_name,
    const uint8_t transport_root[32],
    const struct vcs_zcode_dht_record *record) {
  for (size_t j = 0; j < bounded_count; j++)
    if (!conflicted[j] &&
        record_matches(&evidence->records[j], namespace_name,
                       transport_root) &&
        vcs_zcode_dht_record_same_stream(record, &evidence->records[j]) &&
        evidence->records[j].sequence > record->sequence)
      return true;
  return false;
}

/* True when the record matches this namespace and root, has started its
 * validity window, and is neither conflicted nor superseded. */
static bool record_eligible_for_tally(
    const struct vcs_zcode_replication_evidence *evidence,
    size_t bounded_count, const bool conflicted[], const char *namespace_name,
    const uint8_t transport_root[32], uint64_t now_unix, size_t index) {
  const struct vcs_zcode_dht_record *record = &evidence->records[index];
  return record_matches(record, namespace_name, transport_root) &&
         now_unix >= record->not_before && !conflicted[index] &&
         !record_superseded_by_newer(evidence, bounded_count, conflicted,
                                     namespace_name, transport_root, record);
}

/* Records an unexpired, unseen provider node id and counts it as
 * authenticated when the evidence lists that node. */
static void count_provider_hint(
    const struct vcs_zcode_dht_record *record,
    const struct vcs_zcode_replication_evidence *evidence, uint64_t now_unix,
    uint8_t providers[][32], size_t *provider_count,
    struct vcs_zcode_replication_status *out) {
  if (now_unix < record->expiry &&
      *provider_count < VCS_ZCODE_REPLICATION_MAX_RECORDS_PER_KIND &&
      !seen32(providers, *provider_count, record->provider_node_id)) {
    memcpy(providers[(*provider_count)++], record->provider_node_id, 32);
    if (evidence->authenticated_node_ids &&
        seen32(evidence->authenticated_node_ids,
               evidence->authenticated_count,
               record->provider_node_id))
      out->authenticated_providers++;
  }
}

/* Tallies one storage-ACK record as expired, or as a fresh ack with its
 * owner group and any local revalidation; unexpired acks that repeat an
 * acknowledger or hit the acknowledger cap are not tallied. */
static void count_storage_ack(
    const struct vcs_zcode_dht_record *record,
    const struct vcs_zcode_replication_evidence *evidence, uint64_t now_unix,
    uint8_t acknowledgers[][32], size_t *ack_count, uint8_t groups[][32],
    size_t *group_count, struct vcs_zcode_replication_status *out) {
  if (now_unix >= record->expiry) {
    out->expired_acks++;
    return;
  }
  if (*ack_count >= VCS_ZCODE_REPLICATION_MAX_RECORDS_PER_KIND ||
      seen32(acknowledgers, *ack_count, record->provider_node_id))
    return;
  memcpy(acknowledgers[(*ack_count)++], record->provider_node_id, 32);
  if (memcmp(record->provider_node_id, evidence->local_node_id, 32) == 0 &&
      evidence->local_possession_current)
    out->locally_revalidated_acks++;
  if (*group_count < VCS_ZCODE_REPLICATION_MAX_RECORDS_PER_KIND &&
      !seen32(groups, *group_count, record->owner_group))
    memcpy(groups[(*group_count)++], record->owner_group, 32);
}

/* Sets the partial and durable summary fields from the collected counts. */
static void summarize_replication_status(
    struct vcs_zcode_replication_status *out, bool evidence_overflow,
    size_t ack_count, size_t group_count) {
  out->partial = !out->provider_evidence_complete ||
                 !out->ack_evidence_complete || out->local_cache_only ||
                 evidence_overflow;
  out->durable = !out->partial && !out->conflicted_records &&
                 ack_count >= VCS_ZCODE_REPLICATION_DURABLE_ACKS &&
                 group_count >= VCS_ZCODE_REPLICATION_DURABLE_GROUPS;
}

void vcs_zcode_replication_evaluate_evidence(
    const struct vcs_zcode_replication_evidence *evidence,
    const char *namespace_name, const uint8_t transport_root[32],
    uint64_t now_unix, struct vcs_zcode_replication_status *out) {
  if (!out)
    return;
  memset(out, 0, sizeof(*out));
  if (!evidence || !evidence->records || !namespace_name || !transport_root)
    return;
  out->provider_evidence_complete = evidence->provider_evidence_complete;
  out->ack_evidence_complete = evidence->ack_evidence_complete;
  out->local_cache_only = evidence->local_cache_only;
  uint8_t providers[VCS_ZCODE_REPLICATION_MAX_RECORDS_PER_KIND][32];
  uint8_t acknowledgers[VCS_ZCODE_REPLICATION_MAX_RECORDS_PER_KIND][32];
  uint8_t groups[VCS_ZCODE_REPLICATION_MAX_RECORDS_PER_KIND][32];
  size_t provider_count = 0, ack_count = 0, group_count = 0;
  bool conflicted[VCS_ZCODE_REPLICATION_MAX_EVIDENCE] = {false};
  bool evidence_overflow =
      evidence->count > VCS_ZCODE_REPLICATION_MAX_EVIDENCE;
  size_t bounded_count = evidence->count < VCS_ZCODE_REPLICATION_MAX_EVIDENCE
                             ? evidence->count
                             : VCS_ZCODE_REPLICATION_MAX_EVIDENCE;
  mark_conflicted_records(evidence, bounded_count, conflicted, out);
  for (size_t i = 0; i < bounded_count; i++) {
    const struct vcs_zcode_dht_record *record = &evidence->records[i];
    if (!record_eligible_for_tally(evidence, bounded_count, conflicted,
                                   namespace_name, transport_root, now_unix,
                                   i))
      continue;
    if (record->kind == VCS_ZCODE_DHT_RECORD_PROVIDER)
      count_provider_hint(record, evidence, now_unix, providers,
                          &provider_count, out);
    else if (record->kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK)
      count_storage_ack(record, evidence, now_unix, acknowledgers, &ack_count,
                        groups, &group_count, out);
  }
  out->provider_hints = provider_count;
  out->valid_acks = ack_count;
  out->declared_owner_groups = group_count;
  summarize_replication_status(out, evidence_overflow, ack_count, group_count);
}

void vcs_zcode_replication_evaluate(
    const struct vcs_zcode_dht_record *records, size_t count,
    const char *namespace_name, const uint8_t transport_root[32],
    uint64_t now_unix, struct vcs_zcode_replication_status *out) {
  struct vcs_zcode_replication_evidence evidence = {
      .records = records,
      .count = count,
      .local_cache_only = true,
  };
  vcs_zcode_replication_evaluate_evidence(
      &evidence, namespace_name, transport_root, now_unix, out);
}
