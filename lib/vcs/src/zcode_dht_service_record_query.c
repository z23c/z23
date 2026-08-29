/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Sovereignty-filtered deterministic record paging and diversity. */

#include "zcode_dht_service_internal.h"

#include "base/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

int vcs_zcode_dht_records_canonical_compare(const void *left,
                                             const void *right)
{
  const struct vcs_zcode_dht_record *a = left;
  const struct vcs_zcode_dht_record *b = right;
  uint8_t aw[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
  uint8_t bw[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
  if (vcs_zcode_dht_record_encode(a, aw) != VCS_ZCODE_DHT_RECORD_OK ||
      vcs_zcode_dht_record_encode(b, bw) != VCS_ZCODE_DHT_RECORD_OK)
    return 0;
  return memcmp(aw, bw, sizeof(aw));
}

static size_t records_local_order(
    const struct vcs_zcode_dht_service *service, uint64_t now_unix,
    const struct vcs_zcode_dht_record_selector *selector,
    struct vcs_zcode_dht_record
        ordered[VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT])
{
  if (!service || !service->record_store || !selector)
    return 0;
  struct vcs_zcode_dht_record candidates[
      VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT];
  size_t found = vcs_zcode_dht_record_store_query(
      service->record_store, selector->kind, selector->namespace_name,
      selector->root, now_unix, candidates,
      VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT);
  if (found > VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT)
    found = VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT;
  struct vcs_zcode_dht_record allowed_records[
      VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT];
  size_t allowed = 0;
  for (size_t i = 0; i < found; i++) {
    if (!vcs_zcode_dht_records_policy_allows(
            service, VCS_ZCODE_SOVEREIGNTY_DISCOVER, &candidates[i]))
      continue;
    allowed_records[allowed++] = candidates[i];
  }
  bool selected[VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT] = {0};
  size_t ordered_count = 0;
  for (size_t i = 0; i < allowed; i++) {
    bool provider_seen = false;
    for (size_t j = 0; j < ordered_count; j++)
      if (memcmp(ordered[j].provider_node_id,
                 allowed_records[i].provider_node_id, 32) == 0) {
        provider_seen = true;
        break;
      }
    if (!provider_seen) {
      ordered[ordered_count++] = allowed_records[i];
      selected[i] = true;
    }
  }
  for (size_t i = 0; i < allowed; i++)
    if (!selected[i])
      ordered[ordered_count++] = allowed_records[i];
  return ordered_count;
}

size_t vcs_zcode_dht_service_record_local_query(
    const struct vcs_zcode_dht_service *service, uint64_t now_unix,
    const struct vcs_zcode_dht_record_selector *selector,
    struct vcs_zcode_dht_record *out, size_t out_capacity)
{
  struct vcs_zcode_dht_record ordered[
      VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT];
  size_t count = records_local_order(service, now_unix, selector, ordered);
  size_t copied = count < out_capacity ? count : out_capacity;
  if (copied && out)
    memcpy(out, ordered, copied * sizeof(*out));
  return count;
}

size_t vcs_zcode_dht_service_record_local_scan(
    const struct vcs_zcode_dht_service *service, uint64_t now_unix,
    enum vcs_zcode_dht_record_kind kind, const char *namespace_name,
    struct vcs_zcode_dht_record *out, size_t out_capacity,
    size_t *seen_total_out)
{
  if (seen_total_out)
    *seen_total_out = 0;
  if (!service || !service->record_store || !namespace_name ||
      (!out && out_capacity))
    return 0;
  /* Filter the complete bounded store before applying the caller's output
   * cap. Otherwise denied records in the canonical prefix can hide later
   * permitted rows. Counts are policy-filtered too: a local projection
   * must not disclose the size of a set local policy refuses to reveal. */
  struct vcs_zcode_dht_record *candidates = zcl_calloc(
      VCS_ZCODE_DHT_RECORD_STORE_MAX_RECORDS, sizeof(*candidates),
      "zcode dht board candidates");
  if (!candidates)
    return 0;
  size_t scanned = vcs_zcode_dht_record_store_scan(
      service->record_store, kind, namespace_name, now_unix, candidates,
      VCS_ZCODE_DHT_RECORD_STORE_MAX_RECORDS);
  if (scanned > VCS_ZCODE_DHT_RECORD_STORE_MAX_RECORDS)
    scanned = VCS_ZCODE_DHT_RECORD_STORE_MAX_RECORDS;
  size_t allowed = 0, copied = 0;
  for (size_t i = 0; i < scanned; i++)
    if (vcs_zcode_dht_records_policy_allows(
            service, VCS_ZCODE_SOVEREIGNTY_DISCOVER, &candidates[i])) {
      if (copied < out_capacity)
        out[copied++] = candidates[i];
      allowed++;
    }
  free(candidates);
  if (seen_total_out)
    *seen_total_out = allowed;
  return copied;
}

size_t vcs_zcode_dht_service_record_local_query_page(
    const struct vcs_zcode_dht_service *service, uint64_t now_unix,
    const struct vcs_zcode_dht_record_selector *selector,
    uint8_t page_offset, struct vcs_zcode_dht_record *out,
    size_t out_capacity, uint8_t *next_offset_out)
{
  if (next_offset_out)
    *next_offset_out = 0;
  if (!out || !out_capacity || !next_offset_out ||
      page_offset >= VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT ||
      page_offset % VCS_ZCODE_DHT_RECORDS_PER_FRAME != 0)
    return 0;
  struct vcs_zcode_dht_record ordered[
      VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT];
  size_t total = records_local_order(service, now_unix, selector, ordered);
  if (page_offset >= total)
    return 0;
  size_t count = total - page_offset;
  if (count > VCS_ZCODE_DHT_RECORDS_PER_FRAME)
    count = VCS_ZCODE_DHT_RECORDS_PER_FRAME;
  if (count > out_capacity)
    count = out_capacity;
  memcpy(out, ordered + page_offset, count * sizeof(*out));
  qsort(out, count, sizeof(*out),
        vcs_zcode_dht_records_canonical_compare);
  if (count == VCS_ZCODE_DHT_RECORDS_PER_FRAME &&
      page_offset + count < total)
    *next_offset_out = (uint8_t)(page_offset + count);
  return count;
}
