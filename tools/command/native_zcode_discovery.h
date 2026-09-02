/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Generic native composition over the existing ZCODE DHT records. */

#ifndef ZCL_TOOLS_NATIVE_ZCODE_DISCOVERY_H
#define ZCL_TOOLS_NATIVE_ZCODE_DISCOVERY_H

#include "json/json.h"
#include "vcs/zcode_dht_delegation.h"
#include "vcs/zcode_dht_service.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* These adapters add no wire, index or identity. They compose the existing
 * typed DHT record and restricted-provider RPCs so science, spaces and future
 * typed services share one discovery/transport substrate. */
bool zcl_native_zcode_publish_record(
    const char *kind, const char *namespace_name,
    const char *semantic_root, const char *transport_root,
    int64_t sequence, int64_t not_before, int64_t expiry,
    char token_out[65], char *error_out, size_t error_capacity);

bool zcl_native_zcode_records_discover(
    struct json_value *selector, struct json_value *result);

/* Read-only local projections used by composed readiness/status leaves. The
 * status document is intentionally internal: callers must select only fields
 * appropriate for their public surface. Neither helper starts a lookup or
 * creates identity/store state. The swarm read is the existing dumpstate
 * projection of the running daemon, never a second inventory. */
bool zcl_native_zcode_dht_status_read(struct json_value *result);
bool zcl_native_zcode_swarm_status_read(struct json_value *result);
bool zcl_native_zcode_records_local(
    struct json_value *selector, struct json_value *result);
bool zcl_native_zcode_publication_snapshot_read(
    const char *namespace_name, const char *package_root,
    const char *transport_root, struct json_value *result);
bool zcl_native_zcode_package_status_read(
    const char *package_root, const char *transport_root,
    struct json_value *result);

/* Drive the existing begin/poll/cancel capability under a caller-owned
 * absolute monotonic deadline. Adds no RPC or wire surface. */
bool zcl_native_zcode_records_discover_until(
    struct json_value *selector, struct json_value *result,
    int64_t deadline_mono_ms, bool *deadline_reached_out);

bool zcl_native_zcode_provider_route(
    struct json_value *selector, struct json_value *result);

/* A restricted fetch may route only after iterative PROVIDER discovery has
 * populated the daemon's authenticated local projection for this exact root. */
bool zcl_native_zcode_provider_discover_and_route(
    struct json_value *selector, struct json_value *route_result,
    uint32_t *record_count_out);
bool zcl_native_zcode_provider_discover_and_route_until(
    struct json_value *selector, struct json_value *route_result,
    uint32_t *record_count_out, int64_t deadline_mono_ms,
    bool *deadline_reached_out);

#ifdef ZCL_TESTING
typedef bool (*zcl_native_zcode_discovery_test_fn)(
    struct json_value *selector, struct json_value *result);
void zcl_native_zcode_discovery_test_backend(
    zcl_native_zcode_discovery_test_fn discover,
    zcl_native_zcode_discovery_test_fn route);
#endif

struct zcl_native_zcode_pointer_candidate {
  char transport_root[65];
  char publisher_zid[65];
  char provider_node_id[65];
  bool provider_authenticated;
  uint32_t source_index;
};

struct zcl_native_zcode_pointer_candidates {
  struct zcl_native_zcode_pointer_candidate
      rows[VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS];
  size_t count;
  uint32_t records_seen;
  uint32_t conflicts;
  uint32_t superseded;
};

/* Consume the record projection after its per-signed-stream sequence and
 * conflict selection. Independent candidates are ordered only by local
 * authentication evidence and canonical roots, then diversified so duplicate
 * transport roots cannot crowd the first K attempts. */
bool zcl_native_zcode_pointer_candidates_build(
    const struct json_value *records,
    struct zcl_native_zcode_pointer_candidates *out);

/* Ask the running node to prove this exact public delegation against its
 * ACTIVE ZID projection and delayed beacon. No identity secret crosses RPC. */
bool zcl_native_zcode_delegation_authorized(
    const struct vcs_zcode_dht_delegation *delegation,
    char *error_out, size_t error_capacity);
bool zcl_native_zcode_delegation_authorized_until(
    const struct vcs_zcode_dht_delegation *delegation,
    int64_t deadline_mono_ms, char *error_out, size_t error_capacity,
    bool *deadline_reached_out);

#endif /* ZCL_TOOLS_NATIVE_ZCODE_DISCOVERY_H */
