/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded deterministic read-only space scout mission and evidence. */

#ifndef ZCL_VCS_SPACE_SCOUT_H
#define ZCL_VCS_SPACE_SCOUT_H

#include "vcs/space.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_SPACE_SCOUT_MISSION_VERSION 1u
#define VCS_SPACE_SCOUT_MAP_VERSION 1u
#define VCS_SPACE_SCOUT_ATTESTATION_VERSION 1u
#define VCS_SPACE_SCOUT_START_MAX 8u
#define VCS_SPACE_SCOUT_DEPTH_MAX 8u
#define VCS_SPACE_SCOUT_SPACES_MAX 32u
#define VCS_SPACE_SCOUT_PORTALS_MAX 64u
#define VCS_SPACE_SCOUT_BYTES_MAX (8u * 1024u * 1024u)
#define VCS_SPACE_SCOUT_DEADLINE_MS_MAX 60000u

#define VCS_SPACE_SCOUT_MISSION_WIRE_BYTES \
  (8u + 2u + 32u + 8u + 1u + 1u + 1u + 2u + 4u + 4u + \
   VCS_SPACE_SCOUT_START_MAX * 32u)

enum vcs_space_scout_manifest_result {
  VCS_SPACE_SCOUT_MANIFEST_VERIFIED = 1,
  VCS_SPACE_SCOUT_MANIFEST_POLICY_DENIED,
  VCS_SPACE_SCOUT_MANIFEST_NOT_FOUND,
  VCS_SPACE_SCOUT_MANIFEST_FETCH_SCHEDULED,
  VCS_SPACE_SCOUT_MANIFEST_INVALID,
  VCS_SPACE_SCOUT_MANIFEST_EXPIRED,
  VCS_SPACE_SCOUT_MANIFEST_CHAIN_DENIED,
  VCS_SPACE_SCOUT_MANIFEST_BYTE_LIMIT,
  VCS_SPACE_SCOUT_MANIFEST_DEADLINE,
};

enum vcs_space_scout_portal_result {
  VCS_SPACE_SCOUT_PORTAL_FOLLOWED = 1,
  VCS_SPACE_SCOUT_PORTAL_CYCLE,
  VCS_SPACE_SCOUT_PORTAL_DEPTH_LIMIT,
  VCS_SPACE_SCOUT_PORTAL_SPACE_LIMIT,
  VCS_SPACE_SCOUT_PORTAL_TRUNCATED,
};

enum vcs_space_scout_truncation {
  VCS_SPACE_SCOUT_TRUNCATION_NONE = 0,
  VCS_SPACE_SCOUT_TRUNCATION_DEPTH,
  VCS_SPACE_SCOUT_TRUNCATION_SPACES,
  VCS_SPACE_SCOUT_TRUNCATION_PORTALS,
  VCS_SPACE_SCOUT_TRUNCATION_BYTES,
  VCS_SPACE_SCOUT_TRUNCATION_DEADLINE,
};

struct vcs_space_scout_mission_v1 {
  uint16_t schema_version;
  uint8_t network_genesis[32];
  uint64_t observation_unix;
  uint8_t start_count;
  uint8_t maximum_depth;
  uint8_t maximum_spaces;
  uint16_t maximum_portals;
  uint32_t maximum_bytes;
  uint32_t deadline_ms;
  uint8_t starting_roots[VCS_SPACE_SCOUT_START_MAX][32];
};

struct vcs_space_scout_visit_v1 {
  uint8_t space_root[32];
  uint8_t owner_zid[32];
  uint8_t depth;
  uint8_t manifest_result;
  uint8_t service_count;
  uint8_t service_roots[VCS_SPACE_SERVICE_MAX][32];
};

struct vcs_space_scout_portal_v1 {
  uint8_t from_root[32];
  uint8_t to_root[32];
  uint8_t result;
};

struct vcs_space_scout_failure_v1 {
  uint8_t space_root[32];
  uint8_t result;
};

struct vcs_space_scout_map_v1 {
  uint16_t schema_version;
  uint8_t mission_root[32];
  uint64_t observation_unix;
  uint32_t bytes_observed;
  uint8_t truncation;
  uint8_t visit_count;
  uint16_t portal_count;
  uint8_t failure_count;
  uint8_t policy_denial_count;
  struct vcs_space_scout_visit_v1 visits[VCS_SPACE_SCOUT_SPACES_MAX];
  struct vcs_space_scout_portal_v1 portals[VCS_SPACE_SCOUT_PORTALS_MAX];
  struct vcs_space_scout_failure_v1 failures[VCS_SPACE_SCOUT_SPACES_MAX];
};

/* The canonical map deliberately excludes observer identity so identical
 * mission inputs and observations have identical bytes. This separate signed
 * attestation says only that one local observer produced that map; it grants
 * no authority over any visited space. */
struct vcs_space_scout_attestation_v1 {
  uint16_t schema_version;
  uint8_t mission_root[32];
  uint8_t evidence_map_root[32];
  uint64_t observation_unix;
  struct vcs_zcode_dht_delegation observer_delegation;
  uint8_t signature[64];
};

#define VCS_SPACE_SCOUT_VISIT_WIRE_BYTES \
  (32u + 32u + 1u + 1u + 1u + VCS_SPACE_SERVICE_MAX * 32u)
#define VCS_SPACE_SCOUT_PORTAL_WIRE_BYTES (32u + 32u + 1u)
#define VCS_SPACE_SCOUT_FAILURE_WIRE_BYTES (32u + 1u)
#define VCS_SPACE_SCOUT_MAP_WIRE_BYTES \
  (8u + 2u + 32u + 8u + 4u + 1u + 1u + 2u + 1u + 1u + \
   VCS_SPACE_SCOUT_SPACES_MAX * VCS_SPACE_SCOUT_VISIT_WIRE_BYTES + \
   VCS_SPACE_SCOUT_PORTALS_MAX * VCS_SPACE_SCOUT_PORTAL_WIRE_BYTES + \
   VCS_SPACE_SCOUT_SPACES_MAX * VCS_SPACE_SCOUT_FAILURE_WIRE_BYTES)
#define VCS_SPACE_SCOUT_ATTESTATION_WIRE_BYTES \
  (8u + 2u + 32u + 32u + 8u + VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES + 64u)

enum vcs_space_scout_result {
  VCS_SPACE_SCOUT_OK = 0,
  VCS_SPACE_SCOUT_ERR_NULL,
  VCS_SPACE_SCOUT_ERR_SHAPE,
  VCS_SPACE_SCOUT_ERR_ORDER,
  VCS_SPACE_SCOUT_ERR_SIZE,
  VCS_SPACE_SCOUT_ERR_SIGNATURE,
  VCS_SPACE_SCOUT_ERR_DELEGATION,
  VCS_SPACE_SCOUT_ERR_CALLBACK,
};

const char *vcs_space_scout_result_string(enum vcs_space_scout_result result);
const char *vcs_space_scout_manifest_result_string(uint8_t result);
const char *vcs_space_scout_portal_result_string(uint8_t result);
const char *vcs_space_scout_truncation_string(uint8_t result);

enum vcs_space_scout_result vcs_space_scout_mission_validate(
    const struct vcs_space_scout_mission_v1 *mission);
enum vcs_space_scout_result vcs_space_scout_mission_encode(
    const struct vcs_space_scout_mission_v1 *mission,
    uint8_t out[VCS_SPACE_SCOUT_MISSION_WIRE_BYTES]);
enum vcs_space_scout_result vcs_space_scout_mission_decode(
    struct vcs_space_scout_mission_v1 *out, const uint8_t *wire,
    size_t wire_len);
enum vcs_space_scout_result vcs_space_scout_mission_root(
    const struct vcs_space_scout_mission_v1 *mission, uint8_t out[32]);

enum vcs_space_scout_result vcs_space_scout_map_validate(
    const struct vcs_space_scout_map_v1 *map);
enum vcs_space_scout_result vcs_space_scout_map_validate_for_mission(
    const struct vcs_space_scout_map_v1 *map,
    const struct vcs_space_scout_mission_v1 *mission);
enum vcs_space_scout_result vcs_space_scout_map_encode(
    const struct vcs_space_scout_map_v1 *map,
    uint8_t out[VCS_SPACE_SCOUT_MAP_WIRE_BYTES]);
enum vcs_space_scout_result vcs_space_scout_map_decode(
    struct vcs_space_scout_map_v1 *out, const uint8_t *wire,
    size_t wire_len);
enum vcs_space_scout_result vcs_space_scout_map_root(
    const struct vcs_space_scout_map_v1 *map, uint8_t out[32]);

enum vcs_space_scout_result vcs_space_scout_attestation_validate(
    const struct vcs_space_scout_attestation_v1 *attestation);
enum vcs_space_scout_result vcs_space_scout_attestation_sign(
    struct vcs_space_scout_attestation_v1 *attestation,
    const uint8_t online_seed[32]);
enum vcs_space_scout_result vcs_space_scout_attestation_encode(
    const struct vcs_space_scout_attestation_v1 *attestation,
    uint8_t out[VCS_SPACE_SCOUT_ATTESTATION_WIRE_BYTES]);
enum vcs_space_scout_result vcs_space_scout_attestation_decode(
    struct vcs_space_scout_attestation_v1 *out, const uint8_t *wire,
    size_t wire_len);
enum vcs_space_scout_result vcs_space_scout_attestation_root(
    const struct vcs_space_scout_attestation_v1 *attestation,
    uint8_t out[32]);

typedef enum vcs_space_scout_manifest_result (*vcs_space_scout_observe_fn)(
    void *context, const uint8_t root[32], size_t maximum_wire_bytes,
    struct vcs_space_manifest_v1 *manifest_out, size_t *wire_bytes_out);
typedef uint64_t (*vcs_space_scout_monotonic_ms_fn)(void *context);

struct vcs_space_scout_run_context {
  vcs_space_scout_observe_fn observe;
  void *observe_context;
  vcs_space_scout_monotonic_ms_fn monotonic_ms;
  void *clock_context;
};

/* Pure bounded BFS. The callback must return VERIFIED only for a manifest whose
 * semantic root, signature, network, validity and chain authority it checked.
 * The engine never invokes service objects, packages or arbitrary verbs. */
enum vcs_space_scout_result vcs_space_scout_run(
    const struct vcs_space_scout_mission_v1 *mission,
    const struct vcs_space_scout_run_context *context,
    struct vcs_space_scout_map_v1 *out);

#endif /* ZCL_VCS_SPACE_SCOUT_H */
