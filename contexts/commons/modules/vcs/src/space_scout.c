/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded deterministic read-only space scout evidence codec/engine. */

#include "vcs/space_scout.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "base/safe_alloc.h"
#include "support/cleanse.h"
#include "vcs/signed_evidence.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t mission_magic[8] =
    {'Z', 'C', 'S', 'C', 'M', 'S', '\r', '\n'};
static const uint8_t map_magic[8] =
    {'Z', 'C', 'S', 'C', 'M', 'P', '\r', '\n'};
static const uint8_t attestation_magic[8] =
    {'Z', 'C', 'S', 'C', 'A', 'T', '\r', '\n'};
static const char mission_domain[] = "zcl.space_scout.mission.v1";
static const char map_domain[] = "zcl.space_scout.evidence_map.v1";
static const char attestation_domain[] =
    "zcl.space_scout.evidence_attestation.v1";
static const char attestation_signature_domain[] =
    "zcl.space_scout.evidence_attestation.signature.v1";

static bool roots_ordered(const uint8_t roots[][32], size_t count,
                          size_t capacity)
{
  if (count > capacity)
    return false;
  for (size_t i = 0; i < count; i++)
    if (!zcl_bytes_any_set(roots[i], 32) ||
        (i && memcmp(roots[i - 1], roots[i], 32) >= 0))
      return false;
  return zcl_bytes_all_zero((const uint8_t *)(roots + count),
                            (capacity - count) * 32u);
}

const char *vcs_space_scout_result_string(enum vcs_space_scout_result result)
{
  switch (result) {
  case VCS_SPACE_SCOUT_OK: return "ok";
  case VCS_SPACE_SCOUT_ERR_NULL: return "null-argument";
  case VCS_SPACE_SCOUT_ERR_SHAPE: return "shape";
  case VCS_SPACE_SCOUT_ERR_ORDER: return "order";
  case VCS_SPACE_SCOUT_ERR_SIZE: return "size";
  case VCS_SPACE_SCOUT_ERR_SIGNATURE: return "signature";
  case VCS_SPACE_SCOUT_ERR_DELEGATION: return "delegation";
  case VCS_SPACE_SCOUT_ERR_CALLBACK: return "callback";
  }
  return "unknown";
}

const char *vcs_space_scout_manifest_result_string(uint8_t result)
{
  static const char *const names[] = {
      "unknown", "verified", "policy_denied", "not_found",
      "fetch_scheduled", "invalid", "expired", "chain_denied",
      "byte_limit", "deadline"};
  return result < sizeof(names) / sizeof(names[0]) ? names[result]
                                                   : "unknown";
}

const char *vcs_space_scout_portal_result_string(uint8_t result)
{
  static const char *const names[] = {
      "unknown", "followed", "cycle", "depth_limit", "space_limit",
      "truncated"};
  return result < sizeof(names) / sizeof(names[0]) ? names[result]
                                                   : "unknown";
}

const char *vcs_space_scout_truncation_string(uint8_t result)
{
  static const char *const names[] = {
      "none", "maximum_depth", "maximum_spaces", "maximum_portals",
      "maximum_bytes", "deadline"};
  return result < sizeof(names) / sizeof(names[0]) ? names[result]
                                                   : "unknown";
}

enum vcs_space_scout_result vcs_space_scout_mission_validate(
    const struct vcs_space_scout_mission_v1 *mission)
{
  if (!mission)
    return VCS_SPACE_SCOUT_ERR_NULL;
  if (mission->schema_version != VCS_SPACE_SCOUT_MISSION_VERSION ||
      !zcl_bytes_any_set(mission->network_genesis, 32) || !mission->observation_unix ||
      !mission->start_count ||
      mission->start_count > VCS_SPACE_SCOUT_START_MAX ||
      mission->maximum_depth > VCS_SPACE_SCOUT_DEPTH_MAX ||
      mission->maximum_spaces < mission->start_count ||
      mission->maximum_spaces > VCS_SPACE_SCOUT_SPACES_MAX ||
      !mission->maximum_portals ||
      mission->maximum_portals > VCS_SPACE_SCOUT_PORTALS_MAX ||
      !mission->maximum_bytes ||
      mission->maximum_bytes > VCS_SPACE_SCOUT_BYTES_MAX ||
      !mission->deadline_ms ||
      mission->deadline_ms > VCS_SPACE_SCOUT_DEADLINE_MS_MAX)
    return VCS_SPACE_SCOUT_ERR_SHAPE;
  return roots_ordered(mission->starting_roots, mission->start_count,
                       VCS_SPACE_SCOUT_START_MAX)
             ? VCS_SPACE_SCOUT_OK : VCS_SPACE_SCOUT_ERR_ORDER;
}

enum vcs_space_scout_result vcs_space_scout_mission_encode(
    const struct vcs_space_scout_mission_v1 *mission,
    uint8_t out[VCS_SPACE_SCOUT_MISSION_WIRE_BYTES])
{
  if (!out)
    return VCS_SPACE_SCOUT_ERR_NULL;
  enum vcs_space_scout_result checked =
      vcs_space_scout_mission_validate(mission);
  if (checked != VCS_SPACE_SCOUT_OK)
    return checked;
  size_t off = 0;
  memcpy(out + off, mission_magic, 8); off += 8;
  zcl_write_u16_le(out + off, mission->schema_version); off += 2;
  memcpy(out + off, mission->network_genesis, 32); off += 32;
  zcl_write_u64_le(out + off, mission->observation_unix); off += 8;
  out[off++] = mission->start_count;
  out[off++] = mission->maximum_depth;
  out[off++] = mission->maximum_spaces;
  zcl_write_u16_le(out + off, mission->maximum_portals); off += 2;
  zcl_write_u32_le(out + off, mission->maximum_bytes); off += 4;
  zcl_write_u32_le(out + off, mission->deadline_ms); off += 4;
  memcpy(out + off, mission->starting_roots,
         VCS_SPACE_SCOUT_START_MAX * 32u);
  return off + VCS_SPACE_SCOUT_START_MAX * 32u ==
                 VCS_SPACE_SCOUT_MISSION_WIRE_BYTES
             ? VCS_SPACE_SCOUT_OK : VCS_SPACE_SCOUT_ERR_SIZE;
}

enum vcs_space_scout_result vcs_space_scout_mission_decode(
    struct vcs_space_scout_mission_v1 *out, const uint8_t *wire,
    size_t wire_len)
{
  if (!out || !wire)
    return VCS_SPACE_SCOUT_ERR_NULL;
  memset(out, 0, sizeof(*out));
  if (wire_len != VCS_SPACE_SCOUT_MISSION_WIRE_BYTES ||
      memcmp(wire, mission_magic, 8) != 0)
    return VCS_SPACE_SCOUT_ERR_SIZE;
  size_t off = 8;
  out->schema_version = zcl_read_u16_le(wire + off); off += 2;
  memcpy(out->network_genesis, wire + off, 32); off += 32;
  out->observation_unix = zcl_read_u64_le(wire + off); off += 8;
  out->start_count = wire[off++];
  out->maximum_depth = wire[off++];
  out->maximum_spaces = wire[off++];
  out->maximum_portals = zcl_read_u16_le(wire + off); off += 2;
  out->maximum_bytes = zcl_read_u32_le(wire + off); off += 4;
  out->deadline_ms = zcl_read_u32_le(wire + off); off += 4;
  memcpy(out->starting_roots, wire + off,
         VCS_SPACE_SCOUT_START_MAX * 32u);
  enum vcs_space_scout_result checked = vcs_space_scout_mission_validate(out);
  if (checked != VCS_SPACE_SCOUT_OK)
    memset(out, 0, sizeof(*out));
  return checked;
}

enum vcs_space_scout_result vcs_space_scout_mission_root(
    const struct vcs_space_scout_mission_v1 *mission, uint8_t out[32])
{
  uint8_t wire[VCS_SPACE_SCOUT_MISSION_WIRE_BYTES];
  if (!out)
    return VCS_SPACE_SCOUT_ERR_NULL;
  enum vcs_space_scout_result encoded =
      vcs_space_scout_mission_encode(mission, wire);
  if (encoded == VCS_SPACE_SCOUT_OK &&
      !vcs_signed_evidence_root(mission_domain, strlen(mission_domain), wire,
                                sizeof(wire), out))
    return VCS_SPACE_SCOUT_ERR_NULL;
  return encoded;
}

static int visit_compare(const void *left, const void *right)
{
  const struct vcs_space_scout_visit_v1 *a = left, *b = right;
  return memcmp(a->space_root, b->space_root, 32);
}

static int portal_compare(const void *left, const void *right)
{
  const struct vcs_space_scout_portal_v1 *a = left, *b = right;
  int compared = memcmp(a->from_root, b->from_root, 32);
  if (compared != 0)
    return compared;
  compared = memcmp(a->to_root, b->to_root, 32);
  return compared != 0 ? compared : (int)a->result - (int)b->result;
}

static int failure_compare(const void *left, const void *right)
{
  const struct vcs_space_scout_failure_v1 *a = left, *b = right;
  int compared = memcmp(a->space_root, b->space_root, 32);
  return compared != 0 ? compared : (int)a->result - (int)b->result;
}

static bool result_valid(uint8_t result)
{
  return result >= VCS_SPACE_SCOUT_MANIFEST_VERIFIED &&
         result <= VCS_SPACE_SCOUT_MANIFEST_DEADLINE;
}

static enum vcs_space_scout_result map_shape(
    const struct vcs_space_scout_map_v1 *map)
{
  if (!map)
    return VCS_SPACE_SCOUT_ERR_NULL;
  if (map->schema_version != VCS_SPACE_SCOUT_MAP_VERSION ||
      !zcl_bytes_any_set(map->mission_root, 32) || !map->observation_unix ||
      map->bytes_observed > VCS_SPACE_SCOUT_BYTES_MAX ||
      map->visit_count > VCS_SPACE_SCOUT_SPACES_MAX ||
      map->portal_count > VCS_SPACE_SCOUT_PORTALS_MAX ||
      map->failure_count > VCS_SPACE_SCOUT_SPACES_MAX ||
      map->policy_denial_count > map->failure_count ||
      map->truncation > VCS_SPACE_SCOUT_TRUNCATION_DEADLINE)
    return VCS_SPACE_SCOUT_ERR_SHAPE;
  for (size_t i = 0; i < map->visit_count; i++) {
    const struct vcs_space_scout_visit_v1 *visit = &map->visits[i];
    if (!zcl_bytes_any_set(visit->space_root, 32) || !result_valid(visit->manifest_result) ||
        visit->depth > VCS_SPACE_SCOUT_DEPTH_MAX ||
        visit->service_count > VCS_SPACE_SERVICE_MAX ||
        (i && memcmp(map->visits[i - 1].space_root,
                     visit->space_root, 32) >= 0) ||
        !roots_ordered(visit->service_roots, visit->service_count,
                       VCS_SPACE_SERVICE_MAX) ||
        (visit->manifest_result == VCS_SPACE_SCOUT_MANIFEST_VERIFIED) !=
            zcl_bytes_any_set(visit->owner_zid, 32) ||
        (visit->manifest_result != VCS_SPACE_SCOUT_MANIFEST_VERIFIED &&
         visit->service_count != 0))
      return VCS_SPACE_SCOUT_ERR_ORDER;
  }
  if (!zcl_bytes_all_zero((const uint8_t *)(map->visits + map->visit_count),
                          (VCS_SPACE_SCOUT_SPACES_MAX - map->visit_count) *
                              sizeof(map->visits[0])) ||
      !zcl_bytes_all_zero((const uint8_t *)(map->portals + map->portal_count),
                          (VCS_SPACE_SCOUT_PORTALS_MAX - map->portal_count) *
                              sizeof(map->portals[0])) ||
      !zcl_bytes_all_zero((const uint8_t *)(map->failures + map->failure_count),
                          (VCS_SPACE_SCOUT_SPACES_MAX - map->failure_count) *
                              sizeof(map->failures[0])))
    return VCS_SPACE_SCOUT_ERR_ORDER;
  for (size_t i = 0; i < map->portal_count; i++) {
    bool source_verified = false;
    for (size_t j = 0; j < map->visit_count; j++)
      if (memcmp(map->portals[i].from_root,
                 map->visits[j].space_root, 32) == 0 &&
          map->visits[j].manifest_result ==
              VCS_SPACE_SCOUT_MANIFEST_VERIFIED)
        source_verified = true;
    if (!source_verified || !zcl_bytes_any_set(map->portals[i].from_root, 32) ||
        !zcl_bytes_any_set(map->portals[i].to_root, 32) ||
        map->portals[i].result < VCS_SPACE_SCOUT_PORTAL_FOLLOWED ||
        map->portals[i].result > VCS_SPACE_SCOUT_PORTAL_TRUNCATED ||
        (i && memcmp(map->portals[i - 1].from_root,
                     map->portals[i].from_root, 32) == 0 &&
         memcmp(map->portals[i - 1].to_root,
                map->portals[i].to_root, 32) == 0) ||
        (i && portal_compare(&map->portals[i - 1], &map->portals[i]) >= 0))
      return VCS_SPACE_SCOUT_ERR_ORDER;
  }
  uint8_t denials = 0;
  for (size_t i = 0; i < map->failure_count; i++) {
    if (!zcl_bytes_any_set(map->failures[i].space_root, 32) ||
        !result_valid(map->failures[i].result) ||
        map->failures[i].result == VCS_SPACE_SCOUT_MANIFEST_VERIFIED ||
        (i && failure_compare(&map->failures[i - 1],
                              &map->failures[i]) >= 0))
      return VCS_SPACE_SCOUT_ERR_ORDER;
    denials += map->failures[i].result ==
               VCS_SPACE_SCOUT_MANIFEST_POLICY_DENIED;
  }
  if (denials != map->policy_denial_count)
    return VCS_SPACE_SCOUT_ERR_SHAPE;
  size_t failure_index = 0;
  for (size_t i = 0; i < map->visit_count; i++) {
    if (map->visits[i].manifest_result ==
        VCS_SPACE_SCOUT_MANIFEST_VERIFIED)
      continue;
    if (failure_index >= map->failure_count ||
        memcmp(map->visits[i].space_root,
               map->failures[failure_index].space_root, 32) != 0 ||
        map->visits[i].manifest_result != map->failures[failure_index].result)
      return VCS_SPACE_SCOUT_ERR_SHAPE;
    failure_index++;
  }
  if (failure_index != map->failure_count)
    return VCS_SPACE_SCOUT_ERR_SHAPE;
  return VCS_SPACE_SCOUT_OK;
}

static size_t map_write_unsigned(const struct vcs_space_scout_map_v1 *map,
                                 uint8_t *wire)
{
  size_t off = 0;
  memcpy(wire + off, map_magic, 8); off += 8;
  zcl_write_u16_le(wire + off, map->schema_version); off += 2;
  memcpy(wire + off, map->mission_root, 32); off += 32;
  zcl_write_u64_le(wire + off, map->observation_unix); off += 8;
  zcl_write_u32_le(wire + off, map->bytes_observed); off += 4;
  wire[off++] = map->truncation;
  wire[off++] = map->visit_count;
  zcl_write_u16_le(wire + off, map->portal_count); off += 2;
  wire[off++] = map->failure_count;
  wire[off++] = map->policy_denial_count;
  for (size_t i = 0; i < VCS_SPACE_SCOUT_SPACES_MAX; i++) {
    const struct vcs_space_scout_visit_v1 *visit = &map->visits[i];
    memcpy(wire + off, visit->space_root, 32); off += 32;
    memcpy(wire + off, visit->owner_zid, 32); off += 32;
    wire[off++] = visit->depth;
    wire[off++] = visit->manifest_result;
    wire[off++] = visit->service_count;
    memcpy(wire + off, visit->service_roots,
           VCS_SPACE_SERVICE_MAX * 32u);
    off += VCS_SPACE_SERVICE_MAX * 32u;
  }
  for (size_t i = 0; i < VCS_SPACE_SCOUT_PORTALS_MAX; i++) {
    memcpy(wire + off, map->portals[i].from_root, 32); off += 32;
    memcpy(wire + off, map->portals[i].to_root, 32); off += 32;
    wire[off++] = map->portals[i].result;
  }
  for (size_t i = 0; i < VCS_SPACE_SCOUT_SPACES_MAX; i++) {
    memcpy(wire + off, map->failures[i].space_root, 32); off += 32;
    wire[off++] = map->failures[i].result;
  }
  return off;
}

enum vcs_space_scout_result vcs_space_scout_map_validate(
    const struct vcs_space_scout_map_v1 *map)
{
  return map_shape(map);
}

static const struct vcs_space_scout_visit_v1 *map_visit_find(
    const struct vcs_space_scout_map_v1 *map, const uint8_t root[32])
{
  for (size_t i = 0; map && i < map->visit_count; i++)
    if (memcmp(map->visits[i].space_root, root, 32) == 0)
      return &map->visits[i];
  return NULL;
}

enum vcs_space_scout_result vcs_space_scout_map_validate_for_mission(
    const struct vcs_space_scout_map_v1 *map,
    const struct vcs_space_scout_mission_v1 *mission)
{
  uint8_t mission_root[32];
  if (vcs_space_scout_map_validate(map) != VCS_SPACE_SCOUT_OK ||
      vcs_space_scout_mission_validate(mission) != VCS_SPACE_SCOUT_OK ||
      vcs_space_scout_mission_root(mission, mission_root) !=
          VCS_SPACE_SCOUT_OK)
    return VCS_SPACE_SCOUT_ERR_SHAPE;
  if (memcmp(map->mission_root, mission_root, 32) != 0 ||
      map->observation_unix != mission->observation_unix ||
      map->visit_count > mission->maximum_spaces ||
      map->portal_count > mission->maximum_portals ||
      map->bytes_observed > mission->maximum_bytes)
    return VCS_SPACE_SCOUT_ERR_SHAPE;
  for (size_t i = 0; i < map->visit_count; i++)
    if (map->visits[i].depth > mission->maximum_depth)
      return VCS_SPACE_SCOUT_ERR_SHAPE;
  bool early_stop = map->truncation == VCS_SPACE_SCOUT_TRUNCATION_BYTES ||
                    map->truncation == VCS_SPACE_SCOUT_TRUNCATION_PORTALS ||
                    map->truncation == VCS_SPACE_SCOUT_TRUNCATION_DEADLINE;
  for (size_t i = 0; i < mission->start_count; i++)
    if (!map_visit_find(map, mission->starting_roots[i]) && !early_stop)
      return VCS_SPACE_SCOUT_ERR_SHAPE;
  for (size_t i = 0; i < map->portal_count; i++) {
    const struct vcs_space_scout_portal_v1 *edge = &map->portals[i];
    const struct vcs_space_scout_visit_v1 *source =
        map_visit_find(map, edge->from_root);
    const struct vcs_space_scout_visit_v1 *target =
        map_visit_find(map, edge->to_root);
    if (!source)
      return VCS_SPACE_SCOUT_ERR_SHAPE;
    if (edge->result == VCS_SPACE_SCOUT_PORTAL_FOLLOWED &&
        (!target || target->depth != (uint8_t)(source->depth + 1u) ||
         source->depth >= mission->maximum_depth))
      return VCS_SPACE_SCOUT_ERR_SHAPE;
    if (edge->result == VCS_SPACE_SCOUT_PORTAL_CYCLE && !target)
      return VCS_SPACE_SCOUT_ERR_SHAPE;
    if (edge->result == VCS_SPACE_SCOUT_PORTAL_DEPTH_LIMIT &&
        source->depth < mission->maximum_depth)
      return VCS_SPACE_SCOUT_ERR_SHAPE;
    if (edge->result == VCS_SPACE_SCOUT_PORTAL_SPACE_LIMIT &&
        (source->depth >= mission->maximum_depth || target))
      return VCS_SPACE_SCOUT_ERR_SHAPE;
    if (edge->result == VCS_SPACE_SCOUT_PORTAL_TRUNCATED &&
        (!early_stop || target))
      return VCS_SPACE_SCOUT_ERR_SHAPE;
  }
  return VCS_SPACE_SCOUT_OK;
}

enum vcs_space_scout_result vcs_space_scout_map_encode(
    const struct vcs_space_scout_map_v1 *map,
    uint8_t out[VCS_SPACE_SCOUT_MAP_WIRE_BYTES])
{
  if (!out)
    return VCS_SPACE_SCOUT_ERR_NULL;
  enum vcs_space_scout_result checked = vcs_space_scout_map_validate(map);
  if (checked != VCS_SPACE_SCOUT_OK)
    return checked;
  size_t unsigned_len = map_write_unsigned(map, out);
  if (!unsigned_len || unsigned_len != VCS_SPACE_SCOUT_MAP_WIRE_BYTES)
    return VCS_SPACE_SCOUT_ERR_SIZE;
  return VCS_SPACE_SCOUT_OK;
}

enum vcs_space_scout_result vcs_space_scout_map_decode(
    struct vcs_space_scout_map_v1 *out, const uint8_t *wire,
    size_t wire_len)
{
  if (!out || !wire)
    return VCS_SPACE_SCOUT_ERR_NULL;
  memset(out, 0, sizeof(*out));
  if (wire_len != VCS_SPACE_SCOUT_MAP_WIRE_BYTES ||
      memcmp(wire, map_magic, 8) != 0)
    return VCS_SPACE_SCOUT_ERR_SIZE;
  size_t off = 8;
  out->schema_version = zcl_read_u16_le(wire + off); off += 2;
  memcpy(out->mission_root, wire + off, 32); off += 32;
  out->observation_unix = zcl_read_u64_le(wire + off); off += 8;
  out->bytes_observed = zcl_read_u32_le(wire + off); off += 4;
  out->truncation = wire[off++];
  out->visit_count = wire[off++];
  out->portal_count = zcl_read_u16_le(wire + off); off += 2;
  out->failure_count = wire[off++];
  out->policy_denial_count = wire[off++];
  for (size_t i = 0; i < VCS_SPACE_SCOUT_SPACES_MAX; i++) {
    memcpy(out->visits[i].space_root, wire + off, 32); off += 32;
    memcpy(out->visits[i].owner_zid, wire + off, 32); off += 32;
    out->visits[i].depth = wire[off++];
    out->visits[i].manifest_result = wire[off++];
    out->visits[i].service_count = wire[off++];
    memcpy(out->visits[i].service_roots, wire + off,
           VCS_SPACE_SERVICE_MAX * 32u);
    off += VCS_SPACE_SERVICE_MAX * 32u;
  }
  for (size_t i = 0; i < VCS_SPACE_SCOUT_PORTALS_MAX; i++) {
    memcpy(out->portals[i].from_root, wire + off, 32); off += 32;
    memcpy(out->portals[i].to_root, wire + off, 32); off += 32;
    out->portals[i].result = wire[off++];
  }
  for (size_t i = 0; i < VCS_SPACE_SCOUT_SPACES_MAX; i++) {
    memcpy(out->failures[i].space_root, wire + off, 32); off += 32;
    out->failures[i].result = wire[off++];
  }
  if (off != wire_len) {
    memset(out, 0, sizeof(*out));
    return VCS_SPACE_SCOUT_ERR_SIZE;
  }
  enum vcs_space_scout_result checked = vcs_space_scout_map_validate(out);
  if (checked != VCS_SPACE_SCOUT_OK)
    memset(out, 0, sizeof(*out));
  return checked;
}

enum vcs_space_scout_result vcs_space_scout_map_root(
    const struct vcs_space_scout_map_v1 *map, uint8_t out[32])
{
  if (!out)
    return VCS_SPACE_SCOUT_ERR_NULL;
  uint8_t *wire = zcl_malloc(VCS_SPACE_SCOUT_MAP_WIRE_BYTES,
                             "space_scout_root_wire");
  if (!wire)
    return VCS_SPACE_SCOUT_ERR_SIZE;
  enum vcs_space_scout_result encoded = vcs_space_scout_map_encode(map, wire);
  if (encoded == VCS_SPACE_SCOUT_OK &&
      !vcs_signed_evidence_root(map_domain, strlen(map_domain), wire,
                                VCS_SPACE_SCOUT_MAP_WIRE_BYTES, out))
    encoded = VCS_SPACE_SCOUT_ERR_NULL;
  free(wire);
  return encoded;
}

static enum vcs_space_scout_result attestation_shape(
    const struct vcs_space_scout_attestation_v1 *attestation,
    bool require_signature)
{
  if (!attestation)
    return VCS_SPACE_SCOUT_ERR_NULL;
  if (attestation->schema_version != VCS_SPACE_SCOUT_ATTESTATION_VERSION ||
      !zcl_bytes_any_set(attestation->mission_root, 32) ||
      !zcl_bytes_any_set(attestation->evidence_map_root, 32) ||
      !attestation->observation_unix)
    return VCS_SPACE_SCOUT_ERR_SHAPE;
  if (vcs_zcode_dht_delegation_verify(
          &attestation->observer_delegation, NULL, NULL, 0, NULL,
          attestation->observation_unix) != VCS_ZCODE_DHT_DELEGATION_OK)
    return VCS_SPACE_SCOUT_ERR_DELEGATION;
  if (require_signature && zcl_bytes_all_zero((const uint8_t *)attestation->signature, 64))
    return VCS_SPACE_SCOUT_ERR_SIGNATURE;
  return VCS_SPACE_SCOUT_OK;
}

static size_t attestation_write_unsigned(
    const struct vcs_space_scout_attestation_v1 *attestation, uint8_t *wire)
{
  uint8_t delegation[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES];
  if (vcs_zcode_dht_delegation_encode(&attestation->observer_delegation,
                                      delegation) !=
      VCS_ZCODE_DHT_DELEGATION_OK)
    return 0;
  size_t off = 0;
  memcpy(wire + off, attestation_magic, 8); off += 8;
  zcl_write_u16_le(wire + off, attestation->schema_version); off += 2;
  memcpy(wire + off, attestation->mission_root, 32); off += 32;
  memcpy(wire + off, attestation->evidence_map_root, 32); off += 32;
  zcl_write_u64_le(wire + off, attestation->observation_unix); off += 8;
  memcpy(wire + off, delegation, sizeof(delegation)); off += sizeof(delegation);
  return off;
}

static bool attestation_signature_valid(
    const struct vcs_space_scout_attestation_v1 *attestation)
{
  uint8_t wire[VCS_SPACE_SCOUT_ATTESTATION_WIRE_BYTES] = {0};
  uint8_t preimage[sizeof(attestation_signature_domain) - 1u +
                   VCS_SPACE_SCOUT_ATTESTATION_WIRE_BYTES] = {0};
  size_t unsigned_len = attestation_write_unsigned(attestation, wire);
  size_t domain_len = sizeof(attestation_signature_domain) - 1u;
  memcpy(preimage, attestation_signature_domain, domain_len);
  memcpy(preimage + domain_len, wire, unsigned_len);
  bool valid = unsigned_len && ed25519_verify(
      attestation->signature, preimage, domain_len + unsigned_len,
      attestation->observer_delegation.online_pubkey);
  memory_cleanse(preimage, sizeof(preimage));
  return valid;
}

enum vcs_space_scout_result vcs_space_scout_attestation_validate(
    const struct vcs_space_scout_attestation_v1 *attestation)
{
  enum vcs_space_scout_result checked = attestation_shape(attestation, true);
  if (checked != VCS_SPACE_SCOUT_OK)
    return checked;
  return attestation_signature_valid(attestation)
             ? VCS_SPACE_SCOUT_OK : VCS_SPACE_SCOUT_ERR_SIGNATURE;
}

enum vcs_space_scout_result vcs_space_scout_attestation_sign(
    struct vcs_space_scout_attestation_v1 *attestation,
    const uint8_t online_seed[32])
{
  if (!attestation || !online_seed)
    return VCS_SPACE_SCOUT_ERR_NULL;
  enum vcs_space_scout_result checked = attestation_shape(attestation, false);
  if (checked != VCS_SPACE_SCOUT_OK)
    return checked;
  uint8_t pubkey[32], secret[32];
  ed25519_keypair(pubkey, secret, online_seed);
  if (memcmp(pubkey, attestation->observer_delegation.online_pubkey, 32) != 0) {
    memory_cleanse(secret, sizeof(secret));
    return VCS_SPACE_SCOUT_ERR_DELEGATION;
  }
  uint8_t wire[VCS_SPACE_SCOUT_ATTESTATION_WIRE_BYTES] = {0};
  uint8_t preimage[sizeof(attestation_signature_domain) - 1u +
                   VCS_SPACE_SCOUT_ATTESTATION_WIRE_BYTES] = {0};
  size_t unsigned_len = attestation_write_unsigned(attestation, wire);
  if (!unsigned_len) {
    memory_cleanse(secret, sizeof(secret));
    return VCS_SPACE_SCOUT_ERR_SIZE;
  }
  size_t domain_len = sizeof(attestation_signature_domain) - 1u;
  memcpy(preimage, attestation_signature_domain, domain_len);
  memcpy(preimage + domain_len, wire, unsigned_len);
  ed25519_sign(attestation->signature, preimage, domain_len + unsigned_len,
               secret, pubkey);
  memory_cleanse(secret, sizeof(secret));
  memory_cleanse(preimage, sizeof(preimage));
  return vcs_space_scout_attestation_validate(attestation);
}

enum vcs_space_scout_result vcs_space_scout_attestation_encode(
    const struct vcs_space_scout_attestation_v1 *attestation,
    uint8_t out[VCS_SPACE_SCOUT_ATTESTATION_WIRE_BYTES])
{
  if (!out)
    return VCS_SPACE_SCOUT_ERR_NULL;
  enum vcs_space_scout_result checked =
      vcs_space_scout_attestation_validate(attestation);
  if (checked != VCS_SPACE_SCOUT_OK)
    return checked;
  size_t unsigned_len = attestation_write_unsigned(attestation, out);
  if (!unsigned_len || unsigned_len + 64u !=
                           VCS_SPACE_SCOUT_ATTESTATION_WIRE_BYTES)
    return VCS_SPACE_SCOUT_ERR_SIZE;
  memcpy(out + unsigned_len, attestation->signature, 64);
  return VCS_SPACE_SCOUT_OK;
}

enum vcs_space_scout_result vcs_space_scout_attestation_decode(
    struct vcs_space_scout_attestation_v1 *out, const uint8_t *wire,
    size_t wire_len)
{
  if (!out || !wire)
    return VCS_SPACE_SCOUT_ERR_NULL;
  memset(out, 0, sizeof(*out));
  if (wire_len != VCS_SPACE_SCOUT_ATTESTATION_WIRE_BYTES ||
      memcmp(wire, attestation_magic, 8) != 0)
    return VCS_SPACE_SCOUT_ERR_SIZE;
  size_t off = 8;
  out->schema_version = zcl_read_u16_le(wire + off); off += 2;
  memcpy(out->mission_root, wire + off, 32); off += 32;
  memcpy(out->evidence_map_root, wire + off, 32); off += 32;
  out->observation_unix = zcl_read_u64_le(wire + off); off += 8;
  if (vcs_zcode_dht_delegation_decode(
          &out->observer_delegation, wire + off,
          VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES) !=
      VCS_ZCODE_DHT_DELEGATION_OK) {
    memset(out, 0, sizeof(*out));
    return VCS_SPACE_SCOUT_ERR_DELEGATION;
  }
  off += VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES;
  if (off + 64u != wire_len) {
    memset(out, 0, sizeof(*out));
    return VCS_SPACE_SCOUT_ERR_SIZE;
  }
  memcpy(out->signature, wire + off, 64);
  enum vcs_space_scout_result checked =
      vcs_space_scout_attestation_validate(out);
  if (checked != VCS_SPACE_SCOUT_OK)
    memset(out, 0, sizeof(*out));
  return checked;
}

enum vcs_space_scout_result vcs_space_scout_attestation_root(
    const struct vcs_space_scout_attestation_v1 *attestation,
    uint8_t out[32])
{
  uint8_t wire[VCS_SPACE_SCOUT_ATTESTATION_WIRE_BYTES];
  if (!out)
    return VCS_SPACE_SCOUT_ERR_NULL;
  enum vcs_space_scout_result encoded =
      vcs_space_scout_attestation_encode(attestation, wire);
  if (encoded == VCS_SPACE_SCOUT_OK &&
      !vcs_signed_evidence_root(attestation_domain,
                                strlen(attestation_domain), wire,
                                sizeof(wire), out))
    return VCS_SPACE_SCOUT_ERR_NULL;
  return encoded;
}

static bool root_seen(const uint8_t roots[][32], size_t count,
                      const uint8_t root[32])
{
  for (size_t i = 0; i < count; i++)
    if (memcmp(roots[i], root, 32) == 0)
      return true;
  return false;
}

enum vcs_space_scout_result vcs_space_scout_run(
    const struct vcs_space_scout_mission_v1 *mission,
    const struct vcs_space_scout_run_context *context,
    struct vcs_space_scout_map_v1 *out)
{
  if (!context || !context->observe || !context->monotonic_ms || !out)
    return VCS_SPACE_SCOUT_ERR_NULL;
  enum vcs_space_scout_result checked =
      vcs_space_scout_mission_validate(mission);
  if (checked != VCS_SPACE_SCOUT_OK)
    return checked;
  memset(out, 0, sizeof(*out));
  out->schema_version = VCS_SPACE_SCOUT_MAP_VERSION;
  out->observation_unix = mission->observation_unix;
  if (vcs_space_scout_mission_root(mission, out->mission_root) !=
      VCS_SPACE_SCOUT_OK)
    return VCS_SPACE_SCOUT_ERR_SHAPE;
  uint8_t queue[VCS_SPACE_SCOUT_SPACES_MAX][32] = {{0}};
  uint8_t depths[VCS_SPACE_SCOUT_SPACES_MAX] = {0};
  size_t head = 0, queued = mission->start_count;
  memcpy(queue, mission->starting_roots, mission->start_count * 32u);
  uint64_t start_ms = context->monotonic_ms(context->clock_context);
  uint64_t deadline = start_ms + mission->deadline_ms;
  if (deadline < start_ms)
    deadline = UINT64_MAX;
  while (head < queued) {
    if (context->monotonic_ms(context->clock_context) >= deadline) {
      out->truncation = VCS_SPACE_SCOUT_TRUNCATION_DEADLINE;
      break;
    }
    struct vcs_space_scout_visit_v1 *visit =
        &out->visits[out->visit_count++];
    memcpy(visit->space_root, queue[head], 32);
    visit->depth = depths[head];
    struct vcs_space_manifest_v1 manifest;
    memset(&manifest, 0, sizeof(manifest));
    size_t wire_bytes = 0;
    size_t remaining_bytes =
        mission->maximum_bytes - out->bytes_observed;
    enum vcs_space_scout_manifest_result result = context->observe(
        context->observe_context, queue[head], remaining_bytes,
        &manifest, &wire_bytes);
    bool deadline_after_observe =
        context->monotonic_ms(context->clock_context) >= deadline;
    if (!result_valid((uint8_t)result))
      return VCS_SPACE_SCOUT_ERR_CALLBACK;
    if (deadline_after_observe) {
      result = VCS_SPACE_SCOUT_MANIFEST_DEADLINE;
      wire_bytes = 0;
      out->truncation = VCS_SPACE_SCOUT_TRUNCATION_DEADLINE;
    } else if (result == VCS_SPACE_SCOUT_MANIFEST_DEADLINE) {
      wire_bytes = 0;
      out->truncation = VCS_SPACE_SCOUT_TRUNCATION_DEADLINE;
    } else if (result == VCS_SPACE_SCOUT_MANIFEST_BYTE_LIMIT ||
               wire_bytes > remaining_bytes) {
      result = VCS_SPACE_SCOUT_MANIFEST_BYTE_LIMIT;
      wire_bytes = 0;
      out->truncation = VCS_SPACE_SCOUT_TRUNCATION_BYTES;
    } else if (result == VCS_SPACE_SCOUT_MANIFEST_VERIFIED) {
      out->bytes_observed += (uint32_t)wire_bytes;
    }
    visit->manifest_result = (uint8_t)result;
    if (result == VCS_SPACE_SCOUT_MANIFEST_VERIFIED) {
      memcpy(visit->owner_zid,
             manifest.delegation.doc.master_pubkey, 32);
      visit->service_count = manifest.service_count;
      memcpy(visit->service_roots, manifest.service_roots,
             (size_t)manifest.service_count * 32u);
      for (size_t i = 0; i < manifest.portal_count; i++) {
        if (out->portal_count == mission->maximum_portals) {
          out->truncation = VCS_SPACE_SCOUT_TRUNCATION_PORTALS;
          break;
        }
        struct vcs_space_scout_portal_v1 *edge =
            &out->portals[out->portal_count++];
        memcpy(edge->from_root, queue[head], 32);
        memcpy(edge->to_root, manifest.portal_roots[i], 32);
        if (visit->depth >= mission->maximum_depth) {
          edge->result = VCS_SPACE_SCOUT_PORTAL_DEPTH_LIMIT;
          if (!out->truncation)
            out->truncation = VCS_SPACE_SCOUT_TRUNCATION_DEPTH;
        } else if (root_seen(queue, queued, manifest.portal_roots[i])) {
          edge->result = VCS_SPACE_SCOUT_PORTAL_CYCLE;
        } else if (queued == mission->maximum_spaces) {
          edge->result = VCS_SPACE_SCOUT_PORTAL_SPACE_LIMIT;
          if (!out->truncation)
            out->truncation = VCS_SPACE_SCOUT_TRUNCATION_SPACES;
        } else {
          edge->result = VCS_SPACE_SCOUT_PORTAL_FOLLOWED;
          memcpy(queue[queued], manifest.portal_roots[i], 32);
          depths[queued++] = (uint8_t)(visit->depth + 1u);
        }
      }
    }
    if (result != VCS_SPACE_SCOUT_MANIFEST_VERIFIED) {
      struct vcs_space_scout_failure_v1 *failure =
          &out->failures[out->failure_count++];
      memcpy(failure->space_root, queue[head], 32);
      failure->result = (uint8_t)result;
      out->policy_denial_count +=
          result == VCS_SPACE_SCOUT_MANIFEST_POLICY_DENIED;
    }
    head++;
    if (out->truncation == VCS_SPACE_SCOUT_TRUNCATION_BYTES ||
        out->truncation == VCS_SPACE_SCOUT_TRUNCATION_PORTALS ||
        out->truncation == VCS_SPACE_SCOUT_TRUNCATION_DEADLINE)
      break;
  }
  for (size_t i = 0; i < out->portal_count; i++)
    if ((out->portals[i].result == VCS_SPACE_SCOUT_PORTAL_FOLLOWED ||
         out->portals[i].result == VCS_SPACE_SCOUT_PORTAL_CYCLE) &&
        !map_visit_find(out, out->portals[i].to_root))
      out->portals[i].result = VCS_SPACE_SCOUT_PORTAL_TRUNCATED;
  qsort(out->visits, out->visit_count, sizeof(out->visits[0]), visit_compare);
  qsort(out->portals, out->portal_count, sizeof(out->portals[0]),
        portal_compare);
  qsort(out->failures, out->failure_count, sizeof(out->failures[0]),
        failure_compare);
  return VCS_SPACE_SCOUT_OK;
}
