/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Exact-plan storage service for bounded Space Scout evidence. */

#include "services/metaverse_space_scout_service.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/sha3.h"
#include "vcs/vcs_object.h"

#include <stdlib.h>
#include <string.h>

static const char scout_plan_domain[] = "zcl.metaverse.space.scout.plan.v1";

static bool parse_root(const char *hex, uint8_t out[32])
{
  return hex && strlen(hex) == 64u && zcl_hex_decode_lower(hex, out, 32);
}

static void plan_digest(const uint8_t *wire, size_t wire_len,
                        uint8_t out[32])
{
  struct sha3_256_ctx sha;
  sha3_256_init(&sha);
  sha3_256_write(&sha, (const uint8_t *)scout_plan_domain,
                 sizeof(scout_plan_domain) - 1u);
  sha3_256_write(&sha, wire, wire_len);
  sha3_256_finalize(&sha, out);
}

static bool token_matches(const uint8_t *wire, size_t wire_len,
                          const char *supplied)
{
  uint8_t actual[32], expected[32], difference = 0;
  if (!parse_root(supplied, actual))
    return false; /* raw-return-ok:normal exact-plan refusal */
  plan_digest(wire, wire_len, expected);
  for (size_t i = 0; i < 32; i++)
    difference |= actual[i] ^ expected[i];
  return difference == 0;
}

struct zcl_result metaverse_space_scout_plan(
    const struct vcs_space_scout_mission_v1 *mission,
    struct metaverse_space_scout_plan_out *out)
{
  uint8_t wire[VCS_SPACE_SCOUT_MISSION_WIRE_BYTES], root[32], token[32];
  if (!mission || !out)
    return ZCL_ERR(-1, "space-scout-plan-input-invalid");
  enum vcs_space_scout_result encoded =
      vcs_space_scout_mission_encode(mission, wire);
  if (encoded != VCS_SPACE_SCOUT_OK ||
      vcs_space_scout_mission_root(mission, root) != VCS_SPACE_SCOUT_OK)
    return ZCL_ERR(-1, "space-scout-mission-invalid: %s",
                   vcs_space_scout_result_string(encoded));
  plan_digest(wire, sizeof(wire), token);
  memset(out, 0, sizeof(*out));
  zcl_hex_encode(root, 32, out->mission_root);
  zcl_hex_encode(token, 32, out->plan_token);
  return ZCL_OK;
}

static struct zcl_result verify_mission_bytes(
    const char *workspace, const uint8_t root[32],
    const uint8_t expected[VCS_SPACE_SCOUT_MISSION_WIRE_BYTES])
{
  uint8_t *wire = NULL, derived[32];
  size_t wire_len = 0;
  if (vcs_object_load_raw(workspace, root, &wire, &wire_len) != 0)
    return ZCL_ERR(-1, "space-scout-mission-read-failed");
  struct vcs_space_scout_mission_v1 decoded;
  enum vcs_space_scout_result parsed = vcs_space_scout_mission_decode(
      &decoded, wire, wire_len);
  bool exact = parsed == VCS_SPACE_SCOUT_OK &&
               vcs_space_scout_mission_root(&decoded, derived) ==
                   VCS_SPACE_SCOUT_OK &&
               memcmp(derived, root, 32) == 0 &&
               wire_len == VCS_SPACE_SCOUT_MISSION_WIRE_BYTES &&
               memcmp(wire, expected, wire_len) == 0;
  free(wire);
  return exact ? ZCL_OK
               : ZCL_ERR(-1, "space-scout-mission-cas-mismatch");
}

static struct zcl_result verify_map_bytes(
    const char *workspace, const uint8_t root[32],
    const uint8_t expected[VCS_SPACE_SCOUT_MAP_WIRE_BYTES])
{
  uint8_t *wire = NULL, derived[32];
  size_t wire_len = 0;
  if (vcs_object_load_raw(workspace, root, &wire, &wire_len) != 0)
    return ZCL_ERR(-1, "space-scout-evidence-read-failed");
  struct vcs_space_scout_map_v1 *decoded = zcl_malloc(
      sizeof(*decoded), "space_scout_verify_map");
  if (!decoded) {
    free(wire);
    return ZCL_ERR(-1, "space-scout-evidence-allocation-failed");
  }
  enum vcs_space_scout_result parsed = vcs_space_scout_map_decode(
      decoded, wire, wire_len);
  bool exact = parsed == VCS_SPACE_SCOUT_OK &&
               vcs_space_scout_map_root(decoded, derived) ==
                   VCS_SPACE_SCOUT_OK &&
               memcmp(derived, root, 32) == 0 &&
               wire_len == VCS_SPACE_SCOUT_MAP_WIRE_BYTES &&
               memcmp(wire, expected, wire_len) == 0;
  free(decoded);
  free(wire);
  return exact ? ZCL_OK
               : ZCL_ERR(-1, "space-scout-evidence-cas-mismatch");
}

static struct zcl_result verify_attestation_bytes(
    const char *workspace, const uint8_t root[32],
    const uint8_t expected[VCS_SPACE_SCOUT_ATTESTATION_WIRE_BYTES])
{
  uint8_t *wire = NULL, derived[32];
  size_t wire_len = 0;
  if (vcs_object_load_raw(workspace, root, &wire, &wire_len) != 0)
    return ZCL_ERR(-1, "space-scout-attestation-read-failed");
  struct vcs_space_scout_attestation_v1 decoded;
  enum vcs_space_scout_result parsed = vcs_space_scout_attestation_decode(
      &decoded, wire, wire_len);
  bool exact = parsed == VCS_SPACE_SCOUT_OK &&
               vcs_space_scout_attestation_root(&decoded, derived) ==
                   VCS_SPACE_SCOUT_OK &&
               memcmp(derived, root, 32) == 0 &&
               wire_len == VCS_SPACE_SCOUT_ATTESTATION_WIRE_BYTES &&
               memcmp(wire, expected, wire_len) == 0;
  free(wire);
  return exact ? ZCL_OK
               : ZCL_ERR(-1, "space-scout-attestation-cas-mismatch");
}

struct scout_evidence {
  uint8_t mission_wire[VCS_SPACE_SCOUT_MISSION_WIRE_BYTES];
  uint8_t mission_root[32], map_root[32], attestation_root[32];
  uint8_t attestation_wire[VCS_SPACE_SCOUT_ATTESTATION_WIRE_BYTES];
  uint8_t *map_wire;
};

static struct zcl_result validate_run_plan(
    const struct vcs_space_scout_mission_v1 *mission,
    const char *plan_token, bool confirm,
    const struct vcs_zcode_dht_delegation *observer_delegation,
    struct scout_evidence *evidence)
{
  if (memcmp(mission->network_genesis,
             observer_delegation->network_genesis, 32) != 0)
    return ZCL_ERR(-1, "space-scout-observer-network-mismatch");
  enum vcs_space_scout_result encoded =
      vcs_space_scout_mission_encode(mission, evidence->mission_wire);
  if (encoded != VCS_SPACE_SCOUT_OK ||
      vcs_space_scout_mission_root(mission, evidence->mission_root) !=
          VCS_SPACE_SCOUT_OK)
    return ZCL_ERR(-1, "space-scout-mission-invalid: %s",
                   vcs_space_scout_result_string(encoded));
  if (!confirm)
    return ZCL_ERR(-1, "space-scout-run-requires-confirm-true");
  if (!token_matches(evidence->mission_wire,
                     sizeof(evidence->mission_wire), plan_token))
    return ZCL_ERR(-1, "space-scout-plan-token-stale");
  return ZCL_OK;
}

static struct zcl_result prepare_evidence(
    const struct vcs_space_scout_mission_v1 *mission,
    const struct vcs_space_scout_run_context *run_context,
    const struct vcs_zcode_dht_delegation *observer_delegation,
    const uint8_t online_seed[32], struct vcs_space_scout_map_v1 *map,
    struct scout_evidence *evidence)
{
  enum vcs_space_scout_result ran =
      vcs_space_scout_run(mission, run_context, map);
  if (ran == VCS_SPACE_SCOUT_OK)
    ran = vcs_space_scout_map_encode(map, evidence->map_wire);
  if (ran == VCS_SPACE_SCOUT_OK)
    ran = vcs_space_scout_map_root(map, evidence->map_root);
  struct vcs_space_scout_attestation_v1 attestation;
  memset(&attestation, 0, sizeof(attestation));
  if (ran == VCS_SPACE_SCOUT_OK) {
    attestation.schema_version = VCS_SPACE_SCOUT_ATTESTATION_VERSION;
    memcpy(attestation.mission_root, evidence->mission_root, 32);
    memcpy(attestation.evidence_map_root, evidence->map_root, 32);
    attestation.observation_unix = mission->observation_unix;
    attestation.observer_delegation = *observer_delegation;
    ran = vcs_space_scout_attestation_sign(&attestation, online_seed);
  }
  if (ran == VCS_SPACE_SCOUT_OK)
    ran = vcs_space_scout_attestation_encode(&attestation,
                                             evidence->attestation_wire);
  if (ran == VCS_SPACE_SCOUT_OK)
    ran = vcs_space_scout_attestation_root(&attestation,
                                           evidence->attestation_root);
  if (ran != VCS_SPACE_SCOUT_OK)
    return ZCL_ERR(-1, "space-scout-run-refused: %s",
                   vcs_space_scout_result_string(ran));
  return ZCL_OK;
}

static struct zcl_result persist_evidence(
    const char *workspace, const struct scout_evidence *evidence,
    metaverse_space_scout_store_allowed_fn store_allowed,
    void *store_policy_context, bool *mutated_out,
    struct metaverse_space_scout_run_out *out)
{
  if (!store_allowed(store_policy_context, evidence->mission_root,
                     "space.scout.mission") ||
      !store_allowed(store_policy_context, evidence->map_root,
                     "space.scout.evidence_map") ||
      !store_allowed(store_policy_context, evidence->attestation_root,
                     "space.scout.attestation"))
    return ZCL_ERR(-1, "space-scout-evidence-store-policy-denied");
  bool store_initialized = vcs_object_store_initialized(workspace);
  if (!vcs_object_store_init(workspace))
    return ZCL_ERR(-1, "space-scout-cas-init-failed");
  *mutated_out = !store_initialized;
  bool mission_existed = vcs_object_has(workspace, evidence->mission_root);
  bool map_existed = vcs_object_has(workspace, evidence->map_root);
  bool attestation_existed = vcs_object_has(workspace, evidence->attestation_root);
  bool existed = mission_existed && map_existed && attestation_existed;
  if (!vcs_object_put_addressed(workspace, evidence->mission_root,
                                evidence->mission_wire,
                                sizeof(evidence->mission_wire)))
    return ZCL_ERR(-1, "space-scout-cas-store-failed");
  *mutated_out |= !mission_existed;
  if (!vcs_object_put_addressed(workspace, evidence->map_root,
                                evidence->map_wire,
                                VCS_SPACE_SCOUT_MAP_WIRE_BYTES))
    return ZCL_ERR(-1, "space-scout-cas-store-failed");
  *mutated_out |= !map_existed;
  if (!vcs_object_put_addressed(workspace, evidence->attestation_root,
                                evidence->attestation_wire,
                                sizeof(evidence->attestation_wire)))
    return ZCL_ERR(-1, "space-scout-cas-store-failed");
  *mutated_out |= !attestation_existed;
  struct zcl_result verified = verify_mission_bytes(
      workspace, evidence->mission_root, evidence->mission_wire);
  if (verified.ok)
    verified = verify_map_bytes(workspace, evidence->map_root, evidence->map_wire);
  if (verified.ok)
    verified = verify_attestation_bytes(workspace, evidence->attestation_root,
                                        evidence->attestation_wire);
  if (!verified.ok)
    return verified;
  memset(out, 0, sizeof(*out));
  zcl_hex_encode(evidence->mission_root, 32, out->mission_root);
  zcl_hex_encode(evidence->map_root, 32, out->evidence_root);
  zcl_hex_encode(evidence->attestation_root, 32, out->attestation_root);
  out->already_recorded = existed;
  return ZCL_OK;
}

struct zcl_result metaverse_space_scout_run(
    const char *workspace,
    const struct vcs_space_scout_mission_v1 *mission,
    const char *plan_token, bool confirm,
    const struct vcs_space_scout_run_context *run_context,
    const struct vcs_zcode_dht_delegation *observer_delegation,
    const uint8_t online_seed[32],
    metaverse_space_scout_store_allowed_fn store_allowed,
    void *store_policy_context, bool *mutated_out,
    struct metaverse_space_scout_run_out *out)
{
  if (!workspace || !workspace[0] || !mission || !run_context ||
      !observer_delegation || !online_seed || !store_allowed ||
      !mutated_out || !out)
    return ZCL_ERR(-1, "space-scout-run-input-invalid");
  *mutated_out = false;
  struct scout_evidence evidence;
  struct zcl_result result = validate_run_plan(
      mission, plan_token, confirm, observer_delegation, &evidence);
  if (!result.ok)
    return result;
  struct vcs_space_scout_map_v1 *map = zcl_malloc(
      sizeof(*map), "space_scout_run_map");
  evidence.map_wire = zcl_malloc(VCS_SPACE_SCOUT_MAP_WIRE_BYTES,
                                 "space_scout_run_wire");
  if (!map || !evidence.map_wire) {
    free(evidence.map_wire);
    free(map);
    return ZCL_ERR(-1, "space-scout-run-allocation-failed");
  }
  result = prepare_evidence(mission, run_context, observer_delegation,
                             online_seed, map, &evidence);
  if (result.ok)
    result = persist_evidence(workspace, &evidence, store_allowed,
                               store_policy_context, mutated_out, out);
  free(evidence.map_wire);
  free(map);
  return result;
}

struct zcl_result metaverse_space_scout_attestation_show(
    const char *workspace, const char *attestation_root,
    struct vcs_space_scout_attestation_v1 *out)
{
  uint8_t root[32], derived[32], *wire = NULL;
  size_t wire_len = 0;
  if (!workspace || !parse_root(attestation_root, root) || !out)
    return ZCL_ERR(-1, "space-scout-attestation-show-input-invalid");
  if (vcs_object_load_raw(workspace, root, &wire, &wire_len) != 0)
    return ZCL_ERR(-1, "space-scout-attestation-show-not-found");
  enum vcs_space_scout_result parsed = vcs_space_scout_attestation_decode(
      out, wire, wire_len);
  free(wire);
  if (parsed != VCS_SPACE_SCOUT_OK ||
      vcs_space_scout_attestation_root(out, derived) != VCS_SPACE_SCOUT_OK ||
      memcmp(root, derived, 32) != 0) {
    memset(out, 0, sizeof(*out));
    return ZCL_ERR(-1, "space-scout-attestation-show-cas-corrupt");
  }
  return ZCL_OK;
}

struct zcl_result metaverse_space_scout_show(
    const char *workspace, const char *evidence_root,
    struct vcs_space_scout_map_v1 *out)
{
  uint8_t root[32], derived[32], *wire = NULL;
  size_t wire_len = 0;
  if (!workspace || !parse_root(evidence_root, root) || !out)
    return ZCL_ERR(-1, "space-scout-show-input-invalid");
  if (vcs_object_load_raw(workspace, root, &wire, &wire_len) != 0)
    return ZCL_ERR(-1, "space-scout-show-not-found");
  enum vcs_space_scout_result parsed = vcs_space_scout_map_decode(
      out, wire, wire_len);
  free(wire);
  if (parsed != VCS_SPACE_SCOUT_OK ||
      vcs_space_scout_map_root(out, derived) != VCS_SPACE_SCOUT_OK ||
      memcmp(root, derived, 32) != 0) {
    memset(out, 0, sizeof(*out));
    return ZCL_ERR(-1, "space-scout-show-cas-corrupt");
  }
  return ZCL_OK;
}

struct zcl_result metaverse_space_scout_mission_show(
    const char *workspace, const char *mission_root,
    struct vcs_space_scout_mission_v1 *out)
{
  uint8_t root[32], derived[32], *wire = NULL;
  size_t wire_len = 0;
  if (!workspace || !parse_root(mission_root, root) || !out)
    return ZCL_ERR(-1, "space-scout-mission-show-input-invalid");
  if (vcs_object_load_raw(workspace, root, &wire, &wire_len) != 0)
    return ZCL_ERR(-1, "space-scout-mission-show-not-found");
  enum vcs_space_scout_result parsed = vcs_space_scout_mission_decode(
      out, wire, wire_len);
  free(wire);
  if (parsed != VCS_SPACE_SCOUT_OK ||
      vcs_space_scout_mission_root(out, derived) != VCS_SPACE_SCOUT_OK ||
      memcmp(root, derived, 32) != 0) {
    memset(out, 0, sizeof(*out));
    return ZCL_ERR(-1, "space-scout-mission-show-cas-corrupt");
  }
  return ZCL_OK;
}
