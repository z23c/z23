/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical read-only Sovereign Space v1 object wires. */

#ifndef ZCL_VCS_SPACE_H
#define ZCL_VCS_SPACE_H

#include "vcs/zcode_dht_delegation.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_SERVICE_DESCRIPTOR_VERSION 1u
#define VCS_SPACE_MANIFEST_VERSION 1u
#define VCS_SERVICE_DESCRIPTOR_DOMAIN "zcl.service_descriptor.v1"
#define VCS_SPACE_MANIFEST_DOMAIN "zcl.space_manifest.v1"

#define VCS_SERVICE_OBJECT_MAX 16u
#define VCS_SERVICE_CAPABILITY_MAX 8u
#define VCS_SPACE_SERVICE_MAX 16u
#define VCS_SPACE_OBJECT_MAX 32u
#define VCS_SPACE_PORTAL_MAX 16u
#define VCS_SPACE_NAME_MAX 63u
#define VCS_SPACE_DESCRIPTION_MAX 512u
#define VCS_SERVICE_DESCRIPTOR_WIRE_MAX 813u
#define VCS_SPACE_MANIFEST_WIRE_MAX 3024u

enum vcs_service_read_verb {
  VCS_SERVICE_VERB_DISCOVER = 1u << 0,
  VCS_SERVICE_VERB_FETCH = 1u << 1,
  VCS_SERVICE_VERB_LIST = 1u << 2,
  VCS_SERVICE_VERB_QUERY = 1u << 3,
};

#define VCS_SERVICE_VERB_READ_MASK                                      \
  (VCS_SERVICE_VERB_DISCOVER | VCS_SERVICE_VERB_FETCH |                 \
   VCS_SERVICE_VERB_LIST | VCS_SERVICE_VERB_QUERY)

enum vcs_space_result {
  VCS_SPACE_OK = 0,
  VCS_SPACE_ERR_NULL,
  VCS_SPACE_ERR_SIZE,
  VCS_SPACE_ERR_MAGIC,
  VCS_SPACE_ERR_VERSION,
  VCS_SPACE_ERR_LIMIT,
  VCS_SPACE_ERR_ROOT,
  VCS_SPACE_ERR_ORDER,
  VCS_SPACE_ERR_VERB,
  VCS_SPACE_ERR_TEXT,
  VCS_SPACE_ERR_TIME,
  VCS_SPACE_ERR_DELEGATION,
  VCS_SPACE_ERR_NETWORK,
  VCS_SPACE_ERR_SIGNER,
  VCS_SPACE_ERR_SIGNATURE,
  VCS_SPACE_ERR_CHAIN,
};

const char *vcs_space_result_string(enum vcs_space_result result);

struct vcs_service_descriptor_v1 {
  uint16_t schema_version;
  uint8_t protocol_root[32];
  uint8_t read_verbs;
  uint8_t object_count;
  uint8_t object_roots[VCS_SERVICE_OBJECT_MAX][32];
  uint8_t capability_count;
  uint8_t capability_roots[VCS_SERVICE_CAPABILITY_MAX][32];
};

struct vcs_space_manifest_v1 {
  uint16_t schema_version;
  uint64_t sequence;
  uint64_t not_before;
  uint64_t expiry;
  char name[VCS_SPACE_NAME_MAX + 1u];
  char description[VCS_SPACE_DESCRIPTION_MAX + 1u];
  uint8_t service_count;
  uint8_t service_roots[VCS_SPACE_SERVICE_MAX][32];
  uint8_t object_count;
  uint8_t object_roots[VCS_SPACE_OBJECT_MAX][32];
  uint8_t portal_count;
  uint8_t portal_roots[VCS_SPACE_PORTAL_MAX][32];
  bool has_admission;
  uint8_t admission_root[32];
  struct vcs_zcode_dht_delegation delegation;
  uint8_t signature[64];
};

typedef bool (*vcs_space_chain_verify_fn)(
    void *ctx, const struct vcs_zcode_dht_delegation *delegation);

struct vcs_space_manifest_verify_context {
  uint8_t network_genesis[32];
  uint64_t now_unix;
  vcs_space_chain_verify_fn chain_verify;
  void *chain_ctx;
};

enum vcs_space_result vcs_service_descriptor_validate(
    const struct vcs_service_descriptor_v1 *descriptor);
enum vcs_space_result vcs_service_descriptor_encode(
    const struct vcs_service_descriptor_v1 *descriptor,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len);
enum vcs_space_result vcs_service_descriptor_decode(
    struct vcs_service_descriptor_v1 *out, const uint8_t *wire,
    size_t wire_len);
enum vcs_space_result vcs_service_descriptor_root(
    const struct vcs_service_descriptor_v1 *descriptor, uint8_t out[32]);

enum vcs_space_result vcs_space_manifest_validate(
    const struct vcs_space_manifest_v1 *manifest);
enum vcs_space_result vcs_space_manifest_validate_at(
    const struct vcs_space_manifest_v1 *manifest,
    const uint8_t expected_network_genesis[32], uint64_t now_unix);
/* Live verification adds the caller's local active-chain projection. The
 * callback is mandatory: a signed delegation without an independently folded
 * ACTIVE ZID/beacon verdict is identity evidence, not chain authorization. */
enum vcs_space_result vcs_space_manifest_verify(
    const struct vcs_space_manifest_v1 *manifest,
    const struct vcs_space_manifest_verify_context *verify);
enum vcs_space_result vcs_space_manifest_sign(
    struct vcs_space_manifest_v1 *manifest,
    const uint8_t online_seed[32]);
enum vcs_space_result vcs_space_manifest_encode(
    const struct vcs_space_manifest_v1 *manifest,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len);
enum vcs_space_result vcs_space_manifest_decode(
    struct vcs_space_manifest_v1 *out, const uint8_t *wire,
    size_t wire_len);
enum vcs_space_result vcs_space_manifest_root(
    const struct vcs_space_manifest_v1 *manifest, uint8_t out[32]);

#endif /* ZCL_VCS_SPACE_H */
