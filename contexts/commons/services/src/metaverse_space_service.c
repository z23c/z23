/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Exact-plan CAS and blob-carrier service for Sovereign Space v1. */

#include "services/metaverse_space_service.h"

#include "base/hex.h"
#include "crypto/sha3.h"
#include "vcs/blob_store.h"
#include "vcs/vcs_object.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool hex_root(const char *hex, uint8_t out[32])
{
  if (!hex || strlen(hex) != 64u || !zcl_hex_decode_lower(hex, out, 32))
    return false; /* raw-return-ok:pure input predicate */
  return true;
}

static void plan_digest(enum metaverse_space_object_kind kind,
                        const uint8_t *wire, size_t wire_len,
                        uint8_t out[32])
{
  static const char domain[] = "zcl.metaverse.space.plan.v1";
  struct sha3_256_ctx sha;
  sha3_256_init(&sha);
  sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain) - 1u);
  uint8_t byte = (uint8_t)kind;
  sha3_256_write(&sha, &byte, 1);
  sha3_256_write(&sha, wire, wire_len);
  sha3_256_finalize(&sha, out);
}

static struct zcl_result service_wire(
    const struct vcs_service_descriptor_v1 *descriptor,
    uint8_t wire[VCS_SERVICE_DESCRIPTOR_WIRE_MAX], size_t *wire_len,
    uint8_t root[32])
{
  enum vcs_space_result result = vcs_service_descriptor_encode(
      descriptor, wire, VCS_SERVICE_DESCRIPTOR_WIRE_MAX, wire_len);
  if (result != VCS_SPACE_OK ||
      vcs_service_descriptor_root(descriptor, root) != VCS_SPACE_OK)
    return ZCL_ERR(-1, "space-service-invalid: %s",
                   vcs_space_result_string(result));
  return ZCL_OK;
}

static struct zcl_result manifest_wire(
    const struct vcs_space_manifest_v1 *manifest,
    const struct vcs_space_manifest_verify_context *verify,
    uint8_t wire[VCS_SPACE_MANIFEST_WIRE_MAX], size_t *wire_len,
    uint8_t root[32])
{
  enum vcs_space_result result = vcs_space_manifest_verify(manifest, verify);
  if (result == VCS_SPACE_OK)
    result = vcs_space_manifest_encode(
        manifest, wire, VCS_SPACE_MANIFEST_WIRE_MAX, wire_len);
  if (result != VCS_SPACE_OK ||
      vcs_space_manifest_root(manifest, root) != VCS_SPACE_OK)
    return ZCL_ERR(-1, "space-manifest-invalid: %s",
                   vcs_space_result_string(result));
  return ZCL_OK;
}

static void plan_out(enum metaverse_space_object_kind kind,
                     const uint8_t *wire, size_t wire_len,
                     const uint8_t root[32],
                     struct metaverse_space_plan_out *out)
{
  uint8_t token[32];
  plan_digest(kind, wire, wire_len, token);
  memset(out, 0, sizeof(*out));
  zcl_hex_encode(root, 32, out->object_root);
  zcl_hex_encode(token, 32, out->plan_token);
  out->wire_bytes = wire_len;
}

struct zcl_result metaverse_space_service_plan(
    const struct vcs_service_descriptor_v1 *descriptor,
    struct metaverse_space_plan_out *out)
{
  if (!descriptor || !out)
    return ZCL_ERR(-1, "space-service-plan-input-invalid");
  uint8_t wire[VCS_SERVICE_DESCRIPTOR_WIRE_MAX], root[32];
  size_t wire_len = 0;
  ZCL_CHECK(service_wire(descriptor, wire, &wire_len, root));
  plan_out(METAVERSE_SPACE_OBJECT_SERVICE_DESCRIPTOR, wire, wire_len,
           root, out);
  return ZCL_OK;
}

static bool token_matches(enum metaverse_space_object_kind kind,
                          const uint8_t *wire, size_t wire_len,
                          const char *supplied)
{
  uint8_t actual[32], expected[32], difference = 0;
  if (!hex_root(supplied, actual))
    return false; /* raw-return-ok:invalid plan token is a normal refusal */
  plan_digest(kind, wire, wire_len, expected);
  for (size_t i = 0; i < 32; i++)
    difference |= actual[i] ^ expected[i];
  return difference == 0;
}

static struct zcl_result identify(const uint8_t *wire, size_t wire_len,
                                  struct metaverse_space_object *out)
{
  if (!wire || !wire_len || !out)
    return ZCL_ERR(-1, "space-object-identify-input-invalid");
  memset(out, 0, sizeof(*out));
  struct vcs_service_descriptor_v1 service;
  if (vcs_service_descriptor_decode(&service, wire, wire_len) ==
      VCS_SPACE_OK) {
    out->kind = METAVERSE_SPACE_OBJECT_SERVICE_DESCRIPTOR;
    out->as.service = service;
    if (vcs_service_descriptor_root(&service, out->root) == VCS_SPACE_OK)
      return ZCL_OK;
  }
  struct vcs_space_manifest_v1 manifest;
  if (vcs_space_manifest_decode(&manifest, wire, wire_len) == VCS_SPACE_OK) {
    out->kind = METAVERSE_SPACE_OBJECT_MANIFEST;
    out->as.manifest = manifest;
    if (vcs_space_manifest_root(&manifest, out->root) == VCS_SPACE_OK)
      return ZCL_OK;
  }
  memset(out, 0, sizeof(*out));
  return ZCL_ERR(-1, "space-object-wire-invalid");
}

static struct zcl_result cas_verify(const char *workspace,
                                    const uint8_t root[32],
                                    const uint8_t *expected,
                                    size_t expected_len)
{
  uint8_t *stored = NULL;
  size_t stored_len = 0;
  if (vcs_object_load_raw(workspace, root, &stored, &stored_len) != 0)
    return ZCL_ERR(-1, "space-cas-read-failed");
  struct metaverse_space_object object;
  struct zcl_result identified = identify(stored, stored_len, &object);
  bool exact = identified.ok && memcmp(object.root, root, 32) == 0 &&
               stored_len == expected_len &&
               memcmp(stored, expected, stored_len) == 0;
  free(stored);
  if (!exact)
    return ZCL_ERR(-1, "space-cas-root-or-bytes-mismatch");
  return ZCL_OK;
}

static struct zcl_result commit_wire(
    const char *workspace, enum metaverse_space_object_kind kind,
    const uint8_t *wire, size_t wire_len, const uint8_t root[32],
    const char *plan_token, bool confirm,
    struct metaverse_space_commit_out *out)
{
  if (!workspace || !workspace[0] || !wire || !wire_len || !root || !out)
    return ZCL_ERR(-1, "space-commit-input-invalid");
  if (!confirm)
    return ZCL_ERR(-1, "space-commit-requires-confirm-true");
  if (!token_matches(kind, wire, wire_len, plan_token))
    return ZCL_ERR(-1, "space-plan-token-stale");
  if (!vcs_object_store_init(workspace))
    return ZCL_ERR(-1, "space-cas-init-failed");
  bool existed = vcs_object_has(workspace, root);
  if (!vcs_object_put_addressed(workspace, root, wire, wire_len))
    return ZCL_ERR(-1, "space-cas-store-failed");
  ZCL_CHECK(cas_verify(workspace, root, wire, wire_len));
  memset(out, 0, sizeof(*out));
  zcl_hex_encode(root, 32, out->object_root);
  out->already_committed = existed;
  return ZCL_OK;
}

struct zcl_result metaverse_space_service_commit(
    const char *workspace,
    const struct vcs_service_descriptor_v1 *descriptor,
    const char *plan_token, bool confirm,
    struct metaverse_space_commit_out *out)
{
  uint8_t wire[VCS_SERVICE_DESCRIPTOR_WIRE_MAX], root[32];
  size_t wire_len = 0;
  ZCL_CHECK(service_wire(descriptor, wire, &wire_len, root));
  return commit_wire(workspace,
                     METAVERSE_SPACE_OBJECT_SERVICE_DESCRIPTOR,
                     wire, wire_len, root, plan_token, confirm, out);
}

struct zcl_result metaverse_space_manifest_plan(
    const struct vcs_space_manifest_v1 *manifest,
    const struct vcs_space_manifest_verify_context *verify,
    struct metaverse_space_plan_out *out)
{
  if (!manifest || !verify || !out)
    return ZCL_ERR(-1, "space-manifest-plan-input-invalid");
  uint8_t wire[VCS_SPACE_MANIFEST_WIRE_MAX], root[32];
  size_t wire_len = 0;
  ZCL_CHECK(manifest_wire(manifest, verify, wire, &wire_len, root));
  plan_out(METAVERSE_SPACE_OBJECT_MANIFEST, wire, wire_len, root, out);
  return ZCL_OK;
}

struct zcl_result metaverse_space_manifest_commit(
    const char *workspace, const struct vcs_space_manifest_v1 *manifest,
    const struct vcs_space_manifest_verify_context *verify,
    const char *plan_token, bool confirm,
    struct metaverse_space_commit_out *out)
{
  uint8_t wire[VCS_SPACE_MANIFEST_WIRE_MAX], root[32];
  size_t wire_len = 0;
  ZCL_CHECK(manifest_wire(manifest, verify, wire, &wire_len, root));
  return commit_wire(workspace, METAVERSE_SPACE_OBJECT_MANIFEST,
                     wire, wire_len, root, plan_token, confirm, out);
}

struct zcl_result metaverse_space_show_bounded(
    const char *workspace, const char *object_root, size_t maximum_wire_bytes,
    struct metaverse_space_object *out, size_t *wire_bytes_out)
{
  uint8_t root[32], *wire = NULL;
  size_t wire_len = 0;
  if (wire_bytes_out)
    *wire_bytes_out = 0;
  if (!workspace || !hex_root(object_root, root) || !out || !wire_bytes_out)
    return ZCL_ERR(-1, "root must be 64 lowercase hex characters");
  int loaded = vcs_object_load_raw_bounded(
      workspace, root, maximum_wire_bytes, &wire, &wire_len);
  if (loaded == -2)
    return ZCL_ERR(-1, "space-show-byte-limit");
  if (loaded != 0)
    return ZCL_ERR(-1, "space-show-not-found");
  struct zcl_result result = identify(wire, wire_len, out);
  free(wire);
  if (!result.ok || memcmp(out->root, root, 32) != 0) {
    memset(out, 0, sizeof(*out));
    return ZCL_ERR(-1, "space-show-cas-corrupt");
  }
  *wire_bytes_out = wire_len;
  return ZCL_OK;
}

struct zcl_result metaverse_space_show(
    const char *workspace, const char *object_root,
    struct metaverse_space_object *out)
{
  size_t ignored = 0;
  return metaverse_space_show_bounded(
      workspace, object_root, SIZE_MAX, out, &ignored);
}

struct zcl_result metaverse_space_publish(
    struct vcs_package_store *store, const char *workspace,
    const char *object_root, char out_blob_root[65],
    enum metaverse_space_object_kind *kind_out)
{
  uint8_t root[32], *wire = NULL;
  size_t wire_len = 0;
  if (!store || !workspace || !hex_root(object_root, root) ||
      !out_blob_root || !kind_out)
    return ZCL_ERR(-1, "space-publish-input-invalid");
  if (vcs_object_load_raw(workspace, root, &wire, &wire_len) != 0)
    return ZCL_ERR(-1, "space-publish-not-in-cas");
  struct metaverse_space_object object;
  struct zcl_result identified = identify(wire, wire_len, &object);
  if (!identified.ok || memcmp(object.root, root, 32) != 0) {
    free(wire);
    return ZCL_ERR(-1, "space-publish-cas-corrupt");
  }
  uint8_t blob[32];
  enum vcs_blob_result stored = vcs_blob_put_to(store, wire, wire_len, blob);
  free(wire);
  if (stored != VCS_BLOB_OK)
    return ZCL_ERR(-1, "space-publish-store-refused: %s",
                   vcs_blob_result_string(stored));
  zcl_hex_encode(blob, 32, out_blob_root);
  *kind_out = object.kind;
  return ZCL_OK;
}

struct zcl_result metaverse_space_transport_root(
    const char *workspace, const char *object_root,
    char out_blob_root[65], enum metaverse_space_object_kind *kind_out)
{
  uint8_t root[32], *wire = NULL, blob[32];
  size_t wire_len = 0;
  if (!workspace || !hex_root(object_root, root) ||
      !out_blob_root || !kind_out)
    return ZCL_ERR(-1, "space-transport-root-input-invalid");
  if (vcs_object_load_raw(workspace, root, &wire, &wire_len) != 0)
    return ZCL_ERR(-1, "space-transport-root-not-in-cas");
  struct metaverse_space_object object;
  struct zcl_result identified = identify(wire, wire_len, &object);
  enum vcs_blob_result derived =
      identified.ok && memcmp(object.root, root, 32) == 0
          ? vcs_blob_root_of(wire, wire_len, blob)
          : VCS_BLOB_ERR_CORRUPT;
  free(wire);
  if (derived != VCS_BLOB_OK)
    return ZCL_ERR(-1, "space-transport-root-refused: %s",
                   vcs_blob_result_string(derived));
  zcl_hex_encode(blob, 32, out_blob_root);
  *kind_out = object.kind;
  return ZCL_OK;
}

struct zcl_result metaverse_space_blob_inspect(
    struct vcs_package_store *store, const char *blob_root,
    struct metaverse_space_object *out)
{
  size_t ignored = 0;
  return metaverse_space_blob_inspect_bounded(
      store, blob_root, VCS_BLOB_MAX_BYTES, out, &ignored);
}

struct zcl_result metaverse_space_blob_inspect_bounded(
    struct vcs_package_store *store, const char *blob_root,
    size_t maximum_wire_bytes, struct metaverse_space_object *out,
    size_t *wire_bytes_out)
{
  uint8_t transport[32], wire[VCS_BLOB_MAX_BYTES];
  size_t wire_len = 0;
  if (wire_bytes_out)
    *wire_bytes_out = 0;
  if (!store || !hex_root(blob_root, transport) || !out || !wire_bytes_out)
    return ZCL_ERR(-1, "space-blob-inspect-input-invalid");
  size_t capacity = maximum_wire_bytes < sizeof(wire)
                        ? maximum_wire_bytes : sizeof(wire);
  enum vcs_blob_result loaded = vcs_blob_get_from(
      store, transport, wire, capacity, &wire_len);
  if (loaded == VCS_BLOB_ERR_CAPACITY)
    return ZCL_ERR(-1, "space-blob-inspect-byte-limit");
  if (loaded != VCS_BLOB_OK)
    return ZCL_ERR(-1, "space-blob-inspect-read: %s",
                   vcs_blob_result_string(loaded));
  struct zcl_result identified = identify(wire, wire_len, out);
  if (identified.ok)
    *wire_bytes_out = wire_len;
  return identified;
}

struct zcl_result metaverse_space_admit_bounded(
    struct vcs_package_store *store, const char *workspace,
    const char *expected_object_root, const char *blob_root,
    size_t maximum_wire_bytes, enum metaverse_space_object_kind *kind_out,
    bool *new_out)
{
  uint8_t expected[32], transport[32], wire[VCS_BLOB_MAX_BYTES];
  size_t wire_len = 0;
  if (!store || !workspace || !hex_root(expected_object_root, expected) ||
      !hex_root(blob_root, transport) || !kind_out || !new_out)
    return ZCL_ERR(-1, "space-admit-input-invalid");
  size_t capacity = maximum_wire_bytes < sizeof(wire)
                        ? maximum_wire_bytes : sizeof(wire);
  enum vcs_blob_result loaded = vcs_blob_get_from(
      store, transport, wire, capacity, &wire_len);
  if (loaded == VCS_BLOB_ERR_CAPACITY)
    return ZCL_ERR(-1, "space-admit-byte-limit");
  if (loaded != VCS_BLOB_OK)
    return ZCL_ERR(-1, "space-admit-blob-read: %s",
                   vcs_blob_result_string(loaded));
  struct metaverse_space_object object;
  ZCL_CHECK(identify(wire, wire_len, &object));
  if (memcmp(object.root, expected, 32) != 0)
    return ZCL_ERR(-1, "space-admit-semantic-root-mismatch");
  if (!vcs_object_store_init(workspace))
    return ZCL_ERR(-1, "space-admit-cas-init-failed");
  *new_out = !vcs_object_has(workspace, expected);
  if (*new_out &&
      !vcs_object_put_addressed(workspace, expected, wire, wire_len))
    return ZCL_ERR(-1, "space-admit-cas-store-failed");
  ZCL_CHECK(cas_verify(workspace, expected, wire, wire_len));
  *kind_out = object.kind;
  return ZCL_OK;
}

struct zcl_result metaverse_space_admit(
    struct vcs_package_store *store, const char *workspace,
    const char *expected_object_root, const char *blob_root,
    enum metaverse_space_object_kind *kind_out, bool *new_out)
{
  return metaverse_space_admit_bounded(
      store, workspace, expected_object_root, blob_root, SIZE_MAX,
      kind_out, new_out);
}
