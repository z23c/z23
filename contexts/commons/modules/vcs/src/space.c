/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical read-only Sovereign Space v1 object wires. */

#include "vcs/space.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "support/cleanse.h"
#include "vcs/signed_evidence.h"

#include <limits.h>
#include <string.h>

static const uint8_t service_magic[8] =
    {'Z', 'C', 'S', 'P', 'D', 'S', '\r', '\n'};
static const uint8_t manifest_magic[8] =
    {'Z', 'C', 'S', 'P', 'M', 'F', '\r', '\n'};
static const char manifest_signature_domain[] =
    "zcl.space_manifest.signature.v1";

static bool zero(const uint8_t *value, size_t length)
{
  return !zcl_bytes_any_set(value, length);
}

static bool root_set_valid(const uint8_t roots[][32], size_t count,
                           size_t capacity)
{
  if (!roots || count > capacity)
    return false;
  for (size_t i = 0; i < count; i++) {
    if (!zcl_bytes_any_set(roots[i], 32) ||
        (i > 0 && memcmp(roots[i - 1], roots[i], 32) >= 0))
      return false;
  }
  for (size_t i = count; i < capacity; i++)
    if (!zero(roots[i], 32))
      return false;
  return true;
}

static bool bounded_text(const char *text, size_t maximum, bool required,
                         size_t *length_out)
{
  if (!text)
    return false;
  size_t length = 0;
  while (length <= maximum && text[length]) {
    unsigned char c = (unsigned char)text[length];
    if (c < 0x20 || c > 0x7e)
      return false;
    length++;
  }
  if (length > maximum || (required && length == 0))
    return false;
  if (length_out)
    *length_out = length;
  return true;
}

const char *vcs_space_result_string(enum vcs_space_result result)
{
  switch (result) {
  case VCS_SPACE_OK: return "ok";
  case VCS_SPACE_ERR_NULL: return "null-argument";
  case VCS_SPACE_ERR_SIZE: return "wire-size";
  case VCS_SPACE_ERR_MAGIC: return "wire-magic";
  case VCS_SPACE_ERR_VERSION: return "schema-version";
  case VCS_SPACE_ERR_LIMIT: return "bound-exceeded";
  case VCS_SPACE_ERR_ROOT: return "root-shape";
  case VCS_SPACE_ERR_ORDER: return "root-order";
  case VCS_SPACE_ERR_VERB: return "read-verb";
  case VCS_SPACE_ERR_TEXT: return "text-shape";
  case VCS_SPACE_ERR_TIME: return "validity-window";
  case VCS_SPACE_ERR_DELEGATION: return "delegation";
  case VCS_SPACE_ERR_NETWORK: return "wrong-network";
  case VCS_SPACE_ERR_SIGNER: return "delegated-signer";
  case VCS_SPACE_ERR_SIGNATURE: return "manifest-signature";
  case VCS_SPACE_ERR_CHAIN: return "chain-authorization";
  }
  return "unknown";
}

enum vcs_space_result vcs_service_descriptor_validate(
    const struct vcs_service_descriptor_v1 *descriptor)
{
  if (!descriptor)
    return VCS_SPACE_ERR_NULL;
  if (descriptor->schema_version != VCS_SERVICE_DESCRIPTOR_VERSION)
    return VCS_SPACE_ERR_VERSION;
  if (!zcl_bytes_any_set(descriptor->protocol_root, 32))
    return VCS_SPACE_ERR_ROOT;
  if (!descriptor->read_verbs ||
      (descriptor->read_verbs & ~VCS_SERVICE_VERB_READ_MASK))
    return VCS_SPACE_ERR_VERB;
  if (descriptor->object_count > VCS_SERVICE_OBJECT_MAX ||
      descriptor->capability_count > VCS_SERVICE_CAPABILITY_MAX)
    return VCS_SPACE_ERR_LIMIT;
  if (!root_set_valid(descriptor->object_roots, descriptor->object_count,
                      VCS_SERVICE_OBJECT_MAX) ||
      !root_set_valid(descriptor->capability_roots,
                      descriptor->capability_count,
                      VCS_SERVICE_CAPABILITY_MAX))
    return VCS_SPACE_ERR_ORDER;
  return VCS_SPACE_OK;
}

static size_t service_write(const struct vcs_service_descriptor_v1 *descriptor,
                            uint8_t *wire)
{
  size_t off = 0;
  memcpy(wire + off, service_magic, sizeof(service_magic));
  off += sizeof(service_magic);
  zcl_write_u16_le(wire + off, descriptor->schema_version);
  off += 2;
  memcpy(wire + off, descriptor->protocol_root, 32);
  off += 32;
  wire[off++] = descriptor->read_verbs;
  wire[off++] = descriptor->object_count;
  for (size_t i = 0; i < descriptor->object_count; i++) {
    memcpy(wire + off, descriptor->object_roots[i], 32);
    off += 32;
  }
  wire[off++] = descriptor->capability_count;
  for (size_t i = 0; i < descriptor->capability_count; i++) {
    memcpy(wire + off, descriptor->capability_roots[i], 32);
    off += 32;
  }
  return off;
}

enum vcs_space_result vcs_service_descriptor_encode(
    const struct vcs_service_descriptor_v1 *descriptor,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len)
{
  if (wire_len)
    *wire_len = 0;
  if (!wire || !wire_len)
    return VCS_SPACE_ERR_NULL;
  enum vcs_space_result checked =
      vcs_service_descriptor_validate(descriptor);
  if (checked != VCS_SPACE_OK)
    return checked;
  size_t needed = 8u + 2u + 32u + 1u + 1u +
                  (size_t)descriptor->object_count * 32u + 1u +
                  (size_t)descriptor->capability_count * 32u;
  if (wire_capacity < needed)
    return VCS_SPACE_ERR_SIZE;
  *wire_len = service_write(descriptor, wire);
  return *wire_len == needed ? VCS_SPACE_OK : VCS_SPACE_ERR_SIZE;
}

enum vcs_space_result vcs_service_descriptor_decode(
    struct vcs_service_descriptor_v1 *out, const uint8_t *wire,
    size_t wire_len)
{
  if (!out || !wire)
    return VCS_SPACE_ERR_NULL;
  memset(out, 0, sizeof(*out));
  if (wire_len < 45u || wire_len > VCS_SERVICE_DESCRIPTOR_WIRE_MAX)
    return VCS_SPACE_ERR_SIZE;
  if (memcmp(wire, service_magic, sizeof(service_magic)) != 0)
    return VCS_SPACE_ERR_MAGIC;
  size_t off = sizeof(service_magic);
  out->schema_version = zcl_read_u16_le(wire + off);
  off += 2;
  memcpy(out->protocol_root, wire + off, 32);
  off += 32;
  out->read_verbs = wire[off++];
  out->object_count = wire[off++];
  if (out->object_count > VCS_SERVICE_OBJECT_MAX ||
      off + (size_t)out->object_count * 32u + 1u > wire_len) {
    enum vcs_space_result error =
        out->object_count > VCS_SERVICE_OBJECT_MAX
            ? VCS_SPACE_ERR_LIMIT : VCS_SPACE_ERR_SIZE;
    memset(out, 0, sizeof(*out));
    return error;
  }
  for (size_t i = 0; i < out->object_count; i++) {
    memcpy(out->object_roots[i], wire + off, 32);
    off += 32;
  }
  out->capability_count = wire[off++];
  if (out->capability_count > VCS_SERVICE_CAPABILITY_MAX ||
      off + (size_t)out->capability_count * 32u != wire_len) {
    memset(out, 0, sizeof(*out));
    return out->capability_count > VCS_SERVICE_CAPABILITY_MAX
               ? VCS_SPACE_ERR_LIMIT : VCS_SPACE_ERR_SIZE;
  }
  for (size_t i = 0; i < out->capability_count; i++) {
    memcpy(out->capability_roots[i], wire + off, 32);
    off += 32;
  }
  enum vcs_space_result checked = vcs_service_descriptor_validate(out);
  if (checked != VCS_SPACE_OK)
    memset(out, 0, sizeof(*out));
  return checked;
}

enum vcs_space_result vcs_service_descriptor_root(
    const struct vcs_service_descriptor_v1 *descriptor, uint8_t out[32])
{
  if (!out)
    return VCS_SPACE_ERR_NULL;
  uint8_t wire[VCS_SERVICE_DESCRIPTOR_WIRE_MAX];
  size_t wire_len = 0;
  enum vcs_space_result encoded = vcs_service_descriptor_encode(
      descriptor, wire, sizeof(wire), &wire_len);
  if (encoded != VCS_SPACE_OK)
    return encoded;
  return vcs_signed_evidence_root(VCS_SERVICE_DESCRIPTOR_DOMAIN,
                                  strlen(VCS_SERVICE_DESCRIPTOR_DOMAIN),
                                  wire, wire_len, out)
             ? VCS_SPACE_OK : VCS_SPACE_ERR_NULL;
}

static enum vcs_space_result manifest_shape(
    const struct vcs_space_manifest_v1 *manifest, bool require_signature)
{
  if (!manifest)
    return VCS_SPACE_ERR_NULL;
  if (manifest->schema_version != VCS_SPACE_MANIFEST_VERSION)
    return VCS_SPACE_ERR_VERSION;
  if (!manifest->sequence || manifest->sequence > (uint64_t)INT64_MAX ||
      manifest->service_count > VCS_SPACE_SERVICE_MAX ||
      manifest->object_count > VCS_SPACE_OBJECT_MAX ||
      manifest->portal_count > VCS_SPACE_PORTAL_MAX)
    return VCS_SPACE_ERR_LIMIT;
  if (!manifest->not_before || manifest->expiry <= manifest->not_before)
    return VCS_SPACE_ERR_TIME;
  if (!bounded_text(manifest->name, VCS_SPACE_NAME_MAX, true, NULL) ||
      !bounded_text(manifest->description, VCS_SPACE_DESCRIPTION_MAX,
                    true, NULL))
    return VCS_SPACE_ERR_TEXT;
  if (!root_set_valid(manifest->service_roots, manifest->service_count,
                      VCS_SPACE_SERVICE_MAX) ||
      !root_set_valid(manifest->object_roots, manifest->object_count,
                      VCS_SPACE_OBJECT_MAX) ||
      !root_set_valid(manifest->portal_roots, manifest->portal_count,
                      VCS_SPACE_PORTAL_MAX))
    return VCS_SPACE_ERR_ORDER;
  if (manifest->has_admission != zcl_bytes_any_set(manifest->admission_root, 32))
    return VCS_SPACE_ERR_ROOT;
  if (manifest->not_before < manifest->delegation.not_before ||
      manifest->expiry > manifest->delegation.doc.expiry)
    return VCS_SPACE_ERR_TIME;
  if (vcs_zcode_dht_delegation_verify(
          &manifest->delegation, NULL, NULL, 0, NULL,
          manifest->not_before) != VCS_ZCODE_DHT_DELEGATION_OK)
    return VCS_SPACE_ERR_DELEGATION;
  if (require_signature && !zcl_bytes_any_set(manifest->signature, 64))
    return VCS_SPACE_ERR_SIGNATURE;
  return VCS_SPACE_OK;
}

static size_t manifest_write_unsigned(
    const struct vcs_space_manifest_v1 *manifest, uint8_t *wire)
{
  size_t name_len = 0, description_len = 0, off = 0;
  (void)bounded_text(manifest->name, VCS_SPACE_NAME_MAX, true, &name_len);
  (void)bounded_text(manifest->description, VCS_SPACE_DESCRIPTION_MAX,
                     true, &description_len);
  memcpy(wire + off, manifest_magic, sizeof(manifest_magic));
  off += sizeof(manifest_magic);
  zcl_write_u16_le(wire + off, manifest->schema_version);
  off += 2;
  zcl_write_u64_le(wire + off, manifest->sequence);
  off += 8;
  zcl_write_u64_le(wire + off, manifest->not_before);
  off += 8;
  zcl_write_u64_le(wire + off, manifest->expiry);
  off += 8;
  wire[off++] = (uint8_t)name_len;
  memcpy(wire + off, manifest->name, name_len);
  off += name_len;
  zcl_write_u16_le(wire + off, (uint16_t)description_len);
  off += 2;
  memcpy(wire + off, manifest->description, description_len);
  off += description_len;
  wire[off++] = manifest->service_count;
  for (size_t i = 0; i < manifest->service_count; i++) {
    memcpy(wire + off, manifest->service_roots[i], 32);
    off += 32;
  }
  wire[off++] = manifest->object_count;
  for (size_t i = 0; i < manifest->object_count; i++) {
    memcpy(wire + off, manifest->object_roots[i], 32);
    off += 32;
  }
  wire[off++] = manifest->portal_count;
  for (size_t i = 0; i < manifest->portal_count; i++) {
    memcpy(wire + off, manifest->portal_roots[i], 32);
    off += 32;
  }
  wire[off++] = manifest->has_admission ? 1u : 0u;
  if (manifest->has_admission) {
    memcpy(wire + off, manifest->admission_root, 32);
    off += 32;
  }
  uint8_t delegation[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES];
  if (vcs_zcode_dht_delegation_encode(&manifest->delegation, delegation) !=
      VCS_ZCODE_DHT_DELEGATION_OK)
    return 0;
  zcl_write_u16_le(wire + off, VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES);
  off += 2;
  memcpy(wire + off, delegation, sizeof(delegation));
  off += sizeof(delegation);
  return off;
}

static bool manifest_signature_valid(
    const struct vcs_space_manifest_v1 *manifest)
{
  uint8_t wire[VCS_SPACE_MANIFEST_WIRE_MAX];
  size_t unsigned_len = manifest_write_unsigned(manifest, wire);
  if (!unsigned_len)
    return false;
  uint8_t preimage[sizeof(manifest_signature_domain) - 1u +
                   VCS_SPACE_MANIFEST_WIRE_MAX];
  size_t off = 0;
  memcpy(preimage + off, manifest_signature_domain,
         sizeof(manifest_signature_domain) - 1u);
  off += sizeof(manifest_signature_domain) - 1u;
  memcpy(preimage + off, wire, unsigned_len);
  off += unsigned_len;
  bool valid = ed25519_verify(manifest->signature, preimage, off,
                              manifest->delegation.online_pubkey);
  memory_cleanse(preimage, off);
  return valid;
}

enum vcs_space_result vcs_space_manifest_validate(
    const struct vcs_space_manifest_v1 *manifest)
{
  enum vcs_space_result checked = manifest_shape(manifest, true);
  if (checked != VCS_SPACE_OK)
    return checked;
  return manifest_signature_valid(manifest) ? VCS_SPACE_OK
                                            : VCS_SPACE_ERR_SIGNATURE;
}

enum vcs_space_result vcs_space_manifest_validate_at(
    const struct vcs_space_manifest_v1 *manifest,
    const uint8_t expected_network_genesis[32], uint64_t now_unix)
{
  enum vcs_space_result checked = vcs_space_manifest_validate(manifest);
  if (checked != VCS_SPACE_OK)
    return checked;
  if (expected_network_genesis &&
      memcmp(manifest->delegation.network_genesis,
             expected_network_genesis, 32) != 0)
    return VCS_SPACE_ERR_NETWORK;
  if (now_unix < manifest->not_before || now_unix >= manifest->expiry)
    return VCS_SPACE_ERR_TIME;
  return VCS_SPACE_OK;
}

enum vcs_space_result vcs_space_manifest_verify(
    const struct vcs_space_manifest_v1 *manifest,
    const struct vcs_space_manifest_verify_context *verify)
{
  if (!verify || !verify->chain_verify)
    return VCS_SPACE_ERR_NULL;
  enum vcs_space_result checked = vcs_space_manifest_validate_at(
      manifest, verify->network_genesis, verify->now_unix);
  if (checked != VCS_SPACE_OK)
    return checked;
  return verify->chain_verify(verify->chain_ctx, &manifest->delegation)
             ? VCS_SPACE_OK : VCS_SPACE_ERR_CHAIN;
}

enum vcs_space_result vcs_space_manifest_sign(
    struct vcs_space_manifest_v1 *manifest,
    const uint8_t online_seed[32])
{
  if (!manifest || !online_seed)
    return VCS_SPACE_ERR_NULL;
  enum vcs_space_result checked = manifest_shape(manifest, false);
  if (checked != VCS_SPACE_OK)
    return checked;
  uint8_t pubkey[32], secret[32];
  ed25519_keypair(pubkey, secret, online_seed);
  if (memcmp(pubkey, manifest->delegation.online_pubkey, 32) != 0) {
    memory_cleanse(secret, sizeof(secret));
    return VCS_SPACE_ERR_SIGNER;
  }
  uint8_t wire[VCS_SPACE_MANIFEST_WIRE_MAX];
  size_t unsigned_len = manifest_write_unsigned(manifest, wire);
  if (!unsigned_len) {
    memory_cleanse(secret, sizeof(secret));
    return VCS_SPACE_ERR_DELEGATION;
  }
  uint8_t preimage[sizeof(manifest_signature_domain) - 1u +
                   VCS_SPACE_MANIFEST_WIRE_MAX];
  size_t off = 0;
  memcpy(preimage + off, manifest_signature_domain,
         sizeof(manifest_signature_domain) - 1u);
  off += sizeof(manifest_signature_domain) - 1u;
  memcpy(preimage + off, wire, unsigned_len);
  off += unsigned_len;
  ed25519_sign(manifest->signature, preimage, off, secret, pubkey);
  memory_cleanse(secret, sizeof(secret));
  memory_cleanse(preimage, off);
  return vcs_space_manifest_validate(manifest);
}

enum vcs_space_result vcs_space_manifest_encode(
    const struct vcs_space_manifest_v1 *manifest,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len)
{
  if (wire_len)
    *wire_len = 0;
  if (!wire || !wire_len)
    return VCS_SPACE_ERR_NULL;
  enum vcs_space_result checked = vcs_space_manifest_validate(manifest);
  if (checked != VCS_SPACE_OK)
    return checked;
  uint8_t encoded[VCS_SPACE_MANIFEST_WIRE_MAX];
  size_t unsigned_len = manifest_write_unsigned(manifest, encoded);
  size_t needed = unsigned_len + sizeof(manifest->signature);
  if (!unsigned_len || needed > sizeof(encoded) || wire_capacity < needed)
    return VCS_SPACE_ERR_SIZE;
  memcpy(encoded + unsigned_len, manifest->signature,
         sizeof(manifest->signature));
  memcpy(wire, encoded, needed);
  *wire_len = needed;
  return VCS_SPACE_OK;
}

static bool take(const uint8_t *wire, size_t wire_len, size_t *off,
                 void *out, size_t length)
{
  if (!wire || !off || *off > wire_len || length > wire_len - *off)
    return false;
  if (out && length)
    memcpy(out, wire + *off, length);
  *off += length;
  return true;
}

enum vcs_space_result vcs_space_manifest_decode(
    struct vcs_space_manifest_v1 *out, const uint8_t *wire,
    size_t wire_len)
{
  if (!out || !wire)
    return VCS_SPACE_ERR_NULL;
  memset(out, 0, sizeof(*out));
  if (wire_len < 8u + 2u + 24u + 1u + 1u + 1u + 1u + 1u + 2u +
                     VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES + 64u ||
      wire_len > VCS_SPACE_MANIFEST_WIRE_MAX)
    return VCS_SPACE_ERR_SIZE;
  if (memcmp(wire, manifest_magic, sizeof(manifest_magic)) != 0)
    return VCS_SPACE_ERR_MAGIC;
  size_t off = sizeof(manifest_magic);
  out->schema_version = zcl_read_u16_le(wire + off);
  off += 2;
  out->sequence = zcl_read_u64_le(wire + off);
  off += 8;
  out->not_before = zcl_read_u64_le(wire + off);
  off += 8;
  out->expiry = zcl_read_u64_le(wire + off);
  off += 8;
  uint8_t name_len = wire[off++];
  if (!name_len || name_len > VCS_SPACE_NAME_MAX ||
      !take(wire, wire_len, &off, out->name, name_len))
    goto size_fail;
  if (off + 2u > wire_len)
    goto size_fail;
  uint16_t description_len = zcl_read_u16_le(wire + off);
  off += 2;
  if (!description_len || description_len > VCS_SPACE_DESCRIPTION_MAX ||
      !take(wire, wire_len, &off, out->description, description_len))
    goto size_fail;
  if (off >= wire_len)
    goto size_fail;
  out->service_count = wire[off++];
  if (out->service_count > VCS_SPACE_SERVICE_MAX ||
      !take(wire, wire_len, &off, out->service_roots,
            (size_t)out->service_count * 32u))
    goto limit_fail;
  if (off >= wire_len)
    goto size_fail;
  out->object_count = wire[off++];
  if (out->object_count > VCS_SPACE_OBJECT_MAX ||
      !take(wire, wire_len, &off, out->object_roots,
            (size_t)out->object_count * 32u))
    goto limit_fail;
  if (off >= wire_len)
    goto size_fail;
  out->portal_count = wire[off++];
  if (out->portal_count > VCS_SPACE_PORTAL_MAX ||
      !take(wire, wire_len, &off, out->portal_roots,
            (size_t)out->portal_count * 32u))
    goto limit_fail;
  if (off >= wire_len || wire[off] > 1u)
    goto size_fail;
  out->has_admission = wire[off++] != 0;
  if (out->has_admission &&
      !take(wire, wire_len, &off, out->admission_root, 32))
    goto size_fail;
  if (off + 2u > wire_len)
    goto size_fail;
  uint16_t delegation_len = zcl_read_u16_le(wire + off);
  off += 2;
  if (delegation_len != VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES ||
      off + delegation_len + 64u != wire_len)
    goto size_fail;
  if (vcs_zcode_dht_delegation_decode(&out->delegation, wire + off,
                                      delegation_len) !=
      VCS_ZCODE_DHT_DELEGATION_OK)
    goto delegation_fail;
  off += delegation_len;
  memcpy(out->signature, wire + off, 64);
  enum vcs_space_result checked = vcs_space_manifest_validate(out);
  if (checked != VCS_SPACE_OK)
    memset(out, 0, sizeof(*out));
  return checked;

limit_fail:
  memset(out, 0, sizeof(*out));
  return VCS_SPACE_ERR_LIMIT;
delegation_fail:
  memset(out, 0, sizeof(*out));
  return VCS_SPACE_ERR_DELEGATION;
size_fail:
  memset(out, 0, sizeof(*out));
  return VCS_SPACE_ERR_SIZE;
}

enum vcs_space_result vcs_space_manifest_root(
    const struct vcs_space_manifest_v1 *manifest, uint8_t out[32])
{
  if (!out)
    return VCS_SPACE_ERR_NULL;
  uint8_t wire[VCS_SPACE_MANIFEST_WIRE_MAX];
  size_t wire_len = 0;
  enum vcs_space_result encoded = vcs_space_manifest_encode(
      manifest, wire, sizeof(wire), &wire_len);
  if (encoded != VCS_SPACE_OK)
    return encoded;
  return vcs_signed_evidence_root(VCS_SPACE_MANIFEST_DOMAIN,
                                  strlen(VCS_SPACE_MANIFEST_DOMAIN),
                                  wire, wire_len, out)
             ? VCS_SPACE_OK : VCS_SPACE_ERR_NULL;
}
