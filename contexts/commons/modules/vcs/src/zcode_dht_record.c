/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical signed discovery and evidence DHT records. */

#include "vcs/zcode_dht_record.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "support/cleanse.h"

#include <string.h>

static const uint8_t record_magic[8] = {'Z', 'C', 'D', 'H',
                                        'T', 'R', 0x0d, 0x0a};

static bool record_zero(const uint8_t *value, size_t length)
{
  return !zcl_bytes_any_set(value, length);
}

const char *vcs_zcode_dht_record_error_string(
    enum vcs_zcode_dht_record_error error)
{
  switch (error) {
  case VCS_ZCODE_DHT_RECORD_OK: return "ok";
  case VCS_ZCODE_DHT_RECORD_NULL: return "null-argument";
  case VCS_ZCODE_DHT_RECORD_SIZE: return "wire-size";
  case VCS_ZCODE_DHT_RECORD_MAGIC: return "wire-magic";
  case VCS_ZCODE_DHT_RECORD_VERSION_ERROR: return "wire-version";
  case VCS_ZCODE_DHT_RECORD_KIND: return "record-kind";
  case VCS_ZCODE_DHT_RECORD_NAMESPACE: return "namespace";
  case VCS_ZCODE_DHT_RECORD_ROOT: return "root-shape";
  case VCS_ZCODE_DHT_RECORD_OWNER_GROUP: return "owner-group";
  case VCS_ZCODE_DHT_RECORD_SEQUENCE: return "record-sequence";
  case VCS_ZCODE_DHT_RECORD_WINDOW: return "validity-window";
  case VCS_ZCODE_DHT_RECORD_DELEGATION_WINDOW:
    return "delegation-window-coverage";
  case VCS_ZCODE_DHT_RECORD_NOT_YET_VALID: return "not-yet-valid";
  case VCS_ZCODE_DHT_RECORD_EXPIRED: return "expired";
  case VCS_ZCODE_DHT_RECORD_DELEGATION: return "delegation";
  case VCS_ZCODE_DHT_RECORD_NETWORK: return "wrong-network";
  case VCS_ZCODE_DHT_RECORD_PROVIDER_ID: return "provider-id";
  case VCS_ZCODE_DHT_RECORD_SIGNER: return "delegated-signer";
  case VCS_ZCODE_DHT_RECORD_SIGNATURE: return "record-signature";
  case VCS_ZCODE_DHT_RECORD_CHAIN: return "chain-authorization";
  }
  return "unknown";
}

static size_t namespace_length(const char name[VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES])
{
  size_t length = 0;
  while (length < VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES && name[length])
    length++;
  return length;
}

static bool namespace_valid(
    const char name[VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES], size_t *length_out)
{
  size_t length = namespace_length(name);
  if (length == 0 || length > VCS_ZCODE_DHT_RECORD_NAMESPACE_MAX)
    return false;
  for (size_t i = 0; i < length; i++) {
    unsigned char c = (unsigned char)name[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' ||
          c == '_' || c == '-'))
      return false;
  }
  for (size_t i = length; i < VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES; i++) {
    if (name[i] != '\0')
      return false;
  }
  if (length_out)
    *length_out = length;
  return true;
}

bool vcs_zcode_dht_record_key(
    const uint8_t network_genesis[32],
    enum vcs_zcode_dht_record_kind kind,
    const char namespace_name[VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES],
    const uint8_t root[32], uint8_t out[32])
{
  if (!network_genesis || !namespace_name || !root || !out ||
      !zcl_bytes_any_set(network_genesis, 32) || !zcl_bytes_any_set(root, 32) ||
      !namespace_valid(namespace_name, NULL) ||
      kind < VCS_ZCODE_DHT_RECORD_PROVIDER ||
      kind > VCS_ZCODE_DHT_RECORD_AGENT_SCOPE)
    return false;
  struct sha3_256_ctx hash;
  const uint8_t kind_byte = (uint8_t)kind;
  sha3_256_init(&hash);
  sha3_256_write(&hash, (const uint8_t *)VCS_ZCODE_DHT_RECORD_KEY_DOMAIN,
                 sizeof(VCS_ZCODE_DHT_RECORD_KEY_DOMAIN));
  sha3_256_write(&hash, network_genesis, 32);
  sha3_256_write(&hash, &kind_byte, sizeof(kind_byte));
  sha3_256_write(&hash, (const uint8_t *)namespace_name,
                 VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES);
  sha3_256_write(&hash, root, 32);
  sha3_256_finalize(&hash, out);
  return true;
}

static uint64_t max_window(enum vcs_zcode_dht_record_kind kind)
{
  switch (kind) {
  case VCS_ZCODE_DHT_RECORD_PROVIDER:
    return VCS_ZCODE_DHT_PROVIDER_MAX_SECONDS;
  case VCS_ZCODE_DHT_RECORD_POINTER:
    return VCS_ZCODE_DHT_POINTER_MAX_SECONDS;
  case VCS_ZCODE_DHT_RECORD_STORAGE_ACK:
    return VCS_ZCODE_DHT_STORAGE_ACK_MAX_SECONDS;
  case VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK:
    return VCS_ZCODE_DHT_SOURCE_REPRODUCTION_ACK_MAX_SECONDS;
  case VCS_ZCODE_DHT_RECORD_AGENT_SCOPE:
    return VCS_ZCODE_DHT_AGENT_SCOPE_MAX_SECONDS;
  }
  return 0;
}

static enum vcs_zcode_dht_record_error record_shape(
    const struct vcs_zcode_dht_record *record)
{
  if (!record)
    return VCS_ZCODE_DHT_RECORD_NULL;
  if (!max_window(record->kind))
    return VCS_ZCODE_DHT_RECORD_KIND;
  if (!namespace_valid(record->namespace_name, NULL))
    return VCS_ZCODE_DHT_RECORD_NAMESPACE;
  if (!zcl_bytes_any_set(record->network_genesis, 32) ||
      !zcl_bytes_any_set(record->transport_root, 32))
    return VCS_ZCODE_DHT_RECORD_ROOT;
  if (record->kind == VCS_ZCODE_DHT_RECORD_POINTER) {
    if (!zcl_bytes_any_set(record->semantic_root, 32) ||
        !record_zero(record->owner_group, 32))
      return zcl_bytes_any_set(record->owner_group, 32)
                 ? VCS_ZCODE_DHT_RECORD_OWNER_GROUP
                 : VCS_ZCODE_DHT_RECORD_ROOT;
  } else if (record->kind ==
             VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK) {
    if (!zcl_bytes_any_set(record->semantic_root, 32))
      return VCS_ZCODE_DHT_RECORD_ROOT;
  } else if (!record_zero(record->semantic_root, 32)) {
    return VCS_ZCODE_DHT_RECORD_ROOT;
  }
  if (record->kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK ||
      record->kind == VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK) {
    if (!zcl_bytes_any_set(record->owner_group, 32))
      return VCS_ZCODE_DHT_RECORD_OWNER_GROUP;
  } else if (!record_zero(record->owner_group, 32)) {
    return VCS_ZCODE_DHT_RECORD_OWNER_GROUP;
  }
  if (!zcl_bytes_any_set(record->provider_node_id, 32))
    return VCS_ZCODE_DHT_RECORD_PROVIDER_ID;
  if (!record->sequence || record->sequence > (uint64_t)INT64_MAX)
    return VCS_ZCODE_DHT_RECORD_SEQUENCE;
  uint64_t limit = max_window(record->kind);
  if (!record->not_before || record->expiry <= record->not_before ||
      record->expiry - record->not_before > limit)
    return VCS_ZCODE_DHT_RECORD_WINDOW;
  if (record->delegation.not_before > record->not_before ||
      record->delegation.doc.expiry < record->expiry)
    return VCS_ZCODE_DHT_RECORD_DELEGATION_WINDOW;
  return VCS_ZCODE_DHT_RECORD_OK;
}

static size_t record_write_unsigned(
    const struct vcs_zcode_dht_record *record,
    uint8_t wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES])
{
  size_t namespace_len = namespace_length(record->namespace_name);
  size_t off = 0;
  memcpy(wire + off, record_magic, sizeof(record_magic));
  off += sizeof(record_magic);
  zcl_write_u16_le(wire + off, VCS_ZCODE_DHT_RECORD_VERSION);
  off += 2;
  wire[off++] = (uint8_t)record->kind;
  wire[off++] = (uint8_t)namespace_len;
  memset(wire + off, 0, VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES);
  memcpy(wire + off, record->namespace_name, namespace_len);
  off += VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES;
  memcpy(wire + off, record->network_genesis, 32);
  off += 32;
  memcpy(wire + off, record->semantic_root, 32);
  off += 32;
  memcpy(wire + off, record->transport_root, 32);
  off += 32;
  memcpy(wire + off, record->provider_node_id, 32);
  off += 32;
  memcpy(wire + off, record->owner_group, 32);
  off += 32;
  zcl_write_u64_le(wire + off, record->sequence);
  off += 8;
  zcl_write_u64_le(wire + off, record->not_before);
  off += 8;
  zcl_write_u64_le(wire + off, record->expiry);
  off += 8;
  if (vcs_zcode_dht_delegation_encode(&record->delegation, wire + off) !=
      VCS_ZCODE_DHT_DELEGATION_OK)
    return 0;
  off += VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES;
  return off;
}

static enum vcs_zcode_dht_record_error record_delegation_binding(
    const struct vcs_zcode_dht_record *record)
{
  if (memcmp(record->delegation.network_genesis, record->network_genesis,
             32) != 0)
    return VCS_ZCODE_DHT_RECORD_NETWORK;
  uint8_t derived[32];
  if (!vcs_zcode_dht_delegation_node_id(derived, &record->delegation) ||
      memcmp(derived, record->provider_node_id, 32) != 0)
    return VCS_ZCODE_DHT_RECORD_PROVIDER_ID;
  return VCS_ZCODE_DHT_RECORD_OK;
}

static enum vcs_zcode_dht_record_error record_sign_bytes(
    uint8_t signature[64], const uint8_t *wire, size_t unsigned_len,
    const uint8_t online_seed[32],
    const struct vcs_zcode_dht_delegation *delegation)
{
  uint8_t pubkey[32], secret[32];
  ed25519_keypair(pubkey, secret, online_seed);
  if (memcmp(pubkey, delegation->online_pubkey, 32) != 0) {
    memory_cleanse(secret, sizeof(secret));
    return VCS_ZCODE_DHT_RECORD_SIGNER;
  }
  uint8_t preimage[sizeof(VCS_ZCODE_DHT_RECORD_SIGNATURE_DOMAIN) +
                   VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
  size_t off = 0;
  memcpy(preimage + off, VCS_ZCODE_DHT_RECORD_SIGNATURE_DOMAIN,
         sizeof(VCS_ZCODE_DHT_RECORD_SIGNATURE_DOMAIN));
  off += sizeof(VCS_ZCODE_DHT_RECORD_SIGNATURE_DOMAIN);
  memcpy(preimage + off, wire, unsigned_len);
  off += unsigned_len;
  ed25519_sign(signature, preimage, off, secret, pubkey);
  memory_cleanse(secret, sizeof(secret));
  memory_cleanse(preimage, off);
  return VCS_ZCODE_DHT_RECORD_OK;
}

enum vcs_zcode_dht_record_error vcs_zcode_dht_record_sign(
    struct vcs_zcode_dht_record *record, const uint8_t online_seed[32])
{
  if (!record || !online_seed)
    return VCS_ZCODE_DHT_RECORD_NULL;
  enum vcs_zcode_dht_record_error error = record_shape(record);
  if (error != VCS_ZCODE_DHT_RECORD_OK)
    return error;
  error = record_delegation_binding(record);
  if (error != VCS_ZCODE_DHT_RECORD_OK)
    return error;
  if (vcs_zcode_dht_delegation_verify(
          &record->delegation, record->network_genesis, NULL, 0, NULL,
          record->not_before) != VCS_ZCODE_DHT_DELEGATION_OK)
    return VCS_ZCODE_DHT_RECORD_DELEGATION;
  uint8_t wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
  size_t unsigned_len = record_write_unsigned(record, wire);
  if (!unsigned_len)
    return VCS_ZCODE_DHT_RECORD_DELEGATION;
  return record_sign_bytes(record->signature, wire, unsigned_len, online_seed,
                           &record->delegation);
}

enum vcs_zcode_dht_record_error vcs_zcode_dht_record_encode(
    const struct vcs_zcode_dht_record *record,
    uint8_t wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES])
{
  if (!record || !wire)
    return VCS_ZCODE_DHT_RECORD_NULL;
  enum vcs_zcode_dht_record_error error = record_shape(record);
  if (error != VCS_ZCODE_DHT_RECORD_OK)
    return error;
  error = record_delegation_binding(record);
  if (error != VCS_ZCODE_DHT_RECORD_OK)
    return error;
  if (!zcl_bytes_any_set(record->signature, sizeof(record->signature)))
    return VCS_ZCODE_DHT_RECORD_SIGNATURE;
  size_t off = record_write_unsigned(record, wire);
  if (!off)
    return VCS_ZCODE_DHT_RECORD_DELEGATION;
  memcpy(wire + off, record->signature, sizeof(record->signature));
  off += sizeof(record->signature);
  return off == VCS_ZCODE_DHT_RECORD_WIRE_BYTES ? VCS_ZCODE_DHT_RECORD_OK
                                                : VCS_ZCODE_DHT_RECORD_SIZE;
}

enum vcs_zcode_dht_record_error vcs_zcode_dht_record_id(
    const struct vcs_zcode_dht_record *record, uint8_t out[32])
{
  if (!record || !out)
    return VCS_ZCODE_DHT_RECORD_NULL;
  uint8_t wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
  enum vcs_zcode_dht_record_error error =
      vcs_zcode_dht_record_encode(record, wire);
  if (error != VCS_ZCODE_DHT_RECORD_OK) {
    memset(out, 0, 32);
    return error;
  }
  struct sha3_256_ctx sha;
  sha3_256_init(&sha);
  sha3_256_write(&sha, (const uint8_t *)VCS_ZCODE_DHT_RECORD_ID_DOMAIN,
                 sizeof(VCS_ZCODE_DHT_RECORD_ID_DOMAIN));
  sha3_256_write(&sha, wire, sizeof(wire));
  sha3_256_finalize(&sha, out);
  return VCS_ZCODE_DHT_RECORD_OK;
}

static enum vcs_zcode_dht_record_error record_read_unsigned(
    const uint8_t *wire, struct vcs_zcode_dht_record *record,
    size_t *unsigned_len)
{
  if (memcmp(wire, record_magic, sizeof(record_magic)) != 0)
    return VCS_ZCODE_DHT_RECORD_MAGIC;
  if (zcl_read_u16_le(wire + 8) != VCS_ZCODE_DHT_RECORD_VERSION)
    return VCS_ZCODE_DHT_RECORD_VERSION_ERROR;
  uint8_t kind = wire[10], namespace_len = wire[11];
  if (!max_window((enum vcs_zcode_dht_record_kind)kind))
    return VCS_ZCODE_DHT_RECORD_KIND;
  if (namespace_len == 0 || namespace_len > VCS_ZCODE_DHT_RECORD_NAMESPACE_MAX)
    return VCS_ZCODE_DHT_RECORD_NAMESPACE;
  size_t off = 12;
  memcpy(record->namespace_name, wire + off, namespace_len);
  for (size_t i = namespace_len; i < VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES;
       i++) {
    if (wire[off + i] != 0)
      return VCS_ZCODE_DHT_RECORD_NAMESPACE;
  }
  off += VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES;
  record->kind = (enum vcs_zcode_dht_record_kind)kind;
  memcpy(record->network_genesis, wire + off, 32);
  off += 32;
  memcpy(record->semantic_root, wire + off, 32);
  off += 32;
  memcpy(record->transport_root, wire + off, 32);
  off += 32;
  memcpy(record->provider_node_id, wire + off, 32);
  off += 32;
  memcpy(record->owner_group, wire + off, 32);
  off += 32;
  record->sequence = zcl_read_u64_le(wire + off);
  off += 8;
  record->not_before = zcl_read_u64_le(wire + off);
  off += 8;
  record->expiry = zcl_read_u64_le(wire + off);
  off += 8;
  if (vcs_zcode_dht_delegation_decode(
          &record->delegation, wire + off,
          VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES) !=
      VCS_ZCODE_DHT_DELEGATION_OK)
    return VCS_ZCODE_DHT_RECORD_DELEGATION;
  off += VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES;
  memcpy(record->signature, wire + off, sizeof(record->signature));
  *unsigned_len = off;
  return record_shape(record);
}

static bool record_signature_valid(const struct vcs_zcode_dht_record *record,
                                   const uint8_t *wire, size_t unsigned_len)
{
  uint8_t preimage[sizeof(VCS_ZCODE_DHT_RECORD_SIGNATURE_DOMAIN) +
                   VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
  size_t off = 0;
  memcpy(preimage + off, VCS_ZCODE_DHT_RECORD_SIGNATURE_DOMAIN,
         sizeof(VCS_ZCODE_DHT_RECORD_SIGNATURE_DOMAIN));
  off += sizeof(VCS_ZCODE_DHT_RECORD_SIGNATURE_DOMAIN);
  memcpy(preimage + off, wire, unsigned_len);
  off += unsigned_len;
  bool valid = ed25519_verify(record->signature, preimage, off,
                              record->delegation.online_pubkey);
  memory_cleanse(preimage, off);
  return valid;
}

enum vcs_zcode_dht_record_error vcs_zcode_dht_record_parse(
    const uint8_t *wire, size_t wire_len,
    const struct vcs_zcode_dht_record_verify_context *verify,
    struct vcs_zcode_dht_record *out)
{
  if (!out)
    return VCS_ZCODE_DHT_RECORD_NULL;
  memset(out, 0, sizeof(*out));
  if (!wire || !verify)
    return VCS_ZCODE_DHT_RECORD_NULL;
  if (wire_len != VCS_ZCODE_DHT_RECORD_WIRE_BYTES)
    return VCS_ZCODE_DHT_RECORD_SIZE;
  struct vcs_zcode_dht_record parsed;
  memset(&parsed, 0, sizeof(parsed));
  size_t unsigned_len = 0;
  enum vcs_zcode_dht_record_error error =
      record_read_unsigned(wire, &parsed, &unsigned_len);
  if (error != VCS_ZCODE_DHT_RECORD_OK)
    return error;
  if (memcmp(parsed.network_genesis, verify->network_genesis, 32) != 0)
    return VCS_ZCODE_DHT_RECORD_NETWORK;
  error = record_delegation_binding(&parsed);
  if (error != VCS_ZCODE_DHT_RECORD_OK)
    return error;
  if (verify->now_unix < parsed.not_before)
    return VCS_ZCODE_DHT_RECORD_NOT_YET_VALID;
  if (verify->now_unix >= parsed.expiry)
    return VCS_ZCODE_DHT_RECORD_EXPIRED;
  if (vcs_zcode_dht_delegation_verify(
          &parsed.delegation, verify->network_genesis, NULL, 0, NULL,
          verify->now_unix) != VCS_ZCODE_DHT_DELEGATION_OK)
    return VCS_ZCODE_DHT_RECORD_DELEGATION;
  if (!record_signature_valid(&parsed, wire, unsigned_len))
    return VCS_ZCODE_DHT_RECORD_SIGNATURE;
  if (verify->chain_verify &&
      !verify->chain_verify(verify->chain_ctx, &parsed.delegation))
    return VCS_ZCODE_DHT_RECORD_CHAIN;
  *out = parsed;
  return VCS_ZCODE_DHT_RECORD_OK;
}

enum vcs_zcode_dht_record_error vcs_zcode_dht_record_parse_persisted(
    const uint8_t *wire, size_t wire_len,
    const struct vcs_zcode_dht_record_verify_context *verify,
    bool *expired_out, struct vcs_zcode_dht_record *out)
{
  if (expired_out)
    *expired_out = false;
  if (!out)
    return VCS_ZCODE_DHT_RECORD_NULL;
  memset(out, 0, sizeof(*out));
  if (!wire || !verify || !expired_out)
    return VCS_ZCODE_DHT_RECORD_NULL;
  if (wire_len != VCS_ZCODE_DHT_RECORD_WIRE_BYTES)
    return VCS_ZCODE_DHT_RECORD_SIZE;
  struct vcs_zcode_dht_record parsed;
  memset(&parsed, 0, sizeof(parsed));
  size_t unsigned_len = 0;
  enum vcs_zcode_dht_record_error error =
      record_read_unsigned(wire, &parsed, &unsigned_len);
  if (error != VCS_ZCODE_DHT_RECORD_OK)
    return error;
  if (memcmp(parsed.network_genesis, verify->network_genesis, 32) != 0)
    return VCS_ZCODE_DHT_RECORD_NETWORK;
  error = record_delegation_binding(&parsed);
  if (error != VCS_ZCODE_DHT_RECORD_OK)
    return error;
  if (verify->now_unix < parsed.not_before)
    return VCS_ZCODE_DHT_RECORD_NOT_YET_VALID;
  uint64_t signature_time = verify->now_unix < parsed.expiry
                                ? verify->now_unix
                                : parsed.not_before;
  if (vcs_zcode_dht_delegation_verify(
          &parsed.delegation, verify->network_genesis, NULL, 0, NULL,
          signature_time) != VCS_ZCODE_DHT_DELEGATION_OK)
    return VCS_ZCODE_DHT_RECORD_DELEGATION;
  if (!record_signature_valid(&parsed, wire, unsigned_len))
    return VCS_ZCODE_DHT_RECORD_SIGNATURE;
  if (verify->chain_verify &&
      !verify->chain_verify(verify->chain_ctx, &parsed.delegation))
    return VCS_ZCODE_DHT_RECORD_CHAIN;
  *expired_out = verify->now_unix >= parsed.expiry;
  *out = parsed;
  return VCS_ZCODE_DHT_RECORD_OK;
}

static bool record_slot_equal(const struct vcs_zcode_dht_record *a,
                              const struct vcs_zcode_dht_record *b)
{
  if (a->kind != b->kind || a->sequence != b->sequence ||
      strcmp(a->namespace_name, b->namespace_name) != 0 ||
      memcmp(a->network_genesis, b->network_genesis, 32) != 0 ||
      memcmp(a->provider_node_id, b->provider_node_id, 32) != 0 ||
      memcmp(a->delegation.doc.master_pubkey,
             b->delegation.doc.master_pubkey, 32) != 0)
    return false;
  if (a->kind == VCS_ZCODE_DHT_RECORD_POINTER)
    return memcmp(a->semantic_root, b->semantic_root, 32) == 0;
  return memcmp(a->transport_root, b->transport_root, 32) == 0;
}

static bool record_content_equal(const struct vcs_zcode_dht_record *a,
                                 const struct vcs_zcode_dht_record *b)
{
  uint8_t ad[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES];
  uint8_t bd[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES];
  if (vcs_zcode_dht_delegation_encode(&a->delegation, ad) !=
          VCS_ZCODE_DHT_DELEGATION_OK ||
      vcs_zcode_dht_delegation_encode(&b->delegation, bd) !=
          VCS_ZCODE_DHT_DELEGATION_OK)
    return false;
  return a->kind == b->kind &&
         strcmp(a->namespace_name, b->namespace_name) == 0 &&
         memcmp(a->network_genesis, b->network_genesis, 32) == 0 &&
         memcmp(a->semantic_root, b->semantic_root, 32) == 0 &&
         memcmp(a->transport_root, b->transport_root, 32) == 0 &&
         memcmp(a->provider_node_id, b->provider_node_id, 32) == 0 &&
         memcmp(a->owner_group, b->owner_group, 32) == 0 &&
         a->sequence == b->sequence && a->not_before == b->not_before &&
         a->expiry == b->expiry && memcmp(ad, bd, sizeof(ad)) == 0 &&
         memcmp(a->signature, b->signature, sizeof(a->signature)) == 0;
}

bool vcs_zcode_dht_record_conflicts(
    const struct vcs_zcode_dht_record *a,
    const struct vcs_zcode_dht_record *b)
{
  if (!a || !b || a == b || !record_slot_equal(a, b))
    return false;
  return !record_content_equal(a, b);
}

bool vcs_zcode_dht_record_same_stream(
    const struct vcs_zcode_dht_record *a,
    const struct vcs_zcode_dht_record *b)
{
  if (!a || !b || a->kind != b->kind ||
      strcmp(a->namespace_name, b->namespace_name) != 0 ||
      memcmp(a->network_genesis, b->network_genesis, 32) != 0 ||
      memcmp(a->provider_node_id, b->provider_node_id, 32) != 0 ||
      memcmp(a->delegation.doc.master_pubkey,
             b->delegation.doc.master_pubkey, 32) != 0)
    return false;
  const uint8_t *a_root = a->kind == VCS_ZCODE_DHT_RECORD_POINTER
                              ? a->semantic_root : a->transport_root;
  const uint8_t *b_root = b->kind == VCS_ZCODE_DHT_RECORD_POINTER
                              ? b->semantic_root : b->transport_root;
  return memcmp(a_root, b_root, 32) == 0;
}

bool vcs_zcode_dht_record_conflicted_at(
    const struct vcs_zcode_dht_record *records, size_t count, size_t index)
{
  uint8_t wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
  if (!records || index >= count ||
      vcs_zcode_dht_record_encode(&records[index], wire) !=
          VCS_ZCODE_DHT_RECORD_OK)
    return false;
  for (size_t i = 0; i < count; i++)
    if (i != index && vcs_zcode_dht_record_conflicts(&records[index],
                                                      &records[i]))
      return true;
  return false;
}

bool vcs_zcode_dht_record_superseded_at(
    const struct vcs_zcode_dht_record *records, size_t count, size_t index)
{
  if (!records || index >= count ||
      vcs_zcode_dht_record_conflicted_at(records, count, index))
    return false;
  for (size_t i = 0; i < count; i++)
    if (i != index &&
        !vcs_zcode_dht_record_conflicted_at(records, count, i) &&
        vcs_zcode_dht_record_same_stream(&records[index], &records[i]) &&
        records[i].sequence > records[index].sequence)
      return true;
  return false;
}
