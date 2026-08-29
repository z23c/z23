/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Strict allocation-free mesh status wire codec and receipt proof. */

#include "session/mesh_status_proto.h"

#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"

#include <string.h>

static const uint8_t request_magic[8] = {'Z', 'M', 'S', 'Q', '1', 0, 0, 0};
static const uint8_t receipt_magic[8] = {'Z', 'M', 'S', 'R', '1', 0, 0, 0};
static const char request_root_domain[] = "zcl.mesh.status.request.v1";
static const char capsule_root_domain[] = "zcl.mesh.status.capsule.v1";
static const char receipt_signature_domain[] =
    "zcl.mesh.status.receipt.signature.v1";
static const char receipt_root_domain[] = "zcl.mesh.status.receipt.v1";

#define RECEIPT_UNSIGNED_FIXED_BYTES 344u

static bool bytes_nonzero(const uint8_t *bytes, size_t count)
{
    if (!bytes)
        return false;
    uint8_t any = 0;
    for (size_t i = 0; i < count; i++)
        any |= bytes[i];
    return any != 0;
}

static bool lifetime_valid(uint64_t issued, uint64_t expires)
{
    return issued != 0 && expires > issued &&
           expires - issued <= MESH_STATUS_MAX_LIFETIME_SECONDS;
}

const char *mesh_status_proto_error_string(enum mesh_status_proto_error error)
{
    switch (error) {
    case MESH_STATUS_PROTO_OK: return "ok";
    case MESH_STATUS_PROTO_NULL: return "null";
    case MESH_STATUS_PROTO_SIZE: return "size";
    case MESH_STATUS_PROTO_MAGIC: return "magic";
    case MESH_STATUS_PROTO_VERSION_INVALID: return "version";
    case MESH_STATUS_PROTO_FLAGS: return "flags";
    case MESH_STATUS_PROTO_CAPABILITY: return "capability";
    case MESH_STATUS_PROTO_FIELD: return "field";
    case MESH_STATUS_PROTO_TIME: return "time";
    case MESH_STATUS_PROTO_STATUS: return "status";
    case MESH_STATUS_PROTO_CAPSULE_ROOT: return "capsule-root";
    case MESH_STATUS_PROTO_KEY_MISMATCH: return "key-mismatch";
    case MESH_STATUS_PROTO_SIGNATURE: return "signature";
    }
    return "unknown";
}

const char *mesh_status_receipt_status_string(
    enum mesh_status_receipt_status status)
{
    switch (status) {
    case MESH_STATUS_RECEIPT_OK: return "ok";
    case MESH_STATUS_RECEIPT_BAD_REQUEST: return "bad-request";
    case MESH_STATUS_RECEIPT_CAPABILITY_UNAVAILABLE:
        return "capability-unavailable";
    case MESH_STATUS_RECEIPT_NOT_PAIRED: return "not-paired";
    case MESH_STATUS_RECEIPT_REVOKED: return "revoked";
    case MESH_STATUS_RECEIPT_EXPIRED: return "expired";
    case MESH_STATUS_RECEIPT_SESSION_MISMATCH: return "session-mismatch";
    case MESH_STATUS_RECEIPT_AUTHORITY_CHANGED: return "authority-changed";
    case MESH_STATUS_RECEIPT_DELEGATION_INVALID: return "delegation-invalid";
    case MESH_STATUS_RECEIPT_INTERNAL: return "internal";
    }
    return "unknown";
}

static enum mesh_status_proto_error request_shape(
    const struct mesh_status_request_v1 *request)
{
    if (!request)
        return MESH_STATUS_PROTO_NULL;
    if (request->version != MESH_STATUS_PROTO_VERSION)
        return MESH_STATUS_PROTO_VERSION_INVALID;
    if (request->flags != MESH_STATUS_PROTO_FLAGS_NONE)
        return MESH_STATUS_PROTO_FLAGS;
    if (request->capability != MESH_STATUS_CAP_STATUS_READ)
        return MESH_STATUS_PROTO_CAPABILITY;
    const uint8_t *critical[] = {
        request->request_id, request->network_genesis,
        request->target_master_pubkey, request->requester_master_pubkey,
        request->requester_noise_static, request->pairing_id,
        request->transcript_hash,
    };
    for (size_t i = 0; i < sizeof(critical) / sizeof(critical[0]); i++)
        if (!bytes_nonzero(critical[i], 32))
            return MESH_STATUS_PROTO_FIELD;
    if (request->connection_generation == 0 ||
        request->connection_serial == 0)
        return MESH_STATUS_PROTO_FIELD;
    return lifetime_valid(request->issued_unix, request->expires_unix)
               ? MESH_STATUS_PROTO_OK
               : MESH_STATUS_PROTO_TIME;
}

enum mesh_status_proto_error mesh_status_request_v1_validate(
    const struct mesh_status_request_v1 *request)
{
    return request_shape(request);
}

static size_t request_write(const struct mesh_status_request_v1 *request,
                            uint8_t out[MESH_STATUS_REQUEST_V1_WIRE_BYTES])
{
    size_t off = 0;
    memcpy(out + off, request_magic, sizeof(request_magic)); off += 8;
    zcl_write_u16_le(out + off, request->version); off += 2;
    zcl_write_u16_le(out + off, request->flags); off += 2;
    zcl_write_u64_le(out + off, request->capability); off += 8;
    memcpy(out + off, request->request_id, 32); off += 32;
    memcpy(out + off, request->network_genesis, 32); off += 32;
    memcpy(out + off, request->target_master_pubkey, 32); off += 32;
    memcpy(out + off, request->requester_master_pubkey, 32); off += 32;
    memcpy(out + off, request->requester_noise_static, 32); off += 32;
    memcpy(out + off, request->pairing_id, 32); off += 32;
    memcpy(out + off, request->transcript_hash, 32); off += 32;
    zcl_write_u64_le(out + off, request->connection_generation); off += 8;
    zcl_write_u64_le(out + off, request->connection_serial); off += 8;
    zcl_write_u64_le(out + off, request->issued_unix); off += 8;
    zcl_write_u64_le(out + off, request->expires_unix); off += 8;
    return off;
}

enum mesh_status_proto_error mesh_status_request_v1_encode(
    const struct mesh_status_request_v1 *request,
    uint8_t out[MESH_STATUS_REQUEST_V1_WIRE_BYTES])
{
    if (!out)
        return MESH_STATUS_PROTO_NULL;
    enum mesh_status_proto_error error = request_shape(request);
    if (error != MESH_STATUS_PROTO_OK)
        return error;
    return request_write(request, out) == MESH_STATUS_REQUEST_V1_WIRE_BYTES
               ? MESH_STATUS_PROTO_OK
               : MESH_STATUS_PROTO_SIZE;
}

enum mesh_status_proto_error mesh_status_request_v1_decode(
    struct mesh_status_request_v1 *out, const uint8_t *wire, size_t wire_len)
{
    if (!out || !wire)
        return MESH_STATUS_PROTO_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != MESH_STATUS_REQUEST_V1_WIRE_BYTES)
        return MESH_STATUS_PROTO_SIZE;
    if (memcmp(wire, request_magic, sizeof(request_magic)) != 0)
        return MESH_STATUS_PROTO_MAGIC;
    size_t off = 8;
    out->version = zcl_read_u16_le(wire + off); off += 2;
    out->flags = zcl_read_u16_le(wire + off); off += 2;
    out->capability = zcl_read_u64_le(wire + off); off += 8;
    memcpy(out->request_id, wire + off, 32); off += 32;
    memcpy(out->network_genesis, wire + off, 32); off += 32;
    memcpy(out->target_master_pubkey, wire + off, 32); off += 32;
    memcpy(out->requester_master_pubkey, wire + off, 32); off += 32;
    memcpy(out->requester_noise_static, wire + off, 32); off += 32;
    memcpy(out->pairing_id, wire + off, 32); off += 32;
    memcpy(out->transcript_hash, wire + off, 32); off += 32;
    out->connection_generation = zcl_read_u64_le(wire + off); off += 8;
    out->connection_serial = zcl_read_u64_le(wire + off); off += 8;
    out->issued_unix = zcl_read_u64_le(wire + off); off += 8;
    out->expires_unix = zcl_read_u64_le(wire + off); off += 8;
    enum mesh_status_proto_error error =
        off == wire_len ? request_shape(out) : MESH_STATUS_PROTO_SIZE;
    if (error != MESH_STATUS_PROTO_OK)
        memset(out, 0, sizeof(*out));
    return error;
}

static void hash_bytes(const char *domain, const uint8_t *bytes, size_t count,
                       uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, strlen(domain));
    if (count != 0)
        sha3_256_write(&sha, bytes, count);
    sha3_256_finalize(&sha, out);
}

enum mesh_status_proto_error mesh_status_request_v1_root(
    const struct mesh_status_request_v1 *request, uint8_t out[32])
{
    if (!out)
        return MESH_STATUS_PROTO_NULL;
    memset(out, 0, 32);
    uint8_t wire[MESH_STATUS_REQUEST_V1_WIRE_BYTES];
    enum mesh_status_proto_error error =
        mesh_status_request_v1_encode(request, wire);
    if (error != MESH_STATUS_PROTO_OK)
        return error;
    hash_bytes(request_root_domain, wire, sizeof(wire), out);
    return MESH_STATUS_PROTO_OK;
}

enum mesh_status_proto_error mesh_status_capsule_v1_root(
    const uint8_t *capsule, size_t capsule_len, uint8_t out[32])
{
    if (!out || (!capsule && capsule_len != 0))
        return MESH_STATUS_PROTO_NULL;
    memset(out, 0, 32);
    if (capsule_len > MESH_STATUS_CAPSULE_MAX)
        return MESH_STATUS_PROTO_SIZE;
    uint8_t encoded_len[2];
    zcl_write_u16_le(encoded_len, (uint16_t)capsule_len);
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)capsule_root_domain,
                   sizeof(capsule_root_domain) - 1u);
    sha3_256_write(&sha, encoded_len, sizeof(encoded_len));
    if (capsule_len != 0)
        sha3_256_write(&sha, capsule, capsule_len);
    sha3_256_finalize(&sha, out);
    return MESH_STATUS_PROTO_OK;
}

static bool receipt_status_valid(enum mesh_status_receipt_status status)
{
    return status >= MESH_STATUS_RECEIPT_OK &&
           status <= MESH_STATUS_RECEIPT_INTERNAL;
}

static enum mesh_status_proto_error receipt_shape(
    const struct mesh_status_receipt_v1 *receipt, bool require_signature)
{
    if (!receipt)
        return MESH_STATUS_PROTO_NULL;
    if (receipt->version != MESH_STATUS_PROTO_VERSION)
        return MESH_STATUS_PROTO_VERSION_INVALID;
    if (receipt->flags != MESH_STATUS_PROTO_FLAGS_NONE)
        return MESH_STATUS_PROTO_FLAGS;
    if (!receipt_status_valid(receipt->status))
        return MESH_STATUS_PROTO_STATUS;
    if (receipt->capsule_len > MESH_STATUS_CAPSULE_MAX)
        return MESH_STATUS_PROTO_SIZE;
    if ((receipt->status == MESH_STATUS_RECEIPT_OK &&
         receipt->capsule_len == 0) ||
        (receipt->status != MESH_STATUS_RECEIPT_OK &&
         receipt->capsule_len != 0))
        return MESH_STATUS_PROTO_STATUS;
    const uint8_t *critical[] = {
        receipt->request_id, receipt->request_root,
        receipt->network_genesis, receipt->pairing_id,
        receipt->responder_master_pubkey, receipt->responder_online_pubkey,
        receipt->responder_noise_static, receipt->transcript_hash,
    };
    for (size_t i = 0; i < sizeof(critical) / sizeof(critical[0]); i++)
        if (!bytes_nonzero(critical[i], 32))
            return MESH_STATUS_PROTO_FIELD;
    if (receipt->connection_generation == 0 ||
        receipt->connection_serial == 0)
        return MESH_STATUS_PROTO_FIELD;
    if (!lifetime_valid(receipt->observed_unix, receipt->expires_unix))
        return MESH_STATUS_PROTO_TIME;
    uint8_t capsule_root[32];
    enum mesh_status_proto_error error = mesh_status_capsule_v1_root(
        receipt->capsule, receipt->capsule_len, capsule_root);
    bool root_ok = error == MESH_STATUS_PROTO_OK &&
                   memcmp(capsule_root, receipt->capsule_root, 32) == 0;
    memory_cleanse(capsule_root, sizeof(capsule_root));
    if (!root_ok)
        return MESH_STATUS_PROTO_CAPSULE_ROOT;
    if (require_signature && !bytes_nonzero(receipt->signature, 64))
        return MESH_STATUS_PROTO_SIGNATURE;
    return MESH_STATUS_PROTO_OK;
}

static size_t receipt_write_unsigned(
    const struct mesh_status_receipt_v1 *receipt,
    uint8_t out[RECEIPT_UNSIGNED_FIXED_BYTES])
{
    size_t off = 0;
    memcpy(out + off, receipt_magic, sizeof(receipt_magic)); off += 8;
    zcl_write_u16_le(out + off, receipt->version); off += 2;
    zcl_write_u16_le(out + off, receipt->flags); off += 2;
    zcl_write_u16_le(out + off, (uint16_t)receipt->status); off += 2;
    zcl_write_u16_le(out + off, receipt->capsule_len); off += 2;
    memcpy(out + off, receipt->request_id, 32); off += 32;
    memcpy(out + off, receipt->request_root, 32); off += 32;
    memcpy(out + off, receipt->network_genesis, 32); off += 32;
    memcpy(out + off, receipt->pairing_id, 32); off += 32;
    memcpy(out + off, receipt->responder_master_pubkey, 32); off += 32;
    memcpy(out + off, receipt->responder_online_pubkey, 32); off += 32;
    memcpy(out + off, receipt->responder_noise_static, 32); off += 32;
    memcpy(out + off, receipt->transcript_hash, 32); off += 32;
    zcl_write_u64_le(out + off, receipt->connection_generation); off += 8;
    zcl_write_u64_le(out + off, receipt->connection_serial); off += 8;
    zcl_write_u64_le(out + off, receipt->revocation_generation); off += 8;
    zcl_write_u64_le(out + off, receipt->observed_unix); off += 8;
    zcl_write_u64_le(out + off, receipt->expires_unix); off += 8;
    memcpy(out + off, receipt->capsule_root, 32); off += 32;
    return off;
}

static enum mesh_status_proto_error receipt_signing_root(
    const struct mesh_status_receipt_v1 *receipt, uint8_t out[32])
{
    enum mesh_status_proto_error error = receipt_shape(receipt, false);
    if (error != MESH_STATUS_PROTO_OK)
        return error;
    uint8_t fixed[RECEIPT_UNSIGNED_FIXED_BYTES];
    if (receipt_write_unsigned(receipt, fixed) != sizeof(fixed))
        return MESH_STATUS_PROTO_SIZE;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)receipt_signature_domain,
                   sizeof(receipt_signature_domain) - 1u);
    sha3_256_write(&sha, fixed, sizeof(fixed));
    if (receipt->capsule_len != 0)
        sha3_256_write(&sha, receipt->capsule, receipt->capsule_len);
    sha3_256_finalize(&sha, out);
    return MESH_STATUS_PROTO_OK;
}

size_t mesh_status_receipt_v1_wire_size(
    const struct mesh_status_receipt_v1 *receipt)
{
    return receipt && receipt->capsule_len <= MESH_STATUS_CAPSULE_MAX
               ? MESH_STATUS_RECEIPT_V1_FIXED_BYTES + receipt->capsule_len
               : 0;
}

enum mesh_status_proto_error mesh_status_receipt_v1_validate(
    const struct mesh_status_receipt_v1 *receipt)
{
    enum mesh_status_proto_error error = receipt_shape(receipt, true);
    if (error != MESH_STATUS_PROTO_OK)
        return error;
    uint8_t root[32];
    error = receipt_signing_root(receipt, root);
    bool valid = error == MESH_STATUS_PROTO_OK &&
                 ed25519_verify(receipt->signature, root, sizeof(root),
                                receipt->responder_online_pubkey);
    memory_cleanse(root, sizeof(root));
    return valid ? MESH_STATUS_PROTO_OK : MESH_STATUS_PROTO_SIGNATURE;
}

enum mesh_status_proto_error mesh_status_receipt_v1_sign(
    struct mesh_status_receipt_v1 *receipt,
    const uint8_t responder_online_seed[32])
{
    if (!receipt || !responder_online_seed)
        return MESH_STATUS_PROTO_NULL;
    memset(receipt->signature, 0, sizeof(receipt->signature));
    uint8_t public_key[32], secret[32], root[32];
    ed25519_keypair(public_key, secret, responder_online_seed);
    if (memcmp(public_key, receipt->responder_online_pubkey, 32) != 0) {
        memory_cleanse(secret, sizeof(secret));
        return MESH_STATUS_PROTO_KEY_MISMATCH;
    }
    enum mesh_status_proto_error error = receipt_signing_root(receipt, root);
    if (error == MESH_STATUS_PROTO_OK)
        ed25519_sign(receipt->signature, root, sizeof(root), secret, public_key);
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(root, sizeof(root));
    return error == MESH_STATUS_PROTO_OK
               ? mesh_status_receipt_v1_validate(receipt)
               : error;
}

enum mesh_status_proto_error mesh_status_receipt_v1_encode(
    const struct mesh_status_receipt_v1 *receipt, uint8_t *out,
    size_t out_capacity, size_t *out_len)
{
    if (out_len)
        *out_len = 0;
    if (!receipt || !out || !out_len)
        return MESH_STATUS_PROTO_NULL;
    enum mesh_status_proto_error error =
        mesh_status_receipt_v1_validate(receipt);
    if (error != MESH_STATUS_PROTO_OK)
        return error;
    size_t needed = mesh_status_receipt_v1_wire_size(receipt);
    if (needed == 0 || out_capacity < needed)
        return MESH_STATUS_PROTO_SIZE;
    size_t off = receipt_write_unsigned(receipt, out);
    memcpy(out + off, receipt->capsule, receipt->capsule_len);
    off += receipt->capsule_len;
    memcpy(out + off, receipt->signature, 64);
    off += 64;
    if (off != needed)
        return MESH_STATUS_PROTO_SIZE;
    *out_len = off;
    return MESH_STATUS_PROTO_OK;
}

enum mesh_status_proto_error mesh_status_receipt_v1_decode(
    struct mesh_status_receipt_v1 *out, const uint8_t *wire, size_t wire_len)
{
    if (!out || !wire)
        return MESH_STATUS_PROTO_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len < MESH_STATUS_RECEIPT_V1_FIXED_BYTES ||
        wire_len > MESH_STATUS_RECEIPT_V1_MAX_WIRE_BYTES)
        return MESH_STATUS_PROTO_SIZE;
    if (memcmp(wire, receipt_magic, sizeof(receipt_magic)) != 0)
        return MESH_STATUS_PROTO_MAGIC;
    size_t off = 8;
    out->version = zcl_read_u16_le(wire + off); off += 2;
    out->flags = zcl_read_u16_le(wire + off); off += 2;
    out->status = (enum mesh_status_receipt_status)
        zcl_read_u16_le(wire + off); off += 2;
    out->capsule_len = zcl_read_u16_le(wire + off); off += 2;
    size_t expected = MESH_STATUS_RECEIPT_V1_FIXED_BYTES + out->capsule_len;
    if (out->capsule_len > MESH_STATUS_CAPSULE_MAX || wire_len != expected) {
        memset(out, 0, sizeof(*out));
        return MESH_STATUS_PROTO_SIZE;
    }
    memcpy(out->request_id, wire + off, 32); off += 32;
    memcpy(out->request_root, wire + off, 32); off += 32;
    memcpy(out->network_genesis, wire + off, 32); off += 32;
    memcpy(out->pairing_id, wire + off, 32); off += 32;
    memcpy(out->responder_master_pubkey, wire + off, 32); off += 32;
    memcpy(out->responder_online_pubkey, wire + off, 32); off += 32;
    memcpy(out->responder_noise_static, wire + off, 32); off += 32;
    memcpy(out->transcript_hash, wire + off, 32); off += 32;
    out->connection_generation = zcl_read_u64_le(wire + off); off += 8;
    out->connection_serial = zcl_read_u64_le(wire + off); off += 8;
    out->revocation_generation = zcl_read_u64_le(wire + off); off += 8;
    out->observed_unix = zcl_read_u64_le(wire + off); off += 8;
    out->expires_unix = zcl_read_u64_le(wire + off); off += 8;
    memcpy(out->capsule_root, wire + off, 32); off += 32;
    memcpy(out->capsule, wire + off, out->capsule_len);
    off += out->capsule_len;
    memcpy(out->signature, wire + off, 64); off += 64;
    enum mesh_status_proto_error error =
        off == wire_len ? mesh_status_receipt_v1_validate(out)
                        : MESH_STATUS_PROTO_SIZE;
    if (error != MESH_STATUS_PROTO_OK)
        memset(out, 0, sizeof(*out));
    return error;
}

enum mesh_status_proto_error mesh_status_receipt_v1_root(
    const struct mesh_status_receipt_v1 *receipt, uint8_t out[32])
{
    if (!out)
        return MESH_STATUS_PROTO_NULL;
    memset(out, 0, 32);
    enum mesh_status_proto_error error =
        mesh_status_receipt_v1_validate(receipt);
    if (error != MESH_STATUS_PROTO_OK)
        return error;
    uint8_t fixed[RECEIPT_UNSIGNED_FIXED_BYTES];
    if (receipt_write_unsigned(receipt, fixed) != sizeof(fixed))
        return MESH_STATUS_PROTO_SIZE;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)receipt_root_domain,
                   sizeof(receipt_root_domain) - 1u);
    sha3_256_write(&sha, fixed, sizeof(fixed));
    if (receipt->capsule_len != 0)
        sha3_256_write(&sha, receipt->capsule, receipt->capsule_len);
    sha3_256_write(&sha, receipt->signature, sizeof(receipt->signature));
    sha3_256_finalize(&sha, out);
    return MESH_STATUS_PROTO_OK;
}

enum mesh_status_proto_error mesh_status_receipt_v1_matches_request(
    const struct mesh_status_receipt_v1 *receipt,
    const struct mesh_status_request_v1 *request)
{
    enum mesh_status_proto_error error =
        mesh_status_receipt_v1_validate(receipt);
    if (error != MESH_STATUS_PROTO_OK)
        return error;
    error = mesh_status_request_v1_validate(request);
    if (error != MESH_STATUS_PROTO_OK)
        return error;
    uint8_t request_root[32];
    error = mesh_status_request_v1_root(request, request_root);
    bool fields_match = error == MESH_STATUS_PROTO_OK &&
        memcmp(receipt->request_id, request->request_id, 32) == 0 &&
        memcmp(receipt->request_root, request_root, 32) == 0 &&
        memcmp(receipt->network_genesis, request->network_genesis, 32) == 0 &&
        memcmp(receipt->pairing_id, request->pairing_id, 32) == 0 &&
        memcmp(receipt->responder_master_pubkey,
               request->target_master_pubkey, 32) == 0 &&
        memcmp(receipt->transcript_hash, request->transcript_hash, 32) == 0 &&
        receipt->connection_generation == request->connection_generation &&
        receipt->connection_serial == request->connection_serial;
    memory_cleanse(request_root, sizeof(request_root));
    if (!fields_match)
        return MESH_STATUS_PROTO_FIELD;
    return receipt->observed_unix >= request->issued_unix &&
                   receipt->observed_unix <= request->expires_unix &&
                   receipt->expires_unix <= request->expires_unix
               ? MESH_STATUS_PROTO_OK
               : MESH_STATUS_PROTO_TIME;
}
