/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Strict allocation-free mesh terminal wire codec and receipt
 * proof, mirroring mesh_status_proto. */

#include "session/mesh_terminal_proto.h"

#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"

#include <string.h>

static const uint8_t open_magic[8] = {'Z', 'M', 'T', 'O', '1', 0, 0, 0};
static const uint8_t receipt_magic[8] = {'Z', 'M', 'T', 'K', '1', 0, 0, 0};
static const uint8_t data_magic[8] = {'Z', 'M', 'T', 'D', '1', 0, 0, 0};
static const uint8_t resize_magic[8] = {'Z', 'M', 'T', 'W', '1', 0, 0, 0};
static const uint8_t close_magic[8] = {'Z', 'M', 'T', 'C', '1', 0, 0, 0};
static const char open_root_domain[] = "zcl.mesh.terminal.open.v1";
static const char capsule_root_domain[] = "zcl.mesh.terminal.capsule.v1";
static const char receipt_signature_domain[] =
    "zcl.mesh.terminal.receipt.signature.v1";
static const char receipt_root_domain[] = "zcl.mesh.terminal.receipt.v1";

#define RECEIPT_UNSIGNED_FIXED_BYTES 336u

static bool bytes_nonzero(const uint8_t *bytes, size_t count)
{
    if (!bytes)
        return false;
    uint8_t any = 0;
    for (size_t i = 0; i < count; i++)
        any |= bytes[i];
    return any != 0;
}

static bool lifetime_valid(uint64_t issued, uint64_t expires, uint64_t ceiling)
{
    return issued != 0 && expires > issued && expires - issued <= ceiling;
}

static bool geometry_valid(uint16_t cols, uint16_t rows)
{
    return cols != 0 && cols <= MESH_TERMINAL_MAX_COLS && rows != 0 &&
           rows <= MESH_TERMINAL_MAX_ROWS;
}

const char *mesh_terminal_proto_error_string(
    enum mesh_terminal_proto_error error)
{
    switch (error) {
    case MESH_TERMINAL_PROTO_OK: return "ok";
    case MESH_TERMINAL_PROTO_NULL: return "null";
    case MESH_TERMINAL_PROTO_SIZE: return "size";
    case MESH_TERMINAL_PROTO_MAGIC: return "magic";
    case MESH_TERMINAL_PROTO_VERSION_INVALID: return "version";
    case MESH_TERMINAL_PROTO_FLAGS: return "flags";
    case MESH_TERMINAL_PROTO_CAPABILITY: return "capability";
    case MESH_TERMINAL_PROTO_FIELD: return "field";
    case MESH_TERMINAL_PROTO_TIME: return "time";
    case MESH_TERMINAL_PROTO_GEOMETRY: return "geometry";
    case MESH_TERMINAL_PROTO_STATUS: return "status";
    case MESH_TERMINAL_PROTO_REASON: return "reason";
    case MESH_TERMINAL_PROTO_CAPSULE_ROOT: return "capsule-root";
    case MESH_TERMINAL_PROTO_KEY_MISMATCH: return "key-mismatch";
    case MESH_TERMINAL_PROTO_SIGNATURE: return "signature";
    }
    return "unknown";
}

const char *mesh_terminal_receipt_status_string(
    enum mesh_terminal_receipt_status status)
{
    switch (status) {
    case MESH_TERMINAL_RECEIPT_OK: return "ok";
    case MESH_TERMINAL_RECEIPT_BAD_REQUEST: return "bad-request";
    case MESH_TERMINAL_RECEIPT_CAPABILITY_UNAVAILABLE:
        return "capability-unavailable";
    case MESH_TERMINAL_RECEIPT_NOT_PAIRED: return "not-paired";
    case MESH_TERMINAL_RECEIPT_REVOKED: return "revoked";
    case MESH_TERMINAL_RECEIPT_EXPIRED: return "expired";
    case MESH_TERMINAL_RECEIPT_SESSION_MISMATCH: return "session-mismatch";
    case MESH_TERMINAL_RECEIPT_AUTHORITY_CHANGED: return "authority-changed";
    case MESH_TERMINAL_RECEIPT_DELEGATION_INVALID: return "delegation-invalid";
    case MESH_TERMINAL_RECEIPT_CONCURRENCY_LIMIT: return "concurrency-limit";
    case MESH_TERMINAL_RECEIPT_CONFINEMENT_UNAVAILABLE:
        return "confinement-unavailable";
    case MESH_TERMINAL_RECEIPT_CLOSED: return "closed";
    case MESH_TERMINAL_RECEIPT_INTERNAL: return "internal";
    }
    return "unknown";
}

const char *mesh_terminal_close_reason_string(
    enum mesh_terminal_close_reason reason)
{
    switch (reason) {
    case MESH_TERMINAL_CLOSE_REQUESTED: return "requested";
    case MESH_TERMINAL_CLOSE_REVOKED: return "revoked";
    case MESH_TERMINAL_CLOSE_EXPIRED: return "expired";
    case MESH_TERMINAL_CLOSE_IDLE_TIMEOUT: return "idle-timeout";
    case MESH_TERMINAL_CLOSE_LIFETIME_LIMIT: return "lifetime-limit";
    case MESH_TERMINAL_CLOSE_BYTE_LIMIT: return "byte-limit";
    case MESH_TERMINAL_CLOSE_SESSION_LOST: return "session-lost";
    case MESH_TERMINAL_CLOSE_WORKER_EXITED: return "worker-exited";
    case MESH_TERMINAL_CLOSE_INTERNAL: return "internal";
    case MESH_TERMINAL_CLOSE_SHUTDOWN: return "shutdown";
    }
    return "unknown";
}

/* ── Open ────────────────────────────────────────────────────────────── */

static enum mesh_terminal_proto_error open_shape(
    const struct mesh_terminal_open_v1 *open)
{
    if (!open)
        return MESH_TERMINAL_PROTO_NULL;
    if (open->version != MESH_TERMINAL_PROTO_VERSION)
        return MESH_TERMINAL_PROTO_VERSION_INVALID;
    if (open->flags != MESH_TERMINAL_PROTO_FLAGS_NONE)
        return MESH_TERMINAL_PROTO_FLAGS;
    if (open->capability != MESH_TERMINAL_CAP_TERMINAL_EXEC)
        return MESH_TERMINAL_PROTO_CAPABILITY;
    const uint8_t *critical[] = {
        open->terminal_id, open->pairing_id, open->network_genesis,
        open->target_master_pubkey, open->requester_master_pubkey,
        open->requester_noise_static, open->transcript_hash,
    };
    for (size_t i = 0; i < sizeof(critical) / sizeof(critical[0]); i++)
        if (!bytes_nonzero(critical[i], 32))
            return MESH_TERMINAL_PROTO_FIELD;
    if (open->connection_generation == 0)
        return MESH_TERMINAL_PROTO_FIELD;
    if (!geometry_valid(open->cols, open->rows))
        return MESH_TERMINAL_PROTO_GEOMETRY;
    return lifetime_valid(open->issued_unix, open->expires_unix,
                          MESH_TERMINAL_OPEN_MAX_LIFETIME_SECONDS)
               ? MESH_TERMINAL_PROTO_OK
               : MESH_TERMINAL_PROTO_TIME;
}

enum mesh_terminal_proto_error mesh_terminal_open_v1_validate(
    const struct mesh_terminal_open_v1 *open)
{
    return open_shape(open);
}

static size_t open_write(const struct mesh_terminal_open_v1 *open,
                         uint8_t out[MESH_TERMINAL_OPEN_V1_WIRE_BYTES])
{
    size_t off = 0;
    memcpy(out + off, open_magic, sizeof(open_magic)); off += 8;
    zcl_write_u16_le(out + off, open->version); off += 2;
    zcl_write_u16_le(out + off, open->flags); off += 2;
    zcl_write_u64_le(out + off, open->capability); off += 8;
    memcpy(out + off, open->terminal_id, 32); off += 32;
    memcpy(out + off, open->pairing_id, 32); off += 32;
    memcpy(out + off, open->network_genesis, 32); off += 32;
    memcpy(out + off, open->target_master_pubkey, 32); off += 32;
    memcpy(out + off, open->requester_master_pubkey, 32); off += 32;
    memcpy(out + off, open->requester_noise_static, 32); off += 32;
    memcpy(out + off, open->transcript_hash, 32); off += 32;
    zcl_write_u64_le(out + off, open->connection_generation); off += 8;
    zcl_write_u64_le(out + off, open->issued_unix); off += 8;
    zcl_write_u64_le(out + off, open->expires_unix); off += 8;
    zcl_write_u16_le(out + off, open->cols); off += 2;
    zcl_write_u16_le(out + off, open->rows); off += 2;
    return off;
}

enum mesh_terminal_proto_error mesh_terminal_open_v1_encode(
    const struct mesh_terminal_open_v1 *open,
    uint8_t out[MESH_TERMINAL_OPEN_V1_WIRE_BYTES])
{
    if (!out)
        return MESH_TERMINAL_PROTO_NULL;
    enum mesh_terminal_proto_error error = open_shape(open);
    if (error != MESH_TERMINAL_PROTO_OK)
        return error;
    return open_write(open, out) == MESH_TERMINAL_OPEN_V1_WIRE_BYTES
               ? MESH_TERMINAL_PROTO_OK
               : MESH_TERMINAL_PROTO_SIZE;
}

enum mesh_terminal_proto_error mesh_terminal_open_v1_decode(
    struct mesh_terminal_open_v1 *out, const uint8_t *wire, size_t wire_len)
{
    if (!out || !wire)
        return MESH_TERMINAL_PROTO_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != MESH_TERMINAL_OPEN_V1_WIRE_BYTES)
        return MESH_TERMINAL_PROTO_SIZE;
    if (memcmp(wire, open_magic, sizeof(open_magic)) != 0)
        return MESH_TERMINAL_PROTO_MAGIC;
    size_t off = 8;
    out->version = zcl_read_u16_le(wire + off); off += 2;
    out->flags = zcl_read_u16_le(wire + off); off += 2;
    out->capability = zcl_read_u64_le(wire + off); off += 8;
    memcpy(out->terminal_id, wire + off, 32); off += 32;
    memcpy(out->pairing_id, wire + off, 32); off += 32;
    memcpy(out->network_genesis, wire + off, 32); off += 32;
    memcpy(out->target_master_pubkey, wire + off, 32); off += 32;
    memcpy(out->requester_master_pubkey, wire + off, 32); off += 32;
    memcpy(out->requester_noise_static, wire + off, 32); off += 32;
    memcpy(out->transcript_hash, wire + off, 32); off += 32;
    out->connection_generation = zcl_read_u64_le(wire + off); off += 8;
    out->issued_unix = zcl_read_u64_le(wire + off); off += 8;
    out->expires_unix = zcl_read_u64_le(wire + off); off += 8;
    out->cols = zcl_read_u16_le(wire + off); off += 2;
    out->rows = zcl_read_u16_le(wire + off); off += 2;
    enum mesh_terminal_proto_error error =
        off == wire_len ? open_shape(out) : MESH_TERMINAL_PROTO_SIZE;
    if (error != MESH_TERMINAL_PROTO_OK)
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

enum mesh_terminal_proto_error mesh_terminal_open_v1_root(
    const struct mesh_terminal_open_v1 *open, uint8_t out[32])
{
    if (!out)
        return MESH_TERMINAL_PROTO_NULL;
    memset(out, 0, 32);
    uint8_t wire[MESH_TERMINAL_OPEN_V1_WIRE_BYTES];
    enum mesh_terminal_proto_error error =
        mesh_terminal_open_v1_encode(open, wire);
    if (error != MESH_TERMINAL_PROTO_OK)
        return error;
    hash_bytes(open_root_domain, wire, sizeof(wire), out);
    return MESH_TERMINAL_PROTO_OK;
}

/* ── Receipt ─────────────────────────────────────────────────────────── */

enum mesh_terminal_proto_error mesh_terminal_capsule_v1_root(
    const uint8_t *capsule, size_t capsule_len, uint8_t out[32])
{
    if (!out || (!capsule && capsule_len != 0))
        return MESH_TERMINAL_PROTO_NULL;
    memset(out, 0, 32);
    if (capsule_len > MESH_TERMINAL_CAPSULE_MAX)
        return MESH_TERMINAL_PROTO_SIZE;
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
    return MESH_TERMINAL_PROTO_OK;
}

static bool receipt_status_valid(enum mesh_terminal_receipt_status status)
{
    return status >= MESH_TERMINAL_RECEIPT_OK &&
           status <= MESH_TERMINAL_RECEIPT_INTERNAL;
}

static bool receipt_status_carries_capsule(
    enum mesh_terminal_receipt_status status)
{
    return status == MESH_TERMINAL_RECEIPT_OK ||
           status == MESH_TERMINAL_RECEIPT_CLOSED;
}

static enum mesh_terminal_proto_error receipt_shape(
    const struct mesh_terminal_receipt_v1 *receipt, bool require_signature)
{
    if (!receipt)
        return MESH_TERMINAL_PROTO_NULL;
    if (receipt->version != MESH_TERMINAL_PROTO_VERSION)
        return MESH_TERMINAL_PROTO_VERSION_INVALID;
    if (receipt->flags != MESH_TERMINAL_PROTO_FLAGS_NONE)
        return MESH_TERMINAL_PROTO_FLAGS;
    if (!receipt_status_valid(receipt->status))
        return MESH_TERMINAL_PROTO_STATUS;
    if (receipt->capsule_len > MESH_TERMINAL_CAPSULE_MAX)
        return MESH_TERMINAL_PROTO_SIZE;
    /* Exactly the verdict receipts that carry session evidence hold a
     * capsule; every named refusal is bare. */
    if (receipt_status_carries_capsule(receipt->status) !=
        (receipt->capsule_len != 0))
        return MESH_TERMINAL_PROTO_STATUS;
    const uint8_t *critical[] = {
        receipt->request_id, receipt->request_root,
        receipt->network_genesis, receipt->pairing_id,
        receipt->responder_master_pubkey, receipt->responder_online_pubkey,
        receipt->responder_noise_static, receipt->transcript_hash,
    };
    for (size_t i = 0; i < sizeof(critical) / sizeof(critical[0]); i++)
        if (!bytes_nonzero(critical[i], 32))
            return MESH_TERMINAL_PROTO_FIELD;
    if (receipt->connection_generation == 0)
        return MESH_TERMINAL_PROTO_FIELD;
    if (!lifetime_valid(receipt->observed_unix, receipt->expires_unix,
                        MESH_TERMINAL_RECEIPT_MAX_LIFETIME_SECONDS))
        return MESH_TERMINAL_PROTO_TIME;
    uint8_t capsule_root[32];
    enum mesh_terminal_proto_error error = mesh_terminal_capsule_v1_root(
        receipt->capsule, receipt->capsule_len, capsule_root);
    bool root_ok = error == MESH_TERMINAL_PROTO_OK &&
                   memcmp(capsule_root, receipt->capsule_root, 32) == 0;
    memory_cleanse(capsule_root, sizeof(capsule_root));
    if (!root_ok)
        return MESH_TERMINAL_PROTO_CAPSULE_ROOT;
    if (require_signature && !bytes_nonzero(receipt->signature, 64))
        return MESH_TERMINAL_PROTO_SIGNATURE;
    return MESH_TERMINAL_PROTO_OK;
}

static size_t receipt_write_unsigned(
    const struct mesh_terminal_receipt_v1 *receipt,
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
    zcl_write_u64_le(out + off, receipt->revocation_generation); off += 8;
    zcl_write_u64_le(out + off, receipt->observed_unix); off += 8;
    zcl_write_u64_le(out + off, receipt->expires_unix); off += 8;
    memcpy(out + off, receipt->capsule_root, 32); off += 32;
    return off;
}

static enum mesh_terminal_proto_error receipt_signing_root(
    const struct mesh_terminal_receipt_v1 *receipt, uint8_t out[32])
{
    enum mesh_terminal_proto_error error = receipt_shape(receipt, false);
    if (error != MESH_TERMINAL_PROTO_OK)
        return error;
    uint8_t fixed[RECEIPT_UNSIGNED_FIXED_BYTES];
    if (receipt_write_unsigned(receipt, fixed) != sizeof(fixed))
        return MESH_TERMINAL_PROTO_SIZE;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)receipt_signature_domain,
                   sizeof(receipt_signature_domain) - 1u);
    sha3_256_write(&sha, fixed, sizeof(fixed));
    if (receipt->capsule_len != 0)
        sha3_256_write(&sha, receipt->capsule, receipt->capsule_len);
    sha3_256_finalize(&sha, out);
    return MESH_TERMINAL_PROTO_OK;
}

size_t mesh_terminal_receipt_v1_wire_size(
    const struct mesh_terminal_receipt_v1 *receipt)
{
    return receipt && receipt->capsule_len <= MESH_TERMINAL_CAPSULE_MAX
               ? MESH_TERMINAL_RECEIPT_V1_FIXED_BYTES + receipt->capsule_len
               : 0;
}

enum mesh_terminal_proto_error mesh_terminal_receipt_v1_validate(
    const struct mesh_terminal_receipt_v1 *receipt)
{
    enum mesh_terminal_proto_error error = receipt_shape(receipt, true);
    if (error != MESH_TERMINAL_PROTO_OK)
        return error;
    uint8_t root[32];
    error = receipt_signing_root(receipt, root);
    bool valid = error == MESH_TERMINAL_PROTO_OK &&
                 ed25519_verify(receipt->signature, root, sizeof(root),
                                receipt->responder_online_pubkey);
    memory_cleanse(root, sizeof(root));
    return valid ? MESH_TERMINAL_PROTO_OK : MESH_TERMINAL_PROTO_SIGNATURE;
}

enum mesh_terminal_proto_error mesh_terminal_receipt_v1_sign(
    struct mesh_terminal_receipt_v1 *receipt,
    const uint8_t responder_online_seed[32])
{
    if (!receipt || !responder_online_seed)
        return MESH_TERMINAL_PROTO_NULL;
    memset(receipt->signature, 0, sizeof(receipt->signature));
    uint8_t public_key[32], secret[32], root[32];
    ed25519_keypair(public_key, secret, responder_online_seed);
    if (memcmp(public_key, receipt->responder_online_pubkey, 32) != 0) {
        memory_cleanse(secret, sizeof(secret));
        return MESH_TERMINAL_PROTO_KEY_MISMATCH;
    }
    enum mesh_terminal_proto_error error = receipt_signing_root(receipt, root);
    if (error == MESH_TERMINAL_PROTO_OK)
        ed25519_sign(receipt->signature, root, sizeof(root), secret,
                     public_key);
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(root, sizeof(root));
    return error == MESH_TERMINAL_PROTO_OK
               ? mesh_terminal_receipt_v1_validate(receipt)
               : error;
}

enum mesh_terminal_proto_error mesh_terminal_receipt_v1_encode(
    const struct mesh_terminal_receipt_v1 *receipt, uint8_t *out,
    size_t out_capacity, size_t *out_len)
{
    if (out_len)
        *out_len = 0;
    if (!receipt || !out || !out_len)
        return MESH_TERMINAL_PROTO_NULL;
    enum mesh_terminal_proto_error error =
        mesh_terminal_receipt_v1_validate(receipt);
    if (error != MESH_TERMINAL_PROTO_OK)
        return error;
    size_t needed = mesh_terminal_receipt_v1_wire_size(receipt);
    if (needed == 0 || out_capacity < needed)
        return MESH_TERMINAL_PROTO_SIZE;
    size_t off = receipt_write_unsigned(receipt, out);
    memcpy(out + off, receipt->capsule, receipt->capsule_len);
    off += receipt->capsule_len;
    memcpy(out + off, receipt->signature, 64);
    off += 64;
    if (off != needed)
        return MESH_TERMINAL_PROTO_SIZE;
    *out_len = off;
    return MESH_TERMINAL_PROTO_OK;
}

enum mesh_terminal_proto_error mesh_terminal_receipt_v1_decode(
    struct mesh_terminal_receipt_v1 *out, const uint8_t *wire,
    size_t wire_len)
{
    if (!out || !wire)
        return MESH_TERMINAL_PROTO_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len < MESH_TERMINAL_RECEIPT_V1_FIXED_BYTES ||
        wire_len > MESH_TERMINAL_RECEIPT_V1_MAX_WIRE_BYTES)
        return MESH_TERMINAL_PROTO_SIZE;
    if (memcmp(wire, receipt_magic, sizeof(receipt_magic)) != 0)
        return MESH_TERMINAL_PROTO_MAGIC;
    size_t off = 8;
    out->version = zcl_read_u16_le(wire + off); off += 2;
    out->flags = zcl_read_u16_le(wire + off); off += 2;
    out->status = (enum mesh_terminal_receipt_status)
        zcl_read_u16_le(wire + off); off += 2;
    out->capsule_len = zcl_read_u16_le(wire + off); off += 2;
    size_t expected =
        MESH_TERMINAL_RECEIPT_V1_FIXED_BYTES + out->capsule_len;
    if (out->capsule_len > MESH_TERMINAL_CAPSULE_MAX ||
        wire_len != expected) {
        memset(out, 0, sizeof(*out));
        return MESH_TERMINAL_PROTO_SIZE;
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
    out->revocation_generation = zcl_read_u64_le(wire + off); off += 8;
    out->observed_unix = zcl_read_u64_le(wire + off); off += 8;
    out->expires_unix = zcl_read_u64_le(wire + off); off += 8;
    memcpy(out->capsule_root, wire + off, 32); off += 32;
    memcpy(out->capsule, wire + off, out->capsule_len);
    off += out->capsule_len;
    memcpy(out->signature, wire + off, 64); off += 64;
    enum mesh_terminal_proto_error error =
        off == wire_len ? mesh_terminal_receipt_v1_validate(out)
                        : MESH_TERMINAL_PROTO_SIZE;
    if (error != MESH_TERMINAL_PROTO_OK)
        memset(out, 0, sizeof(*out));
    return error;
}

enum mesh_terminal_proto_error mesh_terminal_receipt_v1_root(
    const struct mesh_terminal_receipt_v1 *receipt, uint8_t out[32])
{
    if (!out)
        return MESH_TERMINAL_PROTO_NULL;
    memset(out, 0, 32);
    enum mesh_terminal_proto_error error =
        mesh_terminal_receipt_v1_validate(receipt);
    if (error != MESH_TERMINAL_PROTO_OK)
        return error;
    uint8_t fixed[RECEIPT_UNSIGNED_FIXED_BYTES];
    if (receipt_write_unsigned(receipt, fixed) != sizeof(fixed))
        return MESH_TERMINAL_PROTO_SIZE;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)receipt_root_domain,
                   sizeof(receipt_root_domain) - 1u);
    sha3_256_write(&sha, fixed, sizeof(fixed));
    if (receipt->capsule_len != 0)
        sha3_256_write(&sha, receipt->capsule, receipt->capsule_len);
    sha3_256_write(&sha, receipt->signature, sizeof(receipt->signature));
    sha3_256_finalize(&sha, out);
    return MESH_TERMINAL_PROTO_OK;
}

enum mesh_terminal_proto_error mesh_terminal_receipt_v1_matches_open(
    const struct mesh_terminal_receipt_v1 *receipt,
    const struct mesh_terminal_open_v1 *open)
{
    enum mesh_terminal_proto_error error =
        mesh_terminal_receipt_v1_validate(receipt);
    if (error != MESH_TERMINAL_PROTO_OK)
        return error;
    error = mesh_terminal_open_v1_validate(open);
    if (error != MESH_TERMINAL_PROTO_OK)
        return error;
    uint8_t open_root[32];
    error = mesh_terminal_open_v1_root(open, open_root);
    bool fields_match = error == MESH_TERMINAL_PROTO_OK &&
        memcmp(receipt->request_id, open->terminal_id, 32) == 0 &&
        memcmp(receipt->request_root, open_root, 32) == 0 &&
        memcmp(receipt->network_genesis, open->network_genesis, 32) == 0 &&
        memcmp(receipt->pairing_id, open->pairing_id, 32) == 0 &&
        memcmp(receipt->responder_master_pubkey,
               open->target_master_pubkey, 32) == 0 &&
        memcmp(receipt->transcript_hash, open->transcript_hash, 32) == 0 &&
        receipt->connection_generation == open->connection_generation;
    memory_cleanse(open_root, sizeof(open_root));
    if (!fields_match)
        return MESH_TERMINAL_PROTO_FIELD;
    /* A CLOSED receipt legitimately lands long after the open window shut
     * (the session itself lives far longer than the open's 60-second
     * answer window); it must still postdate the open's issue. Every other
     * status answers inside the open window. */
    if (receipt->status == MESH_TERMINAL_RECEIPT_CLOSED)
        return receipt->observed_unix >= open->issued_unix
                   ? MESH_TERMINAL_PROTO_OK
                   : MESH_TERMINAL_PROTO_TIME;
    return receipt->observed_unix >= open->issued_unix &&
                   receipt->observed_unix <= open->expires_unix &&
                   receipt->expires_unix <= open->expires_unix
               ? MESH_TERMINAL_PROTO_OK
               : MESH_TERMINAL_PROTO_TIME;
}

/* ── Data frame ──────────────────────────────────────────────────────── */

enum mesh_terminal_proto_error mesh_terminal_data_v1_encode(
    const struct mesh_terminal_data_v1 *data, uint8_t *out,
    size_t out_capacity, size_t *out_len)
{
    if (out_len)
        *out_len = 0;
    if (!data || !out || !out_len)
        return MESH_TERMINAL_PROTO_NULL;
    if (data->payload_len > MESH_TERMINAL_DATA_PAYLOAD_MAX)
        return MESH_TERMINAL_PROTO_SIZE;
    if (!bytes_nonzero(data->terminal_id, 32))
        return MESH_TERMINAL_PROTO_FIELD;
    size_t needed = MESH_TERMINAL_DATA_V1_HEADER_BYTES + data->payload_len;
    if (out_capacity < needed)
        return MESH_TERMINAL_PROTO_SIZE;
    size_t off = 0;
    memcpy(out + off, data_magic, sizeof(data_magic)); off += 8;
    memcpy(out + off, data->terminal_id, 32); off += 32;
    zcl_write_u64_le(out + off, data->seq); off += 8;
    zcl_write_u16_le(out + off, data->payload_len); off += 2;
    memcpy(out + off, data->payload, data->payload_len);
    off += data->payload_len;
    *out_len = off;
    return MESH_TERMINAL_PROTO_OK;
}

enum mesh_terminal_proto_error mesh_terminal_data_v1_decode(
    struct mesh_terminal_data_v1 *out, const uint8_t *wire, size_t wire_len)
{
    if (!out || !wire)
        return MESH_TERMINAL_PROTO_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len < MESH_TERMINAL_DATA_V1_HEADER_BYTES ||
        wire_len > MESH_TERMINAL_DATA_V1_MAX_WIRE_BYTES)
        return MESH_TERMINAL_PROTO_SIZE;
    if (memcmp(wire, data_magic, sizeof(data_magic)) != 0)
        return MESH_TERMINAL_PROTO_MAGIC;
    size_t off = 8;
    memcpy(out->terminal_id, wire + off, 32); off += 32;
    out->seq = zcl_read_u64_le(wire + off); off += 8;
    out->payload_len = zcl_read_u16_le(wire + off); off += 2;
    if (out->payload_len > MESH_TERMINAL_DATA_PAYLOAD_MAX ||
        wire_len != MESH_TERMINAL_DATA_V1_HEADER_BYTES + out->payload_len) {
        memset(out, 0, sizeof(*out));
        return MESH_TERMINAL_PROTO_SIZE;
    }
    memcpy(out->payload, wire + off, out->payload_len);
    if (!bytes_nonzero(out->terminal_id, 32)) {
        memset(out, 0, sizeof(*out));
        return MESH_TERMINAL_PROTO_FIELD;
    }
    return MESH_TERMINAL_PROTO_OK;
}

/* ── Resize frame ────────────────────────────────────────────────────── */

enum mesh_terminal_proto_error mesh_terminal_resize_v1_encode(
    const struct mesh_terminal_resize_v1 *resize,
    uint8_t out[MESH_TERMINAL_RESIZE_V1_WIRE_BYTES])
{
    if (!resize || !out)
        return MESH_TERMINAL_PROTO_NULL;
    if (!bytes_nonzero(resize->terminal_id, 32))
        return MESH_TERMINAL_PROTO_FIELD;
    if (!geometry_valid(resize->cols, resize->rows))
        return MESH_TERMINAL_PROTO_GEOMETRY;
    size_t off = 0;
    memcpy(out + off, resize_magic, sizeof(resize_magic)); off += 8;
    memcpy(out + off, resize->terminal_id, 32); off += 32;
    zcl_write_u16_le(out + off, resize->cols); off += 2;
    zcl_write_u16_le(out + off, resize->rows); off += 2;
    return off == MESH_TERMINAL_RESIZE_V1_WIRE_BYTES
               ? MESH_TERMINAL_PROTO_OK
               : MESH_TERMINAL_PROTO_SIZE;
}

enum mesh_terminal_proto_error mesh_terminal_resize_v1_decode(
    struct mesh_terminal_resize_v1 *out, const uint8_t *wire,
    size_t wire_len)
{
    if (!out || !wire)
        return MESH_TERMINAL_PROTO_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != MESH_TERMINAL_RESIZE_V1_WIRE_BYTES)
        return MESH_TERMINAL_PROTO_SIZE;
    if (memcmp(wire, resize_magic, sizeof(resize_magic)) != 0)
        return MESH_TERMINAL_PROTO_MAGIC;
    size_t off = 8;
    memcpy(out->terminal_id, wire + off, 32); off += 32;
    out->cols = zcl_read_u16_le(wire + off); off += 2;
    out->rows = zcl_read_u16_le(wire + off); off += 2;
    if (!bytes_nonzero(out->terminal_id, 32) ||
        !geometry_valid(out->cols, out->rows)) {
        memset(out, 0, sizeof(*out));
        return MESH_TERMINAL_PROTO_FIELD;
    }
    return MESH_TERMINAL_PROTO_OK;
}

/* ── Close frame ─────────────────────────────────────────────────────── */

enum mesh_terminal_proto_error mesh_terminal_close_v1_encode(
    const struct mesh_terminal_close_v1 *close_frame,
    uint8_t out[MESH_TERMINAL_CLOSE_V1_WIRE_BYTES])
{
    if (!close_frame || !out)
        return MESH_TERMINAL_PROTO_NULL;
    if (!bytes_nonzero(close_frame->terminal_id, 32))
        return MESH_TERMINAL_PROTO_FIELD;
    if (close_frame->reason > MESH_TERMINAL_CLOSE_SHUTDOWN)
        return MESH_TERMINAL_PROTO_REASON;
    size_t off = 0;
    memcpy(out + off, close_magic, sizeof(close_magic)); off += 8;
    memcpy(out + off, close_frame->terminal_id, 32); off += 32;
    out[off] = close_frame->reason; off += 1;
    return off == MESH_TERMINAL_CLOSE_V1_WIRE_BYTES
               ? MESH_TERMINAL_PROTO_OK
               : MESH_TERMINAL_PROTO_SIZE;
}

enum mesh_terminal_proto_error mesh_terminal_close_v1_decode(
    struct mesh_terminal_close_v1 *out, const uint8_t *wire,
    size_t wire_len)
{
    if (!out || !wire)
        return MESH_TERMINAL_PROTO_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != MESH_TERMINAL_CLOSE_V1_WIRE_BYTES)
        return MESH_TERMINAL_PROTO_SIZE;
    if (memcmp(wire, close_magic, sizeof(close_magic)) != 0)
        return MESH_TERMINAL_PROTO_MAGIC;
    size_t off = 8;
    memcpy(out->terminal_id, wire + off, 32); off += 32;
    out->reason = wire[off]; off += 1;
    if (!bytes_nonzero(out->terminal_id, 32) ||
        out->reason > MESH_TERMINAL_CLOSE_SHUTDOWN) {
        memset(out, 0, sizeof(*out));
        return MESH_TERMINAL_PROTO_FIELD;
    }
    return MESH_TERMINAL_PROTO_OK;
}
