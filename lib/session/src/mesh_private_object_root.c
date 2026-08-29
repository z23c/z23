/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical SHA3-256 private-object root derivation. */

#include "session/mesh_private_object_root.h"

#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "session/mesh_private_object_proto.h"

#include <limits.h>
#include <string.h>

enum root_state {
    ROOT_STATE_ACTIVE = 1,
    ROOT_STATE_FAILED,
    ROOT_STATE_FINALIZED,
};

static const uint8_t plaintext_domain[] =
    "zcl.mesh.private-object.plaintext-root.v1";
static const uint8_t ciphertext_domain[] =
    "zcl.mesh.private-object.ciphertext-root.v1";

const char *mesh_private_object_root_error_string(
    enum mesh_private_object_root_error error)
{
    switch (error) {
    case MESH_PRIVATE_OBJECT_ROOT_OK: return "ok";
    case MESH_PRIVATE_OBJECT_ROOT_NULL: return "null";
    case MESH_PRIVATE_OBJECT_ROOT_PARAMETER: return "parameter";
    case MESH_PRIVATE_OBJECT_ROOT_STATE: return "state";
    case MESH_PRIVATE_OBJECT_ROOT_INDEX: return "index";
    case MESH_PRIVATE_OBJECT_ROOT_LENGTH: return "length";
    case MESH_PRIVATE_OBJECT_ROOT_OVERFLOW: return "overflow";
    case MESH_PRIVATE_OBJECT_ROOT_INCOMPLETE: return "incomplete";
    }
    return "unknown";
}

static enum mesh_private_object_root_error root_fail(
    struct mesh_private_object_root_v1 *root,
    enum mesh_private_object_root_error error)
{
    root->state = ROOT_STATE_FAILED;
    memory_cleanse(&root->sha, sizeof(root->sha));
    return error;
}

static uint32_t canonical_chunk_count(uint64_t object_size_bytes)
{
    return (uint32_t)((object_size_bytes - 1u) /
                      MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES + 1u);
}

enum mesh_private_object_root_error mesh_private_object_root_v1_init(
    struct mesh_private_object_root_v1 *root,
    enum mesh_private_object_root_kind kind, uint64_t object_size_bytes,
    uint64_t ciphertext_size_bytes, uint32_t chunk_count)
{
    if (!root)
        return MESH_PRIVATE_OBJECT_ROOT_NULL;
    memset(root, 0, sizeof(*root));
    if (kind != MESH_PRIVATE_OBJECT_ROOT_PLAINTEXT &&
        kind != MESH_PRIVATE_OBJECT_ROOT_CIPHERTEXT)
        return MESH_PRIVATE_OBJECT_ROOT_PARAMETER;
    if (object_size_bytes == 0 ||
        object_size_bytes > MESH_PRIVATE_OBJECT_MAX_OBJECT_BYTES)
        return MESH_PRIVATE_OBJECT_ROOT_PARAMETER;
    uint32_t expected_count = canonical_chunk_count(object_size_bytes);
    if (chunk_count != expected_count)
        return MESH_PRIVATE_OBJECT_ROOT_PARAMETER;
    uint64_t tag_bytes = (uint64_t)chunk_count *
                         MESH_PRIVATE_OBJECT_TAG_BYTES;
    if (object_size_bytes > UINT64_MAX - tag_bytes ||
        ciphertext_size_bytes != object_size_bytes + tag_bytes ||
        ciphertext_size_bytes > MESH_PRIVATE_OBJECT_MAX_CIPHERTEXT_BYTES)
        return MESH_PRIVATE_OBJECT_ROOT_PARAMETER;

    root->object_size_bytes = object_size_bytes;
    root->ciphertext_size_bytes = ciphertext_size_bytes;
    root->chunk_count = chunk_count;
    root->kind = kind;
    root->state = ROOT_STATE_ACTIVE;
    const uint8_t *domain = kind == MESH_PRIVATE_OBJECT_ROOT_PLAINTEXT
                                ? plaintext_domain : ciphertext_domain;
    size_t domain_len = kind == MESH_PRIVATE_OBJECT_ROOT_PLAINTEXT
                            ? sizeof(plaintext_domain) - 1u
                            : sizeof(ciphertext_domain) - 1u;
    uint8_t header[20];
    zcl_write_u64_le(header, object_size_bytes);
    zcl_write_u64_le(header + 8, ciphertext_size_bytes);
    zcl_write_u32_le(header + 16, chunk_count);
    sha3_256_init(&root->sha);
    sha3_256_write(&root->sha, domain, domain_len);
    sha3_256_write(&root->sha, header, sizeof(header));
    memory_cleanse(header, sizeof(header));
    return MESH_PRIVATE_OBJECT_ROOT_OK;
}

static uint32_t root_expected_length(
    const struct mesh_private_object_root_v1 *root, uint32_t chunk_index)
{
    uint64_t offset = (uint64_t)chunk_index *
                      MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES;
    uint64_t remaining = root->object_size_bytes - offset;
    uint32_t plain = remaining > MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES
                         ? MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES
                         : (uint32_t)remaining;
    return root->kind == MESH_PRIVATE_OBJECT_ROOT_CIPHERTEXT
               ? plain + MESH_PRIVATE_OBJECT_TAG_BYTES : plain;
}

enum mesh_private_object_root_error mesh_private_object_root_v1_update(
    struct mesh_private_object_root_v1 *root, uint32_t chunk_index,
    const uint8_t *chunk, size_t chunk_len)
{
    if (!root)
        return MESH_PRIVATE_OBJECT_ROOT_NULL;
    if (root->state != ROOT_STATE_ACTIVE)
        return MESH_PRIVATE_OBJECT_ROOT_STATE;
    if (chunk_index != root->next_chunk || chunk_index >= root->chunk_count)
        return root_fail(root, MESH_PRIVATE_OBJECT_ROOT_INDEX);
    uint32_t expected = root_expected_length(root, chunk_index);
    if (!chunk || chunk_len != expected)
        return root_fail(root, MESH_PRIVATE_OBJECT_ROOT_LENGTH);
    if (root->bytes_seen > UINT64_MAX - chunk_len)
        return root_fail(root, MESH_PRIVATE_OBJECT_ROOT_OVERFLOW);

    uint8_t framing[8];
    zcl_write_u32_le(framing, chunk_index);
    zcl_write_u32_le(framing + 4, expected);
    sha3_256_write(&root->sha, framing, sizeof(framing));
    sha3_256_write(&root->sha, chunk, chunk_len);
    memory_cleanse(framing, sizeof(framing));
    root->bytes_seen += chunk_len;
    root->next_chunk++;
    return MESH_PRIVATE_OBJECT_ROOT_OK;
}

enum mesh_private_object_root_error mesh_private_object_root_v1_finalize(
    struct mesh_private_object_root_v1 *root, uint8_t out[32])
{
    if (!out)
        return MESH_PRIVATE_OBJECT_ROOT_NULL;
    memset(out, 0, 32);
    if (!root)
        return MESH_PRIVATE_OBJECT_ROOT_NULL;
    if (root->state != ROOT_STATE_ACTIVE)
        return MESH_PRIVATE_OBJECT_ROOT_STATE;
    uint64_t expected = root->kind == MESH_PRIVATE_OBJECT_ROOT_PLAINTEXT
                            ? root->object_size_bytes
                            : root->ciphertext_size_bytes;
    if (root->next_chunk != root->chunk_count ||
        root->bytes_seen != expected)
        return root_fail(root, MESH_PRIVATE_OBJECT_ROOT_INCOMPLETE);
    sha3_256_finalize(&root->sha, out);
    memory_cleanse(&root->sha, sizeof(root->sha));
    root->state = ROOT_STATE_FINALIZED;
    return MESH_PRIVATE_OBJECT_ROOT_OK;
}
