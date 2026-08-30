/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_swarm — canonical bounded content.v2 swarm wire codec and verifier. */

#include "vcs/package_swarm.h"

#include "base/bytes.h"
#include "vcs_priv.h"

#include "util/log_macros.h"

#include <limits.h>
#include <string.h>

static const uint8_t package_swarm_magic[4] = {'Z', 'P', 'S', 'W'};

#define SWARM_ANNOUNCE_BYTES 60u
#define SWARM_OBJECT_BYTES 92u
#define SWARM_DATA_FIXED_BYTES 96u
#define SWARM_CANCEL_BYTES 48u

static bool bytes_zero(const uint8_t *bytes, size_t len)
{
    return !zcl_bytes_any_set(bytes, len);
}

static bool announce_valid(const struct vcs_package_swarm_announce *a)
{
    if (!a || !zcl_bytes_any_set(a->package_root, sizeof(a->package_root)) ||
        a->manifest_bytes < VCS_PACKAGE_MANIFEST_WIRE_HEADER_BYTES ||
        a->manifest_bytes > VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES ||
        a->file_count > VCS_PACKAGE_MAX_FILES ||
        a->total_bytes > VCS_PACKAGE_MAX_TOTAL_BYTES ||
        a->total_chunks > VCS_PACKAGE_MAX_TOTAL_CHUNKS)
        return false;

    uint64_t chunks = a->total_chunks;
    uint64_t files = a->file_count;
    uint64_t nonempty_files = chunks < files ? chunks : files;
    uint64_t min_bytes = (chunks - nonempty_files) *
                         (uint64_t)VCS_PACKAGE_CHUNK_BYTES + nonempty_files;
    uint64_t max_bytes = chunks * (uint64_t)VCS_PACKAGE_CHUNK_BYTES;
    uint64_t min_manifest = VCS_PACKAGE_MANIFEST_WIRE_HEADER_BYTES +
                            files * 19u + chunks * 32u;
    uint64_t max_manifest = VCS_PACKAGE_MANIFEST_WIRE_HEADER_BYTES +
                            files * (18u + VCS_PACKAGE_PATH_MAX) +
                            chunks * 32u;
    return chunks <= files * VCS_PACKAGE_MAX_CHUNKS_PER_FILE &&
           a->total_bytes >= min_bytes && a->total_bytes <= max_bytes &&
           a->manifest_bytes >= min_manifest &&
           a->manifest_bytes <= max_manifest;
}

static bool object_valid(const struct vcs_package_swarm_object *object)
{
    if (!object || object->request_id == 0 ||
        !zcl_bytes_any_set(object->package_root, sizeof(object->package_root)))
        return false;
    if (object->object_kind == VCS_PACKAGE_SWARM_OBJECT_MANIFEST)
        return object->file_index == UINT32_MAX &&
               object->chunk_index == UINT32_MAX &&
               bytes_zero(object->expected_hash,
                          sizeof(object->expected_hash));
    if (object->object_kind == VCS_PACKAGE_SWARM_OBJECT_CHUNK)
        return object->file_index < VCS_PACKAGE_MAX_FILES &&
               object->chunk_index < VCS_PACKAGE_MAX_CHUNKS_PER_FILE &&
               zcl_bytes_any_set(object->expected_hash,
                             sizeof(object->expected_hash));
    return false;
}

static bool data_valid(const struct vcs_package_swarm_data *data)
{
    if (!data || !object_valid(&data->object) || !data->bytes)
        return false;
    if (data->object.object_kind == VCS_PACKAGE_SWARM_OBJECT_MANIFEST)
        return data->bytes_len >= VCS_PACKAGE_MANIFEST_WIRE_HEADER_BYTES &&
               data->bytes_len <= VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES;
    return data->bytes_len > 0 &&
           data->bytes_len <= VCS_PACKAGE_CHUNK_BYTES;
}

static bool cancel_valid(const struct vcs_package_swarm_cancel *cancel)
{
    return cancel && cancel->request_id != 0 &&
           zcl_bytes_any_set(cancel->package_root, sizeof(cancel->package_root));
}

static bool manifest_has_canonical_file_order(
    const struct vcs_package_manifest *manifest)
{
    if (!manifest || manifest->count > manifest->cap ||
        (manifest->count > 0 && !manifest->files))
        return false;
    for (size_t i = 1; i < manifest->count; i++) {
        if (!manifest->files[i - 1].path || !manifest->files[i].path ||
            strcmp(manifest->files[i - 1].path,
                   manifest->files[i].path) >= 0)
            return false;
    }
    return true;
}

size_t vcs_package_swarm_wire_size(
    const struct vcs_package_swarm_message *message)
{
    if (!message)
        return 0;
    switch (message->type) {
    case VCS_PACKAGE_SWARM_ANNOUNCE:
        return announce_valid(&message->body.announce) ?
               SWARM_ANNOUNCE_BYTES : 0;
    case VCS_PACKAGE_SWARM_WANT:
        return object_valid(&message->body.want) ? SWARM_OBJECT_BYTES : 0;
    case VCS_PACKAGE_SWARM_DATA:
        if (!data_valid(&message->body.data))
            return 0;
        return SWARM_DATA_FIXED_BYTES + message->body.data.bytes_len;
    case VCS_PACKAGE_SWARM_CANCEL:
        return cancel_valid(&message->body.cancel) ? SWARM_CANCEL_BYTES : 0;
    default:
        return 0;
    }
}

static size_t write_object(uint8_t *out,
                           const struct vcs_package_swarm_object *object)
{
    size_t off = VCS_PACKAGE_SWARM_HEADER_BYTES;
    vcs_wr_u64le(out + off, object->request_id);
    off += 8;
    memcpy(out + off, object->package_root, 32);
    off += 32;
    out[off++] = object->object_kind;
    memset(out + off, 0, 3);
    off += 3;
    vcs_wr_u32le(out + off, object->file_index);
    off += 4;
    vcs_wr_u32le(out + off, object->chunk_index);
    off += 4;
    memcpy(out + off, object->expected_hash, 32);
    return off + 32;
}

bool vcs_package_swarm_serialize(
    const struct vcs_package_swarm_message *message,
    uint8_t *out, size_t out_capacity, size_t *out_len)
{
    if (!out_len)
        LOG_FAIL("vcs.swarm", "null swarm serialization length output");
    *out_len = 0;
    size_t required = vcs_package_swarm_wire_size(message);
    if (required == 0 || required > VCS_PACKAGE_SWARM_MAX_WIRE_BYTES)
        LOG_FAIL("vcs.swarm", "invalid package swarm message");
    *out_len = required;
    if (!out || out_capacity < required)
        LOG_FAIL("vcs.swarm", "package swarm output too small");

    memcpy(out, package_swarm_magic, sizeof(package_swarm_magic));
    vcs_wr_u16le(out + 4, VCS_PACKAGE_SWARM_VERSION);
    out[6] = message->type;
    out[7] = 0;
    size_t off = VCS_PACKAGE_SWARM_HEADER_BYTES;

    switch (message->type) {
    case VCS_PACKAGE_SWARM_ANNOUNCE: {
        const struct vcs_package_swarm_announce *a = &message->body.announce;
        memcpy(out + off, a->package_root, 32);
        off += 32;
        vcs_wr_u32le(out + off, a->manifest_bytes);
        off += 4;
        vcs_wr_u32le(out + off, a->file_count);
        off += 4;
        vcs_wr_u64le(out + off, a->total_bytes);
        off += 8;
        vcs_wr_u32le(out + off, a->total_chunks);
        off += 4;
        break;
    }
    case VCS_PACKAGE_SWARM_WANT:
        off = write_object(out, &message->body.want);
        break;
    case VCS_PACKAGE_SWARM_DATA:
        off = write_object(out, &message->body.data.object);
        vcs_wr_u32le(out + off, message->body.data.bytes_len);
        off += 4;
        memcpy(out + off, message->body.data.bytes,
               message->body.data.bytes_len);
        off += message->body.data.bytes_len;
        break;
    case VCS_PACKAGE_SWARM_CANCEL:
        vcs_wr_u64le(out + off, message->body.cancel.request_id);
        off += 8;
        memcpy(out + off, message->body.cancel.package_root, 32);
        off += 32;
        break;
    default:
        LOG_FAIL("vcs.swarm", "unreachable package swarm type");
    }
    if (off != required)
        LOG_FAIL("vcs.swarm", "package swarm size invariant failed");
    return true;
}

static bool read_object(const uint8_t *wire, size_t wire_len,
                        struct vcs_package_swarm_object *object,
                        size_t *out_off)
{
    if (wire_len < SWARM_OBJECT_BYTES)
        return false;
    size_t off = VCS_PACKAGE_SWARM_HEADER_BYTES;
    object->request_id = vcs_rd_u64le(wire + off);
    off += 8;
    memcpy(object->package_root, wire + off, 32);
    off += 32;
    object->object_kind = wire[off++];
    if (wire[off] != 0 || wire[off + 1] != 0 || wire[off + 2] != 0)
        return false;
    off += 3;
    object->file_index = vcs_rd_u32le(wire + off);
    off += 4;
    object->chunk_index = vcs_rd_u32le(wire + off);
    off += 4;
    memcpy(object->expected_hash, wire + off, 32);
    off += 32;
    if (!object_valid(object))
        return false;
    *out_off = off;
    return true;
}

bool vcs_package_swarm_parse(const uint8_t *wire, size_t wire_len,
                             struct vcs_package_swarm_message *out)
{
    if (!out)
        LOG_FAIL("vcs.swarm", "null package swarm parse output");
    memset(out, 0, sizeof(*out));
    if (!wire || wire_len < VCS_PACKAGE_SWARM_HEADER_BYTES ||
        wire_len > VCS_PACKAGE_SWARM_MAX_WIRE_BYTES ||
        memcmp(wire, package_swarm_magic, sizeof(package_swarm_magic)) != 0 ||
        vcs_rd_u16le(wire + 4) != VCS_PACKAGE_SWARM_VERSION || wire[7] != 0)
        LOG_FAIL("vcs.swarm", "invalid package swarm header");

    out->type = wire[6];
    size_t off = VCS_PACKAGE_SWARM_HEADER_BYTES;
    switch (out->type) {
    case VCS_PACKAGE_SWARM_ANNOUNCE: {
        if (wire_len != SWARM_ANNOUNCE_BYTES)
            goto reject;
        struct vcs_package_swarm_announce *a = &out->body.announce;
        memcpy(a->package_root, wire + off, 32);
        off += 32;
        a->manifest_bytes = vcs_rd_u32le(wire + off);
        off += 4;
        a->file_count = vcs_rd_u32le(wire + off);
        off += 4;
        a->total_bytes = vcs_rd_u64le(wire + off);
        off += 8;
        a->total_chunks = vcs_rd_u32le(wire + off);
        off += 4;
        if (!announce_valid(a))
            goto reject;
        break;
    }
    case VCS_PACKAGE_SWARM_WANT:
        if (wire_len != SWARM_OBJECT_BYTES ||
            !read_object(wire, wire_len, &out->body.want, &off))
            goto reject;
        break;
    case VCS_PACKAGE_SWARM_DATA: {
        if (wire_len < SWARM_DATA_FIXED_BYTES ||
            !read_object(wire, wire_len, &out->body.data.object, &off))
            goto reject;
        uint32_t data_len = vcs_rd_u32le(wire + off);
        off += 4;
        if ((size_t)data_len != wire_len - off)
            goto reject;
        out->body.data.bytes = wire + off;
        out->body.data.bytes_len = data_len;
        off += data_len;
        if (!data_valid(&out->body.data))
            goto reject;
        break;
    }
    case VCS_PACKAGE_SWARM_CANCEL:
        if (wire_len != SWARM_CANCEL_BYTES)
            goto reject;
        out->body.cancel.request_id = vcs_rd_u64le(wire + off);
        off += 8;
        memcpy(out->body.cancel.package_root, wire + off, 32);
        off += 32;
        if (!cancel_valid(&out->body.cancel))
            goto reject;
        break;
    default:
        goto reject;
    }
    if (off != wire_len)
        goto reject;
    return true;

reject:
    memset(out, 0, sizeof(*out));
    LOG_FAIL("vcs.swarm", "noncanonical package swarm payload");
}

bool vcs_package_swarm_verify_data(
    const struct vcs_package_manifest *manifest,
    const struct vcs_package_swarm_object *expected_want,
    const struct vcs_package_swarm_data *data)
{
    if (!object_valid(expected_want) || !data_valid(data))
        LOG_FAIL("vcs.swarm", "invalid package swarm data");
    const struct vcs_package_swarm_object *actual = &data->object;
    if (expected_want->request_id != actual->request_id ||
        expected_want->object_kind != actual->object_kind ||
        expected_want->file_index != actual->file_index ||
        expected_want->chunk_index != actual->chunk_index ||
        memcmp(expected_want->package_root, actual->package_root, 32) != 0 ||
        memcmp(expected_want->expected_hash, actual->expected_hash, 32) != 0)
        LOG_FAIL("vcs.swarm", "DATA does not match outstanding WANT");
    if (data->object.object_kind == VCS_PACKAGE_SWARM_OBJECT_MANIFEST) {
        struct vcs_package_manifest parsed;
        if (!vcs_package_manifest_parse(data->bytes, data->bytes_len, &parsed))
            LOG_FAIL("vcs.swarm", "swarm manifest parse failed");
        uint8_t root[32];
        bool ok = vcs_package_manifest_root(&parsed, root) &&
                  memcmp(root, data->object.package_root, 32) == 0;
        vcs_package_manifest_free(&parsed);
        if (!ok)
            LOG_FAIL("vcs.swarm", "swarm manifest root mismatch");
        return true;
    }

    if (!manifest_has_canonical_file_order(manifest))
        LOG_FAIL("vcs.swarm", "swarm manifest file order is noncanonical");
    if (data->object.file_index >= manifest->count)
        LOG_FAIL("vcs.swarm", "swarm chunk file index out of range");
    uint8_t manifest_root[32];
    if (!vcs_package_manifest_root(manifest, manifest_root) ||
        memcmp(manifest_root, data->object.package_root, 32) != 0)
        LOG_FAIL("vcs.swarm", "swarm chunk package root mismatch");
    const struct vcs_package_file *file =
        &manifest->files[data->object.file_index];
    if (data->object.chunk_index >= file->chunk_count)
        LOG_FAIL("vcs.swarm", "swarm chunk index out of range");
    const uint8_t *expected = file->chunk_hashes +
        (size_t)data->object.chunk_index * 32u;
    if (memcmp(expected, data->object.expected_hash, 32) != 0)
        LOG_FAIL("vcs.swarm", "swarm request hash not in manifest");
    if (!vcs_package_verify_chunk(file, data->object.chunk_index,
                                  data->bytes, data->bytes_len))
        LOG_FAIL("vcs.swarm", "swarm chunk verification failed");
    return true;
}
