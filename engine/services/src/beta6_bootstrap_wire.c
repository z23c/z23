/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: CDataStream codec for the beta6 bootstrap manifest, chunk request and chunk.
 *
 * Byte-for-byte port of the ADD_SERIALIZE_METHODS bodies in the beta6 tree's
 * src/protocol.h (CBootstrapSnapshotFile :185-207, CBootstrapSnapshotManifest
 * :205-289, CBootstrapSnapshotChunkRequest :292-318, CBootstrapSnapshotChunk
 * :320-345). Field order and the version gates are wire contract with a
 * deployed swarm: append only, never reorder, never make a v2/v3 field
 * unconditional.
 *
 * uint256 travels as its 32 internal bytes with no reordering, which is the
 * REVERSE of the displayed hex — struct uint256 already carries that
 * convention (core/math/src/uint256.c blob_set_hex), so a hash parsed with
 * uint256_set_hex serializes exactly as the C++ one does.
 *
 * The static field helpers stay bool: a single one of them can only fail one
 * way, by running out of stream, and each exported entry point below turns
 * that into one named zcl_result naming the record that did not fit.
 */
#include "services/beta6_bootstrap.h"
#include "base/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

/* LIMITED_STRING(s, cap): CompactSize length + raw bytes, with the cap
 * enforced on READ only (protocol.h:164-174), so v1/v2/v3 bytes are
 * unchanged. */
static bool write_limited_string(struct byte_stream *out, const char *value)
{
    size_t len = strlen(value);
    return stream_write_compact_size(out, (uint64_t)len) &&
           (len == 0 || stream_write_bytes(out, (const unsigned char *)value, len));
}

static bool read_limited_string(struct byte_stream *in, char *out, size_t cap)
{
    uint64_t len = 0;
    bool ok = stream_read_compact_size(in, &len) && len < (uint64_t)cap &&
              (len == 0 || stream_read_bytes(in, (unsigned char *)out, (size_t)len));
    if (!ok)
        return false;
    out[len] = '\0';
    return true;
}

static bool write_uint256(struct byte_stream *out, const struct uint256 *value)
{
    return stream_write_bytes(out, value->data, 32);
}

static bool read_uint256(struct byte_stream *in, struct uint256 *out)
{
    return stream_read_bytes(in, out->data, 32);
}

static bool write_file_entry(struct byte_stream *out, const struct beta6_bs_file *file)
{
    return write_limited_string(out, file->path) &&
           stream_write_u64_le(out, file->size) && write_uint256(out, &file->sha256);
}

static bool read_file_entry(struct byte_stream *in, struct beta6_bs_file *out)
{
    memset(out, 0, sizeof(*out));
    return read_limited_string(in, out->path, BETA6_BS_MAX_PATH_LEN) &&
           stream_read_u64_le(in, &out->size) && read_uint256(in, &out->sha256);
}

/* The fields every manifest version carries, in order. */
static bool write_manifest_common(struct byte_stream *out,
                                  const struct beta6_bs_manifest *manifest)
{
    return stream_write_i32_le(out, manifest->version) &&
           write_limited_string(out, manifest->network) &&
           stream_write_i32_le(out, manifest->height) &&
           write_uint256(out, &manifest->hash_block) &&
           write_uint256(out, &manifest->hash_anchor_sha256) &&
           write_uint256(out, &manifest->hash_anchor_sha3) &&
           stream_write_u64_le(out, manifest->snapshot_bytes) &&
           stream_write_u32_le(out, manifest->chunk_size);
}

static bool read_manifest_common(struct byte_stream *in, struct beta6_bs_manifest *out)
{
    return stream_read_i32_le(in, &out->version) &&
           read_limited_string(in, out->network, BETA6_BS_MAX_NETWORK_LEN) &&
           stream_read_i32_le(in, &out->height) && read_uint256(in, &out->hash_block) &&
           read_uint256(in, &out->hash_anchor_sha256) &&
           read_uint256(in, &out->hash_anchor_sha3) &&
           stream_read_u64_le(in, &out->snapshot_bytes) &&
           stream_read_u32_le(in, &out->chunk_size);
}

/* The version-gated appends. nVersion is read first, so on the read side this
 * condition reflects the WIRE version, exactly as the C++ template does. */
static bool write_manifest_tail(struct byte_stream *out,
                                const struct beta6_bs_manifest *manifest)
{
    if (manifest->version >= 2 && !write_uint256(out, &manifest->hash_chainstate))
        return false;
    if (manifest->version < 3)
        return true;
    return stream_write_i32_le(out, manifest->block_tip_height) &&
           write_uint256(out, &manifest->hash_block_tip);
}

static bool read_manifest_tail(struct byte_stream *in, struct beta6_bs_manifest *out)
{
    if (out->version >= 2 && !read_uint256(in, &out->hash_chainstate))
        return false;
    if (out->version < 3)
        return true;
    return stream_read_i32_le(in, &out->block_tip_height) &&
           read_uint256(in, &out->hash_block_tip);
}

static bool write_file_entries(struct byte_stream *out,
                               const struct beta6_bs_manifest *manifest)
{
    if (!stream_write_compact_size(out, (uint64_t)manifest->file_count))
        return false;  // raw-return-ok:the exported encoder names the record that did not fit
    for (size_t i = 0; i < manifest->file_count; i++) {
        if (!write_file_entry(out, &manifest->files[i]))
            return false;  // raw-return-ok:same, with the index named by the caller
    }
    return true;
}

struct zcl_result beta6_bs_manifest_encode(const struct beta6_bs_manifest *manifest,
                                           struct byte_stream *out)
{
    if (!manifest || !out)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 manifest encode needs a manifest and a stream");
    if (manifest->file_count > BETA6_BS_MAX_FILES)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 manifest holds %zu files, over the %u cap",
                       manifest->file_count, (unsigned)BETA6_BS_MAX_FILES);
    if (!write_manifest_common(out, manifest))
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 manifest header did not fit in the stream");
    if (!write_file_entries(out, manifest))
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 manifest file list did not fit in the stream");
    if (!write_manifest_tail(out, manifest))
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 manifest v%d tail did not fit in the stream",
                       (int)manifest->version);
    return ZCL_OK;
}

static bool read_file_entries(struct byte_stream *in, struct beta6_bs_manifest *out)
{
    for (size_t i = 0; i < out->file_count; i++) {
        if (!read_file_entry(in, &out->files[i]))
            return false;  // raw-return-ok:the exported decoder names the truncated list
    }
    return true;
}

struct zcl_result beta6_bs_manifest_decode(struct byte_stream *in,
                                           struct beta6_bs_manifest *out)
{
    if (!in || !out)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 manifest decode needs a stream and an output");
    beta6_bs_manifest_init(out);
    if (!read_manifest_common(in, out))
        return ZCL_ERR(BETA6_BS_ERR_REFUSED, "beta6 manifest header is truncated");

    uint64_t count = 0;
    if (!stream_read_compact_size(in, &count) || count > BETA6_BS_MAX_FILES)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 manifest file count is missing or over the %u cap",
                       (unsigned)BETA6_BS_MAX_FILES);
    if (count > 0) {
        out->files = zcl_calloc((size_t)count, sizeof(*out->files),
                                "beta6 bootstrap manifest files");
        if (!out->files)
            return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                           "out of memory for %llu beta6 manifest files",
                           (unsigned long long)count);
    }
    out->file_count = (size_t)count;
    if (!read_file_entries(in, out))
        return ZCL_ERR(BETA6_BS_ERR_REFUSED, "beta6 manifest file list is truncated");
    if (!read_manifest_tail(in, out))
        return ZCL_ERR(BETA6_BS_ERR_REFUSED, "beta6 manifest v%d tail is truncated",
                       (int)out->version);
    return ZCL_OK;
}

struct zcl_result beta6_bs_chunk_request_encode(
    const struct beta6_bs_chunk_request *request, struct byte_stream *out)
{
    if (!request || !out)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 chunk request encode needs a request and a stream");
    if (!stream_write_u32_le(out, request->file_index) ||
        !stream_write_u64_le(out, request->offset) ||
        !stream_write_u32_le(out, request->length))
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 chunk request did not fit in the stream");
    return ZCL_OK;
}

struct zcl_result beta6_bs_chunk_request_decode(struct byte_stream *in,
                                                struct beta6_bs_chunk_request *out)
{
    if (!in || !out)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 chunk request decode needs a stream and an output");
    memset(out, 0, sizeof(*out));
    if (!stream_read_u32_le(in, &out->file_index) ||
        !stream_read_u64_le(in, &out->offset) || !stream_read_u32_le(in, &out->length))
        return ZCL_ERR(BETA6_BS_ERR_REFUSED, "beta6 chunk request is truncated");
    return ZCL_OK;
}

struct zcl_result beta6_bs_chunk_encode(uint32_t file_index, uint64_t offset,
                                        const unsigned char *data, size_t data_len,
                                        struct byte_stream *out)
{
    if (!out || (!data && data_len > 0))
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 chunk encode needs a stream and %zu bytes of data",
                       data_len);
    if (data_len > BETA6_BS_CHUNK_SIZE)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 chunk of %zu bytes is over the %u chunk size", data_len,
                       (unsigned)BETA6_BS_CHUNK_SIZE);
    if (!stream_write_u32_le(out, file_index) || !stream_write_u64_le(out, offset) ||
        !stream_write_compact_size(out, (uint64_t)data_len))
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 chunk header did not fit in the stream");
    if (data_len > 0 && !stream_write_bytes(out, data, data_len))
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 chunk body of %zu bytes did not fit in the stream",
                       data_len);
    return ZCL_OK;
}

void beta6_bs_manifest_init(struct beta6_bs_manifest *manifest)
{
    if (!manifest)
        return;
    memset(manifest, 0, sizeof(*manifest));
    manifest->version = 1;
    manifest->height = -1;
    manifest->block_tip_height = -1;
}

void beta6_bs_manifest_free(struct beta6_bs_manifest *manifest)
{
    if (!manifest)
        return;
    free(manifest->files);
    manifest->files = NULL;
    manifest->file_count = 0;
}
