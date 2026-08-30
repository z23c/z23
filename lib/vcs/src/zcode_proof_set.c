/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical immutable ZCODE proof-set wire and SHA3 identity. */

#include "vcs/zcode_dev.h"

#include "base/bytes.h"
#include "codec/cursor.h"
#include "crypto/sha3.h"

#include <string.h>

enum vcs_zcode_dev_error vcs_zcode_proof_set_serialize(
    const uint8_t (*roots)[32], size_t count, uint8_t *out,
    size_t out_cap, size_t *out_len)
{
    if (out_len) *out_len = 0;
    if (!roots || !out || !out_len) return VCS_ZCODE_DEV_ERR_NULL;
    if (count == 0 || count > VCS_ZCODE_PROOF_SET_MAX_RECEIPTS)
        return VCS_ZCODE_DEV_ERR_LIMIT;
    size_t need = VCS_ZCODE_PROOF_SET_HEADER_BYTES + count * 32u;
    if (out_cap < need) return VCS_ZCODE_DEV_ERR_WIRE_SIZE;
    for (size_t i = 0; i < count; i++) {
        if (!zcl_bytes_any_set(roots[i], 32)) return VCS_ZCODE_DEV_ERR_ROOT_ZERO;
        if (i > 0 && memcmp(roots[i - 1], roots[i], 32) >= 0)
            return VCS_ZCODE_DEV_ERR_POLICY;
    }
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, out, out_cap);
    bool ok = zcl_codec_write_bytes(&writer, "ZCPSET\r\n", 8) &&
        zcl_codec_write_u16le(&writer, VCS_ZCODE_DEV_VERSION) &&
        zcl_codec_write_u16le(&writer, (uint16_t)count);
    for (size_t i = 0; ok && i < count; i++)
        ok = zcl_codec_write_bytes(&writer, roots[i], 32);
    size_t written = 0;
    if (!ok || !zcl_codec_writer_finish(&writer, &written) || written != need)
        return VCS_ZCODE_DEV_ERR_WIRE_SIZE;
    *out_len = written;
    return VCS_ZCODE_DEV_OK;
}

enum vcs_zcode_dev_error vcs_zcode_proof_set_parse(
    const uint8_t *wire, size_t wire_len, uint8_t (*roots)[32],
    size_t roots_cap, size_t *count)
{
    if (count) *count = 0;
    if (!wire || !roots || !count) return VCS_ZCODE_DEV_ERR_NULL;
    if (wire_len < VCS_ZCODE_PROOF_SET_HEADER_BYTES ||
        memcmp(wire, "ZCPSET\r\n", 8) != 0)
        return VCS_ZCODE_DEV_ERR_WIRE_MAGIC;
    struct zcl_codec_reader reader;
    zcl_codec_reader_init(&reader, wire + 8, wire_len - 8);
    uint16_t version, encoded_count;
    if (!zcl_codec_read_u16le(&reader, &version) ||
        !zcl_codec_read_u16le(&reader, &encoded_count))
        return VCS_ZCODE_DEV_ERR_WIRE_SIZE;
    if (version != VCS_ZCODE_DEV_VERSION)
        return VCS_ZCODE_DEV_ERR_VERSION;
    size_t n = encoded_count;
    if (n == 0 || n > VCS_ZCODE_PROOF_SET_MAX_RECEIPTS || n > roots_cap)
        return VCS_ZCODE_DEV_ERR_LIMIT;
    if (wire_len != VCS_ZCODE_PROOF_SET_HEADER_BYTES + n * 32u)
        return VCS_ZCODE_DEV_ERR_WIRE_SIZE;
    for (size_t i = 0; i < n; i++)
        if (!zcl_codec_read_bytes(&reader, roots[i], 32))
            return VCS_ZCODE_DEV_ERR_WIRE_SIZE;
    if (!zcl_codec_reader_finish(&reader))
        return VCS_ZCODE_DEV_ERR_WIRE_SIZE;
    size_t checked_len = 0;
    enum vcs_zcode_dev_error valid = vcs_zcode_proof_set_serialize(
        (const uint8_t (*)[32])roots, n,
        (uint8_t[VCS_ZCODE_PROOF_SET_WIRE_MAX]){0},
        VCS_ZCODE_PROOF_SET_WIRE_MAX, &checked_len);
    if (valid != VCS_ZCODE_DEV_OK || checked_len != wire_len) return valid;
    *count = n;
    return VCS_ZCODE_DEV_OK;
}

enum vcs_zcode_dev_error vcs_zcode_proof_set_root(
    const uint8_t (*roots)[32], size_t count, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_DEV_ERR_NULL;
    uint8_t wire[VCS_ZCODE_PROOF_SET_WIRE_MAX];
    size_t wire_len = 0;
    enum vcs_zcode_dev_error valid = vcs_zcode_proof_set_serialize(
        roots, count, wire, sizeof(wire), &wire_len);
    if (valid != VCS_ZCODE_DEV_OK) return valid;
    static const char domain[] = VCS_ZCODE_PROOF_SET_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, wire_len);
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_DEV_OK;
}
