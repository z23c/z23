/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: ordered epoch accounting for creation-backed ZC23 issuance. */
#include "vcs/zcode_epoch_creation.h"

#include "base/bytes.h"
#include "base/checked.h"
#include "base/safe_alloc.h"
#include "codec/cursor.h"
#include "crypto/sha3.h"
#include "vcs/zcode_creation_attribution.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t epoch_creation_magic[8] = {
    'Z', 'C', 'E', 'P', 'O', 'C', '\r', '\n'
};

void vcs_zcode_epoch_creation_init(
    struct vcs_zcode_epoch_creation_set_v1 *set)
{
    if (set)
        memset(set, 0, sizeof(*set));
}

void vcs_zcode_epoch_creation_free(
    struct vcs_zcode_epoch_creation_set_v1 *set)
{
    if (!set)
        return;
    free(set->attribution_roots);
    memset(set, 0, sizeof(*set));
}

const char *vcs_zcode_epoch_creation_error_string(
    enum vcs_zcode_epoch_creation_error error)
{
    switch (error) {
    case VCS_ZCODE_EPOCH_CREATION_OK: return "ok";
    case VCS_ZCODE_EPOCH_CREATION_NULL: return "null-argument";
    case VCS_ZCODE_EPOCH_CREATION_ALLOC: return "allocation-failed";
    case VCS_ZCODE_EPOCH_CREATION_WIRE_SIZE: return "wire-size";
    case VCS_ZCODE_EPOCH_CREATION_MAGIC: return "wire-magic";
    case VCS_ZCODE_EPOCH_CREATION_SCHEMA: return "schema-version";
    case VCS_ZCODE_EPOCH_CREATION_RESERVED: return "reserved-field";
    case VCS_ZCODE_EPOCH_CREATION_ROOT: return "authority-root";
    case VCS_ZCODE_EPOCH_CREATION_ORDER: return "attribution-order";
    case VCS_ZCODE_EPOCH_CREATION_PREDECESSOR: return "epoch-predecessor";
    case VCS_ZCODE_EPOCH_CREATION_CAP: return "epoch-cap";
    case VCS_ZCODE_EPOCH_CREATION_SUM: return "epoch-sum";
    case VCS_ZCODE_EPOCH_CREATION_TIME: return "anchor-time";
    case VCS_ZCODE_EPOCH_CREATION_OVERFLOW: return "checked-overflow";
    case VCS_ZCODE_EPOCH_CREATION_CONTEXT: return "validation-context";
    case VCS_ZCODE_EPOCH_CREATION_CAS: return "cas-object";
    case VCS_ZCODE_EPOCH_CREATION_ATTRIBUTION: return "creation-attribution";
    case VCS_ZCODE_EPOCH_CREATION_DUPLICATE: return "duplicate-contribution";
    case VCS_ZCODE_EPOCH_CREATION_MINT: return "observed-mint-mismatch";
    case VCS_ZCODE_EPOCH_CREATION_IMMATURE: return "epoch-immature";
    case VCS_ZCODE_EPOCH_CREATION_REORG: return "epoch-anchor-reorged";
    }
    return "unknown-epoch-creation-error";
}

enum vcs_zcode_epoch_creation_error vcs_zc23_policy_epoch_cap_atoms(
    uint64_t epoch, uint64_t *out_atoms)
{
    if (!out_atoms)
        return VCS_ZCODE_EPOCH_CREATION_NULL;
    *out_atoms = 0;
    if (epoch == 0) {
        *out_atoms = VCS_ZC23_INITIAL_SUPPLY_ATOMS;
        return VCS_ZCODE_EPOCH_CREATION_OK;
    }
    uint64_t era = (epoch - 1u) / VCS_ZC23_EPOCHS_PER_ERA;
    enum vcs_zcode_creation_error error =
        vcs_zc23_epoch_cap_atoms(era, out_atoms);
    return error == VCS_ZCODE_CREATION_OK
        ? VCS_ZCODE_EPOCH_CREATION_OK : VCS_ZCODE_EPOCH_CREATION_OVERFLOW;
}

enum vcs_zcode_epoch_creation_error vcs_zcode_epoch_creation_validate(
    const struct vcs_zcode_epoch_creation_set_v1 *set)
{
    if (!set)
        return VCS_ZCODE_EPOCH_CREATION_NULL;
    if (set->schema_version != VCS_ZCODE_EPOCH_CREATION_VERSION)
        return VCS_ZCODE_EPOCH_CREATION_SCHEMA;
    const uint8_t *roots[] = {
        set->network_genesis_root, set->zc23_policy_root,
        set->committee_evidence_snapshot_root, set->opening_hash,
        set->maturity_hash,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32))
            return VCS_ZCODE_EPOCH_CREATION_ROOT;
    bool has_previous = zcl_bytes_any_set(set->previous_epoch_creation_root, 32);
    if ((set->epoch == 0 && has_previous) ||
        (set->epoch != 0 && !has_previous))
        return VCS_ZCODE_EPOCH_CREATION_PREDECESSOR;

    uint64_t expected_cap = 0;
    if (vcs_zc23_policy_epoch_cap_atoms(set->epoch, &expected_cap) !=
            VCS_ZCODE_EPOCH_CREATION_OK ||
        set->emission_cap_atoms != expected_cap)
        return VCS_ZCODE_EPOCH_CREATION_CAP;
    if (set->actual_mint_atoms > set->emission_cap_atoms ||
        set->unissued_atoms !=
            set->emission_cap_atoms - set->actual_mint_atoms ||
        (set->actual_mint_atoms == 0) != (set->attribution_count == 0))
        return VCS_ZCODE_EPOCH_CREATION_SUM;
    if (set->attribution_count >
            VCS_ZCODE_EPOCH_CREATION_MAX_ATTRIBUTIONS ||
        (set->attribution_count != 0 && !set->attribution_roots))
        return VCS_ZCODE_EPOCH_CREATION_ORDER;
    for (size_t i = 0; i < set->attribution_count; i++) {
        if (!zcl_bytes_any_set(set->attribution_roots[i], 32) ||
            (i != 0 && memcmp(set->attribution_roots[i - 1],
                              set->attribution_roots[i], 32) >= 0))
            return VCS_ZCODE_EPOCH_CREATION_ORDER;
    }

    uint64_t minimum_height = 0;
    if (!zcl_u64_add(set->opening_height, VCS_ZC23_CHALLENGE_BLOCKS,
                     &minimum_height) || set->opening_mtp <= 0 ||
        set->opening_mtp > INT64_MAX - VCS_ZC23_CHALLENGE_SECONDS)
        return VCS_ZCODE_EPOCH_CREATION_OVERFLOW;
    if (set->maturity_height < minimum_height ||
        set->maturity_mtp <
            set->opening_mtp + VCS_ZC23_CHALLENGE_SECONDS)
        return VCS_ZCODE_EPOCH_CREATION_TIME;
    return VCS_ZCODE_EPOCH_CREATION_OK;
}

enum vcs_zcode_epoch_creation_error vcs_zcode_epoch_creation_serialize(
    const struct vcs_zcode_epoch_creation_set_v1 *set,
    uint8_t **out, size_t *out_len)
{
    if (out) *out = NULL;
    if (out_len) *out_len = 0;
    if (!set || !out || !out_len)
        return VCS_ZCODE_EPOCH_CREATION_NULL;
    enum vcs_zcode_epoch_creation_error error =
        vcs_zcode_epoch_creation_validate(set);
    if (error != VCS_ZCODE_EPOCH_CREATION_OK)
        return error;
    size_t roots_bytes = 0, wire_len = 0;
    if (!zcl_size_mul(set->attribution_count, 32u, &roots_bytes) ||
        !zcl_size_add(VCS_ZCODE_EPOCH_CREATION_HEADER_BYTES, roots_bytes,
                      &wire_len))
        return VCS_ZCODE_EPOCH_CREATION_OVERFLOW;
    uint8_t *wire = zcl_malloc(wire_len, "zcode_epoch_creation_wire");
    if (!wire)
        return VCS_ZCODE_EPOCH_CREATION_ALLOC;
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, wire, wire_len);
    bool ok = zcl_codec_write_bytes(&writer, epoch_creation_magic, 8) &&
        zcl_codec_write_u16le(&writer, set->schema_version) &&
        zcl_codec_write_u16le(&writer, 0) &&
        zcl_codec_write_u64le(&writer, set->epoch) &&
        zcl_codec_write_u32le(&writer, (uint32_t)set->attribution_count) &&
        zcl_codec_write_u32le(&writer, 0) &&
        zcl_codec_write_u64le(&writer, set->emission_cap_atoms) &&
        zcl_codec_write_u64le(&writer, set->actual_mint_atoms) &&
        zcl_codec_write_u64le(&writer, set->unissued_atoms) &&
        zcl_codec_write_bytes(&writer, set->network_genesis_root, 32) &&
        zcl_codec_write_bytes(&writer, set->zc23_policy_root, 32) &&
        zcl_codec_write_bytes(&writer,
                              set->previous_epoch_creation_root, 32) &&
        zcl_codec_write_bytes(&writer,
                              set->committee_evidence_snapshot_root, 32) &&
        zcl_codec_write_u64le(&writer, set->opening_height) &&
        zcl_codec_write_bytes(&writer, set->opening_hash, 32) &&
        zcl_codec_write_i64le(&writer, set->opening_mtp) &&
        zcl_codec_write_u64le(&writer, set->maturity_height) &&
        zcl_codec_write_bytes(&writer, set->maturity_hash, 32) &&
        zcl_codec_write_i64le(&writer, set->maturity_mtp);
    for (size_t i = 0; ok && i < set->attribution_count; i++)
        ok = zcl_codec_write_bytes(&writer, set->attribution_roots[i], 32);
    size_t written = 0;
    if (!ok || !zcl_codec_writer_finish(&writer, &written) ||
        written != wire_len) {
        free(wire);
        return VCS_ZCODE_EPOCH_CREATION_WIRE_SIZE;
    }
    *out = wire;
    *out_len = wire_len;
    return VCS_ZCODE_EPOCH_CREATION_OK;
}

enum vcs_zcode_epoch_creation_error vcs_zcode_epoch_creation_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_epoch_creation_set_v1 *out)
{
    if (out)
        vcs_zcode_epoch_creation_init(out);
    if (!wire || !out)
        return VCS_ZCODE_EPOCH_CREATION_NULL;
    if (wire_len < VCS_ZCODE_EPOCH_CREATION_HEADER_BYTES ||
        wire_len > VCS_ZCODE_EPOCH_CREATION_MAX_WIRE_BYTES)
        return VCS_ZCODE_EPOCH_CREATION_WIRE_SIZE;
    struct zcl_codec_reader reader;
    uint8_t magic[8]; uint16_t reserved16; uint32_t count, reserved32;
    zcl_codec_reader_init(&reader, wire, wire_len);
    bool ok = zcl_codec_read_bytes(&reader, magic, 8) &&
        zcl_codec_read_u16le(&reader, &out->schema_version) &&
        zcl_codec_read_u16le(&reader, &reserved16) &&
        zcl_codec_read_u64le(&reader, &out->epoch) &&
        zcl_codec_read_u32le(&reader, &count) &&
        zcl_codec_read_u32le(&reader, &reserved32) &&
        zcl_codec_read_u64le(&reader, &out->emission_cap_atoms) &&
        zcl_codec_read_u64le(&reader, &out->actual_mint_atoms) &&
        zcl_codec_read_u64le(&reader, &out->unissued_atoms) &&
        zcl_codec_read_bytes(&reader, out->network_genesis_root, 32) &&
        zcl_codec_read_bytes(&reader, out->zc23_policy_root, 32) &&
        zcl_codec_read_bytes(&reader,
                             out->previous_epoch_creation_root, 32) &&
        zcl_codec_read_bytes(&reader,
                             out->committee_evidence_snapshot_root, 32) &&
        zcl_codec_read_u64le(&reader, &out->opening_height) &&
        zcl_codec_read_bytes(&reader, out->opening_hash, 32) &&
        zcl_codec_read_i64le(&reader, &out->opening_mtp) &&
        zcl_codec_read_u64le(&reader, &out->maturity_height) &&
        zcl_codec_read_bytes(&reader, out->maturity_hash, 32) &&
        zcl_codec_read_i64le(&reader, &out->maturity_mtp);
    size_t roots_bytes = 0, expected = 0;
    if (!ok || count > VCS_ZCODE_EPOCH_CREATION_MAX_ATTRIBUTIONS ||
        !zcl_size_mul(count, 32u, &roots_bytes) ||
        !zcl_size_add(VCS_ZCODE_EPOCH_CREATION_HEADER_BYTES, roots_bytes,
                      &expected) || expected != wire_len) {
        vcs_zcode_epoch_creation_free(out);
        return VCS_ZCODE_EPOCH_CREATION_WIRE_SIZE;
    }
    if (count != 0) {
        out->attribution_roots = zcl_calloc(
            count, 32u, "zcode_epoch_creation_roots");
        if (!out->attribution_roots) {
            vcs_zcode_epoch_creation_free(out);
            return VCS_ZCODE_EPOCH_CREATION_ALLOC;
        }
    }
    out->attribution_count = count;
    for (size_t i = 0; ok && i < count; i++)
        ok = zcl_codec_read_bytes(&reader, out->attribution_roots[i], 32);
    ok = ok && zcl_codec_reader_finish(&reader);
    if (!ok) {
        vcs_zcode_epoch_creation_free(out);
        return VCS_ZCODE_EPOCH_CREATION_WIRE_SIZE;
    }
    if (memcmp(magic, epoch_creation_magic, 8) != 0) {
        vcs_zcode_epoch_creation_free(out);
        return VCS_ZCODE_EPOCH_CREATION_MAGIC;
    }
    if (reserved16 != 0 || reserved32 != 0) {
        vcs_zcode_epoch_creation_free(out);
        return VCS_ZCODE_EPOCH_CREATION_RESERVED;
    }
    enum vcs_zcode_epoch_creation_error error =
        vcs_zcode_epoch_creation_validate(out);
    if (error != VCS_ZCODE_EPOCH_CREATION_OK)
        vcs_zcode_epoch_creation_free(out);
    return error;
}

enum vcs_zcode_epoch_creation_error vcs_zcode_epoch_creation_root(
    const struct vcs_zcode_epoch_creation_set_v1 *set, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!set || !out)
        return VCS_ZCODE_EPOCH_CREATION_NULL;
    uint8_t *wire = NULL; size_t wire_len = 0;
    enum vcs_zcode_epoch_creation_error error =
        vcs_zcode_epoch_creation_serialize(set, &wire, &wire_len);
    if (error != VCS_ZCODE_EPOCH_CREATION_OK)
        return error;
    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_EPOCH_CREATION_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, wire_len);
    sha3_256_finalize(&sha, out);
    free(wire);
    return VCS_ZCODE_EPOCH_CREATION_OK;
}
