/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical S4 benchmark-execution receipt codecs (see the header
 *          for the object model: observation, never truth). */

#include "vcs/zcode_benchmark_receipt.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "vcs/signed_evidence.h"

#include <string.h>

static const uint8_t workload_magic[8] = {'Z','C','W','R','K','1','\r','\n'};
static const uint8_t manifest_magic[8] = {'Z','C','R','S','M','1','\r','\n'};
static const uint8_t payload_magic[8] = {'Z','C','S','P','L','1','\r','\n'};
static const uint8_t evidence_magic[8] = {'Z','C','B','E','V','1','\r','\n'};
static const uint8_t env_policy_magic[8] =
    {'Z','C','E','N','P','1','\r','\n'};

static bool root_nonzero(const uint8_t root[32])
{
    return zcl_bytes_any_set(root, 32);
}

/* The zcode_science.c fixed-width string rule: content bytes, one NUL,
 * then zeros to the field width; all-zero ("undisclosed") is always sane. */
static bool padded_field_sane(const uint8_t *field, size_t len)
{
    size_t i = 0;
    while (i < len && field[i] != 0) i++;
    if (i == len) return false;
    for (; i < len; i++)
        if (field[i] != 0) return false;
    return true;
}

static void put_bytes(uint8_t *wire, size_t *off, const void *src, size_t len)
{
    memcpy(wire + *off, src, len);
    *off += len;
}

static void put_u16(uint8_t *wire, size_t *off, uint16_t value)
{
    zcl_write_u16_le(wire + *off, value);
    *off += 2;
}

static void put_u64(uint8_t *wire, size_t *off, uint64_t value)
{
    zcl_write_u64_le(wire + *off, value);
    *off += 8;
}

static void get_bytes(const uint8_t *wire, size_t *off, void *out, size_t len)
{
    memcpy(out, wire + *off, len);
    *off += len;
}

static uint16_t get_u16(const uint8_t *wire, size_t *off)
{
    uint16_t value = zcl_read_u16_le(wire + *off);
    *off += 2;
    return value;
}

static uint64_t get_u64(const uint8_t *wire, size_t *off)
{
    uint64_t value = zcl_read_u64_le(wire + *off);
    *off += 8;
    return value;
}

const char *vcs_zcode_receipt_error_string(enum vcs_zcode_receipt_error error)
{
    switch (error) {
    case VCS_ZCODE_RECEIPT_OK: return "ok";
    case VCS_ZCODE_RECEIPT_ERR_NULL: return "null-argument";
    case VCS_ZCODE_RECEIPT_ERR_VERSION: return "schema-version";
    case VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE: return "wire-size";
    case VCS_ZCODE_RECEIPT_ERR_WIRE_MAGIC: return "wire-magic";
    case VCS_ZCODE_RECEIPT_ERR_ROOT_ZERO: return "root-zero";
    case VCS_ZCODE_RECEIPT_ERR_LIMIT: return "limit-invalid";
    case VCS_ZCODE_RECEIPT_ERR_STATUS: return "benchmark-status-invalid";
    case VCS_ZCODE_RECEIPT_ERR_ISOLATION: return "isolation-invalid";
    case VCS_ZCODE_RECEIPT_ERR_ORDER: return "sample-order-invalid";
    case VCS_ZCODE_RECEIPT_ERR_ISA: return "isa-bits-unknown";
    case VCS_ZCODE_RECEIPT_ERR_PADDING: return "padding-invalid";
    case VCS_ZCODE_RECEIPT_ERR_RESERVED: return "reserved-nonzero";
    }
    return "unknown";
}

/* ── workload bundle v1 ─────────────────────────────────────────────── */

enum vcs_zcode_receipt_error vcs_zcode_benchmark_workload_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_benchmark_workload_v1_view *out)
{
    if (!wire || !out) return VCS_ZCODE_RECEIPT_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len < VCS_ZCODE_BENCHMARK_WORKLOAD_HEADER_BYTES ||
        wire_len > VCS_ZCODE_BENCHMARK_WORKLOAD_HEADER_BYTES +
                       VCS_ZCODE_BENCHMARK_WORKLOAD_MAX_PAYLOAD_BYTES)
        return VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE;
    if (memcmp(wire, workload_magic, sizeof(workload_magic)) != 0)
        return VCS_ZCODE_RECEIPT_ERR_WIRE_MAGIC;
    size_t off = sizeof(workload_magic);
    uint16_t version = get_u16(wire, &off);
    if (version != VCS_ZCODE_BENCHMARK_WORKLOAD_VERSION)
        return VCS_ZCODE_RECEIPT_ERR_VERSION;
    uint64_t payload_len = get_u64(wire, &off);
    if (payload_len > VCS_ZCODE_BENCHMARK_WORKLOAD_MAX_PAYLOAD_BYTES)
        return VCS_ZCODE_RECEIPT_ERR_LIMIT;
    /* Exact-length: one payload_len byte too many or too few is a
     * rejection — there is no legal trailing byte. */
    if (wire_len != VCS_ZCODE_BENCHMARK_WORKLOAD_HEADER_BYTES + payload_len)
        return VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE;
    out->schema_version = version;
    out->payload = wire + off;
    out->payload_len = payload_len;
    return VCS_ZCODE_RECEIPT_OK;
}

enum vcs_zcode_receipt_error vcs_zcode_benchmark_workload_v1_serialize(
    const uint8_t *payload, uint64_t payload_len, uint8_t *out,
    size_t out_cap)
{
    if (!out || (payload_len && !payload)) return VCS_ZCODE_RECEIPT_ERR_NULL;
    if (payload_len > VCS_ZCODE_BENCHMARK_WORKLOAD_MAX_PAYLOAD_BYTES)
        return VCS_ZCODE_RECEIPT_ERR_LIMIT;
    if (out_cap < VCS_ZCODE_BENCHMARK_WORKLOAD_HEADER_BYTES + payload_len)
        return VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE;
    size_t off = 0;
    put_bytes(out, &off, workload_magic, sizeof(workload_magic));
    put_u16(out, &off, VCS_ZCODE_BENCHMARK_WORKLOAD_VERSION);
    put_u64(out, &off, payload_len);
    if (payload_len)
        put_bytes(out, &off, payload, payload_len);
    return VCS_ZCODE_RECEIPT_OK;
}

enum vcs_zcode_receipt_error vcs_zcode_benchmark_workload_v1_root(
    const uint8_t *wire, size_t wire_len, uint8_t out[32])
{
    struct vcs_zcode_benchmark_workload_v1_view view;
    enum vcs_zcode_receipt_error error =
        vcs_zcode_benchmark_workload_v1_parse(wire, wire_len, &view);
    if (error != VCS_ZCODE_RECEIPT_OK || !out)
        return out ? error : VCS_ZCODE_RECEIPT_ERR_NULL;
    static const char domain[] = VCS_ZCODE_BENCHMARK_WORKLOAD_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), wire, wire_len,
                                    out)
               ? VCS_ZCODE_RECEIPT_OK : VCS_ZCODE_RECEIPT_ERR_NULL;
}

/* ── raw-sample manifest v1 ─────────────────────────────────────────── */

enum vcs_zcode_receipt_error vcs_zcode_raw_sample_manifest_v1_validate(
    const struct vcs_zcode_raw_sample_manifest_v1 *manifest)
{
    if (!manifest) return VCS_ZCODE_RECEIPT_ERR_NULL;
    if (manifest->schema_version != VCS_ZCODE_RAW_SAMPLE_MANIFEST_VERSION)
        return VCS_ZCODE_RECEIPT_ERR_VERSION;
    if (!root_nonzero(manifest->method_root) ||
        !root_nonzero(manifest->workload_root))
        return VCS_ZCODE_RECEIPT_ERR_ROOT_ZERO;
    if (manifest->measured_samples == 0 ||
        manifest->measured_samples >
            VCS_ZCODE_SAMPLE_PAYLOAD_MAX_SAMPLES ||
        manifest->warmup_samples > VCS_ZCODE_SAMPLE_PAYLOAD_MAX_SAMPLES)
        return VCS_ZCODE_RECEIPT_ERR_LIMIT;
    if (!padded_field_sane(manifest->timer_source,
                           sizeof(manifest->timer_source)))
        return VCS_ZCODE_RECEIPT_ERR_PADDING;
    return VCS_ZCODE_RECEIPT_OK;
}

enum vcs_zcode_receipt_error vcs_zcode_raw_sample_manifest_v1_serialize(
    const struct vcs_zcode_raw_sample_manifest_v1 *manifest,
    uint8_t out[VCS_ZCODE_RAW_SAMPLE_MANIFEST_WIRE_BYTES])
{
    enum vcs_zcode_receipt_error error =
        vcs_zcode_raw_sample_manifest_v1_validate(manifest);
    if (error != VCS_ZCODE_RECEIPT_OK || !out)
        return out ? error : VCS_ZCODE_RECEIPT_ERR_NULL;
    size_t off = 0;
    put_bytes(out, &off, manifest_magic, sizeof(manifest_magic));
    put_u16(out, &off, manifest->schema_version);
    put_bytes(out, &off, manifest->method_root, 32);
    put_bytes(out, &off, manifest->workload_root, 32);
    put_u64(out, &off, manifest->warmup_samples);
    put_u64(out, &off, manifest->measured_samples);
    put_bytes(out, &off, manifest->timer_source,
              sizeof(manifest->timer_source));
    return off == VCS_ZCODE_RAW_SAMPLE_MANIFEST_WIRE_BYTES
               ? VCS_ZCODE_RECEIPT_OK : VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE;
}

enum vcs_zcode_receipt_error vcs_zcode_raw_sample_manifest_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_raw_sample_manifest_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_RECEIPT_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_RAW_SAMPLE_MANIFEST_WIRE_BYTES)
        return VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE;
    if (memcmp(wire, manifest_magic, sizeof(manifest_magic)) != 0)
        return VCS_ZCODE_RECEIPT_ERR_WIRE_MAGIC;
    size_t off = sizeof(manifest_magic);
    out->schema_version = get_u16(wire, &off);
    get_bytes(wire, &off, out->method_root, 32);
    get_bytes(wire, &off, out->workload_root, 32);
    out->warmup_samples = get_u64(wire, &off);
    out->measured_samples = get_u64(wire, &off);
    get_bytes(wire, &off, out->timer_source, sizeof(out->timer_source));
    enum vcs_zcode_receipt_error error =
        vcs_zcode_raw_sample_manifest_v1_validate(out);
    if (error != VCS_ZCODE_RECEIPT_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_receipt_error vcs_zcode_raw_sample_manifest_v1_root(
    const struct vcs_zcode_raw_sample_manifest_v1 *manifest, uint8_t out[32])
{
    uint8_t wire[VCS_ZCODE_RAW_SAMPLE_MANIFEST_WIRE_BYTES];
    enum vcs_zcode_receipt_error error =
        vcs_zcode_raw_sample_manifest_v1_serialize(manifest, wire);
    if (error != VCS_ZCODE_RECEIPT_OK || !out)
        return out ? error : VCS_ZCODE_RECEIPT_ERR_NULL;
    static const char domain[] = VCS_ZCODE_RAW_SAMPLE_MANIFEST_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), wire,
                                    sizeof(wire), out)
               ? VCS_ZCODE_RECEIPT_OK : VCS_ZCODE_RECEIPT_ERR_NULL;
}

/* ── sample payload v1 ──────────────────────────────────────────────── */

enum vcs_zcode_receipt_error vcs_zcode_sample_payload_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_sample_payload_v1_view *out)
{
    if (!wire || !out) return VCS_ZCODE_RECEIPT_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len < VCS_ZCODE_SAMPLE_PAYLOAD_HEADER_BYTES + 8u ||
        wire_len > VCS_ZCODE_SAMPLE_PAYLOAD_HEADER_BYTES +
                       8u * VCS_ZCODE_SAMPLE_PAYLOAD_MAX_SAMPLES)
        return VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE;
    if (memcmp(wire, payload_magic, sizeof(payload_magic)) != 0)
        return VCS_ZCODE_RECEIPT_ERR_WIRE_MAGIC;
    size_t off = sizeof(payload_magic);
    uint16_t version = get_u16(wire, &off);
    if (version != VCS_ZCODE_SAMPLE_PAYLOAD_VERSION)
        return VCS_ZCODE_RECEIPT_ERR_VERSION;
    uint64_t count = get_u64(wire, &off);
    if (count == 0 || count > VCS_ZCODE_SAMPLE_PAYLOAD_MAX_SAMPLES)
        return VCS_ZCODE_RECEIPT_ERR_LIMIT;
    if (wire_len != VCS_ZCODE_SAMPLE_PAYLOAD_HEADER_BYTES + 8u * count)
        return VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE;
    out->schema_version = version;
    out->sample_bytes = wire + off;
    out->count = count;
    return VCS_ZCODE_RECEIPT_OK;
}

bool vcs_zcode_sample_payload_v1_sample_at(
    const struct vcs_zcode_sample_payload_v1_view *view, uint64_t i,
    uint64_t *out)
{
    if (!view || !out || !view->sample_bytes || i >= view->count)
        return false;
    *out = zcl_read_u64_le(view->sample_bytes + 8u * i);
    return true;
}

enum vcs_zcode_receipt_error vcs_zcode_sample_payload_v1_serialize(
    const uint64_t *samples, uint64_t count, uint8_t *out, size_t out_cap)
{
    if (!out || !samples) return VCS_ZCODE_RECEIPT_ERR_NULL;
    if (count == 0 || count > VCS_ZCODE_SAMPLE_PAYLOAD_MAX_SAMPLES)
        return VCS_ZCODE_RECEIPT_ERR_LIMIT;
    if (out_cap < VCS_ZCODE_SAMPLE_PAYLOAD_HEADER_BYTES + 8u * count)
        return VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE;
    size_t off = 0;
    put_bytes(out, &off, payload_magic, sizeof(payload_magic));
    put_u16(out, &off, VCS_ZCODE_SAMPLE_PAYLOAD_VERSION);
    put_u64(out, &off, count);
    for (uint64_t i = 0; i < count; i++)
        put_u64(out, &off, samples[i]);
    return VCS_ZCODE_RECEIPT_OK;
}

enum vcs_zcode_receipt_error vcs_zcode_sample_payload_v1_root(
    const uint8_t *wire, size_t wire_len, uint8_t out[32])
{
    struct vcs_zcode_sample_payload_v1_view view;
    enum vcs_zcode_receipt_error error =
        vcs_zcode_sample_payload_v1_parse(wire, wire_len, &view);
    if (error != VCS_ZCODE_RECEIPT_OK || !out)
        return out ? error : VCS_ZCODE_RECEIPT_ERR_NULL;
    static const char domain[] = VCS_ZCODE_SAMPLE_PAYLOAD_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), wire, wire_len,
                                    out)
               ? VCS_ZCODE_RECEIPT_OK : VCS_ZCODE_RECEIPT_ERR_NULL;
}

/* ── benchmark evidence v1 ──────────────────────────────────────────── */

enum vcs_zcode_receipt_error vcs_zcode_benchmark_evidence_v1_validate(
    const struct vcs_zcode_benchmark_evidence_v1 *evidence)
{
    if (!evidence) return VCS_ZCODE_RECEIPT_ERR_NULL;
    if (evidence->schema_version != VCS_ZCODE_BENCHMARK_EVIDENCE_VERSION)
        return VCS_ZCODE_RECEIPT_ERR_VERSION;
    if (!root_nonzero(evidence->action_root) ||
        !root_nonzero(evidence->manifest_root) ||
        !root_nonzero(evidence->sample_payload_root))
        return VCS_ZCODE_RECEIPT_ERR_ROOT_ZERO;
    if (evidence->status < VCS_ZCODE_BENCHMARK_OBSERVED ||
        evidence->status > VCS_ZCODE_BENCHMARK_EXECUTION_FAILED)
        return VCS_ZCODE_RECEIPT_ERR_STATUS;
    if (evidence->isolation != VCS_ZCODE_BENCHMARK_ISOLATION_FULL &&
        evidence->isolation != VCS_ZCODE_BENCHMARK_ISOLATION_DEGRADED)
        return VCS_ZCODE_RECEIPT_ERR_ISOLATION;
    if (evidence->min_ns > evidence->median_ns ||
        evidence->median_ns > evidence->max_ns)
        return VCS_ZCODE_RECEIPT_ERR_ORDER;
    if (zcl_bytes_any_set(evidence->reserved, sizeof(evidence->reserved)))
        return VCS_ZCODE_RECEIPT_ERR_RESERVED;
    return VCS_ZCODE_RECEIPT_OK;
}

enum vcs_zcode_receipt_error vcs_zcode_benchmark_evidence_v1_serialize(
    const struct vcs_zcode_benchmark_evidence_v1 *evidence,
    uint8_t out[VCS_ZCODE_BENCHMARK_EVIDENCE_WIRE_BYTES])
{
    enum vcs_zcode_receipt_error error =
        vcs_zcode_benchmark_evidence_v1_validate(evidence);
    if (error != VCS_ZCODE_RECEIPT_OK || !out)
        return out ? error : VCS_ZCODE_RECEIPT_ERR_NULL;
    size_t off = 0;
    put_bytes(out, &off, evidence_magic, sizeof(evidence_magic));
    put_u16(out, &off, evidence->schema_version);
    put_bytes(out, &off, evidence->action_root, 32);
    put_bytes(out, &off, evidence->manifest_root, 32);
    put_bytes(out, &off, evidence->sample_payload_root, 32);
    put_u64(out, &off, evidence->min_ns);
    put_u64(out, &off, evidence->median_ns);
    put_u64(out, &off, evidence->max_ns);
    out[off++] = evidence->status;
    out[off++] = evidence->isolation;
    put_bytes(out, &off, evidence->reserved, sizeof(evidence->reserved));
    return off == VCS_ZCODE_BENCHMARK_EVIDENCE_WIRE_BYTES
               ? VCS_ZCODE_RECEIPT_OK : VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE;
}

enum vcs_zcode_receipt_error vcs_zcode_benchmark_evidence_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_benchmark_evidence_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_RECEIPT_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_BENCHMARK_EVIDENCE_WIRE_BYTES)
        return VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE;
    if (memcmp(wire, evidence_magic, sizeof(evidence_magic)) != 0)
        return VCS_ZCODE_RECEIPT_ERR_WIRE_MAGIC;
    size_t off = sizeof(evidence_magic);
    out->schema_version = get_u16(wire, &off);
    get_bytes(wire, &off, out->action_root, 32);
    get_bytes(wire, &off, out->manifest_root, 32);
    get_bytes(wire, &off, out->sample_payload_root, 32);
    out->min_ns = get_u64(wire, &off);
    out->median_ns = get_u64(wire, &off);
    out->max_ns = get_u64(wire, &off);
    out->status = wire[off++];
    out->isolation = wire[off++];
    get_bytes(wire, &off, out->reserved, sizeof(out->reserved));
    enum vcs_zcode_receipt_error error =
        vcs_zcode_benchmark_evidence_v1_validate(out);
    if (error != VCS_ZCODE_RECEIPT_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_receipt_error vcs_zcode_benchmark_evidence_v1_root(
    const struct vcs_zcode_benchmark_evidence_v1 *evidence, uint8_t out[32])
{
    uint8_t wire[VCS_ZCODE_BENCHMARK_EVIDENCE_WIRE_BYTES];
    enum vcs_zcode_receipt_error error =
        vcs_zcode_benchmark_evidence_v1_serialize(evidence, wire);
    if (error != VCS_ZCODE_RECEIPT_OK || !out)
        return out ? error : VCS_ZCODE_RECEIPT_ERR_NULL;
    static const char domain[] = VCS_ZCODE_BENCHMARK_EVIDENCE_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), wire,
                                    sizeof(wire), out)
               ? VCS_ZCODE_RECEIPT_OK : VCS_ZCODE_RECEIPT_ERR_NULL;
}

/* ── environment policy v1 ──────────────────────────────────────────── */

enum vcs_zcode_receipt_error vcs_zcode_environment_policy_v1_validate(
    const struct vcs_zcode_environment_policy_v1 *policy)
{
    if (!policy) return VCS_ZCODE_RECEIPT_ERR_NULL;
    if (policy->schema_version != VCS_ZCODE_ENVIRONMENT_POLICY_VERSION)
        return VCS_ZCODE_RECEIPT_ERR_VERSION;
    if ((policy->required_isa_bits & ~VCS_ZCODE_HW_ISA_KNOWN_MASK) != 0)
        return VCS_ZCODE_RECEIPT_ERR_ISA;
    if (!padded_field_sane(policy->required_timer_source,
                           sizeof(policy->required_timer_source)))
        return VCS_ZCODE_RECEIPT_ERR_PADDING;
    if (zcl_bytes_any_set(policy->reserved, sizeof(policy->reserved)))
        return VCS_ZCODE_RECEIPT_ERR_RESERVED;
    return VCS_ZCODE_RECEIPT_OK;
}

enum vcs_zcode_receipt_error vcs_zcode_environment_policy_v1_serialize(
    const struct vcs_zcode_environment_policy_v1 *policy,
    uint8_t out[VCS_ZCODE_ENVIRONMENT_POLICY_WIRE_BYTES])
{
    enum vcs_zcode_receipt_error error =
        vcs_zcode_environment_policy_v1_validate(policy);
    if (error != VCS_ZCODE_RECEIPT_OK || !out)
        return out ? error : VCS_ZCODE_RECEIPT_ERR_NULL;
    size_t off = 0;
    put_bytes(out, &off, env_policy_magic, sizeof(env_policy_magic));
    put_u16(out, &off, policy->schema_version);
    put_u64(out, &off, policy->required_isa_bits);
    zcl_write_u16_le(out + off, policy->min_physical_cores);
    off += 2;
    zcl_write_u16_le(out + off, policy->min_logical_cores);
    off += 2;
    put_u64(out, &off, policy->min_ram_mib);
    put_bytes(out, &off, policy->required_timer_source,
              sizeof(policy->required_timer_source));
    put_bytes(out, &off, policy->reserved, sizeof(policy->reserved));
    return off == VCS_ZCODE_ENVIRONMENT_POLICY_WIRE_BYTES
               ? VCS_ZCODE_RECEIPT_OK : VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE;
}

enum vcs_zcode_receipt_error vcs_zcode_environment_policy_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_environment_policy_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_RECEIPT_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_ENVIRONMENT_POLICY_WIRE_BYTES)
        return VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE;
    if (memcmp(wire, env_policy_magic, sizeof(env_policy_magic)) != 0)
        return VCS_ZCODE_RECEIPT_ERR_WIRE_MAGIC;
    size_t off = sizeof(env_policy_magic);
    out->schema_version = get_u16(wire, &off);
    out->required_isa_bits = get_u64(wire, &off);
    out->min_physical_cores = zcl_read_u16_le(wire + off);
    off += 2;
    out->min_logical_cores = zcl_read_u16_le(wire + off);
    off += 2;
    out->min_ram_mib = get_u64(wire, &off);
    get_bytes(wire, &off, out->required_timer_source,
              sizeof(out->required_timer_source));
    get_bytes(wire, &off, out->reserved, sizeof(out->reserved));
    enum vcs_zcode_receipt_error error =
        vcs_zcode_environment_policy_v1_validate(out);
    if (error != VCS_ZCODE_RECEIPT_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_receipt_error vcs_zcode_environment_policy_v1_root(
    const struct vcs_zcode_environment_policy_v1 *policy, uint8_t out[32])
{
    uint8_t wire[VCS_ZCODE_ENVIRONMENT_POLICY_WIRE_BYTES];
    enum vcs_zcode_receipt_error error =
        vcs_zcode_environment_policy_v1_serialize(policy, wire);
    if (error != VCS_ZCODE_RECEIPT_OK || !out)
        return out ? error : VCS_ZCODE_RECEIPT_ERR_NULL;
    static const char domain[] = VCS_ZCODE_ENVIRONMENT_POLICY_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), wire,
                                    sizeof(wire), out)
               ? VCS_ZCODE_RECEIPT_OK : VCS_ZCODE_RECEIPT_ERR_NULL;
}

bool vcs_zcode_environment_policy_v1_accepts(
    const struct vcs_zcode_environment_policy_v1 *policy,
    const struct vcs_zcode_hardware_profile_v1 *profile)
{
    if (!policy || !profile) return false;
    if ((profile->isa_bits & policy->required_isa_bits) !=
        policy->required_isa_bits)
        return false;
    if (profile->physical_cores < policy->min_physical_cores ||
        profile->logical_cores < policy->min_logical_cores)
        return false;
    if (profile->ram_mib < policy->min_ram_mib)
        return false;
    if (zcl_bytes_any_set(policy->required_timer_source,
                      sizeof(policy->required_timer_source)) &&
        memcmp(policy->required_timer_source, profile->timer_source,
               sizeof(policy->required_timer_source)) != 0)
        return false;
    return true;
}
