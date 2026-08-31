/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical SHA3-addressed ZCODE scientific evidence wires. */

#include "vcs/zcode_science.h"

#include "base/bytes.h"
#include "zcode_science_platform.h"

#include "base/serialize_le.h"
#include "util/hw_profile.h"
#include "vcs/signed_evidence.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t study_magic[8] = {'Z','C','S','T','U','D','\r','\n'};
static const uint8_t result_magic[8] = {'Z','C','B','E','N','C','\r','\n'};
static const uint8_t reproduction_magic[8] =
    {'Z','C','R','E','P','R','\r','\n'};
static const uint8_t findings_magic[8] = {'Z','C','F','I','N','D','\r','\n'};
static const uint8_t vote_magic[8] = {'Z','C','V','O','T','E','\r','\n'};
static const uint8_t hw_profile_magic[8] = {'Z','C','H','W','P','F','\r','\n'};
static const uint8_t method_magic[8] = {'Z','C','B','M','T','H','\r','\n'};
static const uint8_t result_v2_magic[8] = {'Z','C','B','E','N','2','\r','\n'};

static bool root_nonzero(const uint8_t root[32])
{
    return zcl_bytes_any_set(root, 32);
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

static void put_u32(uint8_t *wire, size_t *off, uint32_t value)
{
    zcl_write_u32_le(wire + *off, value);
    *off += 4;
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

static uint32_t get_u32(const uint8_t *wire, size_t *off)
{
    uint32_t value = zcl_read_u32_le(wire + *off);
    *off += 4;
    return value;
}

static uint64_t get_u64(const uint8_t *wire, size_t *off)
{
    uint64_t value = zcl_read_u64_le(wire + *off);
    *off += 8;
    return value;
}

const char *vcs_zcode_science_error_string(enum vcs_zcode_science_error error)
{
    switch (error) {
    case VCS_ZCODE_SCIENCE_OK: return "ok";
    case VCS_ZCODE_SCIENCE_ERR_NULL: return "null-argument";
    case VCS_ZCODE_SCIENCE_ERR_VERSION: return "schema-version";
    case VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE: return "wire-size";
    case VCS_ZCODE_SCIENCE_ERR_WIRE_MAGIC: return "wire-magic";
    case VCS_ZCODE_SCIENCE_ERR_ROOT_ZERO: return "root-zero";
    case VCS_ZCODE_SCIENCE_ERR_PUBKEY_ZERO: return "pubkey-zero";
    case VCS_ZCODE_SCIENCE_ERR_SIGNATURE: return "signature-invalid";
    case VCS_ZCODE_SCIENCE_ERR_LIMIT: return "limit-invalid";
    case VCS_ZCODE_SCIENCE_ERR_TIME_ORDER: return "time-order-invalid";
    case VCS_ZCODE_SCIENCE_ERR_STATUS: return "benchmark-status-invalid";
    case VCS_ZCODE_SCIENCE_ERR_VERDICT: return "reproduction-verdict-invalid";
    case VCS_ZCODE_SCIENCE_ERR_FLAGS: return "finding-flags-invalid";
    case VCS_ZCODE_SCIENCE_ERR_ROOT_REUSED: return "distinct-root-required";
    case VCS_ZCODE_SCIENCE_ERR_STUDY_MISMATCH: return "study-root-mismatch";
    case VCS_ZCODE_SCIENCE_ERR_TASK_MISMATCH: return "task-root-mismatch";
    case VCS_ZCODE_SCIENCE_ERR_CANDIDATE_MISMATCH:
        return "candidate-root-mismatch";
    case VCS_ZCODE_SCIENCE_ERR_RESULT_MISMATCH: return "result-root-mismatch";
    case VCS_ZCODE_SCIENCE_ERR_REVIEW_MISMATCH: return "review-root-mismatch";
    case VCS_ZCODE_SCIENCE_ERR_ENVIRONMENT_MISMATCH:
        return "environment-root-mismatch";
    case VCS_ZCODE_SCIENCE_ERR_NETWORK_MISMATCH:
        return "network-genesis-mismatch";
    case VCS_ZCODE_SCIENCE_ERR_IDENTITY_MISMATCH:
        return "identity-root-mismatch";
    case VCS_ZCODE_SCIENCE_ERR_EXPIRED: return "object-expired";
    case VCS_ZCODE_SCIENCE_ERR_EVIDENCE_FUTURE: return "evidence-from-future";
    case VCS_ZCODE_SCIENCE_ERR_ACTION_MISMATCH: return "action-root-mismatch";
    case VCS_ZCODE_SCIENCE_ERR_PADDING: return "string-padding-invalid";
    case VCS_ZCODE_SCIENCE_ERR_ISA: return "isa-bits-invalid";
    case VCS_ZCODE_SCIENCE_ERR_DISTRIBUTION:
        return "sample-distribution-invalid";
    case VCS_ZCODE_SCIENCE_ERR_METHOD_MISMATCH: return "method-root-mismatch";
    case VCS_ZCODE_SCIENCE_ERR_HARDWARE_MISMATCH:
        return "hardware-profile-root-mismatch";
    case VCS_ZCODE_SCIENCE_ERR_PROFILE: return "science-profile-invalid";
    case VCS_ZCODE_SCIENCE_ERR_RIGHTS: return "rights-vocabulary-invalid";
    case VCS_ZCODE_SCIENCE_ERR_AUTHORSHIP: return "authorship-invalid";
    case VCS_ZCODE_SCIENCE_ERR_EMBARGO: return "embargo-time-invalid";
    case VCS_ZCODE_SCIENCE_ERR_RELATION_TYPE:
        return "science-relation-type-invalid";
    case VCS_ZCODE_SCIENCE_ERR_RELATION_ORDER:
        return "science-relation-order-invalid";
    case VCS_ZCODE_SCIENCE_ERR_RELATION_MISMATCH:
        return "science-relation-root-mismatch";
    }
    return "unknown";
}

enum vcs_zcode_science_error vcs_zcode_study_spec_validate(
    const struct vcs_zcode_study_spec_v1 *study)
{
    if (!study) return VCS_ZCODE_SCIENCE_ERR_NULL;
    if (study->schema_version != VCS_ZCODE_SCIENCE_VERSION)
        return VCS_ZCODE_SCIENCE_ERR_VERSION;
    const uint8_t *roots[] = {
        study->hypothesis_root, study->null_hypothesis_root,
        study->source_root, study->dependency_lock_root,
        study->toolchain_capsule_root, study->protocol_root,
        study->workloads_root, study->metrics_root,
        study->estimator_tolerance_root, study->environment_policy_root,
        study->citations_root, study->preregistration_policy_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!root_nonzero(roots[i])) return VCS_ZCODE_SCIENCE_ERR_ROOT_ZERO;
    if (memcmp(study->hypothesis_root, study->null_hypothesis_root, 32) == 0)
        return VCS_ZCODE_SCIENCE_ERR_ROOT_REUSED;
    if (study->required_reproductions == 0 ||
        study->required_reproductions > VCS_ZCODE_STUDY_REQUIRED_MAX ||
        study->required_reviews == 0 ||
        study->required_reviews > VCS_ZCODE_STUDY_REQUIRED_MAX ||
        study->sequence == 0)
        return VCS_ZCODE_SCIENCE_ERR_LIMIT;
    if (study->created_unix <= 0 ||
        study->expires_unix <= study->created_unix)
        return VCS_ZCODE_SCIENCE_ERR_TIME_ORDER;
    return VCS_ZCODE_SCIENCE_OK;
}

enum vcs_zcode_science_error vcs_zcode_study_spec_validate_at(
    const struct vcs_zcode_study_spec_v1 *study, int64_t now_unix)
{
    enum vcs_zcode_science_error error = vcs_zcode_study_spec_validate(study);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    if (now_unix <= 0 || now_unix < study->created_unix ||
        now_unix >= study->expires_unix)
        return VCS_ZCODE_SCIENCE_ERR_EXPIRED;
    return VCS_ZCODE_SCIENCE_OK;
}

bool vcs_zcode_study_spec_accepts_submission_at(
    const struct vcs_zcode_study_spec_v1 *study, int64_t now_unix)
{
    return vcs_zcode_study_spec_validate(study) == VCS_ZCODE_SCIENCE_OK &&
           now_unix >= study->created_unix && now_unix < study->expires_unix;
}

enum vcs_zcode_science_error vcs_zcode_study_spec_serialize(
    const struct vcs_zcode_study_spec_v1 *study,
    uint8_t out[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES])
{
    enum vcs_zcode_science_error error = vcs_zcode_study_spec_validate(study);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    size_t off = 0;
    put_bytes(out, &off, study_magic, sizeof(study_magic));
    put_u16(out, &off, study->schema_version);
    const uint8_t *roots[] = {
        study->hypothesis_root, study->null_hypothesis_root,
        study->source_root, study->dependency_lock_root,
        study->toolchain_capsule_root, study->protocol_root,
        study->workloads_root, study->metrics_root,
        study->estimator_tolerance_root, study->environment_policy_root,
        study->citations_root, study->preregistration_policy_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        put_bytes(out, &off, roots[i], 32);
    put_u16(out, &off, study->required_reproductions);
    put_u16(out, &off, study->required_reviews);
    put_u64(out, &off, study->sequence);
    put_u64(out, &off, (uint64_t)study->created_unix);
    put_u64(out, &off, (uint64_t)study->expires_unix);
    return off == VCS_ZCODE_STUDY_SPEC_WIRE_BYTES
               ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
}

enum vcs_zcode_science_error vcs_zcode_study_spec_parse(
    const uint8_t *wire, size_t len, struct vcs_zcode_study_spec_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_SCIENCE_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (len != VCS_ZCODE_STUDY_SPEC_WIRE_BYTES)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
    if (memcmp(wire, study_magic, sizeof(study_magic)) != 0)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_MAGIC;
    size_t off = sizeof(study_magic);
    out->schema_version = get_u16(wire, &off);
    uint8_t *roots[] = {
        out->hypothesis_root, out->null_hypothesis_root, out->source_root,
        out->dependency_lock_root, out->toolchain_capsule_root,
        out->protocol_root, out->workloads_root, out->metrics_root,
        out->estimator_tolerance_root, out->environment_policy_root,
        out->citations_root, out->preregistration_policy_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        get_bytes(wire, &off, roots[i], 32);
    out->required_reproductions = get_u16(wire, &off);
    out->required_reviews = get_u16(wire, &off);
    out->sequence = get_u64(wire, &off);
    out->created_unix = (int64_t)get_u64(wire, &off);
    out->expires_unix = (int64_t)get_u64(wire, &off);
    enum vcs_zcode_science_error error = vcs_zcode_study_spec_validate(out);
    if (error != VCS_ZCODE_SCIENCE_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_science_error vcs_zcode_study_spec_root(
    const struct vcs_zcode_study_spec_v1 *study, uint8_t out[32])
{
    uint8_t wire[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES];
    enum vcs_zcode_science_error error =
        vcs_zcode_study_spec_serialize(study, wire);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    static const char domain[] = VCS_ZCODE_STUDY_SPEC_DOMAIN;
    return vcs_signed_evidence_root(
               domain, sizeof(domain), wire, sizeof(wire), out)
        ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_NULL;
}

enum vcs_zcode_science_error vcs_zcode_benchmark_result_validate(
    const struct vcs_zcode_benchmark_result_v1 *result)
{
    if (!result) return VCS_ZCODE_SCIENCE_ERR_NULL;
    if (result->schema_version != VCS_ZCODE_SCIENCE_VERSION)
        return VCS_ZCODE_SCIENCE_ERR_VERSION;
    const uint8_t *roots[] = {
        result->study_root, result->task_root, result->candidate_root,
        result->action_root, result->achieved_environment_root,
        result->raw_sample_root, result->evidence_root,
        result->challenge_block_hash,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!root_nonzero(roots[i])) return VCS_ZCODE_SCIENCE_ERR_ROOT_ZERO;
    if (result->status < VCS_ZCODE_BENCHMARK_OBSERVED ||
        result->status > VCS_ZCODE_BENCHMARK_EXECUTION_FAILED)
        return VCS_ZCODE_SCIENCE_ERR_STATUS;
    if (result->challenge_block_height == 0 || result->sequence == 0)
        return VCS_ZCODE_SCIENCE_ERR_LIMIT;
    if (result->started_unix <= 0 ||
        result->finished_unix < result->started_unix)
        return VCS_ZCODE_SCIENCE_ERR_TIME_ORDER;
    return VCS_ZCODE_SCIENCE_OK;
}

enum vcs_zcode_science_error vcs_zcode_benchmark_result_serialize(
    const struct vcs_zcode_benchmark_result_v1 *result,
    uint8_t out[VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES])
{
    enum vcs_zcode_science_error error =
        vcs_zcode_benchmark_result_validate(result);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    size_t off = 0;
    put_bytes(out, &off, result_magic, sizeof(result_magic));
    put_u16(out, &off, result->schema_version);
    const uint8_t *roots[] = {
        result->study_root, result->task_root, result->candidate_root,
        result->action_root, result->achieved_environment_root,
        result->raw_sample_root, result->evidence_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        put_bytes(out, &off, roots[i], 32);
    out[off++] = result->status;
    put_u64(out, &off, result->challenge_block_height);
    put_bytes(out, &off, result->challenge_block_hash, 32);
    put_u64(out, &off, result->sequence);
    put_u64(out, &off, (uint64_t)result->started_unix);
    put_u64(out, &off, (uint64_t)result->finished_unix);
    return off == VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES
               ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
}

enum vcs_zcode_science_error vcs_zcode_benchmark_result_parse(
    const uint8_t *wire, size_t len,
    struct vcs_zcode_benchmark_result_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_SCIENCE_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (len != VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
    if (memcmp(wire, result_magic, sizeof(result_magic)) != 0)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_MAGIC;
    size_t off = sizeof(result_magic);
    out->schema_version = get_u16(wire, &off);
    uint8_t *roots[] = {
        out->study_root, out->task_root, out->candidate_root,
        out->action_root, out->achieved_environment_root,
        out->raw_sample_root, out->evidence_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        get_bytes(wire, &off, roots[i], 32);
    out->status = wire[off++];
    out->challenge_block_height = get_u64(wire, &off);
    get_bytes(wire, &off, out->challenge_block_hash, 32);
    out->sequence = get_u64(wire, &off);
    out->started_unix = (int64_t)get_u64(wire, &off);
    out->finished_unix = (int64_t)get_u64(wire, &off);
    enum vcs_zcode_science_error error =
        vcs_zcode_benchmark_result_validate(out);
    if (error != VCS_ZCODE_SCIENCE_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_science_error vcs_zcode_benchmark_result_root(
    const struct vcs_zcode_benchmark_result_v1 *result, uint8_t out[32])
{
    uint8_t wire[VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES];
    enum vcs_zcode_science_error error =
        vcs_zcode_benchmark_result_serialize(result, wire);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    static const char domain[] = VCS_ZCODE_BENCHMARK_RESULT_DOMAIN;
    return vcs_signed_evidence_root(
               domain, sizeof(domain), wire, sizeof(wire), out)
        ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_NULL;
}

enum vcs_zcode_science_error vcs_zcode_reproduction_validate(
    const struct vcs_zcode_reproduction_v1 *reproduction)
{
    if (!reproduction) return VCS_ZCODE_SCIENCE_ERR_NULL;
    if (reproduction->schema_version != VCS_ZCODE_SCIENCE_VERSION)
        return VCS_ZCODE_SCIENCE_ERR_VERSION;
    const uint8_t *roots[] = {
        reproduction->study_root, reproduction->original_result_root,
        reproduction->reproduced_result_root,
        reproduction->comparison_policy_root,
        reproduction->original_environment_root,
        reproduction->reproduced_environment_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!root_nonzero(roots[i])) return VCS_ZCODE_SCIENCE_ERR_ROOT_ZERO;
    if (!root_nonzero(reproduction->reproducer_pubkey))
        return VCS_ZCODE_SCIENCE_ERR_PUBKEY_ZERO;
    if (memcmp(reproduction->original_result_root,
               reproduction->reproduced_result_root, 32) == 0)
        return VCS_ZCODE_SCIENCE_ERR_ROOT_REUSED;
    if (reproduction->verdict < VCS_ZCODE_REPRODUCTION_REPLICATED ||
        reproduction->verdict > VCS_ZCODE_REPRODUCTION_INCONCLUSIVE)
        return VCS_ZCODE_SCIENCE_ERR_VERDICT;
    if (reproduction->sequence == 0) return VCS_ZCODE_SCIENCE_ERR_LIMIT;
    if (reproduction->created_unix <= 0)
        return VCS_ZCODE_SCIENCE_ERR_TIME_ORDER;
    return VCS_ZCODE_SCIENCE_OK;
}

enum vcs_zcode_science_error vcs_zcode_reproduction_serialize(
    const struct vcs_zcode_reproduction_v1 *reproduction,
    uint8_t out[VCS_ZCODE_REPRODUCTION_WIRE_BYTES])
{
    enum vcs_zcode_science_error error =
        vcs_zcode_reproduction_validate(reproduction);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    size_t off = 0;
    put_bytes(out, &off, reproduction_magic, sizeof(reproduction_magic));
    put_u16(out, &off, reproduction->schema_version);
    const uint8_t *roots[] = {
        reproduction->study_root, reproduction->original_result_root,
        reproduction->reproduced_result_root,
        reproduction->comparison_policy_root,
        reproduction->original_environment_root,
        reproduction->reproduced_environment_root,
        reproduction->reproducer_pubkey,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        put_bytes(out, &off, roots[i], 32);
    out[off++] = reproduction->verdict;
    put_u64(out, &off, reproduction->sequence);
    put_u64(out, &off, (uint64_t)reproduction->created_unix);
    return off == VCS_ZCODE_REPRODUCTION_WIRE_BYTES
               ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
}

enum vcs_zcode_science_error vcs_zcode_reproduction_parse(
    const uint8_t *wire, size_t len, struct vcs_zcode_reproduction_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_SCIENCE_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (len != VCS_ZCODE_REPRODUCTION_WIRE_BYTES)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
    if (memcmp(wire, reproduction_magic, sizeof(reproduction_magic)) != 0)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_MAGIC;
    size_t off = sizeof(reproduction_magic);
    out->schema_version = get_u16(wire, &off);
    uint8_t *roots[] = {
        out->study_root, out->original_result_root,
        out->reproduced_result_root, out->comparison_policy_root,
        out->original_environment_root, out->reproduced_environment_root,
        out->reproducer_pubkey,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        get_bytes(wire, &off, roots[i], 32);
    out->verdict = wire[off++];
    out->sequence = get_u64(wire, &off);
    out->created_unix = (int64_t)get_u64(wire, &off);
    enum vcs_zcode_science_error error = vcs_zcode_reproduction_validate(out);
    if (error != VCS_ZCODE_SCIENCE_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_science_error vcs_zcode_reproduction_root(
    const struct vcs_zcode_reproduction_v1 *reproduction, uint8_t out[32])
{
    uint8_t wire[VCS_ZCODE_REPRODUCTION_WIRE_BYTES];
    enum vcs_zcode_science_error error =
        vcs_zcode_reproduction_serialize(reproduction, wire);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    static const char domain[] = VCS_ZCODE_REPRODUCTION_DOMAIN;
    return vcs_signed_evidence_root(
               domain, sizeof(domain), wire, sizeof(wire), out)
        ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_NULL;
}

enum vcs_zcode_science_error vcs_zcode_science_findings_validate(
    const struct vcs_zcode_science_findings_v1 *findings)
{
    if (!findings) return VCS_ZCODE_SCIENCE_ERR_NULL;
    if (findings->schema_version != VCS_ZCODE_SCIENCE_VERSION)
        return VCS_ZCODE_SCIENCE_ERR_VERSION;
    const uint8_t *roots[] = {
        findings->study_root, findings->task_root, findings->candidate_root,
        findings->result_root, findings->proof_set_root,
        findings->methods_root, findings->limitations_root,
        findings->conflicts_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!root_nonzero(roots[i])) return VCS_ZCODE_SCIENCE_ERR_ROOT_ZERO;
    if ((findings->flags & ~VCS_ZCODE_FINDING_V1_FLAG_MASK) != 0 ||
        (((findings->flags & VCS_ZCODE_FINDING_RETRACTION) != 0) !=
         root_nonzero(findings->retraction_target_root)))
        return VCS_ZCODE_SCIENCE_ERR_FLAGS;
    if (findings->severity < VCS_ZCODE_FINDING_INFORMATIONAL ||
        findings->severity > VCS_ZCODE_FINDING_CRITICAL)
        return VCS_ZCODE_SCIENCE_ERR_FLAGS;
    if (findings->sequence == 0) return VCS_ZCODE_SCIENCE_ERR_LIMIT;
    if (findings->created_unix <= 0)
        return VCS_ZCODE_SCIENCE_ERR_TIME_ORDER;
    return VCS_ZCODE_SCIENCE_OK;
}

enum vcs_zcode_science_error vcs_zcode_science_findings_serialize(
    const struct vcs_zcode_science_findings_v1 *findings,
    uint8_t out[VCS_ZCODE_SCIENCE_FINDINGS_WIRE_BYTES])
{
    enum vcs_zcode_science_error error =
        vcs_zcode_science_findings_validate(findings);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    size_t off = 0;
    put_bytes(out, &off, findings_magic, sizeof(findings_magic));
    put_u16(out, &off, findings->schema_version);
    const uint8_t *roots[] = {
        findings->study_root, findings->task_root, findings->candidate_root,
        findings->result_root, findings->proof_set_root,
        findings->methods_root, findings->limitations_root,
        findings->conflicts_root,
        findings->retraction_target_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        put_bytes(out, &off, roots[i], 32);
    put_u16(out, &off, findings->flags);
    out[off++] = findings->severity;
    put_u64(out, &off, findings->sequence);
    put_u64(out, &off, (uint64_t)findings->created_unix);
    return off == VCS_ZCODE_SCIENCE_FINDINGS_WIRE_BYTES
               ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
}

enum vcs_zcode_science_error vcs_zcode_science_findings_parse(
    const uint8_t *wire, size_t len,
    struct vcs_zcode_science_findings_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_SCIENCE_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (len != VCS_ZCODE_SCIENCE_FINDINGS_WIRE_BYTES)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
    if (memcmp(wire, findings_magic, sizeof(findings_magic)) != 0)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_MAGIC;
    size_t off = sizeof(findings_magic);
    out->schema_version = get_u16(wire, &off);
    uint8_t *roots[] = {
        out->study_root, out->task_root, out->candidate_root,
        out->result_root, out->proof_set_root, out->methods_root,
        out->limitations_root, out->conflicts_root,
        out->retraction_target_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        get_bytes(wire, &off, roots[i], 32);
    out->flags = get_u16(wire, &off);
    out->severity = wire[off++];
    out->sequence = get_u64(wire, &off);
    out->created_unix = (int64_t)get_u64(wire, &off);
    enum vcs_zcode_science_error error =
        vcs_zcode_science_findings_validate(out);
    if (error != VCS_ZCODE_SCIENCE_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_science_error vcs_zcode_science_findings_root(
    const struct vcs_zcode_science_findings_v1 *findings, uint8_t out[32])
{
    uint8_t wire[VCS_ZCODE_SCIENCE_FINDINGS_WIRE_BYTES];
    enum vcs_zcode_science_error error =
        vcs_zcode_science_findings_serialize(findings, wire);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    static const char domain[] = VCS_ZCODE_SCIENCE_FINDINGS_DOMAIN;
    return vcs_signed_evidence_root(
               domain, sizeof(domain), wire, sizeof(wire), out)
        ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_NULL;
}

static enum vcs_zcode_science_error curation_vote_fields(
    const struct vcs_zcode_curation_vote_v1 *vote, bool require_signature)
{
    if (!vote) return VCS_ZCODE_SCIENCE_ERR_NULL;
    if (vote->schema_version != VCS_ZCODE_SCIENCE_VERSION)
        return VCS_ZCODE_SCIENCE_ERR_VERSION;
    const uint8_t *roots[] = {
        vote->network_genesis_root, vote->voter_zid_root,
        vote->property_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!root_nonzero(roots[i])) return VCS_ZCODE_SCIENCE_ERR_ROOT_ZERO;
    if (!root_nonzero(vote->signer_pubkey))
        return VCS_ZCODE_SCIENCE_ERR_PUBKEY_ZERO;
    if (vote->signal < VCS_ZCODE_CURATION_USEFUL ||
        vote->signal > VCS_ZCODE_CURATION_FLAG)
        return VCS_ZCODE_SCIENCE_ERR_VERDICT;
    if (vote->sequence == 0) return VCS_ZCODE_SCIENCE_ERR_LIMIT;
    if (vote->expires_unix <= 0) return VCS_ZCODE_SCIENCE_ERR_TIME_ORDER;
    if (require_signature &&
        !zcl_bytes_any_set(vote->signature, sizeof(vote->signature)))
        return VCS_ZCODE_SCIENCE_ERR_SIGNATURE;
    return VCS_ZCODE_SCIENCE_OK;
}

enum vcs_zcode_science_error vcs_zcode_curation_vote_validate(
    const struct vcs_zcode_curation_vote_v1 *vote)
{
    return curation_vote_fields(vote, true);
}

enum vcs_zcode_science_error vcs_zcode_curation_vote_validate_at(
    const struct vcs_zcode_curation_vote_v1 *vote, int64_t now_unix)
{
    enum vcs_zcode_science_error error = vcs_zcode_curation_vote_validate(vote);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    if (now_unix <= 0 || now_unix >= vote->expires_unix)
        return VCS_ZCODE_SCIENCE_ERR_EXPIRED;
    return VCS_ZCODE_SCIENCE_OK;
}

static enum vcs_zcode_science_error curation_vote_body(
    const struct vcs_zcode_curation_vote_v1 *vote,
    uint8_t out[VCS_ZCODE_CURATION_VOTE_BODY_BYTES])
{
    enum vcs_zcode_science_error error = curation_vote_fields(vote, false);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    size_t off = 0;
    put_bytes(out, &off, vote_magic, sizeof(vote_magic));
    put_u16(out, &off, vote->schema_version);
    put_bytes(out, &off, vote->network_genesis_root, 32);
    put_bytes(out, &off, vote->voter_zid_root, 32);
    put_bytes(out, &off, vote->property_root, 32);
    out[off++] = vote->signal;
    put_u64(out, &off, vote->sequence);
    put_u64(out, &off, (uint64_t)vote->expires_unix);
    put_bytes(out, &off, vote->signer_pubkey, 32);
    return off == VCS_ZCODE_CURATION_VOTE_BODY_BYTES
               ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
}

enum vcs_zcode_science_error vcs_zcode_curation_vote_serialize(
    const struct vcs_zcode_curation_vote_v1 *vote,
    uint8_t out[VCS_ZCODE_CURATION_VOTE_WIRE_BYTES])
{
    enum vcs_zcode_science_error error = vcs_zcode_curation_vote_validate(vote);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    error = curation_vote_body(vote, out);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    memcpy(out + VCS_ZCODE_CURATION_VOTE_BODY_BYTES, vote->signature, 64);
    return VCS_ZCODE_SCIENCE_OK;
}

enum vcs_zcode_science_error vcs_zcode_curation_vote_parse(
    const uint8_t *wire, size_t len, struct vcs_zcode_curation_vote_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_SCIENCE_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (len != VCS_ZCODE_CURATION_VOTE_WIRE_BYTES)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
    if (memcmp(wire, vote_magic, sizeof(vote_magic)) != 0)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_MAGIC;
    size_t off = sizeof(vote_magic);
    out->schema_version = get_u16(wire, &off);
    get_bytes(wire, &off, out->network_genesis_root, 32);
    get_bytes(wire, &off, out->voter_zid_root, 32);
    get_bytes(wire, &off, out->property_root, 32);
    out->signal = wire[off++];
    out->sequence = get_u64(wire, &off);
    out->expires_unix = (int64_t)get_u64(wire, &off);
    get_bytes(wire, &off, out->signer_pubkey, 32);
    get_bytes(wire, &off, out->signature, 64);
    enum vcs_zcode_science_error error = vcs_zcode_curation_vote_validate(out);
    if (error != VCS_ZCODE_SCIENCE_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_science_error vcs_zcode_curation_vote_id(
    const struct vcs_zcode_curation_vote_v1 *vote, uint8_t out[32])
{
    uint8_t body[VCS_ZCODE_CURATION_VOTE_BODY_BYTES];
    enum vcs_zcode_science_error error = curation_vote_body(vote, body);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    static const char domain[] = VCS_ZCODE_CURATION_VOTE_DOMAIN;
    return vcs_signed_evidence_root(
               domain, sizeof(domain), body, sizeof(body), out)
        ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_NULL;
}

enum vcs_zcode_science_error vcs_zcode_curation_vote_seal(
    struct vcs_zcode_curation_vote_v1 *vote, const uint8_t secret[32],
    const uint8_t pubkey[32])
{
    if (!vote || !secret || !pubkey) return VCS_ZCODE_SCIENCE_ERR_NULL;
    if (!root_nonzero(pubkey)) return VCS_ZCODE_SCIENCE_ERR_PUBKEY_ZERO;
    memcpy(vote->signer_pubkey, pubkey, 32);
    uint8_t id[32];
    enum vcs_zcode_science_error error = vcs_zcode_curation_vote_id(vote, id);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    return vcs_signed_evidence_seal_root(
               id, secret, pubkey, vote->signature)
        ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_NULL;
}

enum vcs_zcode_science_error vcs_zcode_curation_vote_verify(
    const struct vcs_zcode_curation_vote_v1 *vote,
    const uint8_t expected_network[32], const uint8_t expected_zid[32],
    const uint8_t expected_signer[32], int64_t now_unix)
{
    enum vcs_zcode_science_error error =
        vcs_zcode_curation_vote_validate_at(vote, now_unix);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    if (!expected_network ||
        memcmp(vote->network_genesis_root, expected_network, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_NETWORK_MISMATCH;
    if (!expected_zid || memcmp(vote->voter_zid_root, expected_zid, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_IDENTITY_MISMATCH;
    uint8_t id[32];
    error = vcs_zcode_curation_vote_id(vote, id);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    return vcs_signed_evidence_verify_root(
               id, vote->signature, vote->signer_pubkey, expected_signer)
               ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_SIGNATURE;
}

static enum vcs_zcode_science_error map_task_error(
    enum vcs_zcode_dev_error error)
{
    if (error == VCS_ZCODE_DEV_OK) return VCS_ZCODE_SCIENCE_OK;
    if (error == VCS_ZCODE_DEV_ERR_EXPIRY)
        return VCS_ZCODE_SCIENCE_ERR_EXPIRED;
    if (error == VCS_ZCODE_DEV_ERR_TASK_MISMATCH)
        return VCS_ZCODE_SCIENCE_ERR_TASK_MISMATCH;
    if (error == VCS_ZCODE_DEV_ERR_OUTPUT_MISMATCH)
        return VCS_ZCODE_SCIENCE_ERR_CANDIDATE_MISMATCH;
    return VCS_ZCODE_SCIENCE_ERR_CANDIDATE_MISMATCH;
}

/* The benchmark result carries only action_root (no action-kind field), so
 * the action instance is canonicalized under every registered fixed kind and
 * must match under exactly the kind its descriptor fields select. */
static bool action_root_is_canonical_fixed(
    const struct vcs_build_action_v1 *action, const uint8_t action_root[32])
{
    static const char *const fixed_kinds[] = {
        VCS_BUILD_ACTION_KIND_V1,
        VCS_BUILD_ACTION_KIND_PACKAGE_V1, VCS_BUILD_ACTION_KIND_TEST_V1,
        VCS_BUILD_ACTION_KIND_FUZZ_V1,
        VCS_BUILD_ACTION_KIND_BENCHMARK_V1,
        VCS_BUILD_ACTION_KIND_BENCHMARK_REPRODUCE_V1,
        VCS_BUILD_ACTION_KIND_REVIEW_V1,
    };
    if (!action || !action_root) return false;
    for (size_t i = 0; i < sizeof(fixed_kinds) / sizeof(fixed_kinds[0]); i++) {
        uint8_t canonical[32];
        if (vcs_build_action_v1_root_for_kind(fixed_kinds[i], action,
                                              canonical) &&
            memcmp(canonical, action_root, 32) == 0)
            return true;
    }
    return false;
}

enum vcs_zcode_science_error vcs_zcode_benchmark_result_validate_for_study(
    const struct vcs_zcode_study_spec_v1 *study,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_build_action_v1 *action,
    const struct vcs_zcode_benchmark_result_v1 *result, int64_t now_unix)
{
    /* Verify, not submit: the study is structural-validated only; the window
     * checks below bind the EVIDENCE timestamps, never now_unix. See
     * vcs_zcode_study_spec_accepts_submission_at for the submission gate. */
    enum vcs_zcode_science_error error = vcs_zcode_study_spec_validate(study);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    error = map_task_error(vcs_zcode_task_validate(task));
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    error = map_task_error(vcs_zcode_candidate_validate(candidate));
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    error = vcs_zcode_benchmark_result_validate(result);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    if (!action) return VCS_ZCODE_SCIENCE_ERR_NULL;
    uint8_t study_root[32], task_root[32], candidate_root[32];
    if (vcs_zcode_study_spec_root(study, study_root) !=
            VCS_ZCODE_SCIENCE_OK ||
        memcmp(result->study_root, study_root, 32) != 0 ||
        memcmp(task->goal_root, study_root, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_STUDY_MISMATCH;
    if (vcs_zcode_task_root(task, task_root) != VCS_ZCODE_DEV_OK ||
        memcmp(result->task_root, task_root, 32) != 0 ||
        memcmp(candidate->task_root, task_root, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_TASK_MISMATCH;
    if (vcs_zcode_candidate_root(candidate, candidate_root) !=
            VCS_ZCODE_DEV_OK ||
        memcmp(result->candidate_root, candidate_root, 32) != 0 ||
        memcmp(candidate->base_source_root, task->source_root, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_CANDIDATE_MISMATCH;
    if (memcmp(study->source_root, task->source_root, 32) != 0 ||
        memcmp(study->dependency_lock_root, task->dependency_lock_root, 32) != 0 ||
        memcmp(study->toolchain_capsule_root,
               task->toolchain_capsule_root, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_TASK_MISMATCH;
    if (!action_root_is_canonical_fixed(action, result->action_root))
        return VCS_ZCODE_SCIENCE_ERR_ACTION_MISMATCH;
    if (candidate->created_unix >= task->expires_unix ||
        result->started_unix < study->created_unix ||
        result->finished_unix >= study->expires_unix)
        return VCS_ZCODE_SCIENCE_ERR_EXPIRED;
    if (candidate->created_unix > now_unix ||
        result->finished_unix > now_unix)
        return VCS_ZCODE_SCIENCE_ERR_EVIDENCE_FUTURE;
    return VCS_ZCODE_SCIENCE_OK;
}

enum vcs_zcode_science_error vcs_zcode_reproduction_validate_for_results(
    const struct vcs_zcode_study_spec_v1 *study,
    const struct vcs_zcode_benchmark_result_v1 *original,
    const struct vcs_zcode_benchmark_result_v1 *reproduced,
    const struct vcs_zcode_reproduction_v1 *reproduction, int64_t now_unix)
{
    /* Verify, not submit: the study is structural-validated only, so
     * historical reproductions keep re-verifying after the window closes. */
    enum vcs_zcode_science_error error = vcs_zcode_study_spec_validate(study);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    error = vcs_zcode_benchmark_result_validate(original);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    error = vcs_zcode_benchmark_result_validate(reproduced);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    error = vcs_zcode_reproduction_validate(reproduction);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    uint8_t study_root[32], original_root[32], reproduced_root[32];
    (void)vcs_zcode_study_spec_root(study, study_root);
    if (memcmp(original->study_root, study_root, 32) != 0 ||
        memcmp(reproduced->study_root, study_root, 32) != 0 ||
        memcmp(reproduction->study_root, study_root, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_STUDY_MISMATCH;
    /* A reproduction reruns the SAME task, candidate, and method (fixed
     * action) under the same study; only the environment, samples, and
     * verdict may differ. */
    if (memcmp(original->task_root, reproduced->task_root, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_TASK_MISMATCH;
    if (memcmp(original->candidate_root, reproduced->candidate_root, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_CANDIDATE_MISMATCH;
    if (memcmp(original->action_root, reproduced->action_root, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_ACTION_MISMATCH;
    (void)vcs_zcode_benchmark_result_root(original, original_root);
    (void)vcs_zcode_benchmark_result_root(reproduced, reproduced_root);
    if (memcmp(reproduction->original_result_root, original_root, 32) != 0 ||
        memcmp(reproduction->reproduced_result_root, reproduced_root, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_RESULT_MISMATCH;
    if (memcmp(reproduction->original_environment_root,
               original->achieved_environment_root, 32) != 0 ||
        memcmp(reproduction->reproduced_environment_root,
               reproduced->achieved_environment_root, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_ENVIRONMENT_MISMATCH;
    if (reproduction->created_unix < original->finished_unix ||
        reproduction->created_unix < reproduced->finished_unix ||
        reproduction->created_unix >= study->expires_unix)
        return VCS_ZCODE_SCIENCE_ERR_EXPIRED;
    if (reproduction->created_unix > now_unix)
        return VCS_ZCODE_SCIENCE_ERR_EVIDENCE_FUTURE;
    return VCS_ZCODE_SCIENCE_OK;
}

enum vcs_zcode_science_error vcs_zcode_science_findings_validate_for_review(
    const struct vcs_zcode_study_spec_v1 *study,
    const struct vcs_zcode_review_v1 *review,
    const struct vcs_zcode_benchmark_result_v1 *result,
    const struct vcs_zcode_science_findings_v1 *findings, int64_t now_unix)
{
    /* Verify, not submit: the study is structural-validated only, so
     * historical findings keep re-verifying after the window closes. */
    enum vcs_zcode_science_error error = vcs_zcode_study_spec_validate(study);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    if (vcs_zcode_review_validate(review) != VCS_ZCODE_DEV_OK)
        return VCS_ZCODE_SCIENCE_ERR_REVIEW_MISMATCH;
    error = vcs_zcode_benchmark_result_validate(result);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    error = vcs_zcode_science_findings_validate(findings);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    uint8_t study_root[32], findings_root[32], result_root[32];
    (void)vcs_zcode_study_spec_root(study, study_root);
    if (memcmp(result->study_root, study_root, 32) != 0 ||
        memcmp(findings->study_root, study_root, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_STUDY_MISMATCH;
    (void)vcs_zcode_benchmark_result_root(result, result_root);
    if (memcmp(findings->result_root, result_root, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_RESULT_MISMATCH;
    /* The findings must discuss the exact result they pin: same task and
     * candidate roots as the evaluated result, not just the same study. */
    if (memcmp(findings->task_root, result->task_root, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_TASK_MISMATCH;
    if (memcmp(findings->candidate_root, result->candidate_root, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_CANDIDATE_MISMATCH;
    if (memcmp(findings->task_root, review->task_root, 32) != 0 ||
        memcmp(findings->candidate_root, review->candidate_root, 32) != 0 ||
        memcmp(findings->proof_set_root, review->proof_set_root, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_REVIEW_MISMATCH;
    (void)vcs_zcode_science_findings_root(findings, findings_root);
    if (memcmp(review->findings_root, findings_root, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_REVIEW_MISMATCH;
    /* The findings are formed first and the review binds their root
     * afterward, so the review timestamp may be LATER than the findings',
     * never earlier. */
    if (findings->created_unix < result->finished_unix ||
        review->created_unix < findings->created_unix ||
        findings->created_unix >= study->expires_unix)
        return VCS_ZCODE_SCIENCE_ERR_EXPIRED;
    if (findings->created_unix > now_unix)
        return VCS_ZCODE_SCIENCE_ERR_EVIDENCE_FUTURE;
    return VCS_ZCODE_SCIENCE_OK;
}

/* ── hardware_profile.v1 ────────────────────────────────────────────── */

/* Fixed-width string fields are NUL-padded: content bytes, one NUL, then
 * zeros to the field width. A field with no NUL at all, or content after
 * the first NUL, is a padding violation. All-zero ("undisclosed") is
 * always sane. */
static bool padded_field_sane(const uint8_t *field, size_t len)
{
    size_t i = 0;
    while (i < len && field[i] != 0) i++;
    if (i == len) return false;
    for (; i < len; i++)
        if (field[i] != 0) return false;
    return true;
}

enum vcs_zcode_science_error vcs_zcode_hardware_profile_validate(
    const struct vcs_zcode_hardware_profile_v1 *profile)
{
    if (!profile) return VCS_ZCODE_SCIENCE_ERR_NULL;
    if (profile->schema_version != VCS_ZCODE_HARDWARE_PROFILE_VERSION)
        return VCS_ZCODE_SCIENCE_ERR_VERSION;
    if (!padded_field_sane(profile->cpu_vendor,
                           sizeof(profile->cpu_vendor)) ||
        !padded_field_sane(profile->cpu_brand,
                           sizeof(profile->cpu_brand)) ||
        !padded_field_sane(profile->os_sysname,
                           sizeof(profile->os_sysname)) ||
        !padded_field_sane(profile->os_machine,
                           sizeof(profile->os_machine)) ||
        !padded_field_sane(profile->os_release,
                           sizeof(profile->os_release)) ||
        !padded_field_sane(profile->timer_source,
                           sizeof(profile->timer_source)))
        return VCS_ZCODE_SCIENCE_ERR_PADDING;
    if (profile->physical_cores == 0 || profile->logical_cores == 0)
        return VCS_ZCODE_SCIENCE_ERR_LIMIT;
    if ((profile->isa_bits & ~VCS_ZCODE_HW_ISA_KNOWN_MASK) != 0)
        return VCS_ZCODE_SCIENCE_ERR_ISA;
    if (profile->captured_unix <= 0)
        return VCS_ZCODE_SCIENCE_ERR_TIME_ORDER;
    return VCS_ZCODE_SCIENCE_OK;
}

enum vcs_zcode_science_error vcs_zcode_hardware_profile_serialize(
    const struct vcs_zcode_hardware_profile_v1 *profile,
    uint8_t out[VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES])
{
    enum vcs_zcode_science_error error =
        vcs_zcode_hardware_profile_validate(profile);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    size_t off = 0;
    put_bytes(out, &off, hw_profile_magic, sizeof(hw_profile_magic));
    put_u16(out, &off, profile->schema_version);
    put_bytes(out, &off, profile->cpu_vendor, sizeof(profile->cpu_vendor));
    put_bytes(out, &off, profile->cpu_brand, sizeof(profile->cpu_brand));
    put_u16(out, &off, profile->physical_cores);
    put_u16(out, &off, profile->logical_cores);
    put_u64(out, &off, profile->ram_mib);
    put_u64(out, &off, profile->isa_bits);
    put_bytes(out, &off, profile->os_sysname, sizeof(profile->os_sysname));
    put_bytes(out, &off, profile->os_machine, sizeof(profile->os_machine));
    put_bytes(out, &off, profile->os_release, sizeof(profile->os_release));
    put_bytes(out, &off, profile->device_facts_root,
              sizeof(profile->device_facts_root));
    put_u64(out, &off, profile->tsc_freq_hz);
    put_bytes(out, &off, profile->timer_source,
              sizeof(profile->timer_source));
    put_u64(out, &off, (uint64_t)profile->captured_unix);
    return off == VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES
               ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
}

enum vcs_zcode_science_error vcs_zcode_hardware_profile_parse(
    const uint8_t *wire, size_t len,
    struct vcs_zcode_hardware_profile_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_SCIENCE_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (len != VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
    if (memcmp(wire, hw_profile_magic, sizeof(hw_profile_magic)) != 0)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_MAGIC;
    size_t off = sizeof(hw_profile_magic);
    out->schema_version = get_u16(wire, &off);
    get_bytes(wire, &off, out->cpu_vendor, sizeof(out->cpu_vendor));
    get_bytes(wire, &off, out->cpu_brand, sizeof(out->cpu_brand));
    out->physical_cores = get_u16(wire, &off);
    out->logical_cores = get_u16(wire, &off);
    out->ram_mib = get_u64(wire, &off);
    out->isa_bits = get_u64(wire, &off);
    get_bytes(wire, &off, out->os_sysname, sizeof(out->os_sysname));
    get_bytes(wire, &off, out->os_machine, sizeof(out->os_machine));
    get_bytes(wire, &off, out->os_release, sizeof(out->os_release));
    get_bytes(wire, &off, out->device_facts_root,
              sizeof(out->device_facts_root));
    out->tsc_freq_hz = get_u64(wire, &off);
    get_bytes(wire, &off, out->timer_source, sizeof(out->timer_source));
    out->captured_unix = (int64_t)get_u64(wire, &off);
    enum vcs_zcode_science_error error =
        vcs_zcode_hardware_profile_validate(out);
    if (error != VCS_ZCODE_SCIENCE_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_science_error vcs_zcode_hardware_profile_root(
    const struct vcs_zcode_hardware_profile_v1 *profile, uint8_t out[32])
{
    uint8_t wire[VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES];
    enum vcs_zcode_science_error error =
        vcs_zcode_hardware_profile_serialize(profile, wire);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    static const char domain[] = VCS_ZCODE_HARDWARE_PROFILE_DOMAIN;
    return vcs_signed_evidence_root(
               domain, sizeof(domain), wire, sizeof(wire), out)
        ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_NULL;
}

bool vcs_zcode_hardware_profile_capture(
    struct vcs_zcode_hardware_profile_v1 *out, int64_t now_unix)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    out->schema_version = VCS_ZCODE_HARDWARE_PROFILE_VERSION;
    out->captured_unix = now_unix > 0 ? now_unix : 1;
    (void)hw_profile_init(NULL);
    int physical = hw_profile_physical_cores();
    int logical = hw_profile_online_cores();
    if (logical <= 0) logical = zcode_science_platform_logical_cores();
    if (physical <= 0) physical = logical;
    /* The capture itself is executing, so at least one core exists: clamp
     * the unknown case to 1 rather than emit an unvalidatable object. */
    out->physical_cores = (uint16_t)(physical > 0 ? physical : 1);
    out->logical_cores = (uint16_t)(logical > 0 ? logical : 1);
    int64_t ram_bytes = hw_profile_ram_bytes();
    if (ram_bytes > 0)
        out->ram_mib = (uint64_t)ram_bytes / (UINT64_C(1024) * 1024u);
    const struct hw_profile_isa *isa = hw_profile_isa();
    if (isa) {
        if (isa->avx2) out->isa_bits |= VCS_ZCODE_HW_ISA_AVX2;
        if (isa->avx512f) out->isa_bits |= VCS_ZCODE_HW_ISA_AVX512F;
        if (isa->avx512vl) out->isa_bits |= VCS_ZCODE_HW_ISA_AVX512VL;
        if (isa->avx512bw) out->isa_bits |= VCS_ZCODE_HW_ISA_AVX512BW;
        if (isa->avx512dq) out->isa_bits |= VCS_ZCODE_HW_ISA_AVX512DQ;
        if (isa->vpclmulqdq) out->isa_bits |= VCS_ZCODE_HW_ISA_VPCLMULQDQ;
        if (isa->vaes) out->isa_bits |= VCS_ZCODE_HW_ISA_VAES;
        if (isa->gfni) out->isa_bits |= VCS_ZCODE_HW_ISA_GFNI;
        if (isa->sha_ni) out->isa_bits |= VCS_ZCODE_HW_ISA_SHA_NI;
    }
#if defined(__x86_64__) || defined(__i386__)
    /* Baseline extensions hw_profile does not probe; same builtin idiom as
     * lib/util/src/hw_profile.c. */
    if (__builtin_cpu_supports("sse4.2"))
        out->isa_bits |= VCS_ZCODE_HW_ISA_SSE4_2;
    if (__builtin_cpu_supports("bmi2")) out->isa_bits |= VCS_ZCODE_HW_ISA_BMI2;
    if (__builtin_cpu_supports("fma")) out->isa_bits |= VCS_ZCODE_HW_ISA_FMA;
    if (__builtin_cpu_supports("aes"))
        out->isa_bits |= VCS_ZCODE_HW_ISA_AES_NI;
#endif
    zcode_science_platform_capture(out);
    /* device_facts_root stays all-zero: the canonical extended-facts bundle
     * (DMI/firmware) is the documented extension point and no producer fills
     * it yet. */
    return vcs_zcode_hardware_profile_validate(out) == VCS_ZCODE_SCIENCE_OK;
}

/* ── benchmark_method.v1 ────────────────────────────────────────────── */

const char *vcs_zcode_benchmark_method_distribution_name(
    uint8_t sample_distribution)
{
    switch (sample_distribution) {
    case VCS_ZCODE_SAMPLE_DIST_RAW_ALL: return "raw_all";
    case VCS_ZCODE_SAMPLE_DIST_MINIMUM: return "minimum";
    case VCS_ZCODE_SAMPLE_DIST_MEDIAN_QUARTILES: return "median_quartiles";
    case VCS_ZCODE_SAMPLE_DIST_TRIMMED_MEAN: return "trimmed_mean";
    }
    return "unknown";
}

enum vcs_zcode_science_error vcs_zcode_benchmark_method_validate(
    const struct vcs_zcode_benchmark_method_v1 *method)
{
    if (!method) return VCS_ZCODE_SCIENCE_ERR_NULL;
    if (method->schema_version != VCS_ZCODE_BENCHMARK_METHOD_VERSION)
        return VCS_ZCODE_SCIENCE_ERR_VERSION;
    const uint8_t *roots[] = {
        method->workload_root, method->timer_root, method->estimator_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!root_nonzero(roots[i])) return VCS_ZCODE_SCIENCE_ERR_ROOT_ZERO;
    if (method->measured_samples == 0 ||
        method->measured_samples >
            VCS_ZCODE_BENCHMARK_METHOD_MAX_MEASURED_SAMPLES)
        return VCS_ZCODE_SCIENCE_ERR_LIMIT;
    if (method->sample_distribution < VCS_ZCODE_SAMPLE_DIST_RAW_ALL ||
        method->sample_distribution > VCS_ZCODE_SAMPLE_DIST_TRIMMED_MEAN ||
        method->trim_percent > VCS_ZCODE_BENCHMARK_METHOD_MAX_TRIM_PERCENT ||
        (method->trim_percent != 0 &&
         method->sample_distribution != VCS_ZCODE_SAMPLE_DIST_TRIMMED_MEAN))
        return VCS_ZCODE_SCIENCE_ERR_DISTRIBUTION;
    if (method->reserved != 0) return VCS_ZCODE_SCIENCE_ERR_FLAGS;
    return VCS_ZCODE_SCIENCE_OK;
}

enum vcs_zcode_science_error vcs_zcode_benchmark_method_serialize(
    const struct vcs_zcode_benchmark_method_v1 *method,
    uint8_t out[VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES])
{
    enum vcs_zcode_science_error error =
        vcs_zcode_benchmark_method_validate(method);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    size_t off = 0;
    put_bytes(out, &off, method_magic, sizeof(method_magic));
    put_u16(out, &off, method->schema_version);
    put_bytes(out, &off, method->workload_root, 32);
    put_bytes(out, &off, method->timer_root, 32);
    put_bytes(out, &off, method->estimator_root, 32);
    put_u32(out, &off, method->tolerance_ppm);
    put_u32(out, &off, method->warmup_samples);
    put_u32(out, &off, method->measured_samples);
    out[off++] = method->sample_distribution;
    out[off++] = method->trim_percent;
    out[off++] = method->reserved;
    return off == VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES
               ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
}

enum vcs_zcode_science_error vcs_zcode_benchmark_method_parse(
    const uint8_t *wire, size_t len,
    struct vcs_zcode_benchmark_method_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_SCIENCE_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (len != VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
    if (memcmp(wire, method_magic, sizeof(method_magic)) != 0)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_MAGIC;
    size_t off = sizeof(method_magic);
    out->schema_version = get_u16(wire, &off);
    get_bytes(wire, &off, out->workload_root, 32);
    get_bytes(wire, &off, out->timer_root, 32);
    get_bytes(wire, &off, out->estimator_root, 32);
    out->tolerance_ppm = get_u32(wire, &off);
    out->warmup_samples = get_u32(wire, &off);
    out->measured_samples = get_u32(wire, &off);
    out->sample_distribution = wire[off++];
    out->trim_percent = wire[off++];
    out->reserved = wire[off++];
    enum vcs_zcode_science_error error =
        vcs_zcode_benchmark_method_validate(out);
    if (error != VCS_ZCODE_SCIENCE_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_science_error vcs_zcode_benchmark_method_root(
    const struct vcs_zcode_benchmark_method_v1 *method, uint8_t out[32])
{
    uint8_t wire[VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES];
    enum vcs_zcode_science_error error =
        vcs_zcode_benchmark_method_serialize(method, wire);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    static const char domain[] = VCS_ZCODE_BENCHMARK_METHOD_DOMAIN;
    return vcs_signed_evidence_root(
               domain, sizeof(domain), wire, sizeof(wire), out)
        ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_NULL;
}

/* ── benchmark_result.v2 ────────────────────────────────────────────── */

/* The v2 struct's prefix through finished_unix is layout-identical to the
 * v1 struct; v2 rules are the v1 rules plus the two appended roots. Copying
 * the prefix into a v1 view (with the v1 version) reuses the frozen v1
 * codec semantics instead of restating them. */
static void result_v2_prefix_as_v1(
    const struct vcs_zcode_benchmark_result_v2 *result,
    struct vcs_zcode_benchmark_result_v1 *out)
{
    memset(out, 0, sizeof(*out));
    memcpy(out, result,
           offsetof(struct vcs_zcode_benchmark_result_v2, method_root));
    out->schema_version = VCS_ZCODE_SCIENCE_VERSION;
}

enum vcs_zcode_science_error vcs_zcode_benchmark_result_v2_validate(
    const struct vcs_zcode_benchmark_result_v2 *result)
{
    if (!result) return VCS_ZCODE_SCIENCE_ERR_NULL;
    if (result->schema_version != VCS_ZCODE_BENCHMARK_RESULT_V2_VERSION)
        return VCS_ZCODE_SCIENCE_ERR_VERSION;
    struct vcs_zcode_benchmark_result_v1 v1;
    result_v2_prefix_as_v1(result, &v1);
    enum vcs_zcode_science_error error =
        vcs_zcode_benchmark_result_validate(&v1);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    if (!root_nonzero(result->method_root) ||
        !root_nonzero(result->hardware_profile_root))
        return VCS_ZCODE_SCIENCE_ERR_ROOT_ZERO;
    return VCS_ZCODE_SCIENCE_OK;
}

enum vcs_zcode_science_error vcs_zcode_benchmark_result_v2_serialize(
    const struct vcs_zcode_benchmark_result_v2 *result,
    uint8_t out[VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES])
{
    enum vcs_zcode_science_error error =
        vcs_zcode_benchmark_result_v2_validate(result);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    size_t off = 0;
    put_bytes(out, &off, result_v2_magic, sizeof(result_v2_magic));
    put_u16(out, &off, result->schema_version);
    const uint8_t *roots[] = {
        result->study_root, result->task_root, result->candidate_root,
        result->action_root, result->achieved_environment_root,
        result->raw_sample_root, result->evidence_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        put_bytes(out, &off, roots[i], 32);
    out[off++] = result->status;
    put_u64(out, &off, result->challenge_block_height);
    put_bytes(out, &off, result->challenge_block_hash, 32);
    put_u64(out, &off, result->sequence);
    put_u64(out, &off, (uint64_t)result->started_unix);
    put_u64(out, &off, (uint64_t)result->finished_unix);
    put_bytes(out, &off, result->method_root, 32);
    put_bytes(out, &off, result->hardware_profile_root, 32);
    return off == VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES
               ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
}

enum vcs_zcode_science_error vcs_zcode_benchmark_result_v2_parse(
    const uint8_t *wire, size_t len,
    struct vcs_zcode_benchmark_result_v2 *out)
{
    if (!wire || !out) return VCS_ZCODE_SCIENCE_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (len != VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
    if (memcmp(wire, result_v2_magic, sizeof(result_v2_magic)) != 0)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_MAGIC;
    size_t off = sizeof(result_v2_magic);
    out->schema_version = get_u16(wire, &off);
    uint8_t *roots[] = {
        out->study_root, out->task_root, out->candidate_root,
        out->action_root, out->achieved_environment_root,
        out->raw_sample_root, out->evidence_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        get_bytes(wire, &off, roots[i], 32);
    out->status = wire[off++];
    out->challenge_block_height = get_u64(wire, &off);
    get_bytes(wire, &off, out->challenge_block_hash, 32);
    out->sequence = get_u64(wire, &off);
    out->started_unix = (int64_t)get_u64(wire, &off);
    out->finished_unix = (int64_t)get_u64(wire, &off);
    get_bytes(wire, &off, out->method_root, 32);
    get_bytes(wire, &off, out->hardware_profile_root, 32);
    enum vcs_zcode_science_error error =
        vcs_zcode_benchmark_result_v2_validate(out);
    if (error != VCS_ZCODE_SCIENCE_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_science_error vcs_zcode_benchmark_result_v2_root(
    const struct vcs_zcode_benchmark_result_v2 *result, uint8_t out[32])
{
    uint8_t wire[VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES];
    enum vcs_zcode_science_error error =
        vcs_zcode_benchmark_result_v2_serialize(result, wire);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    static const char domain[] = VCS_ZCODE_BENCHMARK_RESULT_V2_DOMAIN;
    return vcs_signed_evidence_root(
               domain, sizeof(domain), wire, sizeof(wire), out)
        ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_NULL;
}

enum vcs_zcode_science_error vcs_zcode_benchmark_result_v2_validate_for_study(
    const struct vcs_zcode_study_spec_v1 *study,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_build_action_v1 *action,
    const struct vcs_zcode_benchmark_method_v1 *method,
    const struct vcs_zcode_hardware_profile_v1 *profile,
    const struct vcs_zcode_benchmark_result_v2 *result, int64_t now_unix)
{
    enum vcs_zcode_science_error error =
        vcs_zcode_benchmark_result_v2_validate(result);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    error = vcs_zcode_benchmark_method_validate(method);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    error = vcs_zcode_hardware_profile_validate(profile);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    /* The H1-H3-hardened v1 cross-validator applies unchanged to the shared
     * prefix: structural study validate, study/task/candidate root pins,
     * canonical fixed-action binding, and the evidence-window checks. */
    struct vcs_zcode_benchmark_result_v1 v1;
    result_v2_prefix_as_v1(result, &v1);
    error = vcs_zcode_benchmark_result_validate_for_study(
        study, task, candidate, action, &v1, now_unix);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    uint8_t method_root[32], profile_root[32];
    if (vcs_zcode_benchmark_method_root(method, method_root) !=
            VCS_ZCODE_SCIENCE_OK ||
        memcmp(result->method_root, method_root, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_METHOD_MISMATCH;
    if (vcs_zcode_hardware_profile_root(profile, profile_root) !=
            VCS_ZCODE_SCIENCE_OK ||
        memcmp(result->hardware_profile_root, profile_root, 32) != 0)
        return VCS_ZCODE_SCIENCE_ERR_HARDWARE_MISMATCH;
    return VCS_ZCODE_SCIENCE_OK;
}
