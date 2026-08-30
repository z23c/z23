/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical simulation-only package continuity policies. */
#include "vcs/zcode_continuity_policy.h"

#include "base/bytes.h"
#include "base/checked.h"
#include "codec/cursor.h"
#include "crypto/sha3.h"
#include "vcs/signed_evidence.h"

#include <stdbool.h>
#include <string.h>

static const uint8_t continuity_magic[8] =
    {'Z','C','C','O','N','T','\r','\n'};

const char *vcs_zcode_continuity_error_string(
    enum vcs_zcode_continuity_error error)
{
    switch (error) {
    case VCS_ZCODE_CONTINUITY_OK: return "ok";
    case VCS_ZCODE_CONTINUITY_NULL: return "null-argument";
    case VCS_ZCODE_CONTINUITY_WIRE_SIZE: return "wire-size";
    case VCS_ZCODE_CONTINUITY_MAGIC: return "wire-magic";
    case VCS_ZCODE_CONTINUITY_VERSION: return "schema-version";
    case VCS_ZCODE_CONTINUITY_EVENT_MASK: return "closed-event-mask";
    case VCS_ZCODE_CONTINUITY_FLAGS: return "authority-or-simulation-flags";
    case VCS_ZCODE_CONTINUITY_ROOT: return "required-root";
    case VCS_ZCODE_CONTINUITY_TRANSITION: return "capsule-transition";
    case VCS_ZCODE_CONTINUITY_CAP: return "cycle-or-amount-cap";
    case VCS_ZCODE_CONTINUITY_TIME: return "time-order";
    case VCS_ZCODE_CONTINUITY_SEQUENCE: return "sequence";
    case VCS_ZCODE_CONTINUITY_SIGNATURE: return "signature";
    case VCS_ZCODE_CONTINUITY_CONTEXT: return "validation-context";
    case VCS_ZCODE_CONTINUITY_CAS: return "canonical-cas";
    case VCS_ZCODE_CONTINUITY_NETWORK: return "network-mismatch";
    case VCS_ZCODE_CONTINUITY_CONTRIBUTOR: return "contributor-binding";
    case VCS_ZCODE_CONTINUITY_PACKAGE: return "package-binding";
    case VCS_ZCODE_CONTINUITY_RELEASE: return "release-binding";
    case VCS_ZCODE_CONTINUITY_PROOF_POLICY: return "proof-policy-binding";
    }
    return "unknown";
}

static enum vcs_zcode_continuity_error continuity_fields(
    const struct vcs_zcode_continuity_policy_v1 *policy, bool signed_wire)
{
    if (!policy) return VCS_ZCODE_CONTINUITY_NULL;
    if (policy->schema_version != VCS_ZCODE_CONTINUITY_POLICY_VERSION)
        return VCS_ZCODE_CONTINUITY_VERSION;
    if (policy->event_mask == 0 ||
        (policy->event_mask & ~VCS_ZCODE_CONTINUITY_ALLOWED_EVENT_MASK) != 0)
        return VCS_ZCODE_CONTINUITY_EVENT_MASK;
    uint8_t required = VCS_ZCODE_CONTINUITY_NO_AUTHORITY |
                       VCS_ZCODE_CONTINUITY_SIMULATION_ONLY;
    uint8_t allowed = required | VCS_ZCODE_CONTINUITY_ANONYMOUS_DISPLAY;
    if ((policy->flags & required) != required ||
        (policy->flags & ~allowed) != 0)
        return VCS_ZCODE_CONTINUITY_FLAGS;
    const uint8_t *roots[] = {
        policy->network_genesis_root,
        policy->zc23_token_or_simulation_root,
        policy->patron_contributor_binding_root, policy->patron_zid_pubkey,
        policy->package_root, policy->current_release_root,
        policy->from_capsule_root, policy->to_capsule_root,
        policy->proof_policy_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32))
            return VCS_ZCODE_CONTINUITY_ROOT;
    if (memcmp(policy->from_capsule_root, policy->to_capsule_root, 32) == 0)
        return VCS_ZCODE_CONTINUITY_TRANSITION;
    uint64_t maximum_total = 0;
    if (policy->maximum_cycles == 0 || policy->per_cycle_cap_atoms == 0 ||
        policy->total_cap_atoms < policy->per_cycle_cap_atoms ||
        !zcl_u64_mul(policy->maximum_cycles, policy->per_cycle_cap_atoms,
                     &maximum_total) ||
        policy->total_cap_atoms > maximum_total)
        return VCS_ZCODE_CONTINUITY_CAP;
    if (policy->created_unix <= 0 ||
        policy->expires_unix <= policy->created_unix)
        return VCS_ZCODE_CONTINUITY_TIME;
    if (policy->sequence == 0) return VCS_ZCODE_CONTINUITY_SEQUENCE;
    if (signed_wire && !zcl_bytes_any_set(policy->signature, 32))
        return VCS_ZCODE_CONTINUITY_SIGNATURE;
    return VCS_ZCODE_CONTINUITY_OK;
}

enum vcs_zcode_continuity_error vcs_zcode_continuity_policy_validate(
    const struct vcs_zcode_continuity_policy_v1 *policy)
{
    return continuity_fields(policy, true);
}

static enum vcs_zcode_continuity_error continuity_body(
    const struct vcs_zcode_continuity_policy_v1 *policy,
    uint8_t out[VCS_ZCODE_CONTINUITY_POLICY_BODY_BYTES])
{
    enum vcs_zcode_continuity_error error =
        continuity_fields(policy, false);
    if (error != VCS_ZCODE_CONTINUITY_OK || !out)
        return out ? error : VCS_ZCODE_CONTINUITY_NULL;
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, out,
                          VCS_ZCODE_CONTINUITY_POLICY_BODY_BYTES);
    bool ok = zcl_codec_write_bytes(&writer, continuity_magic, 8) &&
        zcl_codec_write_u16le(&writer, policy->schema_version) &&
        zcl_codec_write_u16le(&writer, policy->event_mask) &&
        zcl_codec_write_u8(&writer, policy->flags) &&
        zcl_codec_write_u8(&writer, 0) &&
        zcl_codec_write_u16le(&writer, 0) &&
        zcl_codec_write_bytes(&writer, policy->network_genesis_root, 32) &&
        zcl_codec_write_bytes(&writer,
            policy->zc23_token_or_simulation_root, 32) &&
        zcl_codec_write_bytes(&writer,
            policy->patron_contributor_binding_root, 32) &&
        zcl_codec_write_bytes(&writer, policy->patron_zid_pubkey, 32) &&
        zcl_codec_write_bytes(&writer, policy->package_root, 32) &&
        zcl_codec_write_bytes(&writer, policy->current_release_root, 32) &&
        zcl_codec_write_bytes(&writer, policy->from_capsule_root, 32) &&
        zcl_codec_write_bytes(&writer, policy->to_capsule_root, 32) &&
        zcl_codec_write_bytes(&writer, policy->proof_policy_root, 32) &&
        zcl_codec_write_u32le(&writer, policy->maximum_cycles) &&
        zcl_codec_write_u32le(&writer, 0) &&
        zcl_codec_write_u64le(&writer, policy->per_cycle_cap_atoms) &&
        zcl_codec_write_u64le(&writer, policy->total_cap_atoms) &&
        zcl_codec_write_i64le(&writer, policy->created_unix) &&
        zcl_codec_write_i64le(&writer, policy->expires_unix) &&
        zcl_codec_write_u64le(&writer, policy->sequence);
    size_t written = 0;
    return ok && zcl_codec_writer_finish(&writer, &written) &&
           written == VCS_ZCODE_CONTINUITY_POLICY_BODY_BYTES
        ? VCS_ZCODE_CONTINUITY_OK : VCS_ZCODE_CONTINUITY_WIRE_SIZE;
}

static enum vcs_zcode_continuity_error continuity_signing_root(
    const struct vcs_zcode_continuity_policy_v1 *policy, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!out) return VCS_ZCODE_CONTINUITY_NULL;
    uint8_t body[VCS_ZCODE_CONTINUITY_POLICY_BODY_BYTES];
    enum vcs_zcode_continuity_error error = continuity_body(policy, body);
    if (error != VCS_ZCODE_CONTINUITY_OK) return error;
    static const char domain[] = VCS_ZCODE_CONTINUITY_POLICY_DOMAIN;
    return vcs_signed_evidence_root(
               domain, sizeof(domain), body, sizeof(body), out)
        ? VCS_ZCODE_CONTINUITY_OK : VCS_ZCODE_CONTINUITY_NULL;
}

enum vcs_zcode_continuity_error vcs_zcode_continuity_policy_serialize(
    const struct vcs_zcode_continuity_policy_v1 *policy,
    uint8_t out[VCS_ZCODE_CONTINUITY_POLICY_WIRE_BYTES])
{
    if (!out) return VCS_ZCODE_CONTINUITY_NULL;
    enum vcs_zcode_continuity_error error = continuity_fields(policy, true);
    if (error != VCS_ZCODE_CONTINUITY_OK) return error;
    error = continuity_body(policy, out);
    if (error == VCS_ZCODE_CONTINUITY_OK)
        memcpy(out + VCS_ZCODE_CONTINUITY_POLICY_BODY_BYTES,
               policy->signature, 64);
    return error;
}

enum vcs_zcode_continuity_error vcs_zcode_continuity_policy_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_continuity_policy_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_CONTINUITY_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_CONTINUITY_POLICY_WIRE_BYTES)
        return VCS_ZCODE_CONTINUITY_WIRE_SIZE;
    struct zcl_codec_reader reader;
    uint8_t magic[8], reserved8 = 0;
    uint16_t reserved16 = 0;
    uint32_t reserved32 = 0;
    zcl_codec_reader_init(&reader, wire, wire_len);
    bool ok = zcl_codec_read_bytes(&reader, magic, 8) &&
        zcl_codec_read_u16le(&reader, &out->schema_version) &&
        zcl_codec_read_u16le(&reader, &out->event_mask) &&
        zcl_codec_read_u8(&reader, &out->flags) &&
        zcl_codec_read_u8(&reader, &reserved8) &&
        zcl_codec_read_u16le(&reader, &reserved16) &&
        zcl_codec_read_bytes(&reader, out->network_genesis_root, 32) &&
        zcl_codec_read_bytes(&reader,
            out->zc23_token_or_simulation_root, 32) &&
        zcl_codec_read_bytes(&reader,
            out->patron_contributor_binding_root, 32) &&
        zcl_codec_read_bytes(&reader, out->patron_zid_pubkey, 32) &&
        zcl_codec_read_bytes(&reader, out->package_root, 32) &&
        zcl_codec_read_bytes(&reader, out->current_release_root, 32) &&
        zcl_codec_read_bytes(&reader, out->from_capsule_root, 32) &&
        zcl_codec_read_bytes(&reader, out->to_capsule_root, 32) &&
        zcl_codec_read_bytes(&reader, out->proof_policy_root, 32) &&
        zcl_codec_read_u32le(&reader, &out->maximum_cycles) &&
        zcl_codec_read_u32le(&reader, &reserved32) &&
        zcl_codec_read_u64le(&reader, &out->per_cycle_cap_atoms) &&
        zcl_codec_read_u64le(&reader, &out->total_cap_atoms) &&
        zcl_codec_read_i64le(&reader, &out->created_unix) &&
        zcl_codec_read_i64le(&reader, &out->expires_unix) &&
        zcl_codec_read_u64le(&reader, &out->sequence) &&
        zcl_codec_read_bytes(&reader, out->signature, 64) &&
        zcl_codec_reader_finish(&reader);
    enum vcs_zcode_continuity_error error = !ok
        ? VCS_ZCODE_CONTINUITY_WIRE_SIZE
        : memcmp(magic, continuity_magic, 8) != 0
            ? VCS_ZCODE_CONTINUITY_MAGIC
            : reserved8 || reserved16 || reserved32
                ? VCS_ZCODE_CONTINUITY_FLAGS
                : continuity_fields(out, true);
    if (error != VCS_ZCODE_CONTINUITY_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_continuity_error vcs_zcode_continuity_policy_root(
    const struct vcs_zcode_continuity_policy_v1 *policy, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!out) return VCS_ZCODE_CONTINUITY_NULL;
    uint8_t wire[VCS_ZCODE_CONTINUITY_POLICY_WIRE_BYTES];
    enum vcs_zcode_continuity_error error =
        vcs_zcode_continuity_policy_serialize(policy, wire);
    if (error != VCS_ZCODE_CONTINUITY_OK) return error;
    static const char domain[] = VCS_ZCODE_CONTINUITY_POLICY_ROOT_DOMAIN;
    return vcs_signed_evidence_root(
               domain, sizeof(domain), wire, sizeof(wire), out)
        ? VCS_ZCODE_CONTINUITY_OK : VCS_ZCODE_CONTINUITY_NULL;
}

enum vcs_zcode_continuity_error vcs_zcode_continuity_policy_seal(
    struct vcs_zcode_continuity_policy_v1 *policy,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    if (!policy || !secret || !pubkey) return VCS_ZCODE_CONTINUITY_NULL;
    if (memcmp(policy->patron_zid_pubkey, pubkey, 32) != 0)
        return VCS_ZCODE_CONTINUITY_SIGNATURE;
    uint8_t root[32];
    enum vcs_zcode_continuity_error error =
        continuity_signing_root(policy, root);
    if (error != VCS_ZCODE_CONTINUITY_OK) return error;
    return vcs_signed_evidence_seal_root(
               root, secret, pubkey, policy->signature)
        ? VCS_ZCODE_CONTINUITY_OK : VCS_ZCODE_CONTINUITY_NULL;
}

enum vcs_zcode_continuity_error vcs_zcode_continuity_policy_verify(
    const struct vcs_zcode_continuity_policy_v1 *policy, int64_t now_unix)
{
    enum vcs_zcode_continuity_error error = continuity_fields(policy, true);
    if (error != VCS_ZCODE_CONTINUITY_OK) return error;
    if (now_unix < policy->created_unix || now_unix >= policy->expires_unix)
        return VCS_ZCODE_CONTINUITY_TIME;
    uint8_t root[32];
    error = continuity_signing_root(policy, root);
    if (error != VCS_ZCODE_CONTINUITY_OK) return error;
    return vcs_signed_evidence_verify_root(
               root, policy->signature, policy->patron_zid_pubkey,
               policy->patron_zid_pubkey)
        ? VCS_ZCODE_CONTINUITY_OK : VCS_ZCODE_CONTINUITY_SIGNATURE;
}

enum vcs_zcode_continuity_error vcs_zcode_continuity_event_key(
    const struct vcs_zcode_creation_attribution_v1 *attribution,
    const struct vcs_zcode_continuity_policy_v1 *policy,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_score_receipt_v1 *score, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!attribution || !policy || !task || !score || !out)
        return VCS_ZCODE_CONTINUITY_NULL;
    if (vcs_zcode_creation_attribution_validate(attribution) !=
            VCS_ZCODE_CREATION_OK ||
        attribution->category == VCS_ZCODE_CREATION_PUBLIC_SOURCE ||
        attribution->lineage_kind !=
            VCS_ZCODE_CREATION_LINEAGE_CONTINUITY_POLICY)
        return VCS_ZCODE_CONTINUITY_EVENT_MASK;
    if (vcs_zcode_continuity_policy_verify(
            policy, attribution->created_unix) != VCS_ZCODE_CONTINUITY_OK)
        return VCS_ZCODE_CONTINUITY_SIGNATURE;

    uint8_t policy_root[32];
    if (vcs_zcode_continuity_policy_root(policy, policy_root) !=
            VCS_ZCODE_CONTINUITY_OK ||
        memcmp(policy_root, attribution->lineage_root, 32) != 0)
        return VCS_ZCODE_CONTINUITY_ROOT;
    if (memcmp(policy->package_root, attribution->package_root, 32) != 0 ||
        memcmp(policy->current_release_root,
               attribution->release_root, 32) != 0)
        return VCS_ZCODE_CONTINUITY_PACKAGE;
    if (memcmp(policy->proof_policy_root,
               attribution->proof_policy_root, 32) != 0 ||
        memcmp(task->proof_policy_root,
               attribution->proof_policy_root, 32) != 0)
        return VCS_ZCODE_CONTINUITY_PROOF_POLICY;
    if (memcmp(task->toolchain_capsule_root,
               policy->to_capsule_root, 32) != 0)
        return VCS_ZCODE_CONTINUITY_TRANSITION;
    if (attribution->award_atoms > policy->per_cycle_cap_atoms)
        return VCS_ZCODE_CONTINUITY_CAP;
    if (vcs_zcode_score_receipt_verify(score) != VCS_ZCODE_SCORE_OK ||
        memcmp(score->task_root, attribution->task_root, 32) != 0 ||
        memcmp(score->candidate_root, attribution->candidate_root, 32) != 0 ||
        memcmp(score->package_root, attribution->package_root, 32) != 0 ||
        memcmp(score->release_root, attribution->release_root, 32) != 0)
        return VCS_ZCODE_CONTINUITY_CAS;

    uint8_t event_class = 0, score_unit = 0;
    const uint8_t *subject = NULL, *from = NULL, *to = NULL;
    uint8_t zero[32] = {0};
    switch (attribution->category) {
    case VCS_ZCODE_CREATION_BORN_RED_FIX:
        if ((policy->event_mask & VCS_ZCODE_CONTINUITY_BORN_RED_FIX) == 0)
            return VCS_ZCODE_CONTINUITY_EVENT_MASK;
        event_class = 1;
        score_unit = VCS_ZCODE_SCORE_BORN_RED_DEFECT_TEST;
        subject = score->evidence_roots[score_unit];
        from = zero; to = zero;
        break;
    case VCS_ZCODE_CREATION_SECURITY_FIX:
        if ((policy->event_mask & VCS_ZCODE_CONTINUITY_BORN_RED_FIX) == 0)
            return VCS_ZCODE_CONTINUITY_EVENT_MASK;
        event_class = 1;
        score_unit = VCS_ZCODE_SCORE_BORN_RED_DEFECT_TEST;
        subject = score->evidence_roots[score_unit];
        from = zero; to = zero;
        break;
    case VCS_ZCODE_CREATION_INDEPENDENT_REPRODUCTION:
        if ((policy->event_mask &
             VCS_ZCODE_CONTINUITY_INDEPENDENT_REPRODUCTION) == 0)
            return VCS_ZCODE_CONTINUITY_EVENT_MASK;
        event_class = 2;
        score_unit = VCS_ZCODE_SCORE_INDEPENDENT_REPRODUCTION;
        subject = attribution->release_root;
        from = zero; to = policy->to_capsule_root;
        break;
    case VCS_ZCODE_CREATION_COMPATIBILITY:
        if ((policy->event_mask & VCS_ZCODE_CONTINUITY_COMPATIBILITY) == 0)
            return VCS_ZCODE_CONTINUITY_EVENT_MASK;
        event_class = 3;
        score_unit = VCS_ZCODE_SCORE_COMPATIBILITY_MAINTENANCE;
        subject = attribution->package_root;
        from = policy->from_capsule_root;
        to = policy->to_capsule_root;
        break;
    case VCS_ZCODE_CREATION_PRESERVATION:
        if ((policy->event_mask & VCS_ZCODE_CONTINUITY_PRESERVATION) == 0)
            return VCS_ZCODE_CONTINUITY_EVENT_MASK;
        event_class = 4;
        score_unit = VCS_ZCODE_SCORE_COMPATIBILITY_MAINTENANCE;
        subject = attribution->release_root;
        from = policy->from_capsule_root;
        to = policy->to_capsule_root;
        break;
    default: return VCS_ZCODE_CONTINUITY_EVENT_MASK;
    }
    if ((score->awarded_mask & (UINT8_C(1) << score_unit)) == 0 ||
        !zcl_bytes_any_set(score->evidence_roots[score_unit], 32))
        return VCS_ZCODE_CONTINUITY_CAS;

    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_CONTINUITY_EVENT_KEY_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, &event_class, sizeof(event_class));
    sha3_256_write(&sha, subject, 32);
    sha3_256_write(&sha, from, 32);
    sha3_256_write(&sha, to, 32);
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_CONTINUITY_OK;
}

enum vcs_zcode_continuity_error vcs_zcode_creation_event_key(
    const struct vcs_zcode_creation_attribution_v1 *attribution,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_score_receipt_v1 *score, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!attribution || !task || !score || !out)
        return VCS_ZCODE_CONTINUITY_NULL;
    if (vcs_zcode_creation_attribution_validate(attribution) !=
            VCS_ZCODE_CREATION_OK ||
        attribution->category == VCS_ZCODE_CREATION_PUBLIC_SOURCE)
        return VCS_ZCODE_CONTINUITY_EVENT_MASK;
    if (vcs_zcode_score_receipt_verify(score) != VCS_ZCODE_SCORE_OK ||
        memcmp(score->task_root, attribution->task_root, 32) != 0 ||
        memcmp(score->candidate_root, attribution->candidate_root, 32) != 0 ||
        memcmp(score->package_root, attribution->package_root, 32) != 0 ||
        memcmp(score->release_root, attribution->release_root, 32) != 0 ||
        memcmp(task->proof_policy_root,
               attribution->proof_policy_root, 32) != 0)
        return VCS_ZCODE_CONTINUITY_CAS;

    uint8_t event_class = 0, score_unit = 0;
    switch (attribution->category) {
    case VCS_ZCODE_CREATION_BORN_RED_FIX:
    case VCS_ZCODE_CREATION_SECURITY_FIX:
        event_class = 1;
        score_unit = VCS_ZCODE_SCORE_BORN_RED_DEFECT_TEST;
        break;
    case VCS_ZCODE_CREATION_INDEPENDENT_REPRODUCTION:
        event_class = 2;
        score_unit = VCS_ZCODE_SCORE_INDEPENDENT_REPRODUCTION;
        break;
    case VCS_ZCODE_CREATION_COMPATIBILITY:
        event_class = 3;
        score_unit = VCS_ZCODE_SCORE_COMPATIBILITY_MAINTENANCE;
        break;
    case VCS_ZCODE_CREATION_PRESERVATION:
        event_class = 4;
        score_unit = VCS_ZCODE_SCORE_COMPATIBILITY_MAINTENANCE;
        break;
    default:
        return VCS_ZCODE_CONTINUITY_EVENT_MASK;
    }
    if ((score->awarded_mask & (UINT8_C(1) << score_unit)) == 0 ||
        !zcl_bytes_any_set(score->evidence_roots[score_unit], 32))
        return VCS_ZCODE_CONTINUITY_CAS;

    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_CREATION_EVENT_KEY_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, &event_class, sizeof(event_class));
    sha3_256_write(&sha, score->evidence_roots[score_unit], 32);
    sha3_256_write(&sha, attribution->package_root, 32);
    sha3_256_write(&sha, attribution->release_root, 32);
    sha3_256_write(&sha, task->toolchain_capsule_root, 32);
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_CONTINUITY_OK;
}
