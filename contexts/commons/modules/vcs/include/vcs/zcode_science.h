/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical ZCODE scientific-study and evidence object wires. */

#ifndef ZCL_VCS_ZCODE_SCIENCE_H
#define ZCL_VCS_ZCODE_SCIENCE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "vcs/build_action.h"
#include "vcs/zcode_dev.h"

#define VCS_ZCODE_SCIENCE_VERSION 1u
#define VCS_ZCODE_HARDWARE_PROFILE_VERSION 1u
#define VCS_ZCODE_BENCHMARK_METHOD_VERSION 1u
#define VCS_ZCODE_BENCHMARK_RESULT_V2_VERSION 2u
#define VCS_ZCODE_SCIENCE_STATEMENT_VERSION 1u
#define VCS_ZCODE_SCIENCE_RELATION_SET_VERSION 1u
#define VCS_ZCODE_VECTOR_NAVIGATION_PREREGISTRATION_VERSION 1u
#define VCS_ZCODE_STUDY_SPEC_DOMAIN "zcl.zcode.study_spec.v1"
#define VCS_ZCODE_BENCHMARK_RESULT_DOMAIN "zcl.zcode.benchmark_result.v1"
#define VCS_ZCODE_REPRODUCTION_DOMAIN "zcl.zcode.reproduction.v1"
#define VCS_ZCODE_SCIENCE_FINDINGS_DOMAIN "zcl.zcode.science_findings.v1"
#define VCS_ZCODE_CURATION_VOTE_DOMAIN "zcl.zcode.curation_vote.v1"
#define VCS_ZCODE_HARDWARE_PROFILE_DOMAIN "zcl.zcode.hardware_profile.v1"
#define VCS_ZCODE_BENCHMARK_METHOD_DOMAIN "zcl.zcode.benchmark_method.v1"
#define VCS_ZCODE_BENCHMARK_RESULT_V2_DOMAIN "zcl.zcode.benchmark_result.v2"
#define VCS_ZCODE_SCIENCE_STATEMENT_DOMAIN "zcl.science_statement.v1"
#define VCS_ZCODE_SCIENCE_STATEMENT_SIGNING_DOMAIN \
    "zcl.science_statement.signature.v1"
#define VCS_ZCODE_SCIENCE_RELATION_SET_DOMAIN \
    "zcl.science_statement_relations.v1"
#define VCS_ZCODE_VECTOR_NAVIGATION_PREREGISTRATION_DOMAIN \
    "zcl.vector_navigation_preregistration.v1"

#define VCS_ZCODE_STUDY_SPEC_WIRE_BYTES 422u
#define VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES 299u
#define VCS_ZCODE_REPRODUCTION_WIRE_BYTES 251u
#define VCS_ZCODE_SCIENCE_FINDINGS_WIRE_BYTES 317u
#define VCS_ZCODE_CURATION_VOTE_BODY_BYTES 155u
#define VCS_ZCODE_CURATION_VOTE_WIRE_BYTES 219u
/* hardware_profile.v1: magic 8 + version 2 + cpu_vendor 16 + cpu_brand 48 +
 * cores 2+2 + ram_mib 8 + isa_bits 8 + os_sysname 16 + os_machine 16 +
 * os_release 32 + device_facts_root 32 + tsc_freq_hz 8 + timer_source 16 +
 * captured_unix 8. */
#define VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES 222u
/* benchmark_method.v1: magic 8 + version 2 + three roots 96 + tolerance 4 +
 * warmup 4 + measured 4 + distribution 1 + trim 1 + reserved 1. */
#define VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES 121u
/* benchmark_result.v2: the frozen 299-byte v1 body (magic "ZCBEN2\r\n",
 * version 2) + method_root 32 + hardware_profile_root 32. */
#define VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES 363u
/* statement.v1: magic 8 + version 2 + five closed enums + relation mask 1 +
 * relation count 2 + thirteen roots + observed/embargo times 16 + signer 32
 * + signature 64. */
#define VCS_ZCODE_SCIENCE_STATEMENT_BODY_BYTES 482u
#define VCS_ZCODE_SCIENCE_STATEMENT_WIRE_BYTES 546u
#define VCS_ZCODE_SCIENCE_RELATION_MAX 64u
#define VCS_ZCODE_SCIENCE_RELATION_SET_HEADER_BYTES 12u
#define VCS_ZCODE_SCIENCE_RELATION_ROW_BYTES 33u
#define VCS_ZCODE_SCIENCE_RELATION_SET_MAX_WIRE_BYTES \
    (VCS_ZCODE_SCIENCE_RELATION_SET_HEADER_BYTES + \
     VCS_ZCODE_SCIENCE_RELATION_MAX * VCS_ZCODE_SCIENCE_RELATION_ROW_BYTES)
#define VCS_ZCODE_VECTOR_NAVIGATION_PREREGISTRATION_WIRE_BYTES 696u

#define VCS_ZCODE_STUDY_REQUIRED_MAX 64u
#define VCS_ZCODE_BENCHMARK_METHOD_MAX_MEASURED_SAMPLES (1u << 20)
#define VCS_ZCODE_BENCHMARK_METHOD_MAX_TRIM_PERCENT 49u

enum vcs_zcode_benchmark_status {
    VCS_ZCODE_BENCHMARK_OBSERVED = 1,
    VCS_ZCODE_BENCHMARK_NULL_RESULT = 2,
    VCS_ZCODE_BENCHMARK_NEGATIVE_RESULT = 3,
    VCS_ZCODE_BENCHMARK_EXECUTION_FAILED = 4,
};

enum vcs_zcode_reproduction_verdict {
    VCS_ZCODE_REPRODUCTION_REPLICATED = 1,
    VCS_ZCODE_REPRODUCTION_CONTRADICTED = 2,
    VCS_ZCODE_REPRODUCTION_INCONCLUSIVE = 3,
};

enum vcs_zcode_science_finding_flag {
    VCS_ZCODE_FINDING_NEGATIVE = 1u << 0,
    VCS_ZCODE_FINDING_NULL = 1u << 1,
    VCS_ZCODE_FINDING_ENVIRONMENT_INCOMPATIBLE = 1u << 2,
    VCS_ZCODE_FINDING_STALE = 1u << 3,
    VCS_ZCODE_FINDING_RETRACTION = 1u << 4,
};

#define VCS_ZCODE_FINDING_V1_FLAG_MASK \
    (VCS_ZCODE_FINDING_NEGATIVE | VCS_ZCODE_FINDING_NULL | \
     VCS_ZCODE_FINDING_ENVIRONMENT_INCOMPATIBLE | \
     VCS_ZCODE_FINDING_STALE | VCS_ZCODE_FINDING_RETRACTION)

enum vcs_zcode_science_finding_severity {
    VCS_ZCODE_FINDING_INFORMATIONAL = 1,
    VCS_ZCODE_FINDING_MATERIAL = 2,
    VCS_ZCODE_FINDING_CRITICAL = 3,
};

enum vcs_zcode_curation_signal {
    VCS_ZCODE_CURATION_USEFUL = 1,
    VCS_ZCODE_CURATION_INTERESTING = 2,
    VCS_ZCODE_CURATION_FLAG = 3,
};

/* Immutable wire values: never renumber or reuse a value; append before the
 * matching *_COUNT sentinel and pin the new value in the enum KAT. */
enum vcs_zcode_science_profile {
    VCS_ZCODE_SCIENCE_PROFILE_IDEA = 1,
    VCS_ZCODE_SCIENCE_PROFILE_QUESTION = 2,
    VCS_ZCODE_SCIENCE_PROFILE_HYPOTHESIS = 3,
    VCS_ZCODE_SCIENCE_PROFILE_PREREGISTRATION = 4,
    VCS_ZCODE_SCIENCE_PROFILE_PROTOCOL = 5,
    VCS_ZCODE_SCIENCE_PROFILE_DATASET = 6,
    VCS_ZCODE_SCIENCE_PROFILE_OBSERVATION = 7,
    VCS_ZCODE_SCIENCE_PROFILE_COMPUTATIONAL_RUN = 8,
    VCS_ZCODE_SCIENCE_PROFILE_RESULT = 9,
    VCS_ZCODE_SCIENCE_PROFILE_CLAIM = 10,
    VCS_ZCODE_SCIENCE_PROFILE_REVIEW = 11,
    VCS_ZCODE_SCIENCE_PROFILE_REPLICATION = 12,
    VCS_ZCODE_SCIENCE_PROFILE_COUNTEREVIDENCE = 13,
    VCS_ZCODE_SCIENCE_PROFILE_SUPERSESSION = 14,
    VCS_ZCODE_SCIENCE_PROFILE_RETRACTION = 15,
    VCS_ZCODE_SCIENCE_PROFILE_COUNT = 16,
};

enum vcs_zcode_science_access {
    VCS_ZCODE_SCIENCE_ACCESS_PUBLIC = 1,
    VCS_ZCODE_SCIENCE_ACCESS_CONTROLLED = 2,
    VCS_ZCODE_SCIENCE_ACCESS_METADATA_ONLY = 3,
    VCS_ZCODE_SCIENCE_ACCESS_COUNT = 4,
};

enum vcs_zcode_science_privacy {
    VCS_ZCODE_SCIENCE_PRIVACY_PUBLIC = 1,
    VCS_ZCODE_SCIENCE_PRIVACY_DEIDENTIFIED = 2,
    VCS_ZCODE_SCIENCE_PRIVACY_SENSITIVE = 3,
    VCS_ZCODE_SCIENCE_PRIVACY_COUNT = 4,
};

enum vcs_zcode_science_redistribution {
    VCS_ZCODE_SCIENCE_REDISTRIBUTION_PERMITTED = 1,
    VCS_ZCODE_SCIENCE_REDISTRIBUTION_METADATA_ONLY = 2,
    VCS_ZCODE_SCIENCE_REDISTRIBUTION_PROHIBITED = 3,
    VCS_ZCODE_SCIENCE_REDISTRIBUTION_COUNT = 4,
};

enum vcs_zcode_science_authorship {
    VCS_ZCODE_SCIENCE_AUTHORSHIP_ASSERTED = 1,
    VCS_ZCODE_SCIENCE_AUTHORSHIP_SIGNED = 2,
    VCS_ZCODE_SCIENCE_AUTHORSHIP_COUNT = 3,
};

enum vcs_zcode_science_relation_type {
    VCS_ZCODE_SCIENCE_RELATION_SUPPORT = 1,
    VCS_ZCODE_SCIENCE_RELATION_CONFLICT = 2,
    VCS_ZCODE_SCIENCE_RELATION_SUPERSESSION = 3,
    VCS_ZCODE_SCIENCE_RELATION_RETRACTION = 4,
    VCS_ZCODE_SCIENCE_RELATION_COUNT = 5,
};

#define VCS_ZCODE_SCIENCE_RELATION_MASK(type_) \
    ((uint8_t)(1u << ((uint8_t)(type_) - 1u)))
#define VCS_ZCODE_SCIENCE_RELATION_KNOWN_MASK \
    ((uint8_t)(VCS_ZCODE_SCIENCE_RELATION_MASK( \
                    VCS_ZCODE_SCIENCE_RELATION_SUPPORT) | \
               VCS_ZCODE_SCIENCE_RELATION_MASK( \
                    VCS_ZCODE_SCIENCE_RELATION_CONFLICT) | \
               VCS_ZCODE_SCIENCE_RELATION_MASK( \
                    VCS_ZCODE_SCIENCE_RELATION_SUPERSESSION) | \
               VCS_ZCODE_SCIENCE_RELATION_MASK( \
                    VCS_ZCODE_SCIENCE_RELATION_RETRACTION)))

/* Immutable wire values: never renumber or reuse these values. Append new
 * values before the matching *_COUNT sentinel and extend the enum KAT. */
enum vcs_zcode_vector_navigation_arm {
    VCS_ZCODE_VECTOR_NAVIGATION_ARM_EXACT = 1,
    VCS_ZCODE_VECTOR_NAVIGATION_ARM_BM25 = 2,
    VCS_ZCODE_VECTOR_NAVIGATION_ARM_TRIGRAM = 3,
    VCS_ZCODE_VECTOR_NAVIGATION_ARM_DETERMINISTIC = 4,
    VCS_ZCODE_VECTOR_NAVIGATION_ARM_LEARNED = 5,
    VCS_ZCODE_VECTOR_NAVIGATION_ARM_RERANK = 6,
    VCS_ZCODE_VECTOR_NAVIGATION_ARM_HYBRID = 7,
    VCS_ZCODE_VECTOR_NAVIGATION_ARM_COUNT = 8,
};

enum vcs_zcode_vector_navigation_gate {
    VCS_ZCODE_VECTOR_NAVIGATION_GATE_QUALITY = 1,
    VCS_ZCODE_VECTOR_NAVIGATION_GATE_PRIVACY = 2,
    VCS_ZCODE_VECTOR_NAVIGATION_GATE_RIGHTS = 3,
    VCS_ZCODE_VECTOR_NAVIGATION_GATE_DETERMINISM = 4,
    VCS_ZCODE_VECTOR_NAVIGATION_GATE_RESOURCE = 5,
    VCS_ZCODE_VECTOR_NAVIGATION_GATE_COUNT = 6,
};

enum vcs_zcode_vector_navigation_evidence_kind {
    VCS_ZCODE_VECTOR_NAVIGATION_EVIDENCE_MODEL_HINT = 1,
};

enum vcs_zcode_vector_navigation_prohibition {
    VCS_ZCODE_VECTOR_NAVIGATION_CANNOT_ESTABLISH_TRUTH = 1u << 0,
    VCS_ZCODE_VECTOR_NAVIGATION_CANNOT_ESTABLISH_COMPLETENESS = 1u << 1,
    VCS_ZCODE_VECTOR_NAVIGATION_CANNOT_OMIT_MANDATORY_PROOF = 1u << 2,
};

#define VCS_ZCODE_VECTOR_NAVIGATION_REQUIRED_PROHIBITIONS \
    ((uint16_t)(VCS_ZCODE_VECTOR_NAVIGATION_CANNOT_ESTABLISH_TRUTH | \
                VCS_ZCODE_VECTOR_NAVIGATION_CANNOT_ESTABLISH_COMPLETENESS | \
                VCS_ZCODE_VECTOR_NAVIGATION_CANNOT_OMIT_MANDATORY_PROOF))
#define VCS_ZCODE_VECTOR_NAVIGATION_DEVELOPMENT_QUERIES 96u
#define VCS_ZCODE_VECTOR_NAVIGATION_SEALED_HOLDOUT_QUERIES 48u
#define VCS_ZCODE_VECTOR_NAVIGATION_BOOTSTRAP_SAMPLES 10000u
#define VCS_ZCODE_VECTOR_NAVIGATION_BOOTSTRAP_CONFIDENCE_BP 9500u
#define VCS_ZCODE_VECTOR_NAVIGATION_HIT_AT_10_GAIN_BP 1000u
#define VCS_ZCODE_VECTOR_NAVIGATION_NDCG_AT_10_GAIN_PPM 30000u
#define VCS_ZCODE_VECTOR_NAVIGATION_AGENT_NONINFERIORITY_BP 200u
#define VCS_ZCODE_VECTOR_NAVIGATION_EFFICIENCY_GAIN_BP 1000u
#define VCS_ZCODE_VECTOR_NAVIGATION_APPROX_RECALL_AT_20_BP 9900u

/* x86 ISA bitmap for hardware_profile.v1. Bits 4-12 mirror the
 * platform/modules/util/src/hw_profile.c probes (avx2, avx512f/vl/bw/dq, vpclmulqdq,
 * vaes, gfni, sha_ni); bits 0-3 are the additional baseline extensions
 * (sse4_2, bmi2, fma, aes_ni). Bits 13-63 are reserved and must be zero
 * (validate rejects them). */
enum vcs_zcode_hw_isa_bit {
    VCS_ZCODE_HW_ISA_SSE4_2 = UINT64_C(1) << 0,
    VCS_ZCODE_HW_ISA_BMI2 = UINT64_C(1) << 1,
    VCS_ZCODE_HW_ISA_FMA = UINT64_C(1) << 2,
    VCS_ZCODE_HW_ISA_AES_NI = UINT64_C(1) << 3,
    VCS_ZCODE_HW_ISA_AVX2 = UINT64_C(1) << 4,
    VCS_ZCODE_HW_ISA_AVX512F = UINT64_C(1) << 5,
    VCS_ZCODE_HW_ISA_AVX512VL = UINT64_C(1) << 6,
    VCS_ZCODE_HW_ISA_AVX512BW = UINT64_C(1) << 7,
    VCS_ZCODE_HW_ISA_AVX512DQ = UINT64_C(1) << 8,
    VCS_ZCODE_HW_ISA_VPCLMULQDQ = UINT64_C(1) << 9,
    VCS_ZCODE_HW_ISA_VAES = UINT64_C(1) << 10,
    VCS_ZCODE_HW_ISA_GFNI = UINT64_C(1) << 11,
    VCS_ZCODE_HW_ISA_SHA_NI = UINT64_C(1) << 12,
};

#define VCS_ZCODE_HW_ISA_KNOWN_MASK                                     \
    (VCS_ZCODE_HW_ISA_SSE4_2 | VCS_ZCODE_HW_ISA_BMI2 |                  \
     VCS_ZCODE_HW_ISA_FMA | VCS_ZCODE_HW_ISA_AES_NI |                   \
     VCS_ZCODE_HW_ISA_AVX2 | VCS_ZCODE_HW_ISA_AVX512F |                 \
     VCS_ZCODE_HW_ISA_AVX512VL | VCS_ZCODE_HW_ISA_AVX512BW |            \
     VCS_ZCODE_HW_ISA_AVX512DQ | VCS_ZCODE_HW_ISA_VPCLMULQDQ |          \
     VCS_ZCODE_HW_ISA_VAES | VCS_ZCODE_HW_ISA_GFNI |                    \
     VCS_ZCODE_HW_ISA_SHA_NI)

enum vcs_zcode_sample_distribution {
    VCS_ZCODE_SAMPLE_DIST_RAW_ALL = 1,
    VCS_ZCODE_SAMPLE_DIST_MINIMUM = 2,
    VCS_ZCODE_SAMPLE_DIST_MEDIAN_QUARTILES = 3,
    VCS_ZCODE_SAMPLE_DIST_TRIMMED_MEAN = 4,
};

enum vcs_zcode_science_error {
    VCS_ZCODE_SCIENCE_OK = 0,
    VCS_ZCODE_SCIENCE_ERR_NULL,
    VCS_ZCODE_SCIENCE_ERR_VERSION,
    VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE,
    VCS_ZCODE_SCIENCE_ERR_WIRE_MAGIC,
    VCS_ZCODE_SCIENCE_ERR_ROOT_ZERO,
    VCS_ZCODE_SCIENCE_ERR_PUBKEY_ZERO,
    VCS_ZCODE_SCIENCE_ERR_SIGNATURE,
    VCS_ZCODE_SCIENCE_ERR_LIMIT,
    VCS_ZCODE_SCIENCE_ERR_TIME_ORDER,
    VCS_ZCODE_SCIENCE_ERR_STATUS,
    VCS_ZCODE_SCIENCE_ERR_VERDICT,
    VCS_ZCODE_SCIENCE_ERR_FLAGS,
    VCS_ZCODE_SCIENCE_ERR_ROOT_REUSED,
    VCS_ZCODE_SCIENCE_ERR_STUDY_MISMATCH,
    VCS_ZCODE_SCIENCE_ERR_TASK_MISMATCH,
    VCS_ZCODE_SCIENCE_ERR_CANDIDATE_MISMATCH,
    VCS_ZCODE_SCIENCE_ERR_RESULT_MISMATCH,
    VCS_ZCODE_SCIENCE_ERR_REVIEW_MISMATCH,
    VCS_ZCODE_SCIENCE_ERR_ENVIRONMENT_MISMATCH,
    VCS_ZCODE_SCIENCE_ERR_NETWORK_MISMATCH,
    VCS_ZCODE_SCIENCE_ERR_IDENTITY_MISMATCH,
    VCS_ZCODE_SCIENCE_ERR_EXPIRED,
    /* New codes append at the END only; the codes above are frozen. */
    VCS_ZCODE_SCIENCE_ERR_EVIDENCE_FUTURE,
    VCS_ZCODE_SCIENCE_ERR_ACTION_MISMATCH,
    VCS_ZCODE_SCIENCE_ERR_PADDING,
    VCS_ZCODE_SCIENCE_ERR_ISA,
    VCS_ZCODE_SCIENCE_ERR_DISTRIBUTION,
    VCS_ZCODE_SCIENCE_ERR_METHOD_MISMATCH,
    VCS_ZCODE_SCIENCE_ERR_HARDWARE_MISMATCH,
    VCS_ZCODE_SCIENCE_ERR_PROFILE,
    VCS_ZCODE_SCIENCE_ERR_RIGHTS,
    VCS_ZCODE_SCIENCE_ERR_AUTHORSHIP,
    VCS_ZCODE_SCIENCE_ERR_EMBARGO,
    VCS_ZCODE_SCIENCE_ERR_RELATION_TYPE,
    VCS_ZCODE_SCIENCE_ERR_RELATION_ORDER,
    VCS_ZCODE_SCIENCE_ERR_RELATION_MISMATCH,
};

const char *vcs_zcode_science_error_string(
    enum vcs_zcode_science_error error);

struct vcs_zcode_study_spec_v1 {
    uint16_t schema_version;
    uint8_t hypothesis_root[32];
    uint8_t null_hypothesis_root[32];
    uint8_t source_root[32];
    uint8_t dependency_lock_root[32];
    uint8_t toolchain_capsule_root[32];
    uint8_t protocol_root[32];
    uint8_t workloads_root[32];
    uint8_t metrics_root[32];
    uint8_t estimator_tolerance_root[32];
    uint8_t environment_policy_root[32];
    uint8_t citations_root[32];
    uint8_t preregistration_policy_root[32];
    uint16_t required_reproductions;
    uint16_t required_reviews;
    uint64_t sequence;
    int64_t created_unix;
    int64_t expires_unix;
};

struct vcs_zcode_benchmark_result_v1 {
    uint16_t schema_version;
    uint8_t study_root[32];
    uint8_t task_root[32];
    uint8_t candidate_root[32];
    uint8_t action_root[32];
    uint8_t achieved_environment_root[32];
    uint8_t raw_sample_root[32];
    uint8_t evidence_root[32];
    uint8_t status;
    uint64_t challenge_block_height;
    uint8_t challenge_block_hash[32];
    uint64_t sequence;
    int64_t started_unix;
    int64_t finished_unix;
};

struct vcs_zcode_reproduction_v1 {
    uint16_t schema_version;
    uint8_t study_root[32];
    uint8_t original_result_root[32];
    uint8_t reproduced_result_root[32];
    uint8_t comparison_policy_root[32];
    uint8_t original_environment_root[32];
    uint8_t reproduced_environment_root[32];
    uint8_t reproducer_pubkey[32];
    uint8_t verdict;
    uint64_t sequence;
    int64_t created_unix;
};

struct vcs_zcode_science_findings_v1 {
    uint16_t schema_version;
    uint8_t study_root[32];
    uint8_t task_root[32];
    uint8_t candidate_root[32];
    uint8_t result_root[32];
    uint8_t proof_set_root[32];
    uint8_t methods_root[32];
    uint8_t limitations_root[32];
    uint8_t conflicts_root[32];
    uint8_t retraction_target_root[32];
    uint16_t flags;
    uint8_t severity;
    uint64_t sequence;
    int64_t created_unix;
};

struct vcs_zcode_curation_vote_v1 {
    uint16_t schema_version;
    uint8_t network_genesis_root[32];
    uint8_t voter_zid_root[32];
    uint8_t property_root[32];
    uint8_t signal;
    uint64_t sequence;
    int64_t expires_unix;
    uint8_t signer_pubkey[32];
    uint8_t signature[64];
};

/* hardware_profile.v1 — an OBSERVED host description, never a claim of
 * truth. Fixed-width strings are NUL-padded: content bytes, one NUL, then
 * zeros to the field width; an all-zero field means undisclosed/unavailable.
 * ram_mib == 0 and tsc_freq_hz == 0 are the documented "unknown" values.
 * device_facts_root pins a canonical bundle of extended host facts
 * (DMI/firmware); all-zero when undisclosed/unavailable — it is the
 * extension point for richer host attestation and no producer fills it
 * yet. */
struct vcs_zcode_hardware_profile_v1 {
    uint16_t schema_version;
    uint8_t cpu_vendor[16];
    uint8_t cpu_brand[48];
    uint16_t physical_cores;
    uint16_t logical_cores;
    uint64_t ram_mib;
    uint64_t isa_bits;
    uint8_t os_sysname[16];
    uint8_t os_machine[16];
    uint8_t os_release[32];
    uint8_t device_facts_root[32];
    uint64_t tsc_freq_hz;
    uint8_t timer_source[16];
    int64_t captured_unix;
};

/* benchmark_method.v1 — pins the exact workload payload, the timer method,
 * and the statistical estimator, plus the sampling discipline the observer
 * used. A benchmark is an observation, never truth. */
struct vcs_zcode_benchmark_method_v1 {
    uint16_t schema_version;
    uint8_t workload_root[32];
    uint8_t timer_root[32];
    uint8_t estimator_root[32];
    uint32_t tolerance_ppm;
    uint32_t warmup_samples;
    uint32_t measured_samples;
    uint8_t sample_distribution;
    uint8_t trim_percent;
    uint8_t reserved;
};

/* benchmark_result.v2 — the frozen v1 observation extended with the method
 * and hardware-profile roots. The v1 struct prefix is layout-identical, so
 * v2 validators reuse the v1 codec on the shared prefix. */
struct vcs_zcode_benchmark_result_v2 {
    uint16_t schema_version;
    uint8_t study_root[32];
    uint8_t task_root[32];
    uint8_t candidate_root[32];
    uint8_t action_root[32];
    uint8_t achieved_environment_root[32];
    uint8_t raw_sample_root[32];
    uint8_t evidence_root[32];
    uint8_t status;
    uint64_t challenge_block_height;
    uint8_t challenge_block_hash[32];
    uint64_t sequence;
    int64_t started_unix;
    int64_t finished_unix;
    uint8_t method_root[32];
    uint8_t hardware_profile_root[32];
};

struct vcs_zcode_science_relation_v1 {
    uint8_t type;
    uint8_t statement_root[32];
};

/* Canonical row order is (type, statement_root), strictly ascending. This
 * forbids duplicates and makes one semantic relation set have one wire. */
struct vcs_zcode_science_relation_set_v1 {
    uint16_t schema_version;
    uint16_t row_count;
    struct vcs_zcode_science_relation_v1
        rows[VCS_ZCODE_SCIENCE_RELATION_MAX];
};

/* Universal evidence envelope. Roots preserve the identity of existing
 * objects; empty collections use their schema's canonical nonzero empty-set
 * root. relations_root binds vcs_zcode_science_relation_set_v1, while the
 * count and mask are a bounded declaration that can be checked without I/O.
 * Exact relation semantics require validate_relations() with the rooted set.
 * This object records assertions and rights metadata only: codec, structural
 * validation, and signature success grant no storage, publication, execution,
 * correctness, or local-acceptance authority. */
struct vcs_zcode_science_statement_v1 {
    uint16_t schema_version;
    uint8_t profile;
    uint8_t access;
    uint8_t privacy;
    uint8_t redistribution;
    uint8_t authorship;
    uint8_t relation_types;
    uint16_t relation_count;
    uint8_t subject_root[32];
    uint8_t predicate_body_root[32];
    uint8_t profile_schema_root[32];
    uint8_t provenance_root[32];
    uint8_t activity_root[32];
    uint8_t input_root[32];
    uint8_t authorship_assertion_root[32];
    uint8_t license_root[32];
    uint8_t access_policy_root[32];
    uint8_t privacy_policy_root[32];
    uint8_t external_identifiers_root[32];
    uint8_t citations_root[32];
    uint8_t relations_root[32];
    int64_t observed_unix;
    int64_t embargo_until_unix;
    uint8_t signer_pubkey[32];
    uint8_t signature[64];
};

/* Frozen preregistration body for the optional vector-navigation adoption
 * study. The seven arm roots identify exact, BM25, trigram, deterministic,
 * learned, rerank, and hybrid methods in enum order; the five gate roots
 * identify quality, privacy, rights, determinism, and resource policies in
 * enum order. The result_root freezes the result/grade schema before the
 * study, not an observed future outcome. All roots are exact nonzero object
 * identities. This object and its MODEL_HINT evidence cannot establish truth
 * or completeness, omit a mandatory proof, publish data, or authorize code. */
struct vcs_zcode_vector_navigation_preregistration_v1 {
    uint16_t schema_version;
    uint8_t arm_count;
    uint8_t gate_count;
    uint8_t evidence_kind;
    uint8_t reserved;
    uint16_t prohibited_claims;
    uint16_t development_queries;
    uint16_t sealed_holdout_queries;
    uint32_t paired_bootstrap_samples;
    uint64_t bootstrap_seed;
    uint16_t bootstrap_confidence_bp;
    uint16_t paraphrase_hit_at_10_gain_bp;
    uint32_t overall_ndcg_at_10_gain_ppm;
    uint16_t agent_noninferiority_bp;
    uint16_t efficiency_gain_bp;
    uint16_t approximate_recall_at_20_bp;
    uint16_t maximum_exact_identity_changes;
    uint16_t maximum_mandatory_proof_omissions;
    uint16_t maximum_vector_only_completeness_claims;
    uint32_t reserved_tail;
    uint8_t study_spec_root[32];
    uint8_t source_root[32];
    uint8_t task_root[32];
    uint8_t ontology_root[32];
    uint8_t concept_card_root[32];
    uint8_t model_root[32];
    uint8_t embedding_profile_root[32];
    uint8_t result_root[32];
    uint8_t arm_roots[VCS_ZCODE_VECTOR_NAVIGATION_ARM_COUNT - 1u][32];
    uint8_t gate_roots[VCS_ZCODE_VECTOR_NAVIGATION_GATE_COUNT - 1u][32];
};

enum vcs_zcode_science_error vcs_zcode_study_spec_validate(
    const struct vcs_zcode_study_spec_v1 *study);
enum vcs_zcode_science_error vcs_zcode_study_spec_validate_at(
    const struct vcs_zcode_study_spec_v1 *study, int64_t now_unix);
/* Submit-vs-verify split: expiry gates NEW submissions only. A study accepts
 * a submission at now_unix iff the spec is structurally valid and now_unix is
 * inside [created_unix, expires_unix). Historical evidence created inside the
 * window must keep re-verifying after the window closes, so the cross-object
 * validators below never call this gate (or validate_at) on the study — they
 * check the evidence object's own timestamps against the window instead. */
bool vcs_zcode_study_spec_accepts_submission_at(
    const struct vcs_zcode_study_spec_v1 *study, int64_t now_unix);
enum vcs_zcode_science_error vcs_zcode_study_spec_serialize(
    const struct vcs_zcode_study_spec_v1 *study,
    uint8_t out[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES]);
enum vcs_zcode_science_error vcs_zcode_study_spec_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_study_spec_v1 *out);
enum vcs_zcode_science_error vcs_zcode_study_spec_root(
    const struct vcs_zcode_study_spec_v1 *study, uint8_t out[32]);

enum vcs_zcode_science_error vcs_zcode_benchmark_result_validate(
    const struct vcs_zcode_benchmark_result_v1 *result);
enum vcs_zcode_science_error vcs_zcode_benchmark_result_serialize(
    const struct vcs_zcode_benchmark_result_v1 *result,
    uint8_t out[VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES]);
enum vcs_zcode_science_error vcs_zcode_benchmark_result_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_benchmark_result_v1 *out);
enum vcs_zcode_science_error vcs_zcode_benchmark_result_root(
    const struct vcs_zcode_benchmark_result_v1 *result, uint8_t out[32]);

enum vcs_zcode_science_error vcs_zcode_reproduction_validate(
    const struct vcs_zcode_reproduction_v1 *reproduction);
enum vcs_zcode_science_error vcs_zcode_reproduction_serialize(
    const struct vcs_zcode_reproduction_v1 *reproduction,
    uint8_t out[VCS_ZCODE_REPRODUCTION_WIRE_BYTES]);
enum vcs_zcode_science_error vcs_zcode_reproduction_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_reproduction_v1 *out);
enum vcs_zcode_science_error vcs_zcode_reproduction_root(
    const struct vcs_zcode_reproduction_v1 *reproduction, uint8_t out[32]);

enum vcs_zcode_science_error vcs_zcode_science_findings_validate(
    const struct vcs_zcode_science_findings_v1 *findings);
enum vcs_zcode_science_error vcs_zcode_science_findings_serialize(
    const struct vcs_zcode_science_findings_v1 *findings,
    uint8_t out[VCS_ZCODE_SCIENCE_FINDINGS_WIRE_BYTES]);
enum vcs_zcode_science_error vcs_zcode_science_findings_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_science_findings_v1 *out);
enum vcs_zcode_science_error vcs_zcode_science_findings_root(
    const struct vcs_zcode_science_findings_v1 *findings, uint8_t out[32]);

enum vcs_zcode_science_error vcs_zcode_curation_vote_validate(
    const struct vcs_zcode_curation_vote_v1 *vote);
/* Curation votes are LIVE signals, not historical evidence: unlike the
 * evidence objects above, a vote's expiry keeps gating it at verify time and
 * an expired vote is simply no longer counted. */
enum vcs_zcode_science_error vcs_zcode_curation_vote_validate_at(
    const struct vcs_zcode_curation_vote_v1 *vote, int64_t now_unix);
enum vcs_zcode_science_error vcs_zcode_curation_vote_serialize(
    const struct vcs_zcode_curation_vote_v1 *vote,
    uint8_t out[VCS_ZCODE_CURATION_VOTE_WIRE_BYTES]);
enum vcs_zcode_science_error vcs_zcode_curation_vote_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_curation_vote_v1 *out);
enum vcs_zcode_science_error vcs_zcode_curation_vote_id(
    const struct vcs_zcode_curation_vote_v1 *vote, uint8_t out[32]);
enum vcs_zcode_science_error vcs_zcode_curation_vote_seal(
    struct vcs_zcode_curation_vote_v1 *vote, const uint8_t secret[32],
    const uint8_t pubkey[32]);
enum vcs_zcode_science_error vcs_zcode_curation_vote_verify(
    const struct vcs_zcode_curation_vote_v1 *vote,
    const uint8_t expected_network_genesis[32],
    const uint8_t expected_voter_zid[32],
    const uint8_t expected_signer[32], int64_t now_unix);

/* Cross-object evidence validators. These VERIFY evidence whenever it is
 * read, including long after the study window closed; they reject evidence
 * whose own timestamps fall outside [study.created_unix, study.expires_unix),
 * and report evidence timestamped after now_unix as
 * VCS_ZCODE_SCIENCE_ERR_EVIDENCE_FUTURE so callers can distinguish a clock
 * problem from a window violation. The benchmark result must also bind the
 * canonical root of a registered fixed action (build_action.h): `action` is
 * the executed action instance and result->action_root must equal its
 * canonical root under one of the fixed kinds. */
enum vcs_zcode_science_error vcs_zcode_benchmark_result_validate_for_study(
    const struct vcs_zcode_study_spec_v1 *study,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_build_action_v1 *action,
    const struct vcs_zcode_benchmark_result_v1 *result, int64_t now_unix);
enum vcs_zcode_science_error vcs_zcode_reproduction_validate_for_results(
    const struct vcs_zcode_study_spec_v1 *study,
    const struct vcs_zcode_benchmark_result_v1 *original,
    const struct vcs_zcode_benchmark_result_v1 *reproduced,
    const struct vcs_zcode_reproduction_v1 *reproduction, int64_t now_unix);
enum vcs_zcode_science_error vcs_zcode_science_findings_validate_for_review(
    const struct vcs_zcode_study_spec_v1 *study,
    const struct vcs_zcode_review_v1 *review,
    const struct vcs_zcode_benchmark_result_v1 *result,
    const struct vcs_zcode_science_findings_v1 *findings, int64_t now_unix);

enum vcs_zcode_science_error vcs_zcode_hardware_profile_validate(
    const struct vcs_zcode_hardware_profile_v1 *profile);
enum vcs_zcode_science_error vcs_zcode_hardware_profile_serialize(
    const struct vcs_zcode_hardware_profile_v1 *profile,
    uint8_t out[VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES]);
enum vcs_zcode_science_error vcs_zcode_hardware_profile_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_hardware_profile_v1 *out);
enum vcs_zcode_science_error vcs_zcode_hardware_profile_root(
    const struct vcs_zcode_hardware_profile_v1 *profile, uint8_t out[32]);
/* Best-effort Linux capture: reuses the platform/modules/util hw_profile probes (cores,
 * RAM, ISA), uname(2) for os_*, /proc/cpuinfo for cpu_vendor/cpu_brand/tsc,
 * and the clocksource sysfs node for timer_source. NEVER fails hard: every
 * missing fact stays zero (the documented "unknown"), cores fall back to 1
 * (the capture itself proves at least one core exists), and
 * device_facts_root stays all-zero (extension point). Returns false only on
 * a NULL out; the produced object always passes validate(). */
bool vcs_zcode_hardware_profile_capture(
    struct vcs_zcode_hardware_profile_v1 *out, int64_t now_unix);

enum vcs_zcode_science_error vcs_zcode_benchmark_method_validate(
    const struct vcs_zcode_benchmark_method_v1 *method);
enum vcs_zcode_science_error vcs_zcode_benchmark_method_serialize(
    const struct vcs_zcode_benchmark_method_v1 *method,
    uint8_t out[VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES]);
enum vcs_zcode_science_error vcs_zcode_benchmark_method_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_benchmark_method_v1 *out);
enum vcs_zcode_science_error vcs_zcode_benchmark_method_root(
    const struct vcs_zcode_benchmark_method_v1 *method, uint8_t out[32]);
const char *vcs_zcode_benchmark_method_distribution_name(
    uint8_t sample_distribution);

enum vcs_zcode_science_error vcs_zcode_benchmark_result_v2_validate(
    const struct vcs_zcode_benchmark_result_v2 *result);
enum vcs_zcode_science_error vcs_zcode_benchmark_result_v2_serialize(
    const struct vcs_zcode_benchmark_result_v2 *result,
    uint8_t out[VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES]);
enum vcs_zcode_science_error vcs_zcode_benchmark_result_v2_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_benchmark_result_v2 *out);
enum vcs_zcode_science_error vcs_zcode_benchmark_result_v2_root(
    const struct vcs_zcode_benchmark_result_v2 *result, uint8_t out[32]);
/* v2 cross-validator: identical rules to the H1-H3-hardened v1
 * validate_for_study on the shared v1 prefix (structural study validate,
 * evidence window vs [created,expires), ERR_EVIDENCE_FUTURE, canonical
 * fixed-action binding, study/task/candidate root pins) PLUS the method and
 * hardware-profile bindings: both objects must pass their own validate()
 * and result->method_root / result->hardware_profile_root must equal their
 * canonical roots. */
enum vcs_zcode_science_error vcs_zcode_benchmark_result_v2_validate_for_study(
    const struct vcs_zcode_study_spec_v1 *study,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_build_action_v1 *action,
    const struct vcs_zcode_benchmark_method_v1 *method,
    const struct vcs_zcode_hardware_profile_v1 *profile,
    const struct vcs_zcode_benchmark_result_v2 *result, int64_t now_unix);

/* Statement parse and validate are structural only. They do not verify a signature,
 * resolve relation bytes, establish truth, or grant any authority. */
enum vcs_zcode_science_error vcs_zcode_science_statement_validate(
    const struct vcs_zcode_science_statement_v1 *statement);
enum vcs_zcode_science_error vcs_zcode_science_statement_serialize(
    const struct vcs_zcode_science_statement_v1 *statement,
    uint8_t out[VCS_ZCODE_SCIENCE_STATEMENT_WIRE_BYTES]);
enum vcs_zcode_science_error vcs_zcode_science_statement_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_science_statement_v1 *out);
enum vcs_zcode_science_error vcs_zcode_science_statement_root(
    const struct vcs_zcode_science_statement_v1 *statement, uint8_t out[32]);
enum vcs_zcode_science_error vcs_zcode_science_statement_seal(
    struct vcs_zcode_science_statement_v1 *statement,
    const uint8_t secret[32], const uint8_t pubkey[32]);
enum vcs_zcode_science_error vcs_zcode_science_statement_verify(
    const struct vcs_zcode_science_statement_v1 *statement,
    const uint8_t expected_signer[32]);

/* Relation-set parse and validate are likewise structural. Cross-validation
 * proves only canonical root/count/type agreement, never truth or authority. */
enum vcs_zcode_science_error vcs_zcode_science_relation_set_validate(
    const struct vcs_zcode_science_relation_set_v1 *relations);
enum vcs_zcode_science_error vcs_zcode_science_relation_set_serialize(
    const struct vcs_zcode_science_relation_set_v1 *relations,
    uint8_t out[VCS_ZCODE_SCIENCE_RELATION_SET_MAX_WIRE_BYTES],
    size_t *out_len);
enum vcs_zcode_science_error vcs_zcode_science_relation_set_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_science_relation_set_v1 *out);
enum vcs_zcode_science_error vcs_zcode_science_relation_set_root(
    const struct vcs_zcode_science_relation_set_v1 *relations,
    uint8_t out[32]);
enum vcs_zcode_science_error vcs_zcode_science_statement_validate_relations(
    const struct vcs_zcode_science_statement_v1 *statement,
    const struct vcs_zcode_science_relation_set_v1 *relations);

/* These functions establish canonical structure and exact root bindings only.
 * They do not evaluate study results, establish vector claims, or confer any
 * publication, execution, proof-omission, or local-acceptance authority. */
enum vcs_zcode_science_error
vcs_zcode_vector_navigation_preregistration_validate(
    const struct vcs_zcode_vector_navigation_preregistration_v1 *prereg);
enum vcs_zcode_science_error
vcs_zcode_vector_navigation_preregistration_serialize(
    const struct vcs_zcode_vector_navigation_preregistration_v1 *prereg,
    uint8_t out[VCS_ZCODE_VECTOR_NAVIGATION_PREREGISTRATION_WIRE_BYTES]);
enum vcs_zcode_science_error
vcs_zcode_vector_navigation_preregistration_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_vector_navigation_preregistration_v1 *out);
enum vcs_zcode_science_error vcs_zcode_vector_navigation_preregistration_root(
    const struct vcs_zcode_vector_navigation_preregistration_v1 *prereg,
    uint8_t out[32]);
enum vcs_zcode_science_error
vcs_zcode_vector_navigation_preregistration_validate_bindings(
    const struct vcs_zcode_vector_navigation_preregistration_v1 *prereg,
    const struct vcs_zcode_study_spec_v1 *study,
    const struct vcs_zcode_science_statement_v1 *statement);

#endif /* ZCL_VCS_ZCODE_SCIENCE_H */
