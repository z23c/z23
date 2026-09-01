/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical S4 benchmark-execution receipt wires: the workload
 *          payload bundle, the raw-sample manifest, the per-run sample
 *          payload, the benchmark evidence bundle, and the environment
 *          policy a study pins.
 *
 * These are PURE CODECS in the zcode_science.h tradition: fixed magics,
 * little-endian integers, exactly one legal encoding per object, exact-
 * length parsers that reject any trailing byte and zero the output on
 * every failure. Roots are SHA3-256 over a frozen domain (hashed WITH its
 * trailing NUL, the package_manifest convention) followed by the canonical
 * wire; the root is the object's CAS address.
 *
 * A benchmark is an OBSERVATION, never truth: no object here carries an
 * accepted/correct/true field. The manifest is deliberately STABLE across
 * runs of the same method — it binds the method, the workload, the sample
 * counts, and the timer source, never the observed values — so two runs of
 * one recipe + action + method share method/profile/manifest roots while
 * their sample payloads (and the evidence bundles that reference them)
 * differ with the wall clock. */

#ifndef ZCL_VCS_ZCODE_BENCHMARK_RECEIPT_H
#define ZCL_VCS_ZCODE_BENCHMARK_RECEIPT_H

#include "vcs/zcode_science.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_BENCHMARK_WORKLOAD_VERSION 1u
#define VCS_ZCODE_RAW_SAMPLE_MANIFEST_VERSION 1u
#define VCS_ZCODE_SAMPLE_PAYLOAD_VERSION 1u
#define VCS_ZCODE_BENCHMARK_EVIDENCE_VERSION 1u
#define VCS_ZCODE_ENVIRONMENT_POLICY_VERSION 1u

#define VCS_ZCODE_BENCHMARK_WORKLOAD_DOMAIN "zcl.zcode.benchmark_workload.v1"
#define VCS_ZCODE_RAW_SAMPLE_MANIFEST_DOMAIN \
    "zcl.zcode.raw_sample_manifest.v1"
#define VCS_ZCODE_SAMPLE_PAYLOAD_DOMAIN "zcl.zcode.sample_payload.v1"
#define VCS_ZCODE_BENCHMARK_EVIDENCE_DOMAIN "zcl.zcode.benchmark_evidence.v1"
#define VCS_ZCODE_ENVIRONMENT_POLICY_DOMAIN "zcl.zcode.environment_policy.v1"

/* Envelope overhead for the two variable-length wires:
 * magic 8 + version 2 + count 8 = 18. */
#define VCS_ZCODE_BENCHMARK_WORKLOAD_HEADER_BYTES 18u
#define VCS_ZCODE_SAMPLE_PAYLOAD_HEADER_BYTES 18u
/* raw_sample_manifest.v1: magic 8 + version 2 + method_root 32 +
 * workload_root 32 + warmup 8 + measured 8 + timer_source 16. */
#define VCS_ZCODE_RAW_SAMPLE_MANIFEST_WIRE_BYTES 106u
/* benchmark_evidence.v1: magic 8 + version 2 + three roots 96 +
 * min/median/max 24 + status 1 + isolation 1 + reserved 8. */
#define VCS_ZCODE_BENCHMARK_EVIDENCE_WIRE_BYTES 140u
/* environment_policy.v1: magic 8 + version 2 + required_isa 8 +
 * min cores 2+2 + min_ram_mib 8 + required_timer_source 16 + reserved 8. */
#define VCS_ZCODE_ENVIRONMENT_POLICY_WIRE_BYTES 54u

#define VCS_ZCODE_BENCHMARK_WORKLOAD_MAX_PAYLOAD_BYTES \
    (16u * 1024u * 1024u)
#define VCS_ZCODE_SAMPLE_PAYLOAD_MAX_SAMPLES \
    VCS_ZCODE_BENCHMARK_METHOD_MAX_MEASURED_SAMPLES

/* The isolation vocabulary a benchmark run reports, mirroring
 * package_build's: a run whose confinement applied fully is FULL; anything
 * less is DEGRADED and says so (the executor refuses to run at all when the
 * sandbox self-check fails, so DEGRADED is reserved for run-time degrade
 * reporting, never a silent pass). */
enum vcs_zcode_benchmark_isolation {
    VCS_ZCODE_BENCHMARK_ISOLATION_FULL = 0,
    VCS_ZCODE_BENCHMARK_ISOLATION_DEGRADED = 1,
};

/* Every rejection names the failed rule. The enum order is frozen. */
enum vcs_zcode_receipt_error {
    VCS_ZCODE_RECEIPT_OK = 0,
    VCS_ZCODE_RECEIPT_ERR_NULL,           /* null argument */
    VCS_ZCODE_RECEIPT_ERR_VERSION,        /* schema_version mismatch */
    VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE,      /* wrong/excess length (trailing) */
    VCS_ZCODE_RECEIPT_ERR_WIRE_MAGIC,     /* bad magic */
    VCS_ZCODE_RECEIPT_ERR_ROOT_ZERO,      /* a committed root is all-zero */
    VCS_ZCODE_RECEIPT_ERR_LIMIT,          /* count/scalar outside its bound */
    VCS_ZCODE_RECEIPT_ERR_STATUS,         /* benchmark status out of range */
    VCS_ZCODE_RECEIPT_ERR_ISOLATION,      /* isolation id out of range */
    VCS_ZCODE_RECEIPT_ERR_ORDER,          /* min > median or median > max */
    VCS_ZCODE_RECEIPT_ERR_ISA,            /* ISA bits outside KNOWN_MASK */
    VCS_ZCODE_RECEIPT_ERR_PADDING,        /* fixed-string padding violation */
    VCS_ZCODE_RECEIPT_ERR_RESERVED,       /* a reserved field is nonzero */
};

const char *vcs_zcode_receipt_error_string(enum vcs_zcode_receipt_error error);

/* ── workload bundle v1 (the bytes the fixed kernel observes) ──────────
 * Wire: [8 magic "ZCWRK1\r\n"][2 version][8 payload_len][payload bytes].
 * The parse view BORROWS the payload pointer into the caller's wire — no
 * allocation, and the wire must outlive the view. */
struct vcs_zcode_benchmark_workload_v1_view {
    uint16_t schema_version;
    const uint8_t *payload; /* borrowed, exactly payload_len bytes */
    uint64_t payload_len;
};

enum vcs_zcode_receipt_error vcs_zcode_benchmark_workload_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_benchmark_workload_v1_view *out);
enum vcs_zcode_receipt_error vcs_zcode_benchmark_workload_v1_serialize(
    const uint8_t *payload, uint64_t payload_len, uint8_t *out,
    size_t out_cap);
/* Root over an already-canonical workload wire (parse-validated first). */
enum vcs_zcode_receipt_error vcs_zcode_benchmark_workload_v1_root(
    const uint8_t *wire, size_t wire_len, uint8_t out[32]);

/* ── raw-sample manifest v1 (STABLE across runs; binds no values) ────── */
struct vcs_zcode_raw_sample_manifest_v1 {
    uint16_t schema_version;
    uint8_t method_root[32];
    uint8_t workload_root[32];
    uint64_t warmup_samples;
    uint64_t measured_samples;
    uint8_t timer_source[16]; /* fixed-width NUL-padded; all-zero = unknown */
};

enum vcs_zcode_receipt_error vcs_zcode_raw_sample_manifest_v1_validate(
    const struct vcs_zcode_raw_sample_manifest_v1 *manifest);
enum vcs_zcode_receipt_error vcs_zcode_raw_sample_manifest_v1_serialize(
    const struct vcs_zcode_raw_sample_manifest_v1 *manifest,
    uint8_t out[VCS_ZCODE_RAW_SAMPLE_MANIFEST_WIRE_BYTES]);
enum vcs_zcode_receipt_error vcs_zcode_raw_sample_manifest_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_raw_sample_manifest_v1 *out);
enum vcs_zcode_receipt_error vcs_zcode_raw_sample_manifest_v1_root(
    const struct vcs_zcode_raw_sample_manifest_v1 *manifest, uint8_t out[32]);

/* ── sample payload v1 (one run's observed values, in run order) ───────
 * Wire: [8 magic "ZCSPL1\r\n"][2 version][8 count][count x u64 ns LE].
 * The parse view BORROWS the wire pointer (no allocation; the wire must
 * outlive the view) and samples are read with _sample_at, which memcpys —
 * the 18-byte header leaves the sample array unaligned. */
struct vcs_zcode_sample_payload_v1_view {
    uint16_t schema_version;
    const uint8_t *sample_bytes; /* borrowed, 8 * count bytes */
    uint64_t count;
};

enum vcs_zcode_receipt_error vcs_zcode_sample_payload_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_sample_payload_v1_view *out);
/* Read sample i (i < view->count). Returns false on a bad view or index. */
bool vcs_zcode_sample_payload_v1_sample_at(
    const struct vcs_zcode_sample_payload_v1_view *view, uint64_t i,
    uint64_t *out);
enum vcs_zcode_receipt_error vcs_zcode_sample_payload_v1_serialize(
    const uint64_t *samples, uint64_t count, uint8_t *out, size_t out_cap);
enum vcs_zcode_receipt_error vcs_zcode_sample_payload_v1_root(
    const uint8_t *wire, size_t wire_len, uint8_t out[32]);

/* ── benchmark evidence v1 (one run's summary + confinement facts) ───── */
struct vcs_zcode_benchmark_evidence_v1 {
    uint16_t schema_version;
    uint8_t action_root[32];
    uint8_t manifest_root[32];
    uint8_t sample_payload_root[32];
    uint64_t min_ns;
    uint64_t median_ns;
    uint64_t max_ns;
    uint8_t status;    /* enum vcs_zcode_benchmark_status */
    uint8_t isolation; /* enum vcs_zcode_benchmark_isolation */
    uint8_t reserved[8];
};

enum vcs_zcode_receipt_error vcs_zcode_benchmark_evidence_v1_validate(
    const struct vcs_zcode_benchmark_evidence_v1 *evidence);
enum vcs_zcode_receipt_error vcs_zcode_benchmark_evidence_v1_serialize(
    const struct vcs_zcode_benchmark_evidence_v1 *evidence,
    uint8_t out[VCS_ZCODE_BENCHMARK_EVIDENCE_WIRE_BYTES]);
enum vcs_zcode_receipt_error vcs_zcode_benchmark_evidence_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_benchmark_evidence_v1 *out);
enum vcs_zcode_receipt_error vcs_zcode_benchmark_evidence_v1_root(
    const struct vcs_zcode_benchmark_evidence_v1 *evidence, uint8_t out[32]);

/* ── environment policy v1 (what a study requires of an observer) ──────
 * The study's environment_policy_root addresses this object. A captured
 * hardware profile is admissible under the policy iff it carries every
 * required ISA bit, meets the core/RAM floors, and (when the policy names
 * one) runs the required timer source. All-zero minima and an all-zero
 * timer source constrain nothing. */
struct vcs_zcode_environment_policy_v1 {
    uint16_t schema_version;
    uint64_t required_isa_bits; /* subset of VCS_ZCODE_HW_ISA_KNOWN_MASK */
    uint16_t min_physical_cores;
    uint16_t min_logical_cores;
    uint64_t min_ram_mib;
    uint8_t required_timer_source[16]; /* NUL-padded; all-zero = any */
    uint8_t reserved[8];
};

enum vcs_zcode_receipt_error vcs_zcode_environment_policy_v1_validate(
    const struct vcs_zcode_environment_policy_v1 *policy);
enum vcs_zcode_receipt_error vcs_zcode_environment_policy_v1_serialize(
    const struct vcs_zcode_environment_policy_v1 *policy,
    uint8_t out[VCS_ZCODE_ENVIRONMENT_POLICY_WIRE_BYTES]);
enum vcs_zcode_receipt_error vcs_zcode_environment_policy_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_environment_policy_v1 *out);
enum vcs_zcode_receipt_error vcs_zcode_environment_policy_v1_root(
    const struct vcs_zcode_environment_policy_v1 *policy, uint8_t out[32]);
/* True iff the captured profile satisfies every constraint the policy
 * declares. Both objects must already pass their own validate(). */
bool vcs_zcode_environment_policy_v1_accepts(
    const struct vcs_zcode_environment_policy_v1 *policy,
    const struct vcs_zcode_hardware_profile_v1 *profile);

#endif /* ZCL_VCS_ZCODE_BENCHMARK_RECEIPT_H */
