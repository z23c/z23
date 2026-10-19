/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Derive, sign, and verify the per-pair mandatory coverage
 *          manifest that binds executed test groups to eligible signed
 *          observations.
 *
 * The canonical lifecycle (docs/node/CANONICAL_LIFECYCLE.md, PROOF_SET)
 * separates reusable input keys from immutable observation roots: coverage
 * binds the mandatory input keys derived for a candidate and the receiver's
 * eligibility basis. An explicit observation run emits one signed verdict-leaf
 * observation per qualified executed group into a durable per-pair CAS
 * (see dev_proof_observation.h). What was missing
 * is the object that proves WHICH groups a pair's receipt actually executed
 * and that every one of them is either backed by eligible PASS evidence
 * with no preserved contradiction or named as unqualified. That is this
 * manifest.
 *
 * A producer derives and signs it; a receiver re-verifies it against the
 * receipt's executed-group count and its own enumeration of the same
 * store. Wiring the two into the proof worker and the pre-push hook waits
 * until the default proof emits observations. Both sides run the same
 * bounded verification over the same private CAS, so a producer cannot omit
 * a known eligible contradiction and a corrupted or replayed manifest is
 * named, never silently re-derived.
 *
 * Wire shapes are versioned apart from layout, exactly like the pair
 * receipt: the manifest is admitted only under the policy version stamped
 * into it, and an older or newer producer is named instead of misread. */

#ifndef ZCL_DEV_PROOF_COVERAGE_H
#define ZCL_DEV_PROOF_COVERAGE_H

#include "dev_proof_receipt.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Manifest file on disk: the fixed envelope wire followed by blob_len
 * canonical blob bytes. One file per pair, beside the receipt sidecars. */
#define ZCL_DEV_COVERAGE_MAGIC "Z23COV1"
#define ZCL_DEV_COVERAGE_MAGIC_BYTES 8u
#define ZCL_DEV_COVERAGE_VERSION 1u
#define ZCL_DEV_COVERAGE_UNSIGNED_WIRE_BYTES 232u
#define ZCL_DEV_COVERAGE_WIRE_BYTES \
    (ZCL_DEV_COVERAGE_UNSIGNED_WIRE_BYTES + ZCL_DEV_PROOF_SIGNER_TRAILER_BYTES)
/* Canonical blob ceiling: bounded so a hook push check stays milliseconds. */
#define ZCL_DEV_COVERAGE_BLOB_MAX_BYTES (1u << 20)
/* Hard ceilings, aligned with the observation store and lookup caps. */
#define ZCL_DEV_COVERAGE_MAX_ROWS 8192u
#define ZCL_DEV_COVERAGE_MAX_ROW_ROOTS 256u

/* Refusal tokens. These are the exact strings written into a `why` buffer
 * and printed by the pre-push hook, so a reader can act on the line without
 * reading this file. */
#define ZCL_DEV_COVERAGE_WHY_ARGUMENTS "coverage_arguments_invalid"
#define ZCL_DEV_COVERAGE_WHY_LOG_UNAVAILABLE "coverage_log_unavailable"
#define ZCL_DEV_COVERAGE_WHY_LOG_INVALID "coverage_log_invalid"
#define ZCL_DEV_COVERAGE_WHY_LOG_DUPLICATE "coverage_log_duplicate"
#define ZCL_DEV_COVERAGE_WHY_OBSERVATION_REFUSED "coverage_observation_refused"
#define ZCL_DEV_COVERAGE_WHY_OBSERVATION_FAIL "coverage_observation_fail"
#define ZCL_DEV_COVERAGE_WHY_COUNT_MISMATCH "coverage_count_mismatch"
#define ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE "coverage_store_incomplete"
#define ZCL_DEV_COVERAGE_WHY_STORE_TOO_MANY "coverage_store_too_many_roots"
#define ZCL_DEV_COVERAGE_WHY_EMITTED_MISSING "coverage_emitted_root_missing"
#define ZCL_DEV_COVERAGE_WHY_MISSING "coverage_missing"
#define ZCL_DEV_COVERAGE_WHY_MANIFEST_INVALID "coverage_manifest_invalid"
#define ZCL_DEV_COVERAGE_WHY_MANIFEST_UNSIGNED "coverage_manifest_unsigned"
#define ZCL_DEV_COVERAGE_WHY_MANIFEST_TOO_LARGE "coverage_manifest_too_large"
#define ZCL_DEV_COVERAGE_WHY_BLOB_INVALID "coverage_blob_invalid"
#define ZCL_DEV_COVERAGE_WHY_BINDING "coverage_binding_mismatch"
#define ZCL_DEV_COVERAGE_WHY_CONFLICT "proof_observation_conflict"

/* The receipt identity a manifest is bound to. A manifest is valid for
 * exactly one pair receipt: same commits, same child-set root, same impact
 * policy, same admission policy version. */
struct zcl_dev_coverage_binding {
    uint8_t local_commit[ZCL_DEV_PROOF_OID_MAX];
    uint8_t local_commit_len;
    uint8_t remote_base[ZCL_DEV_PROOF_OID_MAX];
    uint8_t remote_base_len;
    uint8_t child_set_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint8_t impact_policy_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint32_t policy_version;
};

/* Parse the test-dimension child log for canonical observation lines.
 * Every executed group emits exactly one line, first thing on the line:
 *   OBSERVATION group=<name> verdict=PASS key=<hex> root=<hex> source=independent_execution
 * for a group whose signed leaf was recorded, or
 *   OBSERVATION UNQUALIFIED group=<name> reason=<token> coverage=missing
 * for a group that executed but mints no reusable observation because it
 * has no exact input key (today: the reviewed external-input denylist,
 * under --collect-observations). An unqualified row still counts
 * toward the executed set; it carries no key and no root, and it refuses as
 * a conflict when the pair's CAS retains an eligible FAIL for that group.
 * An OBSERVATION REFUSE line refuses derivation. An embedded NUL anywhere
 * in the log refuses as invalid; a bounded complete final observation
 * without LF is accepted at clean EOF. `expected` is the
 * receipt's test-dimension ran count; when it is zero, `log_path` is not
 * opened and zero rows parse. Rows are returned in first-seen log order;
 * the canonical blob sorts them. */
struct zcl_dev_coverage_log_row {
    char group[ZCL_DEV_VERDICT_LEAF_GROUP_BYTES];
    uint8_t group_len;
    uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES];
    uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES];
    bool unqualified; /* executed, no reusable observation: key and root zero */
};

bool zcl_dev_coverage_log_rows(const char *log_path, uint32_t expected,
    struct zcl_dev_coverage_log_row *rows, uint32_t rows_cap,
    uint32_t *out_count, char *why, size_t why_len);

/* Producer side: derive the mandatory set from the executed-group log
 * rows, classify it against the observation CAS, and sign the manifest.
 * Fills `envelope` (ZCL_DEV_COVERAGE_WIRE_BYTES) and allocates the
 * canonical blob (`*blob_out`, caller frees with free()). The store must
 * contain an eligible PASS observation for every keyed (key, group)
 * including each row's emitted root, no eligible contradiction, and no
 * eligible FAIL for an unqualified group; every refusal is named. */
bool zcl_dev_coverage_manifest_derive(const char *store_root,
    const char *test_log_path,
    const struct zcl_dev_coverage_binding *binding, uint32_t expected_rows,
    uint8_t envelope[ZCL_DEV_COVERAGE_WIRE_BYTES],
    uint8_t **blob_out, size_t *blob_len_out,
    char *why, size_t why_len);

/* Read only the blob length from a stored envelope wire. The pre-push
 * hook uses this to size its bounded second read of the manifest file;
 * full parse and verification happen in _manifest_verify. */
bool zcl_dev_coverage_envelope_blob_len(const uint8_t *envelope_wire,
                                        size_t envelope_len,
                                        uint32_t *blob_len_out);

/* Receiver side: verify a stored manifest (the fixed envelope wire and its
 * canonical blob) against the binding, the receipt's executed-group count
 * (`expected_rows`, the test dimension's ran count) and a complete local
 * enumeration of the same observation CAS. Refuses by name; never aborts. */
bool zcl_dev_coverage_manifest_verify(const char *store_root,
    const uint8_t *envelope_wire, size_t envelope_len,
    const uint8_t *blob, size_t blob_len,
    const struct zcl_dev_coverage_binding *binding, uint32_t expected_rows,
    char *why, size_t why_len);

/* ── Query mode (the lifecycle query interface) ─────────────────────────
 * Reports coverage without admitting anything. Parses and verifies the
 * manifest's framing and signature, classifies every row against the
 * store, and summarizes. Structural problems refuse by name; a manifest
 * that parses but misses coverage, mismatches its binding, carries an
 * untrusted signature, or preserves a conflict is reported through the
 * struct — those are answers, not refusals. Unqualified rows (executed
 * groups with no reusable observation) are counted as their own state,
 * never as missing; an unqualified group whose CAS retains an eligible
 * FAIL is reported as a conflict. */
#define ZCL_DEV_COVERAGE_INSPECT_MAX_MISSING 8u
struct zcl_dev_coverage_inspect {
    uint32_t row_count;
    uint32_t covered;
    uint32_t unqualified;  /* executed rows with no reusable observation */
    uint32_t missing;      /* keyed rows with no eligible PASS coverage */
    uint32_t conflicts;    /* rows with an eligible PASS/FAIL contradiction */
    bool binding_mismatch;
    char signer_why[32];   /* empty when the signature verifies */
    uint64_t observed_total;    /* leaves in the store projection */
    uint64_t observed_eligible;
    uint64_t oldest_observed_unix; /* 0 when the store is empty */
    uint64_t newest_observed_unix;
    uint32_t missing_named; /* groups copied into missing_groups */
    char missing_groups[ZCL_DEV_COVERAGE_INSPECT_MAX_MISSING]
                       [ZCL_DEV_VERDICT_LEAF_GROUP_BYTES];
};
bool zcl_dev_coverage_inspect(const char *store_root,
    const uint8_t *envelope_wire, size_t envelope_len,
    const uint8_t *blob, size_t blob_len,
    const struct zcl_dev_coverage_binding *binding,
    struct zcl_dev_coverage_inspect *out, char *why, size_t why_len);

#endif
