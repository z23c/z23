/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the determinism receipt — a fixed-layout, versioned, byte-identical
 * record of one bound observation, plus the entry point that answers whether a
 * fresh run corroborates it.
 *
 * ── A RECEIPT IS EVIDENCE, NEVER PERMISSION ────────────────────────────────
 * This record states exactly one thing: at this commit, with this toolchain,
 * under this environment class, this group's verdict vector had this digest
 * and this classification. It confers NO standing, NO territory, NO authority
 * over any part of this codebase, and it is not an argument that any code is
 * correct, safe, or worth accepting. Nothing here may be read as a grant. A
 * later lane builds whatever acceptance model consumes these; this file
 * deliberately stops at the record and its verification, and must keep
 * stopping there.
 *
 * ── WHY A FIXED LAYOUT AND NOT A STRUCT DUMP ───────────────────────────────
 * The encode/decode path below writes and reads one field at a time through
 * lib/codec's cursors. It never memcpy()s `struct zcl_det_receipt` and never
 * hashes it. A previous lane in this tree found two -O2-only defects, one of
 * them struct padding leaking into a hash: the compiler is free to choose the
 * padding bytes between members, they are not required to be zero, and -O0 and
 * -O2 need not agree on them. Any encoding that touched the struct's storage
 * directly would produce different bytes at different optimisation levels on
 * the same machine, which is precisely the failure this whole module exists to
 * detect. Field-at-a-time little-endian is the only shape that cannot.
 *
 * Integer arithmetic only. No floating point appears in this record or on the
 * path that fills it — a duration in seconds would be both non-reproducible
 * and unrepresentable identically across platforms.
 *
 * ── WHAT IS DELIBERATELY ABSENT ────────────────────────────────────────────
 * No timestamp, no wall-clock duration, no hostname, no pid, no temp path. Any
 * of them would make two honest runs of the same thing produce different
 * receipts, so a receipt could never be re-derived — which would defeat the
 * only property that makes it worth writing down. The environment class digest
 * carries the parts of the environment the measurement is ALLOWED to depend
 * on, and nothing else. */
#ifndef ZCL_DETERMINISM_RECEIPT_H
#define ZCL_DETERMINISM_RECEIPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "determinism/classify.h"
#include "determinism/verdict.h"

#define ZCL_DET_RECEIPT_VERSION 1u
#define ZCL_DET_RECEIPT_COMMIT_LEN 32  /* sha1 or sha256 object id, left-aligned */
#define ZCL_DET_RECEIPT_SIZE 274u      /* pinned; the wire is the contract */

struct zcl_det_receipt {
    uint16_t version;
    uint8_t commit[ZCL_DET_RECEIPT_COMMIT_LEN];
    char group[ZCL_DET_GROUP_MAX];
    uint8_t toolchain[ZCL_DET_DIGEST_LEN];   /* digest of the toolchain identity */
    uint8_t env_class[ZCL_DET_DIGEST_LEN];   /* digest of the environment class */
    uint8_t verdict;                         /* enum zcl_det_class */
    uint8_t reason;                          /* enum zcl_det_unknown_reason */
    uint16_t perturbations;                  /* how many were applied */
    uint32_t split_mask;
    uint32_t check_count;
    uint8_t vector[ZCL_DET_DIGEST_LEN];      /* the verdict-vector digest */
    uint8_t producer[ZCL_DET_DIGEST_LEN];    /* producer identity root */
};

/* Exactly ZCL_DET_RECEIPT_SIZE bytes on success, and nothing written on
 * failure. `out_len` receives the byte count. */
bool zcl_det_receipt_encode(const struct zcl_det_receipt *r, uint8_t *out,
                            size_t out_cap, size_t *out_len);

/* Rejects a wrong magic, an unsupported version, a group field with
 * non-canonical NUL padding or an unprintable byte, an out-of-range verdict or
 * reason, a short buffer, and any trailing byte. Fail-closed at every step:
 * a record that does not decode is not a record. */
bool zcl_det_receipt_decode(const uint8_t *bytes, size_t len,
                            struct zcl_det_receipt *out);

/* SHA3-256 of a label, for the toolchain and environment-class fields. Keeps
 * the record fixed-width without inventing a second string encoding. */
void zcl_det_receipt_label_digest(const char *label,
                                  uint8_t out[ZCL_DET_DIGEST_LEN]);

/* Fill commit[] from a hex object id of 40 or 64 characters, left-aligned and
 * zero-padded. Any other length is refused rather than truncated. */
bool zcl_det_receipt_set_commit(struct zcl_det_receipt *r, const char *hex);

/* ── verification ──────────────────────────────────────────────────────────
 * The three answers are the whole point, and INDETERMINATE is a first-class
 * one: when the commit or the toolchain a receipt names is not what the fresh
 * run used, the honest answer is that this run says nothing about that claim.
 * It must never default to CORROBORATED (which would accept unverified
 * evidence) nor to REFUTED (which would condemn a claim nobody re-ran).
 *
 * INDETERMINATE also covers the case where the difference is EXPLAINED. If
 * either side's verdict is TIMING_SENSITIVE, the group is known to answer
 * differently when the machine's load differs — and load is a property of the
 * moment, not of the environment class, so it cannot be pinned by either side.
 * A differing vector is then precisely what an honest re-runner on a busier
 * box produces, and REFUTED would be a false accusation manufactured by
 * scheduling against a producer with no way to answer it. REFUTED is reserved
 * for a disagreement about something reproducible. */
enum zcl_det_corroboration {
    ZCL_DET_INDETERMINATE = 0,
    ZCL_DET_CORROBORATED = 1,
    ZCL_DET_REFUTED = 2,
};

const char *zcl_det_corroboration_name(enum zcl_det_corroboration c);

enum zcl_det_corroboration zcl_det_receipt_check(
    const struct zcl_det_receipt *claim, const struct zcl_det_receipt *fresh,
    char *why, size_t why_cap);

#endif /* ZCL_DETERMINISM_RECEIPT_H */
