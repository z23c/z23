/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_reproduce — the ZCODE bit-identical REPRODUCTION verdict: the
 * headline acceptance signal for a published package. A release is
 * REPRODUCED when an independent rebuild of the same package root, recipe
 * root, and dependency lock emits byte-for-byte the same artifacts the
 * reference build committed (vcs/package_build.h receipts carry the
 * SHA3-256 and byte count of every emitted output). The signer quorum
 * (contexts/commons/modules/vcs/package_verify_policy.*) is the LATENCY OPTIMIZATION over this:
 * it lets an operator trust a verdict before a local reproduction exists —
 * it never outranks one.
 *
 * The comparator is PURE evaluation over two parsed receipts: it never
 * reads a file, compiles, or executes anything, and it deliberately does
 * NOT compare compiler id/version/flags, isolation, or test bookkeeping —
 * two parties may reach identical bytes through different toolchains, and
 * byte-identity under the same package/recipe/lock commitments is the
 * claim being tested. The verdict names the FIRST divergence rule and
 * carries a printable detail (the diverging path, plus truncated
 * expected/actual hashes on a content mismatch), so a mismatch is always
 * reported loudly, never as a bare false.
 *
 * The scan helper is the one I/O exception (the package_index /
 * package_verify_policy load() precedent): it walks a receipts directory
 * of persisted build receipts (<datadir>/zcode/receipts/, filed by
 * receipt id), keeps the installable receipts naming the exact
 * (package_root, recipe_root) pair, sorts them by receipt id, and
 * compares every one against the lowest-id reference. reproduced=true
 * requires >= 2 DISTINCT receipt ids whose output sets are byte-identical
 * — one receipt is one build; two different builds agreeing on every
 * output byte is the reproduction fact. Receipts carry no signer
 * identity, so "independent" here means distinct build events, recorded
 * honestly; who produced a receipt is a transport concern, not this
 * layer's. */

#ifndef ZCL_VCS_PACKAGE_REPRODUCE_H
#define ZCL_VCS_PACKAGE_REPRODUCE_H

#include "vcs/package_build.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_REPRODUCE_DETAIL_MAX 160u
/* Rows the report carries; receipts beyond the row cap still count toward
 * `matching` (they cannot silently inflate `reproduced`: a truncated scan
 * never reports reproduced=true). */
#define VCS_REPRODUCE_MAX_ROWS 64u
/* Bound on one receipt wire the scan will read. */
#define VCS_REPRODUCE_MAX_WIRE_BYTES VCS_PACKAGE_BUILD_MAX_WIRE_BYTES

/* The named verdict rule. MATCH is the only pass; every other value names
 * exactly why the rebuild is NOT byte-identical to the reference. The
 * enum order is frozen: it appears in typed JSON. */
enum vcs_reproduce_rule {
    VCS_REPRODUCE_MATCH = 0,
    VCS_REPRODUCE_REFERENCE_INVALID,  /* reference receipt fails validate() */
    VCS_REPRODUCE_REBUILD_INVALID,    /* rebuild receipt fails validate() */
    VCS_REPRODUCE_REFERENCE_NOT_INSTALLABLE, /* reference build did not pass */
    VCS_REPRODUCE_REBUILD_NOT_INSTALLABLE,   /* rebuild did not pass */
    VCS_REPRODUCE_PACKAGE_ROOT_MISMATCH,
    VCS_REPRODUCE_RECIPE_ROOT_MISMATCH,
    VCS_REPRODUCE_LOCK_ROOT_MISMATCH,
    VCS_REPRODUCE_DEP_SET_MISMATCH,
    VCS_REPRODUCE_OUTPUT_MISSING,    /* a reference output was not emitted */
    VCS_REPRODUCE_OUTPUT_UNEXPECTED, /* rebuild emitted an uncommitted output */
    VCS_REPRODUCE_OUTPUT_HASH_MISMATCH,
    VCS_REPRODUCE_OUTPUT_SIZE_MISMATCH,
};

const char *vcs_reproduce_rule_string(enum vcs_reproduce_rule rule);

struct vcs_reproduce_verdict {
    bool reproduced; /* true exactly when rule == VCS_REPRODUCE_MATCH */
    uint8_t rule;    /* enum vcs_reproduce_rule */
    char detail[VCS_REPRODUCE_DETAIL_MAX]; /* NUL-terminated; "" on MATCH */
};

/* Compare a rebuild receipt against the reference receipt. Both are
 * validated first; an installable reference and rebuild are then compared
 * on the identity commitments (package root, recipe root, lock root,
 * dependency set) and the output set (path, SHA3-256, byte count). out is
 * fully written on every call; NULL arguments yield a non-reproduced
 * verdict with rule REFERENCE_INVALID/REBUILD_INVALID. */
void vcs_package_reproduce_compare(
    const struct vcs_package_build_receipt *reference,
    const struct vcs_package_build_receipt *rebuild,
    struct vcs_reproduce_verdict *out);

/* ── the receipts-directory scan (the one I/O helper) ───────────────── */

struct vcs_reproduce_row {
    uint8_t receipt_id[32];
    bool reference;  /* the lowest-id receipt the other rows compare to */
    uint8_t rule;    /* enum vcs_reproduce_rule vs the reference */
    char detail[VCS_REPRODUCE_DETAIL_MAX];
    /* The row receipt's pinned toolchain capsule (receipt schema v2). A
     * v1 receipt has neither field set and proves nothing about toolchain
     * identity. */
    bool has_toolchain_capsule;
    uint8_t toolchain_capsule_root[32];
};

struct vcs_reproduce_report {
    uint32_t scanned;   /* receipt files examined */
    uint32_t matching;  /* installable receipts naming the exact root pair */
    bool reproduced;    /* >= 2 distinct receipt ids, every row MATCH */
    /* Toolchain diversity among the MATCHING rows (including rows beyond
     * the display cap): distinct_toolchains counts the distinct nonzero
     * pinned capsule roots; cross_toolchain is true exactly when at least
     * two DIFFERENT capsules produced the identical bytes — the strong
     * toolchain-independence claim. Capsule-less v1 receipts add nothing
     * to either: same-capsule reproduction is honest evidence of process
     * determinism, not of toolchain independence. */
    uint32_t distinct_toolchains;
    bool cross_toolchain;
    struct vcs_reproduce_row rows[VCS_REPRODUCE_MAX_ROWS];
    size_t row_count;
    bool rows_truncated;
};

/* Scan receipts_dir for build receipts naming (package_root, recipe_root)
 * and evaluate byte-identical reproduction among them (see the file
 * header). A missing/unreadable directory is NOT an error: it yields an
 * empty report (no reproduction recorded). Returns false only when the
 * directory exists but cannot be read. out is zeroed on entry. */
bool vcs_package_reproduce_scan(const char *receipts_dir,
                                const uint8_t package_root[32],
                                const uint8_t recipe_root[32],
                                struct vcs_reproduce_report *out);

#endif /* ZCL_VCS_PACKAGE_REPRODUCE_H */
