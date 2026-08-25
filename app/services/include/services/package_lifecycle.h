/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_lifecycle — THE ONE ZCODE install lifecycle state machine. Exactly
 * one owner advances a package through
 *
 *   DISCOVERED -> FETCHING -> VERIFIED -> BUILT -> TESTED -> INSTALLED
 *               -> PINNED
 *
 * and nothing skips a state. Two operator surfaces drive it:
 *
 *   zcode package add plan     resolve a name-or-root, walk the declared
 *                              dependency DAG into a root-pinned lock, and
 *                              report each step's current state WITHOUT
 *                              installing anything. Persists only a plan.
 *   zcode package add commit   re-derive the lock, refuse a stale or expired
 *                              plan, then for every locked step in build
 *                              order: verify (re-hash every chunk from the
 *                              CAS), build+test in the isolated worker,
 *                              re-hash every emitted artifact, install
 *                              atomically, and pin so the package can seed.
 *   zcode package rollback     re-activate the previous generation of one
 *                              package name. Both generations stay on disk.
 *
 * BOUNDARIES THIS LAYER NEVER CROSSES:
 *  - A downloaded or built library is NEVER loaded into this process. It is
 *    a static archive on disk that the confined worker links against; there
 *    is no dlopen, no dlsym, and no link edge from the node to it.
 *  - Compilation and test execution happen ONLY in
 *    build/bin/zclassic23-package-verify --emit (seccomp + rlimits +
 *    Landlock where available). This layer spawns that program and re-checks
 *    its output; it never compiles anything itself.
 *  - Identity is the 32-byte package root. A name or a version only ever
 *    SELECTS a root; the lock, the receipt, the install directory, and the
 *    generation log all key on roots.
 *  - Nothing from a package's own bytes is executed: no Make, CMake, shell,
 *    configure, Python, or install hook. The declarative recipe is the only
 *    build input.
 *
 * Every rejection names the exact failed rule in `rule` and explains it in
 * `detail`; a rejection also returns a non-ok struct zcl_result so a caller
 * that ignores the report still cannot mistake it for success.
 *
 * PHASE BOUNDARY (honest, and reported as such): a step whose bytes are not
 * already complete in the local CAS reports FETCHING with the rule
 * `package-incomplete`. Multi-peer network fetch is a later phase; this
 * layer never pretends to have fetched. */

#ifndef ZCL_SERVICES_PACKAGE_LIFECYCLE_H
#define ZCL_SERVICES_PACKAGE_LIFECYCLE_H

#include "base/result.h"
#include "vcs/package_build.h"
#include "vcs/package_install.h"
#include "vcs/package_reproduce.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PACKAGE_LIFECYCLE_RULE_MAX 63u
#define PACKAGE_LIFECYCLE_DETAIL_MAX 191u

struct package_lifecycle_step {
    uint8_t root[32];
    char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    char semver[VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u];
    uint16_t depth;
    uint8_t state; /* enum vcs_package_lifecycle_state actually REACHED */
    bool already_installed;
    bool has_receipt;
    bool receipt_reused; /* every bound input matches this exact plan */
    uint8_t receipt_id[32];
    char rule[PACKAGE_LIFECYCLE_RULE_MAX + 1u];       /* "" on success */
    char detail[PACKAGE_LIFECYCLE_DETAIL_MAX + 1u];
};

struct package_lifecycle_plan_report {
    uint8_t plan_id[32];
    struct vcs_package_plan plan;
    bool ready; /* every step can proceed to install on commit */
    char rule[PACKAGE_LIFECYCLE_RULE_MAX + 1u];
    char detail[PACKAGE_LIFECYCLE_DETAIL_MAX + 1u];
};

struct package_lifecycle_commit_report {
    uint8_t plan_id[32];
    size_t step_count;
    struct package_lifecycle_step steps[VCS_PACKAGE_LOCK_MAX_NODES];
    bool installed;             /* the TARGET is installed and active */
    uint8_t active_root[32];
    bool had_previous;          /* a different root was active before */
    uint8_t previous_root[32];
    char rule[PACKAGE_LIFECYCLE_RULE_MAX + 1u];
    char detail[PACKAGE_LIFECYCLE_DETAIL_MAX + 1u];
};

struct package_lifecycle_rollback_report {
    char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    uint8_t from_root[32];
    uint8_t to_root[32];
    size_t generation_count;
    char rule[PACKAGE_LIFECYCLE_RULE_MAX + 1u];
    char detail[PACKAGE_LIFECYCLE_DETAIL_MAX + 1u];
};

struct package_lifecycle_reproduce_report {
    char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    char semver[VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u];
    uint8_t root[32];
    uint8_t reference_receipt_id[32]; /* the install build's receipt */
    uint8_t receipt_id[32];           /* the second, distinct receipt */
    bool matched;                     /* every committed output byte-equal */
    uint8_t compare_rule;             /* enum vcs_reproduce_rule */
    char compare_detail[VCS_REPRODUCE_DETAIL_MAX];
    bool filed; /* the second receipt is filed under receipts/<id-hex> */
    /* Outcome of the fastobj compile cache the rebuild was offered, parsed
     * from the worker's zbuild-package-fast-cache=v1 stats line. Zero
     * counters with an empty admission mean no line was reported (a cold
     * run never sets one). */
    bool fast_cache_used;
    uint64_t fast_cache_hits;
    uint64_t fast_cache_misses;
    uint64_t fast_cache_reused_bytes;
    char fast_cache_admission[32];
    char rule[PACKAGE_LIFECYCLE_RULE_MAX + 1u];       /* "" on success */
    char detail[PACKAGE_LIFECYCLE_DETAIL_MAX + 1u];
};

/* `name_or_root` is either a 64-hex package root (identity) or a
 * "publisher/package" name, which SELECTS the highest-semver release under
 * that name. `now_unix` stamps the plan and its expiry (the caller passes
 * the clock so tests are deterministic). */
struct zcl_result package_lifecycle_plan(
    const char *datadir, const char *name_or_root, int64_t now_unix,
    struct package_lifecycle_plan_report *out);

struct zcl_result package_lifecycle_commit(
    const char *datadir, const uint8_t plan_id[32], int64_t now_unix,
    struct package_lifecycle_commit_report *out);

/* Read one filed canonical build receipt by its exact id. This is an inert
 * projection: it parses the bounded receipt wire and re-derives its id, but
 * performs no build, install, activation, pin or publication. The lifecycle
 * remains the sole owner of the on-disk receipt layout. */
struct zcl_result package_lifecycle_receipt_read(
    const char *datadir, const uint8_t receipt_id[32],
    struct vcs_package_build_receipt *out);

/* Read-only exact-root inspection for reuse planners. A directory named for
 * the root is not evidence: when present, its filed receipt, package-scoped
 * dependency lock, and every declared output are revalidated through the
 * same lifecycle owner used by commit. Missing is an ordinary successful
 * query with *installed_out false; tampered evidence is a named failure. */
struct zcl_result package_lifecycle_installed_inspect(
    const char *datadir, const uint8_t root[32],
    struct package_lifecycle_step *out, bool *installed_out);

/* Reproduce the install build of one ALREADY-INSTALLED package: re-verify
 * every committed input against the CAS, re-materialize the source tree,
 * re-run the fixed verifier worker under the standard build profile against
 * the install receipt's own lock root and committed dependency set, and —
 * only when the rebuild receipt is byte-identical on every committed output
 * (vcs_package_reproduce_compare == MATCH) and hashes to a DISTINCT receipt
 * id — file it under <datadir>/zcode/receipts/<receipt-id-hex>. Two distinct
 * receipt ids with byte-identical output sets is the reproduction fact that
 * lets the receipts scan report reproduced=true. Every refusal is named in
 * rule/detail and files nothing.
 *
 * `fast_cache` (optional) is a LOCAL fastobj compile-cache directory handed
 * to the confined candidate worker as --fast-cache=<dir>, so a node that
 * already holds the objects can rebuild with zero compiler spawns. NULL or
 * a string that is empty after trimming means the ordinary cold rebuild —
 * the flag is not passed. The worker quarantines and re-verifies every
 * cache entry itself; the path travels through unchanged, and its outcome
 * lands in the report's fast_cache_* fields. */
struct zcl_result package_lifecycle_reproduce(
    const char *datadir, const char *name_or_root, const char *fast_cache,
    struct package_lifecycle_reproduce_report *out);

struct zcl_result package_lifecycle_rollback(
    const char *datadir, const char *name, int64_t now_unix,
    struct package_lifecycle_rollback_report *out);

/* Read-only: the root currently active for `name` (and how many generations
 * the log holds). *present is false when the name was never installed. */
struct zcl_result package_lifecycle_active(
    const char *datadir, const char *name, uint8_t out_root[32],
    size_t *generation_count_out, bool *present_out);

#endif /* ZCL_SERVICES_PACKAGE_LIFECYCLE_H */
