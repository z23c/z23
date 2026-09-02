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
 *   zcode package rollback     go back one step: re-activate the previous
 *                              generation. Both generations stay on disk,
 *                              and with no name given it picks the package
 *                              whose version changed most recently.
 *
 * THE VERSION A USER WAS RUNNING STAYS INTACT AND RE-SELECTABLE. Installing
 * a new version never destroys the old one — it appends a generation and
 * swaps a symlink, leaving the previous install tree untouched on disk. The
 * way back is one action, needs no identifier, lands on an exact 32-byte
 * root rather than "roughly the previous build", and depends on nothing the
 * new version could have broken: no network, no rebuild, and not one byte
 * read from the version being left. History is bounded by evicting the
 * oldest generations, never by refusing an append, so a long-lived install
 * cannot reach a state where going back is denied.
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
    /* True when the caller named no package and `name` was resolved to the
     * one whose active version changed most recently. */
    bool selected_by_default;
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

/* The PROGRAMS an installed package hands a person: every build-receipt
 * output whose install-relative path is under `bin/`. A package that ships
 * only a library has none, which is an ordinary empty answer, not a
 * failure. `install_dir` is the absolute directory the outputs live in, so
 * an operator-facing path is install_dir + "/" + output. */
#define PACKAGE_LIFECYCLE_MAX_PROGRAMS VCS_PACKAGE_BUILD_MAX_OUTPUTS
#define PACKAGE_LIFECYCLE_INSTALL_DIR_MAX 4399u

struct package_lifecycle_programs {
    char install_dir[PACKAGE_LIFECYCLE_INSTALL_DIR_MAX + 1u];
    size_t count;
    char output[PACKAGE_LIFECYCLE_MAX_PROGRAMS]
               [VCS_PACKAGE_BUILD_PATH_MAX + 1u];
};

/* Read-only projection of ONE installed root's receipt: the bin/ outputs it
 * committed, in the receipt's own canonical order. Nothing is built,
 * installed, activated or executed, and no package byte is loaded into this
 * process — the receipt is parsed, and its paths are reported. A root that
 * is not installed, or whose receipt does not parse, is a named failure. */
struct zcl_result package_lifecycle_installed_programs(
    const char *datadir, const uint8_t root[32],
    struct package_lifecycle_programs *out);

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

/* Re-activate the generation before the active one. `name` NULL or empty
 * means GO BACK ONE STEP: the package whose active version changed most
 * recently is resolved from the local generation logs and reported in
 * `out->name` with `selected_by_default` set.
 *
 * This path deliberately depends on NOTHING that the new version could have
 * broken. It reads the generation log and re-points a symlink; it does not
 * run, link, load, build, or even open the package that is being left, and
 * it never touches the network. So a version that crashes, corrupts its own
 * install tree, or was deleted outright is still one action away from being
 * undone. */
struct zcl_result package_lifecycle_rollback(
    const char *datadir, const char *name, int64_t now_unix,
    struct package_lifecycle_rollback_report *out);

/* Name the package whose active version changed most recently — what
 * `package_lifecycle_rollback` picks when given no name. *present is false
 * when nothing has ever been activated under this datadir. */
struct zcl_result package_lifecycle_last_activated(
    const char *datadir, char *name_out, size_t name_cap, bool *present_out);

/* Read-only: the root currently active for `name` (and how many generations
 * the log holds). *present is false when the name was never installed. */
struct zcl_result package_lifecycle_active(
    const char *datadir, const char *name, uint8_t out_root[32],
    size_t *generation_count_out, bool *present_out);

#endif /* ZCL_SERVICES_PACKAGE_LIFECYCLE_H */
