/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_install — the pure wire rules of the ZCODE install lifecycle: the
 * ADD PLAN (what `zcode package add plan` computed and `... add commit`
 * re-checks) and the per-package GENERATION LOG (what rollback walks). This
 * layer parses, serializes, validates, and hashes bytes; it never touches
 * the filesystem, spawns nothing, and installs nothing. The lifecycle
 * service (engine/services/src/package_lifecycle*.c) owns all I/O.
 *
 * THE PLAN IS A PROPOSAL, NEVER AN AUTHORIZATION. `commit` re-derives the
 * dependency lock from the store and requires the lock root to still match
 * the plan's, and it refuses a plan past `expires_unix`. So a plan cannot
 * authorize installing something the store no longer holds, and a plan left
 * lying around cannot be replayed later against a changed store.
 *
 * The plan id is SHA3-256 over the frozen domain (hashed WITH its trailing
 * 0x00 byte, the package_manifest convention) followed by the canonical plan
 * wire, so a plan id is a commitment to every field below — including the
 * expiry. Editing a persisted plan changes its id and the edited file is
 * simply not found.
 *
 * Canonical plan wire (little-endian):
 *   [8  magic = "ZCLAPL\r\n"]
 *   [2  schema_version = 1]
 *   [32 target_root][32 lock_root]
 *   [8  created_unix][8 expires_unix]
 *   [2  step_count]  count x ([32 root][2 nl][name][2 sl][semver]
 *                             [2 ll][license][2 depth][1 state][1 flags]
 *                             [8 total_bytes][4 total_chunks])
 * Steps are in LOCK BUILD ORDER (dependencies first, target last) — the same
 * order the lock wire fixes, re-checked on parse.
 *
 * Canonical generation-log wire (little-endian):
 *   [8  magic = "ZCLGEN\r\n"]
 *   [2  schema_version = 1]
 *   [2  count]  count x ([32 root][8 activated_unix])
 * Append-only history of which root was made active, oldest first; the LAST
 * entry is the currently intended active root. A rollback appends a new
 * entry naming the older root — history is never rewritten, and the older
 * install stays on disk until explicitly pruned.
 *
 * RETENTION IS BOUNDED BY EVICTION, NEVER BY REFUSAL. The log keeps the
 * newest VCS_PACKAGE_GENERATION_KEEP entries; appending to a full log drops
 * the OLDEST entries first (FIFO) and always succeeds. That policy is the
 * whole point: a log that refuses its own append once full would brick the
 * package — no further install AND no further rollback — which is the exact
 * moment a user most needs to go back. Eviction only ever discards DISTANT
 * history, so the rollback target (the newest distinct root older than the
 * active one) is retained for any KEEP >= 2.
 *
 * VCS_PACKAGE_GENERATION_MAX stays the WIRE bound, above KEEP, so a log
 * written before this policy still parses. */

#ifndef ZCL_VCS_PACKAGE_INSTALL_H
#define ZCL_VCS_PACKAGE_INSTALL_H

#include "vcs/package_deps.h"
#include "vcs/package_release.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_PACKAGE_PLAN_VERSION 1u
#define VCS_PACKAGE_PLAN_ID_DOMAIN "zcl.zcode_add_plan.v1"
#define VCS_PACKAGE_PLAN_WIRE_MAGIC_BYTES 8u
#define VCS_PACKAGE_PLAN_MAX_WIRE_BYTES (256u * 1024u)
/* A plan is a short-lived proposal: 15 minutes. Long enough for an operator
 * to read the plan and decide, short enough that a forgotten plan_id is not
 * a standing authorization. */
#define VCS_PACKAGE_PLAN_TTL_SECONDS 900

#define VCS_PACKAGE_GENERATION_VERSION 1u
#define VCS_PACKAGE_GENERATION_WIRE_MAGIC_BYTES 8u
/* Wire bound: the most entries a log on disk may carry. */
#define VCS_PACKAGE_GENERATION_MAX 256u
/* Retention depth: how many generations an append keeps. Strictly below the
 * wire bound, so a pre-policy log parses and is trimmed by its next append.
 * Must be >= 2 for a rollback target to survive eviction. */
#define VCS_PACKAGE_GENERATION_KEEP 64u
#define VCS_PACKAGE_GENERATION_MAX_WIRE_BYTES \
    (VCS_PACKAGE_GENERATION_WIRE_MAGIC_BYTES + 4u + \
     VCS_PACKAGE_GENERATION_MAX * 40u)

/* The one lifecycle state machine's states. Exactly one owner (the
 * lifecycle service) advances a package through them; nothing skips. */
enum vcs_package_lifecycle_state {
    VCS_PACKAGE_LIFECYCLE_DISCOVERED = 0, /* a release names this root */
    VCS_PACKAGE_LIFECYCLE_FETCHING = 1,   /* bytes still missing from the CAS */
    VCS_PACKAGE_LIFECYCLE_VERIFIED = 2,   /* every chunk re-hashed, envelope ok */
    VCS_PACKAGE_LIFECYCLE_BUILT = 3,      /* the worker produced artifacts */
    VCS_PACKAGE_LIFECYCLE_TESTED = 4,     /* the recipe's tests passed */
    VCS_PACKAGE_LIFECYCLE_INSTALLED = 5,  /* staged + atomically activated */
    VCS_PACKAGE_LIFECYCLE_PINNED = 6,     /* retained in the store, seedable */
};

const char *vcs_package_lifecycle_state_string(
    enum vcs_package_lifecycle_state state);

enum vcs_package_install_error {
    VCS_PACKAGE_INSTALL_OK = 0,
    VCS_PACKAGE_INSTALL_ERR_NULL,
    VCS_PACKAGE_INSTALL_ERR_ALLOC,
    VCS_PACKAGE_INSTALL_ERR_WIRE_MAGIC,
    VCS_PACKAGE_INSTALL_ERR_WIRE_VERSION,
    VCS_PACKAGE_INSTALL_ERR_WIRE_TRUNCATED,
    VCS_PACKAGE_INSTALL_ERR_WIRE_TRAILING,
    VCS_PACKAGE_INSTALL_ERR_WIRE_OVERSIZE,
    VCS_PACKAGE_INSTALL_ERR_ROOT,       /* an all-zero root */
    VCS_PACKAGE_INSTALL_ERR_STEP_COUNT,
    VCS_PACKAGE_INSTALL_ERR_STEP_ORDER, /* not lock build order / duplicated */
    VCS_PACKAGE_INSTALL_ERR_FIELD,      /* a field grammar or bound */
    VCS_PACKAGE_INSTALL_ERR_STATE,      /* state not on the wire list */
    VCS_PACKAGE_INSTALL_ERR_EXPIRY,     /* expiry not after creation */
    VCS_PACKAGE_INSTALL_ERR_GEN_COUNT,
};

const char *vcs_package_install_error_string(
    enum vcs_package_install_error error);

struct vcs_package_plan_step {
    uint8_t root[32];
    char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    char semver[VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u];
    char license[VCS_PACKAGE_RELEASE_LICENSE_MAX + 1u];
    uint16_t depth;
    uint8_t state;      /* enum vcs_package_lifecycle_state at plan time */
    bool complete;      /* every manifest chunk is present in the CAS */
    bool installed;     /* this exact root is already installed */
    uint64_t total_bytes;
    uint32_t total_chunks;
};

struct vcs_package_plan {
    uint8_t target_root[32];
    uint8_t lock_root[32];
    int64_t created_unix;
    int64_t expires_unix;
    struct vcs_package_plan_step steps[VCS_PACKAGE_LOCK_MAX_NODES];
    size_t step_count;
};

void vcs_package_plan_init(struct vcs_package_plan *plan);

enum vcs_package_install_error vcs_package_plan_validate(
    const struct vcs_package_plan *plan);
enum vcs_package_install_error vcs_package_plan_serialize(
    const struct vcs_package_plan *plan, uint8_t **out, size_t *out_len);
enum vcs_package_install_error vcs_package_plan_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_package_plan *out);
enum vcs_package_install_error vcs_package_plan_id(
    const struct vcs_package_plan *plan, uint8_t out[32]);

/* True when `now_unix` is at or past the plan's expiry. A caller that skips
 * this check has turned a proposal into a standing authorization. */
bool vcs_package_plan_expired(const struct vcs_package_plan *plan,
                              int64_t now_unix);

/* ── generation log ─────────────────────────────────────────────────── */

struct vcs_package_generation {
    uint8_t root[32];
    int64_t activated_unix;
};

struct vcs_package_generations {
    struct vcs_package_generation items[VCS_PACKAGE_GENERATION_MAX];
    size_t count; /* oldest first; items[count - 1] is the intended active */
};

void vcs_package_generations_init(struct vcs_package_generations *g);

/* Drop the oldest entries until at most `keep` remain, and return how many
 * were dropped. `keep` is clamped to at least 1 so a trim never empties a
 * non-empty log. This is the ONE eviction policy — FIFO, oldest first —
 * and it is exported so it can be asserted directly. */
size_t vcs_package_generations_trim(struct vcs_package_generations *g,
                                    size_t keep);

/* Append one activation. Rejects an all-zero root; the same root activated
 * twice in a row is rejected (nothing changed). A FULL log is NOT an error:
 * the append first evicts oldest-first down to
 * VCS_PACKAGE_GENERATION_KEEP - 1 entries, so it always has room and can
 * never brick the package. */
enum vcs_package_install_error vcs_package_generations_append(
    struct vcs_package_generations *g, const uint8_t root[32],
    int64_t activated_unix);

enum vcs_package_install_error vcs_package_generations_serialize(
    const struct vcs_package_generations *g, uint8_t **out, size_t *out_len);
enum vcs_package_install_error vcs_package_generations_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_package_generations *out);

/* The root of the newest DISTINCT generation older than the active one —
 * the rollback target. False when there is nothing to roll back to. */
bool vcs_package_generations_previous(const struct vcs_package_generations *g,
                                      uint8_t out_root[32]);

/* Split "publisher/package" into its two halves. False (and both outputs
 * empty) when the name does not carry exactly one '/' with non-empty halves
 * — the install tree keys on these, so a malformed name never becomes a
 * path. */
bool vcs_package_name_split(const char *name,
                            char publisher_out[VCS_PACKAGE_RELEASE_NAME_MAX + 1u],
                            char package_out[VCS_PACKAGE_RELEASE_NAME_MAX + 1u]);

#endif /* ZCL_VCS_PACKAGE_INSTALL_H */
