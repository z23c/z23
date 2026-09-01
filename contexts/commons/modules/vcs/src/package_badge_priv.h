/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_badge_priv — the badge store's internal shape and filesystem
 * primitives, shared between package_badge.c (the codec, policy lens, and
 * the store's badge/plan load-and-register paths) and
 * package_badge_commit.c (the commit record — the issuance idempotence
 * authority). NOT a public header: nothing outside contexts/commons/modules/vcs/src/ includes
 * this, and the concrete struct vcs_badge_store shape stays invisible to
 * every caller of vcs/package_badge.h (which sees only the opaque forward
 * declaration there). */

#ifndef ZCL_VCS_PACKAGE_BADGE_PRIV_H
#define ZCL_VCS_PACKAGE_BADGE_PRIV_H

#include "vcs/package_badge.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* One verified badge plus its precomputed id (the store keeps these in
 * ascending id order). */
struct vcs_badge_loaded {
    struct vcs_badge badge;
    uint8_t id[32];
};

struct vcs_badge_store {
    char root[4400]; /* <datadir>/zcode/badges */
    struct vcs_badge_loaded *badges; /* ascending badge id */
    size_t badge_count;
    size_t badge_cap;
    uint8_t (*plans)[32]; /* persisted plan ids, ascending */
    size_t plan_count;
    size_t plan_cap;
    uint8_t (*commits)[32]; /* committed plan ids, ascending */
    size_t commit_count;
    size_t commit_cap;
    uint32_t corrupt;
    bool truncated;
};

/* ── filesystem + id-set primitives package_badge.c defines; the commit
 *    record (package_badge_commit.c) reuses them under the same
 *    durability discipline (temp + fsync + atomic rename, sorted id
 *    sets) rather than re-implementing it ──────────────────────────── */

bool badge_mkdir_p(const char *path);

/* Durable write: temp sibling + fsync + atomic rename. A crash leaves
 * either the old file or the new one, never a torn one. */
bool badge_atomic_write(const char *path, const uint8_t *data,
                        size_t data_len);

/* Read a whole bounded file. NULL when missing, empty, oversize, or
 * unreadable (missing is not an error: callers treat it as absent). */
uint8_t *badge_read_file(const char *path, size_t cap, size_t *out_len);

/* Insert into a sorted id set; returns the slot index or (size_t)-1 on
 * allocation failure. *inserted is set true when the id was new. */
size_t badge_id_set_insert(uint8_t (**ids)[32], size_t *count, size_t *cap,
                           const uint8_t id[32], bool *inserted);
bool badge_id_set_contains(const uint8_t (*ids)[32], size_t count,
                           const uint8_t id[32]);

#endif /* ZCL_VCS_PACKAGE_BADGE_PRIV_H */
