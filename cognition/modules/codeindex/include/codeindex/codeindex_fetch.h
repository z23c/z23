/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 *
 * codeindex_fetch — adopt a PUBLISHED codeindex generation from another
 * checkout into this one, so a fresh worktree skips the cold index build.
 *
 * ── VERIFY, DON'T TRUST ──
 * The fetched bytes are inert until locally verified. The image's SEALED
 * source identity (source_root_sha3 over exact content + repo-relative paths,
 * and the location-independent source_merkle_root_sha3) must equal freshly
 * computed values for THIS checkout root before anything is installed, and the
 * image itself must pass the same owner-controlled inode checks a canonical
 * open applies. Format and schema tags must equal the running binary's
 * constants — a fetched generation is adopted only when this exact binary
 * could have produced it from this exact tree.
 *
 * The stat-bound depfile freshness keys (dep_root_sha3 / dep_stat_root_sha3)
 * are LOCAL observations, not source content: after content verification they
 * are re-stamped to this checkout's own depfile observation, so a fresh
 * worktree without build/ does not pay a full rebuild on the next open. The
 * sealed source roots and the cold-build self-receipt are carried verbatim.
 *
 * Install goes through the one publication ritual the rebuild path owns
 * (rebuild.lock, private 0600 staging inode, fsync, atomic renameat, fsync of
 * the directory). The source image is copied, never moved or modified. A
 * local store that is already fresh is never overwritten.
 */

#ifndef ZCL_CODEINDEX_FETCH_H
#define ZCL_CODEINDEX_FETCH_H

#include <stdbool.h>
#include <stdint.h>

/* Outcome of one fetch attempt. `code` is "" iff the generation was
 * installed; otherwise it is a stable machine-readable refusal code and
 * message/evidence explain it (evidence names digests and paths). The digest
 * and receipt fields are filled only on success. */
struct codeindex_fetch_report {
    char code[48];
    char message[192];
    char evidence[256];
    uint8_t source_root_sha3[32];
    uint8_t source_merkle_root_sha3[32];
    bool receipt_present;
    long long build_cold_ms;
    long long build_cold_files;
    /* The installed store's depfile freshness keys were re-stamped to THIS
     * checkout's observation. */
    bool dep_restamped;
    /* A post-install open observes the store as fresh (no rebuild pending). */
    bool adopted;
};

/* Verify and install the generation found at `from`, which may name a
 * checkout root (its .codeindex/index.kv), a .codeindex directory, or an
 * index.kv file directly. `root` is the checkout receiving the store.
 * Returns true iff the verified generation was installed; on false the
 * report's code/message/evidence carry the refusal. Fails closed: any
 * mismatch, ambiguity, or I/O fault is a refusal, never a partial install. */
bool codeindex_fetch_install(const char *root, const char *from,
                             struct codeindex_fetch_report *report);

#endif /* ZCL_CODEINDEX_FETCH_H */
