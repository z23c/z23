/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * bundle_carry — move one bounded opaque file (a one-commit bundle, 1 B to 5 MiB)
 * between nodes as an ordinary unsigned content.v2 package, over the
 * unchanged 'zpkgswm' swarm. It adds NO wire message and NO store: the
 * package is exactly one file at VCS_BUNDLE_PATH ("bundle"), split into the
 * standard 1 MiB chunks (at most VCS_BUNDLE_MAX_CHUNKS of them), so it is
 * announced, wanted and transferred like any other package.
 *
 * This is deliberately NOT blob_store. vcs_blob_* stays capped at
 * VCS_BLOB_MAX_BYTES (8 KiB, one chunk, "never raise this"); the bundle
 * surface is a separate, separately-bounded shape with its own path so the
 * two can never be mistaken for each other.
 *
 * AUTHENTICATION SPLIT (as for blobs): the root proves BYTES ONLY — length
 * and the SHA3-256 of every chunk. It carries no signature and no author.
 * What a bundle MEANS is decided by the receiver, who recomputes a sha256
 * of the file and compares it with the one a signed board post named, and
 * who never executes the bytes here.
 *
 * Writes use the _no_evict store variants: an offer must never push another
 * complete package out of a quota'd store. */

#ifndef ZCL_VCS_BUNDLE_CARRY_H
#define ZCL_VCS_BUNDLE_CARRY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct vcs_package_manifest;
struct vcs_package_store;

/* The single canonical path inside every bundle package. Frozen: the
 * manifest root commits it. */
#define VCS_BUNDLE_PATH "bundle"

/* Hard ceiling on the carried file. Never raise this to admit a large
 * object: publish a real package instead. */
#define VCS_BUNDLE_MAX_BYTES (5u * 1024u * 1024u)

/* Chunk ceiling: 5 MiB is 5 chunks; 8 leaves headroom and is the shape
 * rule's own bound. */
#define VCS_BUNDLE_MAX_CHUNKS 8u

enum vcs_bundle_result {
    VCS_BUNDLE_OK = 0,
    VCS_BUNDLE_ERR_NULL,      /* null argument */
    VCS_BUNDLE_ERR_EMPTY,     /* zero-length file */
    VCS_BUNDLE_ERR_TOO_LARGE, /* len > VCS_BUNDLE_MAX_BYTES */
    VCS_BUNDLE_ERR_NO_STORE,  /* no package store (hosting disabled) */
    VCS_BUNDLE_ERR_MANIFEST,  /* manifest build/serialize/parse failure */
    VCS_BUNDLE_ERR_STORE,     /* store refused (quota, cap, I/O, ...) */
    VCS_BUNDLE_ERR_ABSENT,    /* root not tracked / chunk not present */
    VCS_BUNDLE_ERR_SHAPE,     /* tracked root is not a one-file bundle */
    VCS_BUNDLE_ERR_CORRUPT,   /* stored bytes do not match the root */
    VCS_BUNDLE_ERR_CAPACITY,  /* caller buffer smaller than the bundle */
};

const char *vcs_bundle_result_string(enum vcs_bundle_result r);

/* True when `m` is exactly the frozen bundle shape: one file at
 * VCS_BUNDLE_PATH, regular mode, 1..VCS_BUNDLE_MAX_BYTES bytes, at most
 * VCS_BUNDLE_MAX_CHUNKS chunks. Used by the public-shape classifier. */
bool vcs_bundle_manifest_is_bundle(const struct vcs_package_manifest *m);

/* Pure: the root of these bytes, no store touched. */
enum vcs_bundle_result vcs_bundle_root_of(const uint8_t *bytes, size_t len,
                                          uint8_t out_root[32]);

/* Admit the bundle (manifest + every chunk) into `store` without evicting
 * anything. Idempotent. */
enum vcs_bundle_result vcs_bundle_put_to_no_evict(
    struct vcs_package_store *store, const uint8_t *bytes, size_t len,
    uint8_t out_root[32]);

/* The committed length of a tracked bundle root (shape-checked, root
 * re-derived from the stored manifest), without reading any chunk. */
enum vcs_bundle_result vcs_bundle_size_of(struct vcs_package_store *store,
                                          const uint8_t root[32],
                                          size_t *out_len);

/* Read the bundle back, every chunk re-hashed against the manifest. Writes
 * at most out_cap bytes; the exact length lands in *out_len. */
enum vcs_bundle_result vcs_bundle_get_from(struct vcs_package_store *store,
                                           const uint8_t root[32],
                                           uint8_t *out, size_t out_cap,
                                           size_t *out_len);

#endif /* ZCL_VCS_BUNDLE_CARRY_H */
