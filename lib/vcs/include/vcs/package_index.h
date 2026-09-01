/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_index — the local ZCODE package search index (slice 3). This is
 * a REBUILDABLE PROJECTION over the persisted store bytes under
 * <datadir>/zcode/{releases,manifests}: the CAS manifest/release wires stay
 * authoritative and this index holds no truth of its own — like
 * op_return_index, it is rebuilt from the canonical bytes on every build
 * and may be discarded at any time. No second package database is created.
 *
 * An entry projects one persisted (parseable) release envelope plus the
 * summary of its manifest when manifests/<package-root-hex> is present and
 * parses. Entries are sorted by (name, release id) for deterministic
 * search/show output. Bounds: at most VCS_PACKAGE_PUBLISH_MAX_RELEASES
 * releases are loaded; manifest wires are grammar-bounded (1 MiB).
 *
 * Read-only: the index never writes to the store, never verifies
 * signatures (publication did), and never executes published content. */

#ifndef ZCL_VCS_PACKAGE_INDEX_H
#define ZCL_VCS_PACKAGE_INDEX_H

#include "vcs/package_publish.h"
#include "vcs/package_release.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct vcs_package_index_entry {
    char release_id_hex[65];
    char package_root_hex[65];
    char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];   /* publisher/package */
    char semver[VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u];
    char license[VCS_PACKAGE_RELEASE_LICENSE_MAX + 1u];
    char publisher_hex[2u * VCS_PACKAGE_RELEASE_PUBKEY_BYTES + 1u];
    char chain_id[VCS_PACKAGE_RELEASE_CHAIN_ID_MAX + 1u];
    char reward_address[VCS_PACKAGE_RELEASE_REWARD_MAX + 1u];
    uint64_t publisher_sequence;
    bool has_parent;
    char parent_root_hex[65]; /* meaningful when has_parent */
    bool has_znam;
    char znam[VCS_PACKAGE_RELEASE_ZNAM_MAX + 1u];
    /* Manifest summary (zero/absent when manifest_present is false): */
    bool manifest_present;
    uint32_t file_count;
    uint64_t total_bytes;
    uint32_t chunk_total;
    bool license_present;
    uint32_t executable_count;
};

struct vcs_package_index; /* opaque */

/* Build the projection from <zcode_dir> (the store root, e.g.
 * <datadir>/zcode). A missing/empty store yields an empty index. NULL on
 * hard I/O or allocation failure (logged). */
struct vcs_package_index *vcs_package_index_build(const char *zcode_dir);
void vcs_package_index_free(struct vcs_package_index *index);

size_t vcs_package_index_count(const struct vcs_package_index *index);
/* Releases skipped while building the projection because the bounded loader
 * was full or a stored envelope could not be parsed/read. A nonzero value
 * means callers cannot claim a complete filtered view. */
size_t vcs_package_index_skipped_count(const struct vcs_package_index *index);
const struct vcs_package_index_entry *vcs_package_index_at(
    const struct vcs_package_index *index, size_t i);

/* Look up one entry by package root (32 bytes). NULL when absent. */
const struct vcs_package_index_entry *vcs_package_index_find_root(
    const struct vcs_package_index *index, const uint8_t package_root[32]);

struct vcs_package_search {
    const char *publisher;   /* hex prefix of the publisher pubkey, or NULL */
    const char *name_prefix; /* prefix of "publisher/package", or NULL */
    const char *license;     /* exact SPDX id, or NULL */
    const char *keyword;     /* substring of the package name, or NULL */
};

/* Bounded search: fills out[] (entry pointers, sorted order) with up to
 * out_cap matches of ALL given filters; returns the TOTAL number of
 * matches (>= the count written), so callers can flag truncation. */
size_t vcs_package_index_search(const struct vcs_package_index *index,
                                const struct vcs_package_search *search,
                                const struct vcs_package_index_entry **out,
                                size_t out_cap);

#endif /* ZCL_VCS_PACKAGE_INDEX_H */
