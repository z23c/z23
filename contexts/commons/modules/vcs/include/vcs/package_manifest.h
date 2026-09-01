/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_manifest — the offline content.v2 package tree contract. It maps
 * canonical package-relative paths to restricted regular-file modes, exact
 * sizes, and ordered SHA3-256 hashes of 1 MiB chunks. This layer parses,
 * serializes, commits, and verifies bytes only; it has no filesystem, network,
 * payment, install, build, execution, wallet, or node-state authority.
 *
 * Canonical wire encoding (all integers little-endian):
 *   [8 magic = "ZCLPKG\r\n"][2 version][4 chunk_bytes][4 file_count]
 *   repeated in strictly ascending path-byte order:
 *     [2 path_len][path bytes][4 mode][8 file_size][4 chunk_count]
 *     [32 * chunk_count ordered raw SHA3-256 chunk hashes]
 *
 * package_root is a domain-separated flat commitment over sorted per-file
 * hashes. The domains, version, fixed chunk size, modes, sizes, paths, and
 * ordered chunk lists are all committed. A package root proves byte identity
 * only; publisher trust, signatures, build receipts, sandbox approval, and
 * chain anchors are deliberately separate future facts.
 *
 * Hash-domain encoding is exact and frozen: each ASCII domain below is hashed
 * WITH its single trailing 0x00 byte (sizeof the string literal), before the
 * binary fields described by the implementation/KAT. */

#ifndef ZCL_VCS_PACKAGE_MANIFEST_H
#define ZCL_VCS_PACKAGE_MANIFEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_PACKAGE_MANIFEST_VERSION 1u
#define VCS_PACKAGE_FILE_HASH_DOMAIN "zcl.package_file.v1"
#define VCS_PACKAGE_ROOT_HASH_DOMAIN "zcl.package_manifest.v1"
#define VCS_PACKAGE_MANIFEST_WIRE_HEADER_BYTES 18u
#define VCS_PACKAGE_CHUNK_BYTES (1024u * 1024u)
#define VCS_PACKAGE_PATH_MAX 1024u
#define VCS_PACKAGE_PATH_SEGMENT_MAX 255u
#define VCS_PACKAGE_MAX_FILES 8192u
#define VCS_PACKAGE_MAX_CHUNKS_PER_FILE 4096u
#define VCS_PACKAGE_MAX_TOTAL_CHUNKS 16384u
#define VCS_PACKAGE_MAX_FILE_BYTES \
    (UINT64_C(1024) * 1024u * VCS_PACKAGE_MAX_CHUNKS_PER_FILE)
#define VCS_PACKAGE_MAX_TOTAL_BYTES (UINT64_C(16) * 1024u * 1024u * 1024u)
#define VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES (1024u * 1024u)

/* Portable canonical regular-file modes. Other permission bits and every
 * non-regular type (including symlinks) are rejected. */
#define VCS_PACKAGE_MODE_FILE 0100644u
#define VCS_PACKAGE_MODE_EXECUTABLE 0100755u

struct vcs_package_file {
    char *path;              /* heap, NUL-terminated, canonical relative path */
    uint32_t mode;           /* one of VCS_PACKAGE_MODE_* */
    uint64_t size;           /* exact reconstructed file size */
    uint32_t chunk_count;    /* exactly ceil(size / 1 MiB), or zero */
    uint8_t *chunk_hashes;   /* heap, chunk_count * 32 bytes, in file order */
};

struct vcs_package_manifest {
    /* Always stored in strictly ascending canonical path-byte order. This
     * makes network file_index coordinates independent of insertion order. */
    struct vcs_package_file *files;
    size_t count;
    size_t cap;
};

void vcs_package_manifest_init(struct vcs_package_manifest *manifest);
void vcs_package_manifest_free(struct vcs_package_manifest *manifest);

/* A canonical path is non-empty portable ASCII, package-relative, slash-
 * separated, and has no empty, dot, dot-dot, overlong, backslash, drive, or
 * host-reserved byte. The allowed non-separator bytes are
 * [A-Za-z0-9._+@-]. */
bool vcs_package_path_valid(const char *path);

/* Insert a file in canonical path order while copying path and chunk_hashes.
 * Insertion order is not significant. Duplicate paths, non-canonical
 * paths/modes, inconsistent size/chunk_count, and manifest limit overflow are
 * rejected. */
bool vcs_package_manifest_add(struct vcs_package_manifest *manifest,
                              const char *path, uint32_t mode, uint64_t size,
                              const uint8_t *chunk_hashes,
                              uint32_t chunk_count);

/* Canonically serialize a validated manifest. Allocates *out; caller frees.
 * On failure, *out is NULL and *out_len is zero. */
bool vcs_package_manifest_serialize(const struct vcs_package_manifest *manifest,
                                    uint8_t **out, size_t *out_len);

/* Parse only the exact canonical wire form. Initializes *out. Unsorted or
 * duplicate paths, traversal, invalid modes/counts/sizes, overflow,
 * truncation, and any trailing byte are rejected. */
bool vcs_package_manifest_parse(const uint8_t *wire, size_t wire_len,
                                struct vcs_package_manifest *out);

/* Per-file leaf and sorted manifest root for zcl.package_manifest.v1. */
bool vcs_package_file_hash(const struct vcs_package_file *file,
                           uint8_t out[32]);
bool vcs_package_manifest_root(const struct vcs_package_manifest *manifest,
                               uint8_t out[32]);

/* Raw SHA3-256 chunk identity and exact-position verification. A canonical
 * chunk is 1..1 MiB; only a file's final chunk may be shorter than 1 MiB.
 * verify_file is an in-memory convenience for fixtures/small artifacts. */
bool vcs_package_chunk_hash(const uint8_t *chunk, size_t chunk_len,
                            uint8_t out[32]);
bool vcs_package_verify_chunk(const struct vcs_package_file *file,
                              uint32_t chunk_index, const uint8_t *chunk,
                              size_t chunk_len);
bool vcs_package_verify_file(const struct vcs_package_file *file,
                             const uint8_t *bytes, size_t bytes_len);

#endif /* ZCL_VCS_PACKAGE_MANIFEST_H */
