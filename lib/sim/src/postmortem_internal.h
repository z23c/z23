/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the postmortem-capsule private cross-TU contract — the tar/gzip
 * container primitives that postmortem_archive.c defines, the two filesystem
 * primitives postmortem.c defines, and the tar block size all sides pad to.
 *
 * postmortem.c owns the capsule itself: the crash hook, the
 * async-signal-safe capture, the manifest, and load/validate/compress.
 * postmortem_inventory.c owns the capsule DIRECTORY: list, summarise and
 * retention-prune what is already on disk.
 * postmortem_archive.c owns the `.cap.gz` CONTAINER: ustar header encoding,
 * the gzip read/write helpers and the single-member extractor. The split
 * happened when the combined file passed the 800-line shape ceiling. These
 * declarations are all that crosses those seams, so they live here and
 * nowhere else — nothing outside those three translation units may include
 * this header.
 */

#ifndef ZCL_SIM_POSTMORTEM_INTERNAL_H
#define ZCL_SIM_POSTMORTEM_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <zlib.h>

#define TAR_BLOCK_SIZE 512u

/* True when `s` ends in `suffix` — how both sides tell a packed `.cap.gz`
 * from an unpacked `.cap`. Prefixed rather than named `has_suffix` because
 * this is external linkage in a single-binary build and three other
 * translation units already carry a file-static helper of that name.
 * Defined in postmortem.c. */
bool postmortem_has_suffix(const char *s, const char *suffix);

/* Recursively unlink `path`, whether it is a file or a directory tree.
 * Returns 0 or the FIRST negative errno seen, having still attempted the
 * rest. Defined in postmortem.c. */
int postmortem_remove_tree(const char *path);

/* Write `len` bytes into the gzip stream, looping over short writes.
 * Returns 0 or a negative errno. Defined in postmortem_archive.c. */
int gz_write_all(gzFile gz, const void *buf, size_t len);

/* Append `path` to the tar stream under `archive_name` (ustar header, file
 * body, NUL padding to TAR_BLOCK_SIZE). Returns 0 or a negative errno.
 * Defined in postmortem_archive.c. */
int tar_write_file(gzFile gz, const char *archive_name, const char *path);

/* Extract one member of a gzipped tar into a freshly allocated buffer,
 * refusing anything larger than `max_len`. Returns 0 or a negative errno;
 * on success the caller owns *out. Defined in postmortem_archive.c. */
int gz_read_tar_member(const char *archive_path, const char *member,
                       uint8_t **out, size_t *len_out, size_t max_len);

#endif /* ZCL_SIM_POSTMORTEM_INTERNAL_H */
