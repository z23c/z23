/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * blocks_mmap_reader: zero-copy reader for a Bitcoin Core / zclassicd
 * blocks/ directory. Maintains a small LRU of mmap()'d blk*.dat files
 * and returns pointers into them. Used by the fast-sync direct-import
 * path; avoids stdio overhead and per-block malloc.
 */

#ifndef ZCL_STORAGE_BLOCKS_MMAP_READER_H
#define ZCL_STORAGE_BLOCKS_MMAP_READER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct blocks_mmap;

/* Open a blocks/ directory (e.g. "~/.zclassic/blocks"). Returns true
 * on success and writes an opaque handle to *out. The directory's
 * blk*.dat files are not actually mapped yet — they are mmap()'d
 * lazily on first reference. */
bool bmr_open(const char *blocks_dir, struct blocks_mmap **out);

/* Look up the block whose payload begins at offset `nDataPos` inside
 * blk<nFile>.dat. Validates the 8-byte (magic, size) header at
 * (nDataPos - 8). On success returns a pointer to the payload start
 * and writes the payload length to *out_len. On failure returns NULL.
 *
 * The pointer is valid until the next call that evicts the same file
 * from the LRU (currently 8-deep). For sequential height-ordered
 * walks the same file is hit thousands of times in a row, so this
 * effectively never evicts in normal use. Callers that need the bytes
 * past the next call should memcpy. */
const uint8_t *bmr_get_payload(struct blocks_mmap *m,
                               int32_t nFile, uint32_t nDataPos,
                               size_t *out_len);

void bmr_close(struct blocks_mmap *m);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_STORAGE_BLOCKS_MMAP_READER_H */
