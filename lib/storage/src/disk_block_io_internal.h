/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the disk_block_io private cross-TU contract — the one framing
 * helper that the read path in disk_block_io.c consumes and the framing +
 * repair layer in disk_block_io_repair.c defines.
 *
 * disk_block_io.c owns the write path, the FILE* handle caches, the deferred
 * fdatasync bookkeeping and the pread read paths.
 * disk_block_io_repair.c owns everything that must DECODE the on-disk
 * 8-byte magic+size frame header: the frame validity/lookup primitives and
 * the hash-targeted position rescan built on them. The split happened when
 * the combined file passed the 800-line shape ceiling. This single
 * declaration is all that crosses that seam, so it lives here and nowhere
 * else — nothing outside those two translation units may include this
 * header.
 */

#ifndef ZCL_STORAGE_DISK_BLOCK_IO_INTERNAL_H
#define ZCL_STORAGE_DISK_BLOCK_IO_INTERNAL_H

#include "storage/disk_block_io.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Resolve (payload offset, size), or REFUSE an unframed position — see the
 * FRAMED POSITIONS ONLY contract in storage/disk_block_io.h. Defined in
 * disk_block_io_repair.c. */
bool disk_block_locate_payload(int fd,
                               const struct disk_block_pos *pos,
                               uint32_t *out_payload_pos,
                               size_t *out_size);

#endif /* ZCL_STORAGE_DISK_BLOCK_IO_INTERNAL_H */
