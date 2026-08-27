/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * disk_block_datadir_guard -- refuse a datadir that cannot be a path.
 *
 * A datadir that is non-NULL but is not a plausible path means the CALLER is
 * broken, not the disk: the only ways to produce one are a retained pointer
 * into a dead stack frame, a freed context, or a non-string pointer
 * reinterpreted as one. Such a value still formats fine into
 * "%s/blocks/blkNNNNN.dat", so without this guard the node reports it as an
 * ordinary missing file -- which two separate investigations then read as
 * index corruption.
 *
 * This is a secondary safety net. The cure is always to fix the lifetime at
 * the caller so the bytes outlive the read. */
#ifndef ZCL_STORAGE_DISK_BLOCK_DATADIR_GUARD_H
#define ZCL_STORAGE_DISK_BLOCK_DATADIR_GUARD_H

#include <stdbool.h>

/* True when `datadir` could be a path. Deliberately permissive about WHICH
 * path: a relative datadir ("." in simnet) and any printable absolute path
 * pass. It rejects only what cannot be one -- NULL, the empty string, a byte
 * outside printable ASCII, or no terminator inside a path-sized window. */
bool disk_block_datadir_is_plausible(const char *datadir);

/* Refuse an implausible datadir, naming what was handed over. Returns true to
 * proceed, false to refuse; on refusal it emits a throttled line carrying the
 * pointer and a hex preview of its bytes, so the next occurrence identifies
 * the broken caller instead of blaming the filesystem. */
bool disk_block_datadir_ok_or_refuse(const char *datadir, int file, unsigned pos);

#endif /* ZCL_STORAGE_DISK_BLOCK_DATADIR_GUARD_H */
