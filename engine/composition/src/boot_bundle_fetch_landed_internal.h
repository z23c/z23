/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: internal contract for the warm-boot half of the bundle fetch
 * (engine/composition/src/boot_bundle_fetch_landed.c): the verified-stamp that
 * lets a restart skip re-hashing a bundle that already landed, and the reseed
 * (rom_seed registration) that runs on a tracked background thread so the
 * restart path does not wait for a second whole-file hash.
 */
#ifndef ZCL_BOOT_BUNDLE_FETCH_LANDED_INTERNAL_H
#define ZCL_BOOT_BUNDLE_FETCH_LANDED_INTERNAL_H

#include "net/rom_fetch.h"

#include <stdbool.h>
#include <sys/stat.h>

/* True iff <path>.verified holds a stamp whose size, mtime, inode and chunk
 * root all equal the file's current stat and `m`. A missing, malformed or
 * stale stamp is false: the caller then runs the full verify. */
bool bbf_landed_stamp_matches(const char *path, const struct stat *st,
                              const struct rom_fetch_manifest *m);

/* Record <path>.verified after a successful full verify. Best effort. */
void bbf_landed_stamp_write(const char *path, const struct stat *st,
                            const struct rom_fetch_manifest *m);

/* Register the landed bundle with rom_seed on the calling thread (the
 * download path; unchanged behaviour). rom_seed_register re-derives the whole
 * file digest and refuses a mismatch with `m->whole_sha3`, so a corrupt file
 * is never registered. */
void bbf_reseed_landed(const char *datadir, const struct rom_fetch_manifest *m);

/* Same registration on a tracked thread_registry worker (joined by the
 * shutdown thread_registry sweep). Falls back to the calling thread if the
 * thread cannot start. Returns immediately. */
void bbf_reseed_landed_async(const char *datadir,
                             const struct rom_fetch_manifest *m);

#endif /* ZCL_BOOT_BUNDLE_FETCH_LANDED_INTERNAL_H */
