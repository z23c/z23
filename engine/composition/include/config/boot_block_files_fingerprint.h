/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fingerprint of the block files under <datadir>/blocks, recorded in the
 * clean-shutdown marker so a verified fast restart can tell that no block
 * file changed while the node was down. */

#ifndef ZCL_CONFIG_BOOT_BLOCK_FILES_FINGERPRINT_H
#define ZCL_CONFIG_BOOT_BLOCK_FILES_FINGERPRINT_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct shutdown_clean_binding;

struct boot_block_files_fingerprint {
    uint32_t count;      /* regular files among blk00000..blk00255.dat and
                          * blk_sync.dat                                  */
    uint8_t  sha3[32];   /* SHA3-256 over (slot, size, mtime sec, mtime ns)
                          * of each of those files, in slot order         */
};

/* Fingerprint the block files of `datadir`. False when none exists, when a
 * file cannot be inspected, or when an entry is not a plain regular file;
 * the caller then has no fingerprint and must scan. */
bool boot_block_files_fingerprint_read(
    const char *datadir, struct boot_block_files_fingerprint *out);

/* Pure decision: may the boot-time block-file scan be skipped? True only
 * when the fast restart was taken, the marker recorded a fingerprint, and
 * `now` equals it in count and digest. Every other case returns false. */
bool boot_block_files_scan_may_skip(
    bool fast_restart_taken, const struct shutdown_clean_binding *recorded,
    const struct boot_block_files_fingerprint *now);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONFIG_BOOT_BLOCK_FILES_FINGERPRINT_H */
