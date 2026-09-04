/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: name the RAM-backed scratch filesystem this machine offers, if it
 * offers one.
 *
 * Build and test work is dominated by fsync. On a tmpfs there is no disk
 * behind the page cache, so fsync costs nothing and the same work finishes in
 * a fraction of the wall time. Linux exposes one such filesystem by default at
 * /dev/shm. Nothing here decides what to put there; a caller asks whether a
 * RAM-backed root exists with room to spare, and falls back to its ordinary
 * location when the answer is no. */
#ifndef ZCL_PLATFORM_RAM_SCRATCH_H
#define ZCL_PLATFORM_RAM_SCRATCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Headroom a RAM-backed root must still have before anything is put on it.
 * Filling a tmpfs spends real memory, so the guard is deliberately large. */
#define PLATFORM_RAM_SCRATCH_MIN_FREE_BYTES (8ull * 1024ull * 1024ull * 1024ull)

/* Write this machine's RAM-backed scratch root into out_path and return true.
 * Returns false — leaving out_path an empty string — when the machine has no
 * such filesystem, when it is not a writable directory, or when it has less
 * than min_free_bytes available. Pass 0 for min_free_bytes to accept the
 * default guard.
 *
 * ZCL_RAM_SCRATCH_ROOT overrides the candidate path. It must be absolute:
 * anything else — the empty string included — refuses RAM backing outright
 * rather than quietly answering about the default path instead. It exists so a
 * test can pin the answer without depending on a particular machine. */
bool platform_ram_scratch_root(char *out_path, size_t out_cap,
                               uint64_t min_free_bytes);

#endif
