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

/* Longest lease-file path platform_ram_scratch_reserve() will hand back. */
#define PLATFORM_RAM_SCRATCH_LEASE_PATH_MAX 4096u

/* A held reservation on a RAM-backed scratch root. Zeroed means nothing is
 * held, and release accepts that state as a no-op. Treat it as an opaque
 * token: hand it back whole, never read or write its fields. */
struct platform_ram_scratch_lease {
    char path[PLATFORM_RAM_SCRATCH_LEASE_PATH_MAX];
    bool held;
};

/* Reserve `bytes` on the RAM-backed scratch root named by `root` and return
 * true with the lease in *out. Free space seen is not free space kept: N
 * proofs asking at once each observe the same headroom, so a reservation is
 * what makes one caller's yes true for that caller alone. A lease is one
 * small file under <root>/.z23-leases/ named "<pid>-<counter>" holding the
 * reserved byte count as decimal text; the sum-and-create step runs under one
 * flock on <root>/.z23-leases/lock, and the reservation succeeds only when
 *
 *     free_bytes - sum(bytes in live lease files) - bytes
 *         >= PLATFORM_RAM_SCRATCH_MIN_FREE_BYTES.
 *
 * A lease file whose pid no longer exists (kill(pid, 0) fails with ESRCH) is
 * stale: it is neither counted nor kept. `root` must be the absolute path
 * platform_ram_scratch_root() answered. On refusal, or on Windows where no
 * RAM-backed root exists to reserve, *out is zeroed and false is returned. */
bool platform_ram_scratch_reserve(const char *root, uint64_t bytes,
                                  struct platform_ram_scratch_lease *out);

/* Give a held reservation back by unlinking its lease file. Safe on a zeroed
 * or already-released lease, where it does nothing. */
void platform_ram_scratch_release(struct platform_ram_scratch_lease *lease);

#endif
