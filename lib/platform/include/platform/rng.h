/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Injectable RNG interface.
 *
 * Why:
 *   Determinism. Today, every part of the node that wants randomness
 *   reaches for `getrandom(2)` (or worse, `random()` / `time(NULL)`).
 *   That makes deterministic simulation impossible to seed — same simulation
 *   seed, different protocol-level outcomes, no way to bisect a failure.
 *
 *   This header offers a one-pointer abstraction: production resolves
 *   to a static vtable over the host CSPRNG -- `getrandom(2)` on Linux
 *   (with `/dev/urandom` as a fallback for ancient kernels),
 *   `arc4random_buf` on Darwin, `BCryptGenRandom` on Windows. Every
 *   arm fails closed; none of them has a weak fallback. Tests and the
 *   simulator can install an injected RNG with `rng_set_default(...)`.
 *   Same call sites, deterministic behavior under a seeded harness.
 *
 *   Crucially, the production path is unchanged — `rng_fill` still
 *   reads from the kernel CSPRNG. The abstraction has zero security
 *   cost; it only adds an indirect call.
 *
 * Thread safety:
 *   `rng_set_default` / `rng_reset_default` are atomic pointer swaps.
 *   The default vtable is reentrant — `getrandom(2)` is thread-safe.
 *   A test-injected RNG must be reentrant too if multiple threads use
 *   `rng_fill` concurrently.
 */

#ifndef ZCL_PLATFORM_RNG_H
#define ZCL_PLATFORM_RNG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rng_iface rng_iface_t;

struct rng_iface {
    /* Fill `len` bytes of `out` with random data.
     * Returns true on success, false on hard failure (entropy source
     * unavailable). Production code should treat failure as fatal —
     * a node that cannot produce random keys must not run. */
    bool (*fill)(void *self, uint8_t *out, size_t len);
    void *self;
};

/* Returns the process default vtable. Always non-NULL. */
const rng_iface_t *rng_default(void);

/* Convenience: fill out[0..len) using the default. */
bool rng_fill(uint8_t *out, size_t len);

/* Return a uniformly random uint64. Aborts via LOG_FAIL on
 * underlying entropy failure (this should never happen on a Linux
 * system with a functioning kernel CSPRNG). Use when the caller
 * cannot tolerate a NULL/error return — key generation, nonces,
 * etc. */
uint64_t rng_u64(void);

/* Uniform sample in [lo, hi). Uses rejection sampling so the result
 * is unbiased even when (hi - lo) is not a power of two. If lo >= hi
 * the call returns lo (degenerate range — caller bug). */
uint32_t rng_u32_range(uint32_t lo, uint32_t hi);

/* Swap the process-wide default. Intended for tests and the
 * deterministic simulator only — production code never calls this.
 *
 * `iface` must outlive every concurrent reader (typically static
 * storage). Passing NULL is rejected (no-op). */
void rng_set_default(const rng_iface_t *iface);

/* Restore the real-syscall default. Safe to call any number of times. */
void rng_reset_default(void);

/* Install-hook API for the seed tape / simulator.
 *
 * The install-hook is a thinner, faster path than `rng_set_default`:
 * it intercepts ONLY the `rng_u64` fast path (the simulator's hot
 * path). Default behavior is unchanged when no source is installed
 * (one atomic_load + predictable branch, <5 ns in production).
 *
 * Coexists with the existing `rng_iface_t` injection: if both are
 * installed, the install-hook wins for `rng_u64` calls and the
 * iface still wins for `rng_fill` / `rng_u32_range` calls. The seed
 * tape only installs the hook, never the iface.
 *
 * Thread safety: the source pointer is atomic. Install / clear from
 * any thread; concurrent readers see either the old or the new
 * source consistently. The source's `u64` callback must be
 * reentrant if multiple threads call `rng_u64` concurrently. */
struct platform_rng_source {
    uint64_t (*u64)(void *user);
    void *user;
};

/* Install a tape-driven (or otherwise injected) source for `rng_u64`.
 * The `src` pointer must outlive every concurrent reader (typically
 * static or owned by a `seed_tape_t`). NULL is rejected — use
 * `platform_rng_clear_source` instead. */
void platform_rng_set_source(struct platform_rng_source *src);

/* Restore the default (kernel CSPRNG via `getrandom`) path. */
void platform_rng_clear_source(void);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_PLATFORM_RNG_H */
