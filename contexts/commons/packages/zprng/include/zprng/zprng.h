/* zprng — SplitMix64 seeding and xoshiro256** PRNG (C23).
 *
 * SplitMix64 expands a single 64-bit seed into a stream of well
 * distributed 64-bit words; xoshiro256** (Vigna & Blackman) is a
 * fast, all-nonzero-seed, 2^256-1-period generator with strong
 * statistical behavior.  Neither is cryptographically secure — use
 * zrand or an OS CSPRNG for secrets — but both are ideal for
 * simulations, fuzzing, games, and reproducible randomized tests.
 *
 * Self-contained; no dependencies beyond libc.
 *
 * Apache-2.0 licensed.
 */
#ifndef ZPRNG_H
#define ZPRNG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t state;
} zsplitmix64;

typedef struct {
    uint64_t s[4];
} zxoshiro256ss;

void zsplitmix64_init(zsplitmix64 *sm, uint64_t seed);
uint64_t zsplitmix64_next(zsplitmix64 *sm);

/* Seed via SplitMix64(seed).  Any 64-bit seed is valid, including 0. */
void zxoshiro256ss_init(zxoshiro256ss *rng, uint64_t seed);
uint64_t zxoshiro256ss_next(zxoshiro256ss *rng);

/* Uniform uint64 in [0, bound) with rejection sampling against the
 * multiplication-bias-free threshold (Lemire).  Returns 0 for
 * bound == 0. */
uint64_t zxoshiro256ss_below(zxoshiro256ss *rng, uint64_t bound);

/* Uniform double in [0, 1) with 53 bits of precision. */
double zxoshiro256ss_double(zxoshiro256ss *rng);

/* Fisher-Yates shuffle of n elemsize-byte items using rng. */
void zxoshiro256ss_shuffle(zxoshiro256ss *rng, void *base, size_t n,
                           size_t elemsize);

#ifdef __cplusplus
}
#endif

#endif /* ZPRNG_H */
