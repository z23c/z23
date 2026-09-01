/* zrand — xoshiro256** pseudo-random generator (C23).
 *
 * Deterministic PRNG with splitmix64 seeding, Lemire unbiased bounded
 * draws, uniform doubles, Fisher–Yates shuffle, and the standard
 * jump/long-jump functions for stream splitting.
 *
 * This is a fast, well-distributed general-purpose generator. It is
 * NOT cryptographically secure — never use it for keys or tokens.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZRAND_H
#define ZRAND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t s[4];
} zrand;

/* Seed deterministically (splitmix64 expansion). Any seed is valid,
 * including 0. */
void zrand_seed(zrand *r, uint64_t seed);

/* Raw 64-bit draw. */
uint64_t zrand_u64(zrand *r);

/* Uniform in [0, bound); 0 when bound <= 1. Lemire multiply-shift with
 * rejection, unbiased. */
uint64_t zrand_bounded(zrand *r, uint64_t bound);

/* Uniform in [lo, hi); 0 when hi <= lo. */
uint64_t zrand_range(zrand *r, uint64_t lo, uint64_t hi);

/* Uniform double in [0, 1). */
double zrand_double(zrand *r);

/* Coin flip. */
bool zrand_bool(zrand *r);

/* Fill buf with n bytes. */
void zrand_bytes(zrand *r, void *buf, size_t n);

/* Fisher–Yates shuffle of n elements of size elem_size. */
void zrand_shuffle(zrand *r, void *base, size_t n, size_t elem_size);

/* Advance 2^128 steps (jump) or 2^192 steps (long_jump): split the
 * stream for independent workers. */
void zrand_jump(zrand *r);
void zrand_long_jump(zrand *r);

#ifdef __cplusplus
}
#endif

#endif /* ZRAND_H */
