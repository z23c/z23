#include "zprng/zprng.h"

#include <string.h>

static uint64_t rotl64(uint64_t v, unsigned k)
{
    return v << k | v >> (64 - k);
}

void zsplitmix64_init(zsplitmix64 *sm, uint64_t seed)
{
    sm->state = seed;
}

uint64_t zsplitmix64_next(zsplitmix64 *sm)
{
    uint64_t z = (sm->state += UINT64_C(0x9e3779b97f4a7c15));

    z = (z ^ z >> 30) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ z >> 27) * UINT64_C(0x94d049bb133111eb);
    return z ^ z >> 31;
}

void zxoshiro256ss_init(zxoshiro256ss *rng, uint64_t seed)
{
    zsplitmix64 sm;

    zsplitmix64_init(&sm, seed);
    for (int i = 0; i < 4; i++)
        rng->s[i] = zsplitmix64_next(&sm);
}

uint64_t zxoshiro256ss_next(zxoshiro256ss *rng)
{
    uint64_t result = rotl64(rng->s[1] * 5, 7) * 9;
    uint64_t t = rng->s[1] << 17;

    rng->s[2] ^= rng->s[0];
    rng->s[3] ^= rng->s[1];
    rng->s[1] ^= rng->s[2];
    rng->s[0] ^= rng->s[3];
    rng->s[2] ^= t;
    rng->s[3] = rotl64(rng->s[3], 45);
    return result;
}

uint64_t zxoshiro256ss_below(zxoshiro256ss *rng, uint64_t bound)
{
    uint64_t threshold;

    if (!bound)
        return 0;
    /* Reject values below 2^64 mod bound so every output is equally
     * likely (Lemire's unbiased bounded method). */
    threshold = (uint64_t)(-bound) % bound;
    for (;;) {
        uint64_t x = zxoshiro256ss_next(rng);
        if (x >= threshold)
            return x % bound;
    }
}

double zxoshiro256ss_double(zxoshiro256ss *rng)
{
    return (double)(zxoshiro256ss_next(rng) >> 11) * 0x1.0p-53;
}

void zxoshiro256ss_shuffle(zxoshiro256ss *rng, void *base, size_t n,
                           size_t elemsize)
{
    uint8_t tmp[256];

    if (!base || n < 2 || !elemsize || elemsize > sizeof tmp)
        return;
    for (size_t i = n - 1; i > 0; i--) {
        uint8_t *a = (uint8_t *)base + i * elemsize;
        uint8_t *b = (uint8_t *)base +
                     (size_t)zxoshiro256ss_below(rng, (uint64_t)i + 1) *
                         elemsize;

        memcpy(tmp, a, elemsize);
        memcpy(a, b, elemsize);
        memcpy(b, tmp, elemsize);
    }
}
