#include "zrand/zrand.h"

#include <string.h>

static uint64_t rotl64(uint64_t x, int k)
{
    return (x << k) | (x >> (64 - k));
}

static uint64_t splitmix64(uint64_t *state)
{
    uint64_t z = (*state += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

void zrand_seed(zrand *r, uint64_t seed)
{
    if (!r) return;
    uint64_t sm = seed;
    for (int i = 0; i < 4; i++)
        r->s[i] = splitmix64(&sm);
}

uint64_t zrand_u64(zrand *r)
{
    if (!r) return 0;
    uint64_t *s = r->s;
    uint64_t result = rotl64(s[1] * 5, 7) * 9;
    uint64_t t = s[1] << 17;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = rotl64(s[3], 45);
    return result;
}

uint64_t zrand_bounded(zrand *r, uint64_t bound)
{
    if (!r || bound <= 1) return 0;
    /* Lemire multiply-shift with rejection. */
    for (;;) {
        uint64_t x = zrand_u64(r);
        __uint128_t m = (__uint128_t)x * bound;
        uint64_t l = (uint64_t)m;
        if (l >= bound) return (uint64_t)(m >> 64);
        uint64_t t = (uint64_t)(-bound) % bound;
        if (l >= t) return (uint64_t)(m >> 64);
    }
}

uint64_t zrand_range(zrand *r, uint64_t lo, uint64_t hi)
{
    if (!r || hi <= lo) return 0;
    return lo + zrand_bounded(r, hi - lo);
}

double zrand_double(zrand *r)
{
    if (!r) return 0.0;
    /* 53-bit mantissa from the top bits. */
    return (double)(zrand_u64(r) >> 11) * (1.0 / 9007199254740992.0);
}

bool zrand_bool(zrand *r)
{
    return (zrand_u64(r) & 1) != 0;
}

void zrand_bytes(zrand *r, void *buf, size_t n)
{
    if (!r || !buf) return;
    uint8_t *p = buf;
    while (n >= 8) {
        uint64_t v = zrand_u64(r);
        memcpy(p, &v, 8);
        p += 8;
        n -= 8;
    }
    if (n > 0) {
        uint64_t v = zrand_u64(r);
        memcpy(p, &v, n);
    }
}

void zrand_shuffle(zrand *r, void *base, size_t n, size_t elem_size)
{
    if (!r || !base || elem_size == 0 || n < 2) return;
    uint8_t *b = base;
    uint8_t tmp[256];
    uint8_t *scratch = tmp;
    if (elem_size > sizeof tmp) return; /* oversized elements unsupported */
    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)zrand_bounded(r, (uint64_t)i + 1);
        if (j == i) continue;
        memcpy(scratch, b + i * elem_size, elem_size);
        memmove(b + i * elem_size, b + j * elem_size, elem_size);
        memcpy(b + j * elem_size, scratch, elem_size);
    }
}

static void jump_with(zrand *r, const uint64_t jump[4])
{
    uint64_t s0 = 0, s1 = 0, s2 = 0, s3 = 0;
    for (int i = 0; i < 4; i++) {
        for (int b = 0; b < 64; b++) {
            if (jump[i] & (1ull << b)) {
                s0 ^= r->s[0];
                s1 ^= r->s[1];
                s2 ^= r->s[2];
                s3 ^= r->s[3];
            }
            zrand_u64(r);
        }
    }
    r->s[0] = s0;
    r->s[1] = s1;
    r->s[2] = s2;
    r->s[3] = s3;
}

void zrand_jump(zrand *r)
{
    if (!r) return;
    static const uint64_t JUMP[4] = {
        0x180ec6d33cfd0aba, 0xd5a61266f0c9392c,
        0xa9582618e03fc9aa, 0x39abdc4529b1661c
    };
    jump_with(r, JUMP);
}

void zrand_long_jump(zrand *r)
{
    if (!r) return;
    static const uint64_t LONG_JUMP[4] = {
        0x76e15d3efefdcbbf, 0xc5004e441c522fb3,
        0x77710069854ee241, 0x39109bb02acbe635
    };
    jump_with(r, LONG_JUMP);
}
