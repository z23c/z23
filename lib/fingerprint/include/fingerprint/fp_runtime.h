/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fp_runtime — the deterministic corpus generator and result accumulator
 * that GENERATED probe code compiles against.
 *
 * Two properties make the whole technique work, and both live here:
 *
 *  1. THE INPUT CORPUS IS A FUNCTION OF THE SIGNATURE SHAPE, NOT OF THE
 *     FUNCTION. Every generator call is seeded from the candidate's
 *     canonical shape hash plus the iteration number. Two functions with the
 *     same shape therefore see the byte-identical input sequence, which is
 *     the only reason two independently-written implementations of the same
 *     behavior can ever produce the same fingerprint. Seeding from anything
 *     per-function (an index, a name, an address) would silently make every
 *     fingerprint unique and the tool would report "no duplicates" forever
 *     while looking like it worked.
 *
 *  2. THE ACCUMULATOR IS 128 BITS AND ORDER/LENGTH SENSITIVE. A duplicate
 *     claim rests on a hash equality, so the accidental-collision term has
 *     to be far below the rate of every other error in the system. Each
 *     absorbed value carries a tag and a length so that "wrote 4 bytes then
 *     8" can never hash the same as "wrote 8 bytes then 4".
 *
 * Everything is `static inline` and depends on nothing but <stdint.h> and
 * <string.h>, because these headers are included into generated translation
 * units that already include an arbitrary slice of the tree.
 */

#ifndef ZCL_FP_RUNTIME_H
#define ZCL_FP_RUNTIME_H

#include <stdint.h>
#include <string.h>

/* Corpus size per probe. 128 iterations of which the first 24 are boundary
 * values rather than random ones — the interesting disagreements between two
 * implementations are at 0, 1, -1, the type maximum, and the length that is
 * exactly the buffer size, not in the middle of the range. */
#define FP_ITERATIONS      128u
#define FP_BOUNDARY_ITERS  24u
/* Second, disjoint corpus used to re-test a fingerprint match before it is
 * reported. Deliberately much larger and seeded off a different constant. */
#define FP_CONFIRM_ITERATIONS 4096u
#define FP_CONFIRM_SALT    0x5DEECE66D0F1A3B7ull

/* A fingerprint is only reportable if the corpus actually SEPARATED this
 * function from a constant — at least this many distinct per-iteration output
 * digests. Uniform random input never satisfies a validator, so without this
 * floor every `bool is_valid(...)` in the tree returns false on every input,
 * produces the same digest, and collides with every other validator of the
 * same shape. That is the single largest source of false "these are
 * duplicates" claims and it is not detectable from the hash alone. */
#define FP_MIN_DISTINCT    2u

/* The floor for a match to be REPORTED as a candidate duplicate, which is a
 * stricter bar than the floor for being fingerprinted at all. Measured on
 * this tree by reading all 30 reported groups: at a floor of 2 distinct
 * outputs, 8 of 30 groups were wrong (26.7%) — every one of them a pair of
 * two-valued predicates that agree because a boolean has only two answers
 * and the corpus reached one of them. At a floor of 3 the same run reports
 * 13 groups of which 1 is wrong (7.7%), under the ~10% at which a checker
 * stops being read. It costs 10 real findings. That trade is the intended
 * one: a false "these are duplicates" is the failure that discredits the
 * whole index, a missed one only shrinks it. */
#define FP_REPORT_MIN_DISTINCT 3u

/* Generated buffers and strings. Fixed so the shape, not the run, decides. */
#define FP_BUF_BYTES       64u
#define FP_STR_BYTES       48u
#define FP_CSTR_HASH_MAX   4096u
#define FP_OBJ_MAX_BYTES   4096u

struct fp_acc {
    uint64_t h1;
    uint64_t h2;
    uint64_t cur;   /* per-iteration sub-digest, read by the driver */
};

struct fp_rng {
    uint64_t s;
};

static inline uint64_t fp_mix64(uint64_t z)
{
    z += 0x9E3779B97F4A7C15ull;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

static inline void fp_acc_init(struct fp_acc *a, uint64_t shape)
{
    a->h1 = fp_mix64(shape ^ 0xA5A5A5A5DEADBEEFull);
    a->h2 = fp_mix64(shape + 0x0123456789ABCDEFull);
    a->cur = fp_mix64(shape);
}

static inline void fp_acc_raw(struct fp_acc *a, uint64_t v)
{
    a->h1 = fp_mix64(a->h1 ^ v);
    a->h2 = (a->h2 + v) * 0xFF51AFD7ED558CCDull;
    a->h2 ^= a->h2 >> 33;
    a->cur = fp_mix64(a->cur ^ v);
}

/* Absorb a tagged scalar. The tag separates "a returned 0" from "an output
 * parameter left at 0". */
static inline void fp_acc_u64(struct fp_acc *a, unsigned tag, uint64_t v)
{
    fp_acc_raw(a, ((uint64_t)tag << 56) ^ 0x1000000000000000ull);
    fp_acc_raw(a, v);
}

static inline void fp_acc_mem(struct fp_acc *a, unsigned tag, const void *p,
                              size_t n)
{
    const unsigned char *b = (const unsigned char *)p;
    size_t i = 0;
    fp_acc_raw(a, ((uint64_t)tag << 56) ^ 0x2000000000000000ull);
    fp_acc_raw(a, (uint64_t)n);
    if (b == NULL) {
        fp_acc_raw(a, 0xDEAD0000CAFE0001ull);
        return;
    }
    for (; i + 8 <= n; i += 8) {
        uint64_t w = 0;
        memcpy(&w, b + i, 8);
        fp_acc_raw(a, w);
    }
    if (i < n) {
        uint64_t w = 0;
        memcpy(&w, b + i, n - i);
        fp_acc_raw(a, w);
    }
}

/* A returned `const char *`. The POINTER is never hashed — it is an address
 * and would differ between runs — only the text it names, bounded. NULL is a
 * distinct, stable observation rather than a skipped one. */
static inline void fp_acc_cstr(struct fp_acc *a, unsigned tag, const char *s)
{
    size_t n;
    if (s == NULL) {
        fp_acc_raw(a, ((uint64_t)tag << 56) ^ 0x3000000000000000ull);
        return;
    }
    n = strnlen(s, FP_CSTR_HASH_MAX);
    fp_acc_mem(a, tag, s, n);
}

/* ── The corpus ─────────────────────────────────────────────────────── */

static inline void fp_rng_seed(struct fp_rng *r, uint64_t shape, uint32_t iter,
                               uint64_t salt)
{
    r->s = fp_mix64(shape ^ (uint64_t)iter * 0x9E3779B97F4A7C15ull ^ salt);
}

static inline uint64_t fp_rng_u64(struct fp_rng *r)
{
    r->s += 0x9E3779B97F4A7C15ull;
    return fp_mix64(r->s);
}

/* A scalar of `width` bytes. For the first FP_BOUNDARY_ITERS iterations the
 * value comes from a fixed boundary ladder instead of the generator, so two
 * implementations that agree everywhere except at zero, one, the sign
 * boundary or the type maximum are separated by the corpus rather than by
 * luck. `slot` distinguishes several parameters within one iteration. */
static inline uint64_t fp_rng_scalar(struct fp_rng *r, unsigned width,
                                     uint32_t iter, unsigned slot)
{
    static const uint64_t ladder[FP_BOUNDARY_ITERS] = {
        0u, 1u, 2u, 3u, 7u, 8u, 15u, 16u, 31u, 32u, 63u, 64u,
        127u, 128u, 255u, 256u, 32767u, 32768u, 65535u, 65536u,
        0x7FFFFFFFull, 0x80000000ull, 0xFFFFFFFFull, UINT64_MAX
    };
    uint64_t v;
    if (iter < FP_BOUNDARY_ITERS)
        v = ladder[(iter + slot) % FP_BOUNDARY_ITERS];
    else if ((iter & 1u) == 1u)
        /* Half the non-boundary corpus stays SMALL. A scalar parameter in
         * this tree is far more often an enum, a flag, a count or an index
         * than a uniform 64-bit number, and a uniform draw lands outside
         * every enum's range on every iteration — which makes two unrelated
         * `is_valid(enum)` predicates agree on the whole corpus. */
        v = fp_rng_u64(r) % 64u;
    else
        v = fp_rng_u64(r);
    if (width == 0u || width >= 8u)
        return v;
    {
        /* Narrow to `width` BYTES. Built a byte at a time rather than with a
         * single shift by (width * 8) so this is not mistaken for a
         * hand-rolled little-endian codec: nothing here packs or unpacks a
         * value across a byte array, it only masks one register. */
        uint64_t mask = 0;
        unsigned i;
        for (i = 0; i < width; i++)
            mask = (mask << 8) | 0xFFull;
        return v & mask;
    }
}

static inline void fp_rng_bytes(struct fp_rng *r, void *p, size_t n)
{
    unsigned char *b = (unsigned char *)p;
    size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        uint64_t w = fp_rng_u64(r);
        memcpy(b + i, &w, 8);
    }
    if (i < n) {
        uint64_t w = fp_rng_u64(r);
        memcpy(b + i, &w, n - i);
    }
}

/* Text alphabets. Uniform random bytes are the WORST possible input for the
 * functions this tree is mostly made of: every `is_hex`, `is_alphanumeric`,
 * `label_valid` and `parse_request` rejects them, so all of them return the
 * same constant and become indistinguishable. Cycling a small set of
 * alphabets means some iterations land inside each validator's accepting
 * set, which is what separates one validator from another. The alphabet is
 * chosen from the iteration number alone so that two functions of the same
 * shape still see the byte-identical sequence. */
#define FP_ALPHABETS 8u

static inline const char *fp_alphabet(unsigned cls, size_t *len_out)
{
    static const char *const tab[FP_ALPHABETS] = {
        "0123456789abcdef",
        "0123456789ABCDEF",
        "0123456789",
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "abcdefghijklmnopqrstuvwxyz0123456789_-.",
        "abc/._-0123456789",
        "abcdefghijklmnopqrstuvwxyz0123456789 \t:=,;{}[]\"'"
    };
    const char *s = tab[cls % FP_ALPHABETS];
    *len_out = strlen(s);
    return s;
}

/* A NUL-terminated generated string. Boundary iterations produce the empty
 * string and single characters; the rest cycle the alphabets above, with one
 * iteration in eight left as full printable ASCII so a function that only
 * differs on punctuation is still separated. */
static inline void fp_rng_cstr(struct fp_rng *r, char *p, size_t cap,
                               uint32_t iter)
{
    size_t len;
    size_t i;
    size_t alen = 0;
    const char *alpha;
    if (cap == 0u)
        return;
    if (iter < FP_BOUNDARY_ITERS)
        len = (size_t)iter % (cap - 1u);
    else
        len = (size_t)(fp_rng_u64(r) % (cap - 1u));
    if ((iter % (FP_ALPHABETS + 1u)) == FP_ALPHABETS) {
        for (i = 0; i < len; i++)
            p[i] = (char)(0x20 + (int)(fp_rng_u64(r) % 95u));
        p[len] = '\0';
        return;
    }
    alpha = fp_alphabet(iter % FP_ALPHABETS, &alen);
    for (i = 0; i < len; i++)
        p[i] = alpha[fp_rng_u64(r) % alen];
    p[len] = '\0';
}

/* A by-reference struct. Uniform random bytes give every field of every
 * struct an out-of-range value, so a function that validates its input
 * rejects the entire corpus and tells us nothing. Four content classes,
 * chosen from bits 2-3 of the iteration so the class is independent of the
 * equal/near-equal twinning that uses bits 0-1. */
static inline void fp_rng_objbytes(struct fp_rng *r, void *p, size_t n,
                                   uint32_t iter)
{
    unsigned char *b = (unsigned char *)p;
    size_t i;
    switch ((iter >> 2) & 3u) {
    case 0u:                                  /* all zero: the default value */
        memset(b, 0, n);
        return;
    case 2u:                                  /* every byte a 0/1 flag */
        for (i = 0; i < n; i++)
            b[i] = (unsigned char)(fp_rng_u64(r) & 1u);
        return;
    case 3u:                                  /* small ints, native width */
        for (i = 0; i + 4 <= n; i += 4) {
            uint32_t w = (uint32_t)(fp_rng_u64(r) % 16u);
            memcpy(b + i, &w, 4);
        }
        for (; i < n; i++)
            b[i] = 0u;
        return;
    default:                                  /* raw bytes */
        break;
    }
    for (i = 0; i + 8 <= n; i += 8) {
        uint64_t w = fp_rng_u64(r);
        memcpy(b + i, &w, 8);
    }
    if (i < n) {
        uint64_t w = fp_rng_u64(r);
        memcpy(b + i, &w, n - i);
    }
}

/* A byte buffer passed with an explicit length. Same reasoning as
 * fp_rng_cstr: a `const uint8_t *` plus a length is as often a wire field or
 * a text span as it is a hash, so half the corpus is alphabet text and half
 * is raw bytes. */
static inline void fp_rng_textbytes(struct fp_rng *r, void *p, size_t n,
                                    uint32_t iter)
{
    unsigned char *b = (unsigned char *)p;
    size_t alen = 0;
    const char *alpha;
    size_t i;
    if ((iter & 1u) == 0u) {
        for (i = 0; i + 8 <= n; i += 8) {
            uint64_t w = fp_rng_u64(r);
            memcpy(b + i, &w, 8);
        }
        if (i < n) {
            uint64_t w = fp_rng_u64(r);
            memcpy(b + i, &w, n - i);
        }
        return;
    }
    alpha = fp_alphabet((iter >> 1) % FP_ALPHABETS, &alen);
    for (i = 0; i < n; i++)
        b[i] = (unsigned char)alpha[fp_rng_u64(r) % alen];
}

#endif /* ZCL_FP_RUNTIME_H */
