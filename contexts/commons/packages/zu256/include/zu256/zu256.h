/* zu256 — fixed-size 256-bit unsigned integer arithmetic (C23).
 *
 * A zu256256 is four little-endian u64 limbs: value =
 * l[0] + l[1]*2^64 + l[2]*2^128 + l[3]*2^192. Fixed size means no
 * allocation, no aliasing surprises, and predictable cost — the
 * shape used by hashes, IDs, checksums, and crypto-adjacent code
 * (this is NOT constant-time; do not use for secrets).
 *
 * All arithmetic is modular (wraps mod 2^256); *_overflow variants
 * report whether the true mathematical result exceeded the modulus.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZU256_H
#define ZU256_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t l[4]; /* little-endian limbs */
} zu256256;

extern const zu256256 ZU256256_ZERO;
extern const zu256256 ZU256256_ONE;
extern const zu256256 ZU256256_MAX; /* 2^256 - 1 */

zu256256 zu256_from_u64(uint64_t v);
bool       zu256_is_zero(zu256256 a);
int        zu256_cmp(zu256256 a, zu256256 b); /* -1/0/1 */
unsigned   zu256_bitlen(zu256256 a);            /* 0 for zero */

zu256256 zu256_add(zu256256 a, zu256256 b, bool *overflow);
zu256256 zu256_sub(zu256256 a, zu256256 b, bool *underflow);
zu256256 zu256_mul(zu256256 a, zu256256 b, bool *overflow);
/* Division: q = a/b, r = a%b. Division by zero returns false and
 * leaves outputs untouched. */
bool zu256_divmod(zu256256 a, zu256256 b,
                    zu256256 *q, zu256256 *r);

zu256256 zu256_shl(zu256256 a, unsigned n); /* bits shifted out are lost */
zu256256 zu256_shr(zu256256 a, unsigned n);
bool       zu256_bit(zu256256 a, unsigned n); /* n >= 256 -> false */

/* Byte order: big-endian 32-byte arrays, hash/ID style. */
void       zu256_to_be32(zu256256 a, uint8_t out[32]);
zu256256 zu256_from_be32(const uint8_t in[32]);

/* Hex: lowercase, no prefix. to_hex writes exactly 65 bytes
 * (64 hex + NUL). from_hex accepts up to 64 digits, optional 0x
 * prefix; returns false on bad characters or overflow. */
void       zu256_to_hex(zu256256 a, char out[65]);
bool       zu256_from_hex(const char *s, zu256256 *out);

/* Decimal: to_dec writes into out (needs <= 78 digits + NUL);
 * returns false when out_cap is too small. from_dec rejects
 * non-digits and overflow. */
bool zu256_to_dec(zu256256 a, char *out, size_t out_cap);
bool zu256_from_dec(const char *s, zu256256 *out);

#ifdef __cplusplus
}
#endif

#endif /* ZU256_H */
