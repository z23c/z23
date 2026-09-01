/* zmath — checked integer arithmetic and small number theory (C23).
 *
 * Overflow-checked add/sub/mul for u64/i64/size_t, saturating
 * variants, exact division helpers, gcd/lcm, power with overflow
 * checks, min/max/clamp, and decimal digit counts.
 *
 * Header-inline where trivial; the rest lives in zmath.c. No
 * dependencies beyond libc.
 *
 * Apache-2.0 licensed.
 */
#ifndef ZMATH_H
#define ZMATH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Checked arithmetic: return false on overflow, *out unchanged. */
bool zmath_add_u64(uint64_t a, uint64_t b, uint64_t *out);
bool zmath_sub_u64(uint64_t a, uint64_t b, uint64_t *out);
bool zmath_mul_u64(uint64_t a, uint64_t b, uint64_t *out);
bool zmath_add_i64(int64_t a, int64_t b, int64_t *out);
bool zmath_sub_i64(int64_t a, int64_t b, int64_t *out);
bool zmath_mul_i64(int64_t a, int64_t b, int64_t *out);
bool zmath_add_size(size_t a, size_t b, size_t *out);
bool zmath_mul_size(size_t a, size_t b, size_t *out);

/* Saturating arithmetic: clamp to the type's range on overflow. */
uint64_t zmath_sat_add_u64(uint64_t a, uint64_t b);
uint64_t zmath_sat_sub_u64(uint64_t a, uint64_t b);
uint64_t zmath_sat_mul_u64(uint64_t a, uint64_t b);
int64_t  zmath_sat_add_i64(int64_t a, int64_t b);
int64_t  zmath_sat_sub_i64(int64_t a, int64_t b);

/* Division helpers. */
uint64_t zmath_div_ceil_u64(uint64_t a, uint64_t b); /* b==0 -> 0 */

/* Number theory. */
uint64_t zmath_gcd(uint64_t a, uint64_t b);
bool     zmath_lcm(uint64_t a, uint64_t b, uint64_t *out); /* false on overflow */
bool     zmath_pow_u64(uint64_t base, unsigned exp, uint64_t *out);

/* Decimal digit count of v (0 has 1 digit). */
unsigned zmath_digits_u64(uint64_t v);

/* min/max/clamp for the common integer types. */
int64_t  zmath_min_i64(int64_t a, int64_t b);
int64_t  zmath_max_i64(int64_t a, int64_t b);
uint64_t zmath_min_u64(uint64_t a, uint64_t b);
uint64_t zmath_max_u64(uint64_t a, uint64_t b);
int64_t  zmath_clamp_i64(int64_t v, int64_t lo, int64_t hi);
uint64_t zmath_clamp_u64(uint64_t v, uint64_t lo, uint64_t hi);

/* Absolute value of i as unsigned; safe for INT64_MIN. */
uint64_t zmath_abs_i64(int64_t v);

#ifdef __cplusplus
}
#endif

#endif /* ZMATH_H */
