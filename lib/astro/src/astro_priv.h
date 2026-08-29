/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * astro_priv — the unsigned big-magnitude layer struct astro_exact is built
 * on, and the macro block that makes lib/astro's exact/approximate boundary a
 * compile error rather than a comment.
 *
 * ── The magnitude layer ──────────────────────────────────────────────────
 * struct astro_mag is a plain unsigned integer in little-endian 64-bit limbs.
 * It is deliberately WIDER than struct astro_exact: a product of two
 * ASTRO_EXACT_LIMBS values needs twice the room, and astro_exact_div shifts
 * its dividend up by ASTRO_EXACT_FRAC_BITS before dividing. Every routine
 * here is total — no assert, no abort, no undefined behaviour on any input —
 * and reports capacity exhaustion by returning false, so the caller can turn
 * it into an INVALID astro_exact instead of a wrapped number.
 *
 * These are adapted from the author's astro-calc core/rational/rat.c
 * (Apache-2.0, same author). Three defects in that original are fixed here
 * rather than carried across, because each one is a determinism hazard:
 *
 *   1. Carry propagation. The original detected an add carry with
 *      `carry = (sum < a_limb)` while `sum` had already absorbed the incoming
 *      carry. With a_limb == 0, b_limb == UINT64_MAX and carry-in 1 the sum
 *      wraps to 0, the comparison is false, and the carry is DROPPED. This
 *      version adds in two checked steps.
 *   2. Division. The original divided by REPEATED SUBTRACTION, counting one
 *      at a time. Dividing a 240-bit value by a small one does not "run
 *      slowly", it does not terminate in any human timescale — and the
 *      rational normaliser called it through gcd() on every arithmetic
 *      operation. This version is restoring binary long division, bounded by
 *      the dividend's bit length.
 *   3. Overflow. The original used assert() for limb-array exhaustion.
 *      assert() is live in this build (see tools/lint/check_no_runtime_abort.sh)
 *      so that was a remote abort; with -DNDEBUG it would instead be silent
 *      corruption. Neither is acceptable for a value another node checks.
 *
 * ── The floating-point poison ────────────────────────────────────────────
 * Every .c file in lib/astro except src/astro_display.c carries
 *
 *     #pragma GCC poison double float
 *
 * immediately after its last #include. Naming either type below that line is
 * a compile error, so "the exact path never touches floating point" survives
 * edits by people who did not read astro_exact.h. src/astro_display.c is the
 * one deliberate exception; it owns astro_exact_to_double() and says so.
 *
 * The placement rule is "after the includes", not "at the top": the standard
 * headers declare plenty of double-returning prototypes, and poisoning the
 * identifier first would reject them.
 *
 * Both compilers this tree builds with honour the pragma and both diagnose a
 * use of a poisoned identifier as an error. A `#define double ...` would look
 * equivalent and is not: GCC accepts it silently, but clang rejects it under
 * -Wkeyword-macro, which tools/lint/check_clang_portability.sh runs with
 * -Werror. The pragma is the portable spelling.
 */

#ifndef ZCL_ASTRO_PRIV_H
#define ZCL_ASTRO_PRIV_H

#include "astro/astro_chart.h"
#include "astro/astro_exact.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Limbs of the wide magnitude. A product needs 2*ASTRO_EXACT_LIMBS; a
 * dividend pre-shifted by ASTRO_EXACT_FRAC_BITS needs two more. */
#define ASTRO_MAG_LIMBS (2u * ASTRO_EXACT_LIMBS + 2u)
#define ASTRO_MAG_BITS (ASTRO_MAG_LIMBS * 64u)

struct astro_mag {
    uint64_t limb[ASTRO_MAG_LIMBS];
    unsigned used; /* significant limbs, 0 == zero, always normalised */
};

void astro_mag_zero(struct astro_mag *m);
void astro_mag_from_u64(struct astro_mag *m, uint64_t v);
void astro_mag_norm(struct astro_mag *m);
bool astro_mag_is_zero(const struct astro_mag *m);
size_t astro_mag_bitlen(const struct astro_mag *m);
int astro_mag_cmp(const struct astro_mag *a, const struct astro_mag *b);

/* All of these return false on capacity exhaustion and leave *r zeroed. */
bool astro_mag_add(struct astro_mag *r, const struct astro_mag *a,
                   const struct astro_mag *b);
/* Requires a >= b; returns false otherwise (the caller ordered them wrong). */
bool astro_mag_sub(struct astro_mag *r, const struct astro_mag *a,
                   const struct astro_mag *b);
bool astro_mag_mul(struct astro_mag *r, const struct astro_mag *a,
                   const struct astro_mag *b);
bool astro_mag_shl(struct astro_mag *r, const struct astro_mag *a,
                   size_t bits);
/* Truncating; a shift past the top yields zero and true. */
void astro_mag_shr(struct astro_mag *r, const struct astro_mag *a,
                   size_t bits);
/* q and/or r may be NULL. Returns false when b is zero. */
bool astro_mag_divmod(struct astro_mag *q, struct astro_mag *r,
                      const struct astro_mag *a, const struct astro_mag *b);
bool astro_mag_div_u64(struct astro_mag *q, uint64_t *rem,
                       const struct astro_mag *a, uint64_t b);
/* floor(sqrt(a)). Always succeeds. */
void astro_mag_isqrt(struct astro_mag *r, const struct astro_mag *a);

/* Bridge to the public type. astro_exact_pack() returns false — meaning the
 * caller should produce an invalid value — when the magnitude does not fit
 * ASTRO_EXACT_LIMBS. */
void astro_exact_unpack(struct astro_mag *m, const struct astro_exact *a);
bool astro_exact_pack(struct astro_exact *out, const struct astro_mag *m,
                      bool negative);

/* Trig table setup, owned by astro_trig.c and idempotent. Returns false if
 * the tables could not be built, which poisons every trig call. */
bool astro_trig_tables_ready(void);
const struct astro_exact *astro_trig_pi(void);
const struct astro_exact *astro_trig_two_pi(void);
const struct astro_exact *astro_trig_half_pi(void);

/* ── the planetary theory (src/astro_ephemeris.c) ────────────────────────
 * Heliocentric ecliptic polar coordinates, treated as coplanar with the
 * ecliptic; see astro_chart.h for what that costs. Longitudes are DEGREES in
 * [0, 360) and radii are AU. Each returns false when any intermediate went
 * invalid, so a caller never has to inspect the fields to learn that. */
struct astro_polar {
    struct astro_exact longitude_deg;
    struct astro_exact radius_au;
};

/* tau is Julian millennia from J2000 (VSOP87's argument). */
bool astro_earth_heliocentric(struct astro_exact tau, struct astro_polar *out);

/* t is Julian centuries from J2000. Refuses ASTRO_BODY_SUN and
 * ASTRO_BODY_MOON, which are not heliocentric bodies in this model. */
bool astro_planet_heliocentric(enum astro_body body, struct astro_exact t,
                               struct astro_polar *out);

/* The Moon is already geocentric; only its longitude is modelled. */
bool astro_moon_longitude_deg(struct astro_exact t, struct astro_exact *out);

/* Reduce a degree value to [0, 360). */
struct astro_exact astro_degrees_normalize(struct astro_exact degrees);

/* The poison line itself is written out in each exact-path .c rather than
 * wrapped in a macro here: a reader scanning for how the boundary is enforced
 * should find the enforcement, not an indirection to it. See the header
 * comment above for the rule and for why the pragma rather than a #define. */

#endif /* ZCL_ASTRO_PRIV_H */
