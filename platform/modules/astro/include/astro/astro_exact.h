/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * astro_exact — the one numeric type platform/modules/astro computes charts in, and the
 * boundary between what this module claims is VERIFIABLE and what it admits
 * is COSMETIC.
 *
 * ── Why this type exists at all ──────────────────────────────────────────
 * A chart is a seed. A fictional birth instant and place produce planetary
 * longitudes, those produce a character's starting attributes, and a second
 * node may recompute the same chart to check the first one's claim. Two nodes
 * disagreeing about a chart is indistinguishable from one of them lying.
 *
 * `double` cannot carry that. Its result depends on the compiler, the
 * optimisation level, whether the machine has FMA, whether the loop was
 * vectorised (which reassociates a sum), and whether an intermediate stayed
 * in an 80-bit register. Every one of those differences is legal C and none
 * of them is a bug anyone would fix. A chart computed in `double` is
 * reproducible only by accident.
 *
 * So every value a chart is built from is a `struct astro_exact`:
 *
 *     value  =  (-1)^negative  *  magnitude  /  2^ASTRO_EXACT_FRAC_BITS
 *
 * a signed integer over one FIXED denominator. That is exact rational
 * arithmetic with the denominator pinned, and pinning it is the point: an
 * unpinned num/den rational grows its denominator without bound until it
 * silently overflows a fixed limb array, and an overflow that is not refused
 * is exactly the disagreement this type exists to prevent.
 *
 * Every operation is integer-only. No FPU register, no libm call, no rounding
 * mode, no reassociation the compiler is allowed to perform. Two nodes on
 * different architectures at different -O levels get the SAME BITS.
 *
 * ── EXACT vs APPROXIMATE — the boundary, named ───────────────────────────
 * EXACT AND VERIFIABLE. Everything of type struct astro_exact, and everything
 * derived from one by the functions in this header, astro_time.h and
 * astro_chart.h. Concretely: the Julian day, every body's ecliptic longitude,
 * every zodiac sign, every degree/arcminute/arcsecond, the ascendant, every
 * house cusp, and astro_exact_format()'s decimal text. A second node that
 * recomputes any of these MUST get identical bits, and a mismatch is evidence
 * of a defect or a lie — never of "floating point".
 *
 * APPROXIMATE AND COSMETIC. Exactly one function in this module produces a
 * floating-point value: astro_exact_to_double(), declared at the bottom of
 * this header and defined in the ONLY translation unit of platform/modules/astro that is
 * allowed to name `double` (src/astro_display.c). Its result is for printing
 * and for callers who want a rough number. NOTHING in this module consumes
 * it, nothing is compared against it, and no chart value is derived from it.
 * Do not put it on a wire and do not commit to it.
 *
 * That boundary is compiler-enforced, not documented-and-hoped: every other
 * .c file in platform/modules/astro carries `#pragma GCC poison double float` after its
 * includes, so naming a floating-point type on the exact path is a compile
 * error rather than a review comment nobody made. See src/astro_priv.h.
 *
 * ── Where rounding happens, and its exact rule ───────────────────────────
 * Addition, subtraction, negation, comparison and modulo are EXACT: no
 * information is discarded, so they are associative and commutative the way
 * integers are. Only four operations can round, and each rounds by ONE stated
 * rule — truncation toward zero of the magnitude at the 2^-128 grid:
 *   astro_exact_mul   product shifted down by ASTRO_EXACT_FRAC_BITS
 *   astro_exact_div   quotient of a shifted-up dividend
 *   astro_exact_shr   the shift itself
 *   astro_exact_sqrt  floor of the true root at grid resolution
 * "Truncation toward zero" is a property of the MAGNITUDE, which is why the
 * representation is sign-and-magnitude rather than two's complement: a
 * two's-complement shift rounds toward negative infinity and would make
 * f(-x) != -f(x), a needless asymmetry in a value that is an angle.
 *
 * ── Fail-closed ──────────────────────────────────────────────────────────
 * There is no wrap-around and no saturation. Overflow of the limb array,
 * division by zero, and the square root of a negative all produce an INVALID
 * value, and any operation touching an invalid value produces an invalid
 * value. Invalidity therefore propagates to the end of a computation instead
 * of being absorbed, and astro_chart_compute() refuses rather than returning
 * a chart built from a poisoned intermediate. A zeroed struct astro_exact is
 * invalid, so a forgotten initialisation cannot read as the number zero.
 *
 * ── Provenance ───────────────────────────────────────────────────────────
 * The exact-arithmetic and CORDIC design is adapted from the author's
 * astro-calc project (core/rational/, Apache-2.0, same author, same licence);
 * see the module note in astro_chart.h for what was taken, what was rebuilt,
 * and where the planetary theory comes from.
 */

#ifndef ZCL_ASTRO_EXACT_H
#define ZCL_ASTRO_EXACT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Fractional bits of the fixed grid. 128 bits is ~3e-39 of a degree; the
 * astronomy in this module is accurate to arcminutes, so the grid is never
 * the limiting term and the choice can stay a round number. */
#define ASTRO_EXACT_FRAC_BITS 128u

/* Magnitude width. 12 limbs = 768 bits, so a valid value has |v| < 2^640 with
 * 128 fractional bits. Chart quantities live in the low thousands; the
 * headroom is for intermediates during range reduction, where an angle in
 * radians is multiplied out before being taken modulo 2*pi. */
#define ASTRO_EXACT_LIMBS 12u

/* One number on the grid. `valid` last so a zeroed struct is INVALID rather
 * than the number zero — see the fail-closed note above. Callers may copy
 * this by value; it owns no memory and has no lifetime. */
struct astro_exact {
    uint64_t limb[ASTRO_EXACT_LIMBS]; /* magnitude, little-endian limbs */
    uint8_t used;                     /* significant limbs; 0 means zero */
    bool negative;                    /* sign; never true when used == 0 */
    bool valid;                       /* false poisons every operation */
};

/* ── one-time setup ───────────────────────────────────────────────────────
 * The trigonometric tables (pi, the arctangent ladder, the CORDIC gain) are
 * COMPUTED by integer series rather than transcribed, so the first call that
 * needs them builds them. That build is idempotent and its result depends on
 * nothing outside this module, but it writes module-static state, so it is
 * not safe to race. A process that will compute charts from several threads
 * calls this once first; everything else may ignore it. Returns false if the
 * tables could not be built, in which case every trigonometric result and
 * every chart is INVALID rather than approximate. */
bool astro_prepare(void);

/* ── construction ─────────────────────────────────────────────────────── */

/* The invalid value. Every operation given one returns one. */
struct astro_exact astro_exact_invalid(void);

/* Exactly zero. Distinct from astro_exact_invalid(). */
struct astro_exact astro_exact_zero(void);

/* Exactly the integer v. Always representable. */
struct astro_exact astro_exact_from_i64(int64_t v);

/* num/den truncated toward zero at the grid. den == 0 yields invalid.
 * This is the ONLY way a decimal constant should enter this module: write
 * astro_exact_ratio(23439291, 1000000) rather than a floating-point literal,
 * so the constant's value is a property of the source text and not of the
 * compiler's decimal-to-binary conversion. */
struct astro_exact astro_exact_ratio(int64_t num, int64_t den);

/* ── predicates ───────────────────────────────────────────────────────── */

bool astro_exact_is_valid(const struct astro_exact *a);
bool astro_exact_is_zero(const struct astro_exact *a);
bool astro_exact_is_negative(const struct astro_exact *a);

/* -1, 0 or 1. Invalid operands compare as 0 and are indistinguishable from
 * equal here: test astro_exact_is_valid() before believing a comparison. */
int astro_exact_cmp(const struct astro_exact *a, const struct astro_exact *b);

/* Bit-for-bit identity of two values, the predicate a verifier uses. Two
 * invalid values are identical to each other and to nothing else. */
bool astro_exact_identical(const struct astro_exact *a,
                           const struct astro_exact *b);

/* ── arithmetic ───────────────────────────────────────────────────────── */

struct astro_exact astro_exact_neg(struct astro_exact a);
struct astro_exact astro_exact_abs(struct astro_exact a);

/* EXACT: no rounding, so these are associative and commutative. Summing a
 * series forwards and backwards gives identical bits — the property that
 * makes a chart safe to recompute on a machine whose compiler vectorised the
 * loop differently. */
struct astro_exact astro_exact_add(struct astro_exact a, struct astro_exact b);
struct astro_exact astro_exact_sub(struct astro_exact a, struct astro_exact b);

/* Rounds by truncation toward zero at the grid. Overflow yields invalid. */
struct astro_exact astro_exact_mul(struct astro_exact a, struct astro_exact b);
struct astro_exact astro_exact_div(struct astro_exact a, struct astro_exact b);

/* a / 2^bits, truncated toward zero. A shift at or past the whole magnitude
 * width yields zero, not invalid: shifting a finite value that far right is
 * genuinely zero on this grid. */
struct astro_exact astro_exact_shr(struct astro_exact a, unsigned bits);

/* floor of the true square root at grid resolution. Negative yields invalid. */
struct astro_exact astro_exact_sqrt(struct astro_exact a);

/* The representative of a modulo m in [0, m), for m > 0. EXACT. m <= 0
 * yields invalid. This is the range reduction every angle goes through. */
struct astro_exact astro_exact_mod(struct astro_exact a, struct astro_exact m);

/* ── transcendentals ──────────────────────────────────────────────────────
 * Deterministic rational approximations, not closed forms: a CORDIC rotation
 * of a fixed, declared iteration count over the exact type above. They are
 * NOT exact in the mathematical sense — sin(1) is irrational and no rational
 * grid holds it — but they ARE exact in the sense this module needs: the same
 * input gives the same bits on every machine, forever, because the iteration
 * count and every table entry are fixed and every step is integer arithmetic.
 * Accuracy is better than 2^-50 of a radian, which is far below the
 * arcminute-scale error of the planetary theory that consumes them. */

/* Angles in RADIANS. Any finite argument is reduced modulo 2*pi first. */
struct astro_exact astro_exact_sin(struct astro_exact radians);
struct astro_exact astro_exact_cos(struct astro_exact radians);

/* atan2(y, x) in (-pi, pi]. y == 0 && x == 0 yields invalid — the angle is
 * genuinely undefined there and returning 0 would invent one. */
struct astro_exact astro_exact_atan2(struct astro_exact y,
                                     struct astro_exact x);

/* Constants of the grid, computed once by integer series (Machin's formula
 * for pi) rather than parsed from a decimal literal. */
struct astro_exact astro_exact_pi(void);
struct astro_exact astro_exact_two_pi(void);
struct astro_exact astro_exact_degrees_to_radians(struct astro_exact degrees);
struct astro_exact astro_exact_radians_to_degrees(struct astro_exact radians);

/* ── exact readout ────────────────────────────────────────────────────────
 * These are the reproducible way out of the type. Nothing here uses floating
 * point, so their output is as verifiable as the value itself. */

/* floor(value) as an integer. Returns false (and leaves *out untouched) when
 * the value is invalid or does not fit an int64_t. */
bool astro_exact_floor_i64(const struct astro_exact *a, int64_t *out);

/* Fixed-point decimal text, truncated toward zero: "-12.345678".
 * frac_digits <= 18. Returns false on invalid input or a short buffer, and
 * on failure writes an empty string when the buffer has room for one. */
bool astro_exact_format(const struct astro_exact *a, unsigned frac_digits,
                        char *buf, size_t buf_len);

/* ── the approximate escape hatch ─────────────────────────────────────────
 * COSMETIC. The only floating-point value this module will ever hand you.
 * Its low bits are not a promise: it is produced by a conversion this module
 * does not control on every platform. Print it; do not compare it, hash it,
 * store it as a chart's identity, or send it to a peer that will check it.
 * Nothing inside platform/modules/astro calls this. */
double astro_exact_to_double(const struct astro_exact *a);

#endif /* ZCL_ASTRO_EXACT_H */
