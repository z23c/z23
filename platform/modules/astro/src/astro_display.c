/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * astro_display — the module's ONE approximate surface, and the only
 * translation unit in platform/modules/astro permitted to name a floating-point type.
 *
 * Every other .c file here carries `#pragma GCC poison double float` right
 * after its includes (see src/astro_priv.h), which is what makes "the exact
 * path never touches floating point" a compile error rather than a promise.
 * This file is the deliberate exception, and it is one function long so that
 * the exception cannot quietly grow.
 *
 * What comes out of astro_exact_to_double() is COSMETIC. It is for printing
 * and for a caller that wants a rough number to look at. It is not a chart
 * value: nothing inside this module reads it, no chart is derived from it,
 * and it must never be hashed, compared for agreement, stored as an identity,
 * or sent to a peer that will check it. The moment a `double` crosses a node
 * boundary, two honest nodes can disagree and neither can prove which is
 * right — which is the entire reason struct astro_exact exists.
 */

#include "astro/astro_exact.h"
#include "astro_priv.h"

/* Base of the limb ladder, written as a power of two so the constant is
 * exact in the target format rather than parsed from decimal digits. */
#define ASTRO_LIMB_SCALE 18446744073709551616.0 /* 2^64 */

double astro_exact_to_double(const struct astro_exact *a)
{
    if (!astro_exact_is_valid(a))
        return 0.0;
    if (a->used == 0)
        return 0.0;

    double magnitude = 0.0;
    for (unsigned i = a->used; i > 0; i--)
        magnitude = magnitude * ASTRO_LIMB_SCALE + (double)a->limb[i - 1];

    /* Divide by 2^FRAC_BITS one limb-width at a time. Each step is an exact
     * power-of-two division, so the only rounding is the mantissa truncation
     * that made this value approximate in the first place. */
    for (unsigned bits = 0; bits < ASTRO_EXACT_FRAC_BITS; bits += 64u)
        magnitude /= ASTRO_LIMB_SCALE;

    return a->negative ? -magnitude : magnitude;
}
