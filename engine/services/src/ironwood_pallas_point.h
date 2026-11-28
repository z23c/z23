/* purpose: Isolated Jacobian Pallas operations for public research vectors. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef IRONWOOD_PALLAS_POINT_H
#define IRONWOOD_PALLAS_POINT_H
#include "ironwood_pallas_field.h"
/* Jacobian coordinates x=X/Z^2, y=Y/Z^3. Z=0 denotes infinity.
 * Inputs must be canonical, valid curve points. Outputs may alias inputs.
 * Research only: not qualified for secret data or wallet use. */
struct pallas_point { struct pallas_fp x, y, z; };
void pallas_point_double(struct pallas_point *out, const struct pallas_point *a);
void pallas_point_add(struct pallas_point *out, const struct pallas_point *a,
                      const struct pallas_point *b);
/* Research only: scalar bytes must encode a canonical nonzero Orchard IVK. */
void pallas_point_multiply(struct pallas_point *out, const struct pallas_point *p,
                           const uint8_t scalar[32]);
#endif
