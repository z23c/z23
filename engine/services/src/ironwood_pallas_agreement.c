/* purpose: Isolated synthetic Orchard key-agreement research adapter. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "ironwood_pallas_agreement.h"
#include "ironwood_pallas_point.h"
#include "ironwood_pasta_internal.h"
#include <string.h>
struct zcl_result ironwood_research_pallas_agree(const uint8_t ivk[32],
    const uint8_t epk[32], uint8_t out[32])
{
    if (!ivk || !epk || !out) return ZCL_ERR(-1, "Invalid agreement input");
    struct pallas_fp scalar;
    struct zcl_result result = pallas_fp_read(&scalar, ivk);
    if (!result.ok) return result;
    if ((scalar.limb[0] | scalar.limb[1] | scalar.limb[2] | scalar.limb[3]) == 0)
        return ZCL_ERR(-1, "Invalid zero Orchard IVK");
    uint8_t affine[64];
    result = ironwood_pasta_point(epk, IRONWOOD_PALLAS, false, affine);
    if (!result.ok) return result;
    struct pallas_point point = { .z = {{1,0,0,0}} }, shared;
    result = pallas_fp_read(&point.x, affine);
    if (!result.ok) return result;
    result = pallas_fp_read(&point.y, affine + 32);
    if (!result.ok) return result;
    pallas_point_multiply(&shared, &point, ivk);
    struct pallas_fp inv, sq, cube, x, y;
    result = pallas_fp_invert(&inv, &shared.z);
    if (!result.ok) return result;
    pallas_fp_mul(&sq, &inv, &inv); pallas_fp_mul(&cube, &sq, &inv);
    pallas_fp_mul(&x, &shared.x, &sq); pallas_fp_mul(&y, &shared.y, &cube);
    uint8_t encoded[32], ybytes[32];
    pallas_fp_write(encoded, &x); pallas_fp_write(ybytes, &y);
    encoded[31] |= (uint8_t)((ybytes[0] & 1) << 7);
    memcpy(out, encoded, sizeof encoded);
    return ZCL_OK;
}
