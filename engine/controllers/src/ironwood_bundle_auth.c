/* purpose: Authenticate the public cryptography of an Ironwood v6 bundle. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "controllers/ironwood_bundle_auth.h"
#include "services/ironwood_spend_auth.h"
#include "services/ironwood_verify_proof.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "primitives/transaction_v6_wire.h"
#include <stdlib.h>
#include <string.h>

static struct zcl_result check_actions(const struct v6_wire_view *view, const uint8_t sighash[32],
                                       uint8_t (*commitments)[32])
{
    for (uint64_t i = 0; i < view->ironwood.count; ++i) {
        struct v6_action_view action;
        if (!v6_core_bundle_action(&view->ironwood, i, &action) || action.cv.size != 32 ||
            action.rk.size != 32 || action.signature.size != 64)
            return ZCL_ERR(-1, "Cannot read Ironwood action %llu", (unsigned long long)i);
        struct zcl_result r = ironwood_spend_auth_verify(action.rk.data, action.signature.data, sighash);
        if (!r.ok) return ZCL_ERR(-1, "Ironwood spend authorization %llu: %s", (unsigned long long)i, r.message);
        memcpy(commitments[i], action.cv.data, 32);
    }
    return ZCL_OK;
}
struct zcl_result ironwood_bundle_authenticate(const uint8_t *wire, size_t size,
    const struct v6_prevout *prevouts, size_t prevout_count)
{
    struct v6_wire_view view;
    if (!wire || v6_core_parse(wire, size, &view) != V6_WIRE_OK)
        return ZCL_ERR(-1, "Invalid complete v6 transaction frame");
    if (!view.ironwood.count || view.ironwood.count > SIZE_MAX / 32 ||
        view.ironwood.value_balance.size != 8 || view.ironwood.binding_signature.size != 64)
        return ZCL_ERR(-1, "Invalid or absent Ironwood bundle");
    uint8_t sighash[32];
    if (!v6_shielded_sighash(&view, prevouts, prevout_count, sighash))
        return ZCL_ERR(-1, "Cannot derive shielded sighash from ordered prevouts");
    uint8_t (*commitments)[32] = zcl_malloc((size_t)view.ironwood.count * 32, "ironwood bundle commitments");
    if (!commitments) return ZCL_ERR(-1, "Cannot allocate Ironwood commitments");
    struct zcl_result r = check_actions(&view, sighash, commitments);
    if (r.ok) r = ironwood_binding_auth_verify((const uint8_t (*)[32])commitments,
        (size_t)view.ironwood.count, zcl_read_i64_le(view.ironwood.value_balance.data),
        view.ironwood.binding_signature.data, sighash);
    free(commitments);
    if (!r.ok) return r;
    return ironwood_postnu63_verify_proof_resident(wire, size);
}
