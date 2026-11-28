/* purpose: Verify a PostNu6_3 Ironwood proof against its v6 wire statements. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_verify_proof.h"
#include "services/ironwood_postnu63.h"
#include "services/ironwood_postnu63_pinned_h.h"
#include "services/ironwood_postnu63_wire_commitment.h"
#include "services/ironwood_postnu63_query.h"
#include "services/ironwood_opening_equation.h"
#include "services/ironwood_resident_params.h"
#include "primitives/transaction_v6_wire.h"

struct zcl_result ironwood_postnu63_verify_proof(const uint8_t *wire, size_t length,
    const struct ironwood_postnu63_constraint_programs *programs, const struct ironwood_opening_basis *basis)
{
    if (!programs || !basis || !wire) return ZCL_ERR(-1, "Missing Ironwood proof or parameters");
    struct v6_wire_view view;
    if (v6_core_parse(wire, length, &view) != V6_WIRE_OK || !view.ironwood.count)
        return ZCL_ERR(-1, "Expected a complete v6 transaction with an Ironwood proof");
    struct ironwood_postnu63_stage stage;
    uint8_t quotient[32], commitment[32], evaluation[32];
    bool holds = false;
    struct zcl_result r = ironwood_postnu63_prepare_opening(&view, &stage);
    if (r.ok) r = ironwood_postnu63_pinned_h(&stage, programs, quotient);
    if (r.ok) r = ironwood_postnu63_wire_commitment(&view, commitment);
    if (r.ok) r = ironwood_postnu63_wire_value(&view, quotient, evaluation);
    if (r.ok) r = ironwood_postnu63_check_claim(&view, basis, commitment, evaluation, &holds);
    if (!r.ok) return r;
    return holds ? ZCL_OK : ZCL_ERR(-1, "Invalid Ironwood PostNu6_3 opening proof");
}

struct zcl_result ironwood_postnu63_verify_proof_resident(const uint8_t *wire, size_t length)
{
    const struct ironwood_postnu63_constraint_programs programs = {
        {ironwood_resident_custom, sizeof ironwood_resident_custom},
        {ironwood_resident_permutation, sizeof ironwood_resident_permutation},
        {ironwood_resident_lookup, sizeof ironwood_resident_lookup}
    };
    return ironwood_postnu63_verify_proof(wire, length, &programs, &ironwood_resident_basis);
}
