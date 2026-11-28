/* purpose: Derive expected H using the pinned PostNu6_3 constraint programs. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_postnu63_pinned_h.h"
#include "services/ironwood_postnu63.h"
#include "services/ironwood_postnu63_gates.h"
#include "services/ironwood_postnu63_quotient.h"
#include "sha3/sha3.h"
#include "util/safe_alloc.h"
#include <stdlib.h>
#include <string.h>

/* Programs derived from Orchard 0.16.0 PostNu6_3 and halo2_proofs 0.4.0.
 * R1 ironwood-{custom-gates,lookup-gates,permutation}-provenance-1128 retain
 * the upstream instrumentation, conversion recipes and SHA-256 identities. */
enum { CUSTOM_SIZE = 48484, PERM_SIZE = 997, LOOKUP_SIZE = 1159,
       PROGRAM_SIZE = CUSTOM_SIZE + PERM_SIZE + LOOKUP_SIZE, TERMS_PER_ACTION = 215 * 32 };
static const uint8_t program_hashes[3][32] = {
    {0xce,0x78,0x7c,0x0f,0xd7,0xd2,0x0a,0xd0,0xf3,0xd8,0xeb,0x51,0x48,0xaf,0x94,0x69,0x41,0x6e,0xa1,0x0b,0x06,0x8d,0x79,0x33,0xfa,0x5d,0xfc,0x41,0xdc,0x83,0xba,0xa2},
    {0xbf,0xfe,0xf6,0xb3,0x14,0xe0,0xc9,0x9a,0x50,0xd2,0x5d,0x97,0x58,0xb3,0x05,0x95,0xb8,0x65,0x3b,0x83,0x8b,0x1b,0x46,0x86,0xe4,0x7d,0xa3,0x82,0x69,0x8a,0x29,0x74},
    {0x65,0x0e,0xff,0xf6,0xd1,0x44,0x7b,0x34,0x8f,0x82,0x8c,0xf1,0x1e,0xe2,0x31,0x81,0xfe,0xb2,0x20,0x7a,0x64,0x91,0xa1,0x11,0x7d,0x12,0x9b,0x55,0xcf,0x55,0xdf,0xdb}
};
static const uint8_t omega[32] = {0x13,0x78,0xa1,0xad,0x5a,0x54,0x28,0xef,0x4e,0xc2,0xa1,0xaa,0xbc,0x88,0x9b,0x7a,0x0b,0x60,0x6d,0x42,0x95,0xd3,0xcb,0x31,0x9e,0x11,0x32,0x5f,0xad,0x50,0x1b,0x18};
static const uint8_t delta[32] = {0xa2,0x9b,0x7b,0xdd,0x20,0xcd,0x6c,0x6a,0x36,0x56,0xee,0x3e,0xf1,0xf3,0xe4,0xf5,0x9d,0x04,0xa5,0x12,0x71,0x5b,0x45,0xbd,0x6c,0xab,0x06,0x00,0x0f,0x7d,0x75,0x0a};

static struct zcl_result copy_program(uint8_t *destination, const struct ironwood_postnu63_program *program,
                                      size_t size, const uint8_t hash[32])
{
    if (!program->bytes || program->size != size) return ZCL_ERR(-1, "Invalid constraint program length");
    memcpy(destination, program->bytes, size);
    uint8_t actual[32]; sha3_256(destination, size, actual);
    return memcmp(actual, hash, 32) == 0 ? ZCL_OK : ZCL_ERR(-1, "Constraint program identity mismatch");
}

static struct zcl_result evaluate_action(const struct ironwood_postnu63_stage *stage, uint64_t action,
                                          const uint8_t *program, uint8_t *terms)
{
    struct zcl_result r = ironwood_postnu63_custom_gates(stage, action, program, CUSTOM_SIZE,
                                                          terms, IRONWOOD_POSTNU63_GATE_BYTES);
    if (r.ok) r = ironwood_postnu63_permutation_gates(stage, action, omega, delta,
        program + CUSTOM_SIZE, PERM_SIZE, terms + IRONWOOD_POSTNU63_GATE_BYTES, IRONWOOD_POSTNU63_PERMUTATION_BYTES);
    if (r.ok) r = ironwood_postnu63_lookup_gates(stage, action, omega,
        program + CUSTOM_SIZE + PERM_SIZE, LOOKUP_SIZE,
        terms + IRONWOOD_POSTNU63_GATE_BYTES + IRONWOOD_POSTNU63_PERMUTATION_BYTES, IRONWOOD_POSTNU63_LOOKUP_BYTES);
    return r;
}

static struct zcl_result pinned_stage_size(const struct ironwood_postnu63_stage *stage, size_t *terms_size)
{
    if (!stage || stage->phase != IRONWOOD_POSTNU63_EVAL_X1 ||
        !stage->proof.buffer || stage->proof.error != ZCL_CODEC_OK ||
        !stage->actions || stage->actions > (SIZE_MAX - PROGRAM_SIZE) / TERMS_PER_ACTION)
        return ZCL_ERR(-1, "Invalid pinned constraint stage");
    size_t proof_size;
    struct zcl_result r = ironwood_postnu63_proof_size(stage->actions, &proof_size);
    if (!r.ok) return r;
    if (stage->proof.length != proof_size || stage->proof.position != proof_size - 992)
        return ZCL_ERR(-1, "Invalid pinned constraint stage");
    *terms_size = (size_t)stage->actions * TERMS_PER_ACTION;
    return ZCL_OK;
}

struct zcl_result ironwood_postnu63_pinned_h(const struct ironwood_postnu63_stage *stage,
    const struct ironwood_postnu63_constraint_programs *programs, uint8_t out[32])
{
    if (!programs || !out) return ZCL_ERR(-1, "Missing pinned constraint input");
    size_t terms_size;
    struct zcl_result r = pinned_stage_size(stage, &terms_size);
    if (!r.ok) return r;
    uint8_t *work = zcl_malloc(PROGRAM_SIZE + terms_size, "PostNu6_3 constraint programs");
    if (!work) return ZCL_ERR(-1, "Cannot allocate pinned constraint data");
    r = copy_program(work, &programs->custom, CUSTOM_SIZE, program_hashes[0]);
    if (r.ok) r = copy_program(work + CUSTOM_SIZE, &programs->permutation, PERM_SIZE, program_hashes[1]);
    if (r.ok) r = copy_program(work + CUSTOM_SIZE + PERM_SIZE, &programs->lookup, LOOKUP_SIZE, program_hashes[2]);
    uint8_t *terms = work + PROGRAM_SIZE, value[32];
    for (uint64_t action = 0; r.ok && action < stage->actions; ++action)
        r = evaluate_action(stage, action, work, terms + (size_t)action * TERMS_PER_ACTION);
    if (r.ok) r = ironwood_postnu63_expected_h(stage, terms, terms_size, value);
    if (r.ok) memcpy(out, value, sizeof value);
    free(work);
    return r;
}
