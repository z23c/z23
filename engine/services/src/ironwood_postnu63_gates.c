/* purpose: Evaluate caller-supplied PostNu6_3 custom-gate expressions. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_postnu63_gates.h"
#include "services/ironwood_postnu63.h"
#include "services/ironwood_postnu63_domain.h"
#include "ironwood_pasta_internal.h"
#include <openssl/bn.h>
#include <string.h>

enum { GATE_STACK_MAX = 128, GATE_PROGRAM_MAX = 1048576 };
struct gate_machine {
    BN_CTX *ctx;
    BIGNUM *prime, *stack[GATE_STACK_MAX];
    size_t depth, gates, limit;
    uint8_t *values;
    const uint8_t *fixed, *advice, *special;
};

static struct zcl_result gate_push(struct gate_machine *m, const uint8_t *bytes)
{
    if (m->depth == GATE_STACK_MAX) return ZCL_ERR(-1, "Custom gate stack overflow");
    struct zcl_result r = ironwood_pasta_fp_canonical(bytes);
    if (!r.ok) return r;
    if (!BN_lebin2bn(bytes, 32, m->stack[m->depth])) return ZCL_ERR(-1, "Cannot decode custom gate scalar");
    ++m->depth;
    return ZCL_OK;
}

static struct zcl_result gate_arithmetic(struct gate_machine *m, uint8_t op)
{
    if (!m->depth || (op != 'N' && m->depth < 2)) return ZCL_ERR(-1, "Custom gate stack underflow");
    BIGNUM *a = m->stack[m->depth - 1];
    if (op == 'N') {
        if (!BN_mod_sub(a, m->prime, a, m->prime, m->ctx)) return ZCL_ERR(-1, "Cannot negate custom gate scalar");
        return ZCL_OK;
    }
    BIGNUM *b = m->stack[m->depth - 2];
    int ok = op == 'S' ? BN_mod_add(b, b, a, m->prime, m->ctx) : BN_mod_mul(b, b, a, m->prime, m->ctx);
    if (!ok) return ZCL_ERR(-1, "Cannot evaluate custom gate arithmetic");
    --m->depth;
    return ZCL_OK;
}

static struct zcl_result gate_query(struct gate_machine *m, uint8_t op,
                                    const uint8_t *program, size_t size, size_t *position)
{
    if (*position == size) return ZCL_ERR(-1, "Truncated custom gate query");
    unsigned index = program[(*position)++];
    if (index >= (op == 'F' ? 29u : 25u)) return ZCL_ERR(-1, "Invalid custom gate query index");
    return gate_push(m, (op == 'F' ? m->fixed : m->advice) + index * 32);
}

static struct zcl_result gate_special(struct gate_machine *m, const uint8_t *program,
                                      size_t size, size_t *position)
{
    if (!m->special || size - *position < 2) return ZCL_ERR(-1, "Invalid special gate query");
    unsigned index = program[*position] | ((unsigned)program[*position + 1] << 8);
    *position += 2;
    if (index >= 500 && index < 506) return gate_push(m, m->special + (index - 500) * 32);
    if (index >= 600 && index < 615) return gate_push(m, m->special + (index - 594) * 32);
    return ZCL_ERR(-1, "Unknown special gate query");
}

static struct zcl_result gate_instruction(struct gate_machine *m, uint8_t op,
                                          const uint8_t *program, size_t size, size_t *position)
{
    if (op == 'C') {
        if (size - *position < 32) return ZCL_ERR(-1, "Truncated custom gate constant");
        const uint8_t *value = program + *position; *position += 32;
        return gate_push(m, value);
    }
    if (op == 'F' || op == 'A') return gate_query(m, op, program, size, position);
    if (op == 'I') return gate_special(m, program, size, position);
    if (op == 'N' || op == 'S' || op == 'M') return gate_arithmetic(m, op);
    if (op == 'E') {
        if (m->depth != 1 || m->gates == m->limit)
            return ZCL_ERR(-1, "Invalid custom gate expression boundary");
        if (BN_bn2lebinpad(m->stack[0], m->values + m->gates * 32, 32) != 32)
            return ZCL_ERR(-1, "Cannot encode custom gate result");
        ++m->gates; m->depth = 0;
        return ZCL_OK;
    }
    return ZCL_ERR(-1, "Unknown custom gate instruction");
}

static struct zcl_result gate_evaluate(const uint8_t *program, size_t size,
    const uint8_t *fixed, const uint8_t *advice, const uint8_t *special, size_t limit, uint8_t *values)
{
    struct gate_machine m = { .ctx = BN_CTX_new(), .prime = ironwood_pasta_fp_modulus(),
                              .fixed = fixed, .advice = advice, .special = special, .limit = limit, .values = values };
    if (!m.ctx || !m.prime) { BN_CTX_free(m.ctx); BN_free(m.prime); return ZCL_ERR(-1, "Cannot allocate gate field"); }
    BN_CTX_start(m.ctx);
    struct zcl_result r = ZCL_OK;
    for (size_t i = 0; i < GATE_STACK_MAX; ++i)
        if (!(m.stack[i] = BN_CTX_get(m.ctx))) { r = ZCL_ERR(-1, "Cannot allocate gate stack"); break; }
    size_t position = 0;
    while (r.ok && position < size) {
        uint8_t op = program[position++];
        r = gate_instruction(&m, op, program, size, &position);
    }
    if (r.ok && (m.gates != m.limit || m.depth))
        r = ZCL_ERR(-1, "Incomplete custom gate program");
    BN_CTX_end(m.ctx); BN_CTX_free(m.ctx); BN_free(m.prime);
    return r;
}

static struct zcl_result gate_stage(const struct ironwood_postnu63_stage *stage, uint64_t action)
{
    if (!stage || stage->phase != IRONWOOD_POSTNU63_EVAL_X1 ||
        !stage->proof.buffer || stage->proof.error != ZCL_CODEC_OK || action >= stage->actions)
        return ZCL_ERR(-1, "Invalid custom gate input");
    size_t expected = 0;
    struct zcl_result r = ironwood_postnu63_proof_size(stage->actions, &expected);
    if (!r.ok) return r;
    size_t n = (size_t)stage->actions;
    if (stage->proof.length != expected || stage->proof.position != expected - 992 ||
        stage->advice_eval_offset != 736 * n + 288 || stage->fixed_eval_offset != 1536 * n + 288)
        return ZCL_ERR(-1, "Invalid custom gate evaluation offsets");
    return ZCL_OK;
}

struct zcl_result ironwood_postnu63_custom_gates(const struct ironwood_postnu63_stage *stage,
    uint64_t action, const uint8_t *program, size_t program_size, uint8_t *out, size_t out_size)
{
    if (!program || !program_size || program_size > GATE_PROGRAM_MAX || !out ||
        out_size != IRONWOOD_POSTNU63_GATE_BYTES) return ZCL_ERR(-1, "Invalid custom gate program or output");
    struct zcl_result r = gate_stage(stage, action);
    if (!r.ok) return r;
    uint8_t values[IRONWOOD_POSTNU63_GATE_BYTES];
    const uint8_t *fixed = stage->proof.buffer + stage->fixed_eval_offset;
    const uint8_t *advice = stage->proof.buffer + stage->advice_eval_offset + (size_t)action * 25 * 32;
    r = gate_evaluate(program, program_size, fixed, advice, NULL, IRONWOOD_POSTNU63_CUSTOM_GATES, values);
    if (r.ok) memcpy(out, values, sizeof values);
    return r;
}

struct zcl_result ironwood_postnu63_lookup_gates(const struct ironwood_postnu63_stage *stage,
    uint64_t action, const uint8_t omega[32], const uint8_t *program, size_t program_size,
    uint8_t *out, size_t out_size)
{
    if (!omega || !program || !program_size || program_size > GATE_PROGRAM_MAX || !out ||
        out_size != IRONWOOD_POSTNU63_LOOKUP_BYTES) return ZCL_ERR(-1, "Invalid lookup gate program or output");
    struct zcl_result r = gate_stage(stage, action);
    if (!r.ok) return r;
    size_t n = (size_t)stage->actions;
    if (stage->lookup_eval_offset != 1792 * n + 1728) return ZCL_ERR(-1, "Invalid lookup evaluation offset");
    struct ironwood_postnu63_domain_rows rows;
    r = ironwood_postnu63_domain_rows(stage, omega, &rows);
    if (!r.ok) return r;
    uint8_t special[21][32], values[IRONWOOD_POSTNU63_LOOKUP_BYTES];
    memcpy(special[0], rows.l0, 32); memcpy(special[1], rows.last, 32); memcpy(special[2], rows.active, 32);
    memcpy(special[3], stage->theta, 32); memcpy(special[4], stage->beta, 32); memcpy(special[5], stage->gamma, 32);
    memcpy(special[6], stage->proof.buffer + stage->lookup_eval_offset + (size_t)action * 15 * 32, 15 * 32);
    const uint8_t *fixed = stage->proof.buffer + stage->fixed_eval_offset;
    const uint8_t *advice = stage->proof.buffer + stage->advice_eval_offset + (size_t)action * 25 * 32;
    r = gate_evaluate(program, program_size, fixed, advice, special[0], IRONWOOD_POSTNU63_LOOKUP_GATES, values);
    if (r.ok) memcpy(out, values, sizeof values);
    return r;
}
