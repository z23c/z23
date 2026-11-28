/* purpose: Check PostNu6_3 expected-H folding against public upstream traces. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_postnu63.h"
#include "services/ironwood_postnu63_quotient.h"
#include "services/ironwood_postnu63_gates.h"
#include "services/ironwood_postnu63_domain.h"
#include "services/ironwood_postnu63_pinned_h.h"
#include "primitives/transaction_v6_wire.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include <stdio.h>
#include <string.h>

#define Q_CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "ironwood quotient line %d: %s\n", __LINE__, #c); return 1; \
} } while (0)

/* Public one- and funded two-action Orchard 0.16.0 PostNu6_3 traces.
 * Each file contains y, x, then the evaluated gate, permutation and lookup
 * expressions in upstream action order. They do not authenticate a key. */
static int quotient_case(const char *path, size_t actions, const char *expected_hex)
{
    uint8_t input[(2 + 2 * 215) * 32], expected[32], out[32], changed[32], temp[32];
    size_t terms_size = actions * 215 * 32, size = 64 + terms_size;
    FILE *file = fopen(path, "rb");
    Q_CHECK(file);
    bool loaded = fread(input, 1, size, file) == size && fgetc(file) == EOF;
    Q_CHECK(fclose(file) == 0 && loaded);
    Q_CHECK(zcl_hex_decode(expected_hex, expected, sizeof expected));
    struct ironwood_postnu63_stage stage = {0};
    stage.actions = actions; stage.phase = IRONWOOD_POSTNU63_EVAL_X1;
    memcpy(stage.y, input, 32); memcpy(stage.x, input + 32, 32);
    uint8_t *terms = input + 64;
    Q_CHECK(ironwood_postnu63_expected_h(&stage, terms, terms_size, out).ok);
    Q_CHECK(!memcmp(out, expected, 32));
    terms[0] ^= 1;
    Q_CHECK(ironwood_postnu63_expected_h(&stage, terms, terms_size, changed).ok);
    Q_CHECK(memcmp(out, changed, 32));
    terms[0] ^= 1;
    memcpy(temp, terms, 32); memcpy(terms, terms + terms_size - 32, 32);
    memcpy(terms + terms_size - 32, temp, 32);
    Q_CHECK(ironwood_postnu63_expected_h(&stage, terms, terms_size, changed).ok);
    Q_CHECK(memcmp(out, changed, 32));
    return 0;
}

static int quotient_refusals(void)
{
    struct ironwood_postnu63_stage stage = {0};
    uint8_t terms[215 * 32] = {0}, out[32], saved[32];
    memset(out, 0xa5, sizeof out); memcpy(saved, out, sizeof out);
    stage.actions = 1; stage.phase = IRONWOOD_POSTNU63_EVAL_X1;
    stage.x[0] = 1;
    Q_CHECK(!ironwood_postnu63_expected_h(&stage, terms, sizeof terms, out).ok);
    Q_CHECK(!memcmp(out, saved, sizeof out));
    stage.x[0] = 2;
    Q_CHECK(!ironwood_postnu63_expected_h(&stage, terms, sizeof terms - 1, out).ok);
    stage.actions = UINT64_MAX;
    Q_CHECK(!ironwood_postnu63_expected_h(&stage, terms, sizeof terms, out).ok);
    stage.actions = 1; stage.phase = IRONWOOD_POSTNU63_Y_X;
    Q_CHECK(!ironwood_postnu63_expected_h(&stage, terms, sizeof terms, out).ok);
    stage.phase = IRONWOOD_POSTNU63_EVAL_X1; memset(terms, 0xff, 32);
    Q_CHECK(!ironwood_postnu63_expected_h(&stage, terms, sizeof terms, out).ok);
    Q_CHECK(!memcmp(out, saved, sizeof out));
    return 0;
}

static bool fixture_read(const char *path, uint8_t *out, size_t size)
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    bool ok = fread(out, 1, size, f) == size && fgetc(f) == EOF;
    return fclose(f) == 0 && ok;
}

/* Orchard 0.16.0 PostNu6_3 / halo2_proofs 0.4.0: 193 postfix expressions.
 * Source text SHA-256 08bb64dc0293aafcb82e61f5483c6830689d4965ea91b4088e71f6cbcfa5518f;
 * binary SHA-256 4f29d83389cb64af9c5fc3dccfb21a4c66570c95fbcb2c0c3a4abe844b7e50c3.
 * R1 ironwood-custom-gates-provenance-1128/reproduce.sh records conversion;
 * ironwood-quotient.e8m8Kt0J/gates.sh and inject.rs record upstream extraction.
 * The fixture is research data, not an authenticated verifier key. */
static int gate_refusals(struct ironwood_postnu63_stage *stage, const uint8_t *program, size_t program_size)
{
    uint8_t out[IRONWOOD_POSTNU63_GATE_BYTES], before[IRONWOOD_POSTNU63_GATE_BYTES];
    struct ironwood_postnu63_stage snapshot;
    memset(out, 0xa5, sizeof out); memcpy(before, out, sizeof out); memcpy(&snapshot, stage, sizeof snapshot);
    Q_CHECK(!ironwood_postnu63_custom_gates(stage, 0, program, program_size - 1, out, sizeof out).ok);
    const uint8_t bad_query[] = {'F', 29, 'E'}, underflow[] = {'M', 'E'}, bad_op[] = {'Z'};
    Q_CHECK(!ironwood_postnu63_custom_gates(stage, 0, bad_query, sizeof bad_query, out, sizeof out).ok);
    Q_CHECK(!ironwood_postnu63_custom_gates(stage, 0, underflow, sizeof underflow, out, sizeof out).ok);
    Q_CHECK(!ironwood_postnu63_custom_gates(stage, 0, bad_op, sizeof bad_op, out, sizeof out).ok);
    uint8_t overflow[129 * 2];
    for (size_t i = 0; i < 129; ++i) { overflow[2*i] = 'F'; overflow[2*i+1] = 0; }
    Q_CHECK(!ironwood_postnu63_custom_gates(stage, 0, overflow, sizeof overflow, out, sizeof out).ok);
    Q_CHECK(!ironwood_postnu63_custom_gates(stage, stage->actions, program, program_size, out, sizeof out).ok);
    Q_CHECK(!ironwood_postnu63_custom_gates(stage, 0, program, program_size, out, sizeof out - 1).ok);
    Q_CHECK(!memcmp(out, before, sizeof out) && !memcmp(stage, &snapshot, sizeof snapshot));
    return 0;
}

static int gate_bad_inputs(struct ironwood_postnu63_stage *stage, const uint8_t *program,
                           size_t program_size, uint8_t *proof)
{
    uint8_t out[IRONWOOD_POSTNU63_GATE_BYTES], before[IRONWOOD_POSTNU63_GATE_BYTES], saved[32];
    memset(out, 0xa5, sizeof out); memcpy(before, out, sizeof out);
    const uint8_t bad_advice[] = {'A', 25}, short_constant[] = {'C', 1};
    Q_CHECK(!ironwood_postnu63_custom_gates(stage, 0, bad_advice, sizeof bad_advice, out, sizeof out).ok);
    Q_CHECK(!ironwood_postnu63_custom_gates(stage, 0, short_constant, sizeof short_constant, out, sizeof out).ok);
    struct ironwood_postnu63_stage invalid = *stage;
    invalid.proof.buffer = NULL;
    Q_CHECK(!ironwood_postnu63_custom_gates(&invalid, 0, program, program_size, out, sizeof out).ok);
    invalid = *stage; ++invalid.fixed_eval_offset;
    Q_CHECK(!ironwood_postnu63_custom_gates(&invalid, 0, program, program_size, out, sizeof out).ok);
    uint8_t *first_fixed = proof + stage->fixed_eval_offset + 18 * 32;
    memcpy(saved, first_fixed, sizeof saved); memset(first_fixed, 0xff, sizeof saved);
    bool refused = !ironwood_postnu63_custom_gates(stage, 0, program, program_size, out, sizeof out).ok;
    memcpy(first_fixed, saved, sizeof saved);
    Q_CHECK(refused && !memcmp(out, before, sizeof out));
    return 0;
}

static int domain_case(const struct ironwood_postnu63_stage *stage, size_t actions)
{
    static const char *const expected[2][3] = {
        {"bcd1d6350c58259dcede7b8d5f051b1fdc61d73bedb546fed2273626fdbfbb0d",
         "71ec2db10214459101885a8067300936d73070984c45322d6a5d3bd871aa890d",
         "3f6d2be86b65aa881907602a90bc6ae25e1f78c8ee71300b878070f20a7fe319"},
        {"ef7c2f41c1d8d0664e44a5eea91d99583a34024b88c1f8a0aee5a0a90c93f92c",
         "8c87820476bbea638e9cf1b3196eadfa00bb9f640ab7c5a6ceda4238057ef917",
         "1e0a739319825e7aeadad92e33101c11406fd5b12b0ef86180bf99ffd70c3712"}
    };
    uint8_t omega[32], want[3][32];
    Q_CHECK(actions >= 1 && actions <= 2);
    Q_CHECK(zcl_hex_decode("1378a1ad5a5428ef4ec2a1aabc889b7a0b606d4295d3cb319e11325fad501b18", omega, 32));
    for (size_t i = 0; i < 3; ++i) Q_CHECK(zcl_hex_decode(expected[actions - 1][i], want[i], 32));
    struct ironwood_postnu63_domain_rows rows, saved;
    Q_CHECK(ironwood_postnu63_domain_rows(stage, omega, &rows).ok);
    Q_CHECK(!memcmp(rows.l0, want[0], 32) && !memcmp(rows.last, want[1], 32) && !memcmp(rows.active, want[2], 32));
    memcpy(&saved, &rows, sizeof saved);
    struct ironwood_postnu63_stage bad = *stage;
    memset(bad.x, 0, 32); bad.x[0] = 1;
    Q_CHECK(!ironwood_postnu63_domain_rows(&bad, omega, &rows).ok);
    memset(omega, 0, sizeof omega); omega[0] = 1;
    Q_CHECK(!ironwood_postnu63_domain_rows(stage, omega, &rows).ok);
    Q_CHECK(!memcmp(&rows, &saved, sizeof rows));
    return 0;
}

static int lookup_refusals(struct ironwood_postnu63_stage *stage, const uint8_t omega[32],
                           const uint8_t *program, size_t size)
{
    uint8_t out[IRONWOOD_POSTNU63_LOOKUP_BYTES], before[IRONWOOD_POSTNU63_LOOKUP_BYTES];
    memset(out, 0xa5, sizeof out); memcpy(before, out, sizeof out);
    const uint8_t bad_special[] = {'I', 0xf3, 0x01}, short_special[] = {'I', 0xf4};
    Q_CHECK(!ironwood_postnu63_lookup_gates(stage, 0, omega, bad_special, sizeof bad_special, out, sizeof out).ok);
    Q_CHECK(!ironwood_postnu63_lookup_gates(stage, 0, omega, short_special, sizeof short_special, out, sizeof out).ok);
    Q_CHECK(!ironwood_postnu63_lookup_gates(stage, 0, omega, program, size - 1, out, sizeof out).ok);
    struct ironwood_postnu63_stage invalid = *stage;
    ++invalid.lookup_eval_offset;
    Q_CHECK(!ironwood_postnu63_lookup_gates(&invalid, 0, omega, program, size, out, sizeof out).ok);
    memset(invalid.theta, 0xff, 32); --invalid.lookup_eval_offset;
    Q_CHECK(!ironwood_postnu63_lookup_gates(&invalid, 0, omega, program, size, out, sizeof out).ok);
    Q_CHECK(!memcmp(out, before, sizeof out));
    return 0;
}

static int permutation_refusals(struct ironwood_postnu63_stage *stage, const uint8_t omega[32],
                                const uint8_t delta[32], const uint8_t *program, size_t size)
{
    uint8_t out[IRONWOOD_POSTNU63_PERMUTATION_BYTES], before[IRONWOOD_POSTNU63_PERMUTATION_BYTES];
    memset(out, 0xa5, sizeof out); memcpy(before, out, sizeof out);
    const uint8_t wrong_special[] = {'I', 0x58, 0x02}; /* lookup-only index 600 */
    Q_CHECK(!ironwood_postnu63_permutation_gates(stage, 0, omega, delta, wrong_special, sizeof wrong_special, out, sizeof out).ok);
    Q_CHECK(!ironwood_postnu63_permutation_gates(stage, 0, omega, delta, program, size - 1, out, sizeof out).ok);
    struct ironwood_postnu63_stage invalid = *stage;
    ++invalid.sigma_eval_offset;
    Q_CHECK(!ironwood_postnu63_permutation_gates(&invalid, 0, omega, delta, program, size, out, sizeof out).ok);
    uint8_t bad_delta[32]; memset(bad_delta, 0xff, sizeof bad_delta);
    Q_CHECK(!ironwood_postnu63_permutation_gates(stage, 0, omega, bad_delta, program, size, out, sizeof out).ok);
    Q_CHECK(!memcmp(out, before, sizeof out));
    return 0;
}

static int gate_case(const char *proof_path, const char *terms_path, size_t actions,
                     const uint8_t *program, size_t program_size, const uint8_t *lookup, size_t lookup_size,
                     const uint8_t *permutation, size_t permutation_size,
                     const char *expected_h)
{
    static const char *const challenges[2][3] = {
        {"c646b63addb91bb5431ddffc0f0f054c4edcea95143b7006d5fe3f3e6d41000c",
         "1b6a36e4d9361552dc592493d87e3570d0fcb8ed44b81727c4780d9ad73a3b36",
         "973504d5f2f8e6bf4896eb0a60aa7c894f4bf5fb73eb29b1a431e213dda4393f"},
        {"9b4c4db54b5587629516968e6cba32a1c9239bee4c8e5d22dd534b79ed27bc34",
         "8a03d35c2b5547a838e80fa0d0e2a74a3a274758025c1f382035bd8af31ee726",
         "35d7dea4c45b405f44e0b08be51a01de556790d375a158ba97e29e23b960e42f"}
    };
    uint8_t proof[7590], input[(2 + 2 * 215) * 32], values[IRONWOOD_POSTNU63_GATE_BYTES], expected[32], h[32], omega[32], delta[32];
    size_t proof_size = 2720 + actions * 2272, term_size = actions * 215 * 32;
    Q_CHECK(fixture_read(proof_path, proof, 163 * actions + proof_size));
    Q_CHECK(fixture_read(terms_path, input, 64 + term_size));
    Q_CHECK(zcl_hex_decode(expected_h, expected, 32));
    struct ironwood_postnu63_stage stage = {0};
    stage.actions = actions; stage.phase = IRONWOOD_POSTNU63_EVAL_X1;
    stage.proof.buffer = proof + 163 * actions; stage.proof.length = proof_size; stage.proof.position = proof_size - 992;
    stage.instance_eval_offset = 704 * actions + 288;
    stage.advice_eval_offset = 736 * actions + 288; stage.fixed_eval_offset = 1536 * actions + 288;
    stage.sigma_eval_offset = 1536 * actions + 1248; stage.permutation_eval_offset = 1536 * actions + 1728;
    stage.lookup_eval_offset = 1792 * actions + 1728;
    memcpy(stage.y, input, 32); memcpy(stage.x, input + 32, 32);
    Q_CHECK(zcl_hex_decode(challenges[actions - 1][0], stage.theta, 32));
    Q_CHECK(zcl_hex_decode(challenges[actions - 1][1], stage.beta, 32));
    Q_CHECK(zcl_hex_decode(challenges[actions - 1][2], stage.gamma, 32));
    Q_CHECK(zcl_hex_decode("1378a1ad5a5428ef4ec2a1aabc889b7a0b606d4295d3cb319e11325fad501b18", omega, 32));
    Q_CHECK(zcl_hex_decode("a29b7bdd20cd6c6a3656ee3ef1f3e4f59d04a512715b45bd6cab06000f7d750a", delta, 32));
    Q_CHECK(!domain_case(&stage, actions));
    for (size_t a = 0; a < actions; ++a) {
        Q_CHECK(ironwood_postnu63_custom_gates(&stage, a, program, program_size, values, sizeof values).ok);
        Q_CHECK(!memcmp(values, input + 64 + a * 215 * 32, sizeof values));
        memcpy(input + 64 + a * 215 * 32, values, sizeof values);
        Q_CHECK(ironwood_postnu63_permutation_gates(&stage, a, omega, delta, permutation, permutation_size,
                                                   values, IRONWOOD_POSTNU63_PERMUTATION_BYTES).ok);
        Q_CHECK(!memcmp(values, input + 64 + (a * 215 + 193) * 32, IRONWOOD_POSTNU63_PERMUTATION_BYTES));
        memcpy(input + 64 + (a * 215 + 193) * 32, values, IRONWOOD_POSTNU63_PERMUTATION_BYTES);
        Q_CHECK(ironwood_postnu63_lookup_gates(&stage, a, omega, lookup, lookup_size, values, IRONWOOD_POSTNU63_LOOKUP_BYTES).ok);
        Q_CHECK(!memcmp(values, input + 64 + (a * 215 + 200) * 32, IRONWOOD_POSTNU63_LOOKUP_BYTES));
        memcpy(input + 64 + (a * 215 + 200) * 32, values, IRONWOOD_POSTNU63_LOOKUP_BYTES);
    }
    Q_CHECK(ironwood_postnu63_expected_h(&stage, input + 64, term_size, h).ok && !memcmp(h, expected, 32));
    Q_CHECK(!gate_refusals(&stage, program, program_size));
    Q_CHECK(!gate_bad_inputs(&stage, program, program_size, proof + 163 * actions));
    Q_CHECK(!lookup_refusals(&stage, omega, lookup, lookup_size));
    Q_CHECK(!permutation_refusals(&stage, omega, delta, permutation, permutation_size));
    return 0;
}

static int gate_cases(void)
{
    /* Orchard 0.16.0 / halo2_proofs 0.4.0 PostNu6_3 lookup RPN SHA-256
     * 479bada7b99fd3b27431bb2e81c39a457db0f0e1e73ea39cb725fb2a17f36b11;
     * binary SHA-256 8fb1c0ce2729b3be8eaa6afe2f418f70248b62d358500f15c03599b3358f630c.
     * R1 ironwood-lookup-gates-provenance-1128/reproduce.sh records construction. */
    /* Permutation source column-plan SHA-256 ad34b5cb6753df06c880e2014e1fb95270c2ed011d7fdd308c063bc83de44e16;
     * seven-expression program SHA-256 a7017dc7181affb167d21faf2f6dd2c9464d299f46a667114297a235380fd010.
     * R1 ironwood-permutation-provenance-1128/reproduce.sh records construction. */
    uint8_t program[48484], lookup[1159], permutation[997];
    Q_CHECK(fixture_read("tests/fixtures/ironwood/postnu63-custom-gates.bin", program, sizeof program));
    Q_CHECK(fixture_read("tests/fixtures/ironwood/postnu63-lookup-gates.bin", lookup, sizeof lookup));
    Q_CHECK(fixture_read("tests/fixtures/ironwood/postnu63-permutation-gates.bin", permutation, sizeof permutation));
    Q_CHECK(!gate_case("tests/fixtures/ironwood/postnu63-coinbase.bin", "tests/fixtures/ironwood/postnu63-quotient-one.bin",
        1, program, sizeof program, lookup, sizeof lookup, permutation, sizeof permutation,
        "4b60b489fba78511e7852cdfb8cd499053d50db264e2e389bee82f12d23f9415"));
    Q_CHECK(!gate_case("tests/fixtures/ironwood/postnu63-funded.bin", "tests/fixtures/ironwood/postnu63-quotient-two.bin",
        2, program, sizeof program, lookup, sizeof lookup, permutation, sizeof permutation,
        "b6a266e4e45ca24645108adbdaba49e232a16542d4c6a2fe0635e2bb7c5de02a"));
    return 0;
}

/* Reconstruct a structural v6 wire around the public statement(s) and full
 * proof; signatures and unrelated ciphertext bytes are fixture placeholders. */
static bool pinned_view(const uint8_t *input, size_t actions, size_t proof_size,
                        uint8_t wire[9400], struct v6_wire_view *view)
{
    static const uint8_t header[] = {6,0,0,128,0x98,0xb6,0x84,0xd8,0x5b,0x16,0xa5,0x37,
        0x51,0xce,0x52,0xe8,0x5c,0x0e,0x5f,0x0f,0,0,0,0,0,0};
    size_t flags = 26 + actions * 820, anchor = flags + 9, proof = anchor + 35;
    size_t total = proof + proof_size + actions * 64 + 64;
    if (!actions || actions > 2 || total > 9400 || proof_size > 65535) return false;
    memset(wire, 0, total); memcpy(wire, header, 25); wire[25] = (uint8_t)actions;
    for (size_t i = 0; i < actions; ++i) memcpy(wire + 26 + i * 820, input + i * 163 + 32, 128);
    wire[flags] = (uint8_t)(input[160] | (input[161] << 1) | ((1u - input[162]) << 2));
    memcpy(wire + anchor, input, 32); wire[anchor + 32] = 0xfd;
    zcl_write_u16_le(wire + anchor + 33, (uint16_t)proof_size);
    memcpy(wire + proof, input + actions * 163, proof_size);
    return v6_core_parse(wire, total, view) == V6_WIRE_OK;
}

static bool pinned_stage(const struct v6_wire_view *view, struct ironwood_postnu63_stage *stage)
{
    /* Ten public k=11 Lagrange commitments plus W, retained from the pinned
     * upstream oracle; fixture SHA-256 6863c48b9bc83d6e10eb4cdfdb55b8db2c62c27bd426494ac525a4514249f77f. */
    uint8_t basis[11][32], vk[32];
    if (!fixture_read("tests/fixtures/ironwood/postnu63-instance-basis.bin", (uint8_t *)&basis, sizeof basis) ||
        !zcl_hex_decode("99b4fa5429bf1f72bbba9c1620e201206287d2cc6373012d5bb99fedb7f72205", vk, 32)) return false;
    struct zcl_result r = ironwood_postnu63_first_challenge(view, vk, (const uint8_t (*)[32])basis, basis[10], stage);
    if (r.ok) r = ironwood_postnu63_lookup_challenges(stage);
    if (r.ok) r = ironwood_postnu63_yx_challenges(stage);
    if (r.ok) r = ironwood_postnu63_evaluations(stage);
    return r.ok;
}

static int pinned_refusals(const struct ironwood_postnu63_stage *stage,
                           struct ironwood_postnu63_constraint_programs *programs,
                           uint8_t *custom, uint8_t *permutation, uint8_t *lookup)
{
    uint8_t out[32], before[32];
    memset(out, 0xa5, sizeof out); memcpy(before, out, sizeof out);
    uint8_t *p[3] = {custom, permutation, lookup};
    for (size_t i = 0; i < 3; ++i) {
        p[i][0] ^= 1;
        bool refused = !ironwood_postnu63_pinned_h(stage, programs, out).ok;
        p[i][0] ^= 1;
        Q_CHECK(refused && !memcmp(out, before, sizeof out));
    }
    --programs->permutation.size;
    Q_CHECK(!ironwood_postnu63_pinned_h(stage, programs, out).ok && !memcmp(out, before, sizeof out));
    ++programs->permutation.size;
    struct ironwood_postnu63_stage invalid = *stage;
    invalid.phase = IRONWOOD_POSTNU63_Y_X;
    Q_CHECK(!ironwood_postnu63_pinned_h(&invalid, programs, out).ok && !memcmp(out, before, sizeof out));
    invalid = *stage; invalid.actions = UINT64_MAX;
    Q_CHECK(!ironwood_postnu63_pinned_h(&invalid, programs, out).ok && !memcmp(out, before, sizeof out));
    return 0;
}

static int pinned_case(const char *proof_path, size_t actions, const char *expected_hex)
{
    uint8_t input[7590], wire[9400], custom[48484], permutation[997], lookup[1159], expected[32], h[32];
    size_t proof_size = 2720 + actions * 2272;
    Q_CHECK(fixture_read(proof_path, input, actions * 163 + proof_size));
    Q_CHECK(fixture_read("tests/fixtures/ironwood/postnu63-custom-gates.bin", custom, sizeof custom));
    Q_CHECK(fixture_read("tests/fixtures/ironwood/postnu63-permutation-gates.bin", permutation, sizeof permutation));
    Q_CHECK(fixture_read("tests/fixtures/ironwood/postnu63-lookup-gates.bin", lookup, sizeof lookup));
    Q_CHECK(zcl_hex_decode(expected_hex, expected, sizeof expected));
    struct v6_wire_view view;
    Q_CHECK(pinned_view(input, actions, proof_size, wire, &view));
    struct ironwood_postnu63_stage stage, saved;
    Q_CHECK(pinned_stage(&view, &stage));
    memcpy(&saved, &stage, sizeof saved);
    struct ironwood_postnu63_constraint_programs programs = {
        {custom, sizeof custom}, {permutation, sizeof permutation}, {lookup, sizeof lookup}
    };
    Q_CHECK(ironwood_postnu63_pinned_h(&stage, &programs, h).ok && !memcmp(h, expected, 32));
    Q_CHECK(!memcmp(&stage, &saved, sizeof saved));
    Q_CHECK(!pinned_refusals(&stage, &programs, custom, permutation, lookup));
    return 0;
}

static int pinned_cases(void)
{
    Q_CHECK(!pinned_case("tests/fixtures/ironwood/postnu63-coinbase.bin", 1,
                         "4b60b489fba78511e7852cdfb8cd499053d50db264e2e389bee82f12d23f9415"));
    Q_CHECK(!pinned_case("tests/fixtures/ironwood/postnu63-funded.bin", 2,
                         "b6a266e4e45ca24645108adbdaba49e232a16542d4c6a2fe0635e2bb7c5de02a"));
    return 0;
}

int test_ironwood_postnu63_quotient(void)
{
    Q_CHECK(!quotient_case("tests/fixtures/ironwood/postnu63-quotient-one.bin", 1,
                           "4b60b489fba78511e7852cdfb8cd499053d50db264e2e389bee82f12d23f9415"));
    Q_CHECK(!quotient_case("tests/fixtures/ironwood/postnu63-quotient-two.bin", 2,
                           "b6a266e4e45ca24645108adbdaba49e232a16542d4c6a2fe0635e2bb7c5de02a"));
    Q_CHECK(!quotient_refusals());
    Q_CHECK(!gate_cases());
    Q_CHECK(!pinned_cases());
    puts("PostNu6_3 quotient public trace cases passed");
    return 0;
}
