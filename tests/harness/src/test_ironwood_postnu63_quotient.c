/* purpose: Check PostNu6_3 expected-H folding against public upstream traces. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_postnu63.h"
#include "services/ironwood_postnu63_quotient.h"
#include "base/hex.h"
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

int test_ironwood_postnu63_quotient(void)
{
    Q_CHECK(!quotient_case("tests/fixtures/ironwood/postnu63-quotient-one.bin", 1,
                           "4b60b489fba78511e7852cdfb8cd499053d50db264e2e389bee82f12d23f9415"));
    Q_CHECK(!quotient_case("tests/fixtures/ironwood/postnu63-quotient-two.bin", 2,
                           "b6a266e4e45ca24645108adbdaba49e232a16542d4c6a2fe0635e2bb7c5de02a"));
    Q_CHECK(!quotient_refusals());
    puts("PostNu6_3 quotient public trace cases passed");
    return 0;
}
