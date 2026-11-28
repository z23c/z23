/* purpose: Check wire-derived PostNu6_3 opening commitments. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_postnu63_wire_commitment.h"
#include "primitives/transaction_v6_wire.h"
#include "base/hex.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "wire commitment line %d: %s\n", __LINE__, #x); return 1; } } while (0)
static int check_fixture(const char *path, size_t n, const char *expected_hex)
{
    static const uint8_t header[25] = {6,0,0,128,0x98,0xb6,0x84,0xd8,0x5b,0x16,0xa5,0x37,
        0x51,0xce,0x52,0xe8,0x5c,0x0e,0x5f,0x0f,0,0,0,0,0};
    uint8_t input[7590], wire[10000] = {0}, expected[32], out[32], saved[32];
    size_t proof_size = 2720 + n * 2272, bytes = n * V6_IRONWOOD_STATEMENT_SIZE + proof_size;
    FILE *f = fopen(path, "rb");
    CHECK(f && bytes <= sizeof input);
    bool loaded = fread(input, 1, bytes, f) == bytes && fgetc(f) == EOF;
    CHECK(fclose(f) == 0 && loaded);
    size_t flags = 26 + n * 820, anchor = flags + 9, proof = anchor + 35;
    size_t total = proof + proof_size + n * 64 + 64;
    CHECK(total <= sizeof wire);
    memcpy(wire, header, sizeof header); wire[25] = (uint8_t)n;
    for (size_t i = 0; i < n; ++i)
        memcpy(wire + 26 + i * 820, input + i * V6_IRONWOOD_STATEMENT_SIZE + 32, 128);
    wire[flags] = n == 1 ? 6 : 7; memcpy(wire + anchor, input, 32);
    wire[anchor + 32] = 0xfd; wire[anchor + 33] = (uint8_t)proof_size;
    wire[anchor + 34] = (uint8_t)(proof_size >> 8);
    memcpy(wire + proof, input + n * V6_IRONWOOD_STATEMENT_SIZE, proof_size);
    struct v6_wire_view view;
    CHECK(v6_core_parse(wire, total, &view) == V6_WIRE_OK);
    CHECK(zcl_hex_decode(expected_hex, expected, 32));
    CHECK(ironwood_postnu63_wire_commitment(&view, out).ok && !memcmp(out, expected, 32));
    memcpy(saved, out, 32);
    memcpy(wire + proof, wire + proof + 32, 32);
    CHECK(ironwood_postnu63_wire_commitment(&view, out).ok && memcmp(out, saved, 32));
    memcpy(out, saved, 32);
    view.ironwood.proof.size--;
    CHECK(!ironwood_postnu63_wire_commitment(&view, out).ok && !memcmp(out, saved, 32));
    return 0;
}
int test_ironwood_postnu63_wire_commitment(void)
{
    CHECK(check_fixture("tests/fixtures/ironwood/postnu63-coinbase.bin", 1,
        "3169e22cbe2c35665fd334b3b5040345f14f0a71abd908fe67273c34cf8ca106") == 0);
    CHECK(check_fixture("tests/fixtures/ironwood/postnu63-funded.bin", 2,
        "27b1808550d8ce556c79250ae26b071cdde04cd880f7c272b1ba012aa56cdca9") == 0);
    return 0;
}
