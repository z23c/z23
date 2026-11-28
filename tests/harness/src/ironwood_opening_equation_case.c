/* purpose: Check both funded opening equations against independent Halo2 claims. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_opening_equation.h"
#include "services/ironwood_postnu63.h"
#include "services/ironwood_postnu63_query.h"
#include "base/hex.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool ironwood_opening_query_case(size_t actions);

/* Halo2 0.4.0 Params<Vesta>::new(11) and an independent hash-to-curve
 * implementation reproduced every generator, in order, on separate hosts.
 * SHA256(generators) = b3470ff54d467bdfb236f094f7a9355d963d7fbc1e27393452427867a8bcd0db. */
static bool read_basis(struct ironwood_opening_basis *basis)
{
    FILE *f = fopen("engine/services/resources/ironwood/ipa-generators.bin", "rb");
    if (!f) return false;
    size_t size = sizeof basis->generators;
    bool ok = fread(basis->generators, 1, size, f) == size && fgetc(f) == EOF && !ferror(f);
    if (fclose(f)) return false;
    return ok && zcl_hex_decode("379dc4dcfdbf61ccc7d5a0bb9759acf611694f24d0c040f249bad30a83b1a897", basis->u, 32) &&
        zcl_hex_decode("7520d96f3e5cd41760367151608b54821883c10c4b9a4ff2beae227bef94bcab", basis->w, 32);
}

static bool wire_value_case(const struct v6_wire_view *view, size_t i, const uint8_t expected[32])
{
    static const char *const quotients[] = {
        "4b60b489fba78511e7852cdfb8cd499053d50db264e2e389bee82f12d23f9415",
        "b6a266e4e45ca24645108adbdaba49e232a16542d4c6a2fe0635e2bb7c5de02a"
    };
    uint8_t h[32], value[32];
    if (!zcl_hex_decode(quotients[i], h, 32) || !ironwood_postnu63_wire_value(view, h, value).ok ||
        memcmp(value, expected, 32)) return false;
    h[0] ^= 1;
    if (!ironwood_postnu63_wire_value(view, h, value).ok || !memcmp(value, expected, 32)) return false;
    memset(h, 0xff, sizeof h); memcpy(value, expected, 32);
    return !ironwood_postnu63_wire_value(view, h, value).ok && !memcmp(value, expected, 32);
}

static bool pinned_case(const struct v6_wire_view *view, struct ironwood_opening_basis *basis,
                        const uint8_t claim[32], const uint8_t value[32])
{
    bool holds = false;
    if (!ironwood_postnu63_check_claim(view, basis, claim, value, &holds).ok || !holds) return false;
    uint8_t *points[] = {basis->generators[IRONWOOD_IPA_GENERATORS - 1], basis->u, basis->w};
    for (size_t i = 0; i < sizeof points / sizeof points[0]; ++i) {
        points[i][31] ^= 0x80;
        bool refused = !ironwood_postnu63_check_claim(view, basis, claim, value, &holds).ok;
        points[i][31] ^= 0x80;
        if (!refused || !holds) return false;
    }
    return true;
}

/* Upstream single-proof IPA verifier entry, immediately after the final
 * multiopen fold. The commitments combine 77 and 100 logged MSM terms. */
static bool claim_case(const struct v6_wire_view *view, const struct ironwood_postnu63_stage *stage,
                       struct ironwood_opening_basis *basis)
{
    static const char *const commitment_hex[] = {
        "3169e22cbe2c35665fd334b3b5040345f14f0a71abd908fe67273c34cf8ca106",
        "27b1808550d8ce556c79250ae26b071cdde04cd880f7c272b1ba012aa56cdca9"
    };
    static const char *const evaluation_hex[] = {
        "3842e7cc6ad2391040cc392021452cb1fdb9ee44ed59db05feda39ad0075d428",
        "34247345d2f931cdd394eece6af6b051fc6c49c03d5461a827c5dd63c8955d3e"
    };
    if (!stage->actions || stage->actions > 2) return false;
    size_t i = (size_t)stage->actions - 1;
    uint8_t claim[32], value[32];
    if (!zcl_hex_decode(commitment_hex[i], claim, 32) || !zcl_hex_decode(evaluation_hex[i], value, 32))
        return false;
    bool holds = false;
    if (!ironwood_opening_equation(stage, basis, claim, value, &holds).ok || !holds)
        return false;
    if (!wire_value_case(view, i, value) || !pinned_case(view, basis, claim, value)) return false;
    value[0] ^= 1;
    if (!ironwood_opening_equation(stage, basis, claim, value, &holds).ok || holds)
        return false;
    memset(value, 0xff, sizeof value);
    holds = true;
    return !ironwood_opening_equation(stage, basis, claim, value, &holds).ok && holds;
}

bool ironwood_opening_equation_case(const struct v6_wire_view *view, const struct ironwood_postnu63_stage *stage)
{
    struct ironwood_opening_basis *basis = malloc(sizeof *basis);
    if (!basis) return false;
    bool ok = ironwood_opening_query_case((size_t)stage->actions) && read_basis(basis) && claim_case(view, stage, basis);
    free(basis);
    return ok;
}
