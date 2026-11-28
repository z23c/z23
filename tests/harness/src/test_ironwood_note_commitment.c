/* purpose: Check public prepared note commitments against upstream vectors. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_note_commitment.h"
#include "base/hex.h"
#include "primitives/transaction_v6_wire.h"
#include <stdio.h>
#include <string.h>

/* Independent Orchard 0.16.0 / sinsemilla 0.2.0 / pasta_curves 0.6.0
 * prepared-input oracle: gd=generator, pkd=2*generator, rho=7, psi=11,
 * rcm=5, value=1250000000. All inputs are public synthetic values.
 * Oracle source SHA256 4bc275f925a847a695d93be86b424f0f5fbbdfd515bc9c3ddd51c29bc06b1ab7;
 * lock SHA256 7977b0d9894e961585ab192ec11d96029fdbcadc440a37680ed0e6505dfe4704. */
static bool fixture(struct ironwood_note_commitment_public *in, uint8_t expected[32])
{
    memset(in, 0, sizeof *in);
    in->value = 1250000000;
    in->rho[0] = 7; in->psi[0] = 11; in->rcm[0] = 5;
    return zcl_hex_decode("00000000ed302d991bf94c09fc98462200000000000000000000000000000040", in->gd, 32) &&
        zcl_hex_decode("030000b067c50313fcac1144eee2fe0e0000000000000000000000000000001c", in->pkd, 32) &&
        zcl_hex_decode("d616e31cc8e92456641d355d27867e242c56b0ccc59e43bc4b0ecb429b9ae623", expected, 32);
}
static bool changed_rejected(struct ironwood_note_commitment_public *in, const uint8_t expected[32])
{
    uint8_t out[32], wrong[32];
    uint8_t changed[32];
    if (!zcl_hex_decode("30c2150e82ff977563e85421e74547ebfe734650cf8941668120b2cf59baa928", changed, 32)) return false;
    ++in->value;
    bool ok = ironwood_note_commitment_compute_public(in, out).ok && !memcmp(out, changed, 32) && memcmp(out, expected, 32);
    --in->value;
    memcpy(wrong, expected, 32); wrong[0] ^= 1;
    return ok && ironwood_note_commitment_compute_public(in, out).ok && memcmp(out, wrong, 32);
}
static bool invalid_rejected(struct ironwood_note_commitment_public *in)
{
    uint8_t out[32], before[32];
    memset(out, 0xa5, sizeof out); memcpy(before, out, sizeof out);
    memset(in->rho, 0xff, 32);
    if (ironwood_note_commitment_compute_public(in, out).ok || memcmp(out, before, 32)) return false;
    memset(in->rho, 0, 32); in->rho[0] = 7;
    memset(in->gd, 0, 32);
    if (ironwood_note_commitment_compute_public(in, out).ok || memcmp(out, before, 32)) return false;
    uint8_t expected[32];
    if (!fixture(in, expected)) return false;
    memset(in->rcm, 0xff, 32);
    return !ironwood_note_commitment_compute_public(in, out).ok && !memcmp(out, before, 32);
}
/* Orchard 0.16 decrypts the public synthetic H144 reward and derives these
 * prepared values; native compares the result to the actual action cmx.
 * Oracle source SHA256 c5367e48058298eae33910fccea9a3be562c5d4963920149aebac3bd11b8601d,
 * lock aa7a18398626c85fdb8cf35c15e876b6c8a1a84ccdd885c7cd7339c975b66e26;
 * reward wire SHA256 e5595701e68f6de986cae48161aa05042bf4b1c78b31b8206606934181c44143.
 * The prepared values are public fixture data, not a wallet derivation. */
static bool direct_prepared(struct ironwood_note_commitment_public *in)
{
    memset(in, 0, sizeof *in);
    in->value = 1250000000;
    return zcl_hex_decode("b95dc703ea442cae0d299cdb3a4766c663a255b6058d01217257492833901e82", in->gd, 32) &&
        zcl_hex_decode("a75c17c3a668a97f0d6a8c5ce164a518ea9ba9a50ea75191fd861b0ff10e62b0", in->pkd, 32) &&
        zcl_hex_decode("d786245b3ebf8c0664562a12274c524fca17555847dccd9c808430dfb0d4a905", in->rho, 32) &&
        zcl_hex_decode("7be4b6a6be76326fcf077f01e2870c44b0861ee5748fee4a217af878c84d2f2f", in->psi, 32) &&
        zcl_hex_decode("bfe702aabd01887ce663057982b2d95942d4e7f61701dc8c70ea92cd2c7b3a1c", in->rcm, 32);
}
static bool direct_reward_commitment(void)
{
    uint8_t wire[7000], computed[32], changed[32];
    FILE *f = fopen("tests/fixtures/ironwood/direct-reward-note.v6", "rb");
    if (!f) return false;
    size_t n = fread(wire, 1, sizeof wire, f);
    bool ok = !ferror(f) && feof(f) && n == 6054;
    if (fclose(f)) ok = false;
    struct v6_wire_view view;
    struct v6_action_view action;
    struct ironwood_note_commitment_public in;
    if (!ok || v6_core_parse(wire,n,&view)!=V6_WIRE_OK || view.ironwood.count!=1 ||
        !v6_core_bundle_action(&view.ironwood,0,&action) || !direct_prepared(&in) ||
        memcmp(in.rho,action.nullifier.data,32)) return false;
    if (!ironwood_note_commitment_compute_public(&in,computed).ok || memcmp(computed,action.cmx.data,32)) return false;
    ++in.value;
    if (!ironwood_note_commitment_compute_public(&in,changed).ok || !memcmp(changed,action.cmx.data,32)) return false;
    memcpy(changed,action.cmx.data,32); changed[0] ^= 1;
    return memcmp(computed,changed,32) != 0;
}
int test_ironwood_note_commitment(void)
{
    struct ironwood_note_commitment_public in;
    uint8_t expected[32], out[32];
    bool ok = fixture(&in, expected) && ironwood_note_commitment_compute_public(&in, out).ok &&
        !memcmp(out, expected, 32) && changed_rejected(&in, expected) && invalid_rejected(&in) &&
        direct_reward_commitment();
    if (!ok) fprintf(stderr, "Ironwood prepared note commitment fixture failed\n");
    return ok ? 0 : 1;
}
