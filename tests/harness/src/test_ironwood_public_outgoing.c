/* purpose: Verify public Ironwood outgoing recovery against a reward fixture. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_public_outgoing.h"
#include "primitives/transaction_v6_wire.h"
#include "crypto/sha256.h"
#include "base/hex.h"
#include <stdio.h>
#include <string.h>
/* Public H144 reward, opened independently with Orchard 0.16 and AEAD. */
static bool from_wire(struct ironwood_public_outgoing_input *in)
{
    uint8_t wire[10000], digest[32], expected[32]; struct v6_wire_view view;
    FILE *f = fopen("tests/fixtures/ironwood/direct-reward-note.v6", "rb");
    if (!f) return false;
    size_t n = fread(wire, 1, sizeof wire, f); bool ok = !ferror(f) && feof(f);
    if (fclose(f)) ok = false;
    struct sha256_ctx hash;
    sha256_init(&hash); sha256_write(&hash, wire, n); sha256_finalize(&hash, digest);
    if (!ok || !zcl_hex_decode("e5595701e68f6de986cae48161aa05042bf4b1c78b31b8206606934181c44143", expected, 32) ||
        memcmp(digest, expected, 32) || v6_core_parse(wire, n, &view) != V6_WIRE_OK ||
        !view.ironwood.count || view.ironwood.actions.size < 820) return false;
    const uint8_t *a = view.ironwood.actions.data;
    memcpy(in->cv, a, 32); memcpy(in->cmx, a + 96, 32);
    memcpy(in->epk, a + 128, 32); memcpy(in->ciphertext, a + 740, 80);
    return true;
}
int test_ironwood_public_outgoing(void)
{
    struct ironwood_public_outgoing_input in;
    struct ironwood_public_outgoing_plaintext out, expected, before;
    uint8_t ovk[32] = {0};
    if (!from_wire(&in) ||
        !zcl_hex_decode("a75c17c3a668a97f0d6a8c5ce164a518ea9ba9a50ea75191fd861b0ff10e62b0", expected.pk_d, 32) ||
        !zcl_hex_decode("15f59383289da61a8f42ece443f9002ff988d275b34315b3a98529edc616ca24", expected.esk, 32) ||
        !ironwood_public_outgoing_recover(&in, ovk, &out).ok || memcmp(&out, &expected, sizeof out)) return 1;
    memset(&out, 0x5a, sizeof out); before = out; ovk[0] = 1;
    if (ironwood_public_outgoing_recover(&in, ovk, &out).ok || memcmp(&out, &before, sizeof out)) return 1;
    ovk[0] = 0; in.ciphertext[0] ^= 1;
    if (ironwood_public_outgoing_recover(&in, ovk, &out).ok || memcmp(&out, &before, sizeof out)) return 1;
    in.ciphertext[0] ^= 1; in.ciphertext[79] ^= 1;
    if (ironwood_public_outgoing_recover(&in, ovk, &out).ok || memcmp(&out, &before, sizeof out)) return 1;
    return 0;
}
