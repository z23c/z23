/* purpose: Verify v6 transparent sighashes and a signed public P2PKH fixture. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "controllers/transaction_v6_transparent.h"
#include "base/hex.h"
#include "script/script_flags.h"
#include <stdio.h>
#include <string.h>

/* Upstream librustzcash offline oracle: two inputs/two outputs, each of the
 * six ZIP 244 modes. R1 evidence ironwood-transparent-oracle-1128/oracle.rs;
 * vectors SHA256 04cfa243da67302dba8027020e7ba8bfd277b2d736515611a889ffca946ce449. */
static bool refuse_invalid(uint8_t *wire, size_t size, struct transaction_v6_prevout *prev)
{
    uint8_t result[32], before[32];
    memset(result, 0xa5, sizeof result); memcpy(before, result, sizeof before);
    if (v6_transparent_sighash(wire, size, prev, 2, 0, 0, 0x37a5165b, result).ok || memcmp(result,before,32) ||
        v6_transparent_sighash(wire, size, prev, 1, 0, 1, 0x37a5165b, result).ok || memcmp(result,before,32) ||
        v6_transparent_sighash(wire, size, prev, 2, 2, 1, 0x37a5165b, result).ok || memcmp(result,before,32) ||
        v6_transparent_sighash(wire, size, prev, 2, 0, 1, 0x37a5165a, result).ok || memcmp(result,before,32)) return false;
    /* Remove both ten-byte outputs, preserving the four empty bundle counts. */
    wire[103] = 0;
    memmove(wire + 104, wire + 124, 4);
    return !v6_transparent_sighash(wire, 108, prev, 2, 0, 3, 0x37a5165b, result).ok &&
        !memcmp(result, before, 32) &&
        !v6_transparent_sighash(wire, 108, prev, 2, 0, 0x83, 0x37a5165b, result).ok &&
        !memcmp(result, before, 32);
}
static bool six_modes(void)
{
    static const char wire_hex[] =
        "0600008098b684d85b16a53700000000000000000201010101010101010101010101010101010101010101010101010101010101010100000000fdffffff"
        "02020202020202020202020202020202020202020202020202020202020202020200000000fcffffff02e8030000000000000151d007000000000000015200000000";
    static const char *expected[2][6] = {
      {"e8de8722f2b7d0cb920ae16b389766688f5df91e5b8815773d105791b9b72ee6", "f5f7f94a360ec96d08edf5daf3ace779bb3ca36373eda1ac171315e3644fec50", "f8342e86767f0d3b0118c89cafda2304c6fc33e4f3aa069f234b5b741f0ddfb0", "5a2a6fcdbab15861179d99f7089376a668af65dc9fc5d2454acd3b9bc0d215c6", "6d0106072ad98b08c6661521d9a7febc57420c96bed40a908344c1425ff04f5f", "2a25f97c72b2f800ce823e0ebad3219a0f55483720453968d849817030bbfb75"},
      {"de8fd5a4bbf57615a8efa5f2c5861c306fcc243239931e09bbc8c3c5b66ae98d", "b71a044a6a0e2308a2d4862fd99ba262e98725f06b406b92e5e380c2a5ded352", "216e73135b2ffdf248b6a5d36735b292d7e5a56ee09cbf7900339c3712548481", "38a18c0a09870f06e7dc7b0fd14426921f81d8772099e653e8f82f58f114d263", "96233e905d941ecb02fbbdc90cb258e16f3c3a7569484038a733411356144abe", "fe8a9eb321c21bb9ea2f038639b99a2dcb3e0367c6f39cd30de30a210e3eb023"}
    };
    static const uint8_t types[] = {1,2,3,0x81,0x82,0x83}, scripts[] = {0x51,0x52};
    uint8_t wire[(sizeof wire_hex - 1)/2], result[32], want[32];
    struct transaction_v6_prevout prev[] = {{123456,scripts,1}, {654321,scripts+1,1}};
    if (!zcl_hex_decode(wire_hex, wire, sizeof wire)) return false;
    for (size_t i = 0; i < 2; i++) for (size_t j = 0; j < 6; j++) {
        if (!zcl_hex_decode(expected[i][j], want, sizeof want) ||
            !v6_transparent_sighash(wire, sizeof wire, prev, 2, i, types[j], 0x37a5165b, result).ok ||
            memcmp(result, want, sizeof want)) return false;
    }
    return refuse_invalid(wire, sizeof wire, prev);
}
static bool check_cltv_script_sig(const uint8_t wire[9313], const struct transaction_v6_prevout *prev)
{
    uint8_t modified[9316];
    if (wire[57] >= 250) return false;
    memcpy(modified, wire, 58);
    modified[57] += 3;
    modified[58] = 0x51; modified[59] = 0xb1; modified[60] = 0x75;
    memcpy(modified + 61, wire + 58, 9313 - 58);
    return v6_transparent_verify_p2pkh(modified, sizeof modified, prev, 1, 0, 0x37a5165b, 0).ok &&
        !v6_transparent_verify_p2pkh(modified, sizeof modified, prev, 1, 0, 0x37a5165b,
                                     SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY).ok;
}
static bool signed_p2pkh(void)
{
    uint8_t wire[9313], script[25];
    FILE *f = fopen("tests/fixtures/ironwood/postnu63-h1-reward-spend.v6", "rb");
    if (!f) return false;
    bool ok = fread(wire, 1, sizeof wire, f) == sizeof wire && fgetc(f) == EOF && !ferror(f);
    if (fclose(f) != 0 || !ok || !zcl_hex_decode("76a91479b000887626b294a914501a4cd226b58b23598388ac", script, sizeof script)) return false;
    struct transaction_v6_prevout prev = {1250000000,script,sizeof script};
    if (!v6_transparent_verify_p2pkh(wire, sizeof wire, &prev, 1, 0, 0x37a5165b,
                                     SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC).ok ||
        v6_transparent_verify_p2pkh(wire, sizeof wire, &prev, 1, 0, 0x37a5165a, 0).ok ||
        !check_cltv_script_sig(wire, &prev)) return false;
    prev.amount++;
    if (v6_transparent_verify_p2pkh(wire, sizeof wire, &prev, 1, 0, 0x37a5165b, 0).ok) return false;
    prev.amount--; script[4] ^= 1;
    if (v6_transparent_verify_p2pkh(wire, sizeof wire, &prev, 1, 0, 0x37a5165b, 0).ok) return false;
    script[4] ^= 1; wire[21] ^= 1;
    if (v6_transparent_verify_p2pkh(wire, sizeof wire, &prev, 1, 0, 0x37a5165b, 0).ok) return false;
    wire[21] ^= 1; wire[65] ^= 1;
    return !v6_transparent_verify_p2pkh(wire, sizeof wire, &prev, 1, 0, 0x37a5165b, 0).ok;
}
int test_v6_transparent(void) { return six_modes() && signed_p2pkh() ? 0 : 1; }
