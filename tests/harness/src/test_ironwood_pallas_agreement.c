/* purpose: Check synthetic Orchard agreement against pinned upstream evidence. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "../../../engine/services/src/ironwood_pallas_agreement.h"
#include "primitives/transaction_v6_wire.h"
#include "crypto/blake2b.h"
#include "crypto/chacha20poly1305.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include <stdio.h>
#include <string.h>
/* All-zero and [1;32] test spending keys only. Independent Orchard 0.16.0 /
 * pasta_curves 0.6.0 oracle wrong-oracle.rs SHA256
 * 1a809c6866b643579caafc0c83a1587b97c2937ceff950b5bbe6bb4f98369007.
 * p-1 boundary oracle SHA256 ffabafeab1637fe03b3fb668b439b9434954bf8c2b83c774b4c5efb729470084. */
static bool open_note(const uint8_t shared[32], const uint8_t *action, uint8_t plain[564])
{
    static const uint8_t personal[16] = {0x5a,0x63,0x61,0x73,0x68,0x5f,0x4f,0x72,0x63,0x68,0x61,0x72,0x64,0x4b,0x44,0x46};
    static const uint8_t nonce[12] = {0};
    struct blake2b_ctx ctx; uint8_t key[32];
    if (blake2b_init_salt_personal(&ctx,32,NULL,0,NULL,personal) ||
        blake2b_update(&ctx,shared,32) || blake2b_update(&ctx,action+128,32) ||
        blake2b_final(&ctx,key,32)) return false;
    return chacha20poly1305_decrypt(action+160,580,NULL,0,nonce,key,plain);
}
static bool rejected(const uint8_t ivk[32], const uint8_t epk[32])
{
    uint8_t out[32], before[32]; memset(out,0x59,sizeof out); memcpy(before,out,sizeof out);
    return !ironwood_research_pallas_agree(ivk,epk,out).ok && !memcmp(out,before,sizeof out);
}
static bool boundaries(const uint8_t ivk[32], const uint8_t epk[32])
{
    uint8_t zero[32]={0}, one[32]={1}, p[32]={1,0,0,0,0xed,0x30,0x2d,0x99,0x1b,0xf9,0x4c,0x09,0xfc,0x98,0x46,0x22,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x40};
    uint8_t out[32];
    if (!rejected(zero,epk) || !rejected(p,epk) || !rejected(ivk,zero) || !rejected(ivk,p)) return false;
    if (!ironwood_research_pallas_agree(one,epk,out).ok || memcmp(out,epk,32)) return false;
    p[0] = 0;
    uint8_t upper[32];
    if (!zcl_hex_decode("64b6c0d2bc987387e9db2caf87f8b0457081fa2304caa2be5ba6e039774540a3",upper,32) ||
        !ironwood_research_pallas_agree(p,epk,out).ok || memcmp(out,upper,32)) return false;
    memcpy(out,epk,32);
    return ironwood_research_pallas_agree(one,out,out).ok && !memcmp(out,epk,32);
}
static bool fixture_action(uint8_t wire[10000], const uint8_t **action)
{
    FILE *f=fopen("tests/fixtures/ironwood/postnu63-h1-reward-spend.v6","rb");
    if (!f) return false;
    size_t n=fread(wire,1,10000,f); bool ok=!ferror(f) && feof(f);
    if (fclose(f)!=0) ok=false;
    struct v6_wire_view view;
    if (!ok || v6_core_parse(wire,n,&view)!=V6_WIRE_OK || view.ironwood.count!=2 ||
        view.ironwood.actions.size!=1640) return false;
    *action=view.ironwood.actions.data+820;
    return true;
}
static bool fixture(const uint8_t ivk[32], const uint8_t wrong[32], const uint8_t epk[32])
{
    uint8_t wire[10000], shared[32], want[32], plain[564];
    const uint8_t *action = NULL;
    if (!fixture_action(wire, &action)) return false;
    if (memcmp(action+128,epk,32) ||
        !zcl_hex_decode("4d00929d6d5400b85d40ac60273c821345d3a19f73a94a897fecf356fcb44729",want,32) ||
        !ironwood_research_pallas_agree(ivk,epk,shared).ok || memcmp(shared,want,32) ||
        !open_note(shared,action,plain) || zcl_read_u64_le(plain+12)!=1249985000) return false;
    if (!zcl_hex_decode("95571d4bd22454e7319d836cde4ee1a017eef10a11742dde4a52f10cd48183b3",want,32) ||
        !ironwood_research_pallas_agree(wrong,epk,shared).ok || memcmp(shared,want,32)) return false;
    return !open_note(shared,action,plain);
}
int test_ironwood_pallas_agreement(void)
{
    uint8_t ivk[32], wrong[32], epk[32];
    if (!zcl_hex_decode("a1f875872973ea492de3be5ccecfe5567910244cb602994c5800f68c6438b91b",ivk,32) ||
        !zcl_hex_decode("691ab09ae9dc56d92d42d0c9fcc349f03288c3c13acf2de137ef1ba21cc4ee37",wrong,32) ||
        !zcl_hex_decode("54584886e0359da65fb9d846d2f6fb5d6e64869e66b922d02b6c74141004cd2b",epk,32)) return 1;
    return boundaries(ivk,epk) && fixture(ivk,wrong,epk) ? 0 : 1;
}
