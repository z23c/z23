/* purpose: Check public RedPallas action signature verification vectors. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_spend_auth.h"
#include "base/hex.h"
#include <stdio.h>
#include <string.h>

/* Two actions in independently checked funded Ironwood bundle. Bundle SHA256:
 * 8ad077583faf016a1fd9749b451dbf4380243e6f1865df0fd199dfd1a7f1c7c8.
 * The supplied sighash is the transaction signature hash, not the txid. */
static const char *keys[] = {
    "c50a43c49ac39b165b12a4aa7ab3dc4d14e4eb086ea76ffd0eeaa2f5b11a7e09",
    "2895d3104f55f65db89b4e843a8714281f0ff7f0638a42101f7db9e7d5e9558f"
};
static const char *signatures[] = {
    "9e354cc94a770ed7207b27a0d102f3ce8d7b1b4d123f443cc9c2b0b2d5f1ff3a"
    "6b888721296b1ffc7d1ecbcc5ceaa495b8de97eecd9d06f56fd8cd5614aaaa1c",
    "08df5030b25d1dd09868feccccb2282ed4ee505a71e586caa11fcf6b3e7f072b"
    "3fef65ea7689bd5087ae0278caba68173c3cd15205069ff26502c533bdd6f22e"
};
static bool check_case(size_t i)
{
    uint8_t key[32], sig[64], msg[32], bad[64];
    if (!zcl_hex_decode(keys[i], key, 32) || !zcl_hex_decode(signatures[i], sig, 64) ||
        !zcl_hex_decode("19a61a86bd739ad0ffc008dcc239d68bfe79a6b5d2f2488de17d08059fdc905a", msg, 32) ||
        !ironwood_spend_auth_verify(key, sig, msg).ok) return false;
    msg[0] ^= 1;
    if (ironwood_spend_auth_verify(key, sig, msg).ok) return false;
    msg[0] ^= 1;
    memcpy(bad, sig, 64); bad[0] ^= 1;
    if (ironwood_spend_auth_verify(key, bad, msg).ok) return false;
    memcpy(bad, sig, 64); bad[32] ^= 1;
    if (ironwood_spend_auth_verify(key, bad, msg).ok) return false;
    memset(bad + 32, 0xff, 32);
    if (ironwood_spend_auth_verify(key, bad, msg).ok) return false;
    memset(bad, 0xff, 32); memcpy(bad + 32, sig + 32, 32);
    if (ironwood_spend_auth_verify(key, bad, msg).ok) return false;
    if (!zcl_hex_decode("0100000021eb468cdda89409fc98462200000000000000000000000000000040", bad + 32, 32)) return false;
    memcpy(bad, sig, 32);
    if (ironwood_spend_auth_verify(key, bad, msg).ok) return false;
    key[0] ^= 1;
    if (ironwood_spend_auth_verify(key, sig, msg).ok) return false;
    memset(key, 0, 32); memset(bad, 0, 64);
    return !ironwood_spend_auth_verify(key, bad, msg).ok &&
        !ironwood_spend_auth_verify(NULL, sig, msg).ok;
}
static bool check_binding_keys(const uint8_t cv[2][32])
{
    static const int64_t balances[] = {-200000, 0, 200000, INT64_MIN};
    static const char *expected[] = {
        "1ce71c92078cc5ba866fa27635a07b166f031181104412c0fc135889d2f00c20",
        "d73233b085c958baaff91837a0ad051789d9af9f2e336240a1a4abf36b799d9a",
        "f0bbc3593025f61f8a0052edf002ff3e14125bb7a0b308f9594f69ebb752f91b",
        "2e4d6842cd90f5b0812f8887ac776077a2a721b3a7fed8dcc9c40dc4265786b3"};
    uint8_t key[32], want[32];
    for (size_t i = 0; i < 4; ++i)
        if (!zcl_hex_decode(expected[i], want, 32) ||
            !ironwood_binding_key(cv, 2, balances[i], key).ok || memcmp(key, want, 32)) return false;
    return true;
}

static bool check_binding(void)
{
    uint8_t cv[2][32], sig[64], msg[32], key[32], before[32];
    if (!zcl_hex_decode("1ab7122ad5e623a7d8cc2ae609bdc36a9416c833a5af2db40378211396f7bd80", cv[0], 32) ||
        !zcl_hex_decode("ad322be6ba6669192897b02d2322a2914eff0645ef900da1485453345a79ae16", cv[1], 32) ||
        !zcl_hex_decode("43c027b68d25c52b118a2a83a39a651b84029c824bbe3c01bcc1e8a0e9b98202"
                        "1107ddbc49f6587fa189de3339a772725fde4789a9203d3ced55f5d71c93470b", sig, 64) ||
        !zcl_hex_decode("19a61a86bd739ad0ffc008dcc239d68bfe79a6b5d2f2488de17d08059fdc905a", msg, 32) ||
        !check_binding_keys(cv) || !ironwood_binding_auth_verify(cv, 2, -200000, sig, msg).ok) return false;
    if (!ironwood_binding_key(cv, 2, -200000, key).ok ||
        ironwood_spend_auth_verify(key, sig, msg).ok ||
        ironwood_binding_auth_verify(cv, 2, 200000, sig, msg).ok) return false;
    msg[0] ^= 1;
    if (ironwood_binding_auth_verify(cv, 2, -200000, sig, msg).ok) return false;
    msg[0] ^= 1; sig[0] ^= 1;
    if (ironwood_binding_auth_verify(cv, 2, -200000, sig, msg).ok) return false;
    memset(cv[0], 0, 32); memset(sig, 0, 64);
    if (!ironwood_binding_auth_verify(cv, 1, 0, sig, msg).ok) return false;
    memset(key, 0xa5, 32); memcpy(before, key, 32); memset(cv[0], 0xff, 32);
    return !ironwood_binding_key(cv, 2, -200000, key).ok && !memcmp(key, before, 32) &&
        !ironwood_binding_key(cv, 0, -200000, key).ok &&
        !ironwood_binding_key(cv, SIZE_MAX / 32 + 1, -200000, key).ok && !memcmp(key, before, 32);
}

int test_ironwood_spend_auth(void)
{
    bool ok = check_case(0) && check_case(1) && check_binding();
    printf("Ironwood spend authorization: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
