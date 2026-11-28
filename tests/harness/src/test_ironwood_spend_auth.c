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
int test_ironwood_spend_auth(void)
{
    bool ok = check_case(0) && check_case(1);
    printf("Ironwood spend authorization: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
