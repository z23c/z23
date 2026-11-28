/* purpose: Check public RedPallas action signature verification vectors. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_spend_auth.h"
#include "controllers/transaction_v6_digest.h"
#include "controllers/transaction_v6_inspect.h"
#include "controllers/transaction_v6_sighash.h"
#include "base/serialize_le.h"
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

static bool check_binding_refusals(uint8_t cv[2][32], uint8_t sig[64], uint8_t msg[32])
{
    uint8_t key[32], before[32];
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

static bool check_binding(void)
{
    uint8_t cv[2][32], sig[64], msg[32];
    if (!zcl_hex_decode("1ab7122ad5e623a7d8cc2ae609bdc36a9416c833a5af2db40378211396f7bd80", cv[0], 32) ||
        !zcl_hex_decode("ad322be6ba6669192897b02d2322a2914eff0645ef900da1485453345a79ae16", cv[1], 32) ||
        !zcl_hex_decode("43c027b68d25c52b118a2a83a39a651b84029c824bbe3c01bcc1e8a0e9b98202"
                        "1107ddbc49f6587fa189de3339a772725fde4789a9203d3ced55f5d71c93470b", sig, 64) ||
        !zcl_hex_decode("19a61a86bd739ad0ffc008dcc239d68bfe79a6b5d2f2488de17d08059fdc905a", msg, 32) ||
        !check_binding_keys(cv) || !ironwood_binding_auth_verify(cv, 2, -200000, sig, msg).ok) return false;
    return check_binding_refusals(cv, sig, msg);
}

/* Public funded transaction SHA256 09733416ff3f21a0cca4fecc2bbd6ad2f59248a645db01152e4020015038ed54.
 * Upstream ZIP 244 S.2 uses the txid transparent digest when vin is empty,
 * so ZIP 229 txid bytes are this shielded signature hash. This equivalence
 * does not hold for ordinary transparent inputs, which require prevouts. */
static bool check_binding_wire(const uint8_t *wire, size_t size)
{
    uint8_t cv[2][32], expected[32], sighash[32];
    struct v6_wire_view v; struct v6_digests d; struct v6_action_view a;
    if (v6_wire_parse(wire, size, &v) != V6_WIRE_OK || v.inputs != 0 ||
        v.ironwood.count != 2 || v.ironwood.value_balance.size != 8 ||
        v.ironwood.binding_signature.size != 64 || !v6_wire_digests(&v, &d) ||
        !zcl_hex_decode("19a61a86bd739ad0ffc008dcc239d68bfe79a6b5d2f2488de17d08059fdc905a", expected, 32) ||
        memcmp(d.txid, expected, 32) || !v6_shielded_sighash(&v, NULL, 0, sighash) ||
        memcmp(sighash, expected, 32)) return false;
    for (size_t i = 0; i < 2; ++i) {
        if (!v6_bundle_action(&v.ironwood, i, &a) || a.cv.size != 32) return false;
        memcpy(cv[i], a.cv.data, 32);
    }
    int64_t balance = zcl_read_i64_le(v.ironwood.value_balance.data);
    return balance == -200000 &&
        ironwood_binding_auth_verify(cv, 2, balance, v.ironwood.binding_signature.data, sighash).ok;
}

static bool check_binding_transaction(void)
{
    uint8_t wire[11518];
    FILE *f = fopen("tests/fixtures/ironwood/postnu63-two-action-payment.bin", "rb");
    if (!f) return false;
    bool ok = fread(wire, 1, sizeof wire, f) == sizeof wire && fgetc(f) == EOF && !ferror(f);
    if (fclose(f) != 0 || !ok) return false;
    return check_binding_wire(wire, sizeof wire);
}

/* Independent librustzcash v6 PrecomputedSighashData oracle: one non-coinbase
 * input, prevout value 123456 and scriptPubKey OP_TRUE. This fixture is public
 * synthetic data, not an authorization of a spend. */
static bool check_sighash_boundary(const struct v6_wire_view *v);
static bool check_coinbase_sighash(uint8_t *wire, size_t size);
static bool check_transparent_sighash(void)
{
    static const char wire_hex[] = "0600008098b684d85b16a537000000000000000001"
        "0101010101010101010101010101010101010101010101010101010101010101"
        "0100000000feffffff0000000000";
    uint8_t wire[(sizeof wire_hex - 1) / 2], want[32], out[32], before[32];
    uint8_t script_bytes[] = {0x51};
    struct v6_prevout prev = {123456, {script_bytes, sizeof script_bytes}};
    struct v6_wire_view v;
    if (!zcl_hex_decode(wire_hex, wire, sizeof wire) ||
        !zcl_hex_decode("108db092f0363d0685a3e3ef538b5b295ad1d403549bcff1438e719f6cdb3661", want, 32) ||
        v6_core_parse(wire, sizeof wire, &v) != V6_WIRE_OK || v.inputs != 1 ||
        !v6_shielded_sighash(&v, &prev, 1, out) || memcmp(out, want, 32)) return false;
    if (!check_sighash_boundary(&v)) return false;
    prev.amount++;
    if (!v6_shielded_sighash(&v, &prev, 1, out) || !memcmp(out, want, 32)) return false;
    prev.amount--; script_bytes[0] ^= 1;
    if (!v6_shielded_sighash(&v, &prev, 1, out) || !memcmp(out, want, 32)) return false;
    memset(out, 0xa5, 32); memcpy(before, out, 32);
    return !v6_shielded_sighash(&v, NULL, 0, out) && !memcmp(out, before, 32) &&
        check_coinbase_sighash(wire, sizeof wire);
}

static bool check_coinbase_sighash(uint8_t *wire, size_t size)
{
    memset(wire + 21, 0, 32); memset(wire + 53, 0xff, 4);
    struct v6_wire_view v; struct v6_digests d; uint8_t out[32];
    return v6_core_parse(wire, size, &v) == V6_WIRE_OK && v.inputs == 1 &&
        v6_wire_digests(&v, &d) && v6_shielded_sighash(&v, NULL, 0, out) &&
        !memcmp(out, d.txid, 32);
}

static bool check_sighash_boundary(const struct v6_wire_view *v)
{
    uint8_t script[253], expected[32], out[32], before[32];
    memset(script, 0x51, sizeof script);
    struct v6_prevout p = {123456, {script, sizeof script}};
    if (!zcl_hex_decode("2fc76bb0b0afb6c9c5d0984d7041ff7f6e968e1886f362da14a95fc853441be3", expected, 32) ||
        !v6_shielded_sighash(v, &p, 1, out) || memcmp(out, expected, 32)) return false;
    memset(out, 0xa5, 32); memcpy(before, out, 32);
    p.script_pubkey.data = NULL;
    if (v6_shielded_sighash(v, &p, 1, out) || memcmp(out, before, 32)) return false;
    p.script_pubkey.data = script; p.script_pubkey.size = 10001;
    if (v6_shielded_sighash(v, &p, 1, out) || memcmp(out, before, 32)) return false;
    p.script_pubkey.size = 1; p.amount = UINT64_MAX;
    return !v6_shielded_sighash(v, &p, 1, out) && !memcmp(out, before, 32);
}

int test_ironwood_spend_auth(void)
{
    bool ok = check_case(0) && check_case(1) && check_binding() && check_binding_transaction() && check_transparent_sighash();
    printf("Ironwood spend authorization: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
