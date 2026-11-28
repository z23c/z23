/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "controllers/transaction_v6_inspect.h"
#include "controllers/transaction_v6_digest.h"
#include "controllers/transaction_v6_rpc.h"
#include "services/ironwood_instance.h"
#include "base/hex.h"
#include "encoding/utilstrencodings.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "transaction_v6_ironwood_fixture.h"

/* ZIP 229 empty_orchard_and_ironwood upstream conformance vector. */
static const uint8_t empty[] = {6,0,0,128,0x98,0xb6,0x84,0xd8,0x5b,0x16,0xa5,0x37,
    0x51,0xce,0x52,0xe8,0x5c,0x0e,0x5f,0x0f,0,0,0,0,0,0};
static const char expected_txid[] = "6657f1febe7ff9a032381517ce4720db94b18a3dea11a17ce075ec3f9928bfc3";
static const char expected_auth[] = "556216ed932aec11e616a6911ed695bb0810c3ca9c2fe1aba2caf9da62cf5866";
static bool digest_matches(const uint8_t *digest, const char *hex)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i)
        if (hex[2*i] != digits[digest[i] >> 4] || hex[2*i+1] != digits[digest[i] & 15]) return false;
    return true;
}
static bool check_rpc_fields(const struct json_value *result)
{
    return json_get_int(json_get(result, "version")) == 6 &&
        strcmp(json_get_str(json_get(result, "versiongroupid")), "d884b698") == 0 &&
        strcmp(json_get_str(json_get(result, "consensusbranchid")), "37a5165b") == 0 &&
        json_get_int(json_get(result, "expiryheight")) == 342222801 &&
        json_get_int(json_get(result, "ironwood_actions")) == 1 &&
        json_get_int(json_get(result, "ironwood_value_balance_zat")) == 1000 &&
        json_get_str(json_get(result, "ironwood_anchor")) &&
        !strcmp(json_get_str(json_get(result, "ironwood_anchor")),
                "892d5610b098e88ee17a516ad45c307ff93b9fda61ad8738e2b4fafa75d5cf24") &&
        json_get(result, "vin") && json_get(result, "vout") &&
        strcmp(json_get_str(json_get(result, "txid")), expected_txid) == 0 &&
        strcmp(json_get_str(json_get(result, "authdigest")), expected_auth) == 0;
}
static bool check_rpc_branch(char *hex, struct json_value *result)
{
    hex[17] = 'a';
    return transaction_v6_rpc_decode(hex, result) == V6_RPC_OK &&
        strcmp(json_get_str(json_get(result, "consensusbranchid")), "37a5165a") == 0 &&
        strcmp(json_get_str(json_get(result, "txid")), expected_txid) != 0 &&
        strcmp(json_get_str(json_get(result, "authdigest")), expected_auth) != 0;
}
static bool check_v6_rpc_view(void)
{
    size_t n = sizeof ironwood_anchor_a;
    char *hex = malloc(2*n + 1);
    if (!hex) return false;
    HexStr(ironwood_anchor_a, n, false, hex, 2*n + 1);
    struct json_value result;
    json_init(&result);
    bool ok = transaction_v6_rpc_decode(hex, &result) == V6_RPC_OK && check_rpc_fields(&result);
    ok = ok && check_rpc_branch(hex, &result);
    hex[2*n - 2] = 0;
    ok = ok && transaction_v6_rpc_decode(hex, &result) == V6_RPC_INVALID;
    json_free(&result);
    free(hex);
    return ok;
}
static bool check_v6_rpc_budget(void)
{
    enum { INPUTS = 4000, SIZE = 20 + 3 + INPUTS * 41 + 5 };
    uint8_t *wire = calloc(SIZE, 1);
    char *hex = malloc(2 * SIZE + 1);
    if (!wire || !hex) { free(wire); free(hex); return false; }
    memcpy(wire, ironwood_anchor_a, 20);
    wire[20] = 253; wire[21] = 0xa0; wire[22] = 0x0f;
    HexStr(wire, SIZE, false, hex, 2 * SIZE + 1);
    struct json_value result;
    json_init(&result);
    bool ok = transaction_v6_rpc_decode(hex, &result) == V6_RPC_RESOURCE;
    json_free(&result);
    free(hex); free(wire);
    return ok;
}
static bool check_v6_rpc_projection_limit(void)
{
    enum { SIZE = 20 + 1 + 36 + 3 + 10001 + 4 + 5 };
    uint8_t *wire = calloc(SIZE, 1);
    char *hex = malloc(2 * SIZE + 1);
    if (!wire || !hex) { free(wire); free(hex); return false; }
    memcpy(wire, ironwood_anchor_a, 20);
    wire[20] = 1; wire[57] = 253; wire[58] = 0x11; wire[59] = 0x27;
    HexStr(wire, SIZE, false, hex, 2 * SIZE + 1);
    struct json_value result;
    json_init(&result);
    bool ok = transaction_v6_rpc_decode(hex, &result) == V6_RPC_RESOURCE;
    json_free(&result);
    free(hex); free(wire);
    return ok;
}

static bool check_balance_case(uint64_t raw, int64_t expected)
{
    uint8_t wire[sizeof ironwood_anchor_a];
    memcpy(wire, ironwood_anchor_a, sizeof wire);
    uint8_t *amount = wire + 847;
    for (size_t i = 0; i < 8; i++) amount[i] = (uint8_t)(raw >> (8 * i));
    char hex[2 * sizeof wire + 1];
    HexStr(wire, sizeof wire, false, hex, sizeof hex);
    struct json_value result;
    json_init(&result);
    bool ok = transaction_v6_rpc_decode(hex, &result) == V6_RPC_OK;
    const struct json_value *balance = json_get(&result, "ironwood_value_balance_zat");
    ok = ok && balance && balance->type == JSON_INT && json_get_int(balance) == expected;
    json_free(&result);
    return ok;
}

static bool check_balance_cases(void)
{
    return check_balance_case(0, 0) && check_balance_case(123456789, 123456789) &&
        check_balance_case(UINT64_MAX, -1) && check_balance_case(UINT64_C(0x8000000000000000), INT64_MIN);
}


static bool check_empty_rpc(void)
{
    char hex[sizeof(empty) * 2 + 1];
    HexStr(empty, sizeof empty, false, hex, sizeof hex);
    struct json_value result;
    json_init(&result);
    bool ok = transaction_v6_rpc_decode(hex, &result) == V6_RPC_OK &&
        !json_get(&result, "ironwood_anchor") && !json_get(&result, "ironwood_value_balance_zat");
    json_free(&result);
    return ok;
}

static bool check_action_bundle_layout(const struct v6_bundle *bundle,
                                       const struct v6_action_view *first)
{
    return bundle->flags.size == 1 && bundle->binding_signature.size == 64 &&
        bundle->signatures.size == 128 && first->cv.data == bundle->actions.data &&
        first->rk.data == bundle->actions.data + 64 && first->cv.size == 32 &&
        first->rk.size == 32;
}

static bool check_action_signature_layout(const struct v6_bundle *bundle,
                                          const struct v6_action_view *first,
                                          const struct v6_action_view *second)
{
    return first->signature.data == bundle->signatures.data &&
        first->signature.size == 64 &&
        second->signature.data == bundle->signatures.data + 64 &&
        second->signature.size == 64 && first->nullifier.size == 32 &&
        first->cmx.size == 32 && second->nullifier.size == 32 &&
        second->cmx.size == 32;
}

static bool check_action_contents(const struct v6_wire_view *original,
                                  const struct v6_action_view *first,
                                  const struct v6_action_view *second)
{
    if (memcmp(first->nullifier.data, original->ironwood.actions.data + 32, 32) ||
        memcmp(first->cmx.data, original->ironwood.actions.data + 96, 32))
        return false;
    for (size_t i = 0; i < 32; ++i)
        if (second->nullifier.data[i] != 0x27 || second->cmx.data[i] != 0x64)
            return false;
    return true;
}

static bool check_action_values(const struct v6_bundle *bundle,
                                const struct v6_wire_view *original)
{
    struct v6_action_view first, second;
    if (!v6_bundle_action(bundle, 0, &first) ||
        !v6_bundle_action(bundle, 1, &second)) return false;
    return check_action_bundle_layout(bundle, &first) &&
        check_action_signature_layout(bundle, &first, &second) &&
        check_action_contents(original, &first, &second);
}
static bool check_action_failures(const struct v6_wire_view *v, const struct v6_wire_view *absent)
{
    struct v6_action_view out = { .nullifier = {empty, 1} };
    struct v6_bundle short_signatures = v->ironwood;
    short_signatures.signatures.size = 64;
    return !v6_bundle_action(&short_signatures, 1, &out) &&
        !v6_bundle_action(&v->ironwood, 2, &out) &&
        !v6_bundle_action(&absent->ironwood, 0, &out) &&
        !v6_bundle_action(NULL, 0, &out) && !v6_bundle_action(&v->ironwood, 0, NULL) &&
        out.nullifier.data == empty && out.nullifier.size == 1;
}
static bool check_action_views(void)
{
    struct v6_wire_view original, parsed, absent;
    if (v6_wire_parse(ironwood_anchor_a, sizeof ironwood_anchor_a, &original) != V6_WIRE_OK ||
        v6_wire_parse(empty, sizeof empty, &absent) != V6_WIRE_OK ||
        original.ironwood.count != 1 || original.ironwood.actions.size != 820) return false;
    size_t prefix = (size_t)(original.ironwood.actions.data - ironwood_anchor_a);
    size_t n = sizeof ironwood_anchor_a;
    uint8_t *wire = malloc(n + 884);
    if (!wire) return false;
    memcpy(wire, ironwood_anchor_a, prefix + 820);
    memcpy(wire + prefix + 820, wire + prefix, 820);
    memset(wire + prefix + 820 + 32, 0x27, 32);
    memset(wire + prefix + 820 + 96, 0x64, 32);
    memcpy(wire + prefix + 1640, ironwood_anchor_a + prefix + 820, n - prefix - 820 - 64);
    memset(wire + n + 820 - 64, 0x39, 64);
    memcpy(wire + n + 820, ironwood_anchor_a + n - 64, 64);
    wire[prefix - 1] = 2;
    bool ok = v6_wire_parse(wire, n + 884, &parsed) == V6_WIRE_OK &&
        check_action_values(&parsed.ironwood, &original) && check_action_failures(&parsed, &absent);
    uint8_t statement[V6_IRONWOOD_STATEMENT_SIZE];
    ok = ok && v6_ironwood_statement(&parsed, 1, statement, sizeof statement) &&
        !memcmp(statement + 32, parsed.ironwood.actions.data + 820, 128);
    memmove(wire + prefix - 2, wire + prefix - 1, n + 884 - prefix + 1);
    wire[n + 884 - 1] = 0; /* empty Ironwood follows the Orchard bundle */
    wire[prefix - 1 + 1640] &= 3; /* Orchard supports only its two defined flag bits */
    ok = ok && v6_wire_parse(wire, n + 884, &parsed) == V6_WIRE_OK &&
        !parsed.ironwood.count && check_action_values(&parsed.orchard, &original);
    free(wire);
    return ok;
}

static bool check_statement_flag(const struct v6_wire_view *v, unsigned f,
                                 uint8_t out[V6_IRONWOOD_STATEMENT_SIZE])
{
    return v6_ironwood_statement(v, 0, out, V6_IRONWOOD_STATEMENT_SIZE) &&
        !memcmp(out, v->ironwood.anchor.data, 32) &&
        !memcmp(out + 32, v->ironwood.actions.data, 128) &&
        out[160] == (f & 1u) && out[161] == ((f >> 1) & 1u) &&
        out[162] == ((f & 4u) == 0);
}

static bool check_statement_invalid_calls(const struct v6_wire_view *v,
                                          uint8_t out[V6_IRONWOOD_STATEMENT_SIZE])
{
    return !v6_ironwood_statement(v, 0, out, V6_IRONWOOD_STATEMENT_SIZE - 1) &&
        !v6_ironwood_statement(v, 1, out, V6_IRONWOOD_STATEMENT_SIZE) &&
        !v6_ironwood_statement(NULL, 0, out, V6_IRONWOOD_STATEMENT_SIZE) &&
        !v6_ironwood_statement(v, 0, NULL, V6_IRONWOOD_STATEMENT_SIZE);
}

static bool check_funded_view(const uint8_t *s, const struct ironwood_instance_rows *expected)
{
    uint8_t action[820] = {0}, signature[64] = {0}, flags = 7;
    memcpy(action, s + 32, 128);
    struct v6_wire_view v = {0};
    v.ironwood.count = 1;
    v.ironwood.actions = (struct v6_span){action, sizeof action};
    v.ironwood.signatures = (struct v6_span){signature, sizeof signature};
    v.ironwood.anchor = (struct v6_span){s, 32};
    v.ironwood.flags = (struct v6_span){&flags, 1};
    struct ironwood_instance_rows actual;
    return ironwood_instance_project(&v, 0, &actual).ok &&
        !memcmp(&actual, expected, sizeof actual) &&
        !ironwood_instance_project(&v, 1, &actual).ok;
}

static bool check_pallas_encodings(const uint8_t *original)
{
    static const char modulus[] = "01000000ed302d991bf94c09fc98462200000000000000000000000000000040";
    static const char opposite_y[] = "d77d8b3223bfc4f08504d2de7ee2bcc2a8310aa7abb72b09a340f1fffaf85811";
    uint8_t s[V6_IRONWOOD_STATEMENT_SIZE], expected[32];
    struct ironwood_instance_rows out, saved, opposite;
    if (!ironwood_instance_from_statement(original, V6_IRONWOOD_STATEMENT_SIZE, &out).ok) return false;
    memcpy(s, original, sizeof s); s[63] ^= 0x80;
    if (!ironwood_instance_from_statement(s, sizeof s, &opposite).ok ||
        !zcl_hex_decode(opposite_y, expected, sizeof expected) ||
        memcmp(out.row[1], opposite.row[1], 32) || memcmp(opposite.row[2], expected, 32)) return false;
    memcpy(&saved, &out, sizeof out);
    memcpy(s, original, sizeof s);
    if (!zcl_hex_decode(modulus, s + 32, 32) ||
        ironwood_instance_from_statement(s, sizeof s, &out).ok) return false;
    memset(s + 32, 0, 32); s[32] = 2; /* x^3+5 is a non-square in Pallas Fp. */
    return !ironwood_instance_from_statement(s, sizeof s, &out).ok &&
        !memcmp(&out, &saved, sizeof out);
}

static bool check_funded_controls(const uint8_t *original)
{
    uint8_t s[V6_IRONWOOD_STATEMENT_SIZE];
    struct ironwood_instance_rows out, saved;
    memcpy(s, original, sizeof s);
    memset(&out, 0xa5, sizeof out); memcpy(&saved, &out, sizeof out);
    s[160] = 2;
    if (ironwood_instance_from_statement(s, sizeof s, &out).ok) return false;
    memcpy(s, original, sizeof s); memset(s, 0xff, 32);
    if (ironwood_instance_from_statement(s, sizeof s, &out).ok) return false;
    memcpy(s, original, sizeof s); memset(s + 96, 0, 32);
    if (ironwood_instance_from_statement(s, sizeof s, &out).ok ||
        memcmp(&out, &saved, sizeof out)) return false;
    memcpy(s, original, sizeof s); memset(s + 32, 0, 32);
    if (!ironwood_instance_from_statement(s, sizeof s, &out).ok) return false;
    uint8_t zero[32] = {0};
    return !memcmp(out.row[1], zero, 32) && !memcmp(out.row[2], zero, 32);
}

static bool check_commitment_refusals(const struct ironwood_instance_rows *rows,
                                      uint8_t basis[IRONWOOD_INSTANCE_ROWS][32], uint8_t w[32],
                                      uint8_t out[32])
{
    uint8_t saved[32], original[32]; memcpy(saved, out, 32); memcpy(original, basis[3], 32);
    memset(basis[3], 0, 32);
    if (ironwood_instance_commitment(rows, basis, w, out).ok || memcmp(out, saved, 32)) return false;
    memset(basis[3], 0xff, 32);
    if (ironwood_instance_commitment(rows, basis, w, out).ok || memcmp(out, saved, 32)) return false;
    memcpy(basis[3], original, 32); memset(w, 0, 32);
    if (ironwood_instance_commitment(rows, basis, w, out).ok || memcmp(out, saved, 32)) return false;
    memcpy(w, original, 32); /* Valid point; the scalar refusal precedes its use. */
    struct ironwood_instance_rows bad = *rows;
    memset(bad.row[0], 0xff, 32);
    return !ironwood_instance_commitment(&bad, basis, w, out).ok && !memcmp(out, saved, 32);
}

static bool check_commitment_cancellation(uint8_t basis[IRONWOOD_INSTANCE_ROWS][32],
                                           const uint8_t w[32])
{
    struct ironwood_instance_rows rows = {0};
    uint8_t saved[32], out[32], identity[32] = {0};
    memcpy(saved, basis[0], 32);
    memcpy(basis[0], w, 32); basis[0][31] ^= 0x80;
    rows.row[0][0] = 1;
    bool ok = ironwood_instance_commitment(&rows, basis, w, out).ok && !memcmp(out, identity, 32);
    memcpy(basis[0], saved, 32);
    return ok;
}

/* Pinned upstream Halo2 0.4.0 k=11 basis and funded two-action transcript;
 * R1 ironwood-instance-commit.kRFCL9qn/{basis-11-and-w.hex,commitments.txt}. */
static bool check_instance_commitment(const struct ironwood_instance_rows *rows, const char *want)
{
    static const char *points[] = {
        "d8e88412dad928ab63cf8d2532aea6f5b118e3af01091721172c81a568757882",
        "5d1232a1a28cd09dffeec96ea2113ed77971720c6fe715b4f7ec35d98967eb9e",
        "fdd970bc80e05e71fe3c91ddd7d5150dd5acffb8c5a22ba0f8abb661215e9f8a",
        "cd935c612a14c155f78fd01cfe28a09f6ccb123ed459868597b5270aa4440b2a",
        "cdd404a09bc2d634cfb64ef2990b9f377cd9f2c8a476bbf29e827dae2723931e",
        "7427839a4ad1fa088800c46f94d08d83c44d212932488547da8b4f9bb9bce38c",
        "3f41f0b32db4be5ce9343fce46bae7e5e7d19099d3c4ac9ae85af2727fda1e15",
        "08feea323aaebd690f8f397c0d5a1390a410db18a5c47245241905a71b084d3e",
        "b5a4e78ecd3d2025a7e94792dc9b0a5a90dac3b8d03855147a7a46f8289df6a8",
        "8e9fda732d7be75897c1cff1631f05da6fbc405bdb1e5eb4aae62bad9737a490",
        "7520d96f3e5cd41760367151608b54821883c10c4b9a4ff2beae227bef94bcab"
    };
    uint8_t basis[IRONWOOD_INSTANCE_ROWS][32], w[32], out[32], expected[32];
    for (size_t i = 0; i < IRONWOOD_INSTANCE_ROWS; ++i)
        if (!zcl_hex_decode(points[i], basis[i], 32)) return false;
    if (!zcl_hex_decode(points[10], w, 32) || !zcl_hex_decode(want, expected, 32) ||
        !ironwood_instance_commitment(rows, basis, w, out).ok || memcmp(out, expected, 32)) return false;
    struct ironwood_instance_rows zero = {0};
    uint8_t zero_result[32];
    if (!ironwood_instance_commitment(&zero, basis, w, zero_result).ok ||
        memcmp(zero_result, w, 32)) return false;
    return check_commitment_cancellation(basis, w) && check_commitment_refusals(rows, basis, w, out);
}

/* Funded reopened spend, Orchard 0.16.0 PostNu6_3 to_halo2_instance;
 * R1 ironwood-vk-repro.RZfQAkV6/rows-run2.log, action zero. */
static bool check_funded_instance(void)
{
    static const char statement[] =
        "c54832e4998cf9088b77703c858865e752241c1c0115909caeeffaf1396e370e"
        "59c10b7aa34e715e59c4d1642054c53ac61e1ac7aa8f5b650eb55b4b68d4553f"
        "20aa0b094b3bef6b52674892a038108ac022b7eba02ced6f5cb8345e7251600e"
        "99811e9ee44526e3f9713a61599610de79b5cc99459e2e47d523edf7c34a9634"
        "5f6284a9465b1fd2c73495aee25b437da7781fc31de6e01a06e25d936345eb09"
        "010100";
    static const char *rows[] = {
        "c54832e4998cf9088b77703c858865e752241c1c0115909caeeffaf1396e370e",
        "59c10b7aa34e715e59c4d1642054c53ac61e1ac7aa8f5b650eb55b4b68d4553f",
        "2a8274cdc97168a895f47a2a7db6895f57cef5585448d4f65cbf0e000507a72e",
        "20aa0b094b3bef6b52674892a038108ac022b7eba02ced6f5cb8345e7251600e",
        "99811e9ee44526e3f9713a61599610de79b5cc99459e2e47d523edf7c34a9634",
        "90a87f1f6fb70e5bf4f1fa8ab6c58a218d9a7f644b8f9740408c42ae29843512",
        "5f6284a9465b1fd2c73495aee25b437da7781fc31de6e01a06e25d936345eb09",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000"
    };
    uint8_t s[V6_IRONWOOD_STATEMENT_SIZE], expected[32];
    struct ironwood_instance_rows got;
    if (!zcl_hex_decode(statement, s, sizeof s) ||
        !ironwood_instance_from_statement(s, sizeof s, &got).ok) return false;
    for (size_t i = 0; i < IRONWOOD_INSTANCE_ROWS; ++i)
        if (!zcl_hex_decode(rows[i], expected, 32) || memcmp(got.row[i], expected, 32)) return false;
    return check_funded_view(s, &got) && check_funded_controls(s) && check_pallas_encodings(s) &&
        check_instance_commitment(&got, "e55fe4c155c0e04e28e3a39aaa06ec5a77c27eea1aab0c529391e7b2a12fb9a0");
}

static bool check_instance_refusals(void)
{
    uint8_t s[V6_IRONWOOD_STATEMENT_SIZE] = {0};
    struct ironwood_instance_rows out, before;
    memset(&out, 0xa5, sizeof out); memcpy(&before, &out, sizeof out);
    if (ironwood_instance_from_statement(s, sizeof s, &out).ok ||
        ironwood_instance_from_statement(s, sizeof s - 1, &out).ok ||
        ironwood_instance_project(NULL, 0, &out).ok) return false; /* identity rk */
    return !memcmp(&out, &before, sizeof out);
}

static bool check_funded_second_instance(void)
{
    static const char statement[] =
        "c54832e4998cf9088b77703c858865e752241c1c0115909caeeffaf1396e370e"
        "6040aaadabcee434225ed88c72fe893488c9be4c0986ea934fc36d8a05a9c52c"
        "16cbac01db396328cf81c873fe12cc4e77e6233a2a67c89bc6ee81faba151919"
        "c34f9b620a939918a1c81907e072d15961200afdf9fe05b9c44fd6006abace38"
        "75f7a99688cc5939df2646f9eb7e1be51c60b2d84e728dff790bf1807f72963a010100";
    static const char *rows[] = {
        "c54832e4998cf9088b77703c858865e752241c1c0115909caeeffaf1396e370e",
        "6040aaadabcee434225ed88c72fe893488c9be4c0986ea934fc36d8a05a9c52c",
        "7edbf5121bc034db31bac9c7886ec970f9ebcde41029167e102aad3e6d08e41f",
        "16cbac01db396328cf81c873fe12cc4e77e6233a2a67c89bc6ee81faba151919",
        "c34f9b620a939918a1c81907e072d15961200afdf9fe05b9c44fd6006abace38",
        "ae4e600b929038bf1a66b818e17d9db530de88799ef12ecebdfa81a7fb679137",
        "75f7a99688cc5939df2646f9eb7e1be51c60b2d84e728dff790bf1807f72963a",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000"
    };
    uint8_t s[V6_IRONWOOD_STATEMENT_SIZE], expected[32];
    struct ironwood_instance_rows got;
    if (!zcl_hex_decode(statement, s, sizeof s) ||
        !ironwood_instance_from_statement(s, sizeof s, &got).ok) return false;
    for (size_t i = 0; i < IRONWOOD_INSTANCE_ROWS; ++i)
        if (!zcl_hex_decode(rows[i], expected, 32) || memcmp(got.row[i], expected, 32)) return false;
    return check_funded_view(s, &got) &&
        check_instance_commitment(&got, "273cf53ff47191c5a7a25ba8e3a8df751b1b4933500b3653ff54ccd8b94f95a0");
}

/* Structurally serialized v6 frame using the public funded action slices;
 * ciphertexts, proof and signatures are synthetic and are not validated. */
static bool check_two_action_instance(void)
{
    static const char *statements[] = {
        "c54832e4998cf9088b77703c858865e752241c1c0115909caeeffaf1396e370e"
        "59c10b7aa34e715e59c4d1642054c53ac61e1ac7aa8f5b650eb55b4b68d4553f"
        "20aa0b094b3bef6b52674892a038108ac022b7eba02ced6f5cb8345e7251600e"
        "99811e9ee44526e3f9713a61599610de79b5cc99459e2e47d523edf7c34a9634"
        "5f6284a9465b1fd2c73495aee25b437da7781fc31de6e01a06e25d936345eb09010100",
        "c54832e4998cf9088b77703c858865e752241c1c0115909caeeffaf1396e370e"
        "6040aaadabcee434225ed88c72fe893488c9be4c0986ea934fc36d8a05a9c52c"
        "16cbac01db396328cf81c873fe12cc4e77e6233a2a67c89bc6ee81faba151919"
        "c34f9b620a939918a1c81907e072d15961200afdf9fe05b9c44fd6006abace38"
        "75f7a99688cc5939df2646f9eb7e1be51c60b2d84e728dff790bf1807f72963a010100"
    };
    enum { ACTIONS_START = 26, FLAGS = ACTIONS_START + 2 * 820,
           ANCHOR = FLAGS + 9, SIZE = ANCHOR + 32 + 1 + 2 * 64 + 64 };
    uint8_t wire[SIZE] = {0}, s[2][V6_IRONWOOD_STATEMENT_SIZE];
    for (size_t i = 0; i < 2; ++i)
        if (!zcl_hex_decode(statements[i], s[i], sizeof s[i])) return false;
    memcpy(wire, empty, 25); wire[25] = 2;
    for (size_t i = 0; i < 2; ++i) memcpy(wire + ACTIONS_START + 820 * i, s[i] + 32, 128);
    wire[FLAGS] = 7; memcpy(wire + ANCHOR, s[0], 32);
    struct v6_wire_view v;
    if (v6_wire_parse(wire, sizeof wire, &v) != V6_WIRE_OK || v.ironwood.count != 2) return false;
    for (size_t i = 0; i < 2; ++i) {
        struct ironwood_instance_rows expected, actual;
        if (!ironwood_instance_from_statement(s[i], sizeof s[i], &expected).ok ||
            !ironwood_instance_project(&v, i, &actual).ok || memcmp(&actual, &expected, sizeof actual))
            return false;
    }
    return true;
}

static bool check_statement_views(void)
{
    uint8_t wire[sizeof ironwood_anchor_a], out[V6_IRONWOOD_STATEMENT_SIZE];
    memcpy(wire, ironwood_anchor_a, sizeof wire);
    struct v6_wire_view v;
    if (v6_wire_parse(wire, sizeof wire, &v) != V6_WIRE_OK) return false;
    uint8_t *flags = (uint8_t *)v.ironwood.flags.data;
    for (unsigned f = 0; f < 8; ++f) {
        *flags = (uint8_t)f;
        if (!check_statement_flag(&v, f, out)) return false;
    }
    memset(out, 0xa5, sizeof out);
    if (!check_statement_invalid_calls(&v, out)) return false;
    v.ironwood.flags.size = 0;
    if (v6_ironwood_statement(&v, 0, out, sizeof out)) return false;
    for (size_t i = 0; i < sizeof out; ++i) if (out[i] != 0xa5) return false;
    return true;
}

static bool check_empty_view(void)
{
    struct v6_wire_view v;
    return v6_wire_parse(empty, sizeof empty, &v) == V6_WIRE_OK &&
        v.header.data == empty && v.header.size == 20 &&
        v.transparent.data == empty + 20 && v.transparent.size == 2 &&
        !v.sapling_spends.count && !v.sapling_outputs.count &&
        v.orchard.wire.data == empty + 24 && v.orchard.wire.size == 1 &&
        v.ironwood.wire.data == empty + 25 && v.ironwood.wire.size == 1;
}
static bool check_empty_digests(void)
{
    struct v6_wire_view v; struct v6_digests d;
    const char *expected[] = {
        "51618f3e4a3e33ed4c56e481a36f94af8bc168ded6501cf2db4e8d5ce8e16b76",
        "3830381d48c96abea86e4a8500706779a0d4a12f6181f09a17372234ab0aafcb",
        "6f2fc8f98feafd94e74a0df4bed74391ee0b5a69945e4ced8ca8a095206f00ae",
        "0ee4b9560bae4230a99bfa528e0a6aabc7e25386f366599767e7ca107b8c1746",
        "a3367d2fdea2910159fc5026e9bf1fccd3e28ce5e6de46bfb71587230eea9515",
        "798e7fcd05bb7b7e9e49424bdde768a500b66ff23d759b877d0754e3ff797d91",
        "b9cfe643ce45b28c33190f0d5223e475972f2a149dc54404fd8365521f8416c5",
        "ec9768fdaa11f12cdb13f566b595843f3d0e92b6703eafff172e21345b586133"};
    if (v6_wire_parse(empty, sizeof empty, &v) != V6_WIRE_OK || !v6_wire_digests(&v, &d)) return false;
    const uint8_t *actual[] = {d.txid,d.auth,d.sapling_effect,d.sapling_auth,
        d.orchard_effect,d.orchard_auth,d.ironwood_effect,d.ironwood_auth};
    for (size_t i = 0; i < 8; ++i) if (!digest_matches(actual[i],expected[i])) return false;
    memset(&d, 0xff, sizeof d);
    if (v6_wire_digests(NULL, &d)) return false;
    const uint8_t *cleared = (const uint8_t *)&d;
    for (size_t i = 0; i < sizeof d; ++i) if (cleared[i]) return false;
    return true;
}
static bool check_single_cursor(void)
{
    uint8_t tx[76] = {0}; struct v6_wire_view v;
    memcpy(tx, empty, 20); tx[20] = 1; tx[62] = 1;
    struct v6_span in, out; struct v6_wire_cursor ci, co;
    return v6_wire_parse(tx, sizeof tx, &v) == V6_WIRE_OK && v.inputs == 1 && v.outputs == 1 &&
        v6_wire_cursor_init(&v, true, &ci) && v6_wire_cursor_next(&ci, &in) && in.data == tx + 21 && in.size == 41 &&
        v6_wire_cursor_init(&v, false, &co) && v6_wire_cursor_next(&co, &out) && out.data == tx + 63 && out.size == 9 &&
        !v6_wire_cursor_next(&ci, &in) && !v6_wire_cursor_next(&co, &out);
}
static bool check_many_cursor(void)
{
    uint8_t tx[126] = {0}; struct v6_wire_view v;
    memcpy(tx, empty, 20); tx[20] = 2; tx[103] = 2;
    struct v6_span in, out; struct v6_wire_cursor ci, co;
    return v6_wire_parse(tx, sizeof tx, &v) == V6_WIRE_OK &&
        v6_wire_cursor_init(&v, true, &ci) &&
        v6_wire_cursor_next(&ci, &in) && in.data == tx + 21 &&
        v6_wire_cursor_next(&ci, &in) && in.data == tx + 62 && !v6_wire_cursor_next(&ci, &in) &&
        v6_wire_cursor_init(&v, false, &co) &&
        v6_wire_cursor_next(&co, &out) && out.data == tx + 104 &&
        v6_wire_cursor_next(&co, &out) && out.data == tx + 113 && !v6_wire_cursor_next(&co, &out);
}
static bool check_ironwood_digest(void)
{
    struct v6_wire_view v; struct v6_digests d;
    return v6_wire_parse(ironwood_anchor_a, sizeof ironwood_anchor_a, &v) == V6_WIRE_OK &&
        v.ironwood.count && v6_wire_digests(&v, &d) &&
        digest_matches(d.txid, "c3bf28993fec75e07ca111ea3d8ab194db2047ce17153832a0f97fbefef15766") &&
        digest_matches(d.auth, expected_auth) &&
        digest_matches(d.ironwood_effect, "d295c340fed66f3274c8f157e2c3d114dd9ee55951e87c1a99a2c288d4784f18") &&
        digest_matches(d.ironwood_auth, "5b6afe0992f78ec4a88ec90cc4199f7ddad45d1290d818450f0cd3589ce383e8");
}
static bool check_invalid_wire(void)
{
    struct v6_wire_view v;
    for (size_t n = 0; n < sizeof empty; ++n)
        if (v6_wire_parse(empty, n, &v) == V6_WIRE_OK) return false;
    uint8_t bad[sizeof empty + 2];
    memcpy(bad, empty, sizeof empty); bad[sizeof empty] = 0;
    if (v6_wire_parse(bad, sizeof empty + 1, &v) != V6_WIRE_TRAILING) return false;
    if (v.header.data || v.inputs || v.transparent.data || v.ironwood.wire.data) return false;
    memmove(bad + 23, bad + 21, 5); bad[20] = 253; bad[21] = 0; bad[22] = 0;
    return v6_wire_parse(bad, sizeof bad, &v) == V6_WIRE_NONCANONICAL;
}
static bool check_prefix_frames_valid(uint8_t *frames, size_t frames_size,
                                      struct v6_wire_view *v, size_t *consumed)
{
    *consumed = 99;
    if (v6_wire_parse_prefix(frames, frames_size, v, consumed) != V6_WIRE_OK ||
        *consumed != sizeof empty || v->header.data != frames) return false;
    if (v6_wire_parse_prefix(frames + *consumed, sizeof empty, v, consumed) != V6_WIRE_OK ||
        *consumed != sizeof empty) return false;
    return v6_wire_parse(frames, frames_size, v) == V6_WIRE_TRAILING &&
        !v->header.data && !v->transparent.data;
}

static bool check_prefix_frames_invalid(uint8_t *frames,
                                        struct v6_wire_view *v,
                                        size_t *consumed)
{
    *consumed = 99;
    if (v6_wire_parse_prefix(frames, sizeof empty - 1, v, consumed) == V6_WIRE_OK ||
        *consumed != 0 || v->header.data) return false;
    *consumed = 99;
    if (v6_wire_parse_prefix(NULL, sizeof empty, v, consumed) != V6_WIRE_TRUNCATED ||
        *consumed != 0 || v->header.data) return false;
    memset(v, 0xff, sizeof *v);
    if (v6_wire_parse_prefix(frames, sizeof empty, v, NULL) != V6_WIRE_TRUNCATED ||
        v->header.data || v->transparent.data) return false;
    *consumed = 99;
    return v6_wire_parse_prefix(frames, sizeof empty, NULL, consumed) == V6_WIRE_TRUNCATED &&
           *consumed == 0;
}

static bool check_prefix_frames(void)
{
    uint8_t frames[sizeof empty * 2];
    memcpy(frames, empty, sizeof empty);
    memcpy(frames + sizeof empty, empty, sizeof empty);
    struct v6_wire_view v;
    size_t consumed;
    if (!check_prefix_frames_valid(frames, sizeof frames, &v, &consumed))
        return false;
    return check_prefix_frames_invalid(frames, &v, &consumed);
}

static int check_v6_rpc_cases(void)
{
    int failures = 0;
    if (!check_v6_rpc_view()) ++failures;
    if (!check_v6_rpc_budget()) ++failures;
    if (!check_v6_rpc_projection_limit()) ++failures;
    if (!check_empty_rpc()) ++failures;
    if (!check_balance_cases()) ++failures;
    return failures;
}

int test_transaction_v6_inspect(void)
{
    int failures = check_v6_rpc_cases();
    if (!check_action_views()) ++failures;
    if (!check_statement_views()) ++failures;
    if (!check_funded_instance()) ++failures;
    if (!check_funded_second_instance()) ++failures;
    if (!check_two_action_instance()) ++failures;
    if (!check_instance_refusals()) ++failures;
    if (!check_empty_view()) ++failures;
    if (!check_empty_digests()) ++failures;
    if (!check_single_cursor()) ++failures;
    if (!check_many_cursor()) ++failures;
    if (!check_ironwood_digest()) ++failures;
    if (!check_invalid_wire()) ++failures;
    if (!check_prefix_frames()) ++failures;
    printf("v6 wire view: %s\n", failures ? "FAIL" : "PASS");
    return failures;
}
