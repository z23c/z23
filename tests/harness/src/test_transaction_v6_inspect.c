/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "controllers/transaction_v6_inspect.h"
#include "controllers/transaction_v6_digest.h"
#include "controllers/transaction_v6_rpc.h"
#include "services/ironwood_instance.h"
#include "services/ironwood_halo2_transcript.h"
#include "services/ironwood_postnu63.h"
#include "services/ironwood_ipa.h"
#include "crypto/sha256.h"
#include "codec/cursor.h"
#include "base/hex.h"
#include "encoding/utilstrencodings.h"
#include "crypto/blake2b.h"
#include "crypto/chacha20poly1305.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "transaction_v6_ironwood_fixture.h"
#include "transaction_v6_recipient_fixture.h"

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

/* Two actions follow the 20-byte header, empty transparent and Sapling
 * sections, and the Orchard/Ironwood count bytes (parser lines 69-84). */
enum {
    AUTH_ORCHARD_ACTIONS = 25, /* Orchard action records */
    AUTH_ORCHARD_PROOF = 1707, /* Orchard proof after flags, balance, anchor and length */
    AUTH_ORCHARD_SIG0 = 1723, /* Orchard first action signature */
    AUTH_ORCHARD_SIG1 = 1787, /* Orchard second action signature */
    AUTH_ORCHARD_BINDING = 1851, /* Orchard binding signature */
    AUTH_IRONWOOD_ACTIONS = 26, /* Ironwood action records */
    AUTH_IRONWOOD_PROOF = 1708, /* Ironwood proof after flags, balance, anchor and length */
    AUTH_IRONWOOD_SIG0 = 1724, /* Ironwood first action signature */
    AUTH_IRONWOOD_SIG1 = 1788, /* Ironwood second action signature */
    AUTH_IRONWOOD_BINDING = 1852, /* Ironwood binding signature */
    AUTH_PROOF_SIZE = 16, /* CompactSize proof payload length */
    AUTH_SIGNATURE_SIZE = 64, /* Each action and binding signature */
    AUTH_WIRE_SIZE = 1916 /* Complete transaction including the empty other bundle */
};

static void make_auth_wire(uint8_t wire[AUTH_WIRE_SIZE], bool orchard)
{
    memset(wire, 0, AUTH_WIRE_SIZE);
    memcpy(wire, empty, 20);
    size_t actions = orchard ? AUTH_ORCHARD_ACTIONS : AUTH_IRONWOOD_ACTIONS;
    size_t proof = orchard ? AUTH_ORCHARD_PROOF : AUTH_IRONWOOD_PROOF;
    wire[actions - 1] = 2;
    memcpy(wire + actions, ironwood_anchor_a + 26, 820);
    memcpy(wire + actions + 820, ironwood_anchor_a + 26, 820);
    wire[proof - 1] = AUTH_PROOF_SIZE;
    for (size_t i = 0; i < AUTH_PROOF_SIZE; ++i) wire[proof + i] = (uint8_t)(0x10 + i);
    for (size_t i = 0; i < 3 * AUTH_SIGNATURE_SIZE; ++i)
        wire[proof + AUTH_PROOF_SIZE + i] = (uint8_t)(0x40 + i);
}

static bool check_auth_span(const char *name, struct v6_span span, const uint8_t *wire,
                            size_t offset, size_t length)
{
    if (span.data == wire + offset && span.size == length && !memcmp(span.data, wire + offset, length))
        return true;
    fprintf(stderr, "v6 auth span failed: %s\n", name);
    return false;
}

static bool check_auth_bundle(const uint8_t *wire, bool orchard)
{
    struct v6_wire_view v;
    struct v6_action_view first, second;
    if (v6_wire_parse(wire, AUTH_WIRE_SIZE, &v) != V6_WIRE_OK) return false;
    const struct v6_bundle *b = orchard ? &v.orchard : &v.ironwood;
    if (!v6_bundle_action(b, 0, &first) || !v6_bundle_action(b, 1, &second)) return false;
    size_t proof = orchard ? AUTH_ORCHARD_PROOF : AUTH_IRONWOOD_PROOF;
    size_t sig0 = orchard ? AUTH_ORCHARD_SIG0 : AUTH_IRONWOOD_SIG0;
    size_t sig1 = orchard ? AUTH_ORCHARD_SIG1 : AUTH_IRONWOOD_SIG1;
    size_t binding = orchard ? AUTH_ORCHARD_BINDING : AUTH_IRONWOOD_BINDING;
    return check_auth_span("proof", b->proof, wire, proof, AUTH_PROOF_SIZE) &&
        check_auth_span("signatures", b->signatures, wire, sig0, 128) &&
        check_auth_span("action 0 signature", first.signature, wire, sig0, AUTH_SIGNATURE_SIZE) &&
        check_auth_span("action 1 signature", second.signature, wire, sig1, AUTH_SIGNATURE_SIZE) &&
        check_auth_span("binding signature", b->binding_signature, wire, binding, AUTH_SIGNATURE_SIZE);
}

static bool check_auth_truncation(const uint8_t *wire, size_t cut)
{
    struct v6_wire_view v;
    memset(&v, 0xa5, sizeof v);
    if (v6_wire_parse(wire, cut, &v) != V6_WIRE_TRUNCATED) return false;
    const uint8_t *bytes = (const uint8_t *)&v;
    for (size_t i = 0; i < sizeof v; ++i) if (bytes[i]) return false;
    return true;
}

static bool check_auth_views(void)
{
    uint8_t wire[AUTH_WIRE_SIZE];
    make_auth_wire(wire, false);
    if (!check_auth_bundle(wire, false) ||
        !check_auth_truncation(wire, AUTH_IRONWOOD_PROOF + 8) ||
        !check_auth_truncation(wire, AUTH_IRONWOOD_BINDING + 32)) return false;
    make_auth_wire(wire, true);
    return check_auth_bundle(wire, true) &&
        check_auth_truncation(wire, AUTH_ORCHARD_PROOF + 8) &&
        check_auth_truncation(wire, AUTH_ORCHARD_BINDING + 32);
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
static const char *instance_basis_hex[] = {
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
static bool load_instance_basis(uint8_t basis[IRONWOOD_INSTANCE_ROWS][32], uint8_t w[32])
{
    for (size_t i = 0; i < IRONWOOD_INSTANCE_ROWS; ++i)
        if (!zcl_hex_decode(instance_basis_hex[i], basis[i], 32)) return false;
    return zcl_hex_decode(instance_basis_hex[IRONWOOD_INSTANCE_ROWS], w, 32);
}

static bool check_instance_commitment(const struct ironwood_instance_rows *rows, const char *want)
{
    uint8_t basis[IRONWOOD_INSTANCE_ROWS][32], w[32], out[32], expected[32];
    if (!load_instance_basis(basis, w) || !zcl_hex_decode(want, expected, 32) ||
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

static bool absorb_instances(struct ironwood_halo2_transcript *t, const struct v6_wire_view *view,
                             size_t count, bool reverse)
{
    uint8_t basis[IRONWOOD_INSTANCE_ROWS][32], w[32], affine[64];
    if (!load_instance_basis(basis, w)) return false;
    for (size_t i = 0; i < count; ++i) {
        struct ironwood_instance_rows rows;
        uint8_t commitment[32];
        struct zcl_codec_reader input;
        size_t action = reverse ? count - 1 - i : i;
        if (!ironwood_instance_project(view, action, &rows).ok ||
            !ironwood_instance_commitment(&rows, basis, w, commitment).ok) return false;
        zcl_codec_reader_init(&input, commitment, sizeof commitment);
        if (!ironwood_halo2_read_point(t, &input, affine, sizeof affine).ok || input.position != 32)
            return false;
    }
    return true;
}

/* Frames public inputs and advice points only; this is not proof verification. */
static bool first_theta(const struct v6_wire_view *view, size_t count, size_t advice_columns,
                        const uint8_t *proof, size_t proof_size, bool reverse, uint8_t out[32], uint8_t raw[64])
{
    uint8_t vk[32], affine[64], wide[64], value[32];
    struct ironwood_halo2_transcript t;
    struct zcl_codec_reader reader;
    if (!zcl_hex_decode("99b4fa5429bf1f72bbba9c1620e201206287d2cc6373012d5bb99fedb7f72205", vk, 32) ||
        !ironwood_halo2_transcript_init(&t).ok || !ironwood_halo2_transcript_scalar(&t, vk, 32).ok ||
        !absorb_instances(&t, view, count, reverse)) return false;
    zcl_codec_reader_init(&reader, proof, proof_size);
    for (size_t i = 0; i < count; ++i)
        for (size_t j = 0; j < advice_columns; ++j)
            if (!ironwood_halo2_read_point(&t, &reader, affine, sizeof affine).ok) return false;
    if (reader.position != proof_size || !ironwood_halo2_transcript_challenge(&t, wide, sizeof wide).ok ||
        !ironwood_halo2_vesta_scalar(wide, sizeof wide, value, sizeof value).ok) return false;
    memcpy(out, value, sizeof value);
    memcpy(raw, wide, sizeof wide);
    return true;
}


static bool check_first_theta(const struct v6_wire_view *view)
{
    uint8_t expected[32], out[32], before[32], raw[64], want_raw[64], bad[sizeof ironwood_funded_proof_prefix];
    if (!zcl_hex_decode("ca5cf9dd47e21fa547c0f57b93a99b02586bd3af07358dfcf90143e5947f9c50a23ab46f1103d9d7ca878c0f062cea610551b05f107c61280fe82cb6ad263e76", want_raw, 64) ||
        !zcl_hex_decode("9b4c4db54b5587629516968e6cba32a1c9239bee4c8e5d22dd534b79ed27bc34", expected, 32) ||
        !first_theta(view, 2, 10, ironwood_funded_proof_prefix, sizeof ironwood_funded_proof_prefix, false, out, raw) ||
        memcmp(out, expected, 32) || memcmp(raw, want_raw, 64)) return false;
    if (!first_theta(view, 2, 10, ironwood_funded_proof_prefix, sizeof ironwood_funded_proof_prefix, true, out, raw) ||
        !memcmp(out, expected, 32)) return false;
    memset(out, 0xa5, sizeof out); memcpy(before, out, sizeof out);
    if (first_theta(view, 2, 10, ironwood_funded_proof_prefix, sizeof ironwood_funded_proof_prefix - 1, false, out, raw) ||
        memcmp(out, before, 32)) return false;
    memcpy(bad, ironwood_funded_proof_prefix, sizeof bad); memset(bad, 0, 32);
    return !first_theta(view, 2, 10, bad, sizeof bad, false, out, raw) && !memcmp(out, before, 32);
}

/* Build a structural wire from public statements and the complete proof. */
static bool stage_wire(const struct v6_wire_view *source, const uint8_t *input,
                       size_t proof_size, uint8_t *wire, size_t capacity, struct v6_wire_view *out)
{
    size_t count = (size_t)source->ironwood.count;
    if (!count || count > 2 || !source->ironwood.flags.data || proof_size > 65535) return false;
    size_t flags = 26 + count * 820, anchor = flags + 9, proof = anchor + 35;
    size_t total = proof + proof_size + count * 64 + 64;
    if (total > capacity) return false;
    memset(wire, 0, total); memcpy(wire, empty, 25); wire[25] = (uint8_t)count;
    for (size_t i = 0; i < count; ++i)
        memcpy(wire + 26 + i * 820, input + i * V6_IRONWOOD_STATEMENT_SIZE + 32, 128);
    wire[flags] = *source->ironwood.flags.data; memcpy(wire + anchor, input, 32);
    wire[anchor + 32] = 0xfd; wire[anchor + 33] = (uint8_t)proof_size;
    wire[anchor + 34] = (uint8_t)(proof_size >> 8);
    memcpy(wire + proof, input + count * V6_IRONWOOD_STATEMENT_SIZE, proof_size);
    return v6_wire_parse(wire, total, out) == V6_WIRE_OK;
}

static bool stage_fixture(const struct v6_wire_view *view, const char *path,
                          uint8_t input[7590], size_t size)
{
    uint8_t statement[V6_IRONWOOD_STATEMENT_SIZE];
    size_t statements = (size_t)view->ironwood.count * sizeof statement;
    if (statements > 7590 || size > 7590 - statements) return false;
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    bool loaded = fread(input, 1, statements + size, f) == statements + size && fgetc(f) == EOF;
    if (fclose(f) != 0 || !loaded) return false;
    for (uint64_t i = 0; i < view->ironwood.count; ++i)
        if (!v6_core_ironwood_statement(view, i, statement, sizeof statement) ||
            memcmp(statement, input + i * sizeof statement, sizeof statement)) return false;
    return true;
}

static bool stage_refusals(struct v6_wire_view *full, uint8_t *wire, size_t size,
                           const uint8_t vk[32], const uint8_t basis[IRONWOOD_INSTANCE_ROWS][32],
                           const uint8_t w[32], struct ironwood_postnu63_stage *stage)
{
    struct v6_wire_view short_view = *full;
    struct ironwood_postnu63_stage before;
    memcpy(&before, stage, sizeof before);
    --short_view.ironwood.proof.size;
    if (ironwood_postnu63_first_challenge(&short_view, vk, basis, w, stage).ok ||
        memcmp(stage, &before, sizeof before)) return false;
    size_t proof_offset = (size_t)(full->ironwood.proof.data - wire);
    memset(wire + proof_offset, 0, 32);
    if (ironwood_postnu63_first_challenge(full, vk, basis, w, stage).ok ||
        memcmp(stage, &before, sizeof before)) return false;
    size_t saved = size;
    return !ironwood_postnu63_proof_size(UINT64_MAX, &size).ok && size == saved;
}

static bool lookup_short_refusal(const struct ironwood_postnu63_stage *stage)
{
    struct ironwood_postnu63_stage short_stage, before;
    memcpy(&short_stage, stage, sizeof short_stage);
    short_stage.proof.length = short_stage.proof.position + 6 * (size_t)stage->actions * 32 - 1;
    memcpy(&before, &short_stage, sizeof before);
    return !ironwood_postnu63_lookup_challenges(&short_stage).ok && !memcmp(&short_stage, &before, sizeof before);
}

/* Challenges from the pinned upstream 0.4.0 verifier trace for each proof. */
static bool check_lookup_stage(struct ironwood_postnu63_stage *stage, uint8_t *wire)
{
    static const char *const beta[] = {
        "1b6a36e4d9361552dc592493d87e3570d0fcb8ed44b81727c4780d9ad73a3b36",
        "8a03d35c2b5547a838e80fa0d0e2a74a3a274758025c1f382035bd8af31ee726"};
    static const char *const gamma[] = {
        "973504d5f2f8e6bf4896eb0a60aa7c894f4bf5fb73eb29b1a431e213dda4393f",
        "35d7dea4c45b405f44e0b08be51a01de556790d375a158ba97e29e23b960e42f"};
    uint64_t count = stage->actions;
    if (!count || count > 2) return false;
    uint8_t b[32], g[32], swap[32];
    if (!zcl_hex_decode(beta[count - 1], b, 32) || !zcl_hex_decode(gamma[count - 1], g, 32)) return false;
    struct ironwood_postnu63_stage before, failed;
    memcpy(&before, stage, sizeof before);
    if (!lookup_short_refusal(stage)) return false;
    if (!ironwood_postnu63_lookup_challenges(stage).ok || stage->lookup_offset != count * 320 ||
        stage->lookup_size != count * 192 || stage->proof.position != count * 512 ||
        memcmp(stage->beta, b, 32) || memcmp(stage->gamma, g, 32)) return false;
    memcpy(&failed, stage, sizeof failed);
    if (ironwood_postnu63_lookup_challenges(stage).ok || memcmp(stage, &failed, sizeof failed)) return false;
    size_t start = (size_t)(before.proof.buffer - wire) + before.proof.position;
    memcpy(swap, wire + start, 32); memcpy(wire + start, wire + start + 32, 32);
    memcpy(wire + start + 32, swap, 32);
    bool ok = ironwood_postnu63_lookup_challenges(&before).ok && memcmp(before.beta, b, 32);
    memcpy(wire + start + 32, wire + start, 32); memcpy(wire + start, swap, 32);
    return ok;
}

static bool yx_reject_short(const struct ironwood_postnu63_stage *stage, size_t end)
{
    struct ironwood_postnu63_stage short_stage, before;
    memcpy(&short_stage, stage, sizeof short_stage);
    short_stage.proof.length = end - 1;
    memcpy(&before, &short_stage, sizeof before);
    return !ironwood_postnu63_yx_challenges(&short_stage).ok && !memcmp(&short_stage, &before, sizeof before);
}

static bool yx_reject_bad(const struct ironwood_postnu63_stage *stage, uint8_t *wire, size_t offset)
{
    struct ironwood_postnu63_stage trial, before;
    uint8_t saved[32];
    memcpy(&trial, stage, sizeof trial); memcpy(&before, &trial, sizeof before);
    memcpy(saved, wire + offset, 32); memset(wire + offset, 0, 32);
    bool ok = !ironwood_postnu63_yx_challenges(&trial).ok && !memcmp(&trial, &before, sizeof before);
    memcpy(wire + offset, saved, 32);
    return ok;
}

static bool yx_order_sensitive(const struct ironwood_postnu63_stage *stage, uint8_t *wire,
                               size_t perm, size_t product, const uint8_t expected[32])
{
    struct ironwood_postnu63_stage trial;
    uint8_t saved[32];
    memcpy(&trial, stage, sizeof trial);
    memcpy(saved, wire + perm, 32); memcpy(wire + perm, wire + product, 32);
    memcpy(wire + product, saved, 32);
    bool ok = ironwood_postnu63_yx_challenges(&trial).ok && memcmp(trial.y, expected, 32);
    memcpy(wire + product, wire + perm, 32); memcpy(wire + perm, saved, 32);
    return ok;
}

static bool yx_refusals(const struct ironwood_postnu63_stage *stage, uint8_t *wire,
                        size_t perm, size_t prod, size_t random, size_t quotient,
                        size_t end, const uint8_t expected[32])
{
    size_t base = (size_t)(stage->proof.buffer - wire);
    return yx_reject_short(stage, quotient) && yx_reject_short(stage, end) &&
        yx_reject_bad(stage, wire, base + perm) && yx_reject_bad(stage, wire, base + prod) &&
        yx_reject_bad(stage, wire, base + random) && yx_reject_bad(stage, wire, base + quotient) &&
        yx_order_sensitive(stage, wire, base + perm, base + prod, expected);
}

/* PostNu6_3 retained upstream traces, Vesta Fp challenge representations. */
static bool check_yx_stage(struct ironwood_postnu63_stage *stage, uint8_t *wire)
{
    static const char *const ys[] = {
        "60b1247bc1277add885feba2189bf565b04a6be1b1a9542884f3971779f38316",
        "e5e43021d615a67ded66f757b0a083bf9ffff0d7143346a6ba330483a5a1331d"};
    static const char *const xs[] = {
        "3fafa948dc173285045f363b178d2d420f41f8cfc98c533e9cc080d6038f870a",
        "a1c6c0c3c9fc964d3d54bbb9e586a2a3c1e6489881715ed10540fdf622c29d3a"};
    uint64_t count = stage->actions;
    if (!count || count > 2) return false;
    size_t perm = (size_t)count * 512, prod = perm + (size_t)count * 96;
    size_t random = prod + (size_t)count * 96, quotient = random + 32, end = quotient + 256;
    uint8_t y[32], x[32];
    if (!zcl_hex_decode(ys[count - 1], y, 32) || !zcl_hex_decode(xs[count - 1], x, 32) ||
        !yx_refusals(stage, wire, perm, prod, random, quotient, end, y)) return false;
    if (!ironwood_postnu63_yx_challenges(stage).ok || stage->permutation_offset != perm ||
        stage->product_offset != prod || stage->random_offset != random || stage->quotient_offset != quotient ||
        stage->proof.position != end || memcmp(stage->y, y, 32) || memcmp(stage->x, x, 32)) return false;
    struct ironwood_postnu63_stage before;
    memcpy(&before, stage, sizeof before);
    return !ironwood_postnu63_yx_challenges(stage).ok && !memcmp(stage, &before, sizeof before);
}

static bool eval_reject(const struct ironwood_postnu63_stage *stage, uint8_t *wire, size_t offset)
{
    struct ironwood_postnu63_stage trial, before;
    uint8_t saved[32];
    memcpy(&trial, stage, sizeof trial); memcpy(&before, &trial, sizeof before);
    memcpy(saved, wire + offset, 32); memset(wire + offset, 0xff, 32);
    bool ok = !ironwood_postnu63_evaluations(&trial).ok && !memcmp(&trial, &before, sizeof before);
    memcpy(wire + offset, saved, 32);
    return ok;
}

static bool eval_refusals(const struct ironwood_postnu63_stage *stage, uint8_t *wire,
                          const size_t offsets[7], size_t end, const uint8_t expected[32])
{
    struct ironwood_postnu63_stage trial, before;
    memcpy(&trial, stage, sizeof trial); trial.proof.length = end - 1;
    memcpy(&before, &trial, sizeof before);
    if (ironwood_postnu63_evaluations(&trial).ok || memcmp(&trial, &before, sizeof before)) return false;
    size_t base = (size_t)(stage->proof.buffer - wire);
    for (size_t i = 0; i < 7; ++i)
        if (!eval_reject(stage, wire, base + offsets[i])) return false;
    uint8_t saved[32]; size_t a = base + offsets[1], b = a + 32;
    memcpy(&trial, stage, sizeof trial);
    memcpy(saved, wire + a, 32); memcpy(wire + a, wire + b, 32); memcpy(wire + b, saved, 32);
    bool ok = ironwood_postnu63_evaluations(&trial).ok && memcmp(trial.x1, expected, 32);
    memcpy(wire + b, wire + a, 32); memcpy(wire + a, saved, 32);
    return ok;
}

static bool eval_offsets_match(const struct ironwood_postnu63_stage *stage, const size_t o[7], size_t end)
{
    return stage->instance_eval_offset == o[0] && stage->advice_eval_offset == o[1] &&
        stage->fixed_eval_offset == o[2] && stage->random_eval_offset == o[3] &&
        stage->sigma_eval_offset == o[4] && stage->permutation_eval_offset == o[5] &&
        stage->lookup_eval_offset == o[6] && stage->proof.position == end;
}

/* Upstream 0.4.0 PostNu6_3 one/two-action opening aggregation x1. */
static bool check_eval_stage(struct ironwood_postnu63_stage *stage, uint8_t *wire)
{
    static const char *const x1[] = {
        "ef07195d8f747d47ec405d09dfa70d2d4a9dc3ada36823cf344b1c224e41fd2e",
        "b708924eba8cb1cb9ae8ae04b2bd522acfd0e50589df5960475db3e327e78b0d"};
    size_t n = (size_t)stage->actions;
    if (!n || n > 2) return false;
    size_t o[7];
    o[0] = stage->proof.position; o[1] = o[0] + n * 32; o[2] = o[1] + n * 25 * 32;
    o[3] = o[2] + 29 * 32; o[4] = o[3] + 32; o[5] = o[4] + 15 * 32;
    o[6] = o[5] + n * 8 * 32; size_t end = o[6] + n * 15 * 32;
    uint8_t expected[32];
    if (!zcl_hex_decode(x1[n - 1], expected, 32) || !eval_refusals(stage, wire, o, end, expected) ||
        !ironwood_postnu63_evaluations(stage).ok) return false;
    if (!eval_offsets_match(stage, o, end) || memcmp(stage->x1, expected, 32))
        return false;
    struct ironwood_postnu63_stage before;
    memcpy(&before, stage, sizeof before);
    return !ironwood_postnu63_evaluations(stage).ok && !memcmp(stage, &before, sizeof before);
}

/* Public upstream-verified PostNu6_3 statement(s) followed by full proof. */
static bool check_stage(const struct v6_wire_view *view, const char *path, const char *theta)
{
    uint8_t basis[IRONWOOD_INSTANCE_ROWS][32], w[32], vk[32], expected[32], input[7590], wire[9400];
    struct v6_wire_view full;
    struct ironwood_postnu63_stage stage;
    size_t size = 0;
    if (!load_instance_basis(basis, w) || !zcl_hex_decode(theta, expected, 32) ||
        !zcl_hex_decode("99b4fa5429bf1f72bbba9c1620e201206287d2cc6373012d5bb99fedb7f72205", vk, 32) ||
        !ironwood_postnu63_proof_size(view->ironwood.count, &size).ok ||
        !stage_fixture(view, path, input, size) || !stage_wire(view, input, size, wire, sizeof wire, &full) ||
        !ironwood_postnu63_first_challenge(&full, vk, basis, w, &stage).ok ||
        stage.proof.position != view->ironwood.count * 320 || memcmp(stage.theta, expected, 32)) return false;
    return check_lookup_stage(&stage, wire) && check_yx_stage(&stage, wire) && check_eval_stage(&stage, wire) && stage_refusals(&full, wire, size, vk, basis, w, &stage);
}

/* Public coinbase fixture: Orchard 0.16.0 PostNu6_3, R1 evidence
 * ironwood-one-action-order.cl26HsAZ/upstream.trace and bundle-proofs/coinbase.bin. */
static bool check_single_action_stage(void)
{
    static const char statement[] =
        "ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f"
        "b693219c3ff5bc96919949548a73262ecf49a2f2c655707d71a3257a8344b1135"
        "6c71da563064037986e6282cc4b302e54c73760200e77f748137043f38a5128d8"
        "486c4e8ebb47b915d6fd18ff75929dfb40adf6435ef20fa5eb3bd488c1ba383e"
        "d1b871bbb512c9f13ce8199907951b48bc9ab5db83cd729ae8f2de27c5e514000100";
    enum { START = 26, FLAGS = START + 820, ANCHOR = FLAGS + 9,
           SIZE = ANCHOR + 32 + 1 + 64 + 64 };
    uint8_t wire[SIZE] = {0}, s[V6_IRONWOOD_STATEMENT_SIZE];
    if (!zcl_hex_decode(statement, s, sizeof s)) return false;
    memcpy(wire, empty, 25); wire[25] = 1;
    memcpy(wire + START, s + 32, 128); wire[FLAGS] = 6; memcpy(wire + ANCHOR, s, 32);
    struct v6_wire_view view;
    return v6_wire_parse(wire, sizeof wire, &view) == V6_WIRE_OK &&
        check_stage(&view, "tests/fixtures/ironwood/postnu63-coinbase.bin",
                    "c646b63addb91bb5431ddffc0f0f054c4edcea95143b7006d5fe3f3e6d41000c");
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
    return check_single_action_stage() && check_first_theta(&v) &&
        check_stage(&v, "tests/fixtures/ironwood/postnu63-funded.bin",
                    "9b4c4db54b5587629516968e6cba32a1c9239bee4c8e5d22dd534b79ed27bc34");
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

/* The fixed shared point was checked with pasta_curves 0.5.1; the oracle
 * source SHA-256 is befa8af956c39f72fb78bfaa723462607995a02317173b8404f6078c3e7d0499.
 * It is independently derived from public test IVK and
 * EPK; this fixture checks the native KDF and AEAD, not Pallas multiplication
 * or note commitment validity. No keys or ciphertext here protect funds. */
static bool recipient_kdf_open(const uint8_t shared[32], const uint8_t *action,
                               uint8_t plain[564])
{
    /* Zcash_OrchardKDF as its 16 bytes: a string literal is 17 long with its
     * terminator and does not fit (Clang warns under -Wextra). */
    static const uint8_t personal[16] = {
        'Z', 'c', 'a', 's', 'h', '_', 'O', 'r', 'c', 'h', 'a', 'r', 'd', 'K', 'D', 'F'};
    static const uint8_t nonce[12] = {0};
    struct blake2b_ctx ctx;
    uint8_t key[32];
    if (blake2b_init_salt_personal(&ctx, 32, NULL, 0, NULL, personal) ||
        blake2b_update(&ctx, shared, 32) ||
        blake2b_update(&ctx, action + 128, 32) ||
        blake2b_final(&ctx, key, sizeof key)) return false;
    return chacha20poly1305_decrypt(action + 160, 580, NULL, 0, nonce, key, plain);
}

static bool check_recipient_wire(struct v6_wire_view *v, struct v6_action_view *checked)
{
    if (v6_wire_parse(recipient_v6_wire, sizeof recipient_v6_wire, v) != V6_WIRE_OK ||
        v->ironwood.count != 2 || v->ironwood.actions.size != 1640 ||
        !v6_bundle_action(&v->ironwood, 1, checked)) return false;
    return true;
}
static bool check_recipient_action(const uint8_t *action, const uint8_t *epk, const uint8_t *cmx,
                                   const struct v6_action_view *checked)
{
    if (memcmp(action + 128, epk, 32) || memcmp(checked->cmx.data, cmx, 32)) return false;
    return true;
}
static bool check_recipient_note(const uint8_t shared[32], const uint8_t *action, const uint8_t d[11],
                                 const uint8_t rseed[32], uint8_t plain[564])
{
    if (!recipient_kdf_open(shared, action, plain) || plain[0] != 3 ||
        memcmp(plain + 1, d, 11) || memcmp(plain + 20, rseed, 32)) return false;
    return true;
}
static bool check_recipient_value(const uint8_t plain[564])
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)plain[12 + i] << (8 * i);
    if (value != 599985000 || plain[52] != 0xf6) return false;
    for (size_t i = 53; i < 564; ++i) if (plain[i]) return false;
    return true;
}
static bool check_recipient_tamper(uint8_t shared[32], const uint8_t *action, uint8_t plain[564])
{
    uint8_t changed[820];
    memcpy(changed, action, sizeof changed); changed[160] ^= 1;
    if (recipient_kdf_open(shared, changed, plain)) return false;
    memcpy(changed, action, sizeof changed); changed[739] ^= 1;
    if (recipient_kdf_open(shared, changed, plain)) return false;
    memcpy(changed, action, sizeof changed); changed[128] ^= 1;
    if (recipient_kdf_open(shared, changed, plain)) return false;
    shared[0] ^= 1;
    return !recipient_kdf_open(shared, action, plain);
}
static bool check_recipient_fixture(void)
{
    static const char shared_hex[] = "734a260f5d6989c881b5eafaa3f0ca6c631905bf5e25faf6380d9aa27604de38";
    static const char epk_hex[] = "08d042bcd0b2b148401e9d2e0fa3bc095239b36d2703497e9504de9d47544e03";
    static const char cmx_hex[] = "3342f7096c4135e66385c795a1c4f2bccabdb17443fec137804b3f5c3ebc9e37";
    static const char diversifier_hex[] = "e50b58450e72a7f2f43775";
    static const char rseed_hex[] = "0120601c3ea2c965205422fec1396d2d6b8d27a145f32b6378908e5d45b663b0";
    struct v6_wire_view v;
    struct v6_action_view checked;
    uint8_t shared[32], epk[32], cmx[32], d[11], rseed[32], plain[564];
    if (!zcl_hex_decode(shared_hex, shared, sizeof shared) ||
        !zcl_hex_decode(epk_hex, epk, sizeof epk) || !zcl_hex_decode(cmx_hex, cmx, sizeof cmx) ||
        !zcl_hex_decode(diversifier_hex, d, sizeof d) || !zcl_hex_decode(rseed_hex, rseed, sizeof rseed) ||
        !check_recipient_wire(&v, &checked)) return false;
    const uint8_t *action = v.ironwood.actions.data + 820;
    return check_recipient_action(action, epk, cmx, &checked) &&
        check_recipient_note(shared, action, d, rseed, plain) && check_recipient_value(plain) &&
        check_recipient_tamper(shared, action, plain);
}

/* x3 followed by eleven u challenges from upstream 0.4.0 public proof traces. */
static const char *const ipa_wide[2][12] = {
    {
        "76b308fe7aab7dbfb9df37301505818e75646faca5bb270764f7eead7419fd84f7e0a69ce71d24da4f088332efd278b8e1309d1729b3ac8fafe93d4198ad022a",
        "7d475ec17da6dce1f9175bb112f7e59b605845d08e9b530289be6dfea63f3f5f53d8c5f767f0feaa94a23f4f7babf893b620002342beba5db43f205167c598ad",
        "e7d1de8163b7b37955b9cabeb460bc5fe38716d15da3f4a232c807f579ec8f9ee93a2d57d82948e261b78338d77db3960cacb1933e38655373c4ebac27670b86",
        "1255e69d04e3c2eca5096fd9bf496ba3b36aab62efc8a42b599599c4d77e833e624a15390e1acdee7bed752d4209d7bbf945764284382a5de3a804c56a0e5d00",
        "8e403e7428bd6c559ffc004e0a44bab3972d235c6f4ec7200c658e4725a26fec4bce1a3526e5b7b64e48fba3f1d608b5199e8733fe7f5496d52fe125a029ad38",
        "352b1c21532515eb0d35fd7a58e91700d17df540db0c1870586723059eb533cc9e9095fafc2af99f44e6493f50e3f4d68f771f3b3f21e199fd611b8083548b37",
        "79373e29bf4178ea91b3fc0f2fa54da645aec4c817a7b70674d075f9ffde5079d182f6bded7a38c976817fe048d624bcf543f832318d68759d7101946ff4ee33",
        "8571f789f2210addd58a547e3195aa44d687c0c28eb787356f9545d3bf53da9ecb040635cf87304e093f12c8a3aeb9414243e3ac0d2a1dcb647e8841c0390c3c",
        "d0e2190795cfda0369c5a9b65088acc456b6ca81c34a61c3a8b7c73b9f67356781b7a475cfea5b13b8ff1e50bd663399051b09fa66b9754fb42c7bbc5fd48398",
        "58a74cea2a23ac12382ba2dd06c065e297da30ff3f315630d67ef52cab0b364fc1c27df17e3628caf4c8aa88647e4bf97a754d3886d55c37d5636e6922487c2b",
        "03fbe2f29f350fef30dd09df8b1f2fbc30e476c4b77d5c59b8f239f6efd5a7b3f7edbcd4cd53402fc15ae28450352c37d3d4344f180c34eeb12bb16de3d67cd5",
        "30579c16d158b0ed1cc355e92573b00d0bb37e55c90920eacec323bb9c8ad89714e09cdebdd32cc7625fc357db66774e058024fd8f93577b00a1363a88767b3b",
    },
    {
        "de3737f8da1db82493a68c791a0e40bdcb8657fef6625256c231e20856c6b16c988d2e837695a9cd67dcfd6cf80f8626e203e410f1df14e5090e6c0da5d8eadb",
        "7628a8ed92d6988a8b0e481b7228c5f7c4929eb18e73fa7ab594535a01a94a0732703420508351d54a720b123a8d1abf1c10c194543cdab41253d177105b342a",
        "435533288987bde85f6aa4566c4ed53bd0cf8ff6d22aa8a65d8710310a25bbb8507b4785e33a7c1a39286c0273a25f29fdf72cc5cc39c39406808febc8525d64",
        "01a9c12a325676c931e21858ffb665ce48202ff7d490cb48be662d94ec6383e838f330c78a37750e2279c6bb1bfcbaafb24846be447a5a0dd96d92d2f5ac3ab5",
        "a08604d832dbe51bd5359445b504c5ee09defccc5f53574acdb5bf95dd4d4afeab5ef8a2eac8a91ef4550137c93bdce9c2f9db65e44c61eb1954652dfaa6b763",
        "c24dc5ef7e935b030caff7a0ef6d4647d3ca1de25af7d00e319a311945dc9c775a810249e1779da26406979fcf9a218ff237708d27f56225e04ee4f9c0bb0a25",
        "9e0f08fb50af4f9cf33b0612b0f3ed41acb8695e6d86d0036373289fc494c6a78936cb31beb3d852e21a10a41b980a4022eadf645a1ac0e04d6c6e82c867df7b",
        "4db7bb1ceb6a797f3aad583a2ae00250d87ffe8063246f8c964cfcb197abb3b28bb64718223bcdb05cbf903c6ec6d88a0273766fb5b5bd49d6215d079709f7a2",
        "91d6783408fa9fbb13f62285cc5721abf49c3582b22825c0af5cf7136bb0a426d5497c90d07011ccafb93b1a8b7c474c6c3c3443d81fa8a6a51c9326d0b52a6d",
        "f2afecb1eb73fc39af6432af9bcb4df29e6a0a287e056ac8a99604dbe6f84633b30b0c14adf18e75df70d215cb42917e76ba24514182189c8539b9c53a09ff8e",
        "9fb3a30ebfe65aaa23a2584fc0f9a6a6937bb923395b614ddeb4da56f2878b6f5697dbba569832d073904b590f927bb2e5a4bc1b23a12235e2800970fb0de8de",
        "a63ea397cc4825c0499e5b4ca186d0835f527912281d8bdf1e33706c36387bb1f29b35151345b73b3853c60fdc1d8a30f105e8149633a2fb7567c56fe3337ae3",
    },
};

/* SHA256 over all 2048 canonical weights, derived independently from each
 * upstream 0.4.0 proof trace by multiplying challenge subsets by -c. */
static bool check_ipa_weights(size_t which, const uint8_t u[IRONWOOD_IPA_ROUNDS][32])
{
    static const char *const initial[] = {
        "ee89c5db280fbfecf24b3ab6d46cb8e080dd34fac5da017c7f0f07ea6c627910",
        "a355eeef3b753ff1e344792e6c78ee937364315f681550094bc4f589d0279531"};
    static const char *const digest[] = {
        "d60dbd5158128e348743b95980c791f5dd4b7ea9551e52e2c010a70f615a66a4",
        "9e5150cc32ced47b7dd5dbf681b47500e6bfe7f64adcb7da9eb62e6e1a7c52e6"};
    const size_t bytes = (size_t)IRONWOOD_IPA_GENERATORS * 32;
    uint8_t seed[32], expected[32], got[32], changed[IRONWOOD_IPA_ROUNDS][32];
    uint8_t *out = malloc(bytes);
    if (!out) return false;
    bool ok = zcl_hex_decode(initial[which], seed, 32) && zcl_hex_decode(digest[which], expected, 32) &&
        ironwood_ipa_generator_weights(seed, u, out, bytes).ok && !memcmp(out, seed, 32);
    struct sha256_ctx hash;
    if (ok) { sha256_init(&hash); sha256_write(&hash, out, bytes); sha256_finalize(&hash, got); ok = !memcmp(got, expected, 32); }
    memcpy(changed, u, sizeof changed); changed[0][0] ^= 1;
    if (ok) ok = ironwood_ipa_generator_weights(seed, changed, out, bytes).ok;
    if (ok) { sha256_init(&hash); sha256_write(&hash, out, bytes); sha256_finalize(&hash, got); ok = memcmp(got, expected, 32) != 0; }
    memset(out, 0xa5, bytes); memset(changed[0], 0xff, 32);
    if (ok) ok = !ironwood_ipa_generator_weights(seed, changed, out, bytes).ok &&
        !ironwood_ipa_generator_weights(seed, u, out, bytes - 1).ok;
    for (size_t i = 0; ok && i < bytes; ++i) ok = out[i] == 0xa5;
    free(out);
    return ok;
}

/* Halo2 0.4.0 x3 and round challenges in proof transcript order. Expected b
 * was independently calculated by expanding the 2048 generator coefficients
 * and evaluating the resulting polynomial over Vesta Fp. */
static bool check_ipa_coefficient_case(size_t which, const char *want)
{
    uint8_t wide[64], x[32], u[IRONWOOD_IPA_ROUNDS][32], expected[32], out[32], before[32];
    if (!zcl_hex_decode(ipa_wide[which][0], wide, 64) ||
        !ironwood_halo2_vesta_scalar(wide, sizeof wide, x, sizeof x).ok ||
        !zcl_hex_decode(want, expected, 32)) return false;
    for (size_t i = 0; i < IRONWOOD_IPA_ROUNDS; ++i)
        if (!zcl_hex_decode(ipa_wide[which][i + 1], wide, 64) ||
            !ironwood_halo2_vesta_scalar(wide, sizeof wide, u[i], sizeof u[i]).ok) return false;
    if (!ironwood_ipa_compute_b(x, u, out).ok || memcmp(out, expected, 32) ||
        !check_ipa_weights(which, u)) return false;
    u[0][0] ^= 1;
    if (!ironwood_ipa_compute_b(x, u, out).ok || !memcmp(out, expected, 32)) return false;
    memset(out, 0xa5, sizeof out); memcpy(before, out, sizeof before);
    memset(u[0], 0xff, sizeof u[0]);
    return !ironwood_ipa_compute_b(x, u, out).ok && !memcmp(out, before, sizeof out);
}

static bool check_ipa_coefficient(void)
{
    return check_ipa_coefficient_case(0, "24a508c3f75cac2041f193ac07a2747bc6a05f5a9cae1aa3cf8f68633b30ca26") &&
        check_ipa_coefficient_case(1, "fad499d170eb991f2726ac0498f6d4e8006f60b209373a8409a468d95ed8721f");
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

static int check_recipient_auth_cases(void)
{
    int failures = 0;
    if (!check_recipient_fixture()) ++failures;
    if (!check_auth_views()) ++failures;
    return failures;
}

static int check_ipa_cases(void) { return !check_ipa_coefficient(); }

int test_transaction_v6_inspect(void)
{
    int failures = check_v6_rpc_cases() + check_recipient_auth_cases() + check_ipa_cases();
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
