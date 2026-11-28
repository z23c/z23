/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "controllers/transaction_v6_inspect.h"
#include "controllers/transaction_v6_digest.h"
#include "controllers/transaction_v6_rpc.h"
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

static bool check_action_values(const struct v6_bundle *bundle, const struct v6_wire_view *original)
{
    struct v6_action_view first, second;
    if (!v6_bundle_action(bundle, 0, &first) ||
        !v6_bundle_action(bundle, 1, &second)) return false;
    if (bundle->flags.size != 1 || bundle->binding_signature.size != 64 ||
        bundle->signatures.size != 128 || first.cv.data != bundle->actions.data ||
        first.rk.data != bundle->actions.data + 64 || first.cv.size != 32 || first.rk.size != 32 ||
        first.signature.data != bundle->signatures.data || first.signature.size != 64 ||
        second.signature.data != bundle->signatures.data + 64 || second.signature.size != 64 ||
        first.nullifier.size != 32 || first.cmx.size != 32 ||
        second.nullifier.size != 32 || second.cmx.size != 32 ||
        memcmp(first.nullifier.data, original->ironwood.actions.data + 32, 32) ||
        memcmp(first.cmx.data, original->ironwood.actions.data + 96, 32)) return false;
    for (size_t i = 0; i < 32; ++i)
        if (second.nullifier.data[i] != 0x27 || second.cmx.data[i] != 0x64) return false;
    return true;
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

static bool check_statement_views(void)
{
    uint8_t wire[sizeof ironwood_anchor_a], out[V6_IRONWOOD_STATEMENT_SIZE];
    memcpy(wire, ironwood_anchor_a, sizeof wire);
    struct v6_wire_view v;
    if (v6_wire_parse(wire, sizeof wire, &v) != V6_WIRE_OK) return false;
    uint8_t *flags = (uint8_t *)v.ironwood.flags.data;
    for (unsigned f = 0; f < 8; ++f) {
        *flags = (uint8_t)f;
        if (!v6_ironwood_statement(&v, 0, out, sizeof out) ||
            memcmp(out, v.ironwood.anchor.data, 32) ||
            memcmp(out + 32, v.ironwood.actions.data, 128) ||
            out[160] != (f & 1u) || out[161] != ((f >> 1) & 1u) ||
            out[162] != ((f & 4u) == 0)) return false;
    }
    memset(out, 0xa5, sizeof out);
    if (v6_ironwood_statement(&v, 0, out, sizeof out - 1) ||
        v6_ironwood_statement(&v, 1, out, sizeof out) ||
        v6_ironwood_statement(NULL, 0, out, sizeof out) ||
        v6_ironwood_statement(&v, 0, NULL, sizeof out)) return false;
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
static bool check_prefix_frames(void)
{
    uint8_t frames[sizeof empty * 2];
    memcpy(frames, empty, sizeof empty);
    memcpy(frames + sizeof empty, empty, sizeof empty);
    struct v6_wire_view v;
    size_t consumed = 99;
    if (v6_wire_parse_prefix(frames, sizeof frames, &v, &consumed) != V6_WIRE_OK ||
        consumed != sizeof empty || v.header.data != frames) return false;
    if (v6_wire_parse_prefix(frames + consumed, sizeof empty, &v, &consumed) != V6_WIRE_OK ||
        consumed != sizeof empty) return false;
    if (v6_wire_parse(frames, sizeof frames, &v) != V6_WIRE_TRAILING ||
        v.header.data || v.transparent.data) return false;
    consumed = 99;
    if (v6_wire_parse_prefix(frames, sizeof empty - 1, &v, &consumed) == V6_WIRE_OK ||
        consumed != 0 || v.header.data) return false;
    consumed = 99;
    if (v6_wire_parse_prefix(NULL, sizeof empty, &v, &consumed) != V6_WIRE_TRUNCATED ||
        consumed != 0 || v.header.data) return false;
    memset(&v, 0xff, sizeof v);
    if (v6_wire_parse_prefix(frames, sizeof empty, &v, NULL) != V6_WIRE_TRUNCATED ||
        v.header.data || v.transparent.data) return false;
    consumed = 99;
    return v6_wire_parse_prefix(frames, sizeof empty, NULL, &consumed) == V6_WIRE_TRUNCATED &&
           consumed == 0;
}

int test_transaction_v6_inspect(void)
{
    int failures = 0;
    if (!check_v6_rpc_view()) ++failures;
    if (!check_v6_rpc_budget()) ++failures;
    if (!check_v6_rpc_projection_limit()) ++failures;
    if (!check_empty_rpc()) ++failures;
    if (!check_balance_cases()) ++failures;
    if (!check_action_views()) ++failures;
    if (!check_statement_views()) ++failures;
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
