/* purpose: Check Ironwood bundle cryptographic authentication on public wire fixtures. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "controllers/ironwood_bundle_auth.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "core/serialize.h"
#include "primitives/transaction.h"
#include "primitives/transaction_v6_decode.h"
#include "primitives/transaction_v6_wire.h"
#include "services/ironwood_verification_setup.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "bundle auth line %d: %s\n", __LINE__, #x); return 1; } } while (0)
static int check_fixture(const char *path, size_t size)
{
    uint8_t wire[11518];
    CHECK(size <= sizeof wire);
    FILE *f = fopen(path, "rb");
    CHECK(f);
    bool loaded = fread(wire, 1, size, f) == size && fgetc(f) == EOF && !ferror(f);
    CHECK(fclose(f) == 0 && loaded);
    struct v6_wire_view view;
    CHECK(v6_core_parse(wire, size, &view) == V6_WIRE_OK);
    CHECK(view.ironwood.count == 2 && view.inputs == 0);
    struct zcl_result r = ironwood_bundle_authenticate(wire, size, NULL, 0);
    if (!r.ok) fprintf(stderr, "valid Ironwood bundle refused: %s\n", r.message);
    CHECK(r.ok);

    struct transaction tx;
    struct byte_stream stream;
    stream_init_from_data(&stream, wire, size);
    CHECK(transaction_v6_decode_prefix(&tx, &stream, size) && !stream_remaining(&stream));
    uint32_t branch = zcl_read_u32_le(view.header.data + 8);
    const struct ironwood_verification_setup *setup = ironwood_postnu63_verification_setup();
    r = ironwood_bundle_authenticate_checked(&tx, branch, NULL, 0, setup);
    if (!r.ok) fprintf(stderr, "checked Ironwood bundle refused: %s\n", r.message);
    CHECK(r.ok);
    CHECK(!ironwood_bundle_authenticate_checked(&tx, branch ^ 1, NULL, 0, setup).ok);
    CHECK(!ironwood_bundle_authenticate_checked(&tx, branch, NULL, 0, NULL).ok);
    int foreign = 0;
    CHECK(!ironwood_bundle_authenticate_checked(&tx, branch, NULL, 0,
        (const struct ironwood_verification_setup *)&foreign).ok);
    struct transaction_v6_prevout unexpected_checked = {0};
    CHECK(!ironwood_bundle_authenticate_checked(&tx, branch, &unexpected_checked, 1, setup).ok);
    transaction_free(&tx);

    struct v6_action_view action;
    CHECK(v6_core_bundle_action(&view.ironwood, 0, &action));
    size_t spend = (size_t)(action.signature.data - wire);
    size_t binding = (size_t)(view.ironwood.binding_signature.data - wire);
    size_t proof = (size_t)(view.ironwood.proof.data - wire) + view.ironwood.proof.size - 32;
    wire[spend] ^= 1;
    CHECK(!ironwood_bundle_authenticate(wire, size, NULL, 0).ok);
    wire[spend] ^= 1;
    wire[binding] ^= 1;
    CHECK(!ironwood_bundle_authenticate(wire, size, NULL, 0).ok);
    wire[binding] ^= 1;
    wire[proof] ^= 1;
    CHECK(!ironwood_bundle_authenticate(wire, size, NULL, 0).ok);
    wire[proof] ^= 1;
    CHECK(!ironwood_bundle_authenticate(wire, size - 1, NULL, 0).ok);
    struct v6_prevout unexpected = {0};
    CHECK(!ironwood_bundle_authenticate(wire, size, &unexpected, 1).ok);
    zcl_alloc_fault_fail_next("ironwood bundle commitments");
    r = ironwood_bundle_authenticate(wire, size, NULL, 0);
    zcl_alloc_fault_clear();
    CHECK(!r.ok);
    return 0;
}

static int check_funded_prevout(void)
{
    uint8_t wire[9313];
    FILE *f = fopen("tests/fixtures/ironwood/postnu63-h1-reward-spend.v6", "rb");
    CHECK(f);
    bool loaded = fread(wire, 1, sizeof wire, f) == sizeof wire &&
        fgetc(f) == EOF && !ferror(f);
    CHECK(fclose(f) == 0 && loaded);
    struct transaction tx;
    struct byte_stream stream;
    stream_init_from_data(&stream, wire, sizeof wire);
    CHECK(transaction_v6_decode_prefix(&tx, &stream, sizeof wire) &&
        !stream_remaining(&stream) && tx.num_vin == 1);
    struct v6_wire_view view;
    CHECK(v6_core_parse(wire, sizeof wire, &view) == V6_WIRE_OK);
    uint32_t branch = zcl_read_u32_le(view.header.data + 8);
    uint8_t script[25] = {
        0x76, 0xa9, 0x14, 0x79, 0xb0, 0x00, 0x88, 0x76, 0x26, 0xb2, 0x94, 0xa9, 0x14,
        0x50, 0x1a, 0x4c, 0xd2, 0x26, 0xb5, 0x8b, 0x23, 0x59, 0x83, 0x88, 0xac
    };
    struct transaction_v6_prevout prevout = {1250000000, script, sizeof script};
    const struct ironwood_verification_setup *setup = ironwood_postnu63_verification_setup();
    struct zcl_result r = ironwood_bundle_authenticate_checked(&tx, branch, &prevout, 1, setup);
    if (!r.ok) fprintf(stderr, "funded checked Ironwood bundle refused: %s\n", r.message);
    CHECK(r.ok);
    --prevout.amount;
    CHECK(!ironwood_bundle_authenticate_checked(&tx, branch, &prevout, 1, setup).ok);
    ++prevout.amount;
    script[3] ^= 1;
    CHECK(!ironwood_bundle_authenticate_checked(&tx, branch, &prevout, 1, setup).ok);
    script[3] ^= 1;
    transaction_free(&tx);
    return 0;
}

int test_ironwood_bundle_auth(void)
{
    CHECK(check_fixture("tests/fixtures/ironwood/postnu63-two-action-payment.bin", 11518) == 0);
    CHECK(check_fixture("tests/fixtures/ironwood/postnu63-ballot-v6.bin", 9622) == 0);
    CHECK(check_funded_prevout() == 0);
    return 0;
}
