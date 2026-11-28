/* purpose: Check Ironwood bundle cryptographic authentication on public wire fixtures. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "controllers/ironwood_bundle_auth.h"
#include "base/safe_alloc.h"
#include "primitives/transaction_v6_wire.h"
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
int test_ironwood_bundle_auth(void)
{
    CHECK(check_fixture("tests/fixtures/ironwood/postnu63-two-action-payment.bin", 11518) == 0);
    CHECK(check_fixture("tests/fixtures/ironwood/postnu63-ballot-v6.bin", 9622) == 0);
    return 0;
}
