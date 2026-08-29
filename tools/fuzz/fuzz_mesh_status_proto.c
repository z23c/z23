/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Exercise the bounded private machine-status wire under sanitizers. */

#include "session/mesh_status_proto.h"

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

volatile sig_atomic_t g_shutdown_requested = 0;

#define FUZZ_MESH_STATUS_ARMS 2u
#define FUZZ_MESH_STATUS_MAX_INPUT \
    (MESH_STATUS_RECEIPT_V1_MAX_WIRE_BYTES + 1u)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void fuzz_request(const uint8_t *wire, size_t wire_len)
{
    struct mesh_status_request_v1 decoded;
    if (mesh_status_request_v1_decode(&decoded, wire, wire_len) !=
        MESH_STATUS_PROTO_OK)
        return;

    uint8_t canonical[MESH_STATUS_REQUEST_V1_WIRE_BYTES];
    if (mesh_status_request_v1_encode(&decoded, canonical) !=
            MESH_STATUS_PROTO_OK ||
        wire_len != sizeof(canonical) ||
        memcmp(wire, canonical, sizeof(canonical)) != 0)
        abort();
}

static void fuzz_receipt(const uint8_t *wire, size_t wire_len)
{
    struct mesh_status_receipt_v1 decoded;
    if (mesh_status_receipt_v1_decode(&decoded, wire, wire_len) !=
        MESH_STATUS_PROTO_OK)
        return;

    uint8_t canonical[MESH_STATUS_RECEIPT_V1_MAX_WIRE_BYTES];
    size_t canonical_len = 0;
    if (mesh_status_receipt_v1_encode(&decoded, canonical,
                                      sizeof(canonical), &canonical_len) !=
            MESH_STATUS_PROTO_OK ||
        canonical_len != wire_len ||
        memcmp(wire, canonical, wire_len) != 0)
        abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size == 0 || size > FUZZ_MESH_STATUS_MAX_INPUT)
        return 0;

    const uint8_t *wire = data + 1;
    size_t wire_len = size - 1;
    if ((data[0] % FUZZ_MESH_STATUS_ARMS) == 0)
        fuzz_request(wire, wire_len);
    else
        fuzz_receipt(wire, wire_len);
    return 0;
}
