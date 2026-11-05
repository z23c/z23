/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Exercise the peer-reachable zswap wire decoders (accept, partial,
 * quote ad) under sanitizers and hold each to one canonical encoding. */

#include "zswap/zswap_ceremony.h"
#include "zswap/zswap_quote.h"

#include "fuzz_checks.h"

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

volatile sig_atomic_t g_shutdown_requested = 0;

#define FUZZ_ZSWAP_ARMS 3u
#define FUZZ_ZSWAP_MAX_INPUT (ZSWAP_ACCEPT_WIRE_MAX_BYTES + 64u)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* A decode error must leave the output zeroed (the header's contract). */
static void fuzz_accept(const uint8_t *wire, size_t wire_len)
{
    struct zswap_accept_v1 decoded;
    if (zswap_accept_decode(wire, wire_len, &decoded) != ZSWAP_CEREMONY_OK) {
        require_zeroed(&decoded, sizeof(decoded));
        return;
    }
    uint8_t canonical[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    size_t canonical_len = 0;
    if (zswap_accept_encode(&decoded, canonical, sizeof(canonical),
                            &canonical_len) != ZSWAP_CEREMONY_OK ||
        canonical_len != wire_len ||
        memcmp(wire, canonical, wire_len) != 0)
        abort();
}

static void fuzz_partial(const uint8_t *wire, size_t wire_len)
{
    struct zswap_partial_v1 decoded;
    if (zswap_partial_decode(wire, wire_len, &decoded) != ZSWAP_CEREMONY_OK) {
        require_zeroed(&decoded, sizeof(decoded));
        return;
    }
    uint8_t canonical[ZSWAP_PARTIAL_WIRE_MAX_BYTES];
    size_t canonical_len = 0;
    if (zswap_partial_encode(&decoded, canonical, sizeof(canonical),
                             &canonical_len) != ZSWAP_CEREMONY_OK ||
        canonical_len != wire_len ||
        memcmp(wire, canonical, wire_len) != 0)
        abort();
}

static void fuzz_quote(const uint8_t *wire, size_t wire_len)
{
    struct zswap_quote_v1 decoded;
    if (zswap_quote_decode(wire, wire_len, &decoded) != ZSWAP_QUOTE_OK) {
        require_zeroed(&decoded, sizeof(decoded));
        return;
    }
    uint8_t canonical[ZSWAP_QUOTE_WIRE_BYTES];
    if (zswap_quote_encode(&decoded, canonical) != ZSWAP_QUOTE_OK ||
        wire_len != sizeof(canonical) ||
        memcmp(wire, canonical, sizeof(canonical)) != 0)
        abort();
}

/* The first byte picks the decoder; the rest is the wire. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size == 0 || size > FUZZ_ZSWAP_MAX_INPUT)
        return 0;

    const uint8_t *wire = data + 1;
    size_t wire_len = size - 1;
    switch (data[0] % FUZZ_ZSWAP_ARMS) {
    case 0: fuzz_accept(wire, wire_len); break;
    case 1: fuzz_partial(wire, wire_len); break;
    default: fuzz_quote(wire, wire_len); break;
    }
    return 0;
}
