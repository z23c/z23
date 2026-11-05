/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Both swap wire decoders refuse an input script longer than
 * ZSWAP_MAX_INPUT_SCRIPT_BYTES before copying it. The length is a byte a peer
 * chooses, up to 255, and the field holds 128. Wires are built by hand here
 * because the encoders never produce an over-long script. Called from
 * test_zswap_ceremony. */

#include "test/test_core.h"

#include "zswap/zswap_assembly.h"
#include "zswap/zswap_ceremony.h"

#include <stdint.h>
#include <string.h>

static const uint8_t k_accept_magic[8] = {'Z','S','W','A','C','P','\r','\n'};
static const uint8_t k_partial_magic[8] = {'Z','S','W','P','T','L','\r','\n'};

/* One input record: txid whose first byte orders it, vout 0, value 1000, then
 * script_len and body_len script bytes. Returns the new offset. */
static size_t sb_put_input(uint8_t *wire, size_t off, uint8_t order,
                           uint8_t script_len, size_t body_len)
{
    memset(wire + off, 0, 32);
    wire[off] = order;
    off += 32;
    memset(wire + off, 0, 4);
    off += 4;
    memset(wire + off, 0, 8);
    wire[off] = 0xe8;
    wire[off + 1] = 0x03;
    off += 8;
    wire[off++] = script_len;
    memset(wire + off, 0x51, body_len);
    return off + body_len;
}

static size_t sb_accept_head(uint8_t *wire, uint8_t num_inputs)
{
    size_t off = 0;
    memcpy(wire, k_accept_magic, sizeof k_accept_magic);
    off += sizeof k_accept_magic;
    wire[off++] = ZSWAP_ACCEPT_VERSION & 0xff;
    wire[off++] = 0;
    memset(wire + off, 0x11, 32);
    off += 32;
    wire[off++] = num_inputs;
    return off;
}

static bool sb_all_zero(const void *p, size_t n)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++)
        if (b[i]) return false;
    return true;
}

static int sb_accept_expect(const char *name, const uint8_t *wire, size_t len,
                            enum zswap_ceremony_error want)
{
    static struct zswap_accept_v1 out;
    enum zswap_ceremony_error got = zswap_accept_decode(wire, len, &out);
    if (got != want) {
        printf("  FAIL accept %s: got %d want %d\n", name, (int)got, (int)want);
        return 1;
    }
    if (!sb_all_zero(&out, sizeof out)) {
        printf("  FAIL accept %s: refused wire left data in out\n", name);
        return 1;
    }
    return 0;
}

/* Two inputs, the first over-long, and the wire ends after its script. A
 * decoder that copies first runs on to the missing second input and reports
 * a short wire; the bound refuses at the first. The overrun stays inside the
 * struct, so this case fails cleanly on an unfixed decoder. */
static int sb_accept_bound(void)
{
    static uint8_t wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    int failures = 0;
    size_t off = sb_accept_head(wire, 2);
    size_t len = sb_put_input(wire, off, 1, 200, 200);
    failures += sb_accept_expect("len 200", wire, len, ZSWAP_CEREMONY_ERR_ACCEPT);
    len = sb_put_input(wire, off, 1, 129, 129);
    failures += sb_accept_expect("len 129", wire, len, ZSWAP_CEREMONY_ERR_ACCEPT);
    len = sb_put_input(wire, off, 1, 255, 255);
    failures += sb_accept_expect("len 255", wire, len, ZSWAP_CEREMONY_ERR_ACCEPT);
    /* A field-sized script is copied, and the missing second input then makes
     * the wire short. */
    len = sb_put_input(wire, off, 1, ZSWAP_MAX_INPUT_SCRIPT_BYTES,
                       ZSWAP_MAX_INPUT_SCRIPT_BYTES);
    failures += sb_accept_expect("len 128", wire, len, ZSWAP_CEREMONY_ERR_WIRE_SIZE);
    /* An over-long length with too few bytes behind it stays a short wire. */
    len = sb_put_input(wire, off, 1, 200, 10);
    failures += sb_accept_expect("len 200 short", wire, len, ZSWAP_CEREMONY_ERR_WIRE_SIZE);
    return failures;
}

/* The last slot of the array: nothing may be written past it. Run after
 * sb_accept_bound, whose failure already reports an unfixed decoder. */
static int sb_accept_last_slot(void)
{
    static uint8_t wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    size_t off = sb_accept_head(wire, ZSWAP_MAX_BUYER_INPUTS);
    for (uint8_t i = 0; i + 1u < ZSWAP_MAX_BUYER_INPUTS; i++)
        off = sb_put_input(wire, off, (uint8_t)(i + 1), 25, 25);
    size_t len = sb_put_input(wire, off, ZSWAP_MAX_BUYER_INPUTS, 255, 255);
    return sb_accept_expect("last slot", wire, len, ZSWAP_CEREMONY_ERR_ACCEPT);
}

static int sb_partial_expect(const char *name, const uint8_t *wire, size_t len,
                             enum zswap_ceremony_error want)
{
    static struct zswap_partial_v1 out;
    enum zswap_ceremony_error got = zswap_partial_decode(wire, len, &out);
    if (got != want) {
        printf("  FAIL partial %s: got %d want %d\n", name, (int)got, (int)want);
        return 1;
    }
    if (!sb_all_zero(&out, sizeof out)) {
        printf("  FAIL partial %s: refused wire left data in out\n", name);
        return 1;
    }
    return 0;
}

static int sb_partial_bound(void)
{
    static uint8_t wire[ZSWAP_PARTIAL_WIRE_MAX_BYTES];
    int failures = 0;
    size_t off = 0;
    memcpy(wire, k_partial_magic, sizeof k_partial_magic);
    off += sizeof k_partial_magic;
    wire[off++] = ZSWAP_PARTIAL_VERSION & 0xff;
    wire[off++] = 0;
    memset(wire + off, 0x11, 64);
    off += 64;
    size_t len = sb_put_input(wire, off, 1, 255, 255);
    failures += sb_partial_expect("len 255", wire, len, ZSWAP_CEREMONY_ERR_ACCEPT);
    /* Keep the wire above the decoder's minimum so the bound is what refuses. */
    len = sb_put_input(wire, off, 1, 250, 250);
    failures += sb_partial_expect("len 250", wire, len, ZSWAP_CEREMONY_ERR_ACCEPT);
    return failures;
}

int zswap_ceremony_script_bound_tests(void)
{
    int failures = sb_accept_bound();
    failures += sb_partial_bound();
    if (failures == 0)
        failures += sb_accept_last_slot();
    if (failures == 0)
        printf("  OK: over-long input scripts refused before the copy\n");
    return failures;
}
