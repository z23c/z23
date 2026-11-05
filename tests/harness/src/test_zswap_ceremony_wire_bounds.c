/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zswap wire decoders: the size gates at their exact edges, the header
 * checks, the refusals that must fire before the decoder reads on, the
 * short-read refusal, and a field-sized input script that must decode with
 * every neighbouring field intact. Called from test_zswap_ceremony.
 *
 * Two techniques keep a weakened check from hiding behind a later one:
 *  - a wire is cut or ends right after the field under test, so a check that
 *    does not fire sends the decoder on into missing bytes (WIRE_SIZE
 *    instead of ACCEPT);
 *  - the bytes after a cut are 0xff, so a read that ignores the wire length
 *    decodes a huge number the range checks refuse (ACCEPT instead of
 *    WIRE_SIZE). Zero bytes would be rescued by the final length check. */

#include "test/test_core.h"

#include "zswap/zswap_assembly.h"
#include "zswap/zswap_ceremony.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WB_CHECK(name, expr) do {                                       \
    if (expr) { printf("  zswap wire_bounds: %s... OK\n", (name)); }     \
    else { printf("  zswap wire_bounds: %s... FAIL\n", (name));          \
        failures++; }                                                   \
} while (0)

#define WB_I64MAX ((uint64_t)INT64_MAX)
#define WB_BUF_BYTES (ZSWAP_ACCEPT_WIRE_MAX_BYTES + 16u)

/* Offsets in a partial wire: magic 8, version 2, two roots 64, then the
 * token input record (txid 32, vout 4, value 8, script_len 1, script). */
#define WB_P_VALUE 110u
#define WB_P_SCRIPT_LEN 118u
#define WB_P_SCRIPT 119u
/* Offsets in an accept wire: header 42, num_inputs 1, then input records. */
#define WB_A_FIRST 43u
#define WB_A_VALUE (WB_A_FIRST + 36u)
#define WB_A_SCRIPT_LEN (WB_A_FIRST + 44u)

static uint8_t g_buf[WB_BUF_BYTES];

static void wb_put_u64(uint8_t *p, uint64_t v)
{
    for (size_t i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static void wb_input(struct zswap_swap_input *in, uint8_t base,
                     uint16_t script_len)
{
    memset(in, 0, sizeof(*in));
    memset(in->txid, 0x22, 32);
    in->txid[0] = base;
    in->vout = base;
    in->value_sats = 1000 + base;
    in->script_len = script_len;
    for (size_t i = 0; i < script_len; i++)
        in->script_pub_key[i] = (uint8_t)(base * 5u + i * 3u + 1u);
}

static void wb_addr(char field[ZSWAP_ADDRESS_FIELD_BYTES], char c)
{
    memset(field, 0, ZSWAP_ADDRESS_FIELD_BYTES);
    memset(field, c, 35);
}

static void wb_partial(struct zswap_partial_v1 *p, uint16_t script_len)
{
    memset(p, 0, sizeof(*p));
    p->schema_version = ZSWAP_PARTIAL_VERSION;
    memset(p->quote_root, 0x11, 32);
    memset(p->assembly_root, 0x12, 32);
    wb_input(&p->seller.token_input, 0x31, script_len);
    wb_addr(p->seller.zcl_recv_address, 'a');
    wb_addr(p->seller.change_address, 'b');
    p->seller.deadline_unix = 1754000045LL;
    p->seller_pubkey[0] = 0x02;
    memset(p->seller_pubkey + 1, 0x33, 32);
    p->sig_len = 71;
    for (size_t i = 0; i < 70; i++) p->signature[i] = (uint8_t)(i + 1);
    p->signature[70] = 0x01;
}

static size_t wb_partial_wire(uint8_t *wire, uint16_t script_len)
{
    struct zswap_partial_v1 p;
    wb_partial(&p, script_len);
    size_t len = 0;
    if (zswap_partial_encode(&p, wire, WB_BUF_BYTES, &len) != ZSWAP_CEREMONY_OK)
        return 0;
    return len;
}

static void wb_accept(struct zswap_accept_v1 *a, size_t n, uint16_t script_len)
{
    memset(a, 0, sizeof(*a));
    a->schema_version = ZSWAP_ACCEPT_VERSION;
    memset(a->quote_root, 0x44, 32);
    for (size_t i = 0; i < n; i++)
        wb_input(&a->buyer.inputs[i], (uint8_t)(0x10 + i), script_len);
    a->buyer.num_inputs = n;
    wb_addr(a->buyer.token_recv_address, 'c');
    wb_addr(a->buyer.change_address, 'd');
    a->buyer.fee_sats = 10000;
    a->buyer.deadline_unix = 1754000045LL;
}

static size_t wb_accept_wire(uint8_t *wire, size_t n, uint16_t script_len)
{
    struct zswap_accept_v1 a;
    wb_accept(&a, n, script_len);
    size_t len = 0;
    if (zswap_accept_encode(&a, wire, WB_BUF_BYTES, &len) != ZSWAP_CEREMONY_OK)
        return 0;
    return len;
}

/* Decode the first len bytes of g_buf as each wire. */
static enum zswap_ceremony_error wb_adec(size_t len)
{
    struct zswap_accept_v1 out;
    return zswap_accept_decode(g_buf, len, &out);
}

static enum zswap_ceremony_error wb_pdec(size_t len)
{
    struct zswap_partial_v1 out;
    return zswap_partial_decode(g_buf, len, &out);
}

/* g_buf := the first len bytes of wire, 0xff after them. */
static void wb_load(const uint8_t *wire, size_t len)
{
    memset(g_buf, 0xff, sizeof(g_buf));
    memcpy(g_buf, wire, len);
}

/* ── size gates ────────────────────────────────────────────────────── */

static int wb_size_gates(void)
{
    int failures = 0;
    /* A zero buffer has no magic, so a wire past the size gate is WIRE_MAGIC
     * and one the gate refuses is WIRE_SIZE: the code names the side. */
    memset(g_buf, 0, sizeof(g_buf));
    WB_CHECK("accept 42 bytes is under the minimum",
             wb_adec(42) == ZSWAP_CEREMONY_ERR_WIRE_SIZE);
    WB_CHECK("accept 43 bytes passes the gate",
             wb_adec(43) == ZSWAP_CEREMONY_ERR_WIRE_MAGIC);
    WB_CHECK("accept at the maximum passes the gate",
             wb_adec(ZSWAP_ACCEPT_WIRE_MAX_BYTES) ==
                 ZSWAP_CEREMONY_ERR_WIRE_MAGIC);
    WB_CHECK("accept one over the maximum is refused",
             wb_adec(ZSWAP_ACCEPT_WIRE_MAX_BYTES + 1) ==
                 ZSWAP_CEREMONY_ERR_WIRE_SIZE);
    WB_CHECK("accept empty is refused",
             wb_adec(0) == ZSWAP_CEREMONY_ERR_WIRE_SIZE);
    WB_CHECK("partial 362 bytes is under the minimum",
             wb_pdec(362) == ZSWAP_CEREMONY_ERR_WIRE_SIZE);
    WB_CHECK("partial 363 bytes passes the gate",
             wb_pdec(363) == ZSWAP_CEREMONY_ERR_WIRE_MAGIC);
    WB_CHECK("partial at the maximum passes the gate",
             wb_pdec(ZSWAP_PARTIAL_WIRE_MAX_BYTES) ==
                 ZSWAP_CEREMONY_ERR_WIRE_MAGIC);
    WB_CHECK("partial one over the maximum is refused",
             wb_pdec(ZSWAP_PARTIAL_WIRE_MAX_BYTES + 1) ==
                 ZSWAP_CEREMONY_ERR_WIRE_SIZE);
    WB_CHECK("partial empty is refused",
             wb_pdec(0) == ZSWAP_CEREMONY_ERR_WIRE_SIZE);
    return failures;
}

/* ── header: magic and version ─────────────────────────────────────── */

static int wb_header_one(const char *name, const uint8_t *wire, size_t len,
                         bool is_partial)
{
    int failures = 0;
    (void)name;
    wb_load(wire, len);
    WB_CHECK(is_partial ? "partial: the untouched wire decodes"
                        : "accept: the untouched wire decodes",
             (is_partial ? wb_pdec(len) : wb_adec(len)) == ZSWAP_CEREMONY_OK);
    wb_load(wire, len);
    g_buf[7] ^= 0x01;
    WB_CHECK(is_partial ? "partial: last magic byte flipped"
                        : "accept: last magic byte flipped",
             (is_partial ? wb_pdec(len) : wb_adec(len)) ==
                 ZSWAP_CEREMONY_ERR_WIRE_MAGIC);
    wb_load(wire, len);
    g_buf[8] = 2;
    WB_CHECK(is_partial ? "partial: version low byte" : "accept: version low byte",
             (is_partial ? wb_pdec(len) : wb_adec(len)) ==
                 ZSWAP_CEREMONY_ERR_VERSION);
    wb_load(wire, len);
    g_buf[9] = 1;
    WB_CHECK(is_partial ? "partial: version high byte"
                        : "accept: version high byte",
             (is_partial ? wb_pdec(len) : wb_adec(len)) ==
                 ZSWAP_CEREMONY_ERR_VERSION);
    return failures;
}

static int wb_header(void)
{
    static uint8_t wire[WB_BUF_BYTES];
    int failures = 0;
    size_t len = wb_accept_wire(wire, 2, 25);
    WB_CHECK("accept wire builds", len == 327);
    if (len == 0) return failures;
    failures += wb_header_one("accept", wire, len, false);
    len = wb_partial_wire(wire, 25);
    WB_CHECK("partial wire builds", len == 362 + 25);
    if (len == 0) return failures;
    failures += wb_header_one("partial", wire, len, true);
    return failures;
}

/* ── short reads ───────────────────────────────────────────────────── */

/* Each cut ends inside a field; 0xff follows. A decoder that read past the
 * wire would see a huge value or length and refuse it with another code. */
static int wb_accept_cuts(void)
{
    static uint8_t wire[WB_BUF_BYTES];
    int failures = 0;
    size_t len = wb_accept_wire(wire, 2, 25);
    if (len != 327) return 1;
    static const size_t inside[] = {
        WB_A_FIRST + 10,            /* first txid */
        WB_A_FIRST + 34,            /* first vout */
        WB_A_VALUE + 3,             /* first value */
        WB_A_SCRIPT_LEN,            /* first script length byte */
        WB_A_SCRIPT_LEN + 1 + 10,   /* first script */
        WB_A_FIRST + 70 + 20,       /* second txid */
        327 - 16 - 64 - 30,         /* token address */
        327 - 16 - 20,              /* change address */
        327 - 12,                   /* fee */
        327 - 4,                    /* deadline */
    };
    for (size_t i = 0; i < sizeof(inside) / sizeof(inside[0]); i++) {
        wb_load(wire, inside[i]);
        if (wb_adec(inside[i]) != ZSWAP_CEREMONY_ERR_WIRE_SIZE) {
            printf("  zswap wire_bounds: accept cut at %zu... FAIL\n", inside[i]);
            failures++;
        }
    }
    return failures;
}

static int wb_partial_cuts(void)
{
    static uint8_t wire[WB_BUF_BYTES];
    int failures = 0;
    size_t len = wb_partial_wire(wire, ZSWAP_MAX_INPUT_SCRIPT_BYTES);
    if (len != ZSWAP_PARTIAL_WIRE_MAX_BYTES) return 1;
    /* With a 128 byte script the minimum length falls inside the second
     * address (script ends at 247, first address 247..310, second 311..374). */
    static const size_t inside[] = {
        363,                    /* second address */
        370,                    /* second address, near its end */
        378,                    /* deadline */
    };
    for (size_t i = 0; i < sizeof(inside) / sizeof(inside[0]); i++) {
        wb_load(wire, inside[i]);
        if (wb_pdec(inside[i]) != ZSWAP_CEREMONY_ERR_WIRE_SIZE) {
            printf("  zswap wire_bounds: partial cut at %zu... FAIL\n", inside[i]);
            failures++;
        }
    }
    return failures;
}

/* ── refusals that must fire before the decoder reads on ───────────── */

/* Accept: the wire ends right after the first input's script length byte
 * (25). A value the decoder refuses is ACCEPT; one it lets through runs into
 * the missing script and is WIRE_SIZE. */
static int wb_accept_value(void)
{
    static uint8_t wire[WB_BUF_BYTES];
    int failures = 0;
    size_t len = wb_accept_wire(wire, 2, 25);
    if (len != 327) return 1;
    const size_t cut = WB_A_SCRIPT_LEN + 1;
    static const struct { uint64_t v; enum zswap_ceremony_error want; } tab[] = {
        { 0, ZSWAP_CEREMONY_ERR_ACCEPT },
        { 1, ZSWAP_CEREMONY_ERR_WIRE_SIZE },
        { WB_I64MAX, ZSWAP_CEREMONY_ERR_WIRE_SIZE },
        { WB_I64MAX + 1, ZSWAP_CEREMONY_ERR_ACCEPT },
        { UINT64_MAX, ZSWAP_CEREMONY_ERR_ACCEPT },
    };
    for (size_t i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
        wb_load(wire, cut);
        wb_put_u64(g_buf + WB_A_VALUE, tab[i].v);
        if (wb_adec(cut) != tab[i].want) {
            printf("  zswap wire_bounds: accept value case %zu... FAIL\n", i);
            failures++;
        }
    }
    return failures;
}

/* Accept: one trailing byte after a complete wire. A fee or deadline past
 * INT64_MAX is refused as ACCEPT before the length check; a legal one then
 * meets the trailing byte and is WIRE_SIZE. */
static int wb_accept_terms(void)
{
    static uint8_t wire[WB_BUF_BYTES];
    int failures = 0;
    size_t len = wb_accept_wire(wire, 2, 25);
    if (len != 327) return 1;
    static const struct {
        size_t back; uint64_t v; enum zswap_ceremony_error want;
    } tab[] = {
        { 16, WB_I64MAX, ZSWAP_CEREMONY_ERR_WIRE_SIZE },
        { 16, WB_I64MAX + 1, ZSWAP_CEREMONY_ERR_ACCEPT },
        { 8, WB_I64MAX, ZSWAP_CEREMONY_ERR_WIRE_SIZE },
        { 8, WB_I64MAX + 1, ZSWAP_CEREMONY_ERR_ACCEPT },
        { 8, UINT64_MAX, ZSWAP_CEREMONY_ERR_ACCEPT },
    };
    for (size_t i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
        wb_load(wire, len);
        wb_put_u64(g_buf + len - tab[i].back, tab[i].v);
        g_buf[len] = 0;
        if (wb_adec(len + 1) != tab[i].want) {
            printf("  zswap wire_bounds: accept terms case %zu... FAIL\n", i);
            failures++;
        }
    }
    return failures;
}

/* Partial: the token input's value, on a wire whose script length byte
 * claims 100 bytes so that a value the decoder lets through runs off the
 * end. */
static int wb_partial_value(void)
{
    static uint8_t wire[WB_BUF_BYTES];
    int failures = 0;
    size_t len = wb_partial_wire(wire, 1);
    if (len != 363) return 1;
    static const struct { uint64_t v; enum zswap_ceremony_error want; } tab[] = {
        { 0, ZSWAP_CEREMONY_ERR_ACCEPT },
        { 1, ZSWAP_CEREMONY_ERR_WIRE_SIZE },
        { WB_I64MAX, ZSWAP_CEREMONY_ERR_WIRE_SIZE },
        { WB_I64MAX + 1, ZSWAP_CEREMONY_ERR_ACCEPT },
        { UINT64_MAX, ZSWAP_CEREMONY_ERR_ACCEPT },
    };
    for (size_t i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
        wb_load(wire, len);
        g_buf[WB_P_SCRIPT_LEN] = 100;
        wb_put_u64(g_buf + WB_P_VALUE, tab[i].v);
        if (wb_pdec(len) != tab[i].want) {
            printf("  zswap wire_bounds: partial value case %zu... FAIL\n", i);
            failures++;
        }
    }
    return failures;
}

/* Partial: the deadline, on a wire that ends right after it (a 108 byte
 * script, 363 bytes in all). A legal deadline runs into the missing pubkey. */
static int wb_partial_deadline(void)
{
    static uint8_t wire[WB_BUF_BYTES];
    int failures = 0;
    size_t len = wb_partial_wire(wire, 108);
    if (len != 362 + 108) return 1;
    const size_t off = WB_P_SCRIPT + 108 + 128;
    static const struct { uint64_t v; enum zswap_ceremony_error want; } tab[] = {
        { WB_I64MAX, ZSWAP_CEREMONY_ERR_WIRE_SIZE },
        { WB_I64MAX + 1, ZSWAP_CEREMONY_ERR_ACCEPT },
        { UINT64_MAX, ZSWAP_CEREMONY_ERR_ACCEPT },
    };
    for (size_t i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
        wb_load(wire, off + 8);
        wb_put_u64(g_buf + off, tab[i].v);
        if (wb_pdec(off + 8) != tab[i].want) {
            printf("  zswap wire_bounds: partial deadline case %zu... FAIL\n", i);
            failures++;
        }
    }
    return failures;
}

/* ── the script field limit ────────────────────────────────────────── */

static bool wb_input_same(const struct zswap_swap_input *a,
                          const struct zswap_swap_input *b)
{
    return memcmp(a->txid, b->txid, 32) == 0 && a->vout == b->vout &&
           a->value_sats == b->value_sats && a->script_len == b->script_len &&
           memcmp(a->script_pub_key, b->script_pub_key,
                  ZSWAP_MAX_INPUT_SCRIPT_BYTES) == 0;
}

/* A partial whose token script fills the field decodes, and every field
 * after the script is the one that went in. */
static int wb_partial_full_script(void)
{
    static uint8_t wire[WB_BUF_BYTES];
    int failures = 0;
    struct zswap_partial_v1 want, got;
    wb_partial(&want, ZSWAP_MAX_INPUT_SCRIPT_BYTES);
    size_t len = wb_partial_wire(wire, ZSWAP_MAX_INPUT_SCRIPT_BYTES);
    WB_CHECK("partial with a 128 byte script is the maximum size",
             len == ZSWAP_PARTIAL_WIRE_MAX_BYTES);
    memset(&got, 0xa5, sizeof(got));
    WB_CHECK("partial with a 128 byte script decodes",
             zswap_partial_decode(wire, len, &got) == ZSWAP_CEREMONY_OK);
    WB_CHECK("128 byte script: token input intact",
             wb_input_same(&got.seller.token_input, &want.seller.token_input));
    WB_CHECK("128 byte script: addresses intact (the fields after the script)",
             memcmp(got.seller.zcl_recv_address, want.seller.zcl_recv_address,
                    ZSWAP_ADDRESS_FIELD_BYTES) == 0 &&
             memcmp(got.seller.change_address, want.seller.change_address,
                    ZSWAP_ADDRESS_FIELD_BYTES) == 0);
    WB_CHECK("128 byte script: deadline, pubkey and signature intact",
             got.seller.deadline_unix == want.seller.deadline_unix &&
             memcmp(got.seller_pubkey, want.seller_pubkey, 33) == 0 &&
             got.sig_len == want.sig_len &&
             memcmp(got.signature, want.signature, ZSWAP_SIG_FIELD_BYTES) == 0);
    WB_CHECK("128 byte script: roots intact",
             memcmp(got.quote_root, want.quote_root, 32) == 0 &&
             memcmp(got.assembly_root, want.assembly_root, 32) == 0);
    /* One byte more than the field: refused before the copy. */
    wb_load(wire, len);
    g_buf[WB_P_SCRIPT_LEN] = ZSWAP_MAX_INPUT_SCRIPT_BYTES + 1;
    WB_CHECK("partial with a 129 byte script is refused",
             wb_pdec(len) == ZSWAP_CEREMONY_ERR_ACCEPT);
    return failures;
}

/* The largest accept, every script the full field: each input decodes with
 * its own txid, value and script, and the fields after the last record. */
static int wb_accept_full_scripts(void)
{
    static uint8_t wire[WB_BUF_BYTES];
    int failures = 0;
    struct zswap_accept_v1 want, got;
    wb_accept(&want, ZSWAP_MAX_BUYER_INPUTS, ZSWAP_MAX_INPUT_SCRIPT_BYTES);
    size_t len = wb_accept_wire(wire, ZSWAP_MAX_BUYER_INPUTS,
                                ZSWAP_MAX_INPUT_SCRIPT_BYTES);
    WB_CHECK("accept of 16 full scripts is the maximum size",
             len == ZSWAP_ACCEPT_WIRE_MAX_BYTES);
    memset(&got, 0xa5, sizeof(got));
    WB_CHECK("accept of 16 full scripts decodes",
             zswap_accept_decode(wire, len, &got) == ZSWAP_CEREMONY_OK &&
             got.buyer.num_inputs == ZSWAP_MAX_BUYER_INPUTS);
    bool same = true;
    for (size_t i = 0; i < ZSWAP_MAX_BUYER_INPUTS; i++)
        same = same && wb_input_same(&got.buyer.inputs[i], &want.buyer.inputs[i]);
    WB_CHECK("full scripts: every input intact", same);
    WB_CHECK("full scripts: addresses, fee and deadline intact",
             memcmp(got.buyer.token_recv_address, want.buyer.token_recv_address,
                    ZSWAP_ADDRESS_FIELD_BYTES) == 0 &&
             memcmp(got.buyer.change_address, want.buyer.change_address,
                    ZSWAP_ADDRESS_FIELD_BYTES) == 0 &&
             got.buyer.fee_sats == want.buyer.fee_sats &&
             got.buyer.deadline_unix == want.buyer.deadline_unix);
    return failures;
}

int zswap_ceremony_wire_bounds_tests(void)
{
    int failures = 0;
    failures += wb_size_gates();
    failures += wb_header();
    failures += wb_accept_cuts();
    failures += wb_partial_cuts();
    failures += wb_accept_value();
    failures += wb_accept_terms();
    failures += wb_partial_value();
    failures += wb_partial_deadline();
    failures += wb_partial_full_script();
    failures += wb_accept_full_scripts();
    return failures;
}
