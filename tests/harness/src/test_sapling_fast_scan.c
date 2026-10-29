/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Characterization of the Sapling commitment scanner: the public
 * fast_scan_sapling_commitments() and its static scan_tx(), pinned before the
 * scan_tx() complexity split. Every row fixes the return value, the cm bytes
 * written, and the untouched tail of the output array.
 *
 * Blocks are built here byte by byte from the wire sizes the scanner skips,
 * so each row drives one parse branch: Sapling v4 outputs (cv skipped, cm
 * copied, capped at max_cms), spends and the binding signature (present only
 * when spends or outputs exist), JoinSplits in Sapling v4, in overwintered v4
 * with a foreign group id (192-byte proof) and in v2 (296-byte proof), pre-v2
 * transactions (no JoinSplit count), and malformed transactions (-1 from
 * scan_tx: a zero block result, or the partial total once a cm was found). */

#include "test/test_core.h"

#include "sapling/fast_scan.h"

#define SF_BUF_CAP 8192
#define SF_CM_SLOTS 4
#define SF_SENTINEL 0xEE

struct sf_buf {
    uint8_t b[SF_BUF_CAP];
    size_t n;
    bool ok;
};

struct sf_row {
    const char *name;
    void (*build)(struct sf_buf *w);
    int max_cms;
    int want_ret;
    uint8_t want_seed[SF_CM_SLOTS]; /* cm fill byte per written slot */
};

static const uint8_t sf_none[1] = {0};

static void sf_init(struct sf_buf *w)
{
    memset(w, 0, sizeof(*w));
    w->ok = true;
}

static void sf_fill(struct sf_buf *w, uint8_t v, size_t count)
{
    if (!w->ok || count > SF_BUF_CAP - w->n) {
        w->ok = false;
        return;
    }
    memset(w->b + w->n, v, count);
    w->n += count;
}

static void sf_u8(struct sf_buf *w, uint8_t v)
{
    sf_fill(w, v, 1);
}

static void sf_u32le(struct sf_buf *w, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        sf_u8(w, (uint8_t)(v >> (8 * i)));
}

/* Block: 140-byte fixed header, empty solution, transaction count (< 253). */
static void sf_block(struct sf_buf *w, uint8_t num_tx)
{
    sf_fill(w, 0, 140);
    sf_u8(w, 0);
    sf_u8(w, num_tx);
}

/* One Sapling output: cv(32) = 0x11 (must never be copied), cm(32) = seed,
 * then ephemeral key(32) + enc(580) + out(80) + proof(192) = 884 zero bytes. */
static void sf_output(struct sf_buf *w, uint8_t seed)
{
    sf_fill(w, 0x11, 32);
    sf_fill(w, seed, 32);
    sf_fill(w, 0, 32 + 580 + 80 + 192);
}

/* Sapling v4 prefix: version word, Sapling group id, no transparent io,
 * lock_time, expiry_height, value_balance. */
static void sf_sapling_prefix(struct sf_buf *w)
{
    sf_u32le(w, 0x80000004u);
    sf_u32le(w, 0x892F2085u);
    sf_u8(w, 0);
    sf_u8(w, 0);
    sf_u32le(w, 0);
    sf_u32le(w, 0);
    sf_fill(w, 0, 8);
}

/* Sapling v4 transaction: spends (384 bytes each), outputs, JoinSplits
 * (1698 bytes each, plus a 96-byte pubkey + signature when any exist), then
 * the 64-byte binding signature when there is a spend or an output. */
static void sf_sapling_tx(struct sf_buf *w, uint8_t n_spend,
                          const uint8_t *seeds, uint8_t n_out, uint8_t n_js)
{
    sf_sapling_prefix(w);
    sf_u8(w, n_spend);
    sf_fill(w, 0, (size_t)n_spend * (32 + 32 + 32 + 32 + 192 + 64));
    sf_u8(w, n_out);
    for (uint8_t i = 0; i < n_out; i++)
        sf_output(w, seeds[i]);
    sf_u8(w, n_js);
    sf_fill(w, 0, (size_t)n_js * 1698);
    if (n_js > 0)
        sf_fill(w, 0, 32 + 64);
    if (n_spend > 0 || n_out > 0)
        sf_fill(w, 0, 64);
}

static void sf_out_tx(struct sf_buf *w, uint8_t seed)
{
    sf_sapling_tx(w, 0, &seed, 1, 0);
}

/* Pre-Overwinter v1: no JoinSplit count follows lock_time. */
static void sf_v1_tx(struct sf_buf *w)
{
    sf_u32le(w, 0x00000001u);
    sf_u8(w, 0);
    sf_u8(w, 0);
    sf_u32le(w, 0);
}

/* Non-overwintered v2 with one JoinSplit: 296-byte proof, 1802 bytes in all,
 * then the 96-byte pubkey + signature. */
static void sf_v2_js_tx(struct sf_buf *w)
{
    sf_u32le(w, 0x00000002u);
    sf_u8(w, 0);
    sf_u8(w, 0);
    sf_u32le(w, 0);
    sf_u8(w, 1);
    sf_fill(w, 0, 1802);
    sf_fill(w, 0, 96);
}

/* Overwintered v4 with a foreign group id (not Sapling): expiry_height is
 * read, the JoinSplit proof is 192 bytes, 1698 bytes plus the 96-byte tail. */
static void sf_foreign_js_tx(struct sf_buf *w)
{
    sf_u32le(w, 0x80000004u);
    sf_u32le(w, 0x00000000u);
    sf_u8(w, 0);
    sf_u8(w, 0);
    sf_u32le(w, 0);
    sf_u32le(w, 0);
    sf_u8(w, 1);
    sf_fill(w, 0, 1698);
    sf_fill(w, 0, 96);
}

/* Overwintered v3 (Overwinter group id) with no JoinSplits. */
static void sf_overwinter_tx(struct sf_buf *w)
{
    sf_u32le(w, 0x80000003u);
    sf_u32le(w, 0x5BA81B19u);
    sf_u8(w, 0);
    sf_u8(w, 0);
    sf_u32le(w, 0);
    sf_u32le(w, 0);
    sf_u8(w, 0);
}

static void sf_build_empty(struct sf_buf *w)
{
    sf_block(w, 0);
}

static void sf_build_one_out(struct sf_buf *w)
{
    sf_block(w, 1);
    sf_out_tx(w, 0xA1);
}

static void sf_build_two_outs(struct sf_buf *w)
{
    static const uint8_t seeds[2] = {0xA1, 0xB2};
    sf_block(w, 1);
    sf_sapling_tx(w, 0, seeds, 2, 0);
}

static void sf_build_cap_across_txs(struct sf_buf *w)
{
    static const uint8_t seeds[2] = {0xA1, 0xB2};
    sf_block(w, 2);
    sf_sapling_tx(w, 0, seeds, 2, 0);
    sf_out_tx(w, 0xC3);
}

static void sf_build_empty_then_out(struct sf_buf *w)
{
    sf_block(w, 2);
    sf_sapling_tx(w, 0, sf_none, 0, 0);
    sf_out_tx(w, 0xA1);
}

static void sf_build_spend_then_out(struct sf_buf *w)
{
    sf_block(w, 2);
    sf_sapling_tx(w, 1, sf_none, 0, 0);
    sf_out_tx(w, 0xB2);
}

static void sf_build_out_then_out(struct sf_buf *w)
{
    sf_block(w, 2);
    sf_out_tx(w, 0xA1);
    sf_out_tx(w, 0xB2);
}

static void sf_build_js_then_out(struct sf_buf *w)
{
    sf_block(w, 2);
    sf_sapling_tx(w, 0, sf_none, 0, 1);
    sf_out_tx(w, 0xC3);
}

static void sf_build_v1_then_out(struct sf_buf *w)
{
    sf_block(w, 2);
    sf_v1_tx(w);
    sf_out_tx(w, 0xA1);
}

static void sf_build_v2_js_then_out(struct sf_buf *w)
{
    sf_block(w, 2);
    sf_v2_js_tx(w);
    sf_out_tx(w, 0xB2);
}

static void sf_build_foreign_js_then_out(struct sf_buf *w)
{
    sf_block(w, 2);
    sf_foreign_js_tx(w);
    sf_out_tx(w, 0xC3);
}

static void sf_build_overwinter_then_out(struct sf_buf *w)
{
    sf_block(w, 2);
    sf_overwinter_tx(w);
    sf_out_tx(w, 0xA1);
}

/* Output count coded as 0xFD + 16-bit little-endian value (2). */
static void sf_build_wide_count(struct sf_buf *w)
{
    sf_block(w, 1);
    sf_sapling_prefix(w);
    sf_u8(w, 0);
    sf_u8(w, 0xFD);
    sf_u8(w, 2);
    sf_u8(w, 0);
    sf_output(w, 0xA1);
    sf_output(w, 0xB2);
    sf_u8(w, 0);
    sf_fill(w, 0, 64);
}

/* Truncated: the transaction stops after two header bytes. */
static void sf_build_truncated_header(struct sf_buf *w)
{
    sf_block(w, 1);
    sf_u8(w, 0x04);
    sf_u8(w, 0x00);
}

/* Truncated inside an output: cv plus 8 bytes, short of cv + cm. */
static void sf_build_truncated_output(struct sf_buf *w)
{
    sf_block(w, 1);
    sf_sapling_prefix(w);
    sf_u8(w, 0);
    sf_u8(w, 1);
    sf_fill(w, 0x11, 40);
}

/* vin script_len is 0xFD 0x00 0x10 (4096) with no bytes left to skip. */
static void sf_build_script_past_end(struct sf_buf *w)
{
    sf_block(w, 1);
    sf_u32le(w, 0x00000001u);
    sf_u8(w, 1);
    sf_fill(w, 0, 36);
    sf_u8(w, 0xFD);
    sf_u8(w, 0x00);
    sf_u8(w, 0x10);
}

static void sf_build_partial_then_truncated(struct sf_buf *w)
{
    sf_block(w, 2);
    sf_out_tx(w, 0xA1);
    sf_u8(w, 0x04);
    sf_u8(w, 0x00);
}

static const struct sf_row sf_rows[] = {
    {"zero transactions", sf_build_empty, 4, 0, {0}},
    {"one output: cm copied, cv skipped", sf_build_one_out, 4, 1, {0xA1}},
    {"two outputs keep order", sf_build_two_outs, 4, 2, {0xA1, 0xB2}},
    {"max_cms caps writes across txs", sf_build_cap_across_txs, 2, 2,
     {0xA1, 0xB2}},
    {"max_cms zero counts nothing", sf_build_one_out, 0, 0, {0}},
    {"empty sapling tx has no binding sig", sf_build_empty_then_out, 4, 1,
     {0xA1}},
    {"spend tx skips 384-byte spend and binding sig",
     sf_build_spend_then_out, 4, 1, {0xB2}},
    {"output tx skips binding sig", sf_build_out_then_out, 4, 2,
     {0xA1, 0xB2}},
    {"sapling JoinSplit skipped without binding sig", sf_build_js_then_out,
     4, 1, {0xC3}},
    {"pre-Overwinter v1 reads no JoinSplit count", sf_build_v1_then_out,
     4, 1, {0xA1}},
    {"v2 JoinSplit uses 296-byte proof", sf_build_v2_js_then_out, 4, 1,
     {0xB2}},
    {"foreign-id overwintered v4 JoinSplit uses 192-byte proof",
     sf_build_foreign_js_then_out, 4, 1, {0xC3}},
    {"overwinter v3 without JoinSplits reads expiry", sf_build_overwinter_then_out,
     4, 1, {0xA1}},
    {"output count coded as 0xFD", sf_build_wide_count, 4, 2, {0xA1, 0xB2}},
    {"truncated tx header gives zero", sf_build_truncated_header, 4, 0, {0}},
    {"truncated output writes nothing", sf_build_truncated_output, 4, 0, {0}},
    {"vin script past end gives zero", sf_build_script_past_end, 4, 0, {0}},
    {"malformed later tx keeps partial count", sf_build_partial_then_truncated,
     4, 1, {0xA1}},
};

static int sf_check_row(const struct sf_row *r)
{
    struct sf_buf w;
    sf_init(&w);
    r->build(&w);
    if (!w.ok) {
        printf("FAIL %s: fixture overflow\n", r->name);
        return 1;
    }

    uint8_t cms[SF_CM_SLOTS][32];
    memset(cms, SF_SENTINEL, sizeof(cms));
    int got = fast_scan_sapling_commitments(w.b, w.n, cms, r->max_cms);

    int fails = 0;
    if (got != r->want_ret) {
        printf("FAIL %s: return %d, want %d\n", r->name, got, r->want_ret);
        fails++;
    }
    for (int i = 0; i < SF_CM_SLOTS; i++) {
        uint8_t want = i < r->want_ret ? r->want_seed[i] : SF_SENTINEL;
        for (size_t j = 0; j < 32; j++) {
            if (cms[i][j] != want) {
                printf("FAIL %s: cms[%d][%zu] = 0x%02X, want 0x%02X\n",
                       r->name, i, j, cms[i][j], want);
                fails++;
                break;
            }
        }
    }
    return fails;
}

int test_sapling_fast_scan(void)
{
    printf("\n=== sapling fast scan tests ===\n");
    int failures = 0;
    size_t count = sizeof(sf_rows) / sizeof(sf_rows[0]);
    for (size_t i = 0; i < count; i++)
        failures += sf_check_row(&sf_rows[i]);
    if (failures == 0)
        printf("  all %zu rows OK\n", count);
    return failures;
}
