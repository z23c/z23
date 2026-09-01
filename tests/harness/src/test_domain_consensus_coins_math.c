/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Unit tests for domain/consensus/coins_math.{c,h}.
 *
 * Pins the pure UTXO arithmetic extracted from core/modules/coins/ and the
 * pure slice of core/modules/validation/src/update_coins.c. Tests exercise
 * the typed zcl_result API directly AND cross-check against the
 * legacy core/modules/coins wrappers to prove the extraction is
 * behaviour-preserving.
 *
 * Coverage:
 *   - null/edge contracts (null coins, null undo, out-of-range pos,
 *     already-spent vout)
 *   - is_pruned / is_available / spend / cleanup match the wrappers
 *     across edge shapes (empty, all-null, mixed)
 *   - capture_undo roundtrip: spend then verify undo->txout, and
 *     on a fully-pruned coin the height/coinbase/version metadata
 *     was captured for the reorg path
 *   - compress_amount / decompress_amount roundtrip across a
 *     handpicked corpus of edge values (0, 1, 9, 10, 50e6, MAX_MONEY)
 *   - script_compress / script_decompress roundtrip for P2PKH, P2SH,
 *     P2PK compressed, and a non-recognised shape
 *   - script_compress_special_size lookup is total
 */

#include "test/test_core.h"

#include "domain/consensus/coins_math.h"
#include "coins/coins.h"
#include "coins/compressor.h"
#include "coins/undo.h"
#include "primitives/transaction.h"
#include "script/script.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define DCM_CHECK(name, expr) do { \
    printf("domain_consensus_coins_math: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Build a coins record with `n` outputs, each carrying `value` and a
 * trivial OP_CHECKSIG scriptPubKey. The caller owns the storage and
 * must call coins_free(). */
static void mkcoins(struct coins *c, size_t n, int64_t value)
{
    coins_init(c);
    coins_alloc(c, n);
    for (size_t i = 0; i < n; i++) {
        c->vout[i].value = value + (int64_t)i;
        c->vout[i].script_pub_key.data[0] = OP_CHECKSIG;
        c->vout[i].script_pub_key.size = 1;
    }
    c->height = 12345;
    c->version = 4;
    c->is_coinbase = false;
}

static void set_p2pkh(struct script *s)
{
    s->data[0] = OP_DUP;
    s->data[1] = OP_HASH160;
    s->data[2] = 20;
    memset(s->data + 3, 0xAB, 20);
    s->data[23] = OP_EQUALVERIFY;
    s->data[24] = OP_CHECKSIG;
    s->size = 25;
}

static void set_p2sh(struct script *s)
{
    s->data[0] = OP_HASH160;
    s->data[1] = 20;
    memset(s->data + 2, 0xCD, 20);
    s->data[22] = OP_EQUAL;
    s->size = 23;
}

static void set_p2pk_compressed(struct script *s)
{
    s->data[0] = 33;
    s->data[1] = 0x02;
    memset(s->data + 2, 0x42, 32);
    s->data[34] = OP_CHECKSIG;
    s->size = 35;
}

int test_domain_consensus_coins_math(void)
{
    int failures = 0;

    /* ──────────────────── coins_math_is_pruned ──────────────────── */

    /* NULL coins is pruned (defensive). */
    DCM_CHECK("is_pruned(NULL) -> true", coins_math_is_pruned(NULL));

    /* Empty coins is pruned. */
    {
        struct coins c; coins_init(&c);
        DCM_CHECK("is_pruned(empty) -> true", coins_math_is_pruned(&c));
        /* Matches wrapper. */
        DCM_CHECK("wrapper coins_is_pruned matches",
                  coins_is_pruned(&c) == coins_math_is_pruned(&c));
        coins_free(&c);
    }

    /* All-null vouts -> pruned. */
    {
        struct coins c; mkcoins(&c, 3, 1000);
        for (size_t i = 0; i < c.num_vout; i++) tx_out_set_null(&c.vout[i]);
        DCM_CHECK("is_pruned(all-null) -> true", coins_math_is_pruned(&c));
        DCM_CHECK("wrapper matches all-null",
                  coins_is_pruned(&c) == coins_math_is_pruned(&c));
        coins_free(&c);
    }

    /* One live vout -> not pruned. */
    {
        struct coins c; mkcoins(&c, 3, 1000);
        DCM_CHECK("is_pruned(live) -> false", !coins_math_is_pruned(&c));
        coins_free(&c);
    }

    /* ──────────────────── coins_math_is_available ─────────────────── */

    {
        struct coins c; mkcoins(&c, 3, 1000);
        DCM_CHECK("is_available(NULL,0) -> false",
                  !coins_math_is_available(NULL, 0));
        DCM_CHECK("is_available(c,0) -> true",
                  coins_math_is_available(&c, 0));
        DCM_CHECK("is_available(c,3) [OOB] -> false",
                  !coins_math_is_available(&c, 3));
        /* Match wrapper for live + OOB. */
        DCM_CHECK("wrapper coins_is_available matches live",
                  coins_is_available(&c, 0) == coins_math_is_available(&c, 0));
        DCM_CHECK("wrapper coins_is_available matches OOB",
                  coins_is_available(&c, 3) == coins_math_is_available(&c, 3));
        /* Spend one and check. */
        tx_out_set_null(&c.vout[1]);
        DCM_CHECK("is_available(c,1) [spent] -> false",
                  !coins_math_is_available(&c, 1));
        coins_free(&c);
    }

    /* ──────────────────── coins_math_spend ────────────────────────── */

    /* NULL -> false. */
    DCM_CHECK("spend(NULL,0) -> false", !coins_math_spend(NULL, 0));

    {
        struct coins c; mkcoins(&c, 2, 1000);
        bool spent = coins_math_spend(&c, 0);
        DCM_CHECK("spend live -> true", spent);
        DCM_CHECK("spend made vout[0] null", tx_out_is_null(&c.vout[0]));
        /* Crucial invariant: num_vout NOT trimmed (no auto-cleanup). */
        DCM_CHECK("spend does NOT trim num_vout", c.num_vout == 2);
        /* Double-spend -> false. */
        bool again = coins_math_spend(&c, 0);
        DCM_CHECK("double-spend -> false", !again);
        /* OOB -> false. */
        bool oob = coins_math_spend(&c, 99);
        DCM_CHECK("spend OOB -> false", !oob);
        coins_free(&c);
    }

    /* ──────────────────── coins_math_cleanup ─────────────────────── */

    DCM_CHECK("cleanup(NULL) is a no-op", (coins_math_cleanup(NULL), true));

    {
        struct coins c; mkcoins(&c, 5, 1000);
        /* Null out trailing two vouts. */
        tx_out_set_null(&c.vout[3]);
        tx_out_set_null(&c.vout[4]);
        coins_math_cleanup(&c);
        DCM_CHECK("cleanup trims trailing nulls",
                  c.num_vout == 3);
        /* Null in the middle is NOT trimmed. */
        tx_out_set_null(&c.vout[1]);
        coins_math_cleanup(&c);
        DCM_CHECK("cleanup preserves interior null",
                  c.num_vout == 3 && tx_out_is_null(&c.vout[1]));
        coins_free(&c);
    }

    /* ──────────────────── coins_math_capture_undo ─────────────────── */

    /* Null preconditions. */
    {
        struct tx_in_undo u; tx_in_undo_init(&u);
        struct zcl_result r = coins_math_capture_undo(NULL, 0, &u);
        DCM_CHECK("capture_undo(NULL coins) -> ERR_NULL_COINS",
                  !r.ok && r.code == DOMAIN_CONSENSUS_COINS_MATH_ERR_NULL_COINS);
    }
    {
        struct coins c; mkcoins(&c, 1, 50);
        struct zcl_result r = coins_math_capture_undo(&c, 0, NULL);
        DCM_CHECK("capture_undo(NULL undo) -> ERR_NULL_UNDO",
                  !r.ok && r.code == DOMAIN_CONSENSUS_COINS_MATH_ERR_NULL_UNDO);
        coins_free(&c);
    }
    {
        struct coins c; mkcoins(&c, 1, 50);
        struct tx_in_undo u; tx_in_undo_init(&u);
        struct zcl_result r = coins_math_capture_undo(&c, 5, &u);
        DCM_CHECK("capture_undo(pos OOB) -> ERR_OUT_OF_RANGE",
                  !r.ok && r.code == DOMAIN_CONSENSUS_COINS_MATH_ERR_OUT_OF_RANGE);
        coins_free(&c);
    }
    {
        struct coins c; mkcoins(&c, 1, 50);
        tx_out_set_null(&c.vout[0]);
        struct tx_in_undo u; tx_in_undo_init(&u);
        struct zcl_result r = coins_math_capture_undo(&c, 0, &u);
        DCM_CHECK("capture_undo(already-spent) -> ERR_ALREADY_SPENT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_COINS_MATH_ERR_ALREADY_SPENT);
        coins_free(&c);
    }

    /* Happy path: 3-output coin, spend one, undo captures txout but
     * does NOT capture metadata (coin still has live vouts). */
    {
        struct coins c; mkcoins(&c, 3, 1000);
        c.height = 42;
        c.is_coinbase = true;
        c.version = 7;
        struct tx_in_undo u; tx_in_undo_init(&u);
        struct zcl_result r = coins_math_capture_undo(&c, 1, &u);
        DCM_CHECK("capture_undo partial spend -> OK", r.ok);
        DCM_CHECK("capture_undo snapshots txout.value",
                  u.txout.value == 1001);
        DCM_CHECK("capture_undo nulls vout[1]",
                  tx_out_is_null(&c.vout[1]));
        /* Metadata NOT populated when coin still has live vouts. */
        DCM_CHECK("capture_undo partial: no metadata",
                  u.height == 0 && u.coinbase == false && u.version == 0);
        coins_free(&c);
    }

    /* Final-spend path: last live vout gets spent → undo carries the
     * parent metadata (height/coinbase/version) for the reorg path. */
    {
        struct coins c; mkcoins(&c, 1, 5000);
        c.height = 999;
        c.is_coinbase = true;
        c.version = 4;
        struct tx_in_undo u; tx_in_undo_init(&u);
        struct zcl_result r = coins_math_capture_undo(&c, 0, &u);
        DCM_CHECK("capture_undo final spend -> OK", r.ok);
        DCM_CHECK("capture_undo final spend snapshots txout",
                  u.txout.value == 5000);
        DCM_CHECK("capture_undo final spend captures height",
                  u.height == 999);
        DCM_CHECK("capture_undo final spend captures coinbase",
                  u.coinbase == true);
        DCM_CHECK("capture_undo final spend captures version",
                  u.version == 4);
        DCM_CHECK("capture_undo final spend leaves coin pruned",
                  coins_math_is_pruned(&c));
        coins_free(&c);
    }

    /* ──────────────────── amount compress/decompress ──────────────── */

    /* Roundtrip across a handpicked corpus including the boundary cases
     * of the variable-base-10 codec. */
    {
        const uint64_t corpus[] = {
            0ULL, 1ULL, 9ULL, 10ULL, 99ULL, 100ULL,
            1000ULL, 12345ULL,
            50ULL * 100000000ULL,   /* 50 ZCL */
            21ULL * 1000000ULL * 100000000ULL,  /* 21,000,000 ZCL */
        };
        bool all_round = true;
        for (size_t i = 0; i < sizeof(corpus)/sizeof(corpus[0]); i++) {
            uint64_t n  = corpus[i];
            uint64_t cz = coins_math_compress_amount(n);
            uint64_t dz = coins_math_decompress_amount(cz);
            if (dz != n) {
                printf("\n  mismatch n=%" PRIu64 " cz=%" PRIu64
                       " dz=%" PRIu64 "\n", n, cz, dz);
                all_round = false;
            }
            /* Wrappers must yield same values. */
            if (cz != compress_amount(n) || dz != decompress_amount(cz)) {
                printf("\n  wrapper mismatch n=%" PRIu64 "\n", n);
                all_round = false;
            }
        }
        DCM_CHECK("compress/decompress roundtrip + wrapper parity",
                  all_round);
    }

    /* Specific seal values (regression: codec is on-disk format). */
    DCM_CHECK("compress_amount(0)==0",
              coins_math_compress_amount(0) == 0);
    DCM_CHECK("decompress_amount(0)==0",
              coins_math_decompress_amount(0) == 0);
    /* 1 ZCL = 1e8 sats: trailing zeros → packed compactly. */
    {
        uint64_t z = coins_math_compress_amount(100000000ULL);
        DCM_CHECK("compress_amount(1 ZCL) round trips",
                  coins_math_decompress_amount(z) == 100000000ULL);
    }

    /* ──────────────────── script compress/decompress ──────────────── */

    /* P2PKH roundtrip. */
    {
        struct script s; script_init(&s); set_p2pkh(&s);
        unsigned char buf[64];
        size_t blen = 0;
        bool c_ok = coins_math_script_compress(&s, buf, &blen);
        DCM_CHECK("p2pkh compress -> OK len=21", c_ok && blen == 21);
        DCM_CHECK("p2pkh compress tag=0x00", c_ok && buf[0] == 0x00);
        struct script s2; script_init(&s2);
        bool d_ok = coins_math_script_decompress(&s2, 0x00, buf + 1, 20);
        DCM_CHECK("p2pkh decompress -> OK", d_ok);
        DCM_CHECK("p2pkh roundtrip size",
                  d_ok && s2.size == s.size);
        DCM_CHECK("p2pkh roundtrip bytes",
                  d_ok && memcmp(s2.data, s.data, s.size) == 0);
        /* Wrapper parity. */
        unsigned char wbuf[64]; size_t wlen = 0;
        bool w_ok = script_compress(&s, wbuf, &wlen);
        DCM_CHECK("p2pkh wrapper compress matches",
                  w_ok && wlen == blen && memcmp(wbuf, buf, blen) == 0);
    }

    /* P2SH roundtrip. */
    {
        struct script s; script_init(&s); set_p2sh(&s);
        unsigned char buf[64];
        size_t blen = 0;
        bool c_ok = coins_math_script_compress(&s, buf, &blen);
        DCM_CHECK("p2sh compress -> OK len=21,tag=0x01",
                  c_ok && blen == 21 && buf[0] == 0x01);
        struct script s2; script_init(&s2);
        bool d_ok = coins_math_script_decompress(&s2, 0x01, buf + 1, 20);
        DCM_CHECK("p2sh decompress -> OK", d_ok);
        DCM_CHECK("p2sh roundtrip bytes",
                  d_ok && s2.size == s.size &&
                  memcmp(s2.data, s.data, s.size) == 0);
    }

    /* P2PK compressed roundtrip. */
    {
        struct script s; script_init(&s); set_p2pk_compressed(&s);
        unsigned char buf[64];
        size_t blen = 0;
        bool c_ok = coins_math_script_compress(&s, buf, &blen);
        DCM_CHECK("p2pk-compressed compress -> OK len=33",
                  c_ok && blen == 33 && (buf[0] == 0x02 || buf[0] == 0x03));
        struct script s2; script_init(&s2);
        bool d_ok = coins_math_script_decompress(&s2, buf[0], buf + 1, 32);
        DCM_CHECK("p2pk-compressed decompress -> OK", d_ok);
        DCM_CHECK("p2pk-compressed roundtrip bytes",
                  d_ok && s2.size == s.size &&
                  memcmp(s2.data, s.data, s.size) == 0);
    }

    /* Unrecognised shape -> compress returns false (caller falls back). */
    {
        struct script s; script_init(&s);
        s.data[0] = OP_RETURN;
        s.size = 1;
        unsigned char buf[64]; size_t blen = 0;
        bool c_ok = coins_math_script_compress(&s, buf, &blen);
        DCM_CHECK("unrecognised shape -> compress returns false", !c_ok);
    }

    /* Defensive: compress with NULL args -> false (no crash). */
    {
        unsigned char buf[64]; size_t blen = 0;
        DCM_CHECK("compress(NULL,...) -> false",
                  !coins_math_script_compress(NULL, buf, &blen));
        struct script s; script_init(&s);
        DCM_CHECK("compress(...,NULL,...) -> false",
                  !coins_math_script_compress(&s, NULL, &blen));
        DCM_CHECK("compress(...,...,NULL) -> false",
                  !coins_math_script_compress(&s, buf, NULL));
    }

    /* ──────────────────── compress_special_size lookup ────────────── */

    DCM_CHECK("special_size(0)==20",
              coins_math_script_compress_special_size(0) == 20);
    DCM_CHECK("special_size(1)==20",
              coins_math_script_compress_special_size(1) == 20);
    DCM_CHECK("special_size(2)==32",
              coins_math_script_compress_special_size(2) == 32);
    DCM_CHECK("special_size(5)==32",
              coins_math_script_compress_special_size(5) == 32);
    DCM_CHECK("special_size(6)==0",
              coins_math_script_compress_special_size(6) == 0);
    DCM_CHECK("special_size(255)==0",
              coins_math_script_compress_special_size(255) == 0);
    /* Wrapper parity. */
    DCM_CHECK("special_size wrapper matches",
              script_compress_special_size(2) ==
              coins_math_script_compress_special_size(2));

    return failures;
}
