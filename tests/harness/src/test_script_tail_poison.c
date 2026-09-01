/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proof that nothing reads a script byte past `.size`.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * struct tx_in embeds a full 10000-byte script buffer inline (10056 bytes
 * per input, 10016 per output). A real scriptSig is ~107 bytes and a real
 * scriptPubKey 25, so deserializing an average 2954-byte block off this
 * chain allocated ~119 KB of element array — and zero-filling it measured
 * 86% of the cost of parsing that block.
 *
 * transaction_alloc / coins_alloc therefore stopped zero-filling. Every
 * element is still fully initialized by tx_in_init / tx_out_set_null; what
 * is now indeterminate is ONLY data[.size .. MAX_SCRIPT_SIZE).
 *
 * "We grepped and every read looks bounded by .size" is not a proof. This
 * is the proof: drive the SAME wire bytes through the parser three times
 * under three different tail fills (0x00, 0xAA, 0x55) and compare every
 * derived output — txid, re-serialized wire bytes, script classification,
 * the coins round-trip, is_coinbase. If any consumer read one byte past
 * `.size`, the three digests diverge and this fails.
 *
 * THE HARNESS IS PROVED TO HAVE TEETH: the last case deliberately reads one
 * byte past `.size` and asserts the digests DO diverge. Without that, a
 * harness that accidentally compared nothing would pass forever.
 *
 * The poison hook is a PROCESS-GLOBAL. That is safe here because
 * test_parallel runs every group in its own fork()ed child (see its header),
 * so nothing this file sets can reach a group running beside it. Each case
 * below still restores the previous value immediately.
 *
 * Pure and deterministic: no clock, no RNG, no I/O, no live DB. */

#include "test/test_core.h"

#include "coins/coins.h"
#include "core/hash.h"
#include "core/serialize.h"
#include "domain/consensus/coins_math.h"
#include "primitives/transaction.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

/* Tail fills to compare. 0x00 is what calloc used to supply, so a golden
 * value computed before this change still reproduces under it. */
static const int POISONS[] = { 0x00, 0xAA, 0x55 };
#define NPOISON ((int)(sizeof(POISONS) / sizeof(POISONS[0])))

/* ── corpus ──────────────────────────────────────────────────────────
 *
 * Script lengths chosen to straddle every boundary that matters: empty,
 * one byte, the exact P2SH/P2PKH/P2PK forms coins_math classifies (23/25/
 * 35/67 — the ones that index s->data[] directly), one under and one over
 * a 64-byte cache line, the compact-size width changes at 252/253, and the
 * full MAX_SCRIPT_SIZE where there is no tail left at all. */
static const size_t SCRIPT_LENS[] = {
    0, 1, 2, 23, 25, 35, 63, 64, 65, 67, 252, 253, 254, 1023, 1024,
    MAX_SCRIPT_SIZE - 1, MAX_SCRIPT_SIZE
};
#define NLENS ((int)(sizeof(SCRIPT_LENS) / sizeof(SCRIPT_LENS[0])))

/* Deterministic filler so the wire bytes are fixed across runs. */
static void fill_pattern(unsigned char *p, size_t n, unsigned seed)
{
    for (size_t i = 0; i < n; i++)
        p[i] = (unsigned char)((i * 31u + seed * 17u + 7u) & 0xFF);
}

/* Build one transaction covering every script length, serialize it, and
 * hand back the wire bytes. This is the ONLY place the corpus is built; the
 * comparison below never re-builds, it only re-parses. */
static bool build_corpus(struct byte_stream *out)
{
    struct transaction tx;
    transaction_init(&tx);
    if (!transaction_alloc(&tx, (size_t)NLENS, (size_t)NLENS))
        return false;

    tx.version = SAPLING_TX_VERSION;
    tx.overwintered = true;
    tx.version_group_id = SAPLING_VERSION_GROUP_ID;
    tx.lock_time = 0x11223344;
    tx.expiry_height = 4242;

    static unsigned char scratch[MAX_SCRIPT_SIZE];
    for (int i = 0; i < NLENS; i++) {
        size_t n = SCRIPT_LENS[i];
        fill_pattern(scratch, n, (unsigned)i);

        /* A non-null prevout so the tx is not treated as a coinbase. */
        memset(tx.vin[i].prevout.hash.data, (int)(0x40 + i), 32);
        tx.vin[i].prevout.n = (uint32_t)i;
        tx.vin[i].sequence = 0xFFFFFFFEu;
        script_set(&tx.vin[i].script_sig, scratch, n);

        tx.vout[i].value = (int64_t)(1000 + i);
        script_set(&tx.vout[i].script_pub_key, scratch, n);
    }

    /* Make one output a real P2PKH and one a real P2SH so the classifier in
     * coins_math (which indexes s->data[0..24] directly) runs on the shapes
     * it actually recognizes rather than on filler. */
    if (NLENS >= 5) {
        unsigned char p2pkh[25];
        p2pkh[0] = 0x76; p2pkh[1] = 0xa9; p2pkh[2] = 20;
        fill_pattern(p2pkh + 3, 20, 3u);
        p2pkh[23] = 0x88; p2pkh[24] = 0xac;
        script_set(&tx.vout[4].script_pub_key, p2pkh, sizeof p2pkh);

        unsigned char p2sh[23];
        p2sh[0] = 0xa9; p2sh[1] = 20;
        fill_pattern(p2sh + 2, 20, 9u);
        p2sh[22] = 0x87;
        script_set(&tx.vout[3].script_pub_key, p2sh, sizeof p2sh);
    }

    bool ok = transaction_serialize(&tx, out);
    transaction_free(&tx);
    return ok;
}

/* ── the observation ─────────────────────────────────────────────────
 *
 * Everything a consumer could derive from a parsed transaction, folded into
 * one SHA-256. `leak_probe` deliberately reads ONE byte past .size; it is
 * off for the real cases and on only for the negative control. */
static void observe(const unsigned char *wire, size_t wire_len,
                    bool leak_probe, struct uint256 *digest)
{
    struct sha256_ctx h;
    sha256_init(&h);

    struct byte_stream s;
    stream_init_from_data(&s, wire, wire_len);
    struct transaction tx;
    if (!transaction_deserialize(&tx, &s)) {
        const char x = 'X';
        sha256_write(&h, (const unsigned char *)&x, 1);
        sha256_finalize(&h, digest->data);
        return;
    }

    /* 1. txid — the consensus identity of the transaction. */
    transaction_compute_hash(&tx);
    sha256_write(&h, tx.hash.data, 32);

    /* 2. re-serialized wire bytes — catches a serializer that emitted the
     *    tail (it writes .size bytes; a bug there would show up here). */
    struct byte_stream re;
    stream_init(&re, wire_len + 64);
    if (transaction_serialize(&tx, &re))
        sha256_write(&h, re.data, re.size);
    stream_free(&re);

    /* 3. is_coinbase, which walks outpoint_is_null -> uint256_is_null. */
    unsigned char cb = transaction_is_coinbase(&tx) ? 1 : 0;
    sha256_write(&h, &cb, 1);

    /* 4. script classification + the coins round-trip: coins_from_transaction
     *    copies scripts by .size into a freshly (un-zeroed) allocated coins
     *    array, and the compressor indexes s->data[] directly. */
    struct coins c;
    coins_init(&c);
    if (coins_from_transaction(&c, &tx, 700000)) {
        for (size_t i = 0; i < c.num_vout; i++) {
            unsigned char comp[64];
            memset(comp, 0, sizeof comp);
            const struct script *sc = &c.vout[i].script_pub_key;
            size_t clen = 0;
            if (coins_math_script_compress(sc, comp, &clen)) {
                unsigned char tag = 1;
                sha256_write(&h, &tag, 1);
                sha256_write(&h, comp, sizeof comp);
                unsigned char cl = (unsigned char)clen;
                sha256_write(&h, &cl, 1);
            } else {
                unsigned char tag = 0;
                sha256_write(&h, &tag, 1);
                sha256_write(&h, sc->data, sc->size);
            }
            unsigned char v[8];
            for (int b = 0; b < 8; b++)
                v[b] = (unsigned char)((uint64_t)c.vout[i].value >> (8 * b));
            sha256_write(&h, v, 8);
        }
    }
    coins_free(&c);

    /* 5. NEGATIVE CONTROL ONLY: read one byte past .size. This is what a
     *    real tail-reading bug would look like, and it must make the
     *    digests differ — otherwise the four observations above are not
     *    actually sensitive and this whole test proves nothing. */
    if (leak_probe) {
        for (size_t i = 0; i < tx.num_vout; i++) {
            const struct script *sc = &tx.vout[i].script_pub_key;
            if (sc->size < MAX_SCRIPT_SIZE)
                sha256_write(&h, sc->data + sc->size, 1);
        }
    }

    transaction_free(&tx);
    sha256_finalize(&h, digest->data);
}

int test_script_tail_poison(void);
int test_script_tail_poison(void)
{
    int failures = 0;

    struct byte_stream wire;
    stream_init(&wire, 4096);
    bool built = build_corpus(&wire);

    TEST("corpus: builds and covers every script-length boundary") {
        ASSERT_EQ(built ? 1 : 0, 1);
        ASSERT_EQ(wire.size > (size_t)MAX_SCRIPT_SIZE ? 1 : 0, 1);
        PASS();
    }

    if (!built) {
        stream_free(&wire);
        return failures + 1;
    }

    /* The property. Three different tail fills, one digest each. */
    struct uint256 dig[NPOISON];
    for (int p = 0; p < NPOISON; p++) {
        int prev = transaction_alloc_poison_set(POISONS[p]);
        observe(wire.data, wire.size, false, &dig[p]);
        (void)transaction_alloc_poison_set(prev);
    }

    TEST("no consumer reads a script byte past .size (0x00 vs 0xAA)") {
        ASSERT_EQ(memcmp(dig[0].data, dig[1].data, 32), 0);
        PASS();
    }

    TEST("no consumer reads a script byte past .size (0x00 vs 0x55)") {
        ASSERT_EQ(memcmp(dig[0].data, dig[2].data, 32), 0);
        PASS();
    }

    /* Production leaves the tail indeterminate rather than filled. Whatever
     * the allocator happens to hand back must land on the same digest. */
    TEST("production (no fill) matches the zero-filled digest") {
        int prev = transaction_alloc_poison_set(-1);
        struct uint256 d;
        observe(wire.data, wire.size, false, &d);
        (void)transaction_alloc_poison_set(prev);
        ASSERT_EQ(memcmp(dig[0].data, d.data, 32), 0);
        PASS();
    }

    /* Teeth. If this passes, the comparison above was vacuous. */
    TEST("negative control: a one-byte tail read DOES diverge") {
        struct uint256 leak[2];
        for (int p = 0; p < 2; p++) {
            int prev = transaction_alloc_poison_set(POISONS[p]);
            observe(wire.data, wire.size, true, &leak[p]);
            (void)transaction_alloc_poison_set(prev);
        }
        ASSERT_EQ(memcmp(leak[0].data, leak[1].data, 32) != 0 ? 1 : 0, 1);
        PASS();
    }

    /* A stream that ends mid-script must not leave that script claiming
     * `size` bytes over buffer content that was never written — .size is set
     * only after the read succeeds. The cuts are spread DEEP into the wire
     * (a cut in the first few hundred bytes is refused by the num_vin
     * plausibility guard before any script is read, which would exercise
     * nothing). Every surviving script must be fully backed: its bytes must
     * equal the pattern the corpus wrote, never the 0xAA poison. */
    TEST("a cut mid-script leaves .size 0, never a length over unwritten bytes") {
        int bad = 0, cuts = 0, deep = 0;
        static unsigned char expect[MAX_SCRIPT_SIZE];
        for (int k = 1; k < 64; k++) {
            size_t cut = wire.size * (size_t)k / 64;
            if (cut == 0 || cut >= wire.size) continue;
            cuts++;
            int prev = transaction_alloc_poison_set(0xAA);
            struct byte_stream s;
            stream_init_from_data(&s, wire.data, cut);
            struct transaction tx;
            (void)transaction_deserialize(&tx, &s);
            /* Whether it parsed or not, inspect what it left behind. */
            for (size_t i = 0; i < tx.num_vin; i++) {
                const struct script *sc = &tx.vin[i].script_sig;
                if (sc->size > MAX_SCRIPT_SIZE) { bad++; continue; }
                if (sc->size == 0) continue;
                deep++;
                fill_pattern(expect, sc->size, (unsigned)i);
                if (memcmp(sc->data, expect, sc->size) != 0) bad++;
            }
            transaction_free(&tx);
            (void)transaction_alloc_poison_set(prev);
        }
        ASSERT_EQ(bad, 0);
        ASSERT_EQ(cuts, 63);
        /* Prove the loop actually reached scripts rather than bouncing off
         * the num_vin guard every time. */
        ASSERT_EQ(deep > 0 ? 1 : 0, 1);
        PASS();
    }

    /* Unaligned wire buffer: the parser must not depend on the input being
     * aligned, and the digest must not move. */
    TEST("unaligned wire buffer yields the identical digest") {
        unsigned char *pad = zcl_malloc(wire.size + 8, "test_unaligned");
        ASSERT_EQ(pad != NULL ? 1 : 0, 1);
        if (pad) {
            for (int off = 1; off < 8; off++) {
                memcpy(pad + off, wire.data, wire.size);
                int prev = transaction_alloc_poison_set(0x55);
                struct uint256 d;
                observe(pad + off, wire.size, false, &d);
                (void)transaction_alloc_poison_set(prev);
                ASSERT_EQ(memcmp(dig[0].data, d.data, 32), 0);
            }
            free(pad);
        }
        PASS();
    }

_test_next:;
    stream_free(&wire);
    return failures;
}
