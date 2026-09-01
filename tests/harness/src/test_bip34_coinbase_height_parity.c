/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_bip34_coinbase_height_parity — D3 lock-in pin for the BIP34
 * "height in coinbase scriptSig" encoding DIFFERENCE between zcl23 and
 * zclassicd at heights 1-16. See docs/CONSENSUS_PARITY_DOCTRINE.md.
 *
 * THE GAP. At heights 1-16 the height can be serialized two ways:
 *   (a) the single OP_N byte  (0x50 + height)  — e.g. height 5 → 0x55 (OP_5),
 *   (b) the CScriptNum minimal pushdata  [len][bytes] — e.g. height 5 →
 *       0x01 0x05.
 * zclassicd's GetCoinbaseHeight accepts ONLY form (a) for heights 1-16 (it
 * uses the OP_N shortcut and rejects the pushdata form bad-cb-height). zcl23's
 * bip34_check_coinbase_height (core/modules/validation/src/check_block.c:393-421) tries
 * the OP_N byte FIRST, and on no-match falls through to a CScriptNum compare —
 * so it accepts BOTH forms.
 *
 * Exercised through the public predicate check_block_coinbase_height_matches()
 * (the consensus-neutral label check that wraps the same parser). This PINS
 * current behavior:
 *   - height 5, scriptSig 0x55         → accepted (OP_N form, both agree).
 *   - height 5, scriptSig 0x01 0x05    → accepted TODAY by zcl23 (zclassicd
 *                                        rejects bad-cb-height). The parity GAP.
 *   - height 5, scriptSig 0x55 0x00…   → accepted (OP_N first byte; trailing
 *                                        bytes ignored, as zclassicd allows).
 *   - height 5, scriptSig 0x99 (wrong) → rejected by both.
 *   - height >16 (e.g. 17) only the CScriptNum form is the encoding; pin that
 *     the OP_N shortcut no longer applies above 16.
 *
 * A future parity-restore (reject the pushdata form at heights 1-16) flips the
 * "0x01 0x05 accepted" case and this test fails loudly. Replay-gated (heights
 * 1-16 are ancient validated mainnet history — see the doc).
 *
 * Pure: hand-built coinbase transactions, no node / datadir / network.
 */

#include "test/test_core.h"

#include "primitives/transaction.h"
#include "script/script.h"
#include "validation/check_block.h"

#include <stdio.h>
#include <string.h>

#define BCH_CHECK(name, expr) do {                          \
    printf("bip34_coinbase_height_parity: %s... ", (name)); \
    if ((expr)) printf("OK\n");                             \
    else { printf("FAIL\n"); failures++; }                  \
} while (0)

/* Build a coinbase tx (1 vin, null prevout) whose vin[0].script_sig is the
 * given bytes. The output is irrelevant to the height check. */
static void bch_make_coinbase(struct transaction *tx,
                              const unsigned char *sig, size_t siglen)
{
    transaction_init(tx);
    (void)transaction_alloc(tx, 1, 1);
    outpoint_set_null(&tx->vin[0].prevout);
    script_set(&tx->vin[0].script_sig, sig, siglen);
    tx->vout[0].value = 0;
}

int test_bip34_coinbase_height_parity(void);
int test_bip34_coinbase_height_parity(void)
{
    printf("\n=== D3 BIP34 coinbase-height encoding parity (lock-in) ===\n");
    int failures = 0;

    /* (1) height 5, OP_5 single byte (0x55). Both zcl23 and zclassicd
     * accept the OP_N form — pin the baseline. */
    {
        unsigned char sig[] = { 0x55 };
        struct transaction tx;
        bch_make_coinbase(&tx, sig, sizeof(sig));
        BCH_CHECK("height 5 OP_5 (0x55) accepted",
                  check_block_coinbase_height_matches(&tx, 5));
        transaction_free(&tx);
    }

    /* (2) THE PARITY GAP: height 5, CScriptNum pushdata (0x01 0x05). zcl23
     * accepts this TODAY (falls through from the OP_N miss to the CScriptNum
     * compare). zclassicd rejects it bad-cb-height. PIN the acceptance. */
    {
        unsigned char sig[] = { 0x01, 0x05 };
        struct transaction tx;
        bch_make_coinbase(&tx, sig, sizeof(sig));
        BCH_CHECK("height 5 pushdata (0x01 0x05) ACCEPTED today "
                  "(zclassicd rejects — parity GAP)",
                  check_block_coinbase_height_matches(&tx, 5));
        transaction_free(&tx);
    }

    /* (3) height 5, OP_5 byte followed by extra bytes. The OP_N shortcut
     * matches on the FIRST byte and returns true regardless of trailing
     * scriptSig content (extranonce etc.) — both implementations accept. */
    {
        unsigned char sig[] = { 0x55, 0x00, 0xAB, 0xCD };
        struct transaction tx;
        bch_make_coinbase(&tx, sig, sizeof(sig));
        BCH_CHECK("height 5 OP_5 + trailing bytes accepted",
                  check_block_coinbase_height_matches(&tx, 5));
        transaction_free(&tx);
    }

    /* (4) height 5, a scriptSig that is neither the OP_5 byte nor the
     * height-5 CScriptNum → rejected by both. 0x99 is OP_9-ish junk; the
     * CScriptNum compare expects 0x01 0x05, so memcmp fails. */
    {
        unsigned char sig[] = { 0x99, 0x05 };
        struct transaction tx;
        bch_make_coinbase(&tx, sig, sizeof(sig));
        BCH_CHECK("height 5 wrong scriptSig (0x99 0x05) rejected",
                  !check_block_coinbase_height_matches(&tx, 5));
        transaction_free(&tx);
    }

    /* (5) Above the OP_N range (height 17): the OP_N shortcut no longer
     * applies (it is gated nHeight<=16), so ONLY the CScriptNum form
     * (0x01 0x11) is accepted, and the corresponding "OP_N" byte (0x50+17 =
     * 0x61) is rejected. Pins the upper boundary of the 1-16 special-case. */
    {
        unsigned char good[] = { 0x01, 0x11 };   /* CScriptNum for 17 */
        struct transaction tx;
        bch_make_coinbase(&tx, good, sizeof(good));
        BCH_CHECK("height 17 CScriptNum (0x01 0x11) accepted",
                  check_block_coinbase_height_matches(&tx, 17));
        transaction_free(&tx);

        unsigned char opn17[] = { 0x61 };        /* would-be OP_17, invalid */
        bch_make_coinbase(&tx, opn17, sizeof(opn17));
        BCH_CHECK("height 17 fake-OP_N byte (0x61) rejected "
                  "(OP_N shortcut is 1-16 only)",
                  !check_block_coinbase_height_matches(&tx, 17));
        transaction_free(&tx);
    }

    printf("=== D3 BIP34 coinbase-height encoding parity: %d failures ===\n",
           failures);
    return failures;
}
