/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * BIP113 (median-time-past for nLockTime) and BIP65 (OP_CHECKLOCKTIMEVERIFY)
 * hardening tests with adversarial timestamps. */

#include "test/test_core.h"
#include "validation/tx_verifier.h"
#include "validation/check_block.h"
#include "validation/contextual_check_tx.h"
#include "chain/chain.h"
#include "script/script_error.h"
#include "util/safe_alloc.h"

/* ── helpers ─────────────────────────────────────────────── */

static struct block_index *make_chain(struct block_index *chain, int count,
                                       const uint32_t *times)
{
    for (int i = 0; i < count; i++) {
        block_index_init(&chain[i]);
        chain[i].nHeight = i;
        chain[i].nTime = times[i];
        chain[i].pprev = i > 0 ? &chain[i - 1] : NULL;
    }
    return &chain[count - 1];
}

static void make_locktime_block(struct block *blk, uint32_t header_time,
                                 uint32_t lock_time, uint32_t sequence,
                                 int height)
{
    memset(blk, 0, sizeof(*blk));
    blk->header.nVersion = 4;
    blk->header.nTime = header_time;

    blk->num_vtx = 2;
    blk->vtx = zcl_calloc(2, sizeof(struct transaction), "test_vtx");

    blk->vtx[0].version = 1;
    blk->vtx[0].num_vin = 1;
    blk->vtx[0].vin = zcl_calloc(1, sizeof(struct tx_in), "test_vin");
    memset(blk->vtx[0].vin[0].prevout.hash.data, 0, 32);
    blk->vtx[0].vin[0].prevout.n = 0xFFFFFFFF;
    /* BIP34: encode height as minimal CScriptNum */
    uint8_t cb_sig[8];
    size_t cb_len = 0;
    {
        int h = height;
        uint8_t num[4];
        size_t num_len = 0;
        if (h == 0) {
            cb_sig[0] = 0x00; cb_len = 1;
        } else {
            while (h > 0) { num[num_len++] = (uint8_t)(h & 0xff); h >>= 8; }
            if (num[num_len - 1] & 0x80) num[num_len++] = 0x00;
            cb_sig[0] = (uint8_t)num_len;
            memcpy(cb_sig + 1, num, num_len);
            cb_len = 1 + num_len;
        }
    }
    script_set(&blk->vtx[0].vin[0].script_sig, cb_sig, cb_len);
    blk->vtx[0].vin[0].sequence = 0xFFFFFFFF;
    blk->vtx[0].num_vout = 1;
    blk->vtx[0].vout = zcl_calloc(1, sizeof(struct tx_out), "test_vout");
    blk->vtx[0].vout[0].value = 1000000;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&blk->vtx[0].vout[0].script_pub_key, pk, 3);

    blk->vtx[1].version = 1;
    blk->vtx[1].lock_time = lock_time;
    blk->vtx[1].num_vin = 1;
    blk->vtx[1].vin = zcl_calloc(1, sizeof(struct tx_in), "test_vin");
    memset(blk->vtx[1].vin[0].prevout.hash.data, 0xBB, 32);
    blk->vtx[1].vin[0].prevout.n = 0;
    uint8_t sig[] = {0x00, 0x00};
    script_set(&blk->vtx[1].vin[0].script_sig, sig, 2);
    blk->vtx[1].vin[0].sequence = sequence;
    blk->vtx[1].num_vout = 1;
    blk->vtx[1].vout = zcl_calloc(1, sizeof(struct tx_out), "test_vout");
    blk->vtx[1].vout[0].value = 500000;
    script_set(&blk->vtx[1].vout[0].script_pub_key, pk, 3);
}

static void free_locktime_block(struct block *blk)
{
    for (size_t i = 0; i < blk->num_vtx; i++) {
        free(blk->vtx[i].vin);
        free(blk->vtx[i].vout);
    }
    free(blk->vtx);
}

/* ── tests ───────────────────────────────────────────────── */

int test_bip113_bip65(void)
{
    int failures = 0;
    printf("\n=== BIP113/BIP65 Time Hardening ===\n");

    /* ── MTP calculation ──────────────────────────────── */

    printf("MTP of 11 ascending timestamps is middle value... ");
    {
        struct block_index chain[11];
        uint32_t times[] = {100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100};
        struct block_index *tip = make_chain(chain, 11, times);
        int64_t mtp = block_index_get_median_time_past(tip);
        if (mtp != 600) { printf("FAIL (got %"PRId64")\n", mtp); failures++; }
        else printf("OK\n");
    }

    printf("MTP of out-of-order timestamps sorts correctly... ");
    {
        struct block_index chain[11];
        uint32_t times[] = {900, 100, 800, 200, 700, 300, 600, 400, 500, 1000, 50};
        struct block_index *tip = make_chain(chain, 11, times);
        int64_t mtp = block_index_get_median_time_past(tip);
        if (mtp != 500) { printf("FAIL (got %"PRId64")\n", mtp); failures++; }
        else printf("OK\n");
    }

    printf("MTP with fewer than 11 blocks... ");
    {
        struct block_index chain[3];
        uint32_t times[] = {100, 300, 200};
        struct block_index *tip = make_chain(chain, 3, times);
        int64_t mtp = block_index_get_median_time_past(tip);
        if (mtp != 200) { printf("FAIL (got %"PRId64")\n", mtp); failures++; }
        else printf("OK\n");
    }

    printf("MTP single block returns that block's time... ");
    {
        struct block_index chain[1];
        uint32_t times[] = {42};
        struct block_index *tip = make_chain(chain, 1, times);
        int64_t mtp = block_index_get_median_time_past(tip);
        if (mtp != 42) { printf("FAIL (got %"PRId64")\n", mtp); failures++; }
        else printf("OK\n");
    }

    /* ── is_final_tx ──────────────────────────────────── */

    printf("GIVEN tx with locktime=0 THEN always final... ");
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.num_vin = 1;
        tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_vin");
        tx.vin[0].sequence = 0;
        bool ok = is_final_tx(&tx, 100, 1000000);
        free(tx.vin);
        if (!ok) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    printf("GIVEN height-based locktime below block height THEN final... ");
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.lock_time = 100;
        tx.num_vin = 1;
        tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_vin");
        tx.vin[0].sequence = 0;
        bool ok = is_final_tx(&tx, 200, 0);
        free(tx.vin);
        if (!ok) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    printf("GIVEN height-based locktime at block height THEN not final... ");
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.lock_time = 100;
        tx.num_vin = 1;
        tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_vin");
        tx.vin[0].sequence = 0;
        bool ok = is_final_tx(&tx, 100, 0);
        free(tx.vin);
        if (ok) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    printf("GIVEN time-based locktime below MTP THEN final... ");
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.lock_time = 500000100;
        tx.num_vin = 1;
        tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_vin");
        tx.vin[0].sequence = 0;
        bool ok = is_final_tx(&tx, 100, 500000200);
        free(tx.vin);
        if (!ok) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    printf("GIVEN time-based locktime at MTP THEN not final... ");
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.lock_time = 500000100;
        tx.num_vin = 1;
        tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_vin");
        tx.vin[0].sequence = 0;
        bool ok = is_final_tx(&tx, 100, 500000100);
        free(tx.vin);
        if (ok) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    printf("GIVEN all inputs final THEN tx final regardless of locktime... ");
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.lock_time = 999999;
        tx.num_vin = 2;
        tx.vin = zcl_calloc(2, sizeof(struct tx_in), "test_vin");
        tx.vin[0].sequence = 0xFFFFFFFF;
        tx.vin[1].sequence = 0xFFFFFFFF;
        bool ok = is_final_tx(&tx, 100, 0);
        free(tx.vin);
        if (!ok) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    /* ── Adversarial timestamps ───────────────────────── */

    printf("ADVERSARIAL: miner advances timestamp but MTP is lower... ");
    {
        struct block_index chain[12];
        uint32_t times[] = {
            500000000, 500000001, 500000002, 500000003, 500000004,
            500000005, 500000006, 500000007, 500000008, 500000009,
            500000010, 500000100
        };
        struct block_index *tip = make_chain(chain, 12, times);
        int64_t mtp = block_index_get_median_time_past(tip);

        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.lock_time = 500000050;
        tx.num_vin = 1;
        tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_vin");
        tx.vin[0].sequence = 0;

        bool fail = false;
        if (is_final_tx(&tx, 12, mtp))
            fail = true;  /* should NOT be final by MTP */
        if (!is_final_tx(&tx, 12, 500000100))
            fail = true;  /* would be final by wall-clock */
        free(tx.vin);
        if (fail) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    printf("ADVERSARIAL: miner backdates timestamp, MTP unaffected... ");
    {
        struct block_index chain[12];
        uint32_t times[] = {
            500000000, 500000010, 500000020, 500000030, 500000040,
            500000050, 500000060, 500000070, 500000080, 500000090,
            500000100, 500000001
        };
        struct block_index *tip = make_chain(chain, 12, times);
        int64_t mtp = block_index_get_median_time_past(tip);
        if (mtp != 500000050) { printf("FAIL (got %"PRId64")\n", mtp); failures++; }
        else printf("OK\n");
    }

    /* ── contextual_check_block + MTP ─────────────────── */

    printf("contextual_check_block uses BLOCK TIME not MTP (final by block time -> accept)... ");
    {
        struct block_index chain[12];
        uint32_t times[] = {
            500000000, 500000001, 500000002, 500000003, 500000004,
            500000005, 500000006, 500000007, 500000008, 500000009,
            500000010, 500000100
        };
        struct block_index *tip = make_chain(chain, 12, times);
        const struct chain_params *params = chain_params_get();

        /* lock_time 500000050 is ABOVE the tip's MTP (~500000006) but BELOW
         * the block header time 500000200. zclassicd's ContextualCheckBlock
         * hardcodes nLockTimeFlags=0, so the block-connect finality cutoff is
         * the block's OWN header time — this tx is FINAL and the block is
         * ACCEPTED. (c23 previously used MTP here and wrongly REJECTED it,
         * a forward consensus fork. BIP113/MTP applies to the mempool, not
         * to block connection.) */
        struct block blk;
        make_locktime_block(&blk, 500000200, 500000050, 0, 12);

        struct validation_state state;
        validation_state_init(&state);
        bool ok = contextual_check_block(&blk, &state, params, tip, false);
        free_locktime_block(&blk);
        if (!ok) { printf("FAIL (should accept by block time: %s)\n", state.reject_reason); failures++; }
        else printf("OK\n");
    }

    printf("contextual_check_block still rejects tx with locktime ABOVE block time... ");
    {
        struct block_index chain[12];
        uint32_t times[] = {
            500000000, 500000001, 500000002, 500000003, 500000004,
            500000005, 500000006, 500000007, 500000008, 500000009,
            500000010, 500000100
        };
        struct block_index *tip = make_chain(chain, 12, times);
        const struct chain_params *params = chain_params_get();

        /* lock_time 500000300 > block header time 500000200 with a non-final
         * input sequence -> not final under the block-time cutoff -> REJECT.
         * Keeps the finality check's teeth after the MTP->block-time fix. */
        struct block blk;
        make_locktime_block(&blk, 500000200, 500000300, 0, 12);

        struct validation_state state;
        validation_state_init(&state);
        bool ok = contextual_check_block(&blk, &state, params, tip, false);
        free_locktime_block(&blk);
        if (ok) { printf("FAIL (should reject)\n"); failures++; }
        else printf("OK\n");
    }

    printf("contextual_check_block accepts when MTP exceeds locktime... ");
    {
        struct block_index chain[12];
        uint32_t times[] = {
            500000000, 500000010, 500000020, 500000030, 500000040,
            500000050, 500000060, 500000070, 500000080, 500000090,
            500000100, 500000110
        };
        struct block_index *tip = make_chain(chain, 12, times);
        const struct chain_params *params = chain_params_get();

        struct block blk;
        make_locktime_block(&blk, 500000200, 500000050, 0, 12);

        struct validation_state state;
        validation_state_init(&state);
        bool ok = contextual_check_block(&blk, &state, params, tip, false);
        free_locktime_block(&blk);
        if (!ok) { printf("FAIL (%s)\n", state.reject_reason); failures++; }
        else printf("OK\n");
    }

    printf("contextual_check_block accepts height-locked tx past locktime... ");
    {
        struct block_index chain[12];
        uint32_t times[] = {1000,1010,1020,1030,1040,1050,1060,1070,1080,1090,1100,1110};
        struct block_index *tip = make_chain(chain, 12, times);
        const struct chain_params *params = chain_params_get();

        struct block blk;
        make_locktime_block(&blk, 1200, 10, 0, 12);

        struct validation_state state;
        validation_state_init(&state);
        bool ok = contextual_check_block(&blk, &state, params, tip, false);
        free_locktime_block(&blk);
        if (!ok) { printf("FAIL (%s)\n", state.reject_reason); failures++; }
        else printf("OK\n");
    }

    printf("contextual_check_block rejects height-locked tx at boundary... ");
    {
        struct block_index chain[12];
        uint32_t times[] = {1000,1010,1020,1030,1040,1050,1060,1070,1080,1090,1100,1110};
        struct block_index *tip = make_chain(chain, 12, times);
        const struct chain_params *params = chain_params_get();

        struct block blk;
        make_locktime_block(&blk, 1200, 12, 0, 12);

        struct validation_state state;
        validation_state_init(&state);
        bool ok = contextual_check_block(&blk, &state, params, tip, false);
        free_locktime_block(&blk);
        if (ok) { printf("FAIL (should reject)\n"); failures++; }
        else printf("OK\n");
    }

    printf("contextual_check_block accepts final-sequence tx regardless... ");
    {
        struct block_index chain[12];
        uint32_t times[] = {1000,1010,1020,1030,1040,1050,1060,1070,1080,1090,1100,1110};
        struct block_index *tip = make_chain(chain, 12, times);
        const struct chain_params *params = chain_params_get();

        struct block blk;
        make_locktime_block(&blk, 1200, 999999, 0xFFFFFFFF, 12);

        struct validation_state state;
        validation_state_init(&state);
        bool ok = contextual_check_block(&blk, &state, params, tip, false);
        free_locktime_block(&blk);
        if (!ok) { printf("FAIL (%s)\n", state.reject_reason); failures++; }
        else printf("OK\n");
    }

    /* ── Block header timestamp vs MTP ─────────────────── */

    printf("contextual_check_block_header rejects timestamp <= MTP... ");
    {
        struct block_index chain[11];
        uint32_t times[] = {100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100};
        struct block_index *tip = make_chain(chain, 11, times);
        const struct chain_params *params = chain_params_get();

        struct block_header hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.nVersion = 4;
        hdr.nTime = 600;
        hdr.nBits = tip->nBits;

        struct validation_state state;
        validation_state_init(&state);
        bool ok = contextual_check_block_header(&hdr, &state, params, tip, false);
        if (ok) { printf("FAIL (should reject)\n"); failures++; }
        else printf("OK\n");
    }

    printf("contextual_check_block_header: timestamp > MTP not rejected for time-too-old... ");
    {
        struct block_index chain[11];
        uint32_t times[] = {100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100};
        struct block_index *tip = make_chain(chain, 11, times);
        const struct chain_params *params = chain_params_get();

        struct block_header hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.nVersion = 4;
        hdr.nTime = 601;
        hdr.nBits = tip->nBits;

        struct validation_state state;
        validation_state_init(&state);
        bool ok = contextual_check_block_header(&hdr, &state, params, tip, false);
        if (!ok && strcmp(state.reject_reason, "time-too-old") == 0) {
            printf("FAIL (rejected for time-too-old)\n"); failures++;
        } else {
            printf("OK\n");
        }
    }

    /* ── BIP65: OP_CHECKLOCKTIMEVERIFY ─────────────────── */

    printf("BIP65: CLTV rejects negative locktime on stack... ");
    {
        uint8_t s[] = { 0x01, 0x81, 0xb1 };
        struct script pub;
        script_set(&pub, s, sizeof(s));
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.version = 1; tx.lock_time = 100;
        tx.num_vin = 1; tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_vin");
        tx.vin[0].sequence = 0;
        tx.num_vout = 1; tx.vout = zcl_calloc(1, sizeof(struct tx_out), "test_vout");
        tx.vout[0].value = 1000;
        struct tx_sig_checker txc;
        memset(&txc, 0, sizeof(txc));
        txc.tx = &tx;
        struct sig_checker checker = tx_make_sig_checker(&txc);
        struct script empty_sig;
        script_init(&empty_sig);
        ScriptError err = SCRIPT_ERR_OK;
        bool ok = verify_script(&empty_sig, &pub,
                                SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
                                &checker, 0, &err);
        free(tx.vin); free(tx.vout);
        if (ok || err != SCRIPT_ERR_NEGATIVE_LOCKTIME) {
            printf("FAIL (ok=%d err=%d)\n", ok, err); failures++;
        } else printf("OK\n");
    }

    printf("BIP65: CLTV rejects when stack locktime > tx locktime... ");
    {
        uint8_t s[] = { 0x02, 0xc8, 0x00, 0xb1, 0x75, 0x51 };
        struct script pub;
        script_set(&pub, s, sizeof(s));
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.version = 1; tx.lock_time = 100;
        tx.num_vin = 1; tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_vin");
        tx.vin[0].sequence = 0;
        tx.num_vout = 1; tx.vout = zcl_calloc(1, sizeof(struct tx_out), "test_vout");
        tx.vout[0].value = 1000;
        struct tx_sig_checker txc;
        memset(&txc, 0, sizeof(txc));
        txc.tx = &tx;
        struct sig_checker checker = tx_make_sig_checker(&txc);
        struct script empty_sig;
        script_init(&empty_sig);
        ScriptError err = SCRIPT_ERR_OK;
        bool ok = verify_script(&empty_sig, &pub,
                                SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
                                &checker, 0, &err);
        free(tx.vin); free(tx.vout);
        if (ok || err != SCRIPT_ERR_UNSATISFIED_LOCKTIME) {
            printf("FAIL (ok=%d err=%d)\n", ok, err); failures++;
        } else printf("OK\n");
    }

    printf("BIP65: CLTV passes when stack locktime <= tx locktime... ");
    {
        uint8_t s[] = { 0x01, 0x64, 0xb1, 0x75, 0x51 };
        struct script pub;
        script_set(&pub, s, sizeof(s));
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.version = 1; tx.lock_time = 100;
        tx.num_vin = 1; tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_vin");
        tx.vin[0].sequence = 0;
        tx.num_vout = 1; tx.vout = zcl_calloc(1, sizeof(struct tx_out), "test_vout");
        tx.vout[0].value = 1000;
        struct tx_sig_checker txc;
        memset(&txc, 0, sizeof(txc));
        txc.tx = &tx;
        struct sig_checker checker = tx_make_sig_checker(&txc);
        struct script empty_sig;
        script_init(&empty_sig);
        ScriptError err = SCRIPT_ERR_OK;
        bool ok = verify_script(&empty_sig, &pub,
                                SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
                                &checker, 0, &err);
        free(tx.vin); free(tx.vout);
        if (!ok) { printf("FAIL (err=%d)\n", err); failures++; }
        else printf("OK\n");
    }

    printf("BIP65: CLTV rejects final sequence (0xFFFFFFFF)... ");
    {
        uint8_t s[] = { 0x01, 0x64, 0xb1, 0x75, 0x51 };
        struct script pub;
        script_set(&pub, s, sizeof(s));
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.version = 1; tx.lock_time = 200;
        tx.num_vin = 1; tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_vin");
        tx.vin[0].sequence = 0xFFFFFFFF;
        tx.num_vout = 1; tx.vout = zcl_calloc(1, sizeof(struct tx_out), "test_vout");
        tx.vout[0].value = 1000;
        struct tx_sig_checker txc;
        memset(&txc, 0, sizeof(txc));
        txc.tx = &tx;
        struct sig_checker checker = tx_make_sig_checker(&txc);
        struct script empty_sig;
        script_init(&empty_sig);
        ScriptError err = SCRIPT_ERR_OK;
        bool ok = verify_script(&empty_sig, &pub,
                                SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
                                &checker, 0, &err);
        free(tx.vin); free(tx.vout);
        if (ok || err != SCRIPT_ERR_UNSATISFIED_LOCKTIME) {
            printf("FAIL (ok=%d err=%d)\n", ok, err); failures++;
        } else printf("OK\n");
    }

    printf("BIP65: CLTV rejects mixed domain (height vs time)... ");
    {
        uint8_t s[] = { 0x04, 0x00, 0x65, 0xcd, 0x1d, 0xb1, 0x75, 0x51 };
        struct script pub;
        script_set(&pub, s, sizeof(s));
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.version = 1; tx.lock_time = 999999;
        tx.num_vin = 1; tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_vin");
        tx.vin[0].sequence = 0;
        tx.num_vout = 1; tx.vout = zcl_calloc(1, sizeof(struct tx_out), "test_vout");
        tx.vout[0].value = 1000;
        struct tx_sig_checker txc;
        memset(&txc, 0, sizeof(txc));
        txc.tx = &tx;
        struct sig_checker checker = tx_make_sig_checker(&txc);
        struct script empty_sig;
        script_init(&empty_sig);
        ScriptError err = SCRIPT_ERR_OK;
        bool ok = verify_script(&empty_sig, &pub,
                                SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
                                &checker, 0, &err);
        free(tx.vin); free(tx.vout);
        if (ok || err != SCRIPT_ERR_UNSATISFIED_LOCKTIME) {
            printf("FAIL (ok=%d err=%d)\n", ok, err); failures++;
        } else printf("OK\n");
    }

    printf("=== BIP113/BIP65: %d failures ===\n\n", failures);
    return failures;
}
