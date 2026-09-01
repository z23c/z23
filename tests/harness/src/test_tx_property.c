/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Property-based tests for check_transaction (wave 10 #9).
 * QuickCheck-style: generate random transaction mutations,
 * assert no crashes and correct accept/reject. */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "validation/check_transaction.h"
#include "core/amount.h"
#include "primitives/transaction.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "util/safe_alloc.h"

/* Avoid including consensus.h: it conflicts with main_constants.h, which
 * arrives through validation/check_transaction.h. Guard the constants we
 * need instead. */
#ifndef TX_EXPIRY_HEIGHT_THRESHOLD
#define TX_EXPIRY_HEIGHT_THRESHOLD 500000000U
#endif
#ifndef SPROUT_MIN_TX_VERSION
#define SPROUT_MIN_TX_VERSION      1
#endif
#ifndef OVERWINTER_MIN_TX_VERSION
#define OVERWINTER_MIN_TX_VERSION  3
#endif
#ifndef SAPLING_MIN_TX_VERSION
#define SAPLING_MIN_TX_VERSION     4
#endif
#ifndef SAPLING_MAX_TX_VERSION
#define SAPLING_MAX_TX_VERSION     4
#endif

/* Simple PRNG for reproducible tests (xoshiro128+) */
static uint32_t s_rng[4];

static void rng_seed(uint32_t seed)
{
    s_rng[0] = seed;
    s_rng[1] = seed ^ 0xDEADBEEF;
    s_rng[2] = seed ^ 0xCAFEBABE;
    s_rng[3] = seed ^ 0x12345678;
}

static uint32_t rng_next(void)
{
    uint32_t t = s_rng[1] << 9;
    s_rng[2] ^= s_rng[0];
    s_rng[3] ^= s_rng[1];
    s_rng[1] ^= s_rng[2];
    s_rng[0] ^= s_rng[3];
    s_rng[2] ^= t;
    s_rng[3] = (s_rng[3] << 11) | (s_rng[3] >> 21);
    return s_rng[0] + s_rng[3];
}

static uint64_t rng_u64(void)
{
    return ((uint64_t)rng_next() << 32) | rng_next();
}

static int rng_range(int lo, int hi)
{
    if (lo >= hi) return lo;
    return lo + (int)(rng_next() % (uint32_t)(hi - lo));
}

/* ── Transaction builders ─────────────────────────────────────── */

static void make_random_prevout(struct outpoint *op)
{
    for (int i = 0; i < 32; i++)
        op->hash.data[i] = (uint8_t)rng_next();
    op->n = rng_next() % 10;
}

static struct transaction make_valid_tx(void)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.overwintered = false;
    int nin = rng_range(1, 4);
    int nout = rng_range(1, 4);
    tx.num_vin = (size_t)nin;
    tx.vin = zcl_calloc((size_t)nin, sizeof(struct tx_in), "test_tx_vin");
    for (int i = 0; i < nin; i++) {
        make_random_prevout(&tx.vin[i].prevout);
        tx.vin[i].sequence = 0xFFFFFFFF;
        uint8_t sig[] = {0x00, 0x00};
        script_set(&tx.vin[i].script_sig, sig, 2);
    }
    tx.num_vout = (size_t)nout;
    tx.vout = zcl_calloc((size_t)nout, sizeof(struct tx_out), "test_tx_vout");
    for (int i = 0; i < nout; i++) {
        tx.vout[i].value = (int64_t)(rng_next() % 1000000) * COIN / 100;
        uint8_t pk[] = {0x76, 0xa9, 0x14};
        script_set(&tx.vout[i].script_pub_key, pk, 3);
    }
    return tx;
}

static struct transaction make_valid_overwinter_tx(void)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 3;
    tx.overwintered = true;
    tx.version_group_id = OVERWINTER_VERSION_GROUP_ID;
    tx.expiry_height = rng_next() % 499999999;
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_tx_vin");
    make_random_prevout(&tx.vin[0].prevout);
    tx.vin[0].sequence = 0xFFFFFFFF;
    uint8_t sig[] = {0x00, 0x00};
    script_set(&tx.vin[0].script_sig, sig, 2);
    tx.num_vout = 1;
    tx.vout = zcl_calloc(1, sizeof(struct tx_out), "test_tx_vout");
    tx.vout[0].value = 10 * COIN;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx.vout[0].script_pub_key, pk, 3);
    return tx;
}

static struct transaction make_valid_sapling_tx(void)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = SAPLING_MIN_TX_VERSION;
    tx.overwintered = true;
    tx.version_group_id = SAPLING_VERSION_GROUP_ID;
    tx.expiry_height = rng_next() % 499999999;
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_tx_vin");
    make_random_prevout(&tx.vin[0].prevout);
    tx.vin[0].sequence = 0xFFFFFFFF;
    uint8_t sig[] = {0x00, 0x00};
    script_set(&tx.vin[0].script_sig, sig, 2);
    tx.num_vout = 1;
    tx.vout = zcl_calloc(1, sizeof(struct tx_out), "test_tx_vout");
    tx.vout[0].value = 10 * COIN;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx.vout[0].script_pub_key, pk, 3);
    return tx;
}

static void free_tx(struct transaction *tx)
{
    free(tx->vin);
    free(tx->vout);
    free(tx->v_shielded_spend);
    free(tx->v_shielded_output);
    free(tx->v_joinsplit);
}

/* ── Property tests ───────────────────────────────────────────── */

int test_tx_property(void)
{
    int failures = 0;
    rng_seed((uint32_t)platform_time_wall_time_t());

    /* Property 1: valid transactions always accepted */
    printf("prop: valid sprout txs always accepted [100 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 100 && ok; i++) {
            struct transaction tx = make_valid_tx();
            struct validation_state vs;
            validation_state_init(&vs);
            if (!check_transaction(&tx, &vs)) {
                printf("\n  FAIL round %d: %s", i, vs.reject_reason);
                ok = false;
            }
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    printf("prop: valid overwinter txs always accepted [100 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 100 && ok; i++) {
            struct transaction tx = make_valid_overwinter_tx();
            struct validation_state vs;
            validation_state_init(&vs);
            if (!check_transaction(&tx, &vs)) {
                printf("\n  FAIL round %d: %s", i, vs.reject_reason);
                ok = false;
            }
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    printf("prop: valid sapling txs always accepted [100 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 100 && ok; i++) {
            struct transaction tx = make_valid_sapling_tx();
            struct validation_state vs;
            validation_state_init(&vs);
            if (!check_transaction(&tx, &vs)) {
                printf("\n  FAIL round %d: %s", i, vs.reject_reason);
                ok = false;
            }
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    /* Property 2: negative output values always rejected */
    printf("prop: negative output values always rejected [100 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 100 && ok; i++) {
            struct transaction tx = make_valid_tx();
            int idx = rng_range(0, (int)tx.num_vout);
            tx.vout[idx].value = -(int64_t)(rng_u64() % (uint64_t)MAX_MONEY) - 1;
            struct validation_state vs;
            validation_state_init(&vs);
            if (check_transaction(&tx, &vs)) {
                printf("\n  FAIL round %d: accepted negative output", i);
                ok = false;
            }
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    /* Property 3: output > MAX_MONEY always rejected */
    printf("prop: output > MAX_MONEY always rejected [100 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 100 && ok; i++) {
            struct transaction tx = make_valid_tx();
            int idx = rng_range(0, (int)tx.num_vout);
            tx.vout[idx].value = MAX_MONEY + 1 + (int64_t)(rng_next() % 1000000);
            struct validation_state vs;
            validation_state_init(&vs);
            if (check_transaction(&tx, &vs)) {
                printf("\n  FAIL round %d: accepted output > MAX_MONEY", i);
                ok = false;
            }
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    /* Property 4: total output overflow always rejected */
    printf("prop: total output overflow always rejected [50 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 50 && ok; i++) {
            struct transaction tx;
            memset(&tx, 0, sizeof(tx));
            tx.version = 1;
            tx.num_vin = 1;
            tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_tx_vin");
            make_random_prevout(&tx.vin[0].prevout);
            uint8_t sig[] = {0x00, 0x00};
            script_set(&tx.vin[0].script_sig, sig, 2);
            /* 3 outputs each at MAX_MONEY — total overflows */
            tx.num_vout = 3;
            tx.vout = zcl_calloc(3, sizeof(struct tx_out), "test_tx_vout");
            for (int j = 0; j < 3; j++) {
                tx.vout[j].value = MAX_MONEY;
                uint8_t pk[] = {0x76};
                script_set(&tx.vout[j].script_pub_key, pk, 1);
            }
            struct validation_state vs;
            validation_state_init(&vs);
            if (check_transaction(&tx, &vs)) {
                printf("\n  FAIL round %d: accepted overflow outputs", i);
                ok = false;
            }
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    /* Property 5: empty inputs+outputs always rejected */
    printf("prop: empty inputs always rejected [50 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 50 && ok; i++) {
            struct transaction tx;
            memset(&tx, 0, sizeof(tx));
            tx.version = 1;
            tx.num_vin = 0;
            tx.vin = NULL;
            tx.num_vout = rng_range(1, 3);
            tx.vout = zcl_calloc(tx.num_vout, sizeof(struct tx_out), "test_tx_vout");
            for (size_t j = 0; j < tx.num_vout; j++) {
                tx.vout[j].value = COIN;
                uint8_t pk[] = {0x76};
                script_set(&tx.vout[j].script_pub_key, pk, 1);
            }
            struct validation_state vs;
            validation_state_init(&vs);
            if (check_transaction(&tx, &vs)) {
                printf("\n  FAIL round %d: accepted empty inputs", i);
                ok = false;
            }
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    printf("prop: empty outputs always rejected [50 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 50 && ok; i++) {
            struct transaction tx;
            memset(&tx, 0, sizeof(tx));
            tx.version = 1;
            tx.num_vin = 1;
            tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_tx_vin");
            make_random_prevout(&tx.vin[0].prevout);
            uint8_t sig[] = {0x00, 0x00};
            script_set(&tx.vin[0].script_sig, sig, 2);
            tx.num_vout = 0;
            tx.vout = NULL;
            struct validation_state vs;
            validation_state_init(&vs);
            if (check_transaction(&tx, &vs)) {
                printf("\n  FAIL round %d: accepted empty outputs", i);
                ok = false;
            }
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    /* Property 6: duplicate inputs always rejected */
    printf("prop: duplicate inputs always rejected [100 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 100 && ok; i++) {
            struct transaction tx = make_valid_tx();
            if (tx.num_vin >= 2) {
                /* Make input 1 a copy of input 0 */
                tx.vin[1].prevout = tx.vin[0].prevout;
                struct validation_state vs;
                validation_state_init(&vs);
                if (check_transaction(&tx, &vs)) {
                    printf("\n  FAIL round %d: accepted dup inputs", i);
                    ok = false;
                }
            }
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    /* Property 7: version fuzz — invalid versions always rejected */
    printf("prop: version 0 always rejected [50 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 50 && ok; i++) {
            struct transaction tx = make_valid_tx();
            tx.version = 0;
            struct validation_state vs;
            validation_state_init(&vs);
            if (check_transaction(&tx, &vs)) {
                printf("\n  FAIL round %d: accepted version 0", i);
                ok = false;
            }
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    /* Property 8: overwinter with bad version group always rejected */
    printf("prop: overwinter+bad versionGroupId rejected [100 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 100 && ok; i++) {
            struct transaction tx = make_valid_overwinter_tx();
            tx.version_group_id = rng_next();
            /* Skip valid group IDs */
            if (tx.version_group_id == OVERWINTER_VERSION_GROUP_ID ||
                tx.version_group_id == SAPLING_VERSION_GROUP_ID)
                tx.version_group_id ^= 1;
            struct validation_state vs;
            validation_state_init(&vs);
            if (check_transaction(&tx, &vs)) {
                printf("\n  FAIL round %d: accepted bad versionGroupId 0x%08X",
                       i, tx.version_group_id);
                ok = false;
            }
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    /* Property 9: expiry_height >= threshold always rejected */
    printf("prop: expiry_height >= 500M rejected [100 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 100 && ok; i++) {
            struct transaction tx = make_valid_overwinter_tx();
            tx.expiry_height = TX_EXPIRY_HEIGHT_THRESHOLD +
                               rng_next() % 100000;
            struct validation_state vs;
            validation_state_init(&vs);
            if (check_transaction(&tx, &vs)) {
                printf("\n  FAIL round %d: accepted expiry_height %u",
                       i, tx.expiry_height);
                ok = false;
            }
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    /* Property 10: coinbase with joinsplits always rejected */
    printf("prop: coinbase+joinsplits always rejected [50 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 50 && ok; i++) {
            struct transaction tx;
            memset(&tx, 0, sizeof(tx));
            tx.version = 1;
            tx.num_vin = 1;
            tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_tx_vin");
            memset(&tx.vin[0].prevout.hash, 0, 32);
            tx.vin[0].prevout.n = UINT32_MAX;
            uint8_t sig[] = {0x04, 0x01, 0x01, 0x01, 0x01};
            script_set(&tx.vin[0].script_sig, sig, 5);
            tx.num_vout = 1;
            tx.vout = zcl_calloc(1, sizeof(struct tx_out), "test_tx_vout");
            tx.vout[0].value = 10 * COIN;
            uint8_t pk[] = {0x76, 0xa9, 0x14};
            script_set(&tx.vout[0].script_pub_key, pk, 3);
            tx.num_joinsplit = 1 + rng_next() % 3;
            tx.v_joinsplit = zcl_calloc(tx.num_joinsplit,
                                    sizeof(struct js_description), "test_joinsplit");
            struct validation_state vs;
            validation_state_init(&vs);
            if (check_transaction(&tx, &vs)) {
                printf("\n  FAIL round %d: accepted coinbase+joinsplit", i);
                ok = false;
            }
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    /* Property 11: non-coinbase with null prevout always rejected */
    printf("prop: non-coinbase null prevout rejected [100 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 100 && ok; i++) {
            struct transaction tx = make_valid_tx();
            if (tx.num_vin >= 2) {
                /* Make second input a null prevout (only first can be coinbase) */
                memset(&tx.vin[1].prevout.hash, 0, 32);
                tx.vin[1].prevout.n = UINT32_MAX;
                struct validation_state vs;
                validation_state_init(&vs);
                if (check_transaction(&tx, &vs)) {
                    printf("\n  FAIL round %d: accepted non-cb null prevout", i);
                    ok = false;
                }
            }
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    /* Property 12: sapling non-zero value_balance without shielded ops */
    printf("prop: non-zero value_balance without shielded rejected [100 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 100 && ok; i++) {
            struct transaction tx = make_valid_sapling_tx();
            tx.value_balance = (int64_t)(rng_next() % 1000000 + 1);
            if (rng_next() & 1) tx.value_balance = -tx.value_balance;
            struct validation_state vs;
            validation_state_init(&vs);
            if (check_transaction(&tx, &vs)) {
                printf("\n  FAIL round %d: accepted non-zero vb w/o shielded", i);
                ok = false;
            }
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    /* Property 13: value_balance out of range always rejected */
    printf("prop: value_balance out of range rejected [100 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 100 && ok; i++) {
            struct transaction tx = make_valid_sapling_tx();
            /* Need shielded ops to avoid the "non-zero without shielded" check */
            tx.num_shielded_spend = 1;
            tx.v_shielded_spend = zcl_calloc(1, sizeof(struct spend_description), "test_shielded_spend");
            /* Set random unique nullifier */
            for (int b = 0; b < 32; b++)
                tx.v_shielded_spend[0].nullifier.data[b] = (uint8_t)rng_next();
            tx.value_balance = MAX_MONEY + 1 + (int64_t)(rng_next() % 1000000);
            struct validation_state vs;
            validation_state_init(&vs);
            if (check_transaction(&tx, &vs)) {
                printf("\n  FAIL round %d: accepted vb out of range", i);
                ok = false;
            }
            free(tx.v_shielded_spend);
            tx.v_shielded_spend = NULL;
            tx.num_shielded_spend = 0;
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    /* Property 14: coinbase script length bounds */
    printf("prop: coinbase script too short rejected [50 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 50 && ok; i++) {
            struct transaction tx;
            memset(&tx, 0, sizeof(tx));
            tx.version = 1;
            tx.num_vin = 1;
            tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_tx_vin");
            memset(&tx.vin[0].prevout.hash, 0, 32);
            tx.vin[0].prevout.n = UINT32_MAX;
            /* Script of length 0 or 1 */
            uint8_t sig[] = {0x01};
            script_set(&tx.vin[0].script_sig, sig, rng_next() & 1);
            tx.num_vout = 1;
            tx.vout = zcl_calloc(1, sizeof(struct tx_out), "test_tx_vout");
            tx.vout[0].value = 10 * COIN;
            uint8_t pk[] = {0x76};
            script_set(&tx.vout[0].script_pub_key, pk, 1);
            struct validation_state vs;
            validation_state_init(&vs);
            if (check_transaction(&tx, &vs)) {
                printf("\n  FAIL round %d: accepted short coinbase script", i);
                ok = false;
            }
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    printf("prop: coinbase script too long rejected [50 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 50 && ok; i++) {
            struct transaction tx;
            memset(&tx, 0, sizeof(tx));
            tx.version = 1;
            tx.num_vin = 1;
            tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_tx_vin");
            memset(&tx.vin[0].prevout.hash, 0, 32);
            tx.vin[0].prevout.n = UINT32_MAX;
            size_t slen = 101 + rng_next() % 200;
            uint8_t *sig = zcl_calloc(slen, 1, "test_cb_sig");
            for (size_t j = 0; j < slen; j++) sig[j] = (uint8_t)rng_next();
            script_set(&tx.vin[0].script_sig, sig, slen);
            free(sig);
            tx.num_vout = 1;
            tx.vout = zcl_calloc(1, sizeof(struct tx_out), "test_tx_vout");
            tx.vout[0].value = 10 * COIN;
            uint8_t pk[] = {0x76};
            script_set(&tx.vout[0].script_pub_key, pk, 1);
            struct validation_state vs;
            validation_state_init(&vs);
            if (check_transaction(&tx, &vs)) {
                printf("\n  FAIL round %d: accepted long coinbase script (len=%zu)",
                       i, slen);
                ok = false;
            }
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    /* Property 15: random mutation never crashes */
    printf("prop: random bit-flip mutations never crash [500 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 500 && ok; i++) {
            struct transaction tx = make_valid_tx();
            /* Apply 1-5 random mutations to the struct memory */
            unsigned char *raw = (unsigned char *)&tx;
            /* Only mutate the non-pointer fields to avoid segfaults:
             * version, overwintered, version_group_id, lock_time,
             * expiry_height, value_balance, num_vin, num_vout */
            int mutations = rng_range(1, 6);
            for (int m = 0; m < mutations; m++) {
                size_t field = rng_next() % 7;
                switch (field) {
                case 0: tx.version = (int32_t)rng_next(); break;
                case 1: tx.overwintered = rng_next() & 1; break;
                case 2: tx.version_group_id = rng_next(); break;
                case 3: tx.lock_time = rng_next(); break;
                case 4: tx.expiry_height = rng_next(); break;
                case 5:
                    tx.value_balance = (int64_t)rng_u64();
                    break;
                case 6:
                    /* Mutate an output value if we have outputs */
                    if (tx.num_vout > 0) {
                        int idx = rng_range(0, (int)tx.num_vout);
                        tx.vout[idx].value = (int64_t)rng_u64();
                    }
                    break;
                }
                (void)raw; /* suppress unused warning */
            }
            struct validation_state vs;
            validation_state_init(&vs);
            /* We don't care about accept/reject — just no crash */
            (void)check_transaction(&tx, &vs);
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    /* Property 16: duplicate sapling nullifiers always rejected */
    printf("prop: duplicate sapling nullifiers rejected [100 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 100 && ok; i++) {
            struct transaction tx = make_valid_sapling_tx();
            tx.num_shielded_spend = 2;
            tx.v_shielded_spend = zcl_calloc(2, sizeof(struct spend_description), "test_shielded_spend");
            /* Same nullifier for both */
            for (int b = 0; b < 32; b++) {
                uint8_t v = (uint8_t)rng_next();
                tx.v_shielded_spend[0].nullifier.data[b] = v;
                tx.v_shielded_spend[1].nullifier.data[b] = v;
            }
            struct validation_state vs;
            validation_state_init(&vs);
            if (check_transaction(&tx, &vs)) {
                printf("\n  FAIL round %d: accepted dup sapling nullifiers", i);
                ok = false;
            }
            free(tx.v_shielded_spend);
            tx.v_shielded_spend = NULL;
            tx.num_shielded_spend = 0;
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    /* Property 17: boundary value testing — exact MAX_MONEY output is OK */
    printf("prop: output == MAX_MONEY accepted (single output)... ");
    {
        bool ok = true;
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.version = 1;
        tx.num_vin = 1;
        tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_tx_vin");
        make_random_prevout(&tx.vin[0].prevout);
        uint8_t sig[] = {0x00, 0x00};
        script_set(&tx.vin[0].script_sig, sig, 2);
        tx.num_vout = 1;
        tx.vout = zcl_calloc(1, sizeof(struct tx_out), "test_tx_vout");
        tx.vout[0].value = MAX_MONEY;
        uint8_t pk[] = {0x76};
        script_set(&tx.vout[0].script_pub_key, pk, 1);
        struct validation_state vs;
        validation_state_init(&vs);
        ok = check_transaction(&tx, &vs);
        free_tx(&tx);
        if (ok) printf("OK\n"); else { printf("FAIL: %s\n", vs.reject_reason); failures++; }
    }

    /* Property 18: overwinter version < 3 rejected */
    printf("prop: overwinter version < OVERWINTER_MIN rejected [50 rounds]... ");
    {
        bool ok = true;
        for (int i = 0; i < 50 && ok; i++) {
            struct transaction tx = make_valid_overwinter_tx();
            tx.version = rng_range(0, OVERWINTER_MIN_TX_VERSION);
            struct validation_state vs;
            validation_state_init(&vs);
            if (check_transaction(&tx, &vs)) {
                printf("\n  FAIL round %d: accepted version %d", i, tx.version);
                ok = false;
            }
            free_tx(&tx);
        }
        if (ok) printf("OK\n"); else { printf("\n"); failures++; }
    }

    printf("\n%d tx property tests, %d failed\n", 18, failures);
    return failures;
}
