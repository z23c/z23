/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_shielded_receive_persist — MVP C4 "durable receive" gate.
 *
 * WHAT THIS PROVES (the gap the two existing tests miss)
 * -----------------------------------------------------
 * MVP #4 is "balance REFLECTS within 2 blocks" — for an operator who restarts
 * the node, that means DURABLY, across a node.db close/reopen. Two tests exist
 * but neither covers it:
 *   - test_shielded_receive_slice proves decrypt -> IN-MEMORY wallet z-balance;
 *     the note never touches disk.
 *   - test_sqlite persists a sapling note, but a HAND-FABRICATED one (values
 *     filled by hand), never the struct the real decrypt path emits.
 * This gate wires the PRODUCTION chain with zero fabrication: a real payer
 * output (params-free sapling_build_output_description) -> wallet_try_sapling_
 * decrypt (the exact live block-scan call) -> persist the RECOVERED note via
 * node_db_sync_sapling_note into a /tmp node.db -> CLOSE -> REOPEN a fresh
 * handle -> assert db_sapling_note_balance_for_ivk == the received value. It
 * catches a field-mapping drift (swapped diversifier/pk_d, wrong value
 * endianness, truncated cm) that passes both existing tests yet corrupts a
 * restarted wallet's balance.  Params-free + own /tmp datadir => hermetic.
 */

#include "test/test_core.h"

#include "core/uint256.h"
#include "primitives/transaction.h"
#include "sapling/constants.h"
#include "sapling/sapling.h"
#include "sapling/note_encryption.h"
#include "wallet/wallet.h"
#include "wallet/sapling_keys.h"
#include "models/database.h"
#include "models/wallet_tx.h"
#include "controllers/sync_controller.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define SRP_CHECK(name, expr) do {                          \
    printf("shielded_receive_persist: %s... ", (name));     \
    if ((expr)) printf("OK\n");                             \
    else { printf("FAIL\n"); failures++; }                 \
} while (0)

/* Build a single-output shielded tx paying (to_d,to_pk_d) `value`. The
 * cv/cm/epk/enc_ciphertext are produced by the PRODUCTION payer path
 * (sapling_build_output_description); the proof degrades to zero with no
 * params. Identical in mechanism to test_shielded_receive_slice's builder
 * (kept a separate static so the two TUs stay independent). */
static bool srp_build_received_output_tx(struct transaction *tx,
                                         const uint8_t to_d[11],
                                         const uint8_t to_pk_d[32],
                                         uint64_t value)
{
    uint8_t ovk[32];
    memset(ovk, 0x5a, 32);

    uint8_t od_cv[32], od_cm[32], od_epk[32];
    uint8_t od_enc[ZC_SAPLING_ENCCIPHERTEXT_SIZE];
    uint8_t od_out[ZC_SAPLING_OUTCIPHERTEXT_SIZE];
    uint8_t od_proof[GROTH_PROOF_SIZE];
    memset(od_cv, 0, sizeof(od_cv));
    memset(od_cm, 0, sizeof(od_cm));
    memset(od_epk, 0, sizeof(od_epk));
    memset(od_enc, 0, sizeof(od_enc));
    memset(od_out, 0, sizeof(od_out));
    memset(od_proof, 0, sizeof(od_proof));

    if (!sapling_build_output_description(ovk, to_d, to_pk_d, value,
                                          NULL /*default memo*/,
                                          od_cv, od_cm, od_epk,
                                          od_enc, od_out, od_proof, NULL))
        return false;

    transaction_init(tx);
    tx->version = 4;
    tx->overwintered = true;
    tx->value_balance = -(int64_t)value;
    tx->v_shielded_output = zcl_calloc(1, sizeof(struct output_description),
                                       "srp_output_desc");
    if (!tx->v_shielded_output) {
        transaction_free(tx);
        return false;
    }
    tx->num_shielded_output = 1;

    struct output_description *od = &tx->v_shielded_output[0];
    memcpy(od->cv.data, od_cv, 32);
    memcpy(od->cm.data, od_cm, 32);
    memcpy(od->ephemeral_key.data, od_epk, 32);
    memcpy(od->enc_ciphertext, od_enc, ZC_SAPLING_ENCCIPHERTEXT_SIZE);
    memcpy(od->out_ciphertext, od_out, ZC_SAPLING_OUTCIPHERTEXT_SIZE);
    memcpy(od->zkproof, od_proof, GROTH_PROOF_SIZE);
    return true;
}

int test_shielded_receive_persist(void);
int test_shielded_receive_persist(void)
{
    printf("\n=== shielded receive PERSIST "
           "(MVP C4: decrypt -> node_db -> reopen -> z-balance) ===\n");
    int failures = 0;

    if (!getenv("ZCL_STRESS_TESTS")) {
        printf("shielded_receive_persist: SKIP "
               "(set ZCL_STRESS_TESTS=1; run via `make mvp-shielded-receive-persist`)\n");
        return 0;
    }

    const uint64_t RECV_VALUE = 125000000ULL; /* 1.25000000 ZCL */
    char datadir[256], dbpath[320];
    snprintf(datadir, sizeof(datadir), ".zcl_test_recv_persist_%d", (int)getpid());
    mkdir(datadir, 0755);
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", datadir);

    struct wallet *w = zcl_calloc(1, sizeof(struct wallet), "srp_wallet");
    SRP_CHECK("merchant wallet allocated", w != NULL);
    if (!w) {
        printf("=== shielded_receive_persist subset complete: %d failure(s) ===\n",
               failures + 1);
        return failures + 1;
    }
    wallet_init(w);

    uint8_t seed[32];
    memset(seed, 0x11, 32);
    bool ok = sapling_keystore_set_seed(&w->sapling_keys, seed);
    SRP_CHECK("recipient sapling seed set", ok);

    uint8_t to_d[ZC_DIVERSIFIER_SIZE], to_pk_d[32];
    ok = ok && sapling_keystore_new_address(&w->sapling_keys, to_d, to_pk_d);
    SRP_CHECK("recipient sapling address derived", ok);

    uint8_t ivk[32];
    memset(ivk, 0, sizeof(ivk));
    if (ok) memcpy(ivk, w->sapling_keys.keys[0].ivk, 32);

    struct transaction tx;
    bool built = ok && srp_build_received_output_tx(&tx, to_d, to_pk_d, RECV_VALUE);
    SRP_CHECK("payer built shielded output (params-free)", built);

    struct uint256 txid;
    memset(&txid, 0, sizeof(txid));
    txid.data[0] = 0xC4;
    txid.data[1] = 0x07;

    int found = built ? wallet_try_sapling_decrypt(w, &tx, &txid) : 0;
    SRP_CHECK("wallet decrypted exactly one note", found == 1 && w->num_sapling_notes == 1);

    /* Persist the RECOVERED note (every field from the decrypt) into node.db,
     * then CLOSE — mirroring the live tip-finalize block-scan persist. */
    bool persisted = false;
    if (found == 1 && w->num_sapling_notes == 1) {
        const struct sapling_received_note *rn = &w->sapling_notes[0];
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        if (node_db_open(&ndb, dbpath)) {
            persisted = node_db_sync_sapling_note(
                &ndb, txid.data, rn->output_index, (int64_t)rn->value,
                rn->rcm, rn->memo, ZC_MEMO_SIZE, rn->ivk, rn->diversifier,
                rn->pk_d, rn->cm, rn->nf, 100);
            node_db_close(&ndb);
        }
    }
    SRP_CHECK("recovered note persisted + node.db closed", persisted);

    /* REOPEN a fresh handle: the durable balance must survive the restart. */
    int64_t reload_bal = -1, foreign_bal = -1;
    if (persisted) {
        struct node_db r;
        memset(&r, 0, sizeof(r));
        if (node_db_open(&r, dbpath)) {
            reload_bal = db_sapling_note_balance_for_ivk(&r, ivk);
            uint8_t foreign_ivk[32];
            memset(foreign_ivk, 0xEE, 32);
            foreign_bal = db_sapling_note_balance_for_ivk(&r, foreign_ivk);
            node_db_close(&r);
        }
    }
    SRP_CHECK("durable z-balance after REOPEN == received value (1.25 ZCL)",
              reload_bal == (int64_t)RECV_VALUE);
    SRP_CHECK("foreign ivk has zero durable balance (no false reload)",
              foreign_bal == 0);

    if (built)
        transaction_free(&tx);
    wallet_free(w);
    free(w);
    {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", datadir);
        (void)system(cmd);
    }

    if (failures == 0)
        printf("shielded_receive_persist: OK (durable z-balance %lld zat survived "
               "node.db reopen)\n", (long long)RECV_VALUE);
    return failures;
}
