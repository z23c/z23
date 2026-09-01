/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* node_db_catchup_decrypt — the try-decrypt Sapling-outputs block helper
 * of the bulk catchup walk. Single-use orchestration detail of
 * node_db_catchup_service_run, split out of node_db_catchup_service.c so
 * the service stays under the E1 file-size ratchet while the
 * lock-contention seatbelts (node_db_catchup_lock_guard.c) landed. Moved
 * verbatim; only the name gained the node_db_catchup_ export prefix. */

// one-result-type-ok:moved-helper-int — E2 (one way out):
// node_db_catchup_try_sapling_decrypt is the verbatim-moved static helper
// of node_db_catchup_service_run (which keeps the LOCKED plain-int
// contract — see that file's own marker). Its "notes found" int and the
// ok_out bool are consumed by exactly one caller, which logs every
// failure path with height/tx context before aborting the pass; the
// reason travels with the failure through the walk's own LOG_WARN lines.

#include "node_db_catchup_internal.h"

/* node_db_sync_sapling_note lives in engine/controllers/src/
 * sync_controller_writers.c; node_db_catchup_service.c already carries
 * this same include as a grandfathered shape_include_direction baseline
 * entry — this is that debt RELOCATED with the moved helper, not a new
 * upward dependency. */
#include "controllers/sync_controller.h" // shape-layer-ok:relocated-catchup-debt
#include "primitives/transaction.h"
#include "wallet/wallet.h"
#include "wallet/sapling_keys.h"
#include "sapling/sapling.h"
#include "sapling/note_encryption.h"
#include "support/cleanse.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* Try-decrypt Sapling outputs in a transaction and save to SQLite.
 * Returns number of notes found. */
int node_db_catchup_try_sapling_decrypt(struct node_db *ndb,
                                        const struct transaction *tx,
                                        const struct wallet *w,
                                        int height,
                                        bool *ok_out)
{
    if (!ndb || !tx || !w || tx->num_shielded_output == 0 ||
        w->sapling_keys.num_keys == 0) {
        if (ok_out)
            *ok_out = true;
        return 0;
    }

    int found = 0;
    bool ok = true;
    struct uint256 txid;
    {
        struct transaction *mtx = (struct transaction *)tx;
        transaction_compute_hash(mtx);
        txid = mtx->hash;
    }

    for (size_t oi = 0; oi < tx->num_shielded_output; oi++) {
        const struct output_description *od = &tx->v_shielded_output[oi];

        for (size_t ki = 0; ki < w->sapling_keys.num_keys; ki++) {
            const struct sapling_key_entry *ke = &w->sapling_keys.keys[ki];
            if (!ke->used)
                continue;

            uint8_t dhsecret[32];
            if (!sapling_ka_agree(od->ephemeral_key.data, ke->ivk, dhsecret))
                continue;

            uint8_t dec_key[32];
            if (!sapling_kdf(dec_key, dhsecret, od->ephemeral_key.data)) {
                memory_cleanse(dhsecret, sizeof(dhsecret));
                continue;
            }
            memory_cleanse(dhsecret, sizeof(dhsecret));

            uint8_t plaintext[564];
            if (!sapling_note_decrypt(dec_key, od->enc_ciphertext, 580,
                                      plaintext)) {
                memory_cleanse(dec_key, sizeof(dec_key));
                continue;
            }
            memory_cleanse(dec_key, sizeof(dec_key));

            if (plaintext[0] != 0x01)
                continue;

            uint8_t d[11];
            memcpy(d, plaintext + 1, sizeof(d));
            uint64_t value = 0;
            for (int b = 0; b < 8; b++)
                value |= ((uint64_t)plaintext[12 + b]) << (8 * b);
            uint8_t rcm[32];
            memcpy(rcm, plaintext + 20, sizeof(rcm));

            uint8_t pk_d[32];
            if (!sapling_ivk_to_pkd(ke->ivk, d, pk_d))
                continue;

            uint8_t cm[32];
            if (!sapling_compute_cm(d, pk_d, value, rcm, cm))
                continue;
            if (memcmp(cm, od->cm.data, sizeof(cm)) != 0)
                continue;

            uint8_t ak[32], nk[32];
            sapling_ask_to_ak(ke->xsk.expsk.ask, ak);
            sapling_nsk_to_nk(ke->xsk.expsk.nsk, nk);

            /* Position-0 placeholder nullifier. As in
             * wallet_try_sapling_decrypt (contexts/wallet/modules/wallet/src/wallet.c), the note's
             * absolute commitment-tree position is not available at decrypt
             * time; the spec nf is (re)computed at witness-creation time in
             * advance_wallet_witnesses() where position =
             * incremental_tree_size(tree) - 1 is exact. A guessed position
             * would be a WRONG nullifier, strictly worse than this non-blank
             * placeholder. See BUG #7. */
            uint8_t nf[32];
            sapling_compute_nf(d, pk_d, value, rcm, ak, nk, 0, nf);

            if (!node_db_sync_sapling_note(ndb, txid.data, (uint32_t)oi,
                                          (int64_t)value, rcm,
                                          plaintext + 52, 512,
                                          ke->ivk, d, pk_d, cm, nf,
                                          height)) {
                ok = false;
            } else {
                found++;
            }

            memory_cleanse(plaintext, sizeof(plaintext));
            if (!ok)
                break;

            break;
        }

        if (!ok)
            break;
    }
    if (ok_out)
        *ok_out = ok;
    return found;
}
