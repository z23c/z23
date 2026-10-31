/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Trial decryption of a transaction's Sapling outputs against the wallet's
 * incoming viewing keys. Needs no spending key, so a locked wallet still
 * finds its notes. */

#include "base/serialize_le.h"
#include "wallet/wallet.h"
#include "wallet_internal.h"
#include "sapling/note_encryption.h"
#include "sapling/sapling.h"
#include "support/cleanse.h"

#include <string.h>

int wallet_try_sapling_decrypt(struct wallet *w,
                                const struct transaction *tx,
                                const struct uint256 *txid)
{
    int found = 0;

    for (size_t oi = 0; oi < tx->num_shielded_output; oi++) {
        const struct output_description *od = &tx->v_shielded_output[oi];

        for (size_t ki = 0; ki < w->sapling_keys.num_keys; ki++) {
            const struct sapling_key_entry *ke = &w->sapling_keys.keys[ki];
            if (!ke->used)
                continue;

            /* Key agreement: dhsecret = [ivk] * epk */
            uint8_t dhsecret[32];
            if (!sapling_ka_agree(od->ephemeral_key.data, ke->ivk, dhsecret))
                continue;

            /* KDF */
            uint8_t dec_key[32];
            if (!sapling_kdf(dec_key, dhsecret, od->ephemeral_key.data)) {
                memory_cleanse(dhsecret, 32);
                continue;
            }
            memory_cleanse(dhsecret, 32);

            /* Try decrypt */
            uint8_t plaintext[ZC_SAPLING_ENCPLAINTEXT_SIZE];
            if (!sapling_note_decrypt(dec_key, od->enc_ciphertext,
                                       ZC_SAPLING_ENCCIPHERTEXT_SIZE,
                                       plaintext)) {
                memory_cleanse(dec_key, 32);
                continue;
            }
            memory_cleanse(dec_key, 32);

            /* Parse plaintext: leadbyte(1) || d(11) || v(8) || rcm(32) || memo(512) */
            if (plaintext[0] != 0x01)
                continue;

            uint8_t d[11];
            memcpy(d, plaintext + 1, 11);
            uint64_t value = zcl_read_u64_le(plaintext + 12);
            uint8_t rcm[32];
            memcpy(rcm, plaintext + 20, 32);

            /* Derive pk_d from ivk and decrypted diversifier to verify */
            uint8_t pk_d[32];
            if (!sapling_ivk_to_pkd(ke->ivk, d, pk_d))
                continue;

            /* Recompute cm and verify against output_description.cm */
            uint8_t cm[32];
            if (!sapling_compute_cm(d, pk_d, value, rcm, cm))
                continue;

            if (memcmp(cm, od->cm.data, 32) != 0)
                continue;

            /* Compute nullifier for spend detection */
            /* The nullifier needs only the viewing key, so a locked wallet
             * still computes it. */
            const uint8_t *ak = ke->xfvk.fvk.ak;
            const uint8_t *nk = ke->xfvk.fvk.nk;

            struct sapling_received_note note = {0};
            note.txid = *txid;
            note.output_index = (uint32_t)oi;
            memcpy(note.diversifier, d, 11);
            memcpy(note.pk_d, pk_d, 32);
            note.value = value;
            memcpy(note.rcm, rcm, 32);
            memcpy(note.memo, plaintext + 52, 512);
            memcpy(note.ivk, ke->ivk, 32);
            memcpy(note.cm, cm, 32);

            /* The Sapling nullifier needs the note's ABSOLUTE leaf position
             * in the global commitment tree (rho = MixingPedersenHash(cm,
             * position)). That position is NOT knowable here: trial-decrypt
             * runs over a transaction during a block scan, before this note's
             * commitment has been appended to the tree, and a later reorg can
             * still change it. Computing nf with a guessed position would
             * produce a WRONG nullifier that never matches the on-chain spend
             * — strictly worse than this honest placeholder (which simply
             * never matches, so spend detection on this in-memory path is a
             * no-op rather than a false positive). The correct nf must be
             * (re)computed at witness-creation time in advance_wallet_witnesses()
             * (sync_controller_blocks.c) where position =
             * incremental_tree_size(tree) - 1 is exact. See BUG #7 and the
             * regression test in test_sapling.c ("BUG#7 nullifier position").
             * Position 0 placeholder is kept (not all-zero) so the derived
             * nullifier is non-blank and the note still persists past the
             * ActiveRecord presence validation. */
            sapling_compute_nf(d, pk_d, value, rcm, ak, nk, 0, note.nf);

            note.spent = false;

            if (wallet_add_sapling_note(w, &note))
                found++;

            memory_cleanse(plaintext, sizeof(plaintext));
            break; /* This ivk matched, move to next output */
        }
    }
    return found;
}
