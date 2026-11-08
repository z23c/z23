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
#include "sapling/fr.h"
#include "sapling/note_encryption.h"
#include "support/cleanse.h"
#include "util/workpool.h"
#include "util/safe_alloc.h"
#if defined(ZCL_TESTING) && !defined(_WIN32)
#include "util/thread_registry.h"
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* False when a null argument, an output-less transaction, or a keyless
 * wallet makes trial decryption a no-op. Checks short-circuit left to
 * right. */
static bool catchup_sapling_decrypt_inputs_ready(const struct node_db *ndb,
                                                 const struct transaction *tx,
                                                 const struct wallet *w)
{
    return ndb && tx && w && tx->num_shielded_output != 0 &&
           w->sapling_keys.num_keys != 0;
}

/* The public EPK is shared by all trial keys for one output. */
struct catchup_epk {
    struct jub_point point;
    bool prepared, valid;
};

static bool catchup_sapling_agree(const struct output_description *od,
    const struct sapling_key_entry *ke, struct catchup_epk *epk, uint8_t out[32])
{
    if (!epk) return sapling_ka_agree(od->ephemeral_key.data, ke->ivk, out);
    if (!epk->prepared) {
        epk->valid = jub_from_bytes(&epk->point, od->ephemeral_key.data);
        if (epk->valid) jub_mul_by_cofactor(&epk->point, &epk->point);
        epk->prepared = true;
    }
    /* Preserve the existing malformed-point refusal and logging for every key. */
    if (!epk->valid) return sapling_ka_agree(od->ephemeral_key.data, ke->ivk, out);
    struct jub_point product;
    jub_scalar_mul(&product, &epk->point, ke->ivk);
    jub_to_bytes(out, &product);
    return true;
}

/* True when `plaintext` holds a lead-byte 0x01 note opened by `ke`. */
static bool catchup_sapling_open_output_plaintext(
    const struct output_description *od,
    const struct sapling_key_entry *ke,
    uint8_t plaintext[564], struct catchup_epk *epk)
{
    if (!ke->used)
        return false; // raw-return-ok:not-mine answer, no error

    uint8_t dhsecret[32];
    if (!catchup_sapling_agree(od, ke, epk, dhsecret))
        return false; // raw-return-ok:not-mine answer, no error

    uint8_t dec_key[32];
    if (!sapling_kdf(dec_key, dhsecret, od->ephemeral_key.data)) {
        memory_cleanse(dhsecret, sizeof(dhsecret));
        return false; // raw-return-ok:not-mine answer, no error
    }
    memory_cleanse(dhsecret, sizeof(dhsecret));

    if (!sapling_note_decrypt(dec_key, od->enc_ciphertext, 580,
                              plaintext)) {
        memory_cleanse(dec_key, sizeof(dec_key));
        return false; // raw-return-ok:not-mine answer, no error
    }
    memory_cleanse(dec_key, sizeof(dec_key));

    if (plaintext[0] != 0x01)
        return false; // raw-return-ok:not-mine answer, no error
    return true;
}

/* Each worker owns one result. It does not access the database or wallet. */
struct catchup_trial {
    const struct output_description *output;
    const struct sapling_key_entry *key;
    struct catchup_epk *epk;
    bool valid;
};

struct catchup_parallel {
    struct workpool pool;
    struct catchup_trial *trials;
    void **items;
    size_t count;
};

#ifdef ZCL_TESTING
static bool catchup_test_fail_init, catchup_test_fail_run;
static bool catchup_test_run_failed;
static int catchup_test_workers;
#ifndef _WIN32
static bool catchup_test_signal;
void node_db_catchup_parallel_test_signal(bool signal) { catchup_test_signal = signal; }
#endif
static size_t catchup_test_selected;
void node_db_catchup_parallel_test_faults(bool init, bool run)
{ catchup_test_fail_init = init; catchup_test_fail_run = run; catchup_test_run_failed = false; }
bool node_db_catchup_parallel_test_run_failed(void) { return catchup_test_run_failed; }
void node_db_catchup_parallel_test_workers(int count) { catchup_test_workers = count; }
size_t node_db_catchup_parallel_test_selected(void) { return catchup_test_selected; }
int node_db_catchup_parallel_test_worker_count(const struct catchup_parallel_state *state)
{ return state && state->pool ? workpool_num_threads(&state->pool->pool) : 0; }
#endif

static bool catchup_trial_run(void *arg)
{
#if defined(ZCL_TESTING) && !defined(_WIN32)
    if (catchup_test_signal) thread_registry_request_shutdown();
#endif
    struct catchup_trial *trial = arg;
    uint8_t plaintext[564] = {0}, pk_d[32], cm[32];
    trial->valid = false;
    if (catchup_sapling_open_output_plaintext(trial->output, trial->key, plaintext, trial->epk)) {
        uint64_t value = 0;
        for (int b = 0; b < 8; ++b) value |= ((uint64_t)plaintext[12 + b]) << (8 * b);
        trial->valid = sapling_ivk_to_pkd(trial->key->ivk, plaintext + 1, pk_d) &&
            sapling_compute_cm(plaintext + 1, pk_d, value, plaintext + 20, cm) &&
            memcmp(cm, trial->output->cm.data, sizeof(cm)) == 0;
    }
    memory_cleanse(plaintext, sizeof(plaintext));
    memory_cleanse(pk_d, sizeof(pk_d));
    memory_cleanse(cm, sizeof(cm));
    return true;
}

void node_db_catchup_parallel_free(struct catchup_parallel_state *state)
{
    if (!state || !state->pool) return;
    struct catchup_parallel *p = state->pool;
    workpool_destroy(&p->pool);
    memory_cleanse(p->trials, p->count * sizeof(*p->trials));
    free(p->trials);
    free(p->items);
    free(p);
    state->pool = NULL;
}

static struct catchup_parallel *catchup_parallel_get(struct catchup_parallel_state *state, size_t count)
{
    if (!state || count < 2 || count > MAX_SAPLING_KEYS) return NULL;
    if (state->attempted) return state->pool && state->pool->count == count ? state->pool : NULL;
    state->attempted = true;
#ifdef ZCL_TESTING
    if (catchup_test_fail_init) return NULL;
#endif
    struct catchup_parallel *p = zcl_calloc(1, sizeof(*p), "Sapling trial pool");
    if (!p) return NULL;
    p->trials = zcl_calloc(count, sizeof(*p->trials), "Sapling trial results");
    p->items = zcl_calloc(count, sizeof(*p->items), "Sapling trial items");
    int workers = count < 4 ? (int)count : 4;
#ifdef ZCL_TESTING
    if (catchup_test_workers > 0 && catchup_test_workers <= 4) workers = catchup_test_workers;
#endif
    if (!p->trials || !p->items || !workpool_init(&p->pool, workers, count, catchup_trial_run)) {
        free(p->trials); free(p->items); free(p); return NULL;
    }
    p->count = count;
    return state->pool = p;
}

static bool catchup_parallel_select(struct catchup_parallel *p,
    const struct output_description *od, const struct sapling_key_entry *keys,
    size_t *selected, struct catchup_epk *epk)
{
    epk->valid = jub_from_bytes(&epk->point, od->ephemeral_key.data);
    if (epk->valid) jub_mul_by_cofactor(&epk->point, &epk->point);
    epk->prepared = true;
    for (size_t i = 0; i < p->count; ++i) {
        p->trials[i] = (struct catchup_trial){.output = od, .key = &keys[i], .epk = epk};
        p->items[i] = &p->trials[i];
    }
    bool ok = workpool_run(&p->pool, p->items, p->count);
#ifdef ZCL_TESTING
    if (catchup_test_fail_run && ok) { catchup_test_run_failed = true; ok = false; }
#endif
    if (!ok) return false;
    *selected = p->count;
    for (size_t i = 0; i < p->count; ++i) {
        if (p->trials[i].valid) { *selected = i; break; }
    }
#ifdef ZCL_TESTING
    catchup_test_selected = *selected;
#endif
    return true;
}

/* True when this key opened the output. Caller stops scanning keys.
 * *found and *ok change only after the note is commitment-checked. */
static bool catchup_replay_note_save(struct node_db *ndb,
    const struct uint256 *txid, size_t oi, int height, uint64_t value,
    const uint8_t rcm[32], const uint8_t memo[512], const uint8_t ivk[32],
    const uint8_t d[11], const uint8_t pk_d[32], const uint8_t cm[32],
    const uint8_t nf[32], struct sapling_replay_delivery *delivery)
{
    if (oi > UINT32_MAX || value > INT64_MAX) return false;
    struct db_sapling_note note = {0};
    memcpy(note.txid, txid->data, 32);
    note.output_index = (uint32_t)oi;
    note.value = (int64_t)value;
    memcpy(note.rcm, rcm, 32); memcpy(note.memo, memo, 512); note.memo_len = 512;
    memcpy(note.ivk, ivk, 32); memcpy(note.diversifier, d, 11);
    memcpy(note.pk_d, pk_d, 32); memcpy(note.cm, cm, 32);
    memcpy(note.nullifier, nf, 32); note.block_height = height;
    enum sapling_replay_merge_result r = db_sapling_note_merge_replayed(ndb, &note, delivery);
    memory_cleanse(&note, sizeof(note));
    return r == SAPLING_REPLAY_MERGE_EXISTING || r == SAPLING_REPLAY_MERGE_INSERTED;
}

static bool catchup_sapling_output_opened_by_key(
    struct node_db *ndb,
    const struct output_description *od,
    const struct sapling_key_entry *ke,
    const struct uint256 *txid,
    size_t oi,
    int height,
    int *found,
    bool *ok, bool replay, struct sapling_replay_delivery *delivery, struct catchup_epk *epk)
{
    uint8_t plaintext[564];
    if (!catchup_sapling_open_output_plaintext(od, ke, plaintext, epk))
        return false; // raw-return-ok:not-mine answer, no error

    uint8_t d[11];
    memcpy(d, plaintext + 1, sizeof(d));
    uint64_t value = 0;
    for (int b = 0; b < 8; b++)
        value |= ((uint64_t)plaintext[12 + b]) << (8 * b);
    uint8_t rcm[32];
    memcpy(rcm, plaintext + 20, sizeof(rcm));

    uint8_t pk_d[32];
    if (!sapling_ivk_to_pkd(ke->ivk, d, pk_d))
        return false; // raw-return-ok:not-mine answer, no error

    uint8_t cm[32];
    if (!sapling_compute_cm(d, pk_d, value, rcm, cm))
        return false; // raw-return-ok:not-mine answer, no error
    if (memcmp(cm, od->cm.data, sizeof(cm)) != 0)
        return false; // raw-return-ok:not-mine answer, no error

    uint8_t ak[32], nk[32];
    memcpy(ak, ke->xfvk.fvk.ak, sizeof(ak));
    memcpy(nk, ke->xfvk.fvk.nk, sizeof(nk));

    /* Position-0 placeholder nullifier. As in
     * wallet_try_sapling_decrypt (contexts/wallet/modules/wallet/src/wallet.c), the note's
     * absolute commitment-tree position is not available at decrypt
     * time; the spec nf is (re)computed at witness-creation time in
     * advance_wallet_witnesses() where position =
     * incremental_tree_size(tree) - 1 is exact. A guessed position
     * would be a WRONG nullifier, strictly worse than this non-blank
     * placeholder. See BUG #7. */
    uint8_t nf[32];
    bool nf_ok = sapling_compute_nf(d, pk_d, value, rcm, ak, nk, 0, nf);
    bool saved = replay ? nf_ok && catchup_replay_note_save(ndb, txid, oi, height, value, rcm,
                         plaintext + 52, ke->ivk, d, pk_d, cm, nf, delivery) :
        node_db_sync_sapling_note(ndb, txid->data, (uint32_t)oi, (int64_t)value, rcm,
                                  plaintext + 52, 512, ke->ivk, d, pk_d, cm, nf, height);
    if (!saved) {
        *ok = false;
    } else {
        (*found)++;
    }

    memory_cleanse(plaintext, sizeof(plaintext));
    return true;
}

/* Try-decrypt Sapling outputs in a transaction and save to SQLite.
 * Returns number of notes found. */
int node_db_catchup_try_sapling_decrypt(struct node_db *ndb,
                                        const struct transaction *tx,
                                        const struct wallet *w,
                                        int height,
                                        bool *ok_out)
{
    if (!catchup_sapling_decrypt_inputs_ready(ndb, tx, w)) {
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
            if (catchup_sapling_output_opened_by_key(ndb, od, ke, &txid, oi,
                                                     height, &found, &ok, false, NULL, NULL)) {
                if (!ok)
                    break;

                break;
            }
        }

        if (!ok)
            break;
    }
    if (ok_out)
        *ok_out = ok;
    return found;
}

bool node_db_catchup_replay_sapling_decrypt_parallel(struct node_db *ndb,
    struct transaction *tx, const struct sapling_key_entry *keys, size_t key_count,
    int height, int *found_out, struct sapling_replay_delivery *delivery,
    struct catchup_parallel_state *state)
{
    if (!ndb || !tx || (!keys && key_count) || !found_out || !delivery) return false;
    int found = 0;
    bool ok = true;
    transaction_compute_hash(tx);
    for (size_t oi = 0; ok && oi < tx->num_shielded_output; oi++) {
        struct catchup_epk epk = {0};
        struct catchup_parallel *p = catchup_parallel_get(state, key_count);
        if (p) {
            size_t selected = key_count;
            if (!catchup_parallel_select(p, &tx->v_shielded_output[oi], keys, &selected, &epk)) {
                ok = false;
                break;
            }
            if (selected < key_count && !catchup_sapling_output_opened_by_key(ndb,
                    &tx->v_shielded_output[oi], &keys[selected], &tx->hash, oi,
                    height, &found, &ok, true, delivery, &epk)) ok = false;
            continue;
        }
        for (size_t ki = 0; ki < key_count; ki++) {
            if (catchup_sapling_output_opened_by_key(ndb, &tx->v_shielded_output[oi],
                    &keys[ki], &tx->hash, oi, height, &found, &ok, true, delivery, &epk))
                break;
        }
    }
    *found_out = found;
    return ok;
}

bool node_db_catchup_replay_sapling_decrypt(struct node_db *ndb,
    struct transaction *tx, const struct sapling_key_entry *keys, size_t key_count,
    int height, int *found_out, struct sapling_replay_delivery *delivery)
{
    return node_db_catchup_replay_sapling_decrypt_parallel(ndb, tx, keys, key_count,
        height, found_out, delivery, NULL);
}
