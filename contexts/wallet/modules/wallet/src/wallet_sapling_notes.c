/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: in-memory Sapling received-note store of the wallet. */
#include "wallet/wallet.h"
#include "wallet_internal.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"
#include <stdlib.h>
#include <string.h>

#ifdef ZCL_TESTING
static wallet_note_buffer_observer g_note_buffer_observer;

void wallet_set_note_buffer_observer_for_test(wallet_note_buffer_observer fn)
{
    g_note_buffer_observer = fn;
}
#endif

/* Cleanse and release a Sapling note buffer: it holds memos, note randomness
 * and viewing keys. */
void wallet_release_note_buffer(struct sapling_received_note *buf,
                                size_t cap)
{
    if (!buf)
        return;
    memory_cleanse(buf, cap * sizeof(*buf));
#ifdef ZCL_TESTING
    if (g_note_buffer_observer)
        g_note_buffer_observer(buf, cap * sizeof(*buf));
#endif
    free(buf);
}

bool wallet_add_sapling_note(struct wallet *w,
                                const struct sapling_received_note *note)
{
    /* w->cs guards the sapling_notes array, its count and capacity. The
     * append below reallocs (freeing the old buffer), so it must be
     * serialized against every reader; see wallet_copy_sapling_notes(). */
    zcl_mutex_lock(&w->cs);
    /* Check for duplicate */
    for (size_t i = 0; i < w->num_sapling_notes; i++) {
        if (uint256_eq(&w->sapling_notes[i].txid, &note->txid) &&
            w->sapling_notes[i].output_index == note->output_index) {
            zcl_mutex_unlock(&w->cs);
            return false;
        }
    }

    if (w->num_sapling_notes >= w->sapling_notes_cap) {
        size_t new_cap = w->sapling_notes_cap == 0 ? 64 : w->sapling_notes_cap * 2;
        /* Allocate, copy, cleanse the old buffer, free it: realloc would
         * leave the old copy of every memo unwiped in the allocator. */
        struct sapling_received_note *new_buf =
            zcl_malloc(new_cap * sizeof(*new_buf), "sapling_notes");
        if (!new_buf) {
            zcl_mutex_unlock(&w->cs);
            return false;
        }
        if (w->sapling_notes)
            memcpy(new_buf, w->sapling_notes,
                   w->num_sapling_notes * sizeof(*new_buf));
        wallet_release_note_buffer(w->sapling_notes, w->sapling_notes_cap);
        w->sapling_notes = new_buf;
        w->sapling_notes_cap = new_cap;
    }
    w->sapling_notes[w->num_sapling_notes] = *note;
    w->sapling_notes[w->num_sapling_notes].used = true;
    w->num_sapling_notes++;
    zcl_mutex_unlock(&w->cs);
    return true;
}

bool wallet_sapling_nullifier_is_spent(const struct wallet *w,
                                        const uint8_t nf[32])
{
    zcl_mutex_lock((zcl_mutex_t *)&w->cs);
    for (size_t i = 0; i < w->num_sapling_notes; i++) {
        if (w->sapling_notes[i].used && w->sapling_notes[i].spent &&
            memcmp(w->sapling_notes[i].nf, nf, 32) == 0) {
            zcl_mutex_unlock((zcl_mutex_t *)&w->cs);
            return true;
        }
    }
    zcl_mutex_unlock((zcl_mutex_t *)&w->cs);
    return false;
}

void wallet_mark_sapling_nullifiers_spent(struct wallet *w,
                                           const struct transaction *tx)
{
    zcl_mutex_lock(&w->cs);
    for (size_t si = 0; si < tx->num_shielded_spend; si++) {
        const uint8_t *nf = tx->v_shielded_spend[si].nullifier.data;
        for (size_t ni = 0; ni < w->num_sapling_notes; ni++) {
            if (w->sapling_notes[ni].used && !w->sapling_notes[ni].spent &&
                memcmp(w->sapling_notes[ni].nf, nf, 32) == 0) {
                w->sapling_notes[ni].spent = true;
            }
        }
    }
    zcl_mutex_unlock(&w->cs);
}

int64_t wallet_get_sapling_balance(const struct wallet *w)
{
    int64_t balance = 0;
    zcl_mutex_lock((zcl_mutex_t *)&w->cs);
    for (size_t i = 0; i < w->num_sapling_notes; i++) {
        if (w->sapling_notes[i].used && !w->sapling_notes[i].spent)
            balance += (int64_t)w->sapling_notes[i].value;
    }
    zcl_mutex_unlock((zcl_mutex_t *)&w->cs);
    return balance;
}

struct sapling_received_note *wallet_copy_sapling_notes(const struct wallet *w,
                                                         size_t *count)
{
    /* Point-in-time snapshot taken under w->cs so callers can iterate the
     * notes without holding the wallet lock and without racing a concurrent
     * wallet_add_sapling_note() realloc that frees the live array. */
    zcl_mutex_lock((zcl_mutex_t *)&w->cs);
    size_t n = w->num_sapling_notes;
    struct sapling_received_note *snap = NULL;
    if (n > 0) {
        snap = zcl_malloc(n * sizeof(*snap), "sapling_notes_snapshot");
        if (snap)
            memcpy(snap, w->sapling_notes, n * sizeof(*snap));
        else
            n = 0; /* OOM: report an empty snapshot, never a torn one */
    }
    zcl_mutex_unlock((zcl_mutex_t *)&w->cs);
    if (count)
        *count = n;
    return snap;
}
