/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: txid -> slot index over wallet->map_wallet.
 *
 * The slot table holds MAX_WALLET_TX large structs and used to be searched
 * linearly, once per transaction and once per input of every transaction in
 * every connected block. The index is an open-addressing table with linear
 * probing, 2 x MAX_WALLET_TX entries of 8 bytes (1 MiB), embedded in struct
 * wallet so it is allocated, zero-filled and copied together with the table
 * and cannot fail to allocate. Deletion shifts entries back, so there are no
 * tombstones and a probe run always ends at an empty entry (load <= 0.5).
 *
 * Results are identical to the linear scan: when two used slots share a txid
 * (direct table writes can create that; the wallet API cannot) the lowest
 * slot is returned, as the scan did. Maintenance runs under wallet->cs at
 * every place a slot becomes used, is erased, or is bulk-cleared. */

#include "wallet_internal.h"
#include "util/log_macros.h"
#include <stdatomic.h>
#include <string.h>

#define TXI_MASK ((size_t)WALLET_TX_INDEX_SIZE - 1u)

static uint32_t txi_hash(const struct uint256 *id)
{
    uint64_t v;
    memcpy(&v, id->data, sizeof(v));
    return (uint32_t)((v * 0x9E3779B97F4A7C15ull) >> 32);
}

size_t wallet_find_slot_scan(const struct wallet *w, const struct uint256 *hash)
{
    for (size_t i = 0; i < MAX_WALLET_TX; i++) {
        if (w->map_wallet[i].used &&
            uint256_eq(&w->map_wallet[i].tx.hash, hash))
            return i;
    }
    return MAX_WALLET_TX;
}

size_t wallet_find_slot_indexed(const struct wallet *w,
                                const struct uint256 *hash)
{
    size_t best = MAX_WALLET_TX;
    uint32_t h = txi_hash(hash);
    for (size_t i = h & TXI_MASK; w->tx_index[i].slot_plus; i = (i + 1) & TXI_MASK) {
        if (w->tx_index[i].hash != h)
            continue;
        size_t slot = (size_t)w->tx_index[i].slot_plus - 1;
        if (slot < best && w->map_wallet[slot].used &&
            uint256_eq(&w->map_wallet[slot].tx.hash, hash))
            best = slot;
    }
    return best;
}

#ifdef ZCL_TESTING
static atomic_bool g_check = true;
static atomic_size_t g_mismatch;

void wallet_tx_index_set_check_for_test(bool on) { atomic_store(&g_check, on); }
size_t wallet_tx_index_mismatches_for_test(void) { return atomic_load(&g_mismatch); }
#endif

size_t wallet_find_slot_internal(const struct wallet *w,
                                 const struct uint256 *hash)
{
    size_t found = wallet_find_slot_indexed(w, hash);
#ifdef ZCL_TESTING
    /* Reference check in test builds: a table writer that bypassed the index
     * is reported, and the scan answer is returned so behaviour is unchanged. */
    if (atomic_load(&g_check)) {
        size_t ref = wallet_find_slot_scan(w, hash);
        if (ref != found) {
            atomic_fetch_add(&g_mismatch, 1);
            LOG_ERROR("wallet", "tx index disagrees with slot scan: index=%zu scan=%zu",
                      found, ref);
            return ref;
        }
    }
#endif
    return found;
}

static void txi_put(struct wallet *w, size_t slot)
{
    uint32_t h = txi_hash(&w->map_wallet[slot].tx.hash);
    size_t i = h & TXI_MASK;
    while (w->tx_index[i].slot_plus) {
        if (w->tx_index[i].slot_plus == slot + 1 && w->tx_index[i].hash == h)
            return;
        i = (i + 1) & TXI_MASK;
    }
    w->tx_index[i].slot_plus = (uint32_t)slot + 1;
    w->tx_index[i].hash = h;
    w->tx_index_count++;
}

void wallet_tx_index_rebuild_locked(struct wallet *w)
{
    memset(w->tx_index, 0, sizeof(w->tx_index));
    w->tx_index_count = 0;
    for (size_t i = 0; i < MAX_WALLET_TX; i++)
        if (w->map_wallet[i].used)
            txi_put(w, i);
}

void wallet_tx_index_clear(struct wallet *w)
{
    memset(w->tx_index, 0, sizeof(w->tx_index));
    w->tx_index_count = 0;
}

void wallet_tx_index_insert_locked(struct wallet *w, size_t slot)
{
    if (slot >= MAX_WALLET_TX)
        return;
    /* Stale duplicates (a writer that bypassed the index) could otherwise
     * push the load past 0.5; a rebuild re-derives it from the table. */
    if (w->tx_index_count >= MAX_WALLET_TX) {
        wallet_tx_index_rebuild_locked(w);
        return;
    }
    txi_put(w, slot);
}

static void txi_erase_at(struct wallet *w, size_t i)
{
    struct wallet_tx_index_entry *t = w->tx_index;
    for (size_t j = i;;) {
        j = (j + 1) & TXI_MASK;
        if (!t[j].slot_plus)
            break;
        size_t home = t[j].hash & TXI_MASK;
        bool between = i <= j ? (i < home && home <= j) : (i < home || home <= j);
        if (!between) {
            t[i] = t[j];
            i = j;
        }
    }
    t[i].slot_plus = 0;
    t[i].hash = 0;
    if (w->tx_index_count > 0)
        w->tx_index_count--;
}

void wallet_tx_index_remove_locked(struct wallet *w, size_t slot)
{
    if (slot >= MAX_WALLET_TX)
        return;
    uint32_t h = txi_hash(&w->map_wallet[slot].tx.hash);
    for (size_t i = h & TXI_MASK; w->tx_index[i].slot_plus; i = (i + 1) & TXI_MASK) {
        if (w->tx_index[i].slot_plus == slot + 1) {
            txi_erase_at(w, i);
            return;
        }
    }
    /* Not under its own txid: the slot's txid changed or the entry was never
     * made. Find it by slot over the whole index; exact, and never taken
     * when every writer maintains the index. */
    for (size_t i = 0; i < WALLET_TX_INDEX_SIZE; i++) {
        if (w->tx_index[i].slot_plus == slot + 1) {
            txi_erase_at(w, i);
            return;
        }
    }
}
