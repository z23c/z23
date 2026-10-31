// one-result-type-ok:option-state-and-height-queries — an atomic option flag and pure height queries; an absent seed is reported as -1.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Option -catchup-from-seed: start the node.db catchup walk above the
 * shielded seed. See services/node_db_catchup_service.h for the contract. */

#include "services/node_db_catchup_service.h"

#include "storage/anchor_kv.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdatomic.h>

static _Atomic bool g_from_seed;

void node_db_catchup_set_from_seed(bool enabled)
{
    atomic_store(&g_from_seed, enabled);
}

bool node_db_catchup_from_seed(void)
{
    return atomic_load(&g_from_seed);
}

int node_db_catchup_seed_height(void)
{
    sqlite3 *rdb = progress_store_open_reader();
    if (!rdb)
        return -1; // raw-return-ok:no reducer store open; there is no seed to read
    int64_t activation = 0;
    bool found = false;
    bool ok = anchor_kv_activation_cursor(rdb, ANCHOR_POOL_SAPLING, &activation,
                                          &found);
    sqlite3_close(rdb);
    return ok && found && activation > 0 && activation < INT32_MAX
               ? (int)activation
               : -1;
}

int node_db_catchup_first_height(int next, int seed_height, bool from_seed)
{
    if (!from_seed || seed_height < 0 || seed_height + 1 <= next)
        return next;
    return seed_height + 1;
}

int node_db_catchup_start_height(int next)
{
    bool on = node_db_catchup_from_seed();
    return node_db_catchup_first_height(
        next, on ? node_db_catchup_seed_height() : -1, on);
}

bool node_db_catchup_seed_prefix_expected(void)
{
    return node_db_catchup_from_seed() && node_db_catchup_seed_height() >= 0;
}
