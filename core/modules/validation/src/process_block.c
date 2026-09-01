/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * process_block.c — top-level wiring for the validation/process_block
 * translation units:
 *   process_block_core.c             : best-work chain selection
 *   process_block_contextual_header.c: sparse-header contextual skip policy
 *   process_block_self_heal.c        : missing-UTXO failure tracking
 *   process_block_self_heal_hot_loop.c: reimport pause + shutdown policy
 *   process_block_self_heal_scan_state.c: scan counters + tunables
 *   process_block_flush_policy.c     : coins flush + Sapling persistence
 *   process_block_crash_hooks.c      : PBCS_* crash-injection hooks
 *
 * This file keeps the cross-module accessor functions, the node_db
 * wiring, the "more pending" signal, and the misc helpers that don't
 * naturally belong to a narrower owner. */

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "validation/process_block.h"
#include "validation/process_block_internals.h"
#include "storage/node_db_runtime.h"

#include "process_block_internal.h"

/* ── Externs published by other subsystems ───────────────────── */
/* Set in boot.c; re-declare here so process-block helpers can use it without
 * dragging in boot.h. (Mirrors original process_block.c.) */
/* extern struct block_tree_db *g_active_block_tree; — declared in internal.h */
/* extern volatile sig_atomic_t g_shutdown_requested; — declared in internal.h */

/* ── node_db wiring ──────────────────────────────────────────── */
static struct node_db *g_process_block_node_db = NULL;

void process_block_set_node_db(struct node_db *ndb)
{
    g_process_block_node_db = ndb;
}

/* Internal accessor used by the process-block helpers (self-heal,
 * flush-policy). Declared in process_block_internal.h. The former public
 * wrapper (process_block_get_node_db) was removed once its only external
 * caller, the fast-sync legacy_body_pull ingester, was deleted. */
struct node_db *process_block_node_db_internal(void)
{
    struct node_db *ndb = node_db_runtime();
    if (node_db_runtime_handle_open(ndb))
        return ndb;
    return node_db_runtime_handle_open(g_process_block_node_db)
         ? g_process_block_node_db
         : NULL;
}

/* ── live-height stage logger ────────────────────────────────── */
bool process_block_live_height(int height)
{
    return height > 1000000;
}

/* ── body-pull signal (public via process_block.h) ───────────── */
/* See process_block.h. Set by fast-sync ingesters before their loops;
 * cleared after. Each per-block validation pass reads atomically. */
_Atomic int g_body_pull_active = 0;

/* ── active-tip "more pending" signal ─────────────────────────── */
/* Set when a staged activation drain reaches tip_child_connect_limit. Read by
 * chain_activation_controller so we don't wait for the next P2P block to make
 * progress. */
static _Atomic bool s_active_tip_more_pending = false;

bool process_block_active_tip_has_pending(void)
{
    return atomic_load(&s_active_tip_more_pending);
}

/* ── Cross-file accessors used by chain_advance / introspection ── */

struct coins_view_sqlite *process_block_get_coins_sqlite(void)
{
    return process_block_coins_sqlite_ptr();
}
