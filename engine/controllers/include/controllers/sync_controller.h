/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Bridge between the validation pipeline and SQLite.
 *
 * Called from connect_block/disconnect_block to keep
 * SQLite in sync with the UTXO set and block index.
 * Called from wallet_sync_transaction to track wallet UTXOs.
 *
 * This is the "controller" layer — it orchestrates model
 * writes in response to consensus events. */

#ifndef ZCL_DB_NODE_DB_SYNC_H
#define ZCL_DB_NODE_DB_SYNC_H

#include "models/database.h"
#include "models/block.h"
#include "models/tx_index.h"
#include "models/utxo.h"
#include "models/wallet_tx.h"
#include "models/mempool_entry.h"
#include "models/peer.h"
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>

struct block;
struct block_index;
struct transaction;
struct wallet;
struct node_health_snapshot;
struct active_chain;
struct coins_view_db;
struct coins_view_cache;
struct tx_mempool;
struct main_state;
struct chain_params;

struct node_db_sync_job_status {
    bool catchup_active;
    int catchup_height;
    int catchup_target_height;
    int64_t catchup_started_at;
    int64_t catchup_last_progress_at;
    bool import_active;
    int import_rows_written;
    int64_t import_started_at;
    int64_t import_last_progress_at;
};

struct node_db_sync_catchup_job {
    pthread_t thread;
    bool started;
    atomic_bool finished;
    int result;
    struct {
        struct node_db *ndb;
        const struct active_chain *chain;
        struct wallet *w;
        /* Points only into datadir_storage below, never at the starter's
         * argument. node_db_sync_catchup_job_start() spawns the worker and
         * RETURNS: a caller that resolved the network datadir into its own
         * stack buffer (catchup_lifecycle_start does exactly that) is gone
         * before the worker first reads it, and the worker would then build
         * block paths out of whatever later reused that stack. */
        const char *datadir;
        char datadir_storage[4096];
    } args;
};

struct node_db_sync_import_job {
    pthread_t thread;
    bool started;
    int result;
    struct {
        struct node_db *ndb;
        struct coins_view_db *cvdb;
    } args;
};

/* Initialize the sync layer. Opens SQLite at datadir/node.db. */
bool node_db_sync_init(struct node_db *ndb, const char *datadir);

/* Open a dedicated private SQLite handle that points at the same on-disk
 * database as an existing file-backed node_db. This is for explicit
 * isolated import/recovery flows only; live catchup must use the shared
 * db_service write lane. */
bool node_db_sync_open_private_db_like(const struct node_db *src,
                                       struct node_db *out);

#ifdef ZCL_TESTING
void node_db_sync_catchup_test_reset_lane_stats(void);
int node_db_sync_catchup_test_lane_calls(void);
int node_db_sync_catchup_test_worker_lane_calls(void);
#endif

/* Global flag: set to true while rescanwitnesses is running.
 * Prevents connect_block from overwriting the Sapling tree. */
extern _Atomic bool g_sapling_rescan_active;

/* Global flag: set to true while rebuildsaplingtree RPC is running.
 * Suppresses fatal Sapling tree root mismatch rejection so the node
 * can keep accepting blocks while the tree is being rebuilt. */
extern _Atomic bool g_sapling_tree_rebuilding;

/* Rebuild the Sapling commitment tree by replaying all shielded outputs
 * from block files (mmap-based, thread-safe). Returns total commitments
 * appended, or -1 on error. Persists result to node_state["sapling_tree"]. */
int sapling_tree_rebuild(struct node_db *ndb,
                         const struct active_chain *chain,
                         const char *datadir);

/* Persist node_state["sapling_tree"] and its co-located
 * "sapling_tree_rebuild_height" as ONE atomic write (single SQLite
 * transaction, or folded into an already-open caller transaction when
 * ndb->sync_in_batch). Every production writer of the tree blob should go
 * through this instead of two independent node_db_state_set() calls, so a
 * crash between the two can never leave the persisted height out of sync
 * with the persisted tree — the boot-time load-and-verify-at-saved-height
 * check (engine/composition/src/boot.c) depends on that pairing being trustworthy.
 * Returns false (with context logged by the caller) on any write failure. */
bool sapling_tree_persist_pair(struct node_db *ndb,
                               const void *blob, size_t blob_len,
                               int64_t height);

/* Persist the same atomic tree/height pair inside a transaction the caller
 * already owns. This is deliberately separate from
 * sapling_tree_persist_pair(): sqlite3_get_autocommit() cannot distinguish a
 * transaction owned by this call stack from a foreign transaction on the
 * shared connection. The two block-index writers call this only from their
 * serialized DB-service write lane after a successful BEGIN. It never begins
 * or commits and fails closed if the connection is in autocommit mode. */
bool sapling_tree_persist_pair_in_open_tx(struct node_db *ndb,
                                          const void *blob, size_t blob_len,
                                          int64_t height);

/* Kick off the deferred/live Sapling tree rebuild as a background,
 * supervised thread (sapling_tree_rebuild() registers "sync.
 * sapling_tree_rebuild" on the supervisor tree on entry). Called from
 * engine/composition/src/boot.c's "Sapling tree root MISMATCH ... deferring live
 * rebuild until after boot" branch when the synchronous inline rebuild
 * would be too slow to run before P2P/RPC starts — a multi-million-block
 * replay never blocks node startup this way. On spawn failure the tree
 * simply stays stale (as it already was) until an operator runs
 * `rebuildsaplingtree`. */
void sapling_tree_rebuild_start_deferred(struct node_db *ndb,
                                         struct active_chain *chain,
                                         const char *datadir,
                                         struct main_state *ms);

#ifdef ZCL_TESTING
/* Force the next `attempts` internal BEGIN calls inside
 * sapling_tree_persist_pair's retry loop to simulate SQLITE_BUSY without
 * touching the real database — lets tests drive the "retries then
 * succeeds" and "persistent BUSY names a blocker" paths deterministically
 * and fast, without racing real SQLite lock contention. `attempts < 0`
 * forces every subsequent attempt busy (persistent); `0` disables (the
 * default) and lets calls reach the real node_db_begin(). Callers MUST
 * reset to 0 after use so the fault does not leak into later tests. */
void sapling_tree_rebuild_test_force_begin_busy(int attempts);

/* Count of persists DEFERRED because the shared node_db connection already
 * held a foreign open transaction (the real production failure — a nested
 * BEGIN that returns SQLITE_ERROR, un-retryable while the outer tx lives).
 * Lets a test assert the detect-open-tx-and-defer path actually FIRED,
 * rather than only observing the absence of a crash. Reset helper zeroes it
 * so counts do not leak across tests. */
int sapling_tree_rebuild_test_persist_deferrals(void);
void sapling_tree_rebuild_test_reset_persist_deferrals(void);
bool sync_wallet_note_nullifier_refresh_for_test(
    struct wallet *wallet, const uint8_t txid[32], uint32_t output_index,
    const uint8_t nf[32]);
#endif

/* Called after a block is successfully connected to the active chain.
 * Indexes the block header, all transactions, and updates the UTXO set.
 * Runs inside a SQLite transaction for atomicity. */
bool node_db_sync_connect_block(struct node_db *ndb,
                                const struct block *blk,
                                const struct block_index *pindex);
bool node_db_sync_connect_block_async(struct node_db *ndb,
                                      const struct block *blk,
                                      const struct block_index *pindex);
/* Same fire-and-forget enqueue, plus the per-tx wallet projection folded
 * into the same db-service job (runs after the block write inside the job,
 * so its blocks-row time lookup sees this height). Use from a caller that
 * must NOT block on db-service completion — e.g. the regtest tip-finalize
 * feed, which runs under progress_store_tx_lock; a synchronous round-trip
 * there deadlocks AB-BA against any db job that reads progress.kv. */
bool node_db_sync_connect_block_async_with_wallet(struct node_db *ndb,
                                                  const struct block *blk,
                                                  const struct block_index *pindex,
                                                  struct wallet *wallet);

/* Called when a transaction is added to the wallet.
 * Tracks wallet-owned UTXOs and marks spent inputs. */
bool node_db_sync_wallet_tx(struct node_db *ndb,
                            const struct transaction *tx,
                            const struct wallet *w,
                            int block_height);

/* Fire-and-forget confirmed-wallet projection for the live tip path. Copies
 * the exact transaction and block identity before enqueueing on the existing
 * single DB writer, so a reducer thread never waits on SQLite. */
bool node_db_sync_wallet_tx_confirmed_async(
    struct node_db *ndb, const struct transaction *tx, const struct wallet *w,
    int block_height, const uint8_t block_hash[32], int64_t block_time);

/* Called when a transaction enters the mempool. */
bool node_db_sync_mempool_add(struct node_db *ndb,
                              const struct transaction *tx,
                              int64_t fee, int height);

/* Called when a transaction is removed from the mempool
 * (confirmed in a block or evicted). */
bool node_db_sync_mempool_remove(struct node_db *ndb,
                                 const uint8_t txid[32]);

/* Called when a Sapling note is decrypted (trial decryption
 * found a note belonging to our wallet). */
bool node_db_sync_sapling_note(struct node_db *ndb,
                               const uint8_t txid[32],
                               uint32_t output_index,
                               int64_t value,
                               const uint8_t rcm[32],
                               const uint8_t memo[512],
                               size_t memo_len,
                               const uint8_t ivk[32],
                               const uint8_t diversifier[11],
                               const uint8_t pk_d[32],
                               const uint8_t cm[32],
                               const uint8_t nullifier[32],
                               int block_height);

/* Mark Sapling nullifiers as spent (from a confirmed tx).
 *
 * The canonical API returns a tri-state: OK (matched an indexed note),
 * NOT_FOUND (benign — the note isn't in our index; the projection catchup
 * must skip and keep advancing), or ERROR (a real DB write failure, fatal).
 * The _bool_compat wrapper is true only on OK and is unsuitable for
 * catchup. */
enum db_mark_spent_result node_db_sync_sapling_spend(
                                struct node_db *ndb,
                                const uint8_t nullifier[32],
                                const uint8_t spending_txid[32]);
bool node_db_sync_sapling_spend_bool_compat(struct node_db *ndb,
                                const uint8_t nullifier[32],
                                const uint8_t spending_txid[32]);

/* Atomically reserve every wallet-owned Sapling note spent by an unconfirmed
 * locally-authored transaction. Unlike node_db_sync_sapling_spend(), this
 * wallet-only path does NOT insert into the confirmed-chain
 * sapling_nullifiers projection. */
bool node_db_sync_wallet_sapling_spends(
    struct node_db *ndb, const struct transaction *tx);

/* Atomically reconcile every Sapling spend from an exact canonical
 * transaction. Canonical evidence supersedes an unconfirmed local
 * reservation for the same note; a later rollback of that losing txid must
 * not make the mined note spendable again. */
bool node_db_sync_confirmed_sapling_spends(
    struct node_db *ndb, const struct transaction *tx);

/* Before wallet coin selection, reconcile every locally-unspent Sapling note
 * against the complete canonical nullifier ledger and exact active block
 * body. Returns false when that authority is incomplete or unreadable, so a
 * stale note can never be selected merely because reconciliation was down. */
bool node_db_reconcile_canonical_sapling_notes(
    struct node_db *ndb, struct main_state *ms, const char *datadir,
    size_t *reconciled_out);

/* Delete an unrelayed wallet transaction through the node.db single-writer
 * lane. Used as the durable compensation step when a post-flush reservation
 * fails. */
bool node_db_sync_wallet_tx_delete(struct node_db *ndb,
                                   const uint8_t txid[32]);

/* Retract wallet-derived rows created by an exact disconnected block.  The
 * per-transaction keep_pending flags are true only when ordinary mempool
 * admission accepted that non-coinbase transaction after the coin unwind. */
bool node_db_sync_wallet_disconnect_block(struct node_db *ndb,
                                           const struct block *blk,
                                           const bool *keep_pending);

/* Persist a peer address we learned about. */
bool node_db_sync_peer(struct node_db *ndb,
                       const uint8_t ip[16], uint16_t port,
                       uint64_t services, int64_t last_seen);

/* Persist peer bandwidth score and ZCL23 flag on disconnect.
 * Enables fast ZCL23 peer reconnection on next startup. */
bool node_db_sync_peer_score(struct node_db *ndb,
                              const uint8_t ip[16], uint16_t port,
                              uint32_t bandwidth_score, bool is_zcl23);

/* Load persisted state on startup:
 * Returns the chain tip height stored in SQLite, or -1. */
int node_db_sync_get_tip_height(struct node_db *ndb);
bool node_db_sync_get_tip_hash(struct node_db *ndb, uint8_t hash_out[32]);

/* Store the SQLite sync projection cursor. This is not publishable
 * active-chain evidence; CSR owns concrete chain-tip promotion. */
bool node_db_sync_set_tip(struct node_db *ndb,
                          const uint8_t hash[32], int height);

/* Reset the SQLite sync projection cursor to the "no tip" sentinel (-1) so
 * the next catchup re-walks from genesis (start = tip+1 = 0). Used by the
 * -reindex-explorer driver after truncating the projection tables. node.db
 * only; touches no consensus state. */
bool node_db_sync_reset_tip(struct node_db *ndb);

/* Catch up SQLite from existing chain data on disk.
 * Reads blocks from (sqlite_tip+1) to chain_tip and indexes them.
 * Also scans for wallet transactions if wallet is provided.
 * Called once at startup after chain is loaded. */
int node_db_sync_catchup(struct node_db *ndb,
                         const struct active_chain *chain,
                         struct wallet *w,
                         const char *datadir);

/* Import the full UTXO set from chainstate LevelDB into SQLite.
 * Iterates all 'c'-prefixed entries, decodes compressed outputs,
 * and bulk-inserts into the utxos table with address indexing.
 * Returns the number of UTXO outputs imported, or -1 on error. */
int node_db_sync_import_utxos(struct node_db *ndb,
                               struct coins_view_db *cvdb);

/* Save current in-memory mempool to SQLite. Called on shutdown. */
int node_db_sync_mempool_save(struct node_db *ndb,
                              const struct tx_mempool *mempool);

/* Load persisted mempool from SQLite into in-memory pool.
 * Called on startup. Every row is revalidated against the current chain;
 * stale/invalid rows are dropped. Returns count loaded. */
int node_db_sync_mempool_load(struct node_db *ndb,
                              struct tx_mempool *mempool,
                              struct coins_view_cache *coins_tip,
                              struct main_state *main_state,
                              const struct chain_params *params);

void node_db_sync_get_job_status(struct node_db_sync_job_status *out);

void node_db_sync_catchup_job_init(struct node_db_sync_catchup_job *job);
/* datadir may be NULL when run against the caller-provided `ndb` handle
 * (for example in-memory tests); if present it is used for private fallback.*/
bool node_db_sync_catchup_job_start(struct node_db_sync_catchup_job *job,
                                    struct node_db *ndb,
                                    const struct active_chain *chain,
                                    struct wallet *w,
                                    const char *datadir);
bool node_db_sync_catchup_job_join(struct node_db_sync_catchup_job *job,
                                   int *result_out);
bool node_db_sync_catchup_job_is_started(
    const struct node_db_sync_catchup_job *job);

void node_db_sync_import_job_init(struct node_db_sync_import_job *job);
bool node_db_sync_import_job_start(struct node_db_sync_import_job *job,
                                   struct node_db *ndb,
                                   struct coins_view_db *cvdb);
bool node_db_sync_import_job_join(struct node_db_sync_import_job *job,
                                  int *result_out);

#endif
