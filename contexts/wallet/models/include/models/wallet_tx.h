/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_DB_MODEL_WALLET_TX_H
#define ZCL_DB_MODEL_WALLET_TX_H

#include "models/database.h"
#include "models/activerecord.h"
#include <stdbool.h>
#include <stdint.h>

struct db_wallet_tx {
    uint8_t txid[32];
    uint8_t *raw_tx;
    size_t raw_tx_len;
    uint8_t block_hash[32];
    bool has_block;
    int block_height;
    int64_t time_received;
    bool from_me;
    int64_t fee;
};

struct db_wallet_projection_summary {
    int chain_tip_height;
    int effective_tip_height;
    int utxo_count;
    int note_count;
    int64_t transparent_balance;
    int64_t shielded_balance;
    int64_t speed_balance;
};

struct db_wallet_txid_ref {
    uint8_t txid[32];
};

struct db_wallet_tx_raw_view {
    uint8_t *raw_tx;
    size_t raw_tx_len;
    int block_height;
};

/* Callbacks and validation */
struct ar_callbacks *db_wallet_tx_callbacks(void);
bool db_wallet_tx_validate(const struct db_wallet_tx *t, struct ar_errors *errors);

bool db_wallet_tx_save(struct node_db *ndb, const struct db_wallet_tx *t);
bool db_wallet_tx_find(struct node_db *ndb, const uint8_t txid[32],
                       struct db_wallet_tx *out);
bool db_wallet_tx_delete(struct node_db *ndb, const uint8_t txid[32]);
bool db_wallet_tx_mark_unconfirmed(struct node_db *ndb,
                                   const uint8_t txid[32], bool *found_out);
int db_wallet_tx_count(struct node_db *ndb);
/* Number of wallet transactions whose durable projection names a confirmed
 * block hash. Used to detect when the in-memory wallet publication trails
 * confirmed history even though its coarse scan height reached the tip. */
int db_wallet_tx_confirmed_count(struct node_db *ndb);
void db_wallet_tx_free(struct db_wallet_tx *t);

/* Sum of fees over from-me transactions with a positive fee, and the
 * count of such fee-paying transactions (via fee_paying_count, if non-NULL).
 * Returns 0 / sets count 0 on a closed db. */
int64_t db_wallet_tx_total_fees(struct node_db *ndb, int *fee_paying_count);

/* Read-only projection for raw wallet transactions ordered by height desc.
 * Intended for controller/service scans that need deserializable tx blobs
 * without owning SQL directly. Caller must free rows with
 * db_wallet_tx_raw_view_free(). */
int db_wallet_tx_recent_raw(struct node_db *ndb,
                            struct db_wallet_tx_raw_view *out,
                            size_t max);
void db_wallet_tx_raw_view_free(struct db_wallet_tx_raw_view *row);
int db_wallet_tx_list_unconfirmed(struct node_db *ndb,
                                  struct db_wallet_txid_ref *out,
                                  size_t max);
bool db_wallet_tx_update_block_height(struct node_db *ndb,
                                      const uint8_t txid[32],
                                      int block_height);

/* List wallet transactions in descending time order with offset paging. */
int db_wallet_tx_list(struct node_db *ndb, struct db_wallet_tx *out,
                      size_t max, size_t offset);

/* Wallet UTXOs (transparent outputs belonging to the wallet) */
struct db_wallet_utxo {
    uint8_t txid[32];
    uint32_t vout;
    int64_t value;
    uint8_t address_hash[20];
    uint8_t *script;
    size_t script_len;
    int height;
    uint8_t spent_txid[32];
    int spent_vin;
    bool is_spent;
    bool is_coinbase;
};

/* Validation */
bool db_wallet_utxo_validate(const struct db_wallet_utxo *u,
                              struct ar_errors *errors);

bool db_wallet_utxo_save(struct node_db *ndb, const struct db_wallet_utxo *u);
bool db_wallet_utxo_mark_spent(struct node_db *ndb,
                               const uint8_t txid[32], uint32_t vout,
                               const uint8_t spent_by[32], int vin);
bool db_wallet_utxo_find(struct node_db *ndb,
                         const uint8_t txid[32], uint32_t vout,
                         struct db_wallet_utxo *out);
int64_t db_wallet_utxo_balance(struct node_db *ndb);
int64_t db_wallet_utxo_balance_with_count(struct node_db *ndb, int *utxo_count);
/* Value held by inputs reserved by wallet transactions that are currently
 * unconfirmed. It is not spendable, but remains wallet-owned/encumbered. */
int64_t db_wallet_utxo_encumbered_balance(struct node_db *ndb);

/* SPENDABLE transparent balance: the SUM over unspent UTXOs that EXCLUDES
 * immature coinbase (a coinbase output is spendable only once it is buried
 * COINBASE_MATURITY=100 blocks deep), mirroring the spend coin-selector
 * (db_wallet_utxo_select_coins) and rpc_listunspent. Use this for any balance
 * a user can actually spend; the plain db_wallet_utxo_balance is the raw total
 * of all unspent UTXOs (immature coinbase included) and is for diagnostics.
 * The chain tip height is read internally from the blocks table; pass NULL for
 * utxo_count if not needed. */
int64_t db_wallet_utxo_spendable_balance(struct node_db *ndb, int *utxo_count);
int db_wallet_chain_tip_height(struct node_db *ndb);
int db_wallet_effective_tip_height(struct node_db *ndb);
bool db_wallet_projection_summary(struct node_db *ndb,
                                  struct db_wallet_projection_summary *out);

/* List unspent wallet UTXOs. Returns count. */
int db_wallet_utxo_list_unspent(struct node_db *ndb,
                                struct db_wallet_utxo *out, size_t max);

/* List all wallet UTXOs (spent + unspent). Returns count. */
int db_wallet_utxo_list_all(struct node_db *ndb,
                            struct db_wallet_utxo *out, size_t max);

/* Recent wallet activity row: the value/height of an unspent wallet UTXO
 * joined with its block time (0 when the block row is absent). Powers the
 * API wallet panel's "activity" list. */
struct db_wallet_activity {
    int64_t value;
    int height;
    int64_t time;
};

/* List the most-recent unspent wallet UTXOs (height DESC) with block time,
 * up to max rows. Returns count written to out. */
int db_wallet_utxo_recent_activity(struct node_db *ndb,
                                   struct db_wallet_activity *out, size_t max);

/* Coin selection: unspent, non-coinbase (or mature coinbase). */
int db_wallet_utxo_select_coins(struct node_db *ndb, int64_t target,
                                int current_height,
                                struct db_wallet_utxo *out, size_t max);

/* Coin selection restricted to a single 20-byte address hash: unspent,
 * mature-coinbase-only, value DESC, accumulating until the running total
 * reaches `target`. Pushing the address into the SQL WHERE (rather than
 * selecting globally then post-filtering) ensures a fully funded from-address
 * is never falsely rejected with "Insufficient funds" because higher-value
 * coins on OTHER addresses crowded out the selection window. Returns count. */
int db_wallet_utxo_select_coins_for_address(struct node_db *ndb, int64_t target,
                                            int current_height,
                                            const uint8_t address_hash[20],
                                            struct db_wallet_utxo *out,
                                            size_t max);

/* Delete a single wallet UTXO by outpoint. */
bool db_wallet_utxo_delete(struct node_db *ndb,
                            const uint8_t txid[32], uint32_t vout);
bool db_wallet_utxo_delete_for_tx(struct node_db *ndb,
                                  const uint8_t txid[32]);
bool db_wallet_utxo_release_spent_by(struct node_db *ndb,
                                     const uint8_t spent_by[32]);

/* Count wallet UTXOs for a given txid. */
int db_wallet_utxo_count_for_tx(struct node_db *ndb,
                                 const uint8_t txid[32]);

/* Free malloc'd fields (script) after db_wallet_utxo_find(). */
void db_wallet_utxo_free(struct db_wallet_utxo *u);

/* Delete all wallet UTXOs. */
bool db_wallet_utxo_delete_all(struct node_db *ndb);
bool db_wallet_utxo_replace_all(struct node_db *ndb,
                                const struct db_wallet_utxo *rows,
                                size_t count);

/* Delete all wallet transactions. */
bool db_wallet_tx_delete_all(struct node_db *ndb);

/* Sapling notes */
#define DB_SAPLING_NOTE_SOURCE_LOCAL "local"
#define DB_SAPLING_NOTE_SOURCE_VIEW  "view"

struct db_sapling_note {
    uint8_t txid[32];
    uint32_t output_index;
    int64_t value;
    uint8_t rcm[32];
    uint8_t memo[512];
    size_t memo_len;
    uint8_t ivk[32];
    uint8_t diversifier[11];
    uint8_t pk_d[32];
    uint8_t cm[32];
    uint8_t nullifier[32];
    int block_height;
    uint8_t spent_txid[32];
    bool is_spent;
    uint8_t *witness_data;
    size_t witness_data_len;
    int witness_height;
    char address[128]; /* bech32 z-address derived from diversifier+pk_d */
    char source[16];   /* local catchup/decrypt note, or view-only placeholder */
};

bool db_sapling_note_validate(const struct db_sapling_note *n,
                               struct ar_errors *errors);
bool db_sapling_note_save(struct node_db *ndb, const struct db_sapling_note *n);

/* Tri-state result for marking a sapling note spent.
 *
 * The node.db index only tracks wallet/indexed sapling notes, NOT every
 * note on the chain. During projection catchup we replay EVERY on-chain
 * sapling spend; the vast majority reference notes we never indexed. That
 * is a BENIGN miss, not an error — the caller must keep going. Only a real
 * SQLite write failure (busy/error/corrupt) is fatal. The legacy bool API
 * conflated the two (returned false for both), which wedged the whole
 * backfill on the first not-our-note spend. */
enum db_mark_spent_result {
    DB_MARK_SPENT_OK = 0,        /* matched an indexed note and updated it   */
    DB_MARK_SPENT_NOT_FOUND = 1, /* nullifier not in our index (benign skip) */
    DB_MARK_SPENT_ERROR = 2,     /* real DB write error (fatal)              */
};

/* Canonical tri-state API. Distinguishes benign-miss from real write error
 * so the projection catchup can skip not-our-note spends without aborting. */
enum db_mark_spent_result db_sapling_note_mark_spent(
                                struct node_db *ndb,
                                const uint8_t nullifier[32],
                                const uint8_t spent_by[32]);

/* Wallet-author reservation variant: claim only an unspent note, or accept
 * an exact retry by the same transaction.  A different spending txid is a
 * conflict and returns NOT_FOUND without replacing the first reservation. */
enum db_mark_spent_result db_sapling_note_reserve_spend(
                                struct node_db *ndb,
                                const uint8_t nullifier[32],
                                const uint8_t spent_by[32]);

/* Release every wallet-note reservation owned by one transaction. Used only
 * after exact bytes are consensus-expired or an unrelayed commit rolls back. */
bool db_sapling_note_release_reservation(struct node_db *ndb,
                                         const uint8_t spent_by[32]);

enum db_sapling_note_reservation_state {
    DB_NOTE_RESERVATION_ERROR = 0,
    DB_NOTE_RESERVATION_MISSING,
    DB_NOTE_RESERVATION_AVAILABLE,
    DB_NOTE_RESERVATION_SAME_TX,
    DB_NOTE_RESERVATION_CONFLICT,
};

/* Read-only preflight for durable prepared-byte recovery. It distinguishes a
 * temporarily unreadable database from a permanently stale nullifier and an
 * idempotent same-transaction reservation. */
enum db_sapling_note_reservation_state db_sapling_note_reservation_probe(
                                struct node_db *ndb,
                                const uint8_t nullifier[32],
                                const uint8_t spending_txid[32]);

/* Legacy bool wrapper: true only when an indexed note was updated.
 * Treats both NOT_FOUND and ERROR as false — do NOT use this in catchup. */
bool db_sapling_note_mark_spent_bool_compat(struct node_db *ndb,
                                const uint8_t nullifier[32],
                                const uint8_t spent_by[32]);
int64_t db_sapling_note_balance(struct node_db *ndb);
int64_t db_sapling_note_encumbered_balance(struct node_db *ndb);
int64_t db_sapling_note_balance_for_ivk(struct node_db *ndb,
                                        const uint8_t ivk[32]);

/* minconf-aware shielded balance for an ivk: sums only notes confirmed at
 * least `minconf` deep relative to the chain tip (notes with NULL block_height
 * or fewer than minconf confirmations are excluded). `tip_height` is the
 * current chain tip; pass minconf<=0 to count every unspent note (including
 * unconfirmed). */
int64_t db_sapling_note_balance_for_ivk_minconf(struct node_db *ndb,
                                                const uint8_t ivk[32],
                                                int tip_height, int minconf);
int64_t db_sapling_note_balance_with_count(struct node_db *ndb, int *note_count);
int64_t db_sapling_note_balance_for_address(struct node_db *ndb,
                                            const char *address);
int64_t db_sapling_note_balance_for_exact_value(struct node_db *ndb,
                                                int64_t value);

/* List unspent notes. Returns count. */
int db_sapling_note_list_unspent(struct node_db *ndb,
                                 struct db_sapling_note *out, size_t max);

/* Count of unspent notes (spent_txid IS NULL). 0 on error/empty. */
int db_sapling_note_count_unspent(struct node_db *ndb);

struct db_sapling_witness_summary {
    int local_unspent_notes;
    int ready_notes;
    int missing_notes;
    int stale_notes;
    int tip_height;
};

/* Bounded scalar readiness for locally spendable notes. No note identity,
 * address, witness bytes, memo, or key crosses this API. */
bool db_sapling_note_witness_summary(
    struct node_db *ndb, int tip_height,
    struct db_sapling_witness_summary *out);

/* List ALL unspent notes, heap-allocating a buffer sized to the live count
 * (no fixed cap). On success returns a non-negative count and sets *out to a
 * malloc'd array the caller frees with free(); when the count is 0 *out is set
 * to NULL. Returns -1 on allocation/DB error. Use this instead of the fixed-
 * cap db_sapling_note_list_unspent for witness maintenance and listings that
 * must cover every note regardless of value rank. */
int db_sapling_note_list_unspent_alloc(struct node_db *ndb,
                                       struct db_sapling_note **out);

/* List unspent notes for a specific ivk. Returns count. */
int db_sapling_note_list_unspent_for_ivk(struct node_db *ndb,
                                          const uint8_t ivk[32],
                                          struct db_sapling_note *out, size_t max);

/* List all notes (spent + unspent). Returns count. */
int db_sapling_note_list_all(struct node_db *ndb,
                              struct db_sapling_note *out, size_t max);

/* List all notes for the coinanalysis RPC: a narrower projection
 * (txid, output_index, value, block_height, spent_txid, diversifier,
 * pk_d, witness_height) ordered by block_height ASC, with the z-address
 * derived (HRP "zs") only when diversifier+pk_d are present. The other
 * struct fields (rcm/memo/ivk/cm/nullifier) are left zeroed. Returns
 * count written to out. */
int db_sapling_note_list_all_analysis(struct node_db *ndb,
                                      struct db_sapling_note *out, size_t max);

/* Save/load witness data for a Sapling note */
bool db_sapling_note_save_witness(struct node_db *ndb,
                                   const uint8_t txid[32], uint32_t output_index,
                                   const uint8_t *witness_blob, size_t blob_len,
                                   int height);
/* Witness creation reveals the note's exact commitment-tree position.  Persist
 * the position-derived nullifier in the SAME row update so subsequent atomic
 * reservation matches the SpendDescription rather than the decrypt-time
 * position-0 placeholder. */
bool db_sapling_note_save_witness_and_nullifier(
    struct node_db *ndb, const uint8_t txid[32], uint32_t output_index,
    const uint8_t *witness_blob, size_t blob_len, int height,
    const uint8_t nullifier[32]);
bool db_sapling_note_load_witness(struct node_db *ndb,
                                   const uint8_t txid[32], uint32_t output_index,
                                   uint8_t **witness_blob_out, size_t *blob_len_out,
                                   int *height_out);
bool db_sapling_note_delete_all(struct node_db *ndb);
bool db_sapling_note_delete(struct node_db *ndb, const uint8_t txid[32],
                            uint32_t output_index);
bool db_sapling_note_delete_for_tx(struct node_db *ndb,
                                   const uint8_t txid[32]);
bool db_sapling_note_replace_all(struct node_db *ndb,
                                 const struct db_sapling_note *rows,
                                 size_t count);
bool db_sapling_note_replace_view_rows(struct node_db *ndb,
                                       const struct db_sapling_note *rows,
                                       size_t count);
int db_sapling_note_count_unspent_view_for_address(struct node_db *ndb,
                                                   const char *address);

/* Free malloc'd fields (witness_data) after loading a sapling note. */
void db_sapling_note_free(struct db_sapling_note *n);

/* ── Relationships ─────────────────────────────────────────────── */

/* WalletTx has_many :wallet_utxos */
int db_wallet_tx_utxos(struct node_db *ndb, const uint8_t txid[32],
                        struct db_wallet_utxo *out, size_t max);

/* WalletTx has_many :sapling_notes */
int db_wallet_tx_notes(struct node_db *ndb, const uint8_t txid[32],
                        struct db_sapling_note *out, size_t max);

/* WalletUTXO belongs_to :wallet_key */
struct db_wallet_key;
bool db_wallet_utxo_key(struct node_db *ndb, const struct db_wallet_utxo *u,
                        struct db_wallet_key *out);

/* SaplingNote belongs_to :sapling_key */
struct db_sapling_key;
bool db_sapling_note_key(struct node_db *ndb, const struct db_sapling_note *n,
                         struct db_sapling_key *out);

/* Callbacks for wallet UTXO and sapling note */
struct ar_callbacks *db_wallet_utxo_callbacks(void);
/* Test-only: re-arm the wallet_tx + wallet_utxo before/after_save hooks (see .c). */
void wallet_tx_reset_hooks_for_testing(void);
struct ar_callbacks *db_sapling_note_callbacks(void);

#endif
