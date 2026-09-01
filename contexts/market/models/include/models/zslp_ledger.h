/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZSLP per-(token, outpoint) ledger — the PROJECTION that makes token
 * balances fully chain-derived.
 *
 * WHY this exists: `zslp_balances` (contexts/market/models/src/zslp.c) is a credit-only
 * app ledger and is left EMPTY by the chain-scan path on purpose — see
 * explorer_index_zslp.c: "a credit-only ledger cannot debit SEND inputs
 * and would over-count holders; deferred to a future per-(token,outpoint)
 * ledger". THIS is that ledger. Each row is ONE token-bearing transaction
 * output (an SLP UTXO): it is created when a GENESIS/MINT/SEND assigns a
 * token amount to a real output, and marked spent when a later transaction
 * spends that outpoint (the always-on tx_inputs spend graph). A holder's
 * balance is therefore SUM(amount) over that holder's UNSPENT rows — a
 * debit-correct ledger, unlike the credit-only zslp_balances.
 *
 * Chain-derived + rebuildable: every row is derived from confirmed,
 * already-persisted node.db projections — zslp_transfers (the SLP
 * amount/vout/token_id interpretation, produced by explorer_index_apply_slp
 * so we do NOT re-implement the SLP field mapping), tx_outputs (the
 * authoritative recipient address + proof the output really exists), and
 * tx_inputs (the spend graph). Never consulted by consensus; rebuildable
 * from scratch via zslp_ledger_truncate + a fresh backfill.
 *
 * Strict validity: rows enter this ledger only after zslp_validity validates
 * GENESIS shape, recursive SEND ancestry/conservation, or current mint-baton
 * lineage. INVALID and UNKNOWN declarations remain diagnostic-only and never
 * enter balances or coin selection.
 *
 * Threading contract (mirrors op_return_index.h): row inserts + spend marks
 * are idempotent (INSERT OR IGNORE + deterministic UPDATE) and safe from
 * ANY thread, so the live tip hook (zslp_ledger_apply_slp_live, called from
 * explorer_index.c's index_op_return) and the backfill service can write
 * the SAME rows without coordination. The cursor + running digest
 * (zslp_ledger_get_cursor/set_cursor, folded by zslp_ledger_apply_height)
 * are owned EXCLUSIVELY by the single supervisor-driven backfill service so
 * two independently-indexing nodes converge on the same digest. */

#ifndef ZCL_DB_MODEL_ZSLP_LEDGER_H
#define ZCL_DB_MODEL_ZSLP_LEDGER_H

#include "models/database.h"

#include <stdbool.h>
#include <stdint.h>

struct transaction; /* fwd — primitives/transaction.h */
struct slp_message; /* fwd — zslp/slp.h */

/* Live per-block hook: apply a parsed SLP message for the tx in hand.
 * Creates a ledger row for every token-bearing output the message assigns
 * (GENESIS/MINT -> vout 1, SEND -> vouts 1..N; same interpretation as
 * explorer_index_apply_slp) that actually exists on the tx, and marks spent
 * every ledger outpoint this tx's inputs consume. Idempotent; never touches
 * the cursor/digest. Address is resolved from the tx's own output script
 * (tx_outputs for those vouts may not be written yet at this call site).
 * Best-effort: a single row failure is logged, not fatal. */
bool zslp_ledger_apply_slp_live(struct node_db *ndb,
                                const struct transaction *tx,
                                const struct slp_message *m, int height);

/* Backfill one height from node.db projections and fold its running digest.
 * CREATE rows: zslp_transfers JOIN tx_outputs at `height` (token amount +
 * authoritative address + existence proof). SPENDS: tx_inputs at `height`
 * whose consumed outpoint has a ledger row. Rows are (re-)inserted
 * idempotently and spends marked; then a streaming SHA3 digest folds
 * prev_digest, the height, every CREATE (token_id/txid/vout/amount/address/
 * created_height) in (txid,vout) order, and every SPEND (outpoint + spender
 * + height) in (txid,vin_index) order. Folds EVERY height (including ones
 * with no SLP activity) so the digest also proves no height was skipped.
 * Owned exclusively by the backfill service. Returns false on a DB error
 * (caller must stop the batch — advance-cursor-or-named-blocker). */
bool zslp_ledger_apply_height(struct node_db *ndb, int32_t height,
                              const uint8_t prev_digest[32],
                              uint8_t out_digest[32]);

/* Cursor = highest height whose digest has been folded, contiguous from -1
 * (nothing folded yet). Always returns true unless ndb is unusable. */
bool zslp_ledger_get_cursor(struct node_db *ndb, int32_t *out_height,
                            uint8_t out_digest[32]);
bool zslp_ledger_set_cursor(struct node_db *ndb, int32_t height,
                            const uint8_t digest[32]);

/* Drop-and-rederive: delete every ledger row and reset cursor/digest. */
bool zslp_ledger_truncate(struct node_db *ndb);

/* Reconciliation surface: a holder's spendable token balance =
 * SUM(amount) over that (token_id,address)'s UNSPENT rows. token_id is
 * internal (node) byte order; address is the 20-byte hash160. */
int64_t zslp_ledger_balance(struct node_db *ndb, const uint8_t token_id[32],
                            const uint8_t address[20]);

/* The same fold restricted to a stated height: rows created at or below
 * `height` that were unspent as of `height` (never spent, or spent strictly
 * above it). Reproducible by construction — the same ledger contents and the
 * same height always yield the same number, whenever the query runs — which
 * is what makes a token-derived access verdict auditable rather than
 * whatever-the-balance-happened-to-be. Negative heights return 0.
 *
 * Reproducible does NOT mean authoritative on its own: if the ledger has not
 * folded past `height` (zslp_ledger_get_cursor), the answer is a partial
 * index, not history. Callers that gate on it must check the cursor and fail
 * closed. */
int64_t zslp_ledger_balance_at_height(struct node_db *ndb,
                                      const uint8_t token_id[32],
                                      const uint8_t address[20],
                                      int32_t height);

/* One ZSLP token this wallet holds, folded over EVERY address the wallet
 * owns rather than the single (token, address) pair zslp_ledger_balance
 * answers for. */
struct zslp_wallet_token {
    uint8_t token_id[32];  /* internal (node) byte order, as stored */
    int64_t balance;       /* SUM(amount) over the wallet's UNSPENT rows */
    int64_t utxo_count;    /* how many unspent token outputs back it */
};

/* Wallet-wide sweep: every token this wallet holds, one row per token_id in
 * ascending token_id order, each balance folded across the wallet's own
 * addresses. "The wallet's own addresses" is the union of wallet_keys
 * (spendable) and wallet_watch_only (imported, watched) — both are 20-byte
 * hash160 keys in the same node.db as the ledger, so the whole fold is one
 * indexed GROUP BY and never a per-address round trip.
 *
 * Returns the number of rows written to `out` (never negative). A wallet
 * that holds no tokens returns 0 with `out` untouched — an empty holding is
 * an answer, not an error. Bounded by `max`; a wallet holding more distinct
 * tokens than `max` is truncated at the cap (raise the cap to see the rest).
 * Reads only UNSPENT rows, so it is debit-correct by construction. */
int zslp_ledger_wallet_tokens(struct node_db *ndb,
                              struct zslp_wallet_token *out, size_t max);

/* The same wallet-wide fold narrowed to ONE token — the wallet-wide answer
 * to the question zslp_ledger_balance() answers per address. 0 when the
 * wallet holds none of it. */
int64_t zslp_ledger_wallet_balance(struct node_db *ndb,
                                   const uint8_t token_id[32]);

/* Wallet-wide fold at a stated height. Same reproducibility contract and
 * same cursor caveat as zslp_ledger_balance_at_height. */
int64_t zslp_ledger_wallet_balance_at_height(struct node_db *ndb,
                                             const uint8_t token_id[32],
                                             int32_t height);

/* How many transparent addresses the two wallet-wide sweeps above fold
 * over (wallet_keys + wallet_watch_only, de-duplicated). 0 for a wallet
 * with no keys — which is exactly why an empty sweep is empty. */
int64_t zslp_ledger_wallet_address_count(struct node_db *ndb);

/* Row counts for diagnostics. */
int64_t zslp_ledger_count(struct node_db *ndb);
int64_t zslp_ledger_unspent_count(struct node_db *ndb);

/* Exact strict-ledger verdict for a proposed token outpoint. The lookup is
 * intentionally narrower than a balance: a swap buyer must prove that this
 * one outpoint is the one valid TOKEN row it was promised, with the exact
 * token and amount, and that no canonical spend has consumed it. */
enum zslp_ledger_outpoint_state {
    ZSLP_LEDGER_OUTPOINT_ERROR = 0,
    ZSLP_LEDGER_OUTPOINT_ABSENT,
    ZSLP_LEDGER_OUTPOINT_MISMATCH,
    ZSLP_LEDGER_OUTPOINT_SPENT,
    ZSLP_LEDGER_OUTPOINT_UNSPENT_TOKEN,
};
enum zslp_ledger_outpoint_state zslp_ledger_token_outpoint_state(
    struct node_db *ndb, const uint8_t txid[32], uint32_t vout,
    const uint8_t token_id[32], uint64_t amount);

/* Validator-only model seam. zslp_validity is the sole production caller. */
bool zslp_ledger_record_valid_output(struct node_db *ndb,
    const uint8_t token_id[32], const uint8_t txid[32], int32_t vout,
    int64_t amount, const uint8_t *address_or_null, int32_t created_height,
    int role);
bool zslp_ledger_mark_valid_spent(struct node_db *ndb,
    const uint8_t prev_txid[32], int32_t prev_vout,
    const uint8_t spender_txid[32], int32_t height);

#endif /* ZCL_DB_MODEL_ZSLP_LEDGER_H */
