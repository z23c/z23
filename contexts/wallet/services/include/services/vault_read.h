/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_SERVICES_VAULT_READ_H
#define ZCL_SERVICES_VAULT_READ_H

#include "base/result.h"
#include "models/zslp.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;
struct json_value;

/* The vault read model — one honest answer to "what does this node own?".
 *
 * The node can hold six distinct kinds of asset. Every one of them already
 * had a primitive that could count it, and none of them were ever added up:
 * `getbalance` reports transparent UTXOs alone
 * (db_wallet_utxo_spendable_balance), `walletledger` reconciles transparent
 * against shielded, and the remaining four classes had no aggregate at all.
 * Funds committed to an atomic-swap HTLC were the sharpest case: the node
 * holds the redeem script and the secret, so the coins are recoverable and
 * therefore owned, yet they appeared in no balance the operator could ask
 * for. This read model exists so that stops being true.
 *
 * Two rules shape the interface, and both come from that bug:
 *
 *   1. NO NEW BALANCE MATHEMATICS. Every number here is produced by the
 *      query that already owns it — db_wallet_utxo_*_balance,
 *      db_sapling_note_balance_with_count, zslp_ledger_balance,
 *      db_znam_list_by_owner, db_swap_list, db_file_offer_list. This file
 *      enumerates identities and routes; it does not re-derive money. Each
 *      row names the primitive it came from in `source_primitive` so a
 *      reader can go check.
 *
 *   2. NO SILENT OMISSIONS. A class that cannot be determined emits a row
 *      that says so (`determined = false` plus a reason) rather than
 *      vanishing from the output. A confident wrong total is worse than an
 *      admitted gap, and a gap that is merely missing is indistinguishable
 *      from a zero. vault_read_snapshot() fails outright if any class in
 *      the table produced no row at all.
 *
 * Encumbrance is a column, not a footnote. `spendable` and `encumbered` are
 * different facts about ownership: HTLC-locked coins are owned but not
 * spendable today, and collapsing the two is exactly how they went missing.
 */

/* The canonical class list. Adding a kind of asset means adding one line
 * here and one collector in vault_read.c — the build fails if a class in
 * this table has no collector, and the snapshot fails if a collector
 * returns without writing its row. */
#define VAULT_CLASS_TABLE(X)                                            \
    X(TRANSPARENT, "transparent_zcl",   "zatoshi")                      \
    X(SHIELDED,    "shielded_zcl",      "zatoshi")                      \
    X(TOKEN,       "zslp_tokens",       "token_base_units")             \
    X(NAME,        "znam_names",        "names")                        \
    X(SWAP,        "swap_encumbered",   "zatoshi")                      \
    X(MARKET,      "file_market_offers", "offers")

enum vault_class {
#define VAULT_CLASS_ENUM(id_, name_, unit_) VAULT_CLASS_##id_,
    VAULT_CLASS_TABLE(VAULT_CLASS_ENUM)
#undef VAULT_CLASS_ENUM
    VAULT_CLASS_COUNT
};

static_assert(VAULT_CLASS_COUNT == 6,
              "the node holds six asset classes; a change here needs a "
              "collector in vault_read.c and a CLAUDE.md update");

/* Evidence grade, reusing the exact_/heuristic_ vocabulary the `code
 * capsule` command established (tools/command/native_code_command.c). An
 * `exact_` grade means the number came from a query over rows that record
 * ownership directly. `heuristic_` means ownership was inferred from a
 * field that was never designed to prove it. */
enum vault_evidence {
    VAULT_EVIDENCE_UNKNOWN = 0,
    VAULT_EVIDENCE_EXACT_WALLET_UTXO_SUM,
    VAULT_EVIDENCE_EXACT_NOTE_SUM,
    VAULT_EVIDENCE_EXACT_LEDGER_UNSPENT,
    VAULT_EVIDENCE_EXACT_OWNER_ADDRESS_MATCH,
    VAULT_EVIDENCE_EXACT_CONTRACT_STATE,
    VAULT_EVIDENCE_HEURISTIC_PAYMENT_ADDRESS_MATCH
};

/* Wire name for an evidence grade ("exact_wallet_utxo_sum", ...). Never
 * NULL; an out-of-range value renders as "unknown". */
const char *vault_evidence_name(enum vault_evidence evidence);

/* Wire name ("transparent_zcl", ...) and unit ("zatoshi", ...) for a class.
 * Never NULL; an out-of-range class renders as "unknown". */
const char *vault_class_name(enum vault_class cls);
const char *vault_class_unit(enum vault_class cls);

#define VAULT_REASON_MAX 160
#define VAULT_TOKEN_ITEMS_MAX 64

/* Token balances cannot be added across token IDs. Each item therefore
 * keeps its own identifier and base-unit balance. */
struct vault_token_item {
    uint8_t token_id[32];
    char ticker[ZSLP_TICKER_MAX + 1];
    char name[ZSLP_NAME_MAX + 1];
    int decimals;
    int64_t units;
    int64_t utxo_count;
    bool metadata_available;
};

/* One asset class's holdings.
 *
 * The four amount columns are disjoint — a unit of value is counted in
 * exactly one of them, so they may be summed without double-counting:
 *
 *   spendable   available to spend right now
 *   pending     owned but not yet confirmed / not yet final
 *   immature    owned but time-locked by consensus (coinbase maturity)
 *   encumbered  owned but committed to a contract (a live HTLC), payable
 *               only by redeem-with-secret or refund-after-locktime
 *
 * For non-fungible classes (names, market offers) the columns count items
 * in `unit` rather than money, and `is_money` is false so a caller never
 * adds names to zatoshi. Token balances are carried only by the per-token
 * items in vault_snapshot: units from different token IDs are never added. */
struct vault_row {
    enum vault_class    cls;
    const char         *class_name;
    const char         *unit;
    bool                is_money;      /* denominated in zatoshi */

    bool                determined;    /* false => `reason` explains why not */
    char                reason[VAULT_REASON_MAX];

    enum vault_evidence evidence;
    const char         *source_primitive; /* the query that owns the number */

    int64_t             spendable;
    int64_t             pending;
    int64_t             immature;
    int64_t             encumbered;
    int64_t             item_count;    /* rows/notes/UTXOs behind the totals */

    bool                populated;     /* a collector ran and wrote this row */
};

/* The node's own identities, enumerated before any class is asked. Every
 * ownership test in this read model is a match against one of these. */
struct vault_identities {
    int  transparent_keys;   /* wallet_keys */
    int  watch_only;         /* wallet_watch_only */
    int  sapling_keys;       /* wallet_sapling_keys */
    bool truncated;          /* more identities exist than were loaded */
};

struct vault_snapshot {
    struct vault_identities identities;
    struct vault_row        rows[VAULT_CLASS_COUNT];
    struct vault_token_item token_items[VAULT_TOKEN_ITEMS_MAX];
    size_t                  token_item_count;
    bool                    token_items_truncated;

    /* Rollup across the money-denominated classes only. This is the number
     * `getbalance` should have been reporting: transparent + shielded +
     * the HTLC-encumbered coins it silently dropped. */
    int64_t zcl_spendable;
    int64_t zcl_pending;
    int64_t zcl_immature;
    int64_t zcl_encumbered;
    int64_t zcl_total;

    int undetermined_classes; /* rows with determined == false */
};

/* Build the snapshot. Enumerates identities, then runs every collector in
 * the class table.
 *
 * A collector that cannot answer marks its row undetermined and the
 * snapshot still succeeds — that is the honest-gap path, not an error. A
 * collector that fails to write its row at all IS an error: this returns
 * non-ok naming the class, so a class can never drop out of the output
 * unnoticed. Also returns non-ok for a NULL/closed database. */
struct zcl_result vault_read_snapshot(struct node_db *ndb,
                                      struct vault_snapshot *out);

/* Render a snapshot into `out` (set to an object by this call). */
struct zcl_result vault_read_snapshot_to_json(const struct vault_snapshot *snap,
                                              struct json_value *out);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe.
 * key: NULL/empty for every class, or a class name ("swap_encumbered") to
 * emit that one row. */
bool vault_read_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_SERVICES_VAULT_READ_H */
