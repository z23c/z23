/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* The vault read model. See services/vault_read.h for the contract and the
 * two rules that shape it (no new balance mathematics, no silent
 * omissions).
 *
 * Layout: identity enumeration first, then one collector per asset class,
 * then the table that binds a class to its collector. The table is the only
 * place a class list appears in this file; a class with no collector is a
 * compile error and a collector that returns without writing its row is a
 * snapshot error. Neither can produce a quietly-missing line of output. */

#include "services/vault_read.h"

#include "chain/chainparams.h"
#include "config/runtime.h"
#include "json/json.h"
#include "keys/key_io.h"
#include "models/activerecord.h"
#include "models/database.h"
#include "models/file_offer.h"
#include "models/swap_contract.h"
#include "models/wallet_key.h"
#include "models/wallet_tx.h"
#include "models/znam.h"
#include "models/zslp_ledger.h"
#include "net/file_market.h"
#include "script/htlc.h"
#include "script/standard.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* Bounds. Every list primitive below takes a LIMIT, so a node holding more
 * than one of these caps would silently report a partial total — which is
 * the bug this file exists to kill. Saturation is therefore detected and
 * turned into an undetermined row, never into a smaller number. */
#define VAULT_MAX_T_IDENT   512
#define VAULT_MAX_Z_IDENT   256
#define VAULT_MAX_SWAPS     512
#define VAULT_MAX_OFFERS    FILE_MARKET_MAX_OFFERS
#define VAULT_MAX_NAMES     256
#define VAULT_MAX_TOKENS    256

/* A raw Sapling payment address is diversifier(11) || pk_d(32); that is
 * exactly the 43 bytes file_offers.z_addr stores. */
#define VAULT_Z_RAW_LEN     43

/* The node's own identities, loaded once and handed to every collector. */
struct vault_ident {
    char    t_addr[VAULT_MAX_T_IDENT][64];   /* base58 P2PKH, for TEXT joins */
    uint8_t t_hash[VAULT_MAX_T_IDENT][20];   /* hash160, for BLOB joins */
    int     n_t;

    uint8_t z_raw[VAULT_MAX_Z_IDENT][VAULT_Z_RAW_LEN];
    int     n_z;

    bool    truncated;      /* a cap was hit; matches may be incomplete */
    bool    codec_ok;       /* base58 encoding of our own hashes worked */
};

/* ── row helpers ──────────────────────────────────────────────────── */

static void row_begin(struct vault_row *row, enum vault_class cls)
{
    memset(row, 0, sizeof(*row));
    row->cls        = cls;
    row->class_name = vault_class_name(cls);
    row->unit       = vault_class_unit(cls);
    row->is_money   = (strcmp(row->unit, "zatoshi") == 0);
    row->evidence   = VAULT_EVIDENCE_UNKNOWN;
}

/* Mark the row answered: the named primitive produced its numbers. */
static void row_determined(struct vault_row *row, enum vault_evidence ev,
                           const char *source_primitive)
{
    row->determined       = true;
    row->evidence         = ev;
    row->source_primitive = source_primitive;
    row->populated        = true;
}

/* Mark the row an honest gap. The amounts stay zero and `reason` says why a
 * reader must not read that zero as "owns nothing". */
static void row_undetermined(struct vault_row *row, const char *fmt, ...)
{
    va_list ap;

    row->determined = false;
    row->spendable = row->pending = row->immature = row->encumbered = 0;
    row->populated  = true;

    va_start(ap, fmt);
    (void)vsnprintf(row->reason, sizeof(row->reason), fmt, ap);
    va_end(ap);
}

/* A note attached to a row that IS determined — a caveat, not a failure. */
static void row_note(struct vault_row *row, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    (void)vsnprintf(row->reason, sizeof(row->reason), fmt, ap);
    va_end(ap);
}

/* ── identity enumeration ─────────────────────────────────────────── */

/* Prepare an enumeration query. These SELECTs list identities and keys —
 * they never compute a balance, so nothing here duplicates a primitive.
 * Rows are stepped through AR_STEP_ROW as the AR contract requires. */
static bool vault_prepare(struct node_db *ndb, sqlite3_stmt **s,
                          const char *sql)
{
    if (sqlite3_prepare_v2(ndb->db, sql, -1, s, NULL) != SQLITE_OK || !*s) {
        *s = NULL;
        LOG_FAIL("vault", "prepare failed: %s (%s)",
                 sqlite3_errmsg(ndb->db), sql);
    }
    return true;
}

static void ident_add_transparent(const struct db_wallet_key *key, void *ctx)
{
    struct vault_ident *ids = ctx;
    struct tx_destination dest;
    const struct chain_params *cp;
    const unsigned char *pk_pfx, *sc_pfx;
    size_t pk_len = 0, sc_len = 0;

    if (ids->n_t >= VAULT_MAX_T_IDENT) {
        ids->truncated = true;
        return;
    }

    memcpy(ids->t_hash[ids->n_t], key->pubkey_hash, 20);

    cp     = chain_params_get();
    pk_pfx = cp ? chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_len) : NULL;
    sc_pfx = cp ? chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sc_len) : NULL;

    memset(&dest, 0, sizeof(dest));
    dest.type = DEST_KEY_ID;
    memcpy(dest.id.key.id.data, key->pubkey_hash, 20);

    if (pk_pfx && encode_destination(&dest, pk_pfx, pk_len, sc_pfx, sc_len,
                                     ids->t_addr[ids->n_t],
                                     sizeof(ids->t_addr[0])))
        ids->codec_ok = true;
    else
        ids->t_addr[ids->n_t][0] = '\0';

    ids->n_t++;
}

/* Watch-only addresses are already stored as text — the node cannot spend
 * them but it does own the claim, and ZNAM registrations are routinely held
 * on a watched address. */
static void ident_load_watch_only(struct node_db *ndb, struct vault_ident *ids)
{
    sqlite3_stmt *s = NULL;

    if (!vault_prepare(ndb, &s, "SELECT address,address_hash"
                                " FROM wallet_watch_only")) {
        ids->truncated = true;   /* identity set is knowingly incomplete */
        return;
    }
    while (AR_STEP_ROW(s)) {
        if (ids->n_t >= VAULT_MAX_T_IDENT) {
            ids->truncated = true;
            break;
        }
        AR_READ_STR(s, 0, ids->t_addr[ids->n_t], sizeof(ids->t_addr[0]));
        const void *h = sqlite3_column_blob(s, 1);
        if (h && sqlite3_column_bytes(s, 1) == 20)
            memcpy(ids->t_hash[ids->n_t], h, 20);
        if (ids->t_addr[ids->n_t][0] != '\0') {
            ids->codec_ok = true;
            ids->n_t++;
        }
    }
    AR_FINALIZE(s);
}

static void ident_load_sapling(struct node_db *ndb, struct vault_ident *ids)
{
    sqlite3_stmt *s = NULL;

    if (!vault_prepare(ndb, &s, "SELECT diversifier,pk_d"
                                " FROM wallet_sapling_keys")) {
        ids->truncated = true;
        return;
    }
    while (AR_STEP_ROW(s)) {
        if (ids->n_z >= VAULT_MAX_Z_IDENT) {
            ids->truncated = true;
            break;
        }
        const void *d = sqlite3_column_blob(s, 0);
        const void *p = sqlite3_column_blob(s, 1);
        if (!d || !p || sqlite3_column_bytes(s, 0) != 11 ||
            sqlite3_column_bytes(s, 1) != 32)
            continue;
        memcpy(ids->z_raw[ids->n_z], d, 11);
        memcpy(ids->z_raw[ids->n_z] + 11, p, 32);
        ids->n_z++;
    }
    AR_FINALIZE(s);
}

static bool ident_owns_t_addr(const struct vault_ident *ids, const char *addr)
{
    if (!addr || addr[0] == '\0')
        return false;
    for (int i = 0; i < ids->n_t; i++)
        if (strcmp(ids->t_addr[i], addr) == 0)
            return true;
    return false;
}

static bool ident_owns_z_raw(const struct vault_ident *ids,
                             const uint8_t z[VAULT_Z_RAW_LEN])
{
    for (int i = 0; i < ids->n_z; i++)
        if (memcmp(ids->z_raw[i], z, VAULT_Z_RAW_LEN) == 0)
            return true;
    return false;
}

/* ── class collectors ─────────────────────────────────────────────── */

/* Transparent ZCL. Two existing primitives, subtracted: the raw unspent sum
 * and the maturity-filtered sum the coin selector and getbalance both use.
 * The difference is immature coinbase — owned, but not spendable yet. */
static void collect_transparent(struct node_db *ndb,
                                const struct vault_ident *ids,
                                struct vault_row *row)
{
    int utxo_count = 0;
    int64_t total, spendable;

    (void)ids;
    total     = db_wallet_utxo_balance_with_count(ndb, &utxo_count);
    spendable = db_wallet_utxo_spendable_balance(ndb, NULL);

    row->spendable  = spendable;
    row->immature   = total > spendable ? total - spendable : 0;
    row->item_count = utxo_count;
    row_determined(row, VAULT_EVIDENCE_EXACT_WALLET_UTXO_SUM,
                   "db_wallet_utxo_spendable_balance + "
                   "db_wallet_utxo_balance_with_count");
    row_note(row, "immature = raw unspent sum minus the maturity-filtered "
                  "sum getbalance reports");
}

/* Shielded ZCL. wallet_sapling_notes rows exist only for notes this node
 * decrypted with its own incoming viewing key, so membership is ownership. */
static void collect_shielded(struct node_db *ndb,
                             const struct vault_ident *ids,
                             struct vault_row *row)
{
    int note_count = 0;

    (void)ids;
    row->spendable  = db_sapling_note_balance_with_count(ndb, &note_count);
    row->item_count = note_count;
    row_determined(row, VAULT_EVIDENCE_EXACT_NOTE_SUM,
                   "db_sapling_note_balance_with_count");
    row_note(row, "a row exists only for a note this node decrypted with its "
                  "own viewing key");
}

/* ZSLP tokens. zslp_ledger is the debit-correct per-(token,outpoint)
 * projection; zslp_ledger_balance owns the arithmetic. This function only
 * enumerates which (token, our-address) pairs exist and adds up what that
 * primitive returns for each.
 *
 * The projection is built by a backfill service, so an empty ledger is
 * ambiguous: it means either "holds no tokens" or "the backfill has not
 * run". The cursor distinguishes them, and a cursor still at -1 makes this
 * row undetermined rather than a confident zero. */
static void collect_tokens(struct node_db *ndb, const struct vault_ident *ids,
                           struct vault_row *row)
{
    int32_t cursor = -1;
    uint8_t digest[32];
    int64_t total = 0, pairs = 0;
    bool saturated = false;

    memset(digest, 0, sizeof(digest));
    if (!zslp_ledger_get_cursor(ndb, &cursor, digest)) {
        row_undetermined(row, "zslp_ledger cursor unreadable: the token "
                              "projection cannot be trusted to be complete");
        return;
    }
    if (cursor < 0) {
        row_undetermined(row, "zslp_ledger backfill has folded no height "
                              "(cursor=-1); a zero here would report an "
                              "unbuilt projection as an empty wallet");
        return;
    }
    if (ids->n_t == 0) {
        row_determined(row, VAULT_EVIDENCE_EXACT_LEDGER_UNSPENT,
                       "zslp_ledger_balance");
        row_note(row, "no transparent identity to hold tokens against "
                      "(cursor h=%d)", (int)cursor);
        return;
    }

    for (int i = 0; i < ids->n_t && !saturated; i++) {
        uint8_t tokens[VAULT_MAX_TOKENS][32];
        int n_tokens = 0;
        sqlite3_stmt *s = NULL;

        /* Enumeration only — which tokens does this address hold unspent
         * rows for. Not a balance: every amount below comes back from
         * zslp_ledger_balance. */
        if (!vault_prepare(ndb, &s,
                "SELECT DISTINCT token_id FROM zslp_ledger"
                " WHERE address=? AND spent_by_txid IS NULL LIMIT ?")) {
            row_undetermined(row, "zslp_ledger token enumeration failed for "
                                  "identity %d of %d", i + 1, ids->n_t);
            return;
        }
        AR_BIND_BLOB(s, 1, ids->t_hash[i], 20);
        AR_BIND_INT(s, 2, VAULT_MAX_TOKENS);
        while (AR_STEP_ROW(s)) {
            const void *t = sqlite3_column_blob(s, 0);
            if (!t || sqlite3_column_bytes(s, 0) != 32)
                continue;
            if (n_tokens >= VAULT_MAX_TOKENS) {
                saturated = true;
                break;
            }
            memcpy(tokens[n_tokens++], t, 32);
        }
        AR_FINALIZE(s);
        if (n_tokens >= VAULT_MAX_TOKENS)
            saturated = true;

        for (int t = 0; t < n_tokens; t++) {
            total += zslp_ledger_balance(ndb, tokens[t], ids->t_hash[i]);
            pairs++;
        }
    }

    if (saturated) {
        row_undetermined(row, "more than %d distinct tokens on one address: "
                              "the total would be partial",
                         VAULT_MAX_TOKENS);
        return;
    }

    row->spendable  = total;
    row->item_count = pairs;
    row_determined(row, VAULT_EVIDENCE_EXACT_LEDGER_UNSPENT,
                   "zslp_ledger_balance");
    row_note(row, "sum over %lld (token,address) pairs; projection folded "
                  "through h=%d", (long long)pairs, (int)cursor);
}

/* ZNAM names. znam_names.owner_address is a direct ownership column, so a
 * string match against our own addresses is exact. Registration terms
 * (expiry_height) are recorded but not enforced by resolution today, so
 * every owned name counts as held. */
static void collect_names(struct node_db *ndb, const struct vault_ident *ids,
                          struct vault_row *row)
{
    struct znam_entry *entries;
    int64_t held = 0;
    bool saturated = false;

    if (ids->n_t == 0) {
        row_determined(row, VAULT_EVIDENCE_EXACT_OWNER_ADDRESS_MATCH,
                       "db_znam_list_by_owner");
        row_note(row, "no transparent identity, so no address can own a name");
        return;
    }
    if (!ids->codec_ok) {
        row_undetermined(row, "could not render this node's own addresses as "
                              "text, so znam_names.owner_address cannot be "
                              "matched");
        return;
    }

    entries = zcl_calloc(VAULT_MAX_NAMES, sizeof(*entries), "vault_znam");
    if (!entries) {
        row_undetermined(row, "allocation for %d znam rows failed",
                         VAULT_MAX_NAMES);
        return;
    }

    for (int i = 0; i < ids->n_t; i++) {
        int n;
        if (ids->t_addr[i][0] == '\0')
            continue;
        n = db_znam_list_by_owner(ndb, ids->t_addr[i], entries,
                                  VAULT_MAX_NAMES);
        if (n >= VAULT_MAX_NAMES)
            saturated = true;
        held += n;
    }
    free(entries);

    if (saturated) {
        row_undetermined(row, "one address owns %d or more names: the count "
                              "would be partial", VAULT_MAX_NAMES);
        return;
    }

    row->spendable  = held;
    row->item_count = held;
    row_determined(row, VAULT_EVIDENCE_EXACT_OWNER_ADDRESS_MATCH,
                   "db_znam_list_by_owner");
    row_note(row, "owner_address matched against %d identities; registration "
                  "expiry is recorded but not enforced by resolution",
             ids->n_t);
}

/* Swap-encumbered ZCL — the class that had no aggregate at all.
 *
 * Every row in zswp_contracts was written by this node's own swap_initiate
 * / swap_participate / swap_redeem / swap_refund handlers; nothing ingests
 * contracts from the network. Membership plus state is therefore exact
 * ownership evidence, which is why the grade is exact_contract_state and
 * not an address heuristic.
 *
 * FUNDED and EXPIRED contracts are encumbered: coins sit at the P2SH
 * address and are recoverable by redeem-with-secret or, past locktime, by
 * refund. PENDING is pending — the contract exists but nothing is funded
 * yet. REDEEMED and REFUNDED are settled and counted nowhere; the coins
 * have already landed back in wallet_utxos and counting them here would
 * double-count them against the transparent row.
 *
 * Only ZCL-chain contracts enter the zatoshi columns. A BTC/LTC/DOGE
 * contract's amount is denominated in that chain's satoshi and adding it to
 * a ZCL total would be a unit error, so those are counted separately and
 * named in the row's note. */
static void collect_swaps(struct node_db *ndb, const struct vault_ident *ids,
                          struct vault_row *row)
{
    struct swap_contract *swaps;
    int n, foreign = 0, unmatched = 0;
    int64_t encumbered = 0, pending = 0, live = 0;

    swaps = zcl_calloc(VAULT_MAX_SWAPS, sizeof(*swaps), "vault_swaps");
    if (!swaps) {
        row_undetermined(row, "allocation for %d swap contracts failed",
                         VAULT_MAX_SWAPS);
        return;
    }

    n = db_swap_list(ndb, swaps, VAULT_MAX_SWAPS, -1);
    if (n >= VAULT_MAX_SWAPS) {
        free(swaps);
        row_undetermined(row, "%d or more swap contracts: the encumbered "
                              "total would be partial", VAULT_MAX_SWAPS);
        return;
    }

    for (int i = 0; i < n; i++) {
        const struct swap_contract *sc = &swaps[i];

        if (sc->state == SWAP_REDEEMED || sc->state == SWAP_REFUNDED)
            continue;
        if (ids->codec_ok && !ident_owns_t_addr(ids, sc->my_address))
            unmatched++;
        if (sc->chain != SWAP_CHAIN_ZCL) {
            foreign++;
            continue;
        }
        live++;
        if (sc->state == SWAP_PENDING)
            pending += sc->amount;
        else
            encumbered += sc->amount;   /* FUNDED or EXPIRED */
    }
    free(swaps);

    row->encumbered = encumbered;
    row->pending    = pending;
    row->item_count = live;
    row_determined(row, VAULT_EVIDENCE_EXACT_CONTRACT_STATE, "db_swap_list");
    row_note(row, "%lld live ZCL HTLC(s) of %d rows; %d on other chains "
                  "(different unit, excluded); %d my_address not in the "
                  "local identity set",
             (long long)live, n, foreign, unmatched);
}

/* File-market offers — the honest heuristic.
 *
 * file_offers has no ownership column. It is a gossip cache: rows arrive
 * from peers with a TTL and a seeder IP, and the only field that could
 * point back at us is z_addr, the Sapling address a buyer should pay. An
 * offer carrying one of our z-addresses most likely means this node is the
 * seeder — but any peer can gossip a row naming our address, so the match
 * is evidence, not proof. Hence heuristic_payment_address_match.
 *
 * With no Sapling key there is nothing to match against and the row is
 * undetermined rather than zero. */
static void collect_market(struct node_db *ndb, const struct vault_ident *ids,
                           struct vault_row *row)
{
    struct file_offer *offers;
    int n;
    int64_t mine = 0;

    if (ids->n_z == 0) {
        row_undetermined(row, "file_offers has no ownership column and this "
                              "node has no Sapling key to match z_addr "
                              "against");
        return;
    }

    offers = zcl_calloc(VAULT_MAX_OFFERS, sizeof(*offers), "vault_offers");
    if (!offers) {
        row_undetermined(row, "allocation for %d file offers failed",
                         VAULT_MAX_OFFERS);
        return;
    }

    n = db_file_offer_list(ndb, offers, VAULT_MAX_OFFERS);
    if (n >= VAULT_MAX_OFFERS) {
        free(offers);
        row_undetermined(row, "offer cache saturated at %d rows: a count "
                              "would be partial", VAULT_MAX_OFFERS);
        return;
    }

    for (int i = 0; i < n; i++)
        if (ident_owns_z_raw(ids, offers[i].z_addr))
            mine++;
    free(offers);

    row->spendable  = mine;
    row->item_count = mine;
    row_determined(row, VAULT_EVIDENCE_HEURISTIC_PAYMENT_ADDRESS_MATCH,
                   "db_file_offer_list");
    row_note(row, "%lld of %d gossiped offers name one of our %d z-addresses "
                  "as payee; any peer can gossip such a row, so this is "
                  "evidence of seeding, not proof of ownership",
             (long long)mine, n, ids->n_z);
}

/* ── the class table ──────────────────────────────────────────────── */

typedef void (*vault_collect_fn)(struct node_db *ndb,
                                 const struct vault_ident *ids,
                                 struct vault_row *row);

static const struct vault_collector {
    enum vault_class cls;
    vault_collect_fn fn;
} g_collectors[] = {
    { VAULT_CLASS_TRANSPARENT, collect_transparent },
    { VAULT_CLASS_SHIELDED,    collect_shielded    },
    { VAULT_CLASS_TOKEN,       collect_tokens      },
    { VAULT_CLASS_NAME,        collect_names       },
    { VAULT_CLASS_SWAP,        collect_swaps       },
    { VAULT_CLASS_MARKET,      collect_market      },
};

static_assert(sizeof(g_collectors) / sizeof(g_collectors[0]) ==
                  VAULT_CLASS_COUNT,
              "every class in VAULT_CLASS_TABLE needs a collector: dropping "
              "one must not silently drop a line of vault output");

/* ── names ────────────────────────────────────────────────────────── */

const char *vault_class_name(enum vault_class cls)
{
    switch (cls) {
#define VAULT_CLASS_NAME_CASE(id_, name_, unit_) \
    case VAULT_CLASS_##id_: return name_;
    VAULT_CLASS_TABLE(VAULT_CLASS_NAME_CASE)
#undef VAULT_CLASS_NAME_CASE
    case VAULT_CLASS_COUNT: break;
    }
    return "unknown";
}

const char *vault_class_unit(enum vault_class cls)
{
    switch (cls) {
#define VAULT_CLASS_UNIT_CASE(id_, name_, unit_) \
    case VAULT_CLASS_##id_: return unit_;
    VAULT_CLASS_TABLE(VAULT_CLASS_UNIT_CASE)
#undef VAULT_CLASS_UNIT_CASE
    case VAULT_CLASS_COUNT: break;
    }
    return "unknown";
}

const char *vault_evidence_name(enum vault_evidence evidence)
{
    switch (evidence) {
    case VAULT_EVIDENCE_EXACT_WALLET_UTXO_SUM:     return "exact_wallet_utxo_sum";
    case VAULT_EVIDENCE_EXACT_NOTE_SUM:            return "exact_note_sum";
    case VAULT_EVIDENCE_EXACT_LEDGER_UNSPENT:      return "exact_ledger_unspent";
    case VAULT_EVIDENCE_EXACT_OWNER_ADDRESS_MATCH: return "exact_owner_address_match";
    case VAULT_EVIDENCE_EXACT_CONTRACT_STATE:      return "exact_contract_state";
    case VAULT_EVIDENCE_HEURISTIC_PAYMENT_ADDRESS_MATCH:
        return "heuristic_payment_address_match";
    case VAULT_EVIDENCE_UNKNOWN: break;
    }
    return "unknown";
}

/* ── snapshot ─────────────────────────────────────────────────────── */

struct zcl_result vault_read_snapshot(struct node_db *ndb,
                                      struct vault_snapshot *out)
{
    struct vault_ident *ids;

    if (!out)
        return ZCL_ERR(-1, "vault_read_snapshot: NULL out");
    memset(out, 0, sizeof(*out));
    if (!ndb || !ndb->open)
        return ZCL_ERR(-2, "vault_read_snapshot: node_db %s",
                       ndb ? "not open" : "is NULL");

    ids = zcl_calloc(1, sizeof(*ids), "vault_identities");
    if (!ids)
        return ZCL_ERR(-3, "vault_read_snapshot: identity set allocation "
                           "of %zu bytes failed", sizeof(*ids));

    out->identities.transparent_keys = db_wallet_key_each(
        ndb, ident_add_transparent, ids);
    ident_load_watch_only(ndb, ids);
    out->identities.watch_only =
        ids->n_t - out->identities.transparent_keys;
    ident_load_sapling(ndb, ids);
    out->identities.sapling_keys = ids->n_z;
    out->identities.truncated    = ids->truncated;

    for (size_t i = 0; i < VAULT_CLASS_COUNT; i++) {
        const struct vault_collector *c = &g_collectors[i];
        if ((unsigned)c->cls >= VAULT_CLASS_COUNT) {
            free(ids);
            return ZCL_ERR(-4, "vault collector class is out of range");
        }
        struct vault_row *row = &out->rows[c->cls];

        row_begin(row, c->cls);
        c->fn(ndb, ids, row);
    }
    free(ids);

    /* A collector that returned without writing its row would otherwise
     * emit a silent, all-zero line. Refuse the whole snapshot instead. */
    for (size_t i = 0; i < VAULT_CLASS_COUNT; i++) {
        if (!out->rows[i].populated)
            return ZCL_ERR(-4, "vault_read_snapshot: class '%s' produced no "
                               "row — a class may not drop out of the vault "
                               "silently", vault_class_name((enum vault_class)i));
        if (!out->rows[i].determined)
            out->undetermined_classes++;
        if (!out->rows[i].is_money)
            continue;
        out->zcl_spendable  += out->rows[i].spendable;
        out->zcl_pending    += out->rows[i].pending;
        out->zcl_immature   += out->rows[i].immature;
        out->zcl_encumbered += out->rows[i].encumbered;
    }
    out->zcl_total = out->zcl_spendable + out->zcl_pending +
                     out->zcl_immature + out->zcl_encumbered;
    return ZCL_OK;
}

/* ── json ─────────────────────────────────────────────────────────── */

static void row_to_json(const struct vault_row *row, struct json_value *obj)
{
    json_set_object(obj);
    (void)json_push_kv_str(obj, "class", row->class_name);
    (void)json_push_kv_str(obj, "unit", row->unit);
    (void)json_push_kv_bool(obj, "is_money", row->is_money);
    (void)json_push_kv_bool(obj, "determined", row->determined);
    (void)json_push_kv_str(obj, "evidence", vault_evidence_name(row->evidence));
    (void)json_push_kv_str(obj, "source_primitive",
                           row->source_primitive ? row->source_primitive : "");
    (void)json_push_kv_int(obj, "spendable", row->spendable);
    (void)json_push_kv_int(obj, "pending", row->pending);
    (void)json_push_kv_int(obj, "immature", row->immature);
    (void)json_push_kv_int(obj, "encumbered", row->encumbered);
    (void)json_push_kv_int(obj, "item_count", row->item_count);
    (void)json_push_kv_str(obj, row->determined ? "note" : "reason",
                           row->reason);
}

struct zcl_result vault_read_snapshot_to_json(const struct vault_snapshot *snap,
                                              struct json_value *out)
{
    struct json_value classes, identities, totals;

    if (!snap || !out)
        return ZCL_ERR(-1, "vault_read_snapshot_to_json: NULL %s",
                       snap ? "out" : "snapshot");
    json_set_object(out);

    json_init(&identities);
    json_set_object(&identities);
    (void)json_push_kv_int(&identities, "transparent_keys",
                           snap->identities.transparent_keys);
    (void)json_push_kv_int(&identities, "watch_only",
                           snap->identities.watch_only);
    (void)json_push_kv_int(&identities, "sapling_keys",
                           snap->identities.sapling_keys);
    (void)json_push_kv_bool(&identities, "truncated",
                            snap->identities.truncated);
    (void)json_push_kv(out, "identities", &identities);
    json_free(&identities);

    json_init(&classes);
    json_set_array(&classes);
    for (size_t i = 0; i < VAULT_CLASS_COUNT; i++) {
        struct json_value row;
        json_init(&row);
        row_to_json(&snap->rows[i], &row);
        (void)json_push_back(&classes, &row);
        json_free(&row);
    }
    (void)json_push_kv(out, "classes", &classes);
    json_free(&classes);

    json_init(&totals);
    json_set_object(&totals);
    (void)json_push_kv_int(&totals, "spendable", snap->zcl_spendable);
    (void)json_push_kv_int(&totals, "pending", snap->zcl_pending);
    (void)json_push_kv_int(&totals, "immature", snap->zcl_immature);
    (void)json_push_kv_int(&totals, "encumbered", snap->zcl_encumbered);
    (void)json_push_kv_int(&totals, "total", snap->zcl_total);
    (void)json_push_kv_str(&totals, "unit", "zatoshi");
    (void)json_push_kv(out, "zcl", &totals);
    json_free(&totals);

    (void)json_push_kv_int(out, "class_count", VAULT_CLASS_COUNT);
    (void)json_push_kv_int(out, "undetermined_classes",
                           snap->undetermined_classes);
    return ZCL_OK;
}

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
bool vault_read_dump_state_json(struct json_value *out, const char *key)
{
    struct vault_snapshot snap;
    struct zcl_result r;

    if (!out)
        return false;
    json_set_object(out);

    r = vault_read_snapshot(app_runtime_node_db(), &snap);
    if (!r.ok) {
        (void)json_push_kv_bool(out, "available", false);
        (void)json_push_kv_str(out, "error", r.message);
        return true;
    }

    r = vault_read_snapshot_to_json(&snap, out);
    if (!r.ok) {
        (void)json_push_kv_bool(out, "available", false);
        (void)json_push_kv_str(out, "error", r.message);
        return true;
    }

    if (key && *key) {
        /* Narrow to one class, but never by dropping the others from a
         * list — emit the requested row under its own name so an absent
         * class reads as "no such class", not as "owns nothing". */
        bool found = false;
        for (size_t i = 0; i < VAULT_CLASS_COUNT; i++) {
            struct json_value row;
            if (strcmp(snap.rows[i].class_name, key) != 0)
                continue;
            json_init(&row);
            row_to_json(&snap.rows[i], &row);
            (void)json_push_kv(out, "selected", &row);
            json_free(&row);
            found = true;
            break;
        }
        if (!found)
            (void)json_push_kv_str(out, "selected_error",
                                   "no such vault class");
    }
    return true;
}
