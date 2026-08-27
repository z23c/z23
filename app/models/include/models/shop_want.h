/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shop WANT ads — the demand-side mirror of the signed offer (slice D of
 * docs/work/SHOP_COMMAND.md: buyer-posted needs).
 *
 * A buyer publishes "I will pay amount_zatoshi for a digital result
 * satisfying these objectively checkable criteria": a signed, discoverable
 * WANT advertisement with terms. It is NOT an escrow, NOT a payment
 * channel, and NOT a matching engine — nothing here moves or promises
 * value; the amount is declared terms inside a self-authenticating
 * document (ZC23/ZCL value transfer stays simulation/plan-only). The
 * signed shape clones zswap_quote.v1 (same Ed25519 + SHA3-256
 * domain-separated root conventions) with the terms reversed, so the
 * stored wire is relay-ready gossip evidence even though this slice adds
 * no wire-protocol message — P2P relay and fulfillment/award are the
 * named follow-ups.
 *
 * Wire layout (exact, little-endian integers, variable-width criteria):
 *   body (108 + criteria_len bytes):
 *     magic             8   {'Z','S','H','P','W','T','\r','\n'}
 *     schema_version    2   == SHOP_WANT_VERSION
 *     buyer_pubkey     32   buyer Ed25519 public key (the signer)
 *     nonce             8   != 0; uniqueness / replay hygiene
 *     amount_zatoshi    8   declared payment terms, > 0
 *     spec_hash        32   SHA3-256 of an external criteria spec document;
 *                           all-zero means none (the criteria text stands
 *                           alone)
 *     criteria_len      2   1..SHOP_WANT_CRITERIA_MAX
 *     criteria          criteria_len bytes of UTF-8 (no NUL bytes — the
 *                           projection stores it as TEXT)
 *     issued_unix       8   > 0
 *     expires_unix      8   > issued_unix, at most
 *                           SHOP_WANT_MAX_LIFETIME_SECS after it
 *   buyer_signature    64   Ed25519 over body_root by buyer_pubkey
 *
 * body_root = SHA3-256("zcl.shop.want.v1" || NUL || body) is the exact
 * statement the buyer signs; the want id commits the full signed wire:
 *   want_id = SHA3-256("zcl.shop.want.root.v1" || NUL || wire).
 *
 * Persistence: the `shop_wants` table (migration v66) is the rebuildable
 * projection of the signed wires — one row per verified ad, keyed by
 * want_id, storing the exact wire the buyer signed plus LOCAL-ONLY
 * columns that never enter the wire: review_state (the per-node community
 * content moderation curation mark, identical semantics to
 * file_offers.review_state from v65 — never gossiped, a hidden want stays
 * stored) and cancelled_unix/posted_unix bookkeeping. Cancellation is
 * local and key-checked (the cancel leaf re-derives the buyer pubkey from
 * the presented secret); a cancelled or expired row is filtered from the
 * open board, never deleted.
 */

#ifndef ZCL_DB_MODEL_SHOP_WANT_H
#define ZCL_DB_MODEL_SHOP_WANT_H

#include "models/database.h"
#include "models/activerecord.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SHOP_WANT_VERSION 1u
#define SHOP_WANT_DOMAIN "zcl.shop.want.v1"
#define SHOP_WANT_ROOT_DOMAIN "zcl.shop.want.root.v1"

/* Criteria are human-readable, objectively checkable terms — bounded so a
 * read leaf stays a read leaf and the board cannot be turned into a file
 * store. */
#define SHOP_WANT_CRITERIA_MAX 1024u
#define SHOP_WANT_BODY_PREFIX_BYTES 92u  /* magic..criteria_len */
#define SHOP_WANT_BODY_SUFFIX_BYTES 16u  /* issued_unix + expires_unix */
#define SHOP_WANT_BODY_MAX_BYTES \
    (SHOP_WANT_BODY_PREFIX_BYTES + SHOP_WANT_CRITERIA_MAX + \
     SHOP_WANT_BODY_SUFFIX_BYTES)
#define SHOP_WANT_WIRE_MAX_BYTES (SHOP_WANT_BODY_MAX_BYTES + 64u)

/* A want is a standing advertisement, not a 60-second live sign: capped
 * structurally at 30 days — a buyer that still wants re-issues with a
 * fresh nonce rather than extending. The 30-day window only means
 * something against a real clock, so issuance must sit within this much
 * of the posting node's wall time (same anchor fulfillment claims use). */
#define SHOP_WANT_MAX_LIFETIME_SECS (30LL * 24LL * 60LL * 60LL)
#define SHOP_WANT_ISSUED_SKEW_SECS 300

/* Rows fetched for one board query (the zswap yardsale cap's equivalent). */
#define SHOP_WANT_QUERY_CAP 64u

enum shop_want_error {
    SHOP_WANT_OK = 0,
    SHOP_WANT_ERR_NULL,
    SHOP_WANT_ERR_VERSION,
    SHOP_WANT_ERR_WIRE_SIZE,
    SHOP_WANT_ERR_WIRE_MAGIC,
    SHOP_WANT_ERR_PUBKEY_ZERO,
    SHOP_WANT_ERR_NONCE,
    SHOP_WANT_ERR_AMOUNT,
    SHOP_WANT_ERR_CRITERIA,
    SHOP_WANT_ERR_TIME_ORDER,
    SHOP_WANT_ERR_LIFETIME,
    SHOP_WANT_ERR_SIGNATURE,
    SHOP_WANT_ERR_KEY_MISMATCH,
};

const char *shop_want_error_string(enum shop_want_error error);

/* The signed document. */
struct shop_want_v1 {
    uint16_t schema_version;
    uint8_t buyer_pubkey[32];
    uint64_t nonce;
    uint64_t amount_zatoshi;
    uint8_t spec_hash[32];            /* all-zero: no external spec */
    uint16_t criteria_len;
    uint8_t criteria[SHOP_WANT_CRITERIA_MAX]; /* NOT NUL-terminated */
    int64_t issued_unix;
    int64_t expires_unix;
    uint8_t buyer_signature[64];
};

/* One persisted row: the verified signed document, its id, and the
 * local-only columns (moderation curation + cancellation bookkeeping). */
struct shop_want {
    struct shop_want_v1 want;
    uint8_t want_id[32];
    int review_state;          /* enum market_review_state — local only */
    int64_t cancelled_unix;    /* 0 = open */
    int64_t posted_unix;       /* this node's first-persist observation */
};

/* ── codec ──────────────────────────────────────────────────────────── */

/* Structural validation (no cryptography — that is shop_want_verify's
 * job): version, non-zero pubkey/nonce/amount, criteria bounds and no NUL
 * bytes, time order within the structural lifetime cap, non-zero
 * signature. */
enum shop_want_error shop_want_validate(const struct shop_want_v1 *want);

/* Exact-length codec: encode writes the canonical wire; decode requires
 * the buffer to end exactly after the signature (a short or trailing wire
 * is WIRE_SIZE) and validates structurally. On any error out is zeroed. */
enum shop_want_error shop_want_encode(const struct shop_want_v1 *want,
                                      uint8_t *out, size_t out_cap,
                                      size_t *out_len);
enum shop_want_error shop_want_decode(const uint8_t *wire, size_t wire_len,
                                      struct shop_want_v1 *out);

/* The 32-byte statement the buyer signs (body only). */
enum shop_want_error shop_want_body_root(const struct shop_want_v1 *want,
                                         uint8_t out[32]);
/* The want's own id: commits the full signed wire. The board dedups on
 * this value. */
enum shop_want_error shop_want_root(const struct shop_want_v1 *want,
                                    uint8_t out[32]);

/* Sign the body root with the buyer key. The buyer public key is
 * re-derived from buyer_secret and must equal want->buyer_pubkey
 * (KEY_MISMATCH otherwise) — a secret that does not produce the claimed
 * pubkey must never seal. Ed25519 signing is deterministic (RFC 8032), so
 * sealing is byte deterministic. */
enum shop_want_error shop_want_seal(struct shop_want_v1 *want,
                                    const uint8_t buyer_secret[32]);

/* Full verification: structural validity plus the Ed25519 signature over
 * the body root under the embedded buyer_pubkey. Time-free on purpose:
 * expiry is board policy (a filter), never evidence invalidation — a want
 * whose window closed is still proof of what the buyer signed. */
enum shop_want_error shop_want_verify(const struct shop_want_v1 *want);

/* ── persistence (the shop_wants projection, migration v66) ─────────── */

struct ar_callbacks *db_shop_want_callbacks(void);
bool db_shop_want_validate(const struct shop_want *row,
                           struct ar_errors *errors);
/* Insert one verified row (the handler verifies BEFORE saving: rows are
 * written only for wires valid at ingress, the "verify evidence valid
 * when created" record). A byte-identical re-post of the same want_id is
 * a no-op (ON CONFLICT DO NOTHING) — idempotent, never a second row. */
bool db_shop_want_save(struct node_db *ndb, const struct shop_want *row);
bool db_shop_want_find(struct node_db *ndb, const uint8_t want_id[32],
                       struct shop_want *out);
/* The board: rows newest-first. include_closed false filters expired
 * (expires_unix <= now_unix) and cancelled rows; true returns everything.
 * Bounded to max (<= SHOP_WANT_QUERY_CAP) results. */
int db_shop_want_list(struct node_db *ndb, int64_t now_unix,
                      bool include_closed, struct shop_want *out, size_t max);
/* Key-checked cancellation is the controller's job; this is the bare
 * mark: sets cancelled_unix on an open row. False when no OPEN row
 * carries the id (absent or already cancelled — the caller distinguishes
 * with db_shop_want_find first). */
bool db_shop_want_mark_cancelled(struct node_db *ndb,
                                 const uint8_t want_id[32],
                                 int64_t cancelled_unix);
/* The node's own curation mark (the zmarket_review_set equivalent for the
 * demand side). state is one of the three canonical review_state strings;
 * false when no row carries the id. */
bool db_shop_want_set_review_state(struct node_db *ndb,
                                   const uint8_t want_id[32],
                                   const char *review_state);

#endif
