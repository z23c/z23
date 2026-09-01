/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * On-chain node directory projection (onion_directory) — the node's answer to
 * "which .onion hostnames has the CHAIN said are nodes, who said so, and at
 * what height?".
 *
 * One row per v3 onion hostname, keyed by the hostname. Folded purely from
 * confirmed ZDIR OP_RETURN outputs (zdir/zdir.h); rebuildable from block
 * history; never consulted by consensus; never authoritative about anything.
 *
 * A ROW IS A HINT ABOUT WHERE TO LOOK, NOT PROOF OF WHO IS THERE
 * (docs/work/NAT_AND_ONION_TRANSPORT.md). This table can only ever ADD
 * candidates to peer discovery, alongside DNS seeds, fixed seeds, addrman and
 * the signed-descriptor source; nothing here can exclude a peer or narrow a
 * source. The worst a poisoned or squatted row can do is waste one connection
 * attempt.
 *
 * Field semantics:
 *   hostname        the v3 onion hostname (exactly 62 chars, ".onion"), the
 *                   primary key — a re-register overwrites in place.
 *   txid            txid of the transaction that carried the record.
 *   height          height of the block that first REGISTERed the hostname —
 *                   the seniority signal (spec §A3), stable across updates.
 *   owner_address   the t-address of the registering tx's first-input P2PKH
 *                   signer, when resolvable. A row with no recorded owner is
 *                   permanently immutable (fail-closed), exactly as
 *                   zid_identities treats an unresolvable signer.
 *                   KNOWN, ACCEPTED, AND NAMED: that fail-closed choice is
 *                   also a free denial of the UPDATE path. Anyone can
 *                   register a hostname they do not operate from a
 *                   non-P2PKH first input; explorer_index_apply_zdir_overlay
 *                   then stores owner_address "", zdir_owner_matches()
 *                   refuses every signer against it, and the true operator
 *                   can never update or deregister that hostname — no key
 *                   recovers it. The cost is bounded by what a row IS: a
 *                   hint, never proof, that can only ever ADD a dial
 *                   candidate. So a squatted row wastes one connection
 *                   attempt and denies its rightful owner a directory
 *                   entry; it cannot exclude that node from any other
 *                   discovery source, and the node stays reachable. The
 *                   fix is a signer rule that resolves more input forms
 *                   (or an explicit unclaimed state), not opening the
 *                   update path to an unproven signer — that would trade a
 *                   denial for a takeover.
 *   master_pubkey   optional ed25519 zid master key the record bound to this
 *                   hostname (has_pubkey is the in-memory presence bit; the
 *                   column is NULL otherwise). NOT verified here — binding a
 *                   key on-chain is a claim; proving it is contexts/wallet/modules/zid's job.
 *   status          "active" | "retired". Only active rows are dialed.
 *   updated_height  height at which this row last changed.
 *
 * Threading contract: every write goes through db_onion_directory_save
 * (AR_ADHOC_SAVE — a locally-prepared statement per call, INSERT OR REPLACE on
 * the primary key), so it is idempotent and safe from any thread. The read
 * helpers prepare their own statements and hold no cached cursor, so they
 * never park a statement on the shared WAL connection.
 */

#ifndef ZCL_DB_MODEL_ONION_DIRECTORY_H
#define ZCL_DB_MODEL_ONION_DIRECTORY_H

#include "models/database.h"
#include "models/activerecord.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* 56 base32 chars + ".onion"; +1 for the terminating NUL. */
#define ONION_DIRECTORY_HOSTNAME_MAX 63
/* Longest address form the node produces is a 78-char Sapling zs1. */
#define ONION_DIRECTORY_ADDRESS_MAX  96
#define ONION_DIRECTORY_STATUS_MAX   16

#define ONION_DIRECTORY_STATUS_ACTIVE  "active"
#define ONION_DIRECTORY_STATUS_RETIRED "retired"

struct db_onion_directory {
    char    hostname[ONION_DIRECTORY_HOSTNAME_MAX];
    uint8_t txid[32];
    int32_t height;
    char    owner_address[ONION_DIRECTORY_ADDRESS_MAX]; /* "" when unknown */
    uint8_t master_pubkey[32];
    bool    has_pubkey;          /* true iff the column is non-NULL */
    char    status[ONION_DIRECTORY_STATUS_MAX];
    int32_t updated_height;
};

struct ar_callbacks *db_onion_directory_callbacks(void);

/* Rejects: a hostname that is not exactly the Tor v3 shape (the SAME rule
 * core/modules/net enforces — onion_hostname_valid), an unknown status literal, a
 * present-but-all-zero master_pubkey, and negative heights. */
bool db_onion_directory_validate(const struct db_onion_directory *r,
                                 struct ar_errors *errors);

/* INSERT OR REPLACE keyed by hostname — idempotent, any thread. */
bool db_onion_directory_save(struct node_db *ndb,
                             const struct db_onion_directory *row);

/* ── Read API ──────────────────────────────────────────────────────
 * `find` returns false when no row matches (a legitimate negative answer, not
 * an error). `out` is only written on a true return. */

bool db_onion_directory_find(struct node_db *ndb, const char *hostname,
                             struct db_onion_directory *out);

/* MOST-SENIOR-FIRST page of ACTIVE rows only — the peer-discovery read,
 * ordered by ascending `height` (the registration height, i.e. the seniority
 * signal documented above) and then hostname. The page is bounded and the
 * callers ask for a slate they intend to dial, so newest-first would let a
 * burst of fresh registrations take every slot and displace every
 * long-standing node — the ordering is the anti-squatting property, not a
 * cosmetic choice. Returns the number of rows written to `out` (<= max).
 * max<=0 or a negative offset yields 0. */
int db_onion_directory_list_active(struct node_db *ndb,
                                   struct db_onion_directory *out,
                                   int max, int offset);

int64_t db_onion_directory_count(struct node_db *ndb);
int64_t db_onion_directory_count_by_status(struct node_db *ndb,
                                           const char *status);

/* Drop every row — the projection is rebuildable from block history. */
bool db_onion_directory_truncate(struct node_db *ndb);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe.
 * key: NULL/"" for totals; a v3 onion hostname to resolve one row. */
struct json_value;
bool onion_directory_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_DB_MODEL_ONION_DIRECTORY_H */
