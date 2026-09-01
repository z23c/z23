/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model for ZID ANCHOR DOMAINS — the durable record of what a
 * domain batch committed (schema v38: zid_domains + zid_domain_leaves).
 *
 * A domain is a named batch of record digests (zcode, zdesc, zdir, a
 * third-party registry, …), each anchoring at its own cadence. Its leaf
 * set is stored in CANONICAL ORDER — leaf_index is the position the
 * digests occupy after sorting by memcmp over the 32 bytes, exactly the
 * order `zcode release anchor` folds them in — so the stored root is
 * reproducible from the stored leaves alone, without re-reading any
 * directory. That is the whole point of this table: a batch proof cannot
 * silently change meaning, because the leaf set that produced the root is
 * on disk next to it.
 *
 * Meaning-change rule (zid_domain_replace_leaves): replacing a domain's
 * leaf set with a set that folds to a DIFFERENT root clears
 * anchored_txid/anchored_height. The domain is then visibly un-anchored
 * until it is anchored again — never a new leaf set silently wearing the
 * old anchor. Replacing with the same root keeps the anchor (the write is
 * a no-op in meaning).
 *
 * Operator-owned, NOT a chain projection: rows are written by the anchor
 * path, are never rebuilt from block history, and are never consulted by
 * consensus. anchored_txid/anchored_height are NULL until the root is
 * committed on-chain.
 *
 * Threading: writes are single-writer by construction (the operator-
 * triggered `zcode release anchor` leaf). Reads are ordinary AR_QUERY_*
 * lookups and safe from any thread holding a usable node_db. */

#ifndef ZCL_DB_MODEL_ZID_DOMAIN_H
#define ZCL_DB_MODEL_ZID_DOMAIN_H

#include "models/database.h"
#include "models/activerecord.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Domain names follow the ZNAM shape: 1..63 chars, lowercase alphanumeric
 * plus hyphens. Leaf labels are free-form printable ASCII (the release
 * path uses "<name>@<version>"). */
#define ZID_DOMAIN_NAME_MAX  63
#define ZID_DOMAIN_LABEL_MAX 127

/* Bound on one atomic leaf-set replacement. Matches the release batch cap
 * in tools/command/native_zcode_release_command.c so a batch that loads
 * always stores. */
#define ZID_DOMAIN_LEAVES_MAX 1024

struct zid_domain {
    char     domain_name[ZID_DOMAIN_NAME_MAX + 1];
    uint8_t  owner_pubkey[32];
    bool     has_owner;          /* false => owner_pubkey stored as NULL */
    int64_t  num_leaves;
    uint8_t  root[32];           /* bagged zid_tree root over the leaves */
    uint8_t  anchored_txid[32];
    bool     anchored;           /* false => txid/height stored as NULL */
    /* Chain height the anchor tx was BROADCAST at — a lower bound for
     * where to look the txid up, not a confirmation depth. The confirmed
     * height lives in the zanc_anchors projection once the tx lands.
     * -1 when not anchored. */
    int64_t  anchored_height;
    int64_t  updated_at;         /* unix seconds of the last leaf write */
};

struct zid_domain_leaf {
    char     domain_name[ZID_DOMAIN_NAME_MAX + 1];
    int64_t  leaf_index;         /* canonical sorted position */
    uint8_t  record_digest[32];
    char     label[ZID_DOMAIN_LABEL_MAX + 1];
};

struct json_value; /* fwd — json/json.h */

/* ── AR lifecycle ──────────────────────────────────────────────────── */

struct ar_callbacks *db_zid_domain_callbacks(void);
struct ar_callbacks *db_zid_domain_leaf_callbacks(void);

bool db_zid_domain_validate(const struct zid_domain *d,
                            struct ar_errors *errors);
bool db_zid_domain_leaf_validate(const struct zid_domain_leaf *l,
                                 struct ar_errors *errors);

/* Upsert one domain row (INSERT OR REPLACE on domain_name). Writes the
 * row exactly as given — callers that are changing the leaf set should use
 * zid_domain_replace_leaves instead, which enforces the meaning-change
 * rule above. */
bool db_zid_domain_save(struct node_db *ndb, const struct zid_domain *d);

/* Upsert one leaf row (INSERT OR REPLACE on (domain_name, leaf_index)). */
bool db_zid_domain_leaf_save(struct node_db *ndb,
                             const struct zid_domain_leaf *l);

/* ── Domain operations ─────────────────────────────────────────────── */

/* Atomically replace a domain's entire leaf set and record the root it
 * folds to: one transaction covering DELETE-all-leaves + INSERT n leaves +
 * the domain upsert, rolled back whole on any failure (a half-written leaf
 * set would be a root nobody can reproduce). `leaves` must already be in
 * canonical order with leaf_index == its array position. `owner_pubkey`
 * may be NULL (stored NULL, or the existing owner preserved when the row
 * already carries one). An n==0 replacement is legal: the domain becomes
 * an empty batch with the all-zero root. Clears the anchor when the root
 * changes — see the meaning-change rule in the file header. */
bool zid_domain_replace_leaves(struct node_db *ndb, const char *domain_name,
                               const struct zid_domain_leaf *leaves, size_t n,
                               const uint8_t root[32],
                               const uint8_t *owner_pubkey, int64_t updated_at);

/* Record the on-chain anchor for a domain that already exists. Fails when
 * the domain is unknown (there is no root to bind the txid to). */
bool zid_domain_set_anchor(struct node_db *ndb, const char *domain_name,
                           const uint8_t txid[32], int64_t height);

/* ── Reads ─────────────────────────────────────────────────────────── */

/* Returns false when the domain does not exist (a normal lookup miss). */
bool zid_domain_get(struct node_db *ndb, const char *domain_name,
                    struct zid_domain *out);

/* All domains, name-ordered. Returns the row count written to out. */
int zid_domain_list(struct node_db *ndb, struct zid_domain *out, size_t max);

/* One domain's leaves in canonical (leaf_index ASC) order — exactly the
 * order they must be folded in to reproduce the stored root. Returns the
 * row count written to out. */
int zid_domain_leaves(struct node_db *ndb, const char *domain_name,
                      struct zid_domain_leaf *out, size_t max);

/* "prove this digest": indexed lookup of a digest's canonical leaf index
 * within one domain. Returns false when the digest is not a leaf of that
 * domain. */
bool zid_domain_leaf_index_by_digest(struct node_db *ndb,
                                     const char *domain_name,
                                     const uint8_t record_digest[32],
                                     int64_t *index_out);

int64_t zid_domain_count(struct node_db *ndb);
int64_t zid_domain_leaf_count(struct node_db *ndb, const char *domain_name);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe.
 * key = NULL/empty for the domain roster, or a domain name for one
 * domain's root/leaf-count/anchor detail. */
bool zid_domain_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_DB_MODEL_ZID_DOMAIN_H */
