/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model for the ZCL Anchors (ZANC) projection table.
 *
 * One rebuildable table, `zanc_anchors`, projected from confirmed ZANC
 * OP_RETURN outputs by the explorer index (contexts/explorer/models/src/explorer_index.c).
 * The table is a projection of chain history — never authoritative — so it
 * carries no ownership or mutation state: an anchor row is (txid, height,
 * hash_type, digest, label) and is immutable once its tx confirms. The
 * validator is the last checkpoint before a row reaches at-rest storage. */

#ifndef ZCL_DB_MODEL_ZANC_H
#define ZCL_DB_MODEL_ZANC_H

#include "models/database.h"
#include "models/activerecord.h"
#include "zanc/zanc.h"
#include <stdbool.h>

struct zanc_anchor {
    uint8_t txid[32];
    int32_t height;
    uint8_t hash_type;                  /* ZANC_HASH_* */
    uint8_t digest[ZANC_DIGEST_LEN];
    char label[ZANC_LABEL_MAX + 1];
};

struct ar_callbacks *db_zanc_callbacks(void);

bool db_zanc_validate(const struct zanc_anchor *a, struct ar_errors *errors);

bool db_zanc_save(struct node_db *ndb, const struct zanc_anchor *a);

/* Earliest anchor (lowest height, then lexicographically lowest txid) for a
 * given hash_type + digest — the canonical "first committed at" record.
 * Returns true and fills *out on a hit. */
bool db_zanc_find_by_digest(struct node_db *ndb, uint8_t hash_type,
                            const uint8_t digest[ZANC_DIGEST_LEN],
                            struct zanc_anchor *out);

/* Most recent anchors, newest height first. Returns the row count. */
int db_zanc_list(struct node_db *ndb, struct zanc_anchor *out, size_t max);

/* Anchors whose label STARTS WITH `prefix`, newest height first (then txid
 * ascending, so the order is total and stable), with `offset` rows skipped.
 * Returns the count written to `out` (<= max); a short return means the page
 * is the last one.
 *
 * Why this exists: db_zanc_list returns the newest `max` anchors of ANY
 * label. A caller looking for one labeled family (the epoch anchors,
 * "zepoch@<H>") that reads a fixed window of the global list gets a SILENT
 * WRONG ANSWER the moment `max` unrelated anchors are newer than the one it
 * wants — it reports "not anchored" for an anchor that is on-chain. Filtering
 * in SQL and paging removes the window entirely.
 *
 * `prefix` matches with substr(label,1,len)=prefix — a literal byte compare,
 * NOT LIKE, so there are no wildcard characters to escape. An empty/NULL
 * prefix matches every row. */
int db_zanc_list_by_label_prefix(struct node_db *ndb, const char *prefix,
                                 struct zanc_anchor *out, size_t max,
                                 size_t offset);

#endif /* ZCL_DB_MODEL_ZANC_H */
