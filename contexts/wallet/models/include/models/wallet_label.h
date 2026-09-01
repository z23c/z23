/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet address label / address-book model. One row per labeled address
 * (address is the primary key), backing setlabel / getaddressesbylabel /
 * listlabels and the core.wallet.address.label(.by-label) native surface.
 * A plain annotation table: it is never part of the wallet keystore and is
 * never consulted by consensus. */

#ifndef ZCL_DB_MODEL_WALLET_LABEL_H
#define ZCL_DB_MODEL_WALLET_LABEL_H

#include "models/database.h"
#include "models/activerecord.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

enum {
    WALLET_LABEL_ADDRESS_MAX = 255,
    WALLET_LABEL_MAX = 255
};

/* One address -> label mapping. `address` is the primary key: a given
 * address carries at most one label at a time (a re-label overwrites via
 * upsert). `label` may be the empty string — the default/unlabeled bucket,
 * the same convention bitcoind's setlabel "" uses. */
struct db_wallet_label {
    char address[WALLET_LABEL_ADDRESS_MAX + 1];
    char label[WALLET_LABEL_MAX + 1];
    int64_t updated_at;
};

/* Lazily-initialized callback registry for the wallet_label model. Never
 * NULL; shared across all wallet_label save calls. */
struct ar_callbacks *db_wallet_label_callbacks(void);

/* Populate errors with any validation failures for l (address presence /
 * length / printability; label length / printability when non-empty).
 * Returns true iff l is valid. */
bool db_wallet_label_validate(const struct db_wallet_label *l,
                              struct ar_errors *errors);

/* Upsert l into wallet_labels, keyed by address (INSERT OR REPLACE). Runs
 * validation and the AR save lifecycle. Returns false on bad args,
 * validation failure, or DB failure. */
bool db_wallet_label_save(struct node_db *ndb, const struct db_wallet_label *l);

/* Look up the label row for address. Returns false (out untouched) when the
 * address has no row (i.e. is unlabeled) or on bad args. */
bool db_wallet_label_find(struct node_db *ndb, const char *address,
                          struct db_wallet_label *out);

/* Load up to max address rows whose label matches `label` exactly
 * (case-sensitive; "" finds addresses explicitly set to the default/empty
 * label), ordered by address. Returns the number of rows written, or 0 on
 * bad args, an unknown label, or no matches. */
int db_wallet_label_list_by_label(struct node_db *ndb, const char *label,
                                  struct db_wallet_label *out, size_t max);

/* Load up to max distinct labels currently in use, ordered lexically; only
 * the `label` field of each `out` row is populated. Returns the number of
 * rows written, or 0 on bad args / no labels recorded. */
int db_wallet_label_list_distinct(struct node_db *ndb,
                                  struct db_wallet_label *out, size_t max);

#endif
