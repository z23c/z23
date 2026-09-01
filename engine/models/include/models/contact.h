/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_DB_MODEL_CONTACT_H
#define ZCL_DB_MODEL_CONTACT_H

#include "models/database.h"
#include "models/activerecord.h"
#include <stdbool.h>
#include <stdint.h>

enum {
    CONTACT_ADDRESS_MAX = 255,
    CONTACT_NAME_MAX = 63
};

struct db_contact {
    char address[CONTACT_ADDRESS_MAX + 1];
    char name[CONTACT_NAME_MAX + 1];
    int64_t last_used;
};

/* Lazily-initialized callback registry (before/after-save hooks) for the
 * contact model. Never NULL; shared across all contact save calls. */
struct ar_callbacks *db_contact_callbacks(void);

/* Populate errors with any validation failures for c (address/name length,
 * printability, non-negative last_used). Returns true iff c is valid. */
bool db_contact_validate(const struct db_contact *c, struct ar_errors *errors);

/* Upsert c into the contacts table. Runs before-save (a veto returns false
 * without writing) and validation, then INSERT OR REPLACE; on success runs
 * after-save. Returns false on bad args, veto, validation, or DB failure. */
bool db_contact_save(struct node_db *ndb, const struct db_contact *c);

/* Load up to max most-recently-used contacts into out (ordered by last_used
 * descending). Returns the number of rows written, or 0 on bad args/empty. */
int db_contact_recent(struct node_db *ndb, struct db_contact *out, size_t max);

#endif
