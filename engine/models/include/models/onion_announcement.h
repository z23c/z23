/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_DB_MODEL_ONION_ANNOUNCEMENT_H
#define ZCL_DB_MODEL_ONION_ANNOUNCEMENT_H

#include "models/database.h"
#include "models/activerecord.h"
#include <stdbool.h>
#include <stdint.h>

enum {
    ONION_ADDRESS_MAX = 127,
    ONION_SCRIPT_HEX_MAX = 511
};

struct db_onion_announcement {
    char onion_address[ONION_ADDRESS_MAX + 1];
    int64_t announced_at;
    char script_hex[ONION_SCRIPT_HEX_MAX + 1];
};

/* Lazily-initialized callback registry (before/after-save hooks) for the
 * onion-announcement model. Never NULL; shared across all save calls. */
struct ar_callbacks *db_onion_announcement_callbacks(void);

/* Populate errors with any validation failures for a (onion_address and
 * script_hex length, printability). Returns true iff a is valid. */
bool db_onion_announcement_validate(const struct db_onion_announcement *a,
                                    struct ar_errors *errors);

/* Upsert a into the onion_announcements table. Runs before-save (a veto
 * returns false without writing) and validation, then the row write; on
 * success runs after-save. Returns false on bad args, veto, or DB failure. */
bool db_onion_announcement_save(struct node_db *ndb,
                                const struct db_onion_announcement *a);

/* Returns true iff an announcement for onion_address is already stored.
 * Returns false on bad args or when no matching row exists. */
bool db_onion_announcement_exists(struct node_db *ndb,
                                  const char *onion_address);

/* Load up to max most-recent announcements into out (ordered by announced_at
 * descending). Returns the number of rows written, or 0 on bad args/empty. */
int db_onion_announcement_recent(struct node_db *ndb,
                                 struct db_onion_announcement *out,
                                 size_t max);

#endif
