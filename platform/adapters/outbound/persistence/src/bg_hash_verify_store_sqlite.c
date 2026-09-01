/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * bg_hash_verify_store_sqlite — sqlite implementation of
 * bg_hash_verify_store_port.
 *
 * The two methods below are the crash-resume cursor reads/writes
 * (load_progress / save_progress over the node-DB state-kv path). The cursor
 * lives under the EXACT state key "bg_hash_verification_height" with get/set
 * int semantics, so an existing on-disk cursor resumes bit-for-bit identical.
 */

#include "adapters/outbound/persistence/bg_hash_verify_store_sqlite.h"

#include "models/database.h"

#include <stdint.h>

/* The single state key the cursor lives under — fixed so an existing on-disk
 * cursor is read back unchanged. */
#define BGHV_PROGRESS_KEY "bg_hash_verification_height"

/* `self` aliases the node_db* directly — there is no wrapper struct. */
static inline struct node_db *ndb_of(void *self)
{
    return (struct node_db *)self;
}

static bool bghv_load_progress(void *self, int *out)
{
    struct node_db *ndb = ndb_of(self);
    if (!ndb || !ndb->open || !out)
        return false;
    int64_t val = 0;
    if (!node_db_state_get_int(ndb, BGHV_PROGRESS_KEY, &val))
        return false;
    *out = (int)val;
    return true;
}

static bool bghv_save_progress(void *self, int height)
{
    struct node_db *ndb = ndb_of(self);
    if (!ndb || !ndb->open)
        return false;
    return node_db_state_set_int(ndb, BGHV_PROGRESS_KEY, (int64_t)height);
}

bool bg_hash_verify_store_sqlite_bind(struct node_db *ndb,
                                      struct bg_hash_verify_store_port *out_port)
{
    if (!out_port)
        return false;
    *out_port = (struct bg_hash_verify_store_port){
        .self          = ndb,
        .load_progress = bghv_load_progress,
        .save_progress = bghv_save_progress,
    };
    return true;
}
