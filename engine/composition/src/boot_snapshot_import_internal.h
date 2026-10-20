/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef Z23_BOOT_SNAPSHOT_IMPORT_INTERNAL_H
#define Z23_BOOT_SNAPSHOT_IMPORT_INTERNAL_H
#include "base/result.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
struct node_db;
struct sqlite3;
#define SNAPSHOT_IMPORT_PENDING_KEY "snapshot_import_pending.v1"
struct snapshot_import_pending {
    int32_t height;
    uint64_t generation, count;
    uint8_t hash[32], root[32];
};
bool snapshot_import_store_bound(struct node_db *ndb);
bool snapshot_import_directory_bound(const char *directory);
bool snapshot_import_no_installed_state(struct node_db *ndb);
bool snapshot_table_exists(struct sqlite3 *db, const char *name, bool *exists);
bool snapshot_node_blob(struct node_db *ndb, const char *key, void *out,
                        size_t cap, size_t *len, bool *found);
bool snapshot_import_shielded_pristine(struct node_db *ndb);
bool snapshot_import_pending_load(struct node_db *ndb,
    struct snapshot_import_pending *pending, bool *found);
bool snapshot_import_pending_save(struct node_db *ndb,
    const struct snapshot_import_pending *pending);
struct zcl_result snapshot_import_recover(struct node_db *ndb,
    const char *datadir, bool *recovered);
#endif
