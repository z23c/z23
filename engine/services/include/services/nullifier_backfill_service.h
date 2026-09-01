/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * nullifier_backfill_service — owner-gated remediation for the C-3
 * nullifier activation gap. Populate-only: it backfills durable nullifier
 * rows for already-applied historical blocks and never changes a consensus
 * predicate. */

#ifndef ZCL_SERVICES_NULLIFIER_BACKFILL_SERVICE_H
#define ZCL_SERVICES_NULLIFIER_BACKFILL_SERVICE_H

#include "util/result.h"

#include <stdbool.h>
#include <stdint.h>

struct block;
struct main_state;
struct node_db;
struct sqlite3;

#define NULLIFIER_BACKFILL_ACTIVATION_KEY "nullifier_kv.activation_cursor"
#define NULLIFIER_BACKFILL_RESUME_KEY "nullifier_kv.backfill_cursor"
#define NULLIFIER_BACKFILL_CHAIN_KEY "nullifier_kv.backfill_chain_binding"

typedef bool (*nullifier_backfill_read_block_fn)(
    struct block *out,
    int64_t height,
    const char *datadir,
    void *user,
    bool *found_out);

struct nullifier_backfill_config {
    /* Selected-chain authority for the complete run.  node.db height rows are
     * only body locations; they never select or authenticate a chain. */
    struct main_state *main;
    struct node_db *ndb;
    struct sqlite3 *progress_db;
    const char *datadir;
    nullifier_backfill_read_block_fn read_block;
    void *read_block_user;
};

struct nullifier_backfill_report {
    int64_t activation_cursor;
    int64_t start_height;
    int64_t target_exclusive;
    int64_t next_height;
    int64_t blocks_scanned;
    bool completed;
    bool already_complete;
};

struct zcl_result nullifier_backfill_service_run(
    const struct nullifier_backfill_config *cfg,
    struct nullifier_backfill_report *report);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
struct json_value;
bool nullifier_backfill_dump_state_json(struct json_value *out,
                                        const char *key);

#endif /* ZCL_SERVICES_NULLIFIER_BACKFILL_SERVICE_H */
