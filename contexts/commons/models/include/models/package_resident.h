/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: the resident consumer's one committed acceptance projection. */
#ifndef ZCL_MODELS_PACKAGE_RESIDENT_H
#define ZCL_MODELS_PACKAGE_RESIDENT_H

#include "base/result.h"
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

/* Installed bytes alone never populate this record. Only a caller holding
 * explicit execution acceptance may propose an identity; the consumer must
 * validate READY and its exact launch receipt before committing it. */
struct package_resident_identity {
    char package_root[65];
    char receipt_id[65];
    char artifact_sha3[65];
    char program[256];
    int64_t configuration_generation;
};

struct package_resident_record {
    int64_t revision;
    int64_t generation;
    int64_t consumed_ticket;
    struct package_resident_identity current;
    struct package_resident_identity previous;
    struct package_resident_identity pending;
    /* begin output only: exact pending retired inside its transaction. */
    struct package_resident_identity displaced_pending;
    int64_t pending_ticket;
    int64_t pending_generation;
    char pending_nonce[65];
    uint64_t pending_start_token;
    char current_nonce[65];
    uint64_t current_start_token;
};

/* This is an isolated application database, never node.db. Current and
 * previous acceptance plus the successor high-water mark occupy one row.
 * Process descriptors and PIDs are deliberately not restart authority. */
struct package_resident_store { sqlite3 *db; char app[256]; };

/* Trusted host precondition, never a callback supplied by downloaded code.
 * Runs under the same write transaction as the program switch. It must only
 * read through this store: no worker wait, nested transaction or external I/O.
 * A refusal rolls back the switch; it never restores a user-data snapshot. */
struct package_resident_guard {
    void *context;
    struct zcl_result (*check)(void *context, struct package_resident_store *store,
        const struct package_resident_identity *target);
};

struct zcl_result package_resident_store_open(
    struct package_resident_store *store, const char *datadir);
struct zcl_result package_resident_store_close(struct package_resident_store *store);
struct zcl_result package_resident_record_read(
    struct package_resident_store *store, struct package_resident_record *out);
struct zcl_result package_resident_record_begin(
    struct package_resident_store *store, int64_t expected_generation,
    struct package_resident_record *out);
struct zcl_result package_resident_record_commit(
    struct package_resident_store *store, int64_t ticket,
    int64_t expected_generation, const struct package_resident_identity *identity,
    struct package_resident_record *out);
bool package_resident_identity_equal(const struct package_resident_identity *a,
                                    const struct package_resident_identity *b);
/* Named labels select local state; they confer no publisher authority. */
struct zcl_result package_resident_store_open_app(
    struct package_resident_store *store, const char *datadir, const char *app);
/* Open existing state without creating or migrating it. */
struct zcl_result package_resident_store_open_app_readonly(
    struct package_resident_store *store, const char *datadir, const char *app);
struct zcl_result package_resident_record_accept(
    struct package_resident_store *store, int64_t ticket,
    int64_t expected_generation, const struct package_resident_identity *identity,
    const char *nonce, uint64_t start_token, struct package_resident_record *out);
struct zcl_result package_resident_record_activate(
    struct package_resident_store *store, int64_t ticket,
    int64_t expected_generation, const char *nonce, uint64_t start_token,
    struct package_resident_record *out);
struct zcl_result package_resident_record_rollback(
    struct package_resident_store *store, int64_t ticket,
    int64_t expected_generation, const char *nonce, uint64_t start_token,
    struct package_resident_record *out);
struct zcl_result package_resident_record_activate_checked(
    struct package_resident_store *store, int64_t ticket,
    int64_t expected_generation, const char *nonce, uint64_t start_token,
    const struct package_resident_guard *guard, struct package_resident_record *out);
struct zcl_result package_resident_record_rollback_checked(
    struct package_resident_store *store, int64_t ticket,
    int64_t expected_generation, const char *nonce, uint64_t start_token,
    const struct package_resident_guard *guard, struct package_resident_record *out);
#endif
