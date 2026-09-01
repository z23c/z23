/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * wallet_backup_internal — the pieces the wallet-backup service shares
 * across its own translation units, and nothing else.
 *
 * wallet_backup_service.c owns the lifecycle (thread, config, status,
 * supervisor contract); wallet_backup_run.c owns the one-shot snapshot
 * primitive and its per-table verification. The split exists because the
 * combined file passed the 800-line shape ceiling once verification grew
 * from one table to all eight. Nothing outside those two files (plus the
 * rotation/crypto siblings) may include this header — the public contract
 * is services/wallet_backup_service.h.
 */

#ifndef ZCL_SERVICES_WALLET_BACKUP_INTERNAL_H
#define ZCL_SERVICES_WALLET_BACKUP_INTERNAL_H

#include "services/wallet_backup_service.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Comma-joined names of the wallet tables the SOURCE did not have on the
 * last run. Eight bounded names fit with room to spare. */
#define WBS_MISSING_TABLES_MAX 256

/* What per-table verification found, threaded out of the run so the caller
 * (which already holds the service mutex) records it without re-locking a
 * non-recursive lock. */
struct wbs_verify_out {
    int  tables_verified;                     /* tables that matched src */
    char missing[WBS_MISSING_TABLES_MAX];     /* absent-in-source names */
};

/* The whole one-shot run. `vout` (required) receives the per-table
 * verification result. wallet_backup_run_once() is the public thin wrapper
 * that throws `vout` away. */
struct zcl_result wbs_run_once_impl(const char *backup_dir,
                                    struct node_db *db,
                                    char *out_path, size_t out_path_cap,
                                    int64_t *out_key_count,
                                    char *err_out, size_t err_cap,
                                    struct wbs_verify_out *vout);

/* Create `dir` with mode 0700 if missing. ZCL_OK when it exists on return;
 * a non-ok result's .message names the path and the errno reason. */
struct zcl_result wbs_ensure_backup_dir(const char *dir);

/* Absolute on-disk path backing `db`'s sqlite connection. Non-ok (and an
 * empty `out`) for a closed handle or an in-memory database. */
struct zcl_result wbs_source_path(struct node_db *db, char *out, size_t cap);

#endif /* ZCL_SERVICES_WALLET_BACKUP_INTERNAL_H */
