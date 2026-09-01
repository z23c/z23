/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Internal cross-translation-unit glue for the snapshot controller.
 *
 * The public surface lives in controllers/snapshot_controller.h. This
 * header is private to engine/controllers/src/snapshot_controller*.c and
 * declares helpers that needed to become non-static so the snapshot
 * controller could be split across multiple files:
 *
 *   snapshot_controller.c          — snapshot dir mgmt + snapshot_create
 *   snapshot_controller_import.c   — parallel LevelDB→SQLite import
 *   snapshot_controller_txindex.c  — background tx-index builder
 *
 * Do not include from outside engine/controllers/src/. */

#ifndef ZCL_APP_CONTROLLERS_SRC_SNAPSHOT_CONTROLLER_INTERNAL_H
#define ZCL_APP_CONTROLLERS_SRC_SNAPSHOT_CONTROLLER_INTERNAL_H

#include "controllers/snapshot_controller.h"
#include "models/database.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── Shared SQLite transaction helpers (defined in snapshot_controller.c) ──
 * Every snapshot worker thread opens its own node_db connection and drives
 * bulk-load transactions through these checked wrappers so error context is
 * always logged. */

bool snapshot_sql_exec_checked(struct node_db *ndb, const char *sql,
                               const char *label);
bool snapshot_tx_begin_checked(struct node_db *ndb, const char *label);
bool snapshot_tx_commit_checked(struct node_db *ndb, const char *label);
void snapshot_tx_rollback_best_effort(struct node_db *ndb, const char *label);

#endif
