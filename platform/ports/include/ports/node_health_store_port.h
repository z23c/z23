/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * node_health_store_port — storage interface for the three persistent
 * reads node_health_collect() performs against the node DB.
 *
 * node_health is a read-only, NON-CONSENSUS observer: it assembles one
 * health snapshot from many in-memory sources (sync state, peers, jobs,
 * watchdog, mirror lag, alerts) plus exactly three storage queries. Only
 * those three queries touch sqlite, and they are what this port captures:
 *
 *   tip_height_from_blocks(out)  "SELECT COALESCE(MAX(height), -1)
 *                                 FROM blocks"  — fallback tip height when
 *                                 the in-memory chain tip is unavailable.
 *   utxo_count(out)              "SELECT count(*) FROM utxos"  — fallback
 *                                 UTXO-set size for the snapshot.
 *   wal_size_bytes(out)          sqlite3_db_filename(...,"main") then
 *                                 stat("<db>-wal") — size of the WAL file
 *                                 on disk, for the db-pressure surface.
 *
 * No sqlite type appears in this header. The adapter under
 * platform/adapters/outbound/persistence/ is the only thing that includes sqlite
 * for this subsystem. It binds two already-open handles — the shared
 * read query connection (the two SELECTs) and the primary node-DB
 * connection (the one whose WAL we stat) — and never closes either.
 *
 * Threading: node_health_collect() runs on request / metrics / boot
 * threads. The reads are point queries on sqlite's own locking, exactly
 * the concurrency contract the raw inline code had before the seam.
 *
 * Every method returns false on a NULL self / NULL out / storage miss and
 * leaves the out-parameter UNTOUCHED, so the caller keeps the same
 * "fall back to the in-memory estimate" behaviour it had before.
 */

#ifndef ZCL_PORTS_NODE_HEALTH_STORE_PORT_H
#define ZCL_PORTS_NODE_HEALTH_STORE_PORT_H

#include <stdbool.h>
#include <stdint.h>

struct node_health_store_port {
    void *self;

    /* MAX(height) over the blocks table, COALESCE'd to -1 for an empty
     * table. Sets *out and returns true on the single returned row; false
     * (out untouched) if the query db is unavailable or the statement
     * could not be prepared/stepped. Read of the shared query connection. */
    bool (*tip_height_from_blocks)(void *self, int *out);

    /* count(*) over the utxos table. Sets *out and returns true on the
     * single returned row; false (out untouched) otherwise. Read of the
     * shared query connection. */
    bool (*utxo_count)(void *self, int64_t *out);

    /* Size in bytes of the primary node DB's write-ahead-log file
     * ("<db path>-wal"). Sets *out and returns true if the DB filename is
     * known and the WAL file stat()s successfully; false (out untouched)
     * if there is no on-disk filename (e.g. :memory:) or the WAL file does
     * not exist yet. Operates on the primary node-DB connection. */
    bool (*wal_size_bytes)(void *self, int64_t *out);
};

#endif /* ZCL_PORTS_NODE_HEALTH_STORE_PORT_H */
