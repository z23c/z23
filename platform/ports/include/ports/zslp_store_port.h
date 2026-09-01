/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * zslp_store_port — connection-acquisition interface for the ZSLP token
 * application service.
 *
 * zslp is a NON-CONSENSUS application feature (the ZSLP token protocol).
 * Every balance/token/transfer read and write the service performs already
 * goes through the model layer (models/zslp.h, db_zslp_*). The ONLY thing
 * the service did that named sqlite directly was acquire a connection to
 * the on-disk node DB when no in-process runtime connection was available:
 * open "<datadir>/node.db", set the busy timeout, and ensure the
 * zslp_balances table exists. That single connection-open path is exactly
 * what this port captures, with the matching release:
 *
 *   open(self, datadir, db_out)   Open "<datadir>/node.db" with a 5 s busy
 *                                 timeout and CREATE TABLE IF NOT EXISTS
 *                                 zslp_balances(...). On success sets
 *                                 *db_out to the freshly opened, caller-
 *                                 OWNED connection and returns true. On any
 *                                 failure closes whatever was opened, leaves
 *                                 *db_out NULL, and returns false.
 *   close(self, db)               Close a connection previously handed back
 *                                 by open(). NULL is tolerated (no-op).
 *
 * No sqlite type appears in this header: the connection is passed back as
 * an opaque void* so the only thing that names sqlite for the zslp
 * subsystem is the adapter under platform/adapters/outbound/persistence/. The
 * service casts the opaque handle back to sqlite3* when it forwards it to
 * the model layer — byte-for-byte the same handle it opened inline before.
 *
 * The in-process fast path (reuse the already-open runtime node DB, which
 * the service does NOT own and must not close) stays in the service: it
 * touches no sqlite functions, so it is not part of this storage seam.
 *
 * Threading: open()/close() run on request / command threads, the same
 * contract the inline open/close had. The port holds no state of its own
 * between calls.
 */

#ifndef ZCL_PORTS_ZSLP_STORE_PORT_H
#define ZCL_PORTS_ZSLP_STORE_PORT_H

#include <stdbool.h>

struct zslp_store_port {
    void *self;

    /* Open "<datadir>/node.db" as a fresh, caller-owned connection with a
     * 5 s busy timeout and the zslp_balances table ensured. Sets *db_out to
     * the opaque connection handle and returns true on success; on failure
     * (NULL datadir/db_out, open error) closes any partial handle, sets
     * *db_out to NULL where possible, and returns false. */
    bool (*open)(void *self, const char *datadir, void **db_out);

    /* Close a connection returned by open(). NULL `db` is a no-op. */
    void (*close)(void *self, void *db);
};

#endif /* ZCL_PORTS_ZSLP_STORE_PORT_H */
