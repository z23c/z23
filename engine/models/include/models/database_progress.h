/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Shared-connection SQLite progress handlers that coexist.
 *
 * SQLite keeps ONE progress handler per connection and has no getter, so two
 * callers that each install one and clear it to NULL when done replace and
 * then erase each other's: a time budget on an operator query (dbquery) was
 * lost whenever an index rebuild installed and cleared its own handler on the
 * shared node.db connection, and the rebuild's shutdown check was lost the
 * other way round. Every installer on a connection that other threads also
 * use goes through this registry instead of calling sqlite3_progress_handler
 * itself. The registry owns the one real handler: it is installed when the
 * first client arrives, re-tuned as clients come and go, and cleared when the
 * last one leaves.
 *
 * SQLite runs the handler on the thread that is stepping the statement, so a
 * client fires only for statements its own (registering) thread steps. A
 * budget set by one thread therefore never interrupts another thread's
 * statement, which on a write statement would roll back that thread's whole
 * transaction. */

#ifndef ZCL_DATABASE_PROGRESS_H
#define ZCL_DATABASE_PROGRESS_H

#include <sqlite3.h>
#include <stdbool.h>

/* Returns nonzero to interrupt the running statement, as sqlite3_progress_handler. */
typedef int (*db_progress_fn)(void *arg);

/* Registers fn(arg) for statements the calling thread runs on db, called about
 * every ops virtual-machine steps. False (logged) when the registry is full;
 * a caller that needs the limit refuses to proceed without it. */
bool db_progress_add(sqlite3 *db, int ops, db_progress_fn fn, void *arg);

/* Removes the registration made with the same db, fn and arg. The real handler
 * is cleared only when no client of db remains. */
void db_progress_remove(sqlite3 *db, db_progress_fn fn, void *arg);

#endif
