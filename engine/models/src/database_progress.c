/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * ar-validate-skip:connection-handle-not-a-row
 *   Process-wide plumbing over the SQLite connection handle, not a row
 *   record (same rationale as database_long_op.c).
 *
 * Registry that lets several installers share one SQLite progress handler
 * per connection; see models/database_progress.h for why. */

#include "models/database_progress.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdint.h>

#define DB_PROGRESS_MAX_CLIENTS 32

struct db_progress_client {
    sqlite3 *db; /* NULL marks a free slot */
    db_progress_fn fn;
    void *arg;
    int ops;
    int64_t pending; /* VM steps since fn last ran */
    pthread_t owner;
};

static struct db_progress_client g_clients[DB_PROGRESS_MAX_CLIENTS];
/* g_edit_mutex serializes add/remove, including the sqlite3_progress_handler
 * call, which waits for the connection mutex. g_table_mutex guards the table
 * and is the only lock the handler takes: SQLite calls the handler with the
 * connection mutex held, so the handler must never wait on g_edit_mutex. */
static pthread_mutex_t g_edit_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_table_mutex = PTHREAD_MUTEX_INITIALIZER;

/* The finest granularity any client of db asked for, or 0 for none. */
static int progress_tick_locked(sqlite3 *db)
{
    int tick = 0;
    for (size_t i = 0; i < DB_PROGRESS_MAX_CLIENTS; i++)
        if (g_clients[i].db == db && (tick == 0 || g_clients[i].ops < tick))
            tick = g_clients[i].ops;
    return tick;
}

/* The one handler SQLite sees: runs every client of this connection that
 * belongs to the stepping thread and is due. The clients run outside the
 * table lock so they may take their own. */
static int progress_dispatch(void *vdb)
{
    sqlite3 *db = vdb;
    pthread_t self = pthread_self();
    db_progress_fn fns[DB_PROGRESS_MAX_CLIENTS];
    void *args[DB_PROGRESS_MAX_CLIENTS];
    size_t due = 0;

    pthread_mutex_lock(&g_table_mutex);
    int tick = progress_tick_locked(db);
    for (size_t i = 0; i < DB_PROGRESS_MAX_CLIENTS; i++) {
        struct db_progress_client *c = &g_clients[i];
        if (c->db != db || !pthread_equal(c->owner, self))
            continue;
        c->pending += tick;
        if (c->pending < c->ops)
            continue;
        c->pending = 0;
        fns[due] = c->fn;
        args[due++] = c->arg;
    }
    pthread_mutex_unlock(&g_table_mutex);

    int interrupt = 0;
    for (size_t i = 0; i < due; i++)
        if (fns[i](args[i]))
            interrupt = 1;
    return interrupt;
}

/* Points the connection's real handler at the registry, or clears it when no
 * client is left. Caller holds g_edit_mutex. */
static void progress_retune(sqlite3 *db)
{
    pthread_mutex_lock(&g_table_mutex);
    int tick = progress_tick_locked(db);
    pthread_mutex_unlock(&g_table_mutex);
    if (tick > 0)
        sqlite3_progress_handler(db, tick, progress_dispatch, db);
    else
        sqlite3_progress_handler(db, 0, NULL, NULL);
}

bool db_progress_add(sqlite3 *db, int ops, db_progress_fn fn, void *arg)
{
    if (!db || !fn || ops <= 0)
        return false;
    bool added = false;
    pthread_mutex_lock(&g_edit_mutex);
    pthread_mutex_lock(&g_table_mutex);
    for (size_t i = 0; i < DB_PROGRESS_MAX_CLIENTS && !added; i++) {
        struct db_progress_client *c = &g_clients[i];
        if (c->db)
            continue;
        *c = (struct db_progress_client){ .db = db, .fn = fn, .arg = arg,
            .ops = ops, .owner = pthread_self() };
        added = true;
    }
    pthread_mutex_unlock(&g_table_mutex);
    if (added)
        progress_retune(db);
    else
        LOG_ERROR("db", "db progress: client table full (%d), handler not "
                  "installed", DB_PROGRESS_MAX_CLIENTS);
    pthread_mutex_unlock(&g_edit_mutex);
    return added;
}

void db_progress_remove(sqlite3 *db, db_progress_fn fn, void *arg)
{
    if (!db)
        return;
    pthread_mutex_lock(&g_edit_mutex);
    bool removed = false;
    pthread_mutex_lock(&g_table_mutex);
    for (size_t i = 0; i < DB_PROGRESS_MAX_CLIENTS && !removed; i++) {
        struct db_progress_client *c = &g_clients[i];
        if (c->db != db || c->fn != fn || c->arg != arg)
            continue;
        c->db = NULL;
        removed = true;
    }
    pthread_mutex_unlock(&g_table_mutex);
    if (removed)
        progress_retune(db);
    pthread_mutex_unlock(&g_edit_mutex);
}
