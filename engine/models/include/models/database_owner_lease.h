/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Process ownership lease for a canonical node database pathname. */

#ifndef ZCL_DATABASE_OWNER_LEASE_H
#define ZCL_DATABASE_OWNER_LEASE_H

#include <stdbool.h>

struct node_db;

enum node_db_owner_lease_probe {
    NODE_DB_OWNER_LEASE_PROBE_ERROR = -1,
    NODE_DB_OWNER_LEASE_UNOWNED = 0,
    NODE_DB_OWNER_LEASE_LIVE = 1,
    NODE_DB_OWNER_LEASE_OWNED_SELF = 2,
};

/* create_if_missing mirrors the SQLite open contract at this call site.
 * Runtime-create and canonical opens may create a fresh fixture/store;
 * existing-runtime opens must fail without changing the filesystem. */
bool node_db_owner_lease_acquire(struct node_db *ndb, bool create_if_missing);
bool node_db_owner_lease_rebind(struct node_db *ndb);
void node_db_owner_lease_release(struct node_db *ndb);

/* Probe the cross-process ownership lock without changing it.  LIVE means a
 * canonical or explicitly leased mutable handle owns the exact pathname;
 * ERROR is distinct from an offline/unowned database and must fail closed. */
enum node_db_owner_lease_probe node_db_owner_lease_probe(const char *path);

#endif
