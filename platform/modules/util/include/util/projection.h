/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Projection primitive — read-only handle over a backing store at a
 * frozen snapshot.
 *
 * Why this exists
 * ----------------
 * The destination architecture (zclassic23-plan.md, L4 layer) is
 * single-writer per storage engine, with N readers. Readers MUST NOT
 * block writers, and MUST NOT see torn writes mid-transaction. A
 * projection captures a consistent view at open time and serves
 * read-only queries from that view until it is closed.
 *
 * v1 implementation
 * ------------------
 * Wrap a long-lived deferred read transaction on a dedicated sqlite
 * connection. The transaction is started immediately after open with
 * a sentinel `SELECT 1` so the snapshot is locked in. In WAL mode
 * (which the node uses everywhere), this gives true MVCC snapshot
 * isolation: writers progress concurrently against the WAL; the
 * projection continues to see the pre-write committed state.
 *
 * In rollback-journal mode, the deferred read transaction still
 * provides snapshot semantics by holding a SHARED lock that blocks
 * writers from committing — readers never see partial writes.
 *
 * Caller contract
 * ----------------
 * Call projection_open(path) → projection_t *.
 * Issue queries with projection_query_int64.
 * Call projection_close to release the read transaction + connection.
 *
 * Wiring status
 * --------------
 * This generic API is WIRED in production: projection_open,
 * projection_query_int64, and projection_close back the chain
 * projection reads in engine/controllers/src/chain_projection.c. The
 * three additional accessors — projection_query_text,
 * projection_query_double, and projection_is_open — exist for the
 * test suite only and have no production callers yet; they will gain
 * production callers as richer-shaped projection reads land.
 *
 * The path-based open is intentional: a projection always opens its
 * OWN sqlite connection so it cannot be tangled with a writer's
 * transaction state. The cost is one extra fd per live projection. */

#ifndef ZCL_UTIL_PROJECTION_H
#define ZCL_UTIL_PROJECTION_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef struct projection projection_t;

/* Open a projection on the SQLite database at `path`. The projection
 * captures the committed state at open time and holds it for the
 * duration of the handle. Returns NULL on failure (open error or
 * begin-deferred error). */
projection_t *projection_open(const char *path);

/* Close the projection: ends the read transaction and closes the
 * sqlite connection. Idempotent — safe to call on a NULL handle or
 * a partially-failed open. After close, all query methods return
 * a non-OK result. */
void projection_close(projection_t *p);

/* Returns true if the projection is open (queries are still valid). */
bool projection_is_open(const projection_t *p);

/* Run a parameter-free SELECT that returns one INTEGER column from one
 * row. Returns 0 on success and writes the value to *out. Returns -1
 * on:
 *   - NULL handle / closed handle
 *   - prepare error
 *   - zero rows
 *   - more than one row (truncated; still returns -1)
 *   - column type not INTEGER
 *
 * This is the production query accessor — single counters, tip
 * height, current cursor values (see chain_projection.c). Typed
 * queries for richer shapes will land alongside the call sites that
 * need them. */
int projection_query_int64(projection_t *p, const char *sql, int64_t *out);

/* Run a parameter-free SELECT that returns one TEXT column from one row.
 * Copies up to out_cap - 1 bytes and always NUL-terminates on success.
 * Returns 0 on success, -1 on the same shape/argument failures as
 * projection_query_int64. */
int projection_query_text(projection_t *p, const char *sql,
                          char *out, size_t out_cap);

/* Run a parameter-free SELECT that returns one REAL column from one row.
 * INTEGER values are accepted and converted to double because SQLite's
 * dynamic typing can preserve integral REAL literals as INTEGER. */
int projection_query_double(projection_t *p, const char *sql, double *out);

#endif /* ZCL_UTIL_PROJECTION_H */
