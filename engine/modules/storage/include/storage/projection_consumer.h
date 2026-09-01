/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * projection_consumer — generic event-log projection consumer skeleton.
 *
 * Every event-log projection (the `*_projection.c` files under
 * engine/modules/storage/src) hand-duplicates the same plumbing: sqlite pragmas, a
 * shared `projection_meta(k,v)` table (schema_version +
 * last_consumed_offset), cursor load/persist, a BEGIN IMMEDIATE/COMMIT
 * batch wrapped around event_log_stream(), and rebuild-by-fresh-open. This
 * module owns that plumbing once. A caller supplies only its domain schema
 * + per-event apply logic via `struct projection_consumer_spec`.
 *
 * Mirrors the open/catch_up/close shape of znam_projection.c /
 * peers_projection.c (see storage/projection_util.h for the shared
 * stateless helpers this module is itself built on).
 */

#ifndef ZCL_STORAGE_PROJECTION_CONSUMER_H
#define ZCL_STORAGE_PROJECTION_CONSUMER_H

#include "storage/event_log.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct projection_consumer projection_consumer_t;

/* Apply one event's payload to the domain's own tables.
 *   db      - the projection's sqlite handle (already inside the
 *             catch_up batch transaction).
 *   type    - the event_log_type of this event.
 *   payload - the event's raw payload bytes (owned by the streamer, valid
 *             only for the duration of the call).
 *   len     - payload length.
 *   ctx     - spec->ctx, opaque to this module.
 *   out_handled - callee sets *out_handled = true iff `type` was one this
 *             domain recognizes and applied (used for the generic
 *             events-consumed counter). Event types the domain does not
 *             care about are ignored: leave *out_handled false and
 *             return true to skip past them.
 * Returns false to abort the whole catch_up batch (ROLLBACK, cursor stays
 * at its last-persisted value) — e.g. a payload that fails to parse. */
typedef bool (*projection_apply_fn)(sqlite3 *db, enum event_log_type type,
                                    const void *payload, size_t len,
                                    void *ctx, bool *out_handled);

/* Create/upgrade the domain's OWN tables (not projection_meta — this
 * module creates and owns that). Called once, inside open(), after
 * pragmas + projection_meta are ready. May be NULL if a domain has no
 * schema of its own (unusual, but not this module's business to forbid). */
typedef bool (*projection_ensure_schema_fn)(sqlite3 *db, void *ctx);

struct projection_consumer_spec {
    /* Recorded into projection_meta on first open (INSERT OR IGNORE — an
       existing row is never overwritten by a later open() with a
       different value). Purely informational today; no migration logic
       reads it back. */
    uint32_t schema_version;
    projection_ensure_schema_fn ensure_schema;
    projection_apply_fn apply_event;   /* required, non-NULL */
    void *ctx;
    /* Cursor is persisted to projection_meta every N applied events
       inside a catch_up batch, and always once more at the end of the
       batch. 0 => default of 100 (matches every existing projection). */
    uint32_t commit_batch;
};

/* Execute one bare admin SQL statement (DDL/pragma/txn control — not a
 * prepared statement), logging any failure tagged with `log_tag`. Exposed
 * so a domain's ensure_schema() callback shares this module's
 * exec-and-log primitive for its own CREATE TABLE statements instead of
 * every projection keeping a private copy. Returns true on SQLITE_OK. */
bool projection_consumer_exec_sql(sqlite3 *db, const char *log_tag,
                                  const char *sql, const char *ctx);

/* Opens (creating if absent) the sqlite projection at `projection_path`,
 * applies pragmas, ensures projection_meta + (if spec->ensure_schema)
 * the domain schema, and loads the persisted cursor. Returns NULL on any
 * failure (bad args, sqlite open failure, schema failure). */
projection_consumer_t *projection_consumer_open(
    const char *projection_path, event_log_t *log,
    const struct projection_consumer_spec *spec);

/* Checkpoints WAL and closes. NULL-safe. */
void projection_consumer_close(projection_consumer_t *pc);

/* Streams every event from the last persisted cursor to end-of-log inside
 * one BEGIN IMMEDIATE/COMMIT batch, calling spec->apply_event for each.
 * Returns the new cursor offset on success, UINT64_MAX on failure (the
 * batch is rolled back and the in-memory cursor is restored from the last
 * persisted value — a subsequent catch_up retries from there). */
uint64_t projection_consumer_catch_up(projection_consumer_t *pc);

/* Rebuild is a first-class verb, not an implicit fresh-open: resets the
 * persisted + in-memory cursor to 0 and re-drives catch_up from the
 * beginning of the log. The CALLER is responsible for dropping/truncating
 * its own domain tables (this module does not know their names) before
 * calling this — projection_consumer_open()'s ensure_schema recreates
 * them empty on next open, but a rebuild on an already-open handle must
 * clear them itself (e.g. DELETE FROM <table>) before this call, or the
 * replay will see stale rows. Returns the new cursor offset on success
 * (same contract as catch_up), UINT64_MAX on failure. */
uint64_t projection_consumer_rebuild(projection_consumer_t *pc);

/* The sqlite handle — domain read accessors (find/get/count queries) run
 * their own SELECTs against it instead of this module wrapping every
 * possible query. NULL if `pc` is NULL. */
sqlite3 *projection_consumer_db(projection_consumer_t *pc);

struct json_value;
/* Pushes the fields every projection's dump_state_json reports about its
 * consumer: path, last_consumed_offset, events_consumed_total,
 * last_catch_up_ms. Caller still pushes json_set_object/open/emit
 * counters/_health/domain fields itself. NULL-safe (pushes nothing). */
void projection_consumer_dump_common(struct json_value *out,
                                     projection_consumer_t *pc);

#endif /* ZCL_STORAGE_PROJECTION_CONSUMER_H */
