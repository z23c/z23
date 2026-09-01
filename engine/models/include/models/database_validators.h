/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Database Validator Registry
 * ---------------------------
 * Programmatic registry that maps SQLite table names to validator functions
 * that wrap each model's existing `_validate()` routine.  The registry is
 * primarily an introspection and test surface — the actual validation is
 * already wired into every `db_<model>_save()` via `AR_BEGIN_SAVE`.
 *
 * The registry lets callers (tests, metrics, tooling) answer:
 *   - how many validators are registered?
 *   - which tables have validators?
 *   - does this record pass the structural invariants for its table?
 *
 * On failure, `db_run_validators_for()` returns false, populates err_out
 * with a joined message, and emits `EV_MODEL_VALIDATION_FAILED` so
 * subscribers (node_health_service, metrics, tests) see every bad record.
 */

#ifndef ZCL_DB_VALIDATORS_H
#define ZCL_DB_VALIDATORS_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Validator shape: take a typed row, write up to err_cap-1 bytes of error
 * message into err_out (may be NULL), return true on pass, false on fail. */
typedef bool (*db_validator_fn)(const void *row, char *err_out, size_t err_cap);

/* Maximum number of registered validators. Must exceed the 17 logical
 * tables (plus sub-types like sapling_note, wallet_utxo, etc.). */
#define DB_VALIDATOR_MAX 32

/* Register a validator for a table.  Later registrations replace earlier
 * ones for the same table.  Calling with fn=NULL unregisters the entry. */
void db_register_validator(const char *table, db_validator_fn fn);

/* Look up and run the validator for a table.  Returns true if no validator
 * is registered OR the validator passes.  Returns false on failure and
 * populates err_out (if non-NULL) with a joined error message.
 *
 * On failure, emits EV_MODEL_VALIDATION_FAILED with payload
 * "model=<table> errors=<msg>". */
bool db_run_validators_for(const char *table, const void *row,
                           char *err_out, size_t err_cap);

/* Register validators for every model bundled with zclassic23.  Idempotent:
 * calling it twice leaves the registry in the same state.  Called once
 * from node_db_open() at boot. */
void db_register_all_validators(void);

/* ── Introspection (test + metrics surface) ────────────────────── */

/* Current number of registered validators. */
int db_validator_count(void);

/* Get the table name at index [0, db_validator_count()).
 * Returns NULL on out-of-range. */
const char *db_validator_table_at(int index);

/* True if a validator is registered for this table. */
bool db_validator_has(const char *table);

/* Clear the entire registry.  Test-only. */
void db_validator_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_DB_VALIDATORS_H */
