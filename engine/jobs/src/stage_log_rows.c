/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_log_rows — see jobs/stage_log_rows.h. A tiny fixed registry: one
 * seqlock-published counter per tracked *_log table. The table names are a
 * compile-time whitelist (never user input), so the COUNT(*) SQL built from a
 * name cannot inject. */

#include "jobs/stage_log_rows.h"

#include "json/json.h"
#include "platform/time_compat.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/subsystem_snapshot.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct log_rows_entry {
    const char             *table;
    struct zcl_snapshot_env env;
    _Atomic int64_t         rows;
    _Atomic uint64_t        seeded_epoch;  /* 0 = never seeded */
};

/* The tracked tables. Extend here (and, if it can be deleted on reorg, wire a
 * stage_log_rows_note_delete at the delete choke point). */
static struct log_rows_entry g_entries[] = {
    { "body_persist_log",   ZCL_SNAPSHOT_ENV_INIT, 0, 0 },
    { "proof_validate_log", ZCL_SNAPSHOT_ENV_INIT, 0, 0 },
    { "script_validate_log",ZCL_SNAPSHOT_ENV_INIT, 0, 0 },
    { "utxo_apply_log",     ZCL_SNAPSHOT_ENV_INIT, 0, 0 },
};

static struct log_rows_entry *entry_for(const char *table)
{
    if (!table)
        return NULL;
    for (size_t i = 0; i < sizeof(g_entries) / sizeof(g_entries[0]); i++)
        if (strcmp(g_entries[i].table, table) == 0)
            return &g_entries[i];
    return NULL;
}

/* Publish `rows` for `e` through the seqlock envelope. Height is not meaningful
 * for a row count, so last_height stays -1. Callers hold the progress-store
 * writer lock (single publisher) on the mutation paths; the seed path holds it
 * too — so publishes never race each other. */
static void publish(struct log_rows_entry *e, int64_t rows)
{
    zcl_snapshot_publish_begin(&e->env);
    atomic_store_explicit(&e->rows, rows, memory_order_relaxed);
    zcl_snapshot_publish_end(&e->env, -1);
}

void stage_log_rows_seed(struct sqlite3 *db, const char *table)
{
    struct log_rows_entry *e = entry_for(table);
    if (!e || !db)
        return;

    uint64_t epoch = progress_store_epoch();
    /* Re-seed at most once per open epoch. 0 means "never seeded"; the store's
     * first open makes the epoch 1, so a real epoch never collides with it. */
    if (atomic_load_explicit(&e->seeded_epoch, memory_order_acquire) == epoch &&
        epoch != 0)
        return;

    char sql[128];
    int n = snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", e->table);
    if (n <= 0 || n >= (int)sizeof(sql)) {
        LOG_WARN("stage_log_rows", "seed: sql overflow for %s", e->table);
        return;
    }

    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    int64_t count = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:progress-kv-kernel-store
            count = sqlite3_column_int64(st, 0);
    } else {
        LOG_WARN("stage_log_rows", "seed: prepare failed for %s: %s",
                 e->table, sqlite3_errmsg(db));
    }
    sqlite3_finalize(st);
    progress_store_tx_unlock();

    if (count < 0)
        return;  // raw-return-ok:seed-count-unavailable-leave-prior-value
    publish(e, count);
    atomic_store_explicit(&e->seeded_epoch, epoch, memory_order_release);
}

void stage_log_rows_note_insert(const char *table)
{
    struct log_rows_entry *e = entry_for(table);
    if (!e)
        return;
    int64_t rows = atomic_load_explicit(&e->rows, memory_order_relaxed) + 1;
    publish(e, rows);
}

void stage_log_rows_note_delete(const char *table, int64_t removed)
{
    struct log_rows_entry *e = entry_for(table);
    if (!e || removed <= 0)
        return;
    int64_t rows = atomic_load_explicit(&e->rows, memory_order_relaxed) - removed;
    if (rows < 0)
        rows = 0;
    publish(e, rows);
}

int64_t stage_log_rows_value(const char *table)
{
    struct log_rows_entry *e = entry_for(table);
    if (!e)
        return -1;  // raw-return-ok:untracked-table-sentinel-not-an-error
    return atomic_load_explicit(&e->rows, memory_order_relaxed);
}

void stage_log_rows_emit(struct json_value *out, const char *table,
                         const char *count_key)
{
    struct log_rows_entry *e = entry_for(table);
    if (!out || !e || !count_key)
        return;

    /* Single-atomic payload: the read is coherent without the seqlock bracket.
     * The envelope supplies the staleness label (age / generation / never-
     * published). */
    int64_t rows = atomic_load_explicit(&e->rows, memory_order_relaxed);
    json_push_kv_int(out, count_key, rows);

    struct json_value label;
    json_init(&label);
    json_set_object(&label);
    zcl_snapshot_emit_label(&label, &e->env, /*torn=*/false,
                            platform_time_monotonic_us());
    char key[96];
    int n = snprintf(key, sizeof(key), "%s_snapshot", count_key);
    if (n > 0 && n < (int)sizeof(key))
        json_push_kv(out, key, &label);
    json_free(&label);
}
