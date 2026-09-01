/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The writer census's manifest of DERIVATIONS, expanded exactly once.
 *
 * This file exists so that controllers/fact_store_writers.def has a single
 * expansion site: each FACT_WRITE_API row takes the named function's ADDRESS, so
 * a row naming a function that does not exist fails the compile and the link
 * rather than degrading into a runtime "not found". That is the structural
 * enforcement the ontology law asks for, and it only works if the headers that
 * declare those entry points are included right here.
 */

#define _GNU_SOURCE
#include "fact_writers_priv.h"

/* Headers that DECLARE the write entry points the manifest names. */
#include "config/runtime.h"
#include "jobs/stage_repair_internal.h"
#include "models/database.h"
#include "storage/node_db_runtime.h"
#include "storage/progress_store.h"
#include "sync/stage.h"
#include "sync/stage_lcc.h"

#include <string.h>

static const struct fw_store_row fw_stores[] = {
#define FACT_STORE(store_, table_, keycol_, headers_) \
    { .store = (store_), .table = (table_), .key_column = (keycol_), \
      .api_headers = (headers_) },
#define FACT_WRITE_API(store_, fn_, idx_)
#include "controllers/fact_store_writers.def"
#undef FACT_WRITE_API
#undef FACT_STORE
};

static const struct fw_api_row fw_apis[] = {
#define FACT_STORE(store_, table_, keycol_, headers_)
#define FACT_WRITE_API(store_, fn_, idx_) \
    { .store = (store_), .fn = #fn_, .addr = (fact_write_entry_fn)(fn_), \
      .key_arg = (idx_) },
#include "controllers/fact_store_writers.def"
#undef FACT_WRITE_API
#undef FACT_STORE
};

#define FW_N_STORES (sizeof(fw_stores) / sizeof(fw_stores[0]))
#define FW_N_APIS   (sizeof(fw_apis) / sizeof(fw_apis[0]))

const struct fw_store_row *fw_store_rows(size_t *count)
{
    if (count) *count = FW_N_STORES;
    return fw_stores;
}

const struct fw_api_row *fw_api_rows(size_t *count)
{
    if (count) *count = FW_N_APIS;
    return fw_apis;
}

bool fw_api_claimed(const char *store, const char *fn)
{
    if (!store || !fn) return false;
    for (size_t i = 0; i < FW_N_APIS; i++)
        if (strcmp(fw_apis[i].store, store) == 0 &&
            strcmp(fw_apis[i].fn, fn) == 0)
            return true;
    return false;
}

size_t fact_writers_api_row_count(void) { return FW_N_APIS; }
size_t fact_writers_store_row_count(void) { return FW_N_STORES; }
