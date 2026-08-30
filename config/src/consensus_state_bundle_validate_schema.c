/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Contract: consensus_state_bundle_validate_schema.h. */

#include "consensus_state_bundle_validate_schema.h"
#include "consensus_state_sqlite_text.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define SCHEMA_SUBSYS "consensus_bundle_validate_schema"

static bool schema_fail(struct consensus_state_install_result *result,
                        const char *fmt, ...)
{
    char reason[192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(reason, sizeof(reason), fmt, ap);
    va_end(ap);
    if (result) {
        result->status = CONSENSUS_INSTALL_REFUSED;
        snprintf(result->reason, sizeof(result->reason), "%s", reason);
    }
    LOG_WARN(SCHEMA_SUBSYS, "%s", reason);
    return false;
}

struct canonical_column {
    const char *name;
    const char *type;
    int primary_key_ordinal;
};

struct canonical_table {
    const char *name;
    const struct canonical_column *columns;
    size_t column_count;
    const char *required_sql_token;
    const char *required_sql_token_2;
};

#define COL(n, t, pk) { (n), (t), (pk) }
static const struct canonical_column k_bundle_meta_columns[] = {
    COL("singleton","INTEGER",1), COL("schema","TEXT",0),
    COL("height","INTEGER",0), COL("block_hash","BLOB",0),
    COL("history_complete","INTEGER",0),
    COL("source_clean","INTEGER",0),
    COL("validation_profile","INTEGER",0),
    COL("activation_boundary","INTEGER",0), COL("utxo_root","BLOB",0),
    COL("utxo_count","INTEGER",0), COL("total_supply","INTEGER",0),
    COL("anchor_digest","BLOB",0), COL("anchor_count","INTEGER",0),
    COL("sprout_frontier_root","BLOB",0),
    COL("sprout_frontier_height","INTEGER",0),
    COL("sapling_frontier_root","BLOB",0),
    COL("sapling_frontier_height","INTEGER",0),
    COL("nullifier_digest","BLOB",0), COL("nullifier_count","INTEGER",0),
    COL("sprout_source_cursor","INTEGER",0),
    COL("sapling_source_cursor","INTEGER",0),
    COL("nullifier_source_cursor","INTEGER",0),
    COL("source_fold_cursor","INTEGER",0),
    COL("proof_manifest_digest","BLOB",0), COL("source_digest","BLOB",0),
    COL("artifact_digest","BLOB",0),
};
static const struct canonical_column k_source_receipt_columns[] = {
    COL("singleton","INTEGER",1), COL("schema","TEXT",0),
    COL("source_epoch_digest","BLOB",0),
    COL("source_tree_root","BLOB",0),
    COL("running_binary_digest","BLOB",0),
    COL("toolchain_digest","BLOB",0), COL("build_inputs_digest","BLOB",0),
    COL("chain_corpus_digest","BLOB",0), COL("source_clean","INTEGER",0),
    COL("validation_profile","INTEGER",0),
    COL("producer_commit","TEXT",0), COL("fold_cursor","INTEGER",0),
    COL("receipt_digest","BLOB",0),
};
static const struct canonical_column k_bundle_proof_columns[] = {
    COL("ordinal","INTEGER",1), COL("component","TEXT",0),
    COL("cursor","INTEGER",0), COL("first_height","INTEGER",0),
    COL("last_height","INTEGER",0), COL("row_count","INTEGER",0),
    COL("hash_bound_count","INTEGER",0),
    COL("component_digest","BLOB",0),
};
static const struct canonical_column k_proof_parent_columns[] = {
    COL("singleton","INTEGER",1), COL("base_height","INTEGER",0),
    COL("base_block_hash","BLOB",0),
    COL("validation_profile","INTEGER",0),
    COL("proof_manifest_digest","BLOB",0),
    COL("source_digest","BLOB",0), COL("artifact_digest","BLOB",0),
};
static const struct canonical_column k_proof_parent_component_columns[] = {
    COL("ordinal","INTEGER",1), COL("component","TEXT",0),
    COL("cursor","INTEGER",0), COL("first_height","INTEGER",0),
    COL("last_height","INTEGER",0), COL("row_count","INTEGER",0),
    COL("hash_bound_count","INTEGER",0),
    COL("component_digest","BLOB",0), COL("suffix_digest","BLOB",0),
};
static const struct canonical_column k_coins_columns[] = {
    COL("txid","BLOB",1), COL("vout","INTEGER",2),
    COL("value","INTEGER",0), COL("script","BLOB",0),
    COL("height","INTEGER",0), COL("is_coinbase","INTEGER",0),
};
static const struct canonical_column k_anchors_columns[] = {
    COL("pool","INTEGER",1), COL("anchor","BLOB",2),
    COL("height","INTEGER",0), COL("tree","BLOB",0),
};
static const struct canonical_column k_nullifiers_columns[] = {
    COL("pool","INTEGER",1), COL("nf","BLOB",2),
    COL("height","INTEGER",0),
};
#undef COL

static const struct canonical_table k_legacy_tables[] = {
    {"anchors", k_anchors_columns,
     sizeof(k_anchors_columns) / sizeof(k_anchors_columns[0]),
     "CHECK(pool IN(0,1))", "UNIQUE(pool,height)"},
    {"bundle_meta", k_bundle_meta_columns,
     sizeof(k_bundle_meta_columns) / sizeof(k_bundle_meta_columns[0]),
     "CHECK(singleton=1)", NULL},
    {"bundle_proof", k_bundle_proof_columns,
     sizeof(k_bundle_proof_columns) / sizeof(k_bundle_proof_columns[0]),
     "UNIQUE", NULL},
    {"coins", k_coins_columns,
     sizeof(k_coins_columns) / sizeof(k_coins_columns[0]), "WITHOUT ROWID",
     NULL},
    {"nullifiers", k_nullifiers_columns,
     sizeof(k_nullifiers_columns) / sizeof(k_nullifiers_columns[0]),
     "CHECK(pool IN(0,1))", NULL},
    {"source_receipt", k_source_receipt_columns,
     sizeof(k_source_receipt_columns) / sizeof(k_source_receipt_columns[0]),
     "CHECK(singleton=1)", NULL},
};

static const struct canonical_table k_composite_tables[] = {
    {"anchors", k_anchors_columns,
     sizeof(k_anchors_columns) / sizeof(k_anchors_columns[0]),
     "CHECK(pool IN(0,1))", "UNIQUE(pool,height)"},
    {"bundle_meta", k_bundle_meta_columns,
     sizeof(k_bundle_meta_columns) / sizeof(k_bundle_meta_columns[0]),
     "CHECK(singleton=1)", NULL},
    {"bundle_proof", k_bundle_proof_columns,
     sizeof(k_bundle_proof_columns) / sizeof(k_bundle_proof_columns[0]),
     "UNIQUE", NULL},
    {"coins", k_coins_columns,
     sizeof(k_coins_columns) / sizeof(k_coins_columns[0]), "WITHOUT ROWID",
     NULL},
    {"nullifiers", k_nullifiers_columns,
     sizeof(k_nullifiers_columns) / sizeof(k_nullifiers_columns[0]),
     "CHECK(pool IN(0,1))", NULL},
    {"proof_parent", k_proof_parent_columns,
     sizeof(k_proof_parent_columns) / sizeof(k_proof_parent_columns[0]),
     "CHECK(singleton=1)", "CHECK(base_height>=0)"},
    {"proof_parent_component", k_proof_parent_component_columns,
     sizeof(k_proof_parent_component_columns) /
         sizeof(k_proof_parent_component_columns[0]),
     "UNIQUE", "CHECK(ordinal>=0 AND ordinal<8)"},
    {"source_receipt", k_source_receipt_columns,
     sizeof(k_source_receipt_columns) / sizeof(k_source_receipt_columns[0]),
     "CHECK(singleton=1)", NULL},
};

static bool canonical_table_present(sqlite3 *db, const char *name,
                                    bool *present)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(
            db, "SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC) == SQLITE_OK;
    int rc = ok ? sqlite3_step(st) : SQLITE_ERROR; // raw-sql-ok:read-only-introspection
    *present = rc == SQLITE_ROW;
    if (*present)
        rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

static bool canonical_table_columns(sqlite3 *db,
                                    const struct canonical_table *table)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(
            db, "SELECT name,type,pk,hidden FROM pragma_table_xinfo(?) "
                "ORDER BY cid", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, table->name, -1, SQLITE_STATIC);
    bool ok = true;
    for (size_t i = 0; i < table->column_count; i++) {
        int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
        if (rc != SQLITE_ROW ||
            !consensus_state_sqlite_text_equal(
                st, 0, table->columns[i].name) ||
            !consensus_state_sqlite_text_equal(
                st, 1, table->columns[i].type) ||
            sqlite3_column_type(st, 2) != SQLITE_INTEGER ||
            sqlite3_column_int(st, 2) !=
                table->columns[i].primary_key_ordinal ||
            sqlite3_column_type(st, 3) != SQLITE_INTEGER ||
            sqlite3_column_int(st, 3) != 0) {
            ok = false;
            break;
        }
    }
    if (ok)
        ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    sqlite3_finalize(st);
    return ok;
}

bool consensus_state_bundle_validate_canonical_schema(
    sqlite3 *db, struct consensus_state_install_result *result)
{
    bool composite = false;
    if (!canonical_table_present(db, "proof_parent", &composite))
        return schema_fail(result, "bundle schema lineage probe failed");
    const struct canonical_table *tables =
        composite ? k_composite_tables : k_legacy_tables;
    size_t table_count = composite
                             ? sizeof(k_composite_tables) /
                                   sizeof(k_composite_tables[0])
                             : sizeof(k_legacy_tables) /
                                   sizeof(k_legacy_tables[0]);
    sqlite3_stmt *st = NULL;
    static const char sql[] =
        "SELECT type,name,sql FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return schema_fail(result, "bundle schema catalog unreadable");
    bool ok = true;
    for (size_t i = 0; i < table_count; i++) {
        int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
        const struct canonical_table *want = &tables[i];
        int definition_type = rc == SQLITE_ROW
            ? sqlite3_column_type(st, 2) : SQLITE_NULL;
        const char *definition = definition_type == SQLITE_TEXT
            ? (const char *)sqlite3_column_text(st, 2) : NULL;
        if (rc != SQLITE_ROW ||
            !consensus_state_sqlite_text_equal(st, 0, "table") ||
            !consensus_state_sqlite_text_equal(st, 1, want->name) ||
            !definition ||
            sqlite3_column_bytes(st, 2) != (int)strlen(definition) ||
            !strstr(definition, want->required_sql_token) ||
            (want->required_sql_token_2 &&
             !strstr(definition, want->required_sql_token_2)) ||
            ((strcmp(want->name, "anchors") == 0 ||
              strcmp(want->name, "nullifiers") == 0) &&
             !strstr(definition, "WITHOUT ROWID")) ||
            !canonical_table_columns(db, want)) {
            ok = false;
            break;
        }
    }
    if (ok)
        ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    sqlite3_finalize(st);
    if (!ok)
        return schema_fail(result,
                           "bundle schema is not the canonical closed set");

    if (sqlite3_prepare_v2(db, "SELECT count(*) FROM bundle_meta", -1,
                           &st, NULL) != SQLITE_OK)
        return schema_fail(result, "bundle_meta cardinality unavailable");
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    ok = rc == SQLITE_ROW && sqlite3_column_int64(st, 0) == 1 &&
         sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    sqlite3_finalize(st);
    if (!ok)
        return schema_fail(result, "bundle_meta must contain exactly one row");
    return true;
}
