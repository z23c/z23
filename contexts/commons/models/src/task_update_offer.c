/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: persist inert task update proposals separately from acceptance. */
#include "models/task_update_offer.h"
#include "models/activerecord.h"
#include "models/query_builder.h"
#include "base/hex.h"
#include "util/ar_step_readonly.h"
#include "vcs/package_manifest.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(task_update_offer)

static bool tuo_identity_valid(const struct package_resident_identity *id)
{
    uint8_t digest[32];
    return id && memchr(id->package_root, 0, sizeof(id->package_root)) &&
        memchr(id->receipt_id, 0, sizeof(id->receipt_id)) &&
        memchr(id->artifact_sha3, 0, sizeof(id->artifact_sha3)) &&
        memchr(id->program, 0, sizeof(id->program)) &&
        zcl_hex_decode_lower(id->package_root, digest, sizeof(digest)) &&
        zcl_hex_decode_lower(id->receipt_id, digest, sizeof(digest)) &&
        zcl_hex_decode_lower(id->artifact_sha3, digest, sizeof(digest)) &&
        strncmp(id->program, "bin/", 4) == 0 && id->program[4] &&
        vcs_package_path_valid(id->program) &&
        id->configuration_generation >= 0;
}

static bool tuo_valid(const struct task_update_offer *row, struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_custom(errors, row && row->revision > 0 && tuo_identity_valid(&row->candidate),
        "offer", "must contain an exact candidate and positive revision");
    return !ar_errors_any(errors);
}

static struct zcl_result tuo_sql(struct package_resident_store *store, const char *sql)
{
    if (!store || !store->db || !store->app[0])
        return ZCL_ERR(-1, "task-offer: an open named application store is required");
    if (sqlite3_exec(store->db, sql, NULL, NULL, NULL) != SQLITE_OK)
        return ZCL_ERR(-1, "task-offer: %s", sqlite3_errmsg(store->db));
    return ZCL_OK;
}

static bool tuo_text(sqlite3_stmt *s, int column, char *out, size_t size)
{
    if (sqlite3_column_type(s, column) != SQLITE_TEXT) return false;
    const unsigned char *value = sqlite3_column_text(s, column);
    int n = sqlite3_column_bytes(s, column);
    if (!value || n < 0 || (size_t)n >= size || memchr(value, 0, (size_t)n)) return false;
    memcpy(out, value, (size_t)n); out[n] = 0;
    return true;
}

struct zcl_result task_update_offer_read(struct package_resident_store *store,
    struct task_update_offer *out)
{
    if (!out) return ZCL_ERR(-1, "task-offer: output is required");
    ZCL_CHECK(tuo_sql(store, qb_schema_sql(QB_S_task_update_offers_create)));
    struct qb q;
    qb_select(&q, QB_T_task_update_offers);
    const enum qb_column columns[] = { QB_C_task_update_offers_revision,
        QB_C_task_update_offers_dismissed, QB_C_task_update_offers_root,
        QB_C_task_update_offers_receipt, QB_C_task_update_offers_digest,
        QB_C_task_update_offers_program, QB_C_task_update_offers_config };
    qb_select_columns(&q, columns, sizeof(columns) / sizeof(columns[0]));
    qb_where_text(&q, QB_C_task_update_offers_app, QB_EQ, store->app);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(store, &q, s)) return ZCL_ERR(-1, "task-offer: read query refused");
    struct task_update_offer row = { .dismissed = true };
    int rc = AR_STEP_ROW_READONLY(s);
    bool valid = rc == SQLITE_DONE;
    if (rc == SQLITE_ROW) {
        int64_t dismissed = sqlite3_column_int64(s, 1);
        row.revision = sqlite3_column_int64(s, 0);
        row.dismissed = dismissed != 0;
        row.candidate.configuration_generation = sqlite3_column_int64(s, 6);
        valid = sqlite3_column_type(s, 0) == SQLITE_INTEGER &&
            sqlite3_column_type(s, 1) == SQLITE_INTEGER && (dismissed == 0 || dismissed == 1) &&
            sqlite3_column_type(s, 6) == SQLITE_INTEGER &&
            tuo_text(s, 2, row.candidate.package_root, sizeof(row.candidate.package_root)) &&
            tuo_text(s, 3, row.candidate.receipt_id, sizeof(row.candidate.receipt_id)) &&
            tuo_text(s, 4, row.candidate.artifact_sha3, sizeof(row.candidate.artifact_sha3)) &&
            tuo_text(s, 5, row.candidate.program, sizeof(row.candidate.program));
        struct ar_errors errors;
        valid = valid && tuo_valid(&row, &errors);
    }
    int finalized = sqlite3_finalize(s);
    if (!valid || finalized != SQLITE_OK) return ZCL_ERR(-1, "task-offer: malformed or unreadable proposal");
    *out = row;
    return ZCL_OK;
}

static bool tuo_save(struct package_resident_store *store, const struct task_update_offer *row)
{
    AR_BEGIN_SAVE(db_task_update_offer_callbacks(), "task_update_offer", row, tuo_valid);
    struct qb q;
    qb_insert(&q, QB_T_task_update_offers, QB_INSERT_PLAIN);
    qb_value_text(&q, QB_C_task_update_offers_app, store->app);
    qb_value_int(&q, QB_C_task_update_offers_revision, row->revision);
    qb_value_int(&q, QB_C_task_update_offers_dismissed, row->dismissed ? 1 : 0);
    qb_value_text(&q, QB_C_task_update_offers_root, row->candidate.package_root);
    qb_value_text(&q, QB_C_task_update_offers_receipt, row->candidate.receipt_id);
    qb_value_text(&q, QB_C_task_update_offers_digest, row->candidate.artifact_sha3);
    qb_value_text(&q, QB_C_task_update_offers_program, row->candidate.program);
    qb_value_int(&q, QB_C_task_update_offers_config, row->candidate.configuration_generation);
    const enum qb_column conflict[] = { QB_C_task_update_offers_app };
    qb_on_conflict_do_update(&q, conflict, 1);
    const enum qb_column updates[] = { QB_C_task_update_offers_revision, QB_C_task_update_offers_dismissed,
        QB_C_task_update_offers_root, QB_C_task_update_offers_receipt, QB_C_task_update_offers_digest,
        QB_C_task_update_offers_program, QB_C_task_update_offers_config };
    for (size_t i = 0; i < sizeof(updates) / sizeof(updates[0]); ++i) qb_conflict_set_excluded(&q, updates[i]);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(store, &q, s)) return false;
    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    AR_FINISH_SAVE(db_task_update_offer_callbacks(), row, ok);
}

static struct zcl_result tuo_apply(struct package_resident_store *store, int64_t expected,
    const struct package_resident_identity *candidate, struct task_update_offer *row)
{
    ZCL_CHECK(task_update_offer_read(store, row));
    if (row->revision != expected)
        return ZCL_ERR(TASK_UPDATE_OFFER_STALE, "task-offer: stale revision; reload proposal");
    if (!candidate && row->revision == 0)
        return ZCL_ERR(-1, "task-offer: no proposal to dismiss");
    ++row->revision;
    row->dismissed = candidate == NULL;
    if (candidate) row->candidate = *candidate;
    if (!tuo_save(store, row)) return ZCL_ERR(-1, "task-offer: save failed");
    return ZCL_OK;
}

static struct zcl_result tuo_change(struct package_resident_store *store, int64_t expected,
    const struct package_resident_identity *candidate, struct task_update_offer *out)
{
    if (!out || expected < 0 || expected == INT64_MAX || (candidate && !tuo_identity_valid(candidate)))
        return ZCL_ERR(-1, "task-offer: invalid revision or candidate");
    ZCL_CHECK(tuo_sql(store, qb_schema_sql(QB_S_task_update_offers_create)));
    ZCL_CHECK(tuo_sql(store, "BEGIN IMMEDIATE"));
    struct task_update_offer row;
    struct zcl_result result = tuo_apply(store, expected, candidate, &row);
    if (result.ok) result = tuo_sql(store, "COMMIT");
    if (!result.ok && !sqlite3_get_autocommit(store->db)) {
        struct zcl_result rollback = tuo_sql(store, "ROLLBACK");
        if (!rollback.ok) return rollback;
    }
    if (result.ok) *out = row;
    return result;
}

struct zcl_result task_update_offer_save(struct package_resident_store *store,
    int64_t expected_revision, const struct package_resident_identity *candidate, struct task_update_offer *out)
{
    if (!candidate) return ZCL_ERR(-1, "task-offer: candidate required");
    return tuo_change(store, expected_revision, candidate, out);
}

struct zcl_result task_update_offer_dismiss(struct package_resident_store *store,
    int64_t expected_revision, struct task_update_offer *out)
{
    return tuo_change(store, expected_revision, NULL, out);
}
