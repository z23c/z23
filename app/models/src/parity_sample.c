/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * parity_sample model — see models/parity_sample.h. Retained, bounded
 * consensus-parity comparison history written by legacy_mirror_sync. */

#include "models/parity_sample.h"
#include "models/query_builder.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

DEFINE_MODEL_CALLBACKS(parity_sample)

bool db_parity_sample_validate(const struct db_parity_sample *s,
                               struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!s) {
        validates_custom(errors, false, "record", "null sample");
        return !ar_errors_any(errors);
    }
    validates_non_negative(errors, s, ts);
    validates_custom(errors, s->hash_equal == 0 || s->hash_equal == 1,
                     "hash_equal", "must be 0 or 1");
    validates_custom(errors, s->oracle_reachable == 0 || s->oracle_reachable == 1,
                     "oracle_reachable", "must be 0 or 1");
    return !ar_errors_any(errors);
}

bool db_parity_sample_save(struct node_db *ndb,
                           const struct db_parity_sample *s)
{
    if (!ndb || !ndb->open || !s) {
        LOG_FAIL("model", "db_parity_sample_save: bad args");
    }
    if (s->ts == 0)
        ((struct db_parity_sample *)s)->ts =
            (int64_t)platform_time_wall_unix();

    struct qb q;
    qb_insert(&q, QB_T_parity_samples, QB_INSERT_PLAIN);
    qb_value_int(&q, QB_C_parity_samples_ts, s->ts);
    qb_value_int(&q, QB_C_parity_samples_our_height, s->our_height);
    qb_value_int(&q, QB_C_parity_samples_oracle_height, s->oracle_height);
    qb_value_int(&q, QB_C_parity_samples_heights_equal_at,
                 s->heights_equal_at);
    qb_value_int(&q, QB_C_parity_samples_hash_equal, s->hash_equal);
    qb_value_int(&q, QB_C_parity_samples_oracle_reachable,
                 s->oracle_reachable);
    /* ar-lifecycle-ok:qb-adhoc-save-expands-to-AR_BEGIN_SAVE-and-AR_FINISH_SAVE */
    QB_ADHOC_SAVE(ndb, &q, stmt, db_parity_sample_callbacks(),
                  "parity_sample", s, db_parity_sample_validate);
}

bool db_parity_sample_prune(struct node_db *ndb, int keep_rows)
{
    if (!ndb || !ndb->open) {
        LOG_FAIL("model", "db_parity_sample_prune: bad args");
    }
    if (keep_rows < 0)
        keep_rows = 0;

    /* Keep the newest keep_rows ids, delete the rest. The inner SELECT is
     * itself built, so its LIMIT is a bound parameter too. */
    struct qb keep;
    qb_select(&keep, QB_T_parity_samples);
    qb_select_column(&keep, QB_C_parity_samples_id);
    qb_order_by(&keep, QB_C_parity_samples_id, QB_DESC);
    qb_limit(&keep, keep_rows);

    struct qb q;
    qb_delete(&q, QB_T_parity_samples);
    qb_where_in_select(&q, QB_C_parity_samples_id, true, &keep);
    QB_EXEC_BOOL(ndb, &q, stmt);
}

int db_parity_sample_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        return 0;
    struct qb q;
    qb_select(&q, QB_T_parity_samples);
    qb_select_count_star(&q);
    QB_QUERY_COUNT(ndb, &q, stmt);
}

int db_parity_sample_recent(struct node_db *ndb,
                            struct db_parity_sample *out, size_t max)
{
    if (!ndb || !ndb->open || !out || max == 0)
        return 0;
    struct qb q;
    qb_select(&q, QB_T_parity_samples);
    qb_select_column(&q, QB_C_parity_samples_ts);
    qb_select_column(&q, QB_C_parity_samples_our_height);
    qb_select_column(&q, QB_C_parity_samples_oracle_height);
    qb_select_column(&q, QB_C_parity_samples_heights_equal_at);
    qb_select_column(&q, QB_C_parity_samples_hash_equal);
    qb_select_column(&q, QB_C_parity_samples_oracle_reachable);
    qb_order_by(&q, QB_C_parity_samples_id, QB_DESC);
    qb_limit(&q, (int64_t)max);
    QB_QUERY_LIST(ndb, &q, stmt, out, max,
        out[count].ts = AR_COL_INT(stmt, 0);
        out[count].our_height = AR_COL_INT(stmt, 1);
        out[count].oracle_height = AR_COL_INT(stmt, 2);
        out[count].heights_equal_at = AR_COL_INT(stmt, 3);
        out[count].hash_equal = (int)AR_COL_INT(stmt, 4);
        out[count].oracle_reachable = (int)AR_COL_INT(stmt, 5));
}
