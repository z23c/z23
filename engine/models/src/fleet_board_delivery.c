/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fleet_board_delivery model — see models/fleet_board_delivery.h. A bounded,
 * replace-on-answer record of what each peer said about a pushed post. */

#include "models/fleet_board_delivery.h"
#include "models/model_fields.h"
#include "models/def/fleet_board_delivery_fields.def"
#include "models/query_builder.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

#include <string.h>

DEFINE_MODEL_CALLBACKS(fleet_board_delivery)

static const char *const k_verdict_names[FLEET_BOARD_DELIVERY_VERDICTS] = {
    "stored", "held", "deferred", "refused", "unknown",
};

const char *fleet_board_delivery_verdict_name(int64_t verdict)
{
    if (verdict < 0 || verdict >= FLEET_BOARD_DELIVERY_VERDICTS)
        return "unknown";
    return k_verdict_names[verdict];
}

static bool delivery_reason_ok(const char *reason)
{
    size_t n = strnlen(reason, FLEET_BOARD_DELIVERY_REASON_MAX + 1);
    if (n > FLEET_BOARD_DELIVERY_REASON_MAX)
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = reason[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'))
            return false;
    }
    return true;
}

static bool delivery_key_set(const uint8_t key[32])
{
    for (size_t i = 0; i < 32; i++)
        if (key[i])
            return true;
    return false;
}

bool db_fleet_board_delivery_validate(const struct db_fleet_board_delivery *d,
                                      struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!d) {
        validates_custom(errors, false, "record", "null delivery");
        return !ar_errors_any(errors);
    }
    validates_custom(errors, delivery_key_set(d->post_id), "post_id",
                     "must name a post");
    validates_custom(errors, delivery_key_set(d->peer), "peer",
                     "must name a peer");
    validates_range(errors, d, verdict, 0, FLEET_BOARD_DELIVERY_VERDICTS - 1);
    validates_custom(errors, delivery_reason_ok(d->reason), "reason",
                     "at most 40 bytes of a-z, 0-9 and _");
    validates_non_negative(errors, d, at);
    return !ar_errors_any(errors);
}

/* The verdict recorded for (post_id, peer): 1 found, 0 none, -1 unreadable. */
static int delivery_recorded(struct node_db *ndb, const uint8_t post_id[32],
                             const uint8_t peer[32], int64_t *verdict)
{
    struct qb q;
    qb_select(&q, QB_T_fleet_board_deliveries);
    qb_select_column(&q, QB_C_fleet_board_deliveries_verdict);
    qb_where_blob(&q, QB_C_fleet_board_deliveries_post_id, QB_EQ, post_id, 32);
    qb_where_blob(&q, QB_C_fleet_board_deliveries_peer, QB_EQ, peer, 32);
    qb_limit(&q, 1);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s)) {
        LOG_WARN("fleet.board", "delivery lookup prepare failed: %s", qb_error(&q));
        return -1;
    }
    enum zcl_step step = ar_step_checked(s, "fleet_board.delivery lookup", NULL);
    if (step == ZCL_STEP_ROW)
        *verdict = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    if (step == ZCL_STEP_ERROR)
        return -1;
    return step == ZCL_STEP_ROW ? 1 : 0;
}

/* Whether `d` would only weaken a known answer: "not now" or silence over a
 * peer's own "I have it". */
static bool delivery_would_downgrade(struct node_db *ndb,
                                     const struct db_fleet_board_delivery *d,
                                     bool *unreadable)
{
    *unreadable = false;
    if (d->verdict != FLEET_BOARD_DELIVERY_DEFERRED &&
        d->verdict != FLEET_BOARD_DELIVERY_UNKNOWN)
        return false;
    int64_t have = -1;
    int found = delivery_recorded(ndb, d->post_id, d->peer, &have);
    *unreadable = found < 0;
    return found == 1 && (have == FLEET_BOARD_DELIVERY_STORED ||
                          have == FLEET_BOARD_DELIVERY_HELD);
}

bool db_fleet_board_delivery_save(struct node_db *ndb,
                                  const struct db_fleet_board_delivery *d)
{
    if (!ndb || !ndb->open || !d) {
        LOG_FAIL("model", "db_fleet_board_delivery_save: bad args");
    }
    struct node_db_status status;
    node_db_get_status(ndb, &status);
    if (status.tx_open)
        return false; // raw-return-ok:caller-keeps-the-note-and-retries
    bool unreadable = false;
    if (delivery_would_downgrade(ndb, d, &unreadable))
        return true; // raw-return-ok:a-known-stored-or-held-answer-is-kept
    if (unreadable)
        return false; // raw-return-ok:lookup-failed-caller-counts-a-dropped-note
    struct ar_callbacks *cbs = db_fleet_board_delivery_callbacks();
    struct qb q;
    qb_insert(&q, QB_T_fleet_board_deliveries, QB_INSERT_OR_REPLACE);
    qb_value_blob(&q, QB_C_fleet_board_deliveries_post_id, d->post_id, 32);
    qb_value_blob(&q, QB_C_fleet_board_deliveries_peer, d->peer, 32);
    qb_value_int(&q, QB_C_fleet_board_deliveries_verdict, d->verdict);
    qb_value_text(&q, QB_C_fleet_board_deliveries_reason, d->reason);
    qb_value_int(&q, QB_C_fleet_board_deliveries_at, d->at);
    /* ar-lifecycle-ok:qb-adhoc-save-expands-to-AR_BEGIN_SAVE-and-AR_FINISH_SAVE */
    QB_ADHOC_SAVE(ndb, &q, s, cbs, "fleet_board_delivery", d,
                  db_fleet_board_delivery_validate);
}

bool db_fleet_board_delivery_prune(struct node_db *ndb, int keep)
{
    if (!ndb || !ndb->open) {
        LOG_FAIL("model", "db_fleet_board_delivery_prune: bad args");
    }
    if (keep < 1)
        keep = 1;
    struct qb cut;
    qb_select(&cut, QB_T_fleet_board_deliveries);
    qb_select_column(&cut, QB_C_fleet_board_deliveries_at);
    qb_order_by(&cut, QB_C_fleet_board_deliveries_at, QB_DESC);
    qb_limit(&cut, 1);
    qb_offset(&cut, keep - 1);

    struct qb q;
    qb_delete(&q, QB_T_fleet_board_deliveries);
    qb_where_scalar_select(&q, QB_C_fleet_board_deliveries_at, QB_LT, &cut);
    QB_EXEC_BOOL(ndb, &q, s);
}

int db_fleet_board_delivery_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        return 0;
    struct qb q;
    qb_select(&q, QB_T_fleet_board_deliveries);
    qb_select_count_star(&q);
    QB_QUERY_COUNT(ndb, &q, s);
}

#define DELIVERY_QB_COLUMN(kind, col, member, extra) ZCL_MF_CAT(QB_C_fleet_board_deliveries_, col),
static const enum qb_column k_delivery_cols[] = {
    ZCL_MODEL_EXPAND(DELIVERY_QB_COLUMN, FLEET_BOARD_DELIVERY_FIELDS)
};

ZCL_MODEL_READ_ROW_FN(delivery_row_read, struct db_fleet_board_delivery,
                      FLEET_BOARD_DELIVERY_FIELDS)

int db_fleet_board_delivery_for_post(struct node_db *ndb,
                                     const uint8_t post_id[32],
                                     struct db_fleet_board_delivery *out,
                                     size_t max)
{
    if (!ndb || !ndb->open || !post_id || !out || max == 0)
        return -1;
    if (max > FLEET_BOARD_DELIVERY_PEERS_MAX)
        max = FLEET_BOARD_DELIVERY_PEERS_MAX;
    struct qb q;
    qb_select(&q, QB_T_fleet_board_deliveries);
    qb_select_columns(&q, k_delivery_cols,
                      sizeof(k_delivery_cols) / sizeof(k_delivery_cols[0]));
    qb_where_blob(&q, QB_C_fleet_board_deliveries_post_id, QB_EQ, post_id, 32);
    qb_order_by(&q, QB_C_fleet_board_deliveries_at, QB_DESC);
    qb_limit(&q, (int64_t)max);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s)) {
        LOG_WARN("fleet.board", "delivery read prepare failed: %s", qb_error(&q));
        return -1;
    }
    int n = 0;
    enum zcl_step step = ZCL_STEP_DONE;
    while ((size_t)n < max &&
           (step = ar_step_checked(s, "fleet_board.delivery read", NULL)) ==
               ZCL_STEP_ROW)
        delivery_row_read(&out[n++], s);
    sqlite3_finalize(s);
    if (step == ZCL_STEP_ERROR) {
        LOG_WARN("fleet.board", "delivery read failed part-way");
        return -1;
    }
    return n;
}
