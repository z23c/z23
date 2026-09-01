/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * peer_chain_observation model — see models/peer_chain_observation.h. Retained,
 * bounded per-peer chain-intelligence history written by the network monitor.
 * Observational only; never read by consensus. */

#include "models/peer_chain_observation.h"
#include "models/model_text.h"
#include "models/query_builder.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <string.h>

DEFINE_MODEL_CALLBACKS(peer_chain_observation)

/* The read projection, in the order the row reader below consumes it. */
static const enum qb_column k_pco_cols[] = {
    QB_C_peer_chain_observations_peer_id,
    QB_C_peer_chain_observations_addr,
    QB_C_peer_chain_observations_user_agent,
    QB_C_peer_chain_observations_version,
    QB_C_peer_chain_observations_best_height,
    QB_C_peer_chain_observations_tip_hash,
    QB_C_peer_chain_observations_latency_us,
    QB_C_peer_chain_observations_inbound,
    QB_C_peer_chain_observations_first_seen,
    QB_C_peer_chain_observations_last_seen,
    QB_C_peer_chain_observations_observed_at,
};
#define K_PCO_NCOLS (sizeof(k_pco_cols) / sizeof(k_pco_cols[0]))

static bool peer_chain_observation_before_validate(void *record, void *ctx)
{
    struct db_peer_chain_observation *o = record;
    (void)ctx;
    if (!o)
        return false;
    model_trim_ascii(o->addr);
    model_trim_ascii(o->user_agent);
    model_trim_ascii(o->tip_hash);
    model_ascii_downcase(o->tip_hash);
    return true;
}

static struct ar_callbacks *peer_chain_observation_callbacks_ready(void)
{
    struct ar_callbacks *cbs = db_peer_chain_observation_callbacks();
    static bool hooks_done = false;
    if (!hooks_done) {
        ar_register_before_validate(cbs, peer_chain_observation_before_validate);
        hooks_done = true;
    }
    return cbs;
}

bool db_peer_chain_observation_validate(const struct db_peer_chain_observation *o,
                                        struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!o) {
        validates_custom(errors, false, "record", "null observation");
        return !ar_errors_any(errors);
    }
    validates_non_negative(errors, o, observed_at);
    validates_custom(errors, strlen(o->addr) <= PEER_OBS_ADDR_MAX,
                     "addr", "exceeds max length");
    validates_custom(errors, strlen(o->user_agent) <= PEER_OBS_UA_MAX,
                     "user_agent", "exceeds max length");
    validates_custom(errors, strlen(o->tip_hash) <= PEER_OBS_TIP_HEX,
                     "tip_hash", "exceeds max length");
    validates_custom(errors,
                     model_string_is_printable(o->addr),
                     "addr", "contains non-printable characters");
    validates_custom(errors,
                     model_string_is_printable(o->user_agent),
                     "user_agent", "contains non-printable characters");
    validates_custom(errors,
                     o->tip_hash[0] == '\0' || model_string_is_printable(o->tip_hash),
                     "tip_hash", "contains non-printable characters");
    return !ar_errors_any(errors);
}

bool db_peer_chain_observation_save(struct node_db *ndb,
                                    const struct db_peer_chain_observation *o)
{
    struct ar_callbacks *cbs;

    if (!ndb || !ndb->open || !o) {
        LOG_FAIL("model", "db_peer_chain_observation_save: bad args");
    }
    if (o->observed_at == 0)
        ((struct db_peer_chain_observation *)o)->observed_at =
            (int64_t)platform_time_wall_time_t();

    cbs = peer_chain_observation_callbacks_ready();
    struct qb q;
    qb_insert(&q, QB_T_peer_chain_observations, QB_INSERT_PLAIN);
    qb_value_int(&q, QB_C_peer_chain_observations_peer_id, o->peer_id);
    qb_value_text(&q, QB_C_peer_chain_observations_addr, o->addr);
    qb_value_text(&q, QB_C_peer_chain_observations_user_agent, o->user_agent);
    qb_value_int(&q, QB_C_peer_chain_observations_version, o->version);
    qb_value_int(&q, QB_C_peer_chain_observations_best_height,
                 o->best_height);
    qb_value_text(&q, QB_C_peer_chain_observations_tip_hash, o->tip_hash);
    qb_value_int(&q, QB_C_peer_chain_observations_latency_us, o->latency_us);
    qb_value_int(&q, QB_C_peer_chain_observations_inbound, o->inbound);
    qb_value_int(&q, QB_C_peer_chain_observations_first_seen, o->first_seen);
    qb_value_int(&q, QB_C_peer_chain_observations_last_seen, o->last_seen);
    qb_value_int(&q, QB_C_peer_chain_observations_observed_at,
                 o->observed_at);
    /* ar-lifecycle-ok:qb-adhoc-save-expands-to-AR_BEGIN_SAVE-and-AR_FINISH_SAVE */
    QB_ADHOC_SAVE(ndb, &q, s, cbs, "peer_chain_observation", o,
                  db_peer_chain_observation_validate);
}

bool db_peer_chain_observation_prune(struct node_db *ndb, int keep_rows)
{
    if (!ndb || !ndb->open) {
        LOG_FAIL("model", "db_peer_chain_observation_prune: bad args");
    }
    if (keep_rows < 0)
        keep_rows = 0;

    struct qb keep;
    qb_select(&keep, QB_T_peer_chain_observations);
    qb_select_column(&keep, QB_C_peer_chain_observations_id);
    qb_order_by(&keep, QB_C_peer_chain_observations_id, QB_DESC);
    qb_limit(&keep, keep_rows);

    struct qb q;
    qb_delete(&q, QB_T_peer_chain_observations);
    qb_where_in_select(&q, QB_C_peer_chain_observations_id, true, &keep);
    QB_EXEC_BOOL(ndb, &q, s);
}

int db_peer_chain_observation_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        return 0;
    struct qb q;
    qb_select(&q, QB_T_peer_chain_observations);
    qb_select_count_star(&q);
    QB_QUERY_COUNT(ndb, &q, s);
}

int db_peer_chain_observation_recent(struct node_db *ndb,
                                     struct db_peer_chain_observation *out,
                                     size_t max)
{
    if (!ndb || !ndb->open || !out || max == 0)
        return 0;
    struct qb q;
    qb_select(&q, QB_T_peer_chain_observations);
    qb_select_columns(&q, k_pco_cols, K_PCO_NCOLS);
    qb_order_by(&q, QB_C_peer_chain_observations_id, QB_DESC);
    qb_limit(&q, (int64_t)max);
    QB_QUERY_LIST(ndb, &q, s, out, max,
        out[count].peer_id = AR_COL_INT(s, 0);
        AR_READ_STR(s, 1, out[count].addr, sizeof(out[count].addr));
        AR_READ_STR(s, 2, out[count].user_agent, sizeof(out[count].user_agent));
        out[count].version = (int)AR_COL_INT(s, 3);
        out[count].best_height = AR_COL_INT(s, 4);
        AR_READ_STR(s, 5, out[count].tip_hash, sizeof(out[count].tip_hash));
        out[count].latency_us = AR_COL_INT(s, 6);
        out[count].inbound = (int)AR_COL_INT(s, 7);
        out[count].first_seen = AR_COL_INT(s, 8);
        out[count].last_seen = AR_COL_INT(s, 9);
        out[count].observed_at = AR_COL_INT(s, 10));
}
