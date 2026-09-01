/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "event_agent_readiness.h"

#include "controllers/agent_operator_contracts.h"
#include "json/json.h"
#include "services/node_health_service.h"

struct agent_readiness_view {
    const char *status;
    const char *next_action;
    bool chain_ready;
    bool index_ready;
    bool agent_work_ready;
};

bool agent_tip_follow(int gap, int log_head_gap)
{
    return gap <= ZCL_NODE_HEALTH_LAG_WARN_BLOCKS &&
           (log_head_gap < 0 || log_head_gap <= 1);
}

static bool chain_serving_ready(bool serving, bool has_peers,
                                bool operator_needed, int gap,
                                int log_head_gap)
{
    return serving && has_peers && !operator_needed &&
           agent_tip_follow(gap, log_head_gap);
}

static bool index_projection_ready(bool serving, bool has_peers,
                                   bool operator_needed, int gap,
                                   int index_gap, int log_head_gap)
{
    if (index_gap < 0)
        return false;
    return chain_serving_ready(serving, has_peers, operator_needed, gap,
                               log_head_gap) &&
           index_gap <= ZCL_NODE_HEALTH_LAG_WARN_BLOCKS;
}

static const char *readiness_status(bool serving, bool has_peers,
                                    bool operator_needed, int gap,
                                    int index_gap, int log_head_gap)
{
    if (!chain_serving_ready(serving, has_peers, operator_needed, gap,
                             log_head_gap))
        return "not_serving";
    if (!index_projection_ready(serving, has_peers, operator_needed, gap,
                                index_gap, log_head_gap))
        return "serving_projection_deferred";
    return "ready";
}

static const char *readiness_next_action(bool serving, bool has_peers,
                                         bool operator_needed, int gap,
                                         int index_gap, int log_head_gap)
{
    if (operator_needed)
        return "operator_intervention_required";
    if (!chain_serving_ready(serving, has_peers, operator_needed, gap,
                             log_head_gap))
        return "restore_chain_serving";
    if (!index_projection_ready(serving, has_peers, operator_needed, gap,
                                index_gap, log_head_gap))
        return "continue_chain_ops_inspect_indexer_if_needed";
    return "none";
}

static struct agent_readiness_view readiness_view(bool serving, bool has_peers,
                                                  bool operator_needed,
                                                  bool validation_pack_ok,
                                                  int gap, int index_gap,
                                                  int log_head_gap)
{
    struct agent_readiness_view view = {0};
    view.chain_ready = chain_serving_ready(serving, has_peers,
                                           operator_needed, gap,
                                           log_head_gap);
    view.index_ready = index_projection_ready(serving, has_peers,
                                              operator_needed, gap,
                                              index_gap, log_head_gap);
    view.agent_work_ready = view.chain_ready && validation_pack_ok;
    view.status = readiness_status(serving, has_peers, operator_needed,
                                   gap, index_gap, log_head_gap);
    view.next_action = readiness_next_action(serving, has_peers,
                                             operator_needed, gap,
                                             index_gap, log_head_gap);
    return view;
}

void agent_push_readiness_fields_json(struct json_value *out,
                                      bool serving, bool has_peers,
                                      bool operator_needed,
                                      bool validation_pack_ok, int gap,
                                      int index_gap, int log_head_gap)
{
    if (!out)
        return;

    const struct agent_readiness_view view =
        readiness_view(serving, has_peers, operator_needed,
                       validation_pack_ok, gap, index_gap, log_head_gap);
    json_push_kv_str(out, "readiness_status", view.status);
    json_push_kv_bool(out, "chain_serving_ready", view.chain_ready);
    json_push_kv_bool(out, "index_projection_ready", view.index_ready);
    json_push_kv_bool(out, "agent_work_ready", view.agent_work_ready);
    json_push_kv_bool(out, "operator_action_required", operator_needed);
    json_push_kv_str(out, "readiness_next_action", view.next_action);
}

void agent_push_readiness_json(struct json_value *out, const char *key,
                               bool serving, bool has_peers,
                               bool operator_needed,
                               bool validation_pack_ok, int gap,
                               int index_gap, int log_head_gap)
{
    if (!out)
        return;

    const struct agent_readiness_view view =
        readiness_view(serving, has_peers, operator_needed,
                       validation_pack_ok, gap, index_gap, log_head_gap);
    struct json_value obj = {0};
    json_set_object(&obj);
    json_push_kv_str(&obj, "schema", "zcl.agent_readiness.v1");
    json_push_kv_int(&obj, "schema_version", 1);
    json_push_kv_str(&obj, "status", view.status);
    json_push_kv_bool(&obj, "chain_serving_ready", view.chain_ready);
    json_push_kv_bool(&obj, "index_projection_ready", view.index_ready);
    json_push_kv_bool(&obj, "agent_work_ready", view.agent_work_ready);
    json_push_kv_bool(&obj, "operator_action_required", operator_needed);
    json_push_kv_int(&obj, "tip_gap_blocks", gap);
    json_push_kv_int(&obj, "index_gap_blocks", index_gap);
    json_push_kv_int(&obj, "reducer_log_gap_blocks", log_head_gap);
    json_push_kv_str(&obj, "next_action", view.next_action);
    json_push_kv_str(&obj, "semantics",
                     "chain_serving_ready excludes index projection lag; use index_projection_ready for explorer/projection freshness");
    json_push_kv(out, key && key[0] ? key : "readiness", &obj);
    json_free(&obj);
}

void agent_push_readiness_contract_json(struct json_value *out,
                                        const char *key,
                                        bool serving, bool has_peers,
                                        bool operator_needed,
                                        bool validation_pack_ok, int gap,
                                        int index_gap, int log_head_gap,
                                        const struct agent_security_posture *posture)
{
    struct status_readiness_facts_view facts;

    if (!out)
        return;

    agent_push_readiness_fields_json(out, serving, has_peers,
                                     operator_needed, validation_pack_ok,
                                     gap, index_gap, log_head_gap);
    agent_push_readiness_json(out, key, serving, has_peers, operator_needed,
                              validation_pack_ok, gap, index_gap,
                              log_head_gap);
    /* The separately named facts. tip_follow rides the SAME gap numbers the
     * readiness object above already reports, so the two can never disagree;
     * archive_complete is deliberately not one of gap's inputs. */
    status_readiness_facts_collect(gap, log_head_gap, posture, &facts);
    status_push_readiness_facts_json(out, &facts);
}
