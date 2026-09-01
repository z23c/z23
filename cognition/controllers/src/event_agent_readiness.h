#ifndef ZCL_EVENT_AGENT_READINESS_H
#define ZCL_EVENT_AGENT_READINESS_H

#include <stdbool.h>

struct json_value;

/* The tip-following axis of readiness, ALONE: is the node's proven height
 * within warn-lag of the network tip, and has its reducer log caught up to
 * that height? A height-vs-tip comparison and nothing else — deliberately
 * free of serving / peers / operator terms, and deliberately free of any
 * archive-completeness term. A complete block archive is ~13 GB while the
 * cold-sync budget moves a couple of hundred MB, so folding archive
 * completeness in here would make tip-following unreachable by arithmetic.
 *
 * `log_head_gap < 0` means "unknown" and does not by itself deny
 * tip-following. This is the single definition; chain_serving_ready() is
 * this predicate ANDed with the serving/peers/operator terms. */
bool agent_tip_follow(int gap, int log_head_gap);

void agent_push_readiness_json(struct json_value *out, const char *key,
                               bool serving, bool has_peers,
                               bool operator_needed,
                               bool validation_pack_ok, int gap,
                               int index_gap, int log_head_gap);

void agent_push_readiness_fields_json(struct json_value *out,
                                      bool serving, bool has_peers,
                                      bool operator_needed,
                                      bool validation_pack_ok, int gap,
                                      int index_gap, int log_head_gap);

/* The full readiness surface for a zcl.public_status.v3 producer: the flat
 * readiness fields, the nested zcl.agent_readiness.v1 object, AND the
 * separately named readiness facts (tip_follow, wallet_view_ready,
 * wallet_spend_allowed, archive_complete, full_replay_verified — see
 * controllers/agent_operator_contracts.h). `posture` may be NULL, which
 * leaves full_replay_verified at its fail-closed false. */
struct agent_security_posture;

void agent_push_readiness_contract_json(struct json_value *out,
                                        const char *key,
                                        bool serving, bool has_peers,
                                        bool operator_needed,
                                        bool validation_pack_ok, int gap,
                                        int index_gap, int log_head_gap,
                                        const struct agent_security_posture *posture);

#endif /* ZCL_EVENT_AGENT_READINESS_H */
