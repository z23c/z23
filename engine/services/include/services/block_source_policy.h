/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_SERVICES_BLOCK_SOURCE_POLICY_H
#define ZCL_SERVICES_BLOCK_SOURCE_POLICY_H

#include "json/json.h"
#include "util/blocker.h"

#include <stdbool.h>
#include <stdint.h>

struct connman;
struct main_state;
struct node_db;

enum bsp_source {
    BSP_SOURCE_NONE = 0,
    BSP_SOURCE_P2P,
    BSP_SOURCE_SNAPSHOT,
    BSP_SOURCE_LOCAL_IMPORT,
    BSP_SOURCE_ZCLASSICD_MIRROR,
    BSP_SOURCE_NUM
};

enum bsp_decision_result {
    BSP_DECISION_WAIT = 0,
    BSP_DECISION_USE_SOURCE,
    BSP_DECISION_BLOCKED,
    BSP_DECISION_RECOVER,
    BSP_DECISION_NUM
};

struct bsp_source_status {
    enum bsp_source source;
    bool available;
    bool healthy;
    bool blocked;
    /* Typed classification of `blocked` for diagnostics, audit, and
     * future policy decisions. Blocked sources are not selected here;
     * PERMANENT blockers remain distinct from recoverable blockers in
     * status output and decision events. Mirror hash-disagreement stays
     * transient until the divergence locator proves a confirmed split. */
    enum blocker_class blocked_class;
    bool authorized;
    bool selectable;
    int height;
    int score;
    int score_base;
    int score_health;
    int score_height;
    int score_authorized;
    int score_redundancy_bonus;
    int score_target_lag_penalty;
    int score_failure_penalty;
    int score_mirror_gate_penalty;
    int64_t failures;
    int64_t timeouts;
    int64_t outbound_total;
    int64_t inbound_total;
    int64_t healthy_peers;
    int64_t inbound_healthy_peers;
    int64_t total_healthy_peers;
    int64_t connecting_peers;
    int64_t handshake_incomplete;
    int64_t inbound_handshake_incomplete;
    int64_t peer_groups;
    int64_t max_peer_group_size;
    int64_t healthy_peer_groups;
    int64_t healthy_max_peer_group_size;
    int64_t addnode_count;
    int64_t addnode_backoff_active;
    int64_t addnode_backoff_max_sec;
    int64_t addnode_tcp_failures;
    int64_t addnode_protocol_failures;
    int64_t progress_current;
    int64_t progress_total;
    int64_t lag;
    bool lag_known;
    bool lag_valid;
    int64_t retry_count;
    int64_t distinct_peer_count;
    int64_t serving_peer_id;
    char state[32];
    char selection_reason[64];
    char reason[384];
    char blocker[128];
};

struct bsp_plan_input {
    int local_height;
    int best_header_height;
    int target_height;
    int projection_height;
    int64_t projection_lag;
    bool projection_deferred;
    bool local_recovery_active;
    bool local_retries_exhausted;
    /* Concurrent-redundancy override: when mirror source is reachable
     * AND its lag >= mirror_lag_sla_breach_blocks, mirror_fallback_allowed
     * is true regardless of local_recovery_active / retries state. The
     * "wait for local exhaustion" gate must not block redundant catchup
     * once we've fallen demonstrably behind zclassicd. */
    int mirror_lag_sla_breach_blocks;
    char projection_state[32];
    struct bsp_source_status sources[BSP_SOURCE_NUM];
};

struct bsp_decision {
    enum bsp_decision_result result;
    enum bsp_source selected_source;
    bool activation_allowed;
    bool mirror_fallback_allowed;
    int local_height;
    int best_header_height;
    int target_height;
    int projection_height;
    int64_t projection_lag;
    bool projection_deferred;
    int64_t projection_deferred_total;
    int last_projection_deferred_height;
    int64_t last_projection_deferred_time;
    int selected_score;
    char projection_state[32];
    char last_projection_deferred_reason[64];
    char reason[128];
    char blocker[128];
    struct bsp_source_status sources[BSP_SOURCE_NUM];
};

const char *bsp_source_name(enum bsp_source source);
const char *bsp_source_trust_name(enum bsp_source source);
const char *bsp_decision_result_name(enum bsp_decision_result result);

void block_source_policy_plan(const struct bsp_plan_input *in,
                              struct bsp_decision *out);

/* Stateful block-source decision surface. This layer does not connect
 * blocks. It scores candidate advance sources (native P2P, snapshots,
 * local import, zclassicd mirror) and makes the trust/fallback decision
 * explicit before the lower-level chain_advance() path applies anything
 * through local consensus validation. */
void block_source_policy_init(struct connman *cm,
                              struct main_state *ms,
                              struct node_db *ndb);
bool block_source_policy_peer_floor_recovery_needed(
    int healthy_outbound,
    int min_healthy,
    int local_height,
    int peer_height,
    struct bsp_decision *out);
bool block_source_policy_snapshot_offer_allowed(
    int local_height,
    int snapshot_height,
    int peer_tip_height,
    bool offer_valid,
    const char *reason,
    struct bsp_decision *out);
bool block_source_policy_local_header_refill_needed(
    int local_height,
    int missing_height,
    int peer_height,
    int eligible_peers,
    int retry_count,
    bool retries_exhausted,
    struct bsp_decision *out);
void block_source_policy_note_projection_deferred(int height,
                                                  const char *reason);
void block_source_policy_get_status(struct bsp_decision *out);
bool block_source_policy_get_cached_status(struct bsp_decision *out);
/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
bool block_source_policy_dump_state_json(struct json_value *out,
                                         const char *key);
void block_source_policy_reset_for_test(void);

#endif /* ZCL_SERVICES_BLOCK_SOURCE_POLICY_H */
