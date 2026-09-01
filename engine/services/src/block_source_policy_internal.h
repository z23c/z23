/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* Internal shared surface for the block-source policy stateful runtime.
 *
 * The stateful decision surface is owned by cohesive sibling .c files:
 *   - block_source_policy_runtime.c   : live state, lifecycle, runtime-input
 *                                        builder, projection-deferral counter
 *   - block_source_policy_persist.c   : node.db persist/restore of decisions
 *   - block_source_policy_decisions.c : decision predicates + event/record
 *   - block_source_policy_status.c    : status read + dump-state JSON dumper
 *
 * This header declares only the symbols that cross those file boundaries.
 * The public API stays in services/block_source_policy.h, unchanged. */

#ifndef ZCL_SERVICES_BLOCK_SOURCE_POLICY_INTERNAL_H
#define ZCL_SERVICES_BLOCK_SOURCE_POLICY_INTERNAL_H

#include "services/block_source_policy.h"
#include "util/result.h"
#include "util/sync.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;

/* The single live decision-surface state. Defined in
 * block_source_policy_runtime.c; touched by all four sibling files. */
extern struct bsp_state {
    zcl_mutex_t lock;
    bool lock_init;
    struct connman *connman;
    struct main_state *main_state;
    struct node_db *node_db;
    struct bsp_decision last;
    bool has_last;
    int64_t last_decision_time;
    char last_op[32];
    int64_t decisions_total;
    int64_t projection_deferred_total;
    int last_projection_deferred_height;
    int64_t last_projection_deferred_time;
    char last_projection_deferred_reason[64];
    /* Wall-clock of the last projection-deferral KV/event persist; the
     * in-memory counters above update on every note, the disk mirror and
     * diagnostic event are throttled to one persist per
     * BSP_PROJECTION_DEFERRED_PERSIST_INTERVAL_SECS (see the note fn). */
    int64_t last_projection_deferred_persist;
} g_bsp;

void bsp_lock_init_once(void);
void bsp_copy_text(char *dst, size_t dst_len, const char *src);

/* Persistence seam (block_source_policy_persist.c). node.db writes are a
 * genuine error channel (the disk mirror can fail); these carry the failure
 * reason via struct zcl_result rather than swallowing it. The persisted
 * state is a best-effort mirror of in-memory decision state, so callers log
 * a non-ok result but do not change the decision (DEFENSIVE_CODING.md §2). */
struct zcl_result bsp_persist_decision(struct node_db *ndb, const char *op,
                                       const struct bsp_decision *d,
                                       int64_t when, int64_t total);
struct zcl_result bsp_restore_decision(struct node_db *ndb);
struct zcl_result bsp_restore_projection_deferral(struct node_db *ndb);

/* Decision seam (block_source_policy_decisions.c). Records the decision in
 * memory and mirrors it to node.db; returns the persist result so a failed
 * disk write is logged with context (the decision itself never fails). */
struct zcl_result bsp_record_decision(const char *op,
                                      const struct bsp_decision *d);
const char *bsp_source_class_name(enum bsp_source source);

/* Runtime seam (block_source_policy_runtime.c). */
void bsp_build_runtime_input(struct bsp_plan_input *in);
void bsp_enrich_projection_deferral(struct bsp_decision *d);
enum blocker_class bsp_classify_mirror_blocker_class(const char *code);

/* Status seam (block_source_policy_status.c). */
void bsp_source_to_json(const struct bsp_source_status *s,
                        struct json_value *out);
void bsp_decision_to_json(const struct bsp_decision *d,
                          struct json_value *out);

#endif /* ZCL_SERVICES_BLOCK_SOURCE_POLICY_INTERNAL_H */
