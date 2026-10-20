/* purpose: Share the renewal plan state between the pair.renew planner and its executor. */
/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef ZCL_TOOLS_NATIVE_PAIR_RENEW_H
#define ZCL_TOOLS_NATIVE_PAIR_RENEW_H

#include "command/native_pair_common.h"
#include "json/json.h"

struct pr_cfg {
    char state[PAIR_PATH_MAX], hub_state[PAIR_PATH_MAX], hub_config[PAIR_PATH_MAX];
    char evidence[PAIR_PATH_MAX], slot_bin[PAIR_PATH_MAX], unit_file[PAIR_PATH_MAX];
    char peer[PAIR_NAME_MAX], plan_id[65];
    uint64_t before_s;
    uint32_t grant_days;
    bool confirm, force, fault, have_plan_id;
};

struct pr_state {
    uint64_t now;
    struct pair_epoch cur;
    uint32_t next;
    bool hub_known, due, evidence_checked, evidence_current, unit_checked, unit_match;
    char hub_dir[PAIR_PATH_MAX], hub_profile[PAIR_PATH_MAX];
    uint8_t client_key[32], hub_root[32];
    struct json_value client_route, hub_route; /* epoch N route files, owned */
    char slot_name[24], slot_sha[65], evidence_real[PAIR_PATH_MAX];
    char plan_id[65];
};

void pr_state_free(struct pr_state *state);
/* Typed refusal: nothing was created unless mutated is true. */
void pr_fail(struct zcl_command_reply *reply, const char *code, const char *phase, const char *message, bool mutated);
/* Invoke one registered leaf in-process exactly as dispatch would. True iff it PASSED. */
bool pr_leaf(const char *path, const struct json_value *input, struct zcl_command_reply *reply);
/* Create epoch N+1, smoke it, retire N; fills reply with the result or a typed failure. */
void pair_renew_execute(const struct pr_cfg *cfg, const struct pr_state *state, struct zcl_command_reply *reply);
#endif
