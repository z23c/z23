/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef ZCL_AGENT_HEIGHT_CONTRACT_H
#define ZCL_AGENT_HEIGHT_CONTRACT_H

#include <stdint.h>

struct json_value;

struct agent_height_contract_input {
    int64_t served_tip_height;
    int64_t active_tip_height;
    int64_t header_tip_height;
    int64_t peer_best_height;
    int64_t target_height;
    int64_t served_gap_blocks;
    int64_t reducer_log_head;
    int64_t reducer_log_head_gap_blocks;
};

void agent_push_height_contract_json(
    struct json_value *out,
    const char *key,
    const struct agent_height_contract_input *in);

void agent_push_height_contract_fields_json(
    struct json_value *out,
    const char *key,
    int64_t served_tip_height,
    int64_t active_tip_height,
    int64_t header_tip_height,
    int64_t peer_best_height,
    int64_t target_height,
    int64_t served_gap_blocks,
    int64_t reducer_log_head,
    int64_t reducer_log_head_gap_blocks);

#endif /* ZCL_AGENT_HEIGHT_CONTRACT_H */
