/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: private retained experiment event and its stats/export seams. */
#ifndef ZCL_FLEET_LEDGER_EXPERIMENT_H
#define ZCL_FLEET_LEDGER_EXPERIMENT_H
#include "fleetledger/fleet_ledger.h"

#define FLEET_EXPERIMENT_EVENTS_MAX 1024u

struct fleet_experiment_event {
    uint8_t phase;
    uint8_t task_class;
    uint8_t model;
    uint8_t outcome;
    uint8_t note_len;
    bool have_tokens;
    bool have_wall;
    char note[ZCL_FLEET_NOTE_MAX];
    int64_t tokens;
    int64_t wall_s;

    /* Everything export needs beyond what stats groups by. Kept on the
     * SAME retained event rather than a second array: one row, one place
     * it lives in memory. */
    int64_t ts_unix;
    uint8_t box_id[ZCL_FLEET_ID_BYTES];
    uint8_t story_len;
    char story[ZCL_FLEET_STORY_MAX];
    bool have_executor;
    uint8_t executor;
    bool have_harness;
    uint8_t harness;
    bool have_effort;
    uint8_t effort;
    bool have_tokens_in;        int64_t tokens_in;
    bool have_tokens_out;       int64_t tokens_out;
    bool have_tokens_cache;     int64_t tokens_cache;
    bool have_tokens_reasoning; int64_t tokens_reasoning;
    bool have_tool_uses;        int64_t tool_uses;
    bool have_turns;            int64_t turns;
    bool have_lines_added;      int64_t lines_added;
    bool have_lines_removed;    int64_t lines_removed;
    bool have_defects;          int64_t defects;
};

/* Group the retained events by (task_class, model) into out, summarise
 * each group and sort them. *unmatched counts results with no predict. */
enum zcl_fleet_status fleet_experiment_groups(
    const struct fleet_experiment_event *ev, uint32_t n,
    struct zcl_fleet_experiment_group *out, size_t cap, size_t *count,
    uint64_t *unmatched);

/* Copy the events at or after since_unix (optionally of one box) to out. */
enum zcl_fleet_status fleet_experiment_rows(
    const struct fleet_experiment_event *ev, uint32_t n, int64_t since_unix,
    const uint8_t box_id[ZCL_FLEET_ID_BYTES], bool have_box,
    struct zcl_fleet_experiment_row *out, size_t cap, size_t *count);
#endif
