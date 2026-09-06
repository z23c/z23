/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `fleet.triggers` leaves and the closed registry they read,
 * plus the run-once evaluator shared by the CLI and its tests. */

#ifndef ZCL_NATIVE_FLEET_TRIGGERS_H
#define ZCL_NATIVE_FLEET_TRIGGERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct zcl_command_request;
struct zcl_command_reply;
struct json_value;

/* ── registry (engine/composition/triggers.def) ─────────────────────── */

enum zcl_trigger_source {
    ZCL_TRIGGER_SOURCE_LANDING = 0,
    ZCL_TRIGGER_SOURCE_BOARD,
    ZCL_TRIGGER_SOURCE_EXPERIMENT,
};

enum zcl_trigger_op {
    ZCL_TRIGGER_OP_EQ = 0,
    ZCL_TRIGGER_OP_NE,
    ZCL_TRIGGER_OP_PREFIX,
    ZCL_TRIGGER_OP_CONTAINS,
};

enum zcl_trigger_action {
    ZCL_TRIGGER_ACTION_PRINT = 0,
    ZCL_TRIGGER_ACTION_LEDGER,
};

struct zcl_trigger_row {
    const char *id;
    enum zcl_trigger_source source;
    const char *source_name;
    const char *field;
    enum zcl_trigger_op op;
    const char *op_name;
    const char *value;
    enum zcl_trigger_action action;
    const char *action_name;
    const char *why;
};

size_t zcl_trigger_count(void);
/* NULL if index is out of range. */
const struct zcl_trigger_row *zcl_trigger_at(size_t index);

/* ── row-source paths (shared with tests as the layout oracle) ───────── */

bool zcl_trigger_landing_path(char *out, size_t cap);
bool zcl_trigger_board_path(char *out, size_t cap);
bool zcl_trigger_experiment_path(char *out, size_t cap);
bool zcl_trigger_fired_ledger_path(char *out, size_t cap);
bool zcl_trigger_cursor_path(const char *source_name, char *out, size_t cap);

/* ── run-once evaluator ───────────────────────────────────────────────
 * Reads every new row of every source since its cursor, evaluates every
 * trigger whose source matches, performs the matched action, and (unless
 * dry_run) advances the cursor past the rows it read. since_s is a UTC
 * unix floor: a row whose own timestamp field parses older than it is
 * skipped and not counted as checked. Returns false only on an
 * unrecoverable local error (out_why names it); a source that is simply
 * absent is not an error and contributes zero rows. */
bool zcl_trigger_check_run(bool dry_run, int64_t since_s,
                          uint64_t *out_checked, uint64_t *out_fired,
                          struct json_value *out_fired_ids /* array, or NULL */,
                          char *out_why, size_t out_why_cap);

/* ── CLI leaves (bound in engine/composition/commands/fleet.def) ─────── */

void zcl_native_handle_fleet_triggers_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_triggers_check(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

#endif /* ZCL_NATIVE_FLEET_TRIGGERS_H */
