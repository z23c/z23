/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: One local answer to "what is every AI agent on this box doing, and
 *          how has each one graded out?" — the collectors behind
 *          `z23-dev fleet agents`. */

#ifndef ZCL_NATIVE_DEV_AGENTS_H
#define ZCL_NATIVE_DEV_AGENTS_H

#include "command/native_command.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_AGENTS_SCHEMA "zcl.fleet_agents.v1"
#define ZCL_AGENTS_PATH_MAX 4096

/* Rows a single answer will ever carry. Both are transport bounds, not
 * survey bounds: the scan counts everything it finds and reports the total
 * beside the rows it had room to print, so nothing is dropped silently. */
#define ZCL_AGENTS_MAX_WORKSPACE_ROWS 12u
#define ZCL_AGENTS_MAX_GRADE_ROWS 12u
#define ZCL_AGENTS_MAX_UNIT_ROWS 12u
#define ZCL_AGENTS_MAX_PROCESS_ROWS 4u
#define ZCL_AGENTS_TEXT_MAX 6144u

/* The honest line about every machine that is not this one. */
#define ZCL_AGENTS_OTHER_HOSTS_NOTE \
    "other hosts: not collected yet (fleet board transport is the next slice)"

/* One call's inputs. Every path is overridable so the tests can drive the
 * whole command against a fixture tree and a fixture ledger, and `now_unix`
 * is passed in rather than read here so no verdict in this file or its tests
 * is decided by a reading of a real clock. */
struct zcl_agents_options {
    const char *root;        /* workspace root; NULL selects $HOME/.z23 */
    const char *ledger;      /* delegation ledger TSV; NULL selects the default */
    const char *group_by;    /* "executor" (default), "lane", or "class" */
    int64_t since_hours;     /* result-row window; 0 means the whole ledger */
    int64_t now_unix;        /* the caller's "now", in unix seconds */
    bool collect_units;      /* read systemd user units */
};

/* Fill `out` with the `running` and `units` sections: one row per agent
 * workspace under the root, newest activity first. Never fails — a root that
 * does not exist is an empty, `state: "unavailable"` section, because "no
 * agents are working here" is a real answer. */
void zcl_agents_running_json(const struct zcl_agents_options *options,
                             struct json_value *out);

/* Fill `out` with the `grades` section read from the delegation ledger.
 * Returns false only when the ledger cannot be read at all; `why` then holds
 * one plain sentence naming the path. A malformed ROW never fails the call:
 * it is counted, its line number is reported, and it is skipped. */
bool zcl_agents_grades_json(const struct zcl_agents_options *options,
                            struct json_value *out, char *why,
                            size_t why_size);

/* The default ledger path when options->ledger is NULL. */
void zcl_agents_default_ledger(char *out, size_t cap);

/* Render the finished data object as aligned columns. Returns the bytes
 * written (always < cap). The text is built from the SAME object the JSON
 * envelope carries — there is no second data path. */
size_t zcl_agents_render_text(const struct json_value *data, char *out,
                              size_t cap);

/* The bound leaf: dev.fleet.agents, aliased fleet.agents. */
void zcl_native_handle_dev_agents(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply);

#endif /* ZCL_NATIVE_DEV_AGENTS_H */
