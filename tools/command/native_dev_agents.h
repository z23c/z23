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

/* `--publish`/`--fleet` share these with native_dev_agents_publish.c. The
 * post text stays well under the board's 2048-byte ceiling for a non-wiki
 * kind, leaving room for JSON-string escaping and a growing fleet. A post
 * older than the stale window is still merged, just marked stale. */
#define ZCL_AGENTS_PUBLISH_TEXT_MAX 1900u
#define ZCL_AGENTS_STALE_SECONDS (15 * 60)
#define ZCL_AGENTS_MAX_HOST_ROWS 32u

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

/* ── native_dev_agents_publish.c ─────────────────────────────────────────
 * `--publish` posts this box's RUNNING-NOW and GRADES rows to the local
 * node's fleet board as one `agents`-kind, fleet-scoped post; `--fleet`
 * reads the newest such post per host back and merges it with this box's
 * own live scan. Both talk to the local node over the same `fleet_board`
 * RPC method `fleet board post/list` already use — never a second, private
 * copy of the board, and never a shell-out. */

/* This box's human name: the fleet machine roster entry for this board
 * identity's key when one exists, else the OS hostname. Always writes a
 * NUL-terminated, non-empty string. */
void zcl_agents_host_name(char *out, size_t cap);

/* The compact, line-based board-post body: a header line naming the host
 * and the snapshot time, one `R|...` line per live (non-idle) running row,
 * and one `G|...` line per grade row, trimmed to fit under
 * ZCL_AGENTS_PUBLISH_TEXT_MAX. Returns the bytes written, always < cap. */
size_t zcl_agents_publish_text(const struct json_value *running,
                               const struct json_value *grades,
                               const char *host_name, int64_t now,
                               char *out, size_t cap);

/* True when `candidate` is byte-identical to `prev_text` and `prev_created`
 * falls in the same minute as `now` — the dedupe `--publish` runs before
 * every post so running it twice inside one minute never duplicates a row. */
bool zcl_agents_publish_is_duplicate(const char *prev_text,
                                     int64_t prev_created, const char *candidate,
                                     int64_t now);

/* `--publish`: build, dedupe-check and post the summary. Fills reply->data
 * with {ok, posted:bool, id, host}. */
void zcl_agents_do_publish(const struct zcl_agents_options *options,
                           const struct json_value *running,
                           const struct json_value *grades,
                           struct zcl_command_reply *reply);

/* `--fleet`: read the board's `agents` posts, merge the newest one per host
 * with this box's own live rows, and fill `out` with the merged object
 * (`hosts`, `hosts_reporting`, `hosts_known`, and a rendered `text`). */
void zcl_agents_do_fleet_merge(const struct json_value *running,
                               const struct json_value *grades,
                               int64_t now, struct json_value *out);

#endif /* ZCL_NATIVE_DEV_AGENTS_H */
