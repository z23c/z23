/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: One local answer to "what does z23 optimize, and where does each
 *          objective stand right now?" — the closed catalog and readers
 *          behind `z23-dev fleet objectives`. */

#ifndef ZCL_NATIVE_FLEET_OBJECTIVES_H
#define ZCL_NATIVE_FLEET_OBJECTIVES_H

#include "command/native_command.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_OBJECTIVES_SCHEMA "zcl.fleet_objectives.v1"
#define ZCL_OBJECTIVES_REASON_MAX 256u
#define ZCL_OBJECTIVES_TEXT_MAX 4096u

/* One catalog row, decided at compile time from
 * engine/composition/objectives.def. */
struct zcl_objective_row {
    const char *id;
    const char *source;
    const char *direction; /* "min" or "max" */
    int64_t target;
    const char *unit;
    const char *why;
};

/* The catalog itself, in declaration order. */
size_t zcl_objectives_catalog(const struct zcl_objective_row **out);

/* One row's measured answer. `measured` false means `value` carries no
 * meaning and `reason` names why the tree cannot answer today. */
struct zcl_objective_value {
    bool measured;
    int64_t value;
    char reason[ZCL_OBJECTIVES_REASON_MAX];
};

/* Paths and knobs every producer reads from; every field is overridable so
 * tests can drive the whole leaf against a fixture tree, and NULL selects
 * this machine's own default location. */
struct zcl_objectives_options {
    const char *outcomes;     /* outcomes.jsonl */
    const char *attempts_dir; /* the proof attempts directory */
    const char *repo;         /* git worktree read for commit history */
    const char *lintc_dir;    /* tools/lint/lintc */
    const char *baseline;     /* the cyclomatic complexity baseline file */
};

/* Measures one catalog row by id. An id this file does not recognize
 * returns an unmeasured value naming the unknown id; that path only fires
 * on a catalog/producer drift, never on ordinary input. */
struct zcl_objective_value zcl_objectives_measure(
    const struct zcl_objectives_options *options, const char *id);

/* "met", "unmet", or "unmeasured(<reason>)", written into `out` (always
 * NUL-terminated, truncated to fit). */
void zcl_objectives_status(const struct zcl_objective_row *row,
                           const struct zcl_objective_value *value, char *out,
                           size_t cap);

/* Render the finished objectives array as aligned plain-English columns.
 * Returns the bytes written (always < cap). */
size_t zcl_objectives_render_text(const struct json_value *rows, char *out,
                                  size_t cap);

/* The bound leaf: fleet.objectives. */
void zcl_native_handle_fleet_objectives(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);

#endif /* ZCL_NATIVE_FLEET_OBJECTIVES_H */
