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
#define ZCL_OBJECTIVES_TEXT_MAX 6144u
#define ZCL_OBJECTIVES_SCREEN_MAX 8192u

/* One catalog row, decided at compile time from
 * engine/composition/objectives.def. */
struct zcl_objective_row {
    const char *id;
    const char *class_; /* "product" or "lab" */
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
    char note[ZCL_OBJECTIVES_REASON_MAX]; /* measured: what the value names, or "" */
};

/* Paths and knobs every producer reads from; every field is overridable so
 * tests can drive the whole leaf against a fixture tree, and NULL selects
 * this machine's own default location. */
/* One run's shared answer from the node: the status brief is fetched at
 * most once per run and shared by every node producer. Zero it before the
 * run, free it after with zcl_objectives_node_cache_free. */
struct zcl_objectives_node_cache {
    bool filled;
    char *raw; /* NULL when the fetch failed */
    int fetches; /* fetches made so far: 0 or 1 */
};
void zcl_objectives_node_cache_free(struct zcl_objectives_node_cache *cache);

struct zcl_objectives_options {
    const char *outcomes;     /* outcomes.jsonl */
    const char *attempts_dir; /* the proof attempts directory */
    const char *repo;         /* git worktree read for commit history */
    const char *lintc_dir;    /* tools/lint/lintc */
    const char *baseline;     /* the cyclomatic complexity baseline file */
    const char *brief;        /* a status-brief JSON file read in place of
                               * asking the local node (fixtures) */
    const char *datadir;      /* the datadir whose boot_status.json is read;
                               * NULL selects the CLI's resolved datadir */
    const char *experiments;  /* the experiment ledger rows.tsv; NULL selects
                               * $XDG_STATE_HOME/zclassic23/experiments/rows.tsv
                               * (else ~/.local/state/...) */
    int64_t node_budget_ms;   /* the longest a producer may wait on the node,
                               * connect and total; 0 keeps the status
                               * front door's own deadline */
    struct zcl_objectives_node_cache *node_cache; /* NULL fetches per row */
    int64_t now;              /* unix seconds the day and window readers
                               * count from; 0 reads the wall clock */
    const char *session;      /* the lead's Claude Code transcript (.jsonl);
                               * NULL takes the newest one under this
                               * checkout's Claude project directory */
};

/* Measures one catalog row by id. An id this file does not recognize
 * returns an unmeasured value naming the unknown id; that path only fires
 * on a catalog/producer drift, never on ordinary input. */
struct zcl_objective_value zcl_objectives_measure(
    const struct zcl_objectives_options *options, const char *id);

/* The product producers (native_fleet_objectives_node.c): the running node's
 * own answers, unmeasured with a reason when it cannot give them. */
struct zcl_objective_value zcl_objectives_node_rss_mb(
    const struct zcl_objectives_options *options);
struct zcl_objective_value zcl_objectives_node_tip_lag_blocks(
    const struct zcl_objectives_options *options);
struct zcl_objective_value zcl_objectives_node_warm_restart_s(
    const struct zcl_objectives_options *options);

/* The experiment-ledger producer (native_fleet_objectives_tokens.c): the
 * median, over lanes landed in the last 7 days, of the lane's worker agents'
 * uncached input + output tokens. */
struct zcl_objective_value zcl_objectives_tokens_per_landed_commit(
    const struct zcl_objectives_options *options);

/* The fleet.objectives.value report (the same reader): spend per role and
 * model over the same landed lanes. Fills the object `data` with rows, totals,
 * skipped and screen; false with `reason` set when the inputs cannot answer. */
bool zcl_objectives_value_data(const struct zcl_objectives_options *options,
                               struct json_value *data, char *reason,
                               size_t cap);

/* The one-row baseline producer (native_fleet_objectives_baselines.c): the sum
 * of the banned-str counts in the hardening ratchet baseline under repo. */
struct zcl_objective_value zcl_objectives_baseline_hardening_banned_str(
    const struct zcl_objectives_options *options);


/* The agent-to-lane index (native_fleet_objectives_lanes.c): worker agent
 * id -> lane, from the agent-<id>.meta.json job labels under the Claude
 * projects root ($Z23_AGENT_META_ROOT, else ~/.claude/projects). */
#define ZCL_AGENT_INDEX_FILE_CAP 20000u
struct zcl_agent_lane {
    char id[48];
    char lane[104];
    char kind[8]; /* write cx review review1 review2 fix */
};
struct zcl_agent_index {
    struct zcl_agent_lane *items; /* sorted by id after build */
    size_t n;
    size_t cap;
    size_t files;  /* meta files read */
    bool capped;   /* the file cap stopped the scan */
    bool oom;
};
/* False only on an allocation failure. A missing root yields an empty index. */
bool zcl_objectives_agent_index_build(struct zcl_agent_index *ix);
const char *zcl_objectives_agent_lane(const struct zcl_agent_index *ix,
                                      const char *id);
/* The job kind of the same agent, or NULL. */
const char *zcl_objectives_agent_kind(const struct zcl_agent_index *ix,
                                      const char *id);
void zcl_objectives_agent_index_free(struct zcl_agent_index *ix);

/* "met", "unmet", or "unmeasured(<reason>)", written into `out` (always
 * NUL-terminated, truncated to fit). */
void zcl_objectives_status(const struct zcl_objective_row *row,
                           const struct zcl_objective_value *value, char *out,
                           size_t cap);

/* Render the finished objectives array as aligned plain-English columns.
 * Returns the bytes written (always < cap). */
size_t zcl_objectives_render_text(const struct json_value *rows, char *out,
                                  size_t cap);

/* The next target: the measured, unmet row of the finished objectives array
 * with the largest normalized gap to its target,
 * gap = (value - target) / max(|target|, 1) for "min" and
 * (target - value) / max(|target|, 1) for "max". Unmeasured rows are never
 * chosen and a tie goes to the earlier catalog row. A PRODUCT row (class
 * "product") always outranks a lab row: the largest product gap wins, and a
 * lab row is chosen only when no measured product row is unmet. `out` becomes an object
 * {id, class, value, target, direction, unit, gap (rounded to 3 decimals),
 * why, note (the row's per-measurement note, "" when none)}, or
 * JSON null when no measured row is unmet. Returns false only when the object
 * cannot be allocated (reason on stderr, `out` left JSON null). */
bool zcl_objectives_next(const struct json_value *rows, struct json_value *out);

/* One ASCII report-card line per objective, a summary line
 * "lab: met N of M, unmeasured K", and a closing line "next: <id>  <value> vs
 * <target> <unit> - <why>" (or "next: none - <reason>").
 * Returns the bytes written (always < cap). */
size_t zcl_objectives_render_screen(const struct json_value *rows, char *out,
                                    size_t cap);

/* Readers shared with `fleet.goals`. */
bool zcl_objectives_parse_iso8601(const char *s, int64_t *out);
bool zcl_objectives_outcomes_path(const struct zcl_objectives_options *options,
                                  char *buf, size_t cap, const char **out);

/* The experiment ledger rows.tsv: options->experiments, else
 * $XDG_STATE_HOME/zclassic23/experiments/rows.tsv, else ~/.local/state. */
bool zcl_objectives_experiments_path(
    const struct zcl_objectives_options *options, char *buf, size_t cap,
    const char **out);

/* Calls `row` for every JSON-object line of a ledger file. False, with the
 * reason, when the file is missing or any line is unreadable. */
bool zcl_objectives_ledger_walk(const char *path,
                                void (*row)(const struct json_value *, void *),
                                void *user, char *reason, size_t reason_cap);

/* fleet.objectives.verdict helpers, shared with fleet.objectives.step (one
 * reader of objectives.jsonl, no copy). The path is the request's `snapshot`
 * input or <state>/land/objectives.jsonl; false, with the reply filled, when
 * neither exists. The seqs are every valid snapshot row's seq in file order
 * (caller frees); false on a read or allocation error. */
bool zcl_objectives_snapshot_path(const struct zcl_command_request *request,
                                  char *out, size_t cap,
                                  struct zcl_command_reply *reply);
bool zcl_objectives_snapshot_seqs(const char *path, int64_t **seqs, size_t *n,
                                  size_t *skipped);

/* The bound leaf: fleet.objectives. */
void zcl_native_handle_fleet_objectives(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);

#endif /* ZCL_NATIVE_FLEET_OBJECTIVES_H */
