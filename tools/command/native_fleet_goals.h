/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The closed goals catalog and graders behind `z23 fleet goals`,
 *          the live report card of the fleet goals G1-G13, the public-node
 *          criteria C1-C8 and the development milestones D1-D8. */

#ifndef ZCL_NATIVE_FLEET_GOALS_H
#define ZCL_NATIVE_FLEET_GOALS_H

#include "base/format_attribute.h"
#include "command/native_command.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_GOALS_SCHEMA "zcl.fleet_goals.v1"
#define ZCL_GOALS_EVIDENCE_MAX 320u
#define ZCL_GOALS_NEXT_MAX 240u
#define ZCL_GOALS_HOSTS_MAX 32u
#define ZCL_GOALS_TEXT_MAX 16384u
#define ZCL_GOALS_TRAIN_MIN 3
#define ZCL_GOALS_LOOKUP_MS_MAX 50
#define ZCL_GOALS_WIKI_MS_MAX 10000
#define ZCL_GOALS_WIKI_FRESH_S 86400

enum zcl_goal_grade {
    ZCL_GOAL_PASS,
    ZCL_GOAL_PARTIAL,
    ZCL_GOAL_FAIL,
    ZCL_GOAL_UNMEASURED,
};

/* One catalog row, decided at compile time from
 * engine/composition/goals.def. */
struct zcl_goal_row {
    const char *id;
    const char *title;
    const char *bar;
};

size_t zcl_goals_catalog(const struct zcl_goal_row **out);

/* One graded row. `evidence` names the probe and what it read; for an
 * unmeasured row it is the reason. `next` is the command or card that would
 * raise the grade. */
struct zcl_goal_result {
    enum zcl_goal_grade grade;
    char evidence[ZCL_GOALS_EVIDENCE_MAX];
    char next[ZCL_GOALS_NEXT_MAX];
};

/* One admitted host, from `fleet machines` or a test fixture. */
struct zcl_goals_host {
    char name[64];
    char box[65];
    char os[32];
};

/* Inputs every producer reads; NULL or zero selects this machine's own
 * default so tests can drive the whole leaf against a fixture tree. */
struct zcl_goals_options {
    const char *repo;           /* git worktree: lane claims, origin/main log;
                                * NULL resolves the top level of the cwd */
    const char *source_root;    /* checkout the running binary was built from;
                                * NULL when none is recorded or configured */
    const char *outcomes;       /* landing outcomes.jsonl */
    const char *bash_allowlist; /* tools/lint/bash_allowlist.txt */
    const char *claims;         /* z23-agent-claims.jsonl */
    const char *mvp_doc;        /* docs/MVP.md */
    const char *c3_history;     /* cold-start stopwatch history.jsonl (C3) */
    const char *soak_dir;       /* soak evidence dir holding evidence.jsonl (C6) */
    int64_t now_unix;           /* 0 = wall clock */
    bool hosts_given;           /* true: use hosts[] instead of fleet machines */
    const struct zcl_goals_host *hosts;
    size_t host_count;
    bool skip_probes;           /* tests: skip the in-process code and wiki probes */
    int64_t origin_tip_unix;    /* commit time of origin/main; 0 = ask git */
};

const char *zcl_goal_grade_name(enum zcl_goal_grade grade);

/* Graders, exposed so a fixture can pin each threshold. */
enum zcl_goal_grade zcl_goals_grade_trains(int64_t trains, int64_t failed);
enum zcl_goal_grade zcl_goals_grade_lookup(int64_t median_ms);
enum zcl_goal_grade zcl_goals_grade_fresh(size_t fresh, size_t hosts);
enum zcl_goal_grade zcl_goals_grade_claims(int64_t live);
enum zcl_goal_grade zcl_goals_grade_scripts(int64_t scripts);

/* Grades G4 from one fleet.wiki.list answer: data holds its posts array of
 * index rows (host, created_at), own_host is this node board host id in hex.
 * Latency is the list call in ms. Exposed so a fixture can pin each rule. */
struct zcl_goal_result zcl_goals_wiki_grade(bool answered, const char *why,
                                            const struct json_value *data,
                                            const char *own_host,
                                            int64_t now, int64_t latency_ms);

/* Build one graded row: `fmt` formats the evidence, `next` is copied whole. */
struct zcl_goal_result zcl_goal_make(enum zcl_goal_grade grade, const char *next,
                                     const char *fmt, ...)
    ZCL_PRINTF_LIKE(3, 4);

/* Grades C3 and C6 from their newest durable receipt
 * (native_fleet_goals_receipts.c). False when the id has no receipt reader. */
bool zcl_goals_receipt_measure(const struct zcl_goals_options *options,
                               const char *id, struct zcl_goal_result *out);

/* Grades one catalog row by id. An unknown id yields unmeasured naming it. */
struct zcl_goal_result zcl_goals_measure(
    const struct zcl_goals_options *options, const char *id);

/* Counts of each grade over a finished rows array. */
void zcl_goals_tally(const struct json_value *rows, int64_t counts[4]);

/* Aligned plain-text rendering of the rows array. Returns bytes written. */
size_t zcl_goals_render_text(const struct json_value *rows, char *out,
                             size_t cap);

/* The bound leaf: fleet.goals. */
void zcl_native_handle_fleet_goals(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply);

#endif /* ZCL_NATIVE_FLEET_GOALS_H */
