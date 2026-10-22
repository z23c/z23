/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: SENSE for the lab loop. After dev.land records a row as landed,
 *          append one objectives snapshot line to objectives.jsonl beside
 *          outcomes.jsonl, so the catalog in engine/composition/objectives.def
 *          has a trend line over landings.
 *
 * LINE (zcl.objectives_snapshot.v1, one JSON object, newline terminated):
 *   {"schema":..,"ts":<landed_at>,"seq":<row seq>,"tip":"<row tip>",
 *    "objectives":[{"id","value","target","direction","met","reason"}..]}
 * value and met are null, and reason says why, for an objective the tree
 * cannot answer today; a measured objective carries reason "".
 *
 * BEST EFFORT. The producer is `fleet objectives`' own C API, called in
 * process against this queue's outcomes.jsonl and landing worktree. A
 * failure to compute, encode or append is written to the row's attempt log
 * with its context and changes nothing else: not the outcome, not the push,
 * not the reply. The caller invokes this only for an outcome row it has just
 * appended, so a retried or replayed row never writes a second line. A
 * process death between the outcome append and this append loses that one
 * line; the lab can always re-read the report, the queue never waits on it.
 * `fleet objectives` itself still writes nothing: the queue records, the
 * report only reads. */

#include "command/native_dev_land_internal.h"
#include "command/native_fleet_objectives.h"

#include "base/safe_alloc.h"
#include "json/json.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DLO_SCHEMA "zcl.objectives_snapshot.v1"
#define DLO_PATH_MAX (4096u + 96u)

struct dlo_paths {
    char outcomes[DLO_PATH_MAX];
    char attempts[DLO_PATH_MAX];
    char lintc[DLO_PATH_MAX];
    char baseline[DLO_PATH_MAX];
    char snapshot[DLO_PATH_MAX];
};

/* One line in the row's attempt log naming what was not recorded and why. */
static void dlo_note(const struct dl_row *r, const char *what,
                     const char *detail)
{
    char line[DL_NOTE_MAX + 256];
    int n = snprintf(line, sizeof(line),
                     "objectives snapshot not recorded for seq %lld: %s%s%s\n",
                     r->seq, what, detail[0] ? ": " : "", detail);
    if (n > 0)
        dl_log(r, line);
}

static bool dlo_join(char *out, const char *dir, const char *tail)
{
    int n = snprintf(out, DLO_PATH_MAX, "%s%s", dir, tail);
    return n > 0 && (size_t)n < DLO_PATH_MAX;
}

/* Every producer path, absolute and under the land state directory: the
 * producer's own defaults are relative to the working directory, which for
 * a landing step is nothing this file can rely on. */
static bool dlo_paths_make(const struct dl_dirs *d, struct dlo_paths *p)
{
    return dlo_join(p->outcomes, d->land, "/outcomes.jsonl") &&
           dlo_join(p->snapshot, d->land, "/objectives.jsonl") &&
           dlo_join(p->attempts, d->wt, "/.cache/zcl-dev-proof/attempts") &&
           dlo_join(p->lintc, d->wt, "/tools/lint/lintc") &&
           dlo_join(p->baseline, d->wt,
                    "/tools/lint/cyclomatic_complexity_baseline.txt");
}

static bool dlo_push_null(struct json_value *obj, const char *key)
{
    struct json_value nul;
    bool ok;
    json_init(&nul);
    json_set_null(&nul);
    ok = json_push_kv(obj, key, &nul);
    json_free(&nul);
    return ok;
}

/* met is true or false for a measured row and null for an unmeasured one;
 * the verdict itself is the catalog's, never re-derived here. */
static bool dlo_push_met(struct json_value *obj,
                         const struct zcl_objective_row *row,
                         const struct zcl_objective_value *value)
{
    char status[ZCL_OBJECTIVES_REASON_MAX + 32];
    zcl_objectives_status(row, value, status, sizeof(status));
    if (!value->measured)
        return dlo_push_null(obj, "met");
    return json_push_kv_bool(obj, "met", strcmp(status, "met") == 0);
}

static bool dlo_row_json(const struct zcl_objective_row *row,
                         const struct zcl_objectives_options *options,
                         struct json_value *out)
{
    struct zcl_objective_value value = zcl_objectives_measure(options, row->id);
    json_set_object(out);
    return json_push_kv_str(out, "id", row->id) &&
           (value.measured ? json_push_kv_int(out, "value", value.value)
                           : dlo_push_null(out, "value")) &&
           json_push_kv_int(out, "target", row->target) &&
           json_push_kv_str(out, "direction", row->direction) &&
           dlo_push_met(out, row, &value) &&
           json_push_kv_str(out, "reason",
                            value.measured ? "" : value.reason);
}

static bool dlo_objectives_json(const struct zcl_objectives_options *options,
                                struct json_value *rows)
{
    const struct zcl_objective_row *catalog;
    size_t n = zcl_objectives_catalog(&catalog);
    json_set_array(rows);
    for (size_t i = 0; i < n; i++) {
        struct json_value row;
        bool ok;
        json_init(&row);
        ok = dlo_row_json(&catalog[i], options, &row) &&
             json_push_back(rows, &row);
        json_free(&row);
        if (!ok)
            return false;
    }
    return true;
}

static bool dlo_snapshot_json(const struct dl_row *r,
                              const struct zcl_objectives_options *options,
                              struct json_value *snap)
{
    struct json_value rows;
    bool ok;
    json_init(&rows);
    ok = dlo_objectives_json(options, &rows);
    json_set_object(snap);
    ok = ok && json_push_kv_str(snap, "schema", DLO_SCHEMA) &&
         json_push_kv_int(snap, "ts", r->landed_at) &&
         json_push_kv_int(snap, "seq", r->seq) &&
         json_push_kv_str(snap, "tip", r->tip) &&
         json_push_kv(snap, "objectives", &rows);
    json_free(&rows);
    return ok;
}

/* The finished line in a heap buffer, newline included; NULL (logged) when
 * it cannot be built. */
static char *dlo_line(const struct dl_row *r,
                      const struct zcl_objectives_options *options,
                      size_t *len_out)
{
    struct json_value snap;
    char *line = NULL;
    size_t need;
    json_init(&snap);
    if (!dlo_snapshot_json(r, options, &snap)) {
        dlo_note(r, "cannot build the snapshot", "out of memory");
        json_free(&snap);
        return NULL;
    }
    need = json_write(&snap, NULL, 0);
    line = zcl_malloc(need + 2, "dev_land_objectives_line");
    if (!line) {
        dlo_note(r, "cannot allocate the snapshot line", "out of memory");
        json_free(&snap);
        return NULL;
    }
    if (json_write(&snap, line, need + 1) != need) {
        dlo_note(r, "cannot encode the snapshot", "json_write truncated");
        free(line);
        json_free(&snap);
        return NULL;
    }
    line[need] = '\n';
    line[need + 1] = '\0';
    *len_out = need + 1;
    json_free(&snap);
    return line;
}

void dl_objectives_snapshot(const struct dl_dirs *d, const struct dl_row *r,
                            bool fresh)
{
    struct dlo_paths paths;
    struct zcl_objectives_options options;
    char *line;
    size_t len = 0;
    if (!fresh || !d || !r || strcmp(r->state, "landed") != 0)
        return;
    if (!dlo_paths_make(d, &paths)) {
        dlo_note(r, "land state path too long", d->land);
        return;
    }
    memset(&options, 0, sizeof(options));
    options.outcomes = paths.outcomes;
    options.attempts_dir = paths.attempts;
    options.repo = d->wt;
    options.lintc_dir = paths.lintc;
    options.baseline = paths.baseline;
    options.now = r->landed_at;
    line = dlo_line(r, &options, &len);
    if (!line)
        return;
    if (!dl_append_row(paths.snapshot, line, len)) {
        char why[DLO_PATH_MAX + 64];
        int saved = errno;
        (void)snprintf(why, sizeof(why), "append to %s failed (errno %d: %s)",
                       paths.snapshot, saved, strerror(saved));
        dlo_note(r, "cannot append the snapshot line", why);
    }
    free(line);
}
