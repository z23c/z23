/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `fleet.objectives.brief` leaf — turns the objective that
 *          `fleet objectives` would pick next into a zcl.work_card.v1-shaped
 *          card, from the per-objective row in
 *          engine/composition/objective_work.def.
 *
 * WHAT IT DECIDES. Nothing new: the pick is zcl_objectives_next over the
 * rows `fleet.objectives` itself measured. With runner_ok_only the rows are
 * first narrowed to the ones whose work row says an unattended runner may
 * take them, then the same function picks the largest-gap unmet row. The
 * leaf reads what fleet.objectives reads and writes nothing. */

#include "native_fleet_objectives.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "util/log_macros.h"
#include "command/work_card.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct brief_work {
    const char *id;
    int runner_ok;
    const char *owned;
    const char *acceptance;
    const char *stop_if;
};

static const struct brief_work k_work[] = {
#define Z23_OBJECTIVE_WORK(id_, runner_ok_, owned_, acceptance_, stop_if_) \
    {id_, runner_ok_, owned_, acceptance_, stop_if_},
#include "../../engine/composition/objective_work.def"
#undef Z23_OBJECTIVE_WORK
};

/* Every card forbids these, whatever the objective: the consensus core, the
 * reducer, the wallet, the land driver, and what grades the runner (the
 * objectives leaves and catalogs, the lint gates, the deploy tree) plus every
 * pinned Commons package root, read from the registry at compile time so it
 * stays the one source of truth. A trailing '*' makes a token a prefix. */
static const char k_brief_forbidden[] =
    "core/,engine/reducer/,contexts/wallet/,tools/command/native_dev_land*,"
    "tools/command/native_fleet_objectives*,"
    "engine/composition/objective_work.def,"
    "engine/composition/objectives.def,"
    "engine/composition/commands/fleet.def,"
#define ZCODE_PACKAGE(name_, dir_, ...) dir_ "/,"
#include "../../engine/composition/zcode_package_registry.def"
#undef ZCODE_PACKAGE
    "tools/lint/lintc/**,platform/deploy/**";

static const struct brief_work *brief_find(const char *id)
{
    for (size_t i = 0; i < sizeof(k_work) / sizeof(k_work[0]); i++)
        if (id && strcmp(k_work[i].id, id) == 0)
            return &k_work[i];
    return NULL;
}

/* A boolean input. runner_ok_only is in the input validator's closed boolean
 * key list, so a CLI or MCP caller sends a JSON boolean; a direct caller that
 * skips the validator may still send "true" or "1" as text. Both count. */
static bool brief_flag(const struct zcl_command_request *request,
                       const char *key)
{
    const struct json_value *v;
    const char *s;
    if (!request || !request->input)
        return false;
    v = json_get(request->input, key);
    if (!v)
        return false;
    if (v->type == JSON_BOOL)
        return json_get_bool(v);
    s = json_get_str(v);
    return s && (strcmp(s, "true") == 0 || strcmp(s, "1") == 0);
}

/* Pushes `key`: an array of the comma-separated tokens of `csv`. */
static bool brief_push_csv(struct json_value *obj, const char *key,
                           const char *csv)
{
    struct json_value arr;
    bool ok = true;
    json_init(&arr);
    json_set_array(&arr);
    while (ok && *csv) {
        size_t n = strcspn(csv, ",");
        char token[256];
        struct json_value item;
        if (n >= sizeof(token))
            n = sizeof(token) - 1;
        memcpy(token, csv, n);
        token[n] = '\0';
        json_init(&item);
        json_set_str(&item, token);
        ok = json_push_back(&arr, &item);
        json_free(&item);
        csv += strcspn(csv, ",");
        if (*csv == ',')
            csv++;
    }
    ok = ok && json_push_kv(obj, key, &arr);
    json_free(&arr);
    return ok;
}

/* Pushes `key`: an array holding the one string `text`. */
static bool brief_push_one(struct json_value *obj, const char *key,
                           const char *text)
{
    struct json_value arr, item;
    bool ok;
    json_init(&arr);
    json_set_array(&arr);
    json_init(&item);
    json_set_str(&item, text);
    ok = json_push_back(&arr, &item) && json_push_kv(obj, key, &arr);
    json_free(&item);
    json_free(&arr);
    return ok;
}

/* "objective-<id with '-' for '_'>", a kebab name a work card accepts. */
static void brief_name(const char *id, char *out, size_t cap)
{
    size_t n = (size_t)snprintf(out, cap, "objective-%s", id);
    if (n >= cap)
        n = cap - 1;
    for (size_t i = 0; i < n; i++)
        if (out[i] == '_')
            out[i] = '-';
}

static bool brief_push_objective(struct json_value *card,
                                 const struct json_value *next,
                                 const struct brief_work *work)
{
    struct json_value obj;
    bool ok;
    json_init(&obj);
    json_set_object(&obj);
    ok = json_push_kv_str(&obj, "id", work->id) &&
         json_push_kv_int(&obj, "value", json_get_int(json_get(next, "value"))) &&
         json_push_kv_int(&obj, "target",
                          json_get_int(json_get(next, "target"))) &&
         json_push_kv_real(&obj, "gap", json_get_real(json_get(next, "gap"))) &&
         json_push_kv_str(&obj, "unit", json_get_str(json_get(next, "unit"))) &&
         json_push_kv_str(&obj, "why", json_get_str(json_get(next, "why"))) &&
         json_push_kv_bool(&obj, "runner_ok", work->runner_ok != 0) &&
         json_push_kv(card, "objective", &obj);
    json_free(&obj);
    return ok;
}

/* Appends the string `text` to the array `arr`. */
static bool brief_push_str_item(struct json_value *arr, const char *text)
{
    struct json_value item;
    bool ok;
    json_init(&item);
    json_set_str(&item, text);
    ok = json_push_back(arr, &item);
    json_free(&item);
    return ok;
}

/* ---- Narrowing the complexity card to one runnable file ----------------- */

#define BRIEF_COMPLEXITY_ID "functions_over_complexity_cap"
#define BRIEF_BASELINE_DEFAULT "tools/lint/cyclomatic_complexity_baseline.txt"
#define BRIEF_FILE_LINES_MAX 1300

struct brief_inputs {
    const char *repo;
    const char *baseline;
    const char *exclude;
};

struct brief_file {
    char path[240];
    int pins;
    int max_m;
};

struct brief_files {
    struct brief_file *v;
    size_t n, cap;
};

/* True when `path` matches a token of the comma list `csv`: by literal
 * prefix (the part before the first '*') or, when !prefix, exactly. */
static bool brief_csv_has(const char *csv, const char *path, bool prefix)
{
    while (*csv) {
        size_t len = strcspn(csv, ",");
        size_t lit = prefix ? strcspn(csv, ",*") : len;
        if (len && strncmp(path, csv, lit) == 0 &&
            (prefix || path[lit] == '\0'))
            return true;
        csv += len;
        if (*csv)
            csv++;
    }
    return false;
}

/* Splits one baseline row "path:function:M" in place. */
static bool brief_parse_row(char *line, char **path, char **fn, int *m)
{
    char *first, *last;
    line[strcspn(line, "\r\n")] = '\0';
    first = strchr(line, ':');
    last = strrchr(line, ':');
    if (line[0] == '#' || !first || first == last)
        return false;
    *first = '\0';
    *last = '\0';
    *path = line;
    *fn = first + 1;
    *m = atoi(last + 1);
    return true;
}

static struct brief_file *brief_files_find(struct brief_files *f,
                                           const char *path)
{
    if (f->n && strcmp(f->v[f->n - 1].path, path) == 0)
        return &f->v[f->n - 1];
    for (size_t i = 0; i < f->n; i++)
        if (strcmp(f->v[i].path, path) == 0)
            return &f->v[i];
    return NULL;
}

/* Counts one more pin of `m` against `path`. False on allocation failure. */
static bool brief_files_add(struct brief_files *f, const char *path, int m)
{
    struct brief_file *e = brief_files_find(f, path);
    if (!e) {
        if (strlen(path) >= sizeof(e->path))
            return true;
        if (f->n == f->cap) {
            size_t cap = f->cap ? f->cap * 2 : 256;
            struct brief_file *grown =
                zcl_realloc(f->v, cap * sizeof(*grown), "brief_files");
            if (!grown)
                return false;
            f->v = grown;
            f->cap = cap;
        }
        e = &f->v[f->n++];
        memset(e, 0, sizeof(*e));
        memcpy(e->path, path, strlen(path) + 1);
    }
    e->pins++;
    if (m > e->max_m)
        e->max_m = m;
    return true;
}

/* Reads the baseline into per-file pin counts. 0 ok, -1 unreadable or out
 * of memory. */
static int brief_load_files(const char *baseline, struct brief_files *out)
{
    char line[1024], *path, *fn;
    int m, rc = 0;
    FILE *fp = fopen(baseline, "r");
    if (!fp)
        return -1;
    while (rc == 0 && fgets(line, sizeof(line), fp))
        if (brief_parse_row(line, &path, &fn, &m) &&
            !brief_files_add(out, path, m))
            rc = -1;
    (void)fclose(fp);
    return rc;
}

/* True when repo/path exists and has fewer than BRIEF_FILE_LINES_MAX lines. */
static bool brief_file_small(const char *repo, const char *path)
{
    char full[1024], buf[8192];
    size_t got, lines = 0;
    FILE *fp;
    if (snprintf(full, sizeof(full), "%s/%s", repo, path) >=
        (int)sizeof(full))
        return false;
    fp = fopen(full, "rb");
    if (!fp)
        return false;
    while ((got = fread(buf, 1, sizeof(buf), fp)) > 0)
        for (size_t i = 0; i < got; i++)
            lines += buf[i] == '\n';
    (void)fclose(fp);
    return lines < BRIEF_FILE_LINES_MAX;
}

static bool brief_eligible(const struct brief_inputs *in, const char *owned,
                           const char *path)
{
    return brief_csv_has(owned, path, true) &&
           !brief_csv_has(k_brief_forbidden, path, true) &&
           strncmp(path, "tests/", 6) != 0 &&
           !brief_csv_has(in->exclude, path, false) &&
           brief_file_small(in->repo, path);
}

/* 3-6 pins first, then the lowest maximum M, then path order. */
static bool brief_better(const struct brief_file *a, const struct brief_file *b)
{
    bool pa = a->pins >= 3 && a->pins <= 6;
    bool pb = b->pins >= 3 && b->pins <= 6;
    if (pa != pb)
        return pa;
    if (a->max_m != b->max_m)
        return a->max_m < b->max_m;
    return strcmp(a->path, b->path) < 0;
}

/* Chooses the one file for the complexity card. 0 found, 1 none eligible,
 * -1 baseline unreadable or out of memory. */
static int brief_choose(const struct brief_inputs *in, const char *owned,
                        struct brief_file *best)
{
    struct brief_files files = {0};
    bool found = false;
    int rc = brief_load_files(in->baseline, &files);
    for (size_t i = 0; rc == 0 && i < files.n; i++) {
        const struct brief_file *f = &files.v[i];
        if ((found && !brief_better(f, best)) ||
            !brief_eligible(in, owned, f->path))
            continue;
        *best = *f;
        found = true;
    }
    free(files.v);
    if (rc != 0)
        return -1;
    return found ? 0 : 1;
}

/* Pushes `pins`: [{function, m}] for the rows of `file` in the baseline. */
static bool brief_push_pins(struct json_value *card, const char *baseline,
                            const char *file)
{
    char line[1024], *path, *fn;
    struct json_value arr;
    bool ok = true;
    int m;
    FILE *fp = fopen(baseline, "r");
    json_init(&arr);
    json_set_array(&arr);
    while (ok && fp && fgets(line, sizeof(line), fp)) {
        struct json_value pin;
        if (!brief_parse_row(line, &path, &fn, &m) || strcmp(path, file) != 0)
            continue;
        json_init(&pin);
        json_set_object(&pin);
        ok = json_push_kv_str(&pin, "function", fn) &&
             json_push_kv_int(&pin, "m", m) && json_push_back(&arr, &pin);
        json_free(&pin);
    }
    if (fp)
        (void)fclose(fp);
    ok = ok && fp && json_push_kv(card, "pins", &arr);
    json_free(&arr);
    return ok;
}

/* The outcome sentence of a card: the pick's gap, or the one file to fix. */
static void brief_outcome(char *out, size_t cap, const struct json_value *next,
                          const struct brief_file *tgt, bool is_max)
{
    if (tgt)
        (void)snprintf(out, cap,
                       "Bring %d functions in %s to cyclomatic complexity "
                       "<= 15 by behaviour-preserving extraction.",
                       tgt->pins, tgt->path);
    else
        (void)snprintf(out, cap, "Move %s from %lld to %s %lld %s.",
                       json_get_str(json_get(next, "id")),
                       (long long)json_get_int(json_get(next, "value")),
                       is_max ? "at least" : "at most",
                       (long long)json_get_int(json_get(next, "target")),
                       json_get_str(json_get(next, "unit")));
}

/* Pushes `owned`: the catalog globs, or exactly the one file and the
 * baseline when the card is narrowed. */
static bool brief_push_owned(struct json_value *card,
                             const struct brief_work *work,
                             const struct brief_file *tgt)
{
    struct json_value owned;
    bool ok;
    if (!tgt)
        return brief_push_csv(card, "owned", work->owned);
    json_init(&owned);
    json_set_array(&owned);
    ok = brief_push_str_item(&owned, tgt->path) &&
         brief_push_str_item(&owned, BRIEF_BASELINE_DEFAULT) &&
         json_push_kv(card, "owned", &owned);
    json_free(&owned);
    return ok;
}

/* Builds the card for the picked objective `next` into `card`. `tgt` is the
 * one file a narrowed complexity card is about, else NULL. */
static bool brief_build(struct json_value *card, const struct json_value *next,
                        const struct brief_work *work,
                        const struct brief_inputs *in,
                        const struct brief_file *tgt)
{
    char name[WORK_CARD_NAME_MAX + 1], outcome[512];
    bool is_max = strcmp(json_get_str(json_get(next, "direction")), "max") == 0;
    brief_name(work->id, name, sizeof(name));
    brief_outcome(outcome, sizeof(outcome), next, tgt, is_max);
    return json_push_kv_str(card, "schema", WORK_CARD_SCHEMA_ID) &&
           json_push_kv_str(card, "name", name) &&
           json_push_kv_str(card, "level",
                            work->runner_ok ? "sonnet" : "opus") &&
           json_push_kv_str(card, "outcome", outcome) &&
           brief_push_owned(card, work, tgt) &&
           brief_push_csv(card, "forbidden", k_brief_forbidden) &&
           brief_push_one(card, "contract",
                          "Keep behaviour unchanged; never weaken a test, "
                          "assertion, threshold or baseline.") &&
           json_push_kv_str(card, "acceptance", work->acceptance) &&
           brief_push_one(card, "stop_if", work->stop_if) &&
           brief_push_objective(card, next, work) &&
           (!tgt || (json_push_kv_str(card, "target_file", tgt->path) &&
                     brief_push_pins(card, in->baseline, tgt->path)));
}

/* The measured rows narrowed to `only_id` (when set) and to runner_ok rows
 * (when `runner_only`), as a new array. False on allocation failure. */
static bool brief_narrow(const struct json_value *rows, const char *only_id,
                         bool runner_only, struct json_value *out)
{
    json_set_array(out);
    for (size_t i = 0; i < rows->num_children; i++) {
        const struct json_value *row = &rows->children[i];
        const char *id = json_get_str(json_get(row, "id"));
        const struct brief_work *work = brief_find(id);
        if (only_id && (!id || strcmp(id, only_id) != 0))
            continue;
        if (runner_only && (!work || !work->runner_ok))
            continue;
        if (!json_push_back(out, row)) {
            LOG_ERROR("fleet.objectives.brief",
                      "cannot narrow the objective rows: out of memory");
            return false;
        }
    }
    return true;
}

/* Why an explicit `id` gave no card: met, unmeasured, or not runner-ok. */
static void brief_refuse_id(struct zcl_command_reply *reply,
                            const struct json_value *rows, const char *id,
                            bool runner_only)
{
    char message[192];
    const char *status = "not in the measured rows";
    const struct brief_work *work = brief_find(id);
    for (size_t i = 0; i < rows->num_children; i++)
        if (strcmp(json_get_str(json_get(&rows->children[i], "id")), id) == 0)
            status = json_get_str(json_get(&rows->children[i], "status"));
    if (runner_only && work && !work->runner_ok)
        (void)snprintf(message, sizeof(message),
                       "objective %s is not runner_ok; a human takes it", id);
    else
        (void)snprintf(message, sizeof(message),
                       "objective %s has nothing to brief: status %.100s", id,
                       status);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, "OBJECTIVE_NOT_ACTIONABLE",
                           "decide", false, false, message,
                           "z23-dev fleet objectives");
}

static void brief_pass(struct zcl_command_reply *reply)
{
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* A passed reply that carries no card, only a typed reason. */
static void brief_no_card(struct zcl_command_reply *reply, const char *none,
                          const char *reason)
{
    (void)json_push_kv_str(&reply->data, "schema", WORK_CARD_SCHEMA_ID);
    (void)json_push_kv_str(&reply->data, "none", none);
    if (reason)
        (void)json_push_kv_str(&reply->data, "reason", reason);
    brief_pass(reply);
}

static void brief_fail_build(struct zcl_command_reply *reply, const char *id)
{
    LOG_ERROR("fleet.objectives.brief", "no card for the picked objective %s",
              id);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INTERNAL, "BRIEF_BUILD", "decide",
                           false, false,
                           "cannot build the work card for the pick", "");
}

/* Builds the card for the pick; the complexity card is narrowed to one file
 * first, and when no file is eligible the reply is a typed no-card. */
static void brief_finish(struct zcl_command_reply *reply,
                         const struct json_value *next,
                         const struct brief_work *work,
                         const struct brief_inputs *in)
{
    struct brief_file file;
    bool narrow = work && strcmp(work->id, BRIEF_COMPLEXITY_ID) == 0;
    int rc = narrow ? brief_choose(in, work->owned, &file) : 0;
    if (rc > 0)
        brief_no_card(reply,
                      "no file is eligible for the complexity card: every "
                      "pinned file is protected, a test, missing, over 1300 "
                      "lines or excluded",
                      "NO_ELIGIBLE_FILE");
    else if (rc < 0 || !work ||
             !brief_build(&reply->data, next, work, in, narrow ? &file : NULL))
        brief_fail_build(reply, json_get_str(json_get(next, "id")));
    else
        brief_pass(reply);
}

/* Fills the reply from the narrowed rows; the pick is zcl_objectives_next. */
static void brief_reply(struct zcl_command_reply *reply,
                        const struct json_value *rows, const char *id,
                        bool runner_only, const struct brief_inputs *in)
{
    struct json_value narrowed, next;
    bool ok;
    json_init(&narrowed);
    json_init(&next);
    ok = brief_narrow(rows, id, runner_only, &narrowed) &&
         zcl_objectives_next(&narrowed, &next);
    if (!ok) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BRIEF_ALLOC",
                               "decide", false, false,
                               "cannot build the pick: out of memory", "");
    } else if (json_is_null(&next) && id) {
        brief_refuse_id(reply, rows, id, runner_only);
    } else if (json_is_null(&next)) {
        brief_no_card(reply,
                      runner_only
                          ? "no runner_ok objective is measured and unmet"
                          : "no objective is measured and unmet",
                      NULL);
    } else {
        brief_finish(reply, &next,
                     brief_find(json_get_str(json_get(&next, "id"))), in);
    }
    json_free(&next);
    json_free(&narrowed);
}

/* A string input, or `fallback` when absent or empty. */
static const char *brief_str(const struct zcl_command_request *request,
                             const char *key, const char *fallback)
{
    const char *s = (request && request->input)
                        ? json_get_str(json_get(request->input, key))
                        : NULL;
    return s && s[0] ? s : fallback;
}

void zcl_native_handle_fleet_objectives_brief(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct zcl_command_reply measured;
    const char *id = (request && request->input)
                         ? json_get_str(json_get(request->input, "id"))
                         : NULL;
    bool runner_only = brief_flag(request, "runner_ok_only");
    const struct json_value *rows;

    if (reply)
        zcl_command_reply_init(reply, WORK_CARD_SCHEMA_ID);
    if (!reply)
        return;
    if (id && !id[0])
        id = NULL;
    if (id && !brief_find(id)) {
        char message[192];
        (void)snprintf(message, sizeof(message),
                       "unknown objective id '%.80s': not in the closed catalog",
                       id);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "UNKNOWN_OBJECTIVE",
                               "normalize", false, false, message,
                               "z23-dev fleet objectives lists every id");
        return;
    }
    memset(&measured, 0, sizeof(measured));
    zcl_native_handle_fleet_objectives(request, &measured);
    rows = json_get(&measured.data, "objectives");
    if (measured.status != ZCL_COMMAND_STATUS_PASSED || !rows) {
        LOG_ERROR("fleet.objectives.brief", "the objectives did not measure");
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "OBJECTIVES_FAILED",
                               "decide", false, false,
                               "fleet.objectives could not measure the catalog",
                               "z23-dev fleet objectives");
    } else {
        struct brief_inputs in = {brief_str(request, "repo", "."),
                                  brief_str(request, "baseline",
                                            BRIEF_BASELINE_DEFAULT),
                                  brief_str(request, "exclude", "")};
        brief_reply(reply, rows, id, runner_only, &in);
    }
    zcl_command_reply_free(&measured);
}
