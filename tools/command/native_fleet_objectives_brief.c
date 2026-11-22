/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `fleet.objectives.brief` leaf — turns the objective that
 *          `fleet objectives` would pick next into a zcl.work_card.v1-shaped
 *          card, from the per-objective row in
 *          engine/composition/objective_work.def.
 *
 * WHAT IT DECIDES. The pick is zcl_objectives_next over the rows
 * `fleet.objectives` itself measured, except an automatic brief never issues
 * a warm-restart card from a sample without source identity. With
 * runner_ok_only the rows are first narrowed to the ones whose work row says
 * an unattended runner may take them, then the same function picks the
 * largest-gap unmet row. It reads what fleet.objectives reads and writes
 * nothing. */

#include "native_fleet_objectives.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/memory_stream.h"
#include "util/log_macros.h"
#include "command/native_dev_cx_next.h"
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
    const char *note = json_get_str(json_get(next, "note"));
    json_init(&obj);
    json_set_object(&obj);
    ok = json_push_kv_str(&obj, "id", work->id) &&
         json_push_kv_int(&obj, "value", json_get_int(json_get(next, "value"))) &&
         json_push_kv_int(&obj, "target",
                          json_get_int(json_get(next, "target"))) &&
         json_push_kv_real(&obj, "gap", json_get_real(json_get(next, "gap"))) &&
         json_push_kv_str(&obj, "unit", json_get_str(json_get(next, "unit"))) &&
         json_push_kv_str(&obj, "why", json_get_str(json_get(next, "why"))) &&
         (!note[0] || json_push_kv_str(&obj, "note", note)) &&
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
    const char *worktrees; /* fixture: `git worktree list --porcelain` text file */
    const char *revision;
    char *complexity_bytes;
    size_t complexity_len;
};

struct brief_file {
    char path[240];
    int pins;
    int max_m;
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

/* The brief's own filter on the shared selection: the objective's owned
 * paths, none of the forbidden ones, and never a tests/ file. */
static bool brief_allowed(const char *path, void *owned)
{
    return brief_csv_has(owned, path, true) &&
           !brief_csv_has(k_brief_forbidden, path, true) &&
           strncmp(path, "tests/", 6) != 0;
}

/* A baseline-row card's file: allowed, not excluded, and under the size cap. */
static bool brief_eligible(const struct brief_inputs *in, const char *owned,
                           const char *path)
{
    if (!brief_allowed(path, (void *)owned) ||
        brief_csv_has(in->exclude, path, false))
        return false;
    if (!in->revision[0])
        return brief_file_small(in->repo, path);
    size_t len = 0, lines = 0;
    char *blob = zcl_objectives_checkout_blob(in->repo, in->revision, path, &len);
    if (!blob)
        return false;
    for (size_t i = 0; i < len; i++)
        lines += blob[i] == '\n';
    free(blob);
    return lines < BRIEF_FILE_LINES_MAX;
}

/* Chooses the one file for the complexity card by dev.cx.next's rules (live
 * worktrees, exclude, size, sealed paths), 3-6 pins first. 0 found, 1 none
 * eligible, -1 the selection could not run. */
static int brief_origin_lines(const char *path, void *ctx)
{
    const struct brief_inputs *in = ctx;
    size_t len = 0;
    int lines = 0;
    char *blob = zcl_objectives_checkout_blob(in->repo, in->revision, path, &len);
    if (!blob)
        return -1;
    for (size_t i = 0; i < len && lines < BRIEF_FILE_LINES_MAX; i++)
        lines += blob[i] == '\n';
    free(blob);
    return lines;
}

static int brief_choose(const struct brief_inputs *in, const char *owned,
                        struct brief_file *best)
{
    struct zcl_cx_pick_in pick = {
        .repo = in->repo, .baseline = in->baseline, .exclude_csv = in->exclude,
        .allow = brief_allowed, .allow_ctx = (void *)owned, .pin_band = true,
        .baseline_bytes = in->complexity_bytes, .baseline_len = in->complexity_len,
        .count_lines = in->complexity_bytes ? brief_origin_lines : NULL,
        .count_lines_ctx = (void *)in,
    };
    struct zcl_cx_pick_out out;
    int rc = zcl_dev_cx_pick(&pick, &out);
    if (rc != 0)
        return rc;
    memset(best, 0, sizeof(*best));
    if (snprintf(best->path, sizeof(best->path), "%s", out.file) >=
        (int)sizeof(best->path))
        return -1;
    best->pins = out.pins;
    best->max_m = out.max_score;
    return 0;
}

/* Pushes `pins`: [{function, m}] for the rows of `file` in the baseline. */
static bool brief_push_pins(struct json_value *card, const struct brief_inputs *in,
                            const char *file)
{
    char line[1024], *path, *fn;
    struct json_value arr;
    bool ok = true;
    int m;
    FILE *fp = in->complexity_bytes
        ? platform_memory_stream_open_read(in->complexity_bytes, in->complexity_len)
        : fopen(in->baseline, "r");
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
    if (fp && ferror(fp))
        ok = false;
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
                     brief_push_pins(card, in, tgt->path)));
}

static bool brief_unattributed_boot(const struct json_value *row)
{
    const char *id = json_get_str(json_get(row, "id"));
    const char *note = json_get_str(json_get(row, "note"));
    return id && strcmp(id, "node_warm_restart_s") == 0 &&
           note && strstr(note, "source identity unavailable") != NULL;
}

/* The measured rows narrowed to `only_id` (when set) and to runner_ok rows
 * (when `runner_only`), as a new array. Automatic selection never issues a
 * card from an unattributed boot sample; explicit inspection retains it.
 * False on allocation failure. */
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
        if (!only_id && brief_unattributed_boot(row))
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

/* ---- Baseline-row cards: one shrink-only baseline row per card ---------- */

/* A closed table: the objectives whose work is one row of a shrink-only lint
 * baseline. `parse` splits a baseline line in place and yields the repo path
 * the row is about (false for comments and rows of other rules). The card
 * is always the cheapest level: the recipe is mechanical. */
struct brief_baseline {
    const char *id;
    const char *path;
    const char *recipe;
    const char *review_focus;
    bool (*parse)(char *line, char **path);
};

/* "banned-str PATH COUNT" -> PATH, for a COUNT of at least 1. */
static bool brief_parse_banned(char *line, char **path)
{
    static const char rule[] = "banned-str ";
    char *sp;
    line[strcspn(line, "\r\n")] = '\0';
    if (strncmp(line, rule, sizeof(rule) - 1) != 0)
        return false;
    sp = strrchr(line, ' ');
    if (sp <= line + sizeof(rule) - 1 || atoi(sp + 1) < 1)
        return false;
    *sp = '\0';
    *path = line + sizeof(rule) - 1;
    return true;
}

static const struct brief_baseline k_baselines[] = {
    {"baseline_hardening_banned_str", "tools/lint/hardening_ratchet_baseline.txt",
     "Replace each strcpy, strcat, sprintf, vsprintf and gets call in the "
     "target file with the bounded form the codebase already uses: snprintf "
     "with sizeof the destination (there is no shared safe-string helper), "
     "or memcpy of a length you checked; then lower COUNT in the row to the "
     "new finding count, or delete the row at 0.",
     "Every replacement keeps the same bytes for inputs that fit; truncation "
     "cannot cut a value a caller relies on; a return value or length the "
     "old code relied on is still checked.",
     brief_parse_banned},
};

static const struct brief_baseline *brief_baseline_find(const char *id)
{
    for (size_t i = 0; id && i < sizeof(k_baselines) / sizeof(k_baselines[0]);
         i++)
        if (strcmp(k_baselines[i].id, id) == 0)
            return &k_baselines[i];
    return NULL;
}

struct brief_row {
    char path[240];
    char text[512];
};

/* Offers one baseline line as the pick: it must parse, be eligible (never a
 * file under a tests/ directory either) and sort before the current pick. */
static void brief_row_offer(const struct brief_inputs *in, const char *owned,
                            const struct brief_baseline *bl, const char *line,
                            struct brief_row *best, bool *found)
{
    char copy[1024], *path;
    (void)snprintf(copy, sizeof(copy), "%s", line);
    if (!bl->parse(copy, &path) || strlen(path) >= sizeof(best->path) ||
        strlen(line) >= sizeof(best->text) ||
        !brief_eligible(in, owned, path) || strstr(path, "/tests/") ||
        (*found && strcmp(path, best->path) >= 0))
        return;
    (void)snprintf(best->path, sizeof(best->path), "%s", path);
    (void)snprintf(best->text, sizeof(best->text), "%s", line);
    best->text[strcspn(best->text, "\r\n")] = '\0';
    *found = true;
}

/* Chooses the first eligible row by path order. 0 found, 1 none eligible,
 * -1 baseline unreadable. */
static int brief_choose_row(const struct brief_inputs *in, const char *owned,
                            const struct brief_baseline *bl,
                            struct brief_row *best)
{
    char full[1024], line[1024];
    bool found = false;
    FILE *fp;
    char *blob = NULL;
    size_t len = 0;
    if (snprintf(full, sizeof(full), "%s/%s", in->repo, bl->path) >=
        (int)sizeof(full))
        return -1;
    if (in->revision[0]) {
        blob = zcl_objectives_checkout_blob(in->repo, in->revision, bl->path, &len);
        if (!blob)
            return -1;
        if (!len) {
            free(blob);
            return 1;
        }
        fp = platform_memory_stream_open_read(blob, len);
    } else {
        fp = fopen(full, "r");
    }
    if (!fp) {
        free(blob);
        return -1;
    }
    while (fgets(line, sizeof(line), fp))
        brief_row_offer(in, owned, bl, line, best, &found);
    bool read_error = ferror(fp) != 0;
    (void)fclose(fp);
    free(blob);
    if (read_error)
        return -1;
    return found ? 0 : 1;
}

/* Pushes the card fields that make it a baseline-row card. */
static bool brief_push_row_fields(struct json_value *card,
                                  const struct brief_work *work,
                                  const struct brief_baseline *bl,
                                  const struct brief_row *row)
{
    return json_push_kv_str(card, "kind", "baseline_row") &&
           json_push_kv_str(card, "target_file", row->path) &&
           json_push_kv_str(card, "baseline", bl->path) &&
           json_push_kv_str(card, "row", row->text) &&
           json_push_kv_str(card, "recipe", bl->recipe) &&
           json_push_kv_str(card, "verify", work->acceptance) &&
           json_push_kv_str(card, "review_focus", bl->review_focus);
}

static bool brief_build_row(struct json_value *card,
                            const struct json_value *next,
                            const struct brief_work *work,
                            const struct brief_baseline *bl,
                            const struct brief_row *row)
{
    char name[WORK_CARD_NAME_MAX + 1], outcome[512];
    struct json_value owned;
    bool ok;
    brief_name(work->id, name, sizeof(name));
    (void)snprintf(outcome, sizeof(outcome),
                   "Clear the baseline row \"%s\" by fixing the findings in "
                   "%s, then shrink the row.",
                   row->text, row->path);
    json_init(&owned);
    json_set_array(&owned);
    ok = json_push_kv_str(card, "schema", WORK_CARD_SCHEMA_ID) &&
         json_push_kv_str(card, "name", name) &&
         json_push_kv_str(card, "level", "haiku") &&
         json_push_kv_str(card, "outcome", outcome) &&
         brief_push_str_item(&owned, row->path) &&
         brief_push_str_item(&owned, bl->path) &&
         json_push_kv(card, "owned", &owned) &&
         brief_push_csv(card, "forbidden", k_brief_forbidden) &&
         brief_push_one(card, "contract",
                        "Keep behaviour unchanged; never weaken a test, "
                        "assertion, threshold or baseline.") &&
         json_push_kv_str(card, "acceptance", work->acceptance) &&
         brief_push_one(card, "stop_if", work->stop_if) &&
         brief_push_objective(card, next, work) &&
         brief_push_row_fields(card, work, bl, row);
    json_free(&owned);
    return ok;
}

/* The baseline-row reply: the card for the first eligible row, or a typed
 * no-card when none is eligible. */
static void brief_finish_row(struct zcl_command_reply *reply,
                             const struct json_value *next,
                             const struct brief_work *work,
                             const struct brief_baseline *bl,
                             const struct brief_inputs *in)
{
    struct brief_row row = {{0}, {0}};
    int rc = brief_choose_row(in, work->owned, bl, &row);
    if (rc > 0)
        brief_no_card(reply,
                      "no baseline row is eligible: every row is protected, a "
                      "test, missing, over 1300 lines or excluded",
                      "NO_ELIGIBLE_ROW");
    else if (rc < 0 || !brief_build_row(&reply->data, next, work, bl, &row))
        brief_fail_build(reply, work->id);
    else
        brief_pass(reply);
}

/* Builds the card for the pick; the complexity card is narrowed to one file
 * first, and when no file is eligible the reply is a typed no-card. */
static void brief_finish(struct zcl_command_reply *reply,
                         const struct json_value *next,
                         const struct brief_work *work,
                         const struct brief_inputs *in)
{
    const struct brief_baseline *bl = work ? brief_baseline_find(work->id) : NULL;
    struct brief_file file;
    bool narrow = work && strcmp(work->id, BRIEF_COMPLEXITY_ID) == 0;
    int rc;
    if (bl) {
        brief_finish_row(reply, next, work, bl, in);
        return;
    }
    struct brief_inputs selected = *in;
    if (narrow && !in->baseline && in->revision[0]) {
        selected.complexity_bytes = zcl_objectives_checkout_blob(
            in->repo, in->revision, BRIEF_BASELINE_DEFAULT, &selected.complexity_len);
        if (!selected.complexity_bytes) {
            brief_fail_build(reply, work->id);
            return;
        }
    }
    rc = narrow ? brief_choose(&selected, work->owned, &file) : 0;
    if (rc > 0)
        brief_no_card(reply,
                      "no file is eligible for the complexity card: every "
                      "pinned file is protected, a test, missing, over 1300 "
                      "lines, excluded or changed by a live worktree",
                      "NO_ELIGIBLE_FILE");
    else if (rc < 0 || !work ||
             !brief_build(&reply->data, next, work, &selected, narrow ? &file : NULL))
        brief_fail_build(reply, json_get_str(json_get(next, "id")));
    else
        brief_pass(reply);
    free(selected.complexity_bytes);
}

/* With runner_ok_only, records the unmet objective that ranks first overall
 * when it is not runner_ok and so was passed over: `skipped`, an array of
 * {objective, reason}. Read by the loop step, which would otherwise measure
 * twice (once plain, once narrowed) to learn it. Absent when nothing was
 * passed over. */
static void brief_note_skipped(struct zcl_command_reply *reply,
                               const struct json_value *rows)
{
    struct json_value top, arr, item;
    const char *id;
    const struct brief_work *work;
    json_init(&top);
    json_init(&arr);
    json_init(&item);
    if (zcl_objectives_next(rows, &top) && !json_is_null(&top)) {
        id = json_get_str(json_get(&top, "id"));
        work = brief_find(id);
        json_set_array(&arr);
        json_set_object(&item);
        if (work && !work->runner_ok &&
            json_push_kv_str(&item, "objective", id) &&
            json_push_kv_str(&item, "reason", "not runner_ok") &&
            json_push_back(&arr, &item))
            (void)json_push_kv(&reply->data, "skipped", &arr);
    }
    json_free(&item);
    json_free(&arr);
    json_free(&top);
}

/* True when `arr` (an array of strings) holds `name`. */
static bool brief_has_name(const struct json_value *arr, const char *name)
{
    for (size_t i = 0; i < arr->num_children; i++)
        if (strcmp(json_get_str(&arr->children[i]), name) == 0)
            return true;
    return false;
}

/* The rows whose card is not named in `taken`, as a new array. */
static bool brief_without(const struct json_value *rows,
                          const struct json_value *taken, struct json_value *out)
{
    json_set_array(out);
    for (size_t i = 0; i < rows->num_children; i++) {
        char name[WORK_CARD_NAME_MAX + 1];
        brief_name(json_get_str(json_get(&rows->children[i], "id")), name,
                   sizeof(name));
        if (!brief_has_name(taken, name) &&
            !json_push_back(out, &rows->children[i]))
            return false;
    }
    return true;
}

/* The first unmet card no lane has taken. `taken` collects the names passed
 * over, best first; when every unmet card is taken the top one comes back
 * with *all_taken set. `text` (the worktree list) NULL takes nothing. */
static bool brief_pick_free(const struct json_value *rows, const char *text,
                            struct json_value *next, struct json_value *taken,
                            bool *all_taken)
{
    struct json_value rest;
    bool ok = true;
    json_set_array(taken);
    *all_taken = false;
    for (;;) {
        char name[WORK_CARD_NAME_MAX + 1];
        json_init(&rest);
        ok = brief_without(rows, taken, &rest) && zcl_objectives_next(&rest, next);
        json_free(&rest);
        if (!ok || json_is_null(next))
            break;
        brief_name(json_get_str(json_get(next, "id")), name, sizeof(name));
        if (!text || !zcl_objectives_card_taken(text, name))
            return true;
        ok = brief_push_str_item(taken, name);
        json_free(next);
        json_init(next);
        if (!ok)
            return false;
    }
    if (ok && taken->num_children > 0) {
        *all_taken = true;
        ok = zcl_objectives_next(rows, next);
    }
    return ok;
}

/* What the pick reports about the lanes: the names passed over, whether all
 * were, and whether the worktree list could be read at all. */
static void brief_note_taken(struct zcl_command_reply *reply,
                             const struct json_value *taken, bool all_taken,
                             const char *scan)
{
    (void)json_push_kv(&reply->data, "taken", taken);
    (void)json_push_kv_bool(&reply->data, "all_taken", all_taken);
    (void)json_push_kv_str(&reply->data, "worktree_scan", scan);
}

struct brief_lanes {
    struct json_value taken;
    bool all_taken;
    char scan[ZCL_OBJECTIVES_REASON_MAX]; /* "" when no scan was asked for */
};

/* The pick over the narrowed rows. An explicit id briefs that row whatever
 * the lanes hold; otherwise the first card no worktree has taken. A worktree
 * list that cannot be read takes nothing, and `scan` says why. */
static bool brief_pick(const struct json_value *narrowed, const char *id,
                       const struct brief_inputs *in, struct json_value *next,
                       struct brief_lanes *lanes)
{
    char why[160];
    char *text;
    bool ok;
    json_init(&lanes->taken);
    lanes->all_taken = false;
    lanes->scan[0] = '\0';
    if (id)
        return zcl_objectives_next(narrowed, next);
    text = zcl_objectives_worktree_text(in->repo, in->worktrees, why,
                                        sizeof(why));
    (void)snprintf(lanes->scan, sizeof(lanes->scan), "%s%s", text ? "ok" : "unavailable: ",
                   text ? "" : why);
    ok = brief_pick_free(narrowed, text, next, &lanes->taken, &lanes->all_taken);
    free(text);
    return ok;
}

/* Fills the reply from the narrowed rows; the pick is zcl_objectives_next. */
static void brief_reply(struct zcl_command_reply *reply,
                        const struct json_value *rows, const char *id,
                        bool runner_only, const struct brief_inputs *in)
{
    struct json_value narrowed, next;
    struct brief_lanes lanes;
    bool ok;
    json_init(&narrowed);
    json_init(&next);
    json_init(&lanes.taken);
    lanes.scan[0] = '\0';
    ok = brief_narrow(rows, id, runner_only, &narrowed) &&
         brief_pick(&narrowed, id, in, &next, &lanes);
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
    if (ok && runner_only && !id && reply->status == ZCL_COMMAND_STATUS_PASSED)
        brief_note_skipped(reply, rows);
    if (ok && lanes.scan[0] && reply->status == ZCL_COMMAND_STATUS_PASSED)
        brief_note_taken(reply, &lanes.taken, lanes.all_taken, lanes.scan);
    json_free(&lanes.taken);
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
    char revision[65];

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
    const char *repo = brief_str(request, "repo", ".");
    if (!zcl_objectives_checkout_revision(repo, revision)) {
        brief_fail_build(reply, "origin/main");
        return;
    }
    memset(&measured, 0, sizeof(measured));
    zcl_native_handle_fleet_objectives_revision(request, &measured, revision);
    rows = json_get(&measured.data, "objectives");
    if (measured.status != ZCL_COMMAND_STATUS_PASSED || !rows) {
        LOG_ERROR("fleet.objectives.brief", "the objectives did not measure");
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "OBJECTIVES_FAILED",
                               "decide", false, false,
                               "fleet.objectives could not measure the catalog",
                               "z23-dev fleet objectives");
    } else {
        struct brief_inputs in = { .repo = brief_str(request, "repo", "."),
            .baseline = brief_str(request, "baseline", NULL),
            .exclude = brief_str(request, "exclude", ""), .revision = revision,
            .worktrees = brief_str(request, "worktrees", NULL) };
        brief_reply(reply, rows, id, runner_only, &in);
    }
    zcl_command_reply_free(&measured);
}
