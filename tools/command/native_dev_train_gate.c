/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the gate runner behind `dev train check --gates=...`. It runs the
 *          selected gates (fast = make lint-fast, lint = make lint, verify =
 *          make agent-verify ONLY=@changed) in a stack worktree, in that order,
 *          under the checkout-wide build lock, and stops at the first red one.
 *          After a red verify it names which source lane of the stack owns each
 *          failed test group, using the proof's own selector per source.
 *
 * The sources come from the record `dev train build` leaves in the stack
 * worktree's git dir (zcl_dev_train_record_sources); the group selector is
 * zcl_dev_proof_select_range, the same planner `dev proof select` and
 * agent-verify use. Neither is reimplemented here. Make runs through
 * zcl_devloop_process_run(); git through zcl_dev_train_git().
 */

#include "command/native_command.h"
#include "command/native_dev_train_command.h"

#include "base/safe_alloc.h"
#include "dev_proof.h"
#include "devloop.h"
#include "json/json.h"
#include "platform/directory_compat.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)

#define DTG_GIT_TIMEOUT_MS 60000
#define DTG_MAX_GROUPS 256
#define DTG_MAX_SOURCES 16
#define DTG_FAILED_CAP 16384
#define DTG_VERDICT_MAX (1u << 20)
#define DTG_RECORD_NAME "zcl-train-sources"
#define DTG_VERIFY_LOG "build/scratch/agent-verify.t-fast-exact.log"

struct dtg_gate {
    const char *token;
    unsigned bit;
    const char *target;
};

/* The run order is the table order. */
static const struct dtg_gate dtg_gates[] = {
    {"fast", ZCL_DEV_TRAIN_GATE_FAST, "lint-fast"},
    {"lint", ZCL_DEV_TRAIN_GATE_LINT, "lint"},
    {"verify", ZCL_DEV_TRAIN_GATE_VERIFY, "agent-verify"},
};
#define DTG_GATE_COUNT (sizeof(dtg_gates) / sizeof(dtg_gates[0]))

static struct zcl_dev_train_gate_hooks dtg_hooks;

/* ── parse ────────────────────────────────────────────────────────────── */

bool zcl_dev_train_gates_parse(const char *csv, unsigned *mask, char *why,
                               size_t why_cap)
{
    char buf[128];
    *mask = 0;
    if (!csv || strlen(csv) >= sizeof(buf)) {
        (void)snprintf(why, why_cap,
                       "gates must be a comma list of: fast, lint, verify");
        return false;
    }
    (void)snprintf(buf, sizeof(buf), "%s", csv);
    char *save = NULL;
    for (char *tok = strtok_r(buf, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        unsigned bit = 0;
        for (size_t i = 0; i < DTG_GATE_COUNT; i++)
            if (strcmp(tok, dtg_gates[i].token) == 0)
                bit = dtg_gates[i].bit;
        if (!bit) {
            (void)snprintf(why, why_cap,
                           "unknown gate token '%s'; allowed tokens: fast "
                           "(make lint-fast), lint (make lint), verify "
                           "(make agent-verify ONLY=@changed)",
                           tok);
            return false;
        }
        *mask |= bit;
    }
    if (*mask == 0)
        (void)snprintf(why, why_cap,
                       "no gate named; allowed tokens: fast, lint, verify");
    return *mask != 0;
}

/* ── hooks ────────────────────────────────────────────────────────────── */

static bool dtg_run_default(const char *stack_dir, const char *gate,
                            const char *const argv[], int timeout_ms,
                            struct zcl_devloop_process_result *out)
{
    (void)gate;
    return zcl_devloop_process_run(stack_dir, argv, timeout_ms, out);
}

static bool dtg_select_default(const char *source_root, const char *tip,
                               char *groups, size_t groups_cap,
                               bool *universal)
{
    const char *mb_args[] = {"merge-base", "origin/main", tip, NULL};
    char base[128], why[256];
    if (zcl_dev_train_git(source_root, mb_args, base, sizeof(base),
                          DTG_GIT_TIMEOUT_MS) != 0)
        return false;
    zcl_dev_train_strip(base);
    struct zcl_dev_proof_range_selection sel;
    memset(&sel, 0, sizeof(sel));
    sel.groups = groups;
    sel.groups_size = groups_cap;
    if (!zcl_dev_proof_select_range(source_root, base, tip, &sel, why,
                                    sizeof(why)))
        return false;
    *universal = sel.universal;
    return true;
}

void zcl_dev_train_gate_hooks_set(const struct zcl_dev_train_gate_hooks *hooks)
{
    memset(&dtg_hooks, 0, sizeof(dtg_hooks));
    if (hooks)
        dtg_hooks = *hooks;
}

/* ── build-time source record ─────────────────────────────────────────── */

struct dtg_source {
    char source[512];
    char tip[64];
};

static bool dtg_record_path(const char *stack_dir, char *out, size_t cap)
{
    const char *args[] = {"rev-parse", "--absolute-git-dir", NULL};
    char gitdir[PATH_MAX];
    if (zcl_dev_train_git(stack_dir, args, gitdir, sizeof(gitdir),
                          DTG_GIT_TIMEOUT_MS) != 0)
        return false;
    zcl_dev_train_strip(gitdir);
    return gitdir[0] &&
           snprintf(out, cap, "%s/" DTG_RECORD_NAME, gitdir) < (int)cap;
}

static bool dtg_source_tip(const char *source, const char *root, char *tip,
                           size_t cap)
{
    bool is_dir = zcl_dev_train_is_dir(source);
    const char *args[] = {"rev-parse", "--verify", "-q",
                          is_dir ? "HEAD" : source, NULL};
    if (zcl_dev_train_git(is_dir ? source : root, args, tip, cap,
                          DTG_GIT_TIMEOUT_MS) != 0)
        return false;
    zcl_dev_train_strip(tip);
    return tip[0] != '\0';
}

void zcl_dev_train_record_sources(const char *stack_dir, const char *root,
                                  const char *sources_csv)
{
    char path[PATH_MAX], buf[ZCL_COMMAND_MAX_INPUT];
    if (!sources_csv || !dtg_record_path(stack_dir, path, sizeof(path)))
        return;
    FILE *f = fopen(path, "wb");
    if (!f)
        return;
    (void)snprintf(buf, sizeof(buf), "%s", sources_csv);
    char *save = NULL;
    for (char *src = strtok_r(buf, "\n", &save); src;
         src = strtok_r(NULL, "\n", &save)) {
        char tip[64];
        if (strchr(src, '\t') || !dtg_source_tip(src, root, tip, sizeof(tip)))
            continue;
        (void)fprintf(f, "%s\t%s\n", src, tip);
    }
    (void)fclose(f);
}

static size_t dtg_read_sources(const char *stack_dir, struct dtg_source *out,
                               size_t max)
{
    char path[PATH_MAX], line[1024];
    size_t n = 0;
    if (!dtg_record_path(stack_dir, path, sizeof(path)))
        return 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    while (n < max && fgets(line, sizeof(line), f)) {
        zcl_dev_train_strip(line);
        char *tab = strchr(line, '\t');
        if (!tab || (size_t)(tab - line) >= sizeof(out[n].source))
            continue;
        *tab = '\0';
        (void)snprintf(out[n].source, sizeof(out[n].source), "%s", line);
        (void)snprintf(out[n].tip, sizeof(out[n].tip), "%s", tab + 1);
        n++;
    }
    (void)fclose(f);
    return n;
}

/* ── failed groups ────────────────────────────────────────────────────── */

static void dtg_csv_add(char *csv, size_t cap, const char *name)
{
    size_t len = strlen(csv);
    if (!name[0] || len + strlen(name) + 2 > cap)
        return;
    (void)snprintf(csv + len, cap - len, "%s%s", len ? "," : "", name);
}

/* Heap copy of a stack file, NUL-terminated; NULL when absent or oversize. */
static char *dtg_slurp(const char *stack_dir, const char *rel, size_t *len)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", stack_dir, rel) >=
        (int)sizeof(path))
        return NULL;
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    char *buf = zcl_malloc(DTG_VERDICT_MAX + 1u, "train gate file");
    if (buf) {
        *len = fread(buf, 1, DTG_VERDICT_MAX + 1u, f);
        if (*len > DTG_VERDICT_MAX) {
            free(buf);
            buf = NULL;
        } else {
            buf[*len] = '\0';
        }
    }
    (void)fclose(f);
    return buf;
}

static bool dtg_failed_from_verdict(const char *stack_dir, char *csv,
                                    size_t cap)
{
    size_t len = 0;
    char *buf = dtg_slurp(stack_dir, "build/test-verdict.json", &len);
    struct json_value doc;
    if (!buf)
        return false;
    json_init(&doc);
    bool ok = json_read(&doc, buf, len) && doc.type == JSON_OBJ;
    free(buf);
    if (!ok) {
        json_free(&doc);
        return false;
    }
    const struct json_value *arr = json_get(&doc, "failed_groups");
    for (size_t i = 0; arr && arr->type == JSON_ARR && i < json_size(arr); i++) {
        const struct json_value *s = json_at(arr, i);
        if (s && s->type == JSON_STR && json_get_str(s))
            dtg_csv_add(csv, cap, json_get_str(s));
    }
    json_free(&doc);
    return csv[0] != '\0';
}

/* Fallback: the `FAIL <group>` lines of the t-fast-exact step log the
 * Makefile agent-verify recipe names. */
static bool dtg_failed_from_log(const char *stack_dir, char *csv, size_t cap)
{
    size_t len = 0;
    char *buf = dtg_slurp(stack_dir, DTG_VERIFY_LOG, &len);
    if (!buf)
        return false;
    char *save = NULL;
    for (char *line = strtok_r(buf, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char name[128];
        if (strncmp(line, "FAIL ", 5) != 0 ||
            sscanf(line + 5, "%127s", name) != 1 || strcmp(name, "at") == 0)
            continue;
        dtg_csv_add(csv, cap, name);
    }
    free(buf);
    return csv[0] != '\0';
}

/* ── attribution ──────────────────────────────────────────────────────── */

struct dtg_group {
    char name[128];
    uint32_t candidates;
    bool universal;
};

struct dtg_attr {
    struct dtg_group groups[DTG_MAX_GROUPS];
    size_t group_count;
    struct dtg_source sources[DTG_MAX_SOURCES];
    size_t source_count;
};

static bool dtg_csv_has(const char *csv, const char *name)
{
    size_t n = strlen(name);
    for (const char *p = csv; p && *p;) {
        const char *end = strchr(p, ',');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len == n && strncmp(p, name, n) == 0)
            return true;
        p = end ? end + 1 : NULL;
    }
    return false;
}

static void dtg_load_groups(struct dtg_attr *a, const char *failed_csv)
{
    char buf[DTG_FAILED_CAP];
    (void)snprintf(buf, sizeof(buf), "%s", failed_csv);
    char *save = NULL;
    for (char *g = strtok_r(buf, ",", &save); g && a->group_count < DTG_MAX_GROUPS;
         g = strtok_r(NULL, ",", &save))
        (void)snprintf(a->groups[a->group_count++].name,
                       sizeof(a->groups[0].name), "%s", g);
}

/* Mark every failed group that source `idx` selects. A source whose selection
 * is universal, or cannot be computed, may own any group: it is a candidate
 * for all of them and makes each one ambiguous. */
static void dtg_mark_source(struct dtg_attr *a, size_t idx, const char *root,
                            char *groups, size_t groups_cap)
{
    bool universal = false;
    bool (*select_fn)(const char *, const char *, char *, size_t, bool *) =
        dtg_hooks.select ? dtg_hooks.select : dtg_select_default;
    groups[0] = '\0';
    if (!select_fn(root, a->sources[idx].tip, groups, groups_cap, &universal))
        universal = true;
    for (size_t g = 0; g < a->group_count; g++) {
        if (!universal && !dtg_csv_has(groups, a->groups[g].name))
            continue;
        a->groups[g].candidates |= 1u << idx;
        a->groups[g].universal = a->groups[g].universal || universal;
    }
}

static void dtg_push_row(struct json_value *rows, const struct dtg_attr *a,
                         const struct dtg_group *g)
{
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "group", g->name);
    if (__builtin_popcount(g->candidates) == 1 && !g->universal) {
        for (size_t i = 0; i < a->source_count; i++)
            if (g->candidates & (1u << i))
                (void)json_push_kv_str(&row, "guilty", a->sources[i].source);
    } else {
        struct json_value list;
        json_init(&list);
        json_set_array(&list);
        for (size_t i = 0; i < a->source_count; i++) {
            if (!(g->candidates & (1u << i)))
                continue;
            struct json_value s;
            json_init(&s);
            json_set_str(&s, a->sources[i].source);
            (void)json_push_back(&list, &s);
            json_free(&s);
        }
        (void)json_push_kv(&row, "candidates", &list);
        json_free(&list);
    }
    (void)json_push_back(rows, &row);
    json_free(&row);
}

static void dtg_attribute(const char *stack_dir, const char *root,
                          struct zcl_dev_train_gate_report *report)
{
    char failed[DTG_FAILED_CAP] = {0};
    report->attribution_from = "verdict";
    if (!dtg_failed_from_verdict(stack_dir, failed, sizeof(failed))) {
        report->attribution_from = "log";
        if (!dtg_failed_from_log(stack_dir, failed, sizeof(failed)))
            return;
    }
    struct dtg_attr *a = zcl_calloc(1, sizeof(*a), "train gate attribution");
    size_t cap = zcl_dev_proof_select_groups_capacity();
    char *groups = zcl_calloc(cap, 1, "train gate selection");
    if (a && groups) {
        dtg_load_groups(a, failed);
        a->source_count = dtg_read_sources(stack_dir, a->sources,
                                           DTG_MAX_SOURCES);
        for (size_t i = 0; i < a->source_count; i++)
            dtg_mark_source(a, i,
                            zcl_dev_train_is_dir(a->sources[i].source)
                                ? a->sources[i].source
                                : root,
                            groups, cap);
        for (size_t g = 0; g < a->group_count; g++)
            dtg_push_row(report->attribution, a, &a->groups[g]);
    }
    free(groups);
    free(a);
}

/* ── run ──────────────────────────────────────────────────────────────── */

/* Collect the exact `FAIL <gate>` names a red make printed. */
static void dtg_collect_fail_gates(char *output, char *csv, size_t cap)
{
    char *save = NULL;
    for (char *line = strtok_r(output, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char gate[256];
        if (strncmp(line, "FAIL ", 5) == 0 &&
            sscanf(line + 5, "%255s", gate) == 1)
            dtg_csv_add(csv, cap, gate);
    }
}

static void dtg_write_log(const char *stack_dir, const char *token,
                          const struct zcl_devloop_process_result *r,
                          char *log_path, size_t cap)
{
    char build_dir[PATH_MAX];
    (void)snprintf(log_path, cap, "%s/build/train-check.%s.log", stack_dir,
                   token);
    (void)platform_directory_ensure(stack_dir, 0700);
    (void)snprintf(build_dir, sizeof(build_dir), "%s/build", stack_dir);
    (void)platform_directory_ensure(build_dir, 0700);
    FILE *f = fopen(log_path, "wb");
    if (f) {
        (void)fwrite(r->output, 1, r->output_len, f);
        (void)fclose(f);
    }
}

static void dtg_push_gate_row(struct json_value *rows, const char *token,
                              const char *verdict, int64_t wall_ms,
                              const char *log_path)
{
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "gate", token);
    (void)json_push_kv_str(&row, "verdict", verdict);
    (void)json_push_kv_int(&row, "wall_ms", wall_ms);
    (void)json_push_kv_str(&row, "log_path", log_path);
    (void)json_push_back(rows, &row);
    json_free(&row);
}

/* Run one gate; true when it was green. */
static bool dtg_run_one(const char *stack_dir, const struct dtg_gate *gate,
                        int timeout_ms,
                        struct zcl_dev_train_gate_report *report)
{
    const char *argv[] = {"tools/dev/checkout-lock.sh", "foreground",
                          "build/.checkout.lock", "--", "make",
                          "--no-print-directory", gate->target, NULL, NULL};
    if (gate->bit == ZCL_DEV_TRAIN_GATE_VERIFY) {
        /* A verdict left by an earlier run must never name this run's groups. */
        char stale[PATH_MAX];
        (void)snprintf(stale, sizeof(stale), "%s/build/test-verdict.json",
                       stack_dir);
        (void)remove(stale);
        argv[7] = "ONLY=@changed";
    }
    bool (*run_fn)(const char *, const char *, const char *const[], int,
                   struct zcl_devloop_process_result *) =
        dtg_hooks.run ? dtg_hooks.run : dtg_run_default;
    struct zcl_devloop_process_result *r =
        zcl_calloc(1, sizeof(*r), "train gate result");
    bool ran = r && run_fn(stack_dir, gate->token, argv, timeout_ms, r);
    bool ok = ran && r->exit_code == 0 && !r->timed_out;
    if (ran) {
        dtg_write_log(stack_dir, gate->token, r, report->log_path,
                      sizeof(report->log_path));
        report->wall_ms += r->elapsed_ms;
        if (!ok)
            dtg_collect_fail_gates(r->output, report->gates_failed_csv,
                                   sizeof(report->gates_failed_csv));
    }
    dtg_push_gate_row(report->gates, gate->token,
                      ok ? "passed"
                         : (!ran ? "exec_failed"
                                 : (r->timed_out ? "timed_out" : "failed")),
                      ran ? r->elapsed_ms : 0, ran ? report->log_path : "");
    free(r);
    return ok;
}

void zcl_dev_train_run_gates(const char *stack_dir, const char *root,
                             unsigned mask, int timeout_ms,
                             struct zcl_dev_train_gate_report *report)
{
    report->ok = true;
    for (size_t i = 0; i < DTG_GATE_COUNT && report->ok; i++) {
        if (!(mask & dtg_gates[i].bit))
            continue;
        report->ok = dtg_run_one(stack_dir, &dtg_gates[i], timeout_ms, report);
        if (!report->ok && dtg_gates[i].bit == ZCL_DEV_TRAIN_GATE_VERIFY)
            dtg_attribute(stack_dir, root, report);
    }
}

#endif /* ZCL_DEV_BUILD || ZCL_TESTING */
