/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.cx.next. Draws complexity-split units from the pinned
 *          cyclomatic-complexity baseline: one unit per file, fewest
 *          functions first, then lowest max score, then path. Skips sealed,
 *          custody-owned and pinned-root paths, files of 1300 or more lines,
 *          files any worktree of this repository changes against origin/main,
 *          and files named in exclude=. Read-only; ports cx-swarm's picker. */

#include "command/native_command.h"
#include "command/native_dev_cx.h"

#include "base/safe_alloc.h"
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CX_LINES_CAP 1300
#define CX_COUNT_DEFAULT 10
#define CX_COUNT_MAX 200
#define CX_GIT_CAP (4u * 1024u * 1024u)
#define CX_GIT_MS 300000

enum cx_skip {
    CX_KEEP,
    CX_SKIP_SEALED,
    CX_SKIP_CUSTODY,
    CX_SKIP_PACKAGES,
    CX_SKIP_LARGE,
    CX_SKIP_CHANGED,
    CX_SKIP_EXCLUDED,
    CX_SKIP_PREFIX,
    CX_SKIP_MISSING,
    CX_SKIP_KINDS
};

static const char *const k_skip_name[CX_SKIP_KINDS] = {
    "kept", "sealed", "custody", "packages", "large", "changed", "excluded",
    "prefix", "missing"
};

/* Paths the custody checks own, named after the groups of the Makefile's
 * CUSTODY_FOCUSED_TESTS plus the wallet room. A substring match is
 * deliberately wide: a skipped unit costs a pick, a wrong one costs custody. */
static const char *const k_custody_marks[] = {
    "wallet", "custody", "vault", "agent_session", "agent_spend_policy",
    "transaction_intent", "metaverse_agent_broker"
};

struct cx_args {
    int count;
    char cwd[ZCL_CX_PATH_MAX];
    char exclude[ZCL_CX_PATH_MAX];
    char prefix[ZCL_CX_PATH_MAX];
};

struct cx_sets {
    struct cx_set excluded; /* exclude= file */
    struct cx_set changed;  /* changed by a worktree against origin/main */
};

struct cx_unit {
    size_t first, n;
    int max, lines;
};

static void cx_fail(struct zcl_command_reply *reply, const char *code,
                    const char *msg, const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "dev.cx.next", false,
                           false, msg, evidence);
}

static bool cx_arg_str(const struct json_value *in, const char *key,
                       char *out, size_t cap)
{
    const struct json_value *v = json_get(in, key);
    const char *s = v ? json_get_str(v) : NULL;
    if (!s || !s[0]) {
        out[0] = '\0';
        return true;
    }
    return snprintf(out, cap, "%s", s) < (int)cap;
}

static bool cx_args_parse(const struct json_value *in, struct cx_args *a)
{
    const struct json_value *count = in ? json_get(in, "count") : NULL;
    a->count = CX_COUNT_DEFAULT;
    if (count && count->type == JSON_INT)
        a->count = (int)json_get_int(count);
    if (a->count < 1 || a->count > CX_COUNT_MAX)
        return false;
    return cx_arg_str(in, "cwd", a->cwd, sizeof(a->cwd)) &&
           cx_arg_str(in, "exclude", a->exclude, sizeof(a->exclude)) &&
           cx_arg_str(in, "prefix", a->prefix, sizeof(a->prefix));
}

static bool cx_has_prefix(const char *file, const char *csv)
{
    if (!csv[0])
        return true;
    for (const char *p = csv; *p;) {
        size_t n = strcspn(p, ",");
        if (n > 0 && strncmp(file, p, n) == 0)
            return true;
        p += n + (p[n] == ',' ? 1 : 0);
    }
    return false;
}

static bool cx_custody_owned(const char *file)
{
    for (size_t i = 0; i < sizeof(k_custody_marks) / sizeof(*k_custody_marks);
         i++)
        if (strstr(file, k_custody_marks[i]))
            return true;
    return false;
}

static int cx_count_lines(const char *root, const char *file)
{
    char path[ZCL_CX_PATH_MAX];
    size_t len = 0;
    int lines = 0;
    char *text;
    if (snprintf(path, sizeof(path), "%s/%s", root, file) >= (int)sizeof(path))
        return -1;
    text = cx_read_file(path, &len);
    if (!text)
        return -1;
    for (size_t i = 0; i < len; i++)
        lines += text[i] == '\n';
    free(text);
    return lines;
}

static enum cx_skip cx_classify(const char *root, const char *file,
                                const struct cx_sets *sets,
                                const struct cx_args *a, int *lines)
{
    if (strncmp(file, "core/", 5) == 0)
        return CX_SKIP_SEALED;
    if (strncmp(file, "contexts/commons/packages/", 26) == 0)
        return CX_SKIP_PACKAGES;
    if (cx_custody_owned(file))
        return CX_SKIP_CUSTODY;
    if (!cx_has_prefix(file, a->prefix))
        return CX_SKIP_PREFIX;
    if (cx_set_has(&sets->excluded, file))
        return CX_SKIP_EXCLUDED;
    if (cx_set_has(&sets->changed, file))
        return CX_SKIP_CHANGED;
    *lines = cx_count_lines(root, file);
    if (*lines < 0)
        return CX_SKIP_MISSING;
    return *lines >= CX_LINES_CAP ? CX_SKIP_LARGE : CX_KEEP;
}

/* ── git: root, worktrees and what each changes against origin/main ─────── */

static int cx_git(const char *dir, const char *a, const char *b, const char *c,
                  char *buf)
{
    const char *argv[] = {"git", "-c", "core.quotepath=off", a, b, c, NULL};
    int rc = cx_run(dir, argv, buf, CX_GIT_CAP, CX_GIT_MS, false);
    return rc == 0 && strlen(buf) >= CX_GIT_CAP - 1 ? -1 : rc;
}

static bool cx_root_of(const char *cwd, char *root, size_t cap, char *buf)
{
    if (cx_git(cwd[0] ? cwd : NULL, "rev-parse", "--show-toplevel", NULL, buf) !=
        0)
        return false;
    buf[strcspn(buf, "\r\n")] = '\0';
    return buf[0] && snprintf(root, cap, "%s", buf) < (int)cap;
}

/* ── baseline rows ───────────────────────────────────────────────────────── */

static int cx_row_cmp(const void *x, const void *y)
{
    const struct cx_row *a = x, *b = y;
    int c = strcmp(a->file, b->file);
    return c ? c : strcmp(a->fn, b->fn);
}

static struct cx_row *cx_load_rows(const char *root, size_t *count)
{
    char path[ZCL_CX_PATH_MAX];
    struct cx_row *rows = NULL;
    size_t n = 0, cap = 0, len = 0;
    char *text;
    *count = 0;
    if (snprintf(path, sizeof(path), "%s/%s", root, ZCL_CX_BASELINE_REL) >=
        (int)sizeof(path))
        return NULL;
    text = cx_read_file(path, &len);
    if (!text)
        return NULL;
    for (const char *p = text; *p;) {
        size_t l = strcspn(p, "\n");
        if (n == cap) {
            size_t grow = cap ? cap * 2 : 1024;
            struct cx_row *more =
                zcl_realloc(rows, grow * sizeof(*rows), "dev_cx.rows");
            if (!more) {
                free(rows);
                free(text);
                return NULL;
            }
            rows = more;
            cap = grow;
        }
        if (cx_row_parse(p, l, &rows[n]))
            n++;
        p += l + (p[l] == '\n' ? 1 : 0);
    }
    free(text);
    if (rows)
        qsort(rows, n, sizeof(*rows), cx_row_cmp);
    *count = n;
    return rows;
}

/* ── selection and ordering ──────────────────────────────────────────────── */

struct cx_pick {
    const struct cx_row *rows;
    struct cx_unit unit;
    const char *file;
};

static int cx_pick_cmp(const void *x, const void *y)
{
    const struct cx_pick *a = x, *b = y;
    if (a->unit.n != b->unit.n)
        return a->unit.n < b->unit.n ? -1 : 1;
    if (a->unit.max != b->unit.max)
        return a->unit.max < b->unit.max ? -1 : 1;
    return strcmp(a->file, b->file);
}

static size_t cx_group_end(const struct cx_row *rows, size_t n, size_t i)
{
    size_t j = i;
    while (j < n && strcmp(rows[j].file, rows[i].file) == 0)
        j++;
    return j;
}

static int cx_max_score(const struct cx_row *rows, size_t i, size_t j)
{
    int max = 0;
    for (; i < j; i++)
        if (rows[i].score > max)
            max = rows[i].score;
    return max;
}

static size_t cx_select(const struct cx_row *rows, size_t n, const char *root,
                        const struct cx_sets *sets, const struct cx_args *a,
                        struct cx_pick *picks, size_t *skipped)
{
    size_t kept = 0;
    for (size_t i = 0, j; i < n; i = j) {
        int lines = 0;
        enum cx_skip why;
        j = cx_group_end(rows, n, i);
        why = cx_classify(root, rows[i].file, sets, a, &lines);
        skipped[why]++;
        if (why != CX_KEEP)
            continue;
        picks[kept].rows = rows;
        picks[kept].file = rows[i].file;
        picks[kept].unit = (struct cx_unit){ i, j - i,
                                             cx_max_score(rows, i, j), lines };
        kept++;
    }
    qsort(picks, kept, sizeof(*picks), cx_pick_cmp);
    return kept;
}

/* ── reply ───────────────────────────────────────────────────────────────── */

static bool cx_unit_json(const struct cx_pick *p, struct json_value *out)
{
    struct json_value fns, name;
    bool ok;
    json_init(&fns);
    json_set_array(&fns);
    for (size_t k = 0; k < p->unit.n; k++) {
        json_init(&name);
        json_set_str(&name, p->rows[p->unit.first + k].fn);
        ok = json_push_back(&fns, &name);
        json_free(&name);
        if (!ok) {
            json_free(&fns);
            return false;
        }
    }
    json_set_object(out);
    ok = json_push_kv_str(out, "file", p->file) &&
         json_push_kv(out, "functions", &fns) &&
         json_push_kv_int(out, "max_score", p->unit.max) &&
         json_push_kv_int(out, "lines", p->unit.lines);
    json_free(&fns);
    return ok;
}

static bool cx_skipped_json(const size_t *skipped, struct json_value *out)
{
    json_set_object(out);
    for (int k = CX_KEEP + 1; k < CX_SKIP_KINDS; k++)
        if (!json_push_kv_int(out, k_skip_name[k], (int64_t)skipped[k]))
            return false;
    return true;
}

static bool cx_emit(struct zcl_command_reply *reply, const struct cx_pick *p,
                    size_t kept, const struct cx_args *a, const size_t *skipped)
{
    struct json_value units, unit, skips;
    size_t take = kept < (size_t)a->count ? kept : (size_t)a->count;
    bool ok = true;
    json_init(&units);
    json_set_array(&units);
    json_init(&skips);
    for (size_t i = 0; ok && i < take; i++) {
        json_init(&unit);
        ok = cx_unit_json(&p[i], &unit) && json_push_back(&units, &unit);
        json_free(&unit);
    }
    json_set_object(&reply->data);
    ok = ok && cx_skipped_json(skipped, &skips) &&
         json_push_kv_str(&reply->data, "schema", "zcl.dev_cx_next.v1") &&
         json_push_kv_int(&reply->data, "requested", a->count) &&
         json_push_kv_int(&reply->data, "returned", (int64_t)take) &&
         json_push_kv_int(&reply->data, "available", (int64_t)kept) &&
         json_push_kv(&reply->data, "skipped", &skips) &&
         json_push_kv(&reply->data, "units", &units);
    json_free(&units);
    json_free(&skips);
    return ok;
}

/* ── handler ─────────────────────────────────────────────────────────────── */

static bool cx_load_exclude(const char *path, struct cx_set *set)
{
    char *text;
    bool ok;
    if (!path[0])
        return true;
    text = cx_read_file(path, NULL);
    if (!text)
        return false;
    ok = cx_set_add_lines(set, text);
    free(text);
    return ok;
}

static bool cx_prepare(const struct cx_args *a, char *root, size_t cap,
                       struct cx_sets *sets, struct zcl_command_reply *reply)
{
    char why[ZCL_CX_PATH_MAX + 64];
    char *buf = zcl_malloc(CX_GIT_CAP, "dev_cx.next.git");
    bool ok = false;
    if (!buf) {
        cx_fail(reply, "NEXT_NO_MEMORY", "cannot allocate the git buffer", "");
        return false;
    }
    if (!cx_root_of(a->cwd, root, cap, buf))
        cx_fail(reply, "NEXT_NOT_IN_CHECKOUT",
                "cwd is not inside a git checkout", a->cwd);
    else if (!cx_load_exclude(a->exclude, &sets->excluded))
        cx_fail(reply, "NEXT_EXCLUDE_UNREADABLE",
                "exclude= must name a readable file of paths", a->exclude);
    else if (cx_git(root, "rev-parse", "--verify", "refs/remotes/origin/main",
                    buf) != 0)
        cx_fail(reply, "NEXT_NO_ORIGIN_MAIN",
                "refs/remotes/origin/main is missing; fetch it first", root);
    else if (!cx_changed_files(root, &sets->changed, why, sizeof(why)))
        cx_fail(reply, "NEXT_WORKTREE_SCAN",
                "a worktree could not be compared with origin/main", why);
    else
        ok = true;
    free(buf);
    return ok;
}

void zcl_native_handle_dev_cx_next(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    struct cx_args a;
    struct cx_sets sets;
    struct cx_row *rows = NULL;
    struct cx_pick *picks = NULL;
    size_t n = 0, kept, skipped[CX_SKIP_KINDS] = {0};
    char root[ZCL_CX_PATH_MAX];
    memset(&sets, 0, sizeof(sets));
    if (!cx_args_parse(request ? request->input : NULL, &a)) {
        cx_fail(reply, "NEXT_BAD_INPUT",
                "count is 1..200; cwd, exclude and prefix are short strings",
                "input");
        return;
    }
    if (cx_prepare(&a, root, sizeof(root), &sets, reply)) {
        rows = cx_load_rows(root, &n);
        picks = rows ? zcl_calloc(n, sizeof(*picks), "dev_cx.picks") : NULL;
        if (!rows || !picks)
            cx_fail(reply, "NEXT_BASELINE_UNREADABLE",
                    "the complexity baseline could not be read", root);
        else if (kept = cx_select(rows, n, root, &sets, &a, picks, skipped),
                 !cx_emit(reply, picks, kept, &a, skipped))
            cx_fail(reply, "NEXT_NO_MEMORY", "cannot build the reply", "");
    }
    free(picks);
    free(rows);
    cx_set_free(&sets.excluded);
    cx_set_free(&sets.changed);
}
