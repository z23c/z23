/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.batch.culprit, the C form of drop_culprit() in the lab
 *          bridge gate-submit.sh, plus lane granularity. It DECIDES which
 *          commits of a failed stack to drop and never rebases, never
 *          writes the ledger and never runs a gate: SHADOW STEP, the bridge
 *          keeps acting.
 *
 * The decision, in the shell's order:
 *   1. a stack of fewer than two commits drops nothing (too_small);
 *   2. a failure that prints its own fix goes to the autofix round
 *      (fix_printed);
 *   3. the files the failure lines name (native_dev_batch_culprit_paths.c)
 *      meet the files the stack changed; no hit is no_paths;
 *   4. NEW, 11-03 s524: each stack commit is mapped to its lane by patch
 *      identity against every lane the stack holds in stacked.tsv (rows
 *      LANE<TAB>HEAD<TAB>sN). Dropping dead-shell's shell deletion alone had
 *      kept its sibling budget cut and check-no-new-bash failed the rest, so
 *      a culprit pulls in every commit of its lane. A commit that maps to no
 *      lane (the registry re-derive, autofix fix-ups) or to two is never a
 *      culprit (unmapped);
 *   5. after that expansion: at most half the stack (over_half); no header
 *      among the dropped files (header_touched); no kept commit touching a
 *      dropped file (shared_file). The shared ratchet files
 *      (the tools/lint baseline, budget and floor .txt files) count in none.
 *
 * Patch identity is `git cherry HEAD-of-lane` in the stack, which compares
 * the same stable patch ids `git patch-id --stable` prints (git 2.43) and
 * needs no stdin. Not ported: the duplicate_candidates floor, which the
 * bridge answers by running dup-audit.sh; its log names no file, so it ends
 * as no_paths here. git runs by argv only, with origin/main as the base.
 *
 * Inputs: --stack (the stack worktree), --log (the failure log), --stage
 * (lint, fast or agent-verify), --ledger (the directory holding
 * stacked.tsv), --dry_run (accepted; the leaf writes nothing either way). */

#include "command/native_dev_batch_culprit.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CD_BUF (16u * 1024u * 1024u)
#define CD_UNMAPPED (-1)
#define CD_AMBIGUOUS (-2)

struct cd_commit {
    char sha[41];
    char *subject;
    struct cp_set files;
    int lane;
    bool direct, drop;
};

struct cd_lane {
    char name[DB_PATH];
    char head[41];
    bool pulled;
};

struct cd_ctx {
    char stack[DB_PATH];
    char sid[32];
    bool agent_verify;
    struct db_text log, ledger;
    struct cp_set paths, net;
    struct cd_commit *c;
    size_t nc, capc;
    struct cd_lane *lane;
    size_t nl, capl;
    char *buf;
    char code[24];
    char detail[256];
};

static void cd_free(struct cd_ctx *x)
{
    size_t i;
    for (i = 0; i < x->nc; i++) {
        free(x->c[i].subject);
        cp_set_free(&x->c[i].files);
    }
    free(x->c);
    free(x->lane);
    free(x->buf);
    cp_set_free(&x->paths);
    cp_set_free(&x->net);
    db_text_free(&x->log);
    db_text_free(&x->ledger);
}

/* A refusal: the typed code and one line saying why. */
static bool cd_no(struct cd_ctx *x, const char *code, const char *msg)
{
    (void)snprintf(x->code, sizeof(x->code), "%s", code);
    (void)snprintf(x->detail, sizeof(x->detail), "%s", msg);
    return false;
}

/* The same with one count in the message. */
static bool cd_no_n(struct cd_ctx *x, const char *code, const char *fmt,
                    size_t n)
{
    (void)snprintf(x->code, sizeof(x->code), "%s", code);
    (void)snprintf(x->detail, sizeof(x->detail), fmt, n);
    return false;
}

/* ── git ───────────────────────────────────────────────────────────────── */

static struct cd_commit *cd_commit_new(struct cd_ctx *x, const char *line)
{
    struct cd_commit *c;
    size_t len = strlen(line);
    if (x->nc == x->capc) {
        size_t cap = x->capc ? x->capc * 2 : 32;
        struct cd_commit *grown =
            zcl_realloc(x->c, cap * sizeof(*grown), "cd_commits");
        if (!grown)
            return NULL;
        x->c = grown;
        x->capc = cap;
    }
    if (len < 40)
        return NULL;
    c = &x->c[x->nc];
    memset(c, 0, sizeof(*c));
    memcpy(c->sha, line, 40);
    c->lane = CD_UNMAPPED;
    c->subject = zcl_malloc(len, "cd_subject");
    if (!c->subject)
        return NULL;
    (void)snprintf(c->subject, len, "%s", len > 41 ? line + 41 : "");
    x->nc++;
    return c;
}

/* git log --name-only: "\001SHA subject" opens a commit, its files follow. */
static bool cd_parse_log(struct cd_ctx *x, char *out)
{
    struct cd_commit *cur = NULL;
    char *line = out, *nl;
    while (*line) {
        nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        if (line[0] == '\001') {
            cur = cd_commit_new(x, line + 1);
            if (!cur)
                return false;
        } else if (line[0] && cur &&
                   !cp_set_add(&cur->files, line, strlen(line))) {
            return false;
        }
        if (!nl)
            break;
        line = nl + 1;
    }
    return true;
}

static bool cd_load_commits(struct cd_ctx *x)
{
    const char *log[] = {"log", "--no-renames", "--name-only",
                         "--format=%x01%H %s", "origin/main..HEAD", NULL};
    const char *net[] = {"diff", "--name-only", "--no-renames",
                         "origin/main...HEAD", NULL};
    char *p, *nl;
    if (db_git(x->stack, log, x->buf, CD_BUF) != 0)
        return cd_no(x, "BAD_STACK", "git log failed in the stack");
    if (!cd_parse_log(x, x->buf))
        return cd_no(x, "NO_MEMORY", "out of memory reading the stack");
    if (db_git(x->stack, net, x->buf, CD_BUF) != 0)
        return cd_no(x, "BAD_STACK", "git diff failed in the stack");
    for (p = x->buf; *p; p = nl ? nl + 1 : p + strlen(p)) {
        nl = strchr(p, '\n');
        if (nl)
            *nl = '\0';
        if (p[0] && !cp_set_add(&x->net, p, strlen(p)))
            return false;
        if (!nl)
            break;
    }
    return true;
}

/* ── lanes ─────────────────────────────────────────────────────────────── */

static bool cd_hex40(const char *h)
{
    size_t i;
    for (i = 0; i < 40; i++)
        if (!isxdigit((unsigned char)h[i]))
            return false;
    return h[40] == '\0' || h[40] == '\t';
}

static bool cd_lane_add(struct cd_ctx *x, const char *name, const char *head)
{
    size_t i, n = strlen(name);
    while (n > 1 && name[n - 1] == '/')
        n--;
    for (i = 0; i < x->nl; i++)
        if (strlen(x->lane[i].name) == n &&
            memcmp(x->lane[i].name, name, n) == 0)
            return true;
    if (n >= DB_PATH)
        return true;
    if (x->nl == x->capl) {
        size_t cap = x->capl ? x->capl * 2 : 16;
        struct cd_lane *grown =
            zcl_realloc(x->lane, cap * sizeof(*grown), "cd_lanes");
        if (!grown)
            return false;
        x->lane = grown;
        x->capl = cap;
    }
    memset(&x->lane[x->nl], 0, sizeof(x->lane[0]));
    memcpy(x->lane[x->nl].name, name, n);
    memcpy(x->lane[x->nl].head, head, 40);
    x->nl++;
    return true;
}

/* stacked.tsv rows LANE<TAB>HEAD<TAB>sN for this stack. */
static bool cd_load_lanes(struct cd_ctx *x)
{
    size_t pos = 0, len;
    const char *line;
    char name[DB_PATH], head[84];
    while (db_next_line(&x->ledger, &pos, &line, &len)) {
        if (!db_field_is(line, len, 2, x->sid) ||
            !db_field_copy(line, len, 0, name, sizeof(name)) ||
            !db_field_copy(line, len, 1, head, sizeof(head)) ||
            !cd_hex40(head))
            continue;
        if (!cd_lane_add(x, name, head))
            return false;
    }
    return true;
}

/* `git cherry LANEHEAD HEAD origin/main` prints "- SHA" for each stack commit
 * whose patch the lane already holds. */
static void cd_mark_lane(struct cd_ctx *x, size_t li, char *out)
{
    char *line = out, *nl;
    size_t i;
    while (*line) {
        nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        if (line[0] == '-' && line[1] == ' ')
            for (i = 0; i < x->nc; i++)
                if (strncmp(x->c[i].sha, line + 2, 40) == 0)
                    x->c[i].lane = x->c[i].lane == CD_UNMAPPED
                                       ? (int)li
                                       : CD_AMBIGUOUS;
        if (!nl)
            break;
        line = nl + 1;
    }
}

static void cd_map_lanes(struct cd_ctx *x)
{
    size_t li;
    for (li = 0; li < x->nl; li++) {
        const char *cherry[] = {"cherry", x->lane[li].head, "HEAD",
                                "origin/main", NULL};
        if (db_git(x->stack, cherry, x->buf, CD_BUF) == 0)
            cd_mark_lane(x, li, x->buf);
    }
}

/* ── the decision ──────────────────────────────────────────────────────── */

static bool cd_touches(const struct cd_ctx *x, const struct cd_commit *c)
{
    size_t i;
    for (i = 0; i < c->files.n; i++)
        if (cp_set_has(&x->paths, c->files.v[i]) &&
            cp_set_has(&x->net, c->files.v[i]))
            return true;
    return false;
}

/* Steps 3 and 4: the commits the failure names, then their lanes. */
static bool cd_pick(struct cd_ctx *x)
{
    size_t i, hits = 0, mapped = 0;
    for (i = 0; i < x->nc; i++) {
        x->c[i].direct = cd_touches(x, &x->c[i]);
        hits += x->c[i].direct;
        if (x->c[i].direct && x->c[i].lane >= 0) {
            x->lane[x->c[i].lane].pulled = true;
            mapped++;
        }
    }
    if (hits == 0)
        return cd_no(x, "no_paths",
                     "no file the failure names was changed by the stack");
    if (mapped == 0)
        return cd_no_n(x, "unmapped",
                       "%zu named commit(s) map to no single lane; never a culprit",
                       hits);
    for (i = 0; i < x->nc; i++)
        x->c[i].drop = x->c[i].lane >= 0 && x->lane[x->c[i].lane].pulled;
    return true;
}

static size_t cd_dropped(const struct cd_ctx *x)
{
    size_t i, n = 0;
    for (i = 0; i < x->nc; i++)
        n += x->c[i].drop;
    return n;
}

/* The files the dropped commits own, ratchet files left out. */
static bool cd_own(const struct cd_ctx *x, struct cp_set *own)
{
    size_t i, k;
    for (i = 0; i < x->nc; i++)
        for (k = 0; x->c[i].drop && k < x->c[i].files.n; k++)
            if (!cp_is_ratchet(x->c[i].files.v[k]) &&
                !cp_set_add(own, x->c[i].files.v[k],
                            strlen(x->c[i].files.v[k])))
                return false;
    return true;
}

static bool cd_kept_touch(const struct cd_ctx *x, const struct cp_set *own)
{
    size_t i, k;
    for (i = 0; i < x->nc; i++)
        for (k = 0; !x->c[i].drop && k < x->c[i].files.n; k++)
            if (cp_set_has(own, x->c[i].files.v[k]))
                return true;
    return false;
}

static bool cd_has_header(const struct cp_set *own)
{
    size_t i, n;
    for (i = 0; i < own->n; i++) {
        n = strlen(own->v[i]);
        if (n > 2 && strcmp(own->v[i] + n - 2, ".h") == 0)
            return true;
    }
    return false;
}

/* Step 5, after the lane expansion. */
static bool cd_check(struct cd_ctx *x)
{
    struct cp_set own = {0};
    bool ok = false;
    size_t n = cd_dropped(x);
    if (n * 2 > x->nc)
        return cd_no_n(x, "over_half",
                       "%zu of the stack's commits would drop", n);
    if (!cd_own(x, &own))
        return cd_no(x, "NO_MEMORY", "out of memory");
    if (cd_has_header(&own))
        (void)cd_no(x, "header_touched",
                    "the dropped commits add or edit a header");
    else if (cd_kept_touch(x, &own))
        (void)cd_no(x, "shared_file",
                    "a kept commit touches a dropped commit's file");
    else
        ok = true;
    cp_set_free(&own);
    return ok;
}

static bool cd_decide(struct cd_ctx *x)
{
    if (x->nc < 2)
        return cd_no_n(x, "too_small", "the stack holds %zu commit(s)",
                       x->nc);
    if (cp_log_fix_printed(&x->log))
        return cd_no(x, "fix_printed",
                     "the failure prints its own fix; the autofix round "
                     "takes it");
    if (!cp_log_paths(&x->log, x->agent_verify, &x->paths))
        return cd_no(x, "NO_MEMORY", "out of memory");
    if (x->paths.n == 0)
        return cd_no(x, "no_paths", "the failure log names no file");
    return cd_pick(x) && cd_check(x);
}

/* ── the reply ─────────────────────────────────────────────────────────── */

static void cd_strings(struct json_value *arr, const struct cp_set *s)
{
    size_t i;
    json_set_array(arr);
    for (i = 0; i < s->n; i++)
        db_push_str(arr, s->v[i]);
}

static void cd_drop_row(const struct cd_ctx *x, const struct cd_commit *c,
                        struct json_value *row)
{
    struct json_value named;
    size_t i;
    json_set_object(row);
    (void)json_push_kv_str(row, "sha", c->sha);
    (void)json_push_kv_str(row, "subject", c->subject);
    (void)json_push_kv_str(row, "lane", x->lane[c->lane].name);
    (void)json_push_kv_bool(row, "named", c->direct);
    json_init(&named);
    json_set_array(&named);
    for (i = 0; i < c->files.n; i++)
        if (cp_set_has(&x->paths, c->files.v[i]) &&
            cp_set_has(&x->net, c->files.v[i]))
            db_push_str(&named, c->files.v[i]);
    (void)json_push_kv(row, "paths", &named);
    json_free(&named);
}

static void cd_publish(struct zcl_command_reply *reply, const struct cd_ctx *x,
                       bool ok, bool dry, const char *stage)
{
    struct json_value list, paths, row;
    size_t i;
    json_init(&list);
    json_set_array(&list);
    for (i = 0; ok && i < x->nc; i++) {
        if (!x->c[i].drop)
            continue;
        json_init(&row);
        cd_drop_row(x, &x->c[i], &row);
        (void)json_push_back(&list, &row);
        json_free(&row);
    }
    json_init(&paths);
    cd_strings(&paths, &x->paths);
    (void)json_push_kv_str(&reply->data, "leaf", "dev.batch.culprit");
    (void)json_push_kv_str(&reply->data, "stage", stage);
    (void)json_push_kv_str(&reply->data, "stack", x->sid);
    (void)json_push_kv_bool(&reply->data, "dry_run", dry);
    (void)json_push_kv_str(&reply->data, "decision", ok ? "drop" : "refuse");
    if (!ok) {
        (void)json_push_kv_str(&reply->data, "refusal", x->code);
        (void)json_push_kv_str(&reply->data, "detail", x->detail);
    }
    (void)json_push_kv(&reply->data, "drop", &list);
    (void)json_push_kv(&reply->data, "failure_paths", &paths);
    (void)json_push_kv_int(&reply->data, "stack_commits", (int64_t)x->nc);
    (void)json_push_kv_int(&reply->data, "lanes", (int64_t)x->nl);
    json_free(&list);
    json_free(&paths);
}

/* ── inputs ────────────────────────────────────────────────────────────── */

/* z23-stacks524 -> s524, the third column of stacked.tsv. */
static bool cd_stack_id(struct cd_ctx *x)
{
    const char *base = strrchr(x->stack, '/');
    base = base ? base + 1 : x->stack;
    if (strncmp(base, "z23-stack", 9) != 0 || !base[9])
        return false;
    return snprintf(x->sid, sizeof(x->sid), "%s", base + 9) <
           (int)sizeof(x->sid);
}

static bool cd_inputs(const struct json_value *in, struct cd_ctx *x,
                      struct zcl_command_reply *reply)
{
    const char *stage = db_opt_str(in, "stage");
    const char *log = db_opt_str(in, "log");
    const char *ledger = db_opt_str(in, "ledger");
    const char *stack = db_opt_str(in, "stack");
    char path[DB_PATH + 32];
    size_t n = strlen(stack);
    if (strcmp(stage, "lint") != 0 && strcmp(stage, "fast") != 0 &&
        strcmp(stage, "agent-verify") != 0 && strcmp(stage, "agent_verify") != 0) {
        db_refuse(reply, "BAD_INPUT", "input",
                  "--stage is lint, fast or agent-verify");
        return false;
    }
    x->agent_verify = stage[0] == 'a';
    while (n > 1 && stack[n - 1] == '/')
        n--;
    if (!n || n >= sizeof(x->stack) || !log[0] || !ledger[0] ||
        access(log, R_OK) != 0 || !db_join(path, sizeof(path), ledger, "stacked.tsv")) {
        db_refuse(reply, "BAD_INPUT", "input",
                  "--stack, --log (readable) and --ledger are required");
        return false;
    }
    memcpy(x->stack, stack, n);
    if (!cd_stack_id(x) || !db_text_load(log, &x->log) ||
        !db_text_load(path, &x->ledger)) {
        db_refuse(reply, "BAD_INPUT", "input",
                  "the stack must be a z23-stacksN worktree and the log and "
                  "ledger readable");
        return false;
    }
    return true;
}

void zcl_native_handle_dev_batch_culprit(const struct zcl_command_request *request,
                                         struct zcl_command_reply *reply)
{
    const struct json_value *in;
    struct cd_ctx x;
    bool ok;
    if (!reply)
        return;
    in = request ? request->input : NULL;
    if (!in) {
        db_refuse(reply, "BAD_INPUT", "input", "dev.batch.culprit needs input");
        return;
    }
    memset(&x, 0, sizeof(x));
    x.buf = zcl_malloc(CD_BUF, "cd_buf");
    if (!x.buf || !cd_inputs(in, &x, reply)) {
        if (!x.buf)
            db_refuse(reply, "NO_MEMORY", "input", "out of memory");
        cd_free(&x);
        return;
    }
    ok = cd_load_commits(&x) &&
         (cd_load_lanes(&x) || cd_no(&x, "NO_MEMORY", "out of memory"));
    if (ok) {
        cd_map_lanes(&x);
        ok = cd_decide(&x);
    }
    cd_publish(reply, &x, ok, db_opt_flag(in, "dry_run"),
               db_opt_str(in, "stage"));
    cd_free(&x);
}
