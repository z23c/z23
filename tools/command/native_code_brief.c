/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Task-specific brief for `code.guide` (zcl.code_guide_brief.v1).
 *
 * Given the paths an agent will edit and an optional topic, one bounded reply
 * names the nearest AGENTS.md owner of each path, the test groups the shared
 * impact rules route those paths to, the fleet-wiki lessons that match, and
 * the first commands to run. The only reads are AGENTS.md files under the
 * source root and local wiki searches under a one-second deadline; with no node the lessons are marked
 * unavailable and the rest of the brief is unchanged. The serialized data
 * object never exceeds the caller's budget: sections are removed from the
 * lowest-priority end and every removal is reported in `cut`. */

#include "command/native_code_brief.h"

#include "base/safe_alloc.h"
#include "command/native_code_priv.h"
#include "config/command_catalog.h"
#include "controllers/agent_impact_rules.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CB_TAG "native.code.brief"
#define CB_MAX_PATHS 16
#define CB_PATH_CAP 256
#define CB_TOPIC_MAX 64
#define CB_BUDGET_DEFAULT 2048
#define CB_BUDGET_MIN 256
#define CB_BUDGET_MAX 8192
#define CB_MAX_OWNERS 8
#define CB_OWNER_RULES 4
#define CB_RULE_CAP 200
#define CB_MAX_TESTS 12
#define CB_MAX_LESSONS 5
#define CB_MAX_QUERIES 4
#define CB_QUERY_CAP 129
#define CB_MAX_NEXT 3
#define CB_NEXT_CAP 160
#define CB_HEAD_CAP 4096
#define CB_WIKI_DEADLINE_MS 1000

struct cb_owner {
    char file[CB_PATH_CAP];
    char rules[CB_OWNER_RULES][CB_RULE_CAP];
    size_t nrules;
};

struct cb_lesson {
    char slug[CB_TOPIC_MAX + 1];
    char rule[CB_RULE_CAP];
    struct json_value matched;
};

struct cb_brief {
    char paths[CB_MAX_PATHS][CB_PATH_CAP];
    size_t npaths;
    char topic[CB_TOPIC_MAX + 1];
    size_t budget;
    struct cb_owner owners[CB_MAX_OWNERS];
    size_t nowners;
    char tests[CB_MAX_TESTS][ZCL_AGENT_IMPACT_GROUP_MAX];
    size_t ntests;
    bool unmapped;
    struct cb_lesson lessons[CB_MAX_LESSONS];
    size_t nlessons;
    char unavailable[64];
    char next[CB_MAX_NEXT][CB_NEXT_CAP];
    size_t nnext;
    bool cut_lessons, cut_tests, cut_rules, cut_owners, cut_next;
    bool lessons_capped;
    int64_t deadline_ms;
};

/* ── text helpers ─────────────────────────────────────────────────────── */

/* Copy at most cap-1 bytes of src[0..len), ending on a UTF-8 boundary and
 * without trailing blanks. True when text was cut. */
static bool cb_copy(char *dst, size_t cap, const char *src, size_t len)
{
    size_t n = len < cap - 1 ? len : cap - 1;
    bool cut = n < len;
    while (cut && n > 0 && ((unsigned char)src[n] & 0xC0u) == 0x80u)
        n--;
    while (n > 0 && (src[n - 1] == ' ' || src[n - 1] == '\t' ||
                     src[n - 1] == '\r'))
        n--;
    memcpy(dst, src, n);
    dst[n] = '\0';
    return cut;
}

static bool cb_has(const void *list, size_t n, size_t stride,
                   const char *s)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp((const char *)list + i * stride, s) == 0)
            return true;
    return false;
}

/* ── input ────────────────────────────────────────────────────────────── */

static bool cb_path_ok(const char *p)
{
    size_t n = strlen(p);
    if (n == 0 || n >= CB_PATH_CAP || p[0] == '/' || strchr(p, '\\'))
        return false;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)p[i] < 0x20)
            return false;
    for (const char *seg = p; seg;) {
        const char *slash = strchr(seg, '/');
        size_t len = slash ? (size_t)(slash - seg) : strlen(seg);
        if (len == 0 || (len == 2 && seg[0] == '.' && seg[1] == '.'))
            return false;
        seg = slash ? slash + 1 : NULL;
    }
    return true;
}

static const char *cb_add_path(struct cb_brief *b, const char *s, size_t len)
{
    char tmp[CB_PATH_CAP];
    while (len >= 2 && s[0] == '.' && s[1] == '/') {
        s += 2;
        len -= 2;
    }
    if (len == 0 || len >= CB_PATH_CAP)
        return "paths must be repo-relative paths of at most 255 bytes";
    memcpy(tmp, s, len);
    tmp[len] = '\0';
    if (!cb_path_ok(tmp))
        return "paths must be repo-relative paths without .. segments";
    if (cb_has(b->paths, b->npaths, CB_PATH_CAP, tmp))
        return NULL;
    if (b->npaths >= CB_MAX_PATHS)
        return "paths accepts at most 16 entries";
    memcpy(b->paths[b->npaths++], tmp, len + 1);
    return NULL;
}

static const char *cb_parse_list(struct cb_brief *b, const char *csv)
{
    while (*csv) {
        const char *comma = strchr(csv, ',');
        size_t len = comma ? (size_t)(comma - csv) : strlen(csv);
        const char *err = len ? cb_add_path(b, csv, len) : NULL;
        if (err)
            return err;
        csv += len + (comma ? 1 : 0);
    }
    return NULL;
}

static const char *cb_parse_paths(struct cb_brief *b, const struct json_value *v)
{
    if (v->type == JSON_STR)
        return cb_parse_list(b, json_get_str(v));
    if (v->type != JSON_ARR)
        return "paths must be an array or a comma-separated string";
    for (size_t i = 0; i < json_size(v); i++) {
        const struct json_value *e = json_at(v, i);
        if (!e || e->type != JSON_STR)
            return "paths entries must be strings";
        const char *err = cb_add_path(b, json_get_str(e),
                                      strlen(json_get_str(e)));
        if (err)
            return err;
    }
    return NULL;
}

static const char *cb_parse_budget(struct cb_brief *b, const struct json_value *v)
{
    long long n;
    if (v->type != JSON_INT)
        return "budget must be an integer";
    n = json_get_int(v);
    b->budget = n < CB_BUDGET_MIN ? CB_BUDGET_MIN
              : n > CB_BUDGET_MAX ? CB_BUDGET_MAX : (size_t)n;
    return NULL;
}

static const char *cb_parse_topic(struct cb_brief *b, const struct json_value *v)
{
    const char *s = json_get_str(v);
    if (v->type != JSON_STR || !s[0] || strlen(s) > CB_TOPIC_MAX)
        return "topic must be a string of 1 to 64 bytes";
    memcpy(b->topic, s, strlen(s) + 1);
    return NULL;
}

static const char *cb_parse(struct cb_brief *b, const struct json_value *in)
{
    const struct json_value *v;
    const char *err;
    b->budget = CB_BUDGET_DEFAULT;
    if ((v = json_get(in, "paths")) && (err = cb_parse_paths(b, v)))
        return err;
    if ((v = json_get(in, "topic")) && (err = cb_parse_topic(b, v)))
        return err;
    if ((v = json_get(in, "budget")) && (err = cb_parse_budget(b, v)))
        return err;
    if (json_size(in) > (size_t)(!!json_get(in, "paths") +
                                 !!json_get(in, "topic") +
                                 !!json_get(in, "budget")))
        return "code guide accepts only paths, topic and budget";
    if (b->npaths == 0 && !b->topic[0])
        return "a brief needs paths or a topic";
    return NULL;
}

/* ── owners ───────────────────────────────────────────────────────────── */

static size_t cb_read_head(const char *root, const char *rel, char *buf,
                           size_t cap)
{
    char full[CB_PATH_CAP + 1024];
    size_t n;
    FILE *f;
    (void)snprintf(full, sizeof(full), "%s/%s", root, rel);
    f = fopen(full, "rb");
    if (!f)
        return 0;
    n = fread(buf, 1, cap - 1, f);
    (void)fclose(f);
    buf[n] = '\0';
    return n;
}

/* Next line of text starting at *pos; false at the end. */
static bool cb_line(const char *text, size_t *pos, const char **line,
                    size_t *len)
{
    if (!text[*pos])
        return false;
    const char *nl = strchr(text + *pos, '\n');
    *line = text + *pos;
    *len = nl ? (size_t)(nl - *line) : strlen(*line);
    *pos += *len + (nl ? 1 : 0);
    return true;
}

static void cb_owner_push(struct cb_brief *b, struct cb_owner *o,
                          const char *s, size_t len)
{
    if (o->nrules < CB_OWNER_RULES &&
        cb_copy(o->rules[o->nrules], CB_RULE_CAP, s, len))
        b->cut_rules = true;
    if (o->nrules < CB_OWNER_RULES)
        o->nrules++;
}

static bool cb_is_bullet(const char *l, size_t n)
{
    return n > 2 && l[0] == '-' && l[1] == ' ';
}

/* Bullets from base until the first non-bullet line after one. */
static void cb_scan_bullets(struct cb_brief *b, struct cb_owner *o,
                            const char *base)
{
    size_t pos = 0, len;
    const char *line;
    while (cb_line(base, &pos, &line, &len) && o->nrules < CB_OWNER_RULES) {
        if (cb_is_bullet(line, len))
            cb_owner_push(b, o, line + 2, len - 2);
        else if (o->nrules)
            break;
    }
}

/* The first two prose lines, for a guide that has no bullets. */
static void cb_scan_prose(struct cb_brief *b, struct cb_owner *o,
                          const char *base)
{
    size_t pos = 0, len;
    const char *line;
    while (cb_line(base, &pos, &line, &len) && o->nrules < 2)
        if (len && line[0] != '#' && line[0] != '<' && line[0] != '-')
            cb_owner_push(b, o, line, len);
}

/* Rule lines: the bullets after "Rules:" when present, else the first
 * bullets, else the first prose lines. */
static void cb_extract_rules(struct cb_brief *b, struct cb_owner *o,
                             const char *text)
{
    const char *marker = strstr(text, "\nRules:\n");
    cb_scan_bullets(b, o, marker ? marker + 7 : text);
    if (o->nrules == 0)
        cb_scan_prose(b, o, text);
}

/* Nearest AGENTS.md at or above path's directory; false when none. */
static bool cb_owner_file(const char *root, const char *path, char *rel,
                          char *head)
{
    char dir[CB_PATH_CAP];
    size_t len = strlen(path);
    memcpy(dir, path, len + 1);
    for (;;) {
        char *slash = strrchr(dir, '/');
        if (!slash)
            break;
        *slash = '\0';
        (void)snprintf(rel, CB_PATH_CAP, "%s/AGENTS.md", dir);
        if (cb_read_head(root, rel, head, CB_HEAD_CAP))
            return true;
    }
    (void)snprintf(rel, CB_PATH_CAP, "AGENTS.md");
    return cb_read_head(root, rel, head, CB_HEAD_CAP) > 0;
}

static void cb_collect_owners(struct cb_brief *b, const char *root)
{
    char head[CB_HEAD_CAP], rel[CB_PATH_CAP];
    for (size_t i = 0; i < b->npaths; i++) {
        struct cb_owner *o = &b->owners[b->nowners];
        if (!cb_owner_file(root, b->paths[i], rel, head))
            continue;
        bool seen = false;
        for (size_t k = 0; k < b->nowners; k++)
            seen = seen || strcmp(b->owners[k].file, rel) == 0;
        if (seen)
            continue;
        if (b->nowners >= CB_MAX_OWNERS) {
            b->cut_owners = true;
            break;
        }
        memcpy(o->file, rel, strlen(rel) + 1);
        cb_extract_rules(b, o, head);
        b->nowners++;
    }
}

/* ── tests ────────────────────────────────────────────────────────────── */

static void cb_add_test(struct cb_brief *b, const char *group)
{
    if (!group || !group[0] ||
        cb_has(b->tests, b->ntests,
               ZCL_AGENT_IMPACT_GROUP_MAX, group))
        return;
    if (b->ntests >= CB_MAX_TESTS) {
        b->cut_tests = true;
        return;
    }
    (void)snprintf(b->tests[b->ntests++], ZCL_AGENT_IMPACT_GROUP_MAX, "%s",
                   group);
}

static void cb_collect_tests(struct cb_brief *b)
{
    for (size_t i = 0; i < b->npaths; i++) {
        struct agent_impact_acc acc;
        bool crisk = false;
        const char *route =
            zcl_native_code_route_for_path(b->paths[i], &acc, &crisk);
        if (!crisk && acc.groups_len == 0) {
            b->unmapped = true;
            continue;
        }
        cb_add_test(b, route);
        for (size_t g = 0; g < acc.groups_len; g++)
            cb_add_test(b, acc.groups[g]);
    }
}

/* ── lessons ──────────────────────────────────────────────────────────── */

static void cb_add_query(char q[][CB_QUERY_CAP], size_t *n, const char *s,
                         size_t len)
{
    char tmp[CB_QUERY_CAP];
    if (!len || *n >= CB_MAX_QUERIES)
        return;
    (void)cb_copy(tmp, sizeof(tmp), s, len);
    if (!cb_has(q, *n, CB_QUERY_CAP, tmp))
        memcpy(q[(*n)++], tmp, strlen(tmp) + 1);
}

static void cb_stem_query(char q[][CB_QUERY_CAP], size_t *n, const char *p)
{
    const char *base = strrchr(p, '/');
    const char *dot;
    base = base ? base + 1 : p;
    dot = strrchr(base, '.');
    cb_add_query(q, n, base, dot && dot != base ? (size_t)(dot - base)
                                                : strlen(base));
}

/* The topic when given, else each path's file stem, then each path's
 * top-level directory: stems are specific, directories match broadly, so a
 * directory can only fill slots the stems left open. */
static size_t cb_queries(const struct cb_brief *b, char q[][CB_QUERY_CAP])
{
    size_t n = 0;
    if (b->topic[0]) {
        cb_add_query(q, &n, b->topic, strlen(b->topic));
        return n;
    }
    for (size_t i = 0; i < b->npaths; i++)
        cb_stem_query(q, &n, b->paths[i]);
    for (size_t i = 0; i < b->npaths; i++) {
        const char *slash = strchr(b->paths[i], '/');
        if (slash)
            cb_add_query(q, &n, b->paths[i], (size_t)(slash - b->paths[i]));
    }
    return n;
}

static void cb_take_lesson(struct cb_brief *b, const struct json_value *e)
{
    const char *slug = json_get_str(json_get(e, "slug"));
    const struct json_value *rules = json_get(e, "rules");
    const struct json_value *r0 = rules ? json_at(rules, 0) : NULL;
    const char *text = r0 && r0->type == JSON_STR ? json_get_str(r0)
                                                  : json_get_str(json_get(e, "summary"));
    struct cb_lesson *l;
    if (!slug[0] || !text[0] || strlen(slug) > CB_TOPIC_MAX)
        return;
    for (size_t i = 0; i < b->nlessons; i++)
        if (strcmp(b->lessons[i].slug, slug) == 0)
            return;
    if (b->nlessons >= CB_MAX_LESSONS) {
        b->lessons_capped = true;
        return;
    }
    l = &b->lessons[b->nlessons];
    memcpy(l->slug, slug, strlen(slug) + 1);
    if (cb_copy(l->rule, CB_RULE_CAP, text, strlen(text)))
        b->lessons_capped = true;
    json_init(&l->matched);
    if (json_get(e, "matched"))
        json_copy(&l->matched, json_get(e, "matched"));
    else
        json_set_array(&l->matched);
    b->nlessons++;
}

/* One fleet.wiki.find under the brief's absolute deadline. The leaf is
 * called directly, so the caller's authority ceiling is checked here. */
static void cb_wiki_run(const struct zcl_command_request *request,
                        const char *q, int64_t deadline_ms,
                        struct zcl_command_reply *reply)
{
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), "fleet.wiki.find", NULL);
    struct json_value input;
    struct zcl_command_request sub;
    json_init(&input);
    json_set_object(&input);
    memset(&sub, 0, sizeof(sub));
    sub.input = &input;
    sub.context = request->context;
    sub.view = "normal";
    sub.spec = spec;
    zcl_command_reply_init(reply, "zcl.fleet_wiki_find.v1");
    if (!spec || !json_push_kv_str(&input, "q", q))
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "WIKI_UNAVAILABLE",
                               "prepare", false, false, "query", "");
    else if (request->context &&
             request->context->authority_ceiling < spec->authority)
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "AUTHORITY_DENIED",
                               "dispatch", false, false, "wiki search", "");
    else
        zcl_native_fleet_wiki_find_until(&sub, reply, deadline_ms);
    json_free(&input);
}

/* One search. False when it failed; b->unavailable then names why. A query
 * that used up its time cap, or ran past the brief's deadline, is
 * WIKI_DEADLINE rather than a refusal. */
static bool cb_wiki_find(const struct zcl_command_request *request,
                         struct cb_brief *b, const char *q)
{
    struct zcl_command_reply reply;
    int64_t start = platform_time_monotonic_ms();
    const struct json_value *entries;
    bool ok;
    cb_wiki_run(request, q, b->deadline_ms, &reply);
    ok = reply.exit_code == ZCL_COMMAND_EXIT_OK;
    entries = ok ? json_get(&reply.data, "entries") : NULL;
    for (size_t i = 0; entries && i < json_size(entries); i++)
        cb_take_lesson(b, json_at(entries, i));
    if (!ok) {
        int64_t now = platform_time_monotonic_ms();
        bool late = now >= b->deadline_ms ||
                    now - start >= ZCL_COMMAND_LATENCY_BUDGET_FAST_MS - 25 ||
                    strcmp(reply.error.code,
                           "BOARD_OBSERVATION_BUDGET_EXHAUSTED") == 0;
        (void)snprintf(b->unavailable, sizeof(b->unavailable), "%s",
                       late ? "WIKI_DEADLINE"
                            : reply.error.code[0] ? reply.error.code
                                                  : "WIKI_UNAVAILABLE");
    }
    zcl_command_reply_free(&reply);
    return ok;
}

static void cb_collect_lessons(const struct zcl_command_request *request,
                               struct cb_brief *b)
{
    char q[CB_MAX_QUERIES][CB_QUERY_CAP];
    size_t n = cb_queries(b, q);
    size_t answered = 0;
    b->deadline_ms = platform_time_monotonic_ms() + CB_WIKI_DEADLINE_MS;
    for (size_t i = 0; i < n && b->nlessons < CB_MAX_LESSONS; i++) {
        if (!cb_wiki_find(request, b, q[i]))
            break;
        answered++;
    }
    if (answered > 0)
        b->unavailable[0] = '\0';
}

/* ── next ─────────────────────────────────────────────────────────────── */

static bool cb_needs_preflight(const struct cb_brief *b)
{
    for (size_t i = 0; i < b->npaths; i++) {
        const char *p = b->paths[i];
        size_t n = strlen(p);
        if (strncmp(p, "tools/command/", 14) == 0 ||
            strncmp(p, "engine/", 7) == 0 ||
            (n > 4 && strcmp(p + n - 4, ".def") == 0))
            return true;
    }
    return false;
}

static void cb_push_next(struct cb_brief *b, const char *fmt, const char *arg)
{
    if (b->nnext < CB_MAX_NEXT)
        (void)snprintf(b->next[b->nnext++], CB_NEXT_CAP, fmt, arg);
}

/* The group for the focused proof command: t-fast ONLY takes one name. The
 * lint umbrella is proved by the lint commands that follow, so it is named
 * only when it is the sole routed group. */
static const char *cb_focus_group(const struct cb_brief *b)
{
    for (size_t i = 0; i < b->ntests; i++)
        if (strcmp(b->tests[i], "make_lint_gates") != 0)
            return b->tests[i];
    return b->ntests ? b->tests[0] : NULL;
}

static void cb_build_next(struct cb_brief *b)
{
    const char *group = cb_focus_group(b);
    if (group)
        cb_push_next(b, "make t-fast ONLY=%s", group);
    else if (b->npaths)
        cb_push_next(b, "build/bin/z23 code cost %s", b->paths[0]);
    cb_push_next(b, "%s", "make lint-fast");
    if (cb_needs_preflight(b))
        cb_push_next(b, "%s", "make lint-preflight");
}

/* ── render ───────────────────────────────────────────────────────────── */

static void cb_push_strs(struct json_value *obj, const char *key,
                         const char (*list)[CB_RULE_CAP], size_t n)
{
    struct json_value arr, s;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < n; i++) {
        json_init(&s);
        json_set_str(&s, list[i]);
        (void)json_push_back(&arr, &s);
        json_free(&s);
    }
    (void)json_push_kv(obj, key, &arr);
    json_free(&arr);
}

static void cb_push_owners(struct json_value *data, const struct cb_brief *b)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < b->nowners; i++) {
        struct json_value o;
        json_init(&o);
        json_set_object(&o);
        (void)json_push_kv_str(&o, "file", b->owners[i].file);
        cb_push_strs(&o, "rules", b->owners[i].rules, b->owners[i].nrules);
        (void)json_push_back(&arr, &o);
        json_free(&o);
    }
    (void)json_push_kv(data, "owners", &arr);
    json_free(&arr);
}

static void cb_push_lessons(struct json_value *data, const struct cb_brief *b)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < b->nlessons; i++) {
        struct json_value o;
        json_init(&o);
        json_set_object(&o);
        (void)json_push_kv_str(&o, "slug", b->lessons[i].slug);
        (void)json_push_kv_str(&o, "rule", b->lessons[i].rule);
        (void)json_push_kv(&o, "matched", &b->lessons[i].matched);
        (void)json_push_back(&arr, &o);
        json_free(&o);
    }
    (void)json_push_kv(data, "lessons", &arr);
    json_free(&arr);
}

static void cb_push_cut(struct json_value *data, const struct cb_brief *b)
{
    static const char *const names[] = {"lessons", "tests", "owner_rules",
                                        "owners", "next"};
    const bool flags[] = {b->cut_lessons, b->cut_tests, b->cut_rules,
                          b->cut_owners, b->cut_next};
    struct json_value arr, s;
    bool any = false;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < 5; i++) {
        if (!flags[i])
            continue;
        any = true;
        json_init(&s);
        json_set_str(&s, names[i]);
        (void)json_push_back(&arr, &s);
        json_free(&s);
    }
    (void)json_push_kv_bool(data, "truncated", any);
    if (any)
        (void)json_push_kv(data, "cut", &arr);
    json_free(&arr);
}

static void cb_push_tests(struct json_value *data, const struct cb_brief *b)
{
    struct json_value arr, s;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < b->ntests; i++) {
        json_init(&s);
        json_set_str(&s, b->tests[i]);
        (void)json_push_back(&arr, &s);
        json_free(&s);
    }
    (void)json_push_kv(data, "tests", &arr);
    json_free(&arr);
    if (b->unmapped)
        (void)json_push_kv_bool(data, "tests_unmapped", true);
}

static void cb_push_next_cmds(struct json_value *data, const struct cb_brief *b)
{
    struct json_value arr, s;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < b->nnext; i++) {
        json_init(&s);
        json_set_str(&s, b->next[i]);
        (void)json_push_back(&arr, &s);
        json_free(&s);
    }
    (void)json_push_kv(data, "next", &arr);
    json_free(&arr);
}

static void cb_build(const struct cb_brief *b, struct json_value *data)
{
    json_free(data);
    json_init(data);
    json_set_object(data);
    (void)json_push_kv_str(data, "schema", "zcl.code_guide_brief.v1");
    cb_push_owners(data, b);
    cb_push_tests(data, b);
    cb_push_lessons(data, b);
    if (b->unavailable[0])
        (void)json_push_kv_str(data, "lessons_unavailable", b->unavailable);
    if (b->lessons_capped)
        (void)json_push_kv_bool(data, "lessons_capped", true);
    cb_push_next_cmds(data, b);
    cb_push_cut(data, b);
}

/* Remove the lowest-priority content that is left; false when none is. */
static bool cb_reduce(struct cb_brief *b)
{
    if (b->nlessons) {
        json_free(&b->lessons[--b->nlessons].matched);
        b->cut_lessons = true;
    } else if (b->ntests) {
        b->ntests--;
        b->cut_tests = true;
    } else if (b->nowners && b->owners[b->nowners - 1].nrules) {
        b->owners[b->nowners - 1].nrules--;
        b->cut_rules = true;
    } else if (b->nowners) {
        b->nowners--;
        b->cut_owners = true;
    } else if (b->nnext) {
        b->nnext--;
        b->cut_next = true;
    } else {
        return false;
    }
    return true;
}

static bool cb_fit(struct cb_brief *b, struct json_value *data)
{
    for (;;) {
        cb_build(b, data);
        if (json_write(data, NULL, 0) <= b->budget)
            return true;
        if (!cb_reduce(b))
            return false;
    }
}

static void cb_fail(struct zcl_command_reply *reply, enum zcl_command_exit exit,
                    const char *code, const char *message)
{
    LOG_ERROR(CB_TAG, "%s: %s", code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit, code,
                           "validate", false, false, message, "code.guide");
}

static void cb_free(struct cb_brief *b)
{
    for (size_t i = 0; i < b->nlessons; i++)
        json_free(&b->lessons[i].matched);
    free(b);
}

void zcl_code_brief_render(const struct zcl_command_request *request,
                           struct zcl_command_reply *reply)
{
    struct cb_brief *b = zcl_malloc(sizeof(*b), "code_guide_brief");
    const char *err;
    if (!b) {
        cb_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "CODE_GUIDE_ALLOC",
                "the brief could not be allocated");
        return;
    }
    memset(b, 0, sizeof(*b));
    err = cb_parse(b, request->input);
    if (err) {
        cb_fail(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_CODE_GUIDE_INPUT", err);
        cb_free(b);
        return;
    }
    cb_collect_owners(b, code_source_root(request));
    cb_collect_tests(b);
    cb_collect_lessons(request, b);
    cb_build_next(b);
    if (!cb_fit(b, &reply->data))
        cb_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "CODE_GUIDE_OUTPUT",
                "the brief does not fit the budget");
    cb_free(b);
}
