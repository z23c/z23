/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Task-specific brief for `code.guide` (zcl.code_guide_brief.v1).
 *
 * Given the paths an agent will edit and an optional topic, one bounded reply
 * names the nearest AGENTS.md owner of each path, the test groups the shared
 * impact rules route those paths to, the fleet-wiki lessons that concern those paths (at most 3, ranked exact
 * applies_to, directory prefix, file stem; public pages from keys without a
 * role are dropped), and the first commands to run. Local reads also resolve HEAD and inspect the
 * latest test-run artifact; that artifact has no source revision, so its
 * failures are always labeled revision-unbound. AGENTS.md reads and wiki
 * searches retain their existing bounds; with no node the lessons are marked
 * unavailable and the rest of the brief is unchanged. The serialized data
 * object never exceeds the caller's budget: sections are removed from the
 * lowest-priority end and every removal is reported in `cut`. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "command/native_code_brief.h"

#include "base/safe_alloc.h"
#include "codeindex/codeindex_focus.h"
#include "command/native_code_priv.h"
#include "native_fleet_objectives.h"
#include "config/command_catalog.h"
#include "controllers/agent_impact_rules.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "test_group_catalog.h"
#include "util/log_macros.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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
#define CB_MAX_LESSONS 3
#define CB_LESSON_DEFAULT 2 /* lessons returned when the caller sets no budget */
#define CB_MAX_WITHHELD 16
#define CB_MORE_BUDGET 4096
#define CB_MAX_QUERIES 64
#define CB_QUERY_CAP 129
#define CB_MAX_NEXT 5
#define CB_NEXT_CAP (CB_PATH_CAP * 4 + sizeof("build/bin/z23 code cost --path=") + 2)
#define CB_HEAD_CAP 4096
#define CB_WIKI_DEADLINE_MS 1000
#define CB_DIR_PAGES 4
#define CB_LESSON_BYTES 1500
#define CB_STALE_DAYS 30
#define CB_LESSON_APPLIES 3
#define CB_MAX_DROPPED 64

struct cb_owner {
    char file[CB_PATH_CAP];
    char rules[CB_OWNER_RULES][CB_RULE_CAP];
    size_t nrules;
};

struct cb_lesson {
    char slug[CB_TOPIC_MAX + 1];
    char rule[CB_RULE_CAP];
    struct json_value matched;
    char updated[24];
    char applies[CB_LESSON_APPLIES][CB_QUERY_CAP]; /* paths checked for change */
    size_t napplies;
    unsigned char rank;
    bool pub, author_role;
    int64_t age_days; /* -1 when undated */
    const char *stale_reason; /* NULL when fresh */
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
    bool unmapped, test_evidence_unavailable;
    struct cb_lesson lessons[CB_MAX_LESSONS + 1];
    size_t nlessons;
    size_t lesson_limit; /* 0 = CB_MAX_LESSONS */
    uint64_t withheld[CB_MAX_WITHHELD]; /* pages kept off by lesson_limit */
    size_t nwithheld;
    unsigned lessons_more; /* withheld pages not shown */
    char unavailable[64];
    char next[CB_MAX_NEXT][CB_NEXT_CAP];
    size_t nnext;
    bool cut_lessons, cut_tests, cut_rules, cut_owners, cut_next;
    bool lessons_capped, lessons_truncated;
    unsigned lessons_untrusted; /* pages dropped: author holds no role (capped) */
    uint64_t dropped[CB_MAX_DROPPED]; /* hashes of the pages counted */
    size_t ndropped;
    bool lessons_untrusted_incomplete; /* more distinct pages than the set holds */
    int64_t now;
    bool lesson_lost; /* a lesson could not be copied: the query fails */
    char revision[41];
    bool revision_unavailable;
    struct specialist_focus_evidence failure;
    bool failure_present, failure_unavailable, cut_failure, cut_revision;
    int64_t deadline_ms;
    const char *root;
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

#define CB_BAD_PATH "paths must be repo-relative paths without empty segments, backslashes or control bytes"

/* Refusal for a root-relative path, or NULL when its shape is sound. */
static const char *cb_path_shape(const char *p)
{
    if (strchr(p, '\\'))
        return CB_BAD_PATH;
    for (size_t i = 0; p[i]; i++)
        if ((unsigned char)p[i] < 0x20)
            return CB_BAD_PATH;
    const char *seg = p;
    while (seg) {
        const char *slash = strchr(seg, '/');
        size_t len = slash ? (size_t)(slash - seg) : strlen(seg);
        if (len == 2 && seg[0] == '.' && seg[1] == '.')
            return "paths must not contain .. segments";
        if (len == 0)
            return CB_BAD_PATH;
        seg = slash ? slash + 1 : NULL;
    }
    return NULL;
}

/* An absolute path is accepted only under the source root; it becomes the
 * root-relative remainder. The root is compared over the bytes the caller
 * owns, so a prefix that runs past len is never matched. */
static const char *cb_root_relative(const struct cb_brief *b, const char **s,
                                    size_t *len)
{
    size_t rootlen = b->root ? strlen(b->root) : 0;
    while (rootlen > 0 && b->root[rootlen - 1] == '/')
        rootlen--;
    if ((*s)[0] != '/')
        return NULL;
    if (rootlen == 0 || *len <= rootlen ||
        memcmp(*s, b->root, rootlen) != 0 || (*s)[rootlen] != '/')
        return "paths must be under the source root";
    *s += rootlen + 1;
    *len -= rootlen + 1;
    return NULL;
}

static const char *cb_add_path(struct cb_brief *b, const char *s, size_t len)
{
    char tmp[CB_PATH_CAP];
    const char *err;
    while (len >= 2 && s[0] == '.' && s[1] == '/') {
        s += 2;
        len -= 2;
    }
    if ((err = cb_root_relative(b, &s, &len)))
        return err;
    while (len > 0 && s[len - 1] == '/')
        len--;
    if (len == 0)
        return "paths must not be empty";
    if (len >= CB_PATH_CAP)
        return "paths must be at most 255 bytes";
    memcpy(tmp, s, len);
    tmp[len] = '\0';
    if ((err = cb_path_shape(tmp)))
        return err;
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
    b->lesson_limit = json_get(in, "budget") ? CB_MAX_LESSONS : CB_LESSON_DEFAULT;
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
    /* Brief presentation only: keep the path's exact proofs before broad
     * shared-rule groups consume the cap. Full routing stays authoritative. */
    struct agent_impact_acc literal = {0};
    for (size_t i = 0; i < b->npaths; i++)
        agent_impact_collect_literal_groups(b->paths[i], &literal);
    for (size_t g = 0; g < literal.groups_len; g++)
        cb_add_test(b, literal.groups[g]);
    b->cut_tests = b->cut_tests || literal.groups_lost;
    const char *paths[CB_MAX_PATHS], *routes[CB_MAX_PATHS];
    bool risks[CB_MAX_PATHS];
    struct agent_impact_acc *accs = b->npaths > 1
        ? zcl_calloc(b->npaths, sizeof(*accs), "code_guide_routes") : NULL;
    for (size_t i = 0; i < b->npaths; i++)
        paths[i] = b->paths[i];
    bool batched = accs && zcl_native_code_routes_many_at(b->root, paths, b->npaths, accs, routes, risks);
    for (size_t i = 0; i < b->npaths; i++) {
        struct agent_impact_acc local;
        struct agent_impact_acc *acc = batched ? &accs[i] : &local;
        bool crisk = batched ? risks[i] : false;
        const char *route = batched ? routes[i]
            : zcl_native_code_route_at(b->root, b->paths[i], acc, &crisk);
        b->test_evidence_unavailable = b->test_evidence_unavailable || acc->referrer_read_failed;
        if (!crisk && acc->groups_len == 0) {
            b->unmapped = true;
            continue;
        }
        cb_add_test(b, route);
        for (size_t g = 0; g < acc->groups_len; g++)
            cb_add_test(b, acc->groups[g]);
    }
    free(accs);
}

/* ── lessons ──────────────────────────────────────────────────────────── */

enum cb_rank { CB_EXACT, CB_PREFIX, CB_STEM };

struct cb_query {
    char q[CB_QUERY_CAP];
    char applies[CB_QUERY_CAP];
    enum cb_rank rank;
};

static const char *cb_rank_name(enum cb_rank rank)
{
    return rank == CB_EXACT ? "exact" : rank == CB_PREFIX ? "prefix" : "stem";
}

static void cb_add_query(struct cb_query *qs, size_t *n, enum cb_rank rank,
                         const char *q, const char *applies)
{
    struct cb_query *t = &qs[*n];
    if ((!q[0] && !applies[0]) || *n >= CB_MAX_QUERIES ||
        strlen(q) >= CB_QUERY_CAP || strlen(applies) > CB_TOPIC_MAX)
        return;
    for (size_t i = 0; i < *n; i++)
        if (qs[i].rank == rank && !strcmp(qs[i].q, q) &&
            !strcmp(qs[i].applies, applies))
            return;
    memcpy(t->q, q, strlen(q) + 1);
    memcpy(t->applies, applies, strlen(applies) + 1);
    t->rank = rank;
    (*n)++;
}

static void cb_path_queries(struct cb_query *qs, size_t *n, enum cb_rank rank,
                            const char *p)
{
    const char *slash = strrchr(p, '/');
    char dir[CB_QUERY_CAP];
    if (rank == CB_EXACT) {
        cb_add_query(qs, n, rank, "", p);
    } else if (rank == CB_PREFIX) {
        /* Each enclosing directory as an exact applies_to, nearest first,
         * then anything the wiki applies under the nearest one. */
        size_t len = slash ? (size_t)(slash - p) : 0;
        bool nearest = true;
        while (len > 0 && len < sizeof(dir) - 1) {
            memcpy(dir, p, len);
            dir[len] = '\0';
            cb_add_query(qs, n, rank, "", dir);
            if (nearest) {
                dir[len] = '/';
                dir[len + 1] = '\0';
                cb_add_query(qs, n, rank, "", dir);
                nearest = false;
            }
            while (len > 0 && p[len - 1] != '/')
                len--;
            len = len > 0 ? len - 1 : 0;
        }
    } else if (rank == CB_STEM) {
        const char *base = slash ? slash + 1 : p;
        const char *dot = strrchr(base, '.');
        char stem[CB_QUERY_CAP];
        (void)cb_copy(stem, sizeof(stem), base,
                      dot && dot != base ? (size_t)(dot - base) : strlen(base));
        cb_add_query(qs, n, rank, stem, "");
    }
}

/* The queries best rank first: an exact applies_to filter for each path,
 * then each enclosing directory (the nearest also as a prefix), then its file
 * stem. A topic
 * is a stem query. Top-level directory words are never queries: they match
 * every page that happens to mention them. */
static size_t cb_queries(const struct cb_brief *b, struct cb_query *qs)
{
    size_t n = 0;
    if (b->topic[0]) {
        cb_add_query(qs, &n, CB_STEM, b->topic, "");
        return n;
    }
    for (enum cb_rank rank = CB_EXACT; rank <= CB_STEM; rank++)
        for (size_t i = 0; i < b->npaths; i++)
            cb_path_queries(qs, &n, rank, b->paths[i]);
    return n;
}

/* Best first: nearer match, then an author holding a role on this node,
 * then the fleet scope, then newer, then slug. */
static bool cb_lesson_before(const struct cb_lesson *a, const struct cb_lesson *c)
{
    if (a->rank != c->rank)
        return a->rank < c->rank;
    if (a->author_role != c->author_role)
        return a->author_role;
    if (a->pub != c->pub)
        return !a->pub;
    int cmp = strcmp(a->updated, c->updated);
    return cmp ? cmp > 0 : strcmp(a->slug, c->slug) < 0;
}

static uint64_t cb_slug_hash(const char *slug)
{
    uint64_t h = 1469598103934665603ULL;
    for (const char *p = slug; *p; p++)
        h = (h ^ (unsigned char)*p) * 1099511628211ULL;
    return h;
}

/* A page the default lesson limit kept off: remembered once, so the brief can
 * say how many more exist. */
static void cb_note_withheld(struct cb_brief *b, const char *slug)
{
    uint64_t h = cb_slug_hash(slug);
    for (size_t i = 0; i < b->nwithheld; i++)
        if (b->withheld[i] == h)
            return;
    if (b->nwithheld < CB_MAX_WITHHELD)
        b->withheld[b->nwithheld++] = h;
}

/* Offer one built lesson to the ranked slots, taking ownership of its
 * `matched`. A page seen again keeps its better ranking; a lesson past the
 * last slot is dropped and the brief is marked capped. */
static void cb_offer_lesson(struct cb_brief *b, struct cb_lesson *in)
{
    for (size_t i = 0; i < b->nlessons; i++) {
        struct cb_lesson *ex = &b->lessons[i];
        if (ex->pub != in->pub || strcmp(ex->slug, in->slug))
            continue;
        if (!cb_lesson_before(in, ex)) {
            json_free(&in->matched);
            return;
        }
        json_free(&ex->matched);
        memmove(ex, ex + 1, (b->nlessons - i - 1) * sizeof(*ex));
        b->nlessons--;
        break;
    }
    size_t at = b->nlessons;
    b->lessons[b->nlessons++] = *in;
    while (at > 0 && cb_lesson_before(&b->lessons[at], &b->lessons[at - 1])) {
        struct cb_lesson tmp = b->lessons[at - 1];
        b->lessons[at - 1] = b->lessons[at];
        b->lessons[at] = tmp;
        at--;
    }
    size_t limit = b->lesson_limit ? b->lesson_limit : CB_MAX_LESSONS;
    if (b->nlessons > limit) {
        cb_note_withheld(b, b->lessons[b->nlessons - 1].slug);
        json_free(&b->lessons[--b->nlessons].matched);
        b->lessons_capped = true;
    }
}

/* Count a roleless page once, however many queries return it. */
static void cb_count_untrusted(struct cb_brief *b, const char *slug)
{
    uint64_t h = cb_slug_hash(slug);
    for (size_t i = 0; i < b->ndropped; i++)
        if (b->dropped[i] == h)
            return;
    if (b->ndropped == CB_MAX_DROPPED) {
        b->lessons_untrusted_incomplete = true;
        return; /* a lower bound beyond the set: never count a page twice */
    }
    b->dropped[b->ndropped++] = h;
    b->lessons_untrusted++;
}

/* The paths a lesson says it applies to, to be checked for change: the
 * entry's own applies_to (bounded), else the file of an exact query. */
static void cb_lesson_applies(struct cb_lesson *l, const struct json_value *e,
                              const char *fallback)
{
    const struct json_value *a = json_get(e, "applies_to");
    for (size_t i = 0; a && i < json_size(a) && l->napplies < CB_LESSON_APPLIES; i++) {
        const struct json_value *v = json_at(a, i);
        const char *s = v && v->type == JSON_STR ? json_get_str(v) : "";
        if (s[0] && strlen(s) < CB_QUERY_CAP)
            memcpy(l->applies[l->napplies++], s, strlen(s) + 1);
    }
    if (!l->napplies && fallback[0] && strlen(fallback) < CB_QUERY_CAP)
        memcpy(l->applies[l->napplies++], fallback, strlen(fallback) + 1);
}

static bool cb_take_lesson(struct cb_brief *b, const struct json_value *e,
                           enum cb_rank rank, bool pub, const char *applies)
{
    const char *slug = json_get_str(json_get(e, "slug"));
    const struct json_value *rules = json_get(e, "rules");
    const struct json_value *r0 = rules ? json_at(rules, 0) : NULL;
    const char *text = r0 && r0->type == JSON_STR ? json_get_str(r0)
                                                  : json_get_str(json_get(e, "summary"));
    const char *updated = json_get_str(json_get(e, "updated"));
    struct cb_lesson l = {0};
    if (!slug[0] || !text[0] || strlen(slug) > CB_TOPIC_MAX)
        return true;
    l.author_role = json_get_bool(json_get(e, "author_role"));
    if (!l.author_role) {
        /* A page whose author the node no longer vouches for (never a role, or
         * revoked) is untrusted text in any scope. */
        cb_count_untrusted(b, slug);
        return true;
    }
    memcpy(l.slug, slug, strlen(slug) + 1);
    bool clipped = cb_copy(l.rule, CB_RULE_CAP, text, strlen(text));
    (void)cb_copy(l.updated, sizeof(l.updated), updated, strlen(updated));
    l.rank = rank;
    l.pub = pub;
    cb_lesson_applies(&l, e, applies);
    json_init(&l.matched);
    const struct json_value *matched = json_get(e, "matched");
    if (matched && !json_copy_checked(&l.matched, matched)) {
        b->lesson_lost = true;
        if (!b->unavailable[0])
            (void)snprintf(b->unavailable, sizeof(b->unavailable), "%s", "WIKI_UNAVAILABLE");
        return false;
    }
    if (!matched)
        json_set_array(&l.matched);
    b->lessons_capped = b->lessons_capped || clipped;
    cb_offer_lesson(b, &l);
    return true;
}

/* One fleet.wiki.find under the brief's absolute deadline. The leaf is
 * called directly, so the caller's authority ceiling is checked here. */
static void cb_wiki_run(const struct zcl_command_request *request,
                        const struct cb_query *qq, bool pub, const char *after,
                        int64_t deadline_ms, struct zcl_command_reply *reply)
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
    if (!spec || !json_push_kv_str(&input, "q", qq->q) ||
        (qq->applies[0] && !json_push_kv_str(&input, "applies_to", qq->applies)) ||
        !json_push_kv_str(&input, "scope", pub ? "public" : "fleet") ||
        (after[0] && !json_push_kv_str(&input, "after_slug", after)))
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

/* The exact-file query is the only one whose applies_to names a file the
 * lesson can be checked against for change. */
static const char *cb_check_file(const struct cb_query *qq)
{
    return qq->rank == CB_EXACT ? qq->applies : "";
}

/* One page of one search in one scope; *next is the after_slug to resume
 * from, empty when the wiki has no more. False when it failed; b->unavailable
 * then names why. A query that used up its time cap, or ran past the brief's
 * deadline, is WIKI_DEADLINE rather than a refusal. */
static bool cb_wiki_find(const struct zcl_command_request *request,
                         struct cb_brief *b, const struct cb_query *qq,
                         bool pub, const char *after, char *next)
{
    struct zcl_command_reply reply;
    int64_t start = platform_time_monotonic_ms();
    const struct json_value *entries;
    const char *more;
    bool ok;
    cb_wiki_run(request, qq, pub, after, b->deadline_ms, &reply);
    ok = reply.exit_code == ZCL_COMMAND_EXIT_OK;
    entries = ok ? json_get(&reply.data, "entries") : NULL;
    for (size_t i = 0; entries && i < json_size(entries); i++) {
        if (!cb_take_lesson(b, json_at(entries, i), qq->rank, pub,
                            cb_check_file(qq))) {
            ok = false;
            break;
        }
    }
    more = json_get_str(json_get(&reply.data, "after_slug"));
    next[0] = '\0';
    if (ok && json_get_bool(json_get(&reply.data, "incomplete")) &&
        strlen(more) <= CB_TOPIC_MAX && strcmp(more, after) > 0)
        memcpy(next, more, strlen(more) + 1);
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

/* A broad query reads up to CB_DIR_PAGES pages (while the wiki says more and
 * the deadline allows). A page that fails after the first still leaves the
 * query answered, unless a lesson could not be kept. */
static bool cb_wiki_query(const struct zcl_command_request *request,
                          struct cb_brief *b, const struct cb_query *qq,
                          bool pub)
{
    char after[CB_TOPIC_MAX + 1] = "";
    char next[CB_TOPIC_MAX + 1];
    for (int page = 0; page < CB_DIR_PAGES; page++) {
        if (!cb_wiki_find(request, b, qq, pub, after, next))
            return page > 0 && !b->lesson_lost;
        if (!next[0] || platform_time_monotonic_ms() >= b->deadline_ms)
            break;
        memcpy(after, next, strlen(next) + 1);
    }
    return true;
}

/* Rank dominates the ordering, so once every slot holds a nearer match than
 * this query can produce, it cannot change the answer. */
static bool cb_query_useless(const struct cb_brief *b, const struct cb_query *qq)
{
    return b->nlessons == CB_MAX_LESSONS &&
           b->lessons[CB_MAX_LESSONS - 1].rank < qq->rank;
}

/* Seconds since the epoch of the newest commit touching `file`, or 0 when
 * unknown (no checkout, no history, git failed). */
static int64_t cb_file_commit_time(const struct cb_brief *b, const char *file)
{
    const char *argv[] = {"git", "log", "-1", "--format=%ct", "--", file, NULL};
    char out[64];
    if (!b->revision[0] ||
        zcl_spawn_capture_in_dir_observed(argv, b->root, out, sizeof(out),
                                          250, NULL) != 0)
        return 0;
    return (int64_t)strtoll(out, NULL, 10);
}

/* The wiki deadline also bounds the staleness check (0: no deadline). */
static bool cb_past_deadline(const struct cb_brief *b)
{
    return b->deadline_ms && platform_time_monotonic_ms() >= b->deadline_ms;
}

/* Why the paths a lesson applies to may have moved on after `when`: a commit
 * after it, or "applies_to_unchecked" when the deadline ran out first. */
static const char *cb_applies_changed(const struct cb_brief *b,
                                      const struct cb_lesson *l, int64_t when)
{
    for (size_t i = 0; i < l->napplies; i++) {
        if (b->revision[0] && cb_past_deadline(b))
            return "applies_to_unchecked";
        if (cb_file_commit_time(b, l->applies[i]) > when)
            return "applies_to_changed";
    }
    return NULL;
}

/* Age and staleness for what was kept. Stale: undated, older than
 * CB_STALE_DAYS, or the file the lesson applies to changed after it was
 * written. */
static void cb_judge_lessons(struct cb_brief *b)
{
    for (size_t i = 0; i < b->nlessons; i++) {
        struct cb_lesson *l = &b->lessons[i];
        int64_t when = 0;
        l->age_days = -1;
        l->stale_reason = NULL;
        if (!zcl_objectives_parse_iso8601(l->updated, &when)) {
            l->stale_reason = "undated";
            continue;
        }
        l->age_days = b->now > when ? (b->now - when) / 86400 : 0;
        l->stale_reason = cb_applies_changed(b, l, when);
        if (l->stale_reason)
            continue;
        if (l->age_days > CB_STALE_DAYS)
            l->stale_reason = "age";
    }
}

static bool cb_push_lessons(struct json_value *data, const struct cb_brief *b);

/* Serialized size of the lessons array as the brief would emit it. */
static size_t cb_lessons_bytes(const struct cb_brief *b)
{
    struct json_value tmp;
    size_t n = 0;
    json_init(&tmp);
    json_set_object(&tmp);
    if (cb_push_lessons(&tmp, b))
        n = json_write(json_get(&tmp, "lessons"), NULL, 0);
    json_free(&tmp);
    return n;
}

/* Judge, then hold the lessons section to CB_LESSON_BYTES by dropping the
 * lowest-ranked lesson until it fits; the drop is reported. */
static void cb_finish_lessons(struct cb_brief *b)
{
    cb_judge_lessons(b);
    while (b->nlessons && cb_lessons_bytes(b) > CB_LESSON_BYTES) {
        json_free(&b->lessons[--b->nlessons].matched);
        b->lessons_truncated = true;
    }
    for (size_t i = 0; i < b->nwithheld; i++) {
        bool shown = false;
        for (size_t j = 0; j < b->nlessons; j++)
            shown = shown || cb_slug_hash(b->lessons[j].slug) == b->withheld[i];
        b->lessons_more += !shown;
    }
    /* The printed follow-up (an explicit budget) returns at most CB_MAX_LESSONS
     * lessons in all, so promise no more than the room left; the rest is
     * lessons_capped. */
    size_t room = b->nlessons < CB_MAX_LESSONS ? CB_MAX_LESSONS - b->nlessons : 0;
    if (b->lessons_more > room)
        b->lessons_more = (unsigned)room;
}

static void cb_collect_lessons(const struct zcl_command_request *request,
                               struct cb_brief *b)
{
    struct cb_query qs[CB_MAX_QUERIES];
    size_t n = cb_queries(b, qs);
    size_t answered = 0;
    bool dead[2] = {false, false}; /* fleet, public: a scope that failed */
    b->now = (int64_t)platform_time_wall_time_t();
    b->deadline_ms = platform_time_monotonic_ms() + CB_WIKI_DEADLINE_MS;
    for (size_t i = 0; i < n && !b->lesson_lost; i++) {
        if (platform_time_monotonic_ms() >= b->deadline_ms)
            break;
        if (cb_query_useless(b, &qs[i]))
            continue;
        /* Fleet pages first: they come only from keys with a role. */
        for (int pub = 0; pub < 2; pub++) {
            if (dead[pub] || b->lesson_lost)
                continue;
            bool ok = cb_wiki_query(request, b, &qs[i], pub != 0);
            answered += ok;
            dead[pub] = !ok;
        }
    }
    cb_finish_lessons(b);
    if (answered > 0 && !b->lesson_lost)
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

/* Quote paths that need shell protection; preserve simple paths as-is. */
static bool cb_cost_arg(const char *path, char out[static CB_NEXT_CAP])
{
    size_t len = strlen(path);
    if (len >= CB_PATH_CAP)
        return false;
    bool quote = strspn(path, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-") != len;
    size_t n = 0;
    if (quote) out[n++] = '\'';
    for (const char *p = path; *p; p++) {
        if (quote && *p == '\'') {
            memcpy(out + n, "'\\''", 4);
            n += 4;
        } else {
            out[n++] = *p;
        }
    }
    if (quote) out[n++] = '\'';
    out[n] = '\0';
    return n < CB_NEXT_CAP;
}

static void cb_push_next(struct cb_brief *b, const char *fmt, const char *arg)
{
    if (b->nnext >= CB_MAX_NEXT) {
        b->cut_next = true;
        return;
    }
    int n = snprintf(b->next[b->nnext], CB_NEXT_CAP, fmt, arg);
    if (n < 0 || (size_t)n >= CB_NEXT_CAP) {
        b->cut_next = true;
        return;
    }
    b->nnext++;
}

static bool cb_first_group(const struct cb_brief *b,
                           char first[ZCL_TEST_GROUP_FULL_MAX])
{
    for (size_t i = 0; i < b->ntests; i++)
        if (zcl_test_group_resolve_exact(b->tests[i], first)) return true;
    return false;
}

static void cb_build_next(struct cb_brief *b)
{
    char first[ZCL_TEST_GROUP_FULL_MAX];
    if (cb_first_group(b, first)) {
        cb_push_next(b, "make -j8 t-fast-exact ONLY=%s # first mapped group", first);
        if (cb_needs_preflight(b))
            cb_push_next(b, "%s", "make -j\"$(nproc 2>/dev/null || echo 2)\" lint-fast-preflight");
    } else {
        if (b->npaths) {
            char arg[CB_NEXT_CAP];
            if (cb_cost_arg(b->paths[0], arg))
                cb_push_next(b, b->paths[0][0] == '-'
                              ? "build/bin/z23 code cost --path=%s"
                              : "build/bin/z23 code cost %s", arg);
            else
                b->cut_next = true;
        }
        if (cb_needs_preflight(b))
            cb_push_next(b, "%s", "make -j\"$(nproc 2>/dev/null || echo 2)\" lint-fast-preflight");
        else
            cb_push_next(b, "%s", "make lint-fast");
    }
    if (b->ntests == 1 && strcmp(b->tests[0], "make_lint_gates") == 0)
        cb_push_next(b, "%s", "build/bin/z23-lint run --list");
#if defined(__linux__)
    for (size_t i = 0; i < b->npaths; ++i) {
        if (strcmp(b->paths[i], "tools/dev/build-epoch-session.sh") == 0 ||
            strcmp(b->paths[i], "tools/dev/build-epoch-selftest.sh") == 0) {
            char arg[CB_NEXT_CAP];
            char *root = realpath(b->root, NULL);
            if (root && cb_cost_arg(root, arg))
                cb_push_next(b, "z23 ops host gc --checkout=%s --epoch_keep=1", arg);
            else
                b->cut_next = true;
            free(root);
            break;
        }
    }
#endif
    cb_push_next(b, "%s", "z23 ops host gc --apply=false");
}

/* ── checkout and previous-run evidence ───────────────────────────────── */

static void cb_collect_revision(struct cb_brief *b)
{
    char marker[CB_HEAD_CAP];
    struct stat st;
    int n = snprintf(marker, sizeof(marker), "%s/.git", b->root);
    if (n <= 0 || (size_t)n >= sizeof(marker) ||
        stat(marker, &st) != 0) {
        b->revision_unavailable = true;
        return;
    }
    const char *argv[] = {"git", "rev-parse", "--verify", "HEAD", NULL};
    char out[128];
    if (zcl_spawn_capture_in_dir_observed(argv, b->root, out, sizeof(out),
                                          250, NULL) != 0) {
        b->revision_unavailable = true;
        return;
    }
    out[strcspn(out, "\r\n")] = '\0';
    size_t len = strlen(out);
    bool hex = len == 40;
    for (size_t i = 0; hex && i < len; i++)
        hex = (out[i] >= '0' && out[i] <= '9') ||
              (out[i] >= 'a' && out[i] <= 'f');
    if (!hex) {
        b->revision_unavailable = true;
        return;
    }
    memcpy(b->revision, out, 41);
}

static void cb_collect_failure(struct cb_brief *b)
{
    b->failure_present = true;
    specialist_focus_evidence_clear(&b->failure);
    if (!specialist_focus_load_failed_groups(b->root, &b->failure))
        b->failure_unavailable = true;
}

/* ── render ───────────────────────────────────────────────────────────── */

#if defined(ZCL_TESTING)
static _Thread_local const char *g_cb_render_fault;
static _Thread_local unsigned g_cb_render_fault_nth, g_cb_render_fault_after;
/* after: 0 first build, 1 reduced build, 2 next insertion. */
void zcl_code_brief_test_render_fault(const char *label, unsigned nth, unsigned after)
{
    g_cb_render_fault = label;
    g_cb_render_fault_nth = nth;
    g_cb_render_fault_after = after;
}
#endif

/* json_push_back deep-copies this non-owning view. */
static bool cb_array_string(struct json_value *arr, const char *text)
{
    struct json_value view = { .type = JSON_STR, .val.s = (char *)text };
    return json_push_back(arr, &view);
}

static bool cb_push_strs(struct json_value *obj, const char *key,
                         const char (*list)[CB_RULE_CAP], size_t n)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    bool ok = true;
    for (size_t i = 0; ok && i < n; i++)
        ok = cb_array_string(&arr, list[i]);
    if (ok) ok = json_push_kv(obj, key, &arr);
    json_free(&arr);
    return ok;
}

static bool cb_push_owners(struct json_value *data, const struct cb_brief *b)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    bool ok = true;
    for (size_t i = 0; ok && i < b->nowners; i++) {
        struct json_value o;
        json_init(&o);
        json_set_object(&o);
        ok = json_push_kv_str(&o, "file", b->owners[i].file) &&
             cb_push_strs(&o, "rules", b->owners[i].rules, b->owners[i].nrules) &&
             json_push_back(&arr, &o);
        json_free(&o);
    }
    if (ok) ok = json_push_kv(data, "owners", &arr);
    json_free(&arr);
    return ok;
}

/* One lesson as the brief reports it. */
static bool cb_lesson_object(struct json_value *o, const struct cb_lesson *l)
{
    return json_push_kv_str(o, "slug", l->slug) &&
           json_push_kv_str(o, "rule", l->rule) &&
           json_push_kv(o, "matched", &l->matched) &&
           json_push_kv_str(o, "scope", l->pub ? "public" : "fleet") &&
           json_push_kv_str(o, "match", cb_rank_name((enum cb_rank)l->rank)) &&
           json_push_kv_bool(o, "author_role", l->author_role) &&
           (l->age_days < 0 || json_push_kv_int(o, "age_days", l->age_days)) &&
           json_push_kv_bool(o, "stale", l->stale_reason != NULL) &&
           (!l->stale_reason || json_push_kv_str(o, "stale_reason", l->stale_reason));
}

static bool cb_push_lessons(struct json_value *data, const struct cb_brief *b)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    bool ok = true;
    for (size_t i = 0; ok && i < b->nlessons; i++) {
        struct json_value o;
        json_init(&o);
        json_set_object(&o);
        ok = cb_lesson_object(&o, &b->lessons[i]) && json_push_back(&arr, &o);
        json_free(&o);
    }
    if (ok) ok = json_push_kv(data, "lessons", &arr);
    json_free(&arr);
    return ok;
}

#if defined(ZCL_TESTING)
static bool cb_push_lesson_evidence(struct json_value *data, const struct cb_brief *b);

/* Exercise the lesson ranking, trust, staleness and size cap without a fleet
 * wiki service. Each entry may carry test_rank (0 exact, 1 prefix, 2 stem)
 * and test_scope ("public"; fleet when absent); `now` is the wall clock. */
bool zcl_code_brief_test_collect_lessons(const struct json_value *entries,
                                          const char *prior_error, int64_t now,
                                          struct json_value *data)
{
    struct cb_brief *b = zcl_calloc(1, sizeof(*b), "code_guide_test_brief");
    if (!b) return false;
    b->now = now;
    b->lesson_lost = prior_error != NULL;
    if (prior_error)
        (void)snprintf(b->unavailable, sizeof(b->unavailable), "%s", prior_error);
    for (size_t i = 0; i < json_size(entries); i++) {
        const struct json_value *e = json_at(entries, i);
        bool pub = !strcmp(json_get_str(json_get(e, "test_scope")), "public");
        if (!cb_take_lesson(b, e, (enum cb_rank)json_get_int(json_get(e, "test_rank")),
                            pub, json_get_str(json_get(e, "test_applies"))))
            break;
    }
    cb_finish_lessons(b);
    bool ok = cb_push_lesson_evidence(data, b);
    for (size_t i = 0; i < b->nlessons; i++)
        json_free(&b->lessons[i].matched);
    free(b);
    return ok;
}
#endif

static bool cb_push_failure(struct json_value *data, const struct cb_brief *b)
{
    if (!b->failure_present)
        return true;
    struct json_value obj, groups;
    json_init(&obj);
    json_set_object(&obj);
    json_init(&groups);
    json_set_array(&groups);
    const char *status = b->failure_unavailable ? "unavailable"
        : b->failure.tests_run == SPECIALIST_FOCUS_ARTIFACT_MISSING
            ? "no run recorded" : "recorded";
    bool ok = json_push_kv_str(&obj, "status", status) &&
        json_push_kv_str(&obj, "source", ".cache/test-timing/last-run.json");
    if (ok && !b->failure_unavailable &&
        b->failure.tests_run != SPECIALIST_FOCUS_ARTIFACT_MISSING)
        ok = json_push_kv_str(&obj, "revision_binding", "unbound_last_run");
    for (size_t i = 0; ok && !b->failure_unavailable && i < b->failure.failed_count; i++) {
        const char *name = b->failure.failed[i];
        if (cb_has(b->tests, b->ntests, ZCL_AGENT_IMPACT_GROUP_MAX, name))
            ok = cb_array_string(&groups, name);
    }
    if (ok)
        ok = json_push_kv(&obj, "failed_groups", &groups) &&
             json_push_kv(data, "previous_failure", &obj);
    json_free(&groups);
    json_free(&obj);
    return ok;
}

static bool cb_push_cut(struct json_value *data, const struct cb_brief *b)
{
    static const char *const names[] = {"lessons", "failure", "tests",
                                        "owner_rules", "owners", "revision", "next"};
    const bool flags[] = {b->cut_lessons, b->cut_failure, b->cut_tests,
                          b->cut_rules, b->cut_owners, b->cut_revision, b->cut_next};
    struct json_value arr;
    bool any = false, ok = true;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; ok && i < sizeof(flags) / sizeof(flags[0]); i++) {
        if (!flags[i]) continue;
        any = true;
        ok = cb_array_string(&arr, names[i]);
    }
    if (ok) ok = json_push_kv_bool(data, "truncated", any);
    if (ok && any) ok = json_push_kv(data, "cut", &arr);
    json_free(&arr);
    return ok;
}

static bool cb_push_tests(struct json_value *data, const struct cb_brief *b)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    bool ok = true;
    for (size_t i = 0; ok && i < b->ntests; i++)
        ok = cb_array_string(&arr, b->tests[i]);
    if (ok) ok = json_push_kv(data, "tests", &arr);
    json_free(&arr);
    return ok && (!b->unmapped || json_push_kv_bool(data, "tests_unmapped", true)) &&
           (!b->test_evidence_unavailable || json_push_kv_bool(data, "test_evidence_unavailable", true));
}

static bool cb_push_next_cmds(struct json_value *data, const struct cb_brief *b)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    bool ok = true;
    for (size_t i = 0; ok && i < b->nnext; i++)
        ok = cb_array_string(&arr, b->next[i]);
#if defined(ZCL_TESTING)
    if (ok && g_cb_render_fault && g_cb_render_fault_after == 2) {
        zcl_alloc_fault_fail_nth(g_cb_render_fault, g_cb_render_fault_nth);
        g_cb_render_fault = NULL;
    }
#endif
    if (ok) ok = json_push_kv(data, "next", &arr);
    json_free(&arr);
    return ok;
}

static bool cb_push_provenance(struct json_value *data, const struct cb_brief *b)
{
    return (!b->revision[0] || json_push_kv_str(data, "source_revision", b->revision)) &&
           (!b->revision_unavailable || json_push_kv_bool(data, "source_revision_unavailable", true)) &&
           cb_push_failure(data, b);
}

static bool cb_push_routing(struct json_value *data, const struct cb_brief *b)
{
    return ((b->cut_owners && b->nowners == 0) || cb_push_owners(data, b)) &&
           ((b->cut_tests && b->ntests == 0) || cb_push_tests(data, b));
}

static bool cb_push_lesson_flags(struct json_value *data, const struct cb_brief *b,
                                 bool omitted)
{
    return (omitted || !b->lessons_capped ||
            json_push_kv_bool(data, "lessons_capped", true)) &&
           (omitted || !b->lessons_truncated ||
            json_push_kv_bool(data, "lessons_truncated", true)) &&
           (omitted || !b->lessons_untrusted_incomplete ||
            json_push_kv_bool(data, "lessons_untrusted_incomplete", true));
}

/* The exact command that returns the lessons the default limit kept off: the
 * same paths or topic with an explicit budget, which lifts the limit. */
static bool cb_more_command(const struct cb_brief *b, char *out, size_t cap)
{
    size_t n = (size_t)snprintf(out, cap, "build/bin/z23 code guide");
    for (size_t i = 0; i < b->npaths && n < cap; i++) {
        char arg[CB_NEXT_CAP];
        if (!cb_cost_arg(b->paths[i], arg))
            return false;
        n += (size_t)snprintf(out + n, cap - n, " %s", arg);
    }
    if (b->topic[0] && n < cap) {
        char arg[CB_NEXT_CAP];
        if (!cb_cost_arg(b->topic, arg))
            return false;
        n += (size_t)snprintf(out + n, cap - n, " --topic=%s", arg);
    }
    if (n < cap)
        n += (size_t)snprintf(out + n, cap - n, " --budget=%d", CB_MORE_BUDGET);
    return n < cap;
}

static bool cb_push_lessons_more(struct json_value *data, const struct cb_brief *b)
{
    char cmd[CB_NEXT_CAP + 96];
    if (!b->lessons_more)
        return true;
    return json_push_kv_int(data, "lessons_more", (int64_t)b->lessons_more) &&
           (!cb_more_command(b, cmd, sizeof(cmd)) ||
            json_push_kv_str(data, "lessons_more_command", cmd));
}

static bool cb_push_lesson_evidence(struct json_value *data, const struct cb_brief *b)
{
    bool omitted = b->cut_lessons && b->nlessons == 0;
    return (omitted || cb_push_lessons(data, b)) &&
           (omitted || cb_push_lessons_more(data, b)) &&
           (omitted || !b->unavailable[0] ||
            json_push_kv_str(data, "lessons_unavailable", b->unavailable)) &&
           cb_push_lesson_flags(data, b, omitted) &&
           (omitted || !b->lessons_untrusted ||
            json_push_kv_int(data, "lessons_untrusted_dropped", (int64_t)b->lessons_untrusted));
}

static bool cb_build(const struct cb_brief *b, struct json_value *data)
{
    json_free(data);
    json_init(data);
    json_set_object(data);
    return json_push_kv_str(data, "schema", "zcl.code_guide_brief.v1") &&
           cb_push_provenance(data, b) && cb_push_routing(data, b) &&
           cb_push_lesson_evidence(data, b) &&
           ((b->cut_next && b->nnext == 0) || cb_push_next_cmds(data, b)) &&
           cb_push_cut(data, b);
}

/* Remove the lowest-priority content that is left; false when none is. */
static bool cb_reduce(struct cb_brief *b)
{
    if (b->nlessons) {
        json_free(&b->lessons[--b->nlessons].matched);
        b->cut_lessons = true;
    } else if (b->failure_present) {
        b->failure_present = false;
        b->cut_failure = true;
    } else if (!b->cut_lessons) {
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
    } else if (b->revision[0]) {
        b->revision[0] = '\0';
        b->cut_revision = true;
    } else if (b->nnext) {
        b->nnext--;
        b->cut_next = true;
    } else {
        return false;
    }
    return true;
}

enum cb_fit_result { CB_FIT_OK, CB_FIT_ALLOC, CB_FIT_BUDGET };

static enum cb_fit_result cb_fit(struct cb_brief *b, struct json_value *data)
{
    for (;;) {
#if defined(ZCL_TESTING)
        if (g_cb_render_fault && g_cb_render_fault_after != 2 && g_cb_render_fault_after-- == 0) {
            zcl_alloc_fault_fail_nth(g_cb_render_fault, g_cb_render_fault_nth);
            g_cb_render_fault = NULL;
        }
#endif
        if (!cb_build(b, data))
            return CB_FIT_ALLOC;
        if (json_write(data, NULL, 0) <= b->budget)
            return CB_FIT_OK;
        if (!cb_reduce(b))
            return CB_FIT_BUDGET;
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
    b->root = zcl_native_source_root(request);
    err = cb_parse(b, request->input);
    if (err) {
        cb_fail(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_CODE_GUIDE_INPUT", err);
        cb_free(b);
        return;
    }
    cb_collect_revision(b);
    cb_collect_owners(b, zcl_native_source_root(request));
    cb_collect_tests(b);
    cb_collect_failure(b);
    cb_collect_lessons(request, b);
    cb_build_next(b);
    enum cb_fit_result result = cb_fit(b, &reply->data);
    if (result != CB_FIT_OK) {
        json_free(&reply->data);
        json_init(&reply->data);
        cb_fail(reply, ZCL_COMMAND_EXIT_INTERNAL,
                result == CB_FIT_ALLOC ? "CODE_GUIDE_ALLOC" : "CODE_GUIDE_OUTPUT",
                result == CB_FIT_ALLOC ? "the brief could not be allocated"
                                       : "the brief does not fit the budget");
    }
    cb_free(b);
}
