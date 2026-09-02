/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Deterministic specialist-focus ranking from recorded evidence. */

#include "codeindex/codeindex_focus.h"
#include "codeindex/codeindex.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/glob_match.h"
#include "util/log_macros.h"
#include "util/spawn.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FOCUS_TAG "codeindex.focus"

#define FOCUS_W_FAILED 100000
#define FOCUS_W_ISSUE 10000
#define FOCUS_W_LESSON 1000
#define FOCUS_W_UNROUTED 100
#define FOCUS_W_CHURN 1
#define FOCUS_CHURN_MAX 99
#define FOCUS_REASON_PART 8
#define FOCUS_REASON_PART_MAX 160
#define FOCUS_FILE_CAP (256u * 1024u)
#define FOCUS_GIT_CAP (256u * 1024u)
#define FOCUS_PAGE 64
#define FOCUS_ROUTE_CAP 12

static const struct specialist k_specialists[] = {
#define SPECIALIST(name_, terr_, gates_, groups_, facts_) \
    { name_, terr_, gates_, groups_, facts_ },
#include "../../../../engine/composition/specialists.def"
#undef SPECIALIST
};

const struct specialist *specialist_table(size_t *count)
{
    if (count)
        *count = sizeof(k_specialists) / sizeof(k_specialists[0]);
    return k_specialists;
}

const struct specialist *specialist_find(const char *name)
{
    if (!name || !name[0])
        return NULL;
    size_t n = sizeof(k_specialists) / sizeof(k_specialists[0]);
    for (size_t i = 0; i < n; i++) {
        if (strcmp(k_specialists[i].name, name) == 0)
            return &k_specialists[i];
    }
    return NULL;
}

static bool focus_has_glob_meta(const char *pat)
{
    for (const char *p = pat; *p; p++) {
        if (*p == '*' || *p == '?' || *p == '[')
            return true;
    }
    return false;
}

static bool focus_prefix_match(const char *prefix, const char *path)
{
    size_t n = strlen(prefix);
    if (n == 0)
        return false;
    if (strncmp(path, prefix, n) != 0)
        return false;
    return path[n] == '\0' || path[n] == '/';
}

static bool focus_one_territory(const char *pat, size_t len, const char *path)
{
    char buf[512];
    if (!pat || !path || len == 0 || len >= sizeof(buf))
        return false;
    memcpy(buf, pat, len);
    buf[len] = '\0';
    if (focus_has_glob_meta(buf))
        return platform_glob_match(buf, path, false);
    return focus_prefix_match(buf, path);
}

bool specialist_path_in_territory(const struct specialist *spec,
                                  const char *path)
{
    if (!spec || !spec->territories || !path || !path[0])
        return false;
    const char *start = spec->territories;
    while (*start) {
        const char *bar = strchr(start, '|');
        size_t len = bar ? (size_t)(bar - start) : strlen(start);
        if (focus_one_territory(start, len, path))
            return true;
        if (!bar)
            break;
        start = bar + 1;
    }
    return false;
}

void specialist_focus_evidence_clear(struct specialist_focus_evidence *ev)
{
    if (!ev)
        return;
    memset(ev, 0, sizeof(*ev));
}

static bool focus_join(char *dst, size_t cap, const char *root,
                       const char *rel)
{
    int n = snprintf(dst, cap, "%s/%s", root && root[0] ? root : ".", rel);
    if (n < 0 || (size_t)n >= cap) {
        LOG_ERROR(FOCUS_TAG, "path too long: %s/%s",
                  root ? root : ".", rel);
        return false;
    }
    return true;
}

static char *focus_read_file(const char *path, size_t cap, size_t *len_out)
{
    if (len_out)
        *len_out = 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    char *buf = zcl_calloc(1, cap + 1u, "codeindex.focus.file");
    if (!buf) {
        fclose(f);
        LOG_NULL(FOCUS_TAG, "allocate %zu bytes for %s", cap, path);
    }
    size_t n = fread(buf, 1, cap, f);
    int err = ferror(f);
    fclose(f);
    if (err) {
        free(buf);
        LOG_NULL(FOCUS_TAG, "read %s", path);
    }
    buf[n] = '\0';
    if (len_out)
        *len_out = n;
    return buf;
}

static bool focus_add_failed(struct specialist_focus_evidence *ev,
                             const char *name)
{
    if (!name || !name[0])
        return true;
    for (size_t i = 0; i < ev->failed_count; i++) {
        if (strcmp(ev->failed[i], name) == 0)
            return true;
    }
    if (ev->failed_count >= SPECIALIST_FOCUS_FAILED_CAP)
        return true;
    int n = snprintf(ev->failed[ev->failed_count], SPECIALIST_GROUP_MAX,
                     "%s", name);
    if (n < 0 || (size_t)n >= SPECIALIST_GROUP_MAX) {
        LOG_ERROR(FOCUS_TAG, "failed-group name too long: %s", name);
        return false;
    }
    ev->failed_count++;
    return true;
}

bool specialist_focus_load_failed_groups(const char *root,
                                         struct specialist_focus_evidence *ev)
{
    if (!ev)
        LOG_FAIL(FOCUS_TAG, "evidence is NULL");
    char path[4096];
    if (!focus_join(path, sizeof(path), root,
                    ".cache/test-timing/last-run.json"))
        LOG_FAIL(FOCUS_TAG, "last-run path");
    size_t len = 0;
    char *raw = focus_read_file(path, FOCUS_FILE_CAP, &len);
    if (!raw)
        return true;
    struct json_value doc;
    json_init(&doc);
    if (!json_read(&doc, raw, len) || doc.type != JSON_OBJ) {
        json_free(&doc);
        free(raw);
        LOG_FAIL(FOCUS_TAG, "corrupt last-run.json at %s", path);
    }
    free(raw);
    const struct json_value *groups = json_get(&doc, "groups");
    if (!groups || groups->type != JSON_ARR) {
        json_free(&doc);
        return true;
    }
    bool ok = true;
    for (size_t i = 0; i < groups->num_children && ok; i++) {
        const struct json_value *row = &groups->children[i];
        const char *name = json_get_str(json_get(row, "name"));
        int64_t rc = json_get_int(json_get(row, "rc"));
        if (rc != 0)
            ok = focus_add_failed(ev, name);
    }
    json_free(&doc);
    if (!ok)
        LOG_FAIL(FOCUS_TAG, "failed-group table overflowed a name");
    return true;
}

static bool focus_is_path_char(unsigned char c)
{
    return isalnum(c) || c == '_' || c == '.' || c == '/' || c == '-';
}

static bool focus_looks_like_path(const char *s, size_t n)
{
    if (n < 3 || n >= SPECIALIST_PATH_MAX)
        return false;
    bool slash = false;
    for (size_t i = 0; i < n; i++) {
        if (!focus_is_path_char((unsigned char)s[i]))
            return false;
        if (s[i] == '/')
            slash = true;
    }
    if (!slash)
        return false;
    if (n >= 2 && s[n - 2] == '.' &&
        (s[n - 1] == 'c' || s[n - 1] == 'h'))
        return true;
    if (n >= 4 && s[n - 4] == '.' &&
        ((s[n - 3] == 'd' && s[n - 2] == 'e' && s[n - 1] == 'f') ||
         (s[n - 3] == 's' && s[n - 2] == 'h')))
        return true;
    return false;
}

static bool focus_line_is_open(const char *line)
{
    for (const char *p = line; *p; p++) {
        if ((p == line || !isalnum((unsigned char)p[-1])) &&
            (strncmp(p, "CLOSED", 6) == 0 || strncmp(p, "closed", 6) == 0 ||
             strncmp(p, "DONE", 4) == 0 || strncmp(p, "done", 4) == 0) &&
            !isalnum((unsigned char)p[p[0] == 'D' || p[0] == 'd' ? 4 : 6]))
            return false;
    }
    return true;
}

static bool focus_add_binding(struct specialist_focus_binding *rows,
                              size_t *count, size_t cap, const char *path,
                              const char *source)
{
    if (!path || !path[0] || !source)
        return true;
    for (size_t i = 0; i < *count; i++) {
        if (strcmp(rows[i].path, path) == 0)
            return true;
    }
    if (*count >= cap)
        return true;
    int n = snprintf(rows[*count].path, SPECIALIST_PATH_MAX, "%s", path);
    if (n < 0 || (size_t)n >= SPECIALIST_PATH_MAX) {
        LOG_ERROR(FOCUS_TAG, "binding path too long: %s", path);
        return false;
    }
    n = snprintf(rows[*count].source, SPECIALIST_SOURCE_MAX, "%s", source);
    if (n < 0 || (size_t)n >= SPECIALIST_SOURCE_MAX) {
        LOG_ERROR(FOCUS_TAG, "binding source too long: %s", source);
        return false;
    }
    (*count)++;
    return true;
}

static bool focus_scan_paths(const char *text, bool require_open,
                             struct specialist_focus_binding *rows,
                             size_t *count, size_t cap, const char *source)
{
    if (!text)
        return true;
    const char *line = text;
    while (*line) {
        const char *eol = strchr(line, '\n');
        size_t linelen = eol ? (size_t)(eol - line) : strlen(line);
        if (!require_open || focus_line_is_open(line)) {
            for (size_t i = 0; i < linelen; ) {
                while (i < linelen &&
                       (line[i] == '`' || line[i] == '"' ||
                        !focus_is_path_char((unsigned char)line[i])))
                    i++;
                size_t start = i;
                while (i < linelen &&
                       focus_is_path_char((unsigned char)line[i]))
                    i++;
                if (focus_looks_like_path(line + start, i - start)) {
                    char path[SPECIALIST_PATH_MAX];
                    memcpy(path, line + start, i - start);
                    path[i - start] = '\0';
                    if (!focus_add_binding(rows, count, cap, path, source))
                        return false;
                }
            }
        }
        line = eol ? eol + 1 : line + linelen;
    }
    return true;
}

bool specialist_focus_load_notes(const char *root,
                                 struct specialist_focus_evidence *ev)
{
    if (!ev)
        LOG_FAIL(FOCUS_TAG, "evidence is NULL");
    char path[4096];
    if (!focus_join(path, sizeof(path), root, "docs/agent/LESSONS.md"))
        LOG_FAIL(FOCUS_TAG, "lessons path");
    size_t len = 0;
    char *raw = focus_read_file(path, FOCUS_FILE_CAP, &len);
    if (!raw)
        return true;
    bool ok = focus_scan_paths(raw, true, ev->notes, &ev->notes_count,
                               SPECIALIST_FOCUS_NOTE_CAP,
                               "docs/agent/LESSONS.md");
    free(raw);
    if (!ok)
        LOG_FAIL(FOCUS_TAG, "lessons path token overflowed");
    return true;
}

static bool focus_ci_issue_name(const char *path)
{
    char lower[SPECIALIST_PATH_MAX];
    size_t n = 0;
    for (; path && path[n] && n + 1 < sizeof lower; n++)
        lower[n] = (char)tolower((unsigned char)path[n]);
    lower[n] = '\0';
    return strstr(lower, "issue") != NULL;
}

bool specialist_focus_load_issues(const char *root,
                                  struct specialist_focus_evidence *ev)
{
    if (!ev)
        LOG_FAIL(FOCUS_TAG, "evidence is NULL");
    char *buf = zcl_calloc(1, FOCUS_GIT_CAP, "codeindex.focus.issues");
    if (!buf)
        LOG_FAIL(FOCUS_TAG, "allocate git ls-files buffer");
    const char *argv[] = { "git", "-C", root && root[0] ? root : ".",
                           "ls-files", "--", "docs", NULL };
    int rc = zcl_spawn_capture(argv, buf, FOCUS_GIT_CAP, 15000);
    if (rc != 0) {
        free(buf);
        return true;
    }
    bool ok = true;
    char *p = buf;
    while (ok && *p) {
        char *eol = strchr(p, '\n');
        if (eol)
            *eol = '\0';
        size_t n = strlen(p);
        if (n && p[n - 1] == '\r')
            p[n - 1] = '\0';
        if (p[0] && focus_ci_issue_name(p)) {
            char full[4096];
            if (!focus_join(full, sizeof(full), root, p)) {
                ok = false;
                break;
            }
            size_t len = 0;
            char *raw = focus_read_file(full, FOCUS_FILE_CAP, &len);
            if (raw) {
                ok = focus_scan_paths(raw, true, ev->issues,
                                      &ev->issues_count,
                                      SPECIALIST_FOCUS_ISSUE_CAP, p);
                free(raw);
            }
        }
        if (!eol)
            break;
        p = eol + 1;
    }
    free(buf);
    if (!ok)
        LOG_FAIL(FOCUS_TAG, "issue body path token overflowed");
    return true;
}

bool specialist_focus_load_churn(const char *root,
                                 struct specialist_focus_evidence *ev)
{
    if (!ev)
        LOG_FAIL(FOCUS_TAG, "evidence is NULL");
    char *buf = zcl_calloc(1, FOCUS_GIT_CAP, "codeindex.focus.churn");
    if (!buf)
        LOG_FAIL(FOCUS_TAG, "allocate git log buffer");
    const char *argv[] = {
        "git", "-C", root && root[0] ? root : ".", "log", "--name-only",
        "--pretty=format:%ct", "--max-count=200", "--", NULL
    };
    int rc = zcl_spawn_capture(argv, buf, FOCUS_GIT_CAP, 20000);
    if (rc != 0) {
        free(buf);
        return true;
    }
    int commit = -1;
    char *p = buf;
    while (*p) {
        char *eol = strchr(p, '\n');
        if (eol)
            *eol = '\0';
        size_t n = strlen(p);
        if (n && p[n - 1] == '\r')
            p[--n] = '\0';
        bool digits = n > 0;
        for (size_t i = 0; digits && i < n; i++)
            digits = isdigit((unsigned char)p[i]) != 0;
        if (digits) {
            commit++;
        } else if (p[0] && commit >= 0 &&
                   ev->churn_count < SPECIALIST_FOCUS_CHURN_CAP) {
            bool seen = false;
            for (size_t i = 0; i < ev->churn_count; i++) {
                if (strcmp(ev->churn[i].path, p) == 0) {
                    seen = true;
                    break;
                }
            }
            if (!seen) {
                int w = snprintf(ev->churn[ev->churn_count].path,
                                 SPECIALIST_PATH_MAX, "%s", p);
                if (w < 0 || (size_t)w >= SPECIALIST_PATH_MAX) {
                    LOG_ERROR(FOCUS_TAG, "churn path too long: %s", p);
                    free(buf);
                    LOG_FAIL(FOCUS_TAG, "churn path");
                }
                int rec = FOCUS_CHURN_MAX - commit;
                if (rec < 1)
                    rec = 1;
                ev->churn[ev->churn_count].recency = (uint32_t)rec;
                ev->churn_count++;
            }
        }
        if (!eol)
            break;
        p = eol + 1;
    }
    free(buf);
    return true;
}

static bool focus_groups_equal(const char *a, const char *b)
{
    if (!a || !b)
        return false;
    if (strcmp(a, b) == 0)
        return true;
    if (strncmp(a, "test_", 5) == 0 && strcmp(a + 5, b) == 0)
        return true;
    if (strncmp(b, "test_", 5) == 0 && strcmp(b + 5, a) == 0)
        return true;
    if (strncmp(a, "spec_", 5) == 0 && strcmp(a + 5, b) == 0)
        return true;
    if (strncmp(b, "spec_", 5) == 0 && strcmp(b + 5, a) == 0)
        return true;
    return false;
}

static int focus_reason_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int focus_hit_cmp(const void *a, const void *b)
{
    const struct specialist_focus_hit *ha = a;
    const struct specialist_focus_hit *hb = b;
    if (ha->score > hb->score)
        return -1;
    if (ha->score < hb->score)
        return 1;
    return strcmp(ha->path, hb->path);
}

static bool focus_add_reason(char parts[][FOCUS_REASON_PART_MAX], int *n,
                             const char *text)
{
    if (*n >= FOCUS_REASON_PART)
        return true;
    for (int i = 0; i < *n; i++) {
        if (strcmp(parts[i], text) == 0)
            return true;
    }
    int w = snprintf(parts[*n], FOCUS_REASON_PART_MAX, "%s", text);
    if (w < 0 || (size_t)w >= FOCUS_REASON_PART_MAX) {
        LOG_ERROR(FOCUS_TAG, "reason too long: %s", text);
        return false;
    }
    (*n)++;
    return true;
}

static bool focus_join_reasons(char *dst, size_t cap,
                               char parts[][FOCUS_REASON_PART_MAX], int n)
{
    qsort(parts, (size_t)n, FOCUS_REASON_PART_MAX, focus_reason_cmp);
    dst[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < n; i++) {
        int w = snprintf(dst + used, cap - used, "%s%s",
                         i ? "; " : "", parts[i]);
        if (w < 0 || (size_t)w >= cap - used) {
            LOG_ERROR(FOCUS_TAG, "joined reason overflowed");
            return false;
        }
        used += (size_t)w;
    }
    return true;
}

int specialist_focus_rank(struct codeindex *ci,
                          const struct specialist *spec,
                          const struct specialist_focus_evidence *ev,
                          specialist_focus_route_fn route, void *route_user,
                          struct specialist_focus_hit *out, int cap,
                          bool *truncated)
{
    if (truncated)
        *truncated = false;
    if (!ci || !spec || !ev || !route || !out || cap < 0) {
        LOG_ERROR(FOCUS_TAG, "rank missing argument");
        return -1;
    }
    if (cap == 0)
        return 0;

    struct specialist_focus_hit *work =
        zcl_calloc((size_t)SPECIALIST_FOCUS_WORK_CAP,
                   sizeof(*work), "codeindex.focus.work");
    if (!work)
        LOG_ERR(FOCUS_TAG, "allocate rank working set");

    int nwork = 0;
    bool overflow = false;
    int total = codeindex_file_count(ci);
    if (total < 0) {
        free(work);
        LOG_ERR(FOCUS_TAG, "codeindex_file_count failed");
    }
    struct ci_file page[FOCUS_PAGE];
    for (int off = 0; off < total; off += FOCUS_PAGE) {
        int got = codeindex_files_page(ci, off, page, FOCUS_PAGE);
        if (got < 0) {
            free(work);
            LOG_ERR(FOCUS_TAG, "codeindex_files_page failed at %d", off);
        }
        for (int i = 0; i < got; i++) {
            const char *path = page[i].path;
            if (!specialist_path_in_territory(spec, path))
                continue;
            char groups[FOCUS_ROUTE_CAP][SPECIALIST_GROUP_MAX];
            size_t ng = route(path, groups, FOCUS_ROUTE_CAP, route_user);
            int failed = 0;
            char fail_name[SPECIALIST_GROUP_MAX];
            fail_name[0] = '\0';
            for (size_t g = 0; g < ng; g++) {
                for (size_t f = 0; f < ev->failed_count; f++) {
                    if (focus_groups_equal(groups[g], ev->failed[f])) {
                        failed++;
                        if (!fail_name[0]) {
                            (void)snprintf(fail_name, sizeof fail_name, "%s",
                                           ev->failed[f]);
                        }
                    }
                }
            }
            uint32_t recency = 0;
            for (size_t c = 0; c < ev->churn_count; c++) {
                if (strcmp(ev->churn[c].path, path) == 0) {
                    recency = ev->churn[c].recency;
                    break;
                }
            }
            const char *note_src = NULL;
            for (size_t n = 0; n < ev->notes_count; n++) {
                if (strcmp(ev->notes[n].path, path) == 0) {
                    note_src = ev->notes[n].source;
                    break;
                }
            }
            const char *issue_src = NULL;
            for (size_t n = 0; n < ev->issues_count; n++) {
                if (strcmp(ev->issues[n].path, path) == 0) {
                    issue_src = ev->issues[n].source;
                    break;
                }
            }
            bool unrouted = ng == 0;
            if (failed == 0 && recency == 0 && !note_src && !issue_src &&
                !unrouted)
                continue;
            if (nwork >= SPECIALIST_FOCUS_WORK_CAP) {
                overflow = true;
                break;
            }
            char parts[FOCUS_REASON_PART][FOCUS_REASON_PART_MAX];
            int nparts = 0;
            if (failed > 0) {
                char line[FOCUS_REASON_PART_MAX];
                (void)snprintf(line, sizeof line,
                               "failed-group:%s (.cache/test-timing/last-run.json)",
                               fail_name);
                if (!focus_add_reason(parts, &nparts, line)) {
                    free(work);
                    return -1;
                }
            }
            if (recency > 0) {
                char line[FOCUS_REASON_PART_MAX];
                (void)snprintf(line, sizeof line, "churn:git-log recency=%u",
                               recency);
                if (!focus_add_reason(parts, &nparts, line)) {
                    free(work);
                    return -1;
                }
            }
            if (note_src) {
                char line[FOCUS_REASON_PART_MAX];
                (void)snprintf(line, sizeof line, "lesson:%s", note_src);
                if (!focus_add_reason(parts, &nparts, line)) {
                    free(work);
                    return -1;
                }
            }
            if (unrouted) {
                if (!focus_add_reason(parts, &nparts,
                                      "unrouted:agent_impact_rules")) {
                    free(work);
                    return -1;
                }
            }
            if (issue_src) {
                char line[FOCUS_REASON_PART_MAX];
                (void)snprintf(line, sizeof line, "issue:%s", issue_src);
                if (!focus_add_reason(parts, &nparts, line)) {
                    free(work);
                    return -1;
                }
            }
            struct specialist_focus_hit *h = &work[nwork];
            int w = snprintf(h->path, sizeof h->path, "%s", path);
            if (w < 0 || (size_t)w >= sizeof h->path) {
                free(work);
                LOG_ERR(FOCUS_TAG, "hit path too long: %s", path);
            }
            if (!focus_join_reasons(h->reason, sizeof h->reason, parts,
                                    nparts)) {
                free(work);
                return -1;
            }
            h->score = failed * FOCUS_W_FAILED +
                       (issue_src ? FOCUS_W_ISSUE : 0) +
                       (note_src ? FOCUS_W_LESSON : 0) +
                       (unrouted ? FOCUS_W_UNROUTED : 0) +
                       (int)recency * FOCUS_W_CHURN;
            nwork++;
        }
        if (overflow)
            break;
        if (got < FOCUS_PAGE)
            break;
    }

    qsort(work, (size_t)nwork, sizeof(work[0]), focus_hit_cmp);
    int emit = nwork;
    if (emit > cap) {
        overflow = true;
        emit = cap;
    }
    for (int i = 0; i < emit; i++)
        out[i] = work[i];
    free(work);
    if (truncated)
        *truncated = overflow;
    return emit;
}
