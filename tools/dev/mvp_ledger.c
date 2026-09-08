/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: measure the 144-loop MVP experiment — session transcript
 *          scanning and the agents.tsv reader/writer. See
 *          tools/dev/mvp_ledger.h for the contract and the refusal names;
 *          the plan of record lives in tools/dev/mvp_ledger_plan.c and the
 *          loop join in tools/dev/mvp_ledger_join.c. */
#define _POSIX_C_SOURCE 200809L
#include "mvp_ledger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/safe_alloc.h"
#include "fleet_observe.h"
#include "json/json.h"
#include "mvp_ledger_internal.h"
#include "platform/directory_compat.h"

/* ── small helpers ────────────────────────────────────────────────────── */

void mvl_copy(char *dst, size_t cap, const char *src)
{
    size_t n;

    if (!dst || cap == 0)
        return;
    n = src ? strlen(src) : 0;
    if (n >= cap)
        n = cap - 1;
    if (n > 0)
        memcpy(dst, src, n);
    dst[n] = '\0';
}

void mvl_err(char *err, size_t cap, const char *path, size_t line_no,
             const char *reason)
{
    if (!err || cap == 0)
        return;
    (void)snprintf(err, cap, "%s:%zu: %s", path ? path : "-", line_no, reason);
}

bool mvl_path_of(char *dst, size_t cap, const char *a, const char *b,
                 const char *c, const char *d)
{
    const char *parts[4] = {a, b, c, d};
    size_t used = 0;

    if (!dst || cap == 0)
        return false;
    dst[0] = '\0';
    for (int i = 0; i < 4; i++) {
        size_t n = parts[i] ? strlen(parts[i]) : 0;

        if (used + n >= cap) {
            dst[0] = '\0';
            return false;
        }
        if (n > 0)
            memcpy(dst + used, parts[i], n);
        used += n;
    }
    dst[used] = '\0';
    return true;
}

/* Tabs and newlines never reach a TSV cell: they would forge a column. */
void mvl_sanitize(char *s)
{
    for (; s && *s; s++)
        if (*s == '\t' || *s == '\n' || *s == '\r')
            *s = ' ';
}

bool mvl_parse_timestamp(const char *s, int64_t *out)
{
    char norm[MVL_UTC_CAP];
    size_t n;

    if (!s || !out)
        return false;
    n = strlen(s);
    if (n < 20 || n >= sizeof norm)
        return false;
    mvl_copy(norm, sizeof norm, s);
    if (norm[19] == '.') {
        norm[19] = 'Z';
        norm[20] = '\0';
    }
    return fo_parse_iso8601(norm, out);
}

/* ── description → (lane, kind) ───────────────────────────────────────── */

static void mvl_token(const char *src, char *dst, size_t cap)
{
    size_t n = 0;

    while (src[n] && src[n] != ' ' && src[n] != ':' && src[n] != ',')
        n++;
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static bool mvl_prefix(const char *s, const char *pfx, const char **rest)
{
    size_t n = strlen(pfx);

    if (strncmp(s, pfx, n) != 0)
        return false;
    *rest = s + n;
    return true;
}

void mvl_classify_description(const char *desc, char *lane, size_t lane_cap,
                              char *kind, size_t kind_cap)
{
    const char *rest = NULL;
    char token[MVL_LANE_CAP];

    mvl_copy(lane, lane_cap, "-");
    mvl_copy(kind, kind_cap, "other");
    if (!desc)
        return;
    if (mvl_prefix(desc, "Lane ", &rest))
        mvl_copy(kind, kind_cap, "build");
    else if (mvl_prefix(desc, "Re-verify ", &rest))
        mvl_copy(kind, kind_cap, "verify");
    else if (mvl_prefix(desc, "Verify ", &rest))
        mvl_copy(kind, kind_cap, "verify");
    else if (mvl_prefix(desc, "Assemble train ", &rest))
        mvl_copy(kind, kind_cap, "assemble");
    else
        return;
    mvl_token(rest, token, sizeof token);
    if (token[0] == '\0') {
        mvl_copy(kind, kind_cap, "other");
        return;
    }
    if (strcmp(kind, "assemble") == 0)
        (void)snprintf(lane, lane_cap, "train%s", token);
    else
        mvl_copy(lane, lane_cap, token);
}

/* ── outcome matching ─────────────────────────────────────────────────── */

static bool mvl_is_hex(char c)
{
    if (c >= '0' && c <= '9')
        return true;
    if (c >= 'a' && c <= 'f')
        return true;
    return c >= 'A' && c <= 'F';
}

/* A verdict is written many ways — `LAND 249fa5a1…`, "LAND `249fa5a1…`",
 * "**LAND** …" — so the markup between the marker and the sha is skipped
 * rather than made part of the contract. */
static bool mvl_marker_with_sha(const char *text, const char *marker)
{
    size_t mlen = strlen(marker);
    const char *p = text;

    while ((p = strstr(p, marker)) != NULL) {
        size_t hex = 0;
        const char *q = p + mlen;

        while (*q != '\0' && strchr("`'\"*(<[ ", *q) != NULL)
            q++;
        while (mvl_is_hex(q[hex]))
            hex++;
        if (hex >= 7)
            return true;
        p += mlen;
    }
    return false;
}

const char *mvl_match_outcome(const char *text)
{
    if (!text)
        return "-";
    if (mvl_marker_with_sha(text, "LAND "))
        return "LAND";
    if (mvl_marker_with_sha(text, "FIX "))
        return "FIX";
    if (strstr(text, "READY") != NULL)
        return "READY";
    if (strstr(text, "BLOCKED") != NULL)
        return "BLOCKED";
    return "-";
}

/* ── one assistant line ───────────────────────────────────────────────── */

static int64_t mvl_int(const struct json_value *obj, const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;

    return (v && v->type == JSON_INT) ? json_get_int(v) : 0;
}

static void mvl_fold_usage(const struct json_value *msg, struct mvl_agent *a)
{
    const struct json_value *usage = json_get(msg, "usage");
    const struct json_value *details;

    if (!usage || usage->type != JSON_OBJ)
        return;
    a->tokens_out += mvl_int(usage, "output_tokens");
    a->tokens_input += mvl_int(usage, "input_tokens");
    a->tokens_cache_creation += mvl_int(usage, "cache_creation_input_tokens");
    a->tokens_cache_read += mvl_int(usage, "cache_read_input_tokens");
    a->tokens_in = a->tokens_input + a->tokens_cache_creation
                   + a->tokens_cache_read;
    details = json_get(usage, "output_tokens_details");
    if (details && details->type == JSON_OBJ)
        a->thinking_tokens += mvl_int(details, "thinking_tokens");
}

/* Counts tool_use items and records the outcome this message's text
 * carries. The text itself is never retained: only the verdict is, so a
 * long final message costs no memory. */
static void mvl_fold_content(const struct json_value *msg, struct mvl_agent *a)
{
    const struct json_value *content = json_get(msg, "content");
    const char *verdict = NULL;

    if (!content || content->type != JSON_ARR)
        return;
    for (size_t i = 0; i < content->num_children; i++) {
        const struct json_value *item = json_at(content, i);
        const struct json_value *type = item ? json_get(item, "type") : NULL;
        const char *t = (type && type->type == JSON_STR) ? json_get_str(type)
                                                          : NULL;
        const struct json_value *text;

        if (!t)
            continue;
        if (strcmp(t, "tool_use") == 0)
            a->tool_uses++;
        if (strcmp(t, "text") != 0)
            continue;
        text = json_get(item, "text");
        if (!text || text->type != JSON_STR)
            continue;
        if (!verdict || strcmp(verdict, "-") == 0)
            verdict = mvl_match_outcome(json_get_str(text));
    }
    if (verdict)
        mvl_copy(a->outcome, sizeof a->outcome, verdict);
}

static void mvl_fold_time(const char *stamp, int64_t unix_s,
                          struct mvl_agent *a)
{
    if (a->turns == 0 || unix_s < a->first_unix) {
        a->first_unix = unix_s;
        mvl_copy(a->first_utc, sizeof a->first_utc, stamp);
    }
    if (a->turns == 0 || unix_s > a->last_unix) {
        a->last_unix = unix_s;
        mvl_copy(a->last_utc, sizeof a->last_utc, stamp);
    }
}

static const char *mvl_str(const struct json_value *obj, const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;

    return (v && v->type == JSON_STR) ? json_get_str(v) : NULL;
}

static bool mvl_fold_assistant(const struct json_value *root, size_t line_no,
                               struct mvl_agent *a, char *err, size_t err_cap)
{
    const struct json_value *msg = json_get(root, "message");
    const char *stamp = mvl_str(root, "timestamp");
    const char *request = mvl_str(root, "requestId");
    const char *model;
    int64_t unix_s = 0;
    bool fresh_request;

    if (!stamp) {
        mvl_err(err, err_cap, a->agent_id, line_no,
                "mvl_no_timestamp: assistant line has no timestamp");
        return false;
    }
    if (!mvl_parse_timestamp(stamp, &unix_s)) {
        mvl_err(err, err_cap, a->agent_id, line_no,
                "mvl_bad_timestamp: timestamp is not ISO-8601 UTC");
        return false;
    }
    mvl_fold_time(stamp, unix_s, a);
    a->turns++;
    if (!msg || msg->type != JSON_OBJ)
        return true;
    model = mvl_str(msg, "model");
    if (model && a->model[0] == '\0')
        mvl_copy(a->model, sizeof a->model, model);
    fresh_request = !request || strcmp(request, a->last_request) != 0;
    if (request)
        mvl_copy(a->last_request, sizeof a->last_request, request);
    if (fresh_request)
        mvl_fold_usage(msg, a);
    mvl_fold_content(msg, a);
    return true;
}

/* Folds the harness's own `<total_tokens>N tokens left` reminder. It rides
 * an attachment line, not an assistant line, so it is read separately. */
static void mvl_fold_budget(const struct json_value *root,
                            struct mvl_agent *a)
{
    const struct json_value *att = json_get(root, "attachment");
    const char *kind = att ? mvl_str(att, "type") : NULL;
    const char *text = att ? mvl_str(att, "text") : NULL;
    const char *open;
    int64_t left;

    if (!kind || strcmp(kind, "total_tokens_reminder") != 0 || !text)
        return;
    open = strstr(text, "<total_tokens>");
    if (!open)
        return;
    left = strtoll(open + strlen("<total_tokens>"), NULL, 10);
    if (left <= 0)
        return;
    if (a->budget_first == 0)
        a->budget_first = left;
    a->budget_last = left;
}

bool mvl_fold_line(const char *line, size_t line_no, struct mvl_agent *agent,
                   char *err, size_t err_cap)
{
    struct json_value root;
    const char *type;
    bool ok = true;

    json_init(&root);
    if (!json_read(&root, line, strlen(line))) {
        mvl_err(err, err_cap, agent->agent_id, line_no,
                "mvl_bad_json: line is not one JSON value");
        json_free(&root);
        return false;
    }
    if (root.type != JSON_OBJ) {
        mvl_err(err, err_cap, agent->agent_id, line_no,
                "mvl_not_object: line is not a JSON object");
        json_free(&root);
        return false;
    }
    type = mvl_str(&root, "type");
    if (!type) {
        mvl_err(err, err_cap, agent->agent_id, line_no,
                "mvl_no_type: line has no string \"type\"");
        ok = false;
    } else if (strcmp(type, "assistant") == 0)
        ok = mvl_fold_assistant(&root, line_no, agent, err, err_cap);
    else if (strcmp(type, "attachment") == 0)
        mvl_fold_budget(&root, agent);
    json_free(&root);
    return ok;
}

/* ── bounded line reading ─────────────────────────────────────────────── */

/* Returns 1 on a line, 0 at end of file, -1 when the line is longer than
 * MVL_LINE_CAP. `buf` must hold MVL_LINE_CAP + 2 bytes. */
int mvl_read_line(FILE *f, char *buf, size_t cap)
{
    size_t n;

    if (!fgets(buf, (int)cap, f))
        return 0;
    n = strlen(buf);
    if (n + 1 >= cap && buf[n - 1] != '\n')
        return -1;
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        buf[--n] = '\0';
    return 1;
}

bool mvl_scan_transcript(const char *path, struct mvl_agent *agent,
                         char *err, size_t err_cap)
{
    char *buf = zcl_malloc(MVL_LINE_CAP + 2, "mvl_line");
    FILE *f;
    size_t line_no = 0;
    bool ok = true;

    if (!buf) {
        mvl_err(err, err_cap, path, 0,
                "mvl_overflow: no memory for the line buffer");
        return false;
    }
    f = fopen(path, "r");
    if (!f) {
        mvl_err(err, err_cap, path, 0, "mvl_open: cannot read the transcript");
        free(buf);
        return false;
    }
    for (;;) {
        int rc = mvl_read_line(f, buf, MVL_LINE_CAP + 2);

        if (rc == 0)
            break;
        line_no++;
        if (rc < 0) {
            mvl_err(err, err_cap, path, line_no,
                    "mvl_line_too_long: line exceeds MVL_LINE_CAP bytes");
            ok = false;
            break;
        }
        if (buf[0] == '\0')
            continue;
        if (!mvl_fold_line(buf, line_no, agent, err, err_cap)) {
            ok = false;
            break;
        }
    }
    (void)fclose(f);
    free(buf);
    return ok;
}

/* ── the session tree ─────────────────────────────────────────────────── */

static bool mvl_is_agent_file(const char *name, char *id, size_t id_cap)
{
    size_t n = strlen(name);
    const char *dot;

    if (strncmp(name, "agent-", 6) != 0)
        return false;
    if (n < 12 || strcmp(name + n - 6, ".jsonl") != 0)
        return false;
    dot = name + n - 6;
    if ((size_t)(dot - (name + 6)) >= id_cap)
        return false;
    mvl_copy(id, id_cap, name + 6);
    id[dot - (name + 6)] = '\0';
    return true;
}

static void mvl_read_meta(const char *dir, const char *id, char *desc,
                          size_t desc_cap)
{
    char path[MVL_PATH_CAP];
    char raw[4096];
    struct json_value root;
    const char *d;
    FILE *f;
    size_t n;

    mvl_copy(desc, desc_cap, "-");
    if (!mvl_path_of(path, sizeof path, dir, "/agent-", id, ".meta.json"))
        return;
    f = fopen(path, "r");
    if (!f)
        return;
    n = fread(raw, 1, sizeof raw - 1, f);
    (void)fclose(f);
    raw[n] = '\0';
    json_init(&root);
    if (json_read(&root, raw, n)) {
        d = mvl_str(&root, "description");
        if (d)
            mvl_copy(desc, desc_cap, d);
    }
    json_free(&root);
}

struct mvl_agent *mvl_next_row(struct mvl_agents *out, char *err,
                                      size_t err_cap)
{
    struct mvl_agent *a;

    if (out->count >= out->cap) {
        mvl_err(err, err_cap, "session", out->count,
                "mvl_overflow: more agents than MVL_MAX_AGENTS");
        return NULL;
    }
    a = &out->rows[out->count++];
    memset(a, 0, sizeof *a);
    return a;
}

/* Scans one directory of `agent-<id>.jsonl` files. `wf` is NULL for the
 * ordinary subagents directory (lane and kind come from the description) and
 * otherwise names the workflow, which makes every agent in it a design
 * agent of that workflow. */
static bool mvl_scan_agent_dir(const char *dir, const char *wf,
                               struct mvl_agents *out, char *err,
                               size_t err_cap)
{
    struct platform_directory_list files = {0};
    bool ok = true;

    if (!platform_directory_list_regular_sorted(dir, &files))
        return true;
    for (size_t i = 0; ok && i < files.count; i++) {
        char id[MVL_ID_CAP];
        char path[MVL_PATH_CAP];
        struct mvl_agent *a;

        if (!mvl_is_agent_file(files.entries[i].name, id, sizeof id))
            continue;
        a = mvl_next_row(out, err, err_cap);
        if (!a) {
            ok = false;
            break;
        }
        mvl_copy(a->agent_id, sizeof a->agent_id, id);
        if (wf) {
            mvl_copy(a->description, sizeof a->description, wf);
            mvl_copy(a->lane, sizeof a->lane, wf);
            mvl_copy(a->kind, sizeof a->kind, "design");
        } else {
            mvl_read_meta(dir, id, a->description, sizeof a->description);
            mvl_classify_description(a->description, a->lane, sizeof a->lane,
                                     a->kind, sizeof a->kind);
        }
        mvl_sanitize(a->description);
        if (!mvl_path_of(path, sizeof path, dir, "/", files.entries[i].name,
                         "")) {
            mvl_err(err, err_cap, dir, i,
                    "mvl_overflow: transcript path longer than MVL_PATH_CAP");
            ok = false;
            break;
        }
        ok = mvl_scan_transcript(path, a, err, err_cap);
    }
    platform_directory_list_free(&files);
    return ok;
}

static bool mvl_scan_workflows(const char *session_dir,
                               struct mvl_agents *out, char *err,
                               size_t err_cap)
{
    struct platform_directory_list dirs = {0};
    char root[MVL_PATH_CAP];
    bool ok = true;

    if (!mvl_path_of(root, sizeof root, session_dir, "/subagents/workflows",
                     "", "")) {
        mvl_err(err, err_cap, session_dir, 0,
                "mvl_overflow: session path longer than MVL_PATH_CAP");
        return false;
    }
    if (!platform_directory_list_real_sorted(root, &dirs))
        return true;
    for (size_t i = 0; ok && i < dirs.count; i++) {
        char path[MVL_PATH_CAP];

        if (!mvl_path_of(path, sizeof path, root, "/", dirs.entries[i].name,
                         "")) {
            mvl_err(err, err_cap, root, i,
                    "mvl_overflow: workflow path longer than MVL_PATH_CAP");
            ok = false;
            break;
        }
        ok = mvl_scan_agent_dir(path, dirs.entries[i].name, out, err, err_cap);
    }
    platform_directory_list_free(&dirs);
    return ok;
}

static bool mvl_scan_orchestrator(const char *session_dir,
                                  struct mvl_agents *out, char *err,
                                  size_t err_cap)
{
    char path[MVL_PATH_CAP];
    const char *base = strrchr(session_dir, '/');
    struct mvl_agent *a = mvl_next_row(out, err, err_cap);

    if (!a)
        return false;
    mvl_copy(a->agent_id, sizeof a->agent_id, base ? base + 1 : session_dir);
    mvl_copy(a->description, sizeof a->description, "orchestrator session");
    mvl_copy(a->lane, sizeof a->lane, "orchestrator");
    mvl_copy(a->kind, sizeof a->kind, "orchestrator");
    if (!mvl_path_of(path, sizeof path, session_dir, ".jsonl", "", "")) {
        mvl_err(err, err_cap, session_dir, 0,
                "mvl_overflow: session path longer than MVL_PATH_CAP");
        return false;
    }
    return mvl_scan_transcript(path, a, err, err_cap);
}

bool mvl_scan_session(const char *session_dir, struct mvl_agents *out,
                      char *err, size_t err_cap)
{
    char subagents[MVL_PATH_CAP];

    if (!mvl_path_of(subagents, sizeof subagents, session_dir, "/subagents",
                     "", "")) {
        mvl_err(err, err_cap, session_dir, 0,
                "mvl_overflow: session path longer than MVL_PATH_CAP");
        return false;
    }
    if (!mvl_scan_agent_dir(subagents, NULL, out, err, err_cap))
        return false;
    if (!mvl_scan_workflows(session_dir, out, err, err_cap))
        return false;
    return mvl_scan_orchestrator(session_dir, out, err, err_cap);
}
