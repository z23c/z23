/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: fold one muse serve turn's MSP frames into a turn outcome. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "muse_session_internal.h"

/* POSIX-only, matching muse_session.c: the fold reads the same serve pipes. */
#if !defined(_WIN32)

#include "base/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

/* --- wait-time folding ------------------------------------------------ */

/* Turn outcomes fold per-completion usage, not session-wide cumulative totals.
 * Repeated cursors in the bounded delivery window fold once. */
#define MS_CURSOR_RING 16
#define MS_CURSOR_MAX 128

struct ms_wait_state {
    struct muse_session *s;
    const char *session_id;
    const char *turn_id;
    const struct muse_session_policy *policy;
    struct muse_turn_outcome *out;
    char *line;
    char cursors[MS_CURSOR_RING][MS_CURSOR_MAX];
    unsigned cursor_at;
    bool done;
    bool counted_usage;
    bool usage_mismatch;
    uint64_t raw_input_tokens;
};

/* Returns true when this cursor already folded (duplicate delivery). New
 * cursors are recorded. Unusable cursors fold normally (never dropped). */
static bool ms_cursor_repeat(struct ms_wait_state *w, const char *cursor)
{
    if (!cursor || !cursor[0] || strlen(cursor) >= MS_CURSOR_MAX)
        return false;
    for (unsigned i = 0; i < MS_CURSOR_RING; i++) {
        if (w->cursors[i][0] &&
            strcmp(w->cursors[i], cursor) == 0)
            return true;
    }
    (void)ms_copy_str(w->cursors[w->cursor_at % MS_CURSOR_RING],
        MS_CURSOR_MAX, cursor);
    w->cursor_at++;
    return false;
}

static void ms_text_append(struct ms_wait_state *w, const char *chunk)
{
    if (!chunk || !chunk[0]) return;
    size_t have = strlen(w->out->text);
    size_t cap = w->s->max_text_bytes;
    if (have >= cap) return;
    size_t room = cap - have;
    size_t n = strlen(chunk);
    if (n >= room) n = room - 1;
    memcpy(w->out->text + have, chunk, n);
    w->out->text[have + n] = '\0';
}

static void ms_text_replace(struct ms_wait_state *w, const char *full)
{
    if (!full) return;
    size_t cap = w->s->max_text_bytes;
    size_t n = strlen(full);
    if (n >= cap) n = cap - 1;
    memcpy(w->out->text, full, n);
    w->out->text[n] = '\0';
}

/* Confine to the session workspace: absolute paths must sit beneath it,
 * relative paths are read against it and must still fit. */
static bool ms_path_confined(const char *workspace, const char *path)
{
    char absolute[MUSE_WS_MAX + 1024];
    if (path[0] == '/') {
        size_t ws = strlen(workspace);
        if (strncmp(path, workspace, ws) != 0 ||
            (path[ws] != '/' && path[ws] != '\0'))
            return false;
        size_t n = strlen(path);
        if (n >= sizeof(absolute)) return false;
        memcpy(absolute, path, n + 1);
    } else {
        int n = snprintf(absolute, sizeof(absolute), "%s/%s", workspace,
            path);
        if (n <= 0 || (size_t)n >= sizeof(absolute)) return false;
    }
    (void)absolute;
    return true;
}

/* One authorized prefix against the workspace-relative subject. A
 * directory prefix ("notes/") authorizes its whole subtree; a bare prefix
 * ("notes", "src/sum.c") authorizes the node itself and its children,
 * never a sibling that merely shares the spelling ("notes2"). */
static bool ms_prefix_covers(const char *prefix, const char *rel)
{
    if (!prefix || !prefix[0]) return false;
    while (prefix[0] == '/') prefix++;
    size_t pl = strlen(prefix);
    if (pl == 0 || strncmp(rel, prefix, pl) != 0) return false;
    return prefix[pl - 1] == '/' || rel[pl] == '/' || rel[pl] == '\0';
}

static bool ms_path_allowed(const struct muse_session_policy *policy,
    const char *workspace, const char *path)
{
    if (!policy || !path || !path[0] || !workspace || !workspace[0])
        return false;
    if (!ms_path_confined(workspace, path)) return false;
    const char *rel = path[0] == '/' ? path + strlen(workspace) +
            (path[strlen(workspace)] == '/' ? 1 : 0) : path;
    while (rel[0] == '/') rel++;
    /* Reject escapes even when a prefix would otherwise match. */
    if (strstr(rel, "..") != NULL) return false;
    for (size_t i = 0; i < policy->allow_path_count; i++) {
        if (ms_prefix_covers(policy->allow_paths[i], rel)) return true;
    }
    return false;
}

static bool ms_command_allowed(const struct muse_session_policy *policy,
    const char *command)
{
    if (!policy || !command) return false;
    for (size_t i = 0; i < policy->allow_command_count; i++) {
        if (policy->allow_commands[i] &&
            strcmp(policy->allow_commands[i], command) == 0)
            return true;
    }
    return false;
}

/* The fields one approval/request frame hands the decision. */
struct ms_approval_req {
    const struct json_value *aid;
    const struct json_value *subj;
    const struct json_value *choices;
    const struct json_value *psid;
};

/* The five fields an approval/request must carry. False with the refusal
 * recorded when the frame is malformed. */
static bool ms_approval_fields(struct muse_session *s,
    const struct json_value *doc, struct ms_approval_req *f)
{
    const struct json_value *params = json_get(doc, "params");
    const struct json_value *aid =
        params ? json_get(params, "approvalId") : NULL;
    const struct json_value *req =
        params ? json_get(params, "currentRequirementId") : NULL;
    const struct json_value *subj =
        params ? json_get(params, "subject") : NULL;
    const struct json_value *choices =
        params ? json_get(params, "availableChoices") : NULL;
    const struct json_value *psid =
        params ? json_get(params, "sessionId") : NULL;
    if (!params || !aid || aid->type != JSON_STR || !req ||
        !choices || choices->type != JSON_ARR ||
        !psid || psid->type != JSON_STR) {
        ms_fail(s, "invalidParams", false, "approval/request is malformed");
        return false;
    }
    f->aid = aid;
    f->subj = subj;
    f->choices = choices;
    f->psid = psid;
    return true;
}

/* The subject decides: a path inside the authorized scope, or a command on
 * the authorized list. Everything else is denied. */
static bool ms_approval_allows(struct ms_wait_state *w,
    const struct json_value *subj)
{
    const char *kind = subj ? json_get_str(json_get(subj, "kind")) : NULL;
    const char *path = subj ? json_get_str(json_get(subj, "path")) : NULL;
    const char *command = subj ? json_get_str(json_get(subj, "command")) : NULL;
    (void)kind;
    return (path && path[0] &&
            ms_path_allowed(w->policy, w->s->workspace, path)) ||
        (command && command[0] && ms_command_allowed(w->policy, command));
}

/* The host's own choice id for the decision we want; NULL when the host
 * never offered it. */
static const char *ms_approval_choice(const struct json_value *choices,
    const char *want)
{
    const char *choice = NULL;
    size_t n = json_size(choices);
    for (size_t i = 0; i < n && !choice; i++) {
        const struct json_value *c = json_at(choices, i);
        const char *decision =
            c ? json_get_str(json_get(c, "decision")) : NULL;
        const char *cid = c ? json_get_str(json_get(c, "choiceId")) : NULL;
        if (decision && cid && strcmp(decision, want) == 0) choice = cid;
    }
    return choice;
}

/* Copies a quoted requirement token verbatim, escapes included. */
static size_t ms_req_quoted(const char *p, char *out, size_t cap)
{
    size_t k = 0;
    if (k < cap - 1) out[k++] = *p++;
    while (*p && *p != '"' && k < cap - 2) {
        if (*p == '\\' && p[1] && k < cap - 3)
            out[k++] = *p++;
        out[k++] = *p++;
    }
    if (*p == '"' && k < cap - 1) out[k++] = *p;
    return k;
}

/* Copies a bare requirement token up to its field separator, trailing
 * blanks trimmed. */
static size_t ms_req_bare(const char *p, char *out, size_t cap)
{
    size_t k = 0;
    while (*p && *p != ',' && *p != '}' && k < cap - 1) out[k++] = *p++;
    while (k > 0 && (out[k - 1] == ' ' || out[k - 1] == '\t')) k--;
    return k;
}

/* Requirement ids can be scalars or small objects; echo the raw token. */
static bool ms_requirement_raw(const char *line, char *out, size_t cap)
{
    const char *req_at = strstr(line, "\"currentRequirementId\":");
    size_t k;
    out[0] = '\0';
    if (!req_at) return false;
    req_at += strlen("\"currentRequirementId\":");
    k = *req_at == '"' ? ms_req_quoted(req_at, out, cap)
                       : ms_req_bare(req_at, out, cap);
    out[k] = '\0';
    return out[0] != '\0';
}

/* Sends the approval/decide frame carrying the host's own choice. */
static bool ms_approval_decide(struct muse_session *s, const char *aid,
    const char *choice, const char *psid, const char *req_raw)
{
    char dc[MUSE_COMMAND_ID_MAX];
    if (!muse_session_command_id(dc)) {
        ms_fail(s, "internal", false, "command id unavailable");
        return false;
    }
    char frame[4096];
    /* choiceId/approvalId/sessionId are host-minted; lengths are bounded on
     * the receipt path by the frame the host itself produced. */
    int m = snprintf(frame, sizeof(frame),
        "{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"approval/decide\","
        "\"params\":{\"approvalId\":\"%s\",\"choiceId\":\"%s\","
        "\"commandId\":\"%s\",\"requirementId\":%s,\"sessionId\":\"%s\"}}",
        s->next_id++, aid, choice, dc, req_raw, psid);
    if (m <= 0 || (size_t)m >= sizeof(frame)) {
        ms_fail(s, "internal", false, "approval decision overflow");
        return false;
    }
    /* The ids above come from the host frame; a quote inside one would break
     * framing, so refuse rather than emit a forged field. */
    if (strchr(aid, '"') || strchr(choice, '"') || strchr(psid, '"')) {
        ms_fail(s, "invalidParams", false, "approval identity is unusable");
        return false;
    }
    return ms_send_raw(s, frame);
}

/* Receipts a server-initiated request by echoing its raw id verbatim.
 * `what` names the frame in the refusal. */
static bool ms_ack_request(struct muse_session *s, const char *line,
    const char *what)
{
    char receipt[128];
    char rawid[128];
    if (!ms_raw_id(line, rawid, sizeof(rawid))) {
        ms_fail(s, "invalidParams", false, "%s has no id", what);
        return false;
    }
    int m = snprintf(receipt, sizeof(receipt),
        "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{}}", rawid);
    return m > 0 && (size_t)m < sizeof(receipt) && ms_send_raw(s, receipt);
}

/* Answers one server-initiated approval/request frame. The receipt echoes the
 * request id verbatim; the decision travels as approval/decide. */
static bool ms_answer_approval(struct ms_wait_state *w, const char *line,
    const struct json_value *doc)
{
    struct muse_session *s = w->s;
    struct ms_approval_req f = {0};
    if (!ms_approval_fields(s, doc, &f)) return false;
    bool allow = ms_approval_allows(w, f.subj);
    const char *want = allow ? "approved" : "denied";
    const char *choice = ms_approval_choice(f.choices, want);
    /* Refuse to invent a decision the host did not offer. */
    if (!choice) {
        ms_fail(s, "policy", false, "no %s choice offered", want);
        return false;
    }
    char req_raw[1024] = {0};
    if (!ms_requirement_raw(line, req_raw, sizeof(req_raw))) {
        ms_fail(s, "invalidParams", false,
            "approval requirement id is unreadable");
        return false;
    }
    if (!ms_approval_decide(s, json_get_str(f.aid), choice,
            json_get_str(f.psid), req_raw))
        return false;
    if (!ms_ack_request(s, line, "approval request")) return false;
    if (allow) w->out->approvals_approved++;
    else w->out->approvals_denied++;
    return true;
}

static bool ms_decline_input(struct ms_wait_state *w, const char *line,
    const struct json_value *doc)
{
    struct muse_session *s = w->s;
    const struct json_value *params = json_get(doc, "params");
    const struct json_value *uid =
        params ? json_get(params, "userInputId") : NULL;
    const struct json_value *psid =
        params ? json_get(params, "sessionId") : NULL;
    if (!uid || uid->type != JSON_STR || !psid || psid->type != JSON_STR) {
        ms_fail(s, "invalidParams", false, "userInput/request is malformed");
        return false;
    }
    if (strchr(json_get_str(uid), '"') ||
        strchr(json_get_str(psid), '"')) {
        ms_fail(s, "invalidParams", false, "user-input identity is unusable");
        return false;
    }
    char dc[MUSE_COMMAND_ID_MAX];
    if (!muse_session_command_id(dc)) {
        ms_fail(s, "internal", false, "command id unavailable");
        return false;
    }
    char frame[2048];
    int m = snprintf(frame, sizeof(frame),
        "{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"userInput/cancel\","
        "\"params\":{\"commandId\":\"%s\",\"sessionId\":\"%s\","
        "\"userInputId\":\"%s\","
        "\"reason\":\"z23 worker is non-interactive\"}}",
        s->next_id++, dc, json_get_str(psid), json_get_str(uid));
    if (m <= 0 || (size_t)m >= sizeof(frame) || !ms_send_raw(s, frame))
        return false;
    if (!ms_ack_request(s, line, "user-input request")) return false;
    w->out->inputs_declined++;
    return true;
}

static uint64_t ms_u64(const struct json_value *v)
{
    if (!v) return 0;
    if (v->type == JSON_INT && json_get_int(v) > 0)
        return (uint64_t)json_get_int(v);
    return 0;
}

static uint64_t ms_usage_add(uint64_t a, uint64_t b)
{
    return b > UINT64_MAX - a ? UINT64_MAX : a + b;
}

static bool ms_budget_exceeded(const struct muse_session *s, uint64_t used)
{
    return s->max_total_tokens > 0 &&
        (s->tokens_used > s->max_total_tokens ||
         used > s->max_total_tokens - s->tokens_used);
}

/* A response to our own decide/cancel: surface only hard errors. */
static bool ms_fold_response(struct muse_session *s,
    const struct json_value *doc)
{
    const struct json_value *err = json_get(doc, "error");
    if (!err) return true;
    const struct json_value *msg = json_get(err, "message");
    ms_fail(s, "error", false, "%s",
        msg ? json_get_str(msg) : "serve command failed");
    return false;
}

/* Cached input in one usage object: cacheReadTokens, else cachedTokens. */
static uint64_t ms_usage_cached(const struct json_value *usage)
{
    const struct json_value *v = json_get(usage, "cacheReadTokens");
    if (!v)
        v = json_get(usage, "cachedTokens");
    return ms_u64(v);
}

/* billed = total less cached input, never below zero and never more
 * cached than input (a host figure outside that is clamped, not trusted). */
static void ms_usage_bill(struct muse_turn_outcome *o)
{
    if (o->cached_input_tokens > o->input_tokens)
        o->cached_input_tokens = o->input_tokens;
    o->billed_tokens = o->total_tokens > o->cached_input_tokens
        ? o->total_tokens - o->cached_input_tokens : 0;
    if (o->total_tokens == UINT64_MAX)
        o->billed_tokens = UINT64_MAX;
}

/* Reconcile raw terminal usage with counted-once events. Legacy streams
 * without normalized counters use the terminal reading as their total. */
static void ms_fold_usage_terminal(struct ms_wait_state *w,
    const struct json_value *params)
{
    const struct json_value *usage = json_get(params, "usage");
    if (!(usage && usage->type == JSON_OBJ && json_size(usage) > 0)) return;
    if (w->counted_usage) {
        /* Terminal counters are raw provider totals. They must reconcile
         * with the observed events, not replace counted-once prompt totals. */
        if (w->raw_input_tokens != ms_u64(json_get(usage, "inputTokens")) ||
            w->out->output_tokens != ms_u64(json_get(usage, "outputTokens")) ||
            w->out->cached_input_tokens != ms_usage_cached(usage)) {
            ms_fail(w->s, "usageMismatch", false,
                "terminal usage does not reconcile with observed turn usage");
            w->usage_mismatch = true;
            w->s->usage_unresolved = true;
        }
        return;
    }
    w->out->input_tokens = ms_u64(json_get(usage, "inputTokens"));
    w->out->output_tokens = ms_u64(json_get(usage, "outputTokens"));
    w->out->cached_input_tokens = ms_usage_cached(usage);
    uint64_t total = ms_u64(json_get(usage, "totalTokens"));
    if (total == 0)
        total = ms_u64(json_get(params, "totalTokens"));
    if (total == 0)
        total = w->out->input_tokens + w->out->output_tokens;
    w->out->total_tokens = total;
    ms_usage_bill(w->out);
}

/* The terminal turn record: the host's own settlement plus its usage. */
static void ms_fold_completed(struct ms_wait_state *w,
    const struct json_value *params, const char *psid)
{
    const char *tid = json_get_str(json_get(params, "turnId"));
    if (!((!tid || strcmp(tid, w->turn_id) == 0) &&
            (!psid || strcmp(psid, w->session_id) == 0)))
        return;
    const char *terminal = json_get_str(json_get(params, "terminal"));
    (void)ms_copy_str(w->out->terminal, sizeof(w->out->terminal),
        terminal && terminal[0] ? terminal : "completed");
    w->out->duration_ms = (int64_t)ms_u64(json_get(params, "durationMs"));
    if (!json_get(params, "durationMs")) w->out->duration_ms = -1;
    ms_fold_usage_terminal(w, params);
    w->done = true;
}

/* turn/unqueued for our turn: the host dropped it before it ran. */
static void ms_fold_unqueued(struct ms_wait_state *w,
    const struct json_value *params)
{
    const char *tid = json_get_str(json_get(params, "turnId"));
    if (tid && strcmp(tid, w->turn_id) == 0) {
        (void)ms_copy_str(w->out->terminal, sizeof(w->out->terminal),
            "cancelled");
        w->done = true;
    }
}

/* An idle session with no active turn. The terminal record follows on the
 * stream; the wait keeps draining briefly so the receipt still folds it. */
static void ms_fold_status(struct ms_wait_state *w,
    const struct json_value *params, const char *psid)
{
    const char *st = json_get_str(json_get(params, "status"));
    const struct json_value *active = json_get(params, "activeTurnId");
    if (st && strcmp(st, "idle") == 0 &&
        (!active || active->type == JSON_NULL) &&
        (!psid || strcmp(psid, w->session_id) == 0)) {
        if (!w->done && w->out->terminal[0] == '\0')
            (void)ms_copy_str(w->out->terminal,
                sizeof(w->out->terminal), "completed");
    }
}

/* Streaming text for our turn, appended in delivery order. */
static void ms_fold_delta(struct ms_wait_state *w,
    const struct json_value *params)
{
    const char *tid = json_get_str(json_get(params, "turnId"));
    const char *field = json_get_str(json_get(params, "field"));
    const char *delta = json_get_str(json_get(params, "delta"));
    if ((!tid || strcmp(tid, w->turn_id) == 0) && field &&
        strcmp(field, "text") == 0)
        ms_text_append(w, delta);
}

/* A completed agent message replaces the streamed text with the final one. */
static void ms_fold_item(struct ms_wait_state *w,
    const struct json_value *params)
{
    const struct json_value *item = json_get(params, "item");
    const char *tid =
        item ? json_get_str(json_get(item, "turnId")) : NULL;
    const char *knd = item ? json_get_str(json_get(item, "kind")) : NULL;
    const char *text = item ? json_get_str(json_get(item, "text")) : NULL;
    if ((!tid || strcmp(tid, w->turn_id) == 0) && knd &&
        strcmp(knd, "agentMessage") == 0)
        ms_text_replace(w, text ? text : "");
}

/* The host derives per-completion counted-once prompt/total counters.
 * Raw provider counters can use different cache conventions. */
static void ms_fold_usage_apply(struct ms_wait_state *w,
    const struct json_value *params)
{
    const struct json_value *usage = json_get(params, "usage");
    const struct json_value *prompt = json_get(params, "promptTokens");
    uint64_t raw = ms_u64(json_get(usage, "inputTokens"));
    uint64_t input = raw;
    if (prompt && prompt->type == JSON_INT) {
        input = ms_u64(prompt);
        w->counted_usage = true;
    }
    w->raw_input_tokens = ms_usage_add(w->raw_input_tokens, raw);
    w->out->input_tokens = ms_usage_add(w->out->input_tokens, input);
    w->out->output_tokens = ms_usage_add(w->out->output_tokens,
        ms_u64(json_get(usage, "outputTokens")));
    w->out->cached_input_tokens = ms_usage_add(w->out->cached_input_tokens,
        ms_usage_cached(usage));
    uint64_t total = ms_u64(json_get(params, "totalTokens"));
    if (total == 0)
        total = ms_usage_add(input, ms_u64(json_get(usage, "outputTokens")));
    w->out->total_tokens = ms_usage_add(w->out->total_tokens, total);
    ms_usage_bill(w->out);
}

/* One session/tokenUsage event. False only when the token cap trips. */
static bool ms_fold_usage(struct ms_wait_state *w,
    const struct json_value *params, const char *psid)
{
    struct muse_session *s = w->s;
    const char *tid = json_get_str(json_get(params, "turnId"));
    if (!((!tid || strcmp(tid, w->turn_id) == 0) &&
            (!psid || strcmp(psid, w->session_id) == 0)))
        return true;
    const char *cursor = json_get_str(json_get(params, "viewCursor"));
    /* Duplicate delivery: already folded, never double-count. */
    if (ms_cursor_repeat(w, cursor)) return true;
    ms_fold_usage_apply(w, params);
    /* The cap means "may consume at most N": only consumption beyond N
     * trips mid-turn; reaching exactly N completes and the next turn is
     * refused. */
    if (ms_budget_exceeded(s, w->out->billed_tokens)) {
        ms_fail(s, "tokenBudget", false, "token budget spent mid-turn");
        return false;
    }
    return true;
}

/* The notifications that only record turn state or turn text. An unknown
 * method is unrelated async traffic and is ignored. */
static void ms_fold_stream(struct ms_wait_state *w, const char *m,
    const struct json_value *params, const char *psid)
{
    if (!params) return;
    if (strcmp(m, "turn/completed") == 0) ms_fold_completed(w, params, psid);
    else if (strcmp(m, "turn/unqueued") == 0) ms_fold_unqueued(w, params);
    else if (strcmp(m, "session/statusChanged") == 0)
        ms_fold_status(w, params, psid);
    else if (strcmp(m, "item/delta") == 0) ms_fold_delta(w, params);
    else if (strcmp(m, "item/completed") == 0) ms_fold_item(w, params);
}

/* Folds one async frame. Returns false only for a fatal protocol/policy
 * failure; completion sets w->done. */
static bool ms_fold(struct ms_wait_state *w, const char *line)
{
    struct muse_session *s = w->s;
    struct json_value doc = {0};
    if (!json_read(&doc, line, strlen(line))) {
        json_free(&doc);
        ms_fail(s, "parseError", false, "serve sent unparsable JSON");
        return false;
    }
    const struct json_value *method = json_get(&doc, "method");
    const char *m = method && method->type == JSON_STR ? json_get_str(method)
                                                      : NULL;
    bool ok = true;
    if (!m) {
        ok = ms_fold_response(s, &doc);
        json_free(&doc);
        return ok;
    }
    const struct json_value *params = json_get(&doc, "params");
    const char *psid =
        params ? json_get_str(json_get(params, "sessionId")) : NULL;
    if (strcmp(m, "approval/request") == 0) {
        ok = ms_answer_approval(w, line, &doc);
    } else if (strcmp(m, "userInput/request") == 0) {
        ok = ms_decline_input(w, line, &doc);
    } else if (strcmp(m, "session/tokenUsage") == 0 && params) {
        ok = ms_fold_usage(w, params, psid);
    } else {
        ms_fold_stream(w, m, params, psid);
    }
    json_free(&doc);
    return ok;
}

/* Drains frames until the turn settles or a bound trips. 0 when the drain
 * ended on a settlement or the idle grace, -1 with the failure recorded. */
static int ms_drain(struct ms_wait_state *w, char *line, int64_t deadline)
{
    struct muse_session *s = w->s;
    int idle_grace = 0;
    for (;;) {
        int r = ms_read_line(s, line, MUSE_LINE_MAX, deadline);
        if (r != 1) {
            if (r == 0)
                ms_fail(s, "timeout", true, "turn did not complete in time");
            return -1;
        }
        if (!ms_fold(w, line)) return -1;
        if (w->done) return 0;
        /* An idle session with no terminal record yet gets a short grace so
         * the receipt still folds the turn/completed frame. */
        if (w->out->terminal[0] != '\0' && ++idle_grace > 64) return 0;
    }
}

int muse_session_wait(struct muse_session *s, const char *session_id,
    const char *turn_id, const struct muse_session_policy *policy,
    struct muse_turn_outcome *out)
{
    if (!s || !session_id || !turn_id || !out) return -1;
    memset(out, 0, sizeof(*out));
    out->text = zcl_calloc(1, s->max_text_bytes, "muse_session.text");
    if (!out->text) {
        ms_fail(s, "internal", false, "out of memory");
        return -1;
    }
    out->duration_ms = -1;
    char *line = zcl_malloc(MUSE_LINE_MAX, "muse_session.frame");
    if (!line) {
        free(out->text);
        out->text = NULL;
        ms_fail(s, "internal", false, "out of memory");
        return -1;
    }
    struct ms_wait_state w = {
        .s = s, .session_id = session_id, .turn_id = turn_id,
        .policy = policy, .out = out, .line = line, .done = false,
    };
    int64_t deadline = ms_monotonic_ms() + s->turn_timeout_ms;
    int rc = ms_drain(&w, line, deadline);
    if (w.usage_mismatch) rc = -1;
    if (rc == 0 && ms_budget_exceeded(s, out->billed_tokens)) {
        ms_fail(s, "tokenBudget", false, "token budget spent at settlement");
        rc = -1;
    }
    if (rc == 0 && out->terminal[0] == '\0') {
        /* Drain ended on grace without the terminal frame: report what the
         * host settled, not a fabricated completion. */
        ms_fail(s, "incomplete", true, "no terminal turn record folded");
        rc = -1;
    }
    s->tokens_used = ms_usage_add(s->tokens_used, out->billed_tokens);
    free(line);
    if (rc != 0) {
        free(out->text);
        out->text = NULL;
    }
    return rc;
}

int muse_session_cancel(struct muse_session *s, const char *command_id,
    const char *session_id, const char *turn_id)
{
    if (!s || !command_id || !session_id) return -1;
    struct json_value params = {0};
    json_init(&params);
    json_set_object(&params);
    bool ok = json_push_kv_str(&params, "commandId", command_id) &&
        json_push_kv_str(&params, "sessionId", session_id);
    if (ok && turn_id && turn_id[0])
        ok = json_push_kv_str(&params, "turnId", turn_id);
    size_t need = ok ? json_write(&params, NULL, 0) + 1 : 0;
    char *text = ok && need > 0 ? zcl_malloc(need, "muse_session.params") : NULL;
    if (!text) {
        json_free(&params);
        ms_fail(s, "internal", false, "out of memory");
        return -1;
    }
    (void)json_write(&params, text, need);
    json_free(&params);
    int id = s->next_id++;
    ok = ms_send(s, id, "turn/cancel", text);
    free(text);
    if (!ok) return -1;
    char *line = ms_await(s, id, ms_monotonic_ms() + s->open_timeout_ms);
    if (!line) return -1;
    struct json_value doc = {0};
    ok = ms_split(s, line, NULL, &doc);
    free(line);
    json_free(&doc);
    return ok ? 0 : -1;
}

#endif /* !_WIN32 */
