/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Decode one UNTRUSTED engine response.
 *
 * Everything this file reads came off a socket. It is not a parser so much as
 * a series of refusals with a value at the end: each field is bounded and
 * type-checked before it is believed, and the only two outcomes are a fully
 * populated reply or `false` with the output zeroed. There is no partial
 * success, because a half-decoded instruction is what a caller then acts on.
 *
 * The NUL check deserves its own note. The in-tree JSON parser is
 * length-driven and will happily copy a raw 0x00 out of a string literal, but
 * it stores strings as C strings — so the text a caller reads back is
 * TRUNCATED at that byte, with no error anywhere. A hostile vendor could use
 * that to show a reviewer one instruction and a machine another. Refusing the
 * whole body is cheap and removes the class.
 */

#include "engine/engine_wire.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "json/json.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

void engine_reply_free(struct engine_reply *r)
{
    if (!r)
        return;
    free(r->text);
    memset(r, 0, sizeof(*r));
}

/* The bound check every entry point shares. Split out so the error text
 * naming each refusal is written once. */
static bool body_is_admissible(const char *body, size_t len)
{
    if (!body || len == 0)
        LOG_FAIL("engine", "refusing an empty response body");
    if (len > ENGINE_MAX_RESPONSE_BYTES)
        LOG_FAIL("engine", "refusing a %zu-byte response: over the %u-byte cap",
                 len, (unsigned)ENGINE_MAX_RESPONSE_BYTES);
    if (memchr(body, 0, len) != NULL)
        LOG_FAIL("engine",
                 "refusing a response containing a NUL byte: it would silently "
                 "truncate the text this harness is about to act on");
    return true;
}

/* Copy a bounded string field, refusing rather than truncating. An engine
 * that returns a 400-byte finish_reason is malfunctioning or probing; either
 * way this harness does not want a quietly clipped copy of it. */
static bool copy_bounded(const struct json_value *v, char *out, size_t out_len,
                         const char *what)
{
    out[0] = '\0';
    if (!v)
        return true;              /* absent optional field */
    if (v->type == JSON_NULL)
        return true;
    if (v->type != JSON_STR)
        LOG_FAIL("engine", "refusing a non-string %s", what);
    const char *s = json_get_str(v);
    if (!s)
        return true;
    if (strlen(s) >= out_len)
        LOG_FAIL("engine", "refusing an oversized %s: %zu bytes", what,
                 strlen(s));
    memcpy(out, s, strlen(s) + 1);
    return true;
}

static bool copy_required_observable_text(const char *s, char *out,
                                          size_t out_len, const char *what)
{
    out[0] = '\0';
    if (!s || !s[0])
        LOG_FAIL("engine", "refusing Grok metadata without %s", what);
    if (strlen(s) >= out_len)
        LOG_FAIL("engine", "refusing oversized Grok %s", what);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        if (*p < 0x20u || *p > 0x7eu)
            LOG_FAIL("engine", "refusing non-printable Grok %s", what);
    memcpy(out, s, strlen(s) + 1u);
    return true;
}

static bool copy_required_observable(const struct json_value *v, char *out,
                                     size_t out_len, const char *what)
{
    if (!v || v->type != JSON_STR) {
        if (out && out_len != 0) out[0] = '\0';
        LOG_FAIL("engine", "refusing Grok metadata without %s", what);
    }
    return copy_required_observable_text(
        json_get_str(v), out, out_len, what);
}

static bool read_required_nonnegative(const struct json_value *obj,
                                      const char *key, int64_t *out)
{
    *out = 0;
    const struct json_value *v = json_get(obj, key);
    if (!v || v->type != JSON_INT || json_get_int(v) < 0)
        LOG_FAIL("engine", "refusing invalid Grok integer %s", key);
    *out = json_get_int(v);
    return true;
}

static const char *claude_pick_model(const struct json_value *models);

/* A pseudo-terminal capture is the reply plus whatever the CLI wrote to the
 * terminal around it (a leading blank line, a trailing "Finishing session"
 * status line). The reply is the one top-level JSON object; the span below
 * finds it with a string-aware brace match. After it only whitespace and the
 * known status line may follow, so a second document or a half-JSON tail is
 * refused rather than ignored. */
static bool grok_span_scan(const char *body, size_t start, size_t len,
                           size_t *end)
{
    size_t depth = 0;
    bool in_str = false, esc = false;
    for (size_t i = start; i < len; i++) {
        const char c = body[i];
        if (in_str) {
            if (esc) esc = false;
            else if (c == '\\') esc = true;
            else if (c == '"') in_str = false;
        } else if (c == '"') {
            in_str = true;
        } else if (c == '{') {
            depth++;
        } else if (c == '}' && --depth == 0) {
            *end = i + 1u;
            return true;
        }
    }
    return false;
}

static size_t grok_skip_ws(const char *b, size_t i, size_t len)
{
    while (i < len && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' ||
                       b[i] == '\n'))
        i++;
    return i;
}

/* After the reply object only whitespace and the CLI's own status line,
 * "Finishing session" with an optional ellipsis, may follow. Anything else,
 * including any JSON token (true, [1], {}, a lone }), is refused. */
static bool grok_tail_ok(const char *b, size_t i, size_t len)
{
    static const char status[] = "Finishing session";
    i = grok_skip_ws(b, i, len);
    if (i == len)
        return true;
    if (len - i < sizeof(status) - 1u ||
        memcmp(b + i, status, sizeof(status) - 1u) != 0)
        return false;
    i += sizeof(status) - 1u;
    if (len - i >= 3u && memcmp(b + i, "\xe2\x80\xa6", 3u) == 0)
        i += 3u;
    else if (len - i >= 3u && memcmp(b + i, "...", 3u) == 0)
        i += 3u;
    return grok_skip_ws(b, i, len) == len;
}

static bool grok_json_span(const char *body, size_t len, size_t *start,
                           size_t *end)
{
    size_t s = 0;
    while (s < len && (body[s] == ' ' || body[s] == '\t' ||
                       body[s] == '\r' || body[s] == '\n'))
        s++;
    if (s >= len || body[s] != '{' || !grok_span_scan(body, s, len, end))
        return false;
    if (!grok_tail_ok(body, *end, len))
        return false;
    *start = s;
    return true;
}

/* Parse the one reply object out of a capture. false leaves root freed. */
static bool grok_read_root(const char *body, size_t len,
                           struct json_value *root)
{
    size_t s = 0, e = 0;
    json_init(root);
    if (!grok_json_span(body, len, &s, &e) ||
        !json_read(root, body + s, e - s)) {
        json_free(root);
        return false;
    }
    return true;
}

bool engine_cli_error_text(const char *body, size_t len, char *out,
                           size_t out_len)
{
    if (!out || out_len == 0)
        return false;
    out[0] = '\0';
    if (!body_is_admissible(body, len))
        return false;
    struct json_value root;
    if (!grok_read_root(body, len, &root))
        return false;
    const struct json_value *type = json_get(&root, "type");
    const struct json_value *msg = json_get(&root, "message");
    if (type && type->type == JSON_STR &&
        strcmp(json_get_str(type), "error") == 0 &&
        msg && msg->type == JSON_STR && json_get_str(msg))
        (void)snprintf(out, out_len, "%s", json_get_str(msg));
    json_free(&root);
    return out[0] != '\0';
}

/* The sums of every modelUsage row. A real reply may hold several models
 * (the lead model plus a helper), so the usage object is compared with the
 * rows' total, not with one row. */
struct grok_model_sums {
    int64_t input, output, cache_read, cache_create, calls;
};

static bool grok_add(int64_t *acc, int64_t v)
{
    if (v < 0 || *acc > INT64_MAX - v)
        return false;
    *acc += v;
    return true;
}

static bool grok_sum_models(const struct json_value *models,
                            struct grok_model_sums *s)
{
    memset(s, 0, sizeof(*s));
    for (size_t i = 0; i < json_size(models); i++) {
        const struct json_value *row = json_at(models, i);
        int64_t in = 0, out = 0, cr = 0, cc = 0, calls = 0;
        if (!row || row->type != JSON_OBJ ||
            !read_required_nonnegative(row, "inputTokens", &in) ||
            !read_required_nonnegative(row, "outputTokens", &out) ||
            !read_required_nonnegative(row, "cacheReadInputTokens", &cr) ||
            !read_required_nonnegative(row, "cacheCreationInputTokens", &cc) ||
            !read_required_nonnegative(row, "modelCalls", &calls) ||
            !grok_add(&s->input, in) || !grok_add(&s->output, out) ||
            !grok_add(&s->cache_read, cr) ||
            !grok_add(&s->cache_create, cc) || !grok_add(&s->calls, calls))
            return false;
    }
    return true;
}

static bool grok_read_usage(const struct json_value *usage,
                            struct engine_cli_observation *t)
{
    return read_required_nonnegative(usage, "input_tokens",
               &t->input_tokens) &&
           read_required_nonnegative(usage, "cache_read_input_tokens",
               &t->cache_read_input_tokens) &&
           read_required_nonnegative(usage, "cache_creation_input_tokens",
               &t->cache_creation_input_tokens) &&
           read_required_nonnegative(usage, "output_tokens",
               &t->output_tokens) &&
           read_required_nonnegative(usage, "reasoning_tokens",
               &t->reasoning_tokens) &&
           read_required_nonnegative(usage, "total_tokens", &t->total_tokens);
}

/* Cache-inclusive input (total = input + output) or cache-additive (total =
 * input + output + cache read + cache creation); nothing else. */
static bool grok_total_consistent(const struct engine_cli_observation *t)
{
    int64_t uncached = t->input_tokens;
    int64_t cached = t->cache_read_input_tokens;
    if (!grok_add(&uncached, t->output_tokens) ||
        !grok_add(&cached, t->cache_creation_input_tokens))
        return false;
    int64_t additive = uncached;
    const bool additive_ok = grok_add(&additive, cached);
    return (uncached == t->total_tokens && cached <= t->input_tokens) ||
           (additive_ok && additive == t->total_tokens);
}

static bool grok_sums_match(const struct engine_cli_observation *t,
                            const struct grok_model_sums *s)
{
    return t->turns > 0 && grok_total_consistent(t) &&
           t->reasoning_tokens <= t->output_tokens &&
           s->input == t->input_tokens && s->output == t->output_tokens &&
           s->cache_read == t->cache_read_input_tokens &&
           s->cache_create == t->cache_creation_input_tokens &&
           s->calls == t->turns;
}

static bool grok_read_identity(const struct json_value *root,
                               const struct json_value *models,
                               struct engine_cli_observation *t)
{
    const char *best = claude_pick_model(models);
    return best &&
           copy_required_observable(json_get(root, "sessionId"),
               t->session_id, sizeof(t->session_id), "sessionId") &&
           copy_required_observable(json_get(root, "requestId"),
               t->request_id, sizeof(t->request_id), "requestId") &&
           copy_required_observable(json_get(root, "stopReason"),
               t->stop_reason, sizeof(t->stop_reason), "stopReason") &&
           copy_required_observable_text(best, t->resolved_model,
               sizeof(t->resolved_model), "resolved model") &&
           read_required_nonnegative(root, "num_turns", &t->turns);
}

/* The CLI's own refusal ({"type":"error","message":...}) is reported as the
 * reason, not as malformed metadata. */
static void grok_warn_if_error(const char *body, size_t len)
{
    char why[256];
    if (engine_cli_error_text(body, len, why, sizeof(why)))
        LOG_WARN("engine", "Grok CLI reported an error: %s", why);
}

static bool grok_reply_shape_ok(const struct json_value *root,
                                const struct json_value *usage,
                                const struct json_value *models)
{
    const struct json_value *text = json_get(root, "text");
    const struct json_value *incomplete =
        json_get(root, "usage_is_incomplete");
    if (root->type != JSON_OBJ || !text || text->type != JSON_STR)
        LOG_FAIL("engine", "refusing Grok JSON without observable text");
    if (incomplete &&
        (incomplete->type != JSON_BOOL || json_get_bool(incomplete)))
        LOG_FAIL("engine", "refusing incomplete Grok usage");
    if (!usage || usage->type != JSON_OBJ || !models ||
        models->type != JSON_OBJ || json_size(models) < 1u || !models->keys)
        LOG_FAIL("engine", "refusing incomplete Grok usage/model metadata");
    return true;
}

static bool cli_observation_from_grok(const char *body, size_t len,
                                      struct engine_cli_observation *out)
{
    if (!body_is_admissible(body, len))
        return false;
    struct json_value root;
    if (!grok_read_root(body, len, &root)) {
        grok_warn_if_error(body, len);
        LOG_FAIL("engine", "refusing malformed Grok CLI JSON");
    }
    struct engine_cli_observation tmp;
    memset(&tmp, 0, sizeof(tmp));
    struct grok_model_sums sums;
    const struct json_value *usage = json_get(&root, "usage");
    const struct json_value *models = json_get(&root, "modelUsage");
    bool ok = false;
    if (!grok_reply_shape_ok(&root, usage, models)) {
        grok_warn_if_error(body, len);
    } else if (grok_read_identity(&root, models, &tmp) &&
               grok_read_usage(usage, &tmp) &&
               grok_sum_models(models, &sums)) {
        ok = grok_sums_match(&tmp, &sums);
        if (!ok)
            LOG_WARN("engine", "refusing inconsistent Grok usage totals");
    }
    json_free(&root);
    if (!ok)
        return false;
    tmp.known = true;
    *out = tmp;
    return true;
}

/* The resolved model is the modelUsage key that produced the most output. */
static const char *claude_pick_model(const struct json_value *models)
{
    const char *best = NULL;
    int64_t best_out = -1;
    for (size_t i = 0; i < json_size(models); i++) {
        const struct json_value *row = json_at(models, i);
        int64_t o = 0;
        if (!row || row->type != JSON_OBJ || !models->keys ||
            !models->keys[i] ||
            !read_required_nonnegative(row, "outputTokens", &o))
            continue;
        if (o > best_out) { best_out = o; best = models->keys[i]; }
    }
    return best;
}

/* Counters plus the additive total; false on a missing, negative or
 * overflowing value. */
static bool claude_read_counters(const struct json_value *root,
                                 const struct json_value *usage,
                                 struct engine_cli_observation *t)
{
    if (!read_required_nonnegative(root, "num_turns", &t->turns) ||
        !read_required_nonnegative(usage, "input_tokens", &t->input_tokens) ||
        !read_required_nonnegative(usage, "output_tokens",
                                   &t->output_tokens) ||
        !read_required_nonnegative(usage, "cache_read_input_tokens",
                                   &t->cache_read_input_tokens) ||
        !read_required_nonnegative(usage, "cache_creation_input_tokens",
                                   &t->cache_creation_input_tokens))
        return false;
    const int64_t parts[] = { t->output_tokens, t->cache_read_input_tokens,
                              t->cache_creation_input_tokens };
    int64_t sum = t->input_tokens;
    for (size_t i = 0; i < 3; i++) {
        if (parts[i] > INT64_MAX - sum)
            return false;
        sum += parts[i];
    }
    if (t->turns < 1)
        return false;
    t->total_tokens = sum;
    return true;
}

/* total_cost_usd is optional. Only a finite, nonnegative JSON number is a
 * cost; anything else leaves the cost unknown rather than zero. */
static void claude_read_cost(const struct json_value *root,
                             struct engine_cli_observation *t)
{
    const struct json_value *c = json_get(root, "total_cost_usd");
    double v = 0.0;
    if (c && c->type == JSON_REAL)
        v = json_get_real(c);
    else if (c && c->type == JSON_INT)
        v = (double)json_get_int(c);
    else
        return;
    if (!isfinite(v) || v < 0.0)
        return;
    t->cost_usd = v;
    t->cost_known = true;
}

/* A result that is not a clean success: typed refusal, not usage to count. */
static bool claude_result_is_success(const struct json_value *root)
{
    const struct json_value *type = json_get(root, "type");
    const struct json_value *sub = json_get(root, "subtype");
    const struct json_value *err = json_get(root, "is_error");
    const struct json_value *text = json_get(root, "result");
    if (root->type != JSON_OBJ || !type || type->type != JSON_STR ||
        strcmp(json_get_str(type), "result") != 0 ||
        !sub || sub->type != JSON_STR || !err || err->type != JSON_BOOL)
        LOG_FAIL("engine", "refusing Claude JSON that is not a result");
    if (json_get_bool(err) || strcmp(json_get_str(sub), "success") != 0)
        LOG_FAIL("engine", "Claude CLI reported a failed invocation");
    if (!text || text->type != JSON_STR)
        LOG_FAIL("engine", "refusing Claude JSON without result text");
    return true;
}

/* The Claude CLI prints ONE result object. Claude reports no reasoning
 * counter, so that field stays -1 (unreported), never 0. total_tokens is the
 * additive sum (input + output + cache read + cache creation), a shape the
 * dispatcher already accepts for cache-additive accounting. */
static bool cli_observation_from_claude(const char *body, size_t len,
                                        struct engine_cli_observation *out)
{
    if (!body_is_admissible(body, len))
        return false;
    struct json_value root;
    json_init(&root);
    if (!json_read(&root, body, len)) {
        json_free(&root);
        LOG_FAIL("engine", "refusing malformed Claude CLI JSON");
    }
    struct engine_cli_observation tmp;
    memset(&tmp, 0, sizeof(tmp));
    bool ok = false;
    const struct json_value *usage = json_get(&root, "usage");
    const struct json_value *models = json_get(&root, "modelUsage");
    if (claude_result_is_success(&root)) {
        const char *best = NULL;
        if (!usage || usage->type != JSON_OBJ || !models ||
            models->type != JSON_OBJ || json_size(models) < 1u)
            LOG_WARN("engine", "refusing incomplete Claude usage/model metadata");
        else if ((best = claude_pick_model(models)) &&
                 copy_required_observable(json_get(&root, "session_id"),
                     tmp.session_id, sizeof(tmp.session_id), "session_id") &&
                 copy_required_observable_text(best, tmp.resolved_model,
                     sizeof(tmp.resolved_model), "resolved model") &&
                 claude_read_counters(&root, usage, &tmp)) {
            tmp.reasoning_tokens = -1;
            claude_read_cost(&root, &tmp);
            snprintf(tmp.stop_reason, sizeof(tmp.stop_reason), "%s", "success");
            tmp.known = true;
            ok = true;
        }
    }
    json_free(&root);
    if (!ok)
        return false;
    *out = tmp;
    return true;
}

bool engine_cli_observation_parse(const struct engine_vendor *vendor,
                                  const char *body, size_t len,
                                  struct engine_cli_observation *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!vendor)
        LOG_FAIL("engine", "refusing CLI metadata without a vendor");
    if (vendor->report_format == ENGINE_CLI_OUTPUT_PLAIN)
        return true;
    if (vendor->report_format == ENGINE_CLI_OUTPUT_CLAUDE_JSON)
        return cli_observation_from_claude(body, len, out);
    if (vendor->report_format != ENGINE_CLI_OUTPUT_GROK_JSON)
        LOG_FAIL("engine", "refusing unknown CLI output shape");
    return cli_observation_from_grok(body, len, out);
}

/* Usage is optional and stays optional. A vendor that omits it, or sends it
 * with the wrong types, leaves the operator without a cost line — which is
 * reported as unknown, not invented, and never as zero. */
static bool read_counter(const struct json_value *object,
                         const char *const *keys, size_t key_count,
                         int64_t *out)
{
    bool found = false;
    int64_t value = 0;
    for (size_t i = 0; i < key_count; i++) {
        const struct json_value *item = json_get(object, keys[i]);
        if (!item)
            continue;
        if (item->type != JSON_INT || json_get_int(item) < 0)
            return false;
        if (found && value != json_get_int(item))
            return false;
        value = json_get_int(item);
        found = true;
    }
    if (found) *out = value;
    return found;
}

enum counter_state {
    COUNTER_ABSENT,
    COUNTER_VALID,
    COUNTER_INVALID,
};

static enum counter_state read_counter_at(const struct json_value *object,
                                          const char *key, int64_t *out)
{
    const struct json_value *item = json_get(object, key);
    if (!item) return COUNTER_ABSENT;
    if (item->type != JSON_INT || json_get_int(item) < 0)
        return COUNTER_INVALID;
    *out = json_get_int(item);
    return COUNTER_VALID;
}

static enum counter_state read_detail_counter(const struct json_value *usage,
                                              const char *object_key,
                                              const char *counter_key,
                                              int64_t *out)
{
    const struct json_value *details = json_get(usage, object_key);
    if (!details) return COUNTER_ABSENT;
    if (details->type != JSON_OBJ) return COUNTER_INVALID;
    return read_counter_at(details, counter_key, out);
}

static bool read_counter_locations(const struct json_value *usage,
                                   const char *direct_key,
                                   const char *first_details,
                                   const char *second_details,
                                   const char *detail_key, int64_t *out)
{
    bool found = false;
    int64_t value = 0;
    int64_t candidate = 0;
    enum counter_state state = read_counter_at(usage, direct_key, &candidate);
    if (state == COUNTER_INVALID) return false;
    if (state == COUNTER_VALID) {
        value = candidate;
        found = true;
    }

    const char *locations[] = { first_details, second_details };
    for (size_t i = 0; i < 2 && locations[i]; i++) {
        state = read_detail_counter(usage, locations[i], detail_key,
                                    &candidate);
        if (state == COUNTER_INVALID) return false;
        if (state == COUNTER_VALID) {
            if (found && candidate != value) return false;
            value = candidate;
            found = true;
        }
    }
    if (found) *out = value;
    return found;
}

static void read_usage(const struct json_value *root, struct engine_usage *u)
{
    memset(u, 0, sizeof(*u));
    const struct json_value *usage = json_get(root, "usage");
    if (!usage || usage->type != JSON_OBJ)
        return;

    static const char *const prompt[] = { "prompt_tokens", "input_tokens" };
    static const char *const completion[] = { "completion_tokens", "output_tokens" };
    static const char *const total[] = { "total_tokens" };
    static const char *const cache_create[] = { "cache_creation_input_tokens" };
    u->prompt_tokens_known = read_counter(usage,prompt,2,&u->prompt_tokens);
    u->completion_tokens_known = read_counter(usage,completion,2,&u->completion_tokens);
    u->total_tokens_known = read_counter(usage,total,1,&u->total_tokens);
    u->cache_read_input_tokens_known = read_counter_locations(
        usage,"cache_read_input_tokens","prompt_tokens_details",
        "input_tokens_details","cached_tokens",&u->cache_read_input_tokens);
    u->cache_creation_input_tokens_known =
        read_counter(usage,cache_create,1,&u->cache_creation_input_tokens);
    u->reasoning_tokens_known = read_counter_locations(
        usage,"reasoning_tokens","completion_tokens_details",
        "output_tokens_details","reasoning_tokens",&u->reasoning_tokens);
    u->tokens_known = u->prompt_tokens_known && u->completion_tokens_known &&
                      u->total_tokens_known;

    /* Few vendors report money. When one does, it is reported verbatim; when
     * none does, the operator is told the cost is unknown rather than free. */
    static const char *const k_cost[] = { "cost", "total_cost", "cost_usd" };
    for (size_t i = 0; i < sizeof(k_cost) / sizeof(k_cost[0]); i++) {
        const struct json_value *c = json_get(usage, k_cost[i]);
        if (!c)
            continue;
        if (c->type == JSON_REAL)
            u->cost_usd = json_get_real(c);
        else if (c->type == JSON_INT)
            u->cost_usd = (double)json_get_int(c);
        else
            continue;
        if (u->cost_usd >= 0.0)
            u->cost_known = true;
    }
}

/* Pull choices[0].message.content out of an already-parsed root. Every step
 * is a refusal point; none of them tolerates a wrong type. */
static bool read_text(const struct json_value *root, struct engine_reply *out)
{
    const struct json_value *choices = json_get(root, "choices");
    if (!choices || choices->type != JSON_ARR)
        LOG_FAIL("engine", "refusing a response with no `choices` array");
    if (json_size(choices) == 0)
        LOG_FAIL("engine", "refusing a response with zero choices");
    if (json_size(choices) > ENGINE_MAX_CHOICES)
        LOG_FAIL("engine", "refusing a response with %zu choices: over the cap",
                 json_size(choices));

    const struct json_value *choice = json_at(choices, 0);
    if (!choice || choice->type != JSON_OBJ)
        LOG_FAIL("engine", "refusing a choice that is not an object");

    const struct json_value *msg = json_get(choice, "message");
    if (!msg || msg->type != JSON_OBJ)
        LOG_FAIL("engine", "refusing a choice with no `message` object");

    const struct json_value *content = json_get(msg, "content");
    if (!content || content->type != JSON_STR)
        LOG_FAIL("engine", "refusing a message whose `content` is not a string");

    const char *text = json_get_str(content);
    if (!text)
        LOG_FAIL("engine", "refusing a message with unreadable content");
    const size_t n = strlen(text);
    if (n == 0) {
        /* An empty `content` has two very different causes.
         *
         * A REASONING model writes its chain of thought into a sibling
         * field (`reasoning_content` at Z.ai, `reasoning` elsewhere) and
         * only then writes the answer. Give it a small max_tokens and the
         * whole budget goes to the thought: content is "", finish_reason is
         * "length", and the leg is working perfectly. Reporting that as an
         * empty message points an operator at the vendor when the answer is
         * the token budget, so it is named. It is still a refusal — there is
         * no answer to act on — but a refusal with the repair in it. */
        const struct json_value *fr = json_get(choice, "finish_reason");
        const char *fs = (fr && fr->type == JSON_STR) ? json_get_str(fr) : NULL;
        const struct json_value *rc = json_get(msg, "reasoning_content");
        if (!rc)
            rc = json_get(msg, "reasoning");
        if (rc && rc->type == JSON_STR && json_get_str(rc)
            && json_get_str(rc)[0])
            LOG_FAIL("engine",
                     "refusing an empty assistant message: this model wrote "
                     "%zu bytes of reasoning and no answer (finish_reason=%s) "
                     "— raise the output-token budget",
                     strlen(json_get_str(rc)), fs ? fs : "absent");
        LOG_FAIL("engine", "refusing an empty assistant message");
    }
    if (n > ENGINE_MAX_TEXT_BYTES)
        LOG_FAIL("engine", "refusing %zu bytes of assistant text: over the cap",
                 n);

    if (!copy_bounded(json_get(choice, "finish_reason"), out->finish_reason,
                      sizeof(out->finish_reason), "finish_reason"))
        return false;

    out->text = zcl_malloc(n + 1, "engine_reply_text");
    if (!out->text)
        LOG_FAIL("engine", "cannot allocate %zu bytes of reply text", n + 1);
    memcpy(out->text, text, n + 1);
    out->text_len = n;
    return true;
}

size_t engine_response_excerpt(const char *body, size_t len,
                               char *out, size_t cap)
{
    if (!out || cap == 0)
        return 0;
    out[0] = '\0';
    if (!body || len == 0)
        return 0;
    /* Room for the three-dot marker when the body is longer than the room. */
    const size_t room = cap - 1u;
    size_t n = 0;
    bool last_was_space = true;   /* true so a leading run is dropped */
    size_t consumed = 0;
    for (; consumed < len && n < room; consumed++) {
        unsigned char c = (unsigned char)body[consumed];
        const bool printable = (c >= 0x20u && c <= 0x7eu);
        if (!printable || c == ' ') {
            if (last_was_space)
                continue;
            out[n++] = ' ';
            last_was_space = true;
            continue;
        }
        out[n++] = (char)c;
        last_was_space = false;
    }
    while (n > 0 && out[n - 1] == ' ')
        n--;
    out[n] = '\0';
    if (consumed < len && n + 3u < cap) {
        out[n++] = '.'; out[n++] = '.'; out[n++] = '.';
        out[n] = '\0';
    }
    return n;
}

/* Say what came back when a body is refused.
 *
 * A refusal names the RULE that fired ("no `choices` array") plus an excerpt
 * of the document, e.g. a Z.ai coding-plan key against the general-plan
 * endpoint answers HTTP 200 with neither `choices` nor `error`. */
static void log_refused_body(const struct engine_vendor *vendor,
                             const char *body, size_t len, const char *why)
{
    char excerpt[ENGINE_RESPONSE_EXCERPT_BYTES + 4u];
    (void)engine_response_excerpt(body, len, excerpt, sizeof(excerpt));
    LOG_WARN("engine",
             "%s refused a %zu-byte body (%s); first %u bytes: %s",
             vendor && vendor->id ? vendor->id : "?", len, why,
             (unsigned)ENGINE_RESPONSE_EXCERPT_BYTES,
             excerpt[0] ? excerpt : "(nothing printable)");
}

bool engine_response_parse(const struct engine_vendor *vendor,
                           const char *body, size_t len,
                           struct engine_reply *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!vendor)
        LOG_FAIL("engine", "refusing a response with no vendor to attribute it to");
    if (!body_is_admissible(body, len))
        return false;

    struct json_value root;
    json_init(&root);
    if (!json_read(&root, body, len)) {
        json_free(&root);
        log_refused_body(vendor, body, len, "not well-formed JSON");
        LOG_FAIL("engine",
                 "refusing a response that is not well-formed JSON (truncated, "
                 "over-nested, or not JSON at all)");
    }
    bool ok = false;
    if (root.type != JSON_OBJ) {
        LOG_WARN("engine", "refusing a response whose root is not an object");
    } else if (copy_bounded(json_get(&root, "model"), out->model,
                            sizeof(out->model), "model name")
               && read_text(&root, out)) {
        read_usage(&root, &out->usage);
        ok = true;
    }
    json_free(&root);
    if (!ok) {
        engine_reply_free(out);
        log_refused_body(vendor, body, len, "no usable assistant message");
    }
    return ok;
}

static bool engine_response_error_object(const struct json_value *err,
                                         char *out, size_t out_len)
{
    const struct json_value *m = json_get(err, "message");
    const struct json_value *c = json_get(err, "code");
    const char *ms = (m && m->type == JSON_STR) ? json_get_str(m) : NULL;
    const char *cs = (c && c->type == JSON_STR) ? json_get_str(c) : NULL;
    if (ms || cs) {
        (void)snprintf(out, out_len, "%s%s%s", cs ? cs : "",
                       (cs && ms) ? ": " : "", ms ? ms : "");
        return out[0] != '\0';
    }
    return false;
}

bool engine_response_error_text(const char *body, size_t len,
                                char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return false;
    out[0] = '\0';
    if (!body_is_admissible(body, len))
        return false;

    struct json_value root;
    json_init(&root);
    if (!json_read(&root, body, len)) {
        json_free(&root);
        return false;
    }
    bool found = false;
    const struct json_value *err = json_get(&root, "error");
    if (err && err->type == JSON_STR && json_get_str(err)) {
        (void)snprintf(out, out_len, "%s", json_get_str(err));
        found = out[0] != '\0';
    } else if (err && err->type == JSON_OBJ) {
        found = engine_response_error_object(err, out, out_len);
    }
    json_free(&root);
    return found;
}

/* Grok's reply may sit inside PTY chatter; Claude's is the whole body. */
static bool cli_reply_root(const struct engine_vendor *vendor,
                           const char *body, size_t len,
                           struct json_value *root)
{
    if (vendor->report_format == ENGINE_CLI_OUTPUT_GROK_JSON)
        return grok_read_root(body, len, root);
    json_init(root);
    if (json_read(root, body, len))
        return true;
    json_free(root);
    return false;
}

bool engine_cli_reply_text(const struct engine_vendor *vendor,
                           const char *body, size_t len,
                           struct engine_reply *out)
{
    if (!out || !vendor || out->text ||
        (vendor->report_format != ENGINE_CLI_OUTPUT_CLAUDE_JSON &&
         vendor->report_format != ENGINE_CLI_OUTPUT_GROK_JSON))
        return false;

    struct engine_cli_observation observation;
    if (!engine_cli_observation_parse(vendor, body, len, &observation))
        return false;

    struct json_value root;
    if (!cli_reply_root(vendor, body, len, &root))
        LOG_FAIL("engine", "refusing malformed CLI reply text");
    const char *key = vendor->report_format == ENGINE_CLI_OUTPUT_CLAUDE_JSON
                          ? "result" : "text";
    const struct json_value *value = json_get(&root, key);
    const char *text = value && value->type == JSON_STR
                           ? json_get_str(value) : NULL;
    if (!text) {
        json_free(&root);
        LOG_FAIL("engine", "refusing CLI reply without string %s", key);
    }
    const size_t text_len = strlen(text);
    if (text_len > ENGINE_MAX_TEXT_BYTES) {
        json_free(&root);
        LOG_FAIL("engine", "refusing %zu bytes of CLI reply text: over the cap",
                 text_len);
    }
    char *copy = zcl_malloc(text_len + 1u, "engine_cli_reply_text");
    if (!copy) {
        json_free(&root);
        LOG_FAIL("engine", "cannot allocate %zu bytes of CLI reply text",
                 text_len + 1u);
    }
    memcpy(copy, text, text_len + 1u);
    json_free(&root);
    out->text = copy;
    out->text_len = text_len;
    return true;
}
