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

static bool cli_observation_from_grok(const char *body, size_t len,
                                      struct engine_cli_observation *out)
{
    if (!body_is_admissible(body, len))
        return false;
    struct json_value root;
    json_init(&root);
    if (!json_read(&root, body, len)) {
        json_free(&root);
        LOG_FAIL("engine", "refusing malformed Grok CLI JSON");
    }

    struct engine_cli_observation tmp;
    memset(&tmp, 0, sizeof(tmp));
    bool ok = false;
    const struct json_value *usage = json_get(&root, "usage");
    const struct json_value *models = json_get(&root, "modelUsage");
    const struct json_value *incomplete =
        json_get(&root, "usage_is_incomplete");
    const struct json_value *text = json_get(&root, "text");
    if (root.type != JSON_OBJ || !text || text->type != JSON_STR) {
        LOG_WARN("engine", "refusing Grok JSON without observable text");
    } else if (incomplete &&
               (incomplete->type != JSON_BOOL || json_get_bool(incomplete))) {
        LOG_WARN("engine", "refusing incomplete Grok usage");
    } else if (!usage || usage->type != JSON_OBJ ||
               !models || models->type != JSON_OBJ ||
               json_size(models) != 1u || !models->keys ||
               !models->keys[0] || !models->keys[0][0]) {
        LOG_WARN("engine", "refusing incomplete Grok usage/model metadata");
    } else {
        const struct json_value *model_row = json_at(models, 0u);
        int64_t model_input = 0, model_output = 0;
        int64_t model_cache_read = 0, model_cache_create = 0;
        int64_t model_calls = 0;
        if (model_row && model_row->type == JSON_OBJ &&
            copy_required_observable(json_get(&root, "sessionId"),
                tmp.session_id, sizeof(tmp.session_id), "sessionId") &&
            copy_required_observable(json_get(&root, "requestId"),
                tmp.request_id, sizeof(tmp.request_id), "requestId") &&
            copy_required_observable(json_get(&root, "stopReason"),
                tmp.stop_reason, sizeof(tmp.stop_reason), "stopReason") &&
            copy_required_observable_text(models->keys[0],
                tmp.resolved_model, sizeof(tmp.resolved_model),
                "resolved model") &&
            read_required_nonnegative(&root, "num_turns", &tmp.turns) &&
            read_required_nonnegative(usage, "input_tokens",
                &tmp.input_tokens) &&
            read_required_nonnegative(usage, "cache_read_input_tokens",
                &tmp.cache_read_input_tokens) &&
            read_required_nonnegative(usage, "cache_creation_input_tokens",
                &tmp.cache_creation_input_tokens) &&
            read_required_nonnegative(usage, "output_tokens",
                &tmp.output_tokens) &&
            read_required_nonnegative(usage, "reasoning_tokens",
                &tmp.reasoning_tokens) &&
            read_required_nonnegative(usage, "total_tokens",
                &tmp.total_tokens) &&
            read_required_nonnegative(model_row, "inputTokens",
                &model_input) &&
            read_required_nonnegative(model_row, "outputTokens",
                &model_output) &&
            read_required_nonnegative(model_row, "cacheReadInputTokens",
                &model_cache_read) &&
            read_required_nonnegative(model_row, "cacheCreationInputTokens",
                &model_cache_create) &&
            read_required_nonnegative(model_row, "modelCalls",
                &model_calls)) {
            const bool base_add_ok =
                tmp.input_tokens <= INT64_MAX - tmp.output_tokens &&
                tmp.cache_read_input_tokens <=
                    INT64_MAX - tmp.cache_creation_input_tokens;
            const int64_t uncached_total = base_add_ok
                ? tmp.input_tokens + tmp.output_tokens : -1;
            const int64_t cached = base_add_ok
                ? tmp.cache_read_input_tokens +
                  tmp.cache_creation_input_tokens : -1;
            const bool cache_inclusive = base_add_ok &&
                uncached_total == tmp.total_tokens &&
                cached <= tmp.input_tokens;
            const bool additive_ok = base_add_ok && cached >= 0 &&
                uncached_total <= INT64_MAX - cached;
            const bool cache_additive = additive_ok &&
                uncached_total + cached == tmp.total_tokens;
            if (tmp.turns > 0 &&
                (cache_inclusive || cache_additive) &&
                tmp.reasoning_tokens <= tmp.output_tokens &&
                model_input == tmp.input_tokens &&
                model_output == tmp.output_tokens &&
                model_cache_read == tmp.cache_read_input_tokens &&
                model_cache_create == tmp.cache_creation_input_tokens &&
                model_calls == tmp.turns) {
                tmp.known = true;
                ok = true;
            } else {
                LOG_WARN("engine", "refusing inconsistent Grok usage totals");
            }
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
    if (vendor->cli_output == ENGINE_CLI_OUTPUT_PLAIN)
        return true;
    if (vendor->cli_output != ENGINE_CLI_OUTPUT_GROK_JSON)
        LOG_FAIL("engine", "refusing unknown CLI output shape");
    return cli_observation_from_grok(body, len, out);
}

/* Usage is optional and stays optional. A vendor that omits it, or sends it
 * with the wrong types, leaves the operator without a cost line — which is
 * reported as unknown, not invented, and never as zero. */
static void read_usage(const struct json_value *root, struct engine_usage *u)
{
    memset(u, 0, sizeof(*u));
    const struct json_value *usage = json_get(root, "usage");
    if (!usage || usage->type != JSON_OBJ)
        return;

    static const char *const k_prompt[] = { "prompt_tokens", "input_tokens" };
    static const char *const k_completion[] = { "completion_tokens",
                                                "output_tokens" };
    for (size_t i = 0; i < 2; i++) {
        const struct json_value *v = json_get(usage, k_prompt[i]);
        if (v && v->type == JSON_INT && json_get_int(v) >= 0)
            u->prompt_tokens = json_get_int(v);
        v = json_get(usage, k_completion[i]);
        if (v && v->type == JSON_INT && json_get_int(v) >= 0)
            u->completion_tokens = json_get_int(v);
    }
    const struct json_value *tot = json_get(usage, "total_tokens");
    if (tot && tot->type == JSON_INT && json_get_int(tot) >= 0)
        u->total_tokens = json_get_int(tot);
    else
        u->total_tokens = u->prompt_tokens + u->completion_tokens;
    u->tokens_known = (u->total_tokens > 0);

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
    if (n == 0)
        LOG_FAIL("engine", "refusing an empty assistant message");
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
    if (!ok)
        engine_reply_free(out);
    return ok;
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
        const struct json_value *m = json_get(err, "message");
        const struct json_value *c = json_get(err, "code");
        const char *ms = (m && m->type == JSON_STR) ? json_get_str(m) : NULL;
        const char *cs = (c && c->type == JSON_STR) ? json_get_str(c) : NULL;
        if (ms || cs) {
            (void)snprintf(out, out_len, "%s%s%s", cs ? cs : "",
                           (cs && ms) ? ": " : "", ms ? ms : "");
            found = out[0] != '\0';
        }
    }
    json_free(&root);
    return found;
}
