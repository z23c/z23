/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_engine_claude: the Claude CLI engine rows. Registry shape, argv
 * expansion (model and prompt in, no workdir argument), the cwd contract,
 * and the bounded decoder for the CLI's single JSON result object. A failed
 * or malformed result is a typed refusal that leaves the observation
 * unreported, never a zero count. */

#include "test/test_core.h"

#include "engine/engine.h"
#include "engine/engine_wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EC_CHECK(name, expr)                                              \
    do {                                                                  \
        const bool ec_ok_ = (expr);                                       \
        if (!ec_ok_) failures++;                                          \
        printf("engine_claude: %s %s\n", ec_ok_ ? "OK  " : "FAIL", (name)); \
    } while (0)

/* A real claude 2.1.295 result, trimmed of fields the decoder ignores. */
#define OK_BODY \
    "{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false," \
    "\"num_turns\":3,\"result\":\"done\"," \
    "\"session_id\":\"63c495cb-5b9f-4e4a-8979-29ed2a67f8b1\"," \
    "\"total_cost_usd\":0.0027666," \
    "\"usage\":{\"input_tokens\":7,\"cache_creation_input_tokens\":13822," \
    "\"cache_read_input_tokens\":100,\"output_tokens\":41}," \
    "\"modelUsage\":{\"claude-haiku-5-5\":{\"inputTokens\":7," \
    "\"outputTokens\":41,\"cacheReadInputTokens\":100," \
    "\"cacheCreationInputTokens\":13822,\"costUSD\":0.0027666}}}"

static bool refused(const struct engine_vendor *v, const char *body)
{
    struct engine_cli_observation o;
    memset(&o, 0x5a, sizeof(o));
    const bool ok = engine_cli_observation_parse(v, body, strlen(body), &o);
    return !ok && !o.known && o.turns == 0 && o.input_tokens == 0;
}

/* True when some argv element equals (exact) or contains `needle`. */
static bool argv_has(const char *const *argv, size_t n, const char *needle,
                     bool exact)
{
    for (size_t k = 0; k < n; k++)
        if (exact ? strcmp(argv[k], needle) == 0
                  : strstr(argv[k], needle) != NULL)
            return true;
    return false;
}

static int case_row_argv(const struct engine_vendor *v, const char *model)
{
    int failures = 0;
    const struct engine_cli_inputs in = {
        .prompt = "PROMPT-TEXT", .workdir = "/work/dir",
        .turns = "3", .model = model,
    };
    const char *argv[ENGINE_CLI_ARGV_MAX];
    size_t n = engine_cli_argv_build(v, &in, argv, ENGINE_CLI_ARGV_MAX);
    EC_CHECK("argv carries prompt and model, never the workdir",
             n > 0 && strcmp(argv[0], "claude") == 0 &&
             argv_has(argv, n, "PROMPT-TEXT", true) &&
             argv_has(argv, n, model, true) &&
             !argv_has(argv, n, "/work/dir", false) && argv[n] == NULL);
    EC_CHECK("no Bash tool is granted", !argv_has(argv, n, "Bash", false));
    EC_CHECK("no worktree CLAUDE.md chain load",
             argv_has(argv, n, "\"CLAUDE_CODE_DISABLE_CLAUDE_MDS\":\"1\"",
                      false));
    EC_CHECK("no turn cap slot",
             !engine_cli_accepts_turns(v));
    EC_CHECK("cwd is the workdir",
             engine_cli_launch_cwd(v, &in) &&
             strcmp(engine_cli_launch_cwd(v, &in), "/work/dir") == 0);
    return failures;
}

static int case_registry(void)
{
    int failures = 0;
    const char *ids[] = { "claude-haiku", "claude-sonnet" };
    const char *models[] = { "claude-haiku-5-5", "claude-sonnet-5-5" };
    for (size_t i = 0; i < 2; i++) {
        const struct engine_vendor *v = engine_by_id(ids[i]);
        EC_CHECK("row exists", v != NULL);
        if (!v) continue;
        EC_CHECK("row is LOCAL_CLI/EDITS/CLAUDE_JSON",
                 v->wire == ENGINE_WIRE_LOCAL_CLI &&
                 v->delivery == ENGINE_DELIVERS_EDITS &&
                 v->report_format == ENGINE_CLI_OUTPUT_CLAUDE_JSON);
        EC_CHECK("default model", strcmp(v->default_model, models[i]) == 0);
        EC_CHECK("program is claude, prompt is an argument",
                 strcmp(v->program, "claude") == 0 &&
                 v->cli_prompt == ENGINE_CLI_PROMPT_ARG && !v->is_default);
        EC_CHECK("row needs no key", !engine_needs_key(v));

        failures += case_row_argv(v, models[i]);
    }
    const struct engine_cli_inputs in2 = { .workdir = "/w" };
    EC_CHECK("a row naming its dir in argv inherits cwd",
             engine_cli_launch_cwd(engine_by_id("glm-cli"), &in2) == NULL);
    return failures;
}

static int case_decoder(void)
{
    int failures = 0;
    const struct engine_vendor *v = engine_by_id("claude-haiku");
    struct engine_cli_observation o;
    EC_CHECK("success fixture parses",
             engine_cli_observation_parse(v, OK_BODY, strlen(OK_BODY), &o));
    EC_CHECK("input_tokens", o.input_tokens == 7);
    EC_CHECK("output_tokens", o.output_tokens == 41);
    EC_CHECK("cache_read", o.cache_read_input_tokens == 100);
    EC_CHECK("cache_creation", o.cache_creation_input_tokens == 13822);
    EC_CHECK("turns", o.turns == 3);
    EC_CHECK("total is the additive sum", o.total_tokens == 7 + 41 + 100 + 13822);
    EC_CHECK("reasoning stays unreported, not zero", o.reasoning_tokens == -1);
    EC_CHECK("known, model and session",
             o.known && strcmp(o.resolved_model, "claude-haiku-5-5") == 0 &&
             strcmp(o.session_id, "63c495cb-5b9f-4e4a-8979-29ed2a67f8b1") == 0);
    EC_CHECK("total_cost_usd decodes to a known cost",
             o.cost_known && o.cost_usd > 0.00276659 && o.cost_usd < 0.00276661);

    /* The cost is optional and only a finite nonnegative number counts. */
    {
        const char *fields[] = { "\"total_cost_usd\":0.0027666,", "",
                                 "\"total_cost_usd\":-0.5,",
                                 "\"total_cost_usd\":\"0.5\",",
                                 "\"total_cost_usd\":null,",
                                 "\"total_cost_usd\":0," };
        const bool known[] = { true, false, false, false, false, true };
        for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
            char body[1024];
            struct engine_cli_observation c;
            snprintf(body, sizeof(body),
                "{\"type\":\"result\",\"subtype\":\"success\","
                "\"is_error\":false,\"num_turns\":3,\"result\":\"done\","
                "\"session_id\":\"63c495cb-5b9f-4e4a-8979-29ed2a67f8b1\",%s"
                "\"usage\":{\"input_tokens\":7,"
                "\"cache_creation_input_tokens\":1,"
                "\"cache_read_input_tokens\":1,\"output_tokens\":4},"
                "\"modelUsage\":{\"claude-haiku-5-5\":{\"outputTokens\":4}}}",
                fields[i]);
            const bool parsed = engine_cli_observation_parse(
                v, body, strlen(body), &c);
            EC_CHECK("cost variant: run still decodes, cost known only when valid",
                     parsed && c.known && c.cost_known == known[i] &&
                     (known[i] || c.cost_usd == 0.0));
        }
    }

    EC_CHECK("is_error true is a failed invocation",
        refused(v, "{\"type\":\"result\",\"subtype\":\"success\","
                   "\"is_error\":true,\"num_turns\":1,\"result\":\"x\"}"));
    EC_CHECK("subtype error is a failed invocation",
        refused(v, "{\"type\":\"result\",\"subtype\":\"error_max_turns\","
                   "\"is_error\":false,\"num_turns\":1,\"result\":\"x\"}"));
    EC_CHECK("malformed json refused", refused(v, "{\"type\":\"res"));
    char cut[400];
    snprintf(cut, sizeof(cut), "%.*s", (int)strlen(OK_BODY) - 30, OK_BODY);
    EC_CHECK("truncated body refused", refused(v, cut));
    EC_CHECK("plain text refused", refused(v, "just text"));
    EC_CHECK("missing usage refused",
        refused(v, "{\"type\":\"result\",\"subtype\":\"success\","
                   "\"is_error\":false,\"num_turns\":1,\"result\":\"x\","
                   "\"session_id\":\"s\","
                   "\"modelUsage\":{\"m\":{\"outputTokens\":1}}}"));
    EC_CHECK("negative counter refused",
        refused(v, "{\"type\":\"result\",\"subtype\":\"success\","
                   "\"is_error\":false,\"num_turns\":1,\"result\":\"x\","
                   "\"session_id\":\"s\",\"usage\":{\"input_tokens\":-1,"
                   "\"output_tokens\":1,\"cache_read_input_tokens\":0,"
                   "\"cache_creation_input_tokens\":0},"
                   "\"modelUsage\":{\"m\":{\"outputTokens\":1}}}"));

    char big[600];
    char sid[300];
    memset(sid, 'a', sizeof(sid) - 1);
    sid[sizeof(sid) - 1] = '\0';
    snprintf(big, sizeof(big),
        "{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,"
        "\"num_turns\":1,\"result\":\"x\",\"session_id\":\"%s\","
        "\"usage\":{\"input_tokens\":1,\"output_tokens\":1,"
        "\"cache_read_input_tokens\":0,\"cache_creation_input_tokens\":0},"
        "\"modelUsage\":{\"m\":{\"outputTokens\":1}}}", sid);
    EC_CHECK("oversized session_id refused", refused(v, big));
    return failures;
}

static const char grok_body[] =
    "{\"text\":\"done\",\"stopReason\":\"end_turn\","
    "\"sessionId\":\"23c9be10-5084-43a4-8e1a-2735a4650981\","
    "\"requestId\":\"ddc16017-2c5f-4c34-9fa9-ce50a4ec48a0\","
    "\"usage\":{\"input_tokens\":100,"
    "\"cache_read_input_tokens\":60,"
    "\"cache_creation_input_tokens\":10,\"output_tokens\":25,"
    "\"reasoning_tokens\":7,\"total_tokens\":125},"
    "\"num_turns\":4,\"total_cost_usd\":0.125,"
    "\"modelUsage\":{\"grok-4.6-build\":{\"inputTokens\":100,"
    "\"outputTokens\":25,\"cacheReadInputTokens\":60,"
    "\"cacheCreationInputTokens\":10,\"modelCalls\":4}}}";

static int case_reply_text_success(void)
{
    int failures = 0;
    const struct engine_vendor *claude = engine_by_id("claude-haiku");
    const struct engine_vendor *grok = engine_by_id("grok-cli");
    struct engine_reply reply = {0};
    bool ok = engine_cli_reply_text(claude, OK_BODY, strlen(OK_BODY), &reply);
    EC_CHECK("Claude final result text extracts after metadata validation",
             ok && reply.text != NULL && reply.text_len == 4u && strcmp(reply.text, "done") == 0);
    engine_reply_free(&reply);

    ok = engine_cli_reply_text(grok, grok_body, sizeof(grok_body) - 1u, &reply);
    EC_CHECK("Grok top-level text extracts after metadata validation",
             ok && reply.text != NULL && reply.text_len == 4u && strcmp(reply.text, "done") == 0);
    engine_reply_free(&reply);

    return failures;
}

static int case_reply_text_refusal(void)
{
    int failures = 0;
    const struct engine_vendor *grok = engine_by_id("grok-cli");
    const struct engine_vendor *claude = engine_by_id("claude-haiku");
    struct engine_reply reply = {0};
    bool ok;
    char nonstring[sizeof(grok_body)];
    memcpy(nonstring, grok_body, sizeof(grok_body));
    char *text_value = strstr(nonstring, "\"text\":\"done\"");
    if (text_value)
        memcpy(text_value, "\"text\":7     ", 13u);
    reply = (struct engine_reply){0};
    reply.text_len = 77u;
    memcpy(reply.finish_reason, "sentinel", sizeof("sentinel"));
    ok = engine_cli_reply_text(grok, nonstring, sizeof(grok_body) - 1u, &reply);
    EC_CHECK("non-string Grok text is refused without output mutation",
             text_value && !ok && reply.text == NULL && reply.text_len == 77u &&
             strcmp(reply.finish_reason, "sentinel") == 0);

    static const char failed_claude[] =
        "{\"type\":\"result\",\"subtype\":\"success\","
        "\"is_error\":true,\"num_turns\":1,\"result\":\"x\","
        "\"session_id\":\"s\",\"usage\":{\"input_tokens\":1,"
        "\"output_tokens\":1,\"cache_read_input_tokens\":0,"
        "\"cache_creation_input_tokens\":0},"
        "\"modelUsage\":{\"m\":{\"outputTokens\":1}}}";
    ok = engine_cli_reply_text(claude, failed_claude,
                               sizeof(failed_claude) - 1u, &reply);
    EC_CHECK("failed Claude metadata is refused without output mutation",
             !ok && reply.text == NULL && reply.text_len == 77u &&
             strcmp(reply.finish_reason, "sentinel") == 0);

    return failures;
}

static int case_reply_text_empty(void)
{
    int failures = 0;
    const struct engine_vendor *claude = engine_by_id("claude-haiku");
    struct engine_reply reply = {0};
    bool ok;
    static const char empty_claude[] =
        "{\"type\":\"result\",\"subtype\":\"success\","
        "\"is_error\":false,\"num_turns\":1,\"result\":\"\","
        "\"session_id\":\"s\",\"usage\":{\"input_tokens\":1,"
        "\"output_tokens\":0,\"cache_read_input_tokens\":0,"
        "\"cache_creation_input_tokens\":0},"
        "\"modelUsage\":{\"m\":{\"outputTokens\":0}}}";
    reply = (struct engine_reply){0};
    ok = engine_cli_reply_text(claude, empty_claude,
                               sizeof(empty_claude) - 1u, &reply);
    EC_CHECK("empty validated result text remains available to trigger retry",
             ok && reply.text != NULL && reply.text_len == 0u &&
             reply.text[0] == '\0');
    engine_reply_free(&reply);

    return failures;
}

static int case_reply_text_cap(void)
{
    int failures = 0;
    const struct engine_vendor *claude = engine_by_id("claude-haiku");
    struct engine_reply reply = {0};
    bool ok;
    const char prefix[] =
        "{\"type\":\"result\",\"subtype\":\"success\","
        "\"is_error\":false,\"num_turns\":1,\"result\":\"";
    const char suffix[] =
        "\",\"session_id\":\"s\",\"usage\":{\"input_tokens\":1,"
        "\"output_tokens\":0,\"cache_read_input_tokens\":0,"
        "\"cache_creation_input_tokens\":0},"
        "\"modelUsage\":{\"m\":{\"outputTokens\":0}}}";
    const size_t prefix_len = sizeof(prefix) - 1u;
    const size_t suffix_len = sizeof(suffix) - 1u;
    const size_t cap = ENGINE_MAX_TEXT_BYTES;
    const size_t body_len = prefix_len + cap + suffix_len;
    char *body = malloc(body_len + 2u);
    if (!body) {
        EC_CHECK("reply text cap fixture allocation", false);
        return failures;
    }
    memcpy(body, prefix, prefix_len);
    memset(body + prefix_len, 'x', cap);
    memcpy(body + prefix_len + cap, suffix, suffix_len);
    body[body_len] = '\0';
    ok = engine_cli_reply_text(claude, body, body_len, &reply);
    EC_CHECK("text exactly at ENGINE_MAX_TEXT_BYTES is accepted",
             ok && reply.text != NULL && reply.text_len == cap && reply.text[0] == 'x' &&
             reply.text[cap - 1u] == 'x');
    engine_reply_free(&reply);

    reply = (struct engine_reply){0};
    reply.text_len = 77u;
    memcpy(reply.finish_reason, "sentinel", sizeof("sentinel"));
    memmove(body + prefix_len + cap + 1u, body + prefix_len + cap,
            suffix_len + 1u);
    body[prefix_len + cap] = 'x';
    ok = engine_cli_reply_text(claude, body, body_len + 1u, &reply);
    EC_CHECK("text over ENGINE_MAX_TEXT_BYTES is refused atomically",
             !ok && reply.text == NULL && reply.text_len == 77u &&
             strcmp(reply.finish_reason, "sentinel") == 0);
    free(body);
    return failures;
}


int test_engine_claude(void)
{
    int failures = 0;
    failures += case_registry();
    failures += case_decoder();
    failures += case_reply_text_success();
    failures += case_reply_text_refusal();
    failures += case_reply_text_empty();
    failures += case_reply_text_cap();
    printf("engine_claude: %d failure(s)\n", failures);
    return failures;
}
