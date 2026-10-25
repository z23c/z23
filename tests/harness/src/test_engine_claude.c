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


/* The GPT CLI rows: registry shape, the argv `codex exec` is launched with,
 * and that they are never auto-selected by lead. No usage is decoded. */
static int gpt_row_shape(const struct engine_vendor *v, const char *model)
{
    int failures = 0;
    EC_CHECK("gpt row is LOCAL_CLI/EDITS/PLAIN, costs money, retries 1",
             v->wire == ENGINE_WIRE_LOCAL_CLI &&
             v->delivery == ENGINE_DELIVERS_EDITS &&
             v->report_format == ENGINE_CLI_OUTPUT_PLAIN &&
             v->costs_money && v->max_retries == 1 && !v->is_default);
    EC_CHECK("gpt default model", strcmp(v->default_model, model) == 0);
    EC_CHECK("gpt program is codex, prompt is an argument",
             strcmp(v->program, "codex") == 0 &&
             v->cli_prompt == ENGINE_CLI_PROMPT_ARG && !engine_needs_key(v));
    return failures;
}

static int gpt_row_order(const char *const *argv, size_t n, const char *model)
{
    int failures = 0;
    EC_CHECK("gpt argv is codex exec -C workdir -m model, prompt last",
             n > 6 && strcmp(argv[0], "codex") == 0 &&
             strcmp(argv[1], "exec") == 0 && strcmp(argv[2], "-C") == 0 &&
             strcmp(argv[3], "/work/dir") == 0 && strcmp(argv[4], "-m") == 0 &&
             strcmp(argv[5], model) == 0 &&
             strcmp(argv[n - 1], "PROMPT-TEXT") == 0 &&
             strcmp(argv[n - 2], "--") == 0 && argv[n] == NULL);
    return failures;
}

static int gpt_row_policy(const char *const *argv, size_t n)
{
    int failures = 0;
    EC_CHECK("gpt argv is low effort and workspace-write",
             argv_has(argv, n, "model_reasoning_effort=\"low\"", true) &&
             argv_has(argv, n, "workspace-write", true) &&
             !argv_has(argv, n, "danger", false));
    EC_CHECK("gpt argv turns tool network off",
             argv_has(argv, n, "sandbox_workspace_write.network_access=false",
                      true));
    return failures;
}

static int gpt_row_argv(const struct engine_vendor *v, const char *model)
{
    int failures = 0;
    const struct engine_cli_inputs in = {
        .prompt = "PROMPT-TEXT", .workdir = "/work/dir",
        .turns = "3", .model = model,
    };
    const char *argv[ENGINE_CLI_ARGV_MAX];
    size_t n = engine_cli_argv_build(v, &in, argv, ENGINE_CLI_ARGV_MAX);
    failures += gpt_row_order(argv, n, model);
    failures += gpt_row_policy(argv, n);
    EC_CHECK("gpt cwd is not forced (workdir rides -C)",
             engine_cli_launch_cwd(v, &in) == NULL);
    struct engine_cli_inputs over = in;
    over.reasoning_effort = "high";
    EC_CHECK("gpt row refuses an explicit effort override",
             engine_cli_argv_build(v, &over, argv, ENGINE_CLI_ARGV_MAX) == 0);
    return failures;
}

static int case_gpt_rows(void)
{
    int failures = 0;
    const char *ids[] = { "gpt-luna", "gpt-sol" };
    const char *models[] = { "gpt-6-luna", "gpt-6.1-sol" };
    for (size_t i = 0; i < 2; i++) {
        const struct engine_vendor *v = engine_by_id(ids[i]);
        EC_CHECK("gpt row exists", v != NULL);
        if (!v) continue;
        failures += gpt_row_shape(v, models[i]);
        failures += gpt_row_argv(v, models[i]);
    }
    EC_CHECK("no gpt lead tier is auto-selected",
             engine_for_lead_tier("gpt", ENGINE_TIER_LIGHT) == NULL &&
             engine_for_lead_tier("gpt", ENGINE_TIER_STANDARD) == NULL);
    return failures;
}

/* A report kind (read_only) must not be able to edit: the Claude form grants
 * the reading tools alone and names no permission mode, and the Codex form
 * runs its sandbox read-only. An edit kind keeps the exact argv it had. */
static int case_read_only(void)
{
    int failures = 0;
    const struct engine_vendor *c = engine_by_id("claude-haiku");
    const struct engine_cli_inputs in = {
        .prompt = "PROMPT-TEXT", .workdir = "/work/dir",
        .turns = "3", .model = "claude-haiku-5-5", .read_only = true,
    };
    const char *argv[ENGINE_CLI_ARGV_MAX];
    size_t n = engine_cli_argv_build(c, &in, argv, ENGINE_CLI_ARGV_MAX);
    EC_CHECK("report argv grants only Read,Grep,Glob",
             argv_has(argv, n, "Read,Grep,Glob", true) &&
             !argv_has(argv, n, "Read,Edit,Write,Grep,Glob", true) &&
             !argv_has(argv, n, "Edit", true) &&
             !argv_has(argv, n, "Write", true));
    EC_CHECK("report argv names no acceptEdits permission mode",
             !argv_has(argv, n, "--permission-mode", true) &&
             !argv_has(argv, n, "acceptEdits", true));
    EC_CHECK("report argv is 14 elements, terminated",
             n == 14 && argv[n] == NULL);

    struct engine_cli_inputs edit = in;
    edit.read_only = false;
    n = engine_cli_argv_build(c, &edit, argv, ENGINE_CLI_ARGV_MAX);
    EC_CHECK("edit argv is unchanged: 16 elements, acceptEdits at 9",
             n == 16 && argv[n] == NULL &&
             strcmp(argv[9], "acceptEdits") == 0 &&
             strcmp(argv[12], "--tools") == 0 &&
             strcmp(argv[13], "Read,Edit,Write,Grep,Glob") == 0);

    const struct engine_vendor *g = engine_by_id("gpt-sol");
    struct engine_cli_inputs gin = {
        .prompt = "PROMPT-TEXT", .workdir = "/work/dir",
        .turns = "3", .model = "gpt-6.1-sol", .read_only = true,
    };
    n = engine_cli_argv_build(g, &gin, argv, ENGINE_CLI_ARGV_MAX);
    EC_CHECK("codex report runs its sandbox read-only",
             argv_has(argv, n, "read-only", true) &&
             !argv_has(argv, n, "workspace-write", true));
    gin.read_only = false;
    n = engine_cli_argv_build(g, &gin, argv, ENGINE_CLI_ARGV_MAX);
    EC_CHECK("codex edit keeps workspace-write",
             argv_has(argv, n, "workspace-write", true) &&
             !argv_has(argv, n, "read-only", true));

    const struct engine_vendor *glm = engine_by_id("glm-cli");
    struct engine_cli_inputs gl = {
        .prompt = "PROMPT-TEXT", .workdir = "/work/dir",
        .turns = "3", .model = "glm-5.3-flash", .read_only = true,
    };
    n = engine_cli_argv_build(glm, &gl, argv, ENGINE_CLI_ARGV_MAX);
    EC_CHECK("a row with no read-only form keeps its own argv",
             n > 0 && argv_has(argv, n, "--directory", true));
    return failures;
}

/* A real grok 4.7 capture through the pseudo-terminal the row requires:
 * CRLF line ends, extra fields (cwd, cost ticks), and the CLI's own
 * "Finishing session" status line after the object. Ids are fixed values. */
#define GROK_REAL_BODY \
    "{\r\n  \"text\": \"ok\",\r\n  \"stopReason\": \"end_turn\",\r\n" \
    "  \"sessionId\": \"00000000-0000-4000-8000-000000000001\",\r\n" \
    "  \"requestId\": \"00000000-0000-4000-8000-000000000002\",\r\n" \
    "  \"cwd\": \"/work/dir\",\r\n  \"usage\": {\r\n" \
    "    \"input_tokens\": 9179,\r\n    \"cache_read_input_tokens\": 1664,\r\n" \
    "    \"cache_creation_input_tokens\": 0,\r\n    \"output_tokens\": 24,\r\n" \
    "    \"reasoning_tokens\": 23,\r\n    \"total_tokens\": 10867\r\n  },\r\n" \
    "  \"num_turns\": 1,\r\n  \"total_cost_usd\": 0.00657356,\r\n" \
    "  \"total_cost_usd_ticks\": 65735600,\r\n  \"modelUsage\": {\r\n" \
    "    \"grok-4.7-build\": {\r\n      \"inputTokens\": 9179,\r\n" \
    "      \"outputTokens\": 24,\r\n      \"cacheReadInputTokens\": 1664,\r\n" \
    "      \"cacheCreationInputTokens\": 0,\r\n      \"modelCalls\": 1,\r\n" \
    "      \"costUSD\": 0.00657356\r\n    }\r\n  }\r\n}\r\n"
#define GROK_STATUS_TAIL "Finishing session\xe2\x80\xa6\r\n"

static int case_grok_real_capture(void)
{
    int failures = 0;
    const struct engine_vendor *grok = engine_by_id("grok-cli");
    static const char real[] = GROK_REAL_BODY GROK_STATUS_TAIL;
    struct engine_cli_observation o;
    bool ok = engine_cli_observation_parse(grok, real, sizeof(real) - 1u, &o);
    EC_CHECK("real grok 4.7 PTY capture with its status line parses",
             ok && o.known && o.turns == 1 && o.input_tokens == 9179 &&
             o.output_tokens == 24 && o.total_tokens == 10867 &&
             strcmp(o.resolved_model, "grok-4.7-build") == 0);
    struct engine_reply reply = {0};
    ok = engine_cli_reply_text(grok, real, sizeof(real) - 1u, &reply);
    EC_CHECK("real grok capture yields its reply text",
             ok && reply.text && strcmp(reply.text, "ok") == 0);
    engine_reply_free(&reply);

    static const char two_docs[] = GROK_REAL_BODY "{\"x\":1}";
    static const char quoted_tail[] = GROK_REAL_BODY "\"status\"";
    EC_CHECK("a second document after the reply is still refused",
             refused(grok, two_docs));
    EC_CHECK("a quoted tail after the reply is still refused",
             refused(grok, quoted_tail));

    /* Several models: usage is the sum of the rows. */
    static const char two_models[] =
        "{\"text\":\"done\",\"stopReason\":\"end_turn\","
        "\"sessionId\":\"s\",\"requestId\":\"r\","
        "\"usage\":{\"input_tokens\":150,\"cache_read_input_tokens\":0,"
        "\"cache_creation_input_tokens\":0,\"output_tokens\":30,"
        "\"reasoning_tokens\":5,\"total_tokens\":180},\"num_turns\":3,"
        "\"modelUsage\":{\"grok-4.7-build\":{\"inputTokens\":100,"
        "\"outputTokens\":25,\"cacheReadInputTokens\":0,"
        "\"cacheCreationInputTokens\":0,\"modelCalls\":2},"
        "\"grok-4.7-fast\":{\"inputTokens\":50,\"outputTokens\":5,"
        "\"cacheReadInputTokens\":0,\"cacheCreationInputTokens\":0,"
        "\"modelCalls\":1}}}";
    ok = engine_cli_observation_parse(grok, two_models,
                                      sizeof(two_models) - 1u, &o);
    EC_CHECK("two models whose rows sum to the usage parse; most output wins",
             ok && o.known && strcmp(o.resolved_model, "grok-4.7-build") == 0);
    char off[sizeof(two_models)];
    memcpy(off, two_models, sizeof(two_models));
    char *five = strstr(off, "\"outputTokens\":5,");
    if (five) five[15] = '6';
    EC_CHECK("two models whose rows do not sum to the usage are refused",
             five && refused(grok, off));
    return failures;
}

static int case_grok_error_reply(void)
{
    int failures = 0;
    const struct engine_vendor *grok = engine_by_id("grok-cli");
    static const char err[] =
        "{\"type\":\"error\",\"message\":\"Not signed in. Run grok login.\"}"
        "\r\n";
    char why[128];
    EC_CHECK("the CLI's own error message is surfaced",
             engine_cli_error_text(err, sizeof(err) - 1u, why, sizeof(why)) &&
             strcmp(why, "Not signed in. Run grok login.") == 0);
    EC_CHECK("an error reply is not an observation", refused(grok, err));
    EC_CHECK("a good reply is not reported as an error",
             !engine_cli_error_text(GROK_REAL_BODY, strlen(GROK_REAL_BODY),
                                    why, sizeof(why)) && why[0] == '\0');
    return failures;
}

static int case_kimi_reply(const struct engine_vendor *v);

static int case_kimi_row(void)
{
    int failures = 0;
    const struct engine_vendor *v = engine_by_id("kimi-cli");
    EC_CHECK("kimi row exists", v != NULL);
    if (!v)
        return failures + 1;
    EC_CHECK("kimi row is LOCAL_CLI/EDITS/PLAIN, argument prompt, not keyed",
             v->wire == ENGINE_WIRE_LOCAL_CLI &&
             v->delivery == ENGINE_DELIVERS_EDITS &&
             v->report_format == ENGINE_CLI_OUTPUT_PLAIN &&
             v->cli_prompt == ENGINE_CLI_PROMPT_ARG &&
             strcmp(v->program, "kimi") == 0 && !engine_needs_key(v) &&
             v->cli_cwd_is_workdir && !v->is_default);
    const struct engine_cli_inputs in = {
        .prompt = "PROMPT-TEXT", .workdir = "/work/dir", .turns = "3",
        .model = "anything",
    };
    const char *argv[ENGINE_CLI_ARGV_MAX];
    size_t n = engine_cli_argv_build(v, &in, argv, ENGINE_CLI_ARGV_MAX);
    EC_CHECK("kimi argv is kimi -p PROMPT with nothing else",
             n == 3 && strcmp(argv[0], "kimi") == 0 &&
             strcmp(argv[1], "-p") == 0 &&
             strcmp(argv[2], "PROMPT-TEXT") == 0 && argv[3] == NULL);
    EC_CHECK("kimi starts in the worktree",
             engine_cli_launch_cwd(v, &in) &&
             strcmp(engine_cli_launch_cwd(v, &in), "/work/dir") == 0);

    failures += case_kimi_reply(v);
    return failures;
}

static int case_kimi_reply(const struct engine_vendor *v)
{
    int failures = 0;
    /* Real kimi 2.1.1 text reply: bullet, blank line, resume hint. */
    static const char text_reply[] =
        "\xe2\x80\xa2 ok\n\nTo resume this session: kimi -r session_x\n";
    struct engine_cli_observation o;
    memset(&o, 0x5a, sizeof(o));
    EC_CHECK("a kimi text reply is handled; usage stays UNKNOWN, not zero",
             engine_cli_observation_parse(v, text_reply,
                                          sizeof(text_reply) - 1u, &o) &&
             !o.known && !o.cost_known && o.session_id[0] == '\0');
    return failures;
}

int test_engine_claude(void)
{
    int failures = 0;
    failures += case_registry();
    failures += case_read_only();
    failures += case_gpt_rows();
    failures += case_kimi_row();
    failures += case_grok_real_capture();
    failures += case_grok_error_reply();
    failures += case_decoder();
    failures += case_reply_text_success();
    failures += case_reply_text_refusal();
    failures += case_reply_text_empty();
    failures += case_reply_text_cap();
    printf("engine_claude: %d failure(s)\n", failures);
    return failures;
}
