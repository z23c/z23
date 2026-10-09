/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The engine registry — the one table of vendors this tree can dispatch to.
 *
 * Adding a vendor is a row here. Nothing in the dispatch path (request
 * building, response decoding, patch extraction, verdict) branches on a
 * vendor id, so a third engine costs one row and, only if it genuinely speaks
 * a different request document, a wire dialect. Most do not: `grok` and `glm`
 * below differ by a URL, a model name, and an environment variable.
 *
 * `url` is the COMPLETE endpoint, not a base to which a path is appended.
 * That is a deliberate divergence from the prior art in
 * RhettCreighton/VibePoint (src/llm/llm.c:444), which stores a base and then
 * guesses whether to add `/v1/` by sniffing whether the base already ends in
 * a version segment. The guess is right today and is one vendor away from
 * being wrong; a full URL in a table cannot be wrong.
 *
 * No key material appears here. A row names the ENVIRONMENT VARIABLE and the
 * $HOME-relative file where an operator keeps a key; the key itself is read
 * at run time by engine/engine_secret.h and never crosses this module.
 */

#include "engine/engine.h"

#include <stdlib.h>
#include <string.h>

/* ── CLI argument templates ───────────────────────────────────────────────
 * argv[0] is the vendor's `program` and is not repeated here. See
 * engine/engine.h for the placeholder vocabulary. */

/* Reads its prompt from a file and has a turn cap of its own.
 * Keep the supplied context inline: automatic prompt offloading would spend
 * a worker turn reading back a file instead of acting on that context. */
static const char *const k_grok_cli_start_argv[] = {
    "--prompt-file", ENGINE_CLI_PROMPT_TOKEN,
    "--verbatim",
    "--cwd",         ENGINE_CLI_WORKDIR_TOKEN,
    "--max-turns",   ENGINE_CLI_TURNS_TOKEN,
    "--model",       ENGINE_CLI_MODEL_TOKEN,
    "--always-approve",
    "--permission-mode", "bypassPermissions",
    "--no-plan",
    "--no-subagents",
    "--disable-web-search",
    "--tools", "Read,Grep,Glob,Bash,Edit",
    "--output-format", "json",
    NULL
};

/* Takes the prompt TEXT as an argument in headless mode, and names its
 * working directory rather than its cwd. It has no flag meaning what our
 * --turns means: --max-tool-rounds bounds TOOL CALLS, not repair attempts,
 * and mapping a repair budget of 3 onto it would cap real work at three tool
 * calls. So no {turns} slot — the CLI keeps its own default, which is the
 * honest answer to "we have nothing to say about this". */
static const char *const k_glm_cli_start_argv[] = {
    "--no-color",
    "--directory", ENGINE_CLI_WORKDIR_TOKEN,
    "--model",     ENGINE_CLI_MODEL_TOKEN,
    "--prompt",    ENGINE_CLI_PROMPT_TOKEN,
    NULL
};
/* Takes the prompt TEXT as an argument and has NO directory flag: it works in
 * its current directory, so the row sets cli_cwd_is_workdir and the launcher
 * starts it there; {workdir} is deliberately absent. It has no turn cap flag
 * worth mapping, so no {turns} slot. The rest is the cheapest measured shape
 * that still uses subscription login (no --bare, which ignores OAuth): an
 * empty --setting-sources= loads no user/project settings, and the
 * --settings env stops the worktree's CLAUDE.md chain, auto-memory and git
 * instructions from loading (the unit prompt carries the rules). The JSON
 * rides in one --settings= element because a slot starting with '{' is a
 * placeholder. The model gets file tools only, with no Bash: builds go
 * through the harness, which judges. */
static const char *const k_claude_cli_start_argv[] = {
    "-p",             ENGINE_CLI_PROMPT_TOKEN,
    "--model",        ENGINE_CLI_MODEL_TOKEN,
    "--output-format", "json",
    "--no-session-persistence",
    "--permission-mode", "acceptEdits",
    "--setting-sources=",
    "--settings={\"env\":{\"CLAUDE_CODE_DISABLE_CLAUDE_MDS\":\"1\","
    "\"CLAUDE_CODE_DISABLE_AUTO_MEMORY\":\"1\","
    "\"CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS\":\"1\"}}",
    "--tools", "Read,Edit,Write,Grep,Glob",
    "--system-prompt",
    "You edit C23 code in the current git worktree to complete the unit "
    "below; do not run builds.",
    NULL
};
static const char *const k_grok_cli_resume_argv[] = {
    "--resume", ENGINE_CLI_RESUME_TOKEN, NULL
};

static const struct engine_vendor k_engine_vendors[] = {
    {
        .id            = "grok",
        .display       = "xAI Grok (HTTPS API)",
        .url           = "https://api.x.ai/v1/chat/completions",
        .url_env       = "XAI_CHAT_URL",
        .default_model = "grok-4-fast",
        .key_env       = "XAI_API_KEY",
        .key_file_rel  = ".config/zclassic23/engine/xai.key",
        .program       = NULL,
        .wire          = ENGINE_WIRE_OPENAI_CHAT,
        .delivery      = ENGINE_DELIVERS_ENVELOPE,
        .costs_money   = true,
        .max_retries   = 3,
    },
    {
        /* Z.ai's GLM. Its chat surface is OpenAI-compatible, which is why it
         * shares a wire dialect with grok rather than getting its own.
         *
         * The url is the CODING-PLAN endpoint: the general
         * /api/paas/v4/chat/completions answers HTTP 200 with a body carrying
         * neither `choices` nor `error` for a coding-plan key. A general-plan
         * key points ZAI_CHAT_URL at
         * https://api.z.ai/api/paas/v4/chat/completions and changes nothing
         * else.
         *
         * glm-5.3 is the model the plan covers. */
        .id            = "glm",
        .display       = "Z.ai GLM (HTTPS API, coding plan)",
        .url           = "https://api.z.ai/api/coding/paas/v4/chat/completions",
        .url_env       = "ZAI_CHAT_URL",
        .default_model = "glm-5.3",
        .key_env       = "ZAI_API_KEY",
        .key_file_rel  = ".config/zclassic23/engine/zai.key",
        .program       = NULL,
        .wire          = ENGINE_WIRE_OPENAI_CHAT,
        .delivery      = ENGINE_DELIVERS_ENVELOPE,
        .costs_money   = true,
        .max_retries   = 3,
    },
    {
        /* A new OpenAI-compatible engine costs ONE ROW and no change
         * anywhere else: nothing in the request builder, the decoder, the
         * applier, or the verdict knows this vendor. */
        .id            = "openai",
        .display       = "OpenAI (HTTPS API)",
        .url           = "https://api.openai.com/v1/chat/completions",
        .url_env       = "OPENAI_CHAT_URL",
        .default_model = "gpt-4.1-mini",
        .key_env       = "OPENAI_API_KEY",
        .key_file_rel  = ".config/zclassic23/engine/openai.key",
        .program       = NULL,
        .wire          = ENGINE_WIRE_OPENAI_CHAT,
        .delivery      = ENGINE_DELIVERS_ENVELOPE,
        .costs_money   = true,
        .max_retries   = 3,
    },
    {
        /* The subscription-backed agent CLI is behind the same interface as
         * the API engines on purpose: a caller picks an ENGINE, not a
         * transport, and on a host with a subscription but no API key this is
         * the row that costs nothing extra.
         *
         * It edits the worktree itself, so its delivery is EDITS rather than
         * ENVELOPE. That changes only how work arrives; the verdict is
         * unchanged, because the verdict reads the worktree diff and the gate.
         *
         * max_retries is 1, not 3: the CLI retries internally, and stacking a
         * retry loop on top of one multiplies the wall clock invisibly. */
        .id            = "grok-cli",
        .display       = "xAI Grok (installed agent CLI, subscription auth)",
        .url           = NULL,
        .default_model = "grok-4.6",
        .key_env       = NULL,
        .key_file_rel  = NULL,
        .program       = "grok",
        .start_argv    = k_grok_cli_start_argv,
        .cli_reasoning_effort_flag = "--reasoning-effort",
        .resume_argv = k_grok_cli_resume_argv,
        .cli_prompt    = ENGINE_CLI_PROMPT_FILE,
        .cli_needs_tty = true,
        .report_format = ENGINE_CLI_OUTPUT_GROK_JSON,
        .supports_reasoning_effort = true,
        .wire          = ENGINE_WIRE_LOCAL_CLI,
        .delivery      = ENGINE_DELIVERS_EDITS,
        .costs_money   = true,
        .max_retries   = 1,
    },
    {
        /* The Z.ai agent CLI, subscription-authenticated (no per-call
         * credit, unlike the HTTPS rows).
         *
         * glm-5.3-flash rather than the HTTPS row's model: it is the fast
         * model the subscription covers. */
        .id            = "glm-cli",
        .display       = "Z.ai GLM (installed agent CLI, subscription auth)",
        .url           = NULL,
        .default_model = "glm-5.3-flash",
        .key_env       = NULL,
        .key_file_rel  = NULL,
        .program       = "zai",
        .is_default    = true,
        .start_argv    = k_glm_cli_start_argv,
        .cli_prompt    = ENGINE_CLI_PROMPT_ARG,
        .wire          = ENGINE_WIRE_LOCAL_CLI,
        .delivery      = ENGINE_DELIVERS_EDITS,
        .costs_money   = true,
        .max_retries   = 1,
    },
    {
        /* Anthropic's agent CLI, subscription-authenticated. Three rows, one
         * per model tier, because a caller picks an ENGINE and the model is
         * what differs. Prompt is an argument (96 KiB cap applies). The
         * usage object is decoded from its single JSON result. */
        .id            = "claude-haiku",
        .display       = "Anthropic Claude Haiku (installed agent CLI, subscription auth)",
        .url           = NULL,
        .default_model = "claude-haiku-5-5",
        .program       = "claude",
        .start_argv    = k_claude_cli_start_argv,
        .cli_prompt    = ENGINE_CLI_PROMPT_ARG,
        .cli_cwd_is_workdir = true,
        .report_format = ENGINE_CLI_OUTPUT_CLAUDE_JSON,
        .wire          = ENGINE_WIRE_LOCAL_CLI,
        .delivery      = ENGINE_DELIVERS_EDITS,
        .costs_money   = true,
        .lead          = "claude",
        .tier          = ENGINE_TIER_LIGHT,
        .max_retries   = 1,
    },
    {
        .id            = "claude-sonnet",
        .display       = "Anthropic Claude Sonnet (installed agent CLI, subscription auth)",
        .url           = NULL,
        .default_model = "claude-sonnet-5-5",
        .program       = "claude",
        .start_argv    = k_claude_cli_start_argv,
        .cli_prompt    = ENGINE_CLI_PROMPT_ARG,
        .cli_cwd_is_workdir = true,
        .report_format = ENGINE_CLI_OUTPUT_CLAUDE_JSON,
        .wire          = ENGINE_WIRE_LOCAL_CLI,
        .delivery      = ENGINE_DELIVERS_EDITS,
        .costs_money   = true,
        .lead          = "claude",
        .tier          = ENGINE_TIER_STANDARD,
        .max_retries   = 1,
    },
    {
        .id            = "claude-opus",
        .display       = "Anthropic Claude Opus (installed agent CLI, subscription auth)",
        .url           = NULL,
        .default_model = "claude-opus-5-5",
        .program       = "claude",
        .start_argv    = k_claude_cli_start_argv,
        .cli_prompt    = ENGINE_CLI_PROMPT_ARG,
        .cli_cwd_is_workdir = true,
        .report_format = ENGINE_CLI_OUTPUT_CLAUDE_JSON,
        .wire          = ENGINE_WIRE_LOCAL_CLI,
        .delivery      = ENGINE_DELIVERS_EDITS,
        .costs_money   = true,
        .lead          = "claude",
        .tier          = ENGINE_TIER_HEAVY,
        .max_retries   = 1,
    },
    {
        /* The fixture engine. It reads a canned response body from a file
         * instead of opening a socket, so the entire lifecycle — dispatch,
         * decode, apply, gate, verdict — runs on a host with no API key and
         * no money at stake. It is not a mock inside the tests: it is a real
         * row in this table that tools/engine_unit.c dispatches to through
         * the same code path as the others, minus the transport. */
        .id            = "fixture",
        .display       = "local fixture (no network)",
        .url           = NULL,
        .default_model = "fixture-1",
        .key_env       = NULL,
        .key_file_rel  = NULL,
        .program       = NULL,
        .wire          = ENGINE_WIRE_LOCAL_FIXTURE,
        .delivery      = ENGINE_DELIVERS_ENVELOPE,
        .costs_money   = false,
        .max_retries   = 0,
    },
};

static const size_t k_engine_count =
    sizeof(k_engine_vendors) / sizeof(k_engine_vendors[0]);

size_t engine_count(void)
{
    return k_engine_count;
}

const struct engine_vendor *engine_at(size_t index)
{
    if (index >= k_engine_count)
        return NULL;
    return &k_engine_vendors[index];
}

const struct engine_vendor *engine_by_id(const char *id)
{
    if (!id || !id[0])
        return NULL;
    for (size_t i = 0; i < k_engine_count; i++) {
        if (strcmp(k_engine_vendors[i].id, id) == 0)
            return &k_engine_vendors[i];
    }
    return NULL;
}

const char *const *engine_registry_resume_argv(const char *name)
{
    const struct engine_vendor *v = engine_by_id(name);
    return v ? v->resume_argv : NULL;
}

const char *engine_endpoint(const struct engine_vendor *v)
{
    if (!v)
        return NULL;
    if (v->url_env && v->url_env[0]) {
        const char *over = getenv(v->url_env);
        /* Only an https override is honoured. An operator who exports an
         * http:// endpoint has made a mistake this table will not carry out
         * for them, and silently sending a prompt in cleartext is a worse
         * outcome than ignoring the variable. */
        if (over && strncmp(over, "https://", 8) == 0 && over[8] != '\0')
            return over;
    }
    return v->url;
}

bool engine_is_fixture(const struct engine_vendor *v)
{
    return v != NULL && v->wire == ENGINE_WIRE_LOCAL_FIXTURE;
}

bool engine_needs_key(const struct engine_vendor *v)
{
    return v != NULL && v->wire == ENGINE_WIRE_OPENAI_CHAT;
}

const struct engine_vendor *engine_default(void)
{
    for (size_t i = 0; i < k_engine_count; i++)
        if (k_engine_vendors[i].is_default)
            return &k_engine_vendors[i];
    /* Unreachable while the table is well-formed, and test_engine asserts it
     * is. Returning NULL rather than picking row 0 keeps a malformed table
     * from silently electing whoever happens to be first. */
    return NULL;
}

const struct engine_vendor *engine_for_lead_tier(const char *lead,
                                                 enum engine_tier tier)
{
    if (lead == NULL || lead[0] == '\0' || tier == ENGINE_TIER_NONE)
        return NULL;
    for (size_t i = 0; i < k_engine_count; i++)
        if (k_engine_vendors[i].lead != NULL
            && strcmp(k_engine_vendors[i].lead, lead) == 0
            && k_engine_vendors[i].tier == tier)
            return &k_engine_vendors[i];
    return NULL;
}

static const char *const k_tier_names[] = {
    [ENGINE_TIER_NONE]       = "none",
    [ENGINE_TIER_LIGHT]    = "light",
    [ENGINE_TIER_STANDARD] = "standard",
    [ENGINE_TIER_HEAVY]    = "heavy",
};

bool engine_tier_from_name(const char *name, enum engine_tier *out)
{
    if (name == NULL || out == NULL)
        return false;
    for (int t = ENGINE_TIER_LIGHT; t <= ENGINE_TIER_HEAVY; t++) {
        if (strcmp(name, k_tier_names[t]) == 0) {
            *out = (enum engine_tier)t;
            return true;
        }
    }
    return false;
}

const char *engine_tier_name(enum engine_tier tier)
{
    if (tier < ENGINE_TIER_NONE || tier > ENGINE_TIER_HEAVY)
        return "none";
    return k_tier_names[tier];
}
