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

#include <string.h>

static const struct engine_vendor k_engine_vendors[] = {
    {
        .id            = "grok",
        .display       = "xAI Grok (HTTPS API)",
        .url           = "https://api.x.ai/v1/chat/completions",
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
         * shares a wire dialect with grok rather than getting its own. */
        .id            = "glm",
        .display       = "Z.ai GLM (HTTPS API)",
        .url           = "https://api.z.ai/api/paas/v4/chat/completions",
        .default_model = "glm-4.6",
        .key_env       = "ZAI_API_KEY",
        .key_file_rel  = ".config/zclassic23/engine/zai.key",
        .program       = NULL,
        .wire          = ENGINE_WIRE_OPENAI_CHAT,
        .delivery      = ENGINE_DELIVERS_ENVELOPE,
        .costs_money   = true,
        .max_retries   = 3,
    },
    {
        /* Added on 2026-08-30 to test the claim this table makes, not because
         * the tree needs a third API vendor: a new OpenAI-compatible engine
         * must cost ONE ROW and no change anywhere else. It cost one row.
         * Nothing in the request builder, the decoder, the applier, or the
         * verdict knows this vendor exists. */
        .id            = "openai",
        .display       = "OpenAI (HTTPS API)",
        .url           = "https://api.openai.com/v1/chat/completions",
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
        /* The subscription-backed agent CLI this tree already dispatches by
         * hand (tools/dev/grok-unit.sh). It is behind the same interface as
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
        .default_model = NULL,
        .key_env       = NULL,
        .key_file_rel  = NULL,
        .program       = "grok",
        .wire          = ENGINE_WIRE_LOCAL_CLI,
        .delivery      = ENGINE_DELIVERS_EDITS,
        .costs_money   = true,
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

bool engine_is_fixture(const struct engine_vendor *v)
{
    return v != NULL && v->wire == ENGINE_WIRE_LOCAL_FIXTURE;
}

bool engine_needs_key(const struct engine_vendor *v)
{
    return v != NULL && v->wire == ENGINE_WIRE_OPENAI_CHAT;
}
