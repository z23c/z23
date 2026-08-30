/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Build the request body for one engine call.
 *
 * Deliberately boring. It composes a chat-completions document through the
 * in-tree JSON writer — which escapes for us — rather than by string
 * concatenation, because a prompt contains arbitrary source code, quotes, and
 * backslashes, and hand-built JSON is how a prompt ends up silently mangled.
 *
 * NOTHING SECRET GOES IN THE BODY. Authentication is an Authorization header
 * built by the transport from engine/engine_secret.h and never handed to this
 * file. That separation is why a receipt can safely carry the exact request
 * body that was sent.
 *
 * There is no response-schema field and there never will be. See the failure
 * catalogued as (a) in engine/engine.h: a forced schema lets a model satisfy
 * the contract on turn one and end the turn having written nothing. The
 * output contract is stated in band, in the prompt.
 */

#include "engine/engine_wire.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "json/json.h"

#include <string.h>

static bool push_message(struct json_value *arr, const char *role,
                         const char *content)
{
    struct json_value msg;
    json_init(&msg);
    json_set_object(&msg);
    bool ok = json_push_kv_str(&msg, "role", role)
              && json_push_kv_str(&msg, "content", content)
              && json_push_back(arr, &msg);
    json_free(&msg);
    return ok;
}

/* Compose the document. Split out so engine_request_alloc() stays short
 * enough to read in one screen and the ownership of `doc` stays in one
 * place. Returns false with `doc` still valid (the caller frees it). */
static bool build_doc(const struct engine_call *call, struct json_value *doc)
{
    const char *model = call->model && call->model[0]
                            ? call->model
                            : call->vendor->default_model;
    json_set_object(doc);
    if (!json_push_kv_str(doc, "model", model))
        LOG_FAIL("engine", "cannot record the model in the request");

    struct json_value msgs;
    json_init(&msgs);
    json_set_array(&msgs);
    bool ok = true;
    if (call->system_prompt && call->system_prompt[0])
        ok = push_message(&msgs, "system", call->system_prompt);
    if (ok)
        ok = push_message(&msgs, "user", call->user_prompt);
    if (ok)
        ok = json_push_kv(doc, "messages", &msgs);
    json_free(&msgs);
    if (!ok)
        LOG_FAIL("engine", "cannot assemble the message list");

    /* Streaming is off because the transport reads one bounded response and
     * closes; a streamed body would arrive as server-sent events this
     * decoder does not speak, and quietly decoding half of one is exactly the
     * class of failure this module exists to refuse. */
    if (!json_push_kv_bool(doc, "stream", false))
        LOG_FAIL("engine", "cannot record the stream flag");
    if (call->max_output_tokens > 0
        && !json_push_kv_int(doc, "max_tokens", call->max_output_tokens))
        LOG_FAIL("engine", "cannot record the output-token bound");
    return true;
}

char *engine_request_alloc(const struct engine_call *call, size_t *out_len)
{
    if (out_len)
        *out_len = 0;
    if (!call || !call->vendor || !call->user_prompt || !call->user_prompt[0])
        LOG_NULL("engine", "refusing a call with no vendor or no prompt");

    const size_t user_len = strlen(call->user_prompt);
    const size_t sys_len = call->system_prompt ? strlen(call->system_prompt) : 0;
    if (user_len > ENGINE_MAX_PROMPT_BYTES || sys_len > ENGINE_MAX_PROMPT_BYTES)
        LOG_NULL("engine",
                 "refusing a prompt over the %u-byte cap: system=%zu user=%zu",
                 (unsigned)ENGINE_MAX_PROMPT_BYTES, sys_len, user_len);

    struct json_value doc;
    json_init(&doc);
    if (!build_doc(call, &doc)) {
        json_free(&doc);
        return NULL;
    }

    const size_t need = json_write(&doc, NULL, 0);
    char *buf = zcl_malloc(need + 1, "engine_request");
    if (!buf) {
        json_free(&doc);
        LOG_NULL("engine", "cannot allocate a %zu-byte request body", need + 1);
    }
    const size_t wrote = json_write(&doc, buf, need + 1);
    json_free(&doc);
    if (wrote >= need + 1) {
        free(buf);
        LOG_NULL("engine", "request body did not fit its own sizing probe");
    }
    if (out_len)
        *out_len = wrote;
    return buf;
}
