/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_wire — build one request, decode one UNTRUSTED response.
 *
 * The response side is the hostile surface of this whole harness. It is
 * bytes off a socket, shaped by a vendor we do not control, and it is handed
 * to a parser and then used to write files. So the decoder here is written as
 * a refusal machine: every field is bounded, every type is checked, and the
 * failure mode is always "return false with the output zeroed", never a
 * partial result and never a crash.
 *
 * Specifically refused, each with its own test in tests/harness/src/test_engine.c:
 *   - an empty body, or one over ENGINE_MAX_RESPONSE_BYTES;
 *   - a body containing a NUL byte. The in-tree JSON parser is length-driven
 *     but stores strings as C strings, so an embedded NUL silently TRUNCATES
 *     the text a caller then acts on. Truncated instructions are worse than
 *     no instructions, so the NUL is refused before parsing rather than
 *     tolerated after it;
 *   - truncated or otherwise unparseable JSON;
 *   - a root that is not an object; `choices` that is not a non-empty array;
 *     a choice that is not an object; `message`/`content` of the wrong type;
 *   - absurd lengths: more than ENGINE_MAX_CHOICES choices, or assistant text
 *     over ENGINE_MAX_TEXT_BYTES;
 *   - deep nesting, which the JSON parser bounds at its own depth cap and
 *     which this layer therefore sees as a plain parse failure.
 *
 * Optional fields are treated differently from required ones ON PURPOSE. A
 * missing or wrongly-typed `usage` block is recorded as "cost unknown" and
 * the reply still decodes: usage is a courtesy, not a contract, and refusing
 * a good completion because a vendor omitted a token count would throw away
 * real work. A missing or wrongly-typed `content` is a refusal, because that
 * is the thing the caller is about to act on.
 */

#ifndef ZCL_ENGINE_WIRE_H
#define ZCL_ENGINE_WIRE_H

#include "engine/engine.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── request ─────────────────────────────────────────────────────────── */

struct engine_call {
    const struct engine_vendor *vendor;
    const char *model;          /* NULL selects vendor->default_model */
    const char *system_prompt;  /* may be NULL */
    const char *user_prompt;    /* required, <= ENGINE_MAX_PROMPT_BYTES */
    int         max_output_tokens; /* <= 0 omits the field */
};

/* Serialize `call` into the vendor's request shape. Returns a heap buffer the
 * caller frees, with *out_len set to its length (excluding the NUL), or NULL
 * on any bound or argument failure. Nothing secret is ever placed in the
 * body: authentication is a header, built and sent by the transport. */
char *engine_request_alloc(const struct engine_call *call, size_t *out_len);

/* ── response ────────────────────────────────────────────────────────── */

struct engine_usage {
    int64_t prompt_tokens;
    int64_t completion_tokens;
    int64_t total_tokens;
    double  cost_usd;
    bool    tokens_known;
    bool    cost_known;
};

struct engine_reply {
    char   *text;                /* assistant text, heap, NUL-terminated */
    size_t  text_len;
    char    finish_reason[32];
    char    model[96];
    struct engine_usage usage;
};

#define ENGINE_CLI_SESSION_ID_MAX 64u
#define ENGINE_CLI_REQUEST_ID_MAX 96u

/* Observable fields from one structured CLI response. There is deliberately
 * no model-thought or transcript member: those bytes cannot flow into a
 * receipt through this type. `known=false` means truthful UNKNOWN. */
struct engine_cli_observation {
    bool known;
    char resolved_model[96];
    char session_id[ENGINE_CLI_SESSION_ID_MAX];
    char request_id[ENGINE_CLI_REQUEST_ID_MAX];
    char stop_reason[32];
    int64_t turns;
    int64_t input_tokens;
    int64_t cache_read_input_tokens;
    int64_t cache_creation_input_tokens;
    int64_t output_tokens;
    int64_t reasoning_tokens;
    int64_t total_tokens;
};

void engine_reply_free(struct engine_reply *r);

/* Decode one chat-completion response body. `out` is zeroed on failure. */
bool engine_response_parse(const struct engine_vendor *vendor,
                           const char *body, size_t len,
                           struct engine_reply *out);

/* Parse only the observable session projection selected by the vendor row.
 * Plain rows succeed as UNKNOWN without interpreting body. Structured rows
 * fail atomically on malformed, missing, overflowing, or inconsistent data. */
bool engine_cli_observation_parse(const struct engine_vendor *vendor,
                                  const char *body, size_t len,
                                  struct engine_cli_observation *out);

/* How much of a refused body is quoted back to the operator. Enough to see
 * the shape of the document — the top-level keys, an unexpected wrapper, a
 * proxy's HTML error page — and far too little to be a transcript. */
#define ENGINE_RESPONSE_EXCERPT_BYTES 300u

/* Copy a printable, single-line excerpt of an untrusted body into `out`,
 * NUL-terminated, and return its length.
 *
 * WHY QUOTING THE BODY IS SAFE HERE, AND ONLY HERE. Nothing secret ever
 * travels in a response: the credential is an Authorization HEADER built by
 * the transport (engine/engine_secret.h) and the request body carries no key
 * either (engine_wire_request.c). So a response body holds vendor output and
 * vendor error text, and that is exactly what an operator needs to see.
 *
 * Every byte is filtered: anything outside printable ASCII, including a
 * newline, becomes a single space, and runs of space collapse. A refusal
 * message must not be a place a vendor can plant control characters in an
 * operator's terminal, and a body that is 4MB of one line must not become
 * 4MB of log. Truncation is marked with a trailing "…" written as "...".
 *
 * Returns 0 and writes "" when `out` is NULL or `cap` is 0. */
size_t engine_response_excerpt(const char *body, size_t len,
                               char *out, size_t cap);

/* Some vendors answer a bad request with 200 and an `error` object, others
 * with 4xx and the same shape. Extract a bounded, printable description of
 * that error when one is present. Returns false when the body carries no
 * recognizable error — including when the body is garbage, because a decoder
 * for an error path must be as unwilling to invent structure as the main one. */
bool engine_response_error_text(const char *body, size_t len,
                                char *out, size_t out_len);

#endif /* ZCL_ENGINE_WIRE_H */
