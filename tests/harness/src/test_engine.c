/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The engine harness under test. It proves:
 *   1. A hostile engine response (truncated JSON, absurd lengths, wrong
 *      types, deep nesting, embedded NULs) is refused with the output
 *      zeroed, never partially decoded.
 *   2. A key never reaches an artifact: the redacting writer is the only
 *      writer.
 *   3. An engine that reports success and changes nothing is a failure
 *      (engine/engine.h), even with a perfect gate reading.
 *   4. A hollow green (groups_ran = 0, or a fully cached run printing
 *      "ALL TESTS PASSED") is not evidence.
 */

#include "test/test_core.h"
#include "json/json.h"

#include "engine/engine.h"
#include "engine/engine_err.h"
#include "engine/engine_patch.h"
#include "engine/engine_prompt.h"
#include "engine/engine_receipt.h"
#include "engine/engine_rule_score.h"
#include "base/safe_alloc.h"
#include "engine/engine_secret.h"
#include "engine/engine_state.h"
#include "engine/engine_verdict.h"
#include "engine/engine_wire.h"
#include "base/hex.h"
#include "sha3/sha3.h"
#include "vcs/vcs_object.h"
#include "platform/private_file.h"
#if defined(_WIN32)
#include "platform/windows_path.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if defined(_WIN32)
#include <aclapi.h>
#include <direct.h>
#include <windows.h>
#else
#include <sys/wait.h>
#endif
#include <unistd.h>
#include "platform/file_sync.h"
#include <errno.h>
#include <signal.h>

#if !defined(_WIN32)
/* Compile the exact writer with local syscall faults, without runtime hooks. */
static int pin_fault;
static ssize_t pin_write(int fd, const void *buf, size_t n)
{
    if (pin_fault == 1) raise(SIGSTOP);
    return write(fd, buf, n);
}
static int pin_sync(int fd)
{
    if (pin_fault == 2) { errno = EIO; return -1; }
    return platform_file_sync(fd);
}
#define write pin_write
#define platform_file_sync pin_sync
#define engine_receipt_append pin_test_append
#define engine_receipt_fits pin_test_fits
#define engine_receipt_verify_chain pin_test_verify
#include "../../../engine/modules/engine/src/engine_receipt.c"
#undef engine_receipt_verify_chain
#undef engine_receipt_fits
#undef engine_receipt_append
#undef platform_file_sync
#undef write
#endif

#define EN_CHECK(name, expr) do {                    \
    printf("engine: %s... ", (name));                \
    if (expr) { printf("OK\n"); }                    \
    else { printf("FAIL\n"); failures++; }           \
} while (0)

static const char attempt_a[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char attempt_b[] =
    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
static const char *const malformed_attempts[] = {
    "", "0123",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
    "0123456789Abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "0123456789gbcdef0123456789abcdef0123456789abcdef0123456789abcdef",
};

/* A key-shaped string that is NOT a real credential. It matches the two-part
 * <32 hex>.<16 alnum> shape the scrubber knows, which is exactly the point:
 * the test must exercise the same path a real key would take. */
static const char k_planted_key[] =
    "0123456789abcdef0123456789abcdef.AbCdEfGhIjKlMnOp"; /* api-key-example-ok */

/* ── 1. the registry ─────────────────────────────────────────────────── */

static int case_registry(void)
{
    int failures = 0;
    EN_CHECK("the registry is not empty", engine_count() >= 3);
    EN_CHECK("grok resolves", engine_by_id("grok") != NULL);
    EN_CHECK("glm resolves", engine_by_id("glm") != NULL);
    EN_CHECK("an unknown id resolves to nothing",
             engine_by_id("definitely-not-an-engine") == NULL);
    EN_CHECK("an empty id resolves to nothing", engine_by_id("") == NULL);
    EN_CHECK("a null id does not crash", engine_by_id(NULL) == NULL);
    EN_CHECK("iteration past the end returns NULL",
             engine_at(engine_count()) == NULL);

    /* Both HTTPS vendors share ONE wire dialect. That is the shape claim of
     * the whole interface: a new OpenAI-compatible vendor is a row, not an
     * implementation. */
    EN_CHECK("grok and glm share a wire dialect",
             engine_by_id("grok")->wire == engine_by_id("glm")->wire);
    EN_CHECK("the fixture engine spends nothing",
             engine_is_fixture(engine_by_id("fixture"))
             && !engine_by_id("fixture")->costs_money);
    EN_CHECK("a CLI engine is never handed a key",
             !engine_needs_key(engine_by_id("grok-cli")));
    EN_CHECK("Grok's CLI row asks for a PTY",
             engine_by_id("grok-cli")->cli_needs_tty);
    EN_CHECK("a CLI that works over pipes does not inherit Grok's PTY",
             !engine_by_id("glm-cli")->cli_needs_tty);
    EN_CHECK("an HTTPS engine needs one",
             engine_needs_key(engine_by_id("glm")));

    /* The retry budget differs by engine on purpose: a CLI already retries
     * internally, and stacking a loop on one multiplies the wall clock. */
    EN_CHECK("the CLI engine has a smaller retry budget than the API one",
             engine_by_id("grok-cli")->max_retries
             < engine_by_id("grok")->max_retries);

    /* Every row must carry what its dialect needs, or the dispatcher would
     * discover it at run time with a credential already loaded. */
    for (size_t i = 0; i < engine_count(); i++) {
        const struct engine_vendor *v = engine_at(i);
        const bool consistent =
            v->id && v->display
            && (v->wire != ENGINE_WIRE_OPENAI_CHAT
                || (v->url && v->default_model && v->key_env))
            && (v->wire != ENGINE_WIRE_LOCAL_CLI || v->program);
        if (!consistent) {
            printf("engine: registry row %zu is incomplete... FAIL\n", i);
            failures++;
        }
    }
    return failures;
}

/* ── 2. the request ──────────────────────────────────────────────────── */

static int case_request(void)
{
    int failures = 0;
    const struct engine_vendor *v = engine_by_id("glm");
    struct engine_call call = {
        .vendor        = v,
        .model         = NULL,
        .system_prompt = "be brief",
        .user_prompt   = "a \"quoted\" prompt with a \\ backslash\nand a newline",
    };
    size_t len = 0;
    char *body = engine_request_alloc(&call, &len);
    EN_CHECK("a request body is produced", body != NULL && len > 0);
    if (body) {
        EN_CHECK("the default model is used when none is given",
                 strstr(body, v->default_model) != NULL);
        EN_CHECK("the prompt is JSON-escaped, not concatenated",
                 strstr(body, "\\\"quoted\\\"") != NULL
                 && strstr(body, "\\n") != NULL);
        /* The credential is a header, built by the transport. A request body
         * that could carry one is a body that could be logged with one. */
        EN_CHECK("no authorization material is in the request body",
                 strstr(body, "Bearer") == NULL
                 && strstr(body, "api_key") == NULL);
        EN_CHECK("no response schema is forced (see failure (a))",
                 strstr(body, "response_format") == NULL
                 && strstr(body, "json_schema") == NULL);
        free(body);
    }
    struct engine_vendor effort_vendor = *engine_by_id("grok");
    effort_vendor.supports_reasoning_effort = true;
    call.vendor = &effort_vendor;
    call.user_prompt = "x";
    call.reasoning_effort = "high";
    body = engine_request_alloc(&call, &len);
    EN_CHECK("an explicit supported effort reaches the HTTP request",
             body && strstr(body, "\"reasoning_effort\":\"high\"") != NULL);
    free(body);
    call.reasoning_effort = ENGINE_REASONING_EFFORT_PROVIDER_DEFAULT;
    body = engine_request_alloc(&call, &len);
    EN_CHECK("provider-default effort sends no guessed HTTP field",
             body && strstr(body, "reasoning_effort") == NULL);
    free(body);
    call.vendor = v;
    call.reasoning_effort = "high";
    EN_CHECK("an unsupported HTTP effort is refused",
             engine_request_alloc(&call, &len) == NULL);
    call.reasoning_effort = "maximum";
    EN_CHECK("an unknown HTTP effort is refused",
             engine_request_alloc(&call, &len) == NULL);
    call.reasoning_effort = NULL;
    call.user_prompt = NULL;
    EN_CHECK("a call with no prompt is refused",
             engine_request_alloc(&call, &len) == NULL);
    call.user_prompt = "x";
    call.vendor = NULL;
    EN_CHECK("a call with no vendor is refused",
             engine_request_alloc(&call, &len) == NULL);
    return failures;
}

/* ── 3. hostile responses ────────────────────────────────────────────── */

static bool refuses(const char *body, size_t len)
{
    struct engine_reply r;
    memset(&r, 0xa5, sizeof(r));   /* poison: a refusal must still zero it */
    const bool ok = engine_response_parse(engine_by_id("glm"), body, len, &r);
    if (ok) {
        engine_reply_free(&r);
        return false;
    }
    return r.text == NULL && r.text_len == 0;
}

static int case_hostile(void)
{
    int failures = 0;
    const struct engine_vendor *v = engine_by_id("glm");

    /* The control: a well-formed response decodes, so the refusals below are
     * refusals of the INPUT and not of everything. */
    {
        static const char good[] =
            "{\"model\":\"glm-4.6\",\"choices\":[{\"finish_reason\":\"stop\","
            "\"message\":{\"role\":\"assistant\",\"content\":\"hello\"}}],"
            "\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":2,"
            "\"total_tokens\":9}}";
        struct engine_reply r;
        const bool ok = engine_response_parse(v, good, sizeof(good) - 1, &r);
        EN_CHECK("a well-formed response decodes",
                 ok && r.text && strcmp(r.text, "hello") == 0);
        EN_CHECK("token usage is reported when the vendor sends it",
                 ok && r.usage.tokens_known && r.usage.prompt_tokens == 7
                 && r.usage.completion_tokens == 2);
        EN_CHECK("cost is reported as UNKNOWN, never invented as zero",
                 ok && !r.usage.cost_known);
        EN_CHECK("the finish reason survives", ok && strcmp(r.finish_reason, "stop") == 0);
        if (ok)
            engine_reply_free(&r);
    }

    {
        static const char zero[] =
            "{\"choices\":[{\"message\":{\"content\":\"ok\"}}],"
            "\"usage\":{\"prompt_tokens\":0,\"completion_tokens\":0,"
            "\"total_tokens\":0}}";
        struct engine_reply r;
        const bool ok = engine_response_parse(v,zero,sizeof(zero)-1,&r);
        EN_CHECK("explicit zero HTTP usage remains known",
                 ok && r.usage.tokens_known && r.usage.prompt_tokens_known &&
                 r.usage.completion_tokens_known && r.usage.total_tokens_known);
        if (ok) engine_reply_free(&r);
    }
    {
        static const char partial[] =
            "{\"choices\":[{\"message\":{\"content\":\"ok\"}}],"
            "\"usage\":{\"input_tokens\":7}}";
        struct engine_reply r;
        const bool ok=engine_response_parse(v,partial,sizeof(partial)-1,&r);
        EN_CHECK("partial HTTP usage preserves known input and unknown output",
                 ok && r.usage.prompt_tokens_known && r.usage.prompt_tokens==7 &&
                 !r.usage.completion_tokens_known && !r.usage.total_tokens_known &&
                 !r.usage.tokens_known);
        if(ok)engine_reply_free(&r);
    }
    {
        static const char details[] =
            "{\"choices\":[{\"message\":{\"content\":\"ok\"}}],"
            "\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":20,"
            "\"total_tokens\":120,\"prompt_tokens_details\":{\"cached_tokens\":60},"
            "\"completion_tokens_details\":{\"reasoning_tokens\":8}}}";
        struct engine_reply r;
        const bool ok=engine_response_parse(v,details,sizeof(details)-1,&r);
        EN_CHECK("HTTP cache and reasoning detail subsets are preserved",
                 ok && r.usage.cache_read_input_tokens_known &&
                 r.usage.cache_read_input_tokens==60 &&
                 r.usage.reasoning_tokens_known && r.usage.reasoning_tokens==8 &&
                 !r.usage.cache_creation_input_tokens_known);
        if(ok)engine_reply_free(&r);
    }
    {
        static const char conflicting_details[] =
            "{\"choices\":[{\"message\":{\"content\":\"ok\"}}],"
            "\"usage\":{\"cache_read_input_tokens\":40,"
            "\"prompt_tokens_details\":{\"cached_tokens\":39}}}";
        struct engine_reply r;
        const bool ok=engine_response_parse(v,conflicting_details,
                                            sizeof(conflicting_details)-1,&r);
        EN_CHECK("conflicting HTTP usage locations remain unknown",
                 ok && !r.usage.cache_read_input_tokens_known);
        if(ok)engine_reply_free(&r);
    }
    {
        static const char fallback_details[] =
            "{\"choices\":[{\"message\":{\"content\":\"ok\"}}],"
            "\"usage\":{\"prompt_tokens_details\":{},"
            "\"input_tokens_details\":{\"cached_tokens\":31}}}";
        struct engine_reply r;
        const bool ok=engine_response_parse(v,fallback_details,
                                            sizeof(fallback_details)-1,&r);
        EN_CHECK("empty first detail location allows a valid second location",
                 ok && r.usage.cache_read_input_tokens_known &&
                 r.usage.cache_read_input_tokens==31);
        if(ok)engine_reply_free(&r);
    }
    {
        static const char malformed_details[] =
            "{\"choices\":[{\"message\":{\"content\":\"ok\"}}],"
            "\"usage\":{\"prompt_tokens_details\":\"invalid\","
            "\"input_tokens_details\":{\"cached_tokens\":31}}}";
        struct engine_reply r;
        const bool ok=engine_response_parse(v,malformed_details,
                                            sizeof(malformed_details)-1,&r);
        EN_CHECK("malformed detail container invalidates the counter",
                 ok && !r.usage.cache_read_input_tokens_known);
        if(ok)engine_reply_free(&r);
    }
    {
        static const char malformed[] =
            "{\"choices\":[{\"message\":{\"content\":\"ok\"}}],"
            "\"usage\":{\"prompt_tokens\":-1,\"completion_tokens\":\"two\","
            "\"total_tokens\":9223372036854775807,"
            "\"prompt_tokens_details\":{\"cached_tokens\":-2},"
            "\"completion_tokens_details\":{\"reasoning_tokens\":\"many\"}}}";
        struct engine_reply r;
        const bool ok=engine_response_parse(v,malformed,sizeof(malformed)-1,&r);
        EN_CHECK("malformed and negative HTTP counters remain unknown",
                 ok && !r.usage.prompt_tokens_known &&
                 !r.usage.completion_tokens_known &&
                 !r.usage.cache_read_input_tokens_known &&
                 !r.usage.reasoning_tokens_known && r.usage.total_tokens_known &&
                 r.usage.total_tokens==INT64_MAX);
        if(ok)engine_reply_free(&r);
    }
    {
        static const char no_derived_overflow[] =
            "{\"choices\":[{\"message\":{\"content\":\"ok\"}}],"
            "\"usage\":{\"prompt_tokens\":9223372036854775807,"
            "\"completion_tokens\":1}}";
        struct engine_reply r;
        const bool ok=engine_response_parse(v,no_derived_overflow,
                                            sizeof(no_derived_overflow)-1,&r);
        EN_CHECK("missing total is not derived through an overflowing sum",
                 ok && r.usage.prompt_tokens_known &&
                 r.usage.completion_tokens_known && !r.usage.total_tokens_known);
        if(ok)engine_reply_free(&r);
    }

    EN_CHECK("an empty body is refused", refuses("", 0));
    EN_CHECK("a null body is refused", refuses(NULL, 10));
    EN_CHECK("prose that is not JSON is refused",
             refuses("I am sorry, I cannot do that.", 29));

    /* Truncation. This is what an output-token limit or a dropped connection
     * actually looks like, so it is the most likely hostile input of all. */
    {
        static const char full[] =
            "{\"choices\":[{\"message\":{\"content\":\"hello world\"}}]}";
        bool all_refused = true;
        for (size_t cut = 1; cut < sizeof(full) - 1; cut++) {
            if (!refuses(full, cut))
                all_refused = false;
        }
        EN_CHECK("every truncation of a good response is refused", all_refused);
    }

    /* Wrong types at every level that matters. */
    EN_CHECK("a root that is not an object is refused",
             refuses("[1,2,3]", 7));
    EN_CHECK("a root that is a bare string is refused",
             refuses("\"choices\"", 9));
    EN_CHECK("`choices` as a string is refused",
             refuses("{\"choices\":\"nope\"}", 18));
    EN_CHECK("`choices` as an object is refused",
             refuses("{\"choices\":{\"0\":{}}}", 20));
    EN_CHECK("an empty `choices` array is refused",
             refuses("{\"choices\":[]}", 14));
    EN_CHECK("a choice that is not an object is refused",
             refuses("{\"choices\":[42]}", 16));
    EN_CHECK("a `message` that is not an object is refused",
             refuses("{\"choices\":[{\"message\":7}]}", 27));
    EN_CHECK("`content` as a number is refused",
             refuses("{\"choices\":[{\"message\":{\"content\":7}}]}", 39));
    EN_CHECK("`content` as null is refused",
             refuses("{\"choices\":[{\"message\":{\"content\":null}}]}", 42));
    EN_CHECK("`content` as an array is refused",
             refuses("{\"choices\":[{\"message\":{\"content\":[\"a\"]}}]}", 43));
    EN_CHECK("an empty `content` string is refused",
             refuses("{\"choices\":[{\"message\":{\"content\":\"\"}}]}", 40));

    /* An embedded NUL. The JSON parser is length-driven but stores C strings,
     * so a raw 0x00 inside a string literal silently TRUNCATES the text a
     * caller acts on — showing a reviewer one instruction and a machine
     * another. The whole body is refused before parsing. */
    {
        char nul_body[] =
            "{\"choices\":[{\"message\":{\"content\":\"safeXhostile\"}}]}";
        nul_body[38] = '\0';   /* inside the content string */
        EN_CHECK("a body containing a NUL byte is refused",
                 refuses(nul_body, sizeof(nul_body) - 1));
    }

    /* Absurd lengths. A declared length larger than the cap must be refused
     * on the declaration, not after allocating for it. */
    {
        const size_t huge = (size_t)ENGINE_MAX_RESPONSE_BYTES + 1;
        char *pad = malloc(64); /* raw-alloc-ok:test fixture */
        EN_CHECK("a length over the response cap is refused without reading it",
                 pad != NULL && refuses("{}", huge));
        free(pad);
    }
    {
        /* Assistant text over the text cap. Built for real rather than
         * declared, so the cap is proven against actual bytes. */
        const size_t body_cap = (size_t)ENGINE_MAX_TEXT_BYTES + 4096;
        char *big = malloc(body_cap); /* raw-alloc-ok:test fixture */
        if (big) {
            const int head = snprintf(big, body_cap,
                                      "{\"choices\":[{\"message\":{\"content\":\"");
            size_t at = (size_t)head;
            const size_t fill = (size_t)ENGINE_MAX_TEXT_BYTES + 16;
            for (size_t i = 0; i < fill && at < body_cap - 8; i++)
                big[at++] = 'x';
            at += (size_t)snprintf(big + at, body_cap - at, "\"}}]}");
            EN_CHECK("assistant text over the text cap is refused",
                     refuses(big, at));
            free(big);
        } else {
            printf("engine: could not allocate the oversize fixture... FAIL\n");
            failures++;
        }
    }
    {
        /* Too many choices. */
        const size_t cap = 64u * 1024u;
        char *many = malloc(cap); /* raw-alloc-ok:test fixture */
        if (many) {
            size_t at = (size_t)snprintf(many, cap, "{\"choices\":[");
            for (unsigned i = 0; i <= ENGINE_MAX_CHOICES && at < cap - 64; i++)
                at += (size_t)snprintf(many + at, cap - at,
                                       "%s{\"message\":{\"content\":\"a\"}}",
                                       i ? "," : "");
            at += (size_t)snprintf(many + at, cap - at, "]}");
            EN_CHECK("more choices than the cap is refused", refuses(many, at));
            free(many);
        } else {
            printf("engine: could not allocate the many-choices fixture... FAIL\n");
            failures++;
        }
    }

    /* Deep nesting. The JSON parser bounds recursion; this layer must see
     * that as a plain refusal rather than a stack overflow. */
    {
        const size_t depth = 100000;
        char *deep = malloc(depth * 2 + 64); /* raw-alloc-ok:test fixture */
        if (deep) {
            size_t at = (size_t)snprintf(deep, 32, "{\"choices\":");
            for (size_t i = 0; i < depth; i++)
                deep[at++] = '[';
            for (size_t i = 0; i < depth; i++)
                deep[at++] = ']';
            deep[at++] = '}';
            EN_CHECK("a 100000-deep nesting is refused, not survived",
                     refuses(deep, at));
            free(deep);
        } else {
            printf("engine: could not allocate the deep fixture... FAIL\n");
            failures++;
        }
    }

    /* Optional fields with the wrong type must NOT sink a good completion:
     * refusing real work because a vendor sent a string token count would
     * throw away the thing we paid for. It is reported as unknown instead. */
    {
        static const char odd[] =
            "{\"choices\":[{\"message\":{\"content\":\"ok\"}}],"
            "\"usage\":{\"prompt_tokens\":\"lots\",\"cost\":\"free\"}}";
        struct engine_reply r;
        const bool ok = engine_response_parse(v, odd, sizeof(odd) - 1, &r);
        EN_CHECK("a wrongly-typed usage block leaves the completion usable",
                 ok && r.text && strcmp(r.text, "ok") == 0);
        EN_CHECK("and reports the spend as unknown rather than zero",
                 ok && !r.usage.cost_known && !r.usage.tokens_known);
        if (ok)
            engine_reply_free(&r);
    }

    /* The error path is as unwilling to invent structure as the main one. */
    {
        char why[256];
        static const char err[] =
            "{\"error\":{\"code\":\"1113\",\"message\":\"insufficient balance\"}}";
        EN_CHECK("a vendor error object is extracted",
                 engine_response_error_text(err, sizeof(err) - 1, why,
                                            sizeof(why))
                 && strstr(why, "insufficient balance") != NULL);
        EN_CHECK("garbage yields no error text, not invented text",
                 !engine_response_error_text("<<<not json>>>", 14, why,
                                             sizeof(why)));
    }
    return failures;
}

/* ── 4. the file envelope ────────────────────────────────────────────── */

static int case_patch(void)
{
    int failures = 0;
    struct engine_patch p;

    {
        static const char reply[] =
            "Sure, here is the change.\n"
            "Z23-BEGIN-FILE lib/foo/src/bar.c\n"
            "int main(void) { return 0; }\n"
            "Z23-END-FILE\n"
            "Z23-DELETE-FILE lib/foo/src/old.c\n"
            "Hope that helps!\n";
        const bool ok = engine_patch_parse(reply, sizeof(reply) - 1, &p);
        EN_CHECK("a well-formed envelope parses", ok && p.count == 2);
        EN_CHECK("the file body is exact, including its trailing newline",
                 ok && p.count == 2 && p.entries[0].content
                 && strcmp(p.entries[0].content,
                           "int main(void) { return 0; }\n") == 0);
        EN_CHECK("a deletion is recorded as a deletion",
                 ok && p.count == 2 && p.entries[1].remove
                 && p.entries[1].content == NULL);
        if (ok)
            engine_patch_free(&p);
    }

    /* A truncated reply is EXACTLY what an output-token limit produces, and
     * applying half of one leaves a tree that is neither version. */
    {
        static const char cut[] =
            "Z23-BEGIN-FILE lib/foo/src/bar.c\nint main(void) { retu";
        EN_CHECK("an unclosed envelope refuses the WHOLE patch",
                 !engine_patch_parse(cut, sizeof(cut) - 1, &p) && p.count == 0);
    }
    {
        static const char nested[] =
            "Z23-BEGIN-FILE a.c\nZ23-BEGIN-FILE b.c\nZ23-END-FILE\n";
        EN_CHECK("a nested BEGIN is refused",
                 !engine_patch_parse(nested, sizeof(nested) - 1, &p));
    }
    {
        static const char stray[] = "Z23-END-FILE\n";
        EN_CHECK("an END with no open envelope is refused",
                 !engine_patch_parse(stray, sizeof(stray) - 1, &p));
    }
    {
        /* A revised reply for the same path is not malformed: the LAST
         * envelope wins, giving one entry with the second body. */
        static const char twice[] =
            "Z23-BEGIN-FILE a.c\nx\nZ23-END-FILE\n"
            "Z23-BEGIN-FILE a.c\ny\nZ23-END-FILE\n";
        const bool ok = engine_patch_parse(twice, sizeof(twice) - 1, &p);
        EN_CHECK("the same path twice applies as one entry",
                 ok && p.count == 1);
        EN_CHECK("the later envelope's body is the one applied",
                 ok && p.count == 1 && p.entries[0].content
                 && strcmp(p.entries[0].content, "y\n") == 0);
        if (ok)
            engine_patch_free(&p);
    }
    {
        /* The same supersession across kinds: a write followed by a delete
         * for the same path leaves one entry, and it is the delete. */
        static const char write_then_delete[] =
            "Z23-BEGIN-FILE a.c\nx\nZ23-END-FILE\n"
            "Z23-DELETE-FILE a.c\n";
        const bool ok = engine_patch_parse(write_then_delete,
                                           sizeof(write_then_delete) - 1, &p);
        EN_CHECK("a write superseded by a delete leaves one entry",
                 ok && p.count == 1 && p.entries[0].remove
                 && p.entries[0].content == NULL);
        if (ok)
            engine_patch_free(&p);
    }
    {
        /* Prose with no envelope at all is well formed and proposes nothing.
         * That must NOT be an error: "the model changed nothing" is a verdict
         * this harness has to be able to reach honestly. */
        static const char prose[] = "I looked at it and the premise is wrong.\n";
        const bool ok = engine_patch_parse(prose, sizeof(prose) - 1, &p);
        EN_CHECK("prose with no envelope parses to an empty patch",
                 ok && p.count == 0);
        if (ok)
            engine_patch_free(&p);
    }
    {
        char nul_reply[] = "Z23-BEGIN-FILE a.c\nxx\nZ23-END-FILE\n";
        nul_reply[20] = '\0';
        EN_CHECK("a reply containing a NUL is refused",
                 !engine_patch_parse(nul_reply, sizeof(nul_reply) - 1, &p));
    }
    {
        /* A body wrapped in a bare opening fence (optional language tag) and
         * a bare closing fence has both fence lines stripped. */
        static const char fenced[] =
            "Z23-BEGIN-FILE lib/foo/src/bar.c\n"
            "```c\n"
            "int main(void) { return 0; }\n"
            "```\n"
            "Z23-END-FILE\n";
        const bool ok = engine_patch_parse(fenced, sizeof(fenced) - 1, &p);
        EN_CHECK("a fenced body still parses to one file",
                 ok && p.count == 1);
        EN_CHECK("the fence lines are stripped, not written into the file",
                 ok && p.count == 1 && p.entries[0].content
                 && strcmp(p.entries[0].content,
                           "int main(void) { return 0; }\n") == 0);
        if (ok)
            engine_patch_free(&p);
    }
    {
        /* A fence with no language tag, same requirement. */
        static const char fenced_bare[] =
            "Z23-BEGIN-FILE lib/foo/src/bar.c\n"
            "```\n"
            "int main(void) { return 0; }\n"
            "```\n"
            "Z23-END-FILE\n";
        const bool ok = engine_patch_parse(fenced_bare, sizeof(fenced_bare) - 1,
                                           &p);
        EN_CHECK("a bare fence (no language tag) is also stripped",
                 ok && p.count == 1 && p.entries[0].content
                 && strcmp(p.entries[0].content,
                           "int main(void) { return 0; }\n") == 0);
        if (ok)
            engine_patch_free(&p);
    }
    {
        /* A line of backticks INSIDE the body, not first or last, is real
         * content (e.g. a Markdown file the unit is writing) and must be
         * kept verbatim. */
        static const char inner_backticks[] =
            "Z23-BEGIN-FILE docs/x.md\n"
            "before\n"
            "```\n"
            "after\n"
            "Z23-END-FILE\n";
        const bool ok = engine_patch_parse(inner_backticks,
                                           sizeof(inner_backticks) - 1, &p);
        EN_CHECK("a non-terminal fence line is left in the body",
                 ok && p.count == 1 && p.entries[0].content
                 && strcmp(p.entries[0].content,
                           "before\n```\nafter\n") == 0);
        if (ok)
            engine_patch_free(&p);
    }

    /* Containment. This is the security-relevant half: the applier writes
     * relative to an isolated worktree, and a path that cannot escape it is
     * the only kind it accepts. */
    EN_CHECK("a normal source path is accepted",
             engine_patch_path_ok("engine/modules/engine/src/engine_patch.c"));
    EN_CHECK("an absolute path is refused",
             !engine_patch_path_ok("/etc/passwd"));
    EN_CHECK("a parent-directory escape is refused",
             !engine_patch_path_ok("../../etc/passwd"));
    EN_CHECK("an embedded parent-directory segment is refused",
             !engine_patch_path_ok("lib/../../etc/passwd"));
    EN_CHECK("a path reaching into .git is refused",
             !engine_patch_path_ok(".git/config")
             && !engine_patch_path_ok("lib/.git/config"));
    EN_CHECK("a hidden top-level path is refused",
             !engine_patch_path_ok(".ssh/authorized_keys"));
    EN_CHECK("a flag-shaped path is refused",
             !engine_patch_path_ok("--output"));
    EN_CHECK("a path with a shell metacharacter is refused",
             !engine_patch_path_ok("lib/a;rm -rf b.c")
             && !engine_patch_path_ok("lib/$(whoami).c")
             && !engine_patch_path_ok("lib/a\\b.c"));
    EN_CHECK("a doubled separator is refused",
             !engine_patch_path_ok("lib//a.c"));

    /* Line counting and the shrink guard: refuse a whole-file reply that
     * overwrites a file with a fraction of itself. */
    EN_CHECK("an empty buffer is zero lines",
             engine_patch_count_lines("", 0) == 0
             && engine_patch_count_lines(NULL, 0) == 0);
    EN_CHECK("a terminated buffer counts its newlines",
             engine_patch_count_lines("a\nb\nc\n", 6) == 3);
    EN_CHECK("an unterminated final line still counts",
             engine_patch_count_lines("a\nb\nc", 5) == 3);
    EN_CHECK("a new file (no prior lines) is never a shrink",
             !engine_patch_is_drastic_shrink(0, 1));
    EN_CHECK("under half the old line count is a drastic shrink",
             engine_patch_is_drastic_shrink(1850, 40));
    EN_CHECK("exactly half is NOT a drastic shrink",
             !engine_patch_is_drastic_shrink(100, 50));
    EN_CHECK("one line under half IS a drastic shrink",
             engine_patch_is_drastic_shrink(101, 50));
    EN_CHECK("growing or holding steady is never a shrink",
             !engine_patch_is_drastic_shrink(100, 100)
             && !engine_patch_is_drastic_shrink(100, 500));

    /* engine_patch_looks_like_a_path(): tells a real path from prose in a
     * task-brief file-context scan. */
    EN_CHECK("a real relative source path looks like a path",
             engine_patch_looks_like_a_path(
                 "engine/composition/capability_symbols.def"));
    EN_CHECK("a bare filename with an extension looks like a path",
             engine_patch_looks_like_a_path("wallet_gui.c"));
    EN_CHECK("an ordinary word is not a path",
             !engine_patch_looks_like_a_path("dispatcher"));
    EN_CHECK("a directory-shaped token with no extension is not a path",
             !engine_patch_looks_like_a_path("engine/composition"));
    EN_CHECK("a containment violation is not a path even with a dot",
             !engine_patch_looks_like_a_path("../../etc/passwd.conf"));
    EN_CHECK("an empty path is refused",
             !engine_patch_path_ok("") && !engine_patch_path_ok(NULL));
    {
        char long_path[ENGINE_PATCH_MAX_PATH + 32];
        memset(long_path, 'a', sizeof(long_path) - 1);
        long_path[sizeof(long_path) - 1] = '\0';
        EN_CHECK("an over-long path is refused",
                 !engine_patch_path_ok(long_path));
    }
    {
        static const char escape[] =
            "Z23-BEGIN-FILE ../../../etc/cron.d/pwn\nx\nZ23-END-FILE\n";
        EN_CHECK("an escaping path refuses the whole patch",
                 !engine_patch_parse(escape, sizeof(escape) - 1, &p)
                 && p.count == 0);
    }

    /* The protocol text the model is given must describe the parser that
     * reads it, or the two drift and every reply is refused. */
    {
        const char *proto = engine_patch_protocol_text();
        EN_CHECK("the prompt's protocol text names the real markers",
                 proto && strstr(proto, ENGINE_PATCH_BEGIN) != NULL
                 && strstr(proto, ENGINE_PATCH_END) != NULL
                 && strstr(proto, ENGINE_PATCH_DELETE) != NULL);
    }

    /* The describe function archives what a parsed patch would apply, so
     * FAIL(NO-CHANGE) is distinguishable from an accepted parse. */
    {
        static const char reply[] =
            "Z23-BEGIN-FILE lib/foo/src/bar.c\n"
            "int main(void) { return 0; }\n"
            "Z23-END-FILE\n"
            "Z23-DELETE-FILE lib/foo/src/old.c\n";
        const bool ok = engine_patch_parse(reply, sizeof(reply) - 1, &p);
        char desc[256];
        const size_t n = ok ? engine_patch_describe(&p, desc, sizeof(desc)) : 0;
        EN_CHECK("describe lists a written file with its byte count",
                 ok && n > 0
                 && strstr(desc, "lib/foo/src/bar.c: 29 bytes\n") != NULL);
        EN_CHECK("describe marks a deletion distinctly from a write",
                 ok && n > 0
                 && strstr(desc, "lib/foo/src/old.c: DELETE\n") != NULL);
        if (ok)
            engine_patch_free(&p);
    }
    {
        struct engine_patch empty;
        memset(&empty, 0, sizeof(empty));
        char desc[64] = "unwritten";
        const size_t n = engine_patch_describe(&empty, desc, sizeof(desc));
        EN_CHECK("describing an empty patch writes nothing",
                 n == 0 && desc[0] == '\0');
    }
    {
        /* A buffer too small for even one full line truncates safely rather
         * than overflowing or leaving the string unterminated. */
        static const char reply[] =
            "Z23-BEGIN-FILE lib/foo/src/a_very_long_file_name_here.c\n"
            "x\nZ23-END-FILE\n";
        const bool ok = engine_patch_parse(reply, sizeof(reply) - 1, &p);
        char tiny[8];
        const size_t n = ok ? engine_patch_describe(&p, tiny, sizeof(tiny)) : 0;
        EN_CHECK("a too-small buffer stays NUL-terminated",
                 ok && n < sizeof(tiny) && tiny[n] == '\0');
        if (ok)
            engine_patch_free(&p);
    }
    return failures;
}

/* ── 5. secrets ──────────────────────────────────────────────────────── */

static bool secret_fixture_make_insecure(const char *path)
{
#if defined(_WIN32)
    wchar_t wide[32768];
    PSECURITY_DESCRIPTOR descriptor = NULL;
    PACL old_dacl = NULL;
    PACL new_dacl = NULL;
    PSID everyone = NULL;
    SID_IDENTIFIER_AUTHORITY world = SECURITY_WORLD_SID_AUTHORITY;
    bool ok = platform_windows_wide_path(path, wide) &&
              GetNamedSecurityInfoW(wide, SE_FILE_OBJECT,
                                    DACL_SECURITY_INFORMATION, NULL, NULL,
                                    &old_dacl, NULL, &descriptor) == ERROR_SUCCESS &&
              AllocateAndInitializeSid(&world, 1, SECURITY_WORLD_RID,
                                       0, 0, 0, 0, 0, 0, 0, &everyone);
    EXPLICIT_ACCESSW access = {0};
    if (ok) {
        access.grfAccessPermissions = GENERIC_READ;
        access.grfAccessMode = GRANT_ACCESS;
        access.grfInheritance = NO_INHERITANCE;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        access.Trustee.ptstrName = (LPWSTR)everyone;
        ok = SetEntriesInAclW(1, &access, old_dacl, &new_dacl) == ERROR_SUCCESS &&
             SetNamedSecurityInfoW(wide, SE_FILE_OBJECT,
                                   DACL_SECURITY_INFORMATION, NULL, NULL,
                                   new_dacl, NULL) == ERROR_SUCCESS;
    }
    if (new_dacl)
        LocalFree(new_dacl);
    if (everyone)
        FreeSid(everyone);
    if (descriptor)
        LocalFree(descriptor);
    return ok;
#else
    return chmod(path, 0644) == 0;
#endif
}

static bool secret_fixture_write_private(const char *path,
                                         const char *text)
{
    struct platform_private_file file;
    platform_private_file_init(&file);
    (void)platform_private_file_unlink_missing_ok(path);
    const size_t length = strlen(text);
    bool ok = platform_private_file_create(path, &file) &&
              platform_private_file_write_at(&file, text, length, 0) &&
              platform_private_file_flush(&file);
    platform_private_file_close(&file);
    return ok;
}

static int case_secret(void)
{
    int failures = 0;
    char where[128];
    const struct engine_vendor *fixture = engine_by_id("fixture");
    const struct engine_vendor *glm = engine_by_id("glm");

    EN_CHECK("the fixture engine needs no key",
             engine_secret_load(fixture, NULL, where, sizeof(where)));

    /* A key file must be private: exact 0600 on POSIX, owner+SYSTEM-only on
     * Windows. A shared key is already spent, so this is a refusal. */
    char path[PATH_MAX];
    test_fmt_tmpdir(path, sizeof(path), "zcl_engine_key", "key");
    (void)test_ensure_tmproot();
    char key_text[ENGINE_SECRET_MAX];
    (void)snprintf(key_text, sizeof(key_text), "%s\n", k_planted_key);
    EN_CHECK("the private key fixture is created",
             secret_fixture_write_private(path, key_text));
    EN_CHECK("the key fixture can be made non-private",
             secret_fixture_make_insecure(path));
    EN_CHECK("a non-private key file is REFUSED, not warned about",
             !engine_secret_load(glm, path, where, sizeof(where)));
    EN_CHECK("the private key fixture is recreated",
             secret_fixture_write_private(path, key_text));
    EN_CHECK("a private key file loads",
             engine_secret_load(glm, path, where, sizeof(where))
             && engine_secret_loaded());
    EN_CHECK("the source is named without any part of the value",
             strstr(where, k_planted_key) == NULL
             && strstr(where, "0123456789") == NULL);

    /* THE CENTRAL CLAIM: with a key loaded, the harness's own writer cannot
     * put it in an artifact. */
    {
        char artifact[PATH_MAX];
        test_fmt_tmpdir(artifact, sizeof(artifact), "zcl_engine_artifact",
                        "log");
        (void)test_ensure_tmproot();
        char text[1024];
        (void)snprintf(text, sizeof(text),
                       "request failed\nAuthorization: Bearer %s\n"
                       "raw copy: %s\ntrailing prose\n",
                       k_planted_key, k_planted_key);
        const bool wrote = engine_emit_file(artifact, text, strlen(text));
        char back[2048] = {0};
        FILE *rf = fopen(artifact, "rb");
        const size_t n = rf ? fread(back, 1, sizeof(back) - 1, rf) : 0;
        if (rf)
            (void)fclose(rf);
        back[n] = '\0';
        EN_CHECK("the artifact was written", wrote && n > 0);
        EN_CHECK("the key is NOT in the emitted artifact",
                 strstr(back, k_planted_key) == NULL);
        EN_CHECK("no fragment of the key survives either",
                 strstr(back, "0123456789abcdef") == NULL
                 && strstr(back, "AbCdEfGhIjKlMnOp") == NULL);
        EN_CHECK("the surrounding prose is preserved, so the log is still useful",
                 strstr(back, "request failed") != NULL
                 && strstr(back, "trailing prose") != NULL);
        EN_CHECK("the redaction is visible rather than silent",
                 strstr(back, "[REDACTED]") != NULL);
        (void)unlink(artifact);
    }

    /* Key-SHAPED text is scrubbed even when it is not the loaded key — the
     * likeliest credential in a transcript is one this process never held:
     * echoed back by the model, or quoted in a vendor error. */
    {
        char line[512];
        (void)snprintf(line, sizeof(line),
                       "here is my key sk-abcdefghijklmnopqrstuvwxyz012345 and " /* api-key-example-ok */
                       "a header Bearer xai-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 ok"); /* api-key-example-ok */
        engine_redact_inplace(line);
        EN_CHECK("an sk- token this process never loaded is scrubbed",
                 strstr(line, "sk-abcdefghij") == NULL);
        EN_CHECK("a Bearer token this process never loaded is scrubbed",
                 strstr(line, "xai-ABCDEFGHIJ") == NULL);
        EN_CHECK("the word Bearer survives so a reader sees auth was present",
                 strstr(line, "Bearer") != NULL);
        EN_CHECK("ordinary words are untouched",
                 strstr(line, "here is my key") != NULL
                 && strstr(line, " ok") != NULL);
    }

    /* The one legitimate exit for a key, and the fact that clearing works. */
    {
        char hdr[ENGINE_SECRET_MAX + 32];
        EN_CHECK("the authorization header is built from the loaded key",
                 engine_secret_authorization_header(hdr, sizeof(hdr))
                 && strncmp(hdr, "Bearer ", 7) == 0
                 && strstr(hdr, k_planted_key) != NULL);
        engine_secret_clear();
        EN_CHECK("clearing leaves no key", !engine_secret_loaded());
        EN_CHECK("and the header can no longer be built",
                 !engine_secret_authorization_header(hdr, sizeof(hdr)));
    }

    /* A too-short or whitespace-bearing value is a misconfiguration; sending
     * it would put a fragment of a real credential in a vendor's logs. */
    EN_CHECK("the short private key fixture is created",
             secret_fixture_write_private(path, "short\n"));
    EN_CHECK("an implausibly short key is refused",
             !engine_secret_load(glm, path, where, sizeof(where)));
    (void)platform_private_file_unlink_missing_ok(path);
    engine_secret_clear();
    return failures;
}

/* ── 6. the verdict — the law ────────────────────────────────────────── */

/* A gate reading that is as good as one can be: cold run, the group ran, no
 * failures, the bare pass token present. Every case below starts here and
 * changes ONE thing, so each failure verdict is attributable. */
static struct engine_gate_reading perfect(void)
{
    struct engine_gate_reading g = {0};
    g.saw_verdict_line = true;
    g.cached_mode = false;
    g.groups_total = 1;
    g.groups_ran = 1;
    g.groups_failed = 0;
    g.saw_pass_token = true;
    return g;
}

static int case_verdict(void)
{
    int failures = 0;

    {
        struct engine_gate_reading g = perfect();
        EN_CHECK("a real pass is a PASS",
                 engine_verdict_of(&g, 3, false, true) == ENGINE_VERDICT_PASS);
        EN_CHECK("and only PASS counts as passing",
                 engine_verdict_is_pass(ENGINE_VERDICT_PASS)
                 && !engine_verdict_is_pass(ENGINE_VERDICT_NO_CHANGE)
                 && !engine_verdict_is_pass(ENGINE_VERDICT_HOLLOW)
                 && !engine_verdict_is_pass(ENGINE_VERDICT_TIMEOUT)
                 && !engine_verdict_is_pass(ENGINE_VERDICT_UNVERIFIED)
                 && !engine_verdict_is_pass(ENGINE_VERDICT_REFUSED)
                 && !engine_verdict_is_pass(ENGINE_VERDICT_FAIL));
    }

    /* THE LAW. A perfect gate reading plus an empty diff is a FAILURE: the
     * gate measured the tree before the unit ran. */
    {
        struct engine_gate_reading g = perfect();
        const enum engine_verdict v = engine_verdict_of(&g, 0, false, true);
        EN_CHECK("a PERFECT gate plus an empty diff is NO-CHANGE, not PASS",
                 v == ENGINE_VERDICT_NO_CHANGE);
        EN_CHECK("and NO-CHANGE is a failure", !engine_verdict_is_pass(v));
    }

    /* The hollow green: a selector that matched nothing. */
    {
        struct engine_gate_reading g = perfect();
        g.groups_ran = 0;
        EN_CHECK("groups_ran=0 is HOLLOW even with the pass token present",
                 engine_verdict_of(&g, 2, false, true) == ENGINE_VERDICT_HOLLOW);
    }
    /* The other hollow green: everything served from cache. */
    {
        struct engine_gate_reading g = perfect();
        g.cached_mode = true;
        g.groups_cached = 1;
        g.groups_ran = 1;
        EN_CHECK("a fully cached run is HOLLOW: it never ran the new code",
                 engine_verdict_of(&g, 2, false, true) == ENGINE_VERDICT_HOLLOW);
    }
    {
        struct engine_gate_reading g = perfect();
        g.groups_failed = 1;
        EN_CHECK("a failing group is a FAIL",
                 engine_verdict_of(&g, 2, false, true) == ENGINE_VERDICT_FAIL);
    }
    {
        struct engine_gate_reading g = perfect();
        g.saw_pass_token = false;
        EN_CHECK("silence is not consent: no pass token is REFUSED",
                 engine_verdict_of(&g, 2, false, true) == ENGINE_VERDICT_REFUSED);
    }
    {
        struct engine_gate_reading g = {0};
        EN_CHECK("a gate that produced no verdict line is REFUSED",
                 engine_verdict_of(&g, 2, false, true) == ENGINE_VERDICT_REFUSED);
        EN_CHECK("a null gate reading is REFUSED, never a pass",
                 engine_verdict_of(NULL, 2, false, true) == ENGINE_VERDICT_REFUSED);
    }
    {
        struct engine_gate_reading g = perfect();
        EN_CHECK("a timeout reports itself as a TIMEOUT, not a fail or a pass",
                 engine_verdict_of(&g, 2, true, true) == ENGINE_VERDICT_TIMEOUT);
    }
    {
        struct engine_gate_reading g = perfect();
        EN_CHECK("a unit with no group is UNVERIFIED, which is not a pass",
                 engine_verdict_of(&g, 2, false, false)
                     == ENGINE_VERDICT_UNVERIFIED);
    }
    return failures;
}

/* ── 6b. verdict by declared effect ──────────────────────────────────── */

static int case_effect_per_kind(void)
{
    int failures = 0;
    /* Every registered kind must be classified here, so a new kind cannot
     * ship without someone deciding whether its unit may change files. */
    static const struct {
        const char *kind;
        enum engine_prompt_effect effect;
    } want[] = {
        { "fix-gate", ENGINE_PROMPT_EFFECT_EDIT },
        { "add-test", ENGINE_PROMPT_EFFECT_EDIT },
        { "port-arm", ENGINE_PROMPT_EFFECT_EDIT },
        { "doc-claim", ENGINE_PROMPT_EFFECT_EDIT },
        { "review", ENGINE_PROMPT_EFFECT_REPORT },
        { "c23-byte-validator", ENGINE_PROMPT_EFFECT_EDIT },
        { "c23-command-handler", ENGINE_PROMPT_EFFECT_EDIT },
        { "c23-model-save", ENGINE_PROMPT_EFFECT_EDIT },
        { "c23-regression-fixture", ENGINE_PROMPT_EFFECT_EDIT },
        { "c23-wire-codec", ENGINE_PROMPT_EFFECT_EDIT },
        { "c23-cas-operation", ENGINE_PROMPT_EFFECT_EDIT },
        { "c23-service-operation", ENGINE_PROMPT_EFFECT_EDIT },
        { "c23-resource-owner", ENGINE_PROMPT_EFFECT_EDIT },
        { "c23-telemetry-field", ENGINE_PROMPT_EFFECT_EDIT },
        { "c23-controller-route", ENGINE_PROMPT_EFFECT_EDIT },
        { "c23-source-generator", ENGINE_PROMPT_EFFECT_EDIT },
        { "c23-registry-entry", ENGINE_PROMPT_EFFECT_EDIT },
        /* writes its one pack file, so it changes the worktree */
        { "c23-context-pack", ENGINE_PROMPT_EFFECT_EDIT },
        /* regenerates the capability inventory and repairs pins */
        { "c23-gate-tail", ENGINE_PROMPT_EFFECT_EDIT },
        { "c23-proof-triage", ENGINE_PROMPT_EFFECT_REPORT },
        { "c23-patch", ENGINE_PROMPT_EFFECT_EDIT },
        { "c23-review-pass", ENGINE_PROMPT_EFFECT_REPORT },
        { "c23-card-check", ENGINE_PROMPT_EFFECT_REPORT },
    };
    const size_t n = sizeof want / sizeof want[0];
    EN_CHECK("the effect table classifies every registered kind",
             engine_prompt_kind_count() == n);
    for (size_t i = 0; i < engine_prompt_kind_count(); i++) {
        const char *kind = engine_prompt_kind_at(i);
        bool found = false;
        for (size_t j = 0; j < n && kind; j++) {
            if (strcmp(want[j].kind, kind) != 0)
                continue;
            found = true;
            EN_CHECK("a kind's effect is the one the table decided",
                     engine_prompt_kind_effect(kind) == want[j].effect);
        }
        EN_CHECK("every registered kind appears in the effect table", found);
    }
    EN_CHECK("a NULL kind has an UNKNOWN effect",
             engine_prompt_kind_effect(NULL) == ENGINE_PROMPT_EFFECT_UNKNOWN);
    EN_CHECK("an empty kind has an UNKNOWN effect",
             engine_prompt_kind_effect("") == ENGINE_PROMPT_EFFECT_UNKNOWN);
    EN_CHECK("an unregistered kind has an UNKNOWN effect",
             engine_prompt_kind_effect("half-done")
                 == ENGINE_PROMPT_EFFECT_UNKNOWN);
    return failures;
}

static int case_verdict_report(void)
{
    int failures = 0;
    const struct engine_gate_reading g = perfect();
    const enum engine_prompt_effect rep = ENGINE_PROMPT_EFFECT_REPORT;

    const enum engine_verdict done =
        engine_verdict_of_effect(rep, NULL, 0, false, false);
    EN_CHECK("a report that changed nothing is REPORTED",
             done == ENGINE_VERDICT_REPORTED);
    EN_CHECK("REPORTED is not a pass", !engine_verdict_is_pass(done));
    EN_CHECK("REPORTED is terminal", engine_verdict_is_terminal(done));
    EN_CHECK("REPORTED needs neither a gate nor a group",
             engine_verdict_of_effect(rep, &g, 0, false, true) == done);

    const enum engine_verdict edited =
        engine_verdict_of_effect(rep, &g, 1, false, true);
    EN_CHECK("a report that changed a file is REPORT_EDITED, even on a "
             "perfect gate", edited == ENGINE_VERDICT_REPORT_EDITED);
    EN_CHECK("REPORT_EDITED is neither a pass nor terminal",
             !engine_verdict_is_pass(edited)
             && !engine_verdict_is_terminal(edited));
    EN_CHECK("a report that timed out is TIMEOUT, edited or not",
             engine_verdict_of_effect(rep, &g, 0, true, true)
                 == ENGINE_VERDICT_TIMEOUT
             && engine_verdict_of_effect(rep, &g, 4, true, true)
                 == ENGINE_VERDICT_TIMEOUT);
    EN_CHECK("TIMEOUT is not terminal",
             !engine_verdict_is_terminal(ENGINE_VERDICT_TIMEOUT));
    return failures;
}

static int case_verdict_edit_delegates(void)
{
    int failures = 0;
    struct engine_gate_reading ok = perfect();
    struct engine_gate_reading failed = perfect();
    failed.groups_failed = 1;
    struct engine_gate_reading hollow = perfect();
    hollow.groups_ran = 0;
    struct engine_gate_reading silent = {0};
    const struct {
        const struct engine_gate_reading *g;
        size_t changed;
        bool timed_out;
        bool group;
    } in[] = {
        { &ok, 3, false, true },      /* PASS */
        { &ok, 0, false, true },      /* NO_CHANGE */
        { &ok, 2, true, true },       /* TIMEOUT */
        { &ok, 2, false, false },     /* UNVERIFIED */
        { &failed, 2, false, true },  /* FAIL */
        { &hollow, 2, false, true },  /* HOLLOW */
        { &silent, 2, false, true },  /* REFUSED */
        { NULL, 2, false, true },     /* REFUSED */
    };
    const enum engine_prompt_effect effects[] = {
        ENGINE_PROMPT_EFFECT_EDIT, ENGINE_PROMPT_EFFECT_UNKNOWN };
    for (size_t e = 0; e < 2; e++) {
        for (size_t i = 0; i < sizeof in / sizeof in[0]; i++) {
            EN_CHECK("EDIT and UNKNOWN delegate to engine_verdict_of",
                     engine_verdict_of_effect(effects[e], in[i].g,
                                              in[i].changed, in[i].timed_out,
                                              in[i].group)
                     == engine_verdict_of(in[i].g, in[i].changed,
                                          in[i].timed_out, in[i].group));
        }
    }
    EN_CHECK("an EDIT unit that changed nothing is still NO_CHANGE",
             engine_verdict_of_effect(ENGINE_PROMPT_EFFECT_EDIT, &ok, 0,
                                      false, true) == ENGINE_VERDICT_NO_CHANGE);
    EN_CHECK("PASS is terminal and passing",
             engine_verdict_is_terminal(ENGINE_VERDICT_PASS)
             && engine_verdict_is_pass(ENGINE_VERDICT_PASS));
    EN_CHECK("no failure verdict is terminal",
             !engine_verdict_is_terminal(ENGINE_VERDICT_FAIL)
             && !engine_verdict_is_terminal(ENGINE_VERDICT_NO_CHANGE)
             && !engine_verdict_is_terminal(ENGINE_VERDICT_HOLLOW)
             && !engine_verdict_is_terminal(ENGINE_VERDICT_REFUSED)
             && !engine_verdict_is_terminal(ENGINE_VERDICT_UNVERIFIED));
    return failures;
}

static int case_verdict_names(void)
{
    int failures = 0;
    EN_CHECK("REPORTED names itself",
             strcmp(engine_verdict_name(ENGINE_VERDICT_REPORTED),
                    "REPORTED") == 0);
    EN_CHECK("REPORT_EDITED names itself",
             strcmp(engine_verdict_name(ENGINE_VERDICT_REPORT_EDITED),
                    "FAIL(REPORT-EDITED)") == 0);
    for (int v = ENGINE_VERDICT_PASS; v <= ENGINE_VERDICT_REPORT_EDITED; v++) {
        const char *name = engine_verdict_name((enum engine_verdict)v);
        EN_CHECK("every verdict has a distinct non-UNKNOWN name",
                 name && strcmp(name, "UNKNOWN") != 0);
        for (int w = ENGINE_VERDICT_PASS; w < v; w++)
            EN_CHECK("verdict names are pairwise distinct",
                     strcmp(name,
                            engine_verdict_name((enum engine_verdict)w)) != 0);
    }
    return failures;
}

/* ── 7. reading the gate's own output ────────────────────────────────── */

static int case_gate_read(void)
{
    int failures = 0;
    struct engine_gate_reading g;

    {
        static const char log[] =
            "some build noise\n"
            "SUITE VERDICT mode=cold groups_total=743 groups_ran=1 "
            "groups_cached=0 groups_gated=742 groups_failed=0 self_skips=0 "
            "env_unobserved=0 toolkey=abc123\n"
            "ALL TESTS PASSED — 0/1 groups failed, 0 skipped (2.1s wall)\n";
        EN_CHECK("a real cold run reads correctly",
                 engine_gate_read(log, sizeof(log) - 1, &g)
                 && g.saw_verdict_line && !g.cached_mode && g.groups_ran == 1
                 && g.groups_failed == 0 && g.saw_pass_token);
    }
    /* The cached headline contains the pass token, so a substring grep
     * would match a run that executed nothing. */
    {
        static const char log[] =
            "SUITE VERDICT mode=cached groups_total=743 groups_ran=0 "
            "groups_cached=1 groups_gated=742 groups_failed=0 self_skips=0 "
            "env_unobserved=0 toolkey=abc123\n"
            "ALL TESTS PASSED (CACHED) — 0/1 groups failed\n";
        EN_CHECK("the (CACHED) headline does NOT count as the pass token",
                 engine_gate_read(log, sizeof(log) - 1, &g)
                 && g.cached_mode && !g.saw_pass_token && g.groups_ran == 0);
        EN_CHECK("and it judges as HOLLOW",
                 engine_verdict_of(&g, 1, false, true) == ENGINE_VERDICT_HOLLOW);
    }
    {
        static const char log[] =
            "SUITE VERDICT mode=cold groups_total=1 groups_ran=1 "
            "groups_cached=0 groups_gated=0 groups_failed=1 self_skips=0 "
            "env_unobserved=0 toolkey=abc\n"
            "SOME TESTS FAILED — 1/1 groups failed\n";
        EN_CHECK("a failing run reads its failure",
                 engine_gate_read(log, sizeof(log) - 1, &g)
                 && g.groups_failed == 1 && g.saw_fail_token);
    }
    {
        static const char log[] = "make: *** no rule to make target\n";
        EN_CHECK("a log with no verdict line reports that honestly",
                 engine_gate_read(log, sizeof(log) - 1, &g)
                 && !g.saw_verdict_line);
    }
    {
        /* The LAST verdict line wins: a run can print more than one. */
        static const char log[] =
            "SUITE VERDICT mode=cold groups_total=1 groups_ran=9 "
            "groups_failed=0 toolkey=a\n"
            "SUITE VERDICT mode=cold groups_total=1 groups_ran=1 "
            "groups_failed=0 toolkey=b\n";
        EN_CHECK("the last verdict line is the one that counts",
                 engine_gate_read(log, sizeof(log) - 1, &g) && g.groups_ran == 1);
    }
    EN_CHECK("an empty log does not crash", engine_gate_read("", 0, &g));
    EN_CHECK("a null log is refused", !engine_gate_read(NULL, 10, &g));
    {
        /* build-epoch-session.sh's epoch-lease failure is the harness
         * racing itself, so the reading must be retryable. */
        static const char log[] =
            "make: Entering directory '/x'\n"
            "build-epoch-session: acquired profile=dev-v2 epoch=aaa "
            "lease=build/dev-obj/epochs/aaa/.leases/1\n"
            "build-epoch-session: compiler/toolchain changed during build "
            "expected=aaa actual=bbb\n"
            "make: *** [Makefile:3936: build/dev-obj/epochs/aaa/.complete] "
            "Error 2\n"
            "make: Leaving directory '/x'\n";
        EN_CHECK("a build-epoch race is flagged as an environment race",
                 engine_gate_read(log, sizeof(log) - 1, &g)
                 && g.env_epoch_race && !g.saw_verdict_line);
    }
    {
        static const char log[] =
            "SUITE VERDICT mode=cold groups_total=1 groups_ran=1 "
            "groups_failed=0 toolkey=a\n"
            "ALL TESTS PASSED — 0/1 groups failed\n";
        EN_CHECK("an ordinary passing log is not flagged as a race",
                 engine_gate_read(log, sizeof(log) - 1, &g)
                 && !g.env_epoch_race);
    }
    return failures;
}

/* ── 8. failure classes, retries, the breaker ────────────────────────── */

static int case_err(void)
{
    int failures = 0;
    EN_CHECK("2xx is not an error", engine_err_of_status(200) == ENGINE_OK
             && engine_err_of_status(204) == ENGINE_OK);
    EN_CHECK("429 is a rate limit",
             engine_err_of_status(429) == ENGINE_ERR_RATE_LIMIT);
    EN_CHECK("529 is overloaded",
             engine_err_of_status(529) == ENGINE_ERR_OVERLOADED);
    EN_CHECK("401 and 403 are auth failures",
             engine_err_of_status(401) == ENGINE_ERR_AUTH
             && engine_err_of_status(403) == ENGINE_ERR_AUTH);
    EN_CHECK("400 is a bad request",
             engine_err_of_status(400) == ENGINE_ERR_BAD_REQUEST);
    EN_CHECK("5xx is a server error",
             engine_err_of_status(503) == ENGINE_ERR_SERVER);

    /* Retrying an auth failure burns wall clock and never succeeds. */
    EN_CHECK("an auth failure is NOT retried",
             !engine_err_should_retry(ENGINE_ERR_AUTH));
    EN_CHECK("a bad request is NOT retried",
             !engine_err_should_retry(ENGINE_ERR_BAD_REQUEST));
    EN_CHECK("a refused response is NOT retried",
             !engine_err_should_retry(ENGINE_ERR_PARSE));
    EN_CHECK("overload and rate limits ARE retried",
             engine_err_should_retry(ENGINE_ERR_OVERLOADED)
             && engine_err_should_retry(ENGINE_ERR_RATE_LIMIT));

    EN_CHECK("backoff grows and is capped",
             engine_err_backoff_ms(0) < engine_err_backoff_ms(2)
             && engine_err_backoff_ms(99) <= 60000);

    /* A retryable status (429) with an empty-account body is terminal: a
     * status-only classifier would retry a billing failure forever. */
    {
        static const char zai[] =
            "1113: Insufficient balance or no resource package. Please recharge.";
        static const char oai[] =
            "credit_balance_exhausted: You have no credits remaining. Add "
            "credits to continue using the API at https://platform.openai.com/";
        EN_CHECK("Z.ai's 429 for an empty account becomes non-retryable",
                 !engine_err_should_retry(
                     engine_err_refine(ENGINE_ERR_RATE_LIMIT, zai)));
        EN_CHECK("OpenAI's 429 for an empty account becomes non-retryable",
                 !engine_err_should_retry(
                     engine_err_refine(ENGINE_ERR_RATE_LIMIT, oai)));
        EN_CHECK("a genuine rate limit is still retried",
                 engine_err_should_retry(engine_err_refine(
                     ENGINE_ERR_RATE_LIMIT,
                     "Too many requests, please slow down")));
        /* The refinement only ever makes a failure MORE terminal. A vendor
         * must not be able to talk its way back into being retried, and must
         * never be able to talk its way into a success. */
        EN_CHECK("refinement never makes a terminal class retryable",
                 engine_err_refine(ENGINE_ERR_AUTH, "please retry later")
                     == ENGINE_ERR_AUTH
                 && engine_err_refine(ENGINE_ERR_BAD_REQUEST, "transient")
                     == ENGINE_ERR_BAD_REQUEST);
        EN_CHECK("refinement never turns a failure into a success",
                 engine_err_refine(ENGINE_ERR_SERVER, "everything is fine")
                     != ENGINE_OK);
        EN_CHECK("no body leaves the class alone",
                 engine_err_refine(ENGINE_ERR_OVERLOADED, NULL)
                     == ENGINE_ERR_OVERLOADED
                 && engine_err_refine(ENGINE_ERR_OVERLOADED, "")
                     == ENGINE_ERR_OVERLOADED);
        EN_CHECK("the match is case-insensitive across vendors",
                 !engine_err_should_retry(engine_err_refine(
                     ENGINE_ERR_RATE_LIMIT, "INSUFFICIENT BALANCE")));
    }

    /* The breaker: retries alone turn one outage into a bill. */
    {
        struct engine_breaker b = {0};
        EN_CHECK("a fresh circuit is closed", !engine_breaker_is_open(&b, 1000));
        for (int i = 0; i < ENGINE_BREAKER_THRESHOLD; i++)
            engine_breaker_record(&b, ENGINE_ERR_SERVER, 1000);
        EN_CHECK("consecutive failures open the circuit",
                 engine_breaker_is_open(&b, 1000));
        EN_CHECK("it reopens after the cooldown, not before",
                 engine_breaker_is_open(&b, 1000 + ENGINE_BREAKER_COOLDOWN_MS - 1)
                 && !engine_breaker_is_open(&b,
                        1000 + ENGINE_BREAKER_COOLDOWN_MS + 1));
        engine_breaker_record(&b, ENGINE_OK, 2000);
        EN_CHECK("a success closes it immediately",
                 !engine_breaker_is_open(&b, 2000) && b.consecutive_failures == 0);
    }
    EN_CHECK("every class has a name",
             engine_err_name(ENGINE_ERR_TIMEOUT) != NULL
             && strcmp(engine_err_name(ENGINE_ERR_TIMEOUT), "unknown") != 0);
    return failures;
}

/* ── 9. the secret-scanning lint gate proves itself on a planted key ─── */

/* check-no-api-keys must fail on a real key: point its scan-set override at
 * a fixture tree with a key planted and require a non-zero exit. */
static int case_key_gate(void)
{
    int failures = 0;
    char dir[512];
    (void)mkdir("build", 0700);
    (void)mkdir("build/scratch", 0700);
    (void)snprintf(dir, sizeof(dir), "build/scratch/zcl_engine_gate_%d",
                   (int)getpid());

    if (mkdir(dir, 0700) != 0) {
        printf("engine: could not create the gate fixture... FAIL\n");
        return 1;
    }
    /* A clean file first: the gate must pass on it, so a later failure is
     * attributable to the planted key and not to the fixture. */
    char clean[600];
    (void)snprintf(clean, sizeof(clean), "%s/clean.c", dir);
    FILE *f = fopen(clean, "wb");
    bool clean_written = f && fputs("int main(void){return 0;}\n", f) >= 0;
    if (f)
        clean_written = fclose(f) == 0 && clean_written;
    EN_CHECK("the clean gate fixture was written", clean_written);
    (void)setenv("ZCL_API_KEY_SCAN_FILES", clean, 1);
    EN_CHECK("the key gate passes on a clean tree",
             system("bash -lc \"./tools/lint/check_no_api_keys.sh "
                    ">/dev/null 2>&1\"") == 0); /* shellout-ok: test */

    /* Now plant one. Assembled at run time so this source file does not
     * itself contain a key-shaped literal for the gate to find. */
    char leak[600];
    (void)snprintf(leak, sizeof(leak), "%s/leak.c", dir);
    f = fopen(leak, "wb");
    bool leak_written = f &&
        fprintf(f, "static const char *k = \"%s%s\";\n", "sk-",
                "abcdefghijklmnopqrstuvwxyz0123456789") > 0;
    if (f)
        leak_written = fclose(f) == 0 && leak_written;
    EN_CHECK("the planted-key fixture was written", leak_written);
    (void)setenv("ZCL_API_KEY_SCAN_FILES", leak, 1);
    EN_CHECK("the key gate FAILS on a planted key",
             system("bash -lc \"./tools/lint/check_no_api_keys.sh "
                    ">/dev/null 2>&1\"") != 0); /* shellout-ok: test */

    (void)unsetenv("ZCL_API_KEY_SCAN_FILES");
    (void)remove(clean);
    (void)remove(leak);
#if defined(_WIN32)
    (void)_rmdir(dir);
#else
    (void)rmdir(dir);
#endif
    return failures;
}


/* ── 10. the prompt every vendor actually receives ───────────────────────
 * For every wire, either it has its own system channel or the bytes it
 * receives contain the rules. */

static bool prompt_holds_rules(const char *s)
{
    return s && strstr(s, "C23 only") != NULL &&
           strstr(s, "Never weaken an assertion") != NULL &&
           strstr(s, "must actually run") != NULL;
}

static int case_prompt(void)
{
    int failures = 0;
    const char *task = "TASK MARKER: the composed unit prompt.";

    EN_CHECK("the rules name the C23 constraint",
             prompt_holds_rules(engine_system_rules()));

    /* The load-bearing one: no wire may end up with neither channel. */
    const enum engine_wire wires[] = { ENGINE_WIRE_OPENAI_CHAT,
                                       ENGINE_WIRE_LOCAL_CLI,
                                       ENGINE_WIRE_LOCAL_FIXTURE };
    bool every_wire_told = true;
    bool every_wire_keeps_task = true;
    for (size_t i = 0; i < sizeof wires / sizeof wires[0]; i++) {
        size_t len = 0;
        char *got = engine_prompt_compose(wires[i], task, &len);
        if (!got) {
            every_wire_told = false;
            every_wire_keeps_task = false;
            break;
        }
        if (!engine_wire_has_system_channel(wires[i]) && !prompt_holds_rules(got))
            every_wire_told = false;
        if (!strstr(got, task) || len != strlen(got))
            every_wire_keeps_task = false;
        free(got);
    }
    EN_CHECK("every wire either has a system channel or is told the rules "
             "in its prompt", every_wire_told);
    EN_CHECK("and every wire still receives the task, with a truthful length",
             every_wire_keeps_task);

    /* A CLI vendor is named directly so a
     * regression reads as itself rather than as a loop failing. */
    size_t cli_len = 0;
    char *cli = engine_prompt_compose(ENGINE_WIRE_LOCAL_CLI, task, &cli_len);
    EN_CHECK("a CLI vendor receives the rules", prompt_holds_rules(cli));
    EN_CHECK("with the rules first and the task after",
             cli && strstr(cli, "C23 only") < strstr(cli, task));

    /* An HTTP vendor must NOT get them twice: the same block in two places
     * teaches a model the block is decoration. */
    size_t http_len = 0;
    char *http = engine_prompt_compose(ENGINE_WIRE_OPENAI_CHAT, task, &http_len);
    EN_CHECK("an HTTP vendor is not told the rules twice",
             http && !prompt_holds_rules(http));
    EN_CHECK("an HTTP vendor receives exactly the composed prompt",
             http && strcmp(http, task) == 0 && http_len == strlen(task));
    EN_CHECK("the CLI prompt is the longer of the two", cli_len > http_len);
    free(cli);
    free(http);

    /* An over-long prompt is refused, never cut: half a prompt still looks
     * like a prompt, and the model would answer it. */
    size_t huge_len = ENGINE_MAX_PROMPT_BYTES + 1u;
    char *huge = zcl_malloc(huge_len + 1, "test_engine_huge_prompt");
    if (huge) {
        memset(huge, 'x', huge_len);
        huge[huge_len] = '\0';
        size_t out_len = 12345;
        char *over = engine_prompt_compose(ENGINE_WIRE_LOCAL_CLI, huge, &out_len);
        EN_CHECK("a prompt over the ceiling is refused", over == NULL);
        EN_CHECK("and the refusal reports no length", out_len == 0);
        free(over);
        free(huge);
    } else {
        EN_CHECK("the over-length fixture allocates", false);
    }

    size_t nul_len = 999;
    EN_CHECK("a NULL prompt refuses",
             engine_prompt_compose(ENGINE_WIRE_LOCAL_CLI, NULL, &nul_len) == NULL);
    EN_CHECK("and reports no length", nul_len == 0);
    return failures;
}


/* ── the declared prompt shape ────────────────────────────────────────────
 * A prompt missing a required section is refused by name. The rules row is
 * required inline for a CLI wire and forbidden inline for an HTTP wire. */

/* A prompt with every section a CLI wire needs, in order, built from the
 * registry so a new row cannot be added without this fixture carrying it. */
static char *shape_fixture(enum engine_wire wire, const char *skip_id,
                           bool out_of_order)
{
    size_t total = 1;
    size_t n = engine_prompt_section_count();
    for (size_t i = 0; i < n; i++)
        total += strlen(engine_prompt_section_at(i)->marker) + 2;
    char *buf = zcl_malloc(total, "test_engine_shape_fixture");
    if (!buf) return NULL;
    buf[0] = '\0';
    /* Optional rows are carried too: a fixture that omits them would never
     * exercise the ordering cursor they advance. */
    for (size_t i = 0; i < n; i++) {
        size_t idx = i;
        if (out_of_order && n >= 2) {
            /* Swap the first two rows this wire actually carries. */
            if (i == 0) idx = 1;
            else if (i == 1) idx = 0;
        }
        const struct engine_prompt_section *s = engine_prompt_section_at(idx);
        if (skip_id && strcmp(s->id, skip_id) == 0) continue;
        if (s->need == ENGINE_PROMPT_NEED_NO_SYSTEM_CHANNEL
            && engine_wire_has_system_channel(wire)) continue;
        strcat(buf, s->marker);
        strcat(buf, "\n\n");
    }
    return buf;
}

static int case_prompt_shape(void)
{
    int failures = 0;

    EN_CHECK("the prompt shape registry is not empty",
             engine_prompt_section_count() > 0);
    EN_CHECK("an index past the end has no section",
             engine_prompt_section_at(engine_prompt_section_count()) == NULL);

    bool ids_and_markers_present = true;
    for (size_t i = 0; i < engine_prompt_section_count(); i++) {
        const struct engine_prompt_section *s = engine_prompt_section_at(i);
        if (!s || !s->id || !s->id[0] || !s->marker || !s->marker[0])
            ids_and_markers_present = false;
    }
    EN_CHECK("every row has a name and a marker", ids_and_markers_present);

    /* A well-formed prompt passes for every wire in the enum. */
    const enum engine_wire wires[] = { ENGINE_WIRE_OPENAI_CHAT,
                                       ENGINE_WIRE_LOCAL_CLI,
                                       ENGINE_WIRE_LOCAL_FIXTURE };
    bool all_wires_pass = true;
    bool all_wires_require_something = true;
    for (size_t i = 0; i < sizeof wires / sizeof wires[0]; i++) {
        char *good = shape_fixture(wires[i], NULL, false);
        struct engine_prompt_audit a;
        if (!good || !engine_prompt_audit_text(wires[i], good, &a))
            all_wires_pass = false;
        else if (a.required == 0 || a.present != a.required)
            all_wires_require_something = false;
        free(good);
    }
    EN_CHECK("a prompt built from the registry passes for every wire",
             all_wires_pass);
    EN_CHECK("and every wire requires at least one section, all found",
             all_wires_require_something);

    /* Drop each required section in turn. Every one must be refused BY NAME:
     * a refusal that cannot say what is wrong sends the operator back to
     * diffing two prompts by eye. */
    bool each_omission_refused = true;
    bool each_omission_named = true;
    size_t omissions_tested = 0;
    for (size_t i = 0; i < engine_prompt_section_count(); i++) {
        const struct engine_prompt_section *s = engine_prompt_section_at(i);
        if (s->need == ENGINE_PROMPT_NEED_OPTIONAL) continue;
        if (s->need == ENGINE_PROMPT_NEED_NO_SYSTEM_CHANNEL
            && engine_wire_has_system_channel(ENGINE_WIRE_LOCAL_CLI)) continue;
        char *bad = shape_fixture(ENGINE_WIRE_LOCAL_CLI, s->id, false);
        struct engine_prompt_audit a;
        omissions_tested++;
        if (!bad || engine_prompt_audit_text(ENGINE_WIRE_LOCAL_CLI, bad, &a))
            each_omission_refused = false;
        else if (!a.missing || strcmp(a.missing, s->id) != 0)
            each_omission_named = false;
        free(bad);
    }
    EN_CHECK("dropping any required section is refused", each_omission_refused);
    EN_CHECK("and the refusal names the section that is gone",
             each_omission_named);
    EN_CHECK("more than one required section was actually dropped and tested",
             omissions_tested >= 2);

    /* Order is part of the shape: a task placed after the output protocol
     * reads as an example of the protocol. */
    char *swapped = shape_fixture(ENGINE_WIRE_LOCAL_CLI, NULL, true);
    struct engine_prompt_audit ord;
    bool ord_refused = swapped
                       && !engine_prompt_audit_text(ENGINE_WIRE_LOCAL_CLI,
                                                    swapped, &ord);
    EN_CHECK("a prompt with two sections swapped is refused", ord_refused);
    EN_CHECK("and the refusal reports a misplaced section, not a missing one",
             ord_refused && ord.misplaced != NULL && ord.missing == NULL);
    free(swapped);

    /* The rules must not be repeated to a wire that carries them on its own
     * channel. This is the other half of the defect: not sending them, and
     * sending them twice, are both wrong. */
    char *cli_shaped = shape_fixture(ENGINE_WIRE_LOCAL_CLI, NULL, false);
    struct engine_prompt_audit dup;
    bool dup_refused = cli_shaped
                       && !engine_prompt_audit_text(ENGINE_WIRE_OPENAI_CHAT,
                                                    cli_shaped, &dup);
    EN_CHECK("a CLI-shaped prompt sent to an HTTP wire is refused",
             dup_refused);
    EN_CHECK("and the refusal names the repeated section",
             dup_refused && dup.repeated != NULL);
    free(cli_shaped);

    /* What engine_prompt_compose actually produces must pass its own audit,
     * for every wire. This is the check that binds the two halves: a shape
     * registry nothing composes against is a document, not a gate. */
    const char *task = "# Your unit of work\n\nTASK\n\n"
                       "# OUTPUT PROTOCOL\n\n# How this unit will be judged\n";
    bool compose_matches_shape = true;
    for (size_t i = 0; i < sizeof wires / sizeof wires[0]; i++) {
        char *got = engine_prompt_compose(wires[i], task, NULL);
        struct engine_prompt_audit a;
        if (!got || !engine_prompt_audit_text(wires[i], got, &a))
            compose_matches_shape = false;
        free(got);
    }
    EN_CHECK("what compose produces passes the audit for every wire",
             compose_matches_shape);

    EN_CHECK("a NULL prompt fails the audit",
             !engine_prompt_audit_text(ENGINE_WIRE_LOCAL_CLI, NULL, NULL));

    /* The shape hash is the version identity of the prompt. It must be
     * stable within a build and must not be all zeros — a hash function that
     * quietly did nothing would otherwise read as agreement. */
    uint8_t h1[32], h2[32];
    memset(h1, 0, sizeof h1);
    memset(h2, 0xff, sizeof h2);
    engine_prompt_shape_sha3(h1);
    engine_prompt_shape_sha3(h2);
    bool nonzero = false;
    for (size_t i = 0; i < sizeof h1; i++) if (h1[i]) nonzero = true;
    EN_CHECK("the shape hash is stable across calls",
             memcmp(h1, h2, sizeof h1) == 0);
    EN_CHECK("and is not the empty digest of a hash that did nothing",
             nonzero);
    return failures;
}


/* ── the CLI argument vector ──────────────────────────────────────────────
 * CLI vendor arguments come from the registry, not a fixed array. */

static int case_cli_argv(void)
{
    int failures = 0;

    int turns = 77;
    EN_CHECK("CLI turns accepts the bounded decimal range",
             engine_cli_turns_parse("1", &turns) && turns == 1
             && engine_cli_turns_parse("256", &turns) && turns == 256);
    turns = 77;
    EN_CHECK("a missing CLI turn value is refused without changing output",
             !engine_cli_turns_parse(NULL, &turns) && turns == 77);
    const char *bad_turns[] = { "", "0", "257", "+1", " 1", "1 ",
        "1x", "999999999999999999999999" };
    for (size_t i = 0; i < sizeof(bad_turns) / sizeof(bad_turns[0]); i++) {
        const char *text = bad_turns[i];
        turns = 77;
        EN_CHECK("malformed CLI turns are refused without changing output",
                 !engine_cli_turns_parse(text, &turns) && turns == 77);
    }

    /* Every CLI row is complete, and no other row pretends to be one. */
    bool cli_rows_complete = true;
    bool non_cli_rows_clean = true;
    size_t cli_rows = 0;
    for (size_t i = 0; i < engine_count(); i++) {
        const struct engine_vendor *v = engine_at(i);
        if (v->wire == ENGINE_WIRE_LOCAL_CLI) {
            cli_rows++;
            if (!v->program || !v->program[0] || !v->start_argv)
                cli_rows_complete = false;
        } else if (v->program || v->start_argv) {
            non_cli_rows_clean = false;
        }
    }
    EN_CHECK("every CLI row names a program and an argument template",
             cli_rows_complete);
    EN_CHECK("and no non-CLI row carries either", non_cli_rows_clean);
    EN_CHECK("more than one CLI vendor is registered", cli_rows >= 2);

    const struct engine_vendor *grok_cap = engine_by_id("grok-cli");
    const struct engine_vendor *glm_cap = engine_by_id("glm-cli");
    EN_CHECK("Grok CLI explicitly accepts turns",
             grok_cap && engine_cli_accepts_turns(grok_cap));
    EN_CHECK("GLM does not claim a CLI turn slot",
             glm_cap && !engine_cli_accepts_turns(glm_cap));

    const struct engine_cli_inputs in = {
        .prompt  = "/p.txt",
        .workdir = "/w",
        .turns   = "3",
        .model   = "m-1",
        .reasoning_effort = "high",
    };
    const char *argv[ENGINE_CLI_ARGV_MAX];

    /* A file-mode vendor: the exact exec'd vector, not just its count. */
    const struct engine_vendor *fileq = NULL;
    const struct engine_vendor *argq = NULL;
    for (size_t i = 0; i < engine_count(); i++) {
        const struct engine_vendor *v = engine_at(i);
        if (v->wire != ENGINE_WIRE_LOCAL_CLI) continue;
        if (v->cli_prompt == ENGINE_CLI_PROMPT_FILE && !fileq) fileq = v;
        if (v->cli_prompt == ENGINE_CLI_PROMPT_ARG && !argq) argq = v;
    }
    EN_CHECK("a file-prompt CLI vendor is registered", fileq != NULL);
    EN_CHECK("an argument-prompt CLI vendor is registered", argq != NULL);

    if (fileq) {
        size_t n = engine_cli_argv_build(fileq, &in, argv, ENGINE_CLI_ARGV_MAX);
        EN_CHECK("a file-prompt vendor builds a vector", n > 0);
        EN_CHECK("whose argv[0] is the program",
                 n > 0 && strcmp(argv[0], fileq->program) == 0);
        EN_CHECK("which is NULL-terminated", n > 0 && argv[n] == NULL);
        bool carries_prompt = false, carries_workdir = false;
        bool carries_bypass = false, carries_no_plan = false;
        bool carries_model = false, carries_effort = false;
        bool carries_effort_flag = false, disables_subagents = false;
        bool disables_web = false, pins_tools = false;
        bool carries_no_placeholders = true;
        for (size_t i = 1; i < n; i++) {
            if (strcmp(argv[i], in.prompt) == 0)  carries_prompt = true;
            if (strcmp(argv[i], in.workdir) == 0) carries_workdir = true;
            if (strcmp(argv[i], "bypassPermissions") == 0)
                carries_bypass = true;
            if (strcmp(argv[i], "--no-plan") == 0) carries_no_plan = true;
            if (strcmp(argv[i], in.model) == 0) carries_model = true;
            if (strcmp(argv[i], in.reasoning_effort) == 0)
                carries_effort = true;
            if (strcmp(argv[i], "--reasoning-effort") == 0)
                carries_effort_flag = true;
            if (strcmp(argv[i], "--no-subagents") == 0)
                disables_subagents = true;
            if (strcmp(argv[i], "--disable-web-search") == 0)
                disables_web = true;
            if (strcmp(argv[i], "Read,Grep,Glob,Bash,Edit") == 0)
                pins_tools = true;
            if (argv[i][0] == '{') carries_no_placeholders = false;
        }
        EN_CHECK("and carries the prompt path", carries_prompt);
        EN_CHECK("and the working directory", carries_workdir);
        EN_CHECK("and selects the measured autonomous permission mode",
                 carries_bypass);
        EN_CHECK("and disables the interactive plan approval stop",
                 carries_no_plan);
        EN_CHECK("and passes the requested model", carries_model);
        EN_CHECK("and passes explicit reasoning effort as its own flag/value",
                 carries_effort_flag && carries_effort);
        EN_CHECK("and disables hidden subagent work", disables_subagents);
        EN_CHECK("and disables unrelated web retrieval", disables_web);
        EN_CHECK("and pins the observable repository tool schema", pins_tools);
        EN_CHECK("and no placeholder survived substitution",
                 carries_no_placeholders);
        struct engine_cli_inputs provider_default = in;
        provider_default.reasoning_effort =
            ENGINE_REASONING_EFFORT_PROVIDER_DEFAULT;
        n = engine_cli_argv_build(fileq, &provider_default, argv,
                                  ENGINE_CLI_ARGV_MAX);
        bool omitted_effort = n > 0;
        for (size_t i = 1; i < n; i++)
            if (strcmp(argv[i], "--reasoning-effort") == 0)
                omitted_effort = false;
        EN_CHECK("provider-default effort emits no empty CLI flag",
                 omitted_effort);
        struct engine_cli_inputs invalid_effort = in;
        invalid_effort.reasoning_effort = "maximum";
        EN_CHECK("an unknown CLI effort is refused",
                 engine_cli_argv_build(fileq, &invalid_effort, argv,
                                       ENGINE_CLI_ARGV_MAX) == 0);

        const struct engine_vendor *grok = engine_by_id("grok-cli");
        EN_CHECK("grok-cli exposes its resume argv", grok != NULL
                 && grok->resume_argv != NULL
                 && strcmp(grok->resume_argv[0], "--resume") == 0
                 && strcmp(grok->resume_argv[1], ENGINE_CLI_RESUME_TOKEN) == 0);
        if (grok) {
            EN_CHECK("resume accessor returns the registered extension",
                     engine_registry_resume_argv("grok-cli") == grok->resume_argv
                     && engine_registry_resume_argv("glm-cli") == NULL
                     && engine_registry_resume_argv("unknown-engine") == NULL);
            const char *session = "23c9be10-5084-43a4-8e1a-2735a4650981";
            struct engine_cli_inputs base_resume = in;
            base_resume.reasoning_effort = "low";
            struct engine_cli_inputs resumed = base_resume;
            resumed.resume_session_id = session;
            size_t base_n = engine_cli_argv_build(grok, &base_resume, argv,
                                                   ENGINE_CLI_ARGV_MAX);
            const char *base_argv[ENGINE_CLI_ARGV_MAX];
            memcpy(base_argv, argv, sizeof(base_argv));
            size_t resumed_n = engine_cli_argv_build(grok, &resumed, argv,
                                                      ENGINE_CLI_ARGV_MAX);
            size_t verbatim_hits = 0;
            for (size_t i = 0; i < resumed_n; i++)
                if (strcmp(argv[i], "--verbatim") == 0)
                    verbatim_hits++;
            EN_CHECK("Grok argv preserves the supplied prompt exactly once",
                     resumed_n > 0 && verbatim_hits == 1);
            bool has_resume = false, has_id = false, has_restore = false;
            bool preserved = resumed_n == base_n + 2;
            for (size_t i = 0; preserved && i < base_n; i++)
                preserved = strcmp(base_argv[i], argv[i]) == 0;
            for (size_t i = 1; i < resumed_n; i++) {
                if (strcmp(argv[i], "--resume") == 0) has_resume = true;
                if (strcmp(argv[i], session) == 0) has_id = true;
                if (strcmp(argv[i], "--restore-code") == 0) has_restore = true;
            }
            EN_CHECK("valid Grok resume appends exactly flag and session",
                     base_n > 0 && resumed_n == base_n + 2
                     && preserved && has_resume && has_id && !has_restore);
            EN_CHECK("Grok resume needs the additional argv capacity",
                     engine_cli_argv_build(grok, &base_resume, argv, base_n + 1) == base_n
                     && engine_cli_argv_build(grok, &resumed, argv, resumed_n)
                            == 0
                     && engine_cli_argv_build(grok, &resumed, argv, resumed_n + 1)
                            == resumed_n);
            const char *combined_argv[25];
            size_t combined_n = engine_cli_argv_build(grok, &resumed,
                                                       combined_argv, 25);
            EN_CHECK("Grok effort and resume fit 25 slots including NULL",
                     combined_n == 24 && combined_argv[combined_n] == NULL);
            EN_CHECK("Grok effort and resume refuse only 24 slots",
                     engine_cli_argv_build(grok, &resumed, combined_argv, 24)
                         == 0);
            struct engine_vendor malformed_resume = *grok;
            static const char *const unknown_resume[] = {
                "--resume", "{unknown_session}", NULL
            };
            malformed_resume.resume_argv = unknown_resume;
            EN_CHECK("an unknown resume placeholder is refused",
                     engine_cli_argv_build(&malformed_resume, &resumed, argv,
                                           ENGINE_CLI_ARGV_MAX) == 0);

            const char *bad[] = { "", " ",
                "23c9be10-5084-43a4-8e1a-2735a465098",
                "23c9be10-5084-43a4-8e1a-2735a4650981\n",
                "23C9BE10-5084-43A4-8E1A-2735A4650981", NULL };
            for (size_t i = 0; bad[i]; i++) {
                struct engine_cli_inputs invalid = in;
                invalid.resume_session_id = bad[i];
                EN_CHECK("malformed Grok resume session is refused",
                         engine_cli_argv_build(grok, &invalid, argv,
                                               ENGINE_CLI_ARGV_MAX) == 0);
            }
        }
    }

    if (argq) {
        const struct engine_cli_inputs argin = {
            .prompt  = "THE WHOLE PROMPT TEXT",
            .workdir = "/w",
            .turns   = "3",
            .model   = "m-1",
        };
        size_t n = engine_cli_argv_build(argq, &argin, argv,
                                         ENGINE_CLI_ARGV_MAX);
        bool carries_text = false;
        for (size_t i = 1; i < n; i++)
            if (strcmp(argv[i], argin.prompt) == 0) carries_text = true;
        EN_CHECK("an argument-prompt vendor receives the prompt TEXT, not a "
                 "path", n > 0 && carries_text);
        struct engine_cli_inputs unsupported = argin;
        unsupported.reasoning_effort = "low";
        EN_CHECK("a CLI with no effort flag refuses an explicit effort",
                 engine_cli_argv_build(argq, &unsupported, argv,
                                       ENGINE_CLI_ARGV_MAX) == 0);
        unsupported.reasoning_effort = NULL;
        unsupported.resume_session_id =
            "23c9be10-5084-43a4-8e1a-2735a4650981";
        EN_CHECK("an unsupported CLI refuses a resume session",
                 engine_cli_argv_build(argq, &unsupported, argv,
                                       ENGINE_CLI_ARGV_MAX) == 0);

        /* The kernel caps one argv string far below the prompt ceiling. */
        size_t over = ENGINE_CLI_ARG_PROMPT_MAX + 1u;
        char *huge = zcl_malloc(over + 1, "test_engine_cli_huge");
        if (huge) {
            memset(huge, 'x', over);
            huge[over] = '\0';
            struct engine_cli_inputs bigin = argin;
            bigin.prompt = huge;
            EN_CHECK("an argument-mode prompt over the limit is refused",
                     engine_cli_argv_build(argq, &bigin, argv,
                                           ENGINE_CLI_ARGV_MAX) == 0);
            free(huge);
        } else {
            EN_CHECK("the over-length CLI fixture allocates", false);
        }
    }

    /* A placeholder the caller left empty is a refusal, not an empty slot: an
     * argv entry silently filled with nothing is a different command. */
    if (fileq) {
        struct engine_cli_inputs missing = in;
        missing.workdir = NULL;
        EN_CHECK("a placeholder with no value is refused",
                 engine_cli_argv_build(fileq, &missing, argv,
                                       ENGINE_CLI_ARGV_MAX) == 0);
        missing = in;
        missing.workdir = "";
        EN_CHECK("and an empty string counts as no value",
                 engine_cli_argv_build(fileq, &missing, argv,
                                       ENGINE_CLI_ARGV_MAX) == 0);
        EN_CHECK("a cap too small to hold the vector is refused",
                 engine_cli_argv_build(fileq, &in, argv, 2) == 0);
    }

    /* An unknown brace-shaped slot is refused rather than passed through as a
     * literal, which is what a CLI would receive as a confident wrong value. */
    static const char *const bogus_argv[] = { "--flag", "{mdoel}", NULL };
    struct engine_vendor bogus = {
        .id = "bogus", .program = "true",
        .start_argv = bogus_argv, .cli_prompt = ENGINE_CLI_PROMPT_FILE,
        .wire = ENGINE_WIRE_LOCAL_CLI,
    };
    EN_CHECK("an unknown placeholder is refused, not passed through",
             engine_cli_argv_build(&bogus, &in, argv, ENGINE_CLI_ARGV_MAX) == 0);

    struct engine_vendor no_template = bogus;
    no_template.start_argv = NULL;
    EN_CHECK("a CLI row with no template is refused",
             engine_cli_argv_build(&no_template, &in, argv,
                                   ENGINE_CLI_ARGV_MAX) == 0);
    EN_CHECK("and NULL arguments are refused",
             engine_cli_argv_build(NULL, &in, argv, ENGINE_CLI_ARGV_MAX) == 0
             && engine_cli_argv_build(fileq, NULL, argv,
                                      ENGINE_CLI_ARGV_MAX) == 0);
    return failures;
}

static int case_cli_observation(void)
{
    int failures = 0;
    static const char good[] =
        "{\"text\":\"done\",\"stopReason\":\"end_turn\","
        "\"sessionId\":\"23c9be10-5084-43a4-8e1a-2735a4650981\","
        "\"requestId\":\"ddc16017-2c5f-4c34-9fa9-ce50a4ec48a0\","
        "\"thought\":\"must never escape\","
        "\"usage\":{\"input_tokens\":100,"
        "\"cache_read_input_tokens\":60,"
        "\"cache_creation_input_tokens\":10,\"output_tokens\":25,"
        "\"reasoning_tokens\":7,\"total_tokens\":125},"
        "\"num_turns\":4,\"total_cost_usd\":0.125,"
        "\"modelUsage\":{\"grok-4.6-build\":{\"inputTokens\":100,"
        "\"outputTokens\":25,\"cacheReadInputTokens\":60,"
        "\"cacheCreationInputTokens\":10,\"modelCalls\":4,"
        "\"costUSD\":0.125}}}";
    struct engine_cli_observation observed;
    bool ok = engine_cli_observation_parse(engine_by_id("grok-cli"), good,
                                            sizeof(good) - 1u, &observed);
    EN_CHECK("Grok CLI observable metadata parses",
             ok && observed.known
             && strcmp(observed.resolved_model, "grok-4.6-build") == 0
             && strcmp(observed.session_id,
                       "23c9be10-5084-43a4-8e1a-2735a4650981") == 0
             && observed.turns == 4 && observed.input_tokens == 100
             && observed.cache_read_input_tokens == 60
             && observed.cache_creation_input_tokens == 10
             && observed.output_tokens == 25
             && observed.reasoning_tokens == 7
             && observed.total_tokens == 125);

    /* Both Grok accounting shapes (cache-inclusive input, additive cache
     * reads) are accepted only when the total is arithmetically consistent. */
    static const char additive_cache[] =
        "{\"text\":\"done\",\"stopReason\":\"cancelled\","
        "\"sessionId\":\"8a79ed87-5aaa-4924-b75d-f29a52ac3818\","
        "\"requestId\":\"db6794ee-c1e6-4bc8-9b9c-3961c6382f16\","
        "\"usage\":{\"input_tokens\":231579,"
        "\"cache_read_input_tokens\":265088,"
        "\"cache_creation_input_tokens\":0,\"output_tokens\":9830,"
        "\"reasoning_tokens\":8841,\"total_tokens\":506497},"
        "\"num_turns\":10,\"modelUsage\":{\"grok-4.6-build\":{"
        "\"inputTokens\":231579,\"outputTokens\":9830,"
        "\"cacheReadInputTokens\":265088,"
        "\"cacheCreationInputTokens\":0,\"modelCalls\":10}}}";
    memset(&observed, 0xa5, sizeof(observed));
    ok = engine_cli_observation_parse(
        engine_by_id("grok-cli"), additive_cache,
        sizeof(additive_cache) - 1u, &observed);
    EN_CHECK("additive Grok cache accounting parses exactly",
             ok && observed.known && observed.input_tokens == 231579 &&
             observed.cache_read_input_tokens == 265088 &&
             observed.output_tokens == 9830 &&
             observed.total_tokens == 506497);

    memset(&observed, 0xa5, sizeof(observed));
    ok = engine_cli_observation_parse(engine_by_id("glm-cli"), "not json", 8u,
                                      &observed);
    EN_CHECK("plain CLI metadata stays truthful UNKNOWN",
             ok && !observed.known && observed.session_id[0] == '\0');

    static const char bad_total[] =
        "{\"text\":\"done\",\"stopReason\":\"end_turn\","
        "\"sessionId\":\"s\",\"requestId\":\"r\","
        "\"usage\":{\"input_tokens\":100,"
        "\"cache_read_input_tokens\":60,"
        "\"cache_creation_input_tokens\":10,\"output_tokens\":25,"
        "\"reasoning_tokens\":7,\"total_tokens\":124},"
        "\"num_turns\":4,\"modelUsage\":{\"grok-4.6-build\":{"
        "\"inputTokens\":100,\"outputTokens\":25,"
        "\"cacheReadInputTokens\":60,\"cacheCreationInputTokens\":10,"
        "\"modelCalls\":4,\"costUSD\":0.125}}}";
    memset(&observed, 0xa5, sizeof(observed));
    EN_CHECK("inconsistent Grok totals fail closed atomically",
             !engine_cli_observation_parse(engine_by_id("grok-cli"),
                                            bad_total,
                                            sizeof(bad_total) - 1u, &observed)
             && !observed.known && observed.resolved_model[0] == '\0');

    char missing[sizeof(good)];
    memcpy(missing, good, sizeof(good));
    char *session_key = strstr(missing, "sessionId");
    if (session_key) session_key[0] = 'x';
    memset(&observed, 0xa5, sizeof(observed));
    EN_CHECK("missing required Grok metadata fails closed atomically",
             session_key != NULL &&
             !engine_cli_observation_parse(engine_by_id("grok-cli"), missing,
                                            sizeof(good) - 1u, &observed)
             && !observed.known && observed.session_id[0] == '\0');

    char negative[sizeof(good)];
    memcpy(negative, good, sizeof(good));
    char *input_count = strstr(negative, "input_tokens\":100");
    if (input_count) {
        input_count = strchr(input_count, ':');
        if (input_count) memcpy(input_count + 1, "-10", 3u);
    }
    memset(&observed, 0xa5, sizeof(observed));
    EN_CHECK("negative Grok metadata fails closed atomically",
             input_count != NULL &&
             !engine_cli_observation_parse(engine_by_id("grok-cli"), negative,
                                            sizeof(good) - 1u, &observed)
             && !observed.known && observed.total_tokens == 0);

    static const char huge_integer[] =
        "{\"text\":\"done\",\"stopReason\":\"end_turn\","
        "\"sessionId\":\"s\",\"requestId\":\"r\","
        "\"usage\":{\"input_tokens\":9223372036854775808,"
        "\"cache_read_input_tokens\":0,"
        "\"cache_creation_input_tokens\":0,\"output_tokens\":0,"
        "\"reasoning_tokens\":0,\"total_tokens\":0},"
        "\"num_turns\":1,\"modelUsage\":{\"m\":{"
        "\"inputTokens\":0,\"outputTokens\":0,"
        "\"cacheReadInputTokens\":0,\"cacheCreationInputTokens\":0,"
        "\"modelCalls\":1}}}";
    memset(&observed, 0xa5, sizeof(observed));
    EN_CHECK("overflowing Grok metadata fails closed atomically",
             !engine_cli_observation_parse(engine_by_id("grok-cli"),
                                            huge_integer,
                                            sizeof(huge_integer) - 1u,
                                            &observed)
             && !observed.known && observed.input_tokens == 0);

    char nul_body[sizeof(good)];
    memcpy(nul_body, good, sizeof(good));
    nul_body[20] = '\0';
    memset(&observed, 0xa5, sizeof(observed));
    EN_CHECK("embedded NUL Grok metadata fails closed atomically",
             !engine_cli_observation_parse(engine_by_id("grok-cli"), nul_body,
                                            sizeof(good) - 1u, &observed)
             && !observed.known && observed.request_id[0] == '\0');
    return failures;
}


/* ── the default engine ─────────────────────────────────────────────────── */
static int case_default_engine(void)
{
    int failures = 0;

    size_t defaults = 0;
    for (size_t i = 0; i < engine_count(); i++)
        if (engine_at(i)->is_default) defaults++;
    EN_CHECK("exactly one row is the default", defaults == 1);

    const struct engine_vendor *d = engine_default();
    EN_CHECK("and engine_default() returns it", d != NULL && d->is_default);
    EN_CHECK("and it is a row the registry can look up by id",
             d && engine_by_id(d->id) == d);

    EN_CHECK("the default needs no API key", d && !engine_needs_key(d));

    /* The default must work with no credential and must not be the fixture. */
    EN_CHECK("the default is not the fixture engine",
             d && !engine_is_fixture(d));
    return failures;
}


/* ── prompt templates, keyed by task kind ───────────────────────────────
 * A kind missing a required section is refused before dispatch; --kind wins
 * over a `kind:` header. */

static const char *select_kind(const char *flag, const char *task)
{
    if (flag && flag[0])
        return flag;
    return engine_prompt_kind_from_header(task);
}

static int case_c23_prompt_selection(void)
{
    static const struct {
        const char *kind;
        const char *exemplar;
    } patterns[] = {
        {"c23-byte-validator", "zutf8_decode_n"},
        {"c23-command-handler", "zcl_native_handle_code_have"},
        {"c23-model-save", "db_contact_save"},
        {"c23-regression-fixture", "case_rewrite"},
        {"c23-wire-codec", "vcs_zcode_action_input_parse"},
        {"c23-cas-operation", "vcs_object_load_raw_bounded"},
        {"c23-service-operation", "service_state_persist_to_progress_store"},
        {"c23-resource-owner", "qr_matrix_render_rgb"},
    };
    int failures = 0;
    uint8_t previous[32] = {0};
    for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
        char header[128];
        (void)snprintf(header, sizeof(header), "kind: %s\n\nowned task\n",
                       patterns[i].kind);
        const char *selected = select_kind(NULL, header);
        EN_CHECK("C23 task header selects a complete dispatch kind",
                 selected && strcmp(selected, patterns[i].kind) == 0 &&
                 engine_prompt_kind_is_complete(selected));
        const char *task = engine_prompt_template_body(selected, "task");
        const char *rules = engine_prompt_template_body(selected, "rules");
        EN_CHECK("selected procedure binds an exemplar and required inputs",
                 task && strstr(task, patterns[i].exemplar) && rules &&
                 strstr(rules, "report the missing input"));
        size_t bytes = 0;
        for (size_t s = 0; s < engine_prompt_section_count(); s++) {
            const struct engine_prompt_section *sec = engine_prompt_section_at(s);
            const char *body = engine_prompt_template_body(selected, sec->id);
            if (body) bytes += strlen(body);
        }
        EN_CHECK("selected C23 procedure stays within 1800 text bytes",
                 bytes > 0 && bytes <= 1800);
        uint8_t digest[32];
        engine_prompt_template_sha3(selected, digest);
        EN_CHECK("receipt template identity distinguishes selected procedures",
                 memcmp(previous, digest, sizeof(digest)) != 0);
        memcpy(previous, digest, sizeof(previous));
        for (size_t j = 0; task && j < sizeof(patterns) / sizeof(patterns[0]); j++)
            EN_CHECK("selection excludes other procedures' exemplar bodies",
                     i == j || strstr(task, patterns[j].exemplar) == NULL);
    }
    return failures;
}

static int case_template_wire(void)
{
    int failures = 0;
    for (size_t i = 0; i < engine_prompt_kind_count(); i++) {
        const char *kind = engine_prompt_kind_at(i);
        uint8_t *wire = NULL;
        size_t len = 0, expected_len = 4;
        uint32_t rows = 0;
        for (size_t s = 0; s < engine_prompt_section_count(); s++) {
            const struct engine_prompt_section *sec = engine_prompt_section_at(s);
            const char *body = engine_prompt_template_body(kind, sec->id);
            if (!body) continue;
            rows++;
            expected_len += 8 + strlen(sec->id) + strlen(body);
        }
        bool serialized = engine_prompt_template_serialize(kind, &wire, &len);
        EN_CHECK("template wire length includes only canonical framing and rows",
                 serialized && len == expected_len &&
                 len <= ENGINE_PROMPT_TEMPLATE_MAX_BYTES &&
                 wire[0] == 0 && wire[1] == 0 && wire[2] == 0 &&
                 wire[3] == rows);
        if (serialized) {
            uint8_t historical[32], actual[32];
            engine_prompt_template_sha3(kind, historical);
            zcl_sha3_256(wire, len, actual);
            EN_CHECK("canonical template bytes preserve historical receipt root",
                     memcmp(historical, actual, sizeof(actual)) == 0);
        }
        free(wire);
    }
    uint8_t sentinel = 0;
    uint8_t *wire = &sentinel;
    size_t len = 7;
    EN_CHECK("unknown template clears serialization outputs",
             !engine_prompt_template_serialize("absent", &wire, &len) &&
             wire == NULL && len == 0);
    EN_CHECK("missing serialization output is refused",
             !engine_prompt_template_serialize("fix-gate", NULL, &len) &&
             len == 0);
    return failures;
}

/* Every kind declares a capability floor; a new kind without a tier row
 * must fail here. */
static int case_prompt_tiers(void)
{
    int failures = 0;
    bool every_kind_tiered = true;
    for (size_t i = 0; i < engine_prompt_kind_count(); i++) {
        if (engine_prompt_kind_tier(engine_prompt_kind_at(i))
            == ENGINE_PROMPT_TIER_UNKNOWN)
            every_kind_tiered = false;
    }
    EN_CHECK("every declared kind has a tier row", every_kind_tiered);
    EN_CHECK("context-pack, gate-tail and proof-triage are light",
             engine_prompt_kind_tier("c23-context-pack")
                 == ENGINE_PROMPT_TIER_LIGHT
             && engine_prompt_kind_tier("c23-gate-tail")
                 == ENGINE_PROMPT_TIER_LIGHT
             && engine_prompt_kind_tier("c23-proof-triage")
                 == ENGINE_PROMPT_TIER_LIGHT);
    EN_CHECK("a code-writing kind is standard",
             engine_prompt_kind_tier("c23-regression-fixture")
             == ENGINE_PROMPT_TIER_STANDARD);
    EN_CHECK("NULL and an unknown kind have no tier",
             engine_prompt_kind_tier(NULL) == ENGINE_PROMPT_TIER_UNKNOWN
             && engine_prompt_kind_tier("half-done")
                 == ENGINE_PROMPT_TIER_UNKNOWN);
    EN_CHECK("tier names map each enum value",
             strcmp(engine_prompt_tier_name(ENGINE_PROMPT_TIER_UNKNOWN),
                    "unknown") == 0
             && strcmp(engine_prompt_tier_name(ENGINE_PROMPT_TIER_LIGHT),
                       "light") == 0
             && strcmp(engine_prompt_tier_name(ENGINE_PROMPT_TIER_STANDARD),
                       "standard") == 0
             && strcmp(engine_prompt_tier_name((enum engine_prompt_tier)99),
                       "unknown") == 0);
    const char *why = "unset";
    EN_CHECK("tier rows and template kinds agree both ways",
             engine_prompt_tiers_closed(&why) && why == NULL);
    EN_CHECK("closure check accepts a NULL out-pointer",
             engine_prompt_tiers_closed(NULL));
    return failures;
}

static int case_prompt_templates(void)
{
    int failures = 0;

    EN_CHECK("at least one prompt kind is declared",
             engine_prompt_kind_count() > 0);
    EN_CHECK("an index past the last kind has no name",
             engine_prompt_kind_at(engine_prompt_kind_count()) == NULL);

    bool every_kind_complete = true;
    bool every_always_filled = true;
    size_t always = 0;
    for (size_t i = 0; i < engine_prompt_kind_count(); i++) {
        const char *kind = engine_prompt_kind_at(i);
        if (!kind || !engine_prompt_kind_is_complete(kind))
            every_kind_complete = false;
        for (size_t s = 0; s < engine_prompt_section_count(); s++) {
            const struct engine_prompt_section *sec = engine_prompt_section_at(s);
            if (!sec || sec->need != ENGINE_PROMPT_NEED_ALWAYS)
                continue;
            always++;
            const char *body = engine_prompt_template_body(kind, sec->id);
            if (!body || !body[0])
                every_always_filled = false;
        }
    }
    EN_CHECK("every declared kind is selectable", every_kind_complete);
    EN_CHECK("and supplies a body for every always-required section",
             every_always_filled && always > 0);

    EN_CHECK("a kind missing a required section is refused",
             !engine_prompt_kind_is_complete("half-done"));
    EN_CHECK("an unknown kind is not a silent fallback to another kind's words",
             engine_prompt_template_body("half-done", "task") == NULL);
    EN_CHECK("a real kind supplies no body for a section it did not declare",
             engine_prompt_template_body("review", "territory") == NULL);
    EN_CHECK("fix-gate and add-test do not share a task body",
             engine_prompt_template_body("fix-gate", "task") != NULL
             && engine_prompt_template_body("add-test", "task") != NULL
             && strcmp(engine_prompt_template_body("fix-gate", "task"),
                       engine_prompt_template_body("add-test", "task")) != 0);

    failures += case_prompt_tiers();

    const char *headed =
        "kind: add-test\n"
        "\n"
        "write a test that fails first\n";
    const char *from_header = engine_prompt_kind_from_header(headed);
    EN_CHECK("a kind: header line selects that kind",
             from_header && strcmp(from_header, "add-test") == 0);
    EN_CHECK("--kind wins over the task file's header",
             strcmp(select_kind("review", headed), "review") == 0);
    EN_CHECK("without --kind the header kind is used",
             strcmp(select_kind(NULL, headed), "add-test") == 0);
    EN_CHECK("a kind after a blank line is not a header",
             engine_prompt_kind_from_header("task prose\n\nkind: review\n")
             == NULL);
    EN_CHECK("an empty --kind still reads the header",
             strcmp(select_kind("", headed), "add-test") == 0);
    return failures;
}

/* ── carried state (engine/engine_state.h) ───────────────────────────────
 * Extraction, omission (carry forward unchanged), last-block-wins,
 * attempt-vs-turn prepend ordering, and compaction. */

static int case_state(void)
{
    int failures = 0;
    char out[ENGINE_STATE_MAX_BYTES];
    size_t out_len = 0;

    {
        static const char reply[] =
            "Here is my work.\n\n"
            "<state>\n"
            "tried: read the failing assertion\n"
            "gate: not run yet\n"
            "hypothesis: an off-by-one in the loop bound\n"
            "next: fix the bound and re-run\n"
            "</state>\n";
        const bool ok = engine_state_extract(reply, sizeof(reply) - 1, out,
                                             sizeof(out), &out_len);
        EN_CHECK("a reply carrying a state block is extracted", ok);
        EN_CHECK("the extracted text is trimmed and exact",
                 ok && out_len > 0
                 && strstr(out, "off-by-one") != NULL
                 && out[0] != '\n' && out[0] != ' ');
    }
    {
        static const char no_envelope[] =
            "<state>\ntried: nothing, this reply never proposes a file\n"
            "gate: none yet\nhypothesis: none\nnext: think more\n</state>\n";
        EN_CHECK("extraction does not require an envelope at all",
                 engine_state_extract(no_envelope, sizeof(no_envelope) - 1,
                                      out, sizeof(out), &out_len));
    }
    {
        static const char none[] = "Sure, here is a fix.\nNo block here.\n";
        out[0] = 'X';
        EN_CHECK("a reply that omits the block is reported as not found",
                 !engine_state_extract(none, sizeof(none) - 1, out,
                                       sizeof(out), &out_len));
    }
    {
        /* The last complete block wins, as in engine_patch.c. */
        static const char twice[] =
            "<state>\ntried: FIRST DRAFT, discard this\n</state>\n"
            "more thinking...\n"
            "<state>\ntried: SECOND DRAFT, this is the real one\n</state>\n";
        const bool ok = engine_state_extract(twice, sizeof(twice) - 1, out,
                                             sizeof(out), &out_len);
        EN_CHECK("a reply with two blocks keeps the LAST one",
                 ok && strstr(out, "SECOND DRAFT") != NULL
                 && strstr(out, "FIRST DRAFT") == NULL);
    }
    {
        static const char truncated[] =
            "<state>\ntried: this one never closes";
        EN_CHECK("an unclosed block is not a match",
                 !engine_state_extract(truncated, sizeof(truncated) - 1, out,
                                       sizeof(out), &out_len));
    }
    EN_CHECK("a NULL text is not found",
             !engine_state_extract(NULL, 0, out, sizeof(out), &out_len));
    {
        static const char big_open[] = "<state>";
        static const char *closer = "</state>";
        char huge[ENGINE_STATE_MAX_BYTES * 2];
        size_t n = 0;
        memcpy(huge, big_open, strlen(big_open));
        n += strlen(big_open);
        memset(huge + n, 'a', sizeof(huge) - n - strlen(closer) - 1);
        n = sizeof(huge) - strlen(closer) - 1;
        memcpy(huge + n, closer, strlen(closer));
        n += strlen(closer);
        const bool ok = engine_state_extract(huge, n, out, sizeof(out),
                                             &out_len);
        EN_CHECK("an over-long block is truncated, not refused",
                 ok && out_len == sizeof(out) - 1);
    }

    /* ── the carried-state preamble ── */
    {
        char buf[512];
        const size_t n = engine_state_format_preamble(buf, sizeof(buf),
                                                       "my state", NULL);
        EN_CHECK("the within-run wording says 'previous turn'",
                 n > 0 && strstr(buf, "previous turn") != NULL
                 && strstr(buf, "my state") != NULL);
    }
    {
        char buf[512];
        const size_t n = engine_state_format_preamble(buf, sizeof(buf),
                                                       "prior attempt's state",
                                                       "3");
        EN_CHECK("a non-NULL attempt label says 'attempt 3'",
                 n > 0 && strstr(buf, "attempt 3") != NULL
                 && strstr(buf, "prior attempt's state") != NULL);
    }
    {
        char buf[64] = "unchanged";
        EN_CHECK("no state writes nothing",
                 engine_state_format_preamble(buf, sizeof(buf), NULL, NULL)
                     == 0
                 && strcmp(buf, "unchanged") == 0);
    }
    {
        /* The order tools/engine_unit.c's build_carried_preamble() relies
         * on: an attempt's carried state, from an earlier --state-dir, comes
         * before this run's own latest turn state. */
        char buf[1024];
        size_t n = engine_state_format_preamble(buf, sizeof(buf),
                                                "ATTEMPT-STATE-TEXT", "1");
        n += engine_state_format_preamble(buf + n, sizeof(buf) - n,
                                          "TURN-STATE-TEXT", NULL);
        const char *attempt_at = strstr(buf, "ATTEMPT-STATE-TEXT");
        const char *turn_at = strstr(buf, "TURN-STATE-TEXT");
        EN_CHECK("both pieces are present and the attempt's comes first",
                 attempt_at && turn_at && attempt_at < turn_at);
    }

    /* ── does `next:` hand off to a human? ── */
    {
        static const char op[] =
            "tried: two file rewrites\n"
            "gate: still red\n"
            "hypothesis: leftovers from an earlier overwrite\n"
            "next: Operator: restore tests/harness/src/test_impact_composition.c "
            "from the pre-overwrite revision\n";
        EN_CHECK("a next: line naming Operator: is surfaced",
                 engine_state_next_is_operator(op, sizeof(op) - 1));
    }
    {
        static const char no_op[] =
            "tried: fixed the header\n"
            "gate: none yet\n"
            "hypothesis: should compile now\n"
            "next: run the gate\n";
        EN_CHECK("an ordinary next: line is not surfaced as an operator ask",
                 !engine_state_next_is_operator(no_op, sizeof(no_op) - 1));
    }
    {
        /* "Operator" appearing in some OTHER field must not trip this —
         * only the next: line's own value counts. */
        static const char mentions_elsewhere[] =
            "tried: asked whether an Operator override was set\n"
            "gate: none yet\n"
            "hypothesis: none\n"
            "next: keep going\n";
        EN_CHECK("a mention of Operator outside next: does not count",
                 !engine_state_next_is_operator(mentions_elsewhere,
                                                sizeof(mentions_elsewhere) - 1));
    }
    EN_CHECK("an empty state is never an operator ask",
             !engine_state_next_is_operator("", 0)
             && !engine_state_next_is_operator(NULL, 0));

    /* ── compaction ── */
    EN_CHECK("a small prompt does not need compaction",
             !engine_state_needs_compaction(200, 200, 4096, ENGINE_MAX_PROMPT_BYTES));
    EN_CHECK("a prompt at the budget's edge needs compaction",
             engine_state_needs_compaction(ENGINE_STATE_MAX_BYTES,
                                           4096, ENGINE_MAX_PROMPT_BYTES,
                                           ENGINE_MAX_PROMPT_BYTES));
    {
        char comp[8192];
        const size_t n = engine_state_compaction_prompt(
            comp, sizeof(comp), "my carried state so far",
            "First actionable line: none\n...tail...");
        EN_CHECK("the compaction prompt carries the state and the gate tail",
                 n > 0 && strstr(comp, "my carried state so far") != NULL
                 && strstr(comp, "...tail...") != NULL);
        EN_CHECK("the compaction prompt does not invite a file envelope",
                 strstr(comp, "Z23-BEGIN-FILE") == NULL
                 && strstr(comp, "propose file changes") != NULL);
    }

    printf("engine: %d failure(s)\n", failures);
    return failures;
}

/* ── the turn loop end to end (fixture engine) ───────────────────────────
 * Runs the standalone binary with --engine fixture across two turns and
 * checks state.txt after turn 1 and that prompt.txt (turn 2) carries it. */

static const char ENGINE_UNIT_BIN[] = "build/bin/zclassic23-engine-unit";

static bool engine_unit_binary_present(void)
{
    FILE *f = fopen(ENGINE_UNIT_BIN, "rb");
    if (!f)
        return false;
    (void)fclose(f);
    return true;
}

static bool write_whole_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    const size_t len = strlen(content);
    const bool ok = fwrite(content, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

static bool read_whole_file(const char *path, char *out, size_t out_cap)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    const size_t n = fread(out, 1, out_cap - 1, f);
    (void)fclose(f);
    out[n] = '\0';
    return true;
}

static bool template_cas_matches(const char *workspace, const char *kind)
{
    uint8_t *expected = NULL, *actual = NULL;
    size_t expected_len = 0, actual_len = 0;
    uint8_t root[32], observed[32];
    bool ok = engine_prompt_template_serialize(kind, &expected, &expected_len);
    engine_prompt_template_sha3(kind, root);
    ok = ok && vcs_object_load_raw_bounded(
        workspace, root, ENGINE_PROMPT_TEMPLATE_MAX_BYTES,
        &actual, &actual_len) == 0;
    if (ok) {
        zcl_sha3_256(actual, actual_len, observed);
        ok = actual_len == expected_len &&
             memcmp(root, observed, sizeof(root)) == 0 &&
             memcmp(actual, expected, expected_len) == 0;
    }
    free(expected);
    free(actual);
    return ok;
}

static bool unit_fixture_completed(int rc)
{
#if defined(_WIN32)
    return rc == 1;
#else
    return rc >= 0 && WIFEXITED(rc) && WEXITSTATUS(rc) == 1;
#endif
}

static int case_template_cas_corruption(const char *cmd, const char *object_path,
                                       const char *chain_path,
                                       const char *log_path)
{
    int failures = 0;
    struct stat before, after;
    bool measured = stat(chain_path, &before) == 0;
    bool corrupted = write_whole_file(object_path, "invalid-template");
    int rc = system(cmd);
    char log[8192] = {0};
    EN_CHECK("corrupt existing CAS refuses before any provider receipt",
             corrupted && measured && !unit_fixture_completed(rc) &&
             stat(chain_path, &after) == 0 &&
             before.st_size == after.st_size &&
             read_whole_file(log_path, log, sizeof(log)) &&
             strstr(log, "refusing before provider dispatch"));
    EN_CHECK("refusal preserves conflicting CAS bytes",
             read_whole_file(object_path, log, sizeof(log)) &&
             strcmp(log, "invalid-template") == 0);
    return failures;
}

static int case_template_cas_dispatch(const char *cmd, const char *workspace,
                                      const char *chain_path,
                                      const char *log_path)
{
    int failures = 0;
    const char *kind = "fix-gate";
    EN_CHECK("dispatch persists exact selected template in existing CAS",
             template_cas_matches(workspace, kind));
    uint8_t root[32];
    char hex[65], object_path[1024];
    engine_prompt_template_sha3(kind, root);
    zcl_hex_encode(root, sizeof(root), hex);
    int n = snprintf(object_path, sizeof(object_path),
                      "%s/.zvcs/objects/%.2s/%s", workspace, hex, hex + 2);
    if (n < 0 || (size_t)n >= sizeof(object_path)) {
        EN_CHECK("template fixture object path fits", false);
        return failures;
    }
    struct stat first, repeated;
    bool first_stat = stat(object_path, &first) == 0;
    int repeated_rc = system(cmd);
    EN_CHECK("repeated dispatch retains exact existing template object",
             unit_fixture_completed(repeated_rc) && first_stat &&
             stat(object_path, &repeated) == 0 &&
             first.st_ino == repeated.st_ino &&
             template_cas_matches(workspace, kind));
    bool removed = unlink(object_path) == 0;
    int missing_rc = system(cmd);
    EN_CHECK("missing selected template is restored from canonical local bytes",
             unit_fixture_completed(missing_rc) && removed &&
             template_cas_matches(workspace, kind));
    failures += case_template_cas_corruption(cmd, object_path, chain_path,
                                             log_path);
    return failures;
}

static int case_receipt_absent_attempt(const char *chain, bool have_chain)
{
    int failures = 0;
    EN_CHECK("legacy owner without attempt id serializes null",
             have_chain && strstr(chain, "\"attempt_id\":null"));
    return failures;
}

static int case_engine_unit_state_e2e(void)
{
    int failures = 0;

    if (!engine_unit_binary_present()) {
        printf("engine: FAIL (%s is a required test prerequisite for the "
               "state-carrying end-to-end case; nothing can be asserted "
               "without it)\n", ENGINE_UNIT_BIN);
        return 1;
    }

    char rel_dir[512], dir[600];
    test_make_tmpdir(rel_dir, sizeof(rel_dir), "engine_state_e2e", "run");
    /* tools/engine_unit.c refuses relative --worktree/--state-dir. */
    if (!test_abs_path(rel_dir, dir, sizeof(dir))) {
        printf("engine: FAIL (could not absolutize the e2e fixture dir)\n");
        return 1;
    }
    char task_path[700], reply_path[700], state_dir[700], worktree[700];
    (void)snprintf(task_path, sizeof(task_path), "%s/task.txt", dir);
    (void)snprintf(reply_path, sizeof(reply_path), "%s/reply.json", dir);
    (void)snprintf(state_dir, sizeof(state_dir), "%s/state", dir);
    (void)snprintf(worktree, sizeof(worktree), "%s/wt", dir);
#if defined(_WIN32)
    _mkdir(state_dir);
    _mkdir(worktree);
#else
    mkdir(state_dir, 0700);
    /* git worktree add cannot target a path inside this checkout (and a
     * git-worktree lane is already a worktree). The unit accepts an
     * existing directory; the fixture only needs that arm. */
    mkdir(worktree, 0700);
#endif

    const bool wrote_task = write_whole_file(task_path,
        "kind: fix-gate\n\nA smoke task; the fixture engine never reads "
        "this beyond composing a prompt around it.\n");
    /* An OpenAI-dialect response body (dispatch_fixture() pushes the canned
     * file through the SAME hardened decoder a real HTTPS reply would go
     * through), whose message content ends with a <state> block. */
    const bool wrote_reply = write_whole_file(reply_path,
        "{\"choices\":[{\"message\":{\"content\":"
        "\"No file changes this turn.\\n\\n<state>\\n"
        "tried: turn one of the e2e fixture check\\n"
        "gate: none yet\\n"
        "hypothesis: turn two should see this exact sentence\\n"
        "next: nothing, this is a fixture\\n"
        "</state>\\n\"}}],\"usage\":{\"prompt_tokens\":10,"
        "\"completion_tokens\":4,\"total_tokens\":14,"
        "\"prompt_tokens_details\":{\"cached_tokens\":6},"
        "\"completion_tokens_details\":{\"reasoning_tokens\":2}}}");
    EN_CHECK("fixtures for the e2e case are written", wrote_task && wrote_reply);
    if (!wrote_task || !wrote_reply)
        return failures + 1;

    char cmd[2048];
    (void)snprintf(cmd, sizeof(cmd),
        "%s --engine fixture --task %s --no-group --yes-dispatch "
        "--worktree %s --state-dir %s --fixture-reply %s --turns 2 "
        ">%s/run.log 2>&1",
        ENGINE_UNIT_BIN, task_path, worktree, state_dir, reply_path, dir);
     TEST_DISCARD(system(cmd)); /* verdict is read from the files it wrote, not this */

    char state_txt[512] = {0};
    char prompt_txt[64 * 1024] = {0};
    char state_txt_path[700], prompt_txt_path[700], receipt_path[700];
    char chain_path[700];
    (void)snprintf(state_txt_path, sizeof(state_txt_path), "%s/state.txt",
                   state_dir);
    (void)snprintf(prompt_txt_path, sizeof(prompt_txt_path),
                   "%s/prompt.txt", state_dir);
    (void)snprintf(receipt_path, sizeof(receipt_path), "%s/receipt.json",
                   state_dir);
    (void)snprintf(chain_path, sizeof(chain_path), "%s/%s", state_dir,
                   ENGINE_RECEIPT_FILENAME);
    const bool have_state = read_whole_file(state_txt_path, state_txt,
                                            sizeof(state_txt));
    const bool have_prompt = read_whole_file(prompt_txt_path, prompt_txt,
                                             sizeof(prompt_txt));
    char receipt[8192] = {0};
    const bool have_receipt = read_whole_file(receipt_path,receipt,
                                              sizeof(receipt));
    char chain[32768] = {0};
    const bool have_chain = read_whole_file(chain_path, chain, sizeof(chain));

    char run_log_txt[4096] = {0};
    char run_log_path[700];
    (void)snprintf(run_log_path, sizeof(run_log_path), "%s/run.log", dir);
    const bool have_run_log = read_whole_file(run_log_path, run_log_txt,
                                              sizeof(run_log_txt));
    EN_CHECK("--no-group fixture skips worktree-prime",
             have_run_log
             && strstr(run_log_txt, "prime skipped") != NULL
             && strstr(run_log_txt, "could not prime") == NULL);
    EN_CHECK("the harness wrote state.txt after turn 1's reply", have_state);
    EN_CHECK("state.txt holds what turn 1's model wrote",
             have_state
             && strstr(state_txt, "turn two should see this exact sentence")
                    != NULL);
    EN_CHECK("prompt.txt (turn 2's, since each turn overwrites it) exists",
             have_prompt);
    EN_CHECK("turn 2's prompt was handed turn 1's carried state verbatim",
             have_prompt
             && strstr(prompt_txt, "turn two should see this exact sentence")
                    != NULL);
    EN_CHECK("turn 2's prompt announces it as carried state, not raw prose",
             have_prompt
             && strstr(prompt_txt, "carried state from the previous turn")
                    != NULL);
    EN_CHECK("HTTP usage reaches the durable one-run receipt without loss",
             have_receipt && strstr(receipt,"\"input_tokens\":10") &&
             strstr(receipt,"\"output_tokens\":4") &&
             strstr(receipt,"\"total_tokens\":14") &&
             strstr(receipt,"\"cache_read_input_tokens\":6") &&
             strstr(receipt,"\"reasoning_tokens\":2") &&
             strstr(receipt,"\"cache_creation_input_tokens\":null"));
    EN_CHECK("both repair dispatches reach one authoritative chain receipt",
             have_chain &&
             strstr(chain, "\"ordinal\":1,\"phase\":\"turn\"") &&
             strstr(chain, "\"ordinal\":2,\"phase\":\"turn\"") &&
             strstr(chain, "\"total_prompt_tokens\":20") &&
             strstr(chain, "\"total_completion_tokens\":8") &&
             strstr(chain, "\"total_cache_read_input_tokens\":12") &&
             strstr(chain, "\"total_cache_creation_input_tokens\":-1") &&
             strstr(chain, "\"total_reasoning_tokens\":4") &&
             strstr(chain, "\"total_reported_tokens\":28") &&
             strstr(chain, "\"accounting_scope\":\"terminal_dispatch\"") &&
             strstr(chain, "\"total_invocation_elapsed_ms\":") &&
             strstr(chain, "\"cumulative_proof_ms\":0") &&
             strstr(chain, "\"unit_elapsed_ms\":"));

    failures += case_receipt_absent_attempt(chain, have_chain);

    failures += case_template_cas_dispatch(cmd, worktree, chain_path,
                                           run_log_path);

    /* Remove the worktree path so a killed run leaves no registered
     * worktree under test-tmp. Best-effort. */
    char cleanup_cmd[1024];
    (void)snprintf(cleanup_cmd, sizeof(cleanup_cmd),
                   "git worktree remove %s --force >/dev/null 2>&1; "
                   "git branch -D engine/unit >/dev/null 2>&1; "
                   "git worktree prune >/dev/null 2>&1",
                   worktree);
     TEST_DISCARD(system(cleanup_cmd));

    return failures;
}

#if !defined(_WIN32)
static bool engine_test_shell_quote(const char *in, char *out, size_t cap)
{
    size_t n = 0;
    if (!in || !out || cap < 3)
        return false;
    out[n++] = '\'';
    for (const char *p = in; *p; p++) {
        static const char escaped_quote[] = "'\\''";
        const char *piece = *p == '\'' ? escaped_quote : p;
        const size_t count = *p == '\'' ? sizeof(escaped_quote) - 1u : 1u;
        if (n + count + 2u > cap)
            return false;
        memcpy(out + n, piece, count);
        n += count;
    }
    out[n++] = '\'';
    out[n] = '\0';
    return true;
}

struct attempt_cli_fixture {
    const char *counter, *log_path;
    const char *bin, *count, *first, *second, *task, *worktree, *state, *log;
};

static int case_attempt_cli_refusal(const struct attempt_cli_fixture *f,
                                   const char *id, bool probe)
{
    int failures = 0;
    char command[8192], refused[4096] = {0};
    (void)unlink(f->counter);
    (void)snprintf(command, sizeof(command),
        "PATH=%s:$PATH ZCL_FAKE_COUNT=%s ZCL_FAKE_FIRST=%s "
        "ZCL_FAKE_SECOND=%s %s --engine grok-cli --task %s "
        "--no-group --yes-dispatch --turns 2 --worktree %s "
        "--state-dir %s --attempt-id %s %s >%s 2>&1",
        f->bin, f->count, f->first, f->second, ENGINE_UNIT_BIN,
        f->task, f->worktree, f->state, id, probe ? "--probe" : "", f->log);
    const int rc = system(command);
    EN_CHECK("malformed owner id refuses before fake executor",
        rc != -1 && WIFEXITED(rc) && WEXITSTATUS(rc) == 2 &&
        access(f->counter, F_OK) != 0 && errno == ENOENT &&
        read_whole_file(f->log_path, refused, sizeof(refused)) &&
        strstr(refused, "--attempt-id needs exactly 64"));
    return failures;
}

static int case_attempt_cli_refusals(const struct attempt_cli_fixture *f)
{
    int failures = 0;
    /* Probe bypasses receipt-plan validation, exposing a missing owner guard. */
    for (size_t i = 0; i < sizeof(malformed_attempts) /
                            sizeof(malformed_attempts[0]); i++) {
        char id[1404];
        const bool quoted = engine_test_shell_quote(malformed_attempts[i],
                                                    id, sizeof(id));
        if (quoted) {
            failures += case_attempt_cli_refusal(f, id, false);
            failures += case_attempt_cli_refusal(f, id, true);
        }
        EN_CHECK("malformed id is shell quoted", quoted);
    }
    (void)unlink(f->counter);
    return failures;
}

static int case_receipt_exact_attempt(const char *chain, const char *path,
                                      bool have_chain)
{
    int failures = 0;
    char binding[100];
    (void)snprintf(binding, sizeof(binding), "\"attempt_id\":\"%s\"", attempt_a);
    struct engine_receipt_chain_report report;
    EN_CHECK("owner attempt propagates exactly through production receipt",
             have_chain && strstr(chain, binding) &&
             engine_receipt_verify_chain(path, &report) && report.records == 1);
    return failures;
}

static int case_engine_unit_grok_projection_e2e(void)
{
    int failures = 0;
    if (!engine_unit_binary_present()) {
        printf("engine: FAIL (%s is required for Grok projection e2e)\n",
               ENGINE_UNIT_BIN);
        return 1;
    }

    char rel[512], dir[600];
    test_make_tmpdir(rel, sizeof(rel), "engine_grok_projection", "run");
    if (!test_abs_path(rel, dir, sizeof(dir))) {
        printf("engine: FAIL (could not absolutize Grok fixture)\n");
        return 1;
    }
    char bin_dir[700], source[700], fake_grok[700], task[700];
    char first[700], second[700], counter[700], state[700], worktree[700];
    char receipt_path[740], chain_path[740], log_path[740];
    (void)snprintf(bin_dir, sizeof(bin_dir), "%s/bin", dir);
    (void)snprintf(source, sizeof(source), "%s/fake-grok.c", dir);
    (void)snprintf(fake_grok, sizeof(fake_grok), "%s/grok", bin_dir);
    (void)snprintf(task, sizeof(task), "%s/task.txt", dir);
    (void)snprintf(first, sizeof(first), "%s/inclusive.json", dir);
    (void)snprintf(second, sizeof(second), "%s/additive.json", dir);
    (void)snprintf(counter, sizeof(counter), "%s/counter", dir);
    (void)snprintf(state, sizeof(state), "%s/state", dir);
    (void)snprintf(worktree, sizeof(worktree), "%s/wt", dir);
    (void)snprintf(receipt_path, sizeof(receipt_path), "%s/receipt.json", state);
    (void)snprintf(chain_path, sizeof(chain_path), "%s/%s", state,
                   ENGINE_RECEIPT_FILENAME);
    (void)snprintf(log_path, sizeof(log_path), "%s/run.log", dir);
    const bool dirs_ok = mkdir(bin_dir, 0700) == 0 && mkdir(state, 0700) == 0;

    static const char fake_source[] =
        "#include <stdio.h>\n#include <stdlib.h>\n"
        "int main(void){const char*c=getenv(\"ZCL_FAKE_COUNT\");"
        "const char*a=getenv(\"ZCL_FAKE_FIRST\");"
        "const char*b=getenv(\"ZCL_FAKE_SECOND\");"
        "if(!c||!a||!b)return 2;FILE*f=fopen(c,\"rb\");"
        "int later=f!=0;if(f&&fclose(f))return 3;"
        "if(!later){f=fopen(c,\"wb\");if(!f||fclose(f))return 4;}"
        "f=fopen(later?b:a,\"rb\");if(!f)return 5;int ch;"
        "while((ch=fgetc(f))!=EOF)if(fputc(ch,stdout)==EOF)return 6;"
        "if(ferror(f)||fclose(f)||fflush(stdout))return 7;return 0;}\n";
    static const char inclusive[] =
        "{\"text\":\"done\",\"stopReason\":\"end_turn\","
        "\"sessionId\":\"23c9be10-5084-43a4-8e1a-2735a4650981\","
        "\"requestId\":\"ddc16017-2c5f-4c34-9fa9-ce50a4ec48a0\","
        "\"usage\":{\"input_tokens\":100,"
        "\"cache_read_input_tokens\":60,"
        "\"cache_creation_input_tokens\":10,\"output_tokens\":25,"
        "\"reasoning_tokens\":7,\"total_tokens\":125},\"num_turns\":1,"
        "\"modelUsage\":{\"grok-4.6-build\":{\"inputTokens\":100,"
        "\"outputTokens\":25,\"cacheReadInputTokens\":60,"
        "\"cacheCreationInputTokens\":10,\"modelCalls\":1}}}";
    static const char additive[] =
        "{\"text\":\"done\",\"stopReason\":\"cancelled\","
        "\"sessionId\":\"8a79ed87-5aaa-4924-b75d-f29a52ac3818\","
        "\"requestId\":\"db6794ee-c1e6-4bc8-9b9c-3961c6382f16\","
        "\"usage\":{\"input_tokens\":231579,"
        "\"cache_read_input_tokens\":265088,"
        "\"cache_creation_input_tokens\":0,\"output_tokens\":9830,"
        "\"reasoning_tokens\":8841,\"total_tokens\":506497},"
        "\"num_turns\":10,\"modelUsage\":{\"grok-4.6-build\":{"
        "\"inputTokens\":231579,\"outputTokens\":9830,"
        "\"cacheReadInputTokens\":265088,"
        "\"cacheCreationInputTokens\":0,\"modelCalls\":10}}}";
    const bool files_ok = dirs_ok
        && write_whole_file(source, fake_source)
        && write_whole_file(task, "kind: fix-gate\n\nMeasure accounting.\n")
        && write_whole_file(first, inclusive)
        && write_whole_file(second, additive);
    EN_CHECK("Grok dispatch fixtures are written", files_ok);

    char command[8192];
    char q_bin[1404], q_source[1404], q_grok[1404], q_task[1404];
    char q_first[1404], q_second[1404], q_counter[1404], q_state[1404];
    char q_worktree[1404], q_log[1404];
    const bool quoted = engine_test_shell_quote(bin_dir, q_bin, sizeof(q_bin))
        && engine_test_shell_quote(source, q_source, sizeof(q_source))
        && engine_test_shell_quote(fake_grok, q_grok, sizeof(q_grok))
        && engine_test_shell_quote(task, q_task, sizeof(q_task))
        && engine_test_shell_quote(first, q_first, sizeof(q_first))
        && engine_test_shell_quote(second, q_second, sizeof(q_second))
        && engine_test_shell_quote(counter, q_counter, sizeof(q_counter))
        && engine_test_shell_quote(state, q_state, sizeof(q_state))
        && engine_test_shell_quote(worktree, q_worktree, sizeof(q_worktree))
        && engine_test_shell_quote(log_path, q_log, sizeof(q_log));
    bool compiled = false;
    bool detached = false;
    if (files_ok && quoted) {
        (void)snprintf(command, sizeof(command),
                       "git -c core.hooksPath=/dev/null worktree add "
                       "--detach %s HEAD >/dev/null 2>&1",
                       q_worktree);
        detached = system(command) == 0;
        (void)snprintf(command, sizeof(command),
                       "cc -std=c23 -O0 -o %s %s", q_grok, q_source);
        compiled = system(command) == 0;
    }
    EN_CHECK("the fixture owns a detached worktree", detached);
    EN_CHECK("the fake Grok CLI fixture compiles as C23", compiled);
    if (compiled && detached) {
        const struct attempt_cli_fixture attempt_fixture = {
            .counter = counter, .log_path = log_path, .bin = q_bin,
            .count = q_counter, .first = q_first, .second = q_second,
            .task = q_task, .worktree = q_worktree, .state = q_state,
            .log = q_log,
        };
        failures += case_attempt_cli_refusals(&attempt_fixture);

        (void)snprintf(command, sizeof(command),
            "PATH=%s:$PATH ZCL_FAKE_COUNT=%s ZCL_FAKE_FIRST=%s "
            "ZCL_FAKE_SECOND=%s %s --engine grok-cli --task %s --no-group "
            "--yes-dispatch --turns 2 --worktree %s --state-dir %s --attempt-id %s "
            ">%s 2>&1", q_bin, q_counter, q_first, q_second, ENGINE_UNIT_BIN,
            q_task, q_worktree, q_state, attempt_a, q_log);
        TEST_DISCARD(system(command)); /* durable receipts are the evidence */
    }

    char receipt[8192] = {0};
    char chain[32768] = {0};
    const bool have_receipt = compiled && detached
        && read_whole_file(receipt_path, receipt, sizeof(receipt));
    const bool have_chain = compiled && detached
        && read_whole_file(chain_path, chain, sizeof(chain));
    EN_CHECK("the Grok dispatch wrote its one-run receipt", have_receipt);
    EN_CHECK("the Grok dispatch wrote its receipt chain", have_chain);
    failures += case_receipt_exact_attempt(chain, chain_path, have_chain);
    EN_CHECK("additive Grok projection preserves raw and normalized counters",
             have_receipt
             && strstr(receipt, "\"prompt_tokens\":496667")
             && strstr(receipt, "\"input_tokens\":231579")
             && strstr(receipt, "\"output_tokens\":9830")
             && strstr(receipt, "\"cache_read_input_tokens\":265088")
             && strstr(receipt, "\"total_tokens\":506497"));
    EN_CHECK("both Grok accounting shapes are durable per invocation",
             have_chain
             && strstr(chain, "\"prompt_tokens\":100,\"completion_tokens\":25,\"cache_read_input_tokens\":60")
             && strstr(chain, "\"prompt_tokens\":496667,\"completion_tokens\":9830,\"cache_read_input_tokens\":265088")
             && strstr(chain, "\"total_prompt_tokens\":496767")
             && strstr(chain, "\"total_completion_tokens\":9855")
             && strstr(chain, "\"total_reported_tokens\":506622"));

    if (detached) {
        (void)snprintf(command, sizeof(command),
                       "git worktree remove --force %s >/dev/null 2>&1",
                       q_worktree);
        EN_CHECK("only the fixture's detached worktree is removed",
                 system(command) == 0);
    }
    return failures;
}
#endif

/* ── hash-chained engine-unit receipts ─────────────────────────────────
 * Signal, not judgement: the chain says only that nothing was altered
 * after the fact. A tampered earlier line makes every later prev_sha3
 * stop matching. */

static struct engine_receipt receipt_fixture(const char *engine, int64_t ts)
{
    struct engine_receipt r;
    memset(&r, 0, sizeof(r));
    r.ts = ts;
    r.engine = engine;
    r.requested_model = ENGINE_REASONING_EFFORT_PROVIDER_DEFAULT;
    r.resolved_model = NULL;
    r.reasoning_effort = ENGINE_REASONING_EFFORT_PROVIDER_DEFAULT;
    r.kind = "fix-gate";
    r.prompt_tokens = ENGINE_RECEIPT_UNREPORTED;
    r.completion_tokens = ENGINE_RECEIPT_UNREPORTED;
    r.cache_read_input_tokens = ENGINE_RECEIPT_UNREPORTED;
    r.cache_creation_input_tokens = ENGINE_RECEIPT_UNREPORTED;
    r.reasoning_tokens = ENGINE_RECEIPT_UNREPORTED;
    r.total_tokens = ENGINE_RECEIPT_UNREPORTED;
    r.turns = ENGINE_RECEIPT_UNREPORTED;
    r.wall_ms = 10;
    r.http_status = 0;
    r.outcome.lint_rc = ENGINE_RECEIPT_UNREPORTED;
    return r;
}

static struct engine_receipt_invocation
receipt_invocation(int64_t ordinal, const char *phase, const char *result,
                   int64_t prompt, int64_t completion, int64_t cache_read,
                   int64_t cache_creation, int64_t reasoning, int64_t total)
{
    return (struct engine_receipt_invocation) {
        .ordinal = ordinal,
        .phase = phase,
        .result = result,
        .elapsed_ms = ordinal * 10,
        .http_status = strcmp(result, "ok") == 0 ? 200 : 503,
        .prompt_tokens = prompt,
        .completion_tokens = completion,
        .cache_read_input_tokens = cache_read,
        .cache_creation_input_tokens = cache_creation,
        .reasoning_tokens = reasoning,
        .total_tokens = total,
    };
}

static void receipt_head_path(const char *path, char *out, size_t cap)
{
    (void)snprintf(out, cap, "%s%s", path, ENGINE_RECEIPT_HEAD_SUFFIX);
}

static void receipt_unlink(const char *path)
{
    char head[600];
    receipt_head_path(path, head, sizeof(head));
    (void)platform_private_file_unlink_missing_ok(path);
    (void)platform_private_file_unlink_missing_ok(head);
}

static bool receipt_read_whole(const char *path, char *buf, size_t cap,
                               size_t *out_n)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t n = fread(buf, 1, cap - 1u, f);
    int err = ferror(f);
    (void)fclose(f);
    buf[n] = '\0';
    if (out_n)
        *out_n = n;
    return err == 0;
}

static bool receipt_write_whole(const char *path, const char *buf, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    size_t w = fwrite(buf, 1, n, f);
    return fclose(f) == 0 && w == n;
}

static bool receipt_copy(const char *src, const char *dst)
{
    char buf[65536];
    size_t n = 0;
    if (!receipt_read_whole(src, buf, sizeof(buf), &n))
        return false;
    if (!receipt_write_whole(dst, buf, n))
        return false;
    char shead[600], dhead[600];
    receipt_head_path(src, shead, sizeof(shead));
    receipt_head_path(dst, dhead, sizeof(dhead));
    if (!receipt_read_whole(shead, buf, sizeof(buf), &n))
        return false;
    return receipt_write_whole(dhead, buf, n);
}

static bool receipt_nth_line(const char *buf, size_t n, int which,
                             const char **start, size_t *len)
{
    size_t i = 0;
    int line = 0;
    while (i < n) {
        size_t s = i;
        while (i < n && buf[i] != '\n')
            i++;
        line++;
        size_t L = i - s;
        if (i < n)
            i++;
        if (line == which) {
            *start = buf + s;
            *len = L;
            return true;
        }
    }
    return false;
}

static bool tamper_first_line(const char *path)
{
    char buf[65536];
    size_t n = 0;
    if (!receipt_read_whole(path, buf, sizeof(buf), &n) || n == 0)
        return false;
    for (size_t i = 1; i < n; i++) {
        if (buf[i] >= 'a' && buf[i] <= 'z') {
            buf[i] = (char)(buf[i] == 'a' ? 'b' : 'a');
            break;
        }
    }
    return receipt_write_whole(path, buf, n);
}

static bool mutate_first_prev_sha3(const char *src, const char *dst)
{
    if (!receipt_copy(src, dst))
        return false;
    char buf[65536];
    size_t n = 0;
    if (!receipt_read_whole(dst, buf, sizeof(buf), &n))
        return false;
    char *p = strstr(buf, "\"prev_sha3\":\"");
    if (!p)
        return false;
    p += strlen("\"prev_sha3\":\"");
    if (p + 64 > buf + n)
        return false;
    memset(p, 'f', 64);
    return receipt_write_whole(dst, buf, n);
}

static bool mutate_swap_first_two(const char *src, const char *dst)
{
    if (!receipt_copy(src, dst))
        return false;
    char buf[65536];
    size_t n = 0;
    if (!receipt_read_whole(dst, buf, sizeof(buf), &n))
        return false;
    const char *l1, *l2, *l3;
    size_t n1, n2, n3;
    if (!receipt_nth_line(buf, n, 1, &l1, &n1)
        || !receipt_nth_line(buf, n, 2, &l2, &n2)
        || !receipt_nth_line(buf, n, 3, &l3, &n3))
        return false;
    char out[65536];
    if (n2 + 1u + n1 + 1u + n3 + 1u >= sizeof(out))
        return false;
    size_t o = 0;
    memcpy(out + o, l2, n2); o += n2; out[o++] = '\n';
    memcpy(out + o, l1, n1); o += n1; out[o++] = '\n';
    memcpy(out + o, l3, n3); o += n3; out[o++] = '\n';
    return receipt_write_whole(dst, out, o);
}

static bool mutate_drop_line_two(const char *src, const char *dst)
{
    if (!receipt_copy(src, dst))
        return false;
    char buf[65536];
    size_t n = 0;
    if (!receipt_read_whole(dst, buf, sizeof(buf), &n))
        return false;
    const char *l1, *l3;
    size_t n1, n3;
    if (!receipt_nth_line(buf, n, 1, &l1, &n1)
        || !receipt_nth_line(buf, n, 3, &l3, &n3))
        return false;
    char out[65536];
    if (n1 + 1u + n3 + 1u >= sizeof(out))
        return false;
    size_t o = 0;
    memcpy(out + o, l1, n1); o += n1; out[o++] = '\n';
    memcpy(out + o, l3, n3); o += n3; out[o++] = '\n';
    return receipt_write_whole(dst, out, o);
}

static bool mutate_drop_last_newline(const char *src, const char *dst)
{
    if (!receipt_copy(src, dst))
        return false;
    char buf[65536];
    size_t n = 0;
    if (!receipt_read_whole(dst, buf, sizeof(buf), &n) || n == 0)
        return false;
    if (buf[n - 1] != '\n')
        return false;
    return receipt_write_whole(dst, buf, n - 1u);
}

static bool mutate_last_groups_ran(const char *src, const char *dst)
{
    if (!receipt_copy(src, dst))
        return false;
    char buf[65536];
    size_t n = 0;
    if (!receipt_read_whole(dst, buf, sizeof(buf), &n))
        return false;
    const char *last;
    size_t last_n;
    if (!receipt_nth_line(buf, n, 3, &last, &last_n))
        return false;
    char line[ENGINE_RECEIPT_LINE_MAX + 8u];
    if (last_n + 8u >= sizeof(line))
        return false;
    memcpy(line, last, last_n);
    line[last_n] = '\0';
    char *p = strstr(line, "\"groups_ran\":0");
    if (!p)
        return false;
    /* "groups_ran":0 -> "groups_ran":99, one extra byte. */
    size_t prefix = (size_t)(p - line) + strlen("\"groups_ran\":");
    char rebuilt[ENGINE_RECEIPT_LINE_MAX + 8u];
    size_t r = 0;
    memcpy(rebuilt + r, buf, (size_t)(last - buf));
    r += (size_t)(last - buf);
    memcpy(rebuilt + r, line, prefix);
    r += prefix;
    rebuilt[r++] = '9';
    rebuilt[r++] = '9';
    const char *rest = p + strlen("\"groups_ran\":0");
    size_t rest_n = last_n - (size_t)(rest - line);
    memcpy(rebuilt + r, rest, rest_n);
    r += rest_n;
    rebuilt[r++] = '\n';
    return receipt_write_whole(dst, rebuilt, r);
}

static bool verify_refuses(const char *path)
{
    struct engine_receipt_chain_report report;
    return !engine_receipt_verify_chain(path, &report)
        && report.first_bad_line != 0;
}

/* Formats "<cwd>/test-tmp/zcl engine <byte> receipt <pid>.chainlog", a
 * UTF-8, space-containing leaf under test-tmp/. */
static void receipt_unicode_path(char *out, size_t n)
{
    char cwd[PATH_MAX];
    const char *base = getcwd(cwd, sizeof(cwd)) ? cwd : ".";
    (void)snprintf(out, n, "%s/test-tmp/zcl engine \xC5\xBE receipt %d.chainlog",
                   base, (int)getpid());
}

static int case_receipt_attempt_refusals(const char *path,
                                         struct engine_receipt *r)
{
    int failures = 0;
    for (size_t i = 0; i < sizeof(malformed_attempts) /
                            sizeof(malformed_attempts[0]); i++) {
        r->attempt_id = malformed_attempts[i];
        char digest[65] = "not cleared";
        EN_CHECK("receipt API refuses malformed supplied attempt",
                 !engine_receipt_fits(r) &&
                 !engine_receipt_append(path, r, digest) && digest[0] == '\0' &&
                 access(path, F_OK) != 0 && errno == ENOENT);
    }
    return failures;
}

static bool receipt_attempt_pair_matches(
    const struct json_value *const ids[2],
    const struct json_value *const attempts[2])
{
    return ids[0] && ids[1] && attempts[0] && attempts[1] &&
           ids[0]->type == JSON_STR && ids[1]->type == JSON_STR &&
           attempts[0]->type == JSON_STR && attempts[1]->type == JSON_STR &&
           strcmp(json_get_str(ids[0]), json_get_str(ids[1])) == 0 &&
           strcmp(json_get_str(attempts[0]), attempt_a) == 0 &&
           strcmp(json_get_str(attempts[1]), attempt_b) == 0;
}

static int case_receipt_attempt_pair(const char *path)
{
    int failures = 0;
    char whole[ENGINE_RECEIPT_LINE_MAX * 2u + 4u];
    size_t n = 0;
    const char *line = NULL;
    size_t len = 0;
    struct json_value docs[2];
    json_init(&docs[0]);
    json_init(&docs[1]);
    bool parsed = receipt_read_whole(path, whole, sizeof(whole), &n);
    for (size_t i = 0; i < 2 && parsed; i++)
        parsed = receipt_nth_line(whole, n, i + 1u, &line, &len) &&
                 json_read(&docs[i], line, len);
    const struct json_value *ids[2] = {
        json_get(&docs[0], "unit_id"), json_get(&docs[1], "unit_id")
    };
    const struct json_value *attempts[2] = {
        json_get(&docs[0], "attempt_id"), json_get(&docs[1], "attempt_id")
    };
    EN_CHECK("historical unit collision retains distinct exact bindings",
             parsed && receipt_attempt_pair_matches(ids, attempts));
    json_free(&docs[0]);
    json_free(&docs[1]);
    return failures;
}

/* ── task-kind tiers ────────────────────────────────────────────────────── */
static int case_engine_tiers(void)
{
    int failures = 0;

    for (size_t i = 0; i < engine_count(); i++) {
        const struct engine_vendor *a = engine_at(i);
        EN_CHECK("a row with a lead has a tier",
                 a->lead == NULL || a->tier != ENGINE_TIER_NONE);
        for (size_t j = i + 1; j < engine_count(); j++) {
            const struct engine_vendor *b = engine_at(j);
            EN_CHECK("at most one row per (lead, tier)",
                     a->lead == NULL || b->lead == NULL
                     || a->tier != b->tier
                     || strcmp(a->lead, b->lead) != 0);
        }
    }

    EN_CHECK("claude light resolves to claude-haiku",
             engine_for_lead_tier("claude", ENGINE_TIER_LIGHT)
             == engine_by_id("claude-haiku"));
    EN_CHECK("claude standard resolves to claude-sonnet",
             engine_for_lead_tier("claude", ENGINE_TIER_STANDARD)
             == engine_by_id("claude-sonnet"));
    EN_CHECK("claude heavy resolves to claude-opus",
             engine_for_lead_tier("claude", ENGINE_TIER_HEAVY)
             == engine_by_id("claude-opus"));
    EN_CHECK("the three claude rows exist",
             engine_by_id("claude-haiku") != NULL
             && engine_by_id("claude-sonnet") != NULL
             && engine_by_id("claude-opus") != NULL);
    EN_CHECK("a NULL lead selects nothing",
             engine_for_lead_tier(NULL, ENGINE_TIER_LIGHT) == NULL);
    EN_CHECK("an empty lead selects nothing",
             engine_for_lead_tier("", ENGINE_TIER_LIGHT) == NULL);
    EN_CHECK("an unknown lead selects nothing",
             engine_for_lead_tier("nope", ENGINE_TIER_STANDARD) == NULL);
    EN_CHECK("the NONE tier never selects a row",
             engine_for_lead_tier("claude", ENGINE_TIER_NONE) == NULL);

    static const char *const names[] = { "light", "standard", "heavy" };
    for (int t = ENGINE_TIER_LIGHT; t <= ENGINE_TIER_HEAVY; t++) {
        enum engine_tier out = ENGINE_TIER_NONE;
        EN_CHECK("tier names round-trip",
                 engine_tier_from_name(names[t - 1], &out) && out == t
                 && strcmp(engine_tier_name((enum engine_tier)t),
                           names[t - 1]) == 0);
    }
    /* Every tier named in prompt_templates.def must parse as an engine tier. */
    static const char *const kind_tiers[] = {
#define ENGINE_PROMPT_TEMPLATE(kind_, section_, body_)
#define ENGINE_PROMPT_KIND_TIER(kind_, tier_) #tier_,
#include "../../../engine/composition/prompt_templates.def"
#undef ENGINE_PROMPT_KIND_TIER
#undef ENGINE_PROMPT_TEMPLATE
    };
    for (size_t k = 0; k < sizeof kind_tiers / sizeof kind_tiers[0]; k++) {
        enum engine_tier kt = ENGINE_TIER_NONE;
        EN_CHECK("every prompt template kind tier parses as an engine tier",
                 engine_tier_from_name(kind_tiers[k], &kt)
                 && kt != ENGINE_TIER_NONE);
    }

    EN_CHECK("NONE names itself none",
             strcmp(engine_tier_name(ENGINE_TIER_NONE), "none") == 0);

    enum engine_tier out = ENGINE_TIER_STANDARD;
    EN_CHECK("empty tier name is refused",
             !engine_tier_from_name("", &out));
    EN_CHECK("NULL tier name is refused",
             !engine_tier_from_name(NULL, &out));
    EN_CHECK("tier names are case-sensitive",
             !engine_tier_from_name("Light", &out));
    EN_CHECK("none is not a parseable tier",
             !engine_tier_from_name("none", &out));

    const struct engine_vendor *fx = engine_by_id("fixture");
    EN_CHECK("the fixture row is never auto-selected",
             fx && fx->tier == ENGINE_TIER_NONE);
    return failures;
}

static int case_receipt_attempt_binding(void)
{
    int failures = 0;
    char path[PATH_MAX];
    test_fmt_tmpdir(path, sizeof(path), "engine_attempt_binding", "chainlog");
    (void)test_ensure_tmproot();
    receipt_unlink(path);
    struct engine_receipt r = receipt_fixture("fixture", 1000);
    r.task_sha3 = attempt_a; /* same exact task bytes for both attempts */
    EN_CHECK("absent attempt remains valid", engine_receipt_fits(&r));
    failures += case_receipt_attempt_refusals(path, &r);
    r.attempt_id = attempt_a;
    EN_CHECK("valid attempt fits and appends", engine_receipt_fits(&r) &&
             engine_receipt_append(path, &r, NULL));
    r.attempt_id = attempt_b;
    EN_CHECK("same-second second attempt appends",
             engine_receipt_append(path, &r, NULL));
    failures += case_receipt_attempt_pair(path);
    struct engine_receipt_chain_report report;
    EN_CHECK("bound attempts verify with ordinary chain semantics",
             engine_receipt_verify_chain(path, &report) && report.records == 2);
    receipt_unlink(path);
    return failures;
}

static int case_receipt_chain(void)
{
    int failures = 0;
    char path[PATH_MAX];
    test_fmt_tmpdir(path, sizeof(path), "zcl_engine_receipt", "chainlog");
    (void)test_ensure_tmproot();
    receipt_unlink(path);

    struct engine_receipt_chain_report report;
    EN_CHECK("a missing file is an empty chain, not a broken one",
             engine_receipt_verify_chain(path, &report)
             && report.records == 0 && report.first_bad_line == 0);

    struct engine_receipt a = receipt_fixture("fixture", 1000);
    struct engine_receipt b = receipt_fixture("glm", 1001);
    struct engine_receipt c = receipt_fixture("grok", 1002);
    struct engine_receipt_invocation calls[4] = {
        receipt_invocation(1, "turn", "network", -1, -1, -1, -1, -1, -1),
        receipt_invocation(2, "turn", "ok", 10, 4, 6, 0, 2, 14),
        receipt_invocation(3, "compaction", "ok", 3, 2, 1, -1, 0, 5),
        receipt_invocation(4, "turn", "ok", 12, 5, 4, 0, 1, 17),
    };
    struct engine_receipt_invocation overflow_calls[2] = {
        receipt_invocation(1, "turn", "ok", INT64_MAX, 0, 0, 0, 0,
                           INT64_MAX),
        receipt_invocation(2, "turn", "ok", 1, 0, 0, 0, 0, 1),
    };
    a.invocations = calls;
    a.invocations_count = sizeof(calls) / sizeof(calls[0]);
    calls[1].resolved_model = "grok-build-a";
    calls[2].resolved_model = "grok-build-b";
    b.invocations = overflow_calls;
    b.invocations_count = sizeof(overflow_calls) / sizeof(overflow_calls[0]);
    struct engine_receipt_invocation resumed_calls[2] = {
        receipt_invocation(1, "turn", "ok", 10, 4, 0, 0, 1, 14),
        receipt_invocation(2, "turn", "ok", 20, 8, 0, 0, 2, 28),
    };
    c.invocations = resumed_calls;
    c.invocations_count = sizeof(resumed_calls) / sizeof(resumed_calls[0]);
    c.invocation_totals_ambiguous = true;
    struct engine_receipt_invocation maximum_calls
        [ENGINE_RECEIPT_INVOCATIONS_MAX];
    char maximum_model[96];
    char maximum_rule[64];
    memset(maximum_model, 'm', sizeof(maximum_model) - 1u);
    maximum_model[sizeof(maximum_model) - 1u] = '\0';
    memset(maximum_rule, 'r', sizeof(maximum_rule) - 1u);
    maximum_rule[sizeof(maximum_rule) - 1u] = '\0';
    for (size_t i = 0; i < ENGINE_RECEIPT_INVOCATIONS_MAX; i++) {
        maximum_calls[i] = receipt_invocation(
            INT64_MAX, "compaction", "receipt_capacity_worst_case",
            INT64_MAX, INT64_MAX, INT64_MAX, INT64_MAX, INT64_MAX,
            INT64_MAX);
        maximum_calls[i].elapsed_ms = INT64_MAX;
        maximum_calls[i].http_status = INT64_MAX;
        maximum_calls[i].resolved_model = maximum_model;
    }
    struct engine_receipt maximum = receipt_fixture("fixture", INT64_MAX);
    maximum.requested_model = maximum_model;
    maximum.resolved_model = maximum_model;
    maximum.group = maximum_rule;
    maximum.invocations = maximum_calls;
    maximum.invocations_count = ENGINE_RECEIPT_INVOCATIONS_MAX;
    maximum.cumulative_proof_ms = INT64_MAX;
    maximum.unit_elapsed_ms = INT64_MAX;
    EN_CHECK("the maximum operational dispatch plan fits the 16 KiB record",
             engine_receipt_fits(&maximum));
    const char *maximum_rules[ENGINE_RECEIPT_RULES_MAX];
    for (size_t i = 0; i < ENGINE_RECEIPT_RULES_MAX; i++)
        maximum_rules[i] = maximum_rule;
    maximum.rules_shown = maximum_rules;
    maximum.rules_count = ENGINE_RECEIPT_RULES_MAX;
    EN_CHECK("maximum rule and model metadata still fit the record",
             engine_receipt_fits(&maximum));
    char overlong_model[ENGINE_RECEIPT_LINE_MAX];
    memset(overlong_model, 'x', sizeof(overlong_model) - 1u);
    overlong_model[sizeof(overlong_model) - 1u] = '\0';
    maximum.requested_model = overlong_model;
    EN_CHECK("metadata that would overflow the record is detected preflight",
             !engine_receipt_fits(&maximum));
    a.requested_model = "grok-4.6";
    a.resolved_model = "grok-4.6-build";
    a.reasoning_effort = "high";
    a.prompt_tokens = 100;
    a.completion_tokens = 25;
    a.cache_read_input_tokens = 60;
    a.cache_creation_input_tokens = 10;
    a.reasoning_tokens = 7;
    a.total_tokens = 125;
    a.turns = 4;
    a.dispatch_ms = 2018;
    a.proof_ms = 91;
    a.wall_ms = 2109;
    a.cumulative_proof_ms = 180;
    a.unit_elapsed_ms = 2200;
    EN_CHECK("the first record appends", engine_receipt_append(path, &a, NULL));
    EN_CHECK("the second record appends", engine_receipt_append(path, &b, NULL));
    EN_CHECK("the third record appends", engine_receipt_append(path, &c, NULL));
    EN_CHECK("the chain verifies end to end",
             engine_receipt_verify_chain(path, &report)
             && report.records == 3 && report.first_bad_line == 0);

    /* UTF-8 boundary: spaces and a non-ASCII filename. */
    char unicode_path[PATH_MAX];
    (void)test_ensure_tmproot();
    receipt_unicode_path(unicode_path, sizeof(unicode_path));
    receipt_unlink(unicode_path);
    EN_CHECK("a receipt appends through a UTF-8 path containing spaces",
             engine_receipt_append(unicode_path, &a, NULL));
    EN_CHECK("the UTF-8 receipt chain verifies byte-exactly",
             engine_receipt_verify_chain(unicode_path, &report)
             && report.records == 1 && report.first_bad_line == 0);
    receipt_unlink(unicode_path);

    char whole[65536];
    size_t whole_n = 0;
    const char *line1 = NULL;
    size_t line1_n = 0;
    EN_CHECK("the three-record file is readable",
             receipt_read_whole(path, whole, sizeof(whole), &whole_n)
             && receipt_nth_line(whole, whole_n, 1, &line1, &line1_n));
    static const char k_genesis[] =
        "\"prev_sha3\":\"0000000000000000000000000000000000000000000000000000000000000000\"";
    char first[ENGINE_RECEIPT_LINE_MAX + 2u];
    if (line1 && line1_n < sizeof(first)) {
        memcpy(first, line1, line1_n);
        first[line1_n] = '\0';
    } else {
        first[0] = '\0';
    }
    EN_CHECK("the first record's prev_sha3 is 64 zeros",
             strstr(first, k_genesis) != NULL);
    EN_CHECK("groups_ran is a JSON integer, not a float",
             strstr(first, "\"groups_ran\":0") != NULL
             && strstr(first, "\"groups_ran\":0.") == NULL);
    EN_CHECK("ts is a JSON integer, not a float",
             strstr(first, "\"ts\":1000") != NULL
             && strstr(first, "\"ts\":1000.") == NULL);
    EN_CHECK("the durable receipt preserves requested and resolved model",
             strstr(first, "\"model\":\"grok-4.6\"") != NULL &&
             strstr(first, "\"requested_model\":\"grok-4.6\"") != NULL &&
             strstr(first, "\"resolved_model\":\"grok-4.6-build\"") != NULL);
    EN_CHECK("the durable receipt preserves effort and complete CLI usage",
             strstr(first, "\"reasoning_effort\":\"high\"") != NULL &&
             strstr(first, "\"cache_read_input_tokens\":60") != NULL &&
             strstr(first, "\"cache_creation_input_tokens\":10") != NULL &&
             strstr(first, "\"reasoning_tokens\":7") != NULL &&
             strstr(first, "\"total_tokens\":125") != NULL &&
             strstr(first, "\"turns\":4") != NULL);
    EN_CHECK("dispatch and proof timing remain separately measurable",
             strstr(first, "\"dispatch_ms\":2018") != NULL &&
             strstr(first, "\"proof_ms\":91") != NULL &&
             strstr(first, "\"wall_ms\":2109") != NULL &&
             strstr(first, "\"accounting_scope\":\"terminal_dispatch\"") != NULL);
    EN_CHECK("whole-loop timing is separate from terminal compatibility timing",
             strstr(first, "\"total_invocation_elapsed_ms\":100") != NULL &&
             strstr(first, "\"cumulative_proof_ms\":180") != NULL &&
             strstr(first, "\"unit_elapsed_ms\":2200") != NULL);
    EN_CHECK("retry, repair, and compaction calls remain separate observations",
             strstr(first, "\"ordinal\":1,\"phase\":\"turn\",\"result\":\"network\"") != NULL &&
             strstr(first, "\"ordinal\":3,\"phase\":\"compaction\",\"result\":\"ok\"") != NULL &&
             strstr(first, "\"ordinal\":4,\"phase\":\"turn\",\"result\":\"ok\"") != NULL);
    EN_CHECK("each invocation preserves its own resolved model identity",
             strstr(first, "\"resolved_model\":\"grok-build-a\"") != NULL &&
             strstr(first, "\"resolved_model\":\"grok-build-b\"") != NULL);
    EN_CHECK("missing and zero raw counters remain distinguishable",
             strstr(first, "\"cache_creation_input_tokens\":-1") != NULL &&
             strstr(first, "\"cache_creation_input_tokens\":0") != NULL);
    EN_CHECK("partial reporting makes only the affected checked totals unknown",
             strstr(first, "\"total_prompt_tokens\":-1") != NULL &&
             strstr(first, "\"total_completion_tokens\":-1") != NULL &&
             strstr(first, "\"total_reasoning_tokens\":-1") != NULL &&
             strstr(first, "\"total_reported_tokens\":-1") != NULL);

    const char *line2 = NULL;
    size_t line2_n = 0;
    char second[ENGINE_RECEIPT_LINE_MAX + 2u] = {0};
    EN_CHECK("the unknown-metadata receipt is readable",
             receipt_nth_line(whole, whole_n, 2, &line2, &line2_n) &&
             line2_n < sizeof(second));
    if (line2 && line2_n < sizeof(second)) {
        memcpy(second, line2, line2_n);
        second[line2_n] = '\0';
    }
    EN_CHECK("unreported measurement remains explicit UNKNOWN",
             strstr(second, "\"resolved_model\":null") != NULL &&
             strstr(second, "\"reasoning_effort\":\"provider_default\"") != NULL &&
             strstr(second, "\"reasoning_tokens\":-1") != NULL &&
             strstr(second, "\"cache_read_input_tokens\":-1") != NULL);
    EN_CHECK("overflow refuses a fabricated aggregate while preserving raw counters",
             strstr(second, "\"prompt_tokens\":9223372036854775807") != NULL &&
             strstr(second, "\"total_prompt_tokens\":-1") != NULL &&
             strstr(second, "\"total_completion_tokens\":0") != NULL &&
             strstr(second, "\"total_reasoning_tokens\":0") != NULL);

    const char *line3 = NULL;
    size_t line3_n = 0;
    char third[ENGINE_RECEIPT_LINE_MAX + 2u] = {0};
    EN_CHECK("the resumed-session receipt is readable",
             receipt_nth_line(whole, whole_n, 3, &line3, &line3_n) &&
             line3_n < sizeof(third));
    if (line3 && line3_n < sizeof(third)) {
        memcpy(third, line3, line3_n);
        third[line3_n] = '\0';
    }
    EN_CHECK("cumulative-session ambiguity keeps raw calls but refuses totals",
             strstr(third, "\"usage_scope\":\"non_additive_observation\"") != NULL &&
             strstr(third, "\"prompt_tokens\":10") != NULL &&
             strstr(third, "\"prompt_tokens\":20") != NULL &&
             strstr(third, "\"total_prompt_tokens\":-1") != NULL &&
             strstr(third, "\"total_reported_tokens\":-1") != NULL);

    char resumed_path[512], resumed_text[ENGINE_RECEIPT_LINE_MAX + 2u];
    (void)snprintf(resumed_path, sizeof(resumed_path), "%s.resumed", path);
    receipt_unlink(resumed_path);
    c.invocations_count = 1;
    size_t resumed_n = 0;
    EN_CHECK("a first externally resumed observation is non-additive too",
             engine_receipt_append(resumed_path, &c, NULL) &&
             receipt_read_whole(resumed_path, resumed_text,
                                sizeof(resumed_text), &resumed_n) &&
             strstr(resumed_text, "\"usage_scope\":\"non_additive_observation\"") &&
             strstr(resumed_text, "\"prompt_tokens\":10") &&
             strstr(resumed_text, "\"total_reported_tokens\":-1"));
    receipt_unlink(resumed_path);

    struct zcl_rule_receipt_log scored;
    uint32_t bad_line = 0;
    EN_CHECK("the score reader keeps one trial per outer receipt",
             zcl_rule_receipts_parse(whole, whole_n, &scored, &bad_line)
                 == ZCL_RULE_CHAIN_OK &&
             scored.count == 3 && scored.r[0].prompt_tokens == 100);

    struct engine_receipt knull = receipt_fixture("fixture", 1003);
    knull.kind = NULL;
    char kpath[512];
    (void)snprintf(kpath, sizeof(kpath), "%s.kind", path);
    receipt_unlink(kpath);
    EN_CHECK("a NULL kind appends", engine_receipt_append(kpath, &knull, NULL));
    char kbuf[65536];
    size_t kn = 0;
    EN_CHECK("and is written as an empty kind string",
             receipt_read_whole(kpath, kbuf, sizeof(kbuf), &kn)
             && strstr(kbuf, "\"kind\":\"\"") != NULL);
    receipt_unlink(kpath);

    struct engine_receipt bad = receipt_fixture("", 1003);
    bad.engine = "";
    EN_CHECK("a receipt with no engine id is refused",
             !engine_receipt_append(path, &bad, NULL));
    EN_CHECK("refusing an append leaves the chain intact",
             engine_receipt_verify_chain(path, &report) && report.records == 3);

    char mut[512];
    (void)snprintf(mut, sizeof(mut), "%s.mut", path);

    EN_CHECK("copied the honest chain for mutation", receipt_copy(path, mut));
    EN_CHECK("tampering an earlier line is detected", tamper_first_line(mut));
    EN_CHECK("and verification names a bad line", verify_refuses(mut));
    receipt_unlink(mut);

    EN_CHECK("a first line whose prev_sha3 is not genesis is refused",
             mutate_first_prev_sha3(path, mut) && verify_refuses(mut));
    receipt_unlink(mut);
    EN_CHECK("swapping lines 1 and 2 is refused",
             mutate_swap_first_two(path, mut) && verify_refuses(mut));
    receipt_unlink(mut);
    EN_CHECK("dropping the middle line is refused",
             mutate_drop_line_two(path, mut) && verify_refuses(mut));
    receipt_unlink(mut);
    EN_CHECK("a last line with no newline is refused",
             mutate_drop_last_newline(path, mut) && verify_refuses(mut));
    receipt_unlink(mut);
    EN_CHECK("rewriting the last line's groups_ran is refused",
             mutate_last_groups_ran(path, mut) && verify_refuses(mut));
    receipt_unlink(mut);

    {
        char directory[600];
        (void)snprintf(directory, sizeof(directory), "%s.directory", path);
        receipt_unlink(directory);
#if defined(_WIN32)
        const int made_directory = _mkdir(directory);
#else
        const int made_directory = mkdir(directory, 0700);
#endif
        EN_CHECK("created the unreadable chain fixture", made_directory == 0);
        EN_CHECK("an unreadable path is not an empty chain",
                 !engine_receipt_verify_chain(directory, &report));
        EN_CHECK("and an append to it is refused",
                 !engine_receipt_append(directory, &a, NULL));
#if defined(_WIN32)
        (void)_rmdir(directory);
#else
        (void)rmdir(directory);
#endif
    }

#ifndef _WIN32
    if (geteuid() != 0) {
        char locked[512];
        (void)snprintf(locked, sizeof(locked), "%s.locked", path);
        EN_CHECK("copied the chain to chmod 000", receipt_copy(path, locked));
        EN_CHECK("chmod 000 of the chainlog", chmod(locked, 0) == 0);
        bool unreadable_empty = engine_receipt_verify_chain(locked, &report)
                                && report.records == 0;
        bool append_genesis = engine_receipt_append(locked, &a, NULL);
        (void)chmod(locked, 0644);
        EN_CHECK("chmod 000 does not verify as an empty chain",
                 !unreadable_empty);
        EN_CHECK("and does not append a genesis record over unread bytes",
                 !append_genesis);
        receipt_unlink(locked);
    }
#endif

#ifndef _WIN32
    {
        char cpath[512];
        (void)snprintf(cpath, sizeof(cpath), "%s.conc", path);
        receipt_unlink(cpath);
        pid_t pids[8];
        int started = 0;
        for (int i = 0; i < 8; i++) {
            pid_t pid = fork();
            if (pid < 0)
                break;
            if (pid == 0) {
                struct engine_receipt r = receipt_fixture("fixture", 2000 + i);
                _exit(engine_receipt_append(cpath, &r, NULL) ? 0 : 1);
            }
            pids[started++] = pid;
        }
        int kids_ok = started == 8;
        for (int i = 0; i < started; i++) {
            int st = 0;
            if (waitpid(pids[i], &st, 0) != pids[i] || !WIFEXITED(st)
                || WEXITSTATUS(st) != 0)
                kids_ok = 0;
        }
        EN_CHECK("eight concurrent appends all finish", kids_ok);
        EN_CHECK("and the chain verifies with eight records",
                 engine_receipt_verify_chain(cpath, &report)
                 && report.records == 8 && report.first_bad_line == 0);
        receipt_unlink(cpath);
    }
#endif

    receipt_unlink(path);
    return failures;
}

static int case_receipt_text_row(const char *text, bool valid)
{
    int failures = 0;
    char path[512], head[600], before[16386] = {0}, after[16386] = {0};
    char old_pin[66] = {0}, new_pin[66] = {0}, digest[65];
    size_t before_n = 0, after_n = 0;
    test_fmt_tmpdir(path, sizeof(path), "zcl_receipt_text", "chainlog");
    receipt_unlink(path);
    struct engine_receipt r = receipt_fixture("fixture", 1000);
    EN_CHECK("text fixture seed appends", engine_receipt_append(path, &r, NULL));
    receipt_head_path(path, head, sizeof(head));
    EN_CHECK("capture text fixture ledger and pin",
             receipt_read_whole(path, before, sizeof(before), &before_n)
             && receipt_read_whole(head, old_pin, sizeof(old_pin), NULL));
    r.group = text;
    memset(digest, 'x', sizeof(digest));
    EN_CHECK("text preflight matches UTF-8 validity", engine_receipt_fits(&r) == valid);
    EN_CHECK("text append matches UTF-8 validity",
             engine_receipt_append(path, &r, digest) == valid);
    EN_CHECK("read text fixture after append",
             receipt_read_whole(path, after, sizeof(after), &after_n)
             && receipt_read_whole(head, new_pin, sizeof(new_pin), NULL));
    if (valid) {
        struct engine_receipt_chain_report report;
        EN_CHECK("valid text keeps exact non-ASCII and escaped controls",
                 strstr(after, "\"group\":\"caf\xc3\xa9\\n\\t\\\"\\\\\"") != NULL);
        EN_CHECK("valid text chain verifies", engine_receipt_verify_chain(path, &report)
                 && report.records == 2 && digest[0] != '\0');
    } else {
        EN_CHECK("invalid text preserves exact ledger and pin bytes",
                 before_n == after_n && !memcmp(before, after, before_n)
                 && !strcmp(old_pin, new_pin) && digest[0] == '\0');
    }
    receipt_unlink(path);
    return failures;
}

static int case_receipt_text(void)
{
    int failures = 0;
    EN_CHECK("text fixture root exists", test_ensure_tmproot());
    failures += case_receipt_text_row("\xff", false);
    failures += case_receipt_text_row("\xe2\x28\xa1", false);
    failures += case_receipt_text_row("caf\xc3\xa9\n\t\"\\", true);
    return failures;
}

#if !defined(_WIN32)
static int case_pin_name_boundary(void)
{
    int failures = 0;
    char path[4096], head[4096];
    EN_CHECK("boundary fixture root exists", test_ensure_tmproot());
    test_fmt_tmpdir(path, sizeof(path), "zcl_pin_boundary", "chainlog");
    char *basename = strrchr(path, '/') + 1;
    const size_t prefix = strlen(basename);
    const bool fits = prefix <= 250
        && (size_t)(basename - path) <= sizeof(path) - 256;
    EN_CHECK("boundary fixture has room for a 250-byte basename", fits);
    if (!fits)
        return failures;
    memset(basename + prefix, 'p', 250 - prefix);
    basename[250] = '\0';
    receipt_head_path(path, head, sizeof(head));
    receipt_unlink(path);
    struct engine_receipt r = receipt_fixture("fixture", 1000);
    EN_CHECK("250-byte ledger basename appends genesis",
             engine_receipt_append(path, &r, NULL));
    EN_CHECK("255-byte head basename is installed", access(head, F_OK) == 0);
    r.ts = 1001;
    EN_CHECK("250-byte ledger basename appends successor",
             engine_receipt_append(path, &r, NULL));
    struct engine_receipt_chain_report report;
    EN_CHECK("boundary chain and installed pin verify",
             engine_receipt_verify_chain(path, &report) && report.records == 2);
    receipt_unlink(path);
    return failures;
}

static bool pin_fixture_stage(const char *path, long pid, char *stage, size_t cap)
{
    stage[0] = '\0';
    char head[4096], resolved[4096], parent[4096];
    receipt_head_path(path, head, sizeof(head));
    if (!platform_private_destination_resolve(head, resolved, sizeof(resolved),
                                             parent, sizeof(parent)))
        return false;
    const int n = snprintf(stage, cap, "%s/.receipt-pin.%ld.0.tmp", parent, pid);
    return n >= 0 && (size_t)n < cap;
}

static int case_pin_interrupted(const char *path, const char *next)
{
    int failures = 0, status = 0;
    char got[65], stage[640];
    pid_t child = fork();
    if (child == 0) { pin_fault = 1; _exit(write_head_pin(path, next) ? 0 : 1); }
    bool stopped = child > 0 && waitpid(child, &status, WUNTRACED) == child
        && WIFSTOPPED(status);
    EN_CHECK("stopped pin writer leaves the whole old pin",
             stopped && read_head_pin(path, got) == 1 && got[0] == 'a'
             && strspn(got, "a") == 64);
    if (child > 0) { (void)kill(child, SIGKILL); (void)waitpid(child, &status, 0); }
    EN_CHECK("remove only the interrupted fixture stage",
             pin_fixture_stage(path, (long)child, stage, sizeof(stage))
             && platform_private_file_unlink_missing_ok(stage));
    return failures;
}
static int case_pin_atomic(void)
{
    int failures = 0;
    (void)pin_sync; /* The defective writer does not call the sync seam. */
    char path[512], head[600], stage[640], old[66], next[65], got[66];
    test_fmt_tmpdir(path, sizeof(path), "zcl_pin_atomic", "chainlog");
    EN_CHECK("pin fixture root exists", test_ensure_tmproot());
    receipt_head_path(path, head, sizeof(head));
    memset(old, 'a', 64); old[64] = '\n'; old[65] = '\0';
    memset(next, 'b', 64); next[64] = '\0';
    EN_CHECK("seed exact old pin", receipt_write_whole(head, old, 65));
    failures += case_pin_interrupted(path, next);
    pin_fault = 2;
    EN_CHECK("pin sync EIO refuses replacement", !write_head_pin(path, next));
    EN_CHECK("sync refusal preserves exact old bytes",
             receipt_read_whole(head, got, sizeof(got), NULL) && !strcmp(got, old));
    EN_CHECK("sync refusal removes its stage",
             pin_fixture_stage(path, (long)getpid(), stage, sizeof(stage))
             && access(stage, F_OK) != 0
             && errno == ENOENT);
    pin_fault = 0;
    EN_CHECK("normal pin replacement succeeds", write_head_pin(path, next));
    EN_CHECK("whole new pin round trips", read_head_pin(path, got) == 1
             && !strcmp(got, next));
    EN_CHECK("seed malformed pin", receipt_write_whole(head, "bad\n", 4));
    EN_CHECK("malformed existing pin refuses", read_head_pin(path, got) == -1);
    receipt_unlink(path);
    return failures;
}
#endif

/* The review kind hands the reviewer facts, not verdicts: gate-measured rules
 * arrive as facts, the reply is findings, and every finding names its subject. */
static int case_review_findings_not_verdict(void)
{
    int failures = 0;
    const char *rules = engine_prompt_template_body("review", "rules");
    const char *task = engine_prompt_template_body("review", "task");
    const char *judging = engine_prompt_template_body("review", "judging");
    EN_CHECK("review bodies are all supplied", rules && task && judging);
    if (!rules || !task || !judging)
        return failures;
    EN_CHECK("review still does not edit", strstr(rules, "does not edit"));
    EN_CHECK("review takes gate-measured rules as supplied facts",
             strstr(rules, "decided by the gate")
             && strstr(rules, "\"not supplied\""));
    EN_CHECK("review returns findings and no verdict",
             strstr(judging, "Return findings only")
             && strstr(judging, "derives the verdict"));
    EN_CHECK("review marks each finding as about the change or a claim",
             strstr(task, "the CHANGE") && strstr(task, "a CLAIM")
             && strstr(task, "names the sentence"));
    return failures;
}

/* typed task contract: validator table and the real binary ──────────────
 *
 * The pure table first, then the decisive subprocess cases (NEG, POS,
 * LEGACY, carried state, one refusal per newer rule, and preview/real
 * agreement) against the real engine-unit binary. */

#define CONTRACT_HDR "contract: 1\nphase: author\nactor: author\n"
#define CONTRACT_SRC CONTRACT_HDR "execution: source-only\n"
#define CONTRACT_NEG_EVIDENCE \
    "evidence: executed-pass phase=author actor=author\n"
#define CONTRACT_POS_EVIDENCE \
    "evidence: notrun-report phase=author actor=author\n" \
    "evidence: executed-pass phase=verify actor=verifier\n"
#define CONTRACT_OKH CONTRACT_SRC CONTRACT_POS_EVIDENCE
#define CT_A10 "aaaaaaaaaa"
#define CT_A50 CT_A10 CT_A10 CT_A10 CT_A10 CT_A10
#define CT_P191 CT_A50 CT_A50 CT_A50 CT_A10 CT_A10 CT_A10 CT_A10 "a"
#define CT_P192 CT_P191 "a"
#define CT_N31 CT_A10 CT_A10 CT_A10 "a"
#define CT_N32 CT_N31 "a"
#define CT_HEX40 CT_A10 CT_A10 CT_A10 CT_A10
#define CT_HEX40B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define CT_HEX64 CT_HEX40 CT_A10 CT_A10 "aaaa"
#define CT_HEX40C "cccccccccc" "cccccccccc" "cccccccccc" "cccccccccc"
#define CT_HEX40D "dddddddddd" "dddddddddd" "dddddddddd" "dddddddddd"
#define CT_HEX40E "eeeeeeeeee" "eeeeeeeeee" "eeeeeeeeee" "eeeeeeeeee"
#define CT_HEX40F "ffffffffff" "ffffffffff" "ffffffffff" "ffffffffff"
#define CT_LEN(s) (sizeof(s) - 1)
#define CT_PRED_EXEC_FROM \
    "evidence: executed-pass phase=verify actor=verifier from=predecessor\n"

struct contract_row {
    const char *name;
    const char *task;
    enum engine_contract_result want;
    const char *has1, *has2, *has3; /* substrings the reason must hold */
};

#define CT_OK(n, t) {n, t, ENGINE_CONTRACT_OK, NULL, NULL, NULL}
#define CT_NO(n, t, a, b, c) {n, t, ENGINE_CONTRACT_REFUSED, a, b, c}

static const struct contract_row contract_rows[] = {
    {"legacy task is LEGACY even with contract-looking prose keys",
     "kind: fix-gate\n\nphase: 3\nactor: me\n", ENGINE_CONTRACT_LEGACY,
     NULL, NULL, NULL},
    {"a contract line after the blank line is prose, so LEGACY",
     "title\n\ncontract: 1\n", ENGINE_CONTRACT_LEGACY, NULL, NULL, NULL},
    CT_OK("typed OK with the executed-pass split to another phase and actor",
          CONTRACT_OKH "\nbody\n"),
    CT_OK("may-execute may own its executed-pass",
          CONTRACT_HDR "execution: may-execute\n" CONTRACT_NEG_EVIDENCE),
    CT_OK("same phase and actor with notrun-report is fine",
          CONTRACT_SRC "evidence: notrun-report phase=author actor=author\n"),
    CT_NO("NEGATIVE: source-only owning its own executed-pass names both "
          "fields and the correction",
          CONTRACT_SRC CONTRACT_NEG_EVIDENCE,
          "execution=source-only but this same actor=author in phase=author "
          "owes an executed-pass",
          "execution: may-execute", "require notrun-report"),
    CT_NO("unsupported version",
          "contract: 2\nphase: a\nactor: a\nexecution: source-only\n"
          CONTRACT_POS_EVIDENCE, "unsupported contract version", NULL, NULL),
    CT_NO("duplicate phase is refused, never first-wins",
          CONTRACT_HDR "phase: verify\nexecution: source-only\n"
          CONTRACT_POS_EVIDENCE, "duplicate key", "`phase:`", NULL),
    CT_NO("duplicate actor",
          CONTRACT_HDR "actor: verifier\nexecution: source-only\n"
          CONTRACT_POS_EVIDENCE, "duplicate key", "`actor:`", NULL),
    CT_NO("duplicate execution",
          CONTRACT_SRC "execution: may-execute\n" CONTRACT_POS_EVIDENCE,
          "duplicate key", "`execution:`", NULL),
    CT_NO("duplicate contract line", "contract: 1\ncontract: 1\n",
          "duplicate key", NULL, NULL),
    CT_NO("duplicate identical evidence",
          CONTRACT_SRC CONTRACT_POS_EVIDENCE
          "evidence: notrun-report phase=author actor=author\n",
          "duplicate evidence", NULL, NULL),
    CT_NO("unknown key", CONTRACT_SRC "grant: all\n" CONTRACT_POS_EVIDENCE,
          "unknown contract key", "allowed keys are contract, kind", NULL),
    CT_NO("a header line that is not key: value refuses, never falls to "
          "legacy", "contract: 1\nsome prose\n", "not `key: value`", NULL,
          NULL),
    CT_NO("a leading space before a key is not a key",
          "contract: 1\n phase: author\n", "not `key: value`", NULL, NULL),
    CT_NO("malformed evidence: missing actor",
          CONTRACT_SRC "evidence: executed-pass phase=verify\n",
          "evidence must be", NULL, NULL),
    CT_NO("malformed evidence: unknown what",
          CONTRACT_SRC "evidence: passed phase=v actor=v\n",
          "evidence must be", NULL, NULL),
    CT_NO("malformed evidence: trailing token",
          CONTRACT_SRC "evidence: notrun-report phase=v actor=v x\n",
          "evidence must be", NULL, NULL),
    CT_NO("malformed evidence: unknown fourth token",
          CONTRACT_SRC "evidence: notrun-report phase=v actor=v from=me\n",
          "evidence must be", NULL, NULL),
    CT_NO("malformed evidence: uppercase name",
          CONTRACT_SRC "evidence: notrun-report phase=V actor=v\n",
          "evidence must be", NULL, NULL),
    CT_NO("execution word outside the two",
          CONTRACT_HDR "execution: sometimes\n" CONTRACT_POS_EVIDENCE,
          "execution must be", NULL, NULL),
    CT_NO("missing execution", CONTRACT_HDR CONTRACT_POS_EVIDENCE,
          "`execution` is missing", NULL, NULL),
    CT_NO("missing evidence", CONTRACT_SRC, "`evidence` is missing", NULL,
          NULL),
    CT_NO("missing phase",
          "contract: 1\nactor: a\nexecution: source-only\n"
          CONTRACT_POS_EVIDENCE, "`phase` is missing", NULL, NULL),
    CT_OK("CRLF line ends: the CR is trimmed from values",
          "contract: 1\r\nphase: author\r\nactor: author\r\n"
          "execution: source-only\r\n"
          "evidence: notrun-report phase=author actor=author\r\n\nbody\n"),
    CT_NO("CRLF blank line is not a blank line: the header runs on and "
          "refuses loudly",
          "contract: 1\r\nphase: author\r\nactor: author\r\n"
          "execution: source-only\r\n"
          "evidence: notrun-report phase=author actor=author\r\n\r\nbody\r\n",
          "not `key: value`", NULL, NULL),
    CT_OK("a 31-byte name is accepted",
          "contract: 1\nphase: " CT_N31 "\nactor: author\n"
          "execution: source-only\n"
          "evidence: notrun-report phase=" CT_N31 " actor=author\n"),
    CT_NO("a 32-byte name is refused",
          "contract: 1\nphase: " CT_N32 "\nactor: author\n"
          "execution: source-only\n"
          "evidence: notrun-report phase=a actor=author\n",
          "bad phase name", NULL, NULL),

    /* depends, base and must-change bounds: */
    CT_OK("depends of 4 entries is accepted",
          CONTRACT_OKH "base: " CT_HEX40 "\ndepends: " CT_HEX40B "\n"
          "depends: " CT_HEX40C "\ndepends: " CT_HEX40D "\n"
          "depends: " CT_HEX40E "\n"),
    CT_NO("depends of 5 entries is refused",
          CONTRACT_OKH "base: " CT_HEX40 "\ndepends: " CT_HEX40B "\n"
          "depends: " CT_HEX40C "\ndepends: " CT_HEX40D "\n"
          "depends: " CT_HEX40E "\ndepends: " CT_HEX40F "\n",
          "too many depends entries", NULL, NULL),
    CT_NO("base of 41 hex digits is refused",
          CONTRACT_OKH "base: " CT_HEX40 "a\n",
          "must be 40 or 64 lowercase hex digits", NULL, NULL),
    CT_NO("base of 63 hex digits is refused",
          CONTRACT_OKH "base: " CT_HEX40 CT_A10 CT_A10 "aaa\n",
          "must be 40 or 64 lowercase hex digits", NULL, NULL),
    CT_NO("base of 65 hex digits is refused",
          CONTRACT_OKH "base: " CT_HEX64 "a\n",
          "must be 40 or 64 lowercase hex digits", NULL, NULL),
    CT_OK("a must-change path of 191 bytes is accepted",
          CONTRACT_OKH "write-scope: " CT_P191 "\nmust-change: " CT_P191 "\n"),
    CT_NO("a must-change path of 192 bytes is refused",
          CONTRACT_OKH "write-scope: " CT_P191 "\nmust-change: " CT_P192 "\n",
          "bad must-change path", NULL, NULL),

    /* output: */
    CT_OK("output min == max is accepted",
          CONTRACT_OKH "output: min-bytes=5 max-bytes=5\n"),
    CT_OK("output at the cap and min zero are accepted",
          CONTRACT_OKH "output: min-bytes=0 max-bytes=1048576\n"),
    CT_NO("output min above max names both numbers and the correction",
          CONTRACT_OKH "output: min-bytes=6 max-bytes=5\n",
          "min-bytes=6", "max-bytes=5", "lower min-bytes or raise max-bytes"),
    CT_NO("output zero max",
          CONTRACT_OKH "output: min-bytes=0 max-bytes=0\n",
          "max-bytes=0", "min-bytes=0", "lower min-bytes or raise max-bytes"),
    CT_NO("output leading zero",
          CONTRACT_OKH "output: min-bytes=01 max-bytes=5\n",
          "output must be", NULL, NULL),
    CT_NO("output signed", CONTRACT_OKH "output: min-bytes=+1 max-bytes=5\n",
          "output must be", NULL, NULL),
    CT_NO("output over the cap",
          CONTRACT_OKH "output: min-bytes=1 max-bytes=1048577\n",
          "output must be", NULL, NULL),
    CT_NO("output absurdly long number (overflow)",
          CONTRACT_OKH "output: min-bytes=99999999999999999999 max-bytes=5\n",
          "output must be", NULL, NULL),
    CT_NO("output tokens in the wrong order",
          CONTRACT_OKH "output: max-bytes=5 min-bytes=1\n", "output must be",
          NULL, NULL),
    CT_NO("output with a missing token",
          CONTRACT_OKH "output: min-bytes=1\n", "output must be", NULL,
          NULL),
    CT_NO("duplicate output", CONTRACT_OKH "output: min-bytes=1 max-bytes=2\n"
          "output: min-bytes=1 max-bytes=2\n", "duplicate key", "`output:`",
          NULL),

    /* write-scope / must-change */
    CT_OK("source-only with no write-scope is a read-only unit", CONTRACT_OKH),
    CT_OK("must-change covered by an exact write-scope entry",
          CONTRACT_OKH "write-scope: src/a.c\nmust-change: src/a.c\n"),
    CT_OK("must-change under a directory entry",
          CONTRACT_OKH "write-scope: src/\nmust-change: src/deep/a.c\n"),
    CT_NO("segment-wise: src/ab.c is NOT under the entry src/a",
          CONTRACT_OKH "write-scope: src/a\nmust-change: src/ab.c\n",
          "must-change path src/ab.c",
          "add it to write-scope or drop the must-change", NULL),
    CT_NO("segment-wise: src/ab.c is not under the directory src/a/",
          CONTRACT_OKH "write-scope: src/a/\nmust-change: src/ab.c\n",
          "src/ab.c", "add it to write-scope or drop the must-change", NULL),
    CT_NO("must-change with no write-scope at all",
          CONTRACT_OKH "must-change: src/a.c\n", "src/a.c",
          "add it to write-scope or drop the must-change", NULL),
    CT_OK("a path of exactly 191 bytes is accepted",
          CONTRACT_OKH "write-scope: " CT_P191 "\nmust-change: " CT_P191 "\n"),
    CT_NO("a path of 192 bytes is refused",
          CONTRACT_OKH "write-scope: " CT_P192 "\n", "bad write-scope path",
          NULL, NULL),
    CT_NO("a leading slash is refused",
          CONTRACT_OKH "write-scope: /etc/x\n", "bad write-scope path", NULL,
          NULL),
    CT_NO("a .. segment is refused",
          CONTRACT_OKH "write-scope: src/../x\n", "bad write-scope path",
          NULL, NULL),
    CT_NO("a . segment is refused",
          CONTRACT_OKH "write-scope: src/./x\n", "bad write-scope path", NULL,
          NULL),
    CT_NO("an empty segment is refused",
          CONTRACT_OKH "write-scope: src//x\n", "bad write-scope path", NULL,
          NULL),
    CT_NO("a character outside the set is refused",
          CONTRACT_OKH "write-scope: src/a b.c\n", "bad write-scope path",
          NULL, NULL),
    CT_NO("a trailing slash on must-change is refused",
          CONTRACT_OKH "write-scope: src/\nmust-change: src/\n",
          "bad must-change path", NULL, NULL),
    CT_OK(".hidden and ..x are ordinary segments",
          CONTRACT_OKH "write-scope: .hidden/..x/\n"),

    /* base / depends */
    CT_OK("base of 40 and depends of 64 hex",
          CONTRACT_OKH "base: " CT_HEX40 "\ndepends: " CT_HEX64 "\n"),
    CT_NO("base of 39 digits", CONTRACT_OKH "base: " CT_A10 CT_A10 CT_A10
          "aaaaaaaaa\n", "base must be 40 or 64 lowercase hex", NULL, NULL),
    CT_NO("base in uppercase",
          CONTRACT_OKH "base: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
          "base must be 40 or 64 lowercase hex", NULL, NULL),
    CT_NO("depends without a base",
          CONTRACT_OKH "depends: " CT_HEX40 "\n",
          "a dependency ref needs the base it is relative to: add base:",
          NULL, NULL),
    CT_NO("depends equal to base",
          CONTRACT_OKH "base: " CT_HEX40 "\ndepends: " CT_HEX40 "\n",
          "is the base itself or is listed twice", NULL, NULL),
    CT_NO("depends listed twice",
          CONTRACT_OKH "base: " CT_HEX40B "\ndepends: " CT_HEX40 "\ndepends: "
          CT_HEX40 "\n", "is the base itself or is listed twice", NULL, NULL),
    CT_NO("duplicate base",
          CONTRACT_OKH "base: " CT_HEX40 "\nbase: " CT_HEX40B "\n",
          "duplicate key", "`base:`", NULL),

    /* attempt / predecessor */
    CT_OK("repair attempt with a predecessor and a carried notrun-report",
          CONTRACT_OKH "attempt: 2\npredecessor: " CT_HEX40 "\n"
          "evidence: notrun-report phase=verify actor=verifier "
          "from=predecessor\n"),
    CT_OK("attempt 9 with a 64-hex predecessor",
          CONTRACT_OKH "attempt: 9\npredecessor: " CT_HEX64 "\n"),
    CT_NO("attempt above 1 without a predecessor",
          CONTRACT_OKH "attempt: 2\n", "attempt=2", "add predecessor: HEX",
          NULL),
    CT_NO("predecessor with the default attempt",
          CONTRACT_OKH "predecessor: " CT_HEX40 "\n",
          "predecessor is set but attempt is 1", NULL, NULL),
    CT_NO("predecessor with attempt 1 stated",
          CONTRACT_OKH "attempt: 1\npredecessor: " CT_HEX40 "\n",
          "predecessor is set but attempt is 1", NULL, NULL),
    CT_NO("attempt 0", CONTRACT_OKH "attempt: 0\n", "attempt must be one digit",
          NULL, NULL),
    CT_NO("attempt 10", CONTRACT_OKH "attempt: 10\n",
          "attempt must be one digit", NULL, NULL),
    CT_NO("from=predecessor on attempt 1",
          CONTRACT_OKH "evidence: notrun-report phase=verify actor=verifier "
          "from=predecessor\n", "from=predecessor", "attempt is 1", NULL),
    CT_NO("a predecessor's executed-pass is never accepted on a repair",
          CONTRACT_SRC "attempt: 2\npredecessor: " CT_HEX40 "\n"
          CT_PRED_EXEC_FROM,
          "a predecessor's executed-pass covers different bytes; require a "
          "fresh executed-pass in a verification phase", NULL, NULL),

    /* one phase, one actor */
    CT_NO("evidence in the task's phase naming another actor",
          CONTRACT_SRC "evidence: notrun-report phase=author actor=ci\n",
          "phase=author is this task's phase and its actor is author, but "
          "evidence names actor=ci; one phase has one actor here", NULL,
          NULL),
    CT_OK("evidence naming another phase and actor is fine",
          CONTRACT_SRC "evidence: executed-pass phase=verify actor=ci\n"),
};

static int case_contract_rows(void)
{
    int failures = 0;
    for (size_t i = 0; i < sizeof(contract_rows) / sizeof(contract_rows[0]);
         i++) {
        const struct contract_row *r = &contract_rows[i];
        char why[ENGINE_CONTRACT_REASON_BYTES];
        const enum engine_contract_result got = engine_contract_check(
            r->task, strlen(r->task), NULL, why, sizeof(why));
        const bool text = (!r->has1 || strstr(why, r->has1))
                          && (!r->has2 || strstr(why, r->has2))
                          && (!r->has3 || strstr(why, r->has3));
        EN_CHECK(r->name, got == r->want && text
                 && (got == ENGINE_CONTRACT_REFUSED) == (why[0] != '\0'));
    }
    return failures;
}

/* Rows whose task can hold a NUL byte, so each carries its own length, and
 * whose reason must not echo a key the task named (`absent`). */
struct contract_nul_row {
    const char *name;
    const char *task;
    size_t len;
    enum engine_contract_result want;
    const char *has;    /* the reason must hold this */
    const char *absent; /* the reason must not hold this, or NULL */
};

#define CT_NUL_FIRST "\0contract: 1\n" CONTRACT_SRC CONTRACT_POS_EVIDENCE
#define CT_NUL_BODY "kind: fix-gate\n\nbody\0more\n"
#define CT_KEY17 CONTRACT_OKH "abcdefghijklmnopq: x\n"
#define CT_KEY_UNKNOWN CONTRACT_OKH "grant: all\n"

static const struct contract_nul_row contract_nul_rows[] = {
    {"a NUL as the first byte of a contract: line is REFUSED", CT_NUL_FIRST,
     CT_LEN(CT_NUL_FIRST), ENGINE_CONTRACT_REFUSED, "contains a NUL byte",
     NULL},
    {"a NUL in the body after the blank line of a legacy task is REFUSED",
     CT_NUL_BODY, CT_LEN(CT_NUL_BODY), ENGINE_CONTRACT_REFUSED,
     "contains a NUL byte", NULL},
    {"a 17-byte key is REFUSED and its text is not echoed", CT_KEY17,
     CT_LEN(CT_KEY17), ENGINE_CONTRACT_REFUSED, "not `key: value`",
     "abcdefghijklmnopq"},
    {"an unknown short key is REFUSED and its text is not echoed",
     CT_KEY_UNKNOWN, CT_LEN(CT_KEY_UNKNOWN), ENGINE_CONTRACT_REFUSED,
     "allowed keys", "grant"},
};

static int case_contract_nul_rows(void)
{
    int failures = 0;
    for (size_t i = 0; i < sizeof(contract_nul_rows) / sizeof(contract_nul_rows[0]);
         i++) {
        const struct contract_nul_row *r = &contract_nul_rows[i];
        char why[ENGINE_CONTRACT_REASON_BYTES];
        const enum engine_contract_result got = engine_contract_check(
            r->task, r->len, NULL, why, sizeof(why));
        const bool text = strstr(why, r->has) != NULL
                          && (!r->absent || !strstr(why, r->absent));
        EN_CHECK(r->name, got == r->want && text
                 && (got == ENGINE_CONTRACT_REFUSED) == (why[0] != '\0'));
    }
    return failures;
}

static bool contract_view_core_ok(const struct engine_contract *v)
{
    return v->version == 1 && v->evidence_count == 3
           && v->execution == ENGINE_CONTRACT_EXEC_SOURCE_ONLY
           && strcmp(v->phase, "author") == 0
           && v->evidence[1].what == ENGINE_CONTRACT_EVIDENCE_EXECUTED_PASS
           && strcmp(v->evidence[1].phase, "verify") == 0
           && strcmp(v->evidence[1].actor, "verifier") == 0
           && v->evidence[2].from_predecessor
           && !v->evidence[0].from_predecessor;
}

static bool contract_view_keys_ok(const struct engine_contract *v)
{
    return v->has_output && v->min_bytes == 1 && v->max_bytes == 9
           && v->scope_count == 1 && strcmp(v->write_scope[0], "src/") == 0
           && v->must_count == 1 && v->depends_count == 1
           && strcmp(v->base, CT_HEX40) == 0 && v->attempt == 2
           && strcmp(v->predecessor, CT_HEX64) == 0;
}

static int case_contract_view(void)
{
    int failures = 0;
    struct engine_contract v;
    char why[ENGINE_CONTRACT_REASON_BYTES];
    const char *t = CONTRACT_OKH "output: min-bytes=1 max-bytes=9\n"
                    "write-scope: src/\nmust-change: src/a.c\n"
                    "base: " CT_HEX40 "\ndepends: " CT_HEX40B "\n"
                    "attempt: 2\npredecessor: " CT_HEX64 "\n"
                    "evidence: notrun-report phase=verify actor=verifier "
                    "from=predecessor\n\nbody\n";
    const enum engine_contract_result r =
        engine_contract_check(t, strlen(t), &v, why, sizeof(why));
    EN_CHECK("typed OK fills the parsed view",
             r == ENGINE_CONTRACT_OK && contract_view_core_ok(&v));
    EN_CHECK("the newer keys land in the view", contract_view_keys_ok(&v));
    EN_CHECK("a task of length 0 is LEGACY and a NULL task is LEGACY",
             engine_contract_check("contract: 1\n", 0, &v, why, sizeof(why))
                 == ENGINE_CONTRACT_LEGACY
             && engine_contract_check(NULL, 0, NULL, NULL, 0)
                 == ENGINE_CONTRACT_LEGACY);
    return failures;
}


static int case_contract_nul(void)
{
    int failures = 0;
    char why[ENGINE_CONTRACT_REASON_BYTES];
    static const char in_value[] =
        "contract: 1\nphase: aut\0hor\nactor: author\nexecution: source-only\n"
        CONTRACT_POS_EVIDENCE;
    static const char in_key[] =
        "contract: 1\npha\0se: author\nactor: author\nexecution: source-only\n"
        CONTRACT_POS_EVIDENCE;
    static const char in_version[] = "contract: 1\0\nphase: author\n";
    EN_CHECK("an embedded NUL in a value is refused, not truncated",
             engine_contract_check(in_value, sizeof(in_value) - 1, NULL, why,
                                   sizeof(why)) == ENGINE_CONTRACT_REFUSED
             && strstr(why, "contains a NUL byte"));
    EN_CHECK("an embedded NUL in a key is refused",
             engine_contract_check(in_key, sizeof(in_key) - 1, NULL, why,
                                   sizeof(why)) == ENGINE_CONTRACT_REFUSED
             && strstr(why, "contains a NUL byte"));
    EN_CHECK("an embedded NUL in the version value is refused",
             engine_contract_check(in_version, sizeof(in_version) - 1, NULL,
                                   why, sizeof(why)) == ENGINE_CONTRACT_REFUSED
             && strstr(why, "contains a NUL byte"));
    return failures;
}

static size_t contract_fill_lines(char *buf, size_t cap, size_t lines,
                                  const char *line)
{
    size_t n = 0;
    buf[0] = '\0';
    for (size_t i = 0; i < lines; i++)
        n += (size_t)snprintf(buf + n, cap - n, "%s", line);
    return n;
}

static int case_contract_bounds(void)
{
    int failures = 0;
    static char big[16384];
    char why[ENGINE_CONTRACT_REASON_BYTES];
    size_t n = (size_t)snprintf(big, sizeof(big), "%s", CONTRACT_SRC);
    for (unsigned i = 0; i < ENGINE_CONTRACT_MAX_EVIDENCE + 1u; i++)
        n += (size_t)snprintf(big + n, sizeof(big) - n,
                              "evidence: notrun-report phase=p%u actor=a\n",
                              i);
    EN_CHECK("evidence over the item cap refused",
             engine_contract_check(big, n, NULL, why, sizeof(why))
                 == ENGINE_CONTRACT_REFUSED && strstr(why, "too many evidence"));
    n = (size_t)snprintf(big, sizeof(big), "contract: 1\n");
    n += contract_fill_lines(big + n, sizeof(big) - n,
                             ENGINE_CONTRACT_MAX_FIELDS, "kind: x\n");
    EN_CHECK("header over the field cap refused",
             engine_contract_check(big, n, NULL, why, sizeof(why))
                 == ENGINE_CONTRACT_REFUSED && strstr(why, "exceeds its bounds"));
    n = (size_t)snprintf(big, sizeof(big), "contract: 1\nphase: ");
    memset(big + n, 'a', ENGINE_CONTRACT_MAX_HEADER_BYTES + 8u);
    n += ENGINE_CONTRACT_MAX_HEADER_BYTES + 8u;
    EN_CHECK("header over the byte cap refused",
             engine_contract_check(big, n, NULL, why, sizeof(why))
                 == ENGINE_CONTRACT_REFUSED && strstr(why, "exceeds its bounds"));
    EN_CHECK("a tiny reason buffer is bounded, not overrun",
             engine_contract_check(CONTRACT_SRC CONTRACT_NEG_EVIDENCE,
                                   strlen(CONTRACT_SRC CONTRACT_NEG_EVIDENCE),
                                   NULL, why, 16) == ENGINE_CONTRACT_REFUSED
             && strlen(why) == 15);
    return failures;
}

/* A `contract:` line beyond the line or byte window must not hide. */
static int case_contract_window(void)
{
    int failures = 0;
    static char big[16384];
    char why[ENGINE_CONTRACT_REASON_BYTES];
    size_t n = contract_fill_lines(big, sizeof(big),
                                   ENGINE_CONTRACT_MAX_HEADER_LINES, "a: 1\n");
    n += (size_t)snprintf(big + n, sizeof(big) - n, "%s", CONTRACT_OKH);
    EN_CHECK("contract on the line after the line window is REFUSED, not "
             "legacy",
             engine_contract_check(big, n, NULL, why, sizeof(why))
                 == ENGINE_CONTRACT_REFUSED && strstr(why, "exceeds its bounds"));
    n = (size_t)snprintf(big, sizeof(big), "x: ");
    memset(big + n, 'a', 3000u + ENGINE_CONTRACT_MAX_HEADER_BYTES);
    n += 3000u + ENGINE_CONTRACT_MAX_HEADER_BYTES;
    n += (size_t)snprintf(big + n, sizeof(big) - n, "\n%s", CONTRACT_OKH);
    EN_CHECK("contract after one over-long first line is REFUSED, not legacy",
             engine_contract_check(big, n, NULL, why, sizeof(why))
                 == ENGINE_CONTRACT_REFUSED && strstr(why, "exceeds its bounds"));
    n = contract_fill_lines(big, sizeof(big),
                            ENGINE_CONTRACT_MAX_HEADER_LINES + 20u, "a: 1\n");
    EN_CHECK("a long legacy header with no contract line stays LEGACY",
             engine_contract_check(big, n, NULL, why, sizeof(why))
                 == ENGINE_CONTRACT_LEGACY);
    n = (size_t)snprintf(big, sizeof(big), "x: ");
    memset(big + n, 'a', 3000u + ENGINE_CONTRACT_MAX_HEADER_BYTES);
    n += 3000u + ENGINE_CONTRACT_MAX_HEADER_BYTES;
    EN_CHECK("one over-long legacy line stays LEGACY",
             engine_contract_check(big, n, NULL, why, sizeof(why))
                 == ENGINE_CONTRACT_LEGACY);
    n = contract_fill_lines(big, sizeof(big),
                            ENGINE_CONTRACT_MAX_HEADER_LINES + 5u, "a: 1\n");
    n += (size_t)snprintf(big + n, sizeof(big) - n, "\ncontract: 1\n");
    EN_CHECK("contract after the blank line beyond the window is prose",
             engine_contract_check(big, n, NULL, why, sizeof(why))
                 == ENGINE_CONTRACT_LEGACY);

    /* full-size legal header: every key at its cap fits the bounds */
    n = (size_t)snprintf(big, sizeof(big), "%s", CONTRACT_SRC);
    for (unsigned i = 0; i < ENGINE_CONTRACT_MAX_PATHS; i++)
        n += (size_t)snprintf(big + n, sizeof(big) - n,
                              "write-scope: " CT_P191 "\n");
    for (unsigned i = 0; i < 4; i++)
        n += (size_t)snprintf(big + n, sizeof(big) - n,
                              "evidence: notrun-report phase=p%u actor=a\n", i);
    EN_CHECK("8 maximum-length write-scope paths and 4 evidence fit",
             engine_contract_check(big, n, NULL, why, sizeof(why))
                 == ENGINE_CONTRACT_OK);
    n = (size_t)snprintf(big, sizeof(big), "%s", CONTRACT_OKH);
    for (unsigned i = 0; i < ENGINE_CONTRACT_MAX_PATHS + 1u; i++)
        n += (size_t)snprintf(big + n, sizeof(big) - n,
                              "write-scope: d%u/\n", i);
    EN_CHECK("9 write-scope entries refused",
             engine_contract_check(big, n, NULL, why, sizeof(why))
                 == ENGINE_CONTRACT_REFUSED
             && strstr(why, "too many write-scope"));
    n = (size_t)snprintf(big, sizeof(big), "%swrite-scope: src/\n",
                         CONTRACT_OKH);
    for (unsigned i = 0; i < ENGINE_CONTRACT_MAX_PATHS + 1u; i++)
        n += (size_t)snprintf(big + n, sizeof(big) - n,
                              "must-change: src/f%u.c\n", i);
    EN_CHECK("9 must-change entries refused",
             engine_contract_check(big, n, NULL, why, sizeof(why))
                 == ENGINE_CONTRACT_REFUSED
             && strstr(why, "too many must-change"));
    return failures;
}

static int case_contract_kind(void)
{
    int failures = 0;
    const char *k = engine_prompt_kind_from_header(
        "kind: fix-gate\n" CONTRACT_SRC CONTRACT_POS_EVIDENCE "\nbody\n");
    EN_CHECK("kind before the contract lines is found",
             k && strcmp(k, "fix-gate") == 0);
    k = engine_prompt_kind_from_header(
        CONTRACT_SRC CONTRACT_POS_EVIDENCE
        "evidence: notrun-report phase=q actor=q\nkind: add-test\n\nbody\n");
    EN_CHECK("kind after the contract lines is found beyond line 8",
             k && strcmp(k, "add-test") == 0);
    k = engine_prompt_kind_from_header(
        "a: 1\nb: 2\nc: 3\nd: 4\ne: 5\nf: 6\ng: 7\nh: 8\nkind: add-test\n\n"
        "body\n");
    EN_CHECK("legacy 8-line bound unchanged: kind on line 9 is not found",
             k == NULL);
    k = engine_prompt_kind_from_header(
        "a: 1\nb: 2\nc: 3\nd: 4\ne: 5\nf: 6\ng: 7\nh: 8\ni: 9\nkind: x\n"
        "contract: 1\n\nbody\n");
    EN_CHECK("contract on line 11 widens the scan, so kind on line 10 is "
             "found",
             k && strcmp(k, "x") == 0);
    return failures;
}

#if !defined(_WIN32)
struct contract_fx {
    char dir[600];
    char neg[700], pos[700], legacy[700], reply[700];
    char wt[700], st[700];
};

/* Run `args` through the real binary into <dir>/<name>.log; return the exit
 * status (-1 when it did not exit) and the captured text in out. */
static int contract_unit(const struct contract_fx *x, const char *name,
                         const char *args, char *out, size_t cap)
{
    char cmd[4096], log[700];
    (void)snprintf(log, sizeof(log), "%s/%s.log", x->dir, name);
    (void)snprintf(cmd, sizeof(cmd), "%s --engine fixture %s >%s 2>&1",
                   ENGINE_UNIT_BIN, args, log);
    const int rc = system(cmd);
    out[0] = '\0';
    (void)read_whole_file(log, out, cap);
    return rc != -1 && WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

static bool contract_dir_empty(const char *dir)
{
    char cmd[1024];
    (void)snprintf(cmd, sizeof(cmd), "test -z \"$(ls -A %s)\"", dir);
    return system(cmd) == 0;
}

static bool contract_fx_init(struct contract_fx *x)
{
    char rel[512];
    test_make_tmpdir(rel, sizeof(rel), "engine_contract", "run");
    if (!test_abs_path(rel, x->dir, sizeof(x->dir)))
        return false;
    (void)snprintf(x->neg, sizeof(x->neg), "%s/neg.txt", x->dir);
    (void)snprintf(x->pos, sizeof(x->pos), "%s/pos.txt", x->dir);
    (void)snprintf(x->legacy, sizeof(x->legacy), "%s/legacy.txt", x->dir);
    (void)snprintf(x->reply, sizeof(x->reply), "%s/reply.json", x->dir);
    (void)snprintf(x->wt, sizeof(x->wt), "%s/wt", x->dir);
    (void)snprintf(x->st, sizeof(x->st), "%s/st", x->dir);
    (void)mkdir(x->wt, 0700);
    (void)mkdir(x->st, 0700);
    return write_whole_file(x->neg, "kind: fix-gate\n" CONTRACT_SRC
                                    CONTRACT_NEG_EVIDENCE "\nA smoke task.\n")
           && write_whole_file(x->pos, "kind: fix-gate\n" CONTRACT_SRC
                                       CONTRACT_POS_EVIDENCE
                                       "\nA smoke task.\n")
           && write_whole_file(x->legacy,
                               "kind: fix-gate\n\nA task with no contract.\n")
           && write_whole_file(x->reply,
               "{\"choices\":[{\"message\":{\"content\":\"No file changes.\""
               "}}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":4,"
               "\"total_tokens\":14}}");
}

static int case_contract_neg(const struct contract_fx *x)
{
    int failures = 0;
    char args[2048], out[16384], nokey[700], rest[700];
    (void)snprintf(args, sizeof(args), "--task %s --no-group --dry-run "
                   "--fixture-reply %s", x->neg, x->reply);
    const int rc_dry = contract_unit(x, "neg_dry", args, out, sizeof(out));
    EN_CHECK("NEG refused preview exits 0", rc_dry == 0);
    EN_CHECK("NEG dry-run names both fields and the correction",
             strstr(out, "execution=source-only")
             && strstr(out, "actor=author in phase=author")
             && strstr(out, "execution: may-execute"));
    EN_CHECK("NEG dry-run says WOULD BE REFUSED, never would dispatch",
             strstr(out, "WOULD BE REFUSED") && !strstr(out, "would dispatch"));

    (void)snprintf(args, sizeof(args), "--task %s --no-group --yes-dispatch "
                   "--fixture-reply %s", x->neg, x->reply);
    const int rc = contract_unit(x, "neg_real", args, out, sizeof(out));
    EN_CHECK("NEG real path fails non-zero with the same reason",
             rc == 2 && strstr(out, "execution=source-only")
             && strstr(out, "actor=author in phase=author"));

    /* Missing key file, fresh empty worktree and state dir: if any effect
     * path ran first, the failure would be about the key or the workspace,
     * or one of the two directories would no longer be empty. */
    (void)snprintf(nokey, sizeof(nokey), "%s/no-such-key", x->dir);
    (void)snprintf(rest, sizeof(rest), "%s/receipt.json", x->st);
    (void)snprintf(args, sizeof(args), "--task %s --no-group --yes-dispatch "
                   "--fixture-reply %s --key-file %s --worktree %s "
                   "--state-dir %s", x->neg, x->reply, nokey, x->wt, x->st);
    const int rc3 = contract_unit(x, "neg_effects", args, out, sizeof(out));
    EN_CHECK("NEG fails with the CONTRACT reason, not a credential or "
             "workspace error",
             rc3 == 2 && strstr(out, "execution=source-only")
             && !strstr(out, "API key") && !strstr(out, "credential")
             && !strstr(out, "worktree"));
    EN_CHECK("NEG left the worktree and state dirs empty and wrote no receipt",
             contract_dir_empty(x->wt) && contract_dir_empty(x->st)
             && access(rest, F_OK) != 0 && access(nokey, F_OK) != 0);
    return failures;
}

static int case_contract_pos(const struct contract_fx *x)
{
    int failures = 0;
    char args[2048], out[16384];
    (void)snprintf(args, sizeof(args), "--task %s --no-group --dry-run "
                   "--fixture-reply %s", x->pos, x->reply);
    int rc = contract_unit(x, "pos_dry", args, out, sizeof(out));
    EN_CHECK("POS dry-run says would dispatch and prints its contract line",
             rc == 0 && strstr(out, "would dispatch")
             && !strstr(out, "WOULD BE REFUSED")
             && strstr(out, "contract:   v1 phase=author actor=author "
                            "execution=source-only evidence=2"));
    (void)snprintf(args, sizeof(args), "--task %s --no-group --yes-dispatch "
                   "--worktree %s --state-dir %s --fixture-reply %s", x->pos,
                   x->wt, x->st, x->reply);
    rc = contract_unit(x, "pos_real", args, out, sizeof(out));
    EN_CHECK("POS real fixture dispatch is not refused by the contract",
             rc != 2 && !strstr(out, "contract refused")
             && strstr(out, "turn 1/"));

    static char chain[32768];
    char want[128], hex[65], body[512] = {0}, rp[700];
    uint8_t d[32];
    (void)snprintf(rp, sizeof(rp), "%s/%s", x->st, ENGINE_RECEIPT_FILENAME);
    (void)read_whole_file(x->pos, body, sizeof(body));
    zcl_sha3_256((const unsigned char *)body, strlen(body), d);
    zcl_hex_encode(d, 32, hex);
    (void)snprintf(want, sizeof(want), "\"task_sha3\":\"%s\"", hex);
    chain[0] = '\0';
    EN_CHECK("POS receipt binds the sha3 of the task file bytes",
             read_whole_file(rp, chain, sizeof(chain)) && strstr(chain, want));
    return failures;
}

static int case_contract_legacy_and_carry(const struct contract_fx *x)
{
    int failures = 0;
    char args[2048], out[16384], a1[700], a2[700], a1state[700], att[700];
    (void)snprintf(args, sizeof(args), "--task %s --no-group --dry-run "
                   "--fixture-reply %s", x->legacy, x->reply);
    int rc = contract_unit(x, "legacy_dry", args, out, sizeof(out));
    EN_CHECK("LEGACY dry-run is as before plus the untyped line",
             rc == 0 && strstr(out, "would dispatch")
             && strstr(out, "contract:   none (legacy task; obligations "
                            "not checked)"));

    /* Predecessor state sits in a1/state.txt; the run is attempt a2. */
    (void)snprintf(att, sizeof(att), "%s/attempts", x->dir);
    (void)snprintf(a1, sizeof(a1), "%s/a1", att);
    (void)snprintf(a2, sizeof(a2), "%s/a2", att);
    (void)snprintf(a1state, sizeof(a1state), "%s/state.txt", a1);
    (void)mkdir(att, 0700);
    (void)mkdir(a1, 0700);
    (void)mkdir(a2, 0700);
    EN_CHECK("carried-state fixture written",
             write_whole_file(a1state, CONTRACT_SRC CONTRACT_NEG_EVIDENCE
                              "tried: x\n"));
    (void)snprintf(args, sizeof(args), "--task %s --no-group --dry-run "
                   "--fixture-reply %s --state-dir %s", x->legacy, x->reply,
                   a2);
    rc = contract_unit(x, "carry_legacy", args, out, sizeof(out));
    EN_CHECK("a contract-looking predecessor state does not type a legacy task",
             rc == 0 && strstr(out, "carrying") && strstr(out, "would dispatch")
             && strstr(out, "contract:   none (legacy task")
             && !strstr(out, "contract refused"));
    (void)snprintf(args, sizeof(args), "--task %s --no-group --dry-run "
                   "--fixture-reply %s --state-dir %s", x->pos, x->reply, a2);
    rc = contract_unit(x, "carry_pos", args, out, sizeof(out));
    EN_CHECK("a contradictory predecessor state does not refuse a good task",
             rc == 0 && strstr(out, "carrying") && strstr(out, "would dispatch")
             && strstr(out, "evidence=2") && !strstr(out, "contract refused"));
    return failures;
}

/* A must-change path of exactly 191 valid bytes (the validator's limit), no
 * write-scope covering it: 191 = 3 * 50 + 41. No segment is empty, `.` or
 * `..`. */
#define CT_SEG10 "abcd/abcd/abcd/abcd/abcd/abcd/abcd/abcd/abcd/abcd/"
#define CT_PATH191 CT_SEG10 CT_SEG10 CT_SEG10 \
    "abcd/abcd/abcd/abcd/abcd/abcd/abcd/abcd/e"
#define CT_LONG_NAME "uncovered must-change path at the 191-byte limit"
#define CT_LONG_TAIL "add it to write-scope or drop the must-change"

/* Every header that crosses the real binary below: refused ones carry the
 * reason fragment, accepted ones carry NULL. */
struct contract_bin_row {
    const char *name;
    const char *header;
    const char *reason; /* NULL: must be accepted */
};

static const struct contract_bin_row contract_bin_rows[] = {
    {"source-only owns its executed-pass",
     CONTRACT_SRC CONTRACT_NEG_EVIDENCE,
     "execution=source-only but this same actor=author in phase=author "
     "owes an executed-pass"},
    {"output bounds",
     CONTRACT_OKH "output: min-bytes=9 max-bytes=3\n",
     "lower min-bytes or raise max-bytes"},
    {"write scope",
     CONTRACT_OKH "write-scope: src/a\nmust-change: src/ab.c\n",
     "add it to write-scope or drop the must-change"},
    {"missing base", CONTRACT_OKH "depends: " CT_HEX40 "\n",
     "a dependency ref needs the base it is relative to: add base:"},
    {"predecessor evidence",
     CONTRACT_SRC "attempt: 2\npredecessor: " CT_HEX40 "\n" CT_PRED_EXEC_FROM,
     "a predecessor's executed-pass covers different bytes"},
    {"actor/phase conflict",
     CONTRACT_SRC "evidence: notrun-report phase=author actor=ci\n",
     "one phase has one actor here"},
    {"split executed-pass is accepted", CONTRACT_OKH, NULL},
    {"every key present is accepted",
     CONTRACT_OKH "output: min-bytes=1 max-bytes=9\nwrite-scope: src/\n"
     "must-change: src/a.c\nbase: " CT_HEX40 "\ndepends: " CT_HEX40B "\n"
     "attempt: 2\npredecessor: " CT_HEX64 "\n"
     "evidence: notrun-report phase=verify actor=verifier "
     "from=predecessor\n",
     NULL},
    {"duplicate evidence",
     CONTRACT_SRC CONTRACT_POS_EVIDENCE
     "evidence: notrun-report phase=author actor=author\n",
     "duplicate evidence"},
    {"depends equal to base",
     CONTRACT_OKH "base: " CT_HEX40 "\ndepends: " CT_HEX40 "\n",
     "is the base itself"},
    {"attempt 2 without a predecessor", CONTRACT_OKH "attempt: 2\n",
     "no predecessor is named"},
    {"predecessor with attempt 1",
     CONTRACT_OKH "predecessor: " CT_HEX64 "\n",
     "predecessor is set but attempt is 1"},
    {"from=predecessor on attempt 1",
     CONTRACT_OKH "evidence: notrun-report phase=verify actor=verifier "
     "from=predecessor\n",
     "evidence from=predecessor"},
    {CT_LONG_NAME,
     CONTRACT_OKH "write-scope: src/a\nmust-change: " CT_PATH191 "\n",
     CT_LONG_TAIL},
};

/* The reason line starts at "contract refused:" and must end in a newline
 * inside cap, so the copy into dst (cap bytes) is whole. A line that does
 * not fit returns false: a truncated reason must not compare equal. */
static bool contract_reason_line(const char *out, char *dst, size_t cap)
{
    const char *p = strstr(out, "contract refused:");
    if (!p)
        return false;
    size_t n = 0;
    while (n < cap && p[n] && p[n] != '\n')
        n++;
    if (n == cap || p[n] != '\n')
        return false;
    memcpy(dst, p, n);
    dst[n] = '\0';
    return true;
}

/* An accepted header's real run got past the contract gate: exit 1 (the
 * fixture's own no-change verdict), the status line, no refusal, and a
 * verdict line from the engine. */
static bool contract_reaches_dispatch(int rc, const char *real)
{
    return rc == 1 && strstr(real, "contract:   v1")
           && !strstr(real, "contract refused")
           && strstr(real, "engine_unit: ");
}

/* The long must-change row keeps its corrective tail in both captures, so
 * the full reason line was captured and nothing was cut. */
static int contract_agree_tail(const struct contract_bin_row *r,
                               const char *dr, const char *rr)
{
    int failures = 0;
    char name[200];
    if (strcmp(r->name, CT_LONG_NAME) != 0)
        return 0;
    (void)snprintf(name, sizeof(name), "AGREE %s: reason keeps its "
                   "corrective tail", r->name);
    EN_CHECK(name, strstr(dr, CT_LONG_TAIL) && strstr(rr, CT_LONG_TAIL));
    return failures;
}

/* One header through dry-run and real, each in its own fresh empty dirs. */
static int case_contract_agree_row(const struct contract_fx *x, size_t i,
                                   const struct contract_bin_row *r)
{
    int failures = 0;
    char task[700], wt[700], st[700], args[2600], name[200];
    static char dry[16384], real[16384], body[8192];
    char dr[ENGINE_CONTRACT_REASON_BYTES] = {0};
    char rr[ENGINE_CONTRACT_REASON_BYTES] = {0};
    (void)snprintf(task, sizeof(task), "%s/agree%zu.txt", x->dir, i);
    (void)snprintf(wt, sizeof(wt), "%s/agree_wt%zu", x->dir, i);
    (void)snprintf(st, sizeof(st), "%s/agree_st%zu", x->dir, i);
    (void)mkdir(wt, 0700);
    (void)mkdir(st, 0700);
    (void)snprintf(body, sizeof(body), "kind: fix-gate\n%s\nA smoke task.\n",
                   r->header);
    if (!write_whole_file(task, body)) {
        printf("engine: FAIL (cannot write %s)\n", task);
        return 1;
    }
    (void)snprintf(args, sizeof(args), "--task %s --no-group --dry-run "
                   "--fixture-reply %s", task, x->reply);
    const int rc_dry = contract_unit(x, "agree_dry", args, dry, sizeof(dry));
    (void)snprintf(args, sizeof(args), "--task %s --no-group --yes-dispatch "
                   "--fixture-reply %s --worktree %s --state-dir %s", task,
                   x->reply, wt, st);
    const int rc = contract_unit(x, "agree_real", args, real, sizeof(real));
    const bool dry_ref = contract_reason_line(dry, dr, sizeof(dr));
    const bool real_ref = rc == 2 && contract_reason_line(real, rr, sizeof(rr));
    const bool want_ref = r->reason != NULL;

    (void)snprintf(name, sizeof(name), "AGREE %s: preview and real both %s",
                   r->name, want_ref ? "refuse" : "accept");
    EN_CHECK(name, dry_ref == want_ref && real_ref == want_ref);
    if (want_ref) {
        (void)snprintf(name, sizeof(name), "AGREE %s: refused preview exits 0",
                       r->name);
        EN_CHECK(name, rc_dry == 0);
    }
    (void)snprintf(name, sizeof(name), "AGREE %s: reason line byte-identical",
                   r->name);
    EN_CHECK(name, !want_ref
             || (strcmp(dr, rr) == 0 && strstr(dr, r->reason)));
    (void)snprintf(name, sizeof(name), "AGREE %s: accepted real run passes "
                   "the gate and reaches dispatch", r->name);
    EN_CHECK(name, want_ref || contract_reaches_dispatch(rc, real));
    (void)snprintf(name, sizeof(name), "AGREE %s: preview verdict wording",
                   r->name);
    EN_CHECK(name, want_ref ? (strstr(dry, "WOULD BE REFUSED")
                               && !strstr(dry, "would dispatch"))
                            : (strstr(dry, "would dispatch")
                               && !strstr(dry, "WOULD BE REFUSED")));
    (void)snprintf(name, sizeof(name), "AGREE %s: refusal left dirs empty "
                   "and no receipt", r->name);
    EN_CHECK(name, !want_ref
             || (contract_dir_empty(wt) && contract_dir_empty(st)));
    failures += contract_agree_tail(r, dr, rr);
    return failures;
}

/* A NUL byte before the contract line. Written with an explicit length:
 * write_whole_file would stop at the NUL and test a different file. */
#define CT_BIN_NUL "kind: fix-gate\n\0" CONTRACT_SRC CONTRACT_POS_EVIDENCE \
    "\nA smoke task.\n"

static bool contract_write_bytes(const char *path, const char *s, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    const bool ok = fwrite(s, 1, n, f) == n;
    return fclose(f) == 0 && ok;
}

/* Preview and real both refuse the NUL task with one identical reason line,
 * and the refusal leaves both directories empty. */
static int case_contract_agree_nul(const struct contract_fx *x)
{
    int failures = 0;
    char task[700], wt[700], st[700], args[2600];
    static char dry[16384], real[16384];
    char dr[ENGINE_CONTRACT_REASON_BYTES] = {0};
    char rr[ENGINE_CONTRACT_REASON_BYTES] = {0};
    (void)snprintf(task, sizeof(task), "%s/agree_nul.txt", x->dir);
    (void)snprintf(wt, sizeof(wt), "%s/agree_nul_wt", x->dir);
    (void)snprintf(st, sizeof(st), "%s/agree_nul_st", x->dir);
    (void)mkdir(wt, 0700);
    (void)mkdir(st, 0700);
    if (!contract_write_bytes(task, CT_BIN_NUL, CT_LEN(CT_BIN_NUL))) {
        printf("engine: FAIL (cannot write %s)\n", task);
        return 1;
    }
    (void)snprintf(args, sizeof(args), "--task %s --no-group --dry-run "
                   "--fixture-reply %s", task, x->reply);
    const int rc_dry =
        contract_unit(x, "agree_nul_dry", args, dry, sizeof(dry));
    (void)snprintf(args, sizeof(args), "--task %s --no-group --yes-dispatch "
                   "--fixture-reply %s --worktree %s --state-dir %s", task,
                   x->reply, wt, st);
    const int rc = contract_unit(x, "agree_nul_real", args, real, sizeof(real));
    const bool dry_ref = contract_reason_line(dry, dr, sizeof(dr));
    const bool real_ref = rc == 2 && contract_reason_line(real, rr, sizeof(rr));
    EN_CHECK("AGREE NUL before the contract line: preview and real both refuse",
             dry_ref && real_ref);
    EN_CHECK("AGREE NUL before the contract line: refused preview exits 0",
             rc_dry == 0);
    EN_CHECK("AGREE NUL before the contract line: reason line byte-identical "
             "and names the NUL",
             strcmp(dr, rr) == 0 && strstr(dr, "contains a NUL byte"));
    EN_CHECK("AGREE NUL before the contract line: refusal left dirs empty "
             "and no receipt",
             contract_dir_empty(wt) && contract_dir_empty(st));
    return failures;
}

static int case_contract_agree(const struct contract_fx *x)
{
    int failures = 0;
    for (size_t i = 0;
         i < sizeof(contract_bin_rows) / sizeof(contract_bin_rows[0]); i++)
        failures += case_contract_agree_row(x, i, &contract_bin_rows[i]);
    return failures;
}

static int case_contract_binary(void)
{
    int failures = 0;
    struct contract_fx x;
    if (!engine_unit_binary_present()) {
        printf("engine: FAIL (%s is a required prerequisite)\n",
               ENGINE_UNIT_BIN);
        return 1;
    }
    const bool ready = contract_fx_init(&x);
    EN_CHECK("contract fixtures are written", ready);
    if (!ready)
        return failures;
    failures += case_contract_neg(&x);
    failures += case_contract_pos(&x);
    failures += case_contract_legacy_and_carry(&x);
    failures += case_contract_agree(&x);
    failures += case_contract_agree_nul(&x);
    return failures;
}
#endif

static int case_contract(void)
{
    int failures = 0;
    failures += case_contract_rows();
    failures += case_contract_nul_rows();
    failures += case_contract_view();
    failures += case_contract_nul();
    failures += case_contract_bounds();
    failures += case_contract_window();
    failures += case_contract_kind();
#if !defined(_WIN32)
    failures += case_contract_binary();
#endif
    return failures;
}

/* The patch kind takes a fully specified change on a light worker and must
 * report a design question rather than choose; the review-pass kind returns
 * findings and no verdict. Both are light, and the standard edit kinds stay
 * standard. */
static int case_light_patch_kind(void)
{
    int failures = 0;
    EN_CHECK("c23-patch is light",
             engine_prompt_kind_tier("c23-patch") == ENGINE_PROMPT_TIER_LIGHT);
    const char *why = "unset";
    EN_CHECK("tier rows stay closed with the two new kinds",
             engine_prompt_tiers_closed(&why) && why == NULL);
    EN_CHECK("c23-patch supplies every required section",
             engine_prompt_kind_is_complete("c23-patch"));
    const char *patch_rules = engine_prompt_template_body("c23-patch", "rules");
    EN_CHECK("c23-patch reports a design question instead of choosing",
             patch_rules && strstr(patch_rules, "Do not choose"));
    EN_CHECK("c23-patch edits only the files the brief owns",
             patch_rules
             && strstr(patch_rules, "Edit only the files the brief owns"));
    EN_CHECK("c23-patch stops when the brief contradicts the tree",
             patch_rules && strstr(patch_rules, "brief contradicts the tree"));
    const char *patch_task = engine_prompt_template_body("c23-patch", "task");
    EN_CHECK("c23-patch quotes each line before replacing it",
             patch_task
             && strstr(patch_task, "quote the lines you will replace"));
    EN_CHECK("c23-patch never weakens an assertion",
             patch_task
             && strstr(patch_task,
                       "Never weaken, delete or skip an assertion"));
    const char *patch_judging =
        engine_prompt_template_body("c23-patch", "judging");
    EN_CHECK("c23-patch rejects weakening or deleting an assertion",
             patch_judging
             && strstr(patch_judging,
                       "weakening or deleting an assertion"));
    EN_CHECK("c23-patch allows a test update the brief names",
             patch_judging
             && strstr(patch_judging,
                       "A test update the brief names is allowed"));
    EN_CHECK("c23-patch escalates after one failed round",
             patch_judging
             && strstr(patch_judging, "One failed round sends the unit"));
    return failures;
}

static int case_review_pass_no_new_file(void)
{
    int failures = 0;
    const char *review_rules =
        engine_prompt_template_body("c23-review-pass", "rules");
    EN_CHECK("c23-review-pass says a command must leave no new file",
             review_rules && strstr(review_rules, "leave no new file"));
    return failures;
}

static int case_light_review_pass_kind(void)
{
    int failures = 0;
    EN_CHECK("c23-review-pass is light",
             engine_prompt_kind_tier("c23-review-pass")
             == ENGINE_PROMPT_TIER_LIGHT);
    EN_CHECK("c23-review-pass supplies every required section",
             engine_prompt_kind_is_complete("c23-review-pass"));
    const char *review_rules =
        engine_prompt_template_body("c23-review-pass", "rules");
    EN_CHECK("c23-review-pass says not to supply a fact from memory",
             review_rules && strstr(review_rules, "do not supply it from memory"));
    EN_CHECK("c23-review-pass says quote lines exactly",
             review_rules && strstr(review_rules, "do not paraphrase a quote"));
    EN_CHECK("c23-review-pass names a missing cleanup only from the diff",
             review_rules && strstr(review_rules, "NOT IN DIFF"));
    const char *review_protocol =
        engine_prompt_template_body("c23-review-pass", "protocol");
    EN_CHECK("c23-review-pass leads with findings",
             review_protocol && strstr(review_protocol, "Findings first"));
    EN_CHECK("c23-review-pass marks each finding CHANGE or CLAIM",
             review_protocol
             && strstr(review_protocol,
                       "about the CHANGE or about a CLAIM"));
    EN_CHECK("c23-review-pass says uncaught code has unknown coverage",
             review_protocol
             && strstr(review_protocol, "its coverage is unknown"));
    EN_CHECK("c23-review-pass never replaces the independent review",
             review_protocol
             && strstr(review_protocol,
                       "never replaces the required independent review"));
    EN_CHECK("c23-review-pass lists what it did not read",
             review_protocol && strstr(review_protocol, "NOT REVIEWED"));
    EN_CHECK("c23-review-pass says a NOT REVIEWED line is not clean",
             review_protocol && strstr(review_protocol, "is not a clean result"));
    EN_CHECK("c23-review-pass states what it sampled and how",
             review_protocol
             && strstr(review_protocol, "State what you sampled and how"));
    const char *review_judging =
        engine_prompt_template_body("c23-review-pass", "judging");
    EN_CHECK("c23-review-pass returns findings and no verdict",
             review_judging && strstr(review_judging, "Return findings only"));
    EN_CHECK("c23-review-pass discards a finding with no file and line",
             review_judging
             && strstr(review_judging,
                       "A finding with no file and line is discarded"));
    EN_CHECK("c23-review-pass sends flagged work to a whole-change review",
             review_judging
             && strstr(review_judging, "review of the whole change"));
    EN_CHECK("review and fix-gate are still standard",
             engine_prompt_kind_tier("review") == ENGINE_PROMPT_TIER_STANDARD
             && engine_prompt_kind_tier("fix-gate")
                 == ENGINE_PROMPT_TIER_STANDARD);
    return failures;
}

#if !defined(_WIN32)

/* ── the fleet ledger row a finished Claude CLI unit files ───────────────
 * Runs the real binary against a fake `claude` that prints a canned result
 * and a fake ledger program that records its argv, one arg per line. */

#define CLAUDE_LEDGER_BODY(COST) \
    "{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false," \
    "\"num_turns\":3,\"result\":\"done\"," \
    "\"session_id\":\"63c495cb-5b9f-4e4a-8979-29ed2a67f8b1\"," COST \
    "\"usage\":{\"input_tokens\":7,\"cache_creation_input_tokens\":13822," \
    "\"cache_read_input_tokens\":100,\"output_tokens\":41}," \
    "\"modelUsage\":{\"claude-haiku-5-5\":{\"inputTokens\":7," \
    "\"outputTokens\":41,\"cacheReadInputTokens\":100," \
    "\"cacheCreationInputTokens\":13822}}}"

static bool claude_ledger_run(const char *tag, const char *body,
                              char *argv_txt, size_t cap)
{
    char rel[512], dir[600];
    test_make_tmpdir(rel, sizeof(rel), "engine_claude_ledger", tag);
    if (!test_abs_path(rel, dir, sizeof(dir))) {
        test_rm_rf(rel);
        return false;
    }
    char bin_dir[700], state[700], worktree[700], task[700], body_path[700];
    char claude[700], ledger[700], log[700], run_log[700], text[1600];
    (void)snprintf(bin_dir, sizeof(bin_dir), "%s/bin", dir);
    (void)snprintf(state, sizeof(state), "%s/state", dir);
    (void)snprintf(worktree, sizeof(worktree), "%s/wt", dir);
    (void)snprintf(task, sizeof(task), "%s/task.txt", dir);
    (void)snprintf(body_path, sizeof(body_path), "%s/body.json", dir);
    (void)snprintf(claude, sizeof(claude), "%s/claude", bin_dir);
    (void)snprintf(ledger, sizeof(ledger), "%s/ledger.sh", dir);
    (void)snprintf(log, sizeof(log), "%s/ledger.argv", dir);
    (void)snprintf(run_log, sizeof(run_log), "%s/run.log", dir);
    if (mkdir(bin_dir, 0700) != 0 || mkdir(state, 0700) != 0 ||
        mkdir(worktree, 0700) != 0) {
        test_rm_rf(dir);
        return false;
    }
    (void)snprintf(text, sizeof(text), "#!/bin/sh\ncat '%s'\n", body_path);
    bool ok = write_whole_file(claude, text) && chmod(claude, 0700) == 0;
    (void)snprintf(text, sizeof(text),
                   "#!/bin/sh\nfor a in \"$@\"; do printf '%%s\\n' \"$a\"; "
                   "done > '%s'\n", log);
    ok = ok && write_whole_file(ledger, text) && chmod(ledger, 0700) == 0 &&
         write_whole_file(body_path, body) &&
         write_whole_file(task, "kind: fix-gate\n\nMeasure the row.\n");
    if (!ok) {
        test_rm_rf(dir);
        return false;
    }
    char cmd[4096];
    (void)snprintf(cmd, sizeof(cmd),
        "PATH=%s:$PATH %s --engine claude-haiku --task %s --no-group "
        "--yes-dispatch --worktree %s --state-dir %s --fleet-ledger %s "
        ">%s 2>&1", bin_dir, ENGINE_UNIT_BIN, task, worktree, state, ledger,
        run_log);
    TEST_DISCARD(system(cmd)); /* the row is read from what the ledger saw */
    argv_txt[0] = '\0';
    const bool got = read_whole_file(log, argv_txt, cap);
    test_rm_rf(dir); /* read the argv log first: it lives under dir */
    return got;
}

static int case_claude_ledger_row_e2e(void)
{
    int failures = 0;
    if (!engine_unit_binary_present()) {
        printf("engine: FAIL (%s is required for the ledger row e2e)\n",
               ENGINE_UNIT_BIN);
        return 1;
    }
    char row[2048];
    const bool priced = claude_ledger_run("priced",
        CLAUDE_LEDGER_BODY("\"total_cost_usd\":0.0027666,"), row, sizeof(row));
    EN_CHECK("a priced Claude unit files a usage row", priced &&
             strstr(row, "--subject=claude-haiku\n") != NULL);
    EN_CHECK("known token facts are sent (input includes cached input)",
             priced && strstr(row, "--tokens_in=13929\n") &&
             strstr(row, "--tokens_out=41\n") &&
             strstr(row, "--tokens_cached=100\n") &&
             strstr(row, "--turns=3\n"));
    EN_CHECK("the vendor cost is sent in micro-dollars, rounded",
             priced && strstr(row, "--cost_micro_usd=2767\n"));
    EN_CHECK("an unreported reasoning count is omitted, not sent as 0",
             priced && !strstr(row, "tokens_reasoning"));

    const bool unpriced = claude_ledger_run("unpriced",
        CLAUDE_LEDGER_BODY(""), row, sizeof(row));
    EN_CHECK("an unpriced run still files its tokens", unpriced &&
             strstr(row, "--tokens_in=13929\n"));
    EN_CHECK("an unknown cost is omitted, not sent as 0",
             unpriced && !strstr(row, "cost_micro_usd"));

    const bool negative = claude_ledger_run("negative",
        CLAUDE_LEDGER_BODY("\"total_cost_usd\":-1.5,"), row, sizeof(row));
    EN_CHECK("a negative cost is omitted",
             negative && strstr(row, "--tokens_in=13929\n") &&
             !strstr(row, "cost_micro_usd"));

    const bool huge = claude_ledger_run("huge",
        CLAUDE_LEDGER_BODY("\"total_cost_usd\":1e20,"), row, sizeof(row));
    EN_CHECK("a cost that would overflow int64 micro-dollars is not sent",
             huge && strstr(row, "--tokens_in=13929\n") &&
             !strstr(row, "cost_micro_usd"));
    return failures;
}
#endif

/* The card-check kind is read-only: it checks a card against the tree and
 * reports facts and open choices, never a design judgement or a verdict. */
static int case_light_card_check_kind(void)
{
    int failures = 0;
    EN_CHECK("c23-card-check is light",
             engine_prompt_kind_tier("c23-card-check")
             == ENGINE_PROMPT_TIER_LIGHT);
    EN_CHECK("c23-card-check supplies every required section",
             engine_prompt_kind_is_complete("c23-card-check"));
    const char *rules = engine_prompt_template_body("c23-card-check", "rules");
    EN_CHECK("c23-card-check checks every statement of fact",
             rules && strstr(rules, "Check every statement of fact"));
    EN_CHECK("c23-card-check forbids edits, builds and test runs",
             rules && strstr(rules, "Do not edit, build or run tests"));
    EN_CHECK("c23-card-check does not judge the design",
             rules && strstr(rules, "Do not judge the design"));
    const char *task = engine_prompt_template_body("c23-card-check", "task");
    EN_CHECK("c23-card-check marks each claim TRUE, FALSE or NOT FOUND",
             task && strstr(task, "TRUE, FALSE or NOT FOUND"));
    EN_CHECK("c23-card-check gives the true fact for a FALSE claim",
             task && strstr(task, "give the true fact"));
    EN_CHECK("c23-card-check opens the precedent model",
             task && strstr(task, "open that model"));
    EN_CHECK("c23-card-check lists every open choice with a precedent",
             task && strstr(task, "List every choice")
             && strstr(task, "nearest precedent"));
    const char *protocol =
        engine_prompt_template_body("c23-card-check", "protocol");
    EN_CHECK("c23-card-check ends with READY or NOT READY",
             protocol && strstr(protocol, "READY")
             && strstr(protocol, "NOT READY"));
    return failures;
}

int test_engine(void)
{
    int failures = 0;
    failures += case_registry();
    failures += case_request();
    failures += case_hostile();
    failures += case_patch();
    failures += case_secret();
    failures += case_verdict();
    failures += case_effect_per_kind();
    failures += case_verdict_report();
    failures += case_verdict_edit_delegates();
    failures += case_verdict_names();
    failures += case_gate_read();
    failures += case_err();
    failures += case_key_gate();
    failures += case_prompt();
    failures += case_prompt_shape();
    failures += case_prompt_templates();
    failures += case_c23_prompt_selection();
    failures += case_template_wire();
    failures += case_cli_argv();
    failures += case_cli_observation();
    failures += case_default_engine();
    failures += case_engine_tiers();
    failures += case_receipt_attempt_binding();
    failures += case_receipt_chain();
    failures += case_receipt_text();
#if !defined(_WIN32)
    failures += case_pin_name_boundary();
    failures += case_pin_atomic();
#endif
    failures += case_state();
    failures += case_engine_unit_state_e2e();
#if !defined(_WIN32)
    failures += case_engine_unit_grok_projection_e2e();
    failures += case_claude_ledger_row_e2e();
#endif
    failures += case_review_findings_not_verdict();
    failures += case_contract();
    failures += case_light_patch_kind();
    failures += case_light_review_pass_kind();
    failures += case_review_pass_no_new_file();
    failures += case_light_card_check_kind();
    printf("engine: %d failure(s)\n", failures);
    return failures;
}
