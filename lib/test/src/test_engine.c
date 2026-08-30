/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The engine harness under test. Four things are worth proving here and the
 * rest is bookkeeping:
 *
 *   1. A HOSTILE ENGINE RESPONSE IS REFUSED, NOT SURVIVED. Everything the
 *      decoder reads came off a socket. Truncated JSON, absurd lengths, wrong
 *      types, deep nesting and embedded NULs each get a case, and each must
 *      end in `false` with the output zeroed — never a crash, never a partial
 *      decode that a caller then acts on.
 *
 *   2. A KEY NEVER REACHES AN ARTIFACT. The harness writes transcripts, gate
 *      logs and receipts. A credential must not be in any of them, and the
 *      reason it is not must be structural: the redacting writer is the only
 *      writer. So the test loads a real-shaped key and then tries to write it
 *      out through the harness's own emitter.
 *
 *   3. AN ENGINE THAT REPORTS SUCCESS AND CHANGES NOTHING IS A FAILURE. This
 *      is the law of the module (engine/engine.h). The case pairs a PERFECT
 *      gate reading — cold run, group ran, zero failures, pass token present —
 *      with an empty diff, and requires the verdict to be a failure anyway.
 *      A harness that reads only the gate calls that a pass and is wrong.
 *
 *   4. THE HOLLOW GREEN IS CAUGHT. groups_ran = 0 exits 0; a fully cached run
 *      prints a string containing "ALL TESTS PASSED". Neither is evidence.
 */

#include "test/test_core.h"

#include "engine/engine.h"
#include "engine/engine_err.h"
#include "engine/engine_patch.h"
#include "engine/engine_secret.h"
#include "engine/engine_verdict.h"
#include "engine/engine_wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define EN_CHECK(name, expr) do {                    \
    printf("engine: %s... ", (name));                \
    if (expr) { printf("OK\n"); }                    \
    else { printf("FAIL\n"); failures++; }           \
} while (0)

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
        static const char twice[] =
            "Z23-BEGIN-FILE a.c\nx\nZ23-END-FILE\n"
            "Z23-BEGIN-FILE a.c\ny\nZ23-END-FILE\n";
        EN_CHECK("the same path twice is refused",
                 !engine_patch_parse(twice, sizeof(twice) - 1, &p));
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

    /* Containment. This is the security-relevant half: the applier writes
     * relative to an isolated worktree, and a path that cannot escape it is
     * the only kind it accepts. */
    EN_CHECK("a normal source path is accepted",
             engine_patch_path_ok("lib/engine/src/engine_patch.c"));
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
    return failures;
}

/* ── 5. secrets ──────────────────────────────────────────────────────── */

static int case_secret(void)
{
    int failures = 0;
    char where[128];
    const struct engine_vendor *fixture = engine_by_id("fixture");
    const struct engine_vendor *glm = engine_by_id("glm");

    EN_CHECK("the fixture engine needs no key",
             engine_secret_load(fixture, NULL, where, sizeof(where)));

    /* A key file must be 0600. A world-readable key on a shared box is
     * already spent, so this is a refusal and not a warning. */
    char path[512];
    (void)snprintf(path, sizeof(path), "/tmp/zcl_engine_key_%d", (int)getpid());
    FILE *f = fopen(path, "wb");
    if (f) {
        (void)fputs(k_planted_key, f);
        (void)fputc('\n', f);
        (void)fclose(f);
    }
    (void)chmod(path, 0644);
    EN_CHECK("a key file that is not 0600 is REFUSED, not warned about",
             !engine_secret_load(glm, path, where, sizeof(where)));
    (void)chmod(path, 0600);
    EN_CHECK("a 0600 key file loads",
             engine_secret_load(glm, path, where, sizeof(where))
             && engine_secret_loaded());
    EN_CHECK("the source is named without any part of the value",
             strstr(where, k_planted_key) == NULL
             && strstr(where, "0123456789") == NULL);

    /* THE CENTRAL CLAIM: with a key loaded, the harness's own writer cannot
     * put it in an artifact. */
    {
        char artifact[512];
        (void)snprintf(artifact, sizeof(artifact),
                       "/tmp/zcl_engine_artifact_%d", (int)getpid());
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
    f = fopen(path, "wb");
    if (f) {
        (void)fputs("short\n", f);
        (void)fclose(f);
    }
    (void)chmod(path, 0600);
    EN_CHECK("an implausibly short key is refused",
             !engine_secret_load(glm, path, where, sizeof(where)));
    (void)unlink(path);
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

    /* THE LAW. A perfect gate reading plus an empty diff is a FAILURE. The
     * engine reported success, exited 0, and wrote nothing; the gate then
     * measured the tree as it was BEFORE the unit ran, so its green says
     * something about the baseline and nothing whatever about the unit. */
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
    /* The trap that made this function necessary: the cached headline
     * CONTAINS the pass token, so a substring grep matches a run that
     * executed nothing. */
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

    /* MEASURED 2026-08-30. Two unrelated vendors answered 429 — a retryable
     * status — for an empty account, a condition no amount of waiting fixes.
     * A status-only classifier retries a billing failure on every dispatch
     * forever. These are the two bodies they actually sent. */
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

/* check-no-api-keys is only worth having if it FAILS on a real key. The gate
 * accepts a scan-set override for exactly this: point it at a fixture tree
 * with a key planted in it and require a non-zero exit. A gate that has never
 * been seen to fail is a gate nobody has tested. */
static int case_key_gate(void)
{
    int failures = 0;
    char dir[512];
    (void)snprintf(dir, sizeof(dir), "/tmp/zcl_engine_gate_%d", (int)getpid());
    char cmd[2048];

    (void)snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", dir);
    if (system(cmd) != 0) {                             /* shellout-ok: test */
        printf("engine: could not create the gate fixture... FAIL\n");
        return 1;
    }
    /* A clean file first: the gate must pass on it, so a later failure is
     * attributable to the planted key and not to the fixture. */
    (void)snprintf(cmd, sizeof(cmd),
                   "printf 'int main(void){return 0;}\\n' > '%s/clean.c'", dir);
    (void)system(cmd);                                  /* shellout-ok: test */
    (void)snprintf(cmd, sizeof(cmd),
                   "ZCL_API_KEY_SCAN_FILES='%s/clean.c' "
                   "./tools/lint/check_no_api_keys.sh >/dev/null 2>&1", dir);
    EN_CHECK("the key gate passes on a clean tree",
             system(cmd) == 0);                         /* shellout-ok: test */

    /* Now plant one. Assembled at run time so this source file does not
     * itself contain a key-shaped literal for the gate to find. */
    (void)snprintf(cmd, sizeof(cmd),
                   "printf 'static const char *k = \"%s%s\";\\n' > '%s/leak.c'",
                   "sk-", "abcdefghijklmnopqrstuvwxyz0123456789", dir);
    (void)system(cmd);                                  /* shellout-ok: test */
    (void)snprintf(cmd, sizeof(cmd),
                   "ZCL_API_KEY_SCAN_FILES='%s/leak.c' "
                   "./tools/lint/check_no_api_keys.sh >/dev/null 2>&1", dir);
    EN_CHECK("the key gate FAILS on a planted key",
             system(cmd) != 0);                         /* shellout-ok: test */

    (void)snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    (void)system(cmd);                                  /* shellout-ok: test */
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
    failures += case_gate_read();
    failures += case_err();
    failures += case_key_gate();
    printf("engine: %d failure(s)\n", failures);
    return failures;
}
