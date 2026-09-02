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
#include "engine/engine_prompt.h"
#include "engine/engine_receipt.h"
#include "base/safe_alloc.h"
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


/* ── 10. the prompt every vendor actually receives ───────────────────────
 *
 * This case exists because of a defect it would have caught. The rules a
 * dispatched unit is held to were attached to the OpenAI request body's
 * system field, and a CLI vendor has no such field — it is handed one file.
 * Nothing put the rules in that file, so every CLI dispatch went out without
 * them, while --dry-run printed them to the operator. Every dispatch this
 * project has ever completed was a CLI dispatch.
 *
 * So the assertion is not "compose returns a string". It is: for every wire
 * in the enum, either the wire has a system channel of its own, or the bytes
 * it receives contain the rules. There is no third answer, and a wire added
 * later without a decision falls into the second branch. */

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

    /* A CLI vendor is the case that was broken. Name it directly so a
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
 * The registry states what a dispatch prompt must contain. These checks hold
 * it to the two things that make it worth having: a prompt missing a required
 * section is REFUSED rather than dispatched, and the refusal names the section
 * so an operator is not left comparing two blobs. The rules row is the one
 * that already went missing once, so it is checked from both directions —
 * required inline for a CLI wire, forbidden inline for an HTTP wire. */

/* A prompt with every section a CLI wire needs, in order. Built from the
 * registry itself, so a new row cannot be added without this fixture
 * carrying it — the alternative is a hand-written fixture that silently
 * stops covering the thing it was written for. */
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
 * A CLI vendor's arguments used to be a fixed array inside the dispatch tool,
 * shaped around the one CLI this tree happened to use. The cost of that was
 * measured on 2026-08-30: the owner's machine had a working subscription to a
 * second CLI the whole time, every HTTPS row in the table was answering 429
 * for want of credit, and the only thing between the tree and a working
 * engine was seven hard-coded strings in a program no test links.
 *
 * The registry invariant below is the one that would have caught it. */

static int case_cli_argv(void)
{
    int failures = 0;

    /* Every CLI row is complete, and no other row pretends to be one. This is
     * the check that fails the day someone adds a CLI vendor and stops at the
     * program name. */
    bool cli_rows_complete = true;
    bool non_cli_rows_clean = true;
    size_t cli_rows = 0;
    for (size_t i = 0; i < engine_count(); i++) {
        const struct engine_vendor *v = engine_at(i);
        if (v->wire == ENGINE_WIRE_LOCAL_CLI) {
            cli_rows++;
            if (!v->program || !v->program[0] || !v->cli_argv)
                cli_rows_complete = false;
        } else if (v->program || v->cli_argv) {
            non_cli_rows_clean = false;
        }
    }
    EN_CHECK("every CLI row names a program and an argument template",
             cli_rows_complete);
    EN_CHECK("and no non-CLI row carries either", non_cli_rows_clean);
    EN_CHECK("more than one CLI vendor is registered", cli_rows >= 2);

    const struct engine_cli_inputs in = {
        .prompt  = "/tmp/p.txt",
        .workdir = "/w",
        .turns   = "3",
        .model   = "m-1",
    };
    const char *argv[ENGINE_CLI_ARGV_MAX];

    /* A file-mode vendor. The exact vector matters: this is what gets exec'd,
     * and a test that only counted the entries would pass while the flags
     * were wrong. */
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
        bool carries_model = false, disables_subagents = false;
        bool disables_web = false, pins_tools = false;
        bool carries_no_placeholders = true;
        for (size_t i = 1; i < n; i++) {
            if (strcmp(argv[i], in.prompt) == 0)  carries_prompt = true;
            if (strcmp(argv[i], in.workdir) == 0) carries_workdir = true;
            if (strcmp(argv[i], "bypassPermissions") == 0)
                carries_bypass = true;
            if (strcmp(argv[i], "--no-plan") == 0) carries_no_plan = true;
            if (strcmp(argv[i], in.model) == 0) carries_model = true;
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
        EN_CHECK("and disables hidden subagent work", disables_subagents);
        EN_CHECK("and disables unrelated web retrieval", disables_web);
        EN_CHECK("and pins the observable repository tool schema", pins_tools);
        EN_CHECK("and no placeholder survived substitution",
                 carries_no_placeholders);
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

        /* The kernel caps a single argv string far below the prompt ceiling.
         * Refusing here names the real reason; letting it through would
         * surface as "could not launch", pointing at the CLI. */
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
        .cli_argv = bogus_argv, .cli_prompt = ENGINE_CLI_PROMPT_FILE,
        .wire = ENGINE_WIRE_LOCAL_CLI,
    };
    EN_CHECK("an unknown placeholder is refused, not passed through",
             engine_cli_argv_build(&bogus, &in, argv, ENGINE_CLI_ARGV_MAX) == 0);

    struct engine_vendor no_template = bogus;
    no_template.cli_argv = NULL;
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

    /* Grok currently emits both accounting shapes in the wild. Older
     * sessions report input as cache-inclusive; newer sessions report cache
     * reads as an additive category. Preserve the exact counters and accept
     * either shape only when its total is arithmetically consistent. */
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


/* ── the default engine ───────────────────────────────────────────────────
 * A caller who names no engine gets one. Which one is a row in the table, not
 * a string somewhere else that could name a row that is gone. */
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

    /* The property that makes a default safe to have at all: it must work on
     * a host that has never been given a credential. A default needing an API
     * key would fail on a fresh machine with a message about keys, which
     * reads as a broken tool rather than an unmade choice. */
    EN_CHECK("the default needs no API key", d && !engine_needs_key(d));

    /* And it must not be the fixture: a default that quietly sends nothing
     * would make every unattended run look like it worked. */
    EN_CHECK("the default is not the fixture engine",
             d && !engine_is_fixture(d));
    return failures;
}


/* ── prompt templates, keyed by task kind ───────────────────────────────
 * A kind missing a required section would compose a bare header the shape
 * audit cannot tell from a filled one, so it is refused before dispatch.
 * --kind wins over a `kind:` header so an operator can re-run a task as a
 * different job without editing the file. */

static const char *select_kind(const char *flag, const char *task)
{
    if (flag && flag[0])
        return flag;
    return engine_prompt_kind_from_header(task);
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
            if (!engine_prompt_template_body(kind, sec->id))
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
    r.model = "m";
    r.kind = "fix-gate";
    r.prompt_tokens = ENGINE_RECEIPT_UNREPORTED;
    r.completion_tokens = ENGINE_RECEIPT_UNREPORTED;
    r.wall_ms = 10;
    r.http_status = 0;
    r.outcome.lint_rc = ENGINE_RECEIPT_UNREPORTED;
    return r;
}

static bool tamper_first_line(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    char buf[ENGINE_RECEIPT_LINE_MAX + 2u];
    size_t n = fread(buf, 1, sizeof(buf) - 1u, f);
    (void)fclose(f);
    if (n == 0)
        return false;
    for (size_t i = 1; i < n; i++) {
        if (buf[i] >= 'a' && buf[i] <= 'z') {
            buf[i] = (char)(buf[i] == 'a' ? 'b' : 'a');
            break;
        }
    }
    f = fopen(path, "wb");
    if (!f)
        return false;
    const size_t w = fwrite(buf, 1, n, f);
    (void)fclose(f);
    return w == n;
}

static int case_receipt_chain(void)
{
    int failures = 0;
    char path[512];
    (void)snprintf(path, sizeof(path), "/tmp/zcl_engine_receipt_%d.chainlog",
                   (int)getpid());
    (void)unlink(path);

    struct engine_receipt_chain_report report;
    EN_CHECK("a missing file is an empty chain, not a broken one",
             engine_receipt_verify_chain(path, &report)
             && report.records == 0 && report.first_bad_line == 0);

    struct engine_receipt a = receipt_fixture("fixture", 1000);
    struct engine_receipt b = receipt_fixture("glm", 1001);
    struct engine_receipt c = receipt_fixture("grok", 1002);
    EN_CHECK("the first record appends", engine_receipt_append(path, &a, NULL));
    EN_CHECK("the second record appends", engine_receipt_append(path, &b, NULL));
    EN_CHECK("the third record appends", engine_receipt_append(path, &c, NULL));
    EN_CHECK("the chain verifies end to end",
             engine_receipt_verify_chain(path, &report)
             && report.records == 3 && report.first_bad_line == 0);

    struct engine_receipt bad = receipt_fixture("", 1003);
    bad.engine = "";
    EN_CHECK("a receipt with no engine id is refused",
             !engine_receipt_append(path, &bad, NULL));
    EN_CHECK("refusing an append leaves the chain intact",
             engine_receipt_verify_chain(path, &report) && report.records == 3);

    EN_CHECK("tampering an earlier line is detected", tamper_first_line(path));
    EN_CHECK("and verification names a bad line",
             !engine_receipt_verify_chain(path, &report)
             && report.first_bad_line != 0);

    (void)unlink(path);
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
    failures += case_prompt();
    failures += case_prompt_shape();
    failures += case_prompt_templates();
    failures += case_cli_argv();
    failures += case_cli_observation();
    failures += case_default_engine();
    failures += case_receipt_chain();
    printf("engine: %d failure(s)\n", failures);
    return failures;
}
