/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_unknown_command - a wrong first word(s) answers with the standard
 * zcl.result.v1 failure envelope on stdout whose next[] names real nearest
 * commands and the one command that lists the surrounding group.
 *
 * Driven in-process through zcl_native_command_main (the path every typed
 * command takes), stdout and stderr redirected to files.
 *
 * make t-fast ONLY=operator_ux (runs from test_operator_ux) */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "command/native_command_suggest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct uc_run {
    int rc;
    char out[8192];
    char err[1024];
};

static bool uc_slurp(FILE *f, char *dst, size_t cap)
{
    long len = ftell(f);
    if (len < 0 || (size_t)len >= cap)
        return false;
    rewind(f);
    bool ok = fread(dst, 1, (size_t)len, f) == (size_t)len;
    dst[ok ? (size_t)len : 0] = '\0';
    return ok;
}

/* Run `root args...` with both streams captured. */
static bool uc_run(const char *root, const char *const *args, int nargs,
                   struct uc_run *r)
{
    FILE *fo = tmpfile(), *fe = tmpfile();
    bool ok = fo && fe;
    int so = -1, se = -1;
    if (ok) {
        fflush(stdout);
        fflush(stderr);
        so = dup(fileno(stdout));
        se = dup(fileno(stderr));
        ok = so >= 0 && se >= 0 && dup2(fileno(fo), fileno(stdout)) >= 0 &&
             dup2(fileno(fe), fileno(stderr)) >= 0;
    }
    if (ok) {
        setenv("ZCL_HUMAN", "0", 1);
        zcl_native_render_reset_for_test();
        r->rc = zcl_native_command_main(root, args, nargs, "/nonexistent-z23",
                                        0, CHAIN_MAIN, false);
        fflush(stdout);
        fflush(stderr);
    }
    if (so >= 0) {
        dup2(so, fileno(stdout));
        close(so);
    }
    if (se >= 0) {
        dup2(se, fileno(stderr));
        close(se);
    }
    unsetenv("ZCL_HUMAN");
    zcl_native_render_reset_for_test();
    ok = ok && uc_slurp(fo, r->out, sizeof(r->out)) &&
         uc_slurp(fe, r->err, sizeof(r->err));
    if (fo)
        fclose(fo);
    if (fe)
        fclose(fe);
    return ok;
}

/* The next[] entry commands, in order, must each be a registered path. */
static bool uc_next_all_exist(const struct json_value *next)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    for (size_t i = 0; i < next->num_children; i++) {
        const char *cmd = json_get_str(json_get(&next->children[i], "command"));
        if (!cmd || !zcl_command_registry_find(reg, cmd, NULL))
            return false;
    }
    return true;
}

static const char *uc_next_command(const struct json_value *next, size_t i)
{
    return i < next->num_children
               ? json_get_str(json_get(&next->children[i], "command"))
               : "";
}

/* The discover.help entry's input path ("" when it carries none). */
static const char *uc_help_path(const struct json_value *next)
{
    for (size_t i = 0; i < next->num_children; i++)
        if (strcmp(uc_next_command(next, i), "discover.help") == 0) {
            const char *p = json_get_str(
                json_get(json_get(&next->children[i], "input"), "path"));
            return p ? p : "";
        }
    return NULL;
}

static bool uc_envelope(const struct uc_run *r, struct json_value *doc)
{
    const struct json_value *err;
    if (!json_read(doc, r->out, strlen(r->out)) || doc->type != JSON_OBJ)
        return false;
    err = json_get(doc, "error");
    return strcmp(json_get_str(json_get(doc, "schema")), "zcl.result.v1") == 0 &&
           !json_get_bool(json_get(doc, "ok")) &&
           strcmp(json_get_str(json_get(err, "code")), "UNKNOWN_COMMAND") == 0;
}

/* Run `root args...` and parse its stdout envelope; asserts exit code 2. */
static bool uc_expect(const char *root, const char *const *args, int nargs,
                      struct uc_run *r, struct json_value *doc)
{
    return uc_run(root, args, nargs, r) && r->rc == 2 && uc_envelope(r, doc);
}

static int test_ops_ls(void)
{
    int failures = 0;
    struct uc_run r;
    struct json_value doc;
    const char *args[] = {"ls"};
    TEST("z23 ops ls: envelope, exit 2, silent stderr, group listing pointer") {
        ASSERT(uc_expect("ops", args, 1, &r, &doc));
        ASSERT(r.err[0] == '\0');
        const struct json_value *next = json_get(&doc, "next");
        ASSERT(next && next->type == JSON_ARR && uc_next_all_exist(next));
        ASSERT(uc_help_path(next) && strcmp(uc_help_path(next), "ops") == 0);
        ASSERT(strlen(r.out) < 1500);
        json_free(&doc);
        PASS();
    } _test_next:;
    return failures;
}

static int test_core_wallet_lst(void)
{
    int failures = 0;
    struct uc_run r;
    struct json_value doc;
    const char *args[] = {"wallet", "lst"};
    TEST("z23 core wallet lst: envelope, pointer lists core.wallet") {
        ASSERT(uc_expect("core", args, 2, &r, &doc));
        ASSERT(r.err[0] == '\0');
        const struct json_value *next = json_get(&doc, "next");
        ASSERT(next && uc_next_all_exist(next));
        ASSERT(uc_help_path(next) &&
               strcmp(uc_help_path(next), "core.wallet") == 0);
        json_free(&doc);
        PASS();
    } _test_next:;
    return failures;
}

static int test_plugin_list_synonym_and_typo(void)
{
    int failures = 0;
    struct uc_run r;
    struct json_value doc;
    const char *ls[] = {"ls"};
    const char *lst[] = {"lst"};
    TEST("z23 plugin ls / lst suggest the real leaf plugin.list first") {
        ASSERT(uc_expect("plugin", ls, 1, &r, &doc));
        ASSERT(strcmp(uc_next_command(json_get(&doc, "next"), 0),
                      "plugin.list") == 0);
        json_free(&doc);
        ASSERT(uc_expect("plugin", lst, 1, &r, &doc));
        ASSERT(strcmp(uc_next_command(json_get(&doc, "next"), 0),
                      "plugin.list") == 0);
        ASSERT(uc_next_all_exist(json_get(&doc, "next")));
        json_free(&doc);
        PASS();
    } _test_next:;
    return failures;
}

static int test_pluggin_status(void)
{
    int failures = 0;
    struct uc_run r;
    struct json_value doc;
    const char *args[] = {"status"};
    TEST("z23 pluggin status: nearest real command is plugin.status") {
        ASSERT(uc_expect("pluggin", args, 1, &r, &doc));
        const struct json_value *next = json_get(&doc, "next");
        ASSERT(next && uc_next_all_exist(next));
        ASSERT(strcmp(uc_next_command(next, 0), "plugin.status") == 0);
        ASSERT(uc_help_path(next) && strcmp(uc_help_path(next), "plugin") == 0);
        json_free(&doc);
        PASS();
    } _test_next:;
    return failures;
}

static int test_nonsense_word(void)
{
    int failures = 0;
    struct uc_run r;
    struct json_value doc;
    TEST("a nonsense word suggests nothing: only search and the help pointer") {
        ASSERT(uc_expect("zzzqxjv", NULL, 0, &r, &doc));
        const struct json_value *next = json_get(&doc, "next");
        ASSERT(next && next->num_children == 2 && uc_next_all_exist(next));
        ASSERT(strcmp(uc_next_command(next, 0), "discover.search") == 0);
        ASSERT(strcmp(uc_next_command(next, 1), "discover.help") == 0);
        ASSERT(uc_help_path(next) && uc_help_path(next)[0] == '\0');
        json_free(&doc);
        PASS();
    } _test_next:;
    return failures;
}

/* The top-level (RPC-confirmed) path keeps its stderr line byte-for-byte. */
static int test_root_stderr_line_kept(void)
{
    int failures = 0;
    TEST("top-level stderr line is unchanged") {
        char line[512];
        size_t n = zcl_native_render_unknown_command(
            zcl_command_catalog(), "pluggin", line, sizeof(line));
        ASSERT(n > 0);
        static const char want[] =
            "error=UNKNOWN_COMMAND detail=no such command 'pluggin' "
            "try=z23 discover search pluggin\n";
        ASSERT(strncmp(line, want, sizeof(want) - 1) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* The top-level path prints the same envelope for the single wrong word. */
static int test_root_envelope_names_real_commands(void)
{
    int failures = 0;
    TEST("top-level envelope: stat suggests existing leaves, bounded size") {
        char env[4096];
        const char *words[] = {"stat"};
        struct zcl_unknown_command u = {
            "stat", "unknown command root", "stat", "stat", words, 1};
        size_t n = zcl_native_unknown_command_json(zcl_command_catalog(), &u,
                                                   env, sizeof(env));
        ASSERT(n > 0 && n < 1500);
        struct json_value doc;
        ASSERT(json_read(&doc, env, n) && doc.type == JSON_OBJ);
        ASSERT(strcmp(json_get_str(json_get(json_get(&doc, "error"), "code")),
                      "UNKNOWN_COMMAND") == 0);
        const struct json_value *next = json_get(&doc, "next");
        ASSERT(next && next->num_children >= 2 && uc_next_all_exist(next));
        json_free(&doc);

        /* The words typed after the wrong one steer the suggestion. */
        const char *typed[] = {"pluggin", "status"};
        struct zcl_unknown_command v = {"pluggin", "unknown command root",
                                        "pluggin", "pluggin", typed, 2};
        n = zcl_native_unknown_command_json(zcl_command_catalog(), &v, env,
                                            sizeof(env));
        ASSERT(n > 0 && json_read(&doc, env, n));
        ASSERT(strcmp(uc_next_command(json_get(&doc, "next"), 0),
                      "plugin.status") == 0);
        json_free(&doc);
        PASS();
    } _test_next:;
    return failures;
}

/* A typo near a spend, signing or destructive leaf must never put that leaf
 * on a runnable line: every next[] command is a read-only registry leaf (or
 * discover.*), and the risky match is only a discover.describe pointer. */
static bool uc_next_all_safe(const struct json_value *next)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    for (size_t i = 0; i < next->num_children; i++) {
        const struct zcl_command_spec *s =
            zcl_command_registry_find(reg, uc_next_command(next, i), NULL);
        if (!s || s->effect != ZCL_COMMAND_EFFECT_READ ||
            s->risk != ZCL_COMMAND_RISK_READ)
            return false;
    }
    return true;
}

/* The describe pointer's path ("" when there is none). */
static const char *uc_describe_path(const struct json_value *next)
{
    for (size_t i = 0; i < next->num_children; i++)
        if (strcmp(uc_next_command(next, i), "discover.describe") == 0) {
            const char *p = json_get_str(
                json_get(json_get(&next->children[i], "input"), "path"));
            return p ? p : "";
        }
    return "";
}

static bool uc_typo_is_safe(const char *const *words, size_t nw,
                            const char *risky)
{
    char env[4096];
    struct zcl_unknown_command u = {words[0], "unknown", words[0], words[0],
                                    words, nw};
    struct json_value doc;
    size_t n = zcl_native_unknown_command_json(zcl_command_catalog(), &u, env,
                                               sizeof(env));
    bool ok = n > 0 && json_read(&doc, env, n);
    if (!ok)
        return false;
    const struct json_value *next = json_get(&doc, "next");
    ok = next && next->num_children > 0 && uc_next_all_safe(next) &&
         strcmp(uc_describe_path(next), risky) == 0;
    json_free(&doc);
    return ok;
}

static int test_risky_never_runnable(void)
{
    int failures = 0;
    TEST("typos near spend / destructive / signing leaves never run them") {
        const char *gc[] = {"ops", "host", "gc", "aply"};
        ASSERT(uc_typo_is_safe(gc, 4, "ops.host.gc"));
        const char *send[] = {"core", "wallet", "transaction", "sned"};
        ASSERT(uc_typo_is_safe(send, 4, "core.wallet.transaction.send"));
        const char *sign[] = {"ops", "release", "sgn"};
        ASSERT(uc_typo_is_safe(sign, 3, "ops.release.sign"));
        const char *wsend[] = {"core", "wallet", "sned"};
        ASSERT(uc_typo_is_safe(wsend, 3, ""));
        PASS();
    } _test_next:;
    return failures;
}

int unknown_command_cases(void)
{
    int failures = 0;
    failures += test_ops_ls();
    failures += test_core_wallet_lst();
    failures += test_plugin_list_synonym_and_typo();
    failures += test_pluggin_status();
    failures += test_nonsense_word();
    failures += test_root_stderr_line_kept();
    failures += test_root_envelope_names_real_commands();
    failures += test_risky_never_runnable();
    printf("=== unknown_command: %d failures ===\n", failures);
    return failures;
}
