/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * source_id_sha256 answers two different questions and only one of them may
 * ever reach a deploy freshness check:
 *
 *   Q1  "what source tree was this BINARY built from?" — a property of the
 *       executable, baked in at compile time, IDENTICAL from every working
 *       directory.
 *   Q2  "what source tree is in this DIRECTORY right now?" — a property of a
 *       checkout, different in every checkout, by design.
 *
 * Both are published under the key `source_id_sha256`. A freshness check that
 * reads Q2 while believing it read Q1 can pass a stale daemon (its box's
 * checkout looks current) or fail a fresh one (built somewhere else), and this
 * repository has already lost days to a "permanent blocker" that was a stale
 * binary. This group pins the boundary:
 *
 *   A. zcl_build_source_id_sha256() is cwd-invariant, in-process, across
 *      chdir() — the C-side promise the whole scheme rests on.
 *   B. zcl.runtime_build.v2 names the question each identity answers, so a
 *      consumer cannot read one under the other's name.
 *   C. zcl_binary_source_id() (tools/scripts/source_identity_lib.sh) returns
 *      the SAME baked value for one binary from three different working
 *      directories, and refuses rather than substituting a directory-derived
 *      value when the payload is not canonical.
 *   D. NEGATIVE CONTROL for C: the pre-fix implementation — the positional
 *      "first source_id_sha256 in the document" reader — is run against the
 *      same fixture and MUST produce a directory-dependent answer. Without
 *      this the cwd-invariance assertion is unfalsifiable: a test that passes
 *      whether or not the fix is present is not a test. The fixture is a
 *      canonical-schema payload whose FIRST source_id_sha256 is a nested,
 *      cwd-derived one, which is exactly what the positional reader was one
 *      key-ordering change away from returning all along.
 *
 * Hermetic: every fixture lives under a test tmpdir, the "binary" under test
 * is a tiny shell script, no node is started, and no datadir is named.
 */

#include "test/test_core.h"
#include "controllers/agent_controller.h"
#include "json/json.h"
#include "util/clientversion.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The 64-hex value the fixture binary claims to have been built from. It is
 * a constant of the FIXTURE, not of any directory: that is the whole point. */
#define SIA_BAKED \
    "1111111111111111111111111111111111111111111111111111111111111111"

static bool sia_write_exec(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    fputs(content, f);
    if (fclose(f) != 0)
        return false;
    return chmod(path, 0700) == 0;
}

/* Capture one line of a command's stdout, newline stripped. */
static bool sia_capture(const char *cmd, char *out, size_t out_len)
{
    FILE *p = popen(cmd, "r");
    if (!p)
        return false;
    size_t used = fread(out, 1, out_len - 1, p);
    out[used] = '\0';
    while (used > 0 && (out[used - 1] == '\n' || out[used - 1] == '\r'))
        out[--used] = '\0';
    return pclose(p) == 0;
}

/* ── A: the baked constant does not move when the process does ─────── */

static int sia_baked_constant_is_cwd_invariant(void)
{
    int failures = 0;
    char origin[PATH_MAX];

    TEST("baked source id is identical from every working directory") {
        ASSERT(getcwd(origin, sizeof(origin)) != NULL);

        char work[512], abswork[PATH_MAX];
        test_make_tmpdir(work, sizeof(work), "sia", "chdir");
        /* test_make_tmpdir yields a path relative to the repository root; the
         * whole point of this case is to leave that root, so absolutise it. */
        snprintf(abswork, sizeof(abswork), "%s/%s", origin, work);

        /* Read it once, then again from directories that share no prefix with
         * each other or with the repository. A value derived from the cwd —
         * or from a file found relative to it — cannot survive this. */
        char first[128];
        snprintf(first, sizeof(first), "%s", zcl_build_source_id_sha256());
        ASSERT(first[0] != '\0');

        const char *elsewhere[] = { "/", abswork, "/usr" };
        bool same = true;
        for (size_t i = 0; i < sizeof(elsewhere) / sizeof(elsewhere[0]); i++) {
            if (chdir(elsewhere[i]) != 0)
                continue; /* an unreadable dir proves nothing either way */
            same = same &&
                strcmp(first, zcl_build_source_id_sha256()) == 0;
        }
        ASSERT(chdir(origin) == 0);
        ASSERT(same);

        /* And it is what it claims to be: either a real 64-hex identity or the
         * explicit "unknown" of an unstamped build — never a truncated or
         * host-shaped string that a comparison could accidentally accept. */
        size_t n = strlen(first);
        bool hex64 = (n == 64);
        for (size_t i = 0; i < n && hex64; i++)
            hex64 = (first[i] >= '0' && first[i] <= '9') ||
                    (first[i] >= 'a' && first[i] <= 'f');
        ASSERT(hex64 || strcmp(first, "unknown") == 0);

        test_rm_rf_recursive(work);
        PASS();
    } _test_next:;
    return failures;
}

/* ── B: the runtime_build block names which question each field answers ── */

static int sia_runtime_build_names_the_question(void)
{
    int failures = 0;

    TEST("zcl.runtime_build.v2 separates baked identity from deploy intent") {
        const char *expected =
            "2222222222222222222222222222222222222222222222222222222222222222";
        setenv("ZCL_AGENT_EXPECT_SOURCE_ID", expected, 1);

        struct json_value doc;
        json_init(&doc);
        json_set_object(&doc);
        agent_push_runtime_build_json(&doc, "runtime_build");
        const struct json_value *rb = json_get(&doc, "runtime_build");
        ASSERT(rb && rb->type == JSON_OBJ);

        /* The running identity is the baked constant, under a name that says
         * so, with a scope string a reader can act on. */
        ASSERT_STR_EQ(json_get_str(json_get(rb, "running_source_id_sha256")),
                      zcl_build_source_id_sha256());
        ASSERT_STR_EQ(
            json_get_str(json_get(rb, "running_source_id_scope")),
            "baked_into_this_executable_constant_across_working_directories");
        ASSERT_STR_EQ(json_get_str(json_get(rb, "expected_source_id_sha256")),
                      expected);
        ASSERT_STR_EQ(
            json_get_str(json_get(rb, "expected_source_id_scope")),
            "deploy_installed_intent_from_ZCL_AGENT_EXPECT_SOURCE_ID");

        /* No bare `source_id_sha256` inside this block: a nested bare key is
         * how a document starts answering two questions under one name, which
         * is what the shell-side unanimity rule then has to refuse. */
        ASSERT(json_get(rb, "source_id_sha256") == NULL);

        json_free(&doc);
        unsetenv("ZCL_AGENT_EXPECT_SOURCE_ID");
        PASS();
    } _test_next:;
    unsetenv("ZCL_AGENT_EXPECT_SOURCE_ID");
    return failures;
}

/* ── C + D: the shell reader, and the negative control that proves it ── */

/* A stand-in "binary" whose agentbuild payload carries BOTH identities: a
 * fixed baked one (Q1) and a nested one derived from the directory it is run
 * from (Q2). `mode` decides which comes first in the document, which is the
 * only thing a positional reader can see. */
static bool sia_write_fixture_binary(const char *path, const char *mode)
{
    char body[2048];
    snprintf(body, sizeof(body),
        "#!/bin/sh\n"
        "# Fixture stand-in for a built node. Emits a canonical\n"
        "# zcl.agent_build.v2 payload with a FIXED baked identity and a\n"
        "# nested identity derived from the working directory, so a\n"
        "# cwd-dependent read is visibly different from a cwd-invariant one.\n"
        "[ \"${1:-}\" = agentbuild ] || exit 64\n"
        /* A 64-hex value that is a pure function of the working directory.
         * Hashing the whole path (rather than hexdumping a prefix of it)
         * matters: two of the directories under test share a long prefix, and
         * a prefix-derived value would collide and quietly make the
         * cwd-dependence assertions vacuous. */
        "cwd_n=\"$(pwd | cksum | awk '{print $1}')\"\n"
        "cwd_hex=\"$(printf '%%08x%%08x%%08x%%08x%%08x%%08x%%08x%%08x' "
        "\"$cwd_n\" \"$cwd_n\" \"$cwd_n\" \"$cwd_n\" \"$cwd_n\" \"$cwd_n\" "
        "\"$cwd_n\" \"$cwd_n\")\"\n"
        "if [ '%s' = nested_first ]; then\n"
        "  printf '{\"schema\":\"zcl.agent_build.v2\",\"api_version\":\"v1\","
        "\"status\":\"ok\",\"lane\":{\"source_id_sha256\":\"%%s\"},"
        "\"source_id_sha256\":\"%s\",\"build_commit\":\"fixture\"}\\n' "
        "\"$cwd_hex\"\n"
        "else\n"
        "  printf '{\"schema\":\"zcl.agent_build.v2\",\"api_version\":\"v1\","
        "\"status\":\"ok\",\"source_id_sha256\":\"%s\","
        "\"build_commit\":\"fixture\",\"lane\":{\"source_id_sha256\":\"%%s\"}}"
        "\\n' \"$cwd_hex\"\n"
        "fi\n",
        mode, SIA_BAKED, SIA_BAKED);
    return sia_write_exec(path, body);
}

/* Run one reader against one fixture binary from one directory. `reader` is
 * either the shipped zcl_binary_source_id or the pre-fix positional form. */
static bool sia_read_from(const char *repo_root, const char *lib,
                          const char *bin, const char *cwd,
                          const char *reader, char *out, size_t out_len)
{
    char cmd[4096];
    if (strcmp(reader, "strict") == 0)
        snprintf(cmd, sizeof(cmd),
            "cd '%s' && . '%s' && zcl_binary_source_id '%s'",
            cwd, lib, bin);
    else
        /* The implementation this file's fix replaced, reproduced verbatim so
         * the control is the real prior behaviour and not a caricature. */
        snprintf(cmd, sizeof(cmd),
            "cd '%s' && . '%s' && "
            "zcl_json_first_sha256 \"$(timeout 20 '%s' agentbuild "
            "2>/dev/null)\" source_id_sha256",
            cwd, lib, bin);
    (void)repo_root;
    return sia_capture(cmd, out, out_len);
}

static int sia_binary_reader_is_cwd_invariant(void)
{
    int failures = 0;
    char work[512];
    char repo_root[PATH_MAX];
    work[0] = '\0';

    TEST("binary source id is the same from three working directories") {
        ASSERT(getcwd(repo_root, sizeof(repo_root)) != NULL);
        test_make_tmpdir(work, sizeof(work), "sia", "reader");
        char abswork[PATH_MAX];
        snprintf(abswork, sizeof(abswork), "%s/%s", repo_root, work);

        char lib[PATH_MAX];
        snprintf(lib, sizeof(lib), "%s/tools/scripts/source_identity_lib.sh",
                 repo_root);
        struct stat st;
        ASSERT(stat(lib, &st) == 0);

        /* Three genuinely different working directories: the repository root,
         * a subdirectory of it, and a tmpdir outside any checkout. */
        char sub[PATH_MAX], outside[PATH_MAX];
        snprintf(sub, sizeof(sub), "%s/tools", repo_root);
        snprintf(outside, sizeof(outside), "%s/outside", abswork);
        ASSERT(mkdir(outside, 0700) == 0);
        const char *cwds[3] = { repo_root, sub, outside };

        char bin[PATH_MAX];
        snprintf(bin, sizeof(bin), "%s/fake-node", abswork);
        ASSERT(sia_write_fixture_binary(bin, "canonical"));

        /* C: one binary, three directories, one answer — the baked one. */
        char got[3][256];
        for (int i = 0; i < 3; i++) {
            ASSERT(sia_read_from(repo_root, lib, bin, cwds[i], "strict",
                                 got[i], sizeof(got[i])));
            ASSERT_STR_EQ(got[i], SIA_BAKED);
        }

        /* The fixture really does vary by directory — otherwise the three
         * equal answers above would prove nothing about the reader. */
        char nested[3][256];
        for (int i = 0; i < 3; i++) {
            char cmd[4096];
            snprintf(cmd, sizeof(cmd),
                "cd '%s' && '%s' agentbuild | "
                "grep -oE '[0-9a-f]{64}' | sed -n 2p", cwds[i], bin);
            ASSERT(sia_capture(cmd, nested[i], sizeof(nested[i])));
            ASSERT(strlen(nested[i]) == 64);
        }
        ASSERT(strcmp(nested[0], nested[1]) != 0);
        ASSERT(strcmp(nested[0], nested[2]) != 0);

        PASS();
    } _test_next:;
    if (work[0])
        test_rm_rf_recursive(work);
    return failures;
}

static int sia_negative_control_positional_reader(void)
{
    int failures = 0;
    char work[512];
    char repo_root[PATH_MAX];
    work[0] = '\0';

    TEST("NEGATIVE CONTROL: the positional reader answers per-directory") {
        ASSERT(getcwd(repo_root, sizeof(repo_root)) != NULL);
        test_make_tmpdir(work, sizeof(work), "sia", "control");
        char abswork[PATH_MAX];
        snprintf(abswork, sizeof(abswork), "%s/%s", repo_root, work);

        char lib[PATH_MAX];
        snprintf(lib, sizeof(lib), "%s/tools/scripts/source_identity_lib.sh",
                 repo_root);

        char sub[PATH_MAX], outside[PATH_MAX];
        snprintf(sub, sizeof(sub), "%s/tools", repo_root);
        snprintf(outside, sizeof(outside), "%s/outside", abswork);
        ASSERT(mkdir(outside, 0700) == 0);
        const char *cwds[3] = { repo_root, sub, outside };

        /* Same schema, same values — only the ORDER differs, which is the
         * single thing that separates "returns the baked identity" from
         * "returns whatever this directory happens to be" for a reader that
         * takes the first match. */
        char bin[PATH_MAX];
        snprintf(bin, sizeof(bin), "%s/fake-node", abswork);
        ASSERT(sia_write_fixture_binary(bin, "nested_first"));

        char loose[3][256];
        for (int i = 0; i < 3; i++)
            ASSERT(sia_read_from(repo_root, lib, bin, cwds[i], "positional",
                                 loose[i], sizeof(loose[i])));

        /* THE CONTROL BITES: the pre-fix reader hands back three different
         * values for one binary, and not one of them is what that binary was
         * built from. A deploy check on this reader compares a directory to a
         * daemon. */
        ASSERT(strlen(loose[0]) == 64);
        ASSERT(strcmp(loose[0], SIA_BAKED) != 0);
        ASSERT(strcmp(loose[0], loose[1]) != 0);
        ASSERT(strcmp(loose[0], loose[2]) != 0);

        /* The shipped reader refuses the same payload outright rather than
         * substituting a directory-derived value: empty output, which every
         * caller treats as "this binary stated no identity". */
        for (int i = 0; i < 3; i++) {
            char strict[256];
            ASSERT(sia_read_from(repo_root, lib, bin, cwds[i], "strict",
                                 strict, sizeof(strict)));
            ASSERT_STR_EQ(strict, "");
        }

        PASS();
    } _test_next:;
    if (work[0])
        test_rm_rf_recursive(work);
    return failures;
}

/* ── the healthcheck reader a deploy check actually runs on ──────────── */

static int sia_healthcheck_reader_refuses_ambiguity(void)
{
    int failures = 0;
    char repo_root[PATH_MAX];

    TEST("healthcheck reader refuses a payload with two answers") {
        ASSERT(getcwd(repo_root, sizeof(repo_root)) != NULL);
        char lib[PATH_MAX];
        snprintf(lib, sizeof(lib), "%s/tools/scripts/source_identity_lib.sh",
                 repo_root);

        struct { const char *body; const char *want; const char *why; } cases[] = {
            /* The real shape: top-level baked value, repeated verbatim in the
             * nested agent block, runtime_build using its own distinct names. */
            { "{\"schema\":\"zcl.healthcheck.v1\",\"status\":\"ok\","
              "\"source_id_sha256\":\"" SIA_BAKED "\","
              "\"runtime_build\":{\"running_source_id_sha256\":\"" SIA_BAKED
              "\",\"expected_source_id_sha256\":\"" SIA_BAKED "\"},"
              "\"agent\":{\"source_id_sha256\":\"" SIA_BAKED "\"}}",
              SIA_BAKED, "unanimous document answers" },
            /* The same thing still inside its JSON-RPC envelope: refusing
               this would fail a FRESH deploy, which is its own outage. */
            { "{\"result\":{\"schema\":\"zcl.healthcheck.v1\","
              "\"status\":\"ok\",\"source_id_sha256\":\"" SIA_BAKED "\"},"
              "\"error\":null,\"id\":1}",
              SIA_BAKED, "an RPC envelope is still a healthcheck" },
            /* One nested working-tree value under the same key and the
               document no longer says which question it is answering. */
            { "{\"schema\":\"zcl.healthcheck.v1\",\"status\":\"ok\","
              "\"source_id_sha256\":\"" SIA_BAKED "\","
              "\"lane\":{\"source_id_sha256\":"
              "\"3333333333333333333333333333333333333333333333333333333333333333\"}}",
              "", "conflicting values are refused" },
            /* Reversed order: a positional reader flips its answer here; this
               one refuses either way. */
            { "{\"schema\":\"zcl.healthcheck.v1\",\"status\":\"ok\","
              "\"lane\":{\"source_id_sha256\":"
              "\"3333333333333333333333333333333333333333333333333333333333333333\"},"
              "\"source_id_sha256\":\"" SIA_BAKED "\"}",
              "", "order cannot rescue a conflicted document" },
            /* Not a healthcheck at all. */
            { "{\"schema\":\"zcl.agent_build.v2\",\"status\":\"ok\","
              "\"source_id_sha256\":\"" SIA_BAKED "\"}",
              "", "a foreign schema states nothing about the daemon" },
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            char cmd[4096], out[256];
            snprintf(cmd, sizeof(cmd),
                ". '%s' && zcl_healthcheck_v1_running_source_id '%s'",
                lib, cases[i].body);
            ASSERT(sia_capture(cmd, out, sizeof(out)));
            if (strcmp(out, cases[i].want) != 0)
                printf("[%s] ", cases[i].why);
            ASSERT_STR_EQ(out, cases[i].want);
        }
        PASS();
    } _test_next:;
    return failures;
}

int test_source_identity_authority(void)
{
    int failures = 0;
    printf("[test_source_identity_authority] starting\n");
    failures += sia_baked_constant_is_cwd_invariant();
    failures += sia_runtime_build_names_the_question();
    failures += sia_binary_reader_is_cwd_invariant();
    failures += sia_negative_control_positional_reader();
    failures += sia_healthcheck_reader_refuses_ambiguity();
    printf("[test_source_identity_authority] %d failure(s)\n", failures);
    return failures;
}
