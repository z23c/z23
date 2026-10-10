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
#include "base/hex.h"
#include "controllers/agent_controller.h"
#include "crypto/sha3.h"
#include "devloop.h"
#include "json/json.h"
#include "util/clientversion.h"
#include "vcs/build_action.h"

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

static bool sia_write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    if (!f) return false;
    bool ok = fputs(content, f) >= 0;
    if (fclose(f) != 0) ok = false;
    return ok;
}

/* Exercise the existing canonical action encoder with a real captured source
 * identity. Other roots are fixed fixture inputs; this case proves that Git
 * history is absent from the source slot, not that the fixture closes a real
 * compiler's toolchain or include search path. */
static bool sia_fixture_action_root(const char *record, uint8_t out[32])
{
    char source[65], complete[8], mutation[65];
    struct vcs_build_action_v1 action = {0};
    if (sscanf(record, "%64s %7s %64s", source, complete, mutation) != 3 ||
        strcmp(complete, "1") != 0 ||
        !zcl_hex_decode_lower(source, action.source_sha256, 32))
        return false;
    vcs_source_manifest_id((const uint8_t *)source, 64,
                           action.source_cas_sha3);
    sha3_256((const uint8_t *)"fixture-closure", 15,
             action.input_root_sha3);
    sha3_256((const uint8_t *)"fixture-toolchain", 17,
             action.toolchain_capsule_sha3);
    vcs_build_action_v1_fixed_flags_root(action.flags_sha3);
    vcs_build_action_v1_fixed_environment_root(action.environment_sha3);
    (void)snprintf(action.target, sizeof(action.target), "%s",
                   VCS_BUILD_TARGET_V1);
    (void)snprintf(action.profile, sizeof(action.profile), "source-fixture");
    (void)snprintf(action.virtual_workdir,
                   sizeof(action.virtual_workdir), "%s",
                   VCS_BUILD_VIRTUAL_ROOT_V1);
    (void)snprintf(action.declared_outputs,
                   sizeof(action.declared_outputs), "%s",
                   VCS_BUILD_OUTPUT_V1);
    (void)snprintf(action.resource_policy,
                   sizeof(action.resource_policy), "%s",
                   VCS_BUILD_RESOURCE_POLICY_V1);
    return vcs_build_action_v1_root(&action, out);
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

        char work[512];
        /* test_make_tmpdir yields an absolute path, which is what this case
         * needs — its whole point is to leave the repository root behind. */
        test_make_tmpdir(work, sizeof(work), "sia", "chdir");

        /* Read it once, then again from directories that share no prefix with
         * each other or with the repository. A value derived from the cwd —
         * or from a file found relative to it — cannot survive this. */
        char first[128];
        snprintf(first, sizeof(first), "%s", zcl_build_source_id_sha256());
        ASSERT(first[0] != '\0');

        const char *elsewhere[] = { "/", work, "/usr" };
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

        char lib[PATH_MAX];
        snprintf(lib, sizeof(lib), "%s/tools/scripts/source_identity_lib.sh",
                 repo_root);
        struct stat st;
        ASSERT(stat(lib, &st) == 0);

        /* Three genuinely different working directories: the repository root,
         * a subdirectory of it, and a tmpdir outside any checkout. */
        char sub[PATH_MAX], outside[PATH_MAX];
        snprintf(sub, sizeof(sub), "%s/tools", repo_root);
        snprintf(outside, sizeof(outside), "%s/outside", work);
        ASSERT(mkdir(outside, 0700) == 0);
        const char *cwds[3] = { repo_root, sub, outside };

        char bin[PATH_MAX];
        snprintf(bin, sizeof(bin), "%s/fake-node", work);
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

        char lib[PATH_MAX];
        snprintf(lib, sizeof(lib), "%s/tools/scripts/source_identity_lib.sh",
                 repo_root);

        char sub[PATH_MAX], outside[PATH_MAX];
        snprintf(sub, sizeof(sub), "%s/tools", repo_root);
        snprintf(outside, sizeof(outside), "%s/outside", work);
        ASSERT(mkdir(outside, 0700) == 0);
        const char *cwds[3] = { repo_root, sub, outside };

        /* Same schema, same values — only the ORDER differs, which is the
         * single thing that separates "returns the baked identity" from
         * "returns whatever this directory happens to be" for a reader that
         * takes the first match. */
        char bin[PATH_MAX];
        snprintf(bin, sizeof(bin), "%s/fake-node", work);
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

static bool sia_fixture_source_record(const char *repo, const char *script,
                                      char out[160])
{
    char cmd[PATH_MAX + 768];
    int n = snprintf(cmd, sizeof(cmd),
                     "cd '%s' && '%s' capture-record", repo, script);
    return n > 0 && (size_t)n < sizeof(cmd) &&
           sia_capture(cmd, out, 160);
}

static int sia_precommit_source_action(void)
{
    int failures = 0;
    char work[512] = {0}, repo_root[PATH_MAX];
    TEST("live source action survives commit and misses semantic edits") {
        ASSERT(getcwd(repo_root, sizeof(repo_root)) != NULL);
        test_make_tmpdir(work, sizeof(work), "sia", "precommit-action");
        char cmd[2048], path[PATH_MAX], script[PATH_MAX];
        (void)snprintf(script, sizeof(script),
                       "%s/tools/dev/source-identity.sh", repo_root);
        (void)snprintf(cmd, sizeof(cmd),
                       "git init -q '%s' && mkdir -p '%s/core/include' "
                       "'%s/tests/harness/include/test' "
                       "'%s/vendor/x11/include'", work, work, work, work);
        ASSERT(system(cmd) == 0);
        (void)snprintf(path, sizeof(path), "%s/core/input.c", work);
        ASSERT(sia_write_file(path,
            "#include \"shared.h\"\n"
            "#include \"test_core.h\"\n"
            "#if __has_include(\"optional.h\")\n"
            "#include \"optional.h\"\n"
            "#else\n#define OPTIONAL 0\n#endif\n"
            "#if __has_include(<x11_optional.h>)\n"
            "#include <x11_optional.h>\n"
            "#else\n#define X11_OPTIONAL 0\n#endif\n"
            "int value(void) { return SHARED + GENERATED + OPTIONAL "
            "+ X11_OPTIONAL; }\n"));
        (void)snprintf(path, sizeof(path), "%s/core/include/shared.h", work);
        ASSERT(sia_write_file(path, "#define SHARED 1\n"));
        (void)snprintf(path, sizeof(path),
                       "%s/tests/harness/include/test/test_core.h", work);
        ASSERT(sia_write_file(path, "#define GENERATED 2\n"));
        (void)snprintf(path, sizeof(path), "%s/Makefile", work);
        ASSERT(sia_write_file(path, "FLAGS=-DVALUE=0\n"));
        (void)snprintf(path, sizeof(path), "%s/.gitignore", work);
        ASSERT(sia_write_file(path, "vendor/x11/include/*\n"));
        (void)snprintf(cmd, sizeof(cmd), "git -C '%s' add .", work);
        ASSERT(system(cmd) == 0);

        char before[160], after[160], edited[160];
        uint8_t action_before[32], action_after[32];
        ASSERT(sia_fixture_source_record(work, script, before));
        ASSERT(sia_fixture_action_root(before, action_before));
        (void)snprintf(cmd, sizeof(cmd),
                       "git -C '%s' -c user.name=Fixture "
                       "-c user.email=fixture@example.invalid "
                       "-c commit.gpgsign=false commit -qm baseline", work);
        ASSERT(system(cmd) == 0);
        ASSERT(sia_fixture_source_record(work, script, after));
        ASSERT_STR_EQ(before, after);
        ASSERT(sia_fixture_action_root(after, action_after));
        ASSERT(memcmp(action_before, action_after, 32) == 0);

        (void)snprintf(path, sizeof(path), "%s/core/include/shared.h", work);
        ASSERT(sia_write_file(path, "#define SHARED 9\n"));
        ASSERT(sia_fixture_source_record(work, script, edited));
        ASSERT(strcmp(before, edited) != 0);
        ASSERT(sia_fixture_action_root(edited, action_after));
        ASSERT(memcmp(action_before, action_after, 32) != 0);
        ASSERT(sia_write_file(path, "#define SHARED 1\n"));

        (void)snprintf(path, sizeof(path), "%s/Makefile", work);
        ASSERT(sia_write_file(path, "FLAGS=-DVALUE=1\n"));
        ASSERT(sia_fixture_source_record(work, script, edited));
        ASSERT(strcmp(before, edited) != 0);
        ASSERT(sia_fixture_action_root(edited, action_after));
        ASSERT(memcmp(action_before, action_after, 32) != 0);
        ASSERT(sia_write_file(path, "FLAGS=-DVALUE=0\n"));

        (void)snprintf(path, sizeof(path),
                       "%s/tests/harness/include/test/test_core.h", work);
        ASSERT(sia_write_file(path, "#define GENERATED 7\n"));
        ASSERT(sia_fixture_source_record(work, script, edited));
        ASSERT(strcmp(before, edited) != 0);
        ASSERT(sia_fixture_action_root(edited, action_after));
        ASSERT(memcmp(action_before, action_after, 32) != 0);
        ASSERT(sia_write_file(path, "#define GENERATED 2\n"));

        char no_header[512], with_header[512];
        (void)snprintf(cmd, sizeof(cmd),
                       "cc -std=c23 -E -P -I '%s/core/include' "
                       "-I '%s/tests/harness/include/test' "
                       "-I '%s/vendor/x11/include' '%s/core/input.c'",
                       work, work, work, work);
        ASSERT(sia_capture(cmd, no_header, sizeof(no_header)));
        (void)snprintf(path, sizeof(path), "%s/core/include/optional.h", work);
        ASSERT(sia_write_file(path, "#define OPTIONAL 11\n"));
        ASSERT(sia_capture(cmd, with_header, sizeof(with_header)));
        ASSERT(strcmp(no_header, with_header) != 0);
        ASSERT(sia_fixture_source_record(work, script, edited));
        ASSERT(strcmp(before, edited) != 0);
        ASSERT(sia_fixture_action_root(edited, action_after));
        ASSERT(memcmp(action_before, action_after, 32) != 0);
        ASSERT(unlink(path) == 0);
        ASSERT(sia_fixture_source_record(work, script, edited));
        ASSERT(strncmp(before, edited, 64) == 0);
        ASSERT(strcmp(before, edited) != 0); /* ABA token still moved. */
        ASSERT(sia_fixture_action_root(edited, action_after));
        ASSERT(memcmp(action_before, action_after, 32) == 0);

        /* An ignored header under a real -I root is still compiler input.
         * Creation flips __has_include, so excluding it from the source
         * inventory would silently reuse the old precommit action. */
        (void)snprintf(path, sizeof(path),
                       "%s/vendor/x11/include/x11_optional.h", work);
        ASSERT(sia_write_file(path, "#define X11_OPTIONAL 13\n"));
        ASSERT(sia_capture(cmd, with_header, sizeof(with_header)));
        ASSERT(strcmp(no_header, with_header) != 0);
        ASSERT(sia_fixture_source_record(work, script, edited));
        ASSERT(strncmp(before, edited, 64) != 0);
        ASSERT(sia_fixture_action_root(edited, action_after));
        ASSERT(memcmp(action_before, action_after, 32) != 0);
        ASSERT(unlink(path) == 0);
        ASSERT(sia_fixture_source_record(work, script, edited));
        ASSERT(strncmp(before, edited, 64) == 0);
        PASS();
    } _test_next:;
    if (work[0]) test_rm_rf_recursive(work);
    return failures;
}

#if !defined(_WIN32)
static int sia_include_namespace_closure(void)
{
    int failures = 0;
    char work[512] = {0}, root[PATH_MAX], path[PATH_MAX];
    TEST("include namespace captures absent headers and refuses missing closure") {
        test_make_tmpdir(work, sizeof(work), "sia", "include-namespace");
        ASSERT(snprintf(root, sizeof(root), "%s", work) < (int)sizeof(root));
        ASSERT(snprintf(path, sizeof(path), "%s/include", root) <
               (int)sizeof(path));
        ASSERT(mkdir(path, 0700) == 0);
        const char *roots[] = {"include", "optional"};
        char why[128];
        uint8_t before[32], changed[32], restored[32];
        ASSERT(zcl_dev_include_namespace_v1_root(root, roots, 2,
                                                 before, why, sizeof(why)));
        ASSERT(snprintf(path, sizeof(path), "%s/include/feature.h", root) <
               (int)sizeof(path));
        ASSERT(sia_write_file(path, "#define FEATURE 1\n"));
        ASSERT(zcl_dev_include_namespace_v1_root(root, roots, 2,
                                                 changed, why, sizeof(why)));
        ASSERT(memcmp(before, changed, 32) != 0);
        ASSERT(sia_write_file(path, "#define FEATURE 2\n"));
        ASSERT(zcl_dev_include_namespace_v1_root(root, roots, 2,
                                                 restored, why, sizeof(why)));
        ASSERT(memcmp(changed, restored, 32) == 0);
        ASSERT(unlink(path) == 0);
        ASSERT(zcl_dev_include_namespace_v1_root(root, roots, 2,
                                                 restored, why, sizeof(why)));
        ASSERT(memcmp(before, restored, 32) == 0);
        ASSERT(snprintf(path, sizeof(path), "%s/optional", root) <
               (int)sizeof(path));
        ASSERT(mkdir(path, 0700) == 0);
        ASSERT(zcl_dev_include_namespace_v1_root(root, roots, 2,
                                                 changed, why, sizeof(why)));
        ASSERT(memcmp(before, changed, 32) != 0);
        ASSERT(rmdir(path) == 0);
        ASSERT(snprintf(path, sizeof(path), "%s/include/special", root) <
               (int)sizeof(path));
        ASSERT(mkfifo(path, 0600) == 0);
        ASSERT(!zcl_dev_include_namespace_v1_root(root, roots, 2,
                                                  changed, why, sizeof(why)));
        ASSERT(strstr(why, "special_type") != NULL);
        ASSERT(unlink(path) == 0);
        ASSERT(!zcl_dev_include_namespace_v1_root(root, roots, 0,
                                                  changed, why, sizeof(why)));
        PASS();
    } _test_next:;
    if (work[0]) test_rm_rf_recursive(work);
    return failures;
}

static int sia_include_search_semantics(void)
{
    int failures = 0;
    char work[512] = {0}, path[PATH_MAX], cmd[PATH_MAX * 4];
    TEST("ordered include roots catch earlier headers and __has_include") {
        test_make_tmpdir(work, sizeof(work), "sia", "include-search");
        ASSERT(snprintf(path, sizeof(path), "%s/first", work) <
               (int)sizeof(path));
        ASSERT(mkdir(path, 0700) == 0);
        ASSERT(snprintf(path, sizeof(path), "%s/second", work) <
               (int)sizeof(path));
        ASSERT(mkdir(path, 0700) == 0);
        ASSERT(snprintf(path, sizeof(path), "%s/second/choice.h", work) <
               (int)sizeof(path));
        ASSERT(sia_write_file(path, "#define CHOICE 2\n"));
        ASSERT(snprintf(path, sizeof(path), "%s/unit.c", work) <
               (int)sizeof(path));
        ASSERT(sia_write_file(path,
            "#if __has_include(<choice.h>)\n#include <choice.h>\n"
            "#else\n#define CHOICE 0\n#endif\nint selected = CHOICE;\n"
            "#if __has_include(<optional.h>)\nint optional = 1;\n"
            "#else\nint optional = 0;\n#endif\n"));
        ASSERT(snprintf(cmd, sizeof(cmd),
                        "cc -std=c23 -E -P -x c -I '%s/first' "
                        "-I '%s/second' '%s/unit.c'", work, work, work) <
               (int)sizeof(cmd));
        const char *roots[] = {"first", "second"};
        uint8_t before[32], changed[32];
        char why[128], output[512];
        ASSERT(zcl_dev_include_namespace_v1_root(
            work, roots, 2, before, why, sizeof(why)));
        ASSERT(sia_capture(cmd, output, sizeof(output)));
        ASSERT(strstr(output, "int selected = 2;") != NULL);
        ASSERT(strstr(output, "int optional = 0;") != NULL);
        ASSERT(snprintf(path, sizeof(path), "%s/first/choice.h", work) <
               (int)sizeof(path));
        ASSERT(sia_write_file(path, "#define CHOICE 1\n"));
        ASSERT(zcl_dev_include_namespace_v1_root(
            work, roots, 2, changed, why, sizeof(why)));
        ASSERT(memcmp(before, changed, 32) != 0);
        ASSERT(sia_capture(cmd, output, sizeof(output)));
        ASSERT(strstr(output, "int selected = 1;") != NULL);
        ASSERT(snprintf(path, sizeof(path), "%s/first/optional.h", work) <
               (int)sizeof(path));
        ASSERT(sia_write_file(path, "/* presence only */\n"));
        memcpy(before, changed, 32);
        ASSERT(zcl_dev_include_namespace_v1_root(
            work, roots, 2, changed, why, sizeof(why)));
        ASSERT(memcmp(before, changed, 32) != 0);
        ASSERT(sia_capture(cmd, output, sizeof(output)));
        ASSERT(strstr(output, "int optional = 1;") != NULL);
        const char *reversed[] = {"second", "first"};
        ASSERT(zcl_dev_include_namespace_v1_root(
            work, reversed, 2, before, why, sizeof(why)));
        ASSERT(memcmp(before, changed, 32) != 0);
        PASS();
    } _test_next:;
    if (work[0]) test_rm_rf_recursive(work);
    return failures;
}
#endif

#if !defined(_WIN32)
/* Exercise the actual cache publisher with an enforced A-open/B-open/A-rename/B-write schedule. */
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
static FILE *sia_cache_stage(FILE *file);
static int sia_cache_rename(const char *from, const char *to);
int sia_batch_fixture_main(int argc, char **argv);
#define ZCL_SOURCE_IDENTITY_BATCH_INPUT_ID "fixture"
#define main sia_batch_fixture_main
#define fopen(path, mode) sia_cache_stage(fopen(path, mode))
#define fdopen(fd, mode) sia_cache_stage(fdopen(fd, mode))
#define rename sia_cache_rename
#include "../../../tools/dev/source_identity_batch.c"
#undef rename
#undef fdopen
#undef fopen
#undef main
#undef ZCL_SOURCE_IDENTITY_BATCH_INPUT_ID
static int sia_racing, sia_writer_b, sia_ready[2] = {-1, -1}, sia_resume[2] = {-1, -1}, sia_child_status;
static pid_t sia_child;
static bool sia_a_whole;
static struct digest_row sia_row_a = {.path = "a.c", .size = 999999999};
static struct digest_row sia_row_b = {.path = "b.c", .size = 1};
static bool sia_cache_whole(const char *path, const struct digest_row *row)
{
    char actual[512] = {0}, expected[512], hex[65];
    zcl_hex_encode(row->digest, 32, hex);
    snprintf(expected, sizeof(expected), "0 0 0 %" PRIu64 " 0 0 0 0 %s %s\n", row->size, hex, row->path);
    FILE *f = fopen(path, "r");
    if (!f) return false;
    size_t n = fread(actual, 1, sizeof(actual) - 1, f);
    bool ok = feof(f) && !ferror(f) && n == strlen(expected);
    if (fclose(f) != 0) ok = false;
    return ok && strcmp(actual, expected) == 0;
}
static FILE *sia_cache_stage(FILE *file)
{
    if (!sia_racing || !file) return file;
    char byte = 0;
    if (sia_writer_b) {
        if (write(sia_ready[1], &byte, 1) != 1 || read(sia_resume[0], &byte, 1) != 1) _exit(2);
        return file;
    }
    sia_child = fork();
    if (sia_child == 0) {
        alarm(5);
        if (fclose(file) != 0) _exit(3);
        sia_writer_b = 1; g_rows = &sia_row_b;
        cache_save();
        _exit(0);
    }
    struct pollfd ready = {.fd = sia_ready[0], .events = POLLIN};
    if (sia_child < 0 || poll(&ready, 1, 5000) != 1 || read(sia_ready[0], &byte, 1) != 1) {
        if (sia_child > 0) { kill(sia_child, SIGKILL); waitpid(sia_child, NULL, 0); }
        fclose(file); return NULL;
    }
    return file;
}
static int sia_cache_rename(const char *from, const char *to)
{
    int rc = rename(from, to);
    if (sia_racing && !sia_writer_b) {
        sia_racing = 0;
        sia_a_whole = rc == 0 && sia_cache_whole(to, &sia_row_a);
        char byte = 0;
        if (write(sia_resume[1], &byte, 1) != 1) kill(sia_child, SIGKILL);
        if (waitpid(sia_child, &sia_child_status, 0) != sia_child) sia_child_status = -1;
    }
    return rc;
}
static int sia_digest_cache_concurrent(void)
{
    int failures = 0;
    char work[512] = {0};
    bool loaded = false;
    TEST("digest cache concurrent publication retains whole rows and validates metadata") {
        test_make_tmpdir(work, sizeof(work), "sia", "cache-concurrent");
        ASSERT(snprintf(g_cache_path, sizeof(g_cache_path), "%s/cache", work) < (int)sizeof(g_cache_path));
        ASSERT_EQ(pipe(sia_ready), 0); ASSERT_EQ(pipe(sia_resume), 0);
        g_rows = &sia_row_a; g_row_count = 1; g_cache_dirty = 1; g_cache_ready = 1;
        sia_racing = 1; cache_save(); sia_racing = 0;
        ASSERT(sia_a_whole); ASSERT_EQ(sia_child_status, 0);
        ASSERT(sia_cache_whole(g_cache_path, &sia_row_b));
        g_rows = &sia_row_b; g_row_count = 0; g_row_cap = 1; g_cache_ready = 0;
        loaded = true; sia_row_b.path = NULL; cache_load();
        ASSERT_EQ(g_row_count, 1);
        struct stat snapshot; row_apply(&snapshot, &sia_row_b);
        uint8_t digest[32];
        ASSERT_EQ(reuse_snapshot("b.c", &snapshot, digest), 1);
        snapshot.st_size++;
        ASSERT_EQ(reuse_snapshot("b.c", &snapshot, digest), 0);
        PASS();
    } _test_next:;
    close(sia_ready[0]); close(sia_ready[1]); close(sia_resume[0]); close(sia_resume[1]);
    if (loaded) cache_release_path(sia_row_b.path);
    sia_row_b.path = "b.c";
    g_rows = NULL; g_row_count = 0; g_row_cap = 0; g_cache_ready = 0; g_cache_path[0] = '\0';
    if (work[0]) test_rm_rf_recursive(work);
    return failures;
}
static int sia_digest_cache_absent_directory(void)
{
    int failures = 0;
    char work[512] = {0}, root[PATH_MAX], path[PATH_MAX];
    char cmd[PATH_MAX * 4], out[512];
    TEST("digest cache absent directory quietly preserves successful hashing") {
        ASSERT(getcwd(root, sizeof(root)) != NULL);
        test_make_tmpdir(work, sizeof(work), "sia", "cache-absent");
        ASSERT(snprintf(path, sizeof(path), "%s/input", work) < (int)sizeof(path));
        ASSERT(sia_write_file(path, "abc"));
        ASSERT(snprintf(cmd, sizeof(cmd),
            "cd '%s' && { printf 'input\\0' | '%s/build/bin/source-identity-batch' "
            "hash --cache absent/cache >result 2>error; status=$?; "
            "printf 'status=%%s\\n' \"$status\"; cat error; tr '\\000' '\\n' <result; }",
            work, root) < (int)sizeof(cmd));
        ASSERT(sia_capture(cmd, out, sizeof(out)));
        ASSERT(strcmp(out, "status=0\n"
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad "
            " input") == 0);
        ASSERT(snprintf(path, sizeof(path), "%s/absent", work) < (int)sizeof(path));
        struct stat snapshot;
        ASSERT(lstat(path, &snapshot) != 0 && errno == ENOENT);
        PASS();
    } _test_next:;
    if (work[0]) test_rm_rf_recursive(work);
    return failures;
}
/* Corrupt cache framing must not qualify metadata-matched digest reuse. */
static int sia_digest_cache_framing(void)
{
    int failures = 0;
    char work[512] = {0}, root[PATH_MAX], cmd[PATH_MAX * 3], out[256];
    TEST("digest cache rejects NUL and continuation records") {
        ASSERT(getcwd(root, sizeof(root)) != NULL);
        test_make_tmpdir(work, sizeof(work), "sia", "cache-framing");
        char path[PATH_MAX];
        ASSERT(snprintf(path, sizeof(path), "%s/input", work) < (int)sizeof(path));
        ASSERT(sia_write_file(path, "abc"));
        ASSERT(snprintf(cmd, sizeof(cmd),
            "cd '%s' && printf 'input\\0' | '%s/build/bin/source-identity-batch' "
            "hash --cache cache --report-bytes 2>&1 | tr '\\000' '\\n'",
            work, root) < (int)sizeof(cmd));
        ASSERT(sia_capture(cmd, out, sizeof(out)));
        ASSERT(strstr(out, "content_bytes_read=3") != NULL);
        ASSERT(snprintf(path, sizeof(path), "%s/cache", work) < (int)sizeof(path));
        FILE *f = fopen(path, "rb");
        ASSERT(f != NULL);
        char row[8192];
        size_t n = fread(row, 1, sizeof(row), f);
        bool complete = feof(f) && !ferror(f);
        ASSERT_EQ(fclose(f), 0);
        ASSERT(complete && n > 0 && row[n - 1] == '\n');
        for (int kind = 0; kind < 5; kind++) {
            f = fopen(path, "wb");
            ASSERT(f != NULL);
            if (kind == 4) ASSERT_EQ(fwrite(row, 1, n, f), n);
            if (kind == 2) for (int i = 0; i < 8191; i++) ASSERT(fputc('x', f) != EOF);
            ASSERT_EQ(fwrite(row, 1, n - 1, f), n - 1);
            if (kind == 1 || kind == 4) ASSERT_EQ(fwrite("\0extra", 1, 6, f), 6);
            if (kind != 3) ASSERT(fputc('\n', f) != EOF);
            ASSERT_EQ(fclose(f), 0);
            ASSERT(sia_capture(cmd, out, sizeof(out)));
            ASSERT(strstr(out, kind == 1 || kind == 2 || kind == 4 ?
                          "content_bytes_read=3" : "content_bytes_read=0") != NULL);
        }
        PASS();
    } _test_next:;
    if (work[0]) test_rm_rf_recursive(work);
    return failures;
}
#endif

static int sia_tor_receipt_is_not_source(void)
{
    int failures = 0;
    char work[512] = {0}, origin[PATH_MAX], cmd[8192];
    TEST("Tor receipt differs across roots without hiding source inputs") {
        ASSERT(getcwd(origin, sizeof(origin)) != NULL);
        test_make_tmpdir(work, sizeof(work), "sia", "tor-receipt");
        int n = snprintf(cmd, sizeof(cmd),
            "bash -c 'set -euo pipefail; cd \"%s\"; "
            "mkdir -p a/vendor/tor; git init -q a; "
            "git init -q a/vendor/tor; "
            "printf source > a/vendor/tor/input.c; "
            "printf header > a/vendor/tor/input.h; "
            "printf \"*.a\\n\" > a/vendor/tor/.gitignore; "
            "git -C a/vendor/tor add .; "
            "git -C a/vendor/tor -c user.name=Fixture "
            "-c user.email=fixture@example.invalid commit -qm source; "
            "git -C a add vendor/tor; "
            "git -C a -c user.name=Fixture -c user.email=fixture@example.invalid "
            "commit -qm source; cp -a a b; "
            "printf archive > a/vendor/tor/libtor.a; "
            "printf archive > b/vendor/tor/libtor.a; "
            "printf receipt-a > a/vendor/tor/.provenance; "
            "printf receipt-b > b/vendor/tor/.provenance; "
            "script=\"%s/tools/dev/source-identity.sh\"; "
            "helper=$(\"${script%%/*}/source-identity-batch-bootstrap.sh\"); "
            "[ -n \"$helper\" ] && [ -x \"$helper\" ]; "
            "\"$helper\" check-tags < /dev/null; "
            "printf helper=; sha256sum \"$helper\"; "
            "id() { value=$( (cd \"$1\"; "
            "ZCL_SOURCE_IDENTITY_BATCH_DISABLE=\"$2\" \"$script\" capture-record) "
            "| cut -d\" \" -f1) || return 1; "
            "[[ $value =~ ^[0-9a-f]{64}$ ]] || return 1; "
            "printf \"%%s\\n\" \"$value\"; }; "
            "same() { got=$(id b \"$1\") || exit 1; "
            "if [ \"$base\" != \"$got\" ]; then "
            "printf \"receipt-only identity mismatch: expected=%%s actual=%%s\\n\" "
            "\"$base\" \"$got\" >&2; exit 1; fi; }; "
            "different() { got=$(id b \"$1\") || exit 1; "
            "[ \"$base\" != \"$got\" ]; }; "
            "for fallback in 0 1; do "
            "base=$(id a $fallback); "
            "[[ $base =~ ^[0-9a-f]{64}$ ]]; "
            "same $fallback; "
            "for file in input.c input.h libtor.a extra.c; do "
            "[ ! -e b/vendor/tor/$file ] || cp b/vendor/tor/$file saved; "
            "printf changed > b/vendor/tor/$file; "
            "different $fallback; "
            "if [ -e saved ]; then mv saved b/vendor/tor/$file; "
            "else rm b/vendor/tor/$file; fi; done; "
            "same $fallback; "
            "printf other > b/.provenance; "
            "different $fallback; rm b/.provenance; "
            "done; native=$(id a 0); fallback=$(id a 1); "
            "[ \"$native\" = \"$fallback\" ]; "
            "(cd a; \"$script\" paths) | grep -Fx vendor/tor/.provenance; "
            "git -C a/vendor/tor add .provenance; "
            "tracked=$(id a 1); printf receipt-changed > a/vendor/tor/.provenance; "
            "changed=$(id a 1); [ \"$tracked\" != \"$changed\" ]; "
            "native=$(id a 0); [ \"$native\" = \"$changed\" ]; "
            "printf helper-after=; sha256sum \"$helper\"'", work, origin);
        ASSERT(n > 0 && (size_t)n < sizeof(cmd));
        ASSERT(system(cmd) == 0);
        PASS();
    } _test_next:;
    if (work[0]) test_rm_rf_recursive(work);
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
    failures += sia_precommit_source_action();
    failures += sia_tor_receipt_is_not_source();
#if !defined(_WIN32)
    failures += sia_digest_cache_concurrent();
    failures += sia_digest_cache_absent_directory();
    failures += sia_digest_cache_framing();
    failures += sia_include_namespace_closure();
    failures += sia_include_search_semantics();
#endif
    printf("[test_source_identity_authority] %d failure(s)\n", failures);
    return failures;
}
