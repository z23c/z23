/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Contract for the node's own config file: ReadConfigFile(),
 * GetConfigFilePath() and ArgvDataDir() in platform/modules/util/src/util.c.
 *
 * A config reader is a settings-precedence machine and its failures are
 * silent: a file that overrode argv would let a stale line beat the service
 * unit's ExecStart, and a path resolver that fell back to the default
 * datadir would read the live node's config for a throwaway instance.
 *
 * The cases pin four properties:
 *
 *   1. argv wins, always. A key already in the table is left byte-identical.
 *   2. -datadir and -conf inside the file are ignored — the file's own path
 *      is derived FROM the datadir, so such a line could relocate it.
 *   3. resolving a path creates nothing (`z23 help` on a fresh box leaves
 *      no data directory).
 *   4. a missing file is the normal case: -1, no table mutation, no noise.
 *
 * Pure and hermetic: every case drives a tmpdir under ./test-tmp, no node,
 * no network, no live datadir. */

#include "test/test_core.h"

#include "util/util.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Write `body` to <dir>/z23.conf; false on failure so a filesystem problem
 * cannot masquerade as the missing-file path. */
static bool ncf_write_bytes(const char *dir, const char *body, size_t length)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, ZCL_NODE_CONFIG_FILENAME);
    FILE *f = fopen(path, "we");
    if (!f)
        return false;
    bool written = fwrite(body, 1, length, f) == length;
    if (fclose(f) != 0)
        written = false;
    return written;
}

static bool ncf_write_conf(const char *dir, const char *body)
{
    return ncf_write_bytes(dir, body, strlen(body));
}

/* Reset the argument table via ParseParameters(), the production entry
 * point main() uses. */
static void ncf_set_argv(const char *const *argv, int argc)
{
    ParseParameters(argc, argv);
}

static int test_command_line_always_wins(void)
{
    int failures = 0;

    TEST("node-config: a file line never overrides the same key from argv") {
        char dir[512];
        test_make_tmpdir(dir, sizeof(dir), "node_conf", "argvwins");
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dir, ZCL_NODE_CONFIG_FILENAME);

        ASSERT(ncf_write_conf(dir, "packagehost=from-file\n"
                                   "buildworker=from-file\n"));

        const char *argv[] = { "z23", "-packagehost=from-argv" };
        ncf_set_argv(argv, 2);

        int applied = ReadConfigFile(path);
        /* buildworker was absent from argv, so exactly one line applies. */
        ASSERT_EQ(applied, 1);
        ASSERT_STR_EQ(GetArg("-packagehost", ""), "from-argv");
        ASSERT_STR_EQ(GetArg("-buildworker", ""), "from-file");

        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;

    return failures;
}

static int test_file_cannot_move_the_datadir(void)
{
    int failures = 0;

    TEST("node-config: -datadir and -conf inside the file are ignored") {
        char dir[512];
        test_make_tmpdir(dir, sizeof(dir), "node_conf", "nodatadir");
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dir, ZCL_NODE_CONFIG_FILENAME);

        ASSERT(ncf_write_conf(dir, "datadir=/tmp/somewhere-else\n"
                                   "conf=/tmp/other.conf\n"
                                   "packagehost=1\n"));

        const char *argv[] = { "z23" };
        ncf_set_argv(argv, 1);

        int applied = ReadConfigFile(path);
        ASSERT_EQ(applied, 1);   /* packagehost only */
        ASSERT_STR_EQ(GetArg("-datadir", "unset"), "unset");
        ASSERT_STR_EQ(GetArg("-conf", "unset"), "unset");
        ASSERT_STR_EQ(GetArg("-packagehost", ""), "1");

        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;

    return failures;
}

static int test_line_shapes(void)
{
    int failures = 0;

    TEST("node-config: comments, blank lines, spacing and a bare flag") {
        char dir[512];
        test_make_tmpdir(dir, sizeof(dir), "node_conf", "shapes");
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dir, ZCL_NODE_CONFIG_FILENAME);

        /* The leading '-' is optional so a line copied from ExecStart works. */
        ASSERT(ncf_write_conf(dir,
            "# a comment line\n"
            "\n"
            "   \t \n"
            "-packagehost=dashed\n"
            "  buildworker = spaced  \n"
            "listen                       # trailing comment\n"
            "note=keep # this is stripped\n"));

        const char *argv[] = { "z23" };
        ncf_set_argv(argv, 1);

        int applied = ReadConfigFile(path);
        ASSERT_EQ(applied, 4);
        ASSERT_STR_EQ(GetArg("-packagehost", ""), "dashed");
        /* `key = value` must not become a flag named "buildworker ". */
        ASSERT_STR_EQ(GetArg("-buildworker", ""), "spaced");
        /* A bare flag is true, matching ParseParameters' present-but-empty
         * rule. */
        ASSERT_STR_EQ(GetArg("-listen", "absent"), "");
        ASSERT(GetBoolArg("-listen", false));
        ASSERT_STR_EQ(GetArg("-note", ""), "keep");

        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;

    return failures;
}

static int test_comment_continuation(void)
{
    int failures = 0;
    TEST("node-config: overlong comments discard setting continuations") {
        char dir[512], path[1024], body[MAX_ARG_LEN * 3];
        test_make_tmpdir(dir, sizeof(dir), "node_conf", "comment_continuation");
        snprintf(path, sizeof(path), "%s/%s", dir, ZCL_NODE_CONFIG_FILENAME);
        const char *argv[] = { "z23" };
        body[0] = '#';
        memset(body + 1, 'a', MAX_ARG_LEN * 2 - 2);
        snprintf(body + MAX_ARG_LEN * 2 - 1,
                 sizeof(body) - (MAX_ARG_LEN * 2 - 1),
                 "packagehost=1\nbuildworker=1\n");
        ASSERT(ncf_write_conf(dir, body));
        ncf_set_argv(argv, 1);
        ASSERT_EQ(ReadConfigFile(path), 1);
        ASSERT_STR_EQ(GetArg("-packagehost", "absent"), "absent");
        ASSERT_STR_EQ(GetArg("-buildworker", ""), "1");
        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_oversized_value(void)
{
    int failures = 0;
    TEST("node-config: oversized values insert no truncated setting") {
        char dir[512], path[1024], body[MAX_ARG_LEN * 3];
        test_make_tmpdir(dir, sizeof(dir), "node_conf", "oversized_value");
        snprintf(path, sizeof(path), "%s/%s", dir, ZCL_NODE_CONFIG_FILENAME);
        const char *argv[] = { "z23" };
        memcpy(body, "packagehost=", 12);
        memset(body + 12, 'a', MAX_ARG_LEN);
        snprintf(body + 12 + MAX_ARG_LEN, sizeof(body) - 12 - MAX_ARG_LEN,
                 "\nbuildworker=1\n");
        ASSERT(ncf_write_conf(dir, body));
        ncf_set_argv(argv, 1);
        ASSERT_EQ(ReadConfigFile(path), 1);
        ASSERT_STR_EQ(GetArg("-packagehost", "absent"), "absent");
        ASSERT_STR_EQ(GetArg("-buildworker", ""), "1");
        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_spanning_value(void)
{
    int failures = 0;
    TEST("node-config: values spanning records insert no fragments") {
        char dir[512], path[1024], body[MAX_ARG_LEN * 3];
        test_make_tmpdir(dir, sizeof(dir), "node_conf", "spanning_value");
        snprintf(path, sizeof(path), "%s/%s", dir, ZCL_NODE_CONFIG_FILENAME);
        const char *argv[] = { "z23" };
        memcpy(body, "packagehost=", 12);
        memset(body + 12, 'a', MAX_ARG_LEN * 2);
        snprintf(body + 12 + MAX_ARG_LEN * 2,
                 sizeof(body) - 12 - MAX_ARG_LEN * 2, "\nbuildworker=1\n");
        ASSERT(ncf_write_conf(dir, body));
        ncf_set_argv(argv, 1);
        ASSERT_EQ(ReadConfigFile(path), 1);
        ASSERT_STR_EQ(GetArg("-packagehost", "absent"), "absent");
        ASSERT_STR_EQ(GetArg("-buildworker", ""), "1");
        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_representable_value(void)
{
    int failures = 0;
    TEST("node-config: representable values and short EOF records apply") {
        char dir[512], path[1024], body[MAX_ARG_LEN * 3];
        test_make_tmpdir(dir, sizeof(dir), "node_conf", "representable_value");
        snprintf(path, sizeof(path), "%s/%s", dir, ZCL_NODE_CONFIG_FILENAME);
        const char *argv[] = { "z23" };
        memcpy(body, "packagehost=", 12);
        memset(body + 12, 'a', MAX_ARG_LEN - 1);
        snprintf(body + 12 + MAX_ARG_LEN - 1,
                 sizeof(body) - 12 - (MAX_ARG_LEN - 1), "\nbuildworker=1");
        ASSERT(ncf_write_conf(dir, body));
        ncf_set_argv(argv, 1);
        ASSERT_EQ(ReadConfigFile(path), 2);
        ASSERT_EQ(strlen(GetArg("-packagehost", "")), MAX_ARG_LEN - 1);
        ASSERT_STR_EQ(GetArg("-buildworker", ""), "1");
        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_maximum_record(void)
{
    int failures = 0;
    TEST("node-config: maximum key and value fit at newline and EOF") {
        char dir[512], path[1024], body[MAX_ARG_LEN * 3];
        test_make_tmpdir(dir, sizeof(dir), "node_conf", "maximum_record");
        snprintf(path, sizeof(path), "%s/%s", dir, ZCL_NODE_CONFIG_FILENAME);
        const char *argv[] = { "z23" };
        body[0] = '-';
        memset(body + 1, 'k', MAX_ARG_LEN - 2);
        body[MAX_ARG_LEN - 1] = '=';
        memset(body + MAX_ARG_LEN, 'v', MAX_ARG_LEN - 1);
        body[MAX_ARG_LEN * 2 - 1] = '\0';
        ASSERT(ncf_write_conf(dir, body));
        ncf_set_argv(argv, 1);
        ASSERT_EQ(ReadConfigFile(path), 1);
        ASSERT_EQ(strlen(g_args[0].key), MAX_ARG_LEN - 1);
        ASSERT_EQ(strlen(g_args[0].value), MAX_ARG_LEN - 1);
        body[MAX_ARG_LEN * 2 - 1] = '\n';
        body[MAX_ARG_LEN * 2] = '\0';
        ASSERT(ncf_write_conf(dir, body));
        ncf_set_argv(argv, 1);
        ASSERT_EQ(ReadConfigFile(path), 1);
        ASSERT_EQ(strlen(g_args[0].key), MAX_ARG_LEN - 1);
        ASSERT_EQ(strlen(g_args[0].value), MAX_ARG_LEN - 1);
        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_nul_record(void)
{
    int failures = 0;
    TEST("node-config: NUL-bearing records discard hidden trailing bytes") {
        char dir[512], path[1024];
        static const char body[] = "packagehost=1\0junk\nbuildworker=1\n";
        test_make_tmpdir(dir, sizeof(dir), "node_conf", "nul_record");
        snprintf(path, sizeof(path), "%s/%s", dir, ZCL_NODE_CONFIG_FILENAME);
        ASSERT(ncf_write_bytes(dir, body, sizeof(body) - 1));
        const char *argv[] = { "z23" };
        ncf_set_argv(argv, 1);
        ASSERT_EQ(ReadConfigFile(path), 1);
        ASSERT_STR_EQ(GetArg("-packagehost", "absent"), "absent");
        ASSERT_STR_EQ(GetArg("-buildworker", ""), "1");
        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_nul_boundary(void)
{
    int failures = 0;
    TEST("node-config: NUL before the read boundary cannot expose a setting") {
        char dir[512], path[1024], body[MAX_ARG_LEN * 3];
        static const char tail[] = "packagehost=1\nbuildworker=1\n";
        test_make_tmpdir(dir, sizeof(dir), "node_conf", "nul_boundary");
        snprintf(path, sizeof(path), "%s/%s", dir, ZCL_NODE_CONFIG_FILENAME);
        memset(body, 'a', MAX_ARG_LEN * 2 - 1);
        body[0] = '#';
        body[1] = '\0';
        memcpy(body + MAX_ARG_LEN * 2 - 1, tail, sizeof(tail) - 1);
        ASSERT(ncf_write_bytes(dir, body,
                              MAX_ARG_LEN * 2 - 1 + sizeof(tail) - 1));
        const char *argv[] = { "z23" };
        ncf_set_argv(argv, 1);
        ASSERT_EQ(ReadConfigFile(path), 1);
        ASSERT_STR_EQ(GetArg("-packagehost", "absent"), "absent");
        ASSERT_STR_EQ(GetArg("-buildworker", ""), "1");
        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_missing_file_changes_nothing(void)
{
    int failures = 0;

    TEST("node-config: a missing file is -1 and mutates no setting") {
        const char *argv[] = { "z23", "-packagehost=argv" };
        ncf_set_argv(argv, 2);
        int before = g_nargs;

        ASSERT_EQ(ReadConfigFile("./test-tmp/definitely-not-here/z23.conf"), -1);
        ASSERT_EQ(ReadConfigFile(""), -1);
        ASSERT_EQ(ReadConfigFile(NULL), -1);

        ASSERT_EQ(g_nargs, before);
        ASSERT_STR_EQ(GetArg("-packagehost", ""), "argv");

        PASS();
    } _test_next:;

    return failures;
}

static int test_path_resolution_creates_nothing(void)
{
    int failures = 0;

    TEST("node-config: resolving the path mints no data directory") {
        char dir[512];
        test_fmt_tmpdir(dir, sizeof(dir), "node_conf", "nocreate");
        /* Not created: GetConfigFilePath names a file in a missing directory
         * without creating it. */
        test_rm_rf(dir);

        char out[1024];
        GetConfigFilePath(dir, out, sizeof(out));

        char want[1024];
        snprintf(want, sizeof(want), "%s/%s", dir, ZCL_NODE_CONFIG_FILENAME);
        ASSERT_STR_EQ(out, want);

        struct stat st;
        ASSERT(stat(dir, &st) != 0);   /* still absent */

        PASS();
    } _test_next:;

    return failures;
}

static int test_path_falls_back_to_the_argument_table(void)
{
    int failures = 0;

    TEST("node-config: an empty datadir argument falls back to -datadir") {
        const char *argv[] = { "z23", "-datadir=/tmp/z23-nonexistent-fixture" };
        ncf_set_argv(argv, 2);

        char out[1024];
        GetConfigFilePath(NULL, out, sizeof(out));
        ASSERT_STR_EQ(out, "/tmp/z23-nonexistent-fixture/" ZCL_NODE_CONFIG_FILENAME);

        GetConfigFilePath("", out, sizeof(out));
        ASSERT_STR_EQ(out, "/tmp/z23-nonexistent-fixture/" ZCL_NODE_CONFIG_FILENAME);

        PASS();
    } _test_next:;

    return failures;
}

static int test_argv_datadir_scans_past_a_subcommand(void)
{
    int failures = 0;

    TEST("node-config: -datadir is found after a non-flag token") {
        char out[512];

        /* ParseParameters stops at the first non-'-' token, so a CLI
         * invocation has an empty table that would name the default
         * datadir instead of the instance named here. */
        const char *cli[] = { "z23", "zcode", "work", "toolchain",
                              "-datadir=/tmp/z23-cli-instance" };
        ASSERT(ArgvDataDir(5, cli, out, sizeof(out)));
        ASSERT_STR_EQ(out, "/tmp/z23-cli-instance");

        /* The table cannot answer it. */
        ncf_set_argv(cli, 5);
        ASSERT_STR_EQ(GetArg("-datadir", "unset"), "unset");

        const char *dbl[] = { "z23", "--datadir=/tmp/z23-double-dash" };
        ASSERT(ArgvDataDir(2, dbl, out, sizeof(out)));
        ASSERT_STR_EQ(out, "/tmp/z23-double-dash");

        PASS();
    } _test_next:;

    return failures;
}

static int test_argv_datadir_last_nonempty_wins(void)
{
    int failures = 0;

    TEST("node-config: the last nonempty -datadir wins across argv") {
        char out[512], first[512], last[512];
        char first_flag[1024], last_flag[1024], double_flag[1024];
        test_fmt_tmpdir(first, sizeof(first), "node_conf", "first");
        test_fmt_tmpdir(last, sizeof(last), "node_conf", "last");
        snprintf(first_flag, sizeof(first_flag), "-datadir=%s", first);
        snprintf(last_flag, sizeof(last_flag), "-datadir=%s", last);
        snprintf(double_flag, sizeof(double_flag), "--datadir=%s", first);

        const char *duplicate[] = { "z23", first_flag, last_flag };
        ncf_set_argv(duplicate, 3);
        ASSERT(ArgvDataDir(3, duplicate, out, sizeof(out)));
        ASSERT_STR_EQ(out, last);
        ASSERT_STR_EQ(out, GetArg("-datadir", "unset"));

        const char *command[] = { "z23", "status", first_flag, last_flag };
        ncf_set_argv(command, 4);
        ASSERT(ArgvDataDir(4, command, out, sizeof(out)));
        ASSERT_STR_EQ(out, last);
        ASSERT_STR_EQ(GetArg("-datadir", "unset"), "unset");

        const char *mixed[] = { "z23", double_flag, NULL, last_flag,
                                "--datadir=" };
        ASSERT(ArgvDataDir(5, mixed, out, sizeof(out)));
        ASSERT_STR_EQ(out, last);

        const char *single[] = { "z23", first_flag };
        ASSERT(ArgvDataDir(2, single, out, sizeof(out)));
        ASSERT_STR_EQ(out, first);

        PASS();
    } _test_next:;

    return failures;
}

static int test_argv_datadir_absent_and_degenerate(void)
{
    int failures = 0;

    TEST("node-config: absent or empty -datadir returns false, empties out") {
        char out[512];

        const char *none[] = { "z23", "-packagehost=1" };
        memset(out, 'x', sizeof(out));
        ASSERT(!ArgvDataDir(2, none, out, sizeof(out)));
        ASSERT_STR_EQ(out, "");

        /* `-datadir=` with nothing after it is not a directory; accepting it
         * would resolve to "/z23.conf". */
        const char *empty[] = { "z23", "-datadir=" };
        ASSERT(!ArgvDataDir(2, empty, out, sizeof(out)));
        ASSERT_STR_EQ(out, "");

        /* argv[0] is never scanned: a "-datadir=" in the binary's path is
         * not a setting. */
        const char *argv0[] = { "/opt/-datadir=/wrong/z23" };
        ASSERT(!ArgvDataDir(1, argv0, out, sizeof(out)));
        ASSERT_STR_EQ(out, "");

        ASSERT(!ArgvDataDir(2, NULL, out, sizeof(out)));

        PASS();
    } _test_next:;

    return failures;
}

/* ── LogAcceptCategory ─────────────────────────────────────────────────
 *
 * Uses the production argument table (seeded via ParseParameters): NULL
 * category is always accepted, a named category is refused without -debug,
 * and -debug, -debug=1 and the exact category name accept while an
 * unrelated category stays refused. One function per TEST (the harness's
 * `goto _test_next`). */
static int test_log_accept_null_category(void)
{
    int failures = 0;
    TEST("log category: NULL (uncategorized) is always accepted") {
        const char *argv[] = { "z23" };
        ncf_set_argv(argv, 1);
        ASSERT(LogAcceptCategory(NULL));
        PASS();
    } _test_next:;
    return failures;
}

static int test_log_accept_named_category(void)
{
    int failures = 0;
    TEST("log category: named category refused without -debug") {
        const char *argv[] = { "z23", "-datadir=/tmp/x" };
        ncf_set_argv(argv, 2);
        ASSERT(!LogAcceptCategory("net"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_log_accept_debug_spellings(void)
{
    int failures = 0;
    TEST("log category: bare -debug and -debug=1 accept every category") {
        const char *bare[] = { "z23", "-debug" };
        ncf_set_argv(bare, 2);
        ASSERT(LogAcceptCategory("net"));
        ASSERT(LogAcceptCategory("mempoolrepl"));
        const char *one[] = { "z23", "-debug=1" };
        ncf_set_argv(one, 2);
        ASSERT(LogAcceptCategory("net"));
        ASSERT(LogAcceptCategory("mempoolrepl"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_log_accept_exact_category(void)
{
    int failures = 0;
    TEST("log category: -debug=<category> is exact, unrelated stays refused") {
        const char *argv[] = { "z23", "-debug=net" };
        ncf_set_argv(argv, 2);
        ASSERT(LogAcceptCategory("net"));
        ASSERT(!LogAcceptCategory("mempoolrepl"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_bool_argument_values(void)
{
    int failures = 0;
    static const struct {
        const char *flag;
        bool valid;
        bool value;
    } cases[] = {
        { "-packagehost=1junk", false, false },
        { "-packagehost=garbage", false, false },
        { "-packagehost=0junk", false, false },
        { "-packagehost=9223372036854775808", false, false },
        { "-packagehost=-9223372036854775809", false, false },
        { "-packagehost=1 ", false, false },
        { "-packagehost=0", true, false },
        { "-packagehost=1", true, true },
        { "-packagehost=-2", true, true },
        { "-packagehost=2147483648", true, true },
        { "-packagehost=9223372036854775807", true, true },
        { "-packagehost=-9223372036854775808", true, true },
        { "-packagehost= +2", true, true },
        { "-packagehost=", true, true },
        { "-packagehost", true, true },
        { "-unrelated=1", false, false },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        TEST(cases[i].flag) {
            const char *argv[] = { "z23", cases[i].flag };
            ncf_set_argv(argv, 2);
            ASSERT_EQ(GetBoolArg("-packagehost", false),
                      cases[i].valid ? cases[i].value : false);
            ASSERT_EQ(GetBoolArg("-packagehost", true),
                      cases[i].valid ? cases[i].value : true);
            PASS();
        } _test_next:;
    }
    return failures;
}

static int test_profile_lookup(void)
{
    int failures = 0;
    TEST("config lookup matches both profile aliases without modifying argv") {
        char dir[512], path[1024];
        test_make_tmpdir(dir, sizeof(dir), "node_conf", "profile_lookup");
        snprintf(path, sizeof(path), "%s/%s", dir, ZCL_NODE_CONFIG_FILENAME);
        const char *argv[] = { "z23", "-testnet=1" };
        ncf_set_argv(argv, 2);
        ASSERT(ncf_write_conf(dir, "# testnet-profile=ignored\n--testnet-profile = profile\n"));
        ASSERT_EQ(ConfigFileHasKey(path, "-testnet-profile"), 1);
        ASSERT_EQ(ConfigFileHasKey(path, "-regtest"), 0);
        ASSERT_STR_EQ(GetArg("-testnet", ""), "1");
        ASSERT(GetArg("-testnet-profile", NULL) == NULL);
        ASSERT(ncf_write_conf(dir, "testnet-profile-other=ignored\n-testnet-profile=value\n"));
        ASSERT_EQ(ConfigFileHasKey(path, "-testnet-profile"), 1);
        test_cleanup_tmpdir(dir);
        ASSERT_EQ(ConfigFileHasKey(path, "-testnet-profile"), 0);
        PASS();
    } _test_next:;
    return failures;
}


int test_node_config_file(void)
{
    int failures = 0;

    printf("\n=== node config file (<datadir>/%s) ===\n",
           ZCL_NODE_CONFIG_FILENAME);

    failures += test_profile_lookup();
    failures += test_command_line_always_wins();
    failures += test_file_cannot_move_the_datadir();
    failures += test_line_shapes();
    failures += test_comment_continuation();
    failures += test_oversized_value();
    failures += test_spanning_value();
    failures += test_representable_value();
    failures += test_maximum_record();
    failures += test_nul_record();
    failures += test_nul_boundary();
    failures += test_missing_file_changes_nothing();
    failures += test_path_resolution_creates_nothing();
    failures += test_path_falls_back_to_the_argument_table();
    failures += test_argv_datadir_scans_past_a_subcommand();
    failures += test_argv_datadir_last_nonempty_wins();
    failures += test_argv_datadir_absent_and_degenerate();
    failures += test_log_accept_null_category();
    failures += test_log_accept_named_category();
    failures += test_log_accept_debug_spellings();
    failures += test_log_accept_exact_category();
    failures += test_bool_argument_values();

    /* Restore the table so later groups do not inherit a fixture's -datadir. */
    const char *reset[] = { "z23" };
    ncf_set_argv(reset, 1);

    return failures;
}
