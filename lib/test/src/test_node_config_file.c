/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Contract for the node's own config file: ReadConfigFile(),
 * GetConfigFilePath() and ArgvDataDir() in lib/util/src/util.c.
 *
 * The reason this file exists rather than a couple of smoke assertions is
 * that a config reader is a SETTINGS-PRECEDENCE machine, and every way it
 * can be wrong is silent. A file that overrode argv would let a stale
 * on-disk line quietly beat the service unit's ExecStart on the next boot,
 * and nothing would print. A path resolver that fell back to the default
 * datadir would read the OPERATOR'S LIVE NODE's config while the caller
 * had explicitly named a throwaway instance. Neither shows up as a crash.
 *
 * So the cases below pin the four properties that make the reader safe to
 * put in front of main():
 *
 *   1. argv wins, always. A key already in the table is left byte-identical.
 *   2. -datadir and -conf inside the file are ignored — the file's own path
 *      is derived FROM the datadir, so a datadir line could relocate the
 *      directory the file was just read out of.
 *   3. resolving a path creates nothing. `z23 help` on a fresh box must not
 *      leave a data directory behind as a side effect of looking for config.
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

/* Write `body` to <dir>/z23.conf. Returns false if the file could not be
 * created, so a filesystem problem fails the case instead of silently
 * testing the missing-file path. */
static bool ncf_write_conf(const char *dir, const char *body)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, ZCL_NODE_CONFIG_FILENAME);
    FILE *f = fopen(path, "we");
    if (!f)
        return false;
    fputs(body, f);
    fclose(f);
    return true;
}

/* Reset the argument table through the production entry point rather than
 * by poking g_nargs: ParseParameters() is what main() calls, so a change to
 * how it seeds the table is a change these tests should see. */
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

        /* The leading '-' is optional so a line copy-pasted straight out of
         * a unit's ExecStart works unchanged; both spellings must land on
         * the same key. */
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
        /* `key = value` must not become a flag literally named "buildworker ". */
        ASSERT_STR_EQ(GetArg("-buildworker", ""), "spaced");
        /* A bare flag is true, matching ParseParameters' present-but-empty
         * rule, which GetBoolArg reads as true. */
        ASSERT_STR_EQ(GetArg("-listen", "absent"), "");
        ASSERT(GetBoolArg("-listen", false));
        ASSERT_STR_EQ(GetArg("-note", ""), "keep");

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
        /* Deliberately NOT created: GetConfigFilePath must be willing to
         * name a file inside a directory that does not exist, and must not
         * bring the directory into being as a side effect. */
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

        /* THE case this function exists for. ParseParameters stops at the
         * first token that does not begin with '-', so for a CLI invocation
         * the argument table is empty and would name the DEFAULT datadir —
         * the operator's live node — instead of the instance named here. */
        const char *cli[] = { "z23", "zcode", "work", "toolchain",
                              "-datadir=/tmp/z23-cli-instance" };
        ASSERT(ArgvDataDir(5, cli, out, sizeof(out)));
        ASSERT_STR_EQ(out, "/tmp/z23-cli-instance");

        /* The table genuinely cannot answer it: proven, not assumed. */
        ncf_set_argv(cli, 5);
        ASSERT_STR_EQ(GetArg("-datadir", "unset"), "unset");

        const char *dbl[] = { "z23", "--datadir=/tmp/z23-double-dash" };
        ASSERT(ArgvDataDir(2, dbl, out, sizeof(out)));
        ASSERT_STR_EQ(out, "/tmp/z23-double-dash");

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

        /* `-datadir=` with nothing after it is not a directory. Accepting it
         * would resolve the config path to "/z23.conf". */
        const char *empty[] = { "z23", "-datadir=" };
        ASSERT(!ArgvDataDir(2, empty, out, sizeof(out)));
        ASSERT_STR_EQ(out, "");

        /* argv[0] is never scanned: a binary that happens to live at a path
         * containing "-datadir=" must not be read as a setting. */
        const char *argv0[] = { "/opt/-datadir=/wrong/z23" };
        ASSERT(!ArgvDataDir(1, argv0, out, sizeof(out)));
        ASSERT_STR_EQ(out, "");

        ASSERT(!ArgvDataDir(2, NULL, out, sizeof(out)));

        PASS();
    } _test_next:;

    return failures;
}

int test_node_config_file(void)
{
    int failures = 0;

    printf("\n=== node config file (<datadir>/%s) ===\n",
           ZCL_NODE_CONFIG_FILENAME);

    failures += test_command_line_always_wins();
    failures += test_file_cannot_move_the_datadir();
    failures += test_line_shapes();
    failures += test_missing_file_changes_nothing();
    failures += test_path_resolution_creates_nothing();
    failures += test_path_falls_back_to_the_argument_table();
    failures += test_argv_datadir_scans_past_a_subcommand();
    failures += test_argv_datadir_absent_and_degenerate();

    /* Leave the table as the suite found it: these cases rewrote it several
     * times and a later group must not inherit a fixture's -datadir. */
    const char *reset[] = { "z23" };
    ncf_set_argv(reset, 1);

    return failures;
}
