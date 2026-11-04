/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_inspect_html — regressions for the build-check helper
 * (tools/inspect_html.c -> build/bin/inspect_html).
 *
 * Degenerate input contract: an empty --count pattern counts zero
 * matches. strstr(p, "") returns p, so the old advance-by-nlen loop made
 * no progress and spun forever (until the int counter wrapped, which is
 * signed-overflow UB) -- a build script can produce an empty pattern from
 * an unset variable and hang its lane. These cases pin the clean exit
 * and the ordinary counting behavior the helper exists for. */

#include "test/test_core.h"
#include "util/spawn.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define INSPECT_HTML_BIN "build/bin/inspect_html"

/* Write the document under a private tmpdir and invoke the CLI directly. */
static int inspect_html_run_bytes(const char *doc, size_t len,
                                 const char *check, const char *pattern,
                                 char *buf, size_t cap)
{
    char dir[4096], path[4608];
    test_make_tmpdir(dir, sizeof(dir), "inspect_html", "run");
    int n = snprintf(path, sizeof(path), "%s/in.html", dir);
    if (n <= 0 || (size_t)n >= sizeof(path)) return -1;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    bool written = fwrite(doc, 1, len, f) == len;
    if (fclose(f) != 0) written = false;
    if (!written) { (void)test_rm_rf_recursive(dir); return -1; }
    const char *argv[] = { INSPECT_HTML_BIN, path, check, pattern, NULL };
    int rc = zcl_spawn_capture(argv, buf, cap, 5000);
    (void)test_rm_rf_recursive(dir);
    return rc;
}

static int inspect_html_run(const char *doc, const char *check, const char *pattern,
                            char *buf, size_t cap)
{
    return inspect_html_run_bytes(doc, strlen(doc), check, pattern, buf, cap);
}

static int test_inspect_html_count(void)
{
    int failures = 0;
    char buf[256] = {0};
    TEST("inspect_html: empty --count pattern counts zero, not forever") {
        ASSERT(inspect_html_run("<div><p>x</p></div>", "--count", "", buf,
                                sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "0\n") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_inspect_html_count_matches(void)
{
    int failures = 0;
    char buf[256] = {0};
    TEST("inspect_html: ordinary counting still works") {
        ASSERT(inspect_html_run("<div><div></div></div>", "--count", "<div",
                                buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "2\n") == 0);
        ASSERT(inspect_html_run("<p>hello</p>", "--has", "hello", buf,
                                sizeof(buf)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_inspect_html_read_errors(void)
{
    int failures = 0;
    char dir[4096], buf[256] = {0};
    test_make_tmpdir(dir, sizeof(dir), "inspect_html", "directory");
    const char *argv[] = { INSPECT_HTML_BIN, dir, "--no", "forbidden", NULL };
    int rc = zcl_spawn_capture(argv, buf, sizeof(buf), 5000);
    (void)test_rm_rf_recursive(dir);
    TEST("inspect_html: directory read errors cannot pass a negative check") {
        ASSERT(rc == 2);
        PASS();
    } _test_next:;
    return failures;
}

static int test_inspect_html_empty_document(void)
{
    int failures = 0;
    char buf[256] = {0};
    TEST("inspect_html: an empty render still fails validation") {
        ASSERT(inspect_html_run("", "--count", "forbidden",
                                buf, sizeof(buf)) == 2);
        ASSERT(inspect_html_run("", "--has", "forbidden", buf, sizeof(buf)) == 2);
        ASSERT(inspect_html_run("", "--no", "forbidden", buf, sizeof(buf)) == 2);
        ASSERT(inspect_html_run("", "--unresolved", NULL, buf, sizeof(buf)) == 2);
        PASS();
    } _test_next:;
    return failures;
}

static int test_inspect_html_embedded_nul(void)
{
    int failures = 0;
    char buf[256] = {0};
    const char doc[] = "<p>safe</p>\0{{forbidden}}";
    TEST("inspect_html: embedded NUL cannot hide an unresolved template") {
        ASSERT(inspect_html_run_bytes(doc, sizeof(doc) - 1, "--unresolved", NULL,
                                      buf, sizeof(buf)) == 2);
        ASSERT(inspect_html_run_bytes(doc, sizeof(doc) - 1, "--no", "forbidden",
                                      buf, sizeof(buf)) == 2);
        PASS();
    } _test_next:;
    return failures;
}

int test_inspect_html(void)
{
    int failures = 0;
    struct stat st;
    if (stat(INSPECT_HTML_BIN, &st) != 0 || (st.st_mode & S_IXUSR) == 0) {
        printf("inspect_html: build/bin/inspect_html missing (run: "
               "make tools/inspect_html) — skipped\n");
        return 0;
    }
    failures += test_inspect_html_count();
    failures += test_inspect_html_count_matches();
    failures += test_inspect_html_read_errors();
    failures += test_inspect_html_empty_document();
    failures += test_inspect_html_embedded_nul();
    return failures;
}
