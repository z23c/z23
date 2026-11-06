/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-sqlite-step-row --selftest. Plants fixture sources
 * under a private sandbox root (never the real tree), runs the real scan and
 * the real baseline comparison over it, and grades the verdicts:
 *   - every counted shape is counted (direct, reversed, the READONLY alias,
 *     an AR_STEP_ROW use, a comparison split across lines);
 *   - the legal shapes are not (ar_step_checked, a captured rc, the macro's
 *     own #define, comments, string literals, a digit separator);
 *   - an exact baseline passes; a grown file, a new file and a stale
 *     (shrunk) row each fail; a file under tests/ or vendor/ is not scanned.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_sqlite_step_row_priv.h"

static const char k_ssr_st[] = "check-sqlite-step-row";

/* Five counted sites. */
static const char k_ssr_bad[] =
    "int a(sqlite3_stmt *st) { return sqlite3_step(st) == SQLITE_ROW; }\n"
    "int b(sqlite3_stmt *st) { return SQLITE_ROW == sqlite3_step(st); }\n"
    "int c(sqlite3_stmt *st) { return AR_STEP_ROW_READONLY(st) == SQLITE_ROW; }\n"
    "int d(sqlite3_stmt *st) { return AR_STEP_ROW(st); }\n"
    "int e(sqlite3_stmt *st) {\n    return sqlite3_step(f(st, (1)))\n"
    "        ==\n        SQLITE_ROW;\n}\n";

/* Zero counted sites. */
static const char k_ssr_good[] =
    "#define AR_STEP_ROW(stmt) (x)\n"
    "/* sqlite3_step(st) == SQLITE_ROW in a comment */\n"
    "// sqlite3_step(st) == SQLITE_ROW in a line comment\n"
    "static const char *s = \"sqlite3_step(st) == SQLITE_ROW\";\n"
    "static const long big = 1'000'000;\n"
    "int g(sqlite3_stmt *st) { int rc = sqlite3_step(st);\n"
    "    return rc == SQLITE_ROW ? 1 : rc == SQLITE_DONE ? 0 : -1; }\n"
    "int h(sqlite3_stmt *st) {\n"
    "    return ar_step_checked(st, \"x\", NULL) == ZCL_STEP_ROW; }\n"
    "int my_sqlite3_step(int x);\n"
    "int i(void) { return my_sqlite3_step(1) == SQLITE_ROW; }\n";

static int ssr_st_fail(const char *msg, int got)
{
    fprintf(stderr, "%s: SELFTEST FAILED — %s (got %d)\n", k_ssr_st, msg, got);
    return 2;
}

static int ssr_st_count(const char *text)
{
    static char buf[4096];
    size_t n = strlen(text);
    if (n >= sizeof buf)
        return -1;
    memcpy(buf, text, n + 1);
    ssr_blank(buf, n);
    return ssr_count(buf);
}

static int ssr_st_plant(const char *root, const char *rel, const char *text)
{
    char path[4096], dir[4096];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return 2;
    snprintf(dir, sizeof dir, "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash)
        *slash = '\0';
    int rc = csr_mkdirs(dir);
    return rc ? rc : csr_write(path, text);
}

/* Run the real scan + report over root against a baseline text. */
static int ssr_st_verdict(const char *root, const char *baseline)
{
    static struct ssr_set live, base;
    char bpath[4096];
    int files = 0;
    if (ovf(snprintf(bpath, sizeof bpath, "%s/baseline.txt", root),
            sizeof bpath))
        return 2;
    int rc = csr_write(bpath, baseline);
    if (rc == 0)
        rc = ssr_collect(root, &live, &files);
    if (rc == 0)
        rc = ssr_load_baseline(&base, bpath);
    if (rc)
        return rc + 100;
    FILE *sink = tmpfile();
    if (!sink)
        return die("z23-lint: tmpfile failed\n", "");
    rc = ssr_report(&live, &base, bpath, files, sink);
    fclose(sink);
    return rc;
}

static int ssr_st_counts(void)
{
    int n = ssr_st_count(k_ssr_bad);
    if (n != 5)
        return ssr_st_fail("the five counted shapes were not all counted", n);
    n = ssr_st_count(k_ssr_good);
    if (n != 0)
        return ssr_st_fail("a legal shape was counted", n);
    return 0;
}

struct ssr_st_case { const char *baseline; int want; const char *msg; };

static int ssr_st_ratchet(const char *root)
{
    static const struct ssr_st_case cases[] = {
        { "engine/x/src/bad.c 5\n", 0, "an exact baseline did not pass" },
        { "engine/x/src/bad.c 4\n", 1, "a grown file did not fail" },
        { "", 1, "a new unbaselined file did not fail" },
        { "engine/x/src/bad.c 6\n", 1, "a stale (shrunk) row did not fail" },
        { "engine/x/src/bad.c 5\nengine/x/src/gone.c 1\n", 1,
          "a row for a file with no sites did not fail" },
        { "engine/x/src/bad.c\n", 102, "a malformed row was not fatal" },
    };
    int rc = ssr_st_plant(root, "engine/x/src/bad.c", k_ssr_bad);
    if (rc == 0)
        rc = ssr_st_plant(root, "engine/x/src/good.c", k_ssr_good);
    if (rc == 0)
        rc = ssr_st_plant(root, "engine/x/tests/t.c", k_ssr_bad);
    if (rc == 0)
        rc = ssr_st_plant(root, "vendor/v.c", k_ssr_bad);
    if (rc == 0)
        rc = ssr_st_plant(root, "engine/vendor/v.c", k_ssr_bad);
    for (size_t i = 0; rc == 0 && i < sizeof cases / sizeof cases[0]; i++) {
        int got = ssr_st_verdict(root, cases[i].baseline);
        if (got != cases[i].want)
            rc = ssr_st_fail(cases[i].msg, got);
    }
    return rc;
}

int check_sqlite_step_row_selftest(void)
{
    char root[4096];
    int rc = ssr_st_counts();
    if (rc)
        return rc;
    rc = lint_mkdtemp(root, sizeof root, "ssr");
    if (rc)
        return rc;
    rc = ssr_st_ratchet(root);
    int clean = rap_rm_rf(root);
    if (rc)
        return rc;
    if (clean)
        return clean;
    printf("[%s] SELFTEST PASS (five shapes counted; checked, captured, "
           "#define, comment, literal and digit-separator forms not; exact "
           "baseline passes; grown, new, stale and dead rows fail; a "
           "malformed row is fatal; tests/ and vendor/ are not scanned)\n",
           k_ssr_st);
    return 0;
}
