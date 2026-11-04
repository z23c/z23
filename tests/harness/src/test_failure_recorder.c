/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Self-test of the failure flight recorder (test_note / test_note_bytes):
 * a failing ASSERT prints the noted evidence once, framed; a passing TEST
 * prints none; the record is capped with its head and its tail kept. */

#include "test/test_core.h"

#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/wait.h>

#define FR_OUT_CAP 8192

/* The TEST bodies the forked child runs, with stdout sent to a file. */
static int fr_child_failing(void)
{
    int failures = 0;
    test_note("STALE-MUST-NOT-APPEAR"); /* TEST must clear it */
    TEST("recorder: failing") {
        test_note("exit=%d signal=%d", 7, 0);
        test_note_bytes("body", "{\"ok\":false,\"why\":\"deadline\"}", 29);
        ASSERT(1 == 2);
        PASS();
    } _test_next:;
    return failures;
}

static int fr_child_passing(void)
{
    int failures = 0;
    TEST("recorder: passing") {
        test_note("exit=%d", 0);
        ASSERT(1 == 1);
        PASS();
    } _test_next:;
    return failures;
}

static int fr_child_flood(void)
{
    int failures = 0;
    TEST("recorder: flood") {
        test_note("FIRST-NOTE");
        for (int i = 0; i < 400; i++) test_note("filler line %04d", i);
        test_note("LAST-NOTE");
        ASSERT_EQ(3, 4);
        PASS();
    } _test_next:;
    return failures;
}

static bool fr_run(int (*body)(void), char *out, size_t cap, int *failures)
{
    char path[PATH_MAX];
    test_fmt_tmpdir(path, sizeof(path), "zcl_failure_recorder", "out.txt");
    (void)test_ensure_tmproot();
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0 || dup2(fd, STDOUT_FILENO) < 0) _exit(120);
        int n = body();
        fflush(stdout);
        _exit(n);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st)) return false;
    *failures = WEXITSTATUS(st);
    FILE *f = fopen(path, "r");
    size_t got = f ? fread(out, 1, cap - 1, f) : 0;
    if (f) fclose(f);
    out[got] = '\0';
    (void)unlink(path);
    return f != NULL;
}

static int fr_count(const char *hay, const char *needle)
{
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle))
        n++;
    return n;
}

static int fr_test_fail_prints_evidence(void)
{
    int failures = 0;
    TEST("failure recorder: a failing ASSERT prints the noted evidence once") {
        char out[FR_OUT_CAP];
        int child = 0;
        ASSERT(fr_run(fr_child_failing, out, sizeof(out), &child));
        ASSERT(child == 1);
        ASSERT(strstr(out, "FAIL at") != NULL);
        ASSERT(fr_count(out, "--- evidence ") == 1);
        ASSERT(fr_count(out, "--- end evidence ---") == 1);
        ASSERT(strstr(out, "test_failure_recorder.c:") != NULL);
        ASSERT(strstr(out, "exit=7 signal=0") != NULL);
        ASSERT(strstr(out, "\"why\":\"deadline\"") != NULL);
        ASSERT(strstr(out, "STALE-MUST-NOT-APPEAR") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int fr_test_pass_prints_nothing(void)
{
    int failures = 0;
    TEST("failure recorder: a passing TEST prints no evidence") {
        char out[FR_OUT_CAP];
        int child = -1;
        ASSERT(fr_run(fr_child_passing, out, sizeof(out), &child));
        ASSERT(child == 0);
        ASSERT(strstr(out, "evidence") == NULL);
        ASSERT(strstr(out, "exit=0") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int fr_test_cap_keeps_head_and_tail(void)
{
    int failures = 0;
    TEST("failure recorder: the cap holds, head and tail kept") {
        char out[FR_OUT_CAP];
        int child = 0;
        ASSERT(fr_run(fr_child_flood, out, sizeof(out), &child));
        const char *begin = strstr(out, "--- evidence ");
        const char *end = strstr(out, "--- end evidence ---");
        ASSERT(begin != NULL && end != NULL && end > begin);
        ASSERT((size_t)(end - begin) <= TEST_EVIDENCE_CAP + 256);
        ASSERT(strstr(begin, "FIRST-NOTE") != NULL);
        ASSERT(strstr(begin, "LAST-NOTE") != NULL);
        ASSERT(strstr(begin, "filler line 0399") != NULL);
        ASSERT(strstr(begin, "filler line 0200") == NULL);
        ASSERT(strstr(begin, "bytes elided") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int fr_test_bytes_escape_and_cut(void)
{
    int failures = 0;
    TEST("failure recorder: test_note_bytes escapes binary and cuts long input") {
        static char big[6000];
        memset(big, 'x', sizeof(big));
        memcpy(big, "HEADMARK", 8);
        memcpy(big + sizeof(big) - 8, "TAILMARK", 8);
        test_evidence_reset();
        test_note_bytes("bin", "a\x01z", 3);
        test_note_bytes("big", big, sizeof(big));
        char out[TEST_EVIDENCE_CAP + 512];
        size_t n = test_evidence_render(out, sizeof(out), "f.c", 9);
        test_evidence_reset();
        ASSERT(n == strlen(out));
        ASSERT(strstr(out, "a\\x01z") != NULL);
        ASSERT(strstr(out, "HEADMARK") != NULL);
        ASSERT(strstr(out, "TAILMARK") != NULL);
        ASSERT(strstr(out, "--- evidence f.c:9 ---") == out);
        PASS();
    } _test_next:;
    return failures;
}

static int fr_test_long_file(void)
{
    int failures = 0;
    TEST("failure recorder: long file names stay bounded") {
        char file[512], out[TEST_EVIDENCE_CAP + 512];
        memset(file, 'f', sizeof(file) - 1);
        file[sizeof(file) - 1] = '\0';
        test_note("long-file-note");
        size_t n = test_evidence_render(out, sizeof(out), file, 9);
        test_evidence_reset();
        ASSERT(n == strlen(out));
        ASSERT(strstr(out, "\nlong-file-note\n") != NULL);
        ASSERT(strstr(out, "--- end evidence ---\n") != NULL);
        PASS();
    } _test_next:;
    return failures;
}
#endif

int test_failure_recorder(void);
int test_failure_recorder(void)
{
    int failures = 0;
#if defined(_WIN32)
    printf("failure recorder: SKIP (Windows): the fixture forks a child\n");
#else
    failures += fr_test_fail_prints_evidence();
    failures += fr_test_pass_prints_nothing();
    failures += fr_test_cap_keeps_head_and_tail();
    failures += fr_test_bytes_escape_and_cut();
    failures += fr_test_long_file();
    printf("Failure recorder: %d failures\n", failures);
#endif
    return failures;
}
