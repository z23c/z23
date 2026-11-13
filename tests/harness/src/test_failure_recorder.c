/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Self-test of the failure flight recorder (test_note / test_note_bytes):
 * a failing ASSERT prints the noted evidence once, framed; a passing TEST
 * prints none; the record is capped with its head and its tail kept. */

#include "test/test_core.h"
#include "test/host_tool_capture.h"

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

static int fr_child_capture(void)
{
    int failures = 0;
    TEST("recorder: child output") {
        const char *argv[] = {"/bin/sh", "-c",
            "printf stdout-prefix; printf stderr-prefix >&2; "
            "i=0; while [ $i -lt 300 ]; do printf x; printf y >&2; i=$((i+1)); done; "
            "printf stdout-tail; printf stderr-tail >&2; exit 7", NULL};
        char out[32];
        int rc = test_host_tool_capture(argv, out, sizeof(out), 5000);
        ASSERT(rc == 7 && strncmp(out, "stdout-prefix", 13) == 0);
        ASSERT(1 == 2);
        PASS();
    } _test_next:;
    return failures;
}

/* Prefix is the captured reply. Padding pushes it out of the 512-byte
 * stdout tail, so the tail is the child's own output and the reply is a
 * separate observation. */
static int fr_capture_observed(bool fail)
{
    int failures = 0;
    TEST(fail ? "recorder: observed failure" : "recorder: observed pass") {
        const char *argv[] = {
            "/bin/sh", "-c",
            "printf RESP-BODY-MARKER; "
            "dd if=/dev/zero bs=3000 count=1 2>/dev/null | tr '\\0' p; "
            "printf CHILD-OUT-TAIL; exit 13",
            NULL};
        char out[64];
        int rc = test_host_tool_capture(argv, out, sizeof(out), 5000);
        if (fail) ASSERT(1 == 2);
        ASSERT(rc == 13);
        PASS();
    } _test_next:;
    return failures;
}

static int fr_child_observed_fail(void)
{
    return fr_capture_observed(true);
}

static int fr_child_observed_pass(void)
{
    return fr_capture_observed(false);
}

static int fr_child_bare(void)
{
    int failures = 0;
    TEST("recorder: bare failure") {
        ASSERT(1 == 2);
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

static int fr_test_child_tails(void)
{
    int failures = 0;
    TEST("failure recorder: child stdout and stderr tails survive prefix truncation") {
        char out[FR_OUT_CAP];
        int child = 0;
        ASSERT(fr_run(fr_child_capture, out, sizeof(out), &child));
        ASSERT(child == 1);
        ASSERT(strstr(out, "exit=7") != NULL);
        ASSERT(strstr(out, "stdout-tail") != NULL);
        ASSERT(strstr(out, "stderr-tail") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static bool fr_frame_has(const char *out, const char *marker)
{
    const char *begin = strstr(out, "--- evidence ");
    const char *end = strstr(out, "--- end evidence ---");
    const char *hit = begin ? strstr(begin, marker) : NULL;
    return begin && end && hit && hit < end;
}

static int fr_test_observed_failure_prints_all_three(void)
{
    int failures = 0;
    TEST("failure recorder: a failing assertion prints exit, child output, and response body") {
        char out[FR_OUT_CAP];
        int child = 0;
        const char *begin;
        const char *end;
        ASSERT(fr_run(fr_child_observed_fail, out, sizeof(out), &child));
        ASSERT(child == 1);
        ASSERT(strstr(out, "FAIL at") != NULL);
        ASSERT(fr_frame_has(out, "exit=13"));
        ASSERT(fr_frame_has(out, "CHILD-OUT-TAIL"));
        ASSERT(fr_frame_has(out, "RESP-BODY-MARKER"));
        ASSERT(fr_frame_has(out, "response body"));
        begin = strstr(out, "--- evidence ");
        end = strstr(out, "--- end evidence ---");
        ASSERT(begin != NULL && end != NULL && end > begin);
        ASSERT((size_t)(end - begin) <= TEST_EVIDENCE_CAP + 256);
        PASS();
    } _test_next:;
    return failures;
}

static int fr_test_observed_pass_prints_nothing(void)
{
    int failures = 0;
    TEST("failure recorder: a pass that recorded exit, output, and body prints none") {
        char out[FR_OUT_CAP];
        int child = -1;
        ASSERT(fr_run(fr_child_observed_pass, out, sizeof(out), &child));
        ASSERT(child == 0);
        ASSERT(strstr(out, "--- evidence ") == NULL);
        ASSERT(strstr(out, "RESP-BODY-MARKER") == NULL);
        ASSERT(strstr(out, "CHILD-OUT-TAIL") == NULL);
        ASSERT(strstr(out, "exit=13") == NULL);
        ASSERT(strstr(out, "response body") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int fr_test_bare_failure_invents_nothing(void)
{
    int failures = 0;
    TEST("failure recorder: a failure with no observation invents none") {
        char out[FR_OUT_CAP];
        int child = 0;
        ASSERT(fr_run(fr_child_bare, out, sizeof(out), &child));
        ASSERT(child == 1);
        ASSERT(strstr(out, "FAIL at") != NULL);
        ASSERT(strstr(out, "--- evidence ") == NULL);
        ASSERT(strstr(out, "RESP-BODY-MARKER") == NULL);
        ASSERT(strstr(out, "CHILD-OUT-TAIL") == NULL);
        ASSERT(strstr(out, "exit=") == NULL);
        ASSERT(strstr(out, "response body") == NULL);
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
    failures += fr_test_child_tails();
    failures += fr_test_observed_failure_prints_all_three();
    failures += fr_test_observed_pass_prints_nothing();
    failures += fr_test_bare_failure_invents_nothing();
    failures += fr_test_bytes_escape_and_cut();
    failures += fr_test_long_file();
    printf("Failure recorder: %d failures\n", failures);
#endif
    return failures;
}
