/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/refold_rate_verdict.h"
#include "util/safe_alloc.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

static int report(const char *name, bool ok)
{
    printf("refold_rate_verdict: %s... %s\n", name, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static void sample(struct zcl_refold_rate_sample *out, int64_t wall_s,
                   int64_t mono_ns, int64_t hstar)
{
    *out = (struct zcl_refold_rate_sample){
        .monotonic_ns = mono_ns,
        .hstar = hstar,
        .wall_epoch_s = wall_s
    };
}

static int expect_verdict(const char *name,
                          const struct zcl_refold_rate_sample *samples,
                          size_t count, enum zcl_refold_rate_verdict expected)
{
    struct zcl_refold_rate_result result;
    const enum zcl_refold_rate_verdict got =
        zcl_refold_rate_classify(samples, count, &result);
    const bool passed = got == expected && result.verdict == got;
    printf("refold_rate_verdict: %-28s -> %s (samples=%zu intervals=%zu) %s\n",
           name, zcl_refold_rate_verdict_name(got), result.samples,
           result.intervals, passed ? "OK" : "FAIL");
    return passed ? 0 : 1;
}

static int fixture_constant_fast(void)
{
    struct zcl_refold_rate_sample s[31];
    for (size_t i = 0; i < 31; i++)
        sample(&s[i], 1000 + (int64_t)i * 45,
               (int64_t)i * 45000000000LL, 3056758 + (int64_t)i * 5000);
    return expect_verdict("constant-fast-climb", s, 31, ZCL_REFOLD_RATE_FLAT);
}

static int fixture_decaying(void)
{
    struct zcl_refold_rate_sample s[31];
    int64_t h = 3056758;
    int64_t delta = 9000;
    for (size_t i = 0; i < 31; i++) {
        sample(&s[i], 1000 + (int64_t)i * 45,
               (int64_t)i * 45000000000LL, h);
        h += delta;
        if (delta > 400)
            delta -= 300;
        else
            delta = 300;
    }
    return expect_verdict("decaying-climb", s, 31, ZCL_REFOLD_RATE_DECAYING);
}

static int fixture_below_floor(void)
{
    struct zcl_refold_rate_sample s[31];
    for (size_t i = 0; i < 31; i++)
        sample(&s[i], 1000 + (int64_t)i * 45,
               (int64_t)i * 45000000000LL, 3056758 + (int64_t)i * 2000);
    return expect_verdict("flat-below-min-rate", s, 31,
                          ZCL_REFOLD_RATE_DECAYING);
}

static int fixture_pinned(void)
{
    struct zcl_refold_rate_sample s[11];
    for (size_t i = 0; i < 11; i++)
        sample(&s[i], 1000 + (int64_t)i * 45,
               (int64_t)i * 45000000000LL, 3056758);
    return expect_verdict("pinned-no-climb", s, 11, ZCL_REFOLD_RATE_NO_CLIMB);
}

static int fixture_single_sample(void)
{
    struct zcl_refold_rate_sample s;
    sample(&s, 1000, 0, 3056758);
    return expect_verdict("single-sample", &s, 1, ZCL_REFOLD_RATE_NO_CLIMB);
}

static int fixture_install_dip(void)
{
    struct zcl_refold_rate_sample s[23];
    sample(&s[0], 1000, 0, 3176000);
    sample(&s[1], 1045, 45000000000LL, 3056758);
    for (size_t i = 2; i < 23; i++)
        sample(&s[i], 1000 + (int64_t)i * 45,
               (int64_t)i * 45000000000LL,
               3056758 + (int64_t)(i - 2) * 6000);
    return expect_verdict("install-dip-then-flat", s, 23,
                          ZCL_REFOLD_RATE_FLAT);
}

static int fixture_stall(void)
{
    struct zcl_refold_rate_sample s[37];
    for (size_t i = 0; i < 21; i++)
        sample(&s[i], 1000 + (int64_t)i * 45,
               (int64_t)i * 45000000000LL, 3056758 + (int64_t)i * 6000);
    for (size_t i = 21; i < 37; i++)
        sample(&s[i], 1000 + (int64_t)i * 45,
               (int64_t)i * 45000000000LL, 3056758 + 21 * 6000);
    return expect_verdict("climb-then-stall", s, 37,
                          ZCL_REFOLD_RATE_DECAYING);
}

static int fixture_wall_clock_step(void)
{
    static const int64_t wall_s[7] = {1000, 1045, 1000, 1045, 1000, 1045, 1000};
    struct zcl_refold_rate_sample s[7];
    for (size_t i = 0; i < 7; i++)
        sample(&s[i], wall_s[i], (int64_t)i * 45000000000LL,
               3056758 + (int64_t)i * 2250);
    return expect_verdict("wall-clock-step", s, 7,
                          ZCL_REFOLD_RATE_DECAYING);
}

static int rejects_nonpositive_interval(void)
{
    struct zcl_refold_rate_sample s[3];
    struct zcl_refold_rate_result result;
    sample(&s[0], 1000, 100, 100);
    sample(&s[1], 1045, 100, 200);
    sample(&s[2], 1090, 200, 300);
    const bool zero_refused =
        zcl_refold_rate_classify(s, 3, &result) == ZCL_REFOLD_RATE_INVALID_INPUT;
    sample(&s[1], 1045, 99, 200);
    const bool backwards_refused =
        zcl_refold_rate_classify(s, 3, &result) == ZCL_REFOLD_RATE_INVALID_INPUT;
    printf("refold_rate_verdict: nonpositive-interval-refusal... %s\n",
           zero_refused && backwards_refused ? "OK" : "FAIL");
    return zero_refused && backwards_refused ? 0 : 1;
}

#define RR_TMP_MAX 512

static char g_dir[RR_TMP_MAX];

static bool write_file(const char *name, const char *data, size_t length)
{
    char path[RR_TMP_MAX + 32];
    (void)snprintf(path, sizeof(path), "%s/%s", g_dir, name);
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    const bool ok = fwrite(data, 1, length, f) == length;
    return fclose(f) == 0 && ok;
}

/* Drives the production argv path in a child so stdout is captured. */
static int run_cli(const char *name, char *out, size_t cap)
{
    char path[RR_TMP_MAX + 32], capture[RR_TMP_MAX + 32], flag[RR_TMP_MAX + 48];
    (void)snprintf(path, sizeof(path), "%s/%s", g_dir, name);
    (void)snprintf(capture, sizeof(capture), "%s/out.json", g_dir);
    (void)snprintf(flag, sizeof(flag), "--samples=%s", path);
    const char *args[] = {"debug", "refold", "verdict", flag};
    const pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        const int fd = open(capture, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0 || dup2(fd, STDOUT_FILENO) < 0)
            _exit(125);
        const int rc = zcl_native_command_main("ops", args, 4, g_dir, 0,
                                               CHAIN_MAIN, false);
        (void)fflush(stdout);
        _exit(rc & 0x7f);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
        return -1;
    FILE *f = fopen(capture, "rb");
    const size_t n = f ? fread(out, 1, cap - 1, f) : 0;
    out[n] = '\0';
    if (f)
        (void)fclose(f);
    return WEXITSTATUS(status);
}

/* Writes `count` records climbing `slope` blocks per 45 s, drives the real
 * argv path and checks verdict, reply status and process exit code. */
static int cli_case(const char *name, int count, int slope, int want_rc,
                    const char *want_status, const char *want_verdict)
{
    char data[8192], out[8192], status[48], verdict[48];
    size_t used = 0;
    for (int i = 0; i < count; i++)
        used += (size_t)snprintf(data + used, sizeof(data) - used,
            "{\"ts\":%d,\"mono_ns\":%lld,\"hstar\":%d}\n", 1000 + i * 45,
            (long long)i * 45000000000LL, 3056758 + i * slope);
    (void)snprintf(status, sizeof(status), "\"status\":\"%s\"", want_status);
    (void)snprintf(verdict, sizeof(verdict), "%s%s", want_rc == 0 ? "\"verdict\":\"" : "verdict=", want_verdict);
    const bool ok = write_file("case.jsonl", data, used) &&
                    run_cli("case.jsonl", out, sizeof(out)) == want_rc &&
                    strstr(out, status) != NULL &&
                    strstr(out, verdict) != NULL;
    return report(name, ok);
}

static int cli_reports_verdict_exit_codes(void)
{
    return cli_case("cli-flat-exit0-passed", 31, 5000, 0, "passed", "FLAT") +
           cli_case("cli-decaying-exit1-failed", 31, 2000, 1, "failed",
                    "DECAYING") +
           cli_case("cli-no-climb-exit3-blocked", 11, 0, 3, "blocked",
                    "NO_CLIMB");
}

static const char k_rising[] =
    "{\"mono_ns\":0,\"hstar\":100}\n{\"mono_ns\":1000000000,\"hstar\":200}\n"
    "{\"mono_ns\":2000000000,\"hstar\":300}\n";

static int cli_refuses_unterminated_nul_tail(void)
{
    static const char tail[] = "{\"mono_ns\":3000000000,\"hstar\":400}\0junk";
    char data[sizeof(k_rising) + sizeof(tail)], out[8192];
    memcpy(data, k_rising, sizeof(k_rising) - 1);
    memcpy(data + sizeof(k_rising) - 1, tail, sizeof(tail) - 1);
    const bool ok = write_file("nul.jsonl", data,
                               sizeof(k_rising) - 1 + sizeof(tail) - 1) &&
                    run_cli("nul.jsonl", out, sizeof(out)) != 0 &&
                    strstr(out, "INVALID_SAMPLE_FILE") != NULL &&
                    strstr(out, "\"verdict\"") == NULL;
    return report("cli-refuses-embedded-nul-tail", ok);
}

/* One record of exactly `length` bytes before the terminator. */
static size_t padded_record(char *buf, size_t length)
{
    static const char head[] = "{\"mono_ns\":5,\"hstar\":7,\"p\":\"";
    static const char tail[] = "\"}";
    const size_t fixed = sizeof(head) - 1 + sizeof(tail) - 1;
    memcpy(buf, head, sizeof(head) - 1);
    memset(buf + sizeof(head) - 1, 'x', length - fixed);
    memcpy(buf + length - (sizeof(tail) - 1), tail, sizeof(tail) - 1);
    return length;
}

static bool reader_accepts(size_t length, bool newline)
{
    char record[ZCL_REFOLD_RATE_MAX_LINE_BYTES + 8];
    struct zcl_refold_rate_sample *samples = zcl_calloc(
        ZCL_REFOLD_RATE_MAX_SAMPLES, sizeof(*samples), "test_samples");
    char bound_path[RR_TMP_MAX + 32];
    size_t count = 0;
    (void)snprintf(bound_path, sizeof(bound_path), "%s/bound.jsonl", g_dir);
    size_t used = padded_record(record, length);
    if (newline)
        record[used++] = '\n';
    const bool ok = samples && write_file("bound.jsonl", record, used) &&
                    zcl_refold_rate_read_jsonl(bound_path, samples, &count);
    free(samples);
    return ok;
}

static int line_bound_cases(void)
{
    const bool eof511 = reader_accepts(ZCL_REFOLD_RATE_MAX_LINE_BYTES, false);
    const bool eof512 = reader_accepts(ZCL_REFOLD_RATE_MAX_LINE_BYTES + 1, false);
    const bool nl511 = reader_accepts(ZCL_REFOLD_RATE_MAX_LINE_BYTES, true);
    const bool nl512 = reader_accepts(ZCL_REFOLD_RATE_MAX_LINE_BYTES + 1, true);
    char out[8192];
    const bool ok = eof511 && !eof512 && nl511 && !nl512 &&
                    run_cli("bound.jsonl", out, sizeof(out)) != 0 &&
                    strstr(out, "INVALID_SAMPLE_FILE") != NULL;
    return report("line-bound-511-accepted-512-refused", ok);
}

int test_refold_rate_verdict(void)
{
    int failures = 0;
    char *dir = test_mkdtemp(g_dir, sizeof(g_dir), "refold_rate");
    if (!dir) {
        printf("test_refold_rate_verdict: mkdtemp failed\n");
        return 1;
    }
    failures += fixture_constant_fast();
    failures += fixture_decaying();
    failures += fixture_below_floor();
    failures += fixture_pinned();
    failures += fixture_single_sample();
    failures += fixture_install_dip();
    failures += fixture_stall();
    failures += fixture_wall_clock_step();
    failures += rejects_nonpositive_interval();
    failures += cli_reports_verdict_exit_codes();
    failures += cli_refuses_unterminated_nul_tail();
    failures += line_bound_cases();
    test_cleanup_tmpdir(g_dir);
    printf("test_refold_rate_verdict: %s (%d failure(s))\n",
           failures == 0 ? "ALL PASSED" : "FAILED", failures);
    return failures;
}
