#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#endif

static void summary(unsigned failures)
{
    printf("SUITE VERDICT mode=cold groups_total=1 groups_ran=1 "
           "groups_cached=0 groups_gated=0 groups_failed=%u "
           "self_skips=0 env_unobserved=0 toolkey=fixture\n", failures);
    puts(failures ? "SOME TESTS FAILED — 1/1 groups failed" :
                    "ALL TESTS PASSED — 0/1 groups failed");
}

static int overflow_failure(void)
{
    char padding[8192];
    memset(padding, 'x', sizeof(padding));
    for (size_t i = 0; i < 258; i++)
        if (fwrite(padding, 1, sizeof(padding), stdout) != sizeof(padding))
            return 3;
    putchar('\n');
    summary(1);
    return 1;
}

static bool wait_timeout(void)
{
    if (fflush(stdout) != 0) return false;
    struct timespec start, now;
    if (timespec_get(&start, TIME_UTC) != TIME_UTC) return false;
    do {
        if (timespec_get(&now, TIME_UTC) != TIME_UTC) return false;
    } while (now.tv_sec - start.tv_sec < 3);
    return true;
}

int main(void)
{
    const char *mode = getenv("GATE_CAPTURE_CASE");
    if (!mode) return 2;
#if !defined(_WIN32)
    if (strcmp(mode, "overflow-write-failure") == 0) {
        const char *state = getenv("GATE_CAPTURE_STATE");
        if (!state || chmod(state, 0500) != 0) return 3;
    }
#endif
    if (strcmp(mode, "ordinary-fail") == 0) {
        summary(1);
        return 1;
    }
    if (strcmp(mode, "nul-before-pass") == 0) {
        fputs("diagnostic", stdout);
        putchar(0);
        putchar('\n');
    }
    summary(0);
    if (strcmp(mode, "nul-before-fail") == 0) {
        putchar(0);
        puts("\nerror: fixture-marker-after-nul Bearer "
             "sk-" "fixture012345678901234567890123456789");
        summary(1);
        return 1;
    }
    if (strcmp(mode, "overflow-before-fail") == 0 ||
        strcmp(mode, "overflow-write-failure") == 0) {
        return overflow_failure();
    }
    if (strcmp(mode, "timeout") == 0) {
        if (!wait_timeout()) return 3;
    }
    return ferror(stdout) ? 3 : 0;
}
