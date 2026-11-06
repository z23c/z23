/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "test/test_core.h"
#include "platform/clock.h"
#include "util/spawn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
static bool fp_observed(const struct zcl_spawn_binary_observation *o)
{
    return !o->timed_out && !o->overflow && o->eof &&
        o->exit_observed && o->exit_code == 0;
}

static bool fp_child(const char *role, const char *kernel, int64_t end)
{
    int64_t remaining = end - clock_now_monotonic_ns();
    if (remaining <= 0) return false;
    int timeout = remaining / 1000000 > 90000 ? 90000 : (int)(remaining / 1000000);
    if (timeout <= 0) return false;
    char *output = calloc(1, 131073);
    if (!output) return false;
    const char *argv[] = {"build/bin/z23-machine-freebsd-ports", role, kernel, NULL};
    struct zcl_spawn_binary_observation observed = {0};
    struct zcl_result result = zcl_spawn_capture_binary_merged(argv, output, 131072,
                                                              timeout, &observed);
    output[observed.output_len] = '\0';
    char marker[96];
    int n = snprintf(marker, sizeof marker, "PUBLIC_FREEBSD_PORT_PROOF role=%s ", role);
    bool emitted = fwrite(output, 1, observed.output_len, stdout) == observed.output_len && fflush(stdout) == 0;
    bool ok = emitted && result.ok && fp_observed(&observed) &&
        n > 0 && (size_t)n < sizeof marker && strstr(output, marker) != NULL;
    free(output);
    return ok;
}
#endif

int test_rvmachine_freebsd_ports(void);
int test_rvmachine_freebsd_ports(void)
{
#if defined(_WIN32)
    printf("UNOBSERVED: actual FreeBSD raw byte fixture has no Windows qualification\n");
    return 1;
#else
    const char *kernel = getenv("ZCL_TEST_FREEBSD_PORT_FIXTURE_KERNEL");
    if (!kernel || !*kernel) {
        printf("UNOBSERVED (exact PUBLIC FreeBSD port image unavailable)\n");
        return 0;
    }
    int64_t now = clock_now_monotonic_ns();
    if (now <= 0 || now > INT64_MAX - INT64_C(240000000000)) {
        printf("UNOBSERVED: monotonic deadline unavailable for FreeBSD port fixture\n");
        return 1;
    }
    int64_t end = now + INT64_C(240000000000);
    int failures = 0;
    TEST("actual FreeBSD named T/P raw binary bytes and isolation") {
        ASSERT(fp_child("T", kernel, end));
        ASSERT(fp_child("P", kernel, end));
        ASSERT(fp_child("BOTH", kernel, end));
        ASSERT(fp_child("CLOSE", kernel, end));
        PASS();
    } _test_next:;
    return failures;
#endif
}
