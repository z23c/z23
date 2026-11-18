/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "test/test_core.h"
#include <stdio.h>
#include <stdlib.h>
#if !defined(_WIN32)
#include "devloop.h"
#endif

int test_z23android(void);
int test_z23android(void)
{
#if defined(_WIN32)
    puts("test_z23android: skipped on Windows");
    return 0;
#else
    const char *prior = getenv("ZCL_DEVLOOP_TEST_PROCESS");
    char *saved = prior ? strdup(prior) : NULL;
    if ((prior && !saved) || setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) != 0) {
        fprintf(stderr, "test_z23android: cannot enable isolated process fixture\n");
        free(saved);
        return 1;
    }
    char *argv[] = {"make", "-C", "apps/z23android", "test-fast",
                    "BUILD_DIR=../../build/android-harness", NULL};
    char *envp[] = {"PATH=/usr/bin:/bin:/usr/local/bin", NULL};
    struct zcl_devloop_process_result result = {0};
    bool ran = zcl_devloop_process_run_env(".",
        (const char *const *)argv, (const char *const *)envp, 30000, &result);
    bool restored = (saved ? setenv("ZCL_DEVLOOP_TEST_PROCESS", saved, 1) :
        unsetenv("ZCL_DEVLOOP_TEST_PROCESS")) == 0;
    free(saved);
    bool ok = ran && restored && !result.timed_out && !result.cancelled &&
        !result.output_truncated && result.term_signal == 0 && result.exit_code == 0;
    if (result.output_len) (void)fwrite(result.output, 1, result.output_len, ok ? stdout : stderr);
    if (!ok) {
        fprintf(stderr, "test_z23android: failed ran=%d restored=%d timeout=%d "
                "cancelled=%d truncated=%d exit=%d signal=%d\n",
                ran, restored, result.timed_out, result.cancelled,
                result.output_truncated, result.exit_code, result.term_signal);
        return 1;
    }
    puts("test_z23android: all passed");
    return 0;
#endif
}
