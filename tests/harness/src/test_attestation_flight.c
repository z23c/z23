/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_attestation_flight_launch. The child execs a stub acceptance
 * script that prints the environment the launcher must have set. */

#include "test/test_core.h"

#include "attestation_flight.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int afl_stub(const char *dir)
{
    char path[512];
    FILE *file;
    int n = snprintf(path, sizeof path, "%s/zcode_dht_acceptance.sh", dir);
    if (n < 0 || n >= (int)sizeof path)
        return -1;
    file = fopen(path, "w");
    if (!file)
        return -1;
    if (fputs("#!/usr/bin/env bash\n"
              "printf '%s\\n' \"$DHT_PACKAGEHOST\"\n"
              "printf '%s\\n' \"$DHT_AFTER_SPARSE_HOOK\"\n",
              file) < 0 ||
        fclose(file) != 0)
        return -1;
    return 0;
}

static int test_attestation_flight_cases(const char *root)
{
    int failures = 0;
    TEST("attestation flight: sets the flight hook and execs acceptance") {
        int pipefd[2];
        pid_t pid;
        char got[1024];
        char hook[512];
        ssize_t n;
        int status = 0;
        ASSERT(zcl_attestation_flight_launch(NULL) == 2);
        ASSERT(zcl_attestation_flight_launch("") == 2);
        ASSERT(afl_stub(root) == 0);
        ASSERT(pipe(pipefd) == 0);
        pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0) {
            (void)close(pipefd[0]);
            if (dup2(pipefd[1], STDOUT_FILENO) < 0)
                _exit(2);
            (void)close(pipefd[1]);
            _exit(zcl_attestation_flight_launch(root));
        }
        (void)close(pipefd[1]);
        n = 0;
        while (n < (ssize_t)sizeof got - 1) {
            ssize_t step = read(pipefd[0], got + n,
                                sizeof got - 1 - (size_t)n);
            if (step < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (step == 0)
                break;
            n += step;
        }
        (void)close(pipefd[0]);
        ASSERT(waitpid(pid, &status, 0) == pid);
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        ASSERT(n > 0);
        got[n] = '\0';
        (void)snprintf(hook, sizeof hook, "%s/attestation_flight_hook.sh",
                       root);
        ASSERT(strstr(got, "1\n") == got);
        ASSERT(strstr(got, hook) != NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_attestation_flight(void);
int test_attestation_flight(void)
{
    char root[512];
    int failures;
    test_make_tmpdir(root, sizeof root, "attestation_flight", "root");
    failures = test_attestation_flight_cases(root);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_attestation_flight: all passed\n");
    else
        printf("test_attestation_flight: %d FAILED\n", failures);
    return failures;
}
