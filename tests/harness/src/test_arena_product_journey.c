/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_arena_product_journey_launch. The child execs a stub acceptance
 * script that prints the environment the launcher must have set. */

#include "test/test_core.h"

#include "arena_product_journey.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int apj_stub(const char *dir)
{
    char path[512];
    FILE *file;
    int n = snprintf(path, sizeof path, "%s/c23_commons_beta_acceptance.sh",
                     dir);
    if (n < 0 || n >= (int)sizeof path)
        return -1;
    file = fopen(path, "w");
    if (!file)
        return -1;
    if (fputs("#!/usr/bin/env bash\n"
              "printf '%s\\n' \"$C23_BETA_LABEL\"\n"
              "printf '%s\\n' \"$C23_BETA_HOOK\"\n"
              "printf '%s\\n' \"$C23_BETA_INSTALL_ARENA_RUNNER\"\n",
              file) < 0 ||
        fclose(file) != 0)
        return -1;
    return chmod(path, 0755);
}

static int test_arena_product_journey_cases(const char *root)
{
    int failures = 0;
    TEST("arena product journey: sets the beta hook and execs acceptance") {
        int pipefd[2];
        pid_t pid;
        char got[1024];
        char hook[512];
        ssize_t n;
        int status = 0;
        ASSERT(apj_stub(root) == 0);
        ASSERT(pipe(pipefd) == 0);
        pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0) {
            char stub[512];
            (void)close(pipefd[0]);
            if (dup2(pipefd[1], STDOUT_FILENO) < 0)
                _exit(2);
            (void)close(pipefd[1]);
            if (snprintf(stub, sizeof stub, "%s/c23_commons_beta_acceptance.sh",
                         root) >= (int)sizeof stub)
                _exit(2);
            if (setenv("C23_BETA_ACCEPTANCE_BIN", stub, 1) != 0)
                _exit(2);
            _exit(zcl_arena_product_journey_launch(root));
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
        (void)snprintf(hook, sizeof hook, "%s/arena_product_journey_hook.sh",
                       root);
        ASSERT(strstr(got, "arena-product-journey\n") == got);
        ASSERT(strstr(got, hook) != NULL);
        ASSERT(strstr(got, "\n1\n") != NULL);
        ASSERT(zcl_arena_product_journey_launch(NULL) == 2);
        PASS();
    } _test_next:;
    return failures;
}

int test_arena_product_journey(void);
int test_arena_product_journey(void)
{
    char root[512];
    int failures;
    test_make_tmpdir(root, sizeof root, "arena_product_journey", "root");
    failures = test_arena_product_journey_cases(root);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_arena_product_journey: all passed\n");
    else
        printf("test_arena_product_journey: %d FAILED\n", failures);
    return failures;
}
