/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_sovereign_source_network_launch. The child execs a stub
 * acceptance script that prints the environment the launcher must have set. */

#include "test/test_core.h"

#include "sovereign_source_network.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int ssn_stub(const char *dir)
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

static int test_sovereign_source_network_cases(const char *root)
{
    int failures = 0;
    TEST("sovereign source network: sets the publication hook and execs acceptance") {
        int pipefd[2];
        pid_t pid;
        char got[1024];
        char hook[512];
        ssize_t n;
        int status = 0;
        ASSERT(zcl_sovereign_source_network_launch(NULL) == 2);
        ASSERT(zcl_sovereign_source_network_launch("") == 2);
        ASSERT(ssn_stub(root) == 0);
        ASSERT(pipe(pipefd) == 0);
        pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0) {
            (void)close(pipefd[0]);
            if (dup2(pipefd[1], STDOUT_FILENO) < 0)
                _exit(2);
            (void)close(pipefd[1]);
            _exit(zcl_sovereign_source_network_launch(root));
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
        (void)snprintf(hook, sizeof hook,
                       "%s/sovereign_source_network_hook.sh", root);
        ASSERT(strstr(got, "1\n") == got);
        ASSERT(strstr(got, hook) != NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_sovereign_source_network(void);
int test_sovereign_source_network(void)
{
    char root[512];
    int failures;
    test_make_tmpdir(root, sizeof root, "sovereign_source_network", "root");
    failures = test_sovereign_source_network_cases(root);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_sovereign_source_network: all passed\n");
    else
        printf("test_sovereign_source_network: %d FAILED\n", failures);
    return failures;
}
