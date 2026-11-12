/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_publish_build_alias, the shipped alias publisher. A fake
 * session tool records check then verify. A failing verify must leave the
 * previous alias in place and remove the publication temporary. */

#include "test/test_core.h"

#include "publish_build_alias.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char k_source[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char k_mutation[] =
    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
static const char k_epoch[] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char k_compiler[] =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

static int pba_write_exec(const char *path, const char *body)
{
    FILE *file = fopen(path, "w");
    if (!file)
        return -1;
    if (fputs(body, file) < 0 || fclose(file) != 0)
        return -1;
    return chmod(path, 0755);
}

static int pba_capture(struct zcl_publish_alias *req, char *err, size_t err_cap,
                       char *out, size_t out_cap)
{
    int err_pipe[2];
    int out_pipe[2];
    int saved_err;
    int saved_out;
    int status;
    ssize_t n;
    if (pipe(err_pipe) != 0 || pipe(out_pipe) != 0)
        return -1;
    saved_err = dup(STDERR_FILENO);
    saved_out = dup(STDOUT_FILENO);
    if (saved_err < 0 || saved_out < 0 ||
        dup2(err_pipe[1], STDERR_FILENO) < 0 ||
        dup2(out_pipe[1], STDOUT_FILENO) < 0)
        return -1;
    (void)close(err_pipe[1]);
    (void)close(out_pipe[1]);
    req->err_fd = STDERR_FILENO;
    status = zcl_publish_build_alias(req);
    (void)dup2(saved_err, STDERR_FILENO);
    (void)dup2(saved_out, STDOUT_FILENO);
    (void)close(saved_err);
    (void)close(saved_out);
    n = read(err_pipe[0], err, err_cap - 1);
    if (n < 0)
        n = 0;
    err[n] = '\0';
    (void)close(err_pipe[0]);
    n = read(out_pipe[0], out, out_cap - 1);
    if (n < 0)
        n = 0;
    out[n] = '\0';
    (void)close(out_pipe[0]);
    return status;
}

static void pba_fill(struct zcl_publish_alias *req, const char *root)
{
    static char candidate[512];
    static char alias[512];
    static char session[512];
    static char session_tool[512];
    static char verify_tool[512];
    (void)snprintf(candidate, sizeof candidate, "%s/epochs/%s/cand", root,
                   k_epoch);
    (void)snprintf(alias, sizeof alias, "%s/bin/tool", root);
    (void)snprintf(session, sizeof session, "%s/obj/epochs/%s/.build-session",
                   root, k_epoch);
    (void)snprintf(session_tool, sizeof session_tool, "%s/session.sh", root);
    (void)snprintf(verify_tool, sizeof verify_tool, "%s/verify.sh", root);
    memset(req, 0, sizeof *req);
    req->candidate = candidate;
    req->alias = alias;
    req->session = session;
    req->source_id = k_source;
    req->complete = "1";
    req->mutation = k_mutation;
    req->epoch = k_epoch;
    req->compiler_id = k_compiler;
    req->profile = "test-fast-v2";
    req->compile_flags = "-std=c23";
    req->link_flags = "-pie";
    req->cc = "cc";
    req->cxx = "c++";
    req->verify_tool = verify_tool;
    req->session_tool = session_tool;
    req->err_fd = STDERR_FILENO;
}

static int test_publish_build_alias_cases(const char *root)
{
    int failures = 0;
    TEST("publish alias: check then verify, copy bytes, verify refusal "
         "keeps the previous alias") {
        struct zcl_publish_alias req;
        char err[1024];
        char out[1024];
        char path[512];
        char log_path[512];
        char body[1024];
        FILE *file;
        int status;
        pba_fill(&req, root);
        (void)snprintf(path, sizeof path, "%s/epochs", root);
        ASSERT(mkdir(path, 0755) == 0);
        (void)snprintf(path, sizeof path, "%s/epochs/%s", root, k_epoch);
        ASSERT(mkdir(path, 0755) == 0);
        (void)snprintf(path, sizeof path, "%s/epochs/%s/cand", root, k_epoch);
        file = fopen(path, "w");
        ASSERT(file != NULL);
        ASSERT(fputs("payload-v1\n", file) >= 0);
        ASSERT(fclose(file) == 0);
        ASSERT(chmod(path, 0755) == 0);
        (void)snprintf(log_path, sizeof log_path, "%s/session.log", root);
        (void)snprintf(body, sizeof body,
                       "#!/bin/sh\nprintf '%%s\\n' \"$1\" >> '%s'\n"
                       "if [ \"$1\" = verify ] && [ -n \"${PBA_VERIFY_FAIL:-}\" ]; "
                       "then exit 9; fi\nexit 0\n",
                       log_path);
        (void)snprintf(path, sizeof path, "%s/session.sh", root);
        ASSERT(pba_write_exec(path, body) == 0);
        (void)snprintf(path, sizeof path, "%s/verify.sh", root);
        ASSERT(pba_write_exec(path, "#!/bin/sh\nexit 0\n") == 0);
        status = pba_capture(&req, err, sizeof err, out, sizeof out);
        ASSERT(status == 0);
        ASSERT(strstr(out, "publish-build-alias: ") != NULL);
        ASSERT(strstr(out, k_epoch) != NULL);
        ASSERT(strstr(out, "sha256=") != NULL);
        file = fopen(req.alias, "r");
        ASSERT(file != NULL);
        {
            char got[64];
            ASSERT(fgets(got, sizeof got, file) != NULL);
            ASSERT(strcmp(got, "payload-v1\n") == 0);
            ASSERT(fclose(file) == 0);
        }
        file = fopen(log_path, "r");
        ASSERT(file != NULL);
        {
            char got[64];
            ASSERT(fgets(got, sizeof got, file) != NULL);
            ASSERT(strcmp(got, "check\n") == 0);
            ASSERT(fgets(got, sizeof got, file) != NULL);
            ASSERT(strcmp(got, "verify\n") == 0);
            ASSERT(fclose(file) == 0);
        }
        ASSERT(setenv("PBA_VERIFY_FAIL", "1", 1) == 0);
        status = pba_capture(&req, err, sizeof err, out, sizeof out);
        ASSERT(status == 9);
        file = fopen(req.alias, "r");
        ASSERT(file != NULL);
        {
            char got[64];
            ASSERT(fgets(got, sizeof got, file) != NULL);
            ASSERT(strcmp(got, "payload-v1\n") == 0);
            ASSERT(fclose(file) == 0);
        }
        (void)unsetenv("PBA_VERIFY_FAIL");
        req.complete = "0";
        status = pba_capture(&req, err, sizeof err, out, sizeof out);
        ASSERT(status == 2);
        ASSERT(strstr(err, "source capture is incomplete") != NULL);
        req.complete = "1";
        (void)snprintf(path, sizeof path, "%s/outside-cand", root);
        file = fopen(path, "w");
        ASSERT(file != NULL);
        ASSERT(fputs("nope\n", file) >= 0);
        ASSERT(fclose(file) == 0);
        ASSERT(chmod(path, 0755) == 0);
        req.candidate = path;
        status = pba_capture(&req, err, sizeof err, out, sizeof out);
        ASSERT(status == 2);
        ASSERT(strstr(err, "candidate path is outside compile epoch ") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_publish_build_alias(void);
int test_publish_build_alias(void)
{
    char root[512];
    int failures;
    test_make_tmpdir(root, sizeof root, "publish_alias", "root");
    failures = test_publish_build_alias_cases(root);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_publish_build_alias: all passed\n");
    else
        printf("test_publish_build_alias: %d FAILED\n", failures);
    return failures;
}
