/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Drive zcl_c23_portable_release_verify and the portable release
 *          orchestrator against a private checkout of stub tools. */

#include "test/test_core.h"

#include "c23_portable_release.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char k_id_a[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char k_id_b[] =
    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
static const char k_sha[] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

static const char *k_cpr_dirs[] = {
    "tools", "tools/scripts", "tools/dev", "build", "build/bin",
    "sysroot", "sysroot/lib64", "stubcc", "bin", NULL};

static const char *k_cpr_links[] = {
    "build/bin/c23-portable-sysroot",
    "tools/scripts/build_vendor.sh",
    "tools/scripts/build_tor_full.sh",
    "tools/scripts/check_c23_node_binary.sh",
    "tools/dev/source-identity.sh",
    "build/bin/tor-stamp",
    "build/bin/zclassic23",
    "sysroot/lib64/ld-linux-x86-64.so.2",
    "bin/make",
    "bin/objdump",
    NULL};

struct cpr_cmd {
    int kind;
    const char *repo;
    const char *a;
    const char *b;
    const char *c;
};

static int cpr_cmd_run(struct cpr_cmd *cmd)
{
    if (cmd->kind == 1)
        return zcl_c23_portable_release(NULL, 1);
    if (cmd->kind == 2)
        return zcl_c23_portable_release_verify(cmd->a, cmd->b, cmd->c);
    return zcl_c23_portable_release(cmd->repo, 0);
}

static int cpr_spew(const char *path, const char *body)
{
    FILE *fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    if (fputs(body, fp) < 0) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0)
        return -1;
    if (chmod(path, 0755) != 0)
        return -1;
    return 0;
}

static int cpr_put(const char *dir, const char *leaf, const char *text)
{
    char path[PATH_MAX];
    FILE *fp;
    if (snprintf(path, sizeof path, "%s/%s", dir, leaf) >= (int)sizeof path)
        return -1;
    fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    if (fputs(text, fp) < 0) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0)
        return -1;
    return 0;
}

static int cpr_read(const char *path, char *buf, size_t cap)
{
    FILE *fp = fopen(path, "r");
    size_t n;
    if (fp == NULL)
        return -1;
    n = fread(buf, 1, cap - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    return 0;
}

static int cpr_mkdirs(const char *dir)
{
    char path[PATH_MAX];
    int i;
    for (i = 0; k_cpr_dirs[i] != NULL; i++) {
        if (snprintf(path, sizeof path, "%s/%s", dir, k_cpr_dirs[i]) >=
            (int)sizeof path)
            return -1;
        if (mkdir(path, 0700) != 0)
            return -1;
    }
    return 0;
}

static int cpr_write_script(const char *dir)
{
    char body[8192];
    char path[PATH_MAX];
    int nw = snprintf(
        body, sizeof body,
        "#!/bin/sh\n"
        "set -eu\n"
        "dir='%s'\n"
        "log=\"$dir/log\"\n"
        "base=${0##*/}\n"
        "emit() {\n"
        "  while IFS= read -r line || [ -n \"${line-}\" ]; do\n"
        "    printf '%%s\\n' \"$line\"\n"
        "  done < \"$1\"\n"
        "}\n"
        "{\n"
        "  printf '%%s' \"$base\"\n"
        "  for a in \"$@\"; do printf ' [%%s]' \"$a\"; done\n"
        "  printf ' VENDOR_CC=%%s GLIBC=%%s PATH=%%s\\n' "
        "\"${VENDOR_CC-}\" \"${ZCL_C23_MAX_GLIBC-}\" \"${PATH-}\"\n"
        "} >> \"$log\"\n"
        "case \"$base\" in\n"
        "  c23-portable-sysroot)\n"
        "    if [ \"${1-}\" = prepare ]; then printf '%%s\\n' \"$dir/stubcc/cc-wrap\";\n"
        "    elif [ \"${1-}\" = root-path ]; then printf '%%s\\n' \"$dir/sysroot\";\n"
        "    else exit 2; fi ;;\n"
        "  source-identity.sh)\n"
        "    n=0\n"
        "    if [ -f \"$dir/id.count\" ]; then n=$(emit \"$dir/id.count\"); fi\n"
        "    printf '%%s\\n' \"$((n + 1))\" > \"$dir/id.count\"\n"
        "    if [ \"$n\" = 0 ]; then emit \"$dir/id.out\"; else emit \"$dir/id2.out\"; fi ;;\n"
        "  zclassic23)\n"
        "    if [ \"${1-}\" = agentbuild ]; then emit \"$dir/agent.out\"; fi ;;\n"
        "  tor-stamp)\n"
        "    if [ \"${1-}\" = write-sidecar ] && [ -f \"$dir/fail-sidecar\" ]; then exit 3; fi\n"
        "    if [ \"${1-}\" = require-full ] && [ -f \"$dir/fail-require\" ]; then exit 4; fi ;;\n"
        "  build_vendor.sh)\n"
        "    if [ -f \"$dir/fail-vendor\" ]; then exit 9; fi ;;\n"
        "  objdump)\n"
        "    printf 'GLIBC_2.17\\nGLIBC_2.4\\nGLIBC_2.34\\nGLIBC_2\\n' ;;\n"
        "esac\n"
        "exit 0\n",
        dir);
    if (nw < 0 || (size_t)nw >= sizeof body)
        return -1;
    if (snprintf(path, sizeof path, "%s/record.sh", dir) >= (int)sizeof path)
        return -1;
    return cpr_spew(path, body);
}

static int cpr_link_tree(const char *dir, int qemu)
{
    char target[PATH_MAX];
    char dest[PATH_MAX];
    int i;
    if (snprintf(target, sizeof target, "%s/record.sh", dir) >= (int)sizeof target)
        return -1;
    for (i = 0; k_cpr_links[i] != NULL; i++) {
        if (snprintf(dest, sizeof dest, "%s/%s", dir, k_cpr_links[i]) >=
            (int)sizeof dest)
            return -1;
        if (symlink(target, dest) != 0)
            return -1;
    }
    if (snprintf(dest, sizeof dest, "%s/bin/sha256sum", dir) >= (int)sizeof dest)
        return -1;
    if (cpr_spew(dest,
                 "#!/bin/sh\n"
                 "printf '%s  %s\\n' '"
                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                 "' \"$1\"\n") != 0)
        return -1;
    if (!qemu)
        return 0;
    if (snprintf(dest, sizeof dest, "%s/bin/qemu-x86_64", dir) >= (int)sizeof dest)
        return -1;
    if (symlink(target, dest) != 0)
        return -1;
    return 0;
}

static int cpr_put_id(const char *dir, const char *leaf, const char *id)
{
    char line[80];
    int nw = snprintf(line, sizeof line, "%s\n", id);
    if (nw < 0 || (size_t)nw >= sizeof line)
        return -1;
    return cpr_put(dir, leaf, line);
}

static int cpr_put_agent(const char *dir, const char *id)
{
    char body[256];
    int nw = snprintf(
        body, sizeof body,
        "{\"schema\":\"zcl.agent_build.v2\",\"api_version\":\"v1\","
        "\"status\":\"ok\",\"source_id_sha256\":\"%s\","
        "\"build_commit\":\"abc\"}\n",
        id);
    if (nw < 0 || (size_t)nw >= sizeof body)
        return -1;
    return cpr_put(dir, "agent.out", body);
}

static int cpr_arm(const char *dir, int qemu)
{
    if (strchr(dir, '\'') != NULL)
        return -1;
    if (cpr_mkdirs(dir) != 0)
        return -1;
    if (cpr_write_script(dir) != 0)
        return -1;
    if (cpr_link_tree(dir, qemu) != 0)
        return -1;
    if (cpr_put_id(dir, "id.out", k_id_a) != 0)
        return -1;
    if (cpr_put_id(dir, "id2.out", k_id_a) != 0)
        return -1;
    if (cpr_put_agent(dir, k_id_a) != 0)
        return -1;
    return 0;
}

static int cpr_capture(const char *dir, struct cpr_cmd *cmd, char *out,
                       size_t out_cap, char *err, size_t err_cap)
{
    char out_path[PATH_MAX];
    char err_path[PATH_MAX];
    int fd_out;
    int fd_err;
    int saved_out = -1;
    int saved_err = -1;
    if (snprintf(out_path, sizeof out_path, "%s/cap.out", dir) >= (int)sizeof out_path)
        return -1;
    if (snprintf(err_path, sizeof err_path, "%s/cap.err", dir) >= (int)sizeof err_path)
        return -1;
    fd_out = open(out_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    fd_err = open(err_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd_out < 0 || fd_err < 0)
        goto fail;
    saved_out = dup(STDOUT_FILENO);
    saved_err = dup(STDERR_FILENO);
    if (saved_out < 0 || saved_err < 0)
        goto fail;
    fflush(stdout);
    fflush(stderr);
    if (dup2(fd_out, STDOUT_FILENO) < 0 || dup2(fd_err, STDERR_FILENO) < 0)
        goto fail;
    {
        int rc = cpr_cmd_run(cmd);
        fflush(stdout);
        fflush(stderr);
        dup2(saved_out, STDOUT_FILENO);
        dup2(saved_err, STDERR_FILENO);
        close(saved_out);
        close(saved_err);
        close(fd_out);
        close(fd_err);
        saved_out = -1;
        saved_err = -1;
        if (cpr_read(out_path, out, out_cap) != 0 || cpr_read(err_path, err, err_cap) != 0)
            return -1;
        return rc;
    }
fail:
    if (saved_out >= 0) {
        dup2(saved_out, STDOUT_FILENO);
        close(saved_out);
    }
    if (saved_err >= 0) {
        dup2(saved_err, STDERR_FILENO);
        close(saved_err);
    }
    if (fd_out >= 0)
        close(fd_out);
    if (fd_err >= 0)
        close(fd_err);
    return -1;
}

static int cpr_with_path(const char *dir, struct cpr_cmd *cmd, char *out,
                         size_t out_cap, char *err, size_t err_cap)
{
    char old[8192];
    char next[PATH_MAX];
    const char *saved = getenv("PATH");
    int rc;
    if (saved == NULL)
        saved = "";
    if (strlen(saved) + 1 > sizeof old)
        return -1;
    memcpy(old, saved, strlen(saved) + 1);
    if (snprintf(next, sizeof next, "%s/bin", dir) >= (int)sizeof next)
        return -1;
    if (setenv("PATH", next, 1) != 0)
        return -1;
    rc = cpr_capture(dir, cmd, out, out_cap, err, err_cap);
    if (setenv("PATH", old, 1) != 0)
        return -1;
    return rc;
}

static int cpr_case(const char *root, const char *tag, char *dir, size_t cap)
{
    if (snprintf(dir, cap, "%s/%s", root, tag) >= (int)cap)
        return -1;
    if (mkdir(dir, 0700) != 0)
        return -1;
    return 0;
}

static int test_cpr_verify(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[64];
    char err[512];
    struct cpr_cmd cmd;
    int rc;
    const char *upper =
        "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef";
    memset(&cmd, 0, sizeof cmd);
    cmd.kind = 2;
    TEST("verify admits one source epoch and refuses the others") {
        ASSERT(cpr_case(root, "verify", dir, sizeof dir) == 0);
        cmd.a = NULL;
        cmd.b = k_id_a;
        cmd.c = k_id_a;
        rc = cpr_capture(dir, &cmd, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(err, "c23-portable-release: invalid initial source identity\n");
        ASSERT(out[0] == '\0');
        cmd.a = upper;
        rc = cpr_capture(dir, &cmd, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(err, "c23-portable-release: invalid initial source identity\n");
        cmd.a = k_id_a;
        cmd.b = "abcd";
        rc = cpr_capture(dir, &cmd, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(err, "c23-portable-release: invalid final source identity\n");
        cmd.b = k_id_a;
        cmd.c = NULL;
        rc = cpr_capture(dir, &cmd, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(err, "c23-portable-release: node omitted its baked source identity\n");
        cmd.c = k_id_b;
        rc = cpr_capture(dir, &cmd, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(err, "node baked source ") == err + strlen("c23-portable-release: "));
        ASSERT(strstr(err, k_id_b) != NULL);
        ASSERT(strstr(err, k_id_a) != NULL);
        cmd.b = k_id_b;
        cmd.c = k_id_a;
        rc = cpr_capture(dir, &cmd, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(err, "source epoch changed during build: before=") != NULL);
        ASSERT(strstr(err, k_id_a) != NULL);
        ASSERT(strstr(err, k_id_b) != NULL);
        cmd.a = k_id_a;
        cmd.b = k_id_a;
        cmd.c = k_id_a;
        rc = cpr_capture(dir, &cmd, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT_STR_EQ(err, "");
        ASSERT_STR_EQ(out, "");
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_cpr_self_and_repo(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[256];
    char err[512];
    struct cpr_cmd cmd;
    int rc;
    memset(&cmd, 0, sizeof cmd);
    TEST("selftest passes and a missing repo is refused") {
        ASSERT(cpr_case(root, "self", dir, sizeof dir) == 0);
        cmd.kind = 1;
        rc = cpr_capture(dir, &cmd, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT_STR_EQ(out, "c23-portable-release: selftest PASS\n");
        ASSERT_STR_EQ(err, "");
        cmd.kind = 0;
        cmd.repo = "";
        rc = cpr_capture(dir, &cmd, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 2);
        ASSERT_STR_EQ(err, "c23-portable-release: repo is required\n");
        ASSERT_STR_EQ(out, "");
        cmd.repo = NULL;
        rc = cpr_capture(dir, &cmd, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 2);
        ASSERT_STR_EQ(err, "c23-portable-release: repo is required\n");
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_cpr_release(const char *root, const char *tag, int qemu,
                            const char *proof)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[256];
    char err[4096];
    char log[16384];
    char log_path[PATH_MAX];
    char want[1024];
    char path_mark[PATH_MAX];
    struct cpr_cmd cmd;
    int rc;
    memset(&cmd, 0, sizeof cmd);
    TEST(tag) {
        ASSERT(cpr_case(root, tag, dir, sizeof dir) == 0);
        ASSERT(cpr_arm(dir, qemu) == 0);
        cmd.kind = 0;
        cmd.repo = dir;
        rc = cpr_with_path(dir, &cmd, out, sizeof out, err, sizeof err);
        test_note("rc=%d err=%s", rc, err);
        ASSERT_EQ(rc, 0);
        ASSERT_STR_EQ(out, "");
        ASSERT(snprintf(want, sizeof want,
                        "c23-portable-release: rebuilding linked archives through %s/stubcc/cc-wrap\n",
                        dir) > 0);
        ASSERT(strstr(err, want) != NULL);
        ASSERT(snprintf(want, sizeof want,
                        "c23-portable-release: PASS products=6 cpu=x86-64 "
                        "cpu_runtime_proof=%s glibc_floor=2.31 source_id=%s "
                        "node=build/bin/zclassic23 sha256=%s max_abi=GLIBC_2.34\n",
                        proof, k_id_a, k_sha) > 0);
        ASSERT(strstr(err, want) != NULL);
        ASSERT(snprintf(log_path, sizeof log_path, "%s/log", dir) > 0);
        ASSERT(cpr_read(log_path, log, sizeof log) == 0);
        ASSERT(snprintf(want, sizeof want,
                        "c23-portable-sysroot [prepare]") > 0);
        ASSERT(strstr(log, want) != NULL);
        ASSERT(strstr(log, "c23-portable-sysroot [root-path]") != NULL);
        ASSERT(snprintf(path_mark, sizeof path_mark, "PATH=%s/stubcc:", dir) > 0);
        ASSERT(strstr(log, "build_vendor.sh [libtor_stub.a] [libsqlite3.a] [libz.a] "
                           "[libcrypto.a] [libssl.a] [libevent.a] [libevent_openssl.a] "
                           "[libevent_pthreads.a]") != NULL);
        ASSERT(strstr(log, "VENDOR_CC=cc") != NULL);
        ASSERT(strstr(log, path_mark) != NULL);
        ASSERT(strstr(log, "build_tor_full.sh VENDOR_CC=cc") != NULL);
        ASSERT(snprintf(want, sizeof want,
                        "make [-C] [%s] [CC=cc] [VENDOR_CC=cc] [ZCL_C23_PORTABLE_RELEASE=1] "
                        "[zclassic23] [zcl-rpc] [zcl-nodectl] [z23-package-sign] "
                        "[z23-package-verify] [z23-acme]",
                        dir) > 0);
        ASSERT(strstr(log, want) != NULL);
        ASSERT(snprintf(want, sizeof want, "make [-C] [%s] [tor-stamp]", dir) > 0);
        ASSERT(strstr(log, want) != NULL);
        ASSERT(snprintf(want, sizeof want,
                        "tor-stamp [require-full] [%s/build/bin/zclassic23] [the portable release node]",
                        dir) > 0);
        ASSERT(strstr(log, want) != NULL);
        ASSERT(snprintf(want, sizeof want,
                        "tor-stamp [write-sidecar] [%s/build/bin/zclassic23]", dir) > 0);
        ASSERT(strstr(log, want) != NULL);
        ASSERT(snprintf(want, sizeof want,
                        "check_c23_node_binary.sh [%s/build/bin/zclassic23] VENDOR_CC= GLIBC=GLIBC_2.31",
                        dir) > 0);
        ASSERT(strstr(log, want) != NULL);
        ASSERT(snprintf(want, sizeof want,
                        "check_c23_node_binary.sh [%s/build/bin/z23-acme] VENDOR_CC= GLIBC=GLIBC_2.31",
                        dir) > 0);
        ASSERT(strstr(log, want) != NULL);
        ASSERT(snprintf(want, sizeof want,
                        "check_c23_node_binary.sh [%s/build/bin/zcl-rpc] VENDOR_CC= GLIBC=GLIBC_2.31",
                        dir) > 0);
        ASSERT(strstr(log, want) != NULL);
        ASSERT(snprintf(want, sizeof want,
                        "check_c23_node_binary.sh [%s/build/bin/zcl-nodectl] VENDOR_CC= GLIBC=GLIBC_2.31",
                        dir) > 0);
        ASSERT(strstr(log, want) != NULL);
        ASSERT(snprintf(want, sizeof want,
                        "check_c23_node_binary.sh [%s/build/bin/z23-package-sign] VENDOR_CC= GLIBC=GLIBC_2.31",
                        dir) > 0);
        ASSERT(strstr(log, want) != NULL);
        ASSERT(snprintf(want, sizeof want,
                        "check_c23_node_binary.sh [%s/build/bin/z23-package-verify] VENDOR_CC= GLIBC=GLIBC_2.31",
                        dir) > 0);
        ASSERT(strstr(log, want) != NULL);
        ASSERT(snprintf(want, sizeof want,
                        "ld-linux-x86-64.so.2 [--library-path] [%s/sysroot/lib/x86_64-linux-gnu:%s/sysroot/usr/lib/x86_64-linux-gnu] [%s/build/bin/zclassic23] [discover] [search] [package]",
                        dir, dir, dir) > 0);
        ASSERT(strstr(log, want) != NULL);
        ASSERT(snprintf(want, sizeof want, "objdump [-T] [%s/build/bin/zclassic23]", dir) > 0);
        ASSERT(strstr(log, want) != NULL);
        ASSERT(strstr(log, "source-identity.sh [capture]") != NULL);
        if (qemu) {
            ASSERT(snprintf(want, sizeof want,
                            "qemu-x86_64 [-cpu] [qemu64] [%s/sysroot/lib64/ld-linux-x86-64.so.2]",
                            dir) > 0);
            ASSERT(strstr(log, want) != NULL);
        } else {
            ASSERT(strstr(log, "qemu-x86_64") == NULL);
        }
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_cpr_fail(const char *root, const char *tag, const char *flag,
                         const char *id2, const char *agent, int want_rc,
                         const char *needle)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[256];
    char err[2048];
    struct cpr_cmd cmd;
    int rc;
    memset(&cmd, 0, sizeof cmd);
    TEST(tag) {
        ASSERT(cpr_case(root, tag, dir, sizeof dir) == 0);
        ASSERT(cpr_arm(dir, 0) == 0);
        if (flag != NULL)
            ASSERT(cpr_put(dir, flag, "1\n") == 0);
        if (id2 != NULL)
            ASSERT(cpr_put_id(dir, "id2.out", id2) == 0);
        if (agent != NULL)
            ASSERT(cpr_put(dir, "agent.out", agent) == 0);
        if (strcmp(tag, "bad-id") == 0)
            ASSERT(cpr_put(dir, "id.out", "nope\n") == 0);
        cmd.kind = 0;
        cmd.repo = dir;
        rc = cpr_with_path(dir, &cmd, out, sizeof out, err, sizeof err);
        test_note("rc=%d err=%s", rc, err);
        ASSERT_EQ(rc, want_rc);
        ASSERT(strstr(err, needle) != NULL);
        ASSERT(strstr(err, "c23-portable-release: PASS ") == NULL);
        if (strcmp(tag, "require-full fails") == 0)
            ASSERT(strstr(err, "could not write the tor stamp sidecar") == NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

int test_c23_portable_release(void);
int test_c23_portable_release(void)
{
    char root[PATH_MAX];
    int failures;
    test_make_tmpdir(root, sizeof root, "c23_portable_release", "root");
    failures = test_cpr_verify(root);
    failures += test_cpr_self_and_repo(root);
    failures += test_cpr_release(root, "release accepts one settled epoch", 0,
                                 "compiler-baseline");
    failures += test_cpr_release(root, "qemu64 is the runtime proof when present", 1,
                                 "qemu64");
    failures += test_cpr_fail(root, "epoch moves", NULL, k_id_b, NULL, 1,
                              "source epoch changed during build:");
    failures += test_cpr_fail(root, "bad-id", NULL, NULL, NULL, 1,
                              "could not capture settled source identity");
    failures += test_cpr_fail(root, "omitted bake", NULL, NULL, "{}\n", 1,
                              "node omitted its baked source identity");
    failures += test_cpr_fail(root, "vendor fails", "fail-vendor", NULL, NULL, 9,
                              "rebuilding linked archives through");
    failures += test_cpr_fail(root, "sidecar fails", "fail-sidecar", NULL, NULL, 1,
                              "could not write the tor stamp sidecar");
    failures += test_cpr_fail(root, "require-full fails", "fail-require", NULL, NULL, 1,
                              "rebuilding linked archives through");
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_c23_portable_release: all passed\n");
    else
        printf("test_c23_portable_release: %d FAILED\n", failures);
    return failures;
}
