/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Drive zcl_rom_bundle_replicate through usage, copy, and digest
 *          mismatch against a stub SHA3 tool. */

#include "test/test_core.h"

#include "rom_bundle_replicate.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int rbr_put(const char *path, const char *text, int exec_bit)
{
    FILE *fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    if (fputs(text, fp) < 0) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0)
        return -1;
    if (exec_bit && chmod(path, 0755) != 0)
        return -1;
    return 0;
}

static int rbr_read(const char *path, char *buf, size_t cap)
{
    FILE *fp = fopen(path, "r");
    size_t n;
    if (fp == NULL)
        return -1;
    n = fread(buf, 1, cap - 1, fp);
    int extra = fgetc(fp);
    int failed = ferror(fp) || extra != EOF;
    if (fclose(fp) != 0)
        failed = 1;
    buf[n] = '\0';
    return failed ? -1 : 0;
}

static int rbr_capture(const char *scratch, const char *repo, int argc, char **argv,
                       char *out, size_t out_cap, char *err, size_t err_cap)
{
    char out_path[PATH_MAX];
    char err_path[PATH_MAX];
    int saved_out = -1;
    int saved_err = -1;
    int fd_out = -1;
    int fd_err = -1;
    int rc;
    if (snprintf(out_path, sizeof out_path, "%s/stdout.txt", scratch) >= (int)sizeof out_path)
        return -1;
    if (snprintf(err_path, sizeof err_path, "%s/stderr.txt", scratch) >= (int)sizeof err_path)
        return -1;
    fflush(stdout);
    fflush(stderr);
    saved_out = dup(STDOUT_FILENO);
    saved_err = dup(STDERR_FILENO);
    fd_out = open(out_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    fd_err = open(err_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (saved_out < 0 || saved_err < 0 || fd_out < 0 || fd_err < 0)
        goto fail;
    if (dup2(fd_out, STDOUT_FILENO) < 0 || dup2(fd_err, STDERR_FILENO) < 0)
        goto fail;
    rc = zcl_rom_bundle_replicate(repo, argc, argv);
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    close(fd_out);
    close(fd_err);
    if (rbr_read(out_path, out, out_cap) != 0 || rbr_read(err_path, err, err_cap) != 0)
        return -1;
    return rc;
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

static int rbr_no_tmp(const char *dir)
{
    DIR *dp = opendir(dir);
    struct dirent *ent;
    if (dp == NULL)
        return -1;
    while ((ent = readdir(dp)) != NULL) {
        if (strstr(ent->d_name, ".tmp.") != NULL) {
            closedir(dp);
            return -1;
        }
    }
    closedir(dp);
    return 0;
}

static int rbr_sha(const char *dir)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof path, "%s/sha3", dir) >= (int)sizeof path)
        return -1;
    return rbr_put(path,
                   "#!/bin/sh\n"
                   "sz=$(wc -c < \"$1\" | tr -d ' ')\n"
                   "printf '%s  %s\\n' \"$sz\" \"$1\"\n",
                   1);
}

static int test_rbr_usage(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[1024];
    char err[1024];
    char err2[1024];
    char *help[] = {"-h", NULL};
    char *bad[] = {"--nope", NULL};
    char *none[] = {NULL};
    int rc;
    TEST("usage, an unknown option, and a missing bundle are refused") {
        ASSERT(snprintf(dir, sizeof dir, "%s/usage", root) > 0);
        ASSERT(mkdir(dir, 0700) == 0);
        rc = rbr_capture(dir, dir, 1, help, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(out, "Usage:") != NULL);
        ASSERT(strstr(out, "--bundle=PATH") != NULL);
        ASSERT_STR_EQ(err, "");
        rc = rbr_capture(dir, dir, 1, bad, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 2);
        ASSERT(strstr(err, "rom-bundle-replicate: unknown option --nope\n") == err);
        rc = rbr_capture(dir, dir, 0, none, out, sizeof out, err2, sizeof err2);
        ASSERT_EQ(rc, 2);
        ASSERT_STR_EQ(err2, "rom-bundle-replicate: --bundle=PATH is required\n");
        rc = rbr_capture(dir, dir, 0, none, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 2);
        ASSERT_STR_EQ(err, err2);
        rc = rbr_capture(dir, NULL, 0, none, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 2);
        ASSERT_STR_EQ(err, "rom-bundle-replicate: repo is required\n");
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rbr_inputs(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char bundle[PATH_MAX];
    char receipt[PATH_MAX];
    char dest[PATH_MAX];
    char opt_b[PATH_MAX];
    char opt_r[PATH_MAX];
    char opt_d[PATH_MAX];
    char out[64];
    char err[PATH_MAX];
    char *argv[5];
    int rc;
    TEST("an empty bundle and a missing SHA3 tool are refused") {
        ASSERT(snprintf(dir, sizeof dir, "%s/inputs", root) > 0);
        ASSERT(mkdir(dir, 0700) == 0);
        ASSERT(snprintf(bundle, sizeof bundle, "%s/bundle.sqlite", dir) > 0);
        ASSERT(snprintf(receipt, sizeof receipt, "%s/receipt", dir) > 0);
        ASSERT(snprintf(dest, sizeof dest, "%s/dest", dir) > 0);
        ASSERT(rbr_put(bundle, "", 0) == 0);
        ASSERT(rbr_put(receipt, "receipt-bytes\n", 0) == 0);
        ASSERT(snprintf(opt_b, sizeof opt_b, "--bundle=%s", bundle) > 0);
        ASSERT(snprintf(opt_r, sizeof opt_r, "--receipt=%s", receipt) > 0);
        ASSERT(snprintf(opt_d, sizeof opt_d, "--dest=%s", dest) > 0);
        argv[0] = opt_b;
        argv[1] = opt_r;
        argv[2] = opt_d;
        argv[3] = NULL;
        rc = rbr_capture(dir, dir, 3, argv, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 2);
        ASSERT(strstr(err, "rom-bundle-replicate: bundle not found or empty: ") == err);
        ASSERT(rbr_put(bundle, "bundle-bytes\n", 0) == 0);
        rc = rbr_capture(dir, dir, 3, argv, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 2);
        ASSERT(strstr(err, "/build/bin/rom_bundle_sha3 not built") != NULL);
        argv[3] = "--sha3-tool=";
        argv[4] = NULL;
        rc = rbr_capture(dir, dir, 4, argv, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 2);
        ASSERT_STR_EQ(err,
                      "rom-bundle-replicate:  not built (run: make tools/rom_bundle_sha3)\n");
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rbr_pass(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char bundle[PATH_MAX];
    char receipt[PATH_MAX];
    char dest[PATH_MAX];
    char sha[PATH_MAX];
    char binary[PATH_MAX];
    char copied[PATH_MAX];
    char hash_path[PATH_MAX];
    char opt_b[PATH_MAX];
    char opt_r[PATH_MAX];
    char opt_d[PATH_MAX];
    char opt_s[PATH_MAX];
    char opt_bin[PATH_MAX];
    char out[4096];
    char err[1024];
    char body[1024];
    char *argv[6];
    struct stat st;
    int rc;
    TEST("a copy matches its source and records an executable binary") {
        ASSERT(snprintf(dir, sizeof dir, "%s/pass", root) > 0);
        ASSERT(mkdir(dir, 0700) == 0);
        ASSERT(snprintf(bundle, sizeof bundle, "%s/consensus-state-bundle-1.sqlite", dir) > 0);
        ASSERT(snprintf(receipt, sizeof receipt, "%s/receipt.v1", dir) > 0);
        ASSERT(snprintf(dest, sizeof dest, "%s/dest", dir) > 0);
        ASSERT(snprintf(sha, sizeof sha, "%s/sha3", dir) > 0);
        ASSERT(snprintf(binary, sizeof binary, "%s/zclassic23", dir) > 0);
        ASSERT(rbr_put(bundle, "bundle-bytes\n", 0) == 0);
        ASSERT(rbr_put(receipt, "receipt-bytes\n", 0) == 0);
        ASSERT(rbr_put(binary, "#!/bin/sh\nexit 0\n", 1) == 0);
        ASSERT(rbr_sha(dir) == 0);
        ASSERT(snprintf(opt_b, sizeof opt_b, "--bundle=%s", bundle) > 0);
        ASSERT(snprintf(opt_r, sizeof opt_r, "--receipt=%s", receipt) > 0);
        ASSERT(snprintf(opt_d, sizeof opt_d, "--dest=%s", dest) > 0);
        ASSERT(snprintf(opt_s, sizeof opt_s, "--sha3-tool=%s", sha) > 0);
        ASSERT(snprintf(opt_bin, sizeof opt_bin, "--binary=%s", binary) > 0);
        argv[0] = opt_b;
        argv[1] = opt_r;
        argv[2] = opt_d;
        argv[3] = opt_s;
        argv[4] = opt_bin;
        argv[5] = NULL;
        rc = rbr_capture(dir, dir, 5, argv, out, sizeof out, err, sizeof err);
        test_note("rc=%d err=%s", rc, err);
        ASSERT_EQ(rc, 0);
        ASSERT_STR_EQ(err, "");
        ASSERT(strstr(out, "PASS: rom-bundle-replicate — copy verified byte-identical by SHA3-256\n") !=
               NULL);
        ASSERT(strstr(out, "[rom-bundle-replicate] source bundle  sha3: ") != NULL);
        ASSERT(snprintf(copied, sizeof copied, "%s/dest/consensus-state-bundle-1.sqlite", dir) > 0);
        ASSERT(rbr_read(copied, body, sizeof body) == 0);
        ASSERT_STR_EQ(body, "bundle-bytes\n");
        ASSERT(snprintf(copied, sizeof copied, "%s/dest/consensus_state_replay_receipt.v1", dir) > 0);
        ASSERT(rbr_read(copied, body, sizeof body) == 0);
        ASSERT_STR_EQ(body, "receipt-bytes\n");
        ASSERT(snprintf(hash_path, sizeof hash_path, "%s/dest/producing_binary_sha3.txt", dir) > 0);
        ASSERT(rbr_read(hash_path, body, sizeof body) == 0);
        ASSERT(strstr(body, "binary_path: ") != NULL);
        ASSERT(strstr(body, "bundle: consensus-state-bundle-1.sqlite\n") != NULL);
        ASSERT(strstr(body, "replicated_at_unix: ") != NULL);
        ASSERT(lstat(copied, &st) == 0);
        ASSERT(rbr_no_tmp(dest) == 0);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rbr_mismatch(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char bundle[PATH_MAX];
    char receipt[PATH_MAX];
    char dest[PATH_MAX];
    char sha[PATH_MAX];
    char opt_b[PATH_MAX];
    char opt_r[PATH_MAX];
    char opt_d[PATH_MAX];
    char opt_s[PATH_MAX];
    char opt_bin[PATH_MAX];
    char out[2048];
    char err[1024];
    char *argv[6];
    int rc;
    TEST("a dest digest that differs from the source is refused") {
        ASSERT(snprintf(dir, sizeof dir, "%s/bad", root) > 0);
        ASSERT(mkdir(dir, 0700) == 0);
        ASSERT(snprintf(bundle, sizeof bundle, "%s/bundle.sqlite", dir) > 0);
        ASSERT(snprintf(receipt, sizeof receipt, "%s/receipt", dir) > 0);
        ASSERT(snprintf(dest, sizeof dest, "%s/dest", dir) > 0);
        ASSERT(snprintf(sha, sizeof sha, "%s/sha3", dir) > 0);
        ASSERT(rbr_put(bundle, "bundle-bytes\n", 0) == 0);
        ASSERT(rbr_put(receipt, "receipt-bytes\n", 0) == 0);
        ASSERT(rbr_put(sha,
                       "#!/bin/sh\n"
                       "case \"$1\" in\n"
                       "  */dest/*) printf 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  %s\\n' \"$1\" ;;\n"
                       "  *) printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  %s\\n' \"$1\" ;;\n"
                       "esac\n",
                       1) == 0);
        ASSERT(snprintf(opt_b, sizeof opt_b, "--bundle=%s", bundle) > 0);
        ASSERT(snprintf(opt_r, sizeof opt_r, "--receipt=%s", receipt) > 0);
        ASSERT(snprintf(opt_d, sizeof opt_d, "--dest=%s", dest) > 0);
        ASSERT(snprintf(opt_s, sizeof opt_s, "--sha3-tool=%s", sha) > 0);
        ASSERT(snprintf(opt_bin, sizeof opt_bin, "--binary=/no/such/zclassic23") > 0);
        argv[0] = opt_b;
        argv[1] = opt_r;
        argv[2] = opt_d;
        argv[3] = opt_s;
        argv[4] = opt_bin;
        argv[5] = NULL;
        rc = rbr_capture(dir, dir, 5, argv, out, sizeof out, err, sizeof err);
        test_note("rc=%d err=%s", rc, err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(err, "FAIL: bundle copy digest mismatch: dest=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb want=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") != NULL);
        ASSERT(strstr(err, "FAIL: receipt copy digest mismatch:") != NULL);
        ASSERT(strstr(err, "FAIL: rom-bundle-replicate — copy not verified") != NULL);
        ASSERT(strstr(err, "producing binary not found/executable") != NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rbr_long(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char part[201];
    char leaf[201];
    char nest[PATH_MAX];
    char bundle[PATH_MAX];
    char receipt[PATH_MAX];
    char dest[PATH_MAX];
    char sha[PATH_MAX];
    char copied[PATH_MAX];
    char opt_b[PATH_MAX];
    char opt_r[PATH_MAX];
    char opt_d[PATH_MAX];
    char opt_s[PATH_MAX];
    char opt_bin[PATH_MAX];
    char out[16 * PATH_MAX];
    char err[512];
    char body[64];
    char *argv[6];
    int rc;
    TEST("a long bundle path still verifies the first digest field") {
        memset(part, 'c', 200);
        part[200] = '\0';
        memset(leaf, 'b', 180);
        leaf[180] = '\0';
        ASSERT(snprintf(dir, sizeof dir, "%s/long", root) > 0);
        ASSERT(mkdir(dir, 0700) == 0);
        ASSERT(snprintf(nest, sizeof nest, "%s/%s", dir, part) > 0);
        ASSERT(mkdir(nest, 0700) == 0);
        ASSERT(snprintf(dir, sizeof dir, "%s/%s", nest, part) > 0);
        ASSERT(mkdir(dir, 0700) == 0);
        ASSERT(snprintf(bundle, sizeof bundle, "%s/%s.sqlite", dir, leaf) > 0);
        ASSERT(snprintf(receipt, sizeof receipt, "%s/receipt", dir) > 0);
        ASSERT(snprintf(dest, sizeof dest, "%s/dest", dir) > 0);
        ASSERT(rbr_put(bundle, "long-bundle\n", 0) == 0);
        ASSERT(rbr_put(receipt, "long-receipt\n", 0) == 0);
        ASSERT(rbr_sha(dir) == 0);
        ASSERT(snprintf(sha, sizeof sha, "%s/sha3", dir) > 0);
        ASSERT(snprintf(opt_b, sizeof opt_b, "--bundle=%s", bundle) > 0);
        ASSERT(snprintf(opt_r, sizeof opt_r, "--receipt=%s", receipt) > 0);
        ASSERT(snprintf(opt_d, sizeof opt_d, "--dest=%s", dest) > 0);
        ASSERT(snprintf(opt_s, sizeof opt_s, "--sha3-tool=%s", sha) > 0);
        ASSERT(snprintf(opt_bin, sizeof opt_bin, "--binary=") > 0);
        argv[0] = opt_b;
        argv[1] = opt_r;
        argv[2] = opt_d;
        argv[3] = opt_s;
        argv[4] = opt_bin;
        argv[5] = NULL;
        rc = rbr_capture(dir, dir, 5, argv, out, sizeof out, err, sizeof err);
        test_note("rc=%d err=%s", rc, err);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(out, "PASS: rom-bundle-replicate") != NULL);
        ASSERT(snprintf(copied, sizeof copied, "%s/dest/%s.sqlite", dir, leaf) > 0);
        ASSERT(rbr_read(copied, body, sizeof body) == 0);
        ASSERT_STR_EQ(body, "long-bundle\n");
        ASSERT(rbr_no_tmp(dest) == 0);
        PASS();
    }
    _test_next:;
    return failures;
}

int test_rom_bundle_replicate(void);
int test_rom_bundle_replicate(void)
{
    char root[PATH_MAX];
    int failures = 0;
    test_make_tmpdir(root, sizeof root, "rom_bundle_replicate", "root");
    failures += test_rbr_usage(root);
    failures += test_rbr_inputs(root);
    failures += test_rbr_pass(root);
    failures += test_rbr_mismatch(root);
    failures += test_rbr_long(root);
    if (failures == 0)
        printf("test_rom_bundle_replicate: all passed\n");
    else
        printf("test_rom_bundle_replicate: %d FAILED\n", failures);
    return failures;
}
