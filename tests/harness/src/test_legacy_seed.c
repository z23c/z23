/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance bar for ops.host.legacy.seed and .status
 * (tools/command/legacy_seed*.c, legacy_status.c, native_ops_host_legacy.c).
 * Fake legacy datadirs are built here in a throwaway directory; no real
 * zclassicd runs. A "running" source is a forked child holding the datadir
 * lock, synchronised over a pipe, so nothing waits on a clock. */

#define _GNU_SOURCE

#include "test/test_core.h"

#include "command/legacy_seed.h"
#include "command/legacy_status.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "command/legacy_seed_priv.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "rpc/legacy_rpc_client.h"
#include "sha3/sha3.h"
#include "crypto/sha256.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

enum { LST_PATH = 600, LST_NFILES = 9 };

/* name, size. blk/rev 0 are immutable; pair 1 is the tail. */
static const struct { const char *rel; size_t size; } k_files[LST_NFILES] = {
    { "blocks/blk00000.dat", 300000 }, { "blocks/rev00000.dat", 90000 },
    { "blocks/blk00001.dat", 70000 },  { "blocks/rev00001.dat", 20000 },
    { "blocks/index/000005.ldb", 5000 }, { "blocks/index/CURRENT", 16 },
    { "chainstate/000007.ldb", 40000 }, { "chainstate/CURRENT", 16 },
    { "chainstate/LOCK", 0 },
};
static const char *const k_secrets[] = {
    "wallet.dat", "blocks/wallet.dat", "blocks/index/wallet.dat.bak",
    "chainstate/keys.dat", "chainstate/node.key",
};

static int64_t g_free;
static int64_t lst_free(void *ctx, const char *path)
{
    (void)ctx; (void)path;
    return g_free;
}

static bool lst_put(const char *root, const char *rel, size_t size, unsigned salt)
{
    char path[LST_PATH];
    (void)snprintf(path, sizeof(path), "%s/%s", root, rel);
    for (char *s = strchr(path + strlen(root) + 1, '/'); s; s = strchr(s + 1, '/')) {
        *s = '\0';
        (void)mkdir(path, 0700);
        *s = '/';
    }
    FILE *f = fopen(path, "wb");
    for (size_t i = 0; f && i < size; i++)
        fputc((int)((i * 31 + salt + (i >> 8)) & 0xff), f);
    return f && fclose(f) == 0;
}

static bool lst_stamp(const char *root, const char *rel, long sec)
{
    char path[LST_PATH];
    struct timespec ts[2] = { { sec, 123456789 }, { sec, 123456789 } };
    (void)snprintf(path, sizeof(path), "%s/%s", root, rel);
    return utimensat(AT_FDCWD, path, ts, 0) == 0;
}

static bool lst_build(const char *root)
{
    char dir[LST_PATH];
    (void)snprintf(dir, sizeof(dir), "%s/src", root);
    if (mkdir(dir, 0700) != 0 && access(dir, F_OK) != 0)
        return false;
    for (int i = 0; i < LST_NFILES; i++)
        if (!lst_put(dir, k_files[i].rel, k_files[i].size, (unsigned)i) ||
            !lst_stamp(dir, k_files[i].rel, 1700000000 + i))
            return false;
    for (size_t i = 0; i < sizeof(k_secrets) / sizeof(k_secrets[0]); i++)
        if (!lst_put(dir, k_secrets[i], 100, 99))
            return false;
    return lst_put(dir, ".lock", 0, 0);
}

static bool lst_same(const char *a, const char *b)
{
    FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb");
    bool same = fa && fb;
    while (same) {
        int ca = fgetc(fa), cb = fgetc(fb);
        if (ca != cb)
            same = false;
        if (ca == EOF || cb == EOF)
            break;
    }
    if (fa) fclose(fa);
    if (fb) fclose(fb);
    return same;
}

static void lst_req(struct lseed_request *req, const char *root, const char *name)
{
    lseed_request_defaults(req);
    req->margin_bytes = 0;
    (void)snprintf(req->source, sizeof(req->source), "%s/src", root);
    (void)snprintf(req->target, sizeof(req->target), "%s/%s", root, name);
}

static void lst_reset_hooks(void)
{
    memset(lseed_hooks(), 0, sizeof(struct lseed_hooks));
}

static bool lst_exists(const char *root, const char *name, const char *rel)
{
    char path[LST_PATH];
    (void)snprintf(path, sizeof(path), "%s/%s/%s", root, name, rel);
    return access(path, F_OK) == 0;
}

static bool lst_tree_identical(const char *root, const char *name)
{
    char a[LST_PATH], b[LST_PATH];
    for (int i = 0; i < LST_NFILES; i++) {
        (void)snprintf(a, sizeof(a), "%s/src/%s", root, k_files[i].rel);
        (void)snprintf(b, sizeof(b), "%s/%s/%s", root, name, k_files[i].rel);
        if (!lst_same(a, b))
            return false;
    }
    return true;
}

static bool lst_no_secrets(const char *root, const char *name)
{
    for (size_t i = 0; i < sizeof(k_secrets) / sizeof(k_secrets[0]); i++)
        if (lst_exists(root, name, k_secrets[i]))
            return false;
    return true;
}

static int lst_cmp_idx(const void *a, const void *b)
{
    return strcmp(k_files[*(const int *)a].rel, k_files[*(const int *)b].rel);
}

/* Independent manifest: sorted (path, size, sha3) lines hashed again. */
static bool lst_manifest(const char *root, const char *name, char out[65])
{
    int order[LST_NFILES];
    struct sha3_256_ctx all;
    unsigned char d[32];
    for (int i = 0; i < LST_NFILES; i++)
        order[i] = i;
    qsort(order, LST_NFILES, sizeof(int), lst_cmp_idx);
    sha3_256_init(&all);
    for (int k = 0; k < LST_NFILES; k++) {
        char path[LST_PATH], line[LST_PATH + 100], hex[65];
        unsigned char *buf = malloc(k_files[order[k]].size + 1);
        (void)snprintf(path, sizeof(path), "%s/%s/%s", root, name,
                       k_files[order[k]].rel);
        FILE *f = fopen(path, "rb");
        size_t got = f ? fread(buf, 1, k_files[order[k]].size, f) : 0;
        if (f) fclose(f);
        zcl_sha3_256(buf, got, d);
        free(buf);
        for (int i = 0; i < 32; i++)
            (void)snprintf(hex + 2 * i, 3, "%02x", d[i]);
        int n = snprintf(line, sizeof(line), "%s\t%zu\t%s\n",
                         k_files[order[k]].rel, got, hex);
        sha3_256_write(&all, (const unsigned char *)line, (size_t)n);
    }
    sha3_256_finalize(&all, d);
    for (int i = 0; i < 32; i++)
        (void)snprintf(out + 2 * i, 3, "%02x", d[i]);
    return true;
}

/* Child holding the datadir lock until killed. mode 0 fcntl, 1 flock. */
static pid_t lst_hold_lock(const char *datadir, int mode)
{
    int fds[2];
    char path[LST_PATH];
    if (pipe(fds) != 0)
        return -1;
    pid_t pid = fork();
    if (pid == 0) {
        struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_SET };
        (void)snprintf(path, sizeof(path), "%s/.lock", datadir);
        int fd = open(path, O_RDWR);
        int ok = fd >= 0 && (mode == 0 ? fcntl(fd, F_SETLK, &fl)
                                       : flock(fd, LOCK_EX | LOCK_NB)) == 0;
        char c = ok ? 'k' : 'x';
        (void)!write(fds[1], &c, 1);
        for (;;)
            pause();
    }
    char c = 0;
    close(fds[1]);
    bool ready = pid > 0 && read(fds[0], &c, 1) == 1 && c == 'k';
    close(fds[0]);
    if (!ready && pid > 0) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return -1;
    }
    return pid;
}

static void lst_release(pid_t pid)
{
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}

static int test_seed_happy(const char *root)
{
    int failures = 0;
    TEST("legacy seed: byte-identical copy, manifest sha3, no wallet or key") {
        struct lseed_request req;
        struct lseed_result res;
        struct lseed_plan plan;
        char why[256], want[65], text[2048], path[LST_PATH];
        struct stat sa, sb;
        lst_reset_hooks();
        lst_req(&req, root, "happy");
        ASSERT_EQ(lseed_preflight(&req, true, &plan, why, sizeof(why)), LSEED_OK);
        ASSERT_EQ(plan.excluded_files, (uint64_t)4); /* root wallet.dat is never even walked */
        ASSERT_EQ(plan.tail_pair, (int64_t)1);
        ASSERT_EQ(plan.immutable_files, (uint64_t)2);
        ASSERT_EQ(lseed_finish(&req, &res, why, sizeof(why)), LSEED_OK);
        ASSERT(lst_tree_identical(root, "happy"));
        ASSERT(lst_no_secrets(root, "happy"));
        ASSERT(!lst_exists(root, "happy.tmp", "."));
        ASSERT(lst_manifest(root, "happy", want));
        ASSERT_STR_EQ(res.manifest_sha3, want);
        (void)snprintf(path, sizeof(path), "%s/happy/seed-receipt.json", root);
        FILE *f = fopen(path, "r");
        ASSERT(f != NULL);
        size_t n = fread(text, 1, sizeof(text) - 1, f);
        fclose(f);
        text[n] = '\0';
        ASSERT(strstr(text, want) != NULL);
        ASSERT(strstr(text, "\"files\"") != NULL);
        (void)snprintf(path, sizeof(path), "%s/src/blocks/blk00000.dat", root);
        ASSERT_EQ(stat(path, &sa), 0);
        (void)snprintf(path, sizeof(path), "%s/happy/blocks/blk00000.dat", root);
        ASSERT_EQ(stat(path, &sb), 0);
        ASSERT_EQ((int64_t)sa.st_mtim.tv_sec, (int64_t)sb.st_mtim.tv_sec);
        ASSERT_EQ(sa.st_mtim.tv_nsec, sb.st_mtim.tv_nsec);
        PASS();
    }
_test_next:;
    return failures;
}

static int test_seed_two_phase(const char *root)
{
    int failures = 0;
    TEST("legacy seed: stage while running, finish refuses until stopped, recopies changed") {
        struct lseed_request req;
        struct lseed_result res;
        char why[256], src[LST_PATH];
        lst_reset_hooks();
        lst_req(&req, root, "twophase");
        (void)snprintf(src, sizeof(src), "%s/src", root);
        pid_t holder = lst_hold_lock(src, 0);
        ASSERT(holder > 0);
        ASSERT_EQ(lseed_stage(&req, &res, why, sizeof(why)), LSEED_OK);
        ASSERT_EQ(res.copied_files, (uint64_t)2);
        ASSERT(lst_exists(root, "twophase.tmp", "blocks/blk00000.dat"));
        ASSERT(!lst_exists(root, "twophase.tmp", "blocks/blk00001.dat"));
        ASSERT_EQ(lseed_finish(&req, &res, why, sizeof(why)), LSEED_SOURCE_RUNNING);
        lst_release(holder);
        ASSERT(lst_put(src, "blocks/blk00000.dat", 300000, 77));
        ASSERT(lst_stamp(src, "blocks/blk00000.dat", 1800000000));
        ASSERT_EQ(lseed_finish(&req, &res, why, sizeof(why)), LSEED_OK);
        ASSERT_EQ(res.resumed_files, (uint64_t)1); /* rev00000 kept, blk recopied */
        ASSERT(lst_tree_identical(root, "twophase"));
        PASS();
    }
_test_next:;
    return failures;
}

static int test_seed_lock_kinds(const char *root)
{
    int failures = 0;
    TEST("legacy seed: refuses a source held by an fcntl lock, a flock, or a pid file") {
        struct lseed_request req;
        struct lseed_plan plan;
        char why[256], src[LST_PATH], pidfile[LST_PATH + 20];
        lst_reset_hooks();
        lst_req(&req, root, "locked");
        (void)snprintf(src, sizeof(src), "%s/src", root);
        for (int mode = 0; mode < 2; mode++) {
            pid_t holder = lst_hold_lock(src, mode);
            ASSERT(holder > 0);
            ASSERT(lseed_datadir_in_use(src, NULL));
            ASSERT_EQ(lseed_preflight(&req, true, &plan, why, sizeof(why)),
                      LSEED_SOURCE_RUNNING);
            lst_release(holder);
        }
        ASSERT(!lseed_datadir_in_use(src, NULL));
        (void)snprintf(pidfile, sizeof(pidfile), "%s/zclassicd.pid", src);
        FILE *f = fopen(pidfile, "w");
        ASSERT(f != NULL);
        fprintf(f, "%ld\n", (long)getpid());
        fclose(f);
        ASSERT_EQ(lseed_preflight(&req, true, &plan, why, sizeof(why)),
                  LSEED_SOURCE_RUNNING);
        ASSERT_EQ(lseed_preflight(&req, false, &plan, why, sizeof(why)), LSEED_OK);
        ASSERT(plan.source_running);
        ASSERT_EQ(unlink(pidfile), 0);
        ASSERT(!lseed_datadir_in_use(src, NULL));
        PASS();
    }
_test_next:;
    return failures;
}

static int test_seed_refusals(const char *root)
{
    int failures = 0;
    TEST("legacy seed: path, symlink, owner, space and gap refusals") {
        struct lseed_request req;
        struct lseed_plan plan;
        char why[256], a[LST_PATH], b[LST_PATH];
        lst_reset_hooks();
        lst_req(&req, root, "refuse");
        (void)snprintf(a, sizeof(a), "%s/refuse", root);
        ASSERT_EQ(mkdir(a, 0700), 0);
        ASSERT_EQ(lseed_preflight(&req, true, &plan, why, sizeof(why)),
                  LSEED_TARGET_EXISTS);
        ASSERT_EQ(rmdir(a), 0);
        (void)snprintf(b, sizeof(b), "%s/src", root);
        ASSERT_EQ(symlink(b, a), 0); /* target is a symlink */
        ASSERT_EQ(lseed_preflight(&req, true, &plan, why, sizeof(why)),
                  LSEED_TARGET_SYMLINK);
        ASSERT_EQ(unlink(a), 0);
        /* symlinked source */
        (void)snprintf(a, sizeof(a), "%s/srclink", root);
        ASSERT_EQ(symlink(b, a), 0);
        (void)snprintf(req.source, sizeof(req.source), "%s", a);
        ASSERT_EQ(lseed_preflight(&req, true, &plan, why, sizeof(why)),
                  LSEED_SOURCE_SYMLINK);
        lst_req(&req, root, "refuse");
        /* foreign owner */
        lseed_hooks()->owner_override = true;
        lseed_hooks()->owner_uid = (uint32_t)geteuid() + 1;
        ASSERT_EQ(lseed_preflight(&req, true, &plan, why, sizeof(why)),
                  LSEED_OWNER_MISMATCH);
        lst_reset_hooks();
        /* free space */
        lseed_hooks()->free_bytes = lst_free;
        g_free = 1000;
        ASSERT_EQ(lseed_preflight(&req, true, &plan, why, sizeof(why)),
                  LSEED_INSUFFICIENT_SPACE);
        g_free = -1;
        ASSERT_EQ(lseed_preflight(&req, true, &plan, why, sizeof(why)),
                  LSEED_INSUFFICIENT_SPACE);
        g_free = (int64_t)1 << 40;
        ASSERT_EQ(lseed_preflight(&req, true, &plan, why, sizeof(why)), LSEED_OK);
        lst_reset_hooks();
        /* gap */
        req.source_height = 100;
        req.z23_height = 103;
        ASSERT_EQ(lseed_preflight(&req, true, &plan, why, sizeof(why)),
                  LSEED_GAP_EXCEEDED);
        req.z23_height = 102;
        ASSERT_EQ(lseed_preflight(&req, true, &plan, why, sizeof(why)), LSEED_OK);
        req.z23_height = -1;
        ASSERT_EQ(lseed_preflight(&req, true, &plan, why, sizeof(why)), LSEED_OK);
        (void)snprintf(req.target, sizeof(req.target), "relative/path");
        ASSERT_EQ(lseed_preflight(&req, true, &plan, why, sizeof(why)),
                  LSEED_BAD_INPUT);
        PASS();
    }
_test_next:;
    return failures;
}

static int test_seed_symlink_in_tree(const char *root)
{
    int failures = 0;
    TEST("legacy seed: a symlinked file or directory inside blocks/ is refused") {
        struct lseed_request req;
        struct lseed_plan plan;
        char why[256], link[LST_PATH], dest[LST_PATH];
        lst_reset_hooks();
        lst_req(&req, root, "symtree");
        (void)snprintf(dest, sizeof(dest), "%s/src/blocks/blk00000.dat", root);
        (void)snprintf(link, sizeof(link), "%s/src/blocks/blk00002.dat", root);
        ASSERT_EQ(symlink(dest, link), 0);
        ASSERT_EQ(lseed_preflight(&req, false, &plan, why, sizeof(why)),
                  LSEED_SYMLINK_IN_TREE);
        ASSERT_EQ(unlink(link), 0);
        (void)snprintf(dest, sizeof(dest), "%s/src/blocks/index", root);
        (void)snprintf(link, sizeof(link), "%s/src/blocks/idxlink", root);
        ASSERT_EQ(symlink(dest, link), 0);
        ASSERT_EQ(lseed_preflight(&req, false, &plan, why, sizeof(why)),
                  LSEED_SYMLINK_IN_TREE);
        ASSERT_EQ(unlink(link), 0);
        ASSERT_EQ(lseed_preflight(&req, false, &plan, why, sizeof(why)), LSEED_OK);
        PASS();
    }
_test_next:;
    return failures;
}

static int test_seed_crash(const char *root)
{
    int failures = 0;
    TEST("legacy seed: a mid-copy failure leaves no target; rerun after cleanup succeeds") {
        struct lseed_request req;
        struct lseed_result res;
        char why[256], tmp[LST_PATH];
        lst_reset_hooks();
        lst_req(&req, root, "crash");
        req.workers = 1;
        lseed_hooks()->fail_after_files = 3;
        ASSERT_EQ(lseed_finish(&req, &res, why, sizeof(why)), LSEED_COPY_FAILED);
        ASSERT(!lst_exists(root, "crash", "."));
        ASSERT(lst_exists(root, "crash.tmp", LSEED_MARKER_NAME));
        (void)snprintf(tmp, sizeof(tmp), "%s/crash.tmp", root);
        ASSERT_EQ(test_rm_rf_recursive(tmp), 0);
        ASSERT_EQ(lseed_finish(&req, &res, why, sizeof(why)), LSEED_COPY_FAILED);
        ASSERT(!lst_exists(root, "crash", "."));
        lst_reset_hooks();
        ASSERT_EQ(lseed_finish(&req, &res, why, sizeof(why)), LSEED_OK); /* resumes */
        ASSERT(res.resumed_files > 0);
        ASSERT(lst_tree_identical(root, "crash"));
        ASSERT(lst_no_secrets(root, "crash"));
        PASS();
    }
    TEST("legacy seed: a target.tmp from another source is never reused") {
        struct lseed_request req;
        struct lseed_plan plan;
        char why[256], path[LST_PATH];
        lst_reset_hooks();
        lst_req(&req, root, "foreign");
        (void)snprintf(path, sizeof(path), "%s/foreign.tmp", root);
        ASSERT_EQ(mkdir(path, 0700), 0);
        ASSERT(lst_put(path, LSEED_MARKER_NAME, 5, 1));
        ASSERT_EQ(lseed_preflight(&req, false, &plan, why, sizeof(why)),
                  LSEED_TMP_MISMATCH);
        PASS();
    }
_test_next:;
    return failures;
}

static int test_seed_copy_modes(const char *root)
{
    int failures = 0;
    TEST("legacy seed: read/write and copy_file_range paths copy identically") {
        const char *names[] = { "mode_rw", "mode_cfr", "mode_auto" };
        for (int m = 0; m < 3; m++) {
            struct lseed_request req;
            struct lseed_result res;
            char why[256];
            lst_reset_hooks();
            lst_req(&req, root, names[m]);
            lseed_hooks()->copy_mode = m == 2 ? 0 : m + 1;
            ASSERT_EQ(lseed_finish(&req, &res, why, sizeof(why)), LSEED_OK);
            ASSERT(lst_tree_identical(root, names[m]));
            ASSERT(lst_no_secrets(root, names[m]));
            if (m < 2)
                ASSERT_EQ(res.cloned_files, (uint64_t)0);
        }
        PASS();
    }
_test_next:;
    return failures;
}

static struct json_value *lst_parse(const char *text, struct json_value *doc)
{
    json_init(doc);
    return json_read(doc, text, strlen(text)) ? doc : NULL;
}

static bool lst_call(void (*fn)(const struct zcl_command_request *,
                                struct zcl_command_reply *),
                     const char *text, struct zcl_command_reply *reply)
{
    struct json_value doc;
    bool ok = lst_parse(text, &doc) != NULL;
    struct zcl_command_request request = { .input = &doc };
    zcl_command_reply_init(reply, "zcl.test.v1");
    if (ok)
        fn(&request, reply);
    json_free(&doc);
    return ok;
}

static int test_seed_handler(const char *root)
{
    int failures = 0;
    TEST("legacy seed leaf: plan, then confirm and plan_id gate stage and finish") {
        struct zcl_command_reply r;
        char in[2 * LST_PATH + 200], plan_id[65];
        lst_reset_hooks();
        (void)snprintf(in, sizeof(in),
                       "{\"source\":\"%s/src\",\"target\":\"%s/leaf\","
                       "\"margin_mib\":0}", root, root);
        ASSERT(lst_call(zcl_native_handle_ops_host_legacy_seed, in, &r));
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
        (void)snprintf(plan_id, sizeof(plan_id), "%s",
                       json_get_str(json_get(&r.data, "plan_id")));
        zcl_command_reply_free(&r);
        (void)snprintf(in, sizeof(in),
                       "{\"source\":\"%s/src\",\"target\":\"%s/leaf\","
                       "\"margin_mib\":0,\"step\":\"finish\"}", root, root);
        ASSERT(lst_call(zcl_native_handle_ops_host_legacy_seed, in, &r));
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_FAILED);
        zcl_command_reply_free(&r);
        ASSERT(!lst_exists(root, "leaf", "."));
        (void)snprintf(in, sizeof(in),
                       "{\"source\":\"%s/src\",\"target\":\"%s/leaf\","
                       "\"margin_mib\":0,\"step\":\"finish\",\"confirm\":true,"
                       "\"plan_id\":\"%064d\"}", root, root, 0);
        ASSERT(lst_call(zcl_native_handle_ops_host_legacy_seed, in, &r));
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_FAILED);
        zcl_command_reply_free(&r);
        ASSERT(!lst_exists(root, "leaf", "."));
        (void)snprintf(in, sizeof(in),
                       "{\"source\":\"%s/src\",\"target\":\"%s/leaf\","
                       "\"margin_mib\":0,\"step\":\"finish\",\"confirm\":true,"
                       "\"plan_id\":\"%s\"}", root, root, plan_id);
        ASSERT(lst_call(zcl_native_handle_ops_host_legacy_seed, in, &r));
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get(&r.data, "downtime_ms") != NULL);
        zcl_command_reply_free(&r);
        ASSERT(lst_tree_identical(root, "leaf"));
        PASS();
    }
_test_next:;
    return failures;
}

static int test_status(const char *root)
{
    int failures = 0;
    TEST("legacy status: identity match, mismatch, missing, unpinned") {
        char bin[LST_PATH], pin[65], actual[65];
        unsigned char dg[32];
        const char body[] = "fake zclassicd v2.1.2-beta6";
        (void)snprintf(bin, sizeof(bin), "%s/zclassicd", root);
        FILE *f = fopen(bin, "wb");
        ASSERT(f != NULL);
        fwrite(body, 1, sizeof(body) - 1, f);
        fclose(f);
        {
            struct sha256_ctx c;
            sha256_init(&c);
            sha256_write(&c, (const unsigned char *)body, sizeof(body) - 1);
            sha256_finalize(&c, dg);
            for (int i = 0; i < 32; i++)
                (void)snprintf(pin + 2 * i, 3, "%02x", dg[i]);
        }
        ASSERT_EQ(lstat_identity(bin, pin, actual), LSTAT_ID_MATCH);
        ASSERT_STR_EQ(actual, pin);
        pin[0] = pin[0] == '0' ? '1' : '0';
        ASSERT_EQ(lstat_identity(bin, pin, actual), LSTAT_ID_MISMATCH);
        ASSERT_EQ(lstat_identity(bin, "", actual), LSTAT_ID_UNPINNED);
        ASSERT_EQ(lstat_identity("/nonexistent/zclassicd", pin, actual),
                  LSTAT_ID_MISSING);
        PASS();
    }
    TEST("legacy status leaf: identity_only exits non-zero on a mismatch") {
        struct zcl_command_reply r;
        char in[2 * LST_PATH];
        (void)snprintf(in, sizeof(in),
                       "{\"identity_only\":true,\"binary\":\"%s/zclassicd\","
                       "\"sha256\":\"%064d\"}", root, 1);
        ASSERT(lst_call(zcl_native_handle_ops_host_legacy_status, in, &r));
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT(r.exit_code != ZCL_COMMAND_EXIT_OK);
        zcl_command_reply_free(&r);
        PASS();
    }
    TEST("legacy status: port conflicts and catch-up rate") {
        struct lstat_inst inst[3] = {
            { "oracle", 8034, 8232 }, { "bootstrap", 8035, 8233 },
            { "stray", 8034, 9000 },
        };
        char rows[8][LSTAT_CONFLICT_MAX];
        ASSERT_EQ(lstat_port_conflicts(inst, 2, rows, 8), (size_t)0);
        ASSERT_EQ(lstat_port_conflicts(inst, 3, rows, 8), (size_t)1);
        ASSERT_STR_EQ(rows[0], "oracle.port==stray.port:8034");
        inst[2].port = 8233; /* collides with bootstrap rpcport */
        inst[2].rpcport = 8035; /* and with bootstrap port */
        ASSERT_EQ(lstat_port_conflicts(inst, 3, rows, 8), (size_t)2);
        struct lstat_rate r = lstat_rate(100, 1000, 160, 1600, 40);
        ASSERT(r.known && r.eta_known);
        ASSERT_EQ(r.blocks_per_min_x100, (int64_t)600);
        ASSERT_EQ(r.eta_seconds, (int64_t)400);
        ASSERT(!lstat_rate(-1, 0, 5, 10, 3).known);
        ASSERT(!lstat_rate(100, 1000, 90, 1600, 3).known);
        r = lstat_rate(100, 1000, 100, 1600, 5);
        ASSERT(r.known && !r.eta_known);
        PASS();
    }
_test_next:;
    return failures;
}

static bool lst_conf(const char *path, const char *user, const char *pass)
{
    FILE *f = fopen(path, "w");
    if (f)
        fprintf(f, "# test\nrpcuser=%s\nrpcpassword=%s\nrpcport=8232\n", user, pass);
    return f && fclose(f) == 0;
}


static bool lst_mode_conf(const char *path, const char *user, const char *pass,
                          mode_t mode)
{
    return lst_conf(path, user, pass) && chmod(path, mode) == 0;
}

static int test_mirror_creds(const char *root)
{
    int failures = 0;
    TEST("legacy status: mirror creds compare the node's effective conf with each instance") {
        char inst[LST_PATH], node[LST_PATH], home[LST_PATH], dflt[LST_PATH];
        char eff[LST_PATH], u[64], p[128];
        char *old_home = getenv("HOME") ? strdup(getenv("HOME")) : NULL;
        (void)snprintf(inst, sizeof(inst), "%s/src/zclassic.conf", root);
        (void)snprintf(node, sizeof(node), "%s/node.conf", root);
        (void)snprintf(home, sizeof(home), "%s/home", root);
        (void)snprintf(dflt, sizeof(dflt), "%s/home/.zclassic", root);
        ASSERT(mkdir(home, 0700) == 0 && mkdir(dflt, 0700) == 0);
        (void)snprintf(dflt, sizeof(dflt), "%s/home/.zclassic/zclassic.conf", root);
        ASSERT(lst_mode_conf(inst, "oracleuser", "oraclepass", 0600));
        ASSERT(lst_mode_conf(node, "oracleuser", "oraclepass", 0600));
        ASSERT(lst_mode_conf(dflt, "otheruser", "otherpass", 0600));
        setenv("HOME", home, 1);
        unsetenv("ZCL_LEGACY_ORACLE_CONF");
        /* unset: the default path is the effective source */
        ASSERT_STR_EQ(lstat_node_conf("", eff, sizeof(eff)), "default");
        ASSERT_STR_EQ(eff, dflt);
        ASSERT(legacy_rpc_parse_conf(u, sizeof(u), p, sizeof(p), NULL));
        ASSERT_STR_EQ(u, "otheruser");
        ASSERT_EQ(lstat_mirror_creds(eff, inst), LSTAT_CREDS_MISMATCH);
        /* set: the env file is the effective source and now authenticates */
        setenv("ZCL_LEGACY_ORACLE_CONF", node, 1);
        ASSERT_STR_EQ(lstat_node_conf("", eff, sizeof(eff)), "env");
        ASSERT_STR_EQ(eff, node);
        ASSERT(legacy_rpc_parse_conf(u, sizeof(u), p, sizeof(p), NULL));
        ASSERT_STR_EQ(u, "oracleuser");
        ASSERT_EQ(lstat_mirror_creds(eff, inst), LSTAT_CREDS_MATCH);
        /* set but differing from the instance: still detectable */
        ASSERT(lst_mode_conf(node, "oracleuser", "changed", 0600));
        ASSERT_EQ(lstat_mirror_creds(eff, inst), LSTAT_CREDS_MISMATCH);
        /* the caller names what the running node reads */
        ASSERT_STR_EQ(lstat_node_conf(dflt, eff, sizeof(eff)), "input");
        ASSERT_STR_EQ(eff, dflt);
        ASSERT_EQ(lstat_mirror_creds(eff, "/nonexistent/zclassic.conf"),
                  LSTAT_CREDS_UNKNOWN);
        unsetenv("ZCL_LEGACY_ORACLE_CONF");
        if (old_home) {
            setenv("HOME", old_home, 1);
            free(old_home);
        }
        PASS();
    }
    TEST("legacy oracle conf: a symlinked, group-writable or foreign file is not read") {
        char conf[LST_PATH], link[LST_PATH], u[64], p[128];
        (void)snprintf(conf, sizeof(conf), "%s/trusted.conf", root);
        (void)snprintf(link, sizeof(link), "%s/trusted.link", root);
        ASSERT(lst_mode_conf(conf, "cu", "cp", 0600));
        ASSERT_EQ(symlink(conf, link), 0);
        setenv("ZCL_LEGACY_ORACLE_CONF", conf, 1);
        ASSERT(legacy_rpc_parse_conf(u, sizeof(u), p, sizeof(p), NULL));
        ASSERT_STR_EQ(u, "cu");
        setenv("ZCL_LEGACY_ORACLE_CONF", link, 1);
        ASSERT(!legacy_rpc_parse_conf(u, sizeof(u), p, sizeof(p), NULL));
        setenv("ZCL_LEGACY_ORACLE_CONF", conf, 1);
        ASSERT_EQ(chmod(conf, 0620), 0);
        ASSERT(!legacy_rpc_parse_conf(u, sizeof(u), p, sizeof(p), NULL));
        ASSERT_EQ(chmod(conf, 0602), 0);
        ASSERT(!legacy_rpc_parse_conf(u, sizeof(u), p, sizeof(p), NULL));
        ASSERT_EQ(chmod(conf, 0644), 0);
        ASSERT(legacy_rpc_parse_conf(u, sizeof(u), p, sizeof(p), NULL));
        unsetenv("ZCL_LEGACY_ORACLE_CONF");
        PASS();
    }
    TEST("legacy status leaf: reports the effective conf, same-file and mismatch") {
        struct zcl_command_reply r;
        char in[4 * LST_PATH], inst[LST_PATH], other[LST_PATH];
        (void)snprintf(inst, sizeof(inst), "%s/src/zclassic.conf", root);
        (void)snprintf(other, sizeof(other), "%s/other.conf", root);
        ASSERT(lst_mode_conf(inst, "iu", "ip", 0600));
        ASSERT(lst_mode_conf(other, "ou", "op", 0600));
        for (int same = 0; same < 2; same++) {
            const struct json_value *row;
            (void)snprintf(in, sizeof(in),
                           "{\"rpc\":false,\"node_conf\":\"%s\",\"instances\":["
                           "{\"name\":\"oracle\",\"datadir\":\"%s/src\"}]}",
                           same ? inst : other, root);
            ASSERT(lst_call(zcl_native_handle_ops_host_legacy_status, in, &r));
            ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
            row = json_at(json_get(&r.data, "instances"), 0);
            ASSERT_STR_EQ(json_get_str(json_get(row, "mirror_creds")),
                          same ? "match" : "mismatch");
            ASSERT_EQ(json_get_bool(json_get(row, "mirror_conf_is_instance_conf")),
                      same ? true : false);
            ASSERT_STR_EQ(json_get_str(json_get(row, "mirror_conf_source")), "input");
            ASSERT_EQ(json_get(row, "mirror_creds_mismatch") != NULL, same ? false : true);
            zcl_command_reply_free(&r);
        }
        PASS();
    }
_test_next:;
    return failures;
}

static int test_seed_plan_binding(const char *root)
{
    int failures = 0;
    TEST("legacy seed: the plan id binds heights, workers, margin and the source identity") {
        struct lseed_request a, b;
        char ida[65], idb[65], moved[LST_PATH], src[LST_PATH];
        lst_req(&a, root, "bind");
        lseed_plan_id(&a, ida);
        b = a; b.source_height = 7; lseed_plan_id(&b, idb);
        ASSERT(strcmp(ida, idb) != 0);
        b = a; b.z23_height = 9; lseed_plan_id(&b, idb);
        ASSERT(strcmp(ida, idb) != 0);
        b = a; b.workers = 2; lseed_plan_id(&b, idb);
        ASSERT(strcmp(ida, idb) != 0);
        b = a; b.margin_bytes = 5; lseed_plan_id(&b, idb);
        ASSERT(strcmp(ida, idb) != 0);
        b = a; b.max_gap = 9; lseed_plan_id(&b, idb);
        ASSERT(strcmp(ida, idb) != 0);
        b = a; lseed_plan_id(&b, idb);
        ASSERT_STR_EQ(ida, idb);
        /* a replaced source directory is a different plan */
        (void)snprintf(src, sizeof(src), "%s/src", root);
        (void)snprintf(moved, sizeof(moved), "%s/src.moved", root);
        ASSERT_EQ(rename(src, moved), 0);
        ASSERT(lst_build(root));
        lseed_plan_id(&a, idb);
        ASSERT(strcmp(ida, idb) != 0);
        PASS();
    }
    TEST("legacy seed leaf: a stale plan (changed inputs) is refused before any copy") {
        struct zcl_command_reply r;
        char in[2 * LST_PATH + 300], plan_id[65];
        lst_reset_hooks();
        (void)snprintf(in, sizeof(in),
                       "{\"source\":\"%s/src\",\"target\":\"%s/stale\","
                       "\"margin_mib\":0,\"workers\":2}", root, root);
        ASSERT(lst_call(zcl_native_handle_ops_host_legacy_seed, in, &r));
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
        (void)snprintf(plan_id, sizeof(plan_id), "%s",
                       json_get_str(json_get(&r.data, "plan_id")));
        zcl_command_reply_free(&r);
        (void)snprintf(in, sizeof(in),
                       "{\"source\":\"%s/src\",\"target\":\"%s/stale\","
                       "\"margin_mib\":0,\"workers\":3,\"step\":\"finish\","
                       "\"confirm\":true,\"plan_id\":\"%s\"}", root, root, plan_id);
        ASSERT(lst_call(zcl_native_handle_ops_host_legacy_seed, in, &r));
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_FAILED);
        zcl_command_reply_free(&r);
        ASSERT(!lst_exists(root, "stale", "."));
        ASSERT(!lst_exists(root, "stale.tmp", "."));
        PASS();
    }
_test_next:;
    return failures;
}

static int test_seed_lock_missing(const char *root)
{
    int failures = 0;
    TEST("legacy seed: finish refuses a source with no .lock; stage still runs") {
        struct lseed_request req;
        struct lseed_result res;
        char why[256], lock[LST_PATH], off[LST_PATH];
        lst_reset_hooks();
        lst_req(&req, root, "nolock");
        (void)snprintf(lock, sizeof(lock), "%s/src/.lock", root);
        (void)snprintf(off, sizeof(off), "%s/src/.lock.off", root);
        ASSERT_EQ(rename(lock, off), 0);
        ASSERT_EQ(lseed_finish(&req, &res, why, sizeof(why)), LSEED_SOURCE_LOCK_MISSING);
        ASSERT(!lst_exists(root, "nolock", "."));
        ASSERT_EQ(lseed_stage(&req, &res, why, sizeof(why)), LSEED_OK);
        ASSERT_EQ(rename(off, lock), 0);
        PASS();
    }
_test_next:;
    return failures;
}

static int test_seed_swapped_dir(void)
{
    int failures = 0;
    TEST("legacy seed: a subdirectory swapped for a symlink after the walk is refused") {
        char root[LST_PATH] = "", p[LST_PATH], q[LST_PATH], why[256];
        struct lseed_tree tree;
        struct lseed_counts counts = { 0 };
        int src, dst;
        ASSERT(test_mkdtemp(root, sizeof(root), "legacy_swap") && lst_build(root));
        (void)snprintf(p, sizeof(p), "%s/src", root);
        src = open(p, O_RDONLY | O_DIRECTORY);
        (void)snprintf(p, sizeof(p), "%s/dst", root);
        ASSERT_EQ(mkdir(p, 0700), 0);
        dst = open(p, O_RDONLY | O_DIRECTORY);
        ASSERT(src >= 0 && dst >= 0);
        ASSERT_EQ(lseed_walk(src, &tree, why, sizeof(why)), LSEED_OK);
        /* swap blocks/index for a symlink to a decoy holding the same names */
        (void)snprintf(p, sizeof(p), "%s/decoy", root);
        ASSERT_EQ(mkdir(p, 0700), 0);
        ASSERT(lst_put(p, "000005.ldb", 5000, 42));
        ASSERT(lst_put(p, "CURRENT", 16, 43));
        (void)snprintf(p, sizeof(p), "%s/src/blocks/index", root);
        (void)snprintf(q, sizeof(q), "%s/src/blocks/index.real", root);
        ASSERT_EQ(rename(p, q), 0);
        (void)snprintf(q, sizeof(q), "%s/decoy", root);
        ASSERT_EQ(symlink(q, p), 0);
        ASSERT_EQ(lseed_copy_tree(src, dst, &tree, lseed_want_all, 1, &counts,
                                  why, sizeof(why)), LSEED_COPY_FAILED);
        (void)snprintf(p, sizeof(p), "%s/dst/blocks/index/000005.ldb", root);
        ASSERT(access(p, F_OK) != 0); /* nothing came through the symlink */
        lseed_tree_free(&tree);
        close(src);
        close(dst);
        (void)test_rm_rf_recursive(root);
        PASS();
    }
_test_next:;
    return failures;
}

static int test_registry_dispatch(const char *root)
{
    int failures = 0;
    TEST("legacy leaves: typed inputs pass the registry validator and dispatch") {
        const struct zcl_command_registry *reg = zcl_command_catalog();
        const struct zcl_command_spec *seed =
            reg ? zcl_command_registry_find(reg, "ops.host.legacy.seed", NULL) : NULL;
        const struct zcl_command_spec *status =
            reg ? zcl_command_registry_find(reg, "ops.host.legacy.status", NULL) : NULL;
        struct json_value doc;
        char why[256], text[2 * LST_PATH + 400], out[ZCL_COMMAND_RESULT_BUDGET + 1];
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        ASSERT(seed != NULL && status != NULL);
        (void)snprintf(text, sizeof(text),
                       "{\"source\":\"%s/src\",\"target\":\"%s/viareg\","
                       "\"max_gap\":2,\"workers\":4,\"margin_mib\":0,"
                       "\"source_height\":10,\"z23_height\":11}", root, root);
        ASSERT(lst_parse(text, &doc) != NULL);
        ASSERT(zcl_command_registry_input_validate(seed, &doc, why, sizeof(why)));
        ASSERT(zcl_command_registry_execute_json(reg, seed, NULL, &doc, false,
               "ops.host.legacy.seed", "full", 0, 0, NULL, out, sizeof(out),
               &code) > 0);
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"plan_id\"") != NULL);
        json_free(&doc);
        (void)snprintf(text, sizeof(text),
                       "{\"source\":\"%s/src\",\"target\":\"%s/viareg\","
                       "\"workers\":99}", root, root);
        ASSERT(lst_parse(text, &doc) != NULL);
        ASSERT(!zcl_command_registry_input_validate(seed, &doc, why, sizeof(why)));
        json_free(&doc);
        (void)snprintf(text, sizeof(text),
                       "{\"rpc\":false,\"z23_rpcport\":18232,\"z23_height\":5,"
                       "\"now_unix\":1000,\"instances\":[{\"name\":\"a\","
                       "\"datadir\":\"%s/src\",\"port\":8034,\"rpcport\":8232}]}",
                       root);
        ASSERT(lst_parse(text, &doc) != NULL);
        ASSERT(zcl_command_registry_input_validate(status, &doc, why, sizeof(why)));
        ASSERT(zcl_command_registry_execute_json(reg, status, NULL, &doc, false,
               "ops.host.legacy.status", "full", 0, 0, NULL, out, sizeof(out),
               &code) > 0);
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        json_free(&doc);
        PASS();
    }
_test_next:;
    return failures;
}

static char *lst_fake_rpc(const char *datadir, int rpcport, const char *method)
{
    (void)datadir;
    if (strcmp(method, "getconnectioncount") == 0)
        return strdup(rpcport == 8233 ? "{\"result\":0,\"error\":null}"
                                      : "{\"result\":8,\"error\":null}");
    return strdup(rpcport == 8233 ? "{\"result\":{\"blocks\":90,\"headers\":90}}"
                                  : "{\"result\":{\"blocks\":100,\"headers\":100}}");
}

static int test_no_peers(const char *root)
{
    int failures = 0;
    TEST("legacy status: no_peers is flagged for a behind or stalled node with 0 connections") {
        ASSERT(lstat_no_peers(0, 90, 100, -1));
        ASSERT(!lstat_no_peers(3, 90, 100, -1));
        ASSERT(!lstat_no_peers(0, 100, 100, -1));
        ASSERT(lstat_no_peers(0, 100, 100, 100)); /* not advancing */
        ASSERT(!lstat_no_peers(0, 101, 101, 100));
        PASS();
    }
    TEST("legacy status leaf: reports connections per instance through the RPC seam") {
        struct zcl_command_reply r;
        char in[4 * LST_PATH], d1[LST_PATH], d2[LST_PATH], pid[LST_PATH + 24];
        for (int i = 0; i < 2; i++) {
            char *d = i ? d2 : d1;
            (void)snprintf(d, LST_PATH, "%s/peers%d", root, i);
            ASSERT_EQ(mkdir(d, 0700), 0);
            (void)snprintf(pid, sizeof(pid), "%s/zclassicd.pid", d);
            FILE *f = fopen(pid, "w"); /* a live pid marks the datadir running */
            ASSERT(f != NULL);
            fprintf(f, "%ld\n", (long)getpid());
            fclose(f);
        }
        zcl_native_legacy_status_set_rpc(lst_fake_rpc);
        (void)snprintf(in, sizeof(in),
                       "{\"instances\":[{\"name\":\"oracle\",\"datadir\":\"%s\","
                       "\"rpcport\":8232},{\"name\":\"boot\",\"datadir\":\"%s\","
                       "\"rpcport\":8233}],\"z23_height\":100}", d1, d2);
        ASSERT(lst_call(zcl_native_handle_ops_host_legacy_status, in, &r));
        zcl_native_legacy_status_set_rpc(NULL);
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
        const struct json_value *rows = json_get(&r.data, "instances");
        ASSERT_EQ(json_get_int(json_get(json_at(rows, 0), "connections")), (int64_t)8);
        ASSERT(json_get(json_at(rows, 0), "no_peers") == NULL);
        ASSERT_EQ(json_get_int(json_get(json_at(rows, 1), "connections")), (int64_t)0);
        ASSERT_EQ(json_get_int(json_get(json_at(rows, 1), "gap")), (int64_t)10);
        ASSERT(json_get_bool(json_get(json_at(rows, 1), "no_peers")));
        zcl_command_reply_free(&r);
        PASS();
    }
_test_next:;
    return failures;
}

int test_legacy_seed(void)
{
    int failures = 0;
    char root[LST_PATH] = "";
    if (!test_mkdtemp(root, sizeof(root), "legacy_seed") || !lst_build(root)) {
        printf("test_legacy_seed: fixture failed\n");
        return 1;
    }
    failures += test_seed_happy(root);
    failures += test_seed_two_phase(root);
    failures += test_seed_lock_kinds(root);
    failures += test_seed_refusals(root);
    failures += test_seed_symlink_in_tree(root);
    failures += test_seed_crash(root);
    failures += test_seed_copy_modes(root);
    failures += test_seed_handler(root);
    failures += test_status(root);
    failures += test_mirror_creds(root);
    failures += test_registry_dispatch(root);
    failures += test_no_peers(root);
    failures += test_seed_lock_missing(root);
    failures += test_seed_swapped_dir();
    failures += test_seed_plan_binding(root);
    lst_reset_hooks();
    (void)test_rm_rf_recursive(root);
    printf(failures == 0 ? "test_legacy_seed: all passed\n"
                         : "test_legacy_seed: FAILED\n");
    return failures;
}
