/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for the declaration-identity consumer against the live
 * producer and the live compiler: the libclang sensor
 * (build/bin/z23-clang-manifest emit --facts) and cc run on every TU of
 * every edit in tests/harness/src/semantic_consumer_fixture.c.
 *
 *   verdicts    on the live manifests the consumer names exactly the
 *               affected TUs, reasons and obligation fallback the edit table
 *               names, so the checked-in fixtures the semantic_consumer group
 *               reads are representative.
 *   objects     every TU the consumer calls unaffected, or leaves out of its
 *               universe, compiles (-std=c23 -Og -g1, the dev flags' shape)
 *               to the same object bytes before and after the edit: a TU
 *               whose object changed but was not predicted is a MISSED
 *               DEPENDENCY and fails. Predicted TUs whose object did not
 *               change are counted and printed (the conservative margin).
 *
 * Self-skips, visibly, where the sensor has not been built
 * (`make clang-manifest`). ZCL_SEMANTIC_CONSUMER_FIXTURE_OUT=<dir> copies
 * each live manifest there as <dir>/<variant>/<tu>.zsm (fixture refresh).
 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"

#include "base/safe_alloc.h"
#include "test/semantic_consumer_fixture.h"
#include "test/semantic_facts_fixture.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define SCL_SENSOR "build/bin/z23-clang-manifest"
#define SCL_ARGV_MAX 32

struct scl_run {
    char out[PATH_MAX];  /* manifests, objects and logs */
    char root[PATH_MAX]; /* the tree every variant is written into */
    uint8_t *m[SCX_VARIANT_COUNT][SCX_TU_COUNT];
    size_t n[SCX_VARIANT_COUNT][SCX_TU_COUNT];
    size_t over; /* predicted affected, object unchanged */
};

static int scl_spawn(const char *const *argv, const char *log)
{
    pid_t pid = fork();
    int status = 0;
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int fd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            (void)dup2(fd, STDOUT_FILENO);
            (void)dup2(fd, STDERR_FILENO);
            (void)close(fd);
        }
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

static const char *scl_base(const char *tu)
{
    return strrchr(tu, '/') + 1;
}

static void scl_file(char *buf, size_t n, const struct scl_run *r,
                     enum scx_variant v, size_t tu, const char *ext)
{
    (void)snprintf(buf, n, "%s/%s/%s.%s", r->out, k_scx_edits[v].name,
                   scl_base(k_scx_tus[tu]), ext);
}

static bool scl_sensor(const struct scl_run *r, enum scx_variant v, size_t tu)
{
    char out[PATH_MAX], log[PATH_MAX];
    const char *argv[SCL_ARGV_MAX];
    size_t k = 0;
    scl_file(out, sizeof(out), r, v, tu, "zsm");
    scl_file(log, sizeof(log), r, v, tu, "sensor.log");
    argv[k++] = SCL_SENSOR;
    argv[k++] = "emit";
    argv[k++] = "--root";
    argv[k++] = r->root;
    argv[k++] = "--source";
    argv[k++] = k_scx_tus[tu];
    argv[k++] = "--out";
    argv[k++] = out;
    argv[k++] = "--facts";
    argv[k++] = "--cc";
    argv[k++] = SCX_OBJECT_CC;
    argv[k++] = "--toolchain-id";
    argv[k++] = SCX_TOOLCHAIN_ID;
    if (k_scx_edits[v].truncate != NULL &&
        strcmp(k_scx_edits[v].truncate, k_scx_tus[tu]) == 0) {
        argv[k++] = "--max-records"; /* the cap cuts a section */
        argv[k++] = "4";
    }
    argv[k++] = "--";
    if (k_scx_edits[v].extra_flag != NULL)
        argv[k++] = k_scx_edits[v].extra_flag;
    for (size_t i = 0; i < k_scx_nflags; i++)
        argv[k++] = scx_flag(v, i);
    argv[k] = NULL;
    return scl_spawn(argv, log) == 0;
}

/* cc on the same tree and flags, include path made absolute, the root
 * mapped away so the object names no scratch directory. */
static bool scl_compile(const struct scl_run *r, enum scx_variant v, size_t tu)
{
    char out[PATH_MAX], log[PATH_MAX], src[PATH_MAX], inc[PATH_MAX + 32],
        map[PATH_MAX + 32];
    const char *argv[SCL_ARGV_MAX];
    size_t k = 0;
    scl_file(out, sizeof(out), r, v, tu, "o");
    scl_file(log, sizeof(log), r, v, tu, "cc.log");
    (void)snprintf(src, sizeof(src), "%s/%s", r->root, k_scx_tus[tu]);
    (void)snprintf(inc, sizeof(inc), "-I%s/" SCX_DIR "/include", r->root);
    (void)snprintf(map, sizeof(map), "-ffile-prefix-map=%s=/scx", r->root);
    argv[k++] = "cc";
    if (k_scx_edits[v].extra_flag != NULL)
        argv[k++] = k_scx_edits[v].extra_flag;
    for (size_t i = 0; i + 1 < k_scx_nflags; i++) /* all but the -I */
        argv[k++] = scx_flag(v, i);
    argv[k++] = inc;
    argv[k++] = map;
    argv[k++] = "-c";
    argv[k++] = src;
    argv[k++] = "-o";
    argv[k++] = out;
    argv[k] = NULL;
    return scl_spawn(argv, log) == 0;
}

static void scl_export(const struct scl_run *r, enum scx_variant v, size_t tu)
{
    const char *dest = getenv("ZCL_SEMANTIC_CONSUMER_FIXTURE_OUT");
    char dir[PATH_MAX], dst[PATH_MAX + 64];
    FILE *fp;
    if (dest == NULL || dest[0] == '\0')
        return;
    (void)snprintf(dir, sizeof(dir), "%s/%s", dest, k_scx_edits[v].name);
    (void)scx_mkdir(dest);
    (void)scx_mkdir(dir);
    (void)snprintf(dst, sizeof(dst), "%s/%s.zsm", dir, scl_base(k_scx_tus[tu]));
    fp = fopen(dst, "wb");
    if (fp == NULL || fwrite(r->m[v][tu], 1, r->n[v][tu], fp) != r->n[v][tu])
        fprintf(stderr, "scl_export: cannot write %s\n", dst);
    if (fp != NULL && fclose(fp) != 0)
        fprintf(stderr, "scl_export: cannot close %s\n", dst);
}

/* Write variant v into the shared root, then sense and compile each TU. */
static bool scl_produce(struct scl_run *r, enum scx_variant v)
{
    char dir[PATH_MAX], path[PATH_MAX];
    bool ok;
    (void)snprintf(dir, sizeof(dir), "%s/%s", r->out, k_scx_edits[v].name);
    ok = scx_mkdir(dir) && scx_write_tree(r->root, v);
    for (size_t tu = 0; ok && tu < SCX_TU_COUNT; tu++) {
        scl_file(path, sizeof(path), r, v, tu, "zsm");
        ok = scl_sensor(r, v, tu) && scl_compile(r, v, tu) &&
             sft_read(path, &r->m[v][tu], &r->n[v][tu]);
        if (!ok)
            fprintf(stderr, "  scl_produce: %s %s failed (logs under %s)\n",
                    k_scx_edits[v].name, k_scx_tus[tu], dir);
        else
            scl_export(r, v, tu);
    }
    return ok;
}

static bool scl_same_object(const struct scl_run *r, enum scx_variant v,
                            size_t tu)
{
    char a[PATH_MAX], b[PATH_MAX];
    uint8_t *x = NULL, *y = NULL;
    size_t xn = 0, yn = 0;
    bool same;
    scl_file(a, sizeof(a), r, k_scx_edits[v].before, tu, "o");
    scl_file(b, sizeof(b), r, v, tu, "o");
    same = sft_read(a, &x, &xn) && sft_read(b, &y, &yn) && xn == yn &&
           memcmp(x, y, xn) == 0;
    free(x);
    free(y);
    return same;
}

/* Missed dependencies of one variant: object changed, not predicted. */
static size_t scl_missed(struct scl_run *r, enum scx_variant v,
                         const struct scx_result *res)
{
    size_t missed = 0;
    for (size_t tu = 0; tu < SCX_TU_COUNT; tu++) {
        const struct zcl_devloop_facts_tu_verdict *t =
            scx_tu_of(res, k_scx_tus[tu]);
        bool predicted = t != NULL && t->affected;
        bool same = scl_same_object(r, v, tu);
        if (!same && !predicted) {
            missed++;
            fprintf(stderr, "  MISSED DEPENDENCY: %s %s (%s)\n",
                    k_scx_edits[v].name, k_scx_tus[tu],
                    t != NULL ? t->reason : "not in the universe");
        }
        r->over += same && predicted;
    }
    return missed;
}

static int scl_check(struct scl_run *r, enum scx_variant v)
{
    int failures = 0;
    char root[PATH_MAX] = {0};
    struct scx_evidence ev = {0};
    struct scx_result *res = zcl_calloc(1, sizeof(*res), "scl.result");
    size_t unsafe = 0;
    for (size_t tu = 0; tu < SCX_TU_COUNT; tu++) {
        ev.before[tu] = r->m[k_scx_edits[v].before][tu];
        ev.before_len[tu] = r->n[k_scx_edits[v].before][tu];
        ev.after[tu] = r->m[v][tu];
        ev.after_len[tu] = r->n[v][tu];
    }
    TEST_CASE(k_scx_edits[v].name) {
        ASSERT(res != NULL);
        ASSERT(test_mkdtemp(root, sizeof(root), "semconsumer_plan") != NULL);
        ASSERT(scx_consume(root, v, &ev, res));
        ASSERT_EQ(scx_compare(v, res, &unsafe, stderr), 0);
        ASSERT_EQ(scl_missed(r, v, res), 0);
    } TEST_END
    if (res != NULL)
        scx_result_free(res);
    free(res);
    if (root[0] != '\0')
        (void)test_rm_rf_recursive(root);
    return failures;
}

/* __attribute__((alias)) is an error on Darwin ("aliases are not supported
 * on darwin": Mach-O has no weak/alias symbol form for it), so the F6 alias
 * pair cannot be compiled there. Skip it explicitly; every other variant
 * still runs, and on Linux nothing is skipped. */
static bool scl_unsupported(enum scx_variant v)
{
#if defined(__APPLE__)
    if (v == SCX_P_ALIAS || v == SCX_ALIAS) {
        printf("semantic_consumer_live: SKIP %s (aliases are not supported "
               "on darwin)\n", k_scx_edits[v].name);
        return true;
    }
#else
    (void)v;
#endif
    return false;
}

int test_semantic_consumer_live(void)
{
    int failures = 0;
    struct scl_run *r = zcl_calloc(1, sizeof(*r), "scl.run");
    struct stat sb;
    if (stat(SCL_SENSOR, &sb) != 0) {
        printf("semantic_consumer_live: SKIP (needs %s from `make clang-manifest`)\n",
               SCL_SENSOR);
        free(r);
        return 0;
    }
    TEST_CASE("semantic_consumer_live: every variant senses and compiles") {
        ASSERT(r != NULL);
        ASSERT(test_mkdtemp(r->out, sizeof(r->out), "semconsumer_live") != NULL);
        (void)snprintf(r->root, sizeof(r->root), "%s/tree", r->out);
        ASSERT(scx_mkdir(r->root));
        for (int v = 0; v < SCX_VARIANT_COUNT; v++)
            ASSERT(scl_unsupported((enum scx_variant)v) ||
                   scl_produce(r, (enum scx_variant)v));
    } TEST_END
    for (int v = 1; failures == 0 && v < SCX_VARIANT_COUNT; v++)
        if (!k_scx_edits[v].pre && !scl_unsupported((enum scx_variant)v))
            failures += scl_check(r, (enum scx_variant)v);
    if (r != NULL)
        printf("semantic_consumer_live: %zu TU(s) predicted affected with an "
               "unchanged object (conservative margin)\n", r->over);
    for (int v = 0; r != NULL && v < SCX_VARIANT_COUNT; v++)
        for (size_t tu = 0; tu < SCX_TU_COUNT; tu++)
            free(r->m[v][tu]);
    if (r != NULL && failures == 0)
        (void)test_rm_rf_recursive(r->out);
    free(r);
    return failures;
}
