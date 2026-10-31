/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "params.h"
#include "params_job.h"
#include "zsha256/zsha256.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Fault injection: the Nth flush fails, and writes fail once write_limit bytes went through. The first
 * flush after hold_fsync is armed blocks until released, which holds a worker in the middle of a copy. */
int __real_fsync(int fd);
ssize_t __real_write(int fd, const void *buf, size_t len);
ssize_t __real_pread(int fd, void *buf, size_t len, off_t at);
int __real_close(int fd);
void *__real_calloc(size_t n, size_t size);
void __real_free(void *p);
int __real_pthread_create(pthread_t *t, const pthread_attr_t *attr, void *(*fn)(void *), void *arg);
static int fsyncs, fail_fsync_at;
static long long write_limit = -1;
static atomic_int hold_fsync, in_fsync, release_fsync, fail_thread_start, reads, reads_without_cloexec;
static int watch_fd[2] = {-1, -1};
static atomic_int watch_closes[2];
#define TRACKED 16
static _Atomic(void *) allocated[TRACKED];
static atomic_int allocations;
static atomic_bool freed_flag[TRACKED];

static void pause_ms(int ms) { struct timespec pause = {.tv_nsec = ms * 1000000L}; nanosleep(&pause, NULL); }
int __wrap_fsync(int fd)
{
    if (atomic_exchange(&hold_fsync, 0)) {
        atomic_store(&in_fsync, 1);
        while (!atomic_load(&release_fsync)) pause_ms(2);
    }
    fsyncs++;
    if (fail_fsync_at && fsyncs == fail_fsync_at) { errno = EIO; return -1; }
    return __real_fsync(fd);
}
ssize_t __wrap_write(int fd, const void *buf, size_t len)
{
    if (write_limit < 0) return __real_write(fd, buf, len);
    if (write_limit == 0) { errno = ENOSPC; return -1; }
    if ((unsigned long long)write_limit < len) len = (size_t)write_limit;
    ssize_t n = __real_write(fd, buf, len);
    if (n > 0) write_limit -= n;
    return n;
}
ssize_t __wrap_pread(int fd, void *buf, size_t len, off_t at)
{
    atomic_fetch_add(&reads, 1);
    if (!(fcntl(fd, F_GETFD) & FD_CLOEXEC)) atomic_fetch_add(&reads_without_cloexec, 1);
    return __real_pread(fd, buf, len, at);
}
int __wrap_close(int fd)
{
    for (int i = 0; i < 2; i++)
        if (fd == watch_fd[i]) atomic_fetch_add(&watch_closes[i], 1);
    return __real_close(fd);
}
/* Only params_job.c allocates with calloc: its job records are tracked until freed. */
void *__wrap_calloc(size_t n, size_t size)
{
    void *p = __real_calloc(n, size);
    int slot = atomic_fetch_add(&allocations, 1);
    if (slot < TRACKED) { atomic_store(&freed_flag[slot], false); atomic_store(&allocated[slot], p); }
    return p;
}
void __wrap_free(void *p)
{
    for (int i = 0; p && i < TRACKED && i < atomic_load(&allocations); i++)
        if (atomic_load(&allocated[i]) == p) { atomic_store(&freed_flag[i], true); atomic_store(&allocated[i], NULL); }
    __real_free(p);
}
int __wrap_pthread_create(pthread_t *t, const pthread_attr_t *attr, void *(*fn)(void *), void *arg)
{
    return atomic_load(&fail_thread_start) ? EAGAIN : __real_pthread_create(t, attr, fn, arg);
}

#define PREFIX 4097u
static const size_t fixture_size[2] = {(1u << 20) * 5 / 2 + 3, 17};
static char root[1024], files[1100];
static struct zapp_param_file set[2];
static char names[2][16] = {"one.params", "two.params"}, hashes[2][65];
static int opens, check_atomic, final_seen_early;
static long short_by[2];   /* bytes the packaged range claims beyond what the source file holds */

static void path_of(char *out, size_t cap, const char *dir, const char *name) { snprintf(out, cap, "%s/%s", dir, name); }
static bool exists(const char *path) { struct stat st; return lstat(path, &st) == 0; }

/* Source files hold PREFIX bytes of filler, then the fixture bytes, so the offset matters. */
static void make_source(int index)
{
    char path[1200];
    path_of(path, sizeof(path), root, names[index]);
    size_t total = PREFIX + fixture_size[index];
    uint8_t *data = malloc(total);
    assert(data);
    for (size_t i = 0; i < total; i++) data[i] = (uint8_t)((i * 131u + (size_t)index * 7u) >> 3);
    memset(data, 0xEE, PREFIX);
    zsha256_hex(data + PREFIX, fixture_size[index], hashes[index]);
    FILE *f = fopen(path, "wb");
    assert(f && fwrite(data, 1, total, f) == total && fclose(f) == 0);
    free(data);
    set[index] = (struct zapp_param_file){names[index], fixture_size[index], hashes[index]};
}

static int open_source(void *ctx, const char *name, uint64_t *offset, uint64_t *length)
{
    (void)ctx;
    char path[1200], final[1200];
    opens++;
    if (check_atomic) {
        path_of(final, sizeof(final), files, "params");
        if (exists(final)) final_seen_early = 1;
    }
    path_of(path, sizeof(path), root, name);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0) return -1;
    *offset = PREFIX;
    *length = (uint64_t)st.st_size - PREFIX + (uint64_t)short_by[strcmp(name, names[0]) ? 1 : 0];
    return fd;
}

static void reset(int flip_index)
{
    char cmd[2400];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'/files && mkdir '%s'/files", root, root);
    assert(system(cmd) == 0);
    snprintf(files, sizeof(files), "%s/files", root);
    make_source(0);
    make_source(1);
    if (flip_index >= 0) {   /* the pin describes the good bytes; the source holds a flipped copy */
        char path[1200];
        path_of(path, sizeof(path), root, names[flip_index]);
        FILE *f = fopen(path, "r+b");
        assert(f && fseek(f, (long)(PREFIX + fixture_size[flip_index] / 2), SEEK_SET) == 0);
        int c = fgetc(f);
        assert(c != EOF && fseek(f, -1, SEEK_CUR) == 0 && fputc(c ^ 1, f) != EOF && fclose(f) == 0);
    }
    opens = 0; check_atomic = 0; final_seen_early = 0;
    short_by[0] = short_by[1] = 0; fail_fsync_at = 0; write_limit = -1;
}

static int entries(const char *dir)
{
    DIR *d = opendir(dir);
    int n = 0;
    if (!d) return 0;
    for (struct dirent *e; (e = readdir(d));) n += strcmp(e->d_name, ".") && strcmp(e->d_name, "..");
    closedir(d);
    return n;
}

static bool same_bytes(int index)
{
    char a[1500], b[1300];
    path_of(b, sizeof(b), files, "params");
    path_of(a, sizeof(a), b, names[index]);
    struct stat st;
    if (stat(a, &st) != 0 || (size_t)st.st_size != fixture_size[index] || (st.st_mode & 077)) return false;
    char hex[65];
    uint8_t *data = malloc(fixture_size[index]);
    FILE *f = fopen(a, "rb");
    bool ok = f && data && fread(data, 1, fixture_size[index], f) == fixture_size[index];
    if (f) fclose(f);
    if (ok) zsha256_hex(data, fixture_size[index], hex);
    free(data);
    return ok && !strcmp(hex, hashes[index]);
}

static void nothing_left_behind(void)
{
    char p[1300];
    path_of(p, sizeof(p), files, "params");
    assert(!exists(p));
    path_of(p, sizeof(p), files, "params.tmp");
    assert(!exists(p));
    assert(entries(files) == 0);
}

static void install_succeeds(void)
{
    struct zapp_params_source src = {NULL, open_source};
    char why[200] = "";
    reset(-1);
    check_atomic = 1;
    fsyncs = 0;
    assert(zapp_params_install_set(set, 2, &src, files, why, sizeof(why)) == ZAPP_PARAMS_OK);
    assert(!final_seen_early && opens == 2);
    assert(fsyncs >= 4);                       /* each file, the staging directory, the files directory */
    assert(zapp_params_present_set(set, 2, files));
    assert(same_bytes(0) && same_bytes(1));
    assert(entries(files) == 1);
    opens = 0;                                 /* already in place: the source is not touched again */
    assert(zapp_params_install_set(set, 2, &src, files, why, sizeof(why)) == ZAPP_PARAMS_OK && opens == 0);
}

static void hash_mismatch_keeps_nothing(void)
{
    struct zapp_params_source src = {NULL, open_source};
    char why[200] = "";
    for (int bad = 0; bad < 2; bad++) {
        reset(bad);
        assert(zapp_params_install_set(set, 2, &src, files, why, sizeof(why)) == ZAPP_PARAMS_HASH);
        assert(strstr(why, "Nothing was kept") && strstr(why, "hash"));
        assert(!zapp_params_present_set(set, 2, files));
        nothing_left_behind();
    }
}

static void size_and_missing_keep_nothing(void)
{
    struct zapp_params_source src = {NULL, open_source};
    char why[200] = "";
    reset(-1);
    set[1].size += 1;
    assert(zapp_params_install_set(set, 2, &src, files, why, sizeof(why)) == ZAPP_PARAMS_SIZE && why[0]);
    nothing_left_behind();
    reset(-1);
    set[1].name = "absent.params";
    assert(zapp_params_install_set(set, 2, &src, files, why, sizeof(why)) == ZAPP_PARAMS_MISSING && why[0]);
    nothing_left_behind();
}

static void interrupted_copy_restarts(void)
{
    struct zapp_params_source src = {NULL, open_source};
    char why[200] = "", p[1300], q[1400];
    reset(-1);
    path_of(p, sizeof(p), files, "params.tmp");
    assert(mkdir(p, 0700) == 0);
    path_of(q, sizeof(q), p, "one.params.part");
    FILE *f = fopen(q, "wb");
    assert(f && fputs("half a file", f) >= 0 && fclose(f) == 0);
    path_of(p, sizeof(p), files, "params");      /* and a published directory of the wrong size */
    assert(mkdir(p, 0700) == 0);
    path_of(q, sizeof(q), p, "one.params");
    f = fopen(q, "wb");
    assert(f && fputs("short", f) >= 0 && fclose(f) == 0);
    assert(!zapp_params_present_set(set, 2, files));
    assert(zapp_params_install_set(set, 2, &src, files, why, sizeof(why)) == ZAPP_PARAMS_OK);
    assert(same_bytes(0) && same_bytes(1) && entries(files) == 1);
}

static void write_sparse(const char *dir, const char *name, uint64_t size)
{
    char p[1400];
    path_of(p, sizeof(p), dir, name);
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0 && ftruncate(fd, (off_t)size) == 0 && close(fd) == 0);
}

static void node_argument(void)
{
    char arg[1200], dir[1300], expect[1400];
    reset(-1);
    assert(!zapp_params_present(files) && !zapp_params_arg(files, arg, sizeof(arg)));
    path_of(dir, sizeof(dir), files, "params");
    assert(mkdir(dir, 0700) == 0);
    write_sparse(dir, zapp_param_files[0].name, zapp_param_files[0].size);
    assert(!zapp_params_present(files));            /* one of two */
    write_sparse(dir, zapp_param_files[1].name, zapp_param_files[1].size - 1);
    assert(!zapp_params_present(files));            /* wrong size */
    write_sparse(dir, zapp_param_files[1].name, zapp_param_files[1].size);
    assert(zapp_params_present(files) && zapp_params_arg(files, arg, sizeof(arg)));
    snprintf(expect, sizeof(expect), "-paramsdir=%s", dir);
    assert(!strcmp(arg, expect));
    assert(!zapp_params_arg(files, arg, 8));      /* too small to hold it */
}

static void pinned_table_matches_the_published_sums(void)
{
    static const uint64_t sizes[2] = {47958396, 3592860};
    FILE *f = fopen("params.sha256", "r");
    char hex[80], name[80];
    assert(f);
    for (int i = 0; i < 2; i++) {
        assert(fscanf(f, "%79s %79s", hex, name) == 2);
        assert(!strcmp(zapp_param_files[i].sha256, hex) && !strcmp(zapp_param_files[i].name, name));
        assert(zapp_param_files[i].size == sizes[i] && strlen(hex) == 64);
    }
    assert(fscanf(f, "%79s", hex) == EOF);
    fclose(f);
}

static int probe_calls;
static enum zapp_proving probe_answer;
static enum zapp_proving probe_status(void *ctx) { (void)ctx; probe_calls++; return probe_answer; }

static void prover_precondition(void)
{
    char why[200];
    struct zapp_proving_probe node = {NULL, probe_status};
    probe_answer = ZAPP_PROVING_ARMED;
    for (int status = -1; status <= 6; status++) {
        why[0] = 0;
        bool ok = zapp_prover_allowed(status, true, &node, why, sizeof(why));
        assert(ok == (status < 3));
        assert(ok ? why[0] == 0 : strstr(why, "hot") != NULL);
    }
    probe_calls = 0;                              /* an unverified copy is refused without asking the node */
    why[0] = 0;
    assert(!zapp_prover_allowed(0, false, &node, why, sizeof(why)) && strstr(why, "not ready") && !probe_calls);
    why[0] = 0;
    assert(!zapp_prover_allowed(5, false, &node, why, sizeof(why)) && strstr(why, "not ready"));
    assert(!zapp_prover_allowed(3, false, &node, NULL, 0));
    assert(zapp_prover_allowed(2, true, &node, NULL, 0));
    probe_answer = ZAPP_PROVING_UNAVAILABLE;      /* a verified copy is not enough until the node says so */
    why[0] = 0;
    assert(!zapp_prover_allowed(0, true, &node, why, sizeof(why)) && strstr(why, "cannot prove"));
    probe_answer = ZAPP_PROVING_UNKNOWN;
    why[0] = 0;
    assert(!zapp_prover_allowed(0, true, &node, why, sizeof(why)) && strstr(why, "not confirmed"));
    why[0] = 0;
    assert(!zapp_prover_allowed(0, true, NULL, why, sizeof(why)) && strstr(why, "not confirmed"));
    struct zapp_proving_probe none = {NULL, NULL};
    assert(!zapp_prover_allowed(0, true, &none, NULL, 0));
}

static void flip_installed_byte(int index)
{
    char dir[1300], file[1500];
    path_of(dir, sizeof(dir), files, "params");
    path_of(file, sizeof(file), dir, names[index]);
    FILE *f = fopen(file, "r+b");
    assert(f && fseek(f, (long)(fixture_size[index] / 2), SEEK_SET) == 0);
    int c = fgetc(f);
    assert(c != EOF && fseek(f, -1, SEEK_CUR) == 0 && fputc(c ^ 1, f) != EOF && fclose(f) == 0);
}

static void corrupt_copy_is_replaced(void)
{
    struct zapp_params_source src = {NULL, open_source};
    char why[200] = "";
    for (int bad = 0; bad < 2; bad++) {
        reset(-1);
        assert(zapp_params_install_set(set, 2, &src, files, why, sizeof(why)) == ZAPP_PARAMS_OK);
        assert(zapp_params_verify_set(set, 2, files));
        flip_installed_byte(bad);                  /* same size, one bit differs */
        assert(zapp_params_present_set(set, 2, files));   /* the cheap look cannot see it */
        assert(!zapp_params_verify_set(set, 2, files));
        opens = 0;
        assert(zapp_params_install_set(set, 2, &src, files, why, sizeof(why)) == ZAPP_PARAMS_OK);
        assert(opens == 2 && same_bytes(0) && same_bytes(1) && zapp_params_verify_set(set, 2, files));
        assert(entries(files) == 1);
    }
    reset(-1);                                     /* a bad copy that cannot be replaced stays unready */
    assert(zapp_params_install_set(set, 2, &src, files, why, sizeof(why)) == ZAPP_PARAMS_OK);
    flip_installed_byte(0);
    write_limit = 0;
    assert(zapp_params_install_set(set, 2, &src, files, why, sizeof(why)) == ZAPP_PARAMS_IO);
    write_limit = -1;
    nothing_left_behind();
}

/* The Nth flush fails: each file, the staging directory, and the parent after the rename. */
static void flush_failures_keep_nothing(void)
{
    struct zapp_params_source src = {NULL, open_source};
    char why[200] = "";
    for (int nth = 1; nth <= 4; nth++) {
        reset(-1);
        fail_fsync_at = nth;
        fsyncs = 0;
        assert(zapp_params_install_set(set, 2, &src, files, why, sizeof(why)) == ZAPP_PARAMS_IO);
        assert(fsyncs == nth && strstr(why, "Nothing was kept"));
        assert(!zapp_params_present_set(set, 2, files));
        nothing_left_behind();
        fail_fsync_at = 0;                         /* the next install checks again and succeeds */
        assert(zapp_params_install_set(set, 2, &src, files, why, sizeof(why)) == ZAPP_PARAMS_OK);
        assert(same_bytes(0) && same_bytes(1));
    }
}

static void write_errors_keep_nothing(void)
{
    struct zapp_params_source src = {NULL, open_source};
    char why[200] = "";
    long long limits[3] = {0, 100, (long long)fixture_size[0] + 5};
    for (int i = 0; i < 3; i++) {
        reset(-1);
        write_limit = limits[i];
        assert(zapp_params_install_set(set, 2, &src, files, why, sizeof(why)) == ZAPP_PARAMS_IO);
        assert(strstr(why, "Nothing was kept"));
        write_limit = -1;
        nothing_left_behind();
    }
}

static void truncated_source_keeps_nothing(void)
{
    struct zapp_params_source src = {NULL, open_source};
    char why[200] = "", p[1200];
    for (int cut = 0; cut < 2; cut++) {
        reset(-1);
        path_of(p, sizeof(p), root, names[cut]);
        assert(truncate(p, (off_t)(PREFIX + fixture_size[cut] - 9)) == 0);
        short_by[cut] = 9;                          /* the package still claims the full range */
        assert(zapp_params_install_set(set, 2, &src, files, why, sizeof(why)) == ZAPP_PARAMS_IO);
        assert(strstr(why, "Nothing was kept"));
        nothing_left_behind();
    }
}

static void wait_for_job(char *why, size_t cap, enum zapp_params_state *state)
{
    for (int i = 0; i < 2000; i++) {
        *state = zapp_params_job_state(why, cap);
        if (*state != ZAPP_PARAMS_COPYING) return;
        struct timespec pause = {.tv_nsec = 5000000};
        nanosleep(&pause, NULL);
    }
    assert(!"the copy never finished");
}

static void open_fds(struct zapp_params_fd fds[2])
{
    for (int i = 0; i < 2; i++) {
        char path[1200];
        path_of(path, sizeof(path), root, names[i]);
        fds[i] = (struct zapp_params_fd){open(path, O_RDONLY | O_CLOEXEC), PREFIX, fixture_size[i]};
        assert(fds[i].fd >= 0);
    }
}

static bool closed(int fd) { return fcntl(fd, F_GETFD) == -1 && errno == EBADF; }

static void watch(const struct zapp_params_fd fds[2])
{
    for (int i = 0; i < 2; i++) { watch_fd[i] = fds[i].fd; atomic_store(&watch_closes[i], 0); }
}
static void unwatch(void) { watch_fd[0] = watch_fd[1] = -1; }
static void forget_allocations(void) { atomic_store(&allocations, 0); }
static bool allocation_freed(int slot) { return slot < atomic_load(&allocations) && atomic_load(&freed_flag[slot]); }

/* The descriptors of one job are closed exactly once each, its record is freed, and its worker read
 * only close-on-exec descriptors. */
static void job_released_everything(void)
{
    assert(atomic_load(&watch_closes[0]) == 1 && atomic_load(&watch_closes[1]) == 1);
    for (int i = 0; i < atomic_load(&allocations); i++) assert(allocation_freed(i));
}

/* The worker owns only the descriptors it was given and reports by state, with no callback. */
static void job_reports_by_polling(void)
{
    struct zapp_params_fd fds[2], keep[2];
    char why[200] = "x";
    enum zapp_params_state state;
    reset(-1);
    open_fds(fds);
    memcpy(keep, fds, sizeof(keep));
    watch(keep);
    forget_allocations();
    atomic_store(&reads, 0);
    atomic_store(&reads_without_cloexec, 0);
    assert(zapp_params_job_start_set(set, 2, fds, files));
    wait_for_job(why, sizeof(why), &state);
    assert(state == ZAPP_PARAMS_VERIFIED && why[0] == 0);
    assert(same_bytes(0) && same_bytes(1) && closed(keep[0].fd) && closed(keep[1].fd));
    assert(atomic_load(&reads) > 0 && atomic_load(&reads_without_cloexec) == 0);
    job_released_everything();
    reset(0);                                       /* a flipped source: FAILED with a reason, nothing kept */
    open_fds(fds);
    memcpy(keep, fds, sizeof(keep));
    watch(keep);
    forget_allocations();
    assert(zapp_params_job_start_set(set, 2, fds, files));
    wait_for_job(why, sizeof(why), &state);
    assert(state == ZAPP_PARAMS_FAILED && strstr(why, "hash") && closed(keep[0].fd) && closed(keep[1].fd));
    nothing_left_behind();
    job_released_everything();
    unwatch();
    reset(-1);                                      /* a file that could not be opened */
    open_fds(fds);
    close(fds[1].fd);
    fds[1].fd = -1;
    assert(zapp_params_job_start_set(set, 2, fds, files));
    wait_for_job(why, sizeof(why), &state);
    assert(state == ZAPP_PARAMS_FAILED && strstr(why, "missing"));
    nothing_left_behind();
    open_fds(fds);                                  /* an unusable argument still closes what it was given */
    memcpy(keep, fds, sizeof(keep));
    assert(!zapp_params_job_start_set(set, 2, fds, NULL));
    assert(closed(keep[0].fd) && closed(keep[1].fd));
}

/* A second start while a copy runs is refused, closes its descriptors, frees its record and leaves the
 * running copy alone: one worker, one params.tmp. */
static void second_start_is_refused_while_copying(void)
{
    struct zapp_params_fd first[2], second[2], keep[2], keep2[2];
    char why[200] = "";
    enum zapp_params_state state;
    reset(-1);
    open_fds(first);
    memcpy(keep, first, sizeof(keep));
    watch(keep);
    forget_allocations();
    atomic_store(&in_fsync, 0);
    atomic_store(&release_fsync, 0);
    atomic_store(&hold_fsync, 1);
    assert(zapp_params_job_start_set(set, 2, first, files));
    for (int i = 0; i < 2000 && !atomic_load(&in_fsync); i++) pause_ms(2);
    assert(atomic_load(&in_fsync));                  /* the worker is inside its first flush */
    assert(zapp_params_job_state(why, sizeof(why)) == ZAPP_PARAMS_COPYING);
    open_fds(second);
    memcpy(keep2, second, sizeof(keep2));
    assert(!zapp_params_job_start_set(set, 2, second, files));
    assert(closed(keep2[0].fd) && closed(keep2[1].fd));
    assert(allocation_freed(1) && !allocation_freed(0));   /* the refused record is gone, the running one is not */
    assert(zapp_params_job_state(why, sizeof(why)) == ZAPP_PARAMS_COPYING);
    assert(!closed(keep[0].fd) && !closed(keep[1].fd));    /* the running copy still holds its own */
    atomic_store(&release_fsync, 1);
    wait_for_job(why, sizeof(why), &state);
    assert(state == ZAPP_PARAMS_VERIFIED && same_bytes(0) && same_bytes(1));
    job_released_everything();
    unwatch();
}

/* When the worker thread cannot start, the descriptors are closed, the record is freed, and both the
 * earlier outcome and the installed files stand. */
static void thread_start_failure_changes_nothing(void)
{
    struct zapp_params_fd fds[2], keep[2];
    char why[200] = "", before[200] = "";
    enum zapp_params_state state;
    reset(-1);
    open_fds(fds);
    assert(zapp_params_job_start_set(set, 2, fds, files));
    wait_for_job(why, sizeof(why), &state);
    assert(state == ZAPP_PARAMS_VERIFIED);
    for (int round = 0; round < 2; round++) {
        if (round == 1) {                           /* now an earlier FAILED outcome stands the same way */
            flip_installed_byte(0);
            write_limit = 0;
            open_fds(fds);
            assert(zapp_params_job_start_set(set, 2, fds, files));
            wait_for_job(why, sizeof(why), &state);
            write_limit = -1;
            assert(state == ZAPP_PARAMS_FAILED && why[0]);
            nothing_left_behind();
        }
        enum zapp_params_state expect = zapp_params_job_state(before, sizeof(before));
        open_fds(fds);
        memcpy(keep, fds, sizeof(keep));
        watch(keep);
        forget_allocations();
        atomic_store(&fail_thread_start, 1);
        assert(!zapp_params_job_start_set(set, 2, fds, files));
        atomic_store(&fail_thread_start, 0);
        assert(closed(keep[0].fd) && closed(keep[1].fd));
        job_released_everything();
        unwatch();
        state = zapp_params_job_state(why, sizeof(why));
        assert(state == expect && !strcmp(why, before));
        if (round == 0) assert(zapp_params_verify_set(set, 2, files) && same_bytes(0) && same_bytes(1));
    }
}

/* Files this code did not create stay; the pinned files do not, whatever the failure. */
static void foreign_file_stays_and_pins_go(void)
{
    struct zapp_params_source src = {NULL, open_source};
    char why[200] = "", p[1400], dir[1300];
    reset(-1);
    assert(zapp_params_install_set(set, 2, &src, files, why, sizeof(why)) == ZAPP_PARAMS_OK);
    path_of(dir, sizeof(dir), files, "params");
    path_of(p, sizeof(p), dir, "stray.txt");
    FILE *f = fopen(p, "wb");
    assert(f && fputs("kept", f) >= 0 && fclose(f) == 0);
    flip_installed_byte(1);
    write_limit = 0;
    assert(zapp_params_install_set(set, 2, &src, files, why, sizeof(why)) == ZAPP_PARAMS_IO);
    write_limit = -1;
    assert(!zapp_params_present_set(set, 2, files) && !zapp_params_verify_set(set, 2, files));
    assert(exists(p) && entries(dir) == 1);
    assert(unlink(p) == 0 && rmdir(dir) == 0);
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    snprintf(root, sizeof(root), "%s", argv[1]);
    char why[200] = "unset";
    assert(zapp_params_job_state(why, sizeof(why)) == ZAPP_PARAMS_IDLE && why[0] == 0);
    pinned_table_matches_the_published_sums();
    prover_precondition();
    install_succeeds();
    hash_mismatch_keeps_nothing();
    size_and_missing_keep_nothing();
    interrupted_copy_restarts();
    corrupt_copy_is_replaced();
    flush_failures_keep_nothing();
    write_errors_keep_nothing();
    truncated_source_keeps_nothing();
    job_reports_by_polling();
    second_start_is_refused_while_copying();
    thread_start_failure_changes_nothing();
    foreign_file_stays_and_pins_go();
    node_argument();
    puts("params tests passed");
    return 0;
}
