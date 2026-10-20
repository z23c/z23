/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance bar for the host build queue (tools/command/build_admit.h): a
 * job is admitted in FIFO order, never above the lane limit, runs with the
 * scope properties the devbuild wrapper uses, keeps its exit status, and
 * leaves scratch behind only when it failed.
 *
 * The scope launcher is a stub script written into a throwaway directory:
 * it records its arguments and runs the command after `--`, so no real
 * systemd scope is created. Admission uses real flock files in that same
 * directory.
 */

#include "test/test_core.h"

#include "command/build_admit.h"
#include "base/safe_alloc.h"
#include "command/native_command.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "config/command_catalog.h"

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { HBT_PATH = 512, HBT_TEXT = 8192 };

#ifdef __linux__
static void hbt_nap(long ms)
{
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    (void)nanosleep(&ts, NULL); /* real-clock: lets forked fixture jobs reach their lock; the code under test never reads this wait */
}

/* First CPU this process may run on, from the kernel's own allowed list. */
static bool hbt_first_cpu(char *out, size_t cap)
{
    char line[512];
    unsigned cpu;
    bool found = false;
    FILE *f = fopen("/proc/self/status", "r");
    while (f && !found && fgets(line, sizeof(line), f))
        found = sscanf(line, "Cpus_allowed_list: %u", &cpu) == 1;
    if (f)
        fclose(f);
    if (found)
        (void)snprintf(out, cap, "%u", cpu);
    return found;
}

static bool hbt_slurp(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    size_t n;
    if (!f)
        return false;
    n = fread(buf, 1, cap - 1u, f);
    buf[n] = '\0';
    fclose(f);
    return true;
}

static bool hbt_write_stub(const char *dir, const char *stub, const char *log)
{
    FILE *f = fopen(stub, "w");
    (void)dir;
    if (!f)
        return false;
    fprintf(f, "#!/bin/sh\nprintf '%%s\\n' \"$@\" > '%s'\n"
               "while [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n",
            log);
    fclose(f);
    return chmod(stub, 0700) == 0;
}

static bool hbt_config(struct ba_config *cfg, const char *tmp, unsigned lanes)
{
    char stub[HBT_PATH], log[HBT_PATH];
    memset(cfg, 0, sizeof(*cfg));
    (void)snprintf(cfg->state_dir, sizeof(cfg->state_dir), "%s/state", tmp);
    (void)snprintf(cfg->scratch_root, sizeof(cfg->scratch_root), "%s/scratch",
                   tmp);
    (void)snprintf(cfg->disk_path, sizeof(cfg->disk_path), "%s", tmp);
    (void)snprintf(stub, sizeof(stub), "%s/stub", tmp);
    (void)snprintf(log, sizeof(log), "%s/stub.args", tmp);
    (void)snprintf(cfg->scope_launcher, sizeof(cfg->scope_launcher), "%s", stub);
    cfg->cpu_workers = 4;
    cfg->lanes = lanes;
    cfg->poll_ms = 20;
    cfg->zcc_max_mb = 8192;
    cfg->wait = true;
    return hbt_first_cpu(cfg->cpu_list, sizeof(cfg->cpu_list)) &&
           hbt_write_stub(tmp, stub, log);
}

static int hbt_run(const struct ba_config *cfg, const char *const *argv)
{
    int argc = 0;
    while (argv[argc])
        argc++;
    return ba_run(cfg, argv, argc);
}

/* A forked job: runs the command through ba_run and exits with its status. */
static pid_t hbt_spawn(const struct ba_config *cfg, const char *const *argv)
{
    pid_t pid = fork();
    if (pid == 0)
        _exit(hbt_run(cfg, argv));
    return pid;
}

static int hbt_reap(pid_t pid)
{
    int status = 0;
    if (waitpid(pid, &status, 0) != pid)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -2;
}

static size_t hbt_array_size(const struct json_value *doc, const char *key)
{
    return json_size(json_get(doc, key));
}

/* Poll ba_status until `running` and `queued` hold the wanted counts. */
static bool hbt_wait_counts(const char *state, size_t running, size_t queued,
                            struct json_value *doc)
{
    for (int i = 0; i < 300; i++) {
        json_init(doc);
        json_set_object(doc);
        if (ba_status(state, doc) &&
            hbt_array_size(doc, "running") == running &&
            hbt_array_size(doc, "queued") == queued)
            return true;
        json_free(doc);
        hbt_nap(20);
    }
    return false;
}

static size_t hbt_count_jobs(const char *scratch_root)
{
    char pool[HBT_PATH];
    size_t n = 0;
    DIR *d;
    (void)snprintf(pool, sizeof(pool), "%s/z23", scratch_root);
    d = opendir(pool);
    for (struct dirent *e = d ? readdir(d) : NULL; e; e = readdir(d))
        if (strncmp(e->d_name, "job.", 4) == 0)
            n++;
    if (d)
        closedir(d);
    return n;
}

static bool hbt_first_job(const char *scratch_root, char *out, size_t cap)
{
    char pool[HBT_PATH];
    DIR *d;
    (void)snprintf(pool, sizeof(pool), "%s/z23", scratch_root);
    d = opendir(pool);
    for (struct dirent *e = d ? readdir(d) : NULL; e; e = readdir(d)) {
        if (strncmp(e->d_name, "job.", 4) == 0) {
            (void)snprintf(out, cap, "%s/%s", pool, e->d_name);
            closedir(d);
            return true;
        }
    }
    if (d)
        closedir(d);
    return false;
}

#endif

static int hbt_cpu_plan_tests(void)
{
    int failures = 0;
    TEST("host build: the CPU plan keeps two physical cores for the host") {
        static const char eight[] =
            "# CPU,Core,Socket\n0,0,0\n1,0,0\n2,1,0\n3,1,0\n"
            "4,2,0\n5,2,0\n6,3,0\n7,3,0\n";
        static const char six[] = "0,0,0\n1,0,0\n2,1,0\n3,1,0\n4,2,0\n5,2,0\n";
        char list[64];
        unsigned workers = 0;
        ASSERT(ba_cpu_plan_parse(eight, list, sizeof(list), &workers));
        ASSERT_STR_EQ(list, "4,5,6,7");
        ASSERT_EQ(workers, 4u);
        ASSERT(!ba_cpu_plan_parse(six, list, sizeof(list), &workers));
        PASS();
    }
_test_next:;
    return failures;
}

#ifdef __linux__
static int hbt_scope_tests(const struct ba_config *cfg, const char *tmp)
{
    int failures = 0;
    char args[HBT_TEXT], jobs[HBT_TEXT], path[HBT_PATH];
    char job[HBT_PATH];

    TEST("host build: a passing job uses the wrapper's scope properties and releases its scratch") {
        const char *const cmd[] = { "/bin/true", NULL };
        ASSERT_EQ(hbt_run(cfg, cmd), 0);
        (void)snprintf(path, sizeof(path), "%s/stub.args", tmp);
        ASSERT(hbt_slurp(path, args, sizeof(args)));
        ASSERT(strstr(args, "--user\n--scope\n--quiet\n") != NULL);
        ASSERT(strstr(args, "--slice=development.slice\n") != NULL);
        ASSERT(strstr(args, "--property=CPUQuota=400%\n") != NULL);
        ASSERT(strstr(args, "--property=MemoryMax=24G\n") != NULL);
        ASSERT(strstr(args, "--property=MemorySwapMax=0\n") != NULL);
        ASSERT(strstr(args, "--property=CPUWeight=20\n") != NULL);
        ASSERT(strstr(args, "--property=IOWeight=20\n") != NULL);
        ASSERT(strstr(args, "DEVBUILD_ACTIVE=z23\n") != NULL);
        ASSERT(strstr(args, "/usr/bin/taskset\n--cpu-list\n") != NULL);
        ASSERT_EQ(hbt_count_jobs(cfg->scratch_root), 0u);
        (void)snprintf(path, sizeof(path), "%s/state/devbuild.jobs.jsonl", tmp);
        ASSERT(hbt_slurp(path, jobs, sizeof(jobs)));
        ASSERT(strstr(jobs, "\"project\":\"z23\"") != NULL);
        ASSERT(strstr(jobs, "\"rc\":0,") != NULL);
        PASS();
    }

    TEST("host build: a failing job keeps its exit status and its scratch") {
        const char *const cmd[] = { "/bin/sh", "-c",
            "touch \"$TMPDIR/evidence\"; exit 3", NULL };
        char evidence[HBT_PATH + 16];
        ASSERT_EQ(hbt_run(cfg, cmd), 3);
        ASSERT_EQ(hbt_count_jobs(cfg->scratch_root), 1u);
        ASSERT(hbt_first_job(cfg->scratch_root, job, sizeof(job)));
        (void)snprintf(evidence, sizeof(evidence), "%s/evidence", job);
        ASSERT(access(evidence, F_OK) == 0);
        PASS();
    }

    TEST("host build: a caller-owned TMPDIR gets no scratch") {
        struct ba_config own = *cfg;
        const char *const cmd[] = { "/bin/true", NULL };
        own.tmpdir_set = true;
        ASSERT_EQ(hbt_run(&own, cmd), 0);
        ASSERT_EQ(hbt_count_jobs(cfg->scratch_root), 1u);
        PASS();
    }

    TEST("host build: a descendant still holding the scratch retains it") {
        const char *const cmd[] = { "/bin/sh", "-c",
            "sleep 1 >/dev/null 2>&1 & exit 0", NULL };
        ASSERT_EQ(hbt_run(cfg, cmd), 0);
        ASSERT_EQ(hbt_count_jobs(cfg->scratch_root), 2u);
        hbt_nap(1200);
        PASS();
    }
_test_next:;
    return failures;
}

static int hbt_reserve_tests(const struct ba_config *cfg, const char *tmp)
{
    int failures = 0;
    TEST("host build: a free-space reserve refusal defers the job and runs nothing") {
        struct ba_config low = *cfg;
        char marker[HBT_PATH + 16];
        const char *cmd[4] = { "/usr/bin/touch", marker, NULL, NULL };
        (void)snprintf(marker, sizeof(marker), "%s/ran", tmp);
        low.reserve_gib = 1u << 30;
        ASSERT_EQ(hbt_run(&low, cmd), BA_EXIT_DEFERRED);
        ASSERT(access(marker, F_OK) != 0);
        PASS();
    }
_test_next:;
    return failures;
}

static int hbt_limit_tests(const char *tmp)
{
    int failures = 0;
    struct ba_config cfg;
    struct json_value doc;
    const char *const hold[] = { "/bin/sleep", "2", NULL };
    const char *const quick[] = { "/bin/true", NULL };
    pid_t a = -1, b = -1;

    TEST("host build: the lane limit holds and a busy host refuses without --wait") {
        ASSERT(hbt_config(&cfg, tmp, 2));
        a = hbt_spawn(&cfg, hold);
        b = hbt_spawn(&cfg, hold);
        ASSERT(a > 0 && b > 0);
        ASSERT(hbt_wait_counts(cfg.state_dir, 2, 0, &doc));
        json_free(&doc);
        cfg.wait = false;
        ASSERT_EQ(hbt_run(&cfg, quick), BA_EXIT_DEFERRED);
        ASSERT_EQ(hbt_reap(a), 0);
        ASSERT_EQ(hbt_reap(b), 0);
        cfg.wait = true;
        ASSERT_EQ(hbt_run(&cfg, quick), 0);
        PASS();
    }
_test_next:;
    return failures;
}

static int hbt_order_tests(const char *tmp)
{
    int failures = 0;
    struct ba_config cfg;
    struct json_value doc;
    char order[HBT_PATH], text[256];
    char cmd_b[HBT_PATH + 64], cmd_c[HBT_PATH + 64];
    const char *const hold[] = { "/bin/sleep", "1", NULL };
    pid_t a = -1, b = -1, c = -1;

    TEST("host build: waiting jobs are admitted in arrival order") {
        const char *job_b[] = { "/bin/sh", "-c", cmd_b, NULL };
        const char *job_c[] = { "/bin/sh", "-c", cmd_c, NULL };
        ASSERT(hbt_config(&cfg, tmp, 1));
        (void)snprintf(order, sizeof(order), "%s/order", tmp);
        (void)snprintf(cmd_b, sizeof(cmd_b), "echo B >> %s", order);
        (void)snprintf(cmd_c, sizeof(cmd_c), "echo C >> %s", order);
        a = hbt_spawn(&cfg, hold);
        ASSERT(hbt_wait_counts(cfg.state_dir, 1, 0, &doc));
        json_free(&doc);
        b = hbt_spawn(&cfg, job_b);
        ASSERT(hbt_wait_counts(cfg.state_dir, 1, 1, &doc));
        json_free(&doc);
        c = hbt_spawn(&cfg, job_c);
        ASSERT(hbt_wait_counts(cfg.state_dir, 1, 2, &doc));
        ASSERT_EQ(json_get_int(json_get(json_at(json_get(&doc, "queued"), 0),
                                        "pid")), (int64_t)b);
        ASSERT_EQ(json_get_int(json_get(json_at(json_get(&doc, "queued"), 1),
                                        "pid")), (int64_t)c);
        json_free(&doc);
        ASSERT_EQ(hbt_reap(a), 0);
        ASSERT_EQ(hbt_reap(b), 0);
        ASSERT_EQ(hbt_reap(c), 0);
        ASSERT(hbt_slurp(order, text, sizeof(text)));
        ASSERT_STR_EQ(text, "B\nC\n");
        PASS();
    }
_test_next:;
    return failures;
}

static bool hbt_wait_file(const char *path)
{
    for (int i = 0; i < 250; i++) {
        if (access(path, F_OK) == 0)
            return true;
        hbt_nap(20);
    }
    return false;
}

/* The SigIgn mask of /proc/self/status as written by the job. */
static bool hbt_ignored_mask(const char *path, unsigned long long *mask)
{
    char text[HBT_TEXT];
    const char *p;
    if (!hbt_slurp(path, text, sizeof(text)) ||
        !(p = strstr(text, "SigIgn:")))
        return false;
    return sscanf(p, "SigIgn: %llx", mask) == 1;
}

static int hbt_signal_tests(const char *tmp)
{
    int failures = 0;
    struct ba_config cfg;
    char ready[HBT_PATH], got[HBT_PATH], script[2 * HBT_PATH];

    TEST("host build: a SIGTERM sent to the wrapper reaches the job") {
        const char *job[] = { "/bin/sh", "-c", script, NULL };
        pid_t w;
        ASSERT(hbt_config(&cfg, tmp, 1));
        (void)snprintf(ready, sizeof(ready), "%s/term.ready", tmp);
        (void)snprintf(got, sizeof(got), "%s/term.got", tmp);
        (void)snprintf(script, sizeof(script),
                       "trap 'echo got > %s; exit 0' TERM; echo up > %s; "
                       "while :; do sleep 0.05; done", got, ready);
        w = hbt_spawn(&cfg, job);
        ASSERT(w > 0);
        ASSERT(hbt_wait_file(ready));
        ASSERT_EQ(kill(w, SIGTERM), 0);
        ASSERT_EQ(hbt_reap(w), 0);
        ASSERT(access(got, F_OK) == 0);
        PASS();
    }

    TEST("host build: an inherited SIGCHLD ignore keeps the exit status and is not passed to the job") {
        char mask_file[HBT_PATH];
        unsigned long long mask = ~0ull;
        const char *job[] = { "/bin/sh", "-c", script, NULL };
        pid_t w;
        int status = 0;
        ASSERT(hbt_config(&cfg, tmp, 1));
        (void)snprintf(mask_file, sizeof(mask_file), "%s/sigign", tmp);
        (void)snprintf(script, sizeof(script),
                       "grep SigIgn /proc/self/status > %s; exit 5", mask_file);
        w = fork();
        if (w == 0) {
            struct sigaction sa;
            int rc;
            (void)signal(SIGCHLD, SIG_IGN);
            rc = hbt_run(&cfg, job);
            (void)sigaction(SIGCHLD, NULL, &sa);
            _exit(rc == 5 && sa.sa_handler == SIG_IGN ? 0 : 1);
        }
        ASSERT(w > 0);
        ASSERT_EQ(waitpid(w, &status, 0), w);
        ASSERT(WIFEXITED(status));
        ASSERT_EQ(WEXITSTATUS(status), 0);
        ASSERT(hbt_ignored_mask(mask_file, &mask));
        ASSERT_EQ(mask & (1ull << (SIGCHLD - 1)), 0ull);
        PASS();
    }
_test_next:;
    return failures;
}

/* Tickets of 300 waiters, past any fixed listing bound: `live` of them keep
 * their flock (the last `live` names), the rest are dead files. */
static size_t hbt_make_tickets(const char *fifo, size_t total, size_t live,
                               int *fds)
{
    size_t held = 0;
    (void)mkdir(fifo, 0700);
    for (size_t i = 0; i < total; i++) {
        char path[HBT_PATH + 64];
        int fd;
        (void)snprintf(path, sizeof(path), "%s/%019lld-1", fifo,
                       1000000000000000000ll + (long long)i);
        fd = open(path, O_RDONLY | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0)
            return held;
        if (i + live >= total && flock(fd, LOCK_SH) == 0)
            fds[held++] = fd;
        else
            close(fd);
    }
    return held;
}

static int hbt_long_queue_tests(const char *tmp)
{
    enum { TICKETS = 300 };
    int failures = 0;
    int fds[TICKETS];
    struct ba_config cfg;
    struct json_value doc;
    char dir[HBT_PATH], fifo[HBT_PATH + 16], marker[HBT_PATH + 16];
    size_t held;

    TEST("host build: the status lists every waiter of a queue longer than 256") {
        (void)snprintf(dir, sizeof(dir), "%s/long", tmp);
        ASSERT(mkdir(dir, 0700) == 0);
        ASSERT(hbt_config(&cfg, dir, 1));
        (void)snprintf(fifo, sizeof(fifo), "%s/state/z23.fifo", dir);
        (void)mkdir(cfg.state_dir, 0700);
        held = hbt_make_tickets(fifo, TICKETS, TICKETS, fds);
        ASSERT_EQ(held, (size_t)TICKETS);
        json_init(&doc);
        json_set_object(&doc);
        ASSERT(ba_status(cfg.state_dir, &doc));
        ASSERT_EQ(hbt_array_size(&doc, "queued"), (size_t)TICKETS);
        json_free(&doc);
        for (size_t i = 0; i < held; i++)
            close(fds[i]);
        PASS();
    }

    TEST("host build: a live waiter beyond the 256th entry still holds the queue") {
        const char *job[] = { "/usr/bin/touch", marker, NULL };
        pid_t w;
        (void)snprintf(marker, sizeof(marker), "%s/long/ran", tmp);
        (void)snprintf(fifo, sizeof(fifo), "%s/long/state/z23.fifo", tmp);
        held = hbt_make_tickets(fifo, TICKETS, 1, fds);
        ASSERT_EQ(held, 1u);
        w = fork();
        if (w == 0) { /* the job must not keep the waiter's lock alive */
            close(fds[0]);
            _exit(hbt_run(&cfg, job));
        }
        ASSERT(w > 0);
        hbt_nap(400);
        ASSERT(access(marker, F_OK) != 0);
        close(fds[0]);
        ASSERT_EQ(hbt_reap(w), 0);
        ASSERT(access(marker, F_OK) == 0);
        PASS();
    }
_test_next:;
    return failures;
}

#ifdef __linux__
/* A lock whose recorded pid has exited is attributed to the process that
 * still holds its open file description. */
static int hbt_owner_tests(const char *tmp)
{
    int failures = 0;
    struct ba_config cfg;
    struct json_value doc;
    char dir[HBT_PATH], lock[HBT_PATH + 32];

    TEST("host build: an orphaned lock is attributed to the live process of the scanned user only") {
        const struct json_value *row;
        int fd, status = 0;
        pid_t k;
        (void)snprintf(dir, sizeof(dir), "%s/owner", tmp);
        ASSERT(mkdir(dir, 0700) == 0);
        ASSERT(hbt_config(&cfg, dir, 1));
        ASSERT(mkdir(cfg.state_dir, 0700) == 0);
        (void)snprintf(lock, sizeof(lock), "%s/z23.lock", cfg.state_dir);
        fd = open(lock, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
        ASSERT(fd >= 0);
        k = fork();
        if (k == 0)
            _exit(flock(fd, LOCK_EX) == 0 ? 0 : 1);
        ASSERT_EQ(waitpid(k, &status, 0), k);
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        /* Scanning as another user must not read this process, which holds
         * the lock: the holder is then reported without a pid. */
        json_init(&doc);
        json_set_object(&doc);
        ASSERT(ba_status_as(cfg.state_dir, geteuid() + 1, &doc));
        ASSERT_EQ(hbt_array_size(&doc, "running"), 1u);
        row = json_at(json_get(&doc, "running"), 0);
        ASSERT(json_get(row, "pid") == NULL);
        json_free(&doc);
        json_init(&doc);
        json_set_object(&doc);
        ASSERT(ba_status_as(cfg.state_dir, geteuid(), &doc));
        ASSERT_EQ(hbt_array_size(&doc, "running"), 1u);
        row = json_at(json_get(&doc, "running"), 0);
        ASSERT_EQ(json_get_int(json_get(row, "pid")), (int64_t)getpid());
        json_free(&doc);
        close(fd);
        PASS();
    }

    TEST("host build: a holder outside the caller's processes is reported without a pid") {
        const struct json_value *row;
        int fd, status = 0, sync[2];
        char byte = 0;
        pid_t c;
        if (geteuid() == 0) { /* root reads every process */
            PASS();
            goto _test_next;
        }
        (void)snprintf(dir, sizeof(dir), "%s/hidden", tmp);
        ASSERT(mkdir(dir, 0700) == 0);
        ASSERT(hbt_config(&cfg, dir, 1));
        ASSERT(mkdir(cfg.state_dir, 0700) == 0);
        (void)snprintf(lock, sizeof(lock), "%s/z23.lock", cfg.state_dir);
        fd = open(lock, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
        ASSERT(fd >= 0);
        ASSERT(pipe(sync) == 0);
        c = fork();
        if (c == 0) {
            /* A non-dumpable process is owned by root in /proc. Its child
             * takes the lock and exits, leaving the description with c. */
            pid_t g = fork();
            if (g == 0)
                _exit(flock(fd, LOCK_EX) == 0 ? 0 : 1);
            (void)waitpid(g, &status, 0);
            (void)prctl(PR_SET_DUMPABLE, 0);
            (void)!write(sync[1], "x", 1);
            for (;;)
                pause();
        }
        ASSERT(c > 0);
        close(sync[1]);
        ASSERT_EQ(read(sync[0], &byte, 1), 1);
        close(fd);
        json_init(&doc);
        json_set_object(&doc);
        ASSERT(ba_status(cfg.state_dir, &doc));
        ASSERT_EQ(hbt_array_size(&doc, "running"), 1u);
        row = json_at(json_get(&doc, "running"), 0);
        ASSERT_EQ(json_get_int(json_get(row, "lane")), 1);
        ASSERT(json_get(row, "pid") == NULL);
        json_free(&doc);
        (void)kill(c, SIGKILL);
        (void)waitpid(c, &status, 0);
        close(sync[0]);
        PASS();
    }
_test_next:;
    return failures;
}
#endif
#endif /* Linux queue fixtures */

#if !defined(__linux__) && !defined(_WIN32)
static int hbt_platform_refusal_tests(void)
{
    int failures = 0;
    TEST("host build: non-Linux refuses admission and unobserved queue status") {
        struct json_value out = {0};
        json_set_object(&out);
        ASSERT(!ba_status("/unused/host-build-state", &out));
        ASSERT(!ba_status_as("/unused/host-build-state", geteuid(), &out));
        ASSERT_EQ(json_size(&out), 0u);
        json_free(&out);
        const char *const words[] = { "/unused/host-build-command" };
        int rc = 0;
        ASSERT(zcl_native_ops_host_build_try_run(words, 1, 0, &rc));
        ASSERT_EQ(rc, BA_EXIT_DEFERRED);
        struct zcl_command_request request = {0};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.host_build.v1");
        zcl_native_handle_ops_host_build(&request, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(reply.error.code, "HOST_BUILD_PLATFORM_UNAVAILABLE");
        zcl_command_reply_free(&reply);
        zcl_command_reply_init(&reply, "zcl.host_jobs.v1");
        zcl_native_handle_ops_host_jobs(&request, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(reply.error.code, "HOST_BUILD_PLATFORM_UNAVAILABLE");
        zcl_command_reply_free(&reply);
        PASS();
    }
_test_next:;
    return failures;
}
#endif

static int hbt_reserve_env_tests(void)
{
    int failures = 0;
    TEST("host build: the reserve defaults to 30 GiB and DEVBUILD_RESERVE_GIB overrides it") {
        char *saved = getenv("DEVBUILD_RESERVE_GIB");
        char keep[32] = "";
        if (saved)
            (void)snprintf(keep, sizeof(keep), "%s", saved);
        (void)unsetenv("DEVBUILD_RESERVE_GIB");
        ASSERT_EQ(ba_reserve_gib_from_env(), 30u);
        (void)setenv("DEVBUILD_RESERVE_GIB", "7", 1);
        ASSERT_EQ(ba_reserve_gib_from_env(), 7u);
        (void)setenv("DEVBUILD_RESERVE_GIB", "0", 1);
        ASSERT_EQ(ba_reserve_gib_from_env(), 0u);
        (void)setenv("DEVBUILD_RESERVE_GIB", "-1", 1);
        ASSERT_EQ(ba_reserve_gib_from_env(), 30u);
        (void)setenv("DEVBUILD_RESERVE_GIB", "12x", 1);
        ASSERT_EQ(ba_reserve_gib_from_env(), 30u);
        (void)setenv("DEVBUILD_RESERVE_GIB", "", 1);
        ASSERT_EQ(ba_reserve_gib_from_env(), 30u);
        if (saved)
            (void)setenv("DEVBUILD_RESERVE_GIB", keep, 1);
        else
            (void)unsetenv("DEVBUILD_RESERVE_GIB");
        PASS();
    }
_test_next:;
    return failures;
}

#ifdef __linux__
static int hbt_scope_probe(const char *scope, uid_t uid, void *context)
{
    (void)scope;
    (void)uid;
    return *(const int *)context;
}

static bool hbt_broker_record(const char *root, const char *part,
                              unsigned long long tick, const char *version)
{
    char path[HBT_PATH + 128];
    (void)snprintf(path, sizeof(path), "%s/%s/%d-%llu-100", root, part,
                   (int)getpid(), tick);
    FILE *f = fopen(path, "w");
    if (!f) return false;
    bool ok = fprintf(f, "%d %llu devbuild-%d-%llu-100.scope z23 release "
        "16 20 4 200 100 %s 2\n", (int)getpid(), tick, (int)getpid(),
        tick, version) > 0;
    return fclose(f) == 0 && ok;
}

static void hbt_broker_doc(struct json_value *doc)
{
    struct json_value rows = {0};
    json_set_object(doc);
    json_set_array(&rows);
    (void)json_push_kv(doc, "running", &rows);
    (void)json_push_kv(doc, "queued", &rows);
    json_free(&rows);
}

static bool hbt_broker_malformed(const char *root, unsigned long long tick,
                                 unsigned kind)
{
    char path[HBT_PATH + 128], text[1024];
    (void)snprintf(path, sizeof(path), "%s/running/%d-%llu-100", root,
                   (int)getpid(), tick);
    int n = snprintf(text, sizeof(text),
        "%d %llu devbuild-%d-%llu-100.scope z23 release 16 20 4 200 100 broker-v5 2",
        (int)getpid(), tick, (int)getpid(), tick);
    if (n <= 0 || (size_t)n + 16 >= sizeof(text)) return false;
    size_t size = (size_t)n;
    if (kind == 0) {
        memcpy(text + size, "\0trailing", 9);
        size += 9;
    } else if (kind == 1) {
        memset(text + size, 'x', sizeof(text) - size);
        size = sizeof(text);
    } else if (kind == 2) {
        text[0] = 'x';
    } else {
        memcpy(text + size, " extra", 6);
        size += 6;
    }
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fwrite(text, 1, size, f) == size;
    return fclose(f) == 0 && ok;
}

static unsigned long long hbt_start_tick(void)
{
    char text[4096];
    if (!hbt_slurp("/proc/self/stat", text, sizeof(text))) return 0;
    char *at = strrchr(text, ')');
    if (!at) return 0;
    at += 2;
    for (int field = 3; field < 22; field++) {
        at = strchr(at, ' ');
        if (!at) return 0;
        at++;
    }
    return strtoull(at, NULL, 10);
}

static int hbt_broker_tests(const char *tmp)
{
    int failures = 0;
    TEST("host build: broker records preserve live, stale and unknown scope states") {
        char root[HBT_PATH], path[HBT_PATH + 32];
        struct json_value doc = {0};
        unsigned long long tick = hbt_start_tick();
        int scope = 0;
        ASSERT(tick > 0);
        (void)snprintf(root, sizeof(root), "%s/broker", tmp);
        ASSERT(mkdir(root, 0700) == 0);
        (void)snprintf(path, sizeof(path), "%s/running", root);
        ASSERT(mkdir(path, 0700) == 0);
        (void)snprintf(path, sizeof(path), "%s/queue-v5", root);
        ASSERT(mkdir(path, 0700) == 0);
        ASSERT(hbt_broker_record(root, "running", tick, "broker-v5"));
        ASSERT(hbt_broker_record(root, "queue-v5", tick, "broker-v5"));
        hbt_broker_doc(&doc);
        zcl_alloc_fault_fail_next("build_status_broker_view");
        bool allocation_refused =
            !ba_status_broker(root, geteuid(), hbt_scope_probe, &scope, &doc);
        zcl_alloc_fault_clear();
        ASSERT(allocation_refused);
        ASSERT_EQ(hbt_array_size(&doc, "running"), (size_t)0);
        ASSERT_EQ(hbt_array_size(&doc, "queued"), (size_t)0);
        ASSERT(ba_status_broker(root, geteuid(), hbt_scope_probe, &scope, &doc));
        ASSERT_EQ(hbt_array_size(&doc, "running"), (size_t)1);
        ASSERT_EQ(hbt_array_size(&doc, "queued"), (size_t)0);
        const struct json_value *row = json_at(json_get(&doc, "running"), 0);
        ASSERT(strcmp(json_get_str(json_get(row, "source")), "broker-v5") == 0);
        ASSERT(json_get(row, "cmd") == NULL && json_get(row, "cwd") == NULL);
        json_free(&doc);
        ASSERT(hbt_broker_record(root, "running", tick + 1, "broker-v5"));
        ASSERT(hbt_broker_record(root, "queue-v5", tick + 1, "broker-v5"));
        hbt_broker_doc(&doc);
        ASSERT(ba_status_broker(root, geteuid(), hbt_scope_probe, &scope, &doc));
        ASSERT_EQ(hbt_array_size(&doc, "running"), (size_t)1);
        ASSERT_EQ(hbt_array_size(&doc, "queued"), (size_t)0);
        json_free(&doc);
        scope = 1;
        hbt_broker_doc(&doc);
        ASSERT(ba_status_broker(root, geteuid(), hbt_scope_probe, &scope, &doc));
        ASSERT_EQ(hbt_array_size(&doc, "running"), (size_t)2);
        json_free(&doc);
        scope = -1;
        hbt_broker_doc(&doc);
        ASSERT(ba_status_broker(root, geteuid(), hbt_scope_probe, &scope, &doc));
        ASSERT_EQ(hbt_array_size(&doc, "running"), (size_t)2);
        ASSERT(strcmp(json_get_str(json_get(&doc, "broker_coverage")), "unknown") == 0);
        json_free(&doc);
        ASSERT(hbt_broker_record(root, "running", tick + 1, "broker-v6"));
        hbt_broker_doc(&doc);
        ASSERT(ba_status_broker(root, geteuid(), hbt_scope_probe, &scope, &doc));
        ASSERT_EQ(hbt_array_size(&doc, "running"), (size_t)1);
        ASSERT(json_get_int(json_get(&doc, "broker_unknown_records")) > 0);
        json_free(&doc);
        for (unsigned kind = 0; kind < 4; kind++) {
            ASSERT(hbt_broker_malformed(root, tick + 1, kind));
            hbt_broker_doc(&doc);
            ASSERT(ba_status_broker(root, geteuid(), hbt_scope_probe, &scope, &doc));
            ASSERT_EQ(hbt_array_size(&doc, "running"), (size_t)1);
            ASSERT(strcmp(json_get_str(json_get(&doc, "broker_coverage")), "unknown") == 0);
            json_free(&doc);
        }
        ASSERT(hbt_broker_record(root, "running", tick + 1, "broker-v5"));
        hbt_broker_doc(&doc);
        ASSERT(ba_status_broker(root, geteuid(), NULL, NULL, &doc));
        ASSERT_EQ(hbt_array_size(&doc, "running"), (size_t)2);
        ASSERT(strcmp(json_get_str(json_get(&doc, "broker_coverage")), "unknown") == 0);
        json_free(&doc);
        (void)snprintf(path, sizeof(path), "%s/running/invalid", root);
        ASSERT(symlink("/dev/null", path) == 0);
        hbt_broker_doc(&doc);
        ASSERT(ba_status_broker(root, geteuid(), hbt_scope_probe, &scope, &doc));
        ASSERT(json_get_int(json_get(&doc, "broker_unknown_records")) >= 2);
        json_free(&doc);
        (void)snprintf(path, sizeof(path), "%s/absent", root);
        hbt_broker_doc(&doc);
        ASSERT(ba_status_broker(path, geteuid(), hbt_scope_probe, &scope, &doc));
        ASSERT(strcmp(json_get_str(json_get(&doc, "broker_coverage")), "unknown") == 0);
        json_free(&doc);
        PASS();
    }
_test_next:;
    return failures;
}

static int hbt_broker_display_tests(const char *tmp)
{
    int failures = 0;
    TEST("host build: broker display limit retains exact omitted count and bounded JSON") {
        char root[HBT_PATH], path[HBT_PATH + 32];
        struct json_value doc = {0};
        int scope = 1;
        const struct zcl_command_spec *spec = zcl_command_registry_find(
            zcl_command_catalog(), "ops.host.jobs", NULL);
        ASSERT(spec != NULL);
        ASSERT_EQ(spec->budget_bytes, (size_t)65536);
        (void)snprintf(root, sizeof(root), "%s/broker-display", tmp);
        ASSERT(mkdir(root, 0700) == 0);
        (void)snprintf(path, sizeof(path), "%s/running", root);
        ASSERT(mkdir(path, 0700) == 0);
        (void)snprintf(path, sizeof(path), "%s/queue-v5", root);
        ASSERT(mkdir(path, 0700) == 0);
        for (unsigned i = 0; i < BA_BROKER_DISPLAY_MAX; i++)
            ASSERT(hbt_broker_record(root, "running", 1000 + i, "broker-v5"));
        hbt_broker_doc(&doc);
        ASSERT(ba_status_broker(root, geteuid(), hbt_scope_probe, &scope, &doc));
        ASSERT_EQ(hbt_array_size(&doc, "running"), (size_t)BA_BROKER_DISPLAY_MAX);
        ASSERT_EQ(json_get_int(json_get(&doc, "broker_omitted")), 0);
        ASSERT(strcmp(json_get_str(json_get(&doc, "broker_coverage")), "observed") == 0);
        ASSERT(json_write(&doc, NULL, 0) + 8192 < (size_t)spec->budget_bytes);
        json_free(&doc);
        ASSERT(hbt_broker_record(root, "running", 2000, "broker-v5"));
        /* Duplicate every running ID in the queue, including the omitted ID. */
        for (unsigned i = 0; i < BA_BROKER_DISPLAY_MAX; i++)
            ASSERT(hbt_broker_record(root, "queue-v5", 1000 + i, "broker-v5"));
        ASSERT(hbt_broker_record(root, "queue-v5", 2000, "broker-v5"));
        hbt_broker_doc(&doc);
        ASSERT(ba_status_broker(root, geteuid(), hbt_scope_probe, &scope, &doc));
        ASSERT_EQ(hbt_array_size(&doc, "running"), (size_t)BA_BROKER_DISPLAY_MAX);
        ASSERT_EQ(hbt_array_size(&doc, "queued"), (size_t)0);
        ASSERT_EQ(json_get_int(json_get(&doc, "broker_omitted")), 1);
        ASSERT(strcmp(json_get_str(json_get(&doc, "broker_coverage")), "partial") == 0);
        ASSERT(json_write(&doc, NULL, 0) + 8192 < (size_t)spec->budget_bytes);
        json_free(&doc);
        PASS();
    }
_test_next:;
    return failures;
}
#endif

int test_host_build(void)
{
    int failures = 0;
    failures += hbt_cpu_plan_tests();
#ifdef __linux__
    char tmp[HBT_PATH] = "";
    struct ba_config cfg;
    if (!test_mkdtemp(tmp, sizeof(tmp), "host_build") ||
        !hbt_config(&cfg, tmp, 1)) {
        printf("test_host_build: fixture failed\n");
        return failures + 1;
    }
    failures += hbt_scope_tests(&cfg, tmp);
    failures += hbt_reserve_tests(&cfg, tmp);
    failures += hbt_limit_tests(tmp);
    failures += hbt_order_tests(tmp);
    failures += hbt_signal_tests(tmp);
    failures += hbt_long_queue_tests(tmp);
#ifdef __linux__
    failures += hbt_owner_tests(tmp);
#endif
#ifdef __linux__
    failures += hbt_broker_tests(tmp);
    failures += hbt_broker_display_tests(tmp);
#endif
    (void)test_rm_rf_recursive(tmp);
#elif !defined(_WIN32)
    failures += hbt_platform_refusal_tests();
#endif
    failures += hbt_reserve_env_tests();
    if (failures == 0)
        printf("test_host_build: all passed\n");
    else
        printf("test_host_build: %d FAILED\n", failures);
    return failures;
}
