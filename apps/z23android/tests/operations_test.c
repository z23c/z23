/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "operations.h"
#include "params.h"
#include "setup_state.h"
#include "startup_auth.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#if defined(__linux__) && __has_include(<sys/pidfd.h>)
#include <sys/pidfd.h>
#define ZAPP_TEST_HAVE_PIDFD 1
#endif
#include <sys/wait.h>
#include <time.h>

int __real_clock_gettime(clockid_t id, struct timespec *out);
int __wrap_clock_gettime(clockid_t id, struct timespec *out)
{
    if (getenv("ZAPP_TEST_CLOCK_FAIL")) return -1;
    return __real_clock_gettime(id, out);
}

extern char **environ;

/* The fixed entries the app gives the child: the drain budget, the page cache and TMPDIR. */
static bool child_fixed_environment(void)
{
    const char *batch = getenv("ZCL_CATCHUP_DRAIN_BUDGET_MS");
    if (!batch || strcmp(batch, "100")) return false;
    size_t cache_entries = 0;
    for (char **e = environ; *e; ++e)
        if (!strncmp(*e, "ZCL_BIP_PAGE_CACHE_KIB=", sizeof("ZCL_BIP_PAGE_CACHE_KIB=") - 1))
            ++cache_entries;
    const char *cache = getenv("ZCL_BIP_PAGE_CACHE_KIB");
    if (cache_entries != 1 || !cache || strcmp(cache, "32768")) return false;
    const char *temp = getenv("TMPDIR");
    return temp && !strcmp(temp, "/tmp/private-tmp");
}

/* The state root, and HOME: the parent's HOME when one is inherited, else the state root. */
/* Exactly one HOME= entry in the child environment, counted the way the fixed entries are. */
static bool single_home_entry(void)
{
    size_t home_entries = 0;
    for (char **e = environ; *e; ++e)
        if (!strncmp(*e, "HOME=", sizeof("HOME=") - 1)) ++home_entries;
    return home_entries == 1;
}

static bool child_root_environment(void)
{
    const char *state = getenv("XDG_STATE_HOME");
    const char *preserved = getenv("ZAPP_TEST_PRESERVED");
    const char *want = getenv("ZAPP_TEST_STATE");
    const char *home = getenv("HOME");
    const char *home_want = getenv("ZAPP_TEST_HOME");
    if (!single_home_entry() || !home || !want || strcmp(home, home_want ? home_want : want)) return false;
    return state && !strcmp(state, want) && preserved && !strcmp(preserved, "yes");
}

/* The wallet variables the app never passes on: a node must not make or fill a wallet from its environment. */
static bool child_wallet_environment(void)
{
    static const char *const names[] = {"ZCL_WALLET_PASSPHRASE", "ZCL_ALLOW_PLAINTEXT_WALLET", "ZCL_RECOVERY_PHRASE",
                                        "ZCL_WALLET_NO_PHRASE_BACKUP"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (getenv(names[i])) return false;
    return true;
}
static bool child_environment(void)
{
    return child_fixed_environment() && child_root_environment() && child_wallet_environment();
}

static volatile sig_atomic_t interrupted;
static void on_interrupt(int signal) { (void)signal; interrupted = 1; }
/* A stand-in for a node left by an earlier app: "orphan" dies on SIGINT, "saving" takes a moment
 * to save after SIGINT, as a node does, and marks itself ready once it handles SIGINT. */
static int orphan(const char *mode, const char *data)
{
    alarm(30);
    sigset_t blocked, waiting;
    sigemptyset(&blocked); sigaddset(&blocked, SIGINT);
    if (sigprocmask(SIG_BLOCK, &blocked, &waiting)) return 6;
    sigdelset(&waiting, SIGINT);
    if (!strcmp(mode, "saving")) {
        char ready[300];
        signal(SIGINT, on_interrupt);
        snprintf(ready, sizeof(ready), "%s/ready", data + strlen("-datadir="));
        FILE *f = fopen(ready, "w");
        if (!f || fclose(f)) return 5;
    }
    while (!interrupted) sigsuspend(&waiting);
    struct timespec save = {.tv_sec = 2}; nanosleep(&save, NULL);
    return 0;
}

/* Private by default: onion peers only, no clearnet dial, no DNS seeding, loopback bind, then one
 * -addnode for the fleet peer the test supplies. Returns 0 when argv from index first on is exactly that. */
static int private_tail(int argc, char **argv, int first, const char *peer)
{
    if (argc != first + 2 + (peer ? 1 : 0) || strcmp(argv[first], "-onlynet=onion") ||
        strcmp(argv[first + 1], "-bind=127.0.0.1")) return 8;
    if (peer) {
        char want_peer[200];
        snprintf(want_peer, sizeof(want_peer), "-addnode=%s", peer);
        if (strcmp(argv[first + 2], want_peer)) return 9;
    }
    return 0;
}
/* The node arguments the app builds. ZAPP_TEST_PARAMS_ARG is the one extra argument it must add;
 * "none" or unset means none. Returns 0 when they are right. */
static int node_arguments(int argc, char **argv)
{
    const char *want = getenv("ZAPP_TEST_PARAMS_ARG");
    bool with_params = want && strcmp(want, "none") != 0;
    if (strcmp(argv[2], "-operator-lane=canonical") || strcmp(argv[3], "-tor") ||
        strcmp(argv[4], "-onion-persist") || strcmp(argv[5], "-flysync-auto") || strcmp(argv[6], "-nolegacyimport") ||
        strcmp(argv[7], "-nolegacyutxoimport")) return 4;
    int next = 8, first = with_params ? 13 : 12;
    if (with_params && strcmp(argv[next++], want) != 0) return 7;
    if (strcmp(argv[next++], "-private-listeners") || strcmp(argv[next++], "-observation=0")) return 5;
    if (strcmp(argv[next++], "-walletbackup=0")) return 10;
    if (strcmp(argv[next++], "-wallet-startup-auth-fd=198")) return 13;
    return private_tail(argc, argv, first, getenv("ZAPP_TEST_ADDNODE"));
}

static int preview_child(int argc, char **argv)
{
    if (argc > 2 && !strcmp(argv[1], "fleet") && !strcmp(argv[2], "preview")) {
        char body[16384]; size_t n = fread(body, 1, sizeof(body) - 1, stdin); body[n] = 0;
        if (strstr(body, "quick")) { puts("{\"ok\":true}"); return 0; }
        const char *dir = NULL;
        for (int i = 3; i < argc; ++i) if (!strncmp(argv[i], "-datadir=", 9)) dir = argv[i] + 9;
        if (!dir) return 1;
        char started[1200], marker[1200];
        snprintf(started, sizeof(started), "%s/started", dir);
        snprintf(marker, sizeof(marker), "%s/descendant", dir);
        pid_t descendant = fork();
        if (descendant < 0) return 1;
        if (!descendant) { sleep(2); FILE *f = fopen(marker, "w"); if (f) fclose(f); _exit(0); }
        FILE *f = fopen(started, "w"); if (!f || fclose(f)) return 1;
        sleep(10); return 0;
    }
    return -1;
}
static int fleet_child(int argc, char **argv)
{
    int preview = preview_child(argc, argv);
    if (preview >= 0) return preview;
    if (argc > 2 && !strcmp(argv[1], "fleet") && !strcmp(argv[2], "import")) {
        char body[16384]; size_t n = fread(body, 1, sizeof(body) - 1, stdin); body[n] = 0;
        if (strstr(body, "refused")) { puts("{\"ok\":false}"); return 0; }
        if (strstr(body, "partial")) { puts("{\"ok\":false,\"error\":{\"code\":\"FLEET_IMPORT_PARTIAL\"}}"); return 0; }
        puts("{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet.import.v1\"}}"); return 0;
    }
    if (argc > 3 && !strcmp(argv[1], "core") && !strcmp(argv[2], "network") && !strcmp(argv[3], "peers")) {
        for (int i = 1; i < argc; ++i) if (!strncmp(argv[i], "-datadir=", 9)) {
            char marker[1024]; snprintf(marker, sizeof(marker), "%s/dial-called", argv[i] + 9);
            FILE *f = fopen(marker, "w"); if (!f || fclose(f)) return 1;
        }
        puts("{\"ok\":true,\"data\":{\"schema\":\"zcl.peer_add.v1\"}}"); return 0;
    }
    return -1;
}
struct preview_test { struct zapp_runtime *r; atomic_bool cancel; enum zapp_preview_result result; char out[256]; };
static void *preview_thread(void *arg)
{
    struct preview_test *t = arg;
    t->result = zapp_fleet_preview_cancelable(t->r, "invitation", t->out, sizeof(t->out), &t->cancel);
    return NULL;
}
static void preview_cancel_tests(struct zapp_runtime *r)
{
    char directory[] = "/tmp/zapp-preview-XXXXXX", started[256], descendant[256], saved[sizeof(r->directory)];
    assert(mkdtemp(directory));
    snprintf(started, sizeof(started), "%s/started", directory);
    snprintf(descendant, sizeof(descendant), "%s/descendant", directory);
    memcpy(saved, r->directory, sizeof(saved)); snprintf(r->directory, sizeof(r->directory), "%s", directory);
    struct preview_test t = {.r = r}; atomic_init(&t.cancel, true);
    assert(zapp_fleet_preview_cancelable(r, "invitation", t.out, sizeof(t.out), &t.cancel) == ZAPP_PREVIEW_CANCELLED);
    assert(zapp_fleet_machine_preview_cancelable(r, "line", t.out, sizeof(t.out), &t.cancel) == ZAPP_PREVIEW_CANCELLED);
    assert(access(started, F_OK) != 0);
    atomic_store(&t.cancel, false);
    pthread_t worker; assert(pthread_create(&worker, NULL, preview_thread, &t) == 0);
    for (int i = 0; i < 200 && access(started, F_OK) != 0; ++i) { struct timespec d = {.tv_nsec = 10000000}; nanosleep(&d, NULL); }
    assert(access(started, F_OK) == 0);
    struct timespec a, b; assert(clock_gettime(CLOCK_MONOTONIC, &a) == 0);
    atomic_store(&t.cancel, true); assert(pthread_join(worker, NULL) == 0);
    assert(clock_gettime(CLOCK_MONOTONIC, &b) == 0);
    assert((b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000 < 1000);
    assert(t.result == ZAPP_PREVIEW_CANCELLED && !t.out[0]);
    atomic_store(&t.cancel, false);
    assert(zapp_fleet_machine_preview_cancelable(r, "quick", t.out, sizeof(t.out), &t.cancel) == ZAPP_PREVIEW_OK);
    sleep(3); assert(access(descendant, F_OK) != 0); assert(unlink(started) == 0);
    assert(rmdir(directory) == 0); memcpy(r->directory, saved, sizeof(saved));
}
/* The status child and node leave separate markers so ordering is observable. */
static void preload_marker(const char *dir, const char *name, long value)
{
    char path[1200];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "w");
    if (f) { fprintf(f, "%ld", value); fclose(f); }
}
static int preload_status_child(const char *mode, const char *dir)
{
    char input[1200];
    size_t n = fread(input, 1, sizeof(input) - 1, stdin);
    input[n] = 0;
    if (!strstr(input, dir)) return 8;
    preload_marker(dir, "preload-started", (long)getpid());
    if (!strcmp(mode, "wait")) { sleep(60); return 1; }
    if (!strcmp(mode, "fail")) return 1;
    if (!strcmp(mode, "delay")) { sleep(1); preload_marker(dir, "preload-completed", 1); }
    if (!strcmp(mode, "signal")) {
        puts("{\"ok\":false,\"error\":{\"code\":\"WALLET_LOCKED\",\"facts\":{\"persisted_shielded_address\":\"zs1fixture\"}}}");
        fflush(stdout);
        raise(SIGKILL);
    }

    if (!strcmp(mode, "locked") || !strcmp(mode, "wrongexit")) {
        puts("{\"ok\":false,\"error\":{\"code\":\"WALLET_LOCKED\",\"facts\":{\"persisted_shielded_address\":\"zs1fixture\"}}}");
        return !strcmp(mode, "locked") ? 3 : 1;
    }
    puts("{\"ok\":true,\"data\":{\"persisted_shielded_address\":\"zs1fixture\"}}");
    return 0;
}
static int preload_child(int argc, char **argv)
{
    const char *mode = getenv("ZAPP_TEST_PRELOAD");
    if (!mode) return -1;
    const char *dir = NULL;
    for (int i = 1; i < argc; ++i)
        if (!strncmp(argv[i], "-datadir=", 9)) dir = argv[i] + 9;
    if (!dir) return -1;
    if (!strncmp(argv[1], "-datadir=", 9)) {
        char ready[1200];
        snprintf(ready, sizeof(ready), "%s/preload-started", dir);
        if (access(ready, F_OK) != 0) return 10;
        preload_marker(dir, "node-spawned", 1);
        return -1;
    }
    if (argc < 5 || strcmp(argv[1], "core") || strcmp(argv[2], "wallet") ||
        strcmp(argv[3], "recovery") || strcmp(argv[4], "status")) return -1;
    return preload_status_child(mode, dir);
}
static int basic_child(int argc, char **argv)
{
    if ((argc >= 14 && argc <= 16) && !strncmp(argv[1], "-datadir=", 9)) {
        int bad = node_arguments(argc, argv);
        if (bad) return bad;
        if (getenv("ZAPP_TEST_STARTUP_AUTH")) {
            const char request[8] = {'Z','W','A','1',1,0,0,0};
            if (write(198, request, sizeof(request)) != sizeof(request)) return 14;
            for (;;) pause();
        }
        puts("full node arguments accepted");
        return 0;
    }
    if (argc > 2 && strcmp(argv[1], "core") == 0 && strcmp(argv[2], "status") == 0) {
        for (int i = 0; i < 5000; ++i) putchar('x');
        return 0;
    }
    return -1;
}
static bool install_fixed_args(int argc, char **argv, int i, bool with_params, const char *datadir)
{
    return argc == (with_params ? 7 : 6) && !strcmp(argv[1], datadir) &&
        !strcmp(argv[2], "-operator-lane=canonical") && !strcmp(argv[3], "-nolegacyimport") &&
        !strcmp(argv[4], "-nolegacyutxoimport") && i == 5;
}

static bool install_child_args(int argc, char **argv, int i)
{
    const char *allow = getenv("ZCL_DEPLOY_ALLOW_CANONICAL");
    const char *params = getenv("ZAPP_TEST_PARAMS_ARG");
    bool with_params = params && strcmp(params, "none");
    char expected[1400], expected_data[1200];
    const char *test_dir = getenv("ZAPP_TEST_STATE");
    if (!test_dir || snprintf(expected_data, sizeof(expected_data), "-datadir=%s", test_dir) >= (int)sizeof(expected_data)) return false;
    if (!install_fixed_args(argc, argv, i, with_params, expected_data)) return false;
    return snprintf(expected, sizeof(expected), "-install-consensus-bundle=%s/install-bundle.sqlite", argv[1] + 9) < (int)sizeof(expected) &&
        !strcmp(argv[5], expected) && (!with_params || !strcmp(argv[6], params)) && allow && !strcmp(allow, "1");
}
static int install_child(int argc, char **argv)
{
    for (int i = 1; i < argc; ++i) {
        if (strncmp(argv[i], "-install-consensus-bundle=", 26)) continue;
        if (!install_child_args(argc, argv, i)) return 11;
        const char *mode = getenv("ZAPP_TEST_INSTALL");
        if (mode && !strcmp(mode, "block")) { for (;;) pause(); }
        return mode && !strcmp(mode, "fail") ? 1 : 0;
    }
    return -1;
}

static int child(int argc, char **argv)
{
    if (!child_environment()) return 3;
    int installer = install_child(argc, argv);
    if (installer >= 0) return installer;
    if (getenv("ZCL_DEPLOY_ALLOW_CANONICAL")) return 12;
    int preload = preload_child(argc, argv);
    if (preload >= 0) return preload;
    int basic = basic_child(argc, argv);
    if (basic >= 0) return basic;
    int fleet = fleet_child(argc, argv);
    if (fleet >= 0) return fleet;
    if (argc > 2 && strcmp(argv[1], "fleet") == 0 && strcmp(argv[2], "join") == 0) {
        char body[16384];
        size_t n = fread(body, 1, sizeof(body) - 1, stdin);
        body[n] = 0;
        if (!strstr(body, "\"token\":\"invitation\"")) return 1;
        puts("receipt");
        return 0;
    }
    return 2;
}

static void plain_text_tests(void)
{
    char failed[128] = "{\"ok\":false,\"error\":{\"code\":\"E\",\"message\":\"The manager is offline.\"}}";
    zapp_plain_text(failed, sizeof(failed));
    assert(!strcmp(failed, "The manager is offline."));
    char bare[64] = "{\"ok\":false}";
    zapp_plain_text(bare, sizeof(bare));
    assert(!strcmp(bare, "The command did not return a readable result."));
    char warned[160] = "warning: slow disk\n{\"ok\":false,\"error\":{\"message\":\"Join refused.\"}}";
    assert(zapp_json_object(warned) == strchr(warned, '{') && !zapp_json_object("Node starting."));
    zapp_plain_text(warned, sizeof(warned));
    assert(!strcmp(warned, "Join refused."));
    char words[32] = "Node starting.";
    zapp_plain_text(words, sizeof(words));
    assert(!strcmp(words, "Node starting."));
}

static void fleet_preview_tests(void)
{
    const char *key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    char reply[400], preview[512] = "";
    assert(snprintf(reply, sizeof(reply), "warning: local cache\n{\"ok\":true,\"data\":{"
                    "\"schema\":\"zcl.fleet.invite_preview.v1\",\"name\":\"phone\","
                    "\"operator_pubkey\":\"%s\",\"expires_unix\":2000000000}}", key) > 0);
    assert(zapp_fleet_preview_text(reply, preview, sizeof(preview)));
    assert(strstr(preview, "Phone name: phone") && strstr(preview, "0123456789abcdef 0123456789abcdef"));
    assert(!zapp_fleet_preview_text(reply, preview, 10));
    assert(!zapp_fleet_preview_text("{\"ok\":false}", preview, sizeof(preview)));
    assert(!zapp_fleet_preview_text("{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet.join.v1\"}}", preview, sizeof(preview)));
}

static void fleet_machine_preview_tests(void)
{
    char reply[1000], display[512], onion[128];
    const char *key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const char *host = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion";
    assert(snprintf(reply, sizeof(reply), "{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet.preview.v1\",\"kind\":\"machine\",\"name\":\"manager\",\"operator_pubkey\":\"%s\",\"box_pubkey\":\"%s\",\"relay_port\":22200,\"enrolled_at\":1700000000,\"onion\":\"%s\"}}", key, key, host) > 0);
    assert(zapp_fleet_machine_preview_text(reply, display, sizeof(display), onion, sizeof(onion)));
    assert(strstr(display, "manager") && !strcmp(onion, host));
    assert(!zapp_fleet_machine_preview_text("{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet.preview.v1\",\"kind\":\"head\"}}", display, sizeof(display), onion, sizeof(onion)));
    assert(snprintf(reply, sizeof(reply), "{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet.preview.v1\",\"kind\":\"machine\",\"name\":\"manager\",\"operator_pubkey\":\"%s\",\"box_pubkey\":\"%s\",\"relay_port\":22200,\"enrolled_at\":1700000000,\"onion\":\"bad.onion:0\"}}", key, key) > 0);
    assert(!zapp_fleet_machine_preview_text(reply, display, sizeof(display), onion, sizeof(onion)));
}
static void fleet_receipt_tests(void)
{
    char receipt[160] = "previous", token[129], reply[300];
    memset(token, 'A', sizeof(token) - 1); token[126] = '-'; token[127] = '_'; token[128] = 0;
    assert(snprintf(reply, sizeof(reply), "warning: slow disk\n{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet.join.v1\",\"receipt\":\"%s\"}}", token) > 0);
    assert(zapp_fleet_join_receipt(reply, receipt, sizeof(receipt)));
    assert(!strcmp(receipt, token));
    assert(!zapp_fleet_join_receipt(reply, receipt, strlen(receipt)));
    assert(!strcmp(receipt, token));
    assert(snprintf(reply, sizeof(reply), "{\"ok\":false,\"data\":{\"schema\":\"zcl.fleet.join.v1\",\"receipt\":\"%s\"}}", token) > 0);
    assert(!zapp_fleet_join_receipt(reply, receipt, sizeof(receipt)));
    assert(!strcmp(receipt, token));
    assert(snprintf(reply, sizeof(reply), "{\"ok\":true,\"data\":{\"schema\":\"other\",\"receipt\":\"%s\"}}", token) > 0);
    assert(!zapp_fleet_join_receipt(reply, receipt, sizeof(receipt)));
    assert(!strcmp(receipt, token));
    token[64] = ' ';
    assert(snprintf(reply, sizeof(reply), "{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet.join.v1\",\"receipt\":\"%s\"}}", token) > 0);
    assert(!zapp_fleet_join_receipt(reply, receipt, sizeof(receipt)));
    token[64] = 'A';
    assert(!strcmp(receipt, token));
    const char *refused[] = {
        NULL, "", "Node starting.", "{",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet.join.v1\",\"receipt\":\"a\"}}",
        "{\"ok\":false,\"data\":{\"schema\":\"zcl.fleet.join.v1\",\"receipt\":\"refused\"}}",
        "{\"ok\":true,\"data\":{\"schema\":\"other\",\"receipt\":\"wrong\"}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet.join.v1\",\"receipt\":\"\"}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet.join.v1\",\"receipt\":\"bad text\"}}"
    };
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); ++i) {
        assert(!zapp_fleet_join_receipt(refused[i], receipt, sizeof(receipt)));
        assert(!strcmp(receipt, token));
    }
    assert(!zapp_fleet_join_receipt(reply, NULL, sizeof(receipt)));
}

static pid_t spawn_orphan(const char *self, const char *first, const char *second, const char *pidfile)
{
    pid_t other = fork();
    assert(other >= 0);
    if (!other) {
        /* A non-interactive shell starts background jobs with SIGINT ignored, and exec keeps that. */
        if (signal(SIGINT, SIG_DFL) != SIG_ERR) execl(self, self, first, second, (char *)NULL);
        _exit(127);
    }
    FILE *f = fopen(pidfile, "w");
    assert(f && fprintf(f, "%d\n", (int)other) > 0 && fclose(f) == 0);
    return other;
}
static void await_exec(pid_t pid, const char *first)
{
    char file[64], args[256];
    snprintf(file, sizeof(file), "/proc/%d/cmdline", (int)pid);
    for (int i = 0; i < 500; ++i) {
        FILE *f = fopen(file, "r");
        size_t n = f ? fread(args, 1, sizeof(args) - 1, f) : 0;
        if (f) fclose(f);
        args[n] = 0;
        if (n > strlen(args) + 1 && !strcmp(args + strlen(args) + 1, first)) return;
        struct timespec pause = {.tv_nsec = 10000000}; nanosleep(&pause, NULL);
    }
    assert(!"the child never ran");
}
static void await_running(struct zapp_runtime *r)
{
    for (int i = 0; i < 500 && !zapp_node_running(r); ++i) {
        struct timespec pause = {.tv_nsec = 10000000}; nanosleep(&pause, NULL);
    }
    assert(zapp_node_running(r));
}
/* A node that takes time to save after SIGINT reads as stopping until it exits. */
static void saving_cases(struct zapp_runtime *r, const char *self, const char *data, const char *directory,
                         const char *pidfile)
{
    char ready[300], out[128];
    int status;
    assert(snprintf(ready, sizeof(ready), "%s/ready", directory) > 0);
    pid_t other = spawn_orphan(self, data, "saving", pidfile);
    for (int i = 0; i < 500 && access(ready, F_OK); ++i) {
        struct timespec pause = {.tv_nsec = 10000000}; nanosleep(&pause, NULL);
    }
    assert(unlink(ready) == 0 && zapp_node_running(r) && !zapp_node_stopping(r));
    assert(zapp_node_stop(r, out, sizeof(out)) && zapp_node_stopping(r));
    assert(waitpid(other, &status, 0) == other && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(!zapp_node_stopping(r));
}
static void mark_wanted(const struct zapp_runtime *r)
{
    char marker[1100];
    assert(snprintf(marker, sizeof(marker), "%s/node-on", r->state_root) > 0);
    int fd = open(marker, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    assert(fd >= 0 && close(fd) == 0 && zapp_node_wanted(r));
}
#if defined(ZAPP_TEST_HAVE_PIDFD)
static void handoff_guard_case(struct zapp_runtime *r, const char *self, const char *directory)
{
    char out[128]; uint64_t epoch = 0, ticket = 0;
    char executable[sizeof(r->executable)];
    memcpy(executable, r->executable, sizeof(executable));
    assert(snprintf(r->executable, sizeof(r->executable), "%s", self) > 0);
    mark_wanted(r);
    pid_t child = fork(); assert(child >= 0);
    if (!child) { for (;;) pause(); }
    r->node = child; r->stop_sent = false;
    struct zapp_node_identity id;
    assert(zapp_node_identity(r, &id));
    zapp_nodelog_stop(&r->log);
    r->log.started = true;
    r->log.pid = child;
    zapp_nodelog_line(&r->log, "[wallet-replay] phase=discover floor=0 next=12 reference=20", 0);
    struct zapp_replay_progress replay;
    assert(zapp_node_replay_progress(r, &id, &replay) && replay.next == 12);
    struct zapp_node_identity old_replay = id;
    ++old_replay.epoch;
    assert(!zapp_node_replay_progress(r, &old_replay, &replay));
    r->stop_sent = true;
    assert(!zapp_node_replay_progress(r, &id, &replay));
    r->stop_sent = false;
    r->log.started = false;
    struct zapp_node_identity stale = id; ++stale.epoch;
    assert(!zapp_node_handoff_stop(r, &stale, &epoch));
    stale = id; ++stale.start_token;
    assert(!zapp_node_handoff_stop(r, &stale, &epoch));
    stale = id; ++stale.pid;
    assert(!zapp_node_handoff_stop(r, &stale, &epoch));
    assert(zapp_node_handoff_stop(r, &id, &epoch));
    assert(zapp_node_wanted(r) && !zapp_node_handoff_stop(r, &id, &epoch));
    zapp_node_identity_close(&id);
    for (int i = 0; i < 500 && zapp_node_running(r); ++i) {
        struct timespec delay = {.tv_nsec = 10000000}; nanosleep(&delay, NULL);
    }
    if (zapp_node_running(r)) { kill(child, SIGKILL); (void)waitpid(child, NULL, 0); assert(!"handoff stop timeout"); }
    assert(zapp_node_handoff_resume_reserve(r, epoch, &ticket, out, sizeof(out)));
    zapp_node_start_discard(r, ticket);
    assert(!zapp_node_handoff_resume_reserve(r, epoch, &ticket, out, sizeof(out)));
    assert(zapp_node_stop(r, out, sizeof(out)) && !zapp_node_wanted(r));
    assert(!zapp_node_handoff_resume_reserve(r, epoch, &ticket, out, sizeof(out)));
    char data[300], pidfile[300];
    assert(snprintf(data, sizeof(data), "-datadir=%s", directory) > 0);
    assert(snprintf(pidfile, sizeof(pidfile), "%s/zclassic23.pid", directory) > 0);
    pid_t earlier = spawn_orphan(self, data, "orphan", pidfile);
    await_running(r); mark_wanted(r);
    assert(zapp_node_identity(r, &id) && id.pid == earlier);
    stale = id; ++stale.start_token;
    assert(!zapp_node_handoff_stop(r, &stale, &epoch));
    assert(zapp_node_handoff_stop(r, &id, &epoch));
    zapp_node_identity_close(&id);
    int status = 0; pid_t got = 0;
    for (int i = 0; i < 500 && !(got = waitpid(earlier, &status, WNOHANG)); ++i) {
        struct timespec delay = {.tv_nsec = 10000000}; nanosleep(&delay, NULL);
    }
    if (got != earlier) { kill(earlier, SIGKILL); (void)waitpid(earlier, NULL, 0); assert(!"earlier node stop timeout"); }
    assert(zapp_node_wanted(r));
    assert(zapp_node_stop(r, out, sizeof(out)) && !zapp_node_wanted(r));
    memcpy(r->executable, executable, sizeof(executable));
}

#endif
static bool gate_defer(void *ctx) { (void)ctx; return false; }
static bool gate_stop(void *ctx)
{
    char out[128];
    assert(zapp_node_stop(ctx, out, sizeof(out)));
    return false;
}
static void gate_leave(void *ctx) { (void)ctx; assert(!"unused gate leave"); }
static void handoff_gate_case(struct zapp_runtime *r)
{
    char out[128]; uint64_t ticket = 0, deferred = 0;
    mark_wanted(r);
    assert(zapp_node_resume_reserve(r, &ticket, out, sizeof(out)));
    struct zapp_start_gate gate = {r, gate_defer, gate_leave};
    assert(!zapp_node_start_reserved_gated(r, ticket, out, sizeof(out), &gate, &deferred));
    assert(deferred && !zapp_node_start_pending(r) && zapp_node_wanted(r));
    assert(zapp_node_handoff_resume_reserve(r, deferred, &ticket, out, sizeof(out)));
    gate.enter = gate_stop; deferred = 0;
    assert(!zapp_node_start_reserved_gated(r, ticket, out, sizeof(out), &gate, &deferred));
    assert(!deferred && !zapp_node_start_pending(r) && !zapp_node_wanted(r));
}

/* Wallet setup's stop asks the node to exit and leaves the owner's choice; the owner's Stop button removes it. */
static void setup_stop_cases(struct zapp_runtime *r, const char *self, const char *data, const char *pidfile)
{
    char out[128];
    int status;
    pid_t other = spawn_orphan(self, data, "orphan", pidfile);
    await_running(r);
    mark_wanted(r);
    assert(zapp_node_stop_for_setup(r, out, sizeof(out)) && !strcmp(out, "Node stopping. It saves its data first."));
    assert(waitpid(other, &status, 0) == other && WIFSIGNALED(status) && WTERMSIG(status) == SIGINT);
    assert(!zapp_node_running(r) && zapp_node_wanted(r));
    assert(zapp_node_stop_for_setup(r, out, sizeof(out)) && !strcmp(out, "The local node is stopped.") && zapp_node_wanted(r));
    other = spawn_orphan(self, data, "orphan", pidfile);
    await_running(r);
    assert(zapp_node_stop(r, out, sizeof(out)) && !zapp_node_wanted(r));
    assert(waitpid(other, &status, 0) == other && WIFSIGNALED(status) && WTERMSIG(status) == SIGINT);
}
/* A node left by an earlier app process is found through its pid file and its first argument. */
static void earlier_cases(struct zapp_runtime *r, const char *self, const char *directory)
{
    char data[300], pidfile[300], out[128];
    assert(snprintf(data, sizeof(data), "-datadir=%s", directory) > 0);
    assert(snprintf(pidfile, sizeof(pidfile), "%s/zclassic23.pid", directory) > 0);
    setup_stop_cases(r, self, data, pidfile);
    pid_t other = spawn_orphan(self, data, "orphan", pidfile);
    await_running(r);
    assert(!zapp_node_start(r, out, sizeof(out)) && !strcmp(out, "The local node is already running."));
    assert(zapp_node_stop(r, out, sizeof(out)) && !strcmp(out, "Node stopping. It saves its data first."));
    int status;
    assert(waitpid(other, &status, 0) == other && WIFSIGNALED(status) && WTERMSIG(status) == SIGINT);
    assert(!zapp_node_running(r) && !zapp_node_stopping(r));
    saving_cases(r, self, data, directory, pidfile);
    /* One of the app's own commands, -datadir last, under a pid the node file still names. */
    other = spawn_orphan(self, "command", data, pidfile);
    await_exec(other, "command");
    assert(!zapp_node_running(r));
    assert(kill(other, SIGINT) == 0 && waitpid(other, &status, 0) == other);
    FILE *f = fopen(pidfile, "w");
    assert(f && fprintf(f, "%d\n", (int)getpid()) > 0 && fclose(f) == 0);
    assert(!zapp_node_running(r) && unlink(pidfile) == 0);
}
/* With the owner's Start choice saved, the preview package still neither starts a node nor reads
 * the choice. */
static void preview_cases(struct zapp_runtime *r)
{
    char out[128];
    assert(zapp_node_wanted(r));
    r->preview = true;
    assert(!zapp_node_start(r, out, sizeof(out)) && strstr(out, "preview app does not run a node"));
    assert(!zapp_node_wanted(r) && r->node == 0);
    r->preview = false;
    assert(zapp_node_wanted(r));
}
static void command_cases(struct zapp_runtime *r)
{
    char out[128];
    assert(!zapp_operation_run(r, "not-allowed", out, sizeof(out)));
    assert(!zapp_operation_run(r, "fleet_doctor", out, sizeof(out)) && strstr(out, "not available"));
    assert(!zapp_operation_run(r, "status", out, sizeof(out)));
    assert(strstr(out, "[Output limit reached]"));
    assert(zapp_fleet_join_run(r, "invitation", out, sizeof(out)));
    assert(strstr(out, "receipt"));
    const char *onion = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion";
    char dial[1200]; snprintf(dial, sizeof(dial), "%s/dial-called", r->directory); (void)unlink(dial);
    assert(!zapp_fleet_connect_run(r, "refused", onion, out, sizeof(out)) && access(dial, F_OK) != 0);
    assert(!zapp_fleet_connect_run(r, "partial", onion, out, sizeof(out)) && strstr(out, "changed some fleet state") && access(dial, F_OK) != 0);
    assert(zapp_fleet_connect_run(r, "valid", onion, out, sizeof(out)) && strstr(out, "Fleet computer saved. Connecting…") && access(dial, F_OK) == 0);
    assert(unlink(dial) == 0);
    assert(strcmp(getenv("XDG_STATE_HOME"), "/tmp/parent-state") == 0);
    assert(strcmp(getenv("ZCL_CATCHUP_DRAIN_BUDGET_MS"), "77") == 0);
    assert(setenv("ZAPP_TEST_CLOCK_FAIL", "1", 1) == 0);
    assert(!zapp_operation_run(r, "status", out, sizeof(out)));
    assert(strstr(out, "timed out"));
    assert(unsetenv("ZAPP_TEST_CLOCK_FAIL") == 0);
}
/* Start records the owner's choice and Stop clears it; a choice that cannot be saved is reported. */
static void sized_file(const char *dir, int index, uint64_t size)
{
    char file[500];
    assert(snprintf(file, sizeof(file), "%s/%s", dir, zapp_param_files[index].name) > 0);
    int fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0 && ftruncate(fd, (off_t)size) == 0 && close(fd) == 0);
}
/* The fleet's onion peers the app holds reach the node as -addnode, and nothing else is added. */
static void roster_case(struct zapp_runtime *r)
{
    static const char peer[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:8033";
    char file[1200], text[200];
    assert(snprintf(file, sizeof(file), "%s/fleet-onion-peers", r->directory) > 0);
    assert(snprintf(text, sizeof(text), "%s\n1.2.3.4:8033\nnot-an-onion.onion:1\n", peer) > 0);
    int fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0 && write(fd, text, strlen(text)) == (ssize_t)strlen(text) && close(fd) == 0);
    assert(setenv("ZAPP_TEST_ADDNODE", peer, 1) == 0);
    char out[128], expect[1200];
    int status;
    assert(snprintf(expect, sizeof(expect), "-paramsdir=%s/params", r->files) > 0);
    assert(setenv("ZAPP_TEST_PARAMS_ARG", expect, 1) == 0);
    assert(zapp_node_start(r, out, sizeof(out)));
    assert(waitpid(r->node, &status, 0) == r->node && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    r->node = 0;
    assert(unsetenv("ZAPP_TEST_ADDNODE") == 0 && unlink(file) == 0);
}
static void start_expecting(struct zapp_runtime *r, const char *argument)
{
    char out[128];
    int status;
    assert(setenv("ZAPP_TEST_PARAMS_ARG", argument, 1) == 0);
    assert(zapp_node_start(r, out, sizeof(out)));
    assert(waitpid(r->node, &status, 0) == r->node && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    r->node = 0;
}
/* The node always gets -paramsdir=files/params: it looks for the files at its first proof, so a node
 * started before the copy finishes still finds them. */
static void params_argument_cases(struct zapp_runtime *r, const char *directory)
{
    char dir[400], file[500], expect[450];
    assert(snprintf(r->files, sizeof(r->files), "%s", directory) > 0);
    assert(snprintf(dir, sizeof(dir), "%s/params", directory) > 0);
    assert(snprintf(expect, sizeof(expect), "-paramsdir=%s", dir) > 0);
    start_expecting(r, expect);                                   /* no directory yet */
    assert(mkdir(dir, 0700) == 0);
    start_expecting(r, expect);                                   /* no files */
    sized_file(dir, 0, zapp_param_files[0].size);
    start_expecting(r, expect);                                   /* one of two */
    sized_file(dir, 1, zapp_param_files[1].size - 1);
    start_expecting(r, expect);                                   /* wrong size */
    sized_file(dir, 1, zapp_param_files[1].size);
    start_expecting(r, expect);                                   /* complete */
    for (int i = 0; i < ZAPP_PARAMS_COUNT; i++) {
        assert(snprintf(file, sizeof(file), "%s/%s", dir, zapp_param_files[i].name) > 0 && unlink(file) == 0);
    }
    assert(rmdir(dir) == 0);
    start_expecting(r, expect);
}
/* The console log is 300 bytes and the cap for these cases is 256, so spawn must move it to .1 and start a new file. */
static char oversize[300];
static void console_before(struct zapp_runtime *r, const char *directory)
{
    char log[300], rotated[300];
    r->console_cap = 256;
    assert(snprintf(log, sizeof(log), "%s/app-console.log", directory) > 0);
    assert(snprintf(rotated, sizeof(rotated), "%s/app-console.log.1", directory) > 0);
    FILE *f = fopen(rotated, "w");
    assert(f && fputs("older run\n", f) >= 0 && fclose(f) == 0);
    memset(oversize, 'x', sizeof(oversize) - 1);
    oversize[sizeof(oversize) - 1] = 0;
    f = fopen(log, "w");
    assert(f && fprintf(f, "%s\n", oversize) == (int)sizeof(oversize) && fclose(f) == 0);
}
static void console_after(const char *directory)
{
    char log[300], rotated[300];
    struct stat st;
    assert(snprintf(log, sizeof(log), "%s/app-console.log", directory) > 0);
    assert(snprintf(rotated, sizeof(rotated), "%s/app-console.log.1", directory) > 0);
    assert(stat(rotated, &st) == 0 && st.st_size == (off_t)sizeof(oversize));
    assert(stat(log, &st) == 0 && st.st_size < 256);
    assert(unlink(rotated) == 0);
}

static void install_fixture_file(const char *dir, const char *name, const char *text)
{
    char p[1200]; snprintf(p, sizeof(p), "%s/%s", dir, name);
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0 && write(fd, text, strlen(text)) == (ssize_t)strlen(text));
    assert(close(fd) == 0);
}

struct install_start_test { struct zapp_runtime *runtime; bool ok; char out[256]; };
static pthread_mutex_t auth_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t auth_cond = PTHREAD_COND_INITIALIZER;
static bool auth_entered, auth_cancelled;
static void auth_cancel_test(void *ctx)
{
    (void)ctx;
    pthread_mutex_lock(&auth_lock); auth_cancelled = true; pthread_cond_broadcast(&auth_cond); pthread_mutex_unlock(&auth_lock);
}
static bool auth_unwrap_test(struct zapp_startup_auth *auth, const char *files, uint8_t secret[32])
{
    (void)files; (void)secret;
    if (!zapp_startup_auth_register_cancel(auth, auth_cancel_test, NULL)) return false;
    pthread_mutex_lock(&auth_lock); auth_entered = true; pthread_cond_broadcast(&auth_cond);
    struct timespec until; assert(clock_gettime(CLOCK_REALTIME, &until) == 0); until.tv_sec += 5;
    while (!auth_cancelled) assert(pthread_cond_timedwait(&auth_cond, &auth_lock, &until) == 0);
    pthread_mutex_unlock(&auth_lock); zapp_startup_auth_unregister_cancel(auth); return false;
}
static void startup_stop_case(struct zapp_runtime *r)
{
    char out[256];
    auth_entered = auth_cancelled = false;
    zapp_startup_auth_provider(auth_unwrap_test);
    assert(setenv("ZAPP_TEST_STARTUP_AUTH", "1", 1) == 0);
    assert(zapp_node_start(r, out, sizeof(out)));
    pthread_mutex_lock(&auth_lock);
    struct timespec until; assert(clock_gettime(CLOCK_REALTIME, &until) == 0); until.tv_sec += 5;
    while (!auth_entered) assert(pthread_cond_timedwait(&auth_cond, &auth_lock, &until) == 0);
    pthread_mutex_unlock(&auth_lock);
    assert(zapp_node_stop(r, out, sizeof(out)));
    pthread_mutex_lock(&auth_lock); assert(auth_cancelled); pthread_mutex_unlock(&auth_lock);
    assert(unsetenv("ZAPP_TEST_STARTUP_AUTH") == 0);
    int status; pid_t child = r->node, got = 0;
    for (int i = 0; i < 500 && got == 0; i++) {
        got = waitpid(child, &status, WNOHANG);
        if (!got) { struct timespec delay = {.tv_nsec = 10000000}; nanosleep(&delay, NULL); }
    }
    if (got == 0) { (void)kill(child, SIGKILL); (void)waitpid(child, &status, 0); }
    assert(got == child); r->node = 0;
    for (int i = 0; !zapp_startup_auth_ready(r->startup_auth) && i < 500; i++) {
        struct timespec delay = {.tv_nsec = 10000000}; nanosleep(&delay, NULL);
    }
    assert(zapp_startup_auth_ready(r->startup_auth)); zapp_startup_auth_provider(NULL);
}
static void *install_start_thread(void *arg)
{
    struct install_start_test *test = arg;
    test->ok = zapp_node_start(test->runtime, test->out, sizeof(test->out));
    return NULL;
}

static void install_validation_cases(struct zapp_runtime *r, const char *dir)
{
    char out[256], path[1200];
    uint64_t setup_ticket = 0;
    assert(zapp_node_start_reserve(r, &setup_ticket, out, sizeof(out)));
    assert(zapp_setup_kind_write(r->files, ZAPP_KIND_CREATE));
    assert(!zapp_node_start_reserved(r, setup_ticket, out, sizeof(out)) && strstr(out, "cancelled"));
    zapp_setup_kind_forget(r->files);
    install_fixture_file(dir, "install-bundle.sqlite", "fixture");
    install_fixture_file(dir, "install-bundle.consumed", "bad\n");
    assert(!zapp_node_start(r, out, sizeof(out)));
    snprintf(path, sizeof(path), "%s/install-bundle.consumed", dir);
    assert(unlink(path) == 0 && symlink("install-bundle.sqlite", path) == 0);
    assert(!zapp_node_start(r, out, sizeof(out)) && unlink(path) == 0);
    install_fixture_file(dir, "install-bundle.consumed", "install\n");
    assert(chmod(path, 0644) == 0 && !zapp_node_start(r, out, sizeof(out)));
    assert(unlink(path) == 0);
    install_fixture_file(dir, "install-bundle.request", "bad\n");
    assert(!zapp_node_start(r, out, sizeof(out)) && strstr(out, "recovery"));
}

static void install_result_cases(struct zapp_runtime *r, const char *dir)
{
    char out[256], path[1200]; int status;
    install_fixture_file(dir, "install-bundle.request", "install\n");
    snprintf(path, sizeof(path), "%s/install-bundle.request", dir);
    assert(chmod(path, 0644) == 0);
    assert(!zapp_node_start(r, out, sizeof(out)));
    assert(chmod(path, 0600) == 0);
    if (geteuid() == 0) {
        assert(chown(path, 1, (gid_t)-1) == 0);
        assert(!zapp_node_start(r, out, sizeof(out)));
        assert(chown(path, 0, (gid_t)-1) == 0);
    }
    assert(unlink(path) == 0);
    assert(symlink("install-bundle.sqlite", path) == 0);
    assert(!zapp_node_start(r, out, sizeof(out)) && unlink(path) == 0);
    install_fixture_file(dir, "install-bundle.request", "install\n");
    assert(setenv("ZAPP_TEST_INSTALL", "fail", 1) == 0);
    assert(!zapp_node_start(r, out, sizeof(out)) && strstr(out, "recovery"));
    assert(unsetenv("ZAPP_TEST_INSTALL") == 0);
    assert(zapp_node_start(r, out, sizeof(out)));
    assert(waitpid(r->node, &status, 0) == r->node && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    r->node = 0;
    snprintf(path, sizeof(path), "%s/install-bundle.consumed", dir);
    assert(unlink(path) == 0);
    install_fixture_file(dir, "install-bundle.request", "install\n");
    assert(zapp_node_start(r, out, sizeof(out)));
    assert(waitpid(r->node, &status, 0) == r->node && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    r->node = 0;
    snprintf(path, sizeof(path), "%s/install-bundle.consumed", dir);
    assert(unlink(path) == 0);
}

static void install_stop_case(struct zapp_runtime *r, const char *dir)
{
    char out[256], path[1200]; int status;
    install_fixture_file(dir, "install-bundle.request", "install\n");
    assert(setenv("ZAPP_TEST_INSTALL", "block", 1) == 0);
    struct install_start_test test = {.runtime = r}; pthread_t thread;
    assert(pthread_create(&thread, NULL, install_start_thread, &test) == 0);
    bool started = false;
    for (int i = 0; i < 500 && !started; ++i) {
        pthread_mutex_lock(&r->mutex); started = r->installer > 0; pthread_mutex_unlock(&r->mutex);
        if (!started) { struct timespec delay = {.tv_nsec = 10000000}; nanosleep(&delay, NULL); }
    }
    assert(started && zapp_node_installing(r) && zapp_node_running(r) && atomic_load(&r->setup_running));
    uint64_t other_ticket = 0;
    assert(!zapp_node_start_reserve(r, &other_ticket, out, sizeof(out)));
    uint64_t old_epoch = r->start_epoch;
    assert(zapp_node_stop(r, out, sizeof(out)) && r->start_epoch != old_epoch);
    assert(pthread_join(thread, NULL) == 0 && !test.ok && !zapp_node_installing(r));
    assert(unsetenv("ZAPP_TEST_INSTALL") == 0);
    assert(zapp_node_start(r, out, sizeof(out)));
    assert(waitpid(r->node, &status, 0) == r->node && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    r->node = 0;
    snprintf(path, sizeof(path), "%s/install-bundle.consumed", dir); assert(unlink(path) == 0);
}

static void install_crash_case(struct zapp_runtime *r, const char *dir)
{
    char out[256], path[1200]; int status;
    snprintf(path, sizeof(path), "%s/install-bundle.consumed", dir);
    install_fixture_file(dir, "install-bundle.request", "install\n");
    char request[1200]; snprintf(request, sizeof(request), "%s/install-bundle.request", dir);
    assert(link(request, path) == 0); /* interruption after durable consume, before unlink */
    assert(setenv("ZAPP_TEST_INSTALL", "fail", 1) == 0);
    assert(zapp_node_start(r, out, sizeof(out)));
    assert(waitpid(r->node, &status, 0) == r->node && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    r->node = 0;
    assert(unsetenv("ZAPP_TEST_INSTALL") == 0 && unlink(request) == 0 && unlink(path) == 0);
    snprintf(path, sizeof(path), "%s/install-bundle.sqlite", dir);
    assert(unlink(path) == 0);
}

static void install_cases(struct zapp_runtime *r, const char *dir)
{
    install_validation_cases(r, dir);
    install_result_cases(r, dir);
    install_stop_case(r, dir);
    install_crash_case(r, dir);
}

static void node_cases(struct zapp_runtime *r, const char *self, const char *directory)
{
    char out[128];
    char params[1200];
    assert(snprintf(r->files, sizeof(r->files), "%s", directory) > 0);
    assert(snprintf(params, sizeof(params), "-paramsdir=%s/params", directory) > 0);
    assert(setenv("ZAPP_TEST_PARAMS_ARG", params, 1) == 0);
    assert(snprintf(r->directory, sizeof(r->directory), "%s", directory) > 0);
    assert(snprintf(r->state_root, sizeof(r->state_root), "%s/missing", directory) > 0);
    assert(setenv("ZAPP_TEST_STATE", r->state_root, 1) == 0);
    const char *old_allow = getenv("ZCL_DEPLOY_ALLOW_CANONICAL");
    char *saved_allow = old_allow ? strdup(old_allow) : NULL;
    assert(!old_allow || saved_allow);
    assert(setenv("ZCL_DEPLOY_ALLOW_CANONICAL", "bogus", 1) == 0);
    console_before(r, directory);
    assert(zapp_node_start(r, out, sizeof(out)) && strstr(out, "could not save") && !zapp_node_wanted(r));
    int status;
    assert(waitpid(r->node, &status, 0) == r->node && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    r->node = 0;
    console_after(directory);
    assert(snprintf(r->state_root, sizeof(r->state_root), "%s", directory) > 0);
    assert(setenv("ZAPP_TEST_STATE", r->state_root, 1) == 0);
    assert(!zapp_node_wanted(r));
    assert(zapp_node_start(r, out, sizeof(out)) && zapp_node_wanted(r));
    assert(waitpid(r->node, &status, 0) == r->node && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    r->node = 0;
    install_cases(r, directory);
    startup_stop_case(r);
    assert(!strcmp(getenv("ZCL_DEPLOY_ALLOW_CANONICAL"), "bogus"));
    if (saved_allow) assert(setenv("ZCL_DEPLOY_ALLOW_CANONICAL", saved_allow, 1) == 0);
    else assert(unsetenv("ZCL_DEPLOY_ALLOW_CANONICAL") == 0);
    free(saved_allow);
    params_argument_cases(r, directory);
    roster_case(r);
    preview_cases(r);
    assert(zapp_node_stop(r, out, sizeof(out)) && !strcmp(out, "The local node is stopped.") && !zapp_node_wanted(r));
#if defined(ZAPP_TEST_HAVE_PIDFD)
    handoff_guard_case(r, self, directory);
#endif
    handoff_gate_case(r);
    earlier_cases(r, self, directory);
}
static bool pace_file_is(const char *directory, const char *word)
{
    char file[300], got[16] = "";
    snprintf(file, sizeof(file), "%s/pace", directory);
    FILE *f = fopen(file, "r");
    if (!f) return false;
    size_t n = fread(got, 1, sizeof(got) - 1, f);
    fclose(f);
    return n == strlen(word) && !strcmp(got, word);
}
static void pace_failure_tests(struct zapp_runtime *r, const char *directory)
{
    char temporary[300];
    snprintf(temporary, sizeof(temporary), "%s/pace.tmp", directory);
    /* A planted symlink at the temporary name is refused and the recorded pace is kept. */
    assert(symlink("/nonexistent", temporary) == 0);
    assert(!zapp_node_pace_write(r, ZAPP_PACE_NORMAL) && zapp_node_pace(r) == ZAPP_PACE_PAUSE);
    assert(pace_file_is(directory, "pause") && unlink(temporary) == 0);
    /* A read-only directory fails without changing the recorded pace or the file. */
    assert(chmod(directory, 0500) == 0);
    if (geteuid() != 0) {
        assert(!zapp_node_pace_write(r, ZAPP_PACE_NORMAL) && zapp_node_pace(r) == ZAPP_PACE_PAUSE);
        assert(pace_file_is(directory, "pause"));
    }
    assert(chmod(directory, 0700) == 0);
    struct zapp_runtime missing = {0};
    assert(snprintf(missing.directory, sizeof(missing.directory), "%s/absent", directory) > 0);
    assert(!zapp_node_pace_write(&missing, ZAPP_PACE_GENTLE));
    assert(zapp_node_pace(&missing) == ZAPP_PACE_NORMAL);
}
static void pace_tests(void)
{
    char directory[] = "/tmp/zapp-pace-test-XXXXXX", file[300], temporary[300];
    assert(mkdtemp(directory));
    struct zapp_runtime r = {0};
    assert(snprintf(r.directory, sizeof(r.directory), "%s", directory) > 0);
    snprintf(file, sizeof(file), "%s/pace", directory);
    snprintf(temporary, sizeof(temporary), "%s/pace.tmp", directory);
    assert(zapp_node_pace(&r) == ZAPP_PACE_NORMAL && access(file, F_OK) != 0);
    /* A file left by an earlier run is replaced by the first write even when it says normal. */
    FILE *stale = fopen(file, "w");
    assert(stale && fputs("pause", stale) >= 0 && fclose(stale) == 0);
    assert(zapp_node_pace_write(&r, ZAPP_PACE_NORMAL) && pace_file_is(directory, "normal"));
    assert(zapp_node_pace_write(&r, ZAPP_PACE_GENTLE) && pace_file_is(directory, "gentle"));
    assert(zapp_node_pace(&r) == ZAPP_PACE_GENTLE && access(temporary, F_OK) != 0);
    struct stat st;
    assert(stat(file, &st) == 0 && (st.st_mode & 0777) == 0600);
    /* An unchanged pace does not touch the file. */
    assert(unlink(file) == 0);
    assert(zapp_node_pace_write(&r, ZAPP_PACE_GENTLE) && access(file, F_OK) != 0);
    assert(zapp_node_pace_write(&r, ZAPP_PACE_PAUSE) && pace_file_is(directory, "pause"));
    assert(!zapp_node_pace_write(&r, (enum zapp_pace)7) && zapp_node_pace(&r) == ZAPP_PACE_PAUSE);
    pace_failure_tests(&r, directory);
    assert(zapp_node_pace_write(&r, ZAPP_PACE_NORMAL) && pace_file_is(directory, "normal"));
    assert(unlink(file) == 0 && rmdir(directory) == 0);
}
static int waiting_calls;
static void count_waiting(void *arg) { (void)arg; ++waiting_calls; }
static void write_hostname(const char *directory, const char *text)
{
    char dir[400], file[420];
    snprintf(dir, sizeof(dir), "%s/tor_data", directory); (void)mkdir(dir, 0700);
    snprintf(dir, sizeof(dir), "%s/tor_data/onion_service", directory); (void)mkdir(dir, 0700);
    snprintf(file, sizeof(file), "%s/hostname", dir);
    FILE *f = fopen(file, "w");
    assert(f && fputs(text, f) >= 0 && fclose(f) == 0);
}
static void onion_tests(void)
{
    static const char good[] = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
    char directory[] = "/tmp/zapp-onion-test-XXXXXX", file[420], dir[400];
    assert(mkdtemp(directory));
    struct zapp_runtime r = {0};
    assert(pthread_mutex_init(&r.mutex, NULL) == 0);
    assert(snprintf(r.directory, sizeof(r.directory), "%s", directory) > 0);
    /* No file, an empty file and malformed hostnames are never ready. */
    assert(!zapp_onion_ready(&r));
    write_hostname(directory, "");
    assert(!zapp_onion_ready(&r));
    write_hostname(directory, "short.onion\n");
    assert(!zapp_onion_ready(&r));
    write_hostname(directory, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWX.onion\n");
    assert(!zapp_onion_ready(&r));
    write_hostname(directory, "abcdefghijklmnopqrstuvwxyz234561abcdefghijklmnopqrstuvwx.onion\n");
    assert(!zapp_onion_ready(&r));
    write_hostname(directory, "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onionx\n");
    assert(!zapp_onion_ready(&r));
    /* A stopped node never waits. */
    assert(zapp_onion_wait(&r, 5, count_waiting, NULL) == ZAPP_ONION_NODE_STOPPED && waiting_calls == 0);
    pid_t node = fork();
    assert(node >= 0);
    if (node == 0) { sleep(30); _exit(0); }
    r.node = node;
    /* A running node whose address never appears times out after reporting the wait once. */
    assert(zapp_onion_wait(&r, 2, count_waiting, NULL) == ZAPP_ONION_TIMEOUT && waiting_calls == 1);
    write_hostname(directory, good);
    assert(zapp_onion_ready(&r));
    write_hostname(directory, "");
    pid_t writer = fork();
    assert(writer >= 0);
    if (writer == 0) { sleep(1); write_hostname(directory, good); _exit(0); }
    waiting_calls = 0;
    assert(zapp_onion_wait(&r, 10, count_waiting, NULL) == ZAPP_ONION_READY && waiting_calls == 1);
    assert(waitpid(writer, NULL, 0) == writer);
    assert(kill(node, SIGKILL) == 0 && waitpid(node, NULL, 0) == node);
    r.node = 0;
    snprintf(file, sizeof(file), "%s/tor_data/onion_service/hostname", directory);
    snprintf(dir, sizeof(dir), "%s/tor_data/onion_service", directory);
    assert(unlink(file) == 0 && rmdir(dir) == 0);
    snprintf(dir, sizeof(dir), "%s/tor_data", directory);
    assert(rmdir(dir) == 0 && rmdir(directory) == 0);
    pthread_mutex_destroy(&r.mutex);
}
/* Serving is read from the node's boot status: only a zcl.boot_status.v1 document whose serving is true counts. A missing,
 * malformed, oversized or linked file, another schema and a string "true" do not. */
static void write_status(const char *file, const char *text)
{
    FILE *f = fopen(file, "w");
    assert(f && fputs(text, f) >= 0 && fclose(f) == 0);
}
static void serving_tests(void)
{
    char directory[] = "/tmp/zapp-serving-test-XXXXXX", file[420], other[420], *big;
    assert(mkdtemp(directory));
    struct zapp_runtime r = {0};
    assert(snprintf(r.directory, sizeof(r.directory), "%s", directory) > 0);
    snprintf(file, sizeof(file), "%s/boot_status.json", directory);
    snprintf(other, sizeof(other), "%s/elsewhere.json", directory);
    assert(!zapp_node_serving(&r) && !zapp_node_serving(NULL));
    write_status(file, "{\"schema\":\"zcl.boot_status.v1\",\"phase\":\"network\",\"rpc_bound\":false,\"serving\":false}");
    assert(!zapp_node_serving(&r));
    write_status(file, "{\"schema\":\"zcl.boot_status.v1\",\"phase\":\"serving\",\"stage\":\"ready\",\"rpc_bound\":true,\"serving\":true}");
    assert(zapp_node_serving(&r));
    write_status(file, "{\"schema\":\"zcl.boot_status.v2\",\"serving\":true}");
    assert(!zapp_node_serving(&r));
    write_status(file, "{\"schema\":\"zcl.boot_status.v1\",\"serving\":\"true\"}");
    assert(!zapp_node_serving(&r));
    write_status(file, "{\"schema\":\"zcl.boot_status.v1\",\"serving\":tr");
    assert(!zapp_node_serving(&r));
    big = calloc(1, ZAPP_BOOT_STATUS_MAX + 64);
    assert(big);
    snprintf(big, ZAPP_BOOT_STATUS_MAX + 64, "{\"schema\":\"zcl.boot_status.v1\",\"serving\":true,\"activity\":\"%*s\"}",
             ZAPP_BOOT_STATUS_MAX, "");
    write_status(file, big);
    free(big);
    assert(!zapp_node_serving(&r));
    write_status(other, "{\"schema\":\"zcl.boot_status.v1\",\"serving\":true}");
    assert(unlink(file) == 0 && symlink(other, file) == 0);
    assert(!zapp_node_serving(&r));   /* a link is not followed */
    assert(unlink(file) == 0 && unlink(other) == 0 && rmdir(directory) == 0);
}

static void fixture_dir(char *out, size_t cap, const char *base, const char *leaf)
{
    int n = snprintf(out, cap, "%s/%s", base, leaf);
    assert(n > 0 && (size_t)n < cap && mkdir(out, 0700) == 0);
}
/* Android names the files directory through /data/user/0, a link to /data/data. The state and temporary roots the
 * node gets are named without the link, because the node refuses a state root with a link among its parents and
 * would never find its fleet record; the node data keeps the name the app was given. */
static void linked_files_tests(void)
{
    char base[] = "/tmp/zapp-files-test-XXXXXX", data[100], user[100], real_files[160], link[120], files[160];
    char real[PATH_MAX], want[PATH_MAX + 16], made[PATH_MAX + 16];
    assert(mkdtemp(base));
    fixture_dir(data, sizeof(data), base, "data");
    fixture_dir(user, sizeof(user), base, "user");
    fixture_dir(real_files, sizeof(real_files), data, "files");
    assert(snprintf(link, sizeof(link), "%s/0", user) > 0 && symlink(data, link) == 0);
    assert(snprintf(files, sizeof(files), "%s/files", link) > 0 && realpath(real_files, real));
    struct zapp_runtime r;
    assert(zapp_runtime_init(&r, files, "/lib", false));
    assert(snprintf(want, sizeof(want), "%s/state", real) > 0 && !strcmp(r.state_root, want));
    assert(snprintf(want, sizeof(want), "%s/tmp", real) > 0 && !strcmp(r.temporary_root, want));
    assert(snprintf(want, sizeof(want), "%s/node", files) > 0 && !strcmp(r.directory, want));
    assert(!strcmp(r.files, files));
    zapp_runtime_destroy(&r);
    static const char *const made_dirs[] = {"node", "state", "tmp"};
    for (size_t i = 0; i < sizeof(made_dirs) / sizeof(made_dirs[0]); ++i)
        assert(snprintf(made, sizeof(made), "%s/%s", real, made_dirs[i]) > 0 && rmdir(made) == 0);
    struct zapp_runtime missing;
    assert(snprintf(want, sizeof(want), "%s/absent", base) > 0 && !zapp_runtime_init(&missing, want, "/lib", false));
    assert(rmdir(real_files) == 0 && unlink(link) == 0 && rmdir(user) == 0 && rmdir(data) == 0 && rmdir(base) == 0);
}

struct preload_start_test { struct zapp_runtime *r; bool ok; char out[256]; };
static void *preload_start_main(void *arg)
{
    struct preload_start_test *t = arg;
    t->ok = zapp_node_start(t->r, t->out, sizeof(t->out));
    return NULL;
}
static void preload_unlink(const char *dir, const char *name)
{
    char path[1200];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    (void)unlink(path);
}
static long preload_read_marker(const char *dir, const char *name)
{
    char path[1200];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "r");
    long value = 0;
    if (f) { if (fscanf(f, "%ld", &value) != 1) value = 0; fclose(f); }
    return value;
}
static void preload_wait_marker(const char *dir)
{
    for (int i = 0; i < 300 && !preload_read_marker(dir, "preload-started"); ++i) {
        struct timespec pause = {.tv_nsec = 10000000}; nanosleep(&pause, NULL);
    }
    assert(preload_read_marker(dir, "preload-started") > 0);
}
static void preload_reap_node(struct zapp_runtime *r)
{
    int status;
    assert(r->node > 0 && waitpid(r->node, &status, 0) == r->node && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    r->node = 0;
}
static void preload_reservation_cases(struct zapp_runtime *r)
{
    uint64_t stale, current;
    char reservation[256];
    assert(zapp_node_start_reserve(r, &stale, reservation, sizeof(reservation)));
    assert(zapp_node_stop(r, reservation, sizeof(reservation)));
    assert(zapp_node_start_reserve(r, &current, reservation, sizeof(reservation)));
    assert(stale != current);
    assert(!zapp_node_start_reserved(r, stale, reservation, sizeof(reservation)));
    assert(!zapp_node_start_reserve(r, &stale, reservation, sizeof(reservation)));
    zapp_node_start_discard(r, current);
    assert(!atomic_load(&r->setup_running));
}

static void preload_mode_cases(struct zapp_runtime *r, const char *dir)
{
    char out[8192], identity[65]; uint64_t epoch; bool command_ok;
    static const char *const modes[] = {"valid", "locked", "fail", "wrongexit", "signal"};
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i) {
        assert(setenv("ZAPP_TEST_PRELOAD", modes[i], 1) == 0);
        preload_unlink(dir, "preload-started"); preload_unlink(dir, "node-spawned");
        char start[256] = {0};
        bool started = zapp_node_start(r, start, sizeof(start));
        if (!started) fprintf(stderr, "preload mode %s: node start failed: %s\n", modes[i], start);
        assert(started);
        assert(preload_read_marker(dir, "preload-started") > 0);
        preload_reap_node(r);
        assert(preload_read_marker(dir, "node-spawned") > 0);
        assert(zapp_node_preload_ready(r) == (i < 2));
        bool got = zapp_node_preload_get(r, out, sizeof(out), identity, &epoch, &command_ok);
        assert(got == (i < 2));
        if (got) assert(strstr(out, "zs1fixture") && command_ok == (i == 0));
        assert(zapp_node_stop(r, start, sizeof(start)));
        assert(!zapp_node_preload_ready(r));
        assert(!zapp_node_preload_get(r, out, sizeof(out), identity, &epoch, &command_ok));
    }
}

static void preload_race_cases(struct zapp_runtime *r, const char *dir, const char *path)
{
    char out[8192], identity[65]; uint64_t epoch; bool command_ok; FILE *f;
    /* A node that appears during the read wins; start must not spawn or stop it. */
    assert(setenv("ZAPP_TEST_PRELOAD", "delay", 1) == 0);
    preload_unlink(dir, "preload-started"); preload_unlink(dir, "node-spawned");
    struct preload_start_test competing = {.r = r};
    pthread_t competing_thread;
    assert(pthread_create(&competing_thread, NULL, preload_start_main, &competing) == 0);
    preload_wait_marker(dir);
    char node_arg[1200], pidfile[1200];
    snprintf(node_arg, sizeof(node_arg), "-datadir=%s", dir);
    snprintf(pidfile, sizeof(pidfile), "%s/zclassic23.pid", dir);
    pid_t external = spawn_orphan(r->executable, node_arg, "orphan", pidfile);
    await_running(r);
    assert(zapp_node_start_pending_or_running(r));
    assert(pthread_join(competing_thread, NULL) == 0 && !competing.ok);
    assert(kill(external, 0) == 0 && !preload_read_marker(dir, "node-spawned"));
    assert(kill(external, SIGINT) == 0 && waitpid(external, NULL, 0) == external);
    assert(unlink(pidfile) == 0);
    /* A replaced key invalidates the answer while the status child runs. */
    assert(setenv("ZAPP_TEST_PRELOAD", "delay", 1) == 0);
    preload_unlink(dir, "preload-started"); preload_unlink(dir, "node-spawned");
    preload_unlink(dir, "preload-completed");
    struct preload_start_test changed = {.r = r};
    pthread_t changed_thread;
    assert(pthread_create(&changed_thread, NULL, preload_start_main, &changed) == 0);
    preload_wait_marker(dir);
    f = fopen(path, "w"); assert(f && fputs("replacement key", f) >= 0 && fclose(f) == 0);
    assert(pthread_join(changed_thread, NULL) == 0 && changed.ok);
    assert(preload_read_marker(dir, "preload-completed") > 0);
    preload_reap_node(r);
    assert(!zapp_node_preload_ready(r));
    assert(!zapp_node_preload_get(r, out, sizeof(out), identity, &epoch, &command_ok));
    char changed_stop[256]; assert(zapp_node_stop(r, changed_stop, sizeof(changed_stop)));
    f = fopen(path, "w"); assert(f && fputs("fixture key", f) >= 0 && fclose(f) == 0);
    assert(zapp_setup_mark_confirmed(dir, false));
}

static void preload_cancel_cases(struct zapp_runtime *r, const char *dir)
{
    char out[8192], identity[65]; uint64_t epoch; bool command_ok;
    assert(setenv("ZAPP_TEST_PRELOAD", "wait", 1) == 0);
    preload_unlink(dir, "preload-started"); preload_unlink(dir, "node-spawned");
    r->preload_ms = 5000;
    struct preload_start_test t = {.r = r};
    pthread_t thread;
    assert(pthread_create(&thread, NULL, preload_start_main, &t) == 0);
    preload_wait_marker(dir);
    assert(zapp_node_start_pending(r));
    assert(zapp_node_start_pending_or_running(r));
    pid_t child = (pid_t)preload_read_marker(dir, "preload-started");
    char stop[256]; struct timespec a, b;
    assert(!zapp_node_start(r, stop, sizeof(stop)));
    assert(clock_gettime(CLOCK_MONOTONIC, &a) == 0);
    assert(zapp_node_stop(r, stop, sizeof(stop)));
    assert(clock_gettime(CLOCK_MONOTONIC, &b) == 0);
    assert((b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000 < 1000);
    assert(pthread_join(thread, NULL) == 0 && !t.ok && !zapp_node_wanted(r));
    assert(!zapp_node_start_pending(r));
    assert(!zapp_node_start_pending_or_running(r));
    errno = 0;
    assert(waitpid(child, NULL, WNOHANG) == -1 && errno == ECHILD);
    assert(!preload_read_marker(dir, "node-spawned"));
    preload_unlink(dir, "preload-started");
    r->preload_ms = 250;
    assert(zapp_node_start(r, stop, sizeof(stop)));
    child = (pid_t)preload_read_marker(dir, "preload-started");
    errno = 0;
    assert(child > 0 && waitpid(child, NULL, WNOHANG) == -1 && errno == ECHILD);
    preload_reap_node(r);
    assert(preload_read_marker(dir, "node-spawned") > 0);
    assert(!zapp_node_preload_get(r, out, sizeof(out), identity, &epoch, &command_ok));
    assert(zapp_node_stop(r, stop, sizeof(stop)));
}

static void preload_invalidation_case(struct zapp_runtime *r, const char *dir)
{
    /* Keep the process-lifetime invalidation isolated from the remaining tests. */
    zapp_nodelog_stop(&r->log);
    pid_t isolation = fork(); assert(isolation >= 0);
    if (!isolation) {
        assert(setenv("ZAPP_TEST_PRELOAD", "delay", 1) == 0);
        preload_unlink(dir, "preload-started"); preload_unlink(dir, "node-spawned");
        r->preload_ms = 5000;
        struct preload_start_test invalidated = {.r = r};
        pthread_t worker;
        assert(pthread_create(&worker, NULL, preload_start_main, &invalidated) == 0);
        preload_wait_marker(dir);
        assert(zapp_node_start_pending(r));
        zapp_setup_preload_invalidate();
        assert(pthread_join(worker, NULL) == 0 && !invalidated.ok);
        assert(!zapp_node_start_pending(r) && !preload_read_marker(dir, "node-spawned"));
        _exit(0);
    }
    int isolation_status;
    assert(waitpid(isolation, &isolation_status, 0) == isolation &&
           WIFEXITED(isolation_status) && WEXITSTATUS(isolation_status) == 0);
}

static void preload_install_case(struct zapp_runtime *r, const char *dir)
{
    char out[256];
    install_fixture_file(dir, "install-bundle.sqlite", "fixture");
    install_fixture_file(dir, "install-bundle.request", "install\n");
    assert(setenv("ZAPP_TEST_PRELOAD", "valid", 1) == 0);
    preload_unlink(dir, "preload-started"); preload_unlink(dir, "node-spawned");
    assert(zapp_node_start(r, out, sizeof(out)));
    assert(preload_read_marker(dir, "preload-started") > 0);
    preload_reap_node(r);
    assert(!zapp_node_preload_ready(r));
    preload_unlink(dir, "install-bundle.sqlite");
    preload_unlink(dir, "install-bundle.consumed");
}


static void preload_cases(struct zapp_runtime *r, const char *dir)
{
    char path[1200], identity[65];
    snprintf(path, sizeof(path), "%s/wallet_key.blob", dir);
    FILE *f = fopen(path, "w"); assert(f && fputs("fixture key", f) >= 0 && fclose(f) == 0);
    assert(zapp_setup_mark_done(dir) && zapp_setup_mark_confirmed(dir, false));
    assert(zapp_setup_identity(dir, identity));
    assert(snprintf(r->files, sizeof(r->files), "%s", dir) > 0);
    r->preload_ms = 2000;
    preload_install_case(r, dir);
    preload_reservation_cases(r);
    preload_mode_cases(r, dir);
    preload_race_cases(r, dir, path);
    preload_cancel_cases(r, dir);
    preload_invalidation_case(r, dir);
    assert(unsetenv("ZAPP_TEST_PRELOAD") == 0);
    r->preload_ms = 0;
    preload_unlink(dir, "preload-started"); preload_unlink(dir, "node-spawned");
    preload_unlink(dir, "wallet_key.blob"); preload_unlink(dir, "wallet_setup_done");
    preload_unlink(dir, "wallet_setup_confirmed");
    preload_unlink(dir, "preload-completed");
}

int main(int argc, char **argv)
{
    if (argc == 3 && (!strcmp(argv[2], "orphan") || !strcmp(argv[2], "saving"))) return orphan(argv[2], argv[1]);
    if (argc == 3 && !strcmp(argv[1], "command")) return orphan("orphan", argv[2]);
    if (argc > 1) return child(argc, argv);
    plain_text_tests();
    fleet_receipt_tests();
    fleet_preview_tests();
    fleet_machine_preview_tests();
    pace_tests();
    onion_tests();
    linked_files_tests();
    serving_tests();
    struct zapp_runtime r = {0};
    assert(pthread_mutex_init(&r.mutex, NULL) == 0);
    r.startup_auth = zapp_startup_auth_new(); assert(r.startup_auth);
    assert(snprintf(r.executable, sizeof(r.executable), "%s", argv[0]) > 0);
    assert(snprintf(r.directory, sizeof(r.directory), "%s", "/tmp") > 0);
    assert(snprintf(r.state_root, sizeof(r.state_root), "%s", "/tmp/private-state") > 0);
    assert(snprintf(r.temporary_root, sizeof(r.temporary_root), "%s", "/tmp/private-tmp") > 0);
    assert(setenv("XDG_STATE_HOME", "/tmp/parent-state", 1) == 0);
    assert(setenv("ZAPP_TEST_PRESERVED", "yes", 1) == 0);
    assert(setenv("ZAPP_TEST_STATE", "/tmp/private-state", 1) == 0);
    assert(setenv("ZCL_CATCHUP_DRAIN_BUDGET_MS", "77", 1) == 0);
    assert(setenv("ZCL_BIP_PAGE_CACHE_KIB", "999", 1) == 0);
    assert(setenv("ZCL_WALLET_PASSPHRASE", "decoy", 1) == 0 && setenv("ZCL_ALLOW_PLAINTEXT_WALLET", "1", 1) == 0);
    assert(setenv("ZCL_RECOVERY_PHRASE", "decoy words", 1) == 0 && setenv("ZCL_WALLET_NO_PHRASE_BACKUP", "1", 1) == 0);
    char *runner_home = getenv("HOME") ? strdup(getenv("HOME")) : NULL;
    assert(setenv("HOME", "/tmp/parent-home", 1) == 0);
    assert(setenv("ZAPP_TEST_HOME", "/tmp/parent-home", 1) == 0);
    command_cases(&r);
    preview_cancel_tests(&r);
    assert(unsetenv("HOME") == 0 && unsetenv("ZAPP_TEST_HOME") == 0);
    char directory[] = "/tmp/zapp-ops-test-XXXXXX", log[256], out[128];
    assert(mkdtemp(directory));
    node_cases(&r, argv[0], directory);
    preload_cases(&r, directory);
    preload_unlink(directory, "app-console.log.1");
    if (runner_home) assert(setenv("HOME", runner_home, 1) == 0);
    else assert(unsetenv("HOME") == 0);
    free(runner_home);
    assert(snprintf(log, sizeof(log), "%s/app-console.log", directory) > 0);
    assert(unlink(log) == 0 && rmdir(directory) == 0);
    zapp_runtime_signal_stop(&r);
    assert(!zapp_operation_run(&r, "status", out, sizeof(out)));
    assert(strstr(out, "Unable to run native Z23"));
    zapp_startup_auth_free(r.startup_auth);
    pthread_mutex_destroy(&r.mutex);
    puts("operation tests passed");
    return 0;
}
