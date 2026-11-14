/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: exercise live journey child status, timeout and capture ownership. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#define main app_journey_live_main
#include "app_journey_live.c"
#undef main
#include <limits.h>

static volatile sig_atomic_t aj_interrupted;
static void aj_test_interrupt(int sig) { (void)sig; aj_interrupted = 1; }
static int aj_group_owned_test(void);

static int aj_fake_node(void)
{
    int ready[2]; if (pipe(ready) != 0) return 2;
    pid_t p = fork();
    if (p < 0) return 2;
    if (!p) {
        close(ready[0]); if (setsid() < 0) _exit(2);
        char b = 'r'; if (write(ready[1], &b, 1) != 1) _exit(2);
        for (;;) pause();
    }
    close(ready[1]); char b;
    if (read(ready[0], &b, 1) != 1) return 2;
    close(ready[0]);
    const char *home = getenv("HOME"); char path[PATH_MAX];
    if (!home || snprintf(path, sizeof(path), "%s/node-ready", home) >= (int)sizeof(path) ||
        !aj_write_file(path, "ready")) return 2;
    if (snprintf(path, sizeof(path), "%s/node-crash", home) >= (int)sizeof(path)) return 2;
    if (access(path, F_OK) == 0) return 7;
    for (;;) pause();
}

struct aj_nested_paths { char log[PATH_MAX], ready[PATH_MAX], marker[PATH_MAX]; };

static bool aj_nested_prepare(bool crash, struct aj_nested_paths *paths)
{
    const char *root = getenv("AJ_TEST_ROOT");
    if (!root || chdir(root) != 0 || strlen(root) >= sizeof(g_repo)) return false;
    memcpy(g_repo, root, strlen(root) + 1); platform_supervised_init(&g_role_node);
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) return false;
    if (snprintf(paths->log, sizeof(paths->log), "%s/node.log", root) >= (int)sizeof(paths->log) ||
        snprintf(paths->ready, sizeof(paths->ready), "%s/node-ready", root) >= (int)sizeof(paths->ready) ||
        snprintf(paths->marker, sizeof(paths->marker), "%s/node-crash", root) >= (int)sizeof(paths->marker)) return false;
    if (crash && !aj_write_file(paths->marker, "crash")) return false;
    return aj_role_node_start(root, root, paths->log, 20024, 39731, 39732, 39733, APPJ_DEAD_SINK, false);
}

static bool aj_nested_observe(bool crash, const char *ready)
{
    bool seen = false;
    for (int i = 0; i < 100 && !seen; i++) { seen = access(ready, F_OK) == 0; if (!seen) aj_sleep_ms(50); }
    if (crash) for (int i = 0; i < 100 && !g_role_node.observation.engine_exit_observed; i++) {
        (void)platform_supervised_poll(&g_role_node); aj_sleep_ms(50);
    }
    bool observed = !crash || g_role_node.observation.engine_exit_observed;
    return seen && observed;
}

static bool aj_serve_receipt(const char *path)
{
    char body[1024]; int n = aj_slurp(path, body, sizeof(body));
    struct json_value v; json_init(&v);
    bool ok = n > 0 && json_read(&v, body, (size_t)n);
    const struct json_value *enabled = json_get(&v, "hosting_intent_enabled");
    ok = ok && enabled && enabled->type == JSON_BOOL && json_get_bool(enabled) &&
        !strcmp(json_get_str(json_get(&v, "host")), g_host_hex) &&
        !strcmp(json_get_str(json_get(&v, "carrier")), g_carrier) &&
        json_get_int(json_get(&v, "generation")) == 1;
    json_free(&v); return ok;
}

static bool aj_serve_refusals(struct aj_node_ctx *b, const char *root, const char *ready)
{
    static const char *const modes[] = {"status-error", "status-missing", "status-false", "status-mismatch", "status-not-ok"};
    bool ok = true; char path[PATH_MAX];
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        if (snprintf(path, sizeof(path), "%s/%s", root, modes[i]) >= (int)sizeof(path)) return false;
        bool made = aj_write_file(path, "x");
        bool refused = made && !aj_role_serve(b, 1) && access(ready, F_OK) != 0;
        bool removed = unlink(path) == 0;
        ok = made && refused && removed && ok;
    }
    return ok;
}

struct aj_serve_paths { char ready[PATH_MAX], status[PATH_MAX], finish[PATH_MAX]; };

static bool aj_serve_case(struct aj_node_ctx *b, const struct aj_serve_paths *p, int mode)
{
    bool made = mode == 0 ? aj_write_file(p->finish, "done") :
        mode == 2 ? mkdir(p->finish, 0700) == 0 : true;
    bool served = made && aj_role_serve(b, 1);
    bool receipt = aj_serve_receipt(p->ready);
    bool finish_ok = mode == 1 || (mode == 2 ? rmdir(p->finish) == 0 : unlink(p->finish) == 0);
    bool ready_ok = unlink(p->ready) == 0;
    bool status_ok = unlink(p->status) == 0;
    return made && (served == (mode == 0)) && receipt && finish_ok && ready_ok && status_ok;
}

static bool aj_serve_tests(const char *root)
{
    if (strlen(root) >= sizeof(g_work)) return false;
    memcpy(g_work, root, strlen(root) + 1);
    memset(g_host_hex, 'a', 64); g_host_hex[64] = 0;
    memset(g_carrier, 'b', 64); g_carrier[64] = 0;
    struct aj_node_ctx b = {.rpc = 1};
    if (strlen(root) >= sizeof(b.home)) return false;
    memcpy(b.home, root, strlen(root) + 1); memcpy(b.datadir, root, strlen(root) + 1);
    struct aj_serve_paths p;
    if (!aj_path_join(p.ready, sizeof(p.ready), root, "receiver-ready.json") ||
        !aj_path_join(p.status, sizeof(p.status), root, "onion-status.json") ||
        !aj_path_join(p.finish, sizeof(p.finish), root, "finish")) return false;
    bool ok = aj_serve_refusals(&b, root, p.ready);
    for (int i = 0; i < 3; i++) ok = aj_serve_case(&b, &p, i) && ok;
    if (ok) puts("receiver serving readiness and hold: PASS");
    return ok;
}

static int aj_nested_node_test(bool crash)
{
    struct aj_nested_paths paths;
    if (!aj_nested_prepare(crash, &paths)) return 1;
    bool observed = aj_nested_observe(crash, paths.ready);
    bool served = crash || aj_serve_tests(g_repo);
    bool stopped = aj_role_node_stop();
    (void)unlink(paths.ready); (void)unlink(paths.marker); (void)unlink(paths.log);
    return observed && served && (crash ? !stopped : stopped) ? 0 : 1;
}

static bool aj_test_detached_ready(void)
{
        int ready[2]; if (pipe(ready) != 0) return false;
        pid_t p = fork();
        if (p < 0) return false;
        if (!p) {
            close(ready[0]); if (setsid() < 0) _exit(2);
            char r = 'r'; if (write(ready[1], &r, 1) != 1) _exit(2);
            for (;;) pause();
        }
        close(ready[1]); char r;
        if (read(ready[0], &r, 1) != 1) return false;
        close(ready[0]);
        return true;
}

static int aj_test_supervised_child(const char *mode)
{
        char b; if (read(3, &b, 1) != 1 || b != 'R') return 99;
        if (!strcmp(mode, "supervised-fail")) return 7;
        if (!strcmp(mode, "supervised-signal")) { raise(SIGKILL); return 99; }
        if (!strcmp(mode, "supervised-nested")) return aj_nested_node_test(false);
        if (!strcmp(mode, "supervised-nested-crash")) return aj_nested_node_test(true);
        if (!aj_test_detached_ready()) return 99;
        if (!strcmp(mode, "supervised-timeout")) for (;;) pause();
        return 0;
}

static int aj_test_child(const char *mode)
{
    if (!strncmp(mode, "supervised-", 11)) return aj_test_supervised_child(mode);
    if (!strcmp(mode, "held")) {
        pid_t p = fork();
        if (p < 0) return 99;
        if (p == 0) { sleep(2); _exit(0); }
        return 7;
    }
    if (!strcmp(mode, "signal")) { raise(SIGKILL); return 99; }
    /* Real delay lets the parent enter its wait before the interrupt. */
    if (!strcmp(mode, "interrupt")) { sleep(1); kill(getppid(), SIGUSR1); sleep(1); return 0; }
    if (!strcmp(mode, "timeout")) { sleep(5); return 0; }
    return 0;
}

static int aj_role_parse_test(void)
{
    char peer[100]; memset(peer, 'a', 56); memcpy(peer + 56, ".onion:20024", sizeof(".onion:20024"));
    char peerarg[120]; snprintf(peerarg, sizeof(peerarg), "--peer=%s", peer);
    char *good[] = {(char *)"fixture", (char *)"--receiver", (char *)"--work=/tmp/new",
        (char *)"--seconds=10", peerarg, (char *)"--expected=/tmp/public.json", NULL};
    struct aj_role_args r;
    bool ok = aj_role_parse(6, good, &r) && r.receiver && !r.sender && !r.serve && r.seconds == 10;
    good[6] = (char *)"--serve";
    bool serve = aj_role_parse(7, good, &r) && r.serve;
    if (!serve) fprintf(stderr, "receiver --serve was refused\n");
    ok = serve && ok;
    good[6] = NULL;
    char *bad_sender[] = {(char *)"fixture", (char *)"--sender", (char *)"--work=/tmp/new",
        (char *)"--seconds=10", (char *)"--serve", NULL};
    ok = !aj_role_parse(5, bad_sender, &r) && ok;
    peer[0] = '8'; snprintf(peerarg, sizeof(peerarg), "--peer=%s", peer);
    ok = !aj_role_parse(6, good, &r) && ok;
    peer[0] = 'a'; snprintf(peerarg, sizeof(peerarg), "--peer=%s", peer);
    good[2] = (char *)"--work=relative";
    ok = !aj_role_parse(6, good, &r) && ok;
    if (ok) puts("split role parser: PASS");
    return ok ? 0 : 1;
}

static bool aj_role_test_identity(char *root, const char *pub, const char *image)
{
    char body[512];
    snprintf(body, sizeof(body), "result\n  package_root: %s\n  publisher_fingerprint: %s\n  image_sha3: %s\n", root, pub, image);
    bool matching = aj_received_matches(body);
    root[0] = 'd';
    snprintf(body, sizeof(body), "result\n  package_root: %s\n  publisher_fingerprint: %s\n  image_sha3: %s\n", root, pub, image);
    return matching && !aj_received_matches(body);
}

static bool aj_test_dir_empty(const char *path)
{
    DIR *d = opendir(path); struct dirent *entry; bool empty = d != NULL;
    while (d && (entry = readdir(d)) != NULL)
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) empty = false;
    if (d && closedir(d) != 0) empty = false;
    return empty;
}

static bool aj_role_test_workspace(const char *tmp, const char *path)
{
    char work[PATH_MAX];
    if (snprintf(work, sizeof(work), "%s/receiver", tmp) >= (int)sizeof(work)) return false;
    struct aj_role_args r = {.receiver = true, .work = work, .expected = path, .seconds = 5};
    bool prepared = aj_role_prepare(&r);
    bool empty = prepared && aj_test_dir_empty(g_repo_app);
    bool refused = !aj_role_prepare(&r);
    bool removed = aj_rm_rf(work, 0);
    bool bad = aj_write_file(path, "{\"name\":\"bad\"}") && !aj_role_expected(path) &&
        !aj_role_prepare(&r) && access(work, F_OK) != 0;
    return prepared && empty && refused && removed && bad;
}

static int aj_role_expected_test(const char *tmp)
{
    char path[PATH_MAX], root[65], pub[67], image[65], body[512];
    memset(root, 'a', 64); root[64] = 0; memset(pub, 'b', 66); pub[66] = 0;
    memset(image, 'c', 64); image[64] = 0;
    if (snprintf(path, sizeof(path), "%s/expected.json", tmp) >= (int)sizeof(path)) return 1;
    snprintf(body, sizeof(body), "{\"name\":\"example/app\",\"root\":\"%s\",\"publisher\":\"%s\",\"image\":\"%s\"}", root, pub, image);
    bool ok = aj_write_file(path, body) && aj_role_expected(path) && !strcmp(g_root, root) && !strcmp(g_image_a, image);
    ok = aj_role_test_identity(root, pub, image) && ok;
    ok = aj_role_test_workspace(tmp, path) && ok;
    ok = !aj_role_name("a/b/c") && !aj_role_name("a_b/c") && aj_role_name("a-b/c-1") && ok;
    ok = unlink(path) == 0 && ok;
    if (ok) puts("split public handoff validation: PASS");
    return ok ? 0 : 1;
}

#if defined(__linux__)
static int aj_supervised_case(const char *self, const char *tmp, const char *mode, bool success, bool cancel)
{
    int image = aj_role_self_image(), input = open("/dev/null", O_RDONLY | O_CLOEXEC), fds[2];
    if (image < 0 || input < 0 || pipe(fds) != 0) return 1;
    const char *argv[] = {self, "--child", mode, NULL};
    char root_env[PATH_MAX + 32];
    if (snprintf(root_env, sizeof(root_env), "AJ_TEST_ROOT=%s", tmp) >= (int)sizeof(root_env)) return 1;
    const char *env[] = {"PATH=/usr/bin:/bin", root_env, NULL};
    struct platform_supervised_fd_map maps[] = {{input, 0}, {1, 1}, {2, 2}, {fds[0], 3}};
    int64_t start = clock_now_monotonic_ns();
    struct platform_supervised_spec spec = {.executable_fd = image, .argv = argv,
        .env = env, .env_count = 2, .env_policy = PLATFORM_SUPERVISED_ENV_COMPLETE,
        .maps = maps, .map_count = 4, .launch_deadline_ns = start + 5000000000LL,
        .cleanup_timeout_ms = 10000};
    struct platform_supervised_process p; platform_supervised_init(&p);
    enum platform_supervised_state state = platform_supervised_start(&p, &spec);
    close(image); close(input); close(fds[0]);
    if (state != PLATFORM_SUPERVISED_RUNNING) {
        close(fds[1]); if (p.supervisor_pid >= 0) (void)aj_role_drain(&p); return 1;
    }
    g_role_stop = cancel;
    int64_t budget = !strncmp(mode, "supervised-nested", 17) ?
        20000000000LL : 2000000000LL;
    int rc = aj_role_monitor(&p, fds[1], start, start + budget);
    g_role_stop = 0;
    return (rc == 0) == success && p.supervisor_pid < 0 && p.observation.no_children &&
        p.observation.engine_exit_observed ? 0 : 1;
}

static int aj_supervised_test(const char *self, const char *tmp)
{
    struct sigaction old[3];
    if (!aj_role_handlers(old)) return 1;
    pid_t other = fork();
    if (!other) _exit(42);
    int failed = other < 0;
    failed |= aj_supervised_case(self, tmp, "supervised-ok", true, false);
    failed |= aj_supervised_case(self, tmp, "supervised-fail", false, false);
    failed |= aj_supervised_case(self, tmp, "supervised-signal", false, false);
    failed |= aj_supervised_case(self, tmp, "supervised-timeout", false, false);
    failed |= aj_supervised_case(self, tmp, "supervised-timeout", false, true);
    failed |= aj_supervised_case(self, tmp, "supervised-nested", true, false);
    failed |= aj_supervised_case(self, tmp, "supervised-nested-crash", true, false);
    char *owner_argv[] = {(char *)self, (char *)"--child", (char *)"supervised-ok", NULL};
    struct aj_role_args owner_args = {.seconds = 5};
    failed |= aj_role_owner(3, owner_argv, &owner_args) != 0;
    int status; pid_t got;
    do { got = waitpid(other, &status, 0); } while (got < 0 && errno == EINTR);
    if (got != other || !WIFEXITED(status) || WEXITSTATUS(status) != 42) failed = 1;
    if (!aj_role_handlers_restore(old)) failed = 1;
    if (!failed) puts("split supervised owner lifecycle: PASS");
    return failed;
}

static int aj_role_owner_test(const char *self, const char *tmp)
{
    char work[PATH_MAX + 16];
    if (snprintf(work, sizeof(work), "--work=%s", tmp) >= (int)sizeof(work)) return 1;
    char *argv[] = {(char *)self, (char *)"--sender", work, (char *)"--seconds=5", NULL};
    struct aj_role_args r;
    if (!aj_role_parse(4, argv, &r)) return 1;
    bool refused = aj_role_owner(4, argv, &r) != 0;
    char missing[PATH_MAX];
    if (snprintf(missing, sizeof(missing), "%s/control-missing", tmp) >= (int)sizeof(missing)) return 1;
    r.work = missing;
    pid_t p = fork();
    if (!p) { close(3); _exit(aj_role_work(&r) == 2 ? 0 : 1); }
    if (p < 0) return 1;
    int st; pid_t got; do { got = waitpid(p, &st, 0); } while (got < 0 && errno == EINTR);
    bool ok = refused && got == p && WIFEXITED(st) && WEXITSTATUS(st) == 0 && access(missing, F_OK) != 0;
    if (ok) puts("split owner existing work and control refusal: PASS");
    return ok ? 0 : 1;
}
#else
static int aj_supervised_test(const char *self, const char *tmp) { (void)self; (void)tmp; return 0; }
static int aj_role_owner_test(const char *self, const char *tmp) { (void)self; (void)tmp; return 0; }
#endif

static bool aj_test_home_file(const char *name)
{
    const char *home = getenv("HOME"); char path[PATH_MAX];
    return home && snprintf(path, sizeof(path), "%s/%s", home, name) < (int)sizeof(path) && access(path, F_OK) == 0;
}

static int aj_test_host_status(int argc, char **argv, int i)
{
    if (i + 4 >= argc || strncmp(argv[i + 3], "--host=", 7) || strncmp(argv[i + 4], "--carrier=", 10)) return 2;
    if (aj_test_home_file("status-error")) return 7;
    if (aj_test_home_file("status-missing")) { puts("{\"ok\":true,\"data\":{}}"); return 0; }
    const char *host = aj_test_home_file("status-mismatch") ? "wrong" : argv[i + 3] + 7;
    printf("{\"ok\":%s,\"data\":{\"host\":\"%s\",\"carrier\":\"%s\",\"enabled\":%s,\"generation\":1}}\n",
           aj_test_home_file("status-not-ok") ? "false" : "true", host, argv[i + 4] + 10,
           aj_test_home_file("status-false") ? "false" : "true");
    return 0;
}

static int aj_test_get(int argc, char **argv, int i)
{
    if (i + 2 == argc) {
        if (aj_test_home_file("catalog-error")) return 7;
        puts(aj_test_home_file("catalog-absent") ? "example/app-extra abc root 1s ago" : "example/app abc 0123456789abcdef 1s ago");
        return 0;
    }
    if (i + 4 != argc || strcmp(argv[i + 3], "--yes")) return 2;
    int fd = open("get-count", O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return 2;
    char b = 'x'; bool ok = write(fd, &b, 1) == 1 && close(fd) == 0;
    if (!ok) return 2;
    if (access("get-success", F_OK) == 0) { puts("retrieval succeeded"); return 0; }
    puts("distinctive retrieval failure"); return 7;
}

static int aj_test_cli(int argc, char **argv)
{
    for (int i = 0; i + 2 < argc; ++i) {
        if (!strcmp(argv[i], "app") && !strcmp(argv[i + 1], "host") && !strcmp(argv[i + 2], "status"))
            return aj_test_host_status(argc, argv, i);
        if (!strcmp(argv[i], "core") && !strcmp(argv[i + 1], "network") && !strcmp(argv[i + 2], "onion")) {
            puts("{\"data\":{\"p2p_publish_ready\":true}} "); return 0;
        }
    }
    for (int i = 0; i + 1 < argc; ++i)
        if (!strcmp(argv[i], "app") && !strcmp(argv[i + 1], "get")) return aj_test_get(argc, argv, i);
    return -1;
}

static bool aj_single_get_success(struct aj_node_ctx *c, const char *tmp, const char *path)
{
    char success[PATH_MAX], out[4096]; struct stat st;
    if (snprintf(success, sizeof(success), "%s/get-success", tmp) >= (int)sizeof(success)) return false;
    int fd = open(success, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0 || close(fd) != 0) return false;
    bool passed = aj_b_get_once(c, out, sizeof(out)) && strstr(out, "retrieval succeeded");
    bool once = stat(path, &st) == 0 && st.st_size == 1;
    bool cleaned = unlink(success) == 0 && unlink(path) == 0;
    return passed && once && cleaned;
}

static int aj_single_get_test(const char *tmp)
{
    struct aj_node_ctx c = {.rpc = 1};
    size_t len = strlen(tmp);
    if (len >= sizeof(c.datadir) || len >= sizeof(g_repo_app)) return 1;
    memcpy(c.datadir, tmp, len + 1); memcpy(c.home, tmp, len + 1);
    memcpy(g_repo_app, tmp, len + 1);
    snprintf(g_name, sizeof(g_name), "example/app");
    g_board_wait_s = 3;
    char out[4096], path[PATH_MAX];
    bool failed = !aj_b_get_once(&c, out, sizeof(out)) && strstr(out, "distinctive retrieval failure");
    if (snprintf(path, sizeof(path), "%s/get-count", tmp) >= (int)sizeof(path)) return 1;
    struct stat st;
    bool once = stat(path, &st) == 0 && st.st_size == 1;
    (void)unlink(path);
    g_board_wait_s = 1;
    bool passed = aj_single_get_success(&c, tmp, path);
    if (failed && once && passed) puts("single get failure and success: PASS");
    return failed && once && passed ? 0 : 1;
}

static int aj_catalog_test(const char *tmp)
{
    struct aj_node_ctx c = {.rpc = 1}; size_t len = strlen(tmp);
    if (len >= sizeof(c.datadir)) return 1;
    memcpy(c.datadir, tmp, len + 1); memcpy(c.home, tmp, len + 1);
    snprintf(g_name, sizeof(g_name), "example/app"); g_board_wait_s = 2;
    bool ok = !aj_catalog_has_name("example/app-extra abc\n", g_name) &&
        aj_catalog_has_name("other abc\nexample/app abc root\n", g_name);
    char path[PATH_MAX], out[1024];
    const char *modes[] = {"catalog-absent", "catalog-error"};
    for (size_t i = 0; i < 2; i++) {
        if (snprintf(path, sizeof(path), "%s/%s", tmp, modes[i]) >= (int)sizeof(path)) return 1;
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0 || close(fd) != 0) return 1;
        bool absent = !aj_wait_catalog(&c, out, sizeof(out));
        bool removed = unlink(path) == 0;
        ok = absent && removed && ok;
    }
    if (ok) puts("catalog matching and refusal: PASS");
    return ok ? 0 : 1;
}

static int aj_test_call(const char *mode, int timeout, int expected)
{
    char out[256];
    char *args[] = {(char *)"z23", (char *)"--child", (char *)mode, NULL};
    int got = aj_run("/", "/", timeout, out, sizeof out, args);
    if (got != expected) {
        fprintf(stderr, "%s: expected %d, got %d\n", mode, expected, got);
        return 1;
    }
    printf("%s: PASS\n", mode);
    return 0;
}

static int aj_test_setup(const char *self, const char *tmp)
{
    char path[PATH_MAX + 32];
    if (snprintf(g_repo, sizeof g_repo, "%s", tmp) >= (int)sizeof g_repo ||
        snprintf(path, sizeof path, "%s/build", tmp) >= (int)sizeof path || mkdir(path, 0700)) return 2;
    if (snprintf(path, sizeof path, "%s/build/bin", tmp) >= (int)sizeof path || mkdir(path, 0700)) return 2;
    if (snprintf(path, sizeof path, "%s/build/bin/z23", tmp) >= (int)sizeof path || symlink(self, path)) return 2;
    if (snprintf(path, sizeof path, "%s/build/bin/zclassic23", tmp) >= (int)sizeof path || symlink(self, path)) return 2;
    return 0;
}

static int aj_group_startup_test(void)
{
    int ready[2], gate[2];
    if (pipe(ready) || pipe(gate)) return 1;
    pid_t p = fork();
    if (p < 0) return 1;
    if (!p) {
        close(ready[0]); close(gate[1]);
        char b = 'r';
        if (write(ready[1], &b, 1) != 1) _exit(2);
        if (read(gate[0], &b, 1) < 0) _exit(2);
        _exit(0);
    }
    close(ready[1]); close(gate[0]);
    struct pollfd fd = {.fd = ready[0], .events = POLLIN};
    char b; bool ready_ok = poll(&fd, 1, 3000) > 0 && (fd.revents & POLLIN) && read(ready[0], &b, 1) == 1;
    bool stopped = ready_ok && aj_kill_group(p);
    close(ready[0]); close(gate[1]);
    if (!stopped && aj_observe_child(p, WNOHANG) >= 0) {
        (void)kill(p, SIGKILL); (void)waitpid(p, NULL, 0);
    }
    if (!stopped) fprintf(stderr, "group startup custody failed\n");
    else puts("group pre-setsid cleanup: PASS");
    return stopped ? 0 : 1;
}

static void aj_group_test_leader(int ready[2], int alive[2])
{
    close(ready[0]); close(alive[0]);
    if (setsid() < 0 || signal(SIGTERM, SIG_IGN) == SIG_ERR) _exit(2);
    pid_t child = fork();
    if (child < 0) _exit(2);
    if (!child) { close(ready[1]); for (;;) pause(); }
    if (signal(SIGTERM, SIG_DFL) == SIG_ERR) _exit(2);
    char b = 'r'; if (write(ready[1], &b, 1) != 1) _exit(2);
    for (;;) pause();
}

static bool aj_group_test_wait_other(pid_t other)
{
    int st; pid_t got; do { got = waitpid(other, &st, 0); } while (got < 0 && errno == EINTR);
    return got == other && WIFEXITED(st) && WEXITSTATUS(st) == 42 &&
        !aj_kill_group(other) && !aj_kill_group(getpid());
}

static bool aj_group_test_finish(pid_t p, int ready, int alive)
{
    struct pollfd ready_fd = {.fd = ready, .events = POLLIN};
    char b; bool ready_ok = p > 0 && poll(&ready_fd, 1, 3000) > 0 &&
        (ready_fd.revents & POLLIN) && read(ready, &b, 1) == 1;
    bool stopped = p > 0 && aj_kill_group(p);
    bool absent = stopped && kill(-p, 0) < 0 && errno == ESRCH;
    close(ready);
    struct pollfd fd = {.fd = alive, .events = POLLIN | POLLHUP};
    bool eof = poll(&fd, 1, 3000) > 0 && (fd.revents & POLLHUP) && read(alive, &b, 1) == 0;
    close(alive);
    return ready_ok && stopped && absent && eof;
}

static int aj_group_owned_test(void)
{
    int ready[2], alive[2];
    if (pipe(ready) || pipe(alive)) return 1;
    pid_t other = fork();
    if (!other) _exit(42);
    if (other < 0) return 1;
    pid_t p = fork();
    if (!p) aj_group_test_leader(ready, alive);
    close(ready[1]); close(alive[1]);
    bool ok = aj_group_test_finish(p, ready[0], alive[0]);
    ok = aj_group_test_wait_other(other) && ok;
    if (ok) puts("group descendant and unrelated custody: PASS");
    return ok ? 0 : 1;
}

static int aj_test_cases(void)
{
    struct sigaction action = {0}, old;
    action.sa_handler = aj_test_interrupt;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, &old) != 0) return 1;
    int failed = aj_test_call("held", 8, 7) | aj_test_call("ok", 8, 0) |
                 aj_test_call("signal", 8, -1) | aj_test_call("timeout", 1, -1) |
                 aj_test_call("interrupt", 8, 0);
    if (!aj_interrupted || sigaction(SIGUSR1, &old, NULL) != 0) failed = 1;
    pid_t p = fork();
    if (p == 0) _exit(0);
    int st;
    g_alarm_fired = 0;
    if (p < 0 || waitpid(p, &st, 0) != p || aj_finish_child(p, true) != -1) failed = 1;
    else puts("ECHILD: PASS");
    int fds[2]; char out[4] = "bad";
    if (pipe(fds) != 0) return 1;
    close(fds[0]); close(fds[1]);
    if (aj_capture_pipe(fds[0], getpid(), out, sizeof out) || out[0] != '\0') failed = 1;
    else puts("capture read failure: PASS");
    return failed;
}

static int aj_test_dispatch(int argc, char **argv)
{
    if ((argc == 3 || (argc == 4 && !strcmp(argv[3], "--role-worker"))) &&
        !strcmp(argv[1], "--child")) return aj_test_child(argv[2]);
    if (argc > 2 && !strncmp(argv[1], "-datadir=", 9) && !strcmp(argv[2], "-regtest")) return aj_fake_node();
    if (argc > 1 && !strcmp(argv[1], "--node-worker")) return app_journey_live_main(argc, argv);
    if (argc > 1 && (!strcmp(argv[1], "--sender") || !strcmp(argv[1], "--receiver")))
        return app_journey_live_main(argc, argv);
    int cli = aj_test_cli(argc, argv);
    if (cli >= 0) return cli;
    return -1;
}

static int aj_test_suite(const char *self, const char *tmp)
{
    int failed = aj_test_cases() | aj_group_startup_test() | aj_group_owned_test();
    failed |= aj_single_get_test(tmp) | aj_catalog_test(tmp) | aj_role_parse_test();
    failed |= aj_role_expected_test(tmp) | aj_supervised_test(self, tmp) | aj_role_owner_test(self, tmp);
    return failed;
}

int main(int argc, char **argv)
{
    int dispatch = aj_test_dispatch(argc, argv);
    if (dispatch >= 0) return dispatch;
    char self[PATH_MAX], tmp[PATH_MAX], root[PATH_MAX];
    const char *base = getenv("TMPDIR"), *home = getenv("HOME");
    if (!base || !*base) {
        if (!home || snprintf(root, sizeof root, "%s/.cache/development-scratch/z23", home) >= (int)sizeof root || aj_mkdir_p(root)) return 2;
        base = root;
    }
    if (!realpath(argv[0], self) || snprintf(tmp, sizeof tmp, "%s/app-journey-test.XXXXXX", base) >= (int)sizeof tmp || !mkdtemp(tmp)) return 2;
    int failed = aj_test_setup(self, tmp);
    if (!failed) failed = aj_test_suite(self, tmp);
    if (!aj_rm_rf(tmp, 0)) failed = 1;
    if (!failed) puts("app journey child status selftest: PASS");
    return failed;
}
