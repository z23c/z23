#include "mutation_harness.h"
#include "test/test_core.h"
#include "platform/clock.h"
#include "platform/directory_compat.h"
#include "util/supervised_retirement.h"
#include "util/thread_registry.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if defined(__linux__)
#include "platform/supervised_process.h"
#include "sha3/sha3.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#endif

static struct zcl_mut_owner cli_owner = ZCL_MUT_OWNER_INIT;

#if defined(__linux__)
/* Exact fixture child only: no process-group retirement may mask the inner
 * supervisor's owner-EOF cleanup. Timeout is always a failed observation. */
static int cli_wait(pid_t child, int seconds)
{
    int64_t end = clock_now_monotonic_ns() + (int64_t)seconds * 1000000000;
    int status;
    while (clock_now_monotonic_ns() < end) {
        pid_t got = waitpid(child, &status, WNOHANG);
        if (got == child) return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        if (got < 0 && errno != EINTR) return -1;
        struct timespec pause = {.tv_nsec = 10000000};
        (void)nanosleep(&pause, NULL);
    }
    (void)kill(child, SIGKILL);
    (void)waitpid(child, &status, 0);
    return -1;
}

static pid_t cli_start(char *const arguments[], const char *log)
{
    int fd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    pid_t child = fork();
    if (child == 0) {
        if (dup2(fd, 1) < 0 || dup2(fd, 2) < 0) _exit(125);
        (void)close(fd);
        execvp(arguments[0], arguments);
        _exit(127);
    }
    (void)close(fd);
    return child;
}

static int cli_exec(char *const arguments[], const char *log, int seconds)
{
    pid_t child = cli_start(arguments, log);
    return child > 0 ? cli_wait(child, seconds) : -1;
}

static long long cli_recorded_pid(const char *work, const char *name)
{
    char path[PATH_MAX];
    (void)snprintf(path, sizeof(path), "%s/%s", work, name);
    FILE *file = fopen(path, "rb");
    long long pid = -1;
    if (file) {
        if (fscanf(file, "%lld", &pid) != 1) pid = -1;
        (void)fclose(file);
    }
    return pid;
}

struct cli_refusal_paths {
    char marker[PATH_MAX], lock[PATH_MAX], subject[PATH_MAX];
    char cache[PATH_MAX], report[PATH_MAX], workarg[PATH_MAX + 8], reportarg[PATH_MAX + 10];
};
struct cli_refusal_state {
    int leaf_fd, rc;
    bool ready, locked, authorized, settled, dead, released;
};

static bool cli_refusal_prepare(const char *binary, const char *work, const char *log,
    struct cli_refusal_paths *paths)
{
    (void)snprintf(paths->marker, sizeof(paths->marker), "%s/destructor", work);
    (void)snprintf(paths->lock, sizeof(paths->lock), "%s/held.lock", work);
    (void)snprintf(paths->subject, sizeof(paths->subject), "%s/subject.c", work);
    (void)snprintf(paths->cache, sizeof(paths->cache), "%s/cache", work);
    (void)snprintf(paths->report, sizeof(paths->report), "%s/report.json", work);
    (void)snprintf(paths->workarg, sizeof(paths->workarg), "--work=%s", work);
    (void)snprintf(paths->reportarg, sizeof(paths->reportarg), "--report=%s", paths->report);
    FILE *sentinel = fopen(paths->subject, "wb");
    if (!sentinel) return false;
    bool written = fputs("original subject\n", sentinel) >= 0;
    if (fclose(sentinel) != 0 || !written) return false;
    char *control[] = {(char *)binary, "--_fixture-destructor-control", (char *)work, NULL};
    return cli_exec(control, log, 5) == 0 && unlink(paths->marker) == 0;
}

static void cli_refusal_live(const char *work, const struct cli_refusal_paths *paths,
    struct cli_refusal_state *state)
{
    int64_t deadline = clock_now_monotonic_ns() + 4000000000;
    long long leaf = -1;
    while (clock_now_monotonic_ns() < deadline) {
        leaf = cli_recorded_pid(work, "leaf");
        if (leaf > 0 && cli_recorded_pid(work, "supervisor") > 0) break;
        (void)poll(NULL, 0, 10);
    }
    state->leaf_fd = leaf > 0 ? platform_supervised_fixture_pidfd_open(leaf) : -1;
    struct pollfd alive = {.fd = state->leaf_fd, .events = POLLIN};
    int held = open(paths->lock, O_RDWR);
    state->locked = held >= 0 && flock(held, LOCK_EX | LOCK_NB) != 0 &&
        (errno == EWOULDBLOCK || errno == EAGAIN);
    if (held >= 0) (void)close(held);
    state->ready = state->leaf_fd >= 0 && poll(&alive, 1, 0) == 0 && state->locked;
    char release[PATH_MAX];
    (void)snprintf(release, sizeof(release), "%s/allow-exit", work);
    int token = state->ready ? open(release, O_WRONLY | O_CREAT | O_EXCL, 0600) : -1;
    state->authorized = token >= 0;
    if (token >= 0) (void)close(token);
}

static void cli_refusal_settle(const char *work, const struct cli_refusal_paths *paths,
    struct cli_refusal_state *state, pid_t cli)
{
    state->rc = cli_wait(cli, 10);
    long long supervisor = cli_recorded_pid(work, "supervisor");
    /* Never signal the inner supervisor on the passing path. Its exact wait
     * and the retained leaf pidfd establish cleanup independently of the CLI. */
    state->settled = supervisor > 0 && cli_wait((pid_t)supervisor, 5) == 0;
    struct pollfd alive = {.fd = state->leaf_fd, .events = POLLIN};
    state->dead = state->leaf_fd >= 0 && poll(&alive, 1, 0) == 1 && (alive.revents & POLLIN);
    if (state->leaf_fd >= 0) (void)close(state->leaf_fd);
    int lock = open(paths->lock, O_RDWR);
    state->released = lock >= 0 && flock(lock, LOCK_EX | LOCK_NB) == 0;
    if (lock >= 0) (void)close(lock);
}

static bool cli_refusal_files(const struct cli_refusal_paths *paths)
{
    char original[64] = {0};
    FILE *sentinel = fopen(paths->subject, "rb");
    bool unchanged = sentinel && fgets(original, sizeof(original), sentinel) &&
        strcmp(original, "original subject\n") == 0 && fgetc(sentinel) == EOF && !ferror(sentinel);
    if (sentinel) (void)fclose(sentinel);
    return unchanged && access(paths->cache, F_OK) != 0 && access(paths->report, F_OK) != 0 &&
        access(paths->marker, F_OK) != 0;
}

static bool cli_refusal_output(const char *log)
{
    char output[8192] = {0};
    FILE *file = fopen(log, "rb");
    size_t used = file ? fread(output, 1, sizeof(output) - 1, file) : 0;
    bool read_ok = file && !ferror(file) && used < sizeof(output) - 1;
    if (file) (void)fclose(file);
    return read_ok && strstr(output, "UNCLEAN_EXIT") &&
        strstr(output, "next_refused=1 credited=0 retained=1") &&
        strstr(output, "fixture refusals=3 retained=1") && !strstr(output, "score_tenths");
}

static bool cli_refusal_driver(const char *binary, const char *work, const char *log)
{
    if (!platform_supervised_fixture_subreaper()) return false;
    struct cli_refusal_paths paths;
    if (!cli_refusal_prepare(binary, work, log, &paths)) return false;
    char *arguments[] = {(char *)binary, "--file=tools/agent/gate_receipt.c",
        "--group=mutation_harness", paths.workarg, paths.reportarg, "--_fixture-cleanup-refusal", NULL};
    pid_t cli = cli_start(arguments, log);
    if (cli <= 0) return false;
    struct cli_refusal_state state = {.leaf_fd = -1};
    cli_refusal_live(work, &paths, &state);
    cli_refusal_settle(work, &paths, &state, cli);
    printf("  actual CLI chronology: live_leaf=%d held_lock=%d authorized=%d dead_leaf=%d supervisor_clean=%d released_lock=%d\n",
        state.ready, state.locked, state.authorized, state.dead, state.settled, state.released);
    (void)fflush(stdout);
    return state.ready && state.authorized && state.dead && state.rc == ZCL_MUT_EXIT_CLEANUP_PENDING &&
        state.settled && state.released && cli_refusal_files(&paths) && cli_refusal_output(log);
}

static bool cli_fixture_write(const char *root, const char *relative, const char *text)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", root, relative);
    return n > 0 && (size_t)n < sizeof(path) && zcl_mut_write_file(path, text, strlen(text));
}

static bool cli_endpoint_make(const char *root, const char *binary)
{
    const char *cc = getenv("CC");
    if (!cc || !cc[0]) cc = "cc";
    struct zcl_mut_argv compiler = {0};
    if (!zcl_mut_shell_split(cc, &compiler)) return false;
    size_t count = compiler.count;
    zcl_mut_argv_free(&compiler);
    if (!count || count > 32) return false;
    char path[PATH_MAX];
    (void)snprintf(path, sizeof(path), "%s/Makefile", root);
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    (void)fputs("ifneq ($(Z23_MUT_ENV_64),64 a b utf8-\xc3\xa9)\n$(error missing complete environment)\nendif\n"
        "$(file >>$(Z23_MUT_ENDPOINT_LOG),plan env65=1)\n.PHONY: endpoint\nendpoint:\n", file);
    (void)fprintf(file, "\tbuild/bin/zcc --epoch-object dep subject.o subject.c -- %s --_fixture-compiler compile %s -std=c23 -O0", binary, cc);
    for (size_t i = 5 + count; i < ZCL_MUT_ARGV_MAX - 4; ++i)
        (void)fprintf(file, " -DZ23_PAD_%zu=%zu", i, i);
    (void)fprintf(file, "\n\t%s --_fixture-compiler link %s -o subject.bin @subject.rsp", binary, cc);
    for (size_t i = 6 + count; i < ZCL_MUT_ARGV_MAX; ++i)
        (void)fprintf(file, " -DZ23_PAD_%zu=%zu", i, i);
    (void)fputc('\n', file);
    bool ok = !ferror(file);
    return fclose(file) == 0 && ok;
}

static bool cli_setup_error(const char *stage, const char *path)
{
    fprintf(stderr, "private CLI endpoint setup: %s path=%s: %s\n", stage, path, strerror(errno));
    return false;
}

static bool cli_endpoint_setup(const char *root, const char *binary, const char *checkout)
{
    char source[PATH_MAX], path[PATH_MAX];
    if (!platform_directory_ensure(root, 0700)) return cli_setup_error("root directory", root);
    static const char *const dirs[] = {"build", "build/bin", "engine", "engine/composition",
        "engine/composition/commands", "tools", "tools/dev"};
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); ++i) {
        (void)snprintf(path, sizeof(path), "%s/%s", root, dirs[i]);
        if (!platform_directory_ensure(path, 0700)) return cli_setup_error("directory", path);
    }
    static const char *const links[] = {"build/bin/zcc", "build/bin/process-group-exec", "tools/dev/checkout-lock.sh"};
    for (size_t i = 0; i < 3; ++i) {
        (void)snprintf(source, sizeof(source), "%s/%s", checkout, links[i]);
        (void)snprintf(path, sizeof(path), "%s/%s", root, links[i]);
        if (symlink(source, path) != 0) return cli_setup_error("maintained tool link", path);
    }
    static const char subject[] =
        "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n"
        "int f(int x) { return x > 0; }\n"
        "int main(void) {\n"
        " for(unsigned i=0;i<65;i++){char key[40],expected[80];\n"
        " snprintf(key,sizeof(key),\"Z23_MUT_ENV_%u\",i);\n"
        " snprintf(expected,sizeof(expected),\"%u a b utf8-\\xc3\\xa9\",i);\n"
        " const char *value=getenv(key); if(!value||strcmp(value,expected))return 127;}\n"
        " const char *path=getenv(\"Z23_MUT_ENDPOINT_LOG\"); FILE *log=path?fopen(path,\"ab\"):NULL;\n"
        " if(!log)return 127; if(fputs(\"subject env65=1\\n\",log)<0||fclose(log))return 127;\n"
        " int bad=f(1)!=1||f(0)!=0;\n"
        " printf(\"SUITE VERDICT mode=cold groups_total=1 groups_ran=1 groups_cached=0 groups_gated=0 groups_failed=%d self_skips=0 env_unobserved=0 toolkey=endpoint\\n\",bad);return bad;}\n";
    return cli_fixture_write(root, "engine/composition/commands/root.def", "fixture\n") &&
        cli_fixture_write(root, "tools/dev/test_group_catalog.def", "fixture\n") &&
        cli_fixture_write(root, "subject.c", subject) &&
        cli_fixture_write(root, "subject.rsp", "subject.o\n") && cli_endpoint_make(root, binary);
}

static int cli_endpoint_child(const char *root, const char *binary, const char *log)
{
    if (chdir(root) != 0) return 125;
    for (unsigned i = 0; i < 65; ++i) {
        char key[40], value[80];
        (void)snprintf(key, sizeof(key), "Z23_MUT_ENV_%u", i);
        (void)snprintf(value, sizeof(value), "%u a b utf8-\xc3\xa9", i);
        if (setenv(key, value, 1) != 0) return 125;
    }
    if (setenv("Z23_MUT_ENDPOINT_LOG", log, 1) != 0) return 125;
    char *arguments[] = {(char *)binary, "--file=subject.c", "--group=fixture",
        "--target=endpoint", "--work=work", "--report=report", "--limit=1", "--no-cache", NULL};
    execv(binary, arguments);
    return 127;
}

static bool cli_endpoint_result(const char *log, const char *report)
{
    size_t length;
    char *phases = zcl_mut_read_file(log, &length);
    char *result = zcl_mut_read_file(report, &length);
    bool ok = phases && result && strstr(phases, "plan env65=1") &&
        strstr(phases, "compile argv=512 env65=1") && strstr(phases, "link argv=512 env65=1") &&
        strstr(phases, "subject env65=1") && strstr(result, "ran=1\n") &&
        strstr(result, "source_unchanged=1\n");
    free(phases); free(result);
    return ok;
}

static bool cli_endpoint(const char *directory, const char *binary, const char *checkout)
{
    char root[PATH_MAX], log[PATH_MAX], output[PATH_MAX], report[PATH_MAX];
    (void)snprintf(root, sizeof(root), "%s/endpoint", directory);
    if (!cli_endpoint_setup(root, binary, checkout)) return cli_setup_error("fixture files or make recipe", root);
    (void)snprintf(log, sizeof(log), "%s/phases", root);
    (void)snprintf(output, sizeof(output), "%s/output", root);
    (void)snprintf(report, sizeof(report), "%s/report", root);
    int fd = open(output, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return false;
    pid_t child = fork();
    if (child == 0) {
        if (dup2(fd, 1) < 0 || dup2(fd, 2) < 0) _exit(125);
        (void)close(fd);
        _exit(cli_endpoint_child(root, binary, log));
    }
    (void)close(fd);
    int rc = child > 0 ? cli_wait(child, 30) : -1;
    bool ok = rc == 0 && cli_endpoint_result(log, report);
    printf("  actual standalone plan/compiler/link/subject env65 argv512: %s; retained %s\n", ok ? "OK" : "FAIL", root);
    return ok;
}

static int cli_private_refusal(const char *checkout)
{
    char directory[PATH_MAX];
    if (!test_mkdtemp(directory, sizeof(directory), "mutation-cli")) return 1;
    char binary[PATH_MAX], log[PATH_MAX], target[PATH_MAX + 32], compiler[1024];
    (void)snprintf(binary, sizeof(binary), "%s/cli", directory);
    (void)snprintf(log, sizeof(log), "%s/output", directory);
    (void)snprintf(target, sizeof(target), "MUTATION_CAMPAIGN_BIN=%s", binary);
    const char *cc = getenv("CC");
    int n = snprintf(compiler, sizeof(compiler), "CC=%s -DZCL_TESTING", cc ? cc : "cc");
    if (n <= 0 || (size_t)n >= sizeof(compiler)) return 1;
    char *build[] = {"make", "-j8", "mutation-campaign", target, compiler, NULL};
    if (cli_exec(build, log, 180) != 0) {
        printf("  private CLI build failed; retained %s\n", directory);
        return 1;
    }
    pid_t driver = fork();
    if (driver == 0) _exit(cli_refusal_driver(binary, directory, log) ? 0 : 1);
    int rc = driver > 0 ? cli_wait(driver, 20) : -1;
    printf("  private maintained CLI repeated refusal/owner EOF: %s; retained %s\n",
        rc == 0 ? "OK" : "FAIL", directory);
    bool endpoint = cli_endpoint(directory, binary, checkout);
    return rc == 0 && endpoint ? 0 : 1;
}

static int cli_launcher_image(const char *checkout)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/build/bin/process-group-exec", checkout);
    if (n <= 0 || (size_t)n >= sizeof(path)) return -1;
    size_t length = 0;
    char *bytes = zcl_mut_read_file(path, &length);
    if (!bytes) return -1;
    uint8_t digest[32];
    zcl_sha3_256((const uint8_t *)bytes, length, digest);
    int image = -1;
    enum platform_supervised_image_result result =
        platform_supervised_image_capture(bytes, length, digest, &image);
    free(bytes);
    return result == PLATFORM_SUPERVISED_IMAGE_OK ? image : -1;
}

/* With the supervisor held at its cleanup gate, control packets stay unread
 * when it exits. The kernel then reports ECONNRESET to the owner ahead of the
 * final report still queued for it. Waits on outcomes; no clock decides. */
static bool cli_unread_supervise(struct platform_supervised_process *process,
    const struct platform_supervised_spec *spec, int output[2], int release)
{
    if (platform_supervised_start(process, spec) != PLATFORM_SUPERVISED_RUNNING) return false;
    (void)close(output[1]);
    output[1] = -1;
    char byte;
    while (read(output[0], &byte, 1) > 0) {} /* EOF: the engine has exited. */
    bool queued = true;
    for (unsigned i = 0; i < 64; ++i)
        queued = platform_supervised_signal(process, PLATFORM_SUPERVISED_TERMINATE) && queued;
    bool released = write(release, "x", 1) == 1;
    siginfo_t exited = {0};
    while (waitid(P_PID, (id_t)process->supervisor_pid, &exited, WEXITED | WNOWAIT) < 0 &&
           errno == EINTR) {}
    for (unsigned i = 0; i < 16 && process->supervisor_pid >= 0; ++i)
        (void)platform_supervised_poll(process);
    return queued && released;
}

static int cli_unread_packet_report(const char *checkout)
{
    int image = cli_launcher_image(checkout);
    int gate[2] = {-1, -1}, output[2] = {-1, -1};
    int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (image < 0 || input < 0 || pipe(gate) != 0 || pipe(output) != 0) return 1;
    const char *const arguments[] = {"process-group-exec", "/bin/true", NULL};
    const char *const environment[] = {NULL};
    struct platform_supervised_fd_map maps[] = {
        {input, STDIN_FILENO}, {output[1], STDOUT_FILENO}, {output[1], STDERR_FILENO}};
    struct platform_supervised_spec spec = {.executable_fd = image, .argv = arguments,
        .env = environment, .maps = maps, .map_count = 3,
        .launch_deadline_ns = clock_now_monotonic_ns() + INT64_C(600000000000),
        .cleanup_timeout_ms = 10000};
    struct platform_supervised_process process;
    platform_supervised_init(&process);
    platform_supervised_fixture_cleanup_gate(gate[0]);
    bool driven = cli_unread_supervise(&process, &spec, output, gate[1]);
    platform_supervised_fixture_cleanup_gate(-1);
    (void)close(gate[0]); (void)close(gate[1]); (void)close(output[0]);
    if (output[1] >= 0) (void)close(output[1]);
    (void)close(input); (void)close(image);
    bool clean = driven && process.supervisor_pid < 0 &&
        process.observation.state == PLATFORM_SUPERVISED_CLEAN &&
        process.observation.no_children && process.observation.engine_exit_observed;
    printf("  supervisor exit with unread control packets keeps its final report: state=%d no_children=%d %s\n",
        (int)process.observation.state, process.observation.no_children, clean ? "OK" : "FAIL");
    return clean ? 0 : 1;
}
#endif

static int campaign_option(const char *option, bool accepted)
{
    char *arguments[] = {
        "build/bin/mutation-campaign",
        "--file=tools/agent/gate_receipt.c", "--list", (char *)option, NULL,
    };
    char *output = NULL;
    size_t length = 0;
    int status = zcl_mut_spawn_owned(&cli_owner, NULL, arguments, 10000, &output, &length);
    bool correct = accepted ? status == 0 :
        status == 2 && output && strstr(output, "mutation-campaign:") != NULL;
    printf("  mutation_campaign_cli: %s status=%d expected=%d... %s\n",
           option, status, accepted ? 0 : 2, correct ? "OK" : "FAIL");
    free(output);
    return correct ? 0 : 1;
}

int test_mutation_campaign_cli(void)
{
    int failures = 0;
#if defined(__linux__)
    char root[4096];
    const char *source = getenv("ZCL_DEV_SOURCE_ROOT");
    if (!source) source = getcwd(root, sizeof(root));
    if (!source) return 1;
    failures += cli_private_refusal(source);
    failures += cli_unread_packet_report(source);
    if (!source || !zcl_supervised_retirement_begin() || !zcl_mut_owner_open(&cli_owner, source))
        return 1;
#endif
    static const char *const invalid[] = {
        "--limit=typo", "--limit=", "--limit=3junk", "--limit=-1",
        "--limit=+1", "--limit= 1", "--limit=1 ", "--limit=0x10",
        "--limit=18446744073709551616",
        "--build-timeout=typo", "--build-timeout=", "--build-timeout=-1",
        "--build-timeout=1.5", "--build-timeout=1s", "--build-timeout=+1",
        "--test-timeout=typo", "--test-timeout=", "--test-timeout=-1",
        "--test-timeout=1.5", "--test-timeout=1s", "--test-timeout= 1",
        "--test-timeout=9223372036854775807",
        "--build-timeout=184467440737095516160",
    };
    static const char *const valid[] = {
        "--limit=0", "--limit=1", "--limit=0002",
        "--build-timeout=0", "--build-timeout=1", "--build-timeout=900",
        "--test-timeout=0", "--test-timeout=1", "--test-timeout=300",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
        failures += campaign_option(invalid[i], false);
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++)
        failures += campaign_option(valid[i], true);
    char option[96];
    (void)snprintf(option, sizeof(option), "--limit=%zu", SIZE_MAX);
    failures += campaign_option(option, true);
    (void)snprintf(option, sizeof(option), "--limit=%zu0", SIZE_MAX);
    failures += campaign_option(option, false);
    const char *timeouts[] = {"--build-timeout=", "--test-timeout="};
    for (size_t i = 0; i < 2; i++) {
        (void)snprintf(option, sizeof(option), "%s%d", timeouts[i], INT_MAX / 1000);
        failures += campaign_option(option, true);
        (void)snprintf(option, sizeof(option), "%s%d", timeouts[i], INT_MAX / 1000 + 1);
        failures += campaign_option(option, false);
    }
#if defined(__linux__)
    if (!zcl_mut_owner_close(&cli_owner)) failures++;
    zcl_supervised_retirement_request_stop();
    bool drained = zcl_supervised_retirement_drain(clock_now_monotonic_ns() + 1000000000);
    if (!drained || thread_registry_join_all(1) != 0) failures++;
#endif
    return failures;
}
