/* purpose: Dispatch foreground raw HOST roles and exact owner-accepted installed tunnel images. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "services/device_host_runtime_entry.h"
#include "services/package_resident.h"
#include "platform/supervised_process.h"
#include "platform/clock.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
struct installed_input {
    const char *datadir, *text;
    uint8_t root[32], receipt[32], digest[32];
    uint32_t launch_ms, execution_ms, cleanup_ms;
    bool receiver;
};

static bool installed_number(const struct json_value *input, const char *key,
    uint32_t maximum, uint32_t *out)
{
    const struct json_value *v = json_get(input, key);
    if (!v || v->type != JSON_INT || v->val.i <= 0 || (uint64_t)v->val.i > maximum) return false;
    *out = (uint32_t)v->val.i; return true;
}

#endif

static bool installed_keys(const struct json_value *input)
{
    static const char *const keys[] = {"datadir", "package_root", "receipt_id", "artifact_sha3",
        "accept_execution", "runtime_policy", "role", "runtime_input", "launch_ms", "execution_ms", "cleanup_ms"};
    if (!input || input->type != JSON_OBJ || input->num_children != sizeof(keys) / sizeof(keys[0])) return false;
    for (size_t i = 0; i < input->num_children; ++i) {
        if (!input->keys[i]) return false;
        bool found = false;
        for (size_t j = 0; j < sizeof(keys) / sizeof(keys[0]); ++j)
            if (!strcmp(input->keys[i], keys[j])) found = true;
        if (!found) return false;
        for (size_t j = 0; j < i; ++j) if (!strcmp(input->keys[i], input->keys[j])) return false;
    }
    return true;
}

#if defined(__linux__)
static bool installed_approval(const struct json_value *input, struct installed_input *out)
{
    const struct json_value *accept = json_get(input, "accept_execution");
    const char *policy = json_get_str(json_get(input, "runtime_policy"));
    const char *role = json_get_str(json_get(input, "role"));
    if (!accept || accept->type != JSON_BOOL || !accept->val.b || !policy || strcmp(policy, "host_os") || !role) return false;
    if (!strcmp(role, "receiver")) out->receiver = true;
    else if (strcmp(role, "client")) return false;
    out->datadir = json_get_str(json_get(input, "datadir"));
    out->text = json_get_str(json_get(input, "runtime_input"));
    return out->datadir && out->datadir[0] == '/' && strlen(out->datadir) < 1024 &&
        out->text && strlen(out->text) <= 4096;
}

static bool installed_input_read(const struct json_value *input, struct installed_input *out)
{
    memset(out, 0, sizeof(*out));
    if (!installed_keys(input) || !installed_approval(input, out)) return false;
    if (!zcl_hex_decode(json_get_str(json_get(input, "package_root")), out->root, 32) ||
        !zcl_hex_decode(json_get_str(json_get(input, "receipt_id")), out->receipt, 32) ||
        !zcl_hex_decode(json_get_str(json_get(input, "artifact_sha3")), out->digest, 32)) return false;
    bool limits = installed_number(input, "launch_ms", 10000, &out->launch_ms) &&
        installed_number(input, "execution_ms", 600000, &out->execution_ms) &&
        installed_number(input, "cleanup_ms", 10000, &out->cleanup_ms);
    struct json_value runtime = {0};
    bool valid = limits && device_host_runtime_entry_parse(&runtime, out->text, strlen(out->text), out->receiver).ok;
    const char *directory = valid ? json_get_str(json_get(&runtime, "directory")) : NULL;
    valid = valid && directory && directory[0] == '/';
    json_free(&runtime); return valid;
}

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

struct installed_signals {
    struct sigaction prior[3];
    sigset_t mask, owned;
    size_t saved;
    bool mask_saved;
};
static const int installed_signal_numbers[] = {SIGHUP, SIGINT, SIGTERM};

static bool installed_signals_open(struct installed_signals *state)
{
    memset(state, 0, sizeof(*state)); sigemptyset(&state->owned);
    for (size_t i = 0; i < 3; ++i) sigaddset(&state->owned, installed_signal_numbers[i]);
    if (sigprocmask(SIG_BLOCK, &state->owned, &state->mask) < 0) return false;
    state->mask_saved = true;
    struct sigaction action = {.sa_handler = SIG_DFL}; sigemptyset(&action.sa_mask);
    for (size_t i = 0; i < 3; ++i) {
        if (sigaction(installed_signal_numbers[i], &action, &state->prior[i]) < 0) return false;
        state->saved++;
    }
    return true;
}

static bool installed_signals_close(const struct installed_signals *state)
{
    bool ok = true;
    for (size_t i = 0; i < state->saved; ++i)
        if (sigaction(installed_signal_numbers[i], &state->prior[i], NULL) < 0) ok = false;
    if (state->mask_saved && sigprocmask(SIG_SETMASK, &state->mask, NULL) < 0) ok = false;
    return ok;
}

static int64_t installed_deadline(int64_t now, uint32_t milliseconds)
{
    int64_t duration = (int64_t)milliseconds * INT64_C(1000000);
    return now > 0 && now <= INT64_MAX - duration ? now + duration : 0;
}

static bool installed_stdio_open(int flags[2])
{
    flags[0] = fcntl(0, F_GETFL); flags[1] = fcntl(1, F_GETFL);
    return flags[0] >= 0 && flags[1] >= 0 && fcntl(2, F_GETFD) >= 0;
}

static bool installed_stdio_close(const int flags[2])
{
    bool ok = true;
    for (size_t i = 0; i < 2; ++i) if (flags[i] >= 0 && fcntl((int)i, F_SETFL, flags[i]) < 0) ok = false;
    return ok;
}

static bool installed_clean(const struct platform_supervised_process *process)
{
    const struct platform_supervised_observation *o = &process->observation;
    return o->state == PLATFORM_SUPERVISED_CLEAN && o->no_children &&
        o->engine_exit_observed && WIFEXITED(o->engine_wait_status) && WEXITSTATUS(o->engine_wait_status) == 0;
}

static bool installed_success(const struct platform_supervised_process *process,
    bool complete, bool restored, const char *owner_result)
{
    return complete && restored && !strcmp(owner_result, "observed_exit") && installed_clean(process);
}

static bool installed_stop_requested(int number, int64_t now, int64_t deadline, int64_t grace)
{
    return number == SIGINT || number == SIGTERM || now <= 0 || now >= deadline || (grace && now >= grace);
}

static const char *installed_observation_result(const struct platform_supervised_process *process,
    enum platform_supervised_state state)
{
    if (state == PLATFORM_SUPERVISED_CLEAN && process->observation.engine_exit_observed) return "observed_exit";
    if (state == PLATFORM_SUPERVISED_INCOMPLETE) return "cleanup_incomplete";
    if (state == PLATFORM_SUPERVISED_OBSERVATION_FAILED) return "observation_failed";
    return "launch_failed";
}

#ifdef ZCL_TESTING
static bool (*installed_hangup_for_test)(struct platform_supervised_process *process);
#endif
static bool installed_hangup(struct platform_supervised_process *process)
{
#ifdef ZCL_TESTING
    if (installed_hangup_for_test) return installed_hangup_for_test(process);
#endif
    return platform_supervised_signal(process, PLATFORM_SUPERVISED_HANGUP);
}

static enum platform_supervised_state installed_wait(struct platform_supervised_process *process,
    const struct installed_signals *signals, int64_t deadline, uint32_t cleanup_ms, const char **owner_result)
{
    enum platform_supervised_state state;
    int64_t grace = 0;
    bool hangup_refused = false;
    for (;;) {
        struct timespec zero = {0}; int number = sigtimedwait(&signals->owned, NULL, &zero);
        state = platform_supervised_poll(process);
        int64_t now = clock_now_monotonic_ns();
        if (installed_stop_requested(number, now, deadline, grace)) {
            *owner_result = number == SIGINT || number == SIGTERM ? "cancelled" :
                hangup_refused ? "signal_queue_failed" : "deadline";
            return platform_supervised_stop(process, installed_deadline(now, cleanup_ms));
        }
        if (state != PLATFORM_SUPERVISED_RUNNING) {
            *owner_result = installed_observation_result(process, state); return state;
        }
        if (number == SIGHUP) {
            if (!grace) { grace = installed_deadline(now, 1500); if (grace > deadline) grace = deadline; }
            /* ssh HUPs its ProxyCommand as the session ends, often while the
             * engine is already exiting; then the forward fails only because
             * there is no engine left to take it. Observe again before naming
             * a failure, and keep observing through the HUP grace: only an
             * engine still running at grace end was really unsignalable. */
            if (!installed_hangup(process)) {
                state = platform_supervised_poll(process);
                if (state != PLATFORM_SUPERVISED_RUNNING) {
                    *owner_result = installed_observation_result(process, state); return state;
                }
                hangup_refused = true;
            }
        }
        int64_t limit = grace ? grace : deadline;
        int64_t remaining = limit - now;
        int wait = remaining > INT64_C(20000000) ? 20 : (int)((remaining + 999999) / 1000000);
        struct pollfd ready = {.fd = process->control_fd, .events = POLLIN};
        (void)poll(&ready, 1, wait);
    }
}

static enum platform_supervised_state installed_launch(const struct installed_input *input,
    int image, int cwd, char *argument, struct platform_supervised_process *process,
    const struct installed_signals *signals, const char **owner_result)
{
    memcpy(argument, "--input=", 8); memcpy(argument + 8, input->text, strlen(input->text) + 1);
    const char *const argv[] = {"tunnel", input->receiver ? "receiver" : "client", argument, NULL};
    const char *const env[] = {NULL};
    struct platform_supervised_fd_map maps[] = {{0, 0}, {1, 1}, {2, 2}};
    int64_t now = clock_now_monotonic_ns(), execution = installed_deadline(now, input->execution_ms);
    int64_t launch = installed_deadline(now, input->launch_ms);
    if (launch > execution) launch = execution;
    struct platform_supervised_spec spec = {.executable_fd = image, .argv = argv, .env = env,
        .maps = maps, .map_count = 3, .launch_deadline_ns = launch,
        .cleanup_timeout_ms = input->cleanup_ms, .use_cwd_fd = true, .cwd_fd = cwd};
    *owner_result = "launch_failed";
    enum platform_supervised_state state = platform_supervised_start(process, &spec);
    return state == PLATFORM_SUPERVISED_RUNNING || state == PLATFORM_SUPERVISED_CLEAN
        ? installed_wait(process, signals, execution, input->cleanup_ms, owner_result) : state;
}

static int installed_execute(const struct installed_input *input, int image)
{
    struct installed_signals signals; int flags[2] = {-1, -1};
    struct platform_supervised_process process; platform_supervised_init(&process);
    bool stdio_ok = installed_stdio_open(flags), signals_ok = false;
    int cwd = -1; char *argument = NULL;
    if (stdio_ok) signals_ok = installed_signals_open(&signals);
    else memset(&signals, 0, sizeof(signals));
    if (signals_ok) cwd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cwd >= 0) argument = zcl_malloc(strlen(input->text) + 9, "host.installed.argv");
    enum platform_supervised_state state = PLATFORM_SUPERVISED_INVALID;
    const char *owner_result = "setup_refused";
    if (argument) state = installed_launch(input, image, cwd, argument, &process, &signals, &owner_result);
    bool complete = process.supervisor_pid < 0;
    if (!complete) {
        state = platform_supervised_stop(&process, installed_deadline(clock_now_monotonic_ns(), input->cleanup_ms));
        complete = process.supervisor_pid < 0;
    }
    bool handed_off = !complete && state == PLATFORM_SUPERVISED_INCOMPLETE;
    if (handed_off) platform_supervised_owner_eof(&process);
    bool restored = installed_signals_close(&signals);
    restored = installed_stdio_close(flags) && restored;
    fprintf(stderr, "event=HOST_PACKAGE_TERMINAL result=%s state=%u cleanup_complete=%u engine_exit_observed=%u owner_eof_handoff=%u custody_unknown=%u supervisor_observed=%lld top_image_pinned=1 runtime_closure_pinned=0\n",
        owner_result, (unsigned)state, (unsigned)complete, (unsigned)process.observation.engine_exit_observed,
        (unsigned)handed_off, (unsigned)(!complete && !handed_off), (long long)process.supervisor_pid);
    free(argument); if (cwd >= 0) close(cwd);
    return installed_success(&process, complete, restored, owner_result)
        ? ZCL_COMMAND_EXIT_OK : ZCL_COMMAND_EXIT_INTERNAL;
}

static int installed_run(const struct json_value *input)
{
    struct installed_input selected;
    if (!installed_input_read(input, &selected)) {
        fprintf(stderr, "error=HOST_PACKAGE_INPUT_REFUSED\n"); return ZCL_COMMAND_EXIT_INVALID;
    }
    if (fcntl(0, F_GETFD) < 0 || fcntl(1, F_GETFD) < 0 || fcntl(2, F_GETFD) < 0)
        return ZCL_COMMAND_EXIT_INVALID;
    int image = -1;
    struct zcl_result result = package_resident_host_image_capture(selected.datadir, selected.root,
        selected.receipt, selected.digest, &image);
    if (!result.ok) { fprintf(stderr, "error=HOST_PACKAGE_IMAGE_REFUSED\n"); return ZCL_COMMAND_EXIT_BLOCKED; }
    int status = installed_execute(&selected, image); close(image); return status;
}
#ifdef ZCL_TESTING
bool zcl_native_device_host_package_input_for_test(const struct json_value *input)
{
    struct installed_input selected; return installed_input_read(input, &selected);
}
/* The engine exits while its HUP is in flight: the forward fails and the
 * very next observation is the engine's own exit. */
static bool installed_hangup_exited_for_test(struct platform_supervised_process *process)
{
    process->observation = (struct platform_supervised_observation){.state = PLATFORM_SUPERVISED_CLEAN,
        .no_children = true, .engine_exit_observed = true, .engine_wait_status = 0};
    return false;
}
static bool installed_hangup_refused_for_test(struct platform_supervised_process *process)
{
    (void)process; return false;
}
const char *zcl_native_device_host_package_hangup_for_test(bool engine_exits)
{
    struct platform_supervised_process process; platform_supervised_init(&process);
    process.observation = (struct platform_supervised_observation){.state = PLATFORM_SUPERVISED_RUNNING};
    struct installed_signals signals = {0}; sigemptyset(&signals.owned); sigaddset(&signals.owned, SIGHUP);
    sigset_t prior;
    if (pthread_sigmask(SIG_BLOCK, &signals.owned, &prior) != 0) return "mask_failed";
    const char *result = "setup_refused";
    installed_hangup_for_test = engine_exits ? installed_hangup_exited_for_test : installed_hangup_refused_for_test;
    if (raise(SIGHUP) == 0)
        (void)installed_wait(&process, &signals, installed_deadline(clock_now_monotonic_ns(), 5000), 1000, &result);
    installed_hangup_for_test = NULL;
    struct timespec zero = {0};
    while (sigtimedwait(&signals.owned, NULL, &zero) == SIGHUP) {}
    (void)pthread_sigmask(SIG_SETMASK, &prior, NULL);
    return result;
}
bool zcl_native_device_host_package_terminal_for_test(int64_t deadline_ns)
{
    struct platform_supervised_process process; platform_supervised_init(&process);
    process.observation = (struct platform_supervised_observation){.state = PLATFORM_SUPERVISED_CLEAN,
        .no_children = true, .engine_exit_observed = true, .engine_wait_status = 0};
    struct installed_signals signals = {0}; sigemptyset(&signals.owned);
    const char *result = "setup_refused";
    (void)installed_wait(&process, &signals, deadline_ns, 1000, &result);
    return installed_success(&process, true, true, result);
}
#endif
#endif
#if defined(__linux__) || defined(__APPLE__)
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
/* A named input binds a route, so it must be an owner-written regular file
 * that does not change while it is read. */
static bool input_file_admissible(const struct stat *st, size_t capacity)
{
    return S_ISREG(st->st_mode) && st->st_uid == geteuid() && !(st->st_mode & (S_IWGRP | S_IWOTH)) &&
        st->st_size > 0 && (uint64_t)st->st_size < capacity;
}
static bool input_file_read_exact(int fd, char *text, size_t size)
{
    size_t total = 0;
    while (total < size) {
        ssize_t got = read(fd, text + total, size - total);
        if (got <= 0) return false;
        total += (size_t)got;
    }
    char extra;
    return read(fd, &extra, 1) == 0;
}
/* Identity and content stamp: any difference means the file changed. */
static bool input_file_same(const struct stat *a, const struct stat *b)
{
    return a->st_ino == b->st_ino && a->st_dev == b->st_dev && a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec &&
        a->st_mode == b->st_mode && a->st_uid == b->st_uid;
}
static void (*input_file_read_hook_for_test)(const char *path);
#if defined(ZCL_TESTING)
void zcl_native_device_host_input_file_hook_for_test(void (*hook)(const char *path))
{
    input_file_read_hook_for_test = hook;
}
#endif
static bool input_file_load(const char *path, char *text, size_t capacity, size_t *total)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat before, after;
    bool ok = fstat(fd, &before) == 0 && input_file_admissible(&before, capacity) &&
        input_file_read_exact(fd, text, (size_t)before.st_size);
    if (ok && input_file_read_hook_for_test) input_file_read_hook_for_test(path);
    ok = ok && fstat(fd, &after) == 0 && input_file_same(&before, &after);
    close(fd);
    *total = ok ? (size_t)before.st_size : 0;
    return ok;
}
#endif
static bool input_file_arguments(const char *path, const char *text, size_t capacity, const size_t *length)
{
    return path && path[0] == '/' && strnlen(path, 1024) < 1024 && text && capacity >= 2 && length;
}
/* The bound on each read is the caller's capacity minus the terminator. */
bool zcl_native_device_host_input_file_read(const char *path, char *text, size_t capacity, size_t *length)
{
    if (length) *length = 0;
    if (text && capacity) text[0] = '\0';
    if (!input_file_arguments(path, text, capacity, length)) return false;
#if defined(__linux__) || defined(__APPLE__)
    size_t total = 0;
    if (!input_file_load(path, text, capacity, &total)) { text[0] = '\0'; return false; }
    /* One trailing newline is an editor artifact, not part of the object. */
    if (text[total - 1] == '\n') --total;
    text[total] = '\0';
    if (!total || strnlen(text, total + 1) != total) { text[0] = '\0'; return false; }
    *length = total;
    return true;
#else
    return false;
#endif
}
static bool raw_is_host_path(int argc, char **argv)
{
    return argc >= 6 && !strcmp(argv[1], "ops") && !strcmp(argv[2], "mesh") &&
        !strcmp(argv[3], "device") && !strcmp(argv[4], "host");
}

enum host_command { HOST_NONE, HOST_CLIENT, HOST_RECEIVER, HOST_PACKAGE, HOST_SHELL, HOST_COMMAND_COUNT };

static const char *const host_command_path[HOST_COMMAND_COUNT] = {
    [HOST_CLIENT] = "ops.mesh.device.host.client", [HOST_RECEIVER] = "ops.mesh.device.host.receiver",
    [HOST_PACKAGE] = "ops.mesh.device.host.package.run", [HOST_SHELL] = "ops.mesh.device.host.shell",
};

static enum host_command raw_selected_full(const char *name)
{
    for (enum host_command kind = HOST_CLIENT; kind < HOST_COMMAND_COUNT; kind++)
        if (!strcmp(name, host_command_path[kind])) return kind;
    return HOST_NONE;
}

static enum host_command raw_selected_words(int argc, char **argv, size_t *consumed)
{
    if (!raw_is_host_path(argc, argv)) return HOST_NONE;
    *consumed = 5;
    if (!strcmp(argv[5], "client")) return HOST_CLIENT;
    if (!strcmp(argv[5], "receiver")) return HOST_RECEIVER;
    if (!strcmp(argv[5], "shell")) return HOST_SHELL;
    if (argc >= 7 && !strcmp(argv[5], "package") && !strcmp(argv[6], "run")) {
        *consumed = 6; return HOST_PACKAGE;
    }
    return HOST_NONE;
}

static enum host_command raw_selected_command(int argc, char **argv, size_t *consumed)
{
    enum host_command kind = argc >= 2 ? raw_selected_full(argv[1]) : HOST_NONE;
    if (kind != HOST_NONE) { *consumed = 1; return kind; }
    return raw_selected_words(argc, argv, consumed);
}

static bool raw_input_read(int argc, char **argv, size_t consumed,
    const struct zcl_command_spec *spec, bool package, struct json_value *input)
{
    size_t maximum = package ? 8192 : 4096;
    if (!spec || (size_t)argc != consumed + 2) return false;
    const char *argument = argv[consumed + 1], *text = NULL; size_t length = 0;
    char named[8193];
    if (!strncmp(argument, "--input=", 8)) {
        text = argument + 8; length = strnlen(text, maximum + 1);
    } else if (!strncmp(argument, "--input-file=", 13)) {
        if (!zcl_native_device_host_input_file_read(argument + 13, named, maximum + 1, &length)) return false;
        text = named;
    } else return false;
    if (length > maximum) return false;
    bool shell = !strcmp(spec->path, "ops.mesh.device.host.shell");
    bool valid = package || shell ? !strstr(text, "\\u0000") && json_read(input, text, length) && (shell || installed_keys(input))
        : device_host_runtime_entry_parse(input, text, length, !strcmp(spec->path, "ops.mesh.device.host.receiver")).ok;
    char why[160];
    return valid && zcl_command_registry_input_validate(spec, input, why, sizeof(why));
}
/* `--help` is answered by the generic catalog path, not the raw transport. */
static bool raw_help_requested(int argc, char **argv, size_t consumed)
{
    for (int i = (int)consumed + 1; i < argc; i++)
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) return true;
    return false;
}
void zcl_native_device_host_runtime_exit_if_requested(int argc, char **argv)
{
    size_t consumed = 0; enum host_command command = raw_selected_command(argc, argv, &consumed);
    if (command == HOST_NONE) return;
    if (raw_help_requested(argc, argv, consumed)) return;
    const char *path = host_command_path[command];
    int result = ZCL_COMMAND_EXIT_INVALID;
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    struct json_value input = {0};
    bool package = command == HOST_PACKAGE;
    bool valid = raw_input_read(argc, argv, consumed, spec, package, &input);
#if defined(__linux__)
    if (valid) {
        if (package) result = installed_run(&input);
        else if (command == HOST_SHELL) result = zcl_native_device_host_shell_run(&input);
        else {
            enum device_host_runtime_entry_exit status = DEVICE_HOST_ENTRY_INVALID;
            struct zcl_result ran = device_host_runtime_entry_run(&input,
                command == HOST_RECEIVER, &status);
            result = (int)status;
            if (!ran.ok && result == DEVICE_HOST_ENTRY_OK) result = DEVICE_HOST_ENTRY_FAILED;
        }
    }
    else fprintf(stderr, "error=HOST_RUNTIME_INPUT_REFUSED detail=one_bounded_registered_input_object_required\n");
#elif defined(__APPLE__)
    if (!strcmp(path, "ops.mesh.device.host.shell")) {
        if (valid) result = zcl_native_device_host_shell_run(&input);
        else fprintf(stderr, "error=HOST_RUNTIME_INPUT_REFUSED detail=one_bounded_registered_input_object_required\n");
    } else if (!strcmp(path, "ops.mesh.device.host.client") || !strcmp(path, "ops.mesh.device.host.receiver")) {
        if (valid) {
            enum device_host_runtime_entry_exit status = DEVICE_HOST_ENTRY_INVALID;
            struct zcl_result ran = device_host_runtime_entry_run(&input,
                !strcmp(path, "ops.mesh.device.host.receiver"), &status);
            result = (int)status;
            if (!ran.ok && result == DEVICE_HOST_ENTRY_OK) result = DEVICE_HOST_ENTRY_FAILED;
        } else fprintf(stderr, "error=HOST_RUNTIME_INPUT_REFUSED detail=one_bounded_registered_input_object_required\n");
    } else {
        fprintf(stderr, "error=HOST_RUNTIME_UNSUPPORTED platform=unqualified\n");
        result = ZCL_COMMAND_EXIT_BLOCKED;
    }
#else
    (void)valid;
    fprintf(stderr, "error=HOST_RUNTIME_UNSUPPORTED platform=unqualified\n"); result = ZCL_COMMAND_EXIT_BLOCKED;
#endif
    json_free(&input); exit(result);
}
void zcl_native_handle_ops_mesh_device_host_runtime(const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "HOST_RUNTIME_RAW_CLI_ONLY", "dispatch", false, false,
        "foreground HOST transport requires direct registered raw CLI; no JSON/RPC stream fallback", "ops.mesh.device.host");
}
