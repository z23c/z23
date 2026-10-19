/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: one-command remote shell over the HOST tunnel: exec a fixed ssh
 * whose ProxyCommand is this binary's raw HOST client. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "command/native_command.h"
#include "services/device_host_runtime_entry.h"
#include "platform/os_proc.h"
#include "platform/clock.h"
#include "platform/pipe_compat.h"
#include "json/json.h"
#include "base/hex.h"
#include "models/device_pairing.h"
#include "services/device_identity.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
extern char **environ;
#include <sys/wait.h>
#include <unistd.h>
#endif

static const char shell_kex_sntrup[] = "sntrup761x25519-sha512@openssh.com";

/* ssh hands ProxyCommand to "$SHELL -c exec ...", and expands %-tokens in
 * it first, so every interpolated byte is drawn from a set with no shell or
 * ssh token meaning: no whitespace, quotes, '$', '`', ';', '%', '\\' or
 * control bytes. A leading '-' would read as an ssh option. */
static bool shell_alnum(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

static bool shell_token_byte(unsigned char c)
{
    return shell_alnum(c) || c == '.' || c == '_' || c == '-';
}

static bool shell_token_valid(const char *text, size_t maximum)
{
    if (!text || !shell_alnum((unsigned char)text[0])) return false;
    size_t length = strnlen(text, maximum + 1);
    if (length > maximum) return false;
    for (size_t i = 0; i < length; ++i)
        if (!shell_token_byte((unsigned char)text[i])) return false;
    return true;
}

/* One path component: non-empty, not "." or "..", token bytes only. */
static bool shell_component_valid(const char *component, size_t size)
{
    if (!size || (size == 1 && component[0] == '.') || (size == 2 && !memcmp(component, "..", 2))) return false;
    for (size_t i = 0; i < size; ++i)
        if (!shell_token_byte((unsigned char)component[i])) return false;
    return true;
}

/* Absolute, '/'-separated components of the token set, so the path names
 * one canonical place and carries nothing a shell would reinterpret. */
static bool shell_path_valid(const char *path)
{
    if (!path || path[0] != '/') return false;
    size_t length = strnlen(path, 1024);
    if (length >= 1024 || length < 2) return false;
    for (const char *component = path + 1; component <= path + length;) {
        const char *end = strchr(component, '/');
        size_t size = end ? (size_t)(end - component) : strlen(component);
        if (!shell_component_valid(component, size)) return false;
        component += size + 1;
    }
    return true;
}

static bool shell_regular_file(const char *path)
{
#if !defined(_WIN32)
    struct stat st;
    return lstat(path, &st) == 0 && S_ISREG(st.st_mode);
#else
    (void)path; return false;
#endif
}

static const char *shell_refusal(const char *self, const char *user, const char *host, const char *route_input)
{
    if (!shell_token_valid(user, 32)) return "user_refused";
    if (!shell_token_valid(host, 253)) return "host_refused";
    if (!shell_path_valid(route_input) || !shell_regular_file(route_input)) return "route_input_refused";
    if (!shell_path_valid(self)) return "self_refused";
    return NULL;
}

static bool shell_fits(int written, size_t size)
{
    return written >= 0 && (size_t)written < size;
}

bool zcl_native_device_host_shell_argv(const char *self, const char *user, const char *host,
    const char *route_input, bool mlkem_offered, struct zcl_native_host_shell_argv *out, const char **refusal)
{
    if (!out || !refusal) { if (refusal) *refusal = "argument_missing"; return false; }
    memset(out, 0, sizeof(*out));
    *refusal = shell_refusal(self, user, host, route_input);
    if (*refusal) return false;
    const char *kex = mlkem_offered ? "mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com" : shell_kex_sntrup;
    bool fits = shell_fits(snprintf(out->kex, sizeof(out->kex), "KexAlgorithms=%s", kex), sizeof(out->kex)) &&
        shell_fits(snprintf(out->proxy, sizeof(out->proxy),
            "ProxyCommand=%s ops mesh device host client --input-file=%s", self, route_input), sizeof(out->proxy)) &&
        shell_fits(snprintf(out->destination, sizeof(out->destination), "%s@%s", user, host), sizeof(out->destination));
    if (!fits) { memset(out, 0, sizeof(*out)); *refusal = "argument_too_long"; return false; }
    const char *const argv[] = {"ssh", "-o", out->kex, "-o", "StrictHostKeyChecking=yes",
        "-o", "ControlPath=none", "-o", out->proxy, "--", out->destination};
    static_assert(sizeof(argv) / sizeof(argv[0]) <= ZCL_HOST_SHELL_ARGV_MAX, "shell argv bound");
    for (size_t i = 0; i < sizeof(argv) / sizeof(argv[0]); ++i) out->argv[i] = argv[i];
    out->argc = sizeof(argv) / sizeof(argv[0]);
    out->argv[out->argc] = NULL;
    return true;
}

static bool shell_json_argv(struct json_value *out, const char *key, const struct zcl_native_host_shell_argv *plan)
{
    struct json_value list = {0};
    json_set_array(&list);
    bool ok = true;
    for (size_t i = 0; ok && i < plan->argc; ++i) {
        struct json_value item = {0};
        json_set_str(&item, plan->argv[i]);
        ok = json_push_back(&list, &item);
        json_free(&item);
    }
    ok = ok && json_push_kv(out, key, &list);
    json_free(&list);
    return ok;
}

bool zcl_native_device_host_shell_json(const struct zcl_native_host_shell_argv *plan,
    const struct zcl_native_host_shell_argv *mlkem_plan, const char *executable, struct json_value *out)
{
    if (!plan || !out || !plan->argc || !executable) return false;
    json_set_object(out);
    return json_push_kv_str(out, "schema", "zcl.device.host.shell.v1") &&
        json_push_kv_bool(out, "dry_run", true) && json_push_kv_str(out, "executable", executable) &&
        json_push_kv_str(out, "kex_probe", "skipped") && shell_json_argv(out, "argv", plan) &&
        (!mlkem_plan || shell_json_argv(out, "argv_mlkem", mlkem_plan));
}

/* A usable PATH entry is an absolute directory: an empty or relative
 * component would resolve against the caller's working directory. */
#if !defined(_WIN32)
static bool shell_path_components_absolute(const char *path_env)
{
    for (const char *component = path_env;;) {
        const char *end = strchr(component, ':');
        size_t size = end ? (size_t)(end - component) : strlen(component);
        if (!size || component[0] != '/') return false;
        if (!end) return true;
        component = end + 1;
    }
}

static bool shell_executable_file(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode) && access(path, X_OK) == 0;
}
#endif

bool zcl_native_device_host_shell_resolve(const char *path_env, char *out, size_t capacity)
{
    if (out && capacity) out[0] = '\0';
#if !defined(_WIN32)
    if (!path_env || !out || capacity < 2 || !shell_path_components_absolute(path_env)) return false;
    for (const char *component = path_env;;) {
        const char *end = strchr(component, ':');
        size_t size = end ? (size_t)(end - component) : strlen(component);
        const char *slash = component[size - 1] == '/' ? "" : "/";
        char candidate[1100];
        if (shell_fits(snprintf(candidate, sizeof(candidate), "%.*s%sssh", (int)size, component, slash),
                sizeof(candidate)) && shell_executable_file(candidate) && strlen(candidate) < capacity) {
            memcpy(out, candidate, strlen(candidate) + 1);
            return true;
        }
        if (!end) return false;
        component = end + 1;
    }
#else
    (void)path_env;
    return false;
#endif
}

#if defined(__linux__) || defined(__APPLE__)
static const char shell_kex_mlkem[] = "mlkem768x25519-sha256";

static void shell_kex_lines(char *text, bool *mlkem, bool *sntrup)
{
    for (char *line = text; *line;) {
        char *end = strchr(line, '\n');
        if (end) *end = '\0';
        if (!strcmp(line, shell_kex_mlkem)) *mlkem = true;
        if (!strcmp(line, shell_kex_sntrup)) *sntrup = true;
        if (!end) break;
        line = end + 1;
    }
}

static bool shell_probe_reaped(pid_t seen, pid_t child)
{
    return seen == child || (seen < 0 && errno == ECHILD);
}

/* Only the probe PID is signalled, after waitpid establishes child custody.
 * Never signal a process group: ssh inherits the invoking CLI's group. */
static bool shell_probe_reap(pid_t child, bool reaped)
{
    if (reaped) return true;
    int status;
    pid_t seen = waitpid(child, &status, WNOHANG);
    if (shell_probe_reaped(seen, child)) return true;
    if (seen < 0 && errno != EINTR) return false;
    if (kill(child, SIGKILL) < 0 && errno != ESRCH) return false;
    int64_t end = clock_now_monotonic_ns() + INT64_C(2000000000);
    for (unsigned attempt = 0; attempt < 400 && clock_now_monotonic_ns() < end; attempt++) {
        seen = waitpid(child, &status, WNOHANG);
        if (shell_probe_reaped(seen, child)) return true;
        if (seen < 0 && errno != EINTR) return false;
        (void)poll(NULL, 0, 5);
    }
    return false;
}

static bool shell_probe_spawn(const char *ssh, int read_fd, int write_fd, pid_t *child)
{
    posix_spawn_file_actions_t actions;
    int rc = posix_spawn_file_actions_init(&actions);
    if (rc != 0) { errno = rc; return false; }
    rc = posix_spawn_file_actions_addclose(&actions, read_fd);
    if (rc == 0) rc = posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0);
    if (rc == 0) rc = posix_spawn_file_actions_adddup2(&actions, write_fd, 1);
    if (rc == 0) rc = posix_spawn_file_actions_addclose(&actions, write_fd);
    if (rc == 0) rc = posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0);
    char *const argv[] = {(char *)"ssh", (char *)"-Q", (char *)"kex", NULL};
    if (rc == 0) rc = posix_spawn(child, ssh, &actions, NULL, argv, environ);
    (void)posix_spawn_file_actions_destroy(&actions);
    if (rc != 0) { errno = rc; return false; }
    return true;
}

struct shell_probe_output { char text[16384]; size_t used; bool eof; };
static bool shell_probe_read(int fd, struct shell_probe_output *out)
{
    ssize_t got = read(fd, out->text + out->used, sizeof(out->text) - 1 - out->used);
    if (got > 0) {
        if (memchr(out->text + out->used, 0, (size_t)got)) return false;
        out->used += (size_t)got;
        return out->used < sizeof(out->text) - 1;
    }
    if (got == 0) { out->eof = true; return true; }
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
}

static bool shell_probe_collect(pid_t child, int fd, struct shell_probe_output *out, bool *reaped)
{
    int status = 0;
    int64_t end = clock_now_monotonic_ns() + INT64_C(2000000000);
    for (unsigned attempt = 0; attempt < 2000 && clock_now_monotonic_ns() < end; attempt++) {
        if (!out->eof && !shell_probe_read(fd, out)) return false;
        if (!*reaped) {
            pid_t seen = waitpid(child, &status, WNOHANG);
            if (seen == child) *reaped = true;
            else if (seen < 0 && errno != EINTR) return false;
        }
        if (*reaped && out->eof) return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        (void)poll(NULL, 0, 1);
    }
    return false;
}
#endif

/* Probe output, process completion and failure cleanup all have finite bounds. */
static bool shell_kex_probe(const char *ssh, bool *mlkem, bool *sntrup)
{
    *mlkem = *sntrup = false;
#if defined(__linux__) || defined(__APPLE__)
    int pipefd[2];
    if (platform_pipe_cloexec_nonblock(pipefd) != 0) return false;
    /* Keep action sources above stdio even when the caller closed stdio. */
    int output = fcntl(pipefd[1], F_DUPFD_CLOEXEC, 3);
    close(pipefd[1]);
    if (output < 0) { close(pipefd[0]); return false; }
    pid_t child = -1;
    bool spawned = shell_probe_spawn(ssh, pipefd[0], output, &child);
    close(output);
    if (!spawned) { close(pipefd[0]); return false; }
    struct shell_probe_output out = {0}; bool reaped = false;
    bool ok = shell_probe_collect(child, pipefd[0], &out, &reaped);
    close(pipefd[0]);
    if (!shell_probe_reap(child, reaped)) {
        fprintf(stderr, "error=HOST_SHELL_PROBE_REAP_FAILED pid=%ld errno=%d\n", (long)child, errno);
        return false;
    }
    if (!ok) return false;
    shell_kex_lines(out.text, mlkem, sntrup);
    return true;
#else
    (void)ssh; return false;
#endif
}

static bool shell_known_keys(const struct json_value *input)
{
    static const char *const keys[] = {"user", "host", "route_input", "dry_run"};
    for (size_t i = 0; i < input->num_children; ++i) {
        bool known = false;
        for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); ++k)
            known = known || (input->keys[i] && !strcmp(input->keys[i], keys[k]));
        if (!known) return false;
        for (size_t j = 0; j < i; ++j) if (!strcmp(input->keys[i], input->keys[j])) return false;
    }
    return true;
}

struct shell_request { const char *user, *host, *route; bool dry_run; };

static bool shell_input(const struct json_value *input, struct shell_request *out)
{
    if (!input || input->type != JSON_OBJ || input->num_children < 3 || input->num_children > 4 ||
        !shell_known_keys(input)) return false;
    out->user = json_get_str(json_get(input, "user"));
    out->host = json_get_str(json_get(input, "host"));
    out->route = json_get_str(json_get(input, "route_input"));
    const struct json_value *dry = json_get(input, "dry_run");
    if (dry && dry->type != JSON_BOOL) return false;
    out->dry_run = dry && json_get_bool(dry);
    return out->user && out->host && out->route;
}

/* The named route must already be a valid client input, so a mistyped file
 * fails here with a named refusal instead of inside ssh's ProxyCommand. */
static bool shell_route_parse(const char *route, struct json_value *parsed)
{
    char text[4097]; size_t length = 0;
    return zcl_native_device_host_input_file_read(route, text, sizeof(text), &length) &&
        device_host_runtime_entry_parse(parsed, text, length, false).ok;
}

static bool shell_route_valid(const char *route)
{
    struct json_value parsed = {0};
    bool ok = shell_route_parse(route, &parsed);
    json_free(&parsed);
    return ok;
}

/* The grant behind a route must name a host-forward authority that is not
 * revoked and whose interval covers `now`. Read-only: shared-lock inspection. */
static const char *shell_grant_state(const struct json_value *route, uint64_t now)
{
    uint8_t peer[32]; struct device_identity identity = {0}; struct device_pairing_store store;
    struct db_device_pairing row; uint8_t root[32]; struct device_identity_publication_report report;
    const char *directory = json_get_str(json_get(route, "directory"));
    const char *peer_hex = json_get_str(json_get(route, "peer_key"));
    if (!directory || !peer_hex || !zcl_hex_decode(peer_hex, peer, 32)) return "route_input_not_a_client_input";
    if (!device_identity_open(&identity, directory, false, &report).ok) return "profile_unreadable";
    const char *state = NULL;
    if (!device_identity_pair_store(&identity, peer, &store).ok) state = "profile_unreadable";
    else if (!db_device_pairing_inspect(&store, peer, &row, root)) state = "grant_missing";
    else if (row.revoked_at) state = "grant_revoked";
    else if (!(row.capabilities & DEVICE_PAIRING_CAP_HOST_FORWARD)) state = "grant_not_host_forward";
    else if (now < row.paired_at) state = "grant_not_yet_valid";
    else if (now >= row.expires_at) state = "grant_expired";
    device_identity_close(&identity);
    return state;
}

const char *zcl_native_device_host_shell_route_check(const char *route, uint64_t now)
{
    if (!shell_path_valid(route) || !shell_regular_file(route)) return "route_input_refused";
    struct json_value parsed = {0};
    if (!shell_route_parse(route, &parsed)) { json_free(&parsed); return "route_input_not_a_client_input"; }
    const char *state = shell_grant_state(&parsed, now);
    json_free(&parsed);
    return state;
}

static int shell_dry_run(const struct zcl_native_host_shell_argv *sntrup, const struct zcl_native_host_shell_argv *both,
    const char *ssh)
{
    struct json_value out = {0};
    char text[16384];
    bool ok = zcl_native_device_host_shell_json(sntrup, both, ssh, &out);
    size_t length = ok ? json_write(&out, text, sizeof(text)) : 0;
    json_free(&out);
    ok = ok && length > 0 && length < sizeof(text) && printf("%s\n", text) > 0 && fflush(stdout) == 0;
    return ok ? ZCL_COMMAND_EXIT_OK : ZCL_COMMAND_EXIT_INTERNAL;
}

static int shell_exec(const struct zcl_native_host_shell_argv *plan, const char *ssh)
{
#if defined(__linux__) || defined(__APPLE__)
    fflush(NULL);
    execv(ssh, (char *const *)plan->argv);
    fprintf(stderr, "error=HOST_SHELL_EXEC_FAILED errno=%d\n", errno);
    return ZCL_COMMAND_EXIT_FAILED;
#else
    (void)plan; (void)ssh;
    fprintf(stderr, "error=HOST_SHELL_UNSUPPORTED platform=unqualified\n");
    return ZCL_COMMAND_EXIT_BLOCKED;
#endif
}

static int shell_refused(const char *refusal)
{
    fprintf(stderr, "error=HOST_SHELL_INPUT_REFUSED detail=%s\n", refusal);
    return ZCL_COMMAND_EXIT_INVALID;
}

int zcl_native_device_host_shell_run(const struct json_value *input)
{
    struct shell_request request = {0};
    if (!shell_input(input, &request)) {
        fprintf(stderr, "error=HOST_SHELL_INPUT_REFUSED detail=user_host_route_input_and_optional_dry_run\n");
        return ZCL_COMMAND_EXIT_INVALID;
    }
    char self[1024], ssh[1100];
    if (!os_proc_exe_path(self, sizeof(self))) {
        fprintf(stderr, "error=HOST_SHELL_SELF_UNRESOLVED\n"); return ZCL_COMMAND_EXIT_BLOCKED;
    }
    /* One resolution feeds both the probe and the exec, so they cannot
     * disagree about which ssh is meant. */
    if (!zcl_native_device_host_shell_resolve(getenv("PATH"), ssh, sizeof(ssh))) {
        fprintf(stderr, "error=HOST_SHELL_SSH_UNRESOLVED detail=absolute_path_entries_only\n");
        return ZCL_COMMAND_EXIT_BLOCKED;
    }
    struct zcl_native_host_shell_argv plan, both; const char *refusal = NULL;
    bool mlkem = false, sntrup = false;
    /* Refuse malformed requests before executing even the fixed KEX probe. */
    if (!zcl_native_device_host_shell_argv(self, request.user, request.host, request.route, false, &plan, &refusal))
        return shell_refused(refusal);
    if (!shell_route_valid(request.route)) return shell_refused("route_input_not_a_client_input");
    /* dry_run executes nothing, so it cannot probe: it reports both shapes. */
    if (!request.dry_run && (!shell_kex_probe(ssh, &mlkem, &sntrup) || !sntrup)) {
        fprintf(stderr, "error=HOST_SHELL_SSH_KEX_UNAVAILABLE required=%s\n", shell_kex_sntrup);
        return ZCL_COMMAND_EXIT_BLOCKED;
    }
    if (!zcl_native_device_host_shell_argv(self, request.user, request.host, request.route, mlkem, &plan, &refusal))
        return shell_refused(refusal);
    if (request.dry_run &&
        !zcl_native_device_host_shell_argv(self, request.user, request.host, request.route, true, &both, &refusal))
        return shell_refused(refusal);
    return request.dry_run ? shell_dry_run(&plan, &both, ssh) : shell_exec(&plan, ssh);
}
