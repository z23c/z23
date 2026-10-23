/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Actual public-binary foreground runtime; isolated PUBLIC pair fixtures. */
#if defined(__linux__) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"
#include "services/device_identity.h"
#include "services/device_host_runtime.h"
#include "services/device_host_runtime_entry.h"
#include "session/mesh_terminal_hub.h"
static_assert(_Generic(device_host_runtime_client_run(NULL, NULL), struct zcl_result: 1, default: 0),
    "runtime reports explicit observation and canonical result");
static_assert(_Generic(device_host_runtime_receiver_run(NULL, NULL), struct zcl_result: 1, default: 0),
    "runtime reports explicit observation and canonical result");
static_assert(_Generic(device_host_runtime_entry_run(NULL, false, NULL), struct zcl_result: 1, default: 0),
    "raw entry reports explicit exit and canonical result");
static_assert(_Generic(device_host_runtime_entry_parse(NULL, NULL, 0, false), struct zcl_result: 1, default: 0),
    "fallible device API returns canonical zcl_result");
#include "platform/socket_compat.h"
#include "platform/clock.h"
#include "platform/os_sandbox.h"
#include "base/hex.h"
#include "json/json.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include <math.h>
#if defined(__linux__)
#include <signal.h>
#include <inttypes.h>
#include <stdlib.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <dirent.h>

struct runtime_process {
    pid_t pid;
    int input, output, diagnostics, status;
    bool reaped, custody_lost;
    struct rusage usage;
    char diagnostic_text[8192]; size_t diagnostic_used;
};
struct runtime_fixture {
    char home[1024], directory[2][1200];
    struct device_pairing_store store[2]; struct db_device_pairing row[2]; uint8_t root[2][32];
    int target_listener, target; uint16_t target_port, receiver_port;
    struct runtime_process receiver, client;
    bool different_secret;
    bool standalone;
};
/* Each fixture owns at most two children. Reserve two retained slots before
 * every fork; unresolved custody survives the fixture and blocks new launches
 * when insufficient evidence storage remains. */
static struct runtime_process retained_runtime_processes[4];
static size_t retained_runtime_count;
static void runtime_retain_process(const struct runtime_process *process)
{
    if (process->pid <= 0) return;
    if (retained_runtime_count < sizeof(retained_runtime_processes) / sizeof(retained_runtime_processes[0]))
        retained_runtime_processes[retained_runtime_count++] = *process;
    fprintf(stderr, "runtime fixture: retained owned pid=%ld cleanup_incomplete\n", (long)process->pid);
}
static void runtime_process_init(struct runtime_process *process)
{
    memset(process, 0, sizeof(*process)); process->pid = -1;
    process->input = process->output = process->diagnostics = -1;
}
static void runtime_fixture_init(struct runtime_fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture)); fixture->target_listener = fixture->target = -1;
    runtime_process_init(&fixture->receiver); runtime_process_init(&fixture->client);
}
static void runtime_test_close(int *fd) { if (*fd >= 0) { close(*fd); *fd = -1; } }
static bool runtime_test_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}
static bool runtime_test_pipe(int descriptors[2])
{
    if (pipe(descriptors) != 0) return false;
    if (descriptors[0] < 3 || descriptors[1] < 3) return false;
    return fcntl(descriptors[0], F_SETFD, FD_CLOEXEC) == 0 && fcntl(descriptors[1], F_SETFD, FD_CLOEXEC) == 0;
}
static bool runtime_process_poll(struct runtime_process *process)
{
    if (process->reaped) return true;
    if (process->pid < 0 || process->custody_lost) return false;
    pid_t observed = wait4(process->pid, &process->status, WNOHANG, &process->usage);
    if (observed == process->pid) { process->reaped = true; process->pid = -1; return true; }
    if (observed < 0 && errno == ECHILD) { process->custody_lost = true; process->pid = -1; }
    return false;
}
static bool runtime_process_wait(struct runtime_process *process, int64_t deadline)
{
    while (clock_now_monotonic_ns() < deadline) {
        if (runtime_process_poll(process)) return true;
        if (process->custody_lost) return false;
        (void)poll(NULL, 0, 5);
    }
    return runtime_process_poll(process);
}
static bool runtime_process_cleanup(struct runtime_process *process)
{
    runtime_test_close(&process->input);
    bool clean = process->pid < 0 && !process->custody_lost;
    if (process->pid > 0) {
        clean = runtime_process_poll(process);
        if (!clean && process->pid > 0) {
            (void)kill(process->pid, SIGTERM);
            clean = runtime_process_wait(process, clock_now_monotonic_ns() + INT64_C(1000000000));
        }
        if (!clean && process->pid > 0) {
            (void)kill(process->pid, SIGKILL);
            clean = runtime_process_wait(process, clock_now_monotonic_ns() + INT64_C(2000000000));
        }
    }
    runtime_test_close(&process->output); runtime_test_close(&process->diagnostics);
    if (!clean) fprintf(stderr, "runtime fixture: incomplete process cleanup/custody\n");
    return clean;
}
static bool runtime_fixture_close(struct runtime_fixture *fixture)
{
    bool client = runtime_process_cleanup(&fixture->client), receiver = runtime_process_cleanup(&fixture->receiver);
    runtime_test_close(&fixture->target); runtime_test_close(&fixture->target_listener);
    if (client && receiver) { if (fixture->home[0]) test_rm_rf(fixture->home); }
    else { runtime_retain_process(&fixture->client); runtime_retain_process(&fixture->receiver); }
    return client && receiver;
}
static bool runtime_process_pipes(int pipes[3][2])
{
    bool prepared = platform_socket_pair(pipes[0]);
    for (size_t i = 0; i < 2; ++i)
        if (pipes[0][i] < 3 || fcntl(pipes[0][i], F_SETFD, FD_CLOEXEC) != 0) prepared = false;
    for (size_t i = 1; i < 3; ++i) if (!runtime_test_pipe(pipes[i])) prepared = false;
    return prepared;
}
static void runtime_process_exec(int pipes[3][2], char *const argv[], char *const env[])
{
    if (dup2(pipes[0][0], 0) < 0 || dup2(pipes[1][1], 1) < 0 || dup2(pipes[2][1], 2) < 0) _exit(126);
    for (size_t i = 0; i < 3; ++i) { close(pipes[i][0]); close(pipes[i][1]); }
    execve(argv[0], argv, env); _exit(127);
}
static bool runtime_process_parent(struct runtime_process *process, int pipes[3][2], pid_t pid)
{
    runtime_process_init(process);
    if (pid > 0) {
        process->pid = pid; process->input = pipes[0][1]; process->output = pipes[1][0]; process->diagnostics = pipes[2][0];
        pipes[0][1] = pipes[1][0] = pipes[2][0] = -1;
    }
    for (size_t i = 0; i < 3; ++i) { runtime_test_close(&pipes[i][0]); runtime_test_close(&pipes[i][1]); }
    return pid > 0 && runtime_test_nonblock(process->input) && runtime_test_nonblock(process->output) && runtime_test_nonblock(process->diagnostics);
}
static bool runtime_process_fresh(const struct runtime_process *process)
{
    return process->pid <= 0 && !process->custody_lost && process->input < 0 &&
        process->output < 0 && process->diagnostics < 0;
}
static bool runtime_process_start(struct runtime_process *process, const struct runtime_fixture *fixture,
    const struct json_value *input, bool receiver, bool extra)
{
    if (retained_runtime_count + 2 > sizeof(retained_runtime_processes) / sizeof(retained_runtime_processes[0]))
        return false;
    if (!runtime_process_fresh(process))
        return false;
    char wire[4097], argument[4120], home[1200];
    if (json_write(input, wire, sizeof(wire)) <= 0) return false;
    if (snprintf(argument, sizeof(argument), "--input=%s", wire) >= (int)sizeof(argument)) return false;
    if (snprintf(home, sizeof(home), "HOME=%s", fixture->home) >= (int)sizeof(home)) return false;
    char *node_argv[] = {"build/bin/z23", "ops", "mesh", "device", "host", receiver ? "receiver" : "client",
        argument, extra ? "--format=json" : NULL, NULL};
    char *standalone_argv[] = {"build/bin/tunnel", receiver ? "receiver" : "client", argument,
        extra ? "--format=json" : NULL, NULL};
    char **argv = fixture->standalone ? standalone_argv : node_argv;
    char *env[] = {home, "PATH=/usr/bin:/bin", "ZCL_OPERATOR_LANE=INVALID-PUBLIC-RAW-SENTINEL", NULL};
    int pipes[3][2] = {{-1,-1},{-1,-1},{-1,-1}};
    bool prepared = runtime_process_pipes(pipes);
    pid_t pid = prepared ? fork() : -1;
    if (pid == 0) runtime_process_exec(pipes, argv, env);
    return runtime_process_parent(process, pipes, pid);
}
static bool runtime_diagnostics(struct runtime_process *process)
{
    if (process->diagnostic_used >= sizeof(process->diagnostic_text) - 1) return false;
    ssize_t seen = read(process->diagnostics, process->diagnostic_text + process->diagnostic_used,
        sizeof(process->diagnostic_text) - 1 - process->diagnostic_used);
    if (seen > 0) {
        process->diagnostic_used += (size_t)seen; process->diagnostic_text[process->diagnostic_used] = 0;
    }
    return seen >= 0 || errno == EAGAIN || errno == EINTR;
}
static bool runtime_wait_receiver(struct runtime_fixture *fixture)
{
    int64_t deadline = clock_now_monotonic_ns() + INT64_C(5000000000);
    while (clock_now_monotonic_ns() < deadline) {
        if (!runtime_diagnostics(&fixture->receiver)) return false;
        const char *port = strstr(fixture->receiver.diagnostic_text, "listen_port=");
        if (port) {
            char *end; unsigned long number = strtoul(port + strlen("listen_port="), &end, 10);
            if (end != port + strlen("listen_port=") && number > 0 && number <= UINT16_MAX) {
                fixture->receiver_port = (uint16_t)number; return true;
            }
        }
        if (runtime_process_poll(&fixture->receiver)) return false;
        (void)poll(NULL, 0, 5);
    }
    return false;
}
static bool runtime_grants(struct runtime_fixture *fixture)
{
    struct device_identity identity[2] = {0}; struct device_identity_publication_report publication;
    bool ok = true;
    for (size_t i = 0; i < 2; ++i) {
        int n = snprintf(fixture->directory[i], sizeof(fixture->directory[i]), "%s/profile-%zu", fixture->home, i);
        if (n <= 0 || (size_t)n >= sizeof(fixture->directory[i]) ||
            !device_identity_open(&identity[i], fixture->directory[i], true, &publication).ok) ok = false;
    }
    uint64_t now = (uint64_t)(clock_now_wall_ms() / 1000);
    for (size_t i = 0; i < 2 && ok; ++i) {
        size_t peer = 1 - i;
        ok = device_identity_pair_store(&identity[i], identity[peer].public_key, &fixture->store[i]).ok;
        if (!ok) break;
        struct db_device_pairing *row = &fixture->row[i];
        *row = (struct db_device_pairing){.capabilities = DEVICE_PAIRING_CAP_HOST_FORWARD, .paired_at = now - 1, .expires_at = now + 600};
        memcpy(row->local_key, identity[i].public_key, 32); memcpy(row->peer_key, identity[peer].public_key, 32);
        memcpy(row->profile, fixture->store[i].profile, 32);
        row->host_scope.inbound_port = row->host_scope.outbound_port = fixture->target_port;
        row->host_scope.binding.backend_profile = DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK;
        struct device_pairing_psk_binding *binding = &row->host_scope.binding.psk;
        binding->credential_id[0] = 91; binding->key_epoch = 1;
        bool first = memcmp(row->local_key, row->peer_key, 32) < 0;
        memcpy(binding->endpoint_a, first ? row->local_key : row->peer_key, 32);
        memcpy(binding->endpoint_b, first ? row->peer_key : row->local_key, 32);
        uint8_t secret[32] = {17}, proposal[32]; struct device_pairing_psk_publication report;
        if (fixture->different_secret && i == 1) secret[0] = 18;
        struct db_device_pairing found;
        ok = device_pairing_host_proposal_root(row, proposal) &&
            db_device_pairing_insert_host_psk(&fixture->store[i], row, secret, proposal, &report) &&
            db_device_pairing_inspect(&fixture->store[i], row->peer_key, &found, fixture->root[i]);
    }
    device_identity_close(&identity[0]); device_identity_close(&identity[1]); return ok;
}
static bool runtime_fixture_open(struct runtime_fixture *fixture)
{
    if (!test_mkdtemp(fixture->home, sizeof(fixture->home), "host-runtime")) return false;
    fixture->target_listener = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t size = sizeof(address);
    if (fixture->target_listener < 0 || bind(fixture->target_listener, (struct sockaddr *)&address, size) != 0 ||
        listen(fixture->target_listener, 4) != 0 || getsockname(fixture->target_listener, (struct sockaddr *)&address, &size) != 0) return false;
    fixture->target_port = ntohs(address.sin_port); return runtime_grants(fixture);
}
/* Set to run a fixture at the hard maxima of the supervised-hub caps. */
static bool runtime_long_caps;
static bool runtime_input_common(struct json_value *input, const struct runtime_fixture *fixture, size_t node)
{
    json_set_object(input); char peer[65], root[65];
    zcl_hex_encode(fixture->row[node].peer_key, 32, peer); zcl_hex_encode(fixture->root[node], 32, root);
    return json_push_kv_str(input, "directory", fixture->directory[node]) &&
        json_push_kv_str(input, "peer_key", peer) && json_push_kv_str(input, "expected_root", root) &&
        json_push_kv_int(input, "target_port", fixture->target_port) && json_push_kv_str(input, "route_id", "PUBLIC-local-loopback") &&
        json_push_kv_int(input, "handshake_ms", 5000) &&
        json_push_kv_int(input, "session_ms", runtime_long_caps ? 28800000 : 15000) &&
        json_push_kv_int(input, "idle_ms", runtime_long_caps ? 1800000 : 5000) && json_push_kv_bool(input, "confirm", true);
}
static bool runtime_input_receiver(struct json_value *input, const struct runtime_fixture *fixture, unsigned sessions)
{
    return runtime_input_common(input, fixture, 1) && json_push_kv_str(input, "listen_address", "127.0.0.1") &&
        json_push_kv_int(input, "listen_port", 0) && json_push_kv_bool(input, "allow_external", false) &&
        json_push_kv_int(input, "lifetime_ms", runtime_long_caps ? 86400000 : 30000) && json_push_kv_int(input, "max_sessions", sessions) &&
        json_push_kv_int(input, "max_active", 2);
}
static bool runtime_input_client(struct json_value *input, const struct runtime_fixture *fixture)
{
    return runtime_input_common(input, fixture, 0) && json_push_kv_str(input, "route_address", "127.0.0.1") &&
        json_push_kv_int(input, "route_port", fixture->receiver_port) && json_push_kv_int(input, "connect_ms", 3000);
}
struct runtime_echo { uint8_t bytes[4096]; size_t used, sent; bool eof; };
static bool runtime_echo_read(int fd, struct runtime_echo *echo)
{
    ssize_t seen = recv(fd, echo->bytes, sizeof(echo->bytes), MSG_DONTWAIT);
    if (seen > 0) echo->used = (size_t)seen;
    else if (!seen) echo->eof = true;
    else return errno == EAGAIN || errno == EINTR;
    return true;
}
static bool runtime_echo_write(int fd, struct runtime_echo *echo)
{
    ssize_t sent = send(fd, echo->bytes + echo->sent, echo->used - echo->sent, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (sent > 0) echo->sent += (size_t)sent;
    else if (sent < 0 && errno != EAGAIN && errno != EINTR) return false;
    if (echo->sent == echo->used) echo->used = echo->sent = 0;
    return true;
}
static bool runtime_echo_step(struct runtime_fixture *fixture, struct runtime_echo *echo)
{
    if (fixture->target < 0) {
        size_t size = 0; struct sockaddr_in address; size = sizeof(address);
        fixture->target = platform_socket_accept(fixture->target_listener, (struct sockaddr *)&address, &size);
        if (fixture->target < 0) return errno == EAGAIN || errno == EINTR;
        if (!runtime_test_nonblock(fixture->target)) return false;
    }
    if (!echo->used && !echo->eof) {
        if (!runtime_echo_read(fixture->target, echo)) return false;
    }
    if (echo->used) {
        if (!runtime_echo_write(fixture->target, echo)) return false;
    }
    return true;
}
static bool runtime_send_input(struct runtime_process *process, const uint8_t *bytes, size_t length, size_t *sent)
{
    if (*sent == length) { runtime_test_close(&process->input); return true; }
    size_t remaining = length - *sent; if (remaining > 4096) remaining = 4096;
    ssize_t count = send(process->input, bytes + *sent, remaining, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (count > 0) *sent += (size_t)count;
    return count >= 0 || errno == EAGAIN || errno == EINTR;
}
static bool runtime_read_output(struct runtime_process *process, const uint8_t *bytes, size_t length,
    size_t *seen, bool *eof)
{
    uint8_t buffer[4096]; ssize_t count = read(process->output, buffer, sizeof(buffer));
    if (count > 0) {
        if ((size_t)count > length - *seen || memcmp(buffer, bytes + *seen, (size_t)count)) return false;
        *seen += (size_t)count;
    } else if (!count) *eof = true;
    return count >= 0 || errno == EAGAIN || errno == EINTR;
}
static bool runtime_pump_step(struct runtime_fixture *fixture, struct runtime_echo *echo,
    const uint8_t *bytes, size_t length, size_t *sent, size_t *seen, bool *eof)
{
    return runtime_send_input(&fixture->client, bytes, length, sent) && runtime_echo_step(fixture, echo) &&
        runtime_read_output(&fixture->client, bytes, length, seen, eof) &&
        runtime_diagnostics(&fixture->client) && runtime_diagnostics(&fixture->receiver);
}
static bool runtime_roundtrip(struct runtime_fixture *fixture, unsigned seed)
{
    uint8_t bytes[65536]; for (size_t i = 0; i < sizeof(bytes); ++i) bytes[i] = (uint8_t)(i + seed * 17);
    struct runtime_echo echo = {0}; size_t sent = 0, seen = 0; bool eof = false, half_closed = false;
    int64_t deadline = clock_now_monotonic_ns() + INT64_C(20000000000);
    while (clock_now_monotonic_ns() < deadline && !eof) {
        if (!runtime_pump_step(fixture, &echo, bytes, sizeof(bytes), &sent, &seen, &eof)) return false;
        if (echo.eof && !echo.used && !half_closed) {
            if (shutdown(fixture->target, SHUT_WR) != 0) return false;
            half_closed = true;
        }
        (void)poll(NULL, 0, 1);
    }
    return eof && sent == sizeof(bytes) && seen == sizeof(bytes) && half_closed;
}
static bool runtime_fixture_home_only_profiles(const struct runtime_fixture *fixture)
{
    DIR *directory = opendir(fixture->home);
    if (!directory) return false;
    unsigned seen = 0;
    bool valid = true;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (!strcmp(entry->d_name, "profile-0")) seen |= 1;
        else if (!strcmp(entry->d_name, "profile-1")) seen |= 2;
        else { valid = false; break; }
    }
    if (errno != 0) valid = false;
    if (closedir(directory) != 0) valid = false;
    return valid && seen == 3;
}

static int runtime_binary_sessions(bool standalone)
{
    int failures = 0; struct runtime_fixture fixture; runtime_fixture_init(&fixture); struct json_value input = {0};
    fixture.standalone = standalone;
    TEST_CASE("HOST runtime: actual native receiver/client two fresh sessions, exact binary64KiB and authenticated EOF") {
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_fixture_home_only_profiles(&fixture));
        ASSERT(runtime_input_receiver(&input, &fixture, 2));
        ASSERT(runtime_process_start(&fixture.receiver, &fixture, &input, true, false)); ASSERT(runtime_wait_receiver(&fixture));
        json_free(&input);
        for (unsigned session = 0; session < 2; ++session) {
            ASSERT(runtime_input_client(&input, &fixture)); ASSERT(runtime_process_start(&fixture.client, &fixture, &input, false, false));
            ASSERT(runtime_roundtrip(&fixture, session));
            ASSERT(runtime_process_wait(&fixture.client, clock_now_monotonic_ns() + INT64_C(3000000000)));
            ASSERT(WIFEXITED(fixture.client.status)); ASSERT_EQ(WEXITSTATUS(fixture.client.status), 0);
            ASSERT(strstr(fixture.client.diagnostic_text, "INVALID-PUBLIC-RAW-SENTINEL") == NULL);
            ASSERT(runtime_process_cleanup(&fixture.client)); runtime_test_close(&fixture.target); json_free(&input);
        }
        ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(WIFEXITED(fixture.receiver.status)); ASSERT_EQ(WEXITSTATUS(fixture.receiver.status), 0);
        uint8_t byte; ASSERT_EQ(read(fixture.receiver.output, &byte, 1), 0);
        /* HOME initially owns only the two explicit identity profiles. Raw
         * dispatch must leave that entry set unchanged, with no boot-created
         * configuration or node directory. */
        ASSERT(runtime_fixture_home_only_profiles(&fixture));
    } TEST_END
    json_free(&input); if (!runtime_fixture_close(&fixture)) ++failures; return failures;
}
/* The terminal hub behind the real PSK receiver: the hub listens on the
 * fixture's target port, the receiver carries a real client's bytes to it, and
 * this process speaks the hub protocol on the client's stdin/stdout. */
static bool hop_wait(int fd, short events, int64_t deadline)
{
    struct pollfd p = {.fd = fd, .events = events};
    int64_t left = (deadline - clock_now_monotonic_ns()) / 1000000;
    return left > 0 && poll(&p, 1, (int)left) > 0 && (p.revents & (events | POLLHUP)) != 0;
}
static bool hop_send(int fd, uint8_t type, const void *payload, size_t length)
{
    uint8_t frame[MESH_TERMINAL_HUB_FRAME_MAX]; if (length) memcpy(frame + 3, payload, length);
    size_t total = mesh_terminal_hub_frame_seal(frame, type, length), done = 0;
    int64_t deadline = clock_now_monotonic_ns() + INT64_C(5000000000);
    while (total && done < total) {
        ssize_t n = write(fd, frame + done, total - done);
        if (n > 0) done += (size_t)n;
        else if (n < 0 && errno != EAGAIN && errno != EINTR) return false;
        else if (!hop_wait(fd, POLLOUT, deadline)) return false;
    }
    return total != 0;
}
static bool hop_frame(int fd, uint8_t *type, uint8_t *payload, size_t *length)
{
    uint8_t buffer[MESH_TERMINAL_HUB_FRAME_MAX]; size_t have = 0, want = 3;
    int64_t deadline = clock_now_monotonic_ns() + INT64_C(8000000000);
    while (have < want) {
        if (!hop_wait(fd, POLLIN, deadline)) return false;
        ssize_t n = read(fd, buffer + have, want - have);
        if (n == 0) return false;
        if (n < 0) { if (errno == EAGAIN || errno == EINTR) continue; return false; }
        have += (size_t)n;
        if (have == 3 && want == 3) {
            if (!mesh_terminal_hub_frame_header(buffer, 3, type, length)) return false;
            want = 3 + *length;
        }
    }
    memcpy(payload, buffer + 3, *length); return true;
}
/* Reads DATA until `needle` appears (if given) or EXIT arrives; *code is the EXIT code or -1. */
static bool hop_until(int fd, const char *needle, int *code)
{
    char seen[2048]; size_t fill = 0; seen[0] = 0; *code = -1;
    for (;;) {
        uint8_t type, payload[MESH_TERMINAL_HUB_PAYLOAD_MAX]; size_t length;
        if (!hop_frame(fd, &type, payload, &length)) return false;
        if (type == MESH_TERMINAL_HUB_EXIT && length == 4) { *code = (payload[1] & 1) ? payload[2] : -1; return needle == NULL; }
        if (type != MESH_TERMINAL_HUB_DATA) continue;
        for (size_t i = 0; i < length && fill + 1 < sizeof(seen); ++i) seen[fill++] = (char)payload[i];
        seen[fill] = 0;
        if (needle && strstr(seen, needle)) return true;
    }
}
static int hop_compare(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b; return (x > y) - (x < y);
}
/* The hub runs every session in a user+PID namespace and refuses (never an
 * unconfined shell) where the host denies one, e.g. Ubuntu 23.10+ with
 * kernel.apparmor_restrict_unprivileged_userns=1. Those legs reach READY only
 * where the namespace works; elsewhere they report UNOBSERVED. */
static bool runtime_userns_observed(const char *leg)
{
    if (os_sandbox_userns_available()) return true;
    printf("UNOBSERVED (device_host_runtime: user namespaces refused on this host, see\n"
           "  platform/packaging/linux/apparmor — %s)\n", leg);
    return false;
}
static int runtime_hub_hop(void)
{
    if (!runtime_userns_observed("terminal hub hop")) return 0;
    enum { SAMPLES = 100 };
    int failures = 0; struct runtime_fixture fixture; runtime_fixture_init(&fixture); struct json_value input = {0};
    pid_t hub = -1; char shell[600];
    TEST_CASE("HOST runtime: terminal hub behind the real PSK receiver, exit status and keystroke round trip") {
        ASSERT(test_abs_path("build/bin/fbsh", shell, sizeof(shell)));
        ASSERT(runtime_fixture_open(&fixture));
        hub = fork(); ASSERT(hub >= 0);
        if (hub == 0) {
            struct mesh_terminal_hub_listen_cfg cfg; memset(&cfg, 0, sizeof(cfg));
            for (int i = 0; i < 32; ++i) cfg.serve.key[i] = (uint8_t)(100 + i);
            cfg.serve.shell_path = shell; cfg.serve.workdir = fixture.home;
            cfg.serve.max_bytes_in = 1u << 20; cfg.serve.max_bytes_out = 1u << 24;
            cfg.serve.lifetime_seconds = 60; cfg.serve.idle_seconds = 30; cfg.serve.stop_fd = -1;
            cfg.max_active = 1; cfg.max_sessions = 1; cfg.audit_fd = open("/dev/null", O_WRONLY);
            _exit(mesh_terminal_hub_listen_run(fixture.target_listener, &cfg));
        }
        runtime_test_close(&fixture.target_listener);
        ASSERT(runtime_input_receiver(&input, &fixture, 1));
        ASSERT(runtime_process_start(&fixture.receiver, &fixture, &input, true, false)); ASSERT(runtime_wait_receiver(&fixture));
        json_free(&input);
        ASSERT(runtime_input_client(&input, &fixture)); ASSERT(runtime_process_start(&fixture.client, &fixture, &input, false, false));
        int in = fixture.client.input, out = fixture.client.output, code;
        uint8_t type, payload[MESH_TERMINAL_HUB_PAYLOAD_MAX], hello[MESH_TERMINAL_HUB_PAYLOAD_MAX], key[32]; size_t length;
        for (int i = 0; i < 32; ++i) key[i] = (uint8_t)(100 + i);
        ASSERT(hop_frame(out, &type, payload, &length)); ASSERT_EQ(type, MESH_TERMINAL_HUB_CHALLENGE);
        struct mesh_terminal_hub_request request = {.cols = 80, .rows = 24, .name = "hop"};
        size_t hello_length = mesh_terminal_hub_hello_build(hello, key, payload + 1, &request);
        ASSERT(hello_length != 0 && hop_send(in, MESH_TERMINAL_HUB_HELLO, hello, hello_length));
        ASSERT(hop_frame(out, &type, payload, &length)); ASSERT_EQ(type, MESH_TERMINAL_HUB_READY);
        const char *line = "echo Z23HU\"B\"_HOP\n";
        ASSERT(hop_send(in, MESH_TERMINAL_HUB_DATA, line, strlen(line))); ASSERT(hop_until(out, "Z23HUB_HOP", &code));
        int64_t samples[SAMPLES];
        for (int i = 0; i < SAMPLES; ++i) {
            char probe[2] = {(char)('a' + i % 26), 0}; int64_t start = clock_now_monotonic_ns();
            ASSERT(hop_send(in, MESH_TERMINAL_HUB_DATA, probe, 1)); ASSERT(hop_until(out, probe, &code));
            samples[i] = (clock_now_monotonic_ns() - start) / 1000;
        }
        qsort(samples, SAMPLES, sizeof(samples[0]), hop_compare);
        printf("\n  keystroke round trip through the PSK receiver and client (n=%d): min=%lld us median=%lld us p99=%lld us\n",
            SAMPLES, (long long)samples[0], (long long)samples[SAMPLES / 2], (long long)samples[SAMPLES * 99 / 100]);
        ASSERT(samples[SAMPLES / 2] < 20000);
        const char *leave = "\nexit 3\n";
        ASSERT(hop_send(in, MESH_TERMINAL_HUB_DATA, leave, strlen(leave))); ASSERT(hop_until(out, NULL, &code)); ASSERT_EQ(code, 3);
        runtime_test_close(&fixture.client.input);
        ASSERT(runtime_process_wait(&fixture.client, clock_now_monotonic_ns() + INT64_C(5000000000)));
        ASSERT(runtime_process_cleanup(&fixture.client));
        ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(5000000000)));
        int status = 0; ASSERT_EQ(waitpid(hub, &status, 0), hub); hub = -1; ASSERT(WIFEXITED(status));
    } TEST_END
    if (hub > 0) { kill(hub, SIGKILL); (void)waitpid(hub, NULL, 0); }
    json_free(&input); if (!runtime_fixture_close(&fixture)) ++failures; return failures;
}
/* The real command, `terminal connect --route_input`, over the same hop: the
 * lead's process forks the device-host client itself. */
static pid_t hop_spawn_hub(struct runtime_fixture *fixture, const char *shell)
{
    pid_t hub = fork();
    if (hub != 0) return hub;
    struct mesh_terminal_hub_listen_cfg cfg; memset(&cfg, 0, sizeof(cfg));
    for (int i = 0; i < 32; ++i) cfg.serve.key[i] = (uint8_t)(100 + i);
    cfg.serve.shell_path = shell; cfg.serve.workdir = fixture->home;
    cfg.serve.max_bytes_in = 1u << 20; cfg.serve.max_bytes_out = 1u << 24;
    cfg.serve.lifetime_seconds = 60; cfg.serve.idle_seconds = 30; cfg.serve.stop_fd = -1;
    cfg.max_active = 1; cfg.max_sessions = 1; cfg.audit_fd = open("/dev/null", O_WRONLY);
    _exit(mesh_terminal_hub_listen_run(fixture->target_listener, &cfg));
}
static bool hop_write_files(const struct runtime_fixture *fixture, const struct json_value *input, char *key_path, char *json_path)
{
    char wire[4097]; uint8_t key[32];
    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)(100 + i);
    snprintf(key_path, 1300, "%s/hub.key", fixture->home); snprintf(json_path, 1300, "%s/client.json", fixture->home);
    int len = json_write(input, wire, sizeof(wire)); if (len <= 0) return false;
    int fd = open(key_path, O_WRONLY | O_CREAT | O_EXCL, 0600); if (fd < 0) return false;
    bool ok = write(fd, key, 32) == 32; close(fd);
    fd = open(json_path, O_WRONLY | O_CREAT | O_EXCL, 0600); if (fd < 0) return false;
    ok = ok && write(fd, wire, (size_t)len) == len; close(fd); return ok;
}
static void hop_drain(int fd, char *text, size_t cap, size_t *used)
{
    ssize_t seen = read(fd, text + *used, cap - 1 - *used);
    if (seen > 0) { *used += (size_t)seen; text[*used] = 0; }
}
static bool hop_connect(const char *key_path, const char *json_path, const char *typed, char *out, char *err, int *status)
{
    int in[2], o[2], e[2]; if (pipe(in) || pipe(o) || pipe(e)) return false;
    pid_t pid = fork(); if (pid < 0) return false;
    if (pid == 0) {
        char keyarg[1400], routearg[1400];
        snprintf(keyarg, sizeof keyarg, "--key_file=%s", key_path); snprintf(routearg, sizeof routearg, "--route_input=%s", json_path);
        char *argv[] = {"build/bin/z23", "ops", "mesh", "terminal", "connect", keyarg, routearg, NULL};
        char *env[] = {"PATH=/usr/bin:/bin", NULL};
        dup2(in[0], 0); dup2(o[1], 1); dup2(e[1], 2);
        for (int i = 0; i < 2; ++i) { close(in[i]); close(o[i]); close(e[i]); }
        execve(argv[0], argv, env); _exit(127);
    }
    close(in[0]); close(o[1]); close(e[1]);
    bool ok = write(in[1], typed, strlen(typed)) == (ssize_t)strlen(typed); close(in[1]);
    size_t uo = 0, ue = 0; out[0] = err[0] = 0; int64_t deadline = clock_now_monotonic_ns() + INT64_C(20000000000);
    bool done = false;
    while (!done && clock_now_monotonic_ns() < deadline) {
        struct pollfd p[2] = {{o[0], POLLIN, 0}, {e[0], POLLIN, 0}};
        (void)poll(p, 2, 50);
        if (p[0].revents) hop_drain(o[0], out, 4096, &uo);
        if (p[1].revents) hop_drain(e[0], err, 4096, &ue);
        done = waitpid(pid, status, WNOHANG) == pid;
    }
    if (!done) { kill(pid, SIGKILL); (void)waitpid(pid, status, 0); ok = false; }
    hop_drain(o[0], out, 4096, &uo); hop_drain(e[0], err, 4096, &ue);
    close(o[0]); close(e[0]); return ok;
}
static int runtime_hub_connect(bool wrong)
{
    if (!wrong && !runtime_userns_observed("terminal connect route_input")) return 0;
    int failures = 0; struct runtime_fixture fixture; runtime_fixture_init(&fixture); struct json_value input = {0};
    fixture.different_secret = wrong; pid_t hub = -1; char shell[600], key_path[1300], json_path[1300], out[4096], err[4096];
    TEST_CASE(wrong ? "HOST runtime: terminal connect --route_input with a wrong PSK ends in one typed line"
                    : "HOST runtime: terminal connect --route_input runs a script and returns its exit code") {
        ASSERT(test_abs_path("build/bin/fbsh", shell, sizeof(shell)));
        ASSERT(runtime_fixture_open(&fixture)); hub = hop_spawn_hub(&fixture, shell); ASSERT(hub >= 0);
        runtime_test_close(&fixture.target_listener);
        ASSERT(runtime_input_receiver(&input, &fixture, 1));
        ASSERT(runtime_process_start(&fixture.receiver, &fixture, &input, true, false)); ASSERT(runtime_wait_receiver(&fixture));
        json_free(&input); ASSERT(runtime_input_client(&input, &fixture));
        ASSERT(hop_write_files(&fixture, &input, key_path, json_path));
        int status = 0;
        ASSERT(hop_connect(key_path, json_path, "echo Z23ROUTE_OK; exit 3\n", out, err, &status));
        ASSERT(WIFEXITED(status));
        if (!wrong) {
            ASSERT_EQ(WEXITSTATUS(status), 3); ASSERT(strstr(out, "Z23ROUTE_OK") != NULL);
        } else {
            ASSERT(WEXITSTATUS(status) != 0 && WEXITSTATUS(status) != 127); ASSERT(strstr(out, "Z23ROUTE_OK") == NULL);
            size_t lines = 0; for (const char *c = err; *c; ++c) lines += *c == '\n';
            ASSERT_EQ(lines, 1u); ASSERT(strncmp(err, "z23: ", 5) == 0);
        }
        (void)kill(fixture.receiver.pid, SIGTERM);
        ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(5000000000)));
    } TEST_END
    if (hub > 0) { kill(hub, SIGKILL); (void)waitpid(hub, NULL, 0); }
    json_free(&input); if (!runtime_fixture_close(&fixture)) ++failures; return failures;
}
static int runtime_raw_refusals(bool standalone)
{
    int failures = 0; struct runtime_fixture fixture; runtime_fixture_init(&fixture); struct json_value input = {0};
    fixture.standalone = standalone;
    TEST_CASE("HOST raw entry: extra formatting flag refuses without JSON/config/node side effects") {
        ASSERT(runtime_fixture_open(&fixture)); fixture.receiver_port = 1;
        ASSERT(runtime_input_client(&input, &fixture));
        ASSERT(runtime_process_start(&fixture.client, &fixture, &input, false, true));
        ASSERT(runtime_process_wait(&fixture.client, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(WIFEXITED(fixture.client.status)); ASSERT(WEXITSTATUS(fixture.client.status) != 0);
        uint8_t byte; ASSERT_EQ(read(fixture.client.output, &byte, 1), 0);
        ASSERT(runtime_diagnostics(&fixture.client));
        ASSERT(strstr(fixture.client.diagnostic_text, "HOST_RUNTIME_INPUT_REFUSED") != NULL);
        ASSERT(strstr(fixture.client.diagnostic_text, "INVALID-PUBLIC-RAW-SENTINEL") == NULL);
    } TEST_END
    json_free(&input); if (!runtime_fixture_close(&fixture)) ++failures; return failures;
}
static bool runtime_target_absent(const struct runtime_fixture *fixture)
{
    struct pollfd interest = {.fd = fixture->target_listener, .events = POLLIN};
    return poll(&interest, 1, 0) == 0;
}
static bool runtime_terminal(struct runtime_process *process, const char *result)
{
    if (!runtime_diagnostics(process)) return false;
    char expected[64];
    int length = snprintf(expected, sizeof(expected), "result=%s cleanup_complete=1", result);
    return length > 0 && (size_t)length < sizeof(expected) &&
        strstr(process->diagnostic_text, "event=HOST_RUNTIME_TERMINAL") &&
        strstr(process->diagnostic_text, expected);
}
static int runtime_client_authority_refusal(unsigned field)
{
    int failures = 0; struct runtime_fixture fixture; runtime_fixture_init(&fixture);
    struct json_value input = {0};
    TEST_CASE("HOST runtime: wrong exact root, peer or port refuses before target effects") {
        ASSERT(runtime_fixture_open(&fixture));
        ASSERT(runtime_input_receiver(&input, &fixture, 1));
        ASSERT(runtime_process_start(&fixture.receiver, &fixture, &input, true, false));
        ASSERT(runtime_wait_receiver(&fixture)); json_free(&input);
        if (field == 0) fixture.root[0][0] ^= 1;
        if (field == 1) fixture.row[0].peer_key[0] ^= 1;
        uint16_t original_port = fixture.target_port;
        if (field == 2) fixture.target_port = original_port == UINT16_MAX ? 1 : original_port + 1;
        ASSERT(runtime_input_client(&input, &fixture)); fixture.target_port = original_port;
        ASSERT(runtime_process_start(&fixture.client, &fixture, &input, false, false));
        ASSERT(runtime_process_wait(&fixture.client, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(WIFEXITED(fixture.client.status)); ASSERT(WEXITSTATUS(fixture.client.status) != 0);
        ASSERT(runtime_terminal(&fixture.client, "refused"));
        uint8_t byte; ASSERT_EQ(read(fixture.client.output, &byte, 1), 0);
        ASSERT(runtime_target_absent(&fixture));
    } TEST_END
    json_free(&input); if (!runtime_fixture_close(&fixture)) ++failures; return failures;
}
static int runtime_route_connect(uint16_t port)
{
    int fd = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    if (fd < 0) return -1;
    struct sockaddr_in address = {.sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons(port)};
    int connected = connect(fd, (struct sockaddr *)&address, sizeof(address));
    if (connected < 0 && errno == EINPROGRESS) {
        struct pollfd interest = {.fd = fd, .events = POLLOUT};
        int error = 0; socklen_t size = sizeof(error);
        connected = poll(&interest, 1, 1000) > 0 &&
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && !error ? 0 : -1;
    }
    if (connected < 0) { close(fd); return -1; }
    return fd;
}
static int runtime_truncated_handshake(void)
{
    int failures = 0, carrier = -1; struct runtime_fixture fixture; runtime_fixture_init(&fixture);
    struct json_value input = {0};
    TEST_CASE("HOST runtime: truncated unauthenticated carrier closes without target connection") {
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_input_receiver(&input, &fixture, 1));
        ASSERT(runtime_process_start(&fixture.receiver, &fixture, &input, true, false));
        ASSERT(runtime_wait_receiver(&fixture)); carrier = runtime_route_connect(fixture.receiver_port);
        ASSERT(carrier >= 0); uint8_t fragment = 1;
        ASSERT_EQ(send(carrier, &fragment, 1, MSG_NOSIGNAL), 1);
        ASSERT_EQ(shutdown(carrier, SHUT_WR), 0);
        struct pollfd interest = {.fd = carrier, .events = POLLIN};
        ASSERT(poll(&interest, 1, 1000) > 0); ASSERT_EQ(recv(carrier, &fragment, 1, MSG_DONTWAIT), 0);
        /* Unauthenticated failures no longer consume a session slot, so the receiver keeps listening. */
        ASSERT_EQ(kill(fixture.receiver.pid, SIGTERM), 0);
        ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(WIFEXITED(fixture.receiver.status)); ASSERT(runtime_target_absent(&fixture));
        ASSERT(runtime_terminal(&fixture.receiver, "cancelled"));
        ASSERT(strstr(fixture.receiver.diagnostic_text, "accepted=0 completed=0 refused=1") != NULL);
        ASSERT_EQ(read(fixture.receiver.output, &fragment, 1), 0);
    } TEST_END
    runtime_test_close(&carrier); json_free(&input);
    if (!runtime_fixture_close(&fixture)) ++failures;
    return failures;
}
static bool runtime_listener_closed(uint16_t port)
{
    int fd = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    if (fd < 0) return false;
    struct sockaddr_in address = {.sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons(port)};
    int result = connect(fd, (struct sockaddr *)&address, sizeof(address));
    bool refused = result < 0 && errno == ECONNREFUSED;
    if (result < 0 && errno == EINPROGRESS) {
        struct pollfd interest = {.fd = fd, .events = POLLOUT};
        int error = 0; socklen_t size = sizeof(error);
        refused = poll(&interest, 1, 1000) > 0 &&
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == ECONNREFUSED;
    }
    close(fd); return refused;
}
static int runtime_receiver_cancel(int signal_number)
{
    int failures = 0; struct runtime_fixture fixture; runtime_fixture_init(&fixture);
    struct json_value input = {0};
    TEST_CASE("HOST runtime: receiver SIGTERM/SIGHUP cancels normally and closes selected listener") {
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_input_receiver(&input, &fixture, 1));
        ASSERT(runtime_process_start(&fixture.receiver, &fixture, &input, true, false));
        ASSERT(runtime_wait_receiver(&fixture)); ASSERT(fixture.receiver.pid > 0);
        ASSERT_EQ(kill(fixture.receiver.pid, signal_number), 0);
        ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(3000000000)));
        /* The native cancellation rail returns normally, rather than dying
         * from the default SIGTERM disposition. */
        ASSERT(WIFEXITED(fixture.receiver.status)); ASSERT(WEXITSTATUS(fixture.receiver.status) != 0);
        ASSERT(runtime_terminal(&fixture.receiver, "cancelled"));
        uint8_t byte; ASSERT_EQ(read(fixture.receiver.output, &byte, 1), 0);
        ASSERT(runtime_listener_closed(fixture.receiver_port)); ASSERT(runtime_target_absent(&fixture));
    } TEST_END
    json_free(&input); if (!runtime_fixture_close(&fixture)) ++failures; return failures;
}
static int runtime_wrong_secret(void)
{
    int failures = 0; struct runtime_fixture fixture; runtime_fixture_init(&fixture);
    fixture.different_secret = true; struct json_value input = {0};
    TEST_CASE("HOST runtime: independently stored wrong pair secret refuses without target connection") {
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_input_receiver(&input, &fixture, 1));
        ASSERT(runtime_process_start(&fixture.receiver, &fixture, &input, true, false));
        ASSERT(runtime_wait_receiver(&fixture)); json_free(&input);
        ASSERT(runtime_input_client(&input, &fixture));
        ASSERT(runtime_process_start(&fixture.client, &fixture, &input, false, false));
        ASSERT(runtime_process_wait(&fixture.client, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(WIFEXITED(fixture.client.status)); ASSERT(WEXITSTATUS(fixture.client.status) != 0);
        ASSERT_EQ(kill(fixture.receiver.pid, SIGTERM), 0);
        ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(3000000000)));
        uint8_t byte; ASSERT_EQ(read(fixture.client.output, &byte, 1), 0);
        ASSERT(runtime_terminal(&fixture.client, "refused"));
        ASSERT(runtime_terminal(&fixture.receiver, "cancelled"));
        ASSERT(strstr(fixture.receiver.diagnostic_text, "accepted=0 completed=0 refused=1") != NULL);
        ASSERT(runtime_target_absent(&fixture));
    } TEST_END
    json_free(&input); if (!runtime_fixture_close(&fixture)) ++failures; return failures;
}
static bool runtime_send_hello(struct runtime_fixture *fixture, int carrier,
                               struct device_host_psk_session *session)
{
    struct device_host_psk_spec spec = {.store = &fixture->store[0],
        .direction = DEVICE_PAIRING_HOST_OUTBOUND, .port = fixture->target_port,
        .deadline_ns = clock_now_monotonic_ns() + INT64_C(5000000000)};
    memcpy(spec.peer, fixture->row[0].peer_key, 32); memcpy(spec.approved_root, fixture->root[0], 32);
    enum device_host_psk_result status;
    struct zcl_result started = device_host_psk_start(session, &spec, &status);
    if (!started.ok || status != DEVICE_HOST_PSK_PROGRESS) return false;
    struct device_pairing_guard guard = {0}; const uint8_t *bytes; size_t length;
    struct zcl_result acquired = device_host_psk_pending_acquire(session, &guard, &bytes, &length, &status);
    if (!acquired.ok || status != DEVICE_HOST_PSK_PROGRESS)
        return false;
    ssize_t sent = send(carrier, bytes, length, MSG_DONTWAIT | MSG_NOSIGNAL);
    struct zcl_result result = device_host_psk_pending_written(session, &guard,
        sent > 0 ? (size_t)sent : 0, &status);
    return sent > 0 && (size_t)sent == length && result.ok && status == DEVICE_HOST_PSK_PROGRESS;
}
static bool runtime_feed_hello(struct device_host_psk_session *session,
                               const uint8_t *bytes, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        size_t consumed = 0;
        enum device_host_psk_result status;
        struct zcl_result result = device_host_psk_receive_bytes(session, bytes + offset,
            length - offset, &consumed, &status);
        if (!result.ok || status != DEVICE_HOST_PSK_PROGRESS || !consumed)
            return false;
        offset += consumed;
    }
    return true;
}
static bool runtime_receive_hello(int carrier, struct device_host_psk_session *session)
{
    int64_t deadline = clock_now_monotonic_ns() + INT64_C(3000000000);
    while (clock_now_monotonic_ns() < deadline) {
        struct pollfd interest = {.fd = carrier, .events = POLLIN}; uint8_t response[512];
        if (poll(&interest, 1, 20) < 0) return false;
        ssize_t count = recv(carrier, response, sizeof(response), MSG_DONTWAIT);
        if (count > 0) {
            if (!runtime_feed_hello(session, response, (size_t)count)) return false;
            if (session->phase == DEVICE_HOST_PSK_CLIENT_SEND_CONFIRM) return true;
        } else if (!count || (errno != EAGAIN && errno != EINTR)) return false;
    }
    return false;
}
static bool runtime_socket_eof(int fd);
static int runtime_unconfirmed_hello(void)
{
    int failures = 0, carrier = -1; struct runtime_fixture fixture; runtime_fixture_init(&fixture);
    struct json_value input = {0}; struct device_host_psk_session session; device_host_psk_init(&session);
    TEST_CASE("HOST runtime: complete valid client hello receives server hello but cannot dial before confirmation") {
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_input_receiver(&input, &fixture, 1));
        ASSERT(runtime_process_start(&fixture.receiver, &fixture, &input, true, false));
        ASSERT(runtime_wait_receiver(&fixture)); carrier = runtime_route_connect(fixture.receiver_port);
        ASSERT(carrier >= 0); ASSERT(runtime_send_hello(&fixture, carrier, &session));
        ASSERT(runtime_receive_hello(carrier, &session));
        /* Verify the server flight, but deliberately withhold queued C_CONFIRM. */
        ASSERT(runtime_target_absent(&fixture)); ASSERT_EQ(shutdown(carrier, SHUT_WR), 0);
        ASSERT(runtime_socket_eof(carrier)); ASSERT_EQ(kill(fixture.receiver.pid, SIGTERM), 0);
        ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(runtime_target_absent(&fixture));
    } TEST_END
    device_host_psk_destroy(&session); runtime_test_close(&carrier); json_free(&input);
    if (!runtime_fixture_close(&fixture)) ++failures;
    return failures;
}
static bool runtime_start_pair(struct runtime_fixture *fixture)
{
    struct json_value input = {0};
    bool ok = runtime_input_receiver(&input, fixture, 1) &&
        runtime_process_start(&fixture->receiver, fixture, &input, true, false) && runtime_wait_receiver(fixture);
    json_free(&input);
    ok = ok && runtime_input_client(&input, fixture) &&
        runtime_process_start(&fixture->client, fixture, &input, false, false);
    json_free(&input); return ok;
}
static bool runtime_target_ready(struct runtime_fixture *fixture)
{
    int64_t deadline = clock_now_monotonic_ns() + INT64_C(3000000000);
    while (clock_now_monotonic_ns() < deadline) {
        struct sockaddr_in address; size_t size = sizeof(address);
        fixture->target = platform_socket_accept(fixture->target_listener, (struct sockaddr *)&address, &size);
        if (fixture->target >= 0) return runtime_test_nonblock(fixture->target);
        if (errno != EAGAIN && errno != EINTR) return false;
        if (runtime_process_poll(&fixture->client)) {
            (void)runtime_diagnostics(&fixture->client);
            (void)runtime_diagnostics(&fixture->receiver);
            fprintf(stderr, "runtime target-not-ready client: %s\nreceiver: %s\n",
                fixture->client.diagnostic_text, fixture->receiver.diagnostic_text);
            return false;
        }
        (void)poll(NULL, 0, 1);
    }
    return false;
}
static bool runtime_byte_barrier(struct runtime_fixture *fixture)
{
    uint8_t byte = 0x5a, observed = 0;
    if (send(fixture->client.input, &byte, 1, MSG_NOSIGNAL) != 1) return false;
    struct pollfd interest = {.fd = fixture->target, .events = POLLIN};
    if (poll(&interest, 1, 3000) <= 0 || recv(fixture->target, &observed, 1, MSG_DONTWAIT) != 1 || observed != byte)
        return false;
    if (send(fixture->target, &byte, 1, MSG_NOSIGNAL) != 1) return false;
    interest.fd = fixture->client.output;
    return poll(&interest, 1, 3000) > 0 && read(fixture->client.output, &observed, 1) == 1 && observed == byte;
}
static bool runtime_revoke_row(struct runtime_fixture *fixture, size_t node)
{
    int64_t deadline = clock_now_monotonic_ns() + INT64_C(3000000000);
    while (clock_now_monotonic_ns() < deadline) {
        enum device_pairing_publication publication = DEVICE_PAIRING_NOT_PUBLISHED;
        if (db_device_pairing_revoke_expected(&fixture->store[node], fixture->row[node].peer_key,
            (uint64_t)(clock_now_wall_ms() / 1000), fixture->root[node], &publication))
            return publication == DEVICE_PAIRING_DURABLE;
        if (publication != DEVICE_PAIRING_NOT_PUBLISHED) return false;
        /* Only retry a no-publication attempt after a successful unchanged
         * exact-root observation. Unknown publication is never retried. */
        struct db_device_pairing current; uint8_t root[32]; bool inspected = false;
        while (clock_now_monotonic_ns() < deadline && !inspected) {
            inspected = db_device_pairing_inspect(&fixture->store[node], fixture->row[node].peer_key, &current, root);
            if (!inspected) (void)poll(NULL, 0, 1);
        }
        if (!inspected || memcmp(root, fixture->root[node], 32)) return false;
    }
    return false;
}
static bool runtime_revoke_completed(struct runtime_fixture *fixture)
{
    return runtime_revoke_row(fixture, 1);
}
static bool runtime_socket_eof(int fd)
{
    struct pollfd interest = {.fd = fd, .events = POLLIN}; uint8_t byte;
    return poll(&interest, 1, 3000) > 0 && recv(fd, &byte, 1, MSG_DONTWAIT) == 0;
}
static int runtime_completed_revoke(bool active)
{
    int failures = 0; struct runtime_fixture fixture; runtime_fixture_init(&fixture);
    TEST_CASE("HOST runtime: completed established idle/prior-traffic revoke closes target with no post-revoke plaintext") {
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_start_pair(&fixture)); ASSERT(runtime_target_ready(&fixture));
        /* Target accept precedes S_READY. A fully observed/drained roundtrip
         * establishes both roles before either idle or prior-traffic revoke. */
        ASSERT(runtime_byte_barrier(&fixture));
        if (active) ASSERT(runtime_byte_barrier(&fixture));
        ASSERT(runtime_revoke_completed(&fixture));
        struct db_device_pairing current; uint8_t root[32];
        ASSERT(db_device_pairing_inspect(&fixture.store[1], fixture.row[1].peer_key, &current, root));
        ASSERT(current.revoked_at != 0);
        uint8_t post_revoke = 0xc3;
        ssize_t attempted = send(fixture.client.input, &post_revoke, 1, MSG_DONTWAIT | MSG_NOSIGNAL);
        ASSERT(attempted == 1 || (attempted < 0 && errno == EPIPE));
        /* Active-case pre-revoke bytes were fully observed and drained.
         * EOF here proves the newly attempted marker was never released. */
        ASSERT(runtime_socket_eof(fixture.target));
        ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(runtime_terminal(&fixture.receiver, "refused"));
        ASSERT(runtime_listener_closed(fixture.receiver_port));
        ASSERT(runtime_process_wait(&fixture.client, clock_now_monotonic_ns() + INT64_C(3000000000)));
        uint8_t byte; ASSERT_EQ(read(fixture.client.output, &byte, 1), 0);
    } TEST_END
    if (!runtime_fixture_close(&fixture)) ++failures;
    return failures;
}
static int runtime_client_cancel(void)
{
    int failures = 0; struct runtime_fixture fixture; runtime_fixture_init(&fixture);
    TEST_CASE("HOST runtime: established client SIGTERM cancels normally and closes actual target") {
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_start_pair(&fixture)); ASSERT(runtime_target_ready(&fixture));
        ASSERT(runtime_byte_barrier(&fixture)); ASSERT(fixture.client.pid > 0);
        ASSERT_EQ(kill(fixture.client.pid, SIGTERM), 0);
        ASSERT(runtime_process_wait(&fixture.client, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(WIFEXITED(fixture.client.status)); ASSERT(runtime_terminal(&fixture.client, "cancelled"));
        ASSERT(runtime_socket_eof(fixture.target));
        ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(3000000000)));
        uint8_t byte; ASSERT_EQ(read(fixture.client.output, &byte, 1), 0);
        ASSERT(runtime_listener_closed(fixture.receiver_port));
    } TEST_END
    if (!runtime_fixture_close(&fixture)) ++failures;
    return failures;
}
static bool runtime_input_number(struct json_value *input, const char *key, int64_t number)
{
    struct json_value *field = (struct json_value *)json_get(input, key);
    if (!field || field->type != JSON_INT) return false;
    json_set_int(field, number); return true;
}
static int runtime_closed_route(uint16_t *port)
{
    int fd = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    if (fd < 0) return -1;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t size = sizeof(address);
    if (bind(fd, (struct sockaddr *)&address, size) != 0 ||
        getsockname(fd, (struct sockaddr *)&address, &size) != 0) { close(fd); return -1; }
    /* Hold the non-listening binding: no unrelated listener can claim it. */
    *port = ntohs(address.sin_port); return fd;
}
static int runtime_fresh_backup(void)
{
    int failures = 0, primary = -1; struct runtime_fixture fixture; runtime_fixture_init(&fixture);
    struct json_value input = {0}; uint16_t primary_port = 0;
    TEST_CASE("HOST runtime: explicit refused primary then NEW client process uses selected backup with fresh session") {
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_input_receiver(&input, &fixture, 1));
        ASSERT(runtime_process_start(&fixture.receiver, &fixture, &input, true, false));
        ASSERT(runtime_wait_receiver(&fixture)); json_free(&input);
        primary = runtime_closed_route(&primary_port); ASSERT(primary >= 0);
        ASSERT(runtime_input_client(&input, &fixture)); ASSERT(runtime_input_number(&input, "route_port", primary_port));
        ASSERT(runtime_process_start(&fixture.client, &fixture, &input, false, false)); pid_t first_pid = fixture.client.pid;
        ASSERT(runtime_process_wait(&fixture.client, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(runtime_terminal(&fixture.client, "io_error")); ASSERT(runtime_target_absent(&fixture));
        uint8_t byte; ASSERT_EQ(read(fixture.client.output, &byte, 1), 0);
        ASSERT(runtime_process_cleanup(&fixture.client)); json_free(&input);
        ASSERT(runtime_input_client(&input, &fixture));
        ASSERT(runtime_process_start(&fixture.client, &fixture, &input, false, false));
        ASSERT(fixture.client.pid > 0 && fixture.client.pid != first_pid);
        ASSERT(runtime_roundtrip(&fixture, 9));
        ASSERT(runtime_process_wait(&fixture.client, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(WIFEXITED(fixture.client.status)); ASSERT_EQ(WEXITSTATUS(fixture.client.status), 0);
        ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(runtime_terminal(&fixture.receiver, "eof"));
        ASSERT(strstr(fixture.receiver.diagnostic_text, "accepted=1 completed=1 refused=0") != NULL);
    } TEST_END
    runtime_test_close(&primary); json_free(&input);
    if (!runtime_fixture_close(&fixture)) ++failures;
    return failures;
}
static int runtime_handshake_deadline(void)
{
    int failures = 0, carrier = -1; struct runtime_fixture fixture; runtime_fixture_init(&fixture);
    struct json_value input = {0};
    TEST_CASE("HOST runtime: finite handshake deadline closes silent live carrier without target connection") {
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_input_receiver(&input, &fixture, 1));
        ASSERT(runtime_input_number(&input, "handshake_ms", 100));
        ASSERT(runtime_process_start(&fixture.receiver, &fixture, &input, true, false));
        ASSERT(runtime_wait_receiver(&fixture)); carrier = runtime_route_connect(fixture.receiver_port); ASSERT(carrier >= 0);
        /* Keep the peer open without sending EOF/FIN or protocol bytes. */
        ASSERT(runtime_socket_eof(carrier));
        ASSERT_EQ(kill(fixture.receiver.pid, SIGTERM), 0);
        ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(runtime_terminal(&fixture.receiver, "cancelled"));
        ASSERT(strstr(fixture.receiver.diagnostic_text, "accepted=0 completed=0 refused=1") != NULL); ASSERT(runtime_target_absent(&fixture));
    } TEST_END
    runtime_test_close(&carrier); json_free(&input);
    if (!runtime_fixture_close(&fixture)) ++failures;
    return failures;
}
static int runtime_idle_deadline(void)
{
    int failures = 0; struct runtime_fixture fixture; runtime_fixture_init(&fixture);
    struct json_value input = {0};
    TEST_CASE("HOST runtime: established client finite idle deadline closes target and reports deadline") {
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_input_receiver(&input, &fixture, 1));
        ASSERT(runtime_process_start(&fixture.receiver, &fixture, &input, true, false));
        ASSERT(runtime_wait_receiver(&fixture)); json_free(&input);
        ASSERT(runtime_input_client(&input, &fixture)); ASSERT(runtime_input_number(&input, "idle_ms", 1500));
        ASSERT(runtime_process_start(&fixture.client, &fixture, &input, false, false));
        ASSERT(runtime_target_ready(&fixture)); ASSERT(runtime_byte_barrier(&fixture));
        /* Leave both directions open and empty: no EOF or cancellation can
         * explain the named deadline. The wait bound is fixture cleanup. */
        ASSERT(runtime_process_wait(&fixture.client, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(runtime_terminal(&fixture.client, "deadline")); ASSERT(runtime_socket_eof(fixture.target));
        uint8_t byte; ASSERT_EQ(read(fixture.client.output, &byte, 1), 0);
    } TEST_END
    json_free(&input); if (!runtime_fixture_close(&fixture)) ++failures;
    return failures;
}
static int runtime_prefix_pending(int fd)
{
    uint8_t prefix; ssize_t seen = recv(fd, &prefix, 1, MSG_DONTWAIT | MSG_PEEK);
    if (seen == 1) return prefix == 0x61 ? 1 : -1;
    if (seen < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
    return -1;
}
static bool runtime_child_live(struct runtime_process *process)
{
    bool finished = runtime_process_poll(process);
    return !finished && process->pid > 0 && !process->custody_lost;
}
static bool runtime_backpressure(struct runtime_fixture *fixture)
{
    int capacity = 4096;
    if (setsockopt(fixture->client.input, SOL_SOCKET, SO_SNDBUF, &capacity, sizeof(capacity)) != 0 ||
        setsockopt(fixture->target, SOL_SOCKET, SO_RCVBUF, &capacity, sizeof(capacity)) != 0) return false;
    uint8_t bytes[4096]; memset(bytes, 0x61, sizeof(bytes)); size_t total = 0;
    int64_t deadline = clock_now_monotonic_ns() + INT64_C(3000000000);
    while (clock_now_monotonic_ns() < deadline && total < 16u * 1024u * 1024u) {
        ssize_t sent = send(fixture->client.input, bytes, sizeof(bytes), MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent > 0) { total += (size_t)sent; continue; }
        if (sent >= 0 || errno != EAGAIN) return false;
        int pending = runtime_prefix_pending(fixture->target);
        if (pending > 0 && total > 0) {
            bool client = runtime_child_live(&fixture->client);
            bool receiver = runtime_child_live(&fixture->receiver);
            return client && receiver;
        }
        if (pending < 0) return false;
        (void)poll(NULL, 0, 1);
    }
    return false;
}
static bool runtime_post_revoke_marker(struct runtime_process *process)
{
    uint8_t marker = 0xff; int64_t deadline = clock_now_monotonic_ns() + INT64_C(1000000000);
    while (clock_now_monotonic_ns() < deadline) {
        ssize_t sent = send(process->input, &marker, 1, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent == 1 || (sent < 0 && errno == EPIPE)) return true;
        if (sent >= 0 || (errno != EAGAIN && errno != EINTR)) return false;
        (void)poll(NULL, 0, 1);
    }
    return false;
}
static bool runtime_drain_prefix(int fd, uint8_t expected, size_t *observed)
{
    int64_t deadline = clock_now_monotonic_ns() + INT64_C(3000000000); *observed = 0;
    while (clock_now_monotonic_ns() < deadline) {
        uint8_t bytes[4096]; ssize_t count = recv(fd, bytes, sizeof(bytes), MSG_DONTWAIT);
        if (!count) return true;
        if (count > 0) {
            for (ssize_t i = 0; i < count; ++i) if (bytes[i] != expected) return false;
            *observed += (size_t)count; continue;
        }
        if (errno != EAGAIN && errno != EINTR) return false;
        struct pollfd interest = {.fd = fd, .events = POLLIN}; (void)poll(&interest, 1, 20);
    }
    return false;
}
static int runtime_during_traffic_revoke(void)
{
    int failures = 0; struct runtime_fixture fixture; runtime_fixture_init(&fixture);
    TEST_CASE("HOST runtime: durable revoke during actual source backpressure retains authorized prefix but forbids new marker") {
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_start_pair(&fixture)); ASSERT(runtime_target_ready(&fixture));
        ASSERT(runtime_byte_barrier(&fixture)); ASSERT(runtime_backpressure(&fixture));
        /* Target prefix remains unread, source is demonstrably blocked, both
         * real processes are live. Previously released bytes are not recalled. */
        ASSERT(runtime_revoke_completed(&fixture)); ASSERT(runtime_post_revoke_marker(&fixture.client));
        int drain_capacity = 1024 * 1024;
        ASSERT_EQ(setsockopt(fixture.target, SOL_SOCKET, SO_RCVBUF, &drain_capacity, sizeof(drain_capacity)), 0);
        size_t prefix = 0; ASSERT(runtime_drain_prefix(fixture.target, 0x61, &prefix)); ASSERT(prefix > 0);
        ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(runtime_terminal(&fixture.receiver, "refused")); ASSERT(runtime_listener_closed(fixture.receiver_port));
        ASSERT(runtime_process_wait(&fixture.client, clock_now_monotonic_ns() + INT64_C(3000000000)));
        uint8_t byte; ASSERT_EQ(read(fixture.client.output, &byte, 1), 0);
    } TEST_END
    if (!runtime_fixture_close(&fixture)) ++failures;
    return failures;
}
static bool runtime_drain_hello(int carrier, bool require_hello)
{
    int64_t deadline = clock_now_monotonic_ns() + INT64_C(3000000000); size_t hello = 0;
    while (clock_now_monotonic_ns() < deadline) {
        uint8_t bytes[4096]; ssize_t count = recv(carrier, bytes, sizeof(bytes), MSG_DONTWAIT);
        if (!count) return !require_hello || hello > 0;
        if (count > 0) { hello += (size_t)count; if (hello > DEVICE_HOST_PSK_WIRE) return false; }
        else if (errno != EAGAIN && errno != EINTR) return false;
        struct pollfd interest = {.fd = carrier, .events = POLLIN}; (void)poll(&interest, 1, 20);
    }
    return false;
}
static int runtime_named_handshake_deadline(bool hangup)
{
    int failures = 0, carrier = -1; struct runtime_fixture fixture; runtime_fixture_init(&fixture);
    struct json_value input = {0};
    TEST_CASE("HOST runtime: silent peer yields named handshake deadline or preauth HUP cancellation without plaintext release") {
        ASSERT(runtime_fixture_open(&fixture)); fixture.receiver_port = fixture.target_port;
        ASSERT(runtime_input_client(&input, &fixture)); ASSERT(runtime_input_number(&input, "handshake_ms", hangup ? 5000 : 100));
        ASSERT(runtime_process_start(&fixture.client, &fixture, &input, false, false));
        struct pollfd listener = {.fd = fixture.target_listener, .events = POLLIN};
        ASSERT(poll(&listener, 1, 1000) > 0);
        struct sockaddr_in address; size_t size = sizeof(address);
        carrier = platform_socket_accept(fixture.target_listener, (struct sockaddr *)&address, &size); ASSERT(carrier >= 0);
        ASSERT(runtime_test_nonblock(carrier));
        if (hangup) ASSERT_EQ(kill(fixture.client.pid, SIGHUP), 0);
        /* This is the explicitly selected raw carrier fixture, NOT the fixed
         * authorized receiver target. It remains live but sends no server flight. */
        ASSERT(runtime_process_wait(&fixture.client, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(runtime_terminal(&fixture.client, hangup ? "cancelled" : "deadline"));
        ASSERT(strstr(fixture.client.diagnostic_text, "plaintext_read=0 plaintext_written=0") != NULL);
        ASSERT(runtime_drain_hello(carrier, !hangup)); uint8_t byte;
        ASSERT_EQ(read(fixture.client.output, &byte, 1), 0);
    } TEST_END
    runtime_test_close(&carrier); json_free(&input);
    if (!runtime_fixture_close(&fixture)) ++failures;
    return failures;
}
static int64_t runtime_measure_now(void)
{
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time) != 0) return 0;
    if (time.tv_sec < 0 || time.tv_nsec < 0 || time.tv_nsec >= INT64_C(1000000000) ||
        time.tv_sec > (INT64_MAX - time.tv_nsec) / INT64_C(1000000000)) return 0;
    return (int64_t)time.tv_sec * INT64_C(1000000000) + time.tv_nsec;
}
static bool runtime_measure_readable(int fd)
{
    int64_t start = runtime_measure_now();
    if (start <= 0 || start > INT64_MAX - INT64_C(3000000000)) return false;
    int64_t deadline = start + INT64_C(3000000000);
    for (;;) {
        int64_t now = runtime_measure_now();
        if (now < start || now >= deadline) return false;
        struct pollfd interest = {.fd = fd, .events = POLLIN};
        int ready = poll(&interest, 1, 20);
        if (ready > 0) return true;
        if (ready < 0 && errno != EINTR) return false;
    }
}
struct runtime_sparse_sample { int64_t rtt, relay, gap, end; };
static bool runtime_measure_byte(int fd, uint8_t expected, bool socket)
{
    if (!runtime_measure_readable(fd)) return false;
    uint8_t seen; ssize_t count = socket ? recv(fd, &seen, 1, MSG_DONTWAIT) : read(fd, &seen, 1);
    return count == 1 && seen == expected;
}
static bool runtime_sparse_echo(struct runtime_fixture *fixture, unsigned index,
                                struct runtime_sparse_sample *sample, int64_t previous)
{
    uint8_t sent = (uint8_t)(index + 1);
    int64_t start = runtime_measure_now();
    if (previous <= 0 || start < previous) return false;
    sample->gap = start - previous;
    if (send(fixture->client.input, &sent, 1, MSG_NOSIGNAL) != 1 ||
        !runtime_measure_byte(fixture->target, sent, true))
        return false;
    int64_t target_seen = runtime_measure_now();
    if (target_seen < start) return false;
    if (send(fixture->target, &sent, 1, MSG_NOSIGNAL) != 1) return false;
    int64_t send_done = runtime_measure_now();
    if (send_done < target_seen) return false;
    sample->relay = send_done - target_seen;
    if (!runtime_measure_byte(fixture->client.output, sent, false)) return false;
    sample->end = runtime_measure_now();
    if (sample->end < send_done) return false;
    sample->rtt = sample->end - start;
    return true;
}
static int runtime_sample_order(const void *left, const void *right)
{
    int64_t a = *(const int64_t *)left, b = *(const int64_t *)right;
    return (a > b) - (a < b);
}
static int64_t runtime_process_cpu_us(const struct runtime_process *process)
{
    return ((int64_t)process->usage.ru_utime.tv_sec + process->usage.ru_stime.tv_sec) * INT64_C(1000000) +
        process->usage.ru_utime.tv_usec + process->usage.ru_stime.tv_usec;
}
static void runtime_sparse_report(const struct runtime_sparse_sample samples[32], int64_t setup,
                                  const struct runtime_fixture *fixture)
{
    int64_t sorted[32];
    for (size_t i = 0; i < 32; ++i) {
        sorted[i] = samples[i].rtt;
        fprintf(stderr, "PSK_SPARSE_RTT sample=%zu gap_ns=%" PRId64 " rtt_ns=%" PRId64 " fixture_relay_ns=%" PRId64 "\n",
            i, samples[i].gap, samples[i].rtt, samples[i].relay);
    }
    qsort(sorted, 32, sizeof(sorted[0]), runtime_sample_order);
    fprintf(stderr, "PSK_SPARSE_SUMMARY samples=32 p50_ns=%" PRId64 " p95_ns=%" PRId64 " setup_ns=%" PRId64
        " client_cpu_us=%" PRId64 " receiver_cpu_us=%" PRId64
        " cpu_scope=whole_process_including_setup fixture_poll=blocking_readiness cadence_ms=37,53,71\n",
        sorted[15], sorted[30], setup, runtime_process_cpu_us(&fixture->client), runtime_process_cpu_us(&fixture->receiver));
}
static bool runtime_sparse_finish(struct runtime_fixture *fixture)
{
    runtime_test_close(&fixture->client.input);
    if (!runtime_socket_eof(fixture->target) || shutdown(fixture->target, SHUT_WR) != 0) return false;
    if (!runtime_process_wait(&fixture->client, clock_now_monotonic_ns() + INT64_C(3000000000)) ||
        !runtime_process_wait(&fixture->receiver, clock_now_monotonic_ns() + INT64_C(3000000000))) return false;
    uint8_t byte;
    return read(fixture->client.output, &byte, 1) == 0 &&
        WIFEXITED(fixture->client.status) && WEXITSTATUS(fixture->client.status) == 0 &&
        WIFEXITED(fixture->receiver.status) && WEXITSTATUS(fixture->receiver.status) == 0;
}
static int runtime_multi_active_deadline(void)
{
    int failures = 0, silent = -1; struct runtime_fixture fixture; runtime_fixture_init(&fixture);
    struct json_value input = {0};
    TEST_CASE("HOST readiness: earliest silent slot expires while later established slot continues exact echo and FIN drain") {
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_input_receiver(&input, &fixture, 1));
        ASSERT(runtime_input_number(&input, "handshake_ms", 3000));
        ASSERT(runtime_process_start(&fixture.receiver, &fixture, &input, true, false));
        ASSERT(runtime_wait_receiver(&fixture)); silent = runtime_route_connect(fixture.receiver_port); ASSERT(silent >= 0);
        json_free(&input); ASSERT(runtime_input_client(&input, &fixture));
        ASSERT(runtime_process_start(&fixture.client, &fixture, &input, false, false));
        ASSERT(runtime_target_ready(&fixture)); ASSERT(runtime_byte_barrier(&fixture));
        struct pollfd earlier = {.fd = silent, .events = POLLIN}; ASSERT_EQ(poll(&earlier, 1, 0), 0);
        /* Two simultaneous slots: no data/EOF on the earlier raw carrier,
         * later slot is already mutually established with drained traffic. */
        ASSERT(runtime_socket_eof(silent)); ASSERT(runtime_child_live(&fixture.client)); ASSERT(runtime_child_live(&fixture.receiver));
        ASSERT(runtime_byte_barrier(&fixture)); ASSERT(runtime_roundtrip(&fixture, 11));
        ASSERT(runtime_process_wait(&fixture.client, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(runtime_terminal(&fixture.receiver, "eof"));
        ASSERT(strstr(fixture.receiver.diagnostic_text, "accepted=1 completed=1 refused=1") != NULL);
        ASSERT(WIFEXITED(fixture.client.status)); ASSERT_EQ(WEXITSTATUS(fixture.client.status), 0);
    } TEST_END
    runtime_test_close(&silent); json_free(&input);
    if (!runtime_fixture_close(&fixture)) ++failures;
    return failures;
}
static bool runtime_entry_wire(struct json_value *input, unsigned fault, char wire[8192])
{
    if (fault == 0 && !json_push_kv_bool(input, "unknown", true)) return false;
    if (fault == 1 && !json_push_kv_bool(input, "confirm", true)) return false;
    if (fault == 2 && !runtime_input_number(input, "idle_ms", 0)) return false;
    size_t length = json_write(input, wire, 8192);
    if (!length || length >= 8192) return false;
    if (fault == 3) { memcpy(wire + length, " true", 6); return true; }
    if (fault == 4) {
        char *route = strstr(wire, "PUBLIC-local-loopback\"");
        if (!route) return false;
        route += strlen("PUBLIC-local-loopback");
        memmove(route + 6, route, strlen(route) + 1); memcpy(route, "\\u0000", 6);
    }
    if (fault == 5) { memset(wire + length, ' ', 4097 - length); wire[4097] = 0; }
    return true;
}
static int runtime_entry_parser(unsigned fault)
{
    int failures = 0; struct runtime_fixture fixture; runtime_fixture_init(&fixture);
    struct json_value input = {0}, parsed = {0}; char wire[8192];
    TEST_CASE("HOST shared entry: bounded exact object refuses unknown/duplicate keys, zero duration, trailing data, NUL and overbudget") {
        ASSERT(runtime_fixture_open(&fixture)); fixture.receiver_port = 1;
        ASSERT(runtime_input_client(&input, &fixture));
        size_t length = json_write(&input, wire, sizeof(wire)); ASSERT(length > 0 && length < sizeof(wire));
        ASSERT(device_host_runtime_entry_parse(&parsed, wire, length, false).ok); json_free(&parsed); json_init(&parsed);
        ASSERT(runtime_entry_wire(&input, fault, wire));
        struct zcl_result refused = device_host_runtime_entry_parse(&parsed, wire, strlen(wire), false);
        ASSERT(!refused.ok); ASSERT(refused.code < 0); ASSERT(refused.message[0]);
        ASSERT(refused.source_file != NULL);
        ASSERT_EQ(parsed.type, JSON_NULL);
    } TEST_END
    json_free(&input); json_free(&parsed);
    if (!runtime_fixture_close(&fixture)) ++failures;
    return failures;
}
static int runtime_client_hup(void)
{
    int failures = 0; struct runtime_fixture fixture; runtime_fixture_init(&fixture);
    fixture.standalone = true;
    TEST_CASE("HOST standalone: established OpenSSH-style SIGHUP drains ordinary EOF into authenticated FIN") {
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_start_pair(&fixture)); ASSERT(runtime_target_ready(&fixture));
        ASSERT(runtime_byte_barrier(&fixture)); ASSERT(fixture.client.pid > 0);
        ASSERT_EQ(kill(fixture.client.pid, SIGHUP), 0);
        ASSERT(runtime_sparse_finish(&fixture));
        ASSERT(WIFEXITED(fixture.client.status)); ASSERT_EQ(WEXITSTATUS(fixture.client.status), 0);
        ASSERT(runtime_terminal(&fixture.client, "eof")); ASSERT(runtime_terminal(&fixture.receiver, "eof"));
        ASSERT(strstr(fixture.receiver.diagnostic_text, "accepted=1 completed=1 refused=0") != NULL);
        ASSERT(runtime_listener_closed(fixture.receiver_port));
    } TEST_END
    if (!runtime_fixture_close(&fixture)) ++failures;
    return failures;
}
static bool runtime_grace_activity(int input, int output, bool socket, uint64_t *seen)
{
    uint8_t byte = 0x33, bytes[64];
    ssize_t sent = send(input, &byte, 1, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (sent < 0 && errno != EAGAIN && errno != EINTR && errno != EPIPE) return false;
    ssize_t count = socket ? recv(output, bytes, sizeof(bytes), MSG_DONTWAIT) : read(output, bytes, sizeof(bytes));
    if (count < 0) return errno == EAGAIN || errno == EINTR;
    for (ssize_t i = 0; i < count; ++i) if (bytes[i] != byte) return false;
    *seen += (uint64_t)count; return true;
}
static bool runtime_repeat_hup(struct runtime_fixture *fixture, uint64_t seen[2], unsigned *signals)
{
    int64_t start = runtime_measure_now(), deadline = start + INT64_C(3000000000);
    if (start <= 0) return false;
    while (!runtime_process_poll(&fixture->client)) {
        int64_t now = runtime_measure_now();
        if (now < start || now >= deadline || fixture->client.pid <= 0 || fixture->client.custody_lost) return false;
        if (kill(fixture->client.pid, SIGHUP) != 0 && errno != ESRCH) return false;
        ++*signals;
        if (!runtime_grace_activity(fixture->client.input, fixture->target, true, &seen[0])) return false;
        if (!runtime_grace_activity(fixture->target, fixture->client.output, false, &seen[1])) return false;
        (void)poll(NULL, 0, 10);
    }
    int64_t end = runtime_measure_now();
    if (end < start) return false;
    fprintf(stderr, "HUP_GRACE_OBSERVATION elapsed_ns=%lld signals=%u target_bytes=%llu output_bytes=%llu\n",
        (long long)(end - start), *signals, (unsigned long long)seen[0], (unsigned long long)seen[1]);
    return true;
}
static int runtime_hup_kept_open(void)
{
    int failures = 0; struct runtime_fixture fixture; runtime_fixture_init(&fixture); fixture.standalone = true;
    uint64_t seen[2] = {0}; unsigned signals = 0;
    TEST_CASE("HOST standalone: kept-open streams and repeated HUP/activity cannot refresh graceful deadline") {
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_start_pair(&fixture)); ASSERT(runtime_target_ready(&fixture));
        ASSERT(runtime_byte_barrier(&fixture));
        /* Default idle/session are five/fifteen seconds: neither can satisfy
         * the three-second cleanup ceiling. No fixture EOF before terminal. */
        ASSERT(runtime_repeat_hup(&fixture, seen, &signals)); ASSERT(signals > 1);
        ASSERT(seen[0] > 0); ASSERT(seen[1] > 0);
        ASSERT(runtime_terminal(&fixture.client, "deadline"));
        size_t suffix = 0; ASSERT(runtime_drain_prefix(fixture.target, 0x33, &suffix));
        ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(runtime_listener_closed(fixture.receiver_port));
    } TEST_END
    if (!runtime_fixture_close(&fixture)) ++failures;
    return failures;
}
static int runtime_hup_priority(bool revoke)
{
    int failures = 0; struct runtime_fixture fixture; runtime_fixture_init(&fixture); fixture.standalone = true;
    TEST_CASE("HOST standalone: hard cancellation or current grant revocation wins during graceful HUP drain") {
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_start_pair(&fixture)); ASSERT(runtime_target_ready(&fixture));
        ASSERT(runtime_byte_barrier(&fixture)); ASSERT_EQ(kill(fixture.client.pid, SIGHUP), 0);
        ASSERT(runtime_byte_barrier(&fixture)); /* Actual post-HUP traffic, no app EOF. */
        if (revoke) ASSERT(runtime_revoke_row(&fixture, 0));
        else ASSERT_EQ(kill(fixture.client.pid, SIGTERM), 0);
        ASSERT(runtime_process_wait(&fixture.client, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(runtime_terminal(&fixture.client, revoke ? "refused" : "cancelled"));
        ASSERT(runtime_socket_eof(fixture.target));
        ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(runtime_listener_closed(fixture.receiver_port));
    } TEST_END
    if (!runtime_fixture_close(&fixture)) ++failures;
    return failures;
}
struct runtime_signal_scope { struct sigaction actions[3]; sigset_t mask; size_t saved; bool mask_saved; };
static const int runtime_signal_numbers[] = {SIGINT, SIGTERM, SIGHUP};
static bool runtime_signal_scope_restore(const struct runtime_signal_scope *scope)
{
    bool ok = true;
    for (size_t i = 0; i < scope->saved; ++i)
        if (sigaction(runtime_signal_numbers[i], &scope->actions[i], NULL) != 0) ok = false;
    if (scope->mask_saved && sigprocmask(SIG_SETMASK, &scope->mask, NULL) != 0) ok = false;
    return ok;
}
static bool runtime_signal_scope_open(struct runtime_signal_scope *scope)
{
    memset(scope, 0, sizeof(*scope));
    if (sigprocmask(SIG_SETMASK, NULL, &scope->mask) != 0) return false;
    scope->mask_saved = true; sigset_t blocked = scope->mask;
    struct sigaction ignored = {.sa_handler = SIG_IGN}; sigemptyset(&ignored.sa_mask);
    for (size_t i = 0; i < 3; ++i) {
        if (sigaction(runtime_signal_numbers[i], NULL, &scope->actions[i]) != 0) return false;
        ++scope->saved;
        if (sigaction(runtime_signal_numbers[i], &ignored, NULL) != 0) return false;
        sigaddset(&blocked, runtime_signal_numbers[i]);
    }
    return sigprocmask(SIG_SETMASK, &blocked, NULL) == 0;
}
static bool runtime_signal_scope_observed(const struct runtime_signal_scope *scope)
{
    sigset_t observed;
    if (sigprocmask(SIG_SETMASK, NULL, &observed) != 0) return false;
    for (size_t i = 0; i < 3; ++i) {
        struct sigaction action;
        if (sigaction(runtime_signal_numbers[i], NULL, &action) != 0 || action.sa_handler != SIG_IGN ||
            sigismember(&observed, runtime_signal_numbers[i]) != 1) return false;
    }
    for (int number = 1; number < NSIG; ++number) {
        bool owned = number == SIGINT || number == SIGTERM || number == SIGHUP;
        if (!owned && sigismember(&observed, number) != sigismember(&scope->mask, number)) return false;
    }
    return true;
}
static bool runtime_entry_signal_probe(const struct json_value *input, bool receiver)
{
    struct runtime_signal_scope scope; bool installed = runtime_signal_scope_open(&scope);
    enum device_host_runtime_entry_exit result = DEVICE_HOST_ENTRY_INVALID;
    if (installed) {
        struct zcl_result ran = device_host_runtime_entry_run(input, receiver, &result);
        if (!ran.ok && result == DEVICE_HOST_ENTRY_OK) result = DEVICE_HOST_ENTRY_FAILED;
    }
    bool observed = installed && runtime_signal_scope_observed(&scope);
    bool restored = runtime_signal_scope_restore(&scope);
    return observed && restored && result == DEVICE_HOST_ENTRY_FAILED;
}
static int runtime_hup_signal_restore(void)
{
    int failures = 0; struct runtime_fixture fixture; runtime_fixture_init(&fixture); struct json_value input = {0};
    TEST_CASE("HOST shared entry: receiver deadline restores prior ignored dispositions and blocked mask before assertions") {
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_input_receiver(&input, &fixture, 1));
        ASSERT(runtime_input_number(&input, "lifetime_ms", 1));
        ASSERT(runtime_entry_signal_probe(&input, true)); ASSERT(runtime_target_absent(&fixture));
    } TEST_END
    json_free(&input); if (!runtime_fixture_close(&fixture)) ++failures;
    return failures;
}
struct runtime_stdio_scope { int saved[2], flags[2], pipes[3][2]; };
static bool runtime_stdio_scope_open(struct runtime_stdio_scope *scope)
{
    *scope = (struct runtime_stdio_scope){.saved = {-1, -1}, .pipes = {{-1,-1},{-1,-1},{-1,-1}}};
    for (int i = 0; i < 2; ++i) {
        scope->saved[i] = fcntl(i, F_DUPFD_CLOEXEC, 3);
        if (scope->saved[i] < 0) return false;
    }
    if (!runtime_process_pipes(scope->pipes)) return false;
    if (dup2(scope->pipes[0][0], 0) < 0 || dup2(scope->pipes[1][1], 1) < 0) return false;
    for (int i = 0; i < 2; ++i) {
        scope->flags[i] = fcntl(i, F_GETFL);
        if (scope->flags[i] < 0 || (scope->flags[i] & O_NONBLOCK)) return false;
    }
    return true;
}
static bool runtime_stdio_scope_restore(struct runtime_stdio_scope *scope)
{
    bool ok = true;
    for (int i = 0; i < 2; ++i) {
        if (scope->saved[i] >= 0 && dup2(scope->saved[i], i) < 0) ok = false;
        runtime_test_close(&scope->saved[i]);
    }
    for (int i = 0; i < 3; ++i) { runtime_test_close(&scope->pipes[i][0]); runtime_test_close(&scope->pipes[i][1]); }
    return ok;
}
static bool runtime_entry_stdio_probe(const struct json_value *input)
{
    struct runtime_stdio_scope scope; bool opened = runtime_stdio_scope_open(&scope);
    bool signal_restored = opened && runtime_entry_signal_probe(input, false);
    bool flags_restored = opened && fcntl(0, F_GETFL) == scope.flags[0] && fcntl(1, F_GETFL) == scope.flags[1];
    bool restored = runtime_stdio_scope_restore(&scope);
    return signal_restored && flags_restored && restored;
}
static int runtime_hup_stdio_restore(void)
{
    int failures = 0, route = -1; struct runtime_fixture fixture; runtime_fixture_init(&fixture);
    struct json_value input = {0}; uint16_t port = 0;
    TEST_CASE("HOST shared entry: client refused route restores signal rail and inherited blocking stdio OFD flags") {
        ASSERT(runtime_fixture_open(&fixture)); route = runtime_closed_route(&port); ASSERT(route >= 0);
        fixture.receiver_port = port; ASSERT(runtime_input_client(&input, &fixture));
        ASSERT(runtime_entry_stdio_probe(&input)); ASSERT(runtime_target_absent(&fixture));
    } TEST_END
    runtime_test_close(&route); json_free(&input); if (!runtime_fixture_close(&fixture)) ++failures;
    return failures;
}
static int runtime_sparse_measurement(void)
{
    int failures = 0; struct runtime_fixture fixture; runtime_fixture_init(&fixture);
    struct runtime_sparse_sample samples[32] = {0}; int64_t setup_start = runtime_measure_now();
    TEST_CASE("HOST runtime: sparse actual-binary exact byte RTT observations, no performance threshold") {
        ASSERT(setup_start > 0);
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_start_pair(&fixture)); ASSERT(runtime_target_ready(&fixture));
        ASSERT(runtime_byte_barrier(&fixture)); int64_t setup_end = runtime_measure_now(); ASSERT(setup_end >= setup_start);
        int64_t setup = setup_end - setup_start;
        int64_t previous = setup_end; const int gaps[] = {37, 53, 71};
        for (unsigned i = 0; i < 32; ++i) {
            ASSERT_EQ(poll(NULL, 0, gaps[i % 3]), 0);
            ASSERT(runtime_sparse_echo(&fixture, i, &samples[i], previous)); previous = samples[i].end;
        }
        ASSERT(runtime_sparse_finish(&fixture)); runtime_sparse_report(samples, setup, &fixture);
    } TEST_END
    if (!runtime_fixture_close(&fixture)) ++failures;
    return failures;
}
static bool runtime_package_input(struct json_value *input)
{
    static const char hex[] = "1111111111111111111111111111111111111111111111111111111111111111";
    static const char runtime[] = "{\"directory\":\"/PUBLIC-unopened\",\"peer_key\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"expected_root\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"target_port\":22,\"route_id\":\"PUBLIC\",\"handshake_ms\":1000,\"session_ms\":5000,\"idle_ms\":1000,\"confirm\":true,\"route_address\":\"127.0.0.1\",\"route_port\":22,\"connect_ms\":1000}";
    json_set_object(input);
    bool identity = json_push_kv_str(input, "datadir", "/PUBLIC-unopened") &&
        json_push_kv_str(input, "package_root", hex) && json_push_kv_str(input, "receipt_id", hex) &&
        json_push_kv_str(input, "artifact_sha3", hex);
    bool approval = json_push_kv_bool(input, "accept_execution", true) &&
        json_push_kv_str(input, "runtime_policy", "host_os") && json_push_kv_str(input, "role", "client");
    return identity && approval && json_push_kv_str(input, "runtime_input", runtime) &&
        json_push_kv_int(input, "launch_ms", 1000) && json_push_kv_int(input, "execution_ms", 5000) &&
        json_push_kv_int(input, "cleanup_ms", 1000);
}

static int runtime_package_approval(void)
{
    int failures = 0; struct json_value input = {0};
    TEST_CASE("device_host_runtime: installed input explicit host approval and role") {
        ASSERT(runtime_package_input(&input));
        ASSERT(zcl_native_device_host_package_input_for_test(&input));
        struct json_value *field = (struct json_value *)json_get(&input, "accept_execution");
        json_set_bool(field, false); ASSERT(!zcl_native_device_host_package_input_for_test(&input));
        json_set_null(field); ASSERT(!zcl_native_device_host_package_input_for_test(&input));
        json_set_bool(field, true);
        field = (struct json_value *)json_get(&input, "runtime_policy");
        json_set_str(field, "confined"); ASSERT(!zcl_native_device_host_package_input_for_test(&input));
        json_set_str(field, "host_os");
        field = (struct json_value *)json_get(&input, "role");
        json_set_str(field, "shell"); ASSERT(!zcl_native_device_host_package_input_for_test(&input));
        json_set_str(field, "client");
        field = (struct json_value *)json_get(&input, "datadir");
        json_set_str(field, "relative"); ASSERT(!zcl_native_device_host_package_input_for_test(&input));
    } TEST_END
    json_free(&input); return failures;
}

static int runtime_package_types(void)
{
    int failures = 0; struct json_value input = {0};
    const char *const keys[] = {"launch_ms", "execution_ms", "cleanup_ms"};
    const int64_t maximum[] = {10000, 600000, 10000};
    TEST_CASE("device_host_runtime: installed leaf duration types and exact limits") {
        ASSERT(runtime_package_input(&input));
        const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(),
            "ops.mesh.device.host.package.run", NULL);
        ASSERT(spec); char why[160];
        ASSERT(zcl_command_registry_input_validate(spec, &input, why, sizeof(why)));
        for (size_t i = 0; i < 3; ++i) {
            struct json_value *field = (struct json_value *)json_get(&input, keys[i]);
            json_set_int(field, 1); ASSERT(zcl_command_registry_input_validate(spec, &input, why, sizeof(why)));
            json_set_int(field, maximum[i]); ASSERT(zcl_command_registry_input_validate(spec, &input, why, sizeof(why)));
            const int64_t bad[] = {0, -1, maximum[i] + 1, INT64_MAX};
            for (size_t j = 0; j < sizeof(bad) / sizeof(bad[0]); ++j) {
                json_set_int(field, bad[j]); ASSERT(!zcl_command_registry_input_validate(spec, &input, why, sizeof(why)));
            }
            json_set_real(field, 1.5); ASSERT(!zcl_command_registry_input_validate(spec, &input, why, sizeof(why)));
            json_set_real(field, NAN); ASSERT(!zcl_command_registry_input_validate(spec, &input, why, sizeof(why)));
            json_set_real(field, INFINITY); ASSERT(!zcl_command_registry_input_validate(spec, &input, why, sizeof(why)));
            json_set_str(field, "1"); ASSERT(!zcl_command_registry_input_validate(spec, &input, why, sizeof(why)));
            json_set_int(field, 1000);
        }
        struct json_value *accept = (struct json_value *)json_get(&input, "accept_execution");
        json_set_str(accept, "true"); ASSERT(!zcl_command_registry_input_validate(spec, &input, why, sizeof(why)));
    } TEST_END
    json_free(&input); return failures;
}

static int64_t runtime_package_time(void *opaque)
{
    return *(const int64_t *)opaque;
}

static int runtime_package_terminal_bound(void)
{
    int failures = 0; const int64_t times[] = {49, 50, 51, 0, -1}; bool accepted[5];
    const clock_iface_t *prior = clock_default(); int64_t now = 0;
    const clock_iface_t fake = {.now_monotonic_ns = runtime_package_time, .now_wall_ms = runtime_package_time, .self = &now};
    clock_set_default(&fake);
    for (size_t i = 0; i < 5; ++i) { now = times[i]; accepted[i] = zcl_native_device_host_package_terminal_for_test(50); }
    clock_set_default(prior);
    TEST_CASE("device_host_runtime: observed CLEAN never overrides expired owner deadline") {
        ASSERT(accepted[0]);
        for (size_t i = 1; i < 5; ++i) ASSERT(!accepted[i]);
    } TEST_END
    return failures;
}

static int runtime_typed_outputs(void)
{
    int failures = 0;
    struct device_host_runtime_client_spec client = {0}, before_client = client;
    struct device_host_runtime_receiver_spec receiver = {0}, before_receiver = receiver;
    struct json_value input = {0};
    TEST_CASE("HOST typed runtime: aliased observations and exit status refuse before effects") {
        struct zcl_result result = device_host_runtime_client_run(&client,
            (struct device_host_runtime_observation *)&client);
        ASSERT(!result.ok); ASSERT(!memcmp(&client, &before_client, sizeof(client)));
        result = device_host_runtime_receiver_run(&receiver,
            (struct device_host_runtime_observation *)&receiver);
        ASSERT(!result.ok); ASSERT(!memcmp(&receiver, &before_receiver, sizeof(receiver)));
        result = device_host_runtime_entry_run(&input, false, (enum device_host_runtime_entry_exit *)&input.type);
        ASSERT(!result.ok); ASSERT_EQ(input.type, JSON_NULL);
        enum device_host_runtime_entry_exit status;
        result = device_host_runtime_entry_run(&input, false, &status);
        ASSERT(!result.ok); ASSERT_EQ(status, DEVICE_HOST_ENTRY_INVALID); ASSERT(result.message[0]);
    } TEST_END
    json_free(&input); return failures;
}
/* One unauthenticated carrier: connect, optionally send garbage, half-close, and wait for the
 * receiver to close its side, so the flood is serialized without any wall-clock pacing. */
static bool runtime_junk_connect(uint16_t port, unsigned kind)
{
    int fd = runtime_route_connect(port); if (fd < 0) return false;
    static const uint8_t garbage[48] = {0xde, 0xad, 0xbe, 0xef, 1, 2, 3};
    bool ok = kind % 3 == 0 || send(fd, garbage, kind % 3 == 1 ? 1 : sizeof(garbage), MSG_NOSIGNAL) > 0;
    ok = ok && shutdown(fd, SHUT_WR) == 0 && runtime_socket_eof(fd);
    close(fd); return ok;
}
static bool runtime_junk_flood(struct runtime_process *receiver, uint16_t port, unsigned count)
{
    for (unsigned i = 0; i < count; ++i) {
        if (!runtime_junk_connect(port, i)) { fprintf(stderr, "junk connect %u failed errno=%d\n", i, errno); return false; }
        /* Each refused carrier logs one line; discard so the bounded capture keeps the terminal line. */
        if (!runtime_diagnostics(receiver)) return false;
        receiver->diagnostic_used = 0;
    }
    return true;
}
static int runtime_preauth_slots(unsigned sessions, unsigned junk, bool flood)
{
    int failures = 0; struct runtime_fixture fixture; runtime_fixture_init(&fixture); struct json_value input = {0};
    TEST_CASE("HOST runtime: unauthenticated connects never consume session slots; pre-auth flood ceiling closes listener") {
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_input_receiver(&input, &fixture, sessions));
        ASSERT(runtime_process_start(&fixture.receiver, &fixture, &input, true, false)); ASSERT(runtime_wait_receiver(&fixture));
        json_free(&input);
        ASSERT(runtime_junk_flood(&fixture.receiver, fixture.receiver_port, junk));
        if (flood) {
            ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(3000000000)));
            ASSERT(WIFEXITED(fixture.receiver.status)); ASSERT(WEXITSTATUS(fixture.receiver.status) != 0);
            ASSERT(runtime_terminal(&fixture.receiver, "refused"));
            ASSERT(strstr(fixture.receiver.diagnostic_text, "accepted=0 completed=0") != NULL);
            ASSERT(strstr(fixture.receiver.diagnostic_text, "preauth_refused=256") != NULL);
            ASSERT(runtime_listener_closed(fixture.receiver_port)); ASSERT(runtime_target_absent(&fixture));
        } else {
            ASSERT(runtime_input_client(&input, &fixture));
            ASSERT(runtime_process_start(&fixture.client, &fixture, &input, false, false));
            ASSERT(runtime_roundtrip(&fixture, 7));
            ASSERT(runtime_process_wait(&fixture.client, clock_now_monotonic_ns() + INT64_C(3000000000)));
            ASSERT(WIFEXITED(fixture.client.status)); ASSERT_EQ(WEXITSTATUS(fixture.client.status), 0);
            if (sessions == 1) {
                ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(3000000000)));
                ASSERT(runtime_terminal(&fixture.receiver, "eof"));
                char expected[64];
                snprintf(expected, sizeof(expected), "accepted=1 completed=1 refused=%u", junk);
                ASSERT(strstr(fixture.receiver.diagnostic_text, expected) != NULL);
            } else {
                ASSERT_EQ(kill(fixture.receiver.pid, SIGTERM), 0);
                ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(3000000000)));
                ASSERT(runtime_terminal(&fixture.receiver, "cancelled"));
                char expected[64];
                snprintf(expected, sizeof(expected), "accepted=1 completed=");
                ASSERT(strstr(fixture.receiver.diagnostic_text, expected) != NULL);
                snprintf(expected, sizeof(expected), "preauth_refused=%u", junk);
                ASSERT(strstr(fixture.receiver.diagnostic_text, expected) != NULL);
            }
        }
    } TEST_END
    json_free(&input); if (!runtime_fixture_close(&fixture)) ++failures; return failures;
}
static bool runtime_send_confirm(int carrier, struct device_host_psk_session *session)
{
    enum device_host_psk_result status; struct device_pairing_guard guard = {0}; const uint8_t *bytes; size_t length;
    struct zcl_result acquired = device_host_psk_pending_acquire(session, &guard, &bytes, &length, &status);
    if (!acquired.ok) return false;
    ssize_t sent = send(carrier, bytes, length, MSG_DONTWAIT | MSG_NOSIGNAL);
    struct zcl_result result = device_host_psk_pending_written(session, &guard, sent > 0 ? (size_t)sent : 0, &status);
    return sent > 0 && (size_t)sent == length && result.ok;
}
static int runtime_session_cap_before_target(void)
{
    enum { CLIENTS = 3 };
    int failures = 0, carrier[CLIENTS] = {-1, -1, -1}; struct runtime_fixture fixture; runtime_fixture_init(&fixture);
    struct json_value input = {0}; struct device_host_psk_session session[CLIENTS];
    for (int i = 0; i < CLIENTS; ++i) device_host_psk_init(&session[i]);
    TEST_CASE("HOST runtime: sessions over max_sessions are refused at PSK success before any target connection") {
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_input_receiver(&input, &fixture, 1));
        ASSERT(runtime_input_number(&input, "max_active", CLIENTS));
        ASSERT(runtime_process_start(&fixture.receiver, &fixture, &input, true, false)); ASSERT(runtime_wait_receiver(&fixture));
        for (int i = 0; i < CLIENTS; ++i) {
            carrier[i] = runtime_route_connect(fixture.receiver_port); ASSERT(carrier[i] >= 0);
            ASSERT(runtime_send_hello(&fixture, carrier[i], &session[i]));
        }
        for (int i = 0; i < CLIENTS; ++i) ASSERT(runtime_receive_hello(carrier[i], &session[i]));
        /* All three are authenticated-capable and pending at once; confirm back to back. */
        for (int i = 0; i < CLIENTS; ++i) ASSERT(runtime_send_confirm(carrier[i], &session[i]));
        unsigned refused = 0;
        for (int i = 0; i < CLIENTS; ++i) if (runtime_socket_eof(carrier[i])) ++refused;
        ASSERT_EQ(refused, CLIENTS - 1u);
        ASSERT(runtime_target_ready(&fixture)); /* exactly one session reached the target */
        struct sockaddr_in address; size_t size = sizeof(address);
        int extra = platform_socket_accept(fixture.target_listener, (struct sockaddr *)&address, &size);
        ASSERT(extra < 0); if (extra >= 0) close(extra);
        ASSERT_EQ(kill(fixture.receiver.pid, SIGTERM), 0);
        ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(runtime_terminal(&fixture.receiver, "cancelled")); /* cancel flag wins over the drained loop */
        ASSERT(strstr(fixture.receiver.diagnostic_text, "accepted=1 ") != NULL);
    } TEST_END
    for (int i = 0; i < CLIENTS; ++i) { device_host_psk_destroy(&session[i]); runtime_test_close(&carrier[i]); }
    json_free(&input); if (!runtime_fixture_close(&fixture)) ++failures; return failures;
}
static int runtime_restart_rebind(void)
{
    int failures = 0, silent = -1; struct runtime_fixture fixture; runtime_fixture_init(&fixture);
    struct json_value input = {0};
    TEST_CASE("HOST runtime: receiver rebinds its exact port at once after a busy run left TIME_WAIT") {
        ASSERT(runtime_fixture_open(&fixture)); ASSERT(runtime_input_receiver(&input, &fixture, 1));
        ASSERT(runtime_input_number(&input, "handshake_ms", 300));
        ASSERT(runtime_process_start(&fixture.receiver, &fixture, &input, true, false));
        ASSERT(runtime_wait_receiver(&fixture));
        /* The receiver closes the silent carrier first, so its side holds TIME_WAIT on the listen port. */
        silent = runtime_route_connect(fixture.receiver_port); ASSERT(silent >= 0);
        ASSERT(runtime_socket_eof(silent)); runtime_test_close(&silent);
        uint16_t port = fixture.receiver_port; ASSERT(fixture.receiver.pid > 0);
        ASSERT_EQ(kill(fixture.receiver.pid, SIGTERM), 0);
        ASSERT(runtime_process_wait(&fixture.receiver, clock_now_monotonic_ns() + INT64_C(3000000000)));
        ASSERT(runtime_process_cleanup(&fixture.receiver)); runtime_process_init(&fixture.receiver);
        json_free(&input); ASSERT(runtime_input_receiver(&input, &fixture, 1));
        struct json_value *listen_port = (struct json_value *)json_get(&input, "listen_port");
        ASSERT(listen_port != NULL); json_set_int(listen_port, port);
        ASSERT(runtime_process_start(&fixture.receiver, &fixture, &input, true, false));
        ASSERT(runtime_wait_receiver(&fixture)); ASSERT_EQ(fixture.receiver_port, port);
    } TEST_END
    runtime_test_close(&silent); json_free(&input);
    if (!runtime_fixture_close(&fixture)) ++failures;
    return failures;
}
static int runtime_long_caps_revoke(void)
{
    /* Whole pair runs at the hard maxima (24 h lifetime, 8 h session, 30 min idle):
     * a mid-session revoke must still end the session, so long sessions never outlive revocation. */
    runtime_long_caps = true;
    int failures = runtime_completed_revoke(false) + runtime_completed_revoke(true);
    runtime_long_caps = false; return failures;
}
static bool runtime_limit_wire(bool receiver, const char *key, int64_t value, char wire[8192])
{
    struct runtime_fixture fixture; runtime_fixture_init(&fixture); struct json_value input = {0};
    fixture.receiver_port = 1;
    bool ok = runtime_fixture_open(&fixture) && (receiver ? runtime_input_receiver(&input, &fixture, 1) : runtime_input_client(&input, &fixture)) &&
        runtime_input_number(&input, key, value) && json_write(&input, wire, 8192) > 0;
    json_free(&input); return runtime_fixture_close(&fixture) && ok;
}
static bool runtime_limit_accepted(bool receiver, const char *key, int64_t value)
{
    char wire[8192]; struct json_value parsed = {0};
    if (!runtime_limit_wire(receiver, key, value, wire)) return false;
    bool ok = device_host_runtime_entry_parse(&parsed, wire, strlen(wire), receiver).ok; json_free(&parsed); return ok;
}
static int runtime_long_caps_limits(void)
{
    int failures = 0;
    TEST_CASE("HOST shared entry: supervised-hub maxima are accepted, maxima plus one refuse, prior values stay valid") {
        for (int role = 0; role < 2; ++role) {
            bool receiver = role != 0;
            ASSERT(runtime_limit_accepted(receiver, "session_ms", 600000));
            ASSERT(runtime_limit_accepted(receiver, "idle_ms", 60000));
            ASSERT(runtime_limit_accepted(receiver, "session_ms", 28800000));
            ASSERT(!runtime_limit_accepted(receiver, "session_ms", 28800001));
            ASSERT(runtime_limit_accepted(receiver, "idle_ms", 1800000));
            ASSERT(!runtime_limit_accepted(receiver, "idle_ms", 1800001));
        }
        ASSERT(runtime_limit_accepted(true, "lifetime_ms", 600000));
        ASSERT(runtime_limit_accepted(true, "lifetime_ms", 86400000));
        ASSERT(!runtime_limit_accepted(true, "lifetime_ms", 86400001));
        ASSERT(runtime_limit_accepted(true, "max_sessions", 64)); ASSERT(!runtime_limit_accepted(true, "max_sessions", 65));
        ASSERT(runtime_limit_accepted(true, "max_active", 4)); ASSERT(!runtime_limit_accepted(true, "max_active", 5));
    } TEST_END
    return failures;
}
int test_device_host_runtime(void);
int test_device_host_runtime(void)
{
    int failures = runtime_typed_outputs() + runtime_binary_sessions(false) + runtime_raw_refusals(false) +
        runtime_binary_sessions(true) + runtime_raw_refusals(true) + runtime_hub_hop() +
        runtime_hub_connect(false) + runtime_hub_connect(true);
    for (unsigned field = 0; field < 3; ++field)
        failures += runtime_client_authority_refusal(field);
    for (unsigned fault = 0; fault < 6; ++fault)
        failures += runtime_entry_parser(fault);
    return failures + runtime_package_approval() + runtime_package_types() + runtime_package_terminal_bound() + runtime_truncated_handshake() + runtime_receiver_cancel(SIGTERM) + runtime_receiver_cancel(SIGHUP) +
        runtime_wrong_secret() + runtime_unconfirmed_hello() +
        runtime_completed_revoke(false) + runtime_completed_revoke(true) + runtime_client_cancel() +
        runtime_fresh_backup() + runtime_handshake_deadline() + runtime_idle_deadline() +
        runtime_during_traffic_revoke() + runtime_named_handshake_deadline(false) + runtime_named_handshake_deadline(true) + runtime_multi_active_deadline() + runtime_client_hup() +
        runtime_hup_kept_open() + runtime_hup_priority(false) + runtime_hup_priority(true) + runtime_hup_signal_restore() + runtime_hup_stdio_restore() + runtime_sparse_measurement() +
        runtime_preauth_slots(1, 3, false) + runtime_preauth_slots(64, 70, false) + runtime_preauth_slots(1, 256, true) + runtime_session_cap_before_target() + runtime_restart_rebind() + runtime_long_caps_limits() + runtime_long_caps_revoke();
}
#elif defined(__APPLE__)
int host_runtime_darwin_cases(void);
int test_device_host_runtime(void);
int test_device_host_runtime(void)
{
    return host_runtime_darwin_cases();
}
#else
int test_device_host_runtime(void);
int test_device_host_runtime(void)
{
    struct device_host_runtime_observation observation;
    struct zcl_result result = device_host_runtime_client_run(NULL, &observation);
    return !result.ok && observation.result == DEVICE_HOST_BRIDGE_UNSUPPORTED ? 0 : 1;
}
#endif
