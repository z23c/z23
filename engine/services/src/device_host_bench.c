/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: in-process PSK tunnel throughput over a throwaway paired authority.
 * // supervisor-ok:foreground-bounded-bench -- one finite measurement that joins every thread it starts; no resident service. */
#include "services/device_host_bench.h"
#include "services/device_host_bridge.h"
#include "platform/clock.h"
#include "util/file_tree_ops.h"
#include "platform/private_directory.h"
#include "util/log_macros.h"
#include <string.h>

double device_host_bench_median(const double *values, size_t count)
{
    double sorted[DEVICE_HOST_BENCH_REPEATS_MAX];
    if (!values || count == 0 || count > DEVICE_HOST_BENCH_REPEATS_MAX) return 0.0;
    for (size_t i = 0; i < count; ++i) {
        size_t at = i;
        while (at > 0 && sorted[at - 1] > values[i]) { sorted[at] = sorted[at - 1]; --at; }
        sorted[at] = values[i];
    }
    return count % 2 ? sorted[count / 2] : (sorted[count / 2 - 1] + sorted[count / 2]) / 2.0;
}

#if defined(__linux__) || defined(__APPLE__)
#include "platform/socket_compat.h"
#include "base/safe_alloc.h"
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

enum { BENCH_PATTERN = 65536 };
struct bench_pump { int fd; size_t total, moved; const uint8_t *pattern; int64_t window_ns; bool ok; };
struct bench_fixture {
    char directory[2][PLATFORM_TEMP_PATH_MAX + 16];
    struct device_pairing_store store[2];
    struct db_device_pairing row[2];
    uint8_t root[2][32];
    struct device_host_psk_bridge client, server;
    struct device_host_psk_bridge_spec client_spec, server_spec;
    int carrier[2], plain[2], listener, target;
    uint16_t port;
    atomic_bool cancelled;
};
/* Pairing rows are valid at 100..200 s wall; the virtual wall clock stays at 150 s
 * while the monotonic source is the real one, as the bridge test does. */
static const clock_iface_t *bench_previous;
static int64_t bench_mono(void *self) { (void)self; return bench_previous->now_monotonic_ns(bench_previous->self); }
static int64_t bench_wall(void *self) { (void)self; return 150000; }

static bool bench_poll(int fd, short events)
{
    struct pollfd event = {.fd = fd, .events = events};
    int ready = poll(&event, 1, 100);
    return ready >= 0 || errno == EINTR;
}
static void *bench_run_bridge(void *opaque)
{
    enum device_host_bridge_result status;
    (void)device_host_psk_bridge_run(opaque, &status);
    return NULL;
}
static void *bench_write(void *opaque)
{
    struct bench_pump *pump = opaque; int64_t deadline = clock_now_monotonic_ns() + pump->window_ns;
    while (pump->moved < pump->total && clock_now_monotonic_ns() < deadline) {
        size_t offset = pump->moved % BENCH_PATTERN, size = BENCH_PATTERN - offset;
        if (size > pump->total - pump->moved) size = pump->total - pump->moved;
        ssize_t n = send(pump->fd, pump->pattern + offset, size, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n > 0) pump->moved += (size_t)n;
        else if ((n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) ||
            !bench_poll(pump->fd, POLLOUT)) return NULL;
    }
    pump->ok = pump->moved == pump->total && shutdown(pump->fd, SHUT_WR) == 0;
    return NULL;
}
static bool bench_read_loop(int fd, size_t total, const uint8_t *pattern, int64_t window_ns, uint8_t *buffer)
{
    size_t seen = 0; int64_t deadline = clock_now_monotonic_ns() + window_ns;
    while (clock_now_monotonic_ns() < deadline) {
        size_t offset = seen % BENCH_PATTERN;
        ssize_t n = recv(fd, buffer, BENCH_PATTERN - offset, MSG_DONTWAIT);
        if (n == 0) return seen == total;
        if (n > 0) {
            if (memcmp(buffer, pattern + offset, (size_t)n)) return false;
            seen += (size_t)n;
        } else if ((errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) || !bench_poll(fd, POLLIN)) return false;
    }
    return false;
}
static bool bench_read(int fd, size_t total, const uint8_t *pattern, int64_t window_ns)
{
    uint8_t *buffer = zcl_malloc(BENCH_PATTERN, "tunnel_bench_read");
    if (!buffer) return false;
    bool ok = bench_read_loop(fd, total, pattern, window_ns, buffer);
    free(buffer);
    return ok;
}
static bool bench_direction(int source, int destination, size_t total, const uint8_t *pattern,
    int64_t window_ns, double *mib_per_s)
{
    struct bench_pump pump = {.fd = source, .total = total, .pattern = pattern, .window_ns = window_ns};
    pthread_t writer; int64_t start = clock_now_monotonic_ns();
    /* raw-pthread-ok: foreground pump joined before the direction returns */
    if (pthread_create(&writer, NULL, bench_write, &pump)) return false;
    bool ok = bench_read(destination, total, pattern, window_ns);
    int64_t elapsed = clock_now_monotonic_ns() - start;
    pthread_join(writer, NULL);
    *mib_per_s = elapsed > 0 ? ((double)total / 1048576.0) / ((double)elapsed / 1e9) : 0.0;
    return ok && pump.ok;
}
static bool bench_listener(struct bench_fixture *f)
{
    f->listener = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    if (f->listener < 0) return false;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t size = sizeof(address);
    if (bind(f->listener, (const struct sockaddr *)&address, sizeof(address)) < 0 || listen(f->listener, 1) < 0 ||
        getsockname(f->listener, (struct sockaddr *)&address, &size) < 0) return false;
    f->port = ntohs(address.sin_port);
    return true;
}
static bool bench_pair(int pair[2])
{
    if (!platform_socket_pair(pair)) return false;
    for (size_t i = 0; i < 2; ++i)
        if (fcntl(pair[i], F_SETFD, FD_CLOEXEC) != 0 || !platform_socket_set_nonblocking(pair[i], true)) return false;
    return true;
}
static void bench_fixture_close(struct bench_fixture *f)
{
    device_host_psk_bridge_close(&f->client, DEVICE_HOST_BRIDGE_CANCELLED);
    device_host_psk_bridge_close(&f->server, DEVICE_HOST_BRIDGE_CANCELLED);
    const int descriptors[] = {f->carrier[0], f->carrier[1], f->plain[0], f->plain[1], f->listener, f->target};
    for (size_t i = 0; i < sizeof(descriptors) / sizeof(descriptors[0]); ++i) if (descriptors[i] >= 0) close(descriptors[i]);
}
/* One paired authority per side inside the private temp root; the PSK secret is a fixed
 * throwaway that never leaves this process and pairs nothing real. */
static bool bench_fixture_open(struct bench_fixture *f, const char *root, unsigned index, int64_t window_ns)
{
    memset(f, 0, sizeof(*f)); f->carrier[0] = f->carrier[1] = f->plain[0] = f->plain[1] = f->listener = f->target = -1;
    atomic_init(&f->cancelled, false);
    device_host_psk_bridge_init(&f->client); device_host_psk_bridge_init(&f->server);
    if (!bench_listener(f) || !bench_pair(f->carrier) || !bench_pair(f->plain)) return false;
    for (size_t i = 0; i < 2; ++i) {
        if (snprintf(f->directory[i], sizeof(f->directory[i]), "%s/run%u%c", root, index, i ? 'b' : 'a') <= 0 ||
            !platform_private_directory_create(f->directory[i])) return false;
        struct db_device_pairing *row = &f->row[i];
        *row = (struct db_device_pairing){.profile = {1}, .paired_at = 100, .expires_at = 200, .capabilities = DEVICE_PAIRING_CAP_HOST_FORWARD};
        row->local_key[0] = i ? 3 : 2; row->peer_key[0] = i ? 2 : 3;
        row->host_scope.inbound_port = row->host_scope.outbound_port = f->port;
        row->host_scope.binding.backend_profile = DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK;
        struct device_pairing_psk_binding *binding = &row->host_scope.binding.psk;
        binding->credential_id[0] = 91; binding->key_epoch = 1; binding->endpoint_a[0] = 2; binding->endpoint_b[0] = 3;
        uint8_t secret[32] = {17}, proposal[32];
        struct device_pairing_psk_publication report; struct db_device_pairing found;
        if (!device_pairing_store_open(&f->store[i], f->directory[i], row->profile, row->local_key) ||
            !device_pairing_host_proposal_root(row, proposal) ||
            !db_device_pairing_insert_host_psk(&f->store[i], row, secret, proposal, &report) ||
            !db_device_pairing_inspect(&f->store[i], row->peer_key, &found, f->root[i])) return false;
    }
    int64_t deadline = clock_now_monotonic_ns() + 2 * window_ns + INT64_C(60000000000);
    struct device_host_psk_spec c = {.store = &f->store[0], .direction = DEVICE_PAIRING_HOST_OUTBOUND,
        .port = f->port, .deadline_ns = deadline, .cancelled = &f->cancelled};
    struct device_host_psk_spec s = c; s.store = &f->store[1]; s.direction = DEVICE_PAIRING_HOST_INBOUND;
    memcpy(c.peer, f->row[0].peer_key, 32); memcpy(c.approved_root, f->root[0], 32);
    memcpy(s.peer, f->row[1].peer_key, 32); memcpy(s.approved_root, f->root[1], 32);
    f->client_spec = (struct device_host_psk_bridge_spec){.session = c, .carrier_input_fd = f->carrier[0], .carrier_output_fd = f->carrier[0],
        .input_fd = f->plain[1], .output_fd = f->plain[1]};
    f->server_spec = (struct device_host_psk_bridge_spec){.session = s, .carrier_input_fd = f->carrier[1], .carrier_output_fd = f->carrier[1],
        .input_fd = -1, .output_fd = -1};
    return true;
}
static bool bench_step(struct device_host_psk_bridge *bridge, enum device_host_bridge_result *status)
{
    *status = DEVICE_HOST_BRIDGE_REFUSED;
    return device_host_psk_bridge_step(bridge, status).ok &&
        (*status == DEVICE_HOST_BRIDGE_PROGRESS || *status == DEVICE_HOST_BRIDGE_WAIT);
}
static bool bench_admit(struct bench_fixture *f)
{
    enum device_host_bridge_result c = DEVICE_HOST_BRIDGE_REFUSED, s = DEVICE_HOST_BRIDGE_REFUSED;
    bool client_ok = device_host_psk_bridge_open(&f->client, &f->client_spec, &c).ok;
    if (f->client.observation.io_taken) { f->carrier[0] = -1; f->plain[1] = -1; }
    bool server_ok = device_host_psk_bridge_open(&f->server, &f->server_spec, &s).ok;
    if (f->server.observation.io_taken) f->carrier[1] = -1;
    return client_ok && server_ok && c == DEVICE_HOST_BRIDGE_READY && s == DEVICE_HOST_BRIDGE_READY;
}
static bool bench_ready(struct bench_fixture *f)
{
    int64_t deadline = clock_now_monotonic_ns() + INT64_C(10000000000);
    while (clock_now_monotonic_ns() < deadline) {
        enum device_host_bridge_result c, s;
        if (!bench_step(&f->client, &c) || !bench_step(&f->server, &s)) return false;
        if (f->target < 0) {
            f->target = accept(f->listener, NULL, NULL);
            if (f->target >= 0 && (fcntl(f->target, F_SETFD, FD_CLOEXEC) != 0 || !platform_socket_set_nonblocking(f->target, true))) return false;
            if (f->target < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return false;
        }
        if (f->client.session.phase == DEVICE_HOST_PSK_ESTABLISHED && f->server.session.phase == DEVICE_HOST_PSK_ESTABLISHED)
            return f->target >= 0 && f->server.observation.target_connected;
        (void)poll(NULL, 0, 1);
    }
    return false;
}
static bool bench_once(struct bench_fixture *f, size_t total, const uint8_t *pattern, struct device_host_bench_run *run)
{
    int64_t window_ns = INT64_C(30000000000) + (int64_t)(total >> 20) * INT64_C(250000000);
    if (!bench_admit(f) || !bench_ready(f)) return false;
    uint64_t full0 = 0, cached0 = 0, full1 = 0, cached1 = 0;
    device_pairing_guard_counts(&full0, &cached0);
    pthread_t client, server;
    /* raw-pthread-ok: bridge poll loops joined before the run returns */
    if (pthread_create(&client, NULL, bench_run_bridge, &f->client)) return false;
    /* raw-pthread-ok: bridge poll loops joined before the run returns */
    if (pthread_create(&server, NULL, bench_run_bridge, &f->server)) {
        atomic_store(&f->cancelled, true); pthread_join(client, NULL); return false;
    }
    bool forward_ok = bench_direction(f->plain[0], f->target, total, pattern, window_ns, &run->forward_mib_s);
    bool reverse_ok = forward_ok && bench_direction(f->target, f->plain[0], total, pattern, window_ns, &run->reverse_mib_s);
    if (!reverse_ok) atomic_store(&f->cancelled, true);
    pthread_join(client, NULL); pthread_join(server, NULL);
    device_pairing_guard_counts(&full1, &cached1);
    run->records = 2 * ((total + 4095) / 4096);
    run->full_acquisitions = full1 - full0; run->cached_acquisitions = cached1 - cached0;
    return reverse_ok && f->client.observation.result == DEVICE_HOST_BRIDGE_EOF &&
        f->server.observation.result == DEVICE_HOST_BRIDGE_EOF;
}

static struct zcl_result bench_repeats(struct device_host_bench_result *out)
{
    uint8_t *pattern = zcl_malloc(BENCH_PATTERN, "tunnel_bench_pattern");
    struct bench_fixture *fixture = zcl_malloc(sizeof(*fixture), "tunnel_bench_fixture");
    struct zcl_result result = ZCL_OK;
    if (!pattern || !fixture) result = ZCL_ERR(-4, "tunnel bench: out of memory");
    else {
        for (size_t i = 0; i < BENCH_PATTERN; ++i) pattern[i] = (uint8_t)(i * 131u + (i >> 9));
        bench_previous = clock_default();
        clock_iface_t clock = {bench_mono, bench_wall, NULL};
        clock_set_default(&clock);
        for (unsigned i = 0; i < out->repeats && result.ok; ++i) {
            bool ok = bench_fixture_open(fixture, out->profile_root, i, INT64_C(30000000000)) &&
                bench_once(fixture, out->mib << 20, pattern, &out->runs[i]);
            bench_fixture_close(fixture);
            if (!ok) result = ZCL_ERR(-5, "tunnel bench: run %u failed (admission, transfer or verification)", i + 1);
        }
        clock_set_default(bench_previous);
    }
    free(pattern); free(fixture);
    return result;
}

struct zcl_result device_host_bench_run(size_t mib, unsigned repeats, struct device_host_bench_result *out)
{
    if (!out) return ZCL_ERR(-1, "tunnel bench: result storage is required");
    memset(out, 0, sizeof(*out));
    if (mib < 1 || mib > DEVICE_HOST_BENCH_MIB_MAX || repeats < 1 || repeats > DEVICE_HOST_BENCH_REPEATS_MAX)
        return ZCL_ERR(-2, "tunnel bench: mib must be 1..%d and repeats 1..%d", DEVICE_HOST_BENCH_MIB_MAX, DEVICE_HOST_BENCH_REPEATS_MAX);
    out->mib = mib; out->repeats = repeats;
    if (!platform_temp_directory_create("z23-tunnel-bench-", out->profile_root, sizeof(out->profile_root)))
        return ZCL_ERR(-3, "tunnel bench: private temp profile could not be created");
    struct zcl_result result = bench_repeats(out);
    out->profile_removed = zcl_tree_remove(out->profile_root).ok;
    if (!out->profile_removed && result.ok) result = ZCL_ERR(-6, "tunnel bench: temp profile could not be removed");
    return result;
}
#else
struct zcl_result device_host_bench_run(size_t mib, unsigned repeats, struct device_host_bench_result *out)
{
    (void)mib; (void)repeats;
    if (out) memset(out, 0, sizeof(*out));
    return ZCL_ERR(-7, "tunnel bench: unsupported on this platform");
}
#endif
