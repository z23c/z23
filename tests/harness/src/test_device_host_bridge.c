/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: real raw sockets, fixed targets and current host authority release. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "test/test_core.h"
#include "services/device_host_bridge.h"
#include "services/device_host_bench.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"
#include "json/json.h"
#include "platform/private_file.h"
#include "platform/clock.h"
static_assert(_Generic(device_host_bridge_open(NULL, NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_bridge_step(NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_bridge_run(NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_psk_bridge_open(NULL, NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_psk_bridge_step(NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_psk_bridge_set_deadline(NULL, 0, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_psk_bridge_poll_interest(NULL, NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_psk_bridge_poll_observed(NULL, 0, 0, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");

static_assert(_Generic(device_host_bridge_run(NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_psk_queue_data(NULL, NULL, 0, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_psk_queue_fin(NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_psk_pending_acquire(NULL, NULL, NULL, NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_psk_pending_written(NULL, NULL, 0, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");

#if defined(__linux__) || defined(__APPLE__)
#include "platform/socket_compat.h"
#include "platform/pipe_compat.h"
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

/* Preserve the existing domain-state assertions while checking EVERY migrated
 * call's rich-result/status contract. Counter is folded into group failure. */
static unsigned typed_state_failures;
static void typed_state_check(struct zcl_result result, bool normal)
{
    if (result.ok != normal || (result.ok && result.code != 0) ||
        (!result.ok && (!result.code || !result.message[0] || !result.source_file)))
        ++typed_state_failures;
}
static enum device_host_bridge_result typed_test_device_host_bridge_open(struct device_host_bridge *bridge,
    const struct device_host_bridge_spec *spec)
{
    enum device_host_bridge_result status = DEVICE_HOST_BRIDGE_REFUSED;
    struct zcl_result result = device_host_bridge_open(bridge, spec, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_BRIDGE_EOF);
    return status;
}
static enum device_host_bridge_result typed_test_device_host_bridge_step(struct device_host_bridge *bridge)
{
    enum device_host_bridge_result status = DEVICE_HOST_BRIDGE_REFUSED;
    struct zcl_result result = device_host_bridge_step(bridge, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_BRIDGE_EOF);
    return status;
}
static enum device_host_bridge_result typed_test_device_host_bridge_run(struct device_host_bridge *bridge)
{
    enum device_host_bridge_result status = DEVICE_HOST_BRIDGE_REFUSED;
    struct zcl_result result = device_host_bridge_run(bridge, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_BRIDGE_EOF);
    return status;
}
static enum device_host_bridge_result typed_test_device_host_psk_bridge_open(struct device_host_psk_bridge *bridge,
    const struct device_host_psk_bridge_spec *spec)
{
    enum device_host_bridge_result status = DEVICE_HOST_BRIDGE_REFUSED;
    struct zcl_result result = device_host_psk_bridge_open(bridge, spec, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_BRIDGE_EOF);
    return status;
}
static enum device_host_bridge_result typed_test_device_host_psk_bridge_step(struct device_host_psk_bridge *bridge)
{
    enum device_host_bridge_result status = DEVICE_HOST_BRIDGE_REFUSED;
    struct zcl_result result = device_host_psk_bridge_step(bridge, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_BRIDGE_EOF);
    return status;
}
static enum device_host_bridge_result typed_test_device_host_psk_bridge_set_deadline(struct device_host_psk_bridge *bridge,
    int64_t deadline_ns)
{
    enum device_host_bridge_result status = DEVICE_HOST_BRIDGE_REFUSED;
    struct zcl_result result = device_host_psk_bridge_set_deadline(bridge, deadline_ns, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_BRIDGE_EOF);
    return status;
}
static enum device_host_bridge_result typed_test_device_host_psk_bridge_poll_interest(const struct device_host_psk_bridge *bridge,
    struct device_host_bridge_poll_plan *out)
{
    enum device_host_bridge_result status = DEVICE_HOST_BRIDGE_REFUSED;
    struct zcl_result result = device_host_psk_bridge_poll_interest(bridge, out, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_BRIDGE_EOF);
    return status;
}
static enum device_host_bridge_result typed_test_device_host_psk_bridge_poll_observed(struct device_host_psk_bridge *bridge,
    int fd,
    unsigned events)
{
    enum device_host_bridge_result status = DEVICE_HOST_BRIDGE_REFUSED;
    struct zcl_result result = device_host_psk_bridge_poll_observed(bridge, fd, events, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_BRIDGE_EOF);
    return status;
}

static enum device_host_psk_result typed_test_device_host_psk_queue_data(struct device_host_psk_session *session,
    const uint8_t *plaintext,
    size_t length)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_queue_data(session, plaintext, length, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_PSK_EOF);
    return status;
}
static enum device_host_psk_result typed_test_device_host_psk_queue_fin(struct device_host_psk_session *session)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_queue_fin(session, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_PSK_EOF);
    return status;
}
static enum device_host_psk_result typed_test_device_host_psk_pending_acquire(struct device_host_psk_session *session,
    struct device_pairing_guard *guard,
    const uint8_t **bytes,
    size_t *length)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_pending_acquire(session, guard, bytes, length, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_PSK_EOF);
    return status;
}
static enum device_host_psk_result typed_test_device_host_psk_pending_written(struct device_host_psk_session *session,
    struct device_pairing_guard *guard,
    size_t count)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_pending_written(session, guard, count, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_PSK_EOF);
    return status;
}

struct bridge_fixture {
    char directory[1024];
    struct device_pairing_store store;
    struct db_device_pairing row;
    struct device_host_bridge bridge;
    struct device_host_bridge_spec spec;
    int input[2], output[2], transport[2];
    const clock_iface_t *prior_clock;
    clock_iface_t clock;
    int64_t wall_ms;
    bool expired;
    bool controlled_mono;
    bool expire_at_write;
    unsigned wall_observations;
    atomic_bool cancelled;
};

static int64_t fixture_wall(void *opaque)
{
    struct bridge_fixture *fixture = opaque;
    if (fixture->expire_at_write && ++fixture->wall_observations > 2) return 200000;
    return fixture->wall_ms;
}
static int64_t fixture_mono(void *opaque)
{
    if (((struct bridge_fixture *)opaque)->expired) return INT64_MAX;
    if (((struct bridge_fixture *)opaque)->controlled_mono) return INT64_C(1000000000);
    const clock_iface_t *prior = ((struct bridge_fixture *)opaque)->prior_clock;
    return prior->now_monotonic_ns(prior->self);
}
static bool fixture_socket_pair(int pair[2])
{
    if (!platform_socket_pair(pair)) return false;
    for (size_t i = 0; i < 2; i++) {
        if (fcntl(pair[i], F_SETFD, FD_CLOEXEC) == 0 &&
            platform_socket_set_nonblocking(pair[i], true)) continue;
        int saved = errno;
        close(pair[0]); close(pair[1]); pair[0] = pair[1] = -1;
        errno = saved; return false;
    }
    return true;
}

static int fixture_accept(int listener)
{
    int fd = accept(listener, NULL, NULL);
    if (fd < 0) return -1;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 &&
        platform_socket_set_nonblocking(fd, true)) return fd;
    int saved = errno; close(fd); errno = saved; return -1;
}

static int fixture_pipe(int descriptors[2], int flags)
{
    if (platform_pipe_cloexec_nonblock(descriptors) != 0) return -1;
    if (flags & O_NONBLOCK) return 0;
    if (platform_socket_set_nonblocking(descriptors[0], false) &&
        platform_socket_set_nonblocking(descriptors[1], false)) return 0;
    int saved = errno; close(descriptors[0]); close(descriptors[1]);
    descriptors[0] = descriptors[1] = -1; errno = saved; return -1;
}

static void fixture_init(struct bridge_fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    fixture->input[0] = fixture->input[1] = -1;
    fixture->output[0] = fixture->output[1] = -1;
    fixture->transport[0] = fixture->transport[1] = -1;
    fixture->row = (struct db_device_pairing){.profile = {1}, .local_key = {2},
        .peer_key = {3}, .paired_at = 100, .expires_at = 200,
        .capabilities = DEVICE_PAIRING_CAP_HOST_FORWARD,
        .host_scope = {.inbound_port = 2222, .outbound_port = 2222,
            .binding = {.backend_profile = 1, .local_pq_key_root = {4}, .peer_pq_key_root = {5}}}};
    fixture->prior_clock = clock_default();
    fixture->wall_ms = 150000;
    fixture->clock = (clock_iface_t){fixture_mono, fixture_wall, fixture};
    atomic_init(&fixture->cancelled, false);
    device_host_bridge_init(&fixture->bridge);
}
static bool fixture_open(struct bridge_fixture *fixture)
{
    if (!test_mkdtemp(fixture->directory, sizeof(fixture->directory), "host-bridge")) return false;
    if (!fixture_socket_pair(fixture->input) || !fixture_socket_pair(fixture->output) ||
        !fixture_socket_pair(fixture->transport)) return false;
    if (!device_pairing_store_open(&fixture->store, fixture->directory,
        fixture->row.profile, fixture->row.local_key)) return false;
    uint8_t proposal[32];
    enum device_pairing_publication publication;
    if (!device_pairing_host_proposal_root(&fixture->row, proposal) ||
        !db_device_pairing_insert_host(&fixture->store, &fixture->row, proposal, &publication)) return false;
    fixture->spec = (struct device_host_bridge_spec){.store = &fixture->store,
        .authenticated_binding = fixture->row.host_scope.binding,
        .direction = DEVICE_PAIRING_HOST_OUTBOUND, .port = 2222,
        .input_fd = fixture->input[1], .output_fd = fixture->output[1],
        .outbound_fd = fixture->transport[0], .cancelled = &fixture->cancelled,
        .deadline_ns = fixture_mono(fixture) + INT64_C(5000000000)};
    memcpy(fixture->spec.peer, fixture->row.peer_key, 32);
    struct db_device_pairing found;
    if (!db_device_pairing_inspect(&fixture->store, fixture->row.peer_key, &found,
        fixture->spec.approved_root)) return false;
    clock_set_default(&fixture->clock);
    return true;
}
static enum device_host_bridge_result fixture_admit(struct bridge_fixture *fixture)
{
    enum device_host_bridge_result result = typed_test_device_host_bridge_open(&fixture->bridge, &fixture->spec);
    if (fixture->bridge.observation.io_taken) {
        fixture->input[1] = fixture->output[1] = -1;
        fixture->transport[0] = -1;
    }
    return result;
}
static void fixture_close(struct bridge_fixture *fixture)
{
    device_host_bridge_close(&fixture->bridge, DEVICE_HOST_BRIDGE_CANCELLED);
    device_pairing_test_interrupt(0);
    clock_set_default(fixture->prior_clock);
    for (size_t i = 0; i < 2; ++i) {
        if (fixture->input[i] >= 0) close(fixture->input[i]);
        if (fixture->output[i] >= 0) close(fixture->output[i]);
        if (fixture->transport[i] >= 0) close(fixture->transport[i]);
    }
    if (fixture->directory[0]) test_rm_rf(fixture->directory);
}

static ssize_t fill_queue(int fd, uint8_t value)
{
    int size = 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) < 0) return -1;
    uint8_t bytes[4096]; memset(bytes, value, sizeof(bytes));
    size_t total = 0;
    for (size_t chunk = sizeof(bytes); chunk; chunk = chunk == 1 ? 0 : 1) {
        for (;;) {
            ssize_t n = send(fd, bytes, chunk, MSG_DONTWAIT | MSG_NOSIGNAL);
            if (n > 0) { total += (size_t)n; if (total > 1048576) return -1; continue; }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            return -1;
        }
    }
    return (ssize_t)total;
}
static bool drain_filler_eof(int fd, size_t expected, uint8_t value)
{
    size_t total = 0;
    uint8_t bytes[4096];
    for (;;) {
        ssize_t n = recv(fd, bytes, sizeof(bytes), MSG_DONTWAIT);
        if (n == 0) return total == expected;
        if (n < 0) return false;
        for (ssize_t i = 0; i < n; ++i) if (bytes[i] != value) return false;
        total += (size_t)n;
        if (total > expected) return false;
    }
}
static bool change_authority(struct bridge_fixture *fixture, unsigned reason)
{
    enum device_pairing_publication publication;
    if (reason == 0) return db_device_pairing_revoke_expected(&fixture->store,
        fixture->row.peer_key, 150, fixture->spec.approved_root, &publication);
    if (reason == 1) { fixture->wall_ms = 200000; return true; }
    if (reason == 2) {
        struct db_device_pairing replacement = fixture->row;
        replacement.expires_at++;
        uint8_t proposal[32];
        return device_pairing_host_proposal_root(&replacement, proposal) &&
            db_device_pairing_upgrade_host(&fixture->store, &replacement, proposal,
                fixture->spec.approved_root, 150, &publication);
    }
    if (reason == 4) {
        struct db_device_pairing replacement = fixture->row;
        replacement.expires_at++;
        uint8_t proposal[32];
        if (!device_pairing_host_proposal_root(&replacement, proposal)) return false;
        device_pairing_test_interrupt(1);
        return !db_device_pairing_upgrade_host(&fixture->store, &replacement, proposal,
            fixture->spec.approved_root, 150, &publication) && publication == DEVICE_PAIRING_NOT_PUBLISHED;
    }
    if (reason == 5) { fixture->expired = true; return true; }
    atomic_store(&fixture->cancelled, true);
    return true;
}
static int bridge_pending_refusal(unsigned reason)
{
    int failures = 0;
    struct bridge_fixture fixture; fixture_init(&fixture);
    fixture.controlled_mono = true; /* Stepwise authority cases own their clock. */
    TEST_CASE("device_host_bridge: buffered bytes in both directions never release after authority loss") {
        ASSERT(fixture_open(&fixture));
        ssize_t target_filler = fill_queue(fixture.transport[0], 0xa1);
        ssize_t output_filler = fill_queue(fixture.output[1], 0xb2);
        ASSERT(target_filler > 0); ASSERT(output_filler > 0);
        uint8_t forward[37], reverse[41]; memset(forward, 0xc3, sizeof(forward)); memset(reverse, 0xd4, sizeof(reverse));
        ASSERT_EQ(send(fixture.input[0], forward, sizeof(forward), MSG_NOSIGNAL), sizeof(forward));
        ASSERT_EQ(send(fixture.transport[1], reverse, sizeof(reverse), MSG_NOSIGNAL), sizeof(reverse));
        ASSERT_EQ(fixture_admit(&fixture), DEVICE_HOST_BRIDGE_READY);
        ASSERT_EQ(typed_test_device_host_bridge_step(&fixture.bridge), DEVICE_HOST_BRIDGE_PROGRESS);
        ASSERT_EQ(fixture.bridge.forward.used, fixture.bridge.forward.sent + sizeof(forward));
        ASSERT_EQ(fixture.bridge.reverse.used, fixture.bridge.reverse.sent + sizeof(reverse));
        ASSERT_EQ(fixture.bridge.observation.to_target_bytes, 0);
        ASSERT_EQ(fixture.bridge.observation.from_target_bytes, 0);
        ASSERT(change_authority(&fixture, reason));
        enum device_host_bridge_result expected = reason == 3 ? DEVICE_HOST_BRIDGE_CANCELLED :
            (reason == 5 ? DEVICE_HOST_BRIDGE_DEADLINE : DEVICE_HOST_BRIDGE_REFUSED);
        ASSERT_EQ(typed_test_device_host_bridge_step(&fixture.bridge), expected);
        ASSERT(!fixture.bridge.active);
        ASSERT_EQ(fixture.bridge.forward.used, 0); ASSERT_EQ(fixture.bridge.reverse.used, 0);
        ASSERT(drain_filler_eof(fixture.transport[1], (size_t)target_filler, 0xa1));
        ASSERT(drain_filler_eof(fixture.output[0], (size_t)output_filler, 0xb2));
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

static bool fixture_wait_readable(int fd)
{
    int64_t deadline = clock_now_monotonic_ns() + INT64_C(5000000000);
    for (unsigned attempt = 0; attempt < 500 && clock_now_monotonic_ns() < deadline; attempt++) {
        struct pollfd event = {.fd = fd, .events = POLLIN};
        int ready = poll(&event, 1, 10);
        if (ready > 0) return (event.revents & (POLLIN | POLLHUP)) != 0;
        if (ready < 0 && errno != EINTR) return false;
    }
    return false;
}
static int loopback_listener(uint16_t *port)
{
    int fd = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    if (fd < 0) return -1;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t size = sizeof(address);
    if (bind(fd, (const struct sockaddr *)&address, sizeof(address)) < 0 ||
        listen(fd, 1) < 0 || getsockname(fd, (struct sockaddr *)&address, &size) < 0) {
        close(fd); return -1;
    }
    *port = ntohs(address.sin_port);
    return fd;
}
static bool no_connection(int listener)
{
    int fd = fixture_accept(listener);
    if (fd >= 0) { close(fd); return false; }
    return errno == EAGAIN || errno == EWOULDBLOCK;
}
static int bridge_fixed_inbound(void)
{
    int failures = 0, listener = -1, target = -1;
    struct bridge_fixture fixture; fixture_init(&fixture);
    TEST_CASE("device_host_bridge: exact root and binding precede fixed loopback connect") {
        uint16_t port;
        listener = loopback_listener(&port); ASSERT(listener >= 0);
        fixture.row.host_scope.inbound_port = port;
        ASSERT(fixture_open(&fixture));
        fixture.spec.direction = DEVICE_PAIRING_HOST_INBOUND;
        fixture.spec.port = port;
        fixture.spec.outbound_fd = -1;
        uint8_t root[32]; memcpy(root, fixture.spec.approved_root, 32);
        fixture.spec.approved_root[31] ^= 1;
        ASSERT_EQ(typed_test_device_host_bridge_open(&fixture.bridge, &fixture.spec), DEVICE_HOST_BRIDGE_REFUSED);
        ASSERT(!fixture.bridge.observation.io_taken); ASSERT(no_connection(listener));
        ASSERT(fcntl(fixture.input[1], F_GETFD) >= 0);
        memcpy(fixture.spec.approved_root, root, 32);
        fixture.spec.authenticated_binding.peer_pq_key_root[31] ^= 1;
        ASSERT_EQ(typed_test_device_host_bridge_open(&fixture.bridge, &fixture.spec), DEVICE_HOST_BRIDGE_REFUSED);
        ASSERT(no_connection(listener));
        fixture.spec.authenticated_binding = fixture.row.host_scope.binding;
        ASSERT_EQ(typed_test_device_host_bridge_open(&fixture.bridge, &fixture.spec), DEVICE_HOST_BRIDGE_READY);
        fixture.input[1] = fixture.output[1] = -1;
        target = fixture_accept(listener); ASSERT(target >= 0);
        ASSERT(fixture.bridge.observation.target_connected);
        uint8_t bytes[] = {0, 1, 2, 0xff, '\n', 0x80, 0};
        ASSERT_EQ(send(fixture.input[0], bytes, sizeof(bytes), MSG_NOSIGNAL), sizeof(bytes));
        ASSERT_EQ(typed_test_device_host_bridge_step(&fixture.bridge), DEVICE_HOST_BRIDGE_PROGRESS);
        uint8_t observed[sizeof(bytes)];
        ASSERT(fixture_wait_readable(target));
        ASSERT_EQ(recv(target, observed, sizeof(observed), MSG_DONTWAIT), sizeof(bytes));
        ASSERT(!memcmp(bytes, observed, sizeof(bytes)));
        ASSERT_EQ(send(target, bytes, sizeof(bytes), MSG_NOSIGNAL), sizeof(bytes));
        ASSERT(fixture_wait_readable(fixture.bridge.transport_fd));
        ASSERT_EQ(typed_test_device_host_bridge_step(&fixture.bridge), DEVICE_HOST_BRIDGE_PROGRESS);
        ASSERT_EQ(recv(fixture.output[0], observed, sizeof(observed), MSG_DONTWAIT), sizeof(bytes));
        ASSERT(!memcmp(bytes, observed, sizeof(bytes)));
    } TEST_END
    fixture_close(&fixture);
    if (target >= 0) close(target);
    if (listener >= 0) close(listener);
    return failures;
}

static int bridge_invalid_transport(void)
{
    int failures = 0, unconnected = -1;
    struct bridge_fixture fixture; fixture_init(&fixture);
    TEST_CASE("device_host_bridge: unconnected outbound socket refuses before taking descriptors") {
        ASSERT(fixture_open(&fixture));
        unconnected = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
        ASSERT(unconnected >= 0);
        fixture.spec.outbound_fd = unconnected;
        ASSERT_EQ(typed_test_device_host_bridge_open(&fixture.bridge, &fixture.spec), DEVICE_HOST_BRIDGE_REFUSED);
        ASSERT(!fixture.bridge.observation.io_taken);
        ASSERT(fcntl(unconnected, F_GETFD) >= 0);
        ASSERT(fcntl(fixture.input[1], F_GETFD) >= 0);
        ASSERT(fcntl(fixture.output[1], F_GETFD) >= 0);
    } TEST_END
    fixture_close(&fixture);
    if (unconnected >= 0) close(unconnected);
    return failures;
}

static int bridge_halfclose(void)
{
    int failures = 0;
    struct bridge_fixture fixture; fixture_init(&fixture);
    TEST_CASE("device_host_bridge: input EOF permits remaining reverse bytes before final EOF") {
        ASSERT(fixture_open(&fixture)); ASSERT_EQ(fixture_admit(&fixture), DEVICE_HOST_BRIDGE_READY);
        uint8_t request[] = {0, 1, 2, 0xff}, response[DEVICE_HOST_BRIDGE_BUFFER];
        for (size_t i = 0; i < sizeof(response); ++i) response[i] = (uint8_t)i;
        ASSERT_EQ(send(fixture.input[0], request, sizeof(request), MSG_NOSIGNAL), sizeof(request));
        ASSERT(shutdown(fixture.input[0], SHUT_WR) == 0);
        ASSERT_EQ(typed_test_device_host_bridge_step(&fixture.bridge), DEVICE_HOST_BRIDGE_PROGRESS);
        uint8_t seen[DEVICE_HOST_BRIDGE_BUFFER];
        ASSERT_EQ(recv(fixture.transport[1], seen, sizeof(request), MSG_DONTWAIT), sizeof(request));
        ASSERT(!memcmp(seen, request, sizeof(request)));
        ASSERT_EQ(typed_test_device_host_bridge_step(&fixture.bridge), DEVICE_HOST_BRIDGE_PROGRESS);
        ASSERT(fixture.bridge.active); ASSERT(fixture.bridge.forward.half_closed);
        ASSERT_EQ(recv(fixture.transport[1], seen, 1, MSG_DONTWAIT), 0);
        ASSERT_EQ(send(fixture.transport[1], response, sizeof(response), MSG_NOSIGNAL), sizeof(response));
        ASSERT(shutdown(fixture.transport[1], SHUT_WR) == 0);
        ASSERT_EQ(typed_test_device_host_bridge_step(&fixture.bridge), DEVICE_HOST_BRIDGE_PROGRESS);
        ASSERT_EQ(recv(fixture.output[0], seen, sizeof(seen), MSG_DONTWAIT), sizeof(response));
        ASSERT(!memcmp(seen, response, sizeof(response)));
        ASSERT_EQ(typed_test_device_host_bridge_step(&fixture.bridge), DEVICE_HOST_BRIDGE_EOF);
        ASSERT_EQ(recv(fixture.output[0], seen, 1, MSG_DONTWAIT), 0);
        ASSERT_EQ(fixture.bridge.observation.to_target_bytes, sizeof(request));
        ASSERT_EQ(fixture.bridge.observation.from_target_bytes, sizeof(response));
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

static bool reap_fixture(pid_t child, int *status)
{
    int64_t deadline = clock_now_monotonic_ns() + INT64_C(5000000000);
    while (clock_now_monotonic_ns() < deadline) {
        pid_t reaped = waitpid(child, status, WNOHANG);
        if (reaped == child) return true;
        if (reaped < 0 && errno != EINTR) return false;
        (void)poll(NULL, 0, 20);
    }
    return false;
}

static bool revoke_idle_fixture(struct bridge_fixture *fixture)
{
    int64_t deadline = clock_now_monotonic_ns() + INT64_C(5000000000);
    while (clock_now_monotonic_ns() < deadline) {
        enum device_pairing_publication publication;
        bool revoked = db_device_pairing_revoke_expected(&fixture->store,
            fixture->row.peer_key, 150, fixture->spec.approved_root, &publication);
        if (revoked) return publication == DEVICE_PAIRING_DURABLE;
        if (publication != DEVICE_PAIRING_NOT_PUBLISHED) return false;
        struct db_device_pairing current;
        uint8_t root[32];
        if (!db_device_pairing_inspect(&fixture->store, fixture->row.peer_key, &current, root) ||
            memcmp(root, fixture->spec.approved_root, 32)) return false;
        (void)poll(NULL, 0, 1);
    }
    return false;
}

static bool cleanup_fixture_child(pid_t child)
{
    int status;
    pid_t observed = waitpid(child, &status, WNOHANG);
    if (observed == child || (observed < 0 && errno == ECHILD)) return true;
    if (observed < 0) return false;
    if (kill(child, SIGKILL) < 0 && errno != ESRCH) return false;
    if (reap_fixture(child, &status)) return true;
    fprintf(stderr, "device_host_bridge fixture cleanup incomplete: child=%ld errno=%d\n",
        (long)child, errno);
    return false;
}
static int bridge_closed_transport_child(void)
{
    struct sigaction action = {.sa_handler = SIG_DFL}; sigemptyset(&action.sa_mask);
    if (sigaction(SIGPIPE, &action, NULL) != 0) return 120;
    sigset_t signals; sigemptyset(&signals); sigaddset(&signals, SIGPIPE);
    if (sigprocmask(SIG_UNBLOCK, &signals, NULL) != 0) return 121;
    struct bridge_fixture fixture; fixture_init(&fixture);
    if (!fixture_open(&fixture)) { fixture_close(&fixture); return 122; }
    if (fixture_admit(&fixture) != DEVICE_HOST_BRIDGE_READY) { fixture_close(&fixture); return 123; }
    /* Queue an actual bridge write, then remove its transport reader. */
    fixture.bridge.forward.bytes[0] = 0x5a;
    fixture.bridge.forward.used = 1;
    close(fixture.transport[1]); fixture.transport[1] = -1;
    enum device_host_bridge_result result = typed_test_device_host_bridge_step(&fixture.bridge);
    bool refused = result == DEVICE_HOST_BRIDGE_IO_ERROR && !fixture.bridge.active &&
        fixture.bridge.observation.error_number == EPIPE;
    fixture_close(&fixture); return refused ? 0 : 124;
}
static int bridge_closed_transport(void)
{
    int failures = 0; pid_t child = -1;
    TEST_CASE("device_host_bridge: closed socket transport under default unblocked SIGPIPE terminates IO cleanly") {
        ASSERT_EQ(fflush(NULL), 0);
        child = fork(); ASSERT(child >= 0);
        if (child == 0) _exit(bridge_closed_transport_child());
        int status;
        ASSERT(reap_fixture(child, &status)); child = -1;
        ASSERT(WIFEXITED(status)); ASSERT_EQ(WEXITSTATUS(status), 0);
    } TEST_END
    if (child > 0 && !cleanup_fixture_child(child)) failures++;
    return failures;
}
static int bridge_idle_revoke(void)
{
    int failures = 0, ready[2] = {-1, -1};
    pid_t child = -1;
    struct bridge_fixture fixture; fixture_init(&fixture);
    TEST_CASE("device_host_bridge: idle run refuses unavailable or revoked authority; bounded owner retry completes revoke") {
        ASSERT(fixture_open(&fixture)); ASSERT_EQ(fixture_admit(&fixture), DEVICE_HOST_BRIDGE_READY);
        ASSERT(fixture_pipe(ready, O_CLOEXEC) == 0);
        child = fork(); ASSERT(child >= 0);
        if (!child) {
            close(ready[0]); close(fixture.input[0]); close(fixture.output[0]); close(fixture.transport[1]);
            char signal = 'R';
            if (write(ready[1], &signal, 1) != 1) _exit(9);
            close(ready[1]);
            enum device_host_bridge_result result = typed_test_device_host_bridge_run(&fixture.bridge);
            _exit(result == DEVICE_HOST_BRIDGE_REFUSED && !fixture.bridge.active ? 0 : 10);
        }
        close(ready[1]); ready[1] = -1;
        /* Transfer service-owned descriptors to the consenting child only. */
        device_host_bridge_close(&fixture.bridge, DEVICE_HOST_BRIDGE_CANCELLED);
        struct pollfd event = {.fd = ready[0], .events = POLLIN};
        ASSERT(poll(&event, 1, 5000) > 0);
        char signal; ASSERT_EQ(read(ready[0], &signal, 1), 1); ASSERT_EQ(signal, 'R');
        ASSERT(revoke_idle_fixture(&fixture));
        int status;
        ASSERT(reap_fixture(child, &status)); child = -1;
        ASSERT(WIFEXITED(status)); ASSERT_EQ(WEXITSTATUS(status), 0);
        uint8_t byte;
        ASSERT_EQ(recv(fixture.transport[1], &byte, 1, MSG_DONTWAIT), 0);
        ASSERT_EQ(recv(fixture.output[0], &byte, 1, MSG_DONTWAIT), 0);
    } TEST_END
    if (child > 0 && !cleanup_fixture_child(child)) failures++;
    for (size_t i = 0; i < 2; ++i) if (ready[i] >= 0) close(ready[i]);
    fixture_close(&fixture);
    return failures;
}

static int bridge_partial_release(void)
{
    int failures = 0;
    struct bridge_fixture fixture; fixture_init(&fixture);
    TEST_CASE("device_host_bridge: observed partial prefix remains authorized and revoked suffix is discarded") {
        ASSERT(fixture_open(&fixture));
        ssize_t filler = fill_queue(fixture.transport[0], 0x51); ASSERT(filler > 0);
        uint8_t payload[DEVICE_HOST_BRIDGE_BUFFER]; memset(payload, 0x62, sizeof(payload));
        ASSERT_EQ(send(fixture.input[0], payload, sizeof(payload), MSG_NOSIGNAL), sizeof(payload));
        ASSERT_EQ(fixture_admit(&fixture), DEVICE_HOST_BRIDGE_READY);
        ASSERT_EQ(typed_test_device_host_bridge_step(&fixture.bridge), DEVICE_HOST_BRIDGE_PROGRESS);
        ASSERT_EQ(fixture.bridge.forward.sent, 0);
        size_t drained = 0;
        for (unsigned attempt = 0; attempt < 64 && !fixture.bridge.forward.sent; ++attempt) {
            uint8_t bytes[512];
            ssize_t n = recv(fixture.transport[1], bytes, sizeof(bytes), MSG_DONTWAIT);
            ASSERT(n > 0);
            for (ssize_t i = 0; i < n; ++i) ASSERT_EQ(bytes[i], 0x51);
            drained += (size_t)n;
            enum device_host_bridge_result result = typed_test_device_host_bridge_step(&fixture.bridge);
            ASSERT(result == DEVICE_HOST_BRIDGE_WAIT || result == DEVICE_HOST_BRIDGE_PROGRESS);
        }
        size_t released = fixture.bridge.forward.sent;
        ASSERT(released > 0); ASSERT(released < sizeof(payload));
        ASSERT_EQ(fixture.bridge.observation.to_target_bytes, released);
        ASSERT(change_authority(&fixture, 0));
        ASSERT_EQ(typed_test_device_host_bridge_step(&fixture.bridge), DEVICE_HOST_BRIDGE_REFUSED);
        size_t remaining_filler = (size_t)filler - drained, seen = 0;
        for (;;) {
            uint8_t bytes[512];
            ssize_t n = recv(fixture.transport[1], bytes, sizeof(bytes), MSG_DONTWAIT);
            if (n == 0) break;
            ASSERT(n > 0);
            for (ssize_t i = 0; i < n; ++i) {
                ASSERT_EQ(bytes[i], seen < remaining_filler ? 0x51 : 0x62);
                seen++;
            }
        }
        ASSERT_EQ(seen, remaining_filler + released);
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

static int bridge_broken_pipe(void)
{
    int failures = 0;
    struct bridge_fixture fixture; fixture_init(&fixture);
    TEST_CASE("device_host_bridge: broken raw output pipe records EPIPE without SIGPIPE process death") {
        ASSERT(fixture_open(&fixture));
        close(fixture.output[0]); close(fixture.output[1]);
        fixture.output[0] = fixture.output[1] = -1;
        ASSERT(fixture_pipe(fixture.output, O_CLOEXEC | O_NONBLOCK) == 0);
        fixture.spec.output_fd = fixture.output[1];
        ASSERT_EQ(fixture_admit(&fixture), DEVICE_HOST_BRIDGE_READY);
        close(fixture.output[0]); fixture.output[0] = -1;
        uint8_t payload[] = {0, 0xff, 0x80};
        ASSERT_EQ(send(fixture.transport[1], payload, sizeof(payload), MSG_NOSIGNAL), sizeof(payload));
        struct sigaction prior, normal = {.sa_handler = SIG_DFL};
        sigemptyset(&normal.sa_mask);
        ASSERT(sigaction(SIGPIPE, NULL, &prior) == 0);
        sigset_t before, after, allowed, pending;
        ASSERT(pthread_sigmask(SIG_SETMASK, NULL, &before) == 0);
        ASSERT(sigpending(&pending) == 0);
        ASSERT_EQ(sigismember(&pending, SIGPIPE), 0);
        allowed = before;
        sigdelset(&allowed, SIGPIPE);
        int installed = sigaction(SIGPIPE, &normal, NULL);
        int unblocked = installed == 0 ? pthread_sigmask(SIG_SETMASK, &allowed, NULL) : EINVAL;
        enum device_host_bridge_result result = installed == 0 && unblocked == 0 ?
            typed_test_device_host_bridge_step(&fixture.bridge) : DEVICE_HOST_BRIDGE_UNSUPPORTED;
        int observed = pthread_sigmask(SIG_SETMASK, NULL, &after);
        /* Restore mask AND disposition before assertions can leave fixture. */
        int restored_mask = pthread_sigmask(SIG_SETMASK, &before, NULL);
        int restored = sigaction(SIGPIPE, &prior, NULL);
        ASSERT_EQ(restored_mask, 0); ASSERT_EQ(restored, 0);
        ASSERT_EQ(installed, 0); ASSERT_EQ(unblocked, 0); ASSERT_EQ(observed, 0);
        ASSERT_EQ(result, DEVICE_HOST_BRIDGE_IO_ERROR);
        ASSERT_EQ(fixture.bridge.observation.error_number, EPIPE);
        ASSERT_EQ(sigismember(&after, SIGPIPE), 0);
        ASSERT(!fixture.bridge.active);
        ASSERT_EQ(fixture.bridge.observation.from_target_bytes, 0);
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

static int bridge_fullbytes(void)
{
    int failures = 0;
    struct bridge_fixture fixture; fixture_init(&fixture);
    TEST_CASE("device_host_bridge: exact 64KiB duplex bytes including every binary value") {
        ASSERT(fixture_open(&fixture)); ASSERT_EQ(fixture_admit(&fixture), DEVICE_HOST_BRIDGE_READY);
        uint8_t bytes[DEVICE_HOST_BRIDGE_BUFFER], seen[DEVICE_HOST_BRIDGE_BUFFER];
        for (unsigned chunk = 0; chunk < 16; ++chunk) {
            for (size_t i = 0; i < sizeof(bytes); ++i) bytes[i] = (uint8_t)(chunk * 17 + i);
            ASSERT_EQ(send(fixture.input[0], bytes, sizeof(bytes), MSG_NOSIGNAL), sizeof(bytes));
            ASSERT_EQ(typed_test_device_host_bridge_step(&fixture.bridge), DEVICE_HOST_BRIDGE_PROGRESS);
            ASSERT_EQ(recv(fixture.transport[1], seen, sizeof(seen), MSG_DONTWAIT), sizeof(bytes));
            ASSERT(!memcmp(bytes, seen, sizeof(bytes)));
            ASSERT_EQ(send(fixture.transport[1], bytes, sizeof(bytes), MSG_NOSIGNAL), sizeof(bytes));
            ASSERT_EQ(typed_test_device_host_bridge_step(&fixture.bridge), DEVICE_HOST_BRIDGE_PROGRESS);
            ASSERT_EQ(recv(fixture.output[0], seen, sizeof(seen), MSG_DONTWAIT), sizeof(bytes));
            ASSERT(!memcmp(bytes, seen, sizeof(bytes)));
        }
        ASSERT_EQ(fixture.bridge.observation.to_target_bytes, 65536);
        ASSERT_EQ(fixture.bridge.observation.from_target_bytes, 65536);
    } TEST_END
    fixture_close(&fixture);
    return failures;
}


static int bridge_write_boundary(bool forward)
{
    int failures = 0;
    struct bridge_fixture fixture; fixture_init(&fixture);
    TEST_CASE("device_host_bridge: expiry after initial authorization forbids first raw byte release") {
        ASSERT(fixture_open(&fixture)); ASSERT_EQ(fixture_admit(&fixture), DEVICE_HOST_BRIDGE_READY);
        uint8_t bytes[] = {0, 0xff, 0x80, '\n', 0x41};
        int sender = forward ? fixture.input[0] : fixture.transport[1];
        int receiver = forward ? fixture.transport[1] : fixture.output[0];
        ASSERT_EQ(send(sender, bytes, sizeof(bytes), MSG_NOSIGNAL), sizeof(bytes));
        /* Arm AFTER open: step's initial authorization samples wall twice
         * at150. The first per-write authorization samples200 (expiry).
         * No sleep/hook: this uses the existing injected clock interface. */
        fixture.wall_observations = 0;
        fixture.expire_at_write = true;
        enum device_host_bridge_result result = typed_test_device_host_bridge_step(&fixture.bridge);
        uint8_t observed;
        ASSERT_EQ(recv(receiver, &observed, 1, MSG_DONTWAIT), 0);
        ASSERT_EQ(fixture.bridge.observation.to_target_bytes, 0);
        ASSERT_EQ(fixture.bridge.observation.from_target_bytes, 0);
        ASSERT_EQ(result, DEVICE_HOST_BRIDGE_REFUSED);
        ASSERT_EQ(fixture.wall_observations, 3);
        ASSERT(!fixture.bridge.active);
        ASSERT_EQ(fixture.bridge.forward.used, 0); ASSERT_EQ(fixture.bridge.reverse.used, 0);
    } TEST_END
    fixture_close(&fixture);
    return failures;
}


struct psk_io_fixture {
    char directory[2][1024]; struct device_pairing_store store[2]; struct db_device_pairing row[2]; uint8_t root[2][32];
    struct device_host_psk_bridge client, server; struct device_host_psk_bridge_spec client_spec, server_spec;
    int carrier[2], plain[2], listener, target; uint16_t port;
    const clock_iface_t *previous; clock_iface_t clock; int64_t wall_ms;
    atomic_bool cancelled; unsigned generation; int64_t frozen_ns;
    bool revoke_at_plaintext, revocation_attempted, revocation_published;
};
static int64_t psk_io_fixture_mono(void *opaque)
{
    struct psk_io_fixture *f = opaque;
    return f->frozen_ns ? f->frozen_ns : f->previous->now_monotonic_ns(f->previous->self);
}
static int64_t psk_io_fixture_wall(void *opaque)
{
    struct psk_io_fixture *f = opaque;
    if (f->revoke_at_plaintext && !f->revocation_attempted && f->server.session.borrowed_guard &&
        f->server.session.borrowing_plaintext) {
        f->revocation_attempted = true;
        enum device_pairing_publication publication;
        f->revocation_published = db_device_pairing_revoke_expected(f->server_spec.session.store,
            f->server_spec.session.peer, 150, f->server_spec.session.approved_root, &publication);
        if (f->revocation_published) f->revocation_published = publication == DEVICE_PAIRING_DURABLE;
    }
    return f->wall_ms;
}
static void psk_io_fixture_init(struct psk_io_fixture *f)
{
    memset(f, 0, sizeof(*f)); f->carrier[0] = f->carrier[1] = f->plain[0] = f->plain[1] = -1;
    f->listener = f->target = -1; f->wall_ms = 150000; f->previous = clock_default(); atomic_init(&f->cancelled, false);
    f->clock = (clock_iface_t){psk_io_fixture_mono, psk_io_fixture_wall, f};
    device_host_psk_bridge_init(&f->client); device_host_psk_bridge_init(&f->server);
}
static void psk_io_fixture_close(struct psk_io_fixture *f)
{
    device_host_psk_bridge_close(&f->client, DEVICE_HOST_BRIDGE_CANCELLED);
    device_host_psk_bridge_close(&f->server, DEVICE_HOST_BRIDGE_CANCELLED);
    clock_set_default(f->previous); device_pairing_test_interrupt(0);
    const int descriptors[] = {f->carrier[0],f->carrier[1],f->plain[0],f->plain[1],f->listener,f->target};
    for (size_t i = 0; i < sizeof(descriptors) / sizeof(descriptors[0]); ++i) if (descriptors[i] >= 0) close(descriptors[i]);
    for (size_t i = 0; i < 2; ++i) if (f->directory[i][0]) test_rm_rf(f->directory[i]);
}
static bool psk_io_fixture_open(struct psk_io_fixture *f, unsigned orientation, bool wrong_secret)
{
    f->listener = loopback_listener(&f->port);
    if (f->listener < 0 || !fixture_socket_pair(f->carrier) || !fixture_socket_pair(f->plain)) return false;
    for (size_t i = 0; i < 2; ++i) {
        if (!test_mkdtemp(f->directory[i], sizeof(f->directory[i]), "host-psk-io")) return false;
        struct db_device_pairing *row = &f->row[i];
        *row = (struct db_device_pairing){.profile = {1}, .paired_at = 100, .expires_at = 200, .capabilities = DEVICE_PAIRING_CAP_HOST_FORWARD};
        row->local_key[0] = i ? 3 : 2; row->peer_key[0] = i ? 2 : 3;
        row->host_scope.inbound_port = row->host_scope.outbound_port = f->port;
        row->host_scope.binding.backend_profile = DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK;
        struct device_pairing_psk_binding *binding = &row->host_scope.binding.psk;
        binding->credential_id[0] = 91; binding->key_epoch = 1; binding->endpoint_a[0] = 2; binding->endpoint_b[0] = 3;
        uint8_t secret[32] = {17}, proposal[32]; if (wrong_secret && i == 1) secret[0] ^= 1;
        struct device_pairing_psk_publication report; struct db_device_pairing found;
        if (!device_pairing_store_open(&f->store[i], f->directory[i], row->profile, row->local_key) ||
            !device_pairing_host_proposal_root(row, proposal) || !db_device_pairing_insert_host_psk(&f->store[i], row, secret, proposal, &report) ||
            !db_device_pairing_inspect(&f->store[i], row->peer_key, &found, f->root[i])) return false;
    }
    clock_set_default(&f->clock);
    struct device_host_psk_spec c = {.store = &f->store[orientation], .direction = DEVICE_PAIRING_HOST_OUTBOUND,
        .port = f->port, .deadline_ns = psk_io_fixture_mono(f) + INT64_C(5000000000), .cancelled = &f->cancelled};
    struct device_host_psk_spec s = c; s.store = &f->store[1 - orientation]; s.direction = DEVICE_PAIRING_HOST_INBOUND;
    memcpy(c.peer, f->row[orientation].peer_key, 32); memcpy(c.approved_root, f->root[orientation], 32);
    memcpy(s.peer, f->row[1 - orientation].peer_key, 32); memcpy(s.approved_root, f->root[1 - orientation], 32);
    f->client_spec = (struct device_host_psk_bridge_spec){.session = c, .carrier_input_fd = f->carrier[0], .carrier_output_fd = f->carrier[0],
        .input_fd = f->plain[1], .output_fd = f->plain[1]};
    f->server_spec = (struct device_host_psk_bridge_spec){.session = s, .carrier_input_fd = f->carrier[1], .carrier_output_fd = f->carrier[1], .input_fd = -1, .output_fd = -1};
    return true;
}
static bool psk_io_fixture_admit(struct psk_io_fixture *f)
{
    uint8_t nonce[32] = {0}; nonce[0] = (uint8_t)(0x80 + f->generation);
    device_host_psk_test_nonce(nonce, false);
    enum device_host_bridge_result c = typed_test_device_host_psk_bridge_open(&f->client, &f->client_spec);
    if (f->client.observation.io_taken) { f->carrier[0] = -1; f->plain[1] = -1; }
    nonce[0] = (uint8_t)(0xa0 + f->generation); device_host_psk_test_nonce(nonce, false);
    enum device_host_bridge_result s = typed_test_device_host_psk_bridge_open(&f->server, &f->server_spec);
    if (f->server.observation.io_taken) f->carrier[1] = -1;
    f->generation++;
    return c == DEVICE_HOST_BRIDGE_READY && s == DEVICE_HOST_BRIDGE_READY;
}
static bool psk_io_live_result(enum device_host_bridge_result result)
{
    return result == DEVICE_HOST_BRIDGE_PROGRESS || result == DEVICE_HOST_BRIDGE_WAIT;
}
static bool psk_io_pair_step(struct device_host_psk_bridge *client, struct device_host_psk_bridge *server)
{
    enum device_host_bridge_result c = typed_test_device_host_psk_bridge_step(client), s = typed_test_device_host_psk_bridge_step(server);
    return psk_io_live_result(c) && psk_io_live_result(s);
}
static bool psk_io_fixture_ready(struct psk_io_fixture *f)
{
    int64_t deadline = psk_io_fixture_mono(f) + INT64_C(5000000000);
    while (psk_io_fixture_mono(f) < deadline) {
        if (!psk_io_pair_step(&f->client, &f->server)) return false;
        if (f->target < 0) {
            f->target = fixture_accept(f->listener);
            if (f->target < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return false;
        }
        if (f->client.session.phase == DEVICE_HOST_PSK_ESTABLISHED && f->server.session.phase == DEVICE_HOST_PSK_ESTABLISHED)
            return f->target >= 0 && f->server.observation.target_connected;
        (void)poll(NULL, 0, 1);
    }
    return false;
}
static bool psk_io_try_send(int fd, const uint8_t *bytes, size_t size, size_t *sent)
{
    if (*sent == size) return true;
    ssize_t n = send(fd, bytes + *sent, size - *sent, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n > 0) { *sent += (size_t)n; return true; }
    return n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
}
static bool psk_io_try_receive(int fd, const uint8_t *bytes, size_t size, size_t *seen)
{
    uint8_t output[4096]; ssize_t n = recv(fd, output, sizeof(output), MSG_DONTWAIT);
    if (n > 0) {
        if ((size_t)n > size - *seen || memcmp(output, bytes + *seen, (size_t)n)) return false;
        *seen += (size_t)n; return true;
    }
    return n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
}
static bool psk_io_transfer(struct psk_io_fixture *f, int source, int destination, const uint8_t *bytes, size_t size)
{
    size_t sent = 0, seen = 0; int64_t deadline = psk_io_fixture_mono(f) + INT64_C(5000000000);
    while (psk_io_fixture_mono(f) < deadline && seen < size) {
        if (!psk_io_try_send(source, bytes, size, &sent) || !psk_io_pair_step(&f->client, &f->server) ||
            !psk_io_try_receive(destination, bytes, size, &seen)) return false;
    }
    return sent == size && seen == size;
}
static int psk_io_admission_and_bytes(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    TEST_CASE("host PSK IO: neither target connect nor plaintext read precedes mutual readiness; actual duplex64KiB bothroles") {
        for (unsigned orientation = 0; orientation < 2; ++orientation) {
            ASSERT(psk_io_fixture_open(&f, orientation, false)); ASSERT(psk_io_fixture_admit(&f));
            const uint8_t early[] = {0,0xff,0x80,1}; ASSERT_EQ(send(f.plain[0], early, sizeof(early), MSG_NOSIGNAL), sizeof(early));
            ASSERT(no_connection(f.listener)); ASSERT_EQ(f.client.observation.plaintext_read_bytes, 0);
            ASSERT(psk_io_live_result(typed_test_device_host_psk_bridge_step(&f.client)));
            ASSERT(no_connection(f.listener)); ASSERT_EQ(f.client.observation.plaintext_read_bytes, 0);
            ASSERT(psk_io_live_result(typed_test_device_host_psk_bridge_step(&f.server)));
            ASSERT(no_connection(f.listener)); ASSERT(!f.server.observation.target_connect_started);
            ASSERT(psk_io_live_result(typed_test_device_host_psk_bridge_step(&f.client)));
            ASSERT(no_connection(f.listener)); ASSERT_EQ(f.client.observation.plaintext_read_bytes, 0);
            ASSERT(psk_io_fixture_ready(&f));
            uint8_t seen[sizeof(early)]; int64_t deadline = psk_io_fixture_mono(&f) + INT64_C(5000000000); ssize_t n = -1;
            while (psk_io_fixture_mono(&f) < deadline && n < 0) {
                ASSERT(psk_io_pair_step(&f.client, &f.server)); n = recv(f.target, seen, sizeof(seen), MSG_DONTWAIT);
            }
            ASSERT_EQ(n, sizeof(early)); ASSERT(!memcmp(early, seen, sizeof(early)));
            uint8_t bytes[4096];
            for (unsigned chunk = 0; chunk < 16; ++chunk) {
                for (size_t i = 0; i < sizeof(bytes); ++i) bytes[i] = (uint8_t)(chunk * 17 + i);
                ASSERT(psk_io_transfer(&f, f.plain[0], f.target, bytes, sizeof(bytes)));
                ASSERT(psk_io_transfer(&f, f.target, f.plain[0], bytes, sizeof(bytes)));
            }
            ASSERT_EQ(f.server.observation.plaintext_written_bytes, 65536 + sizeof(early));
            ASSERT_EQ(f.client.observation.plaintext_written_bytes, 65536);
            psk_io_fixture_close(&f); psk_io_fixture_init(&f);
        }
    } TEST_END
    psk_io_fixture_close(&f); return failures;
}
static int psk_io_wrong_key_and_truncation(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    TEST_CASE("host PSK IO: wrong secret cannot connect target; raw handshake EOF is never FIN") {
        ASSERT(psk_io_fixture_open(&f, 0, true)); ASSERT(psk_io_fixture_admit(&f));
        ASSERT(psk_io_live_result(typed_test_device_host_psk_bridge_step(&f.client)));
        ASSERT(psk_io_live_result(typed_test_device_host_psk_bridge_step(&f.server)));
        ASSERT_EQ(typed_test_device_host_psk_bridge_step(&f.client), DEVICE_HOST_BRIDGE_REFUSED);
        ASSERT(!f.client.active); ASSERT(no_connection(f.listener)); ASSERT(!f.server.observation.target_connect_started);
        ASSERT_EQ(f.client.observation.plaintext_read_bytes, 0);
        psk_io_fixture_close(&f); psk_io_fixture_init(&f);
        ASSERT(psk_io_fixture_open(&f, 0, false)); ASSERT(psk_io_fixture_admit(&f));
        device_host_psk_bridge_close(&f.client, DEVICE_HOST_BRIDGE_IO_ERROR);
        ASSERT_EQ(typed_test_device_host_psk_bridge_step(&f.server), DEVICE_HOST_BRIDGE_REFUSED);
        ASSERT(no_connection(f.listener)); ASSERT(!f.server.observation.target_connect_started);
    } TEST_END
    psk_io_fixture_close(&f); return failures;
}
static bool psk_io_wait_plaintext(struct psk_io_fixture *f, bool client)
{
    struct device_host_psk_bridge *bridge = client ? &f->client : &f->server;
    int64_t deadline = psk_io_fixture_mono(f) + INT64_C(5000000000);
    while (psk_io_fixture_mono(f) < deadline) {
        if (!psk_io_pair_step(&f->client, &f->server)) return false;
        if (bridge->session.plaintext_used) return true;
    }
    return false;
}
static int psk_io_buffered_revoke(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    TEST_CASE("host PSK IO: real full plaintext socket withholds decoded bytes, completed revoke discards suffix and gives actual EOF") {
        ASSERT(psk_io_fixture_open(&f, 0, false)); ASSERT(psk_io_fixture_admit(&f)); ASSERT(psk_io_fixture_ready(&f));
        ssize_t filler = fill_queue(f.client.spec.output_fd, 0xee); ASSERT(filler > 0);
        const uint8_t payload[] = {1,2,3,4}; ASSERT_EQ(send(f.target, payload, sizeof(payload), MSG_NOSIGNAL), sizeof(payload));
        ASSERT(psk_io_wait_plaintext(&f, true));
        ASSERT(psk_io_live_result(typed_test_device_host_psk_bridge_step(&f.client)));
        ASSERT_EQ(f.client.session.plaintext_used, sizeof(payload)); ASSERT_EQ(f.client.session.plaintext_sent, 0);
        ASSERT_EQ(f.client.observation.plaintext_written_bytes, 0);
        enum device_pairing_publication publication;
        ASSERT(db_device_pairing_revoke_expected(f.client_spec.session.store, f.client_spec.session.peer, 150,
            f.client_spec.session.approved_root, &publication)); ASSERT_EQ(publication, DEVICE_PAIRING_DURABLE);
        ASSERT_EQ(typed_test_device_host_psk_bridge_step(&f.client), DEVICE_HOST_BRIDGE_REFUSED);
        ASSERT(drain_filler_eof(f.plain[0], (size_t)filler, 0xee));
        ASSERT_EQ(f.client.session.plaintext_used, 0); ASSERT(!f.client.active);
    } TEST_END
    psk_io_fixture_close(&f); return failures;
}
static ssize_t psk_io_wait_byte(struct psk_io_fixture *f, int fd, uint8_t *byte);

/* Drive only the still-authorized client. A complete new encrypted record
 * must leave its carrier before the revoked server is stepped even once. */
static bool psk_io_client_record_attempt(struct psk_io_fixture *f, size_t size,
    uint64_t read_before, uint64_t written_before)
{
    int64_t deadline = f->previous->now_monotonic_ns(f->previous->self) + INT64_C(5000000000);
    while (f->previous->now_monotonic_ns(f->previous->self) < deadline) {
        enum device_host_bridge_result result = typed_test_device_host_psk_bridge_step(&f->client);
        if (!psk_io_live_result(result)) return false;
        if (f->client.observation.plaintext_read_bytes == read_before + size &&
            f->client.observation.carrier_written_bytes > written_before &&
            !f->client.session.pending_used && !f->client.local_used) return true;
        if (f->client.observation.plaintext_read_bytes > read_before + size) return false;
        if (poll(NULL, 0, 1) < 0 && errno != EINTR) return false;
    }
    return false;
}

static int psk_io_idle_revoke_then_record(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    TEST_CASE("host PSK IO: pairing revoked while bridge is idle; next record is refused and never reaches target") {
        ASSERT(psk_io_fixture_open(&f, 0, false)); ASSERT(psk_io_fixture_admit(&f)); ASSERT(psk_io_fixture_ready(&f));
        for (unsigned i = 0; i < 4; ++i) ASSERT(psk_io_pair_step(&f.client, &f.server));
        ASSERT_EQ(f.server.observation.plaintext_written_bytes, 0);
        enum device_pairing_publication publication;
        ASSERT(db_device_pairing_revoke_expected(f.server_spec.session.store, f.server_spec.session.peer, 150,
            f.server_spec.session.approved_root, &publication)); ASSERT_EQ(publication, DEVICE_PAIRING_DURABLE);
        const uint8_t record[] = {0x52, 0x65, 0x76};
        ASSERT_EQ(f.client.session.pending_used, 0); ASSERT_EQ(f.client.local_used, 0);
        uint64_t read_before = f.client.observation.plaintext_read_bytes;
        uint64_t written_before = f.client.observation.carrier_written_bytes;
        uint64_t server_read_before = f.server.observation.carrier_read_bytes;
        ASSERT_EQ(send(f.plain[0], record, sizeof(record), MSG_NOSIGNAL), sizeof(record));
        ASSERT(psk_io_client_record_attempt(&f, sizeof(record), read_before, written_before));
        ASSERT_EQ(f.client.observation.plaintext_read_bytes, read_before + sizeof(record));
        ASSERT(f.client.observation.carrier_written_bytes > written_before);
        ASSERT_EQ(f.server.observation.carrier_read_bytes, server_read_before);
        ASSERT(f.server.active);
        enum device_host_bridge_result result = typed_test_device_host_psk_bridge_step(&f.server);
        ASSERT_EQ(result, DEVICE_HOST_BRIDGE_REFUSED); ASSERT(!f.server.active);
        ASSERT_EQ(f.server.observation.plaintext_written_bytes, 0);
        uint8_t seen = 0; ASSERT_EQ(psk_io_wait_byte(&f, f.target, &seen), 0);
    } TEST_END
    psk_io_fixture_close(&f); return failures;
}
static ssize_t psk_io_wait_byte(struct psk_io_fixture *f, int fd, uint8_t *byte)
{
    int64_t deadline = psk_io_fixture_mono(f) + INT64_C(5000000000);
    while (psk_io_fixture_mono(f) < deadline) {
        ssize_t n = recv(fd, byte, 1, MSG_DONTWAIT);
        if (n >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) return n;
        struct pollfd event = {.fd = fd, .events = POLLIN}; (void)poll(&event, 1, 1);
    }
    return -1;
}
/* Continuous stream: several records are delivered under the carried per-record authority,
 * then the receiving side's pairing is revoked between two records. The very next record
 * must be refused before any byte reaches the target and the session must end refused. */
static int psk_io_revoke_between_stream_records(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    TEST_CASE("host PSK IO: revoke between two records of a continuous stream; next record is never delivered and the session ends refused") {
        ASSERT(psk_io_fixture_open(&f, 0, false)); ASSERT(psk_io_fixture_admit(&f)); ASSERT(psk_io_fixture_ready(&f));
        for (unsigned i = 0; i < 4; ++i) {
            uint8_t record[64]; memset(record, 0x30 + (int)i, sizeof(record));
            ASSERT(psk_io_transfer(&f, f.plain[0], f.target, record, sizeof(record)));
        }
        ASSERT_EQ(f.server.observation.plaintext_written_bytes, 4 * 64);
        enum device_pairing_publication publication;
        ASSERT(db_device_pairing_revoke_expected(f.server_spec.session.store, f.server_spec.session.peer, 150,
            f.server_spec.session.approved_root, &publication)); ASSERT_EQ(publication, DEVICE_PAIRING_DURABLE);
        const uint8_t late[] = {0x4c, 0x61, 0x74, 0x65};
        uint64_t read_before = f.client.observation.plaintext_read_bytes;
        uint64_t written_before = f.client.observation.carrier_written_bytes;
        ASSERT_EQ(send(f.plain[0], late, sizeof(late), MSG_NOSIGNAL), sizeof(late));
        ASSERT(psk_io_client_record_attempt(&f, sizeof(late), read_before, written_before));
        ASSERT(f.server.active);
        ASSERT_EQ(typed_test_device_host_psk_bridge_step(&f.server), DEVICE_HOST_BRIDGE_REFUSED);
        ASSERT(!f.server.active);
        ASSERT_EQ(f.server.observation.plaintext_written_bytes, 4 * 64);
        uint8_t seen = 0; ASSERT_EQ(psk_io_wait_byte(&f, f.target, &seen), 0);
    } TEST_END
    psk_io_fixture_close(&f); return failures;
}
/* One receiving step reads, decrypts and releases a record under ONE authority acquisition. */
static int psk_io_receive_single_authority(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    TEST_CASE("host PSK IO: one receive step reads, decrypts and releases a record under a single authority acquisition") {
        ASSERT(psk_io_fixture_open(&f, 0, false)); ASSERT(psk_io_fixture_admit(&f)); ASSERT(psk_io_fixture_ready(&f));
        uint64_t read_before = f.client.observation.plaintext_read_bytes;
        uint64_t written_before = f.client.observation.carrier_written_bytes;
        const uint8_t payload = 0x62; ASSERT_EQ(send(f.plain[0], &payload, 1, MSG_NOSIGNAL), 1);
        ASSERT(psk_io_client_record_attempt(&f, sizeof(payload), read_before, written_before));
        uint64_t full0 = 0, cached0 = 0, full1 = 0, cached1 = 0;
        device_pairing_guard_counts(&full0, &cached0);
        ASSERT(psk_io_live_result(typed_test_device_host_psk_bridge_step(&f.server)));
        device_pairing_guard_counts(&full1, &cached1);
        ASSERT_EQ(f.server.observation.plaintext_written_bytes, 1);
        ASSERT_EQ((full1 - full0) + (cached1 - cached0), 1);
        uint8_t observed = 0; ASSERT_EQ(psk_io_wait_byte(&f, f.target, &observed), 1); ASSERT_EQ(observed, payload);
    } TEST_END
    psk_io_fixture_close(&f); return failures;
}
static int psk_io_actual_guard_boundary(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    TEST_CASE("host PSK IO: current lock spans actual target write; completed in-action revoke may release no byte") {
        ASSERT(psk_io_fixture_open(&f, 0, false)); ASSERT(psk_io_fixture_admit(&f)); ASSERT(psk_io_fixture_ready(&f));
        uint64_t read_before = f.client.observation.plaintext_read_bytes;
        uint64_t written_before = f.client.observation.carrier_written_bytes;
        const uint8_t payload = 0x61; ASSERT_EQ(send(f.plain[0], &payload, 1, MSG_NOSIGNAL), 1);
        /* The record leaves the client carrier, then the server's single step reads, decrypts and writes
         * it under one carried guard, so the revoke hook fires inside that step's actual target write. */
        ASSERT(psk_io_client_record_attempt(&f, sizeof(payload), read_before, written_before));
        ASSERT_EQ(f.server.observation.plaintext_written_bytes, 0);
        f.revoke_at_plaintext = true;
        enum device_host_bridge_result result = typed_test_device_host_psk_bridge_step(&f.server);
        f.revoke_at_plaintext = false;
        uint8_t observed = 0; ssize_t count = psk_io_wait_byte(&f, f.target, &observed);
        fprintf(stderr, "PSK target write witness: revoke_published=%u actual_bytes=%ld written=%llu\n",
            f.revocation_published, (long)count, (unsigned long long)f.server.observation.plaintext_written_bytes);
        ASSERT(f.revocation_attempted);
        /* This checks the actual target: a lock-only premature-release mutant
         * completes revoke and must not emit the observed forbidden byte. */
        if (f.revocation_published) ASSERT_EQ(count, 0);
        else { ASSERT(psk_io_live_result(result)); ASSERT_EQ(count, 1); ASSERT_EQ(observed, payload); }
    } TEST_END
    psk_io_fixture_close(&f); return failures;
}
static int psk_io_fin_and_extra(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f); struct device_pairing_guard guard = {0};
    TEST_CASE("host PSK IO: authenticated reverse FIN drains, coalesced final FIN plus observed extra bytes is refusal") {
        ASSERT(psk_io_fixture_open(&f, 0, false)); ASSERT(psk_io_fixture_admit(&f)); ASSERT(psk_io_fixture_ready(&f));
        ASSERT_EQ(shutdown(f.target, SHUT_WR), 0);
        int64_t deadline = psk_io_fixture_mono(&f) + INT64_C(5000000000);
        while (!f.client.session.receive_fin && psk_io_fixture_mono(&f) < deadline) ASSERT(psk_io_pair_step(&f.client, &f.server));
        ASSERT(f.client.session.receive_fin); ASSERT(f.server.session.send_fin); ASSERT(!f.client.session.send_fin);
        const uint8_t reverse = 0x72;
        ASSERT(psk_io_transfer(&f, f.plain[0], f.target, &reverse, 1));
        ASSERT_EQ(typed_test_device_host_psk_queue_fin(&f.client.session), DEVICE_HOST_PSK_PROGRESS);
        const uint8_t *bytes = NULL; size_t length = 0;
        ASSERT_EQ(typed_test_device_host_psk_pending_acquire(&f.client.session, &guard, &bytes, &length), DEVICE_HOST_PSK_PROGRESS);
        uint8_t packet[DEVICE_HOST_PSK_WIRE + 1]; memcpy(packet, bytes, length); packet[length] = 0xff;
        ssize_t sent = send(f.client.spec.carrier_output_fd, packet, length + 1, MSG_NOSIGNAL);
        enum device_host_psk_result completed = typed_test_device_host_psk_pending_written(&f.client.session, &guard, length);
        ASSERT_EQ(sent, (ssize_t)(length + 1)); ASSERT_EQ(completed, DEVICE_HOST_PSK_PROGRESS);
        enum device_host_bridge_result first = typed_test_device_host_psk_bridge_step(&f.server);
        ASSERT(psk_io_live_result(first)); ASSERT(f.server.unread_used > f.server.unread_sent);
        ASSERT_EQ(typed_test_device_host_psk_bridge_step(&f.server), DEVICE_HOST_BRIDGE_REFUSED); ASSERT(!f.server.active);
    } TEST_END
    device_pairing_guard_release(&guard); psk_io_fixture_close(&f); return failures;
}
static int psk_io_refused_target(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    TEST_CASE("host PSK IO: actual loopback connection refusal yields no S_READY or client plaintext reads") {
        ASSERT(psk_io_fixture_open(&f, 0, false)); close(f.listener); f.listener = -1;
        ASSERT(psk_io_fixture_admit(&f));
        enum device_host_bridge_result result = DEVICE_HOST_BRIDGE_WAIT;
        int64_t deadline = psk_io_fixture_mono(&f) + INT64_C(5000000000);
        while (psk_io_fixture_mono(&f) < deadline && psk_io_live_result(result)) {
            (void)typed_test_device_host_psk_bridge_step(&f.client); result = typed_test_device_host_psk_bridge_step(&f.server);
            (void)poll(NULL, 0, 1);
        }
        ASSERT_EQ(result, DEVICE_HOST_BRIDGE_IO_ERROR); ASSERT_EQ(f.server.observation.error_number, ECONNREFUSED);
        ASSERT(!f.server.observation.target_connected); ASSERT_EQ(f.client.observation.plaintext_read_bytes, 0);
    } TEST_END
    psk_io_fixture_close(&f); return failures;
}
static int psk_io_closed_stderr(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f); pid_t child = -1;
    TEST_CASE("host PSK IO: closed stderr refuses before custody or target allocation without harming harness diagnostics") {
        ASSERT(psk_io_fixture_open(&f, 0, false)); child = fork(); ASSERT(child >= 0);
        if (!child) {
            close(STDERR_FILENO);
            enum device_host_bridge_result result = typed_test_device_host_psk_bridge_open(&f.client, &f.client_spec);
            _exit(result == DEVICE_HOST_BRIDGE_REFUSED && !f.client.observation.io_taken &&
                fcntl(f.carrier[0], F_GETFD) >= 0 && fcntl(f.plain[1], F_GETFD) >= 0 ? 0 : 1);
        }
        int status = 0; bool reaped = reap_fixture(child, &status);
        if (reaped) child = -1;
        ASSERT(reaped); ASSERT(WIFEXITED(status)); ASSERT_EQ(WEXITSTATUS(status), 0); ASSERT(no_connection(f.listener));
    } TEST_END
    if (child > 0 && !cleanup_fixture_child(child)) failures++;
    psk_io_fixture_close(&f); return failures;
}
static int psk_io_preflight_refusals(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f); int unconnected = -1;
    TEST_CASE("host PSK IO: invalid descriptor geometry and wrong root retain caller custody and never dial") {
        ASSERT(psk_io_fixture_open(&f, 0, false));
        struct device_host_psk_bridge_spec bad = f.client_spec;
        bad.carrier_input_fd = bad.carrier_output_fd = f.plain[1];
        ASSERT_EQ(typed_test_device_host_psk_bridge_open(&f.client, &bad), DEVICE_HOST_BRIDGE_REFUSED);
        ASSERT(!f.client.observation.io_taken); ASSERT(fcntl(f.plain[1], F_GETFD) >= 0);
        unconnected = platform_socket_open(AF_UNIX, SOCK_STREAM, 0, true, true); ASSERT(unconnected >= 0);
        bad = f.client_spec; bad.carrier_input_fd = bad.carrier_output_fd = unconnected;
        ASSERT_EQ(typed_test_device_host_psk_bridge_open(&f.client, &bad), DEVICE_HOST_BRIDGE_REFUSED);
        ASSERT(fcntl(unconnected, F_GETFD) >= 0);
        bad = f.client_spec; bad.session.approved_root[0] ^= 1;
        ASSERT_EQ(typed_test_device_host_psk_bridge_open(&f.client, &bad), DEVICE_HOST_BRIDGE_REFUSED);
        ASSERT(!f.client.observation.io_taken); ASSERT(fcntl(f.carrier[0], F_GETFD) >= 0);
        ASSERT_EQ(typed_test_device_host_psk_bridge_open(&f.client, &f.client_spec), DEVICE_HOST_BRIDGE_REFUSED);
        ASSERT(no_connection(f.listener));
    } TEST_END
    if (unconnected >= 0) close(unconnected);
    psk_io_fixture_close(&f); return failures;
}
static bool psk_io_backup_ready(struct psk_io_fixture *f, struct device_host_psk_bridge *client,
    struct device_host_psk_bridge *server, int *target)
{
    int64_t deadline = psk_io_fixture_mono(f) + INT64_C(5000000000);
    while (psk_io_fixture_mono(f) < deadline) {
        if (!psk_io_pair_step(client, server)) return false;
        if (*target < 0) *target = fixture_accept(f->listener);
        if (client->session.phase == DEVICE_HOST_PSK_ESTABLISHED && server->session.phase == DEVICE_HOST_PSK_ESTABLISHED)
            return *target >= 0;
        (void)poll(NULL, 0, 1);
    }
    return false;
}
static int psk_io_explicit_backup(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    struct device_host_psk_bridge client, server; device_host_psk_bridge_init(&client); device_host_psk_bridge_init(&server);
    int carrier[2] = {-1,-1}, plain[2] = {-1,-1}, target = -1;
    TEST_CASE("host PSK IO: failed primary closes, explicit fresh carrier and new nonce/context succeeds without automatic retry") {
        ASSERT(psk_io_fixture_open(&f, 0, false)); ASSERT(psk_io_fixture_admit(&f)); ASSERT(psk_io_fixture_ready(&f));
        uint8_t old_nonce[32]; memcpy(old_nonce, f.client.session.nonce, sizeof(old_nonce));
        device_host_psk_bridge_close(&f.client, DEVICE_HOST_BRIDGE_IO_ERROR);
        ASSERT_EQ(typed_test_device_host_psk_bridge_step(&f.server), DEVICE_HOST_BRIDGE_REFUSED);
        ASSERT_EQ(typed_test_device_host_psk_bridge_open(&f.client, &f.client_spec), DEVICE_HOST_BRIDGE_REFUSED);
        close(f.target); f.target = -1;
        ASSERT(fixture_socket_pair(carrier)); ASSERT(fixture_socket_pair(plain));
        struct device_host_psk_bridge_spec c = f.client_spec, s = f.server_spec;
        c.carrier_input_fd = c.carrier_output_fd = carrier[0]; c.input_fd = c.output_fd = plain[1];
        s.carrier_input_fd = s.carrier_output_fd = carrier[1];
        c.session.deadline_ns = s.session.deadline_ns = psk_io_fixture_mono(&f) + INT64_C(5000000000);
        uint8_t nonce[32] = {0x81}; device_host_psk_test_nonce(nonce, false);
        enum device_host_bridge_result result = typed_test_device_host_psk_bridge_open(&client, &c);
        if (client.observation.io_taken) { carrier[0] = -1; plain[1] = -1; }
        ASSERT_EQ(result, DEVICE_HOST_BRIDGE_READY);
        nonce[0] = 0xa1; device_host_psk_test_nonce(nonce, false);
        result = typed_test_device_host_psk_bridge_open(&server, &s); if (server.observation.io_taken) carrier[1] = -1;
        ASSERT_EQ(result, DEVICE_HOST_BRIDGE_READY);
        ASSERT(psk_io_backup_ready(&f, &client, &server, &target));
        ASSERT(memcmp(old_nonce, client.session.nonce, sizeof(old_nonce))); ASSERT_EQ(client.session.send_sequence, 0);
        const uint8_t byte = 0x42; ASSERT_EQ(send(plain[0], &byte, 1, MSG_NOSIGNAL), 1);
        uint8_t seen = 0; ssize_t count = -1; int64_t deadline = psk_io_fixture_mono(&f) + INT64_C(5000000000);
        while (psk_io_fixture_mono(&f) < deadline && count < 0) {
            ASSERT(psk_io_pair_step(&client, &server)); count = recv(target, &seen, 1, MSG_DONTWAIT);
        }
        ASSERT_EQ(count, 1); ASSERT_EQ(seen, byte); ASSERT_EQ(server.observation.plaintext_written_bytes, 1);
    } TEST_END
    device_host_psk_bridge_close(&client, DEVICE_HOST_BRIDGE_CANCELLED); device_host_psk_bridge_close(&server, DEVICE_HOST_BRIDGE_CANCELLED);
    for (size_t i = 0; i < 2; ++i) { if (carrier[i] >= 0) close(carrier[i]); if (plain[i] >= 0) close(plain[i]); }
    if (target >= 0) close(target);
    psk_io_fixture_close(&f); return failures;
}
#if defined(__APPLE__)
/* Pause the peer and queue only authenticated records until the real kernel
 * accepts a positive prefix. Queue pressure is observed, not inferred from a
 * platform-specific number of socket-buffer allocations. */
static bool psk_io_fill_authenticated(struct psk_io_fixture *f, const uint8_t payload[4096],
    size_t *complete, uint64_t *before)
{
    *complete = 0;
    for (unsigned record = 0; record < 64; record++) {
        if (send(f->plain[0], payload, 4096, MSG_NOSIGNAL) != 4096) return false;
        *before = f->client.observation.carrier_written_bytes;
        if (!psk_io_live_result(typed_test_device_host_psk_bridge_step(&f->client))) return false;
        if (f->client.session.pending_sent > 0 &&
            f->client.session.pending_sent < f->client.session.pending_used) return true;
        if (f->client.session.pending_used != 0) return false;
        ++*complete;
    }
    return false;
}
static bool psk_io_drain_authenticated_prefix(struct psk_io_fixture *f,
    const uint8_t payload[4096], size_t records)
{
    size_t total = records * 4096, seen = 0;
    int64_t deadline = psk_io_fixture_mono(f) + INT64_C(5000000000);
    for (unsigned attempt = 0; attempt < 5000 && psk_io_fixture_mono(f) < deadline; attempt++) {
        if (!psk_io_live_result(typed_test_device_host_psk_bridge_step(&f->server))) return false;
        uint8_t bytes[4096]; ssize_t n = recv(f->target, bytes, sizeof(bytes), MSG_DONTWAIT);
        if (n > 0) {
            if ((size_t)n > total - seen) return false;
            for (size_t i = 0; i < (size_t)n; i++)
                if (bytes[i] != payload[(seen + i) % 4096]) return false;
            seen += (size_t)n;
        } else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) return false;
        if (seen == total && f->server.observation.plaintext_written_bytes == total &&
            f->server.session.incoming_used > 0) return true;
        (void)poll(NULL, 0, 1);
    }
    return false;
}
static int psk_io_partial_ciphertext_mac(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    struct shake_wrap_state sealed = {0};
    TEST_CASE("host PSK IO: actual short ciphertext syscall retains suffix/state and no premature plaintext on macOS") {
        ASSERT(psk_io_fixture_open(&f, 0, false)); ASSERT(psk_io_fixture_admit(&f)); ASSERT(psk_io_fixture_ready(&f));
        int small = 1024, low = 1;
        ASSERT_EQ(setsockopt(f.client.spec.carrier_output_fd, SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)), 0);
        ASSERT_EQ(setsockopt(f.client.spec.carrier_output_fd, SOL_SOCKET, SO_SNDLOWAT, &low, sizeof(low)), 0);
        uint8_t payload[4096]; for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)i;
        size_t complete = 0; uint64_t before = 0;
        ASSERT(psk_io_fill_authenticated(&f, payload, &complete, &before));
        ASSERT(f.client.session.pending_sent > 0); ASSERT(f.client.session.pending_sent < f.client.session.pending_used);
        sealed = f.client.session.send; ASSERT_EQ(f.client.session.send_sequence, complete + 1);
        ASSERT(psk_io_drain_authenticated_prefix(&f, payload, complete));
        ASSERT_EQ(f.server.session.plaintext_used, 0);
        ASSERT(f.server.session.incoming_used > 0); ASSERT(f.server.session.incoming_used < DEVICE_HOST_PSK_WIRE);
        uint8_t byte; ASSERT_EQ(recv(f.target, &byte, 1, MSG_DONTWAIT), -1);
        ASSERT(errno == EAGAIN || errno == EWOULDBLOCK);
        int64_t deadline = psk_io_fixture_mono(&f) + INT64_C(5000000000); size_t seen = 0;
        while (psk_io_fixture_mono(&f) < deadline && seen < sizeof(payload)) {
            ASSERT(psk_io_pair_step(&f.client, &f.server)); ASSERT(psk_io_try_receive(f.target, payload, sizeof(payload), &seen));
        }
        ASSERT_EQ(seen, sizeof(payload)); ASSERT_EQ(f.client.observation.carrier_written_bytes - before, DEVICE_HOST_PSK_WIRE);
        ASSERT_EQ(f.client.session.send_sequence, complete + 1); ASSERT(!memcmp(&sealed, &f.client.session.send, sizeof(sealed)));
        ASSERT_EQ(f.server.observation.plaintext_written_bytes, (complete + 1) * sizeof(payload));
    } TEST_END
    shake_wrap_destroy(&sealed); psk_io_fixture_close(&f); return failures;
}
#endif
static int psk_io_partial_ciphertext(void)
{
#if defined(__APPLE__)
    return psk_io_partial_ciphertext_mac();
#else
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    struct shake_wrap_state sealed = {0};
    TEST_CASE("host PSK IO: actual short ciphertext syscall retains suffix/state and no plaintext before full authenticated record") {
        ASSERT(psk_io_fixture_open(&f, 0, false)); ASSERT(psk_io_fixture_admit(&f)); ASSERT(psk_io_fixture_ready(&f));
        int small = 1024; ASSERT_EQ(setsockopt(f.client.spec.carrier_output_fd, SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)), 0);
        /* An empty AF_UNIX send queue can accept the entire large write even
         * above its nominal byte budget. Three complete authenticated small
         * records occupy distinct skb allocations while the peer is paused;
         * the next large record has room for a positive prefix, not all of it.
         * No unauthenticated filler is injected into the carrier. */
        const uint8_t warm[] = {0xf0, 0xf1, 0xf2};
        for (size_t i = 0; i < sizeof(warm); ++i) {
            ASSERT_EQ(send(f.plain[0], warm + i, 1, MSG_NOSIGNAL), 1);
            ASSERT(psk_io_live_result(typed_test_device_host_psk_bridge_step(&f.client)));
            ASSERT_EQ(f.client.session.pending_used, 0);
        }
        uint8_t payload[4096]; for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (uint8_t)i;
        ASSERT_EQ(send(f.plain[0], payload, sizeof(payload), MSG_NOSIGNAL), sizeof(payload));
        uint64_t before = f.client.observation.carrier_written_bytes;
        ASSERT(psk_io_live_result(typed_test_device_host_psk_bridge_step(&f.client)));
        ASSERT(f.client.session.pending_sent > 0); ASSERT(f.client.session.pending_sent < f.client.session.pending_used);
        sealed = f.client.session.send; ASSERT_EQ(f.client.session.send_sequence, 4);
        int64_t warm_deadline = psk_io_fixture_mono(&f) + INT64_C(5000000000);
        while (psk_io_fixture_mono(&f) < warm_deadline && f.server.observation.plaintext_written_bytes < sizeof(warm))
            ASSERT(psk_io_live_result(typed_test_device_host_psk_bridge_step(&f.server)));
        ASSERT_EQ(f.server.observation.plaintext_written_bytes, sizeof(warm));
        ASSERT_EQ(f.server.session.plaintext_used, 0);
        ASSERT(f.server.session.incoming_used > 0); ASSERT(f.server.session.incoming_used < DEVICE_HOST_PSK_WIRE);
        size_t warm_seen = 0;
        while (psk_io_fixture_mono(&f) < warm_deadline && warm_seen < sizeof(warm))
            ASSERT(psk_io_try_receive(f.target, warm, sizeof(warm), &warm_seen));
        ASSERT_EQ(warm_seen, sizeof(warm));
        uint8_t byte; ssize_t absent = recv(f.target, &byte, 1, MSG_DONTWAIT); int error = errno;
        ASSERT_EQ(absent, -1); ASSERT(error == EAGAIN || error == EWOULDBLOCK);
        int64_t deadline = psk_io_fixture_mono(&f) + INT64_C(5000000000); size_t seen = 0;
        while (psk_io_fixture_mono(&f) < deadline && seen < sizeof(payload)) {
            ASSERT(psk_io_pair_step(&f.client, &f.server)); ASSERT(psk_io_try_receive(f.target, payload, sizeof(payload), &seen));
        }
        ASSERT_EQ(seen, sizeof(payload)); ASSERT_EQ(f.client.observation.carrier_written_bytes - before, DEVICE_HOST_PSK_WIRE);
        ASSERT_EQ(f.client.session.send_sequence, 4); ASSERT(!memcmp(&sealed, &f.client.session.send, sizeof(sealed)));
        ASSERT_EQ(f.server.observation.plaintext_written_bytes, sizeof(warm) + sizeof(payload));
    } TEST_END
    shake_wrap_destroy(&sealed); psk_io_fixture_close(&f); return failures;
#endif
}
struct bridge_deadline_clock {
    int64_t now, expired;
    struct device_host_psk_bridge *watch;
    bool saw_established;
};
static int64_t bridge_deadline_mono(void *opaque)
{
    struct bridge_deadline_clock *clock = opaque;
    if (clock->watch && clock->watch->session.phase == DEVICE_HOST_PSK_ESTABLISHED) {
        clock->saw_established = true; clock->now = clock->expired;
    }
    return clock->now;
}
static int64_t bridge_deadline_wall(void *opaque) { (void)opaque; return 150000; }
static int psk_io_deadline_expiry(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    struct bridge_deadline_clock clock = {0};
    clock_iface_t fake = {bridge_deadline_mono, bridge_deadline_wall, &clock};
    TEST_CASE("host PSK deadline: expired authenticated idle bound cannot revive; ceiling immutable") {
        ASSERT(psk_io_fixture_open(&f, 0, false)); ASSERT(psk_io_fixture_admit(&f)); ASSERT(psk_io_fixture_ready(&f));
        int64_t ceiling = f.client.hard_deadline_ns, tight = ceiling - INT64_C(1000000);
        clock.now = tight - 1; clock_set_default(&fake);
        ASSERT_EQ(typed_test_device_host_psk_bridge_set_deadline(&f.client, tight), DEVICE_HOST_BRIDGE_READY);
        ASSERT_EQ(f.client.spec.session.deadline_ns, tight); ASSERT_EQ(f.client.session.spec.deadline_ns, tight);
        ASSERT_EQ(f.client.hard_deadline_ns, ceiling);
        clock.now = tight;
        ASSERT_EQ(typed_test_device_host_psk_bridge_set_deadline(&f.client, ceiling), DEVICE_HOST_BRIDGE_DEADLINE);
        ASSERT(!f.client.active);
        struct pollfd readable = {.fd = f.server.spec.carrier_input_fd, .events = POLLIN};
        ASSERT(poll(&readable, 1, 1000) > 0);
        uint8_t byte; ASSERT_EQ(recv(f.server.spec.carrier_input_fd, &byte, 1, MSG_DONTWAIT), 0);
        ASSERT_EQ(typed_test_device_host_psk_bridge_set_deadline(&f.client, ceiling + 1), DEVICE_HOST_BRIDGE_DEADLINE);
    } TEST_END
    psk_io_fixture_close(&f); return failures;
}
static int psk_io_deadline_handshake(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    struct bridge_deadline_clock clock = {0};
    clock_iface_t fake = {bridge_deadline_mono, bridge_deadline_wall, &clock};
    TEST_CASE("host PSK deadline: ready transition crossing old handshake bound releases no client input") {
        ASSERT(psk_io_fixture_open(&f, 0, false)); ASSERT(psk_io_fixture_admit(&f));
        int64_t tight = f.client.hard_deadline_ns - INT64_C(1000000);
        clock.now = tight - 1; clock.expired = tight; clock.watch = &f.client; clock_set_default(&fake);
        ASSERT_EQ(typed_test_device_host_psk_bridge_set_deadline(&f.client, tight), DEVICE_HOST_BRIDGE_READY);
        enum device_host_bridge_result result = DEVICE_HOST_BRIDGE_WAIT;
        int64_t wait_deadline = psk_io_fixture_mono(&f) + INT64_C(5000000000);
        while (psk_io_live_result(result) && psk_io_fixture_mono(&f) < wait_deadline) {
            result = typed_test_device_host_psk_bridge_step(&f.client);
            if (psk_io_live_result(result)) (void)typed_test_device_host_psk_bridge_step(&f.server);
        }
        ASSERT(clock.saw_established); ASSERT_EQ(result, DEVICE_HOST_BRIDGE_DEADLINE);
        ASSERT_EQ(f.client.observation.plaintext_read_bytes, 0); ASSERT(!f.client.active);
        ASSERT_EQ(typed_test_device_host_psk_bridge_set_deadline(&f.client, tight + 1), DEVICE_HOST_BRIDGE_DEADLINE);
    } TEST_END
    psk_io_fixture_close(&f); return failures;
}
static int psk_io_deadline_phase_ceiling(void)
{
    int failures = 0;
    for (unsigned scenario = 0; scenario < 2; ++scenario) {
        struct psk_io_fixture f; psk_io_fixture_init(&f);
        struct bridge_deadline_clock clock = {0}; clock_iface_t fake = {bridge_deadline_mono, bridge_deadline_wall, &clock};
        TEST_CASE("host PSK deadline: no unauthenticated extension or immutable ceiling bypass") {
            ASSERT(psk_io_fixture_open(&f, 0, false)); ASSERT(psk_io_fixture_admit(&f));
            if (scenario) ASSERT(psk_io_fixture_ready(&f));
            int64_t ceiling = f.client.hard_deadline_ns, tight = ceiling - INT64_C(1000000);
            clock.now = tight - 1; clock_set_default(&fake);
            ASSERT_EQ(typed_test_device_host_psk_bridge_set_deadline(&f.client, tight), DEVICE_HOST_BRIDGE_READY);
            ASSERT_EQ(typed_test_device_host_psk_bridge_set_deadline(&f.client, scenario ? ceiling + 1 : ceiling), DEVICE_HOST_BRIDGE_REFUSED);
            ASSERT(!f.client.active);
        } TEST_END
        psk_io_fixture_close(&f);
    }
    return failures;
}
static int psk_io_deadline_borrowed(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    struct device_pairing_guard guard = {0};
    TEST_CASE("host PSK deadline: borrowed span refuses unchanged without unlocking caller custody") {
        ASSERT(psk_io_fixture_open(&f, 0, false)); ASSERT(psk_io_fixture_admit(&f)); ASSERT(psk_io_fixture_ready(&f));
        uint8_t byte = 42; ASSERT_EQ(typed_test_device_host_psk_queue_data(&f.client.session, &byte, 1), DEVICE_HOST_PSK_PROGRESS);
        const uint8_t *bytes = NULL; size_t length = 0;
        enum device_host_psk_result borrowed = typed_test_device_host_psk_pending_acquire(&f.client.session, &guard, &bytes, &length);
        int64_t before = f.client.spec.session.deadline_ns;
        enum device_host_bridge_result result = typed_test_device_host_psk_bridge_set_deadline(&f.client, before - 1);
        bool retained = guard.held && f.client.session.borrowed_guard == &guard;
        bool unchanged = f.client.active && f.client.spec.session.deadline_ns == before && f.client.session.spec.deadline_ns == before;
        enum device_pairing_publication publication;
        bool denied = !db_device_pairing_revoke_expected(&f.store[0], f.row[0].peer_key, 150, f.root[0], &publication);
        enum device_host_psk_result released = typed_test_device_host_psk_pending_written(&f.client.session, &guard, 0);
        ASSERT_EQ(borrowed, DEVICE_HOST_PSK_PROGRESS); ASSERT(length > 0); ASSERT(bytes != NULL);
        ASSERT_EQ(result, DEVICE_HOST_BRIDGE_REFUSED); ASSERT(retained); ASSERT(unchanged); ASSERT(denied);
        ASSERT_EQ(released, DEVICE_HOST_PSK_PROGRESS); ASSERT(!guard.held);
    } TEST_END
    if (f.client.session.borrowed_guard) (void)typed_test_device_host_psk_pending_written(&f.client.session, &guard, 0);
    device_pairing_guard_release(&guard); psk_io_fixture_close(&f); return failures;
}
static unsigned psk_plan_events(const struct device_host_bridge_poll_plan *plan, int fd)
{
    for (size_t i = 0; i < plan->count; ++i)
        if (plan->entries[i].fd == fd) return plan->entries[i].events;
    return 0;
}
static int psk_io_poll_interest(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    struct device_pairing_guard guard = {0};
    TEST_CASE("host PSK readiness: idle reads only, merged pending write, borrowed refusal preserves output and custody") {
        ASSERT(psk_io_fixture_open(&f, 0, false)); ASSERT(psk_io_fixture_admit(&f)); ASSERT(psk_io_fixture_ready(&f));
        struct device_host_bridge_poll_plan plan;
        ASSERT_EQ(typed_test_device_host_psk_bridge_poll_interest(&f.client, &plan), DEVICE_HOST_BRIDGE_READY);
        ASSERT(!plan.immediate); ASSERT_EQ(plan.deadline_ns, f.client.spec.session.deadline_ns);
        ASSERT_EQ(psk_plan_events(&plan, f.client.spec.carrier_input_fd), DEVICE_HOST_BRIDGE_POLL_READ);
        ASSERT_EQ(psk_plan_events(&plan, f.client.spec.input_fd), DEVICE_HOST_BRIDGE_POLL_READ);
        ASSERT_EQ(plan.count, 2);
        uint8_t byte = 0x42; ASSERT_EQ(typed_test_device_host_psk_queue_data(&f.client.session, &byte, 1), DEVICE_HOST_PSK_PROGRESS);
        ASSERT_EQ(typed_test_device_host_psk_bridge_poll_interest(&f.client, &plan), DEVICE_HOST_BRIDGE_READY);
        ASSERT_EQ(psk_plan_events(&plan, f.client.spec.carrier_input_fd), DEVICE_HOST_BRIDGE_POLL_READ | DEVICE_HOST_BRIDGE_POLL_WRITE);
        ASSERT_EQ(psk_plan_events(&plan, f.client.spec.input_fd), 0);
        const uint8_t *bytes = NULL; size_t length = 0;
        ASSERT_EQ(typed_test_device_host_psk_pending_acquire(&f.client.session, &guard, &bytes, &length), DEVICE_HOST_PSK_PROGRESS);
        struct device_host_bridge_poll_plan before = plan;
        ASSERT_EQ(typed_test_device_host_psk_bridge_poll_interest(&f.client, &plan), DEVICE_HOST_BRIDGE_REFUSED);
        ASSERT(!memcmp(&plan, &before, sizeof(plan))); ASSERT(guard.held);
        ASSERT_EQ(typed_test_device_host_psk_pending_written(&f.client.session, &guard, 0), DEVICE_HOST_PSK_PROGRESS);
        ASSERT(!guard.held);
    } TEST_END
    if (f.client.session.borrowed_guard) (void)typed_test_device_host_psk_pending_written(&f.client.session, &guard, 0);
    device_pairing_guard_release(&guard); psk_io_fixture_close(&f); return failures;
}
static bool psk_plan_quiet(const struct device_host_bridge_poll_plan *plan)
{
    struct pollfd entries[5];
    for (size_t i = 0; i < plan->count; ++i) {
        if (!plan->entries[i].events) return false;
        entries[i] = (struct pollfd){.fd = plan->entries[i].fd,
            .events = (short)(((plan->entries[i].events & DEVICE_HOST_BRIDGE_POLL_READ) ? POLLIN : 0) |
                             ((plan->entries[i].events & DEVICE_HOST_BRIDGE_POLL_WRITE) ? POLLOUT : 0))};
    }
    return !plan->immediate && poll(entries, plan->count, 0) == 0;
}
static int psk_io_poll_stalled_hup(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    TEST_CASE("host PSK readiness: real carrier HUP with blocked verified plaintext does not continuously wake idle plan") {
        ASSERT(psk_io_fixture_open(&f, 0, false)); ASSERT(psk_io_fixture_admit(&f)); ASSERT(psk_io_fixture_ready(&f));
        ASSERT(fill_queue(f.client.spec.output_fd, 0x71) > 0);
        uint8_t byte = 0x42; ASSERT_EQ(send(f.target, &byte, 1, MSG_NOSIGNAL), 1);
        int64_t deadline = psk_io_fixture_mono(&f) + INT64_C(3000000000);
        while (!f.client.session.plaintext_used && psk_io_fixture_mono(&f) < deadline)
            ASSERT(psk_io_pair_step(&f.client, &f.server));
        ASSERT_EQ(f.client.session.plaintext_used, 1); ASSERT_EQ(f.client.session.plaintext_sent, 0);
        int carrier = f.client.spec.carrier_input_fd;
        device_host_psk_bridge_close(&f.server, DEVICE_HOST_BRIDGE_CANCELLED);
        struct pollfd actual = {.fd = carrier, .events = POLLIN};
        ASSERT(poll(&actual, 1, 1000) > 0); ASSERT(actual.revents & POLLHUP);
        ASSERT_EQ(typed_test_device_host_psk_bridge_poll_observed(&f.client, carrier, DEVICE_HOST_BRIDGE_POLL_HANGUP), DEVICE_HOST_BRIDGE_READY);
        ASSERT_EQ(typed_test_device_host_psk_bridge_step(&f.client), DEVICE_HOST_BRIDGE_WAIT);
        struct device_host_bridge_poll_plan plan;
        ASSERT_EQ(typed_test_device_host_psk_bridge_poll_interest(&f.client, &plan), DEVICE_HOST_BRIDGE_READY);
        ASSERT_EQ(psk_plan_events(&plan, carrier), 0); ASSERT(psk_plan_quiet(&plan));
        ASSERT(f.client.active); ASSERT_EQ(f.client.session.plaintext_used, 1);
        ASSERT_EQ(f.client.observation.plaintext_written_bytes, 0);
    } TEST_END
    psk_io_fixture_close(&f); return failures;
}
static int psk_io_poll_pending_hup(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    TEST_CASE("host PSK readiness: real full shared-carrier HUP with pending ciphertext fails guarded EPIPE and closes") {
        ASSERT(psk_io_fixture_open(&f, 0, false)); ASSERT(psk_io_fixture_admit(&f)); ASSERT(psk_io_fixture_ready(&f));
        uint8_t byte = 0x43; ASSERT_EQ(typed_test_device_host_psk_queue_data(&f.client.session, &byte, 1), DEVICE_HOST_PSK_PROGRESS);
        ASSERT(f.client.session.pending_used > 0); int carrier = f.client.spec.carrier_output_fd;
        device_host_psk_bridge_close(&f.server, DEVICE_HOST_BRIDGE_CANCELLED);
        struct pollfd event = {.fd = carrier, .events = POLLOUT};
        ASSERT(poll(&event, 1, 1000) > 0); ASSERT(event.revents & POLLHUP);
        ASSERT_EQ(typed_test_device_host_psk_bridge_poll_observed(&f.client, carrier, DEVICE_HOST_BRIDGE_POLL_HANGUP), DEVICE_HOST_BRIDGE_READY);
        enum device_host_bridge_result status;
        struct zcl_result failed = device_host_psk_bridge_step(&f.client, &status);
        ASSERT(!failed.ok); ASSERT_EQ(failed.code, -EPIPE); ASSERT_EQ(status, DEVICE_HOST_BRIDGE_IO_ERROR);
        ASSERT_EQ(f.client.observation.error_number, EPIPE); ASSERT(!f.client.active);
        ASSERT_EQ(f.client.session.pending_used, 0);
        ASSERT_EQ(recv(f.plain[0], &byte, 1, MSG_DONTWAIT), 0);
    } TEST_END
    psk_io_fixture_close(&f); return failures;
}
static bool psk_io_finish_steps(struct psk_io_fixture *f)
{
    int64_t deadline = psk_io_fixture_mono(f) + INT64_C(3000000000);
    while (psk_io_fixture_mono(f) < deadline) {
        if (f->client.active) {
            enum device_host_bridge_result result = typed_test_device_host_psk_bridge_step(&f->client);
            if (!psk_io_live_result(result) && result != DEVICE_HOST_BRIDGE_EOF) return false;
        }
        if (f->server.active) {
            enum device_host_bridge_result result = typed_test_device_host_psk_bridge_step(&f->server);
            if (!psk_io_live_result(result) && result != DEVICE_HOST_BRIDGE_EOF) return false;
        }
        if (!f->client.active && !f->server.active) return true;
        (void)poll(NULL, 0, 1);
    }
    return false;
}
static int psk_io_poll_reverse_fin(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    const uint8_t reverse[] = {0, 0xff, 0x42, 0x81};
    TEST_CASE("host PSK readiness: authenticated FIN and peer write-half EOF preserve pending reverse DATA and FIN") {
        ASSERT(psk_io_fixture_open(&f, 0, false)); ASSERT(psk_io_fixture_admit(&f)); ASSERT(psk_io_fixture_ready(&f));
        ASSERT_EQ(typed_test_device_host_psk_queue_data(&f.server.session, reverse, sizeof(reverse)), DEVICE_HOST_PSK_PROGRESS);
        ASSERT_EQ(typed_test_device_host_psk_queue_fin(&f.client.session), DEVICE_HOST_PSK_PROGRESS);
        ASSERT(psk_io_live_result(typed_test_device_host_psk_bridge_step(&f.client))); ASSERT(f.client.carrier_half_closed);
        ASSERT(psk_io_live_result(typed_test_device_host_psk_bridge_step(&f.server))); ASSERT(f.server.session.receive_fin);
        uint8_t byte; ASSERT_EQ(psk_io_wait_byte(&f, f.target, &byte), 0);
        ASSERT_EQ(typed_test_device_host_psk_queue_fin(&f.server.session), DEVICE_HOST_PSK_PROGRESS);
        ASSERT(f.server.session.pending_used > 0);
        struct device_host_bridge_poll_plan plan;
        ASSERT_EQ(typed_test_device_host_psk_bridge_poll_interest(&f.server, &plan), DEVICE_HOST_BRIDGE_READY);
        ASSERT(psk_plan_events(&plan, f.server.spec.carrier_output_fd) & DEVICE_HOST_BRIDGE_POLL_WRITE);
        ASSERT(psk_io_finish_steps(&f));
        uint8_t seen[sizeof(reverse)]; ASSERT_EQ(recv(f.plain[0], seen, sizeof(seen), MSG_DONTWAIT), sizeof(seen));
        ASSERT(!memcmp(seen, reverse, sizeof(seen))); ASSERT_EQ(recv(f.plain[0], &byte, 1, MSG_DONTWAIT), 0);
        ASSERT_EQ(f.client.observation.result, DEVICE_HOST_BRIDGE_EOF); ASSERT_EQ(f.server.observation.result, DEVICE_HOST_BRIDGE_EOF);
    } TEST_END
    psk_io_fixture_close(&f); return failures;
}
static int psk_io_typed_outputs(void)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    struct device_pairing_guard guard = {0};
    TEST_CASE("host bridge typed boundary: spec, context, plan and held guard status aliases preserve ownership") {
        ASSERT(psk_io_fixture_open(&f, 0, false));
        uint16_t port = f.client_spec.session.port;
        struct zcl_result result = device_host_psk_bridge_open(&f.client, &f.client_spec,
            (enum device_host_bridge_result *)&f.client_spec);
        ASSERT(!result.ok); ASSERT(!f.client.active); ASSERT(!f.client.observation.io_taken);
        ASSERT_EQ(f.client_spec.session.port, port);
        ASSERT(psk_io_fixture_admit(&f));
        enum device_host_bridge_result prior = f.client.observation.result;
        result = device_host_psk_bridge_step(&f.client, &f.client.observation.result);
        ASSERT(!result.ok); ASSERT(f.client.active); ASSERT_EQ(f.client.observation.result, prior);
        struct device_host_bridge_poll_plan plan = {.deadline_ns = 71}, before = plan;
        result = device_host_psk_bridge_poll_interest(&f.client, &plan,
            (enum device_host_bridge_result *)&plan.deadline_ns);
        ASSERT(!result.ok); ASSERT(!memcmp(&plan, &before, sizeof(plan))); ASSERT(f.client.active);
        enum device_host_psk_result state; const uint8_t *bytes = NULL; size_t length = 0;
        result = device_host_psk_pending_acquire(&f.client.session, &guard, &bytes, &length, &state);
        ASSERT(result.ok); ASSERT(guard.held);
        int64_t deadline = f.client.spec.session.deadline_ns;
        result = device_host_psk_bridge_set_deadline(&f.client, deadline,
            (enum device_host_bridge_result *)&guard.row);
        ASSERT(!result.ok); ASSERT(guard.held); ASSERT(f.client.session.borrowed_guard == &guard);
        ASSERT_EQ(f.client.spec.session.deadline_ns, deadline); ASSERT(f.client.active);
        result = device_host_psk_pending_written(&f.client.session, &guard, 0, &state);
        ASSERT(result.ok); ASSERT(!guard.held);
    } TEST_END
    device_pairing_guard_release(&guard); psk_io_fixture_close(&f); return failures;
}
/* Mode 0 revokes, 1 rotates, 2 strands a stage-1 publication intent while the
 * grant bytes and inode stay unchanged. Each commits between steps, with no
 * guard held, so no record is in progress and nothing more may cross. */
static bool psk_io_change_server(struct psk_io_fixture *f, unsigned mode)
{
    const struct device_host_psk_spec *s = &f->server_spec.session;
    enum device_pairing_publication publication = DEVICE_PAIRING_NOT_PUBLISHED;
    if (mode == 0) return db_device_pairing_revoke_expected(s->store, s->peer, 150, s->approved_root, &publication) &&
        publication == DEVICE_PAIRING_DURABLE;
    if (mode == 2) {
        device_pairing_test_interrupt(1);
        bool published = db_device_pairing_revoke_expected(s->store, s->peer, 150, s->approved_root, &publication);
        device_pairing_test_interrupt(0);
        return !published;
    }
    struct db_device_pairing next = f->row[1]; struct device_pairing_psk_publication report;
    next.host_scope.binding.psk.credential_id[0] = 92; next.host_scope.binding.psk.key_epoch = 2;
    uint8_t secret[32] = {18}, proposal[32];
    return device_pairing_host_proposal_root(&next, proposal) &&
        db_device_pairing_rotate_host_psk(s->store, &next, secret, proposal, s->approved_root, 150, &report) &&
        report.grant == DEVICE_PAIRING_DURABLE;
}
static int psk_io_midstream_authority(unsigned mode)
{
    int failures = 0; struct psk_io_fixture f; psk_io_fixture_init(&f);
    TEST_CASE("host PSK IO: revoke, rotation or stranded intent committed mid-stream stops every further server record") {
        ASSERT(psk_io_fixture_open(&f, 0, false)); ASSERT(psk_io_fixture_admit(&f)); ASSERT(psk_io_fixture_ready(&f));
        uint8_t bytes[4096]; for (size_t i = 0; i < sizeof(bytes); ++i) bytes[i] = (uint8_t)(i * 7 + mode);
        /* Freeze the monotonic source so a slow run cannot age the server cache past its window. */
        f.frozen_ns = psk_io_fixture_mono(&f);
        uint64_t cached0 = 0, cached1 = 0; device_pairing_guard_counts(NULL, &cached0);
        for (unsigned i = 0; i < 4; ++i) {
            ASSERT(psk_io_transfer(&f, f.plain[0], f.target, bytes, sizeof(bytes)));
            ASSERT(psk_io_transfer(&f, f.target, f.plain[0], bytes, sizeof(bytes)));
        }
        device_pairing_guard_counts(NULL, &cached1); ASSERT(cached1 > cached0);
        ASSERT_EQ(send(f.plain[0], bytes, sizeof(bytes), MSG_NOSIGNAL), sizeof(bytes));
        ASSERT_EQ(send(f.target, bytes, sizeof(bytes), MSG_NOSIGNAL), sizeof(bytes));
        for (unsigned i = 0; i < 8; ++i) ASSERT(psk_io_live_result(typed_test_device_host_psk_bridge_step(&f.client)));
        /* The change must land on a live, fresh cache so the cheap path is what observes it. */
        const struct device_pairing_guard_cache *cache = &f.server.session.authority;
        ASSERT(cache->valid); f.frozen_ns = cache->validated_ns; /* pin the shared virtual clock: the cached read is fresh by construction */
        ASSERT(psk_io_change_server(&f, mode));
        struct device_host_psk_bridge_observation before = f.server.observation;
        enum device_host_bridge_result result = DEVICE_HOST_BRIDGE_PROGRESS;
        for (unsigned i = 0; i < 64 && psk_io_live_result(result); ++i) {
            result = typed_test_device_host_psk_bridge_step(&f.server);
            if (f.client.active) (void)typed_test_device_host_psk_bridge_step(&f.client);
        }
        ASSERT_EQ(result, DEVICE_HOST_BRIDGE_REFUSED); ASSERT(!f.server.active);
        ASSERT_EQ(f.server.observation.carrier_read_bytes, before.carrier_read_bytes);
        ASSERT_EQ(f.server.observation.carrier_written_bytes, before.carrier_written_bytes);
        ASSERT_EQ(f.server.observation.plaintext_read_bytes, before.plaintext_read_bytes);
        ASSERT_EQ(f.server.observation.plaintext_written_bytes, before.plaintext_written_bytes);
    } TEST_END
    psk_io_fixture_close(&f); return failures;
}
/* Bounded throughput witness: the shared in-process bench (services/device_host_bench.c)
 * that backs `ops mesh device host bench`. Default 4 MiB per direction keeps
 * t-fast under its budget; ZCL_DEVICE_HOST_BENCH_MIB (1..512) sizes a
 * measurement run. Prints MiB/s and authority acquisitions per record. */
static size_t psk_bench_size(void)
{
    const char *text = getenv("ZCL_DEVICE_HOST_BENCH_MIB");
    unsigned long mib = text && *text ? strtoul(text, NULL, 10) : 4;
    return mib < 1 || mib > DEVICE_HOST_BENCH_MIB_MAX ? 4 : (size_t)mib;
}
static int psk_io_throughput(void)
{
    int failures = 0;
    TEST_CASE("host PSK IO throughput: shared bench moves bounded duplex bytes intact and removes its temp profile") {
        struct device_host_bench_result bench;
        struct zcl_result result = device_host_bench_run(psk_bench_size(), 1, &bench);
        ASSERT(result.ok); ASSERT(bench.profile_removed); ASSERT(platform_private_path_absent(bench.profile_root));
        const struct device_host_bench_run *run = &bench.runs[0];
        printf("\n[device_host_psk throughput] MiB/direction=%zu forward=%.1f MiB/s reverse=%.1f MiB/s"
            " records=%llu full_acquisitions=%llu (%.3f/record) cached_acquisitions=%llu (%.3f/record)\n", bench.mib,
            run->forward_mib_s, run->reverse_mib_s, (unsigned long long)run->records,
            (unsigned long long)run->full_acquisitions, (double)run->full_acquisitions / (double)run->records,
            (unsigned long long)run->cached_acquisitions, (double)run->cached_acquisitions / (double)run->records);
    } TEST_END
    return failures;
}
/* `ops mesh device host bench` through registry dispatch: mib=1 repeats=1, typed schema
 * fields, the atomic receipt file, input bounds, and a temp profile that is gone afterwards.
 * No throughput value is asserted; wall-clock speed is the benchmark's output, not a gate. */
static bool bench_dir_empty(const char *directory)
{
    DIR *handle = opendir(directory); if (!handle) return false;
    bool empty = true; struct dirent *entry;
    while ((entry = readdir(handle)) != NULL) if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) empty = false;
    closedir(handle); return empty;
}
static bool bench_number(const struct json_value *object, const char *key)
{
    const struct json_value *value = json_get(object, key);
    return value && (value->type == JSON_REAL || value->type == JSON_INT);
}
static bool bench_runs_ok(const struct json_value *data)
{
    const struct json_value *per_record = json_get(data, "acquisitions_per_record");
    const struct json_value *forward = json_get(data, "forward_runs_mib_s"), *reverse = json_get(data, "reverse_runs_mib_s");
    return bench_number(data, "forward_mib_s") && bench_number(data, "reverse_mib_s") &&
        forward && json_size(forward) == 1 && reverse && json_size(reverse) == 1 &&
        json_get_int(json_get(data, "records")) == 512 && per_record &&
        bench_number(per_record, "full") && bench_number(per_record, "cached");
}
static bool bench_provenance_ok(const struct json_value *data)
{
    const struct json_value *flags = json_get(data, "build_flags");
    const char *source = json_get_str(json_get(data, "source_id_sha256")), *stamp = json_get_str(json_get(data, "timestamp"));
    return flags && json_get(flags, "optimized") && json_get(flags, "compiler") && bench_number(data, "host_load1") &&
        source && source[0] && stamp && stamp[0] && json_get(data, "timestamp_unix_ms") &&
        json_get(data, "profile_removed") && json_get_bool(json_get(data, "profile_removed"));
}
static bool bench_schema_ok(const struct json_value *data)
{
    const char *schema = json_get_str(json_get(data, "schema"));
    return schema && !strcmp(schema, "zcl.tunnel_bench.v1") && json_get_int(json_get(data, "mib")) == 1 &&
        json_get_int(json_get(data, "repeats")) == 1 && bench_runs_ok(data) && bench_provenance_ok(data);
}
static int psk_bench_leaf(void)
{
    int failures = 0;
    TEST_CASE("device_host_bench leaf: registry dispatch returns zcl.tunnel_bench.v1, writes the receipt and removes its temp profile") {
        char scratch[1024], receipt_dir[1024], receipt[1100], *saved = getenv("TMPDIR"), saved_copy[1024] = "";
        if (saved) snprintf(saved_copy, sizeof(saved_copy), "%s", saved);
        ASSERT(test_mkdtemp(scratch, sizeof(scratch), "bench-tmp")); ASSERT(test_mkdtemp(receipt_dir, sizeof(receipt_dir), "bench-receipt"));
        snprintf(receipt, sizeof(receipt), "%s/tunnel.json", receipt_dir);
        ASSERT_EQ(setenv("TMPDIR", scratch, 1), 0);
        const struct zcl_command_registry *registry = zcl_command_catalog();
        const struct zcl_command_spec *spec = zcl_command_registry_find(registry, "ops.mesh.device.host.bench", NULL);
        ASSERT(spec != NULL); ASSERT(spec->handler == zcl_native_handle_ops_mesh_device_host_bench);
        struct json_value input; json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_int(&input, "mib", 1)); ASSERT(json_push_kv_int(&input, "repeats", 1));
        ASSERT(json_push_kv_str(&input, "receipt_out", receipt));
        char why[192]; ASSERT(zcl_command_registry_input_validate(spec, &input, why, sizeof(why)));
        struct zcl_command_context context = {.registry = registry, .granted_capabilities = ~(uint64_t)0, .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
        static char out[16384]; enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
        size_t n = zcl_command_registry_execute_json(registry, spec, &context, &input, false, spec->path, "normal", 0, 0, NULL, out, sizeof(out), &exit_code);
        json_free(&input);
        if (saved) setenv("TMPDIR", saved_copy, 1); else unsetenv("TMPDIR");
        struct json_value envelope; ASSERT(n > 0); ASSERT(json_read(&envelope, out, n));
        ASSERT(json_get_bool(json_get(&envelope, "ok")));
        ASSERT(bench_schema_ok(json_get(&envelope, "data")));
        /* The private profile lived under TMPDIR; nothing may remain there. */
        ASSERT(bench_dir_empty(scratch));
        char text[4096] = ""; FILE *file = fopen(receipt, "r"); ASSERT(file != NULL);
        size_t length = fread(text, 1, sizeof(text) - 1, file); fclose(file);
        struct json_value stored; ASSERT(length > 0); ASSERT(json_read(&stored, text, length)); ASSERT(bench_schema_ok(&stored));
        json_free(&stored); json_free(&envelope);
        test_rm_rf(scratch); test_rm_rf(receipt_dir);
    } TEST_END
    return failures;
}
static int psk_bench_leaf_bounds(void)
{
    int failures = 0;
    TEST_CASE("device_host_bench leaf: registry input bounds and the shared median") {
        const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), "ops.mesh.device.host.bench", NULL);
        ASSERT(spec != NULL);
        static const struct { const char *key; int64_t value; bool accepted; } cases[] = {
            {"mib", 0, false}, {"mib", 1, true}, {"mib", 512, true}, {"mib", 513, false},
            {"repeats", 0, false}, {"repeats", 5, true}, {"repeats", 6, false}};
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            struct json_value input; json_init(&input); json_set_object(&input);
            ASSERT(json_push_kv_int(&input, cases[i].key, cases[i].value));
            char why[192];
            ASSERT_EQ(zcl_command_registry_input_validate(spec, &input, why, sizeof(why)), cases[i].accepted);
            json_free(&input);
        }
        const double odd[] = {30.0, 10.0, 20.0}, even[] = {40.0, 10.0};
        ASSERT(device_host_bench_median(odd, 3) == 20.0); ASSERT(device_host_bench_median(even, 2) == 25.0);
        ASSERT(device_host_bench_median(odd, 0) == 0.0);
    } TEST_END
    return failures;
}
int test_device_host_bridge(void);
int test_device_host_bridge(void)
{
    typed_state_failures = 0;
    int failures = bridge_pending_refusal(0) + bridge_pending_refusal(1) +
        bridge_pending_refusal(2) + bridge_pending_refusal(3) + bridge_pending_refusal(4) +
        bridge_pending_refusal(5) + bridge_fixed_inbound() +
        bridge_invalid_transport() + bridge_halfclose() + bridge_partial_release() +
        bridge_broken_pipe() + bridge_closed_transport() + bridge_idle_revoke() + bridge_fullbytes() +
        bridge_write_boundary(true) + bridge_write_boundary(false) + psk_io_admission_and_bytes() +
        psk_io_wrong_key_and_truncation() + psk_io_buffered_revoke() + psk_io_idle_revoke_then_record() + psk_io_revoke_between_stream_records() + psk_io_actual_guard_boundary() + psk_io_receive_single_authority() +
        psk_io_fin_and_extra() + psk_io_refused_target() + psk_io_closed_stderr() +
        psk_io_preflight_refusals() + psk_io_explicit_backup() + psk_io_partial_ciphertext() +
        psk_io_deadline_expiry() + psk_io_deadline_handshake() + psk_io_deadline_phase_ceiling() + psk_io_deadline_borrowed() +
        psk_io_poll_interest() + psk_io_poll_stalled_hup() + psk_io_poll_pending_hup() + psk_io_poll_reverse_fin();
    failures += psk_io_typed_outputs() + psk_io_midstream_authority(0) + psk_io_midstream_authority(1) +
        psk_io_midstream_authority(2) + psk_io_throughput() + psk_bench_leaf() + psk_bench_leaf_bounds();
    return failures + (int)typed_state_failures;
}
#else
int test_device_host_bridge(void);
int test_device_host_bridge(void)
{
    int failures = 0;
    TEST_CASE("device_host_bridge: unqualified platform refuses raw transfer") {
        struct device_host_bridge bridge; device_host_bridge_init(&bridge);
        enum device_host_bridge_result status;
        struct zcl_result raw = device_host_bridge_open(&bridge, NULL, &status);
        ASSERT(!raw.ok); ASSERT_EQ(status, DEVICE_HOST_BRIDGE_UNSUPPORTED);
        ASSERT(!bridge.observation.io_taken);
        struct device_host_psk_bridge psk; device_host_psk_bridge_init(&psk);
        struct zcl_result encrypted = device_host_psk_bridge_open(&psk, NULL, &status);
        ASSERT(!encrypted.ok); ASSERT_EQ(status, DEVICE_HOST_BRIDGE_UNSUPPORTED);
        ASSERT(!psk.observation.io_taken);
    } TEST_END
    return failures;
}
#endif
