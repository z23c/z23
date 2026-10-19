/* purpose: Release buffered HOST bytes only under current root-bound directional authority. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "services/device_host_bridge.h"
#include "platform/clock.h"
#include "base/cleanse.h"
#include <string.h>
#include "util/log_macros.h"
#include <errno.h>

void device_host_bridge_init(struct device_host_bridge *bridge)
{
    if (bridge) *bridge = (struct device_host_bridge){.transport_fd = -1};
}
void device_host_psk_bridge_init(struct device_host_psk_bridge *bridge)
{
    if (bridge) *bridge = (struct device_host_psk_bridge){.target_fd = -1};
}
#if defined(__linux__) || defined(__APPLE__)
#include "platform/socket_compat.h"
#include "platform/pipe_compat.h"
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static enum device_host_psk_result host_call_device_host_psk_start(struct device_host_psk_session *session,
    const struct device_host_psk_spec *spec)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_start(session, spec, &status);
    if (!result.ok) LOG_ERROR("device_host", "%s (code=%d)", result.message, result.code);
    return status;
}

static enum device_host_psk_result host_call_device_host_psk_receive_bytes(struct device_host_psk_session *session,
    const uint8_t *bytes,
    size_t length,
    size_t *consumed)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_receive_bytes(session, bytes, length, consumed, &status);
    if (!result.ok) LOG_ERROR("device_host", "%s (code=%d)", result.message, result.code);
    return status;
}

static enum device_host_psk_result host_call_device_host_psk_queue_data(struct device_host_psk_session *session,
    const uint8_t *plaintext,
    size_t length)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_queue_data(session, plaintext, length, &status);
    if (!result.ok) LOG_ERROR("device_host", "%s (code=%d)", result.message, result.code);
    return status;
}

static enum device_host_psk_result host_call_device_host_psk_queue_fin(struct device_host_psk_session *session)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_queue_fin(session, &status);
    if (!result.ok) LOG_ERROR("device_host", "%s (code=%d)", result.message, result.code);
    return status;
}

static enum device_host_psk_result host_call_device_host_psk_pending_acquire(struct device_host_psk_session *session,
    struct device_pairing_guard *guard,
    const uint8_t **bytes,
    size_t *length)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_pending_acquire(session, guard, bytes, length, &status);
    if (!result.ok) LOG_ERROR("device_host", "%s (code=%d)", result.message, result.code);
    return status;
}

static enum device_host_psk_result host_call_device_host_psk_pending_written(struct device_host_psk_session *session,
    struct device_pairing_guard *guard,
    size_t count)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_pending_written(session, guard, count, &status);
    if (!result.ok) LOG_ERROR("device_host", "%s (code=%d)", result.message, result.code);
    return status;
}

static enum device_host_psk_result host_call_device_host_psk_plaintext_acquire(struct device_host_psk_session *session,
    struct device_pairing_guard *guard,
    const uint8_t **bytes,
    size_t *length)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_plaintext_acquire(session, guard, bytes, length, &status);
    if (!result.ok) LOG_ERROR("device_host", "%s (code=%d)", result.message, result.code);
    return status;
}

static enum device_host_psk_result host_call_device_host_psk_queue_data_held(struct device_host_psk_session *session,
    const struct device_pairing_guard *guard,
    const uint8_t *plaintext,
    size_t length)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_queue_data_held(session, guard, plaintext, length, &status);
    if (!result.ok) LOG_ERROR("device_host", "%s (code=%d)", result.message, result.code);
    return status;
}

static enum device_host_psk_result host_call_device_host_psk_pending_acquire_held(struct device_host_psk_session *session,
    struct device_pairing_guard *guard,
    const uint8_t **bytes,
    size_t *length)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_pending_acquire_held(session, guard, bytes, length, &status);
    if (!result.ok) LOG_ERROR("device_host", "%s (code=%d)", result.message, result.code);
    return status;
}

static enum device_host_psk_result host_call_device_host_psk_plaintext_acquire_held(struct device_host_psk_session *session,
    struct device_pairing_guard *guard,
    const uint8_t **bytes,
    size_t *length)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_plaintext_acquire_held(session, guard, bytes, length, &status);
    if (!result.ok) LOG_ERROR("device_host", "%s (code=%d)", result.message, result.code);
    return status;
}

static enum device_host_psk_result host_call_device_host_psk_plaintext_released(struct device_host_psk_session *session,
    struct device_pairing_guard *guard,
    size_t count)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_plaintext_released(session, guard, count, &status);
    if (!result.ok) LOG_ERROR("device_host", "%s (code=%d)", result.message, result.code);
    return status;
}

static enum device_host_psk_result host_call_device_host_psk_target_admitted(struct device_host_psk_session *session,
    const struct device_pairing_guard *guard)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_target_admitted(session, guard, &status);
    if (!result.ok) LOG_ERROR("device_host", "%s (code=%d)", result.message, result.code);
    return status;
}

static enum device_host_psk_result host_call_device_host_psk_transport_eof(struct device_host_psk_session *session)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_transport_eof(session, &status);
    if (!result.ok) LOG_ERROR("device_host", "%s (code=%d)", result.message, result.code);
    return status;
}



static bool stream_socket(int fd)
{
    int type = 0;
    socklen_t size = sizeof(type);
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) == 0 && type == SOCK_STREAM;
}

static bool raw_fd(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    struct stat info;
    if (flags < 0 || !(flags & O_NONBLOCK) || fstat(fd, &info) < 0) return false;
    return S_ISFIFO(info.st_mode) || (S_ISSOCK(info.st_mode) && stream_socket(fd));
}

static bool connected_socket(int fd)
{
    struct sockaddr_storage peer;
    socklen_t length = sizeof(peer);
    return stream_socket(fd) && getpeername(fd, (struct sockaddr *)&peer, &length) == 0;
}

static bool stdio_valid(const struct device_host_bridge_spec *spec)
{
    if (!raw_fd(spec->input_fd) || !raw_fd(spec->output_fd)) return false;
    if ((fcntl(spec->input_fd, F_GETFL) & O_ACCMODE) == O_WRONLY ||
        (fcntl(spec->output_fd, F_GETFL) & O_ACCMODE) == O_RDONLY) return false;
    if (spec->input_fd == spec->output_fd && !stream_socket(spec->input_fd)) return false;
    return true;
}

static bool spec_valid(const struct device_host_bridge_spec *spec)
{
    if (!spec || !spec->store || !spec->port || spec->deadline_ns <= 0) return false;
    if (!stdio_valid(spec)) {
        int error = errno;
        LOG_RETURN((errno = error, false), "device_host_bridge", "raw stream descriptors fail geometry or access-mode validation");
    }
    if (spec->direction == DEVICE_PAIRING_HOST_INBOUND) return spec->outbound_fd == -1;
    if (spec->direction != DEVICE_PAIRING_HOST_OUTBOUND) return false;
    return spec->outbound_fd != spec->input_fd && spec->outbound_fd != spec->output_fd &&
        raw_fd(spec->outbound_fd) && connected_socket(spec->outbound_fd);
}

static int wait_until_ms(int64_t deadline_ns)
{
    int64_t now = clock_now_monotonic_ns();
    if (now < 0 || now >= deadline_ns) return 0;
    uint64_t ns = (uint64_t)deadline_ns - (uint64_t)now;
    uint64_t ms = ns / UINT64_C(1000000) + (ns % UINT64_C(1000000) != 0);
    return ms > 20 ? 20 : (int)ms;
}
static int wait_ms(const struct device_host_bridge *bridge)
{
    return wait_until_ms(bridge->spec.deadline_ns);
}
static void close_unique(const int *descriptors, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        if (descriptors[i] < 0) continue;
        bool duplicate = false;
        for (size_t j = 0; j < i; ++j) if (descriptors[j] == descriptors[i]) duplicate = true;
        if (!duplicate) close(descriptors[i]);
    }
}

static enum device_host_bridge_result current_limit(const struct device_host_bridge *bridge)
{
    if (bridge->spec.cancelled && atomic_load(bridge->spec.cancelled))
        return DEVICE_HOST_BRIDGE_CANCELLED;
    return wait_ms(bridge) ? DEVICE_HOST_BRIDGE_READY : DEVICE_HOST_BRIDGE_DEADLINE;
}

static bool current_interval(const struct db_device_pairing *row)
{
    int64_t ms = clock_now_wall_ms();
    if (ms < 0) return false;
    uint64_t now = (uint64_t)ms / 1000;
    return now >= row->paired_at && now < row->expires_at;
}

static enum device_host_bridge_result authorize(struct device_host_bridge *bridge,
    struct device_pairing_guard *guard)
{
    enum device_host_bridge_result limit = current_limit(bridge);
    if (limit != DEVICE_HOST_BRIDGE_READY) return limit;
    int64_t ms = clock_now_wall_ms();
    if (ms < 0) return DEVICE_HOST_BRIDGE_REFUSED;
    if (!device_pairing_guard_acquire_host_forward(bridge->spec.store, bridge->spec.peer,
        (uint64_t)ms / 1000, &bridge->spec.authenticated_binding,
        bridge->spec.direction, bridge->spec.port, guard)) return DEVICE_HOST_BRIDGE_REFUSED;
    limit = current_limit(bridge);
    if (limit == DEVICE_HOST_BRIDGE_READY &&
        (!current_interval(&guard->row) || memcmp(guard->root, bridge->spec.approved_root, 32)))
        limit = DEVICE_HOST_BRIDGE_REFUSED;
    if (limit != DEVICE_HOST_BRIDGE_READY) device_pairing_guard_release(guard);
    return limit;
}



static enum device_host_bridge_result connect_ready(struct device_host_bridge *bridge)
{
    for (;;) {
        struct device_pairing_guard guard = {0};
        enum device_host_bridge_result result = authorize(bridge, &guard);
        if (result != DEVICE_HOST_BRIDGE_READY) return result;
        device_pairing_guard_release(&guard);
        struct pollfd event = {.fd = bridge->transport_fd, .events = POLLOUT};
        int ready = poll(&event, 1, wait_ms(bridge));
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return DEVICE_HOST_BRIDGE_IO_ERROR;
        if (!ready) continue;
        result = authorize(bridge, &guard);
        if (result != DEVICE_HOST_BRIDGE_READY) return result;
        int error = 0;
        socklen_t size = sizeof(error);
        int observed = getsockopt(bridge->transport_fd, SOL_SOCKET, SO_ERROR, &error, &size);
        int syscall_error = errno;
        device_pairing_guard_release(&guard);
        if (observed < 0 || error) {
            bridge->observation.error_number = error ? error : syscall_error;
            return DEVICE_HOST_BRIDGE_IO_ERROR;
        }
        return DEVICE_HOST_BRIDGE_READY;
    }
}

static enum device_host_bridge_result connect_inbound(struct device_host_bridge *bridge,
    struct device_pairing_guard *guard)
{
    bridge->transport_fd = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    if (bridge->transport_fd < 0) {
        device_pairing_guard_release(guard);
        return DEVICE_HOST_BRIDGE_IO_ERROR;
    }
    struct sockaddr_in target = {.sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons(bridge->spec.port)};
    int connected = platform_socket_connect(bridge->transport_fd,
        (const struct sockaddr *)&target, sizeof(target));
    int error = errno;
    device_pairing_guard_release(guard);
    if (connected == 0) return DEVICE_HOST_BRIDGE_READY;
    if (error != EINPROGRESS) {
        bridge->observation.error_number = error;
        return DEVICE_HOST_BRIDGE_IO_ERROR;
    }
    return connect_ready(bridge);
}

static enum device_host_bridge_result device_host_bridge_open_state(struct device_host_bridge *bridge,
    const struct device_host_bridge_spec *spec)
{
    if (!bridge || bridge->active || !spec_valid(spec)) return DEVICE_HOST_BRIDGE_REFUSED;
    bridge->spec = *spec;
    bridge->observation = (struct device_host_bridge_observation){0};
    struct device_pairing_guard guard = {0};
    enum device_host_bridge_result result = authorize(bridge, &guard);
    if (result != DEVICE_HOST_BRIDGE_READY) {
        bridge->observation.result = result;
        return result;
    }
    bridge->active = true;
    bridge->observation.io_taken = true;
    bridge->output_socket = stream_socket(spec->output_fd);
    if (spec->direction == DEVICE_PAIRING_HOST_INBOUND) result = connect_inbound(bridge, &guard);
    else {
        bridge->transport_fd = spec->outbound_fd;
        device_pairing_guard_release(&guard);
    }
    if (result != DEVICE_HOST_BRIDGE_READY) device_host_bridge_close(bridge, result);
    else {
        bridge->observation.target_connected = true;
        bridge->observation.result = result;
    }
    return result;
}

static bool transient_error(int error)
{
    return error == EAGAIN || error == EWOULDBLOCK || error == EINTR;
}

static ssize_t pipe_write(int fd, const void *bytes, size_t size)
{
    return platform_pipe_write_nosigpipe(fd, bytes, size);
}

static enum device_host_bridge_result read_buffer(struct device_host_bridge *bridge, int fd,
    struct device_host_bridge_buffer *buffer, bool *progress)
{
    if (buffer->eof || buffer->used != buffer->sent) return DEVICE_HOST_BRIDGE_READY;
    buffer->used = buffer->sent = 0;
    ssize_t count = read(fd, buffer->bytes, sizeof(buffer->bytes));
    if (count > 0) { buffer->used = (size_t)count; *progress = true; }
    else if (count == 0) { buffer->eof = true; *progress = true; }
    else if (!transient_error(errno)) {
        bridge->observation.error_number = errno;
        return DEVICE_HOST_BRIDGE_IO_ERROR;
    }
    return DEVICE_HOST_BRIDGE_READY;
}

static enum device_host_bridge_result write_buffer(struct device_host_bridge *bridge,
    struct device_host_bridge_buffer *buffer, bool forward, bool *progress)
{
    if (buffer->used == buffer->sent) return DEVICE_HOST_BRIDGE_READY;
    struct device_pairing_guard guard = {0};
    enum device_host_bridge_result result = authorize(bridge, &guard);
    if (result != DEVICE_HOST_BRIDGE_READY) return result;
    int fd = forward ? bridge->transport_fd : bridge->spec.output_fd;
    bool socket = forward || bridge->output_socket;
    ssize_t written = socket ? send(fd, buffer->bytes + buffer->sent,
        buffer->used - buffer->sent, MSG_DONTWAIT | MSG_NOSIGNAL) :
        pipe_write(fd, buffer->bytes + buffer->sent, buffer->used - buffer->sent);
    int error = errno;
    device_pairing_guard_release(&guard);
    if (written > 0) {
        buffer->sent += (size_t)written;
        if (forward) bridge->observation.to_target_bytes += (uint64_t)written;
        else bridge->observation.from_target_bytes += (uint64_t)written;
        *progress = true;
    } else if (written < 0 && !transient_error(error)) {
        bridge->observation.error_number = error;
        return DEVICE_HOST_BRIDGE_IO_ERROR;
    }
    return DEVICE_HOST_BRIDGE_READY;
}

static enum device_host_bridge_result half_close(struct device_host_bridge *bridge,
    struct device_host_bridge_buffer *buffer, bool forward)
{
    if (!buffer->eof || buffer->used != buffer->sent || buffer->half_closed)
        return DEVICE_HOST_BRIDGE_READY;
    struct device_pairing_guard guard = {0};
    enum device_host_bridge_result result = authorize(bridge, &guard);
    if (result != DEVICE_HOST_BRIDGE_READY) return result;
    int fd = forward ? bridge->transport_fd : bridge->spec.output_fd;
    int closed = 0;
    if (forward || bridge->output_socket) closed = shutdown(fd, SHUT_WR);
    else { closed = close(fd); bridge->spec.output_fd = -1; }
    int error = errno;
    device_pairing_guard_release(&guard);
    if (closed < 0) { bridge->observation.error_number = error; return DEVICE_HOST_BRIDGE_IO_ERROR; }
    buffer->half_closed = true;
    return DEVICE_HOST_BRIDGE_READY;
}

static enum device_host_bridge_result device_host_bridge_step_state(struct device_host_bridge *bridge)
{
    if (!bridge || !bridge->active) return DEVICE_HOST_BRIDGE_REFUSED;
    struct device_pairing_guard guard = {0};
    enum device_host_bridge_result result = authorize(bridge, &guard);
    if (result == DEVICE_HOST_BRIDGE_READY) device_pairing_guard_release(&guard);
    bool progress = false;
    if (result == DEVICE_HOST_BRIDGE_READY) result = read_buffer(bridge, bridge->spec.input_fd, &bridge->forward, &progress);
    if (result == DEVICE_HOST_BRIDGE_READY) result = read_buffer(bridge, bridge->transport_fd, &bridge->reverse, &progress);
    if (result == DEVICE_HOST_BRIDGE_READY) result = write_buffer(bridge, &bridge->forward, true, &progress);
    if (result == DEVICE_HOST_BRIDGE_READY) result = write_buffer(bridge, &bridge->reverse, false, &progress);
    if (result == DEVICE_HOST_BRIDGE_READY) result = half_close(bridge, &bridge->forward, true);
    if (result == DEVICE_HOST_BRIDGE_READY) result = half_close(bridge, &bridge->reverse, false);
    if (result != DEVICE_HOST_BRIDGE_READY) { device_host_bridge_close(bridge, result); return result; }
    if (bridge->forward.half_closed && bridge->reverse.half_closed) {
        device_host_bridge_close(bridge, DEVICE_HOST_BRIDGE_EOF);
        return DEVICE_HOST_BRIDGE_EOF;
    }
    bridge->observation.result = progress ? DEVICE_HOST_BRIDGE_PROGRESS : DEVICE_HOST_BRIDGE_WAIT;
    return bridge->observation.result;
}

static void wait_progress(const struct device_host_bridge *bridge)
{
    struct pollfd descriptors[] = {
        {.fd = bridge->spec.input_fd, .events = POLLIN},
        {.fd = bridge->transport_fd, .events = POLLIN},
        {.fd = bridge->spec.output_fd, .events = 0}};
    if (bridge->forward.eof || bridge->forward.used != bridge->forward.sent) descriptors[0].fd = -1;
    if (bridge->reverse.eof || bridge->reverse.used != bridge->reverse.sent) descriptors[1].events = 0;
    if (bridge->forward.used != bridge->forward.sent) descriptors[1].events |= POLLOUT;
    if (bridge->reverse.used != bridge->reverse.sent) descriptors[2].events = POLLOUT;
    if (!descriptors[1].events) descriptors[1].fd = -1;
    if (!descriptors[2].events) descriptors[2].fd = -1;
    (void)poll(descriptors, 3, wait_ms(bridge));
}

static enum device_host_bridge_result device_host_bridge_run_state(struct device_host_bridge *bridge)
{
    for (;;) {
        enum device_host_bridge_result result = device_host_bridge_step_state(bridge);
        if (result == DEVICE_HOST_BRIDGE_WAIT) wait_progress(bridge);
        else if (result != DEVICE_HOST_BRIDGE_PROGRESS) return result;
    }
}
/* Backend2 composition shares this descriptor/poll/signal owner. */
static enum device_host_bridge_result psk_io_map(enum device_host_psk_result result)
{
    switch (result) {
    case DEVICE_HOST_PSK_PROGRESS: case DEVICE_HOST_PSK_WAIT: case DEVICE_HOST_PSK_TARGET_REQUIRED:
    case DEVICE_HOST_PSK_READY: case DEVICE_HOST_PSK_EOF: return DEVICE_HOST_BRIDGE_READY;
    case DEVICE_HOST_PSK_DEADLINE: return DEVICE_HOST_BRIDGE_DEADLINE;
    case DEVICE_HOST_PSK_CANCELLED: return DEVICE_HOST_BRIDGE_CANCELLED;
    default: return DEVICE_HOST_BRIDGE_REFUSED;
    }
}
static enum device_host_bridge_result psk_io_limit(const struct device_host_psk_bridge *bridge)
{
    if (bridge->spec.session.cancelled && atomic_load(bridge->spec.session.cancelled)) return DEVICE_HOST_BRIDGE_CANCELLED;
    int64_t now = clock_now_monotonic_ns();
    if (now <= 0 || now >= bridge->spec.session.deadline_ns) return DEVICE_HOST_BRIDGE_DEADLINE;
    return DEVICE_HOST_BRIDGE_READY;
}
static enum device_host_bridge_result psk_io_action_limit(const struct device_host_psk_bridge *bridge,
    const struct device_pairing_guard *guard)
{
    enum device_host_bridge_result result = psk_io_limit(bridge);
    if (result == DEVICE_HOST_BRIDGE_READY && !current_interval(&guard->row)) return DEVICE_HOST_BRIDGE_REFUSED;
    return result;
}
/* Authority is acquired ONCE per record per direction and that single held guard is carried
 * through the record's whole path: read + decrypt + release of plaintext inbound, read + seal +
 * queue/send outbound. A step takes one guard at its start (this is also the idle-revoke
 * probe); the first action that forwards or releases a record uses it instead of re-acquiring,
 * and every such action RELEASES the guard when its record is done. A guard that is still
 * held therefore always began after the previous record's release.
 * Invariant (exact): no record's plaintext is forwarded or released unless an authority check
 * that started after the previous record's release succeeded under the shared lock with the
 * grant-state and intent-absent revalidation (or a full acquisition). A revoke or root change
 * that completes before a record's check is never followed by that record being forwarded;
 * one that arrives later waits on the exclusive lock until the record's action is done.
 * A guard is never carried across steps, records or waits, and no lock fd is retained. */
static enum device_host_bridge_result psk_io_authorize(struct device_host_psk_bridge *bridge,
    struct device_pairing_guard *guard)
{
    enum device_host_bridge_result result = psk_io_limit(bridge);
    if (result != DEVICE_HOST_BRIDGE_READY) return result;
    if (guard->held) {
        result = psk_io_action_limit(bridge, guard);
        if (result != DEVICE_HOST_BRIDGE_READY) device_pairing_guard_release(guard);
        return result;
    }
    int64_t ms = clock_now_wall_ms();
    if (ms <= 0) return DEVICE_HOST_BRIDGE_REFUSED;
    if (!device_pairing_guard_acquire_host_psk_cached(bridge->spec.session.store, bridge->spec.session.peer,
        bridge->spec.session.approved_root, (uint64_t)ms / 1000, &bridge->session.snapshot.row.host_scope.binding.psk,
        bridge->spec.session.direction, bridge->spec.session.port, &bridge->session.authority, guard)) return DEVICE_HOST_BRIDGE_REFUSED;
    result = psk_io_action_limit(bridge, guard);
    if (result != DEVICE_HOST_BRIDGE_READY) device_pairing_guard_release(guard);
    return result;
}
static bool psk_io_pair_valid(int input, int output)
{
    if (input == STDERR_FILENO || output == STDERR_FILENO) return false;
    struct device_host_bridge_spec raw = {.input_fd = input, .output_fd = output};
    if (!stdio_valid(&raw)) {
        int error = errno;
        LOG_RETURN((errno = error, false), "device_host_bridge", "PSK stream descriptors fail geometry or access-mode validation");
    }
    if (stream_socket(input) && !connected_socket(input)) return false;
    if (stream_socket(output) && !connected_socket(output)) return false;
    return true;
}
static bool psk_io_spec_valid(const struct device_host_psk_bridge_spec *spec)
{
    if (fcntl(STDERR_FILENO, F_GETFD) < 0) return false;
    if (!spec || !psk_io_pair_valid(spec->carrier_input_fd, spec->carrier_output_fd)) return false;
    if (spec->session.direction == DEVICE_PAIRING_HOST_INBOUND) return spec->input_fd == -1 && spec->output_fd == -1;
    if (spec->session.direction != DEVICE_PAIRING_HOST_OUTBOUND || !psk_io_pair_valid(spec->input_fd, spec->output_fd)) return false;
    return spec->carrier_input_fd != spec->input_fd && spec->carrier_input_fd != spec->output_fd &&
        spec->carrier_output_fd != spec->input_fd && spec->carrier_output_fd != spec->output_fd;
}

static enum device_host_bridge_result device_host_psk_bridge_open_state(struct device_host_psk_bridge *bridge,
    const struct device_host_psk_bridge_spec *spec)
{
    if (!bridge || bridge->started || !psk_io_spec_valid(spec)) return DEVICE_HOST_BRIDGE_REFUSED;
    uintptr_t context = (uintptr_t)bridge, input = (uintptr_t)spec;
    if (context < input + sizeof(*spec) && input < context + sizeof(*bridge)) return DEVICE_HOST_BRIDGE_REFUSED;
    bridge->spec = *spec; bridge->started = true;
    bridge->hard_deadline_ns = spec->session.deadline_ns;
    device_host_psk_init(&bridge->session);
    enum device_host_bridge_result result = psk_io_map(host_call_device_host_psk_start(&bridge->session, &spec->session));
    if (result != DEVICE_HOST_BRIDGE_READY) {
        device_host_psk_bridge_close(bridge, result); return result;
    }
    bridge->active = true; bridge->observation.io_taken = true;
    bridge->carrier_output_socket = stream_socket(spec->carrier_output_fd);
    bridge->output_socket = spec->output_fd >= 0 && stream_socket(spec->output_fd);
    bridge->observation.result = DEVICE_HOST_BRIDGE_READY;
    return DEVICE_HOST_BRIDGE_READY;
}
static enum device_host_bridge_result psk_io_deadline_result(
    const struct device_host_psk_bridge *bridge, int64_t deadline_ns, int64_t now)
{
    if (now <= 0 || now >= bridge->spec.session.deadline_ns) return DEVICE_HOST_BRIDGE_DEADLINE;
    if (bridge->session.phase == DEVICE_HOST_PSK_FINISHED || bridge->session.phase == DEVICE_HOST_PSK_FAILED)
        return DEVICE_HOST_BRIDGE_REFUSED;
    if (bridge->spec.session.cancelled && atomic_load_explicit(bridge->spec.session.cancelled, memory_order_relaxed))
        return DEVICE_HOST_BRIDGE_CANCELLED;
    if (deadline_ns <= now || deadline_ns > bridge->hard_deadline_ns) return DEVICE_HOST_BRIDGE_REFUSED;
    if (deadline_ns > bridge->spec.session.deadline_ns && bridge->session.phase != DEVICE_HOST_PSK_ESTABLISHED)
        return DEVICE_HOST_BRIDGE_REFUSED;
    return DEVICE_HOST_BRIDGE_READY;
}
static enum device_host_bridge_result device_host_psk_bridge_set_deadline_state(
    struct device_host_psk_bridge *bridge, int64_t deadline_ns)
{
    if (!bridge) return DEVICE_HOST_BRIDGE_REFUSED;
    if (!bridge->active) return bridge->started ? bridge->observation.result : DEVICE_HOST_BRIDGE_REFUSED;
    if (bridge->session.borrowed_guard) return DEVICE_HOST_BRIDGE_REFUSED;
    int64_t now = clock_now_monotonic_ns();
    enum device_host_bridge_result result = psk_io_deadline_result(bridge, deadline_ns, now);
    if (result != DEVICE_HOST_BRIDGE_READY) {
        device_host_psk_bridge_close(bridge, result); return result;
    }
    bridge->spec.session.deadline_ns = deadline_ns;
    bridge->session.spec.deadline_ns = deadline_ns;
    return result;
}
static int psk_io_input(const struct device_host_psk_bridge *bridge)
{
    return bridge->spec.session.direction == DEVICE_PAIRING_HOST_INBOUND ? bridge->target_fd : bridge->spec.input_fd;
}
static int psk_io_output(const struct device_host_psk_bridge *bridge)
{
    return bridge->spec.session.direction == DEVICE_PAIRING_HOST_INBOUND ? bridge->target_fd : bridge->spec.output_fd;
}
static bool psk_io_target_connected(const struct device_host_psk_bridge *bridge)
{
    struct sockaddr_in address; socklen_t length = sizeof(address);
    return getpeername(bridge->target_fd, (struct sockaddr *)&address, &length) == 0 &&
        length == sizeof(address) && address.sin_family == AF_INET &&
        address.sin_addr.s_addr == htonl(INADDR_LOOPBACK) && address.sin_port == htons(bridge->spec.session.port);
}
static enum device_host_bridge_result psk_io_target_ready(struct device_host_psk_bridge *bridge,
    struct device_pairing_guard *guard)
{
    enum device_host_bridge_result result = psk_io_action_limit(bridge, guard);
    if (result == DEVICE_HOST_BRIDGE_READY)
        result = psk_io_map(host_call_device_host_psk_target_admitted(&bridge->session, guard));
    if (result == DEVICE_HOST_BRIDGE_READY) {
        bridge->connect_pending = false; bridge->output_socket = true; bridge->observation.target_connected = true;
    }
    return result;
}
static enum device_host_bridge_result psk_io_connect_start(struct device_host_psk_bridge *bridge, bool *progress)
{
    struct device_pairing_guard guard = {0};
    enum device_host_bridge_result result = psk_io_authorize(bridge, &guard);
    if (result != DEVICE_HOST_BRIDGE_READY) return result;
    bridge->target_fd = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    if (bridge->target_fd < 0) {
        bridge->observation.error_number = errno; device_pairing_guard_release(&guard); return DEVICE_HOST_BRIDGE_IO_ERROR;
    }
    (void)platform_socket_set_no_delay(bridge->target_fd, true); /* Records are released whole; never Nagle-delay them. */
    struct sockaddr_in target = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons(bridge->spec.session.port)};
    result = psk_io_action_limit(bridge, &guard);
    if (result != DEVICE_HOST_BRIDGE_READY) { device_pairing_guard_release(&guard); return result; }
    int connected = platform_socket_connect(bridge->target_fd, (const struct sockaddr *)&target, sizeof(target));
    int error = errno; bridge->observation.target_connect_started = true; *progress = true;
    if (connected == 0) result = psk_io_target_ready(bridge, &guard);
    else if (error == EINPROGRESS) bridge->connect_pending = true;
    else { bridge->observation.error_number = error; result = DEVICE_HOST_BRIDGE_IO_ERROR; }
    device_pairing_guard_release(&guard); return result;
}
static enum device_host_bridge_result psk_io_connect_complete(struct device_host_psk_bridge *bridge, bool *progress)
{
    struct pollfd event = {.fd = bridge->target_fd, .events = POLLOUT};
    int ready = poll(&event, 1, 0);
    if (ready < 0) {
        if (errno == EINTR) return DEVICE_HOST_BRIDGE_READY;
        bridge->observation.error_number = errno; return DEVICE_HOST_BRIDGE_IO_ERROR;
    }
    if (!ready) return DEVICE_HOST_BRIDGE_READY;
    struct device_pairing_guard guard = {0}; enum device_host_bridge_result result = psk_io_authorize(bridge, &guard);
    if (result != DEVICE_HOST_BRIDGE_READY) return result;
    int error = 0; socklen_t size = sizeof(error);
    int observed = getsockopt(bridge->target_fd, SOL_SOCKET, SO_ERROR, &error, &size); int syscall_error = errno;
    bool connected = observed == 0 && !error && psk_io_target_connected(bridge);
    int peer_error = errno;
    if (!connected) {
        bridge->observation.error_number = error ? error : (observed < 0 ? syscall_error : peer_error); result = DEVICE_HOST_BRIDGE_IO_ERROR;
    } else { result = psk_io_target_ready(bridge, &guard); *progress = true; }
    device_pairing_guard_release(&guard); return result;
}
static enum device_host_bridge_result psk_io_target_step(struct device_host_psk_bridge *bridge, bool *progress)
{
    if (bridge->session.phase != DEVICE_HOST_PSK_NEED_TARGET) return DEVICE_HOST_BRIDGE_READY;
    if (bridge->connect_pending) return psk_io_connect_complete(bridge, progress);
    if (bridge->target_fd >= 0) return DEVICE_HOST_BRIDGE_REFUSED;
    if (bridge->spec.reserve_target && !bridge->spec.reserve_target(bridge->spec.reserve_context))
        return DEVICE_HOST_BRIDGE_REFUSED;
    return psk_io_connect_start(bridge, progress);
}
static ssize_t psk_io_write(int fd, bool socket, const uint8_t *bytes, size_t length)
{
    return socket ? send(fd, bytes, length, MSG_DONTWAIT | MSG_NOSIGNAL) : pipe_write(fd, bytes, length);
}
struct psk_io_span { struct device_pairing_guard *guard; const uint8_t *bytes; size_t length; bool plaintext; };
static enum device_host_bridge_result psk_io_complete_span(struct device_host_psk_bridge *bridge,
    struct psk_io_span *span, size_t count)
{
    if (bridge->session.borrowed_guard != span->guard) {
        device_pairing_guard_release(span->guard); return DEVICE_HOST_BRIDGE_REFUSED;
    }
    enum device_host_psk_result completed = span->plaintext ? host_call_device_host_psk_plaintext_released(&bridge->session, span->guard, count) :
        host_call_device_host_psk_pending_written(&bridge->session, span->guard, count);
    device_pairing_guard_release(span->guard); return psk_io_map(completed);
}
/* span->guard is the step's guard: held means this record's single authority is carried in,
 * unheld means the span acquires its own. Either way completion releases it. */
static enum device_host_bridge_result psk_io_acquire_span(struct device_host_psk_bridge *bridge, struct psk_io_span *span)
{
    bool carried = span->guard->held;
    enum device_host_psk_result acquired = span->plaintext ?
        (carried ? host_call_device_host_psk_plaintext_acquire_held(&bridge->session, span->guard, &span->bytes, &span->length) :
            host_call_device_host_psk_plaintext_acquire(&bridge->session, span->guard, &span->bytes, &span->length)) :
        (carried ? host_call_device_host_psk_pending_acquire_held(&bridge->session, span->guard, &span->bytes, &span->length) :
            host_call_device_host_psk_pending_acquire(&bridge->session, span->guard, &span->bytes, &span->length));
    enum device_host_bridge_result result = psk_io_map(acquired);
    if (result != DEVICE_HOST_BRIDGE_READY) { device_pairing_guard_release(span->guard); return result; }
    if (!span->guard->held || !span->length) {
        (void)psk_io_complete_span(bridge, span, 0); return DEVICE_HOST_BRIDGE_REFUSED;
    }
    return DEVICE_HOST_BRIDGE_READY;
}
static enum device_host_bridge_result psk_io_write_span(struct device_host_psk_bridge *bridge,
    bool plaintext, bool *progress, struct device_pairing_guard *guard)
{
    size_t used = plaintext ? bridge->session.plaintext_used : bridge->session.pending_used;
    if (!used) return DEVICE_HOST_BRIDGE_READY;
    struct psk_io_span span = {.guard = guard, .plaintext = plaintext};
    enum device_host_bridge_result result = psk_io_acquire_span(bridge, &span);
    if (result != DEVICE_HOST_BRIDGE_READY) return result;
    result = psk_io_action_limit(bridge, span.guard);
    ssize_t written = -1; int error = 0;
    if (result == DEVICE_HOST_BRIDGE_READY) {
        int fd = plaintext ? psk_io_output(bridge) : bridge->spec.carrier_output_fd;
        bool socket = plaintext ? bridge->output_socket : bridge->carrier_output_socket;
        written = psk_io_write(fd, socket, span.bytes, span.length); error = errno;
    }
    size_t count = written > 0 ? (size_t)written : 0;
    enum device_host_bridge_result completed = psk_io_complete_span(bridge, &span, count);
    if (result != DEVICE_HOST_BRIDGE_READY) return result;
    if (completed != DEVICE_HOST_BRIDGE_READY) return completed;
    if (written > 0) {
        if (plaintext) bridge->observation.plaintext_written_bytes += count; else bridge->observation.carrier_written_bytes += count;
        *progress = true;
    } else if (!written || !transient_error(error)) {
        bridge->observation.error_number = written ? error : EPIPE; return DEVICE_HOST_BRIDGE_IO_ERROR;
    }
    return DEVICE_HOST_BRIDGE_READY;
}
static bool psk_io_receive_enabled(const struct device_host_psk_bridge *bridge)
{
    if (bridge->session.plaintext_used) return false;
    if (bridge->session.phase == DEVICE_HOST_PSK_ESTABLISHED || bridge->session.phase == DEVICE_HOST_PSK_FINISHED) return true;
    return !bridge->session.pending_used;
}
static enum device_host_bridge_result psk_io_consume_unread(struct device_host_psk_bridge *bridge, bool *progress)
{
    if (!psk_io_receive_enabled(bridge)) return DEVICE_HOST_BRIDGE_READY;
    for (unsigned pass = 0; pass < 2; ++pass) {
        size_t remaining = bridge->unread_used - bridge->unread_sent;
        if (!remaining || !psk_io_receive_enabled(bridge)) break;
        size_t consumed = 0;
        enum device_host_psk_result received = host_call_device_host_psk_receive_bytes(&bridge->session,
            bridge->unread + bridge->unread_sent, remaining, &consumed);
        enum device_host_bridge_result result = psk_io_map(received);
        if (result != DEVICE_HOST_BRIDGE_READY) return result;
        bridge->unread_sent += consumed;
        if (!consumed) break;
        *progress = true;
    }
    if (bridge->unread_used == bridge->unread_sent) {
        memory_cleanse(bridge->unread, bridge->unread_used); bridge->unread_used = 0; bridge->unread_sent = 0;
    }
    return DEVICE_HOST_BRIDGE_READY;
}
/* A read that would only report EAGAIN needs no authority acquisition: probe readiness first
 * (one zero-timeout poll) and acquire the guard only when a read can actually deliver or
 * report an end/error. Bytes are still read only while the guard is held. */
static bool psk_io_read_ready(int fd)
{
    if (fd < 0) return true; /* let the read report the bad descriptor */
    struct pollfd event = {.fd = fd, .events = POLLIN};
    int ready = poll(&event, 1, 0);
    return ready != 0;
}
static enum device_host_bridge_result psk_io_read_carrier(struct device_host_psk_bridge *bridge, bool *progress,
    struct device_pairing_guard *guard)
{
    if (bridge->carrier_eof || bridge->unread_used || !psk_io_receive_enabled(bridge)) return DEVICE_HOST_BRIDGE_READY;
    if (!psk_io_read_ready(bridge->spec.carrier_input_fd)) return DEVICE_HOST_BRIDGE_READY;
    enum device_host_bridge_result result = psk_io_authorize(bridge, guard);
    if (result != DEVICE_HOST_BRIDGE_READY) return result;
    ssize_t count = read(bridge->spec.carrier_input_fd, bridge->unread, sizeof(bridge->unread)); int error = errno;
    if (count > 0) {
        bridge->unread_used = (size_t)count; bridge->observation.carrier_read_bytes += (uint64_t)count; *progress = true;
        /* Read, decrypt and first plaintext release run under the one guard taken above, exactly as
         * the outbound path carries one guard through read, seal and send. */
        result = psk_io_consume_unread(bridge, progress);
        if (result == DEVICE_HOST_BRIDGE_READY && guard->held && bridge->session.plaintext_used)
            result = psk_io_write_span(bridge, true, progress, guard);
        device_pairing_guard_release(guard);
        return result;
    }
    device_pairing_guard_release(guard);
    if (!count) { bridge->carrier_eof = true; *progress = true; }
    else if (!transient_error(error)) { bridge->observation.error_number = error; return DEVICE_HOST_BRIDGE_IO_ERROR; }
    return DEVICE_HOST_BRIDGE_READY;
}
/* A held guard is this record's authority: seal under it and leave it held for the send. */
static enum device_host_bridge_result psk_io_queue_local(struct device_host_psk_bridge *bridge, bool *progress,
    struct device_pairing_guard *guard)
{
    if (bridge->session.phase != DEVICE_HOST_PSK_ESTABLISHED || bridge->session.pending_used || bridge->session.send_fin)
        return DEVICE_HOST_BRIDGE_READY;
    enum device_host_psk_result queued;
    if (bridge->local_used) queued = guard->held ?
        host_call_device_host_psk_queue_data_held(&bridge->session, guard, bridge->local, bridge->local_used) :
        host_call_device_host_psk_queue_data(&bridge->session, bridge->local, bridge->local_used);
    else if (bridge->local_eof) queued = host_call_device_host_psk_queue_fin(&bridge->session);
    else return DEVICE_HOST_BRIDGE_READY;
    enum device_host_bridge_result result = psk_io_map(queued);
    if (result == DEVICE_HOST_BRIDGE_READY && queued != DEVICE_HOST_PSK_WAIT) {
        memory_cleanse(bridge->local, bridge->local_used); bridge->local_used = 0; *progress = true;
    }
    return result;
}
static enum device_host_bridge_result psk_io_read_local(struct device_host_psk_bridge *bridge, bool *progress,
    struct device_pairing_guard *guard)
{
    if (bridge->session.phase != DEVICE_HOST_PSK_ESTABLISHED || bridge->local_eof || bridge->local_used ||
        bridge->session.pending_used || bridge->session.send_fin) return DEVICE_HOST_BRIDGE_READY;
    if (!psk_io_read_ready(psk_io_input(bridge))) return psk_io_queue_local(bridge, progress, guard);
    enum device_host_bridge_result result = psk_io_authorize(bridge, guard);
    if (result != DEVICE_HOST_BRIDGE_READY) return result;
    ssize_t count = read(psk_io_input(bridge), bridge->local, sizeof(bridge->local)); int error = errno;
    if (count > 0) { bridge->local_used = (size_t)count; bridge->observation.plaintext_read_bytes += (uint64_t)count; *progress = true; }
    else if (!count) { bridge->local_eof = true; *progress = true; }
    else if (!transient_error(error)) {
        bridge->observation.error_number = error; device_pairing_guard_release(guard); return DEVICE_HOST_BRIDGE_IO_ERROR;
    }
    /* Read, seal and first send of this record all run under the one guard taken above. */
    result = psk_io_queue_local(bridge, progress, guard);
    if (result == DEVICE_HOST_BRIDGE_READY && guard->held) result = psk_io_write_span(bridge, false, progress, guard);
    device_pairing_guard_release(guard);
    return result;
}
static enum device_host_bridge_result psk_io_half_close(struct device_host_psk_bridge *bridge, bool carrier, bool *progress,
    struct device_pairing_guard *guard)
{
    bool *closed = carrier ? &bridge->carrier_half_closed : &bridge->output_half_closed;
    bool finished = carrier ? bridge->session.send_fin && !bridge->session.pending_used :
        bridge->session.receive_fin && !bridge->session.plaintext_used;
    if (*closed || !finished) return DEVICE_HOST_BRIDGE_READY;
    enum device_host_bridge_result result = psk_io_authorize(bridge, guard);
    if (result != DEVICE_HOST_BRIDGE_READY) return result;
    int fd = carrier ? bridge->spec.carrier_output_fd : psk_io_output(bridge);
    bool socket = carrier ? bridge->carrier_output_socket : bridge->output_socket;
    int observed;
    if (socket) observed = shutdown(fd, SHUT_WR);
    else {
        observed = close(fd);
        if (carrier) bridge->spec.carrier_output_fd = -1; else bridge->spec.output_fd = -1;
    }
    int error = errno; device_pairing_guard_release(guard);
    if (observed < 0) { bridge->observation.error_number = error; return DEVICE_HOST_BRIDGE_IO_ERROR; }
    *closed = true; *progress = true; return DEVICE_HOST_BRIDGE_READY;
}
static enum device_host_bridge_result psk_io_eof(struct device_host_psk_bridge *bridge)
{
    if (!bridge->carrier_eof || bridge->unread_used || bridge->session.plaintext_used) return DEVICE_HOST_BRIDGE_READY;
    return psk_io_map(host_call_device_host_psk_transport_eof(&bridge->session));
}
static enum device_host_bridge_result psk_io_work(struct device_host_psk_bridge *bridge, bool *progress,
    struct device_pairing_guard *guard)
{
    enum device_host_bridge_result result = psk_io_target_step(bridge, progress);
    if (result == DEVICE_HOST_BRIDGE_READY) result = psk_io_write_span(bridge, false, progress, guard);
    if (result == DEVICE_HOST_BRIDGE_READY) result = psk_io_write_span(bridge, true, progress, guard);
    if (result == DEVICE_HOST_BRIDGE_READY) result = psk_io_consume_unread(bridge, progress);
    if (result == DEVICE_HOST_BRIDGE_READY) result = psk_io_read_carrier(bridge, progress, guard);
    if (result == DEVICE_HOST_BRIDGE_READY) result = psk_io_target_step(bridge, progress);
    if (result == DEVICE_HOST_BRIDGE_READY) result = psk_io_queue_local(bridge, progress, guard);
    if (result == DEVICE_HOST_BRIDGE_READY) result = psk_io_read_local(bridge, progress, guard);
    if (result == DEVICE_HOST_BRIDGE_READY) result = psk_io_write_span(bridge, false, progress, guard);
    if (result == DEVICE_HOST_BRIDGE_READY) result = psk_io_half_close(bridge, false, progress, guard);
    if (result == DEVICE_HOST_BRIDGE_READY) result = psk_io_half_close(bridge, true, progress, guard);
    if (result == DEVICE_HOST_BRIDGE_READY) result = psk_io_eof(bridge);
    return result;
}
static enum device_host_bridge_result device_host_psk_bridge_step_state(struct device_host_psk_bridge *bridge)
{
    if (!bridge) return DEVICE_HOST_BRIDGE_REFUSED;
    if (!bridge->active) return bridge->started ? bridge->observation.result : DEVICE_HOST_BRIDGE_REFUSED;
    struct device_pairing_guard guard = {0}; enum device_host_bridge_result result = psk_io_authorize(bridge, &guard);
    /* The step's one guard stays held for the first record action; released below. */
    bool progress = false;
    if (result == DEVICE_HOST_BRIDGE_READY && bridge->poll_error) {
        bridge->observation.error_number = EIO; result = DEVICE_HOST_BRIDGE_IO_ERROR;
    }
    if (result == DEVICE_HOST_BRIDGE_READY) result = psk_io_work(bridge, &progress, &guard);
    device_pairing_guard_release(&guard);
    if (result != DEVICE_HOST_BRIDGE_READY) { device_host_psk_bridge_close(bridge, result); return result; }
    if (bridge->session.phase == DEVICE_HOST_PSK_FINISHED && !bridge->unread_used &&
        bridge->output_half_closed && bridge->carrier_half_closed) {
        device_host_psk_bridge_close(bridge, DEVICE_HOST_BRIDGE_EOF); return DEVICE_HOST_BRIDGE_EOF;
    }
    if (progress) bridge->poll_hangup_count = 0;
    bridge->observation.result = progress ? DEVICE_HOST_BRIDGE_PROGRESS : DEVICE_HOST_BRIDGE_WAIT;
    return bridge->observation.result;
}
static bool psk_poll_latched(const struct device_host_psk_bridge *bridge, int fd)
{
    for (size_t i = 0; i < bridge->poll_hangup_count; ++i)
        if (bridge->poll_hangup_fds[i] == fd) return true;
    return false;
}
static bool psk_poll_add(const struct device_host_psk_bridge *bridge,
    struct device_host_bridge_poll_plan *plan, int fd, unsigned events)
{
    if (fd < 0 || !events || psk_poll_latched(bridge, fd)) return true;
    for (size_t i = 0; i < plan->count; ++i)
        if (plan->entries[i].fd == fd) { plan->entries[i].events |= events; return true; }
    if (plan->count == 5) return false;
    plan->entries[plan->count++] = (struct device_host_bridge_poll_entry){.fd = fd, .events = events};
    return true;
}
static bool psk_poll_local_enabled(const struct device_host_psk_bridge *bridge)
{
    return bridge->session.phase == DEVICE_HOST_PSK_ESTABLISHED && !bridge->local_eof &&
        !bridge->local_used && !bridge->session.pending_used && !bridge->session.send_fin;
}
static bool psk_poll_transition(const struct device_host_psk_bridge *bridge)
{
    if (bridge->session.phase == DEVICE_HOST_PSK_NEED_TARGET && !bridge->connect_pending) return true;
    if (bridge->unread_used && psk_io_receive_enabled(bridge)) return true;
    if (bridge->session.receive_fin && !bridge->session.plaintext_used && !bridge->output_half_closed) return true;
    return bridge->session.send_fin && !bridge->session.pending_used && !bridge->carrier_half_closed;
}
static bool psk_poll_local_transition(const struct device_host_psk_bridge *bridge)
{
    return bridge->session.phase == DEVICE_HOST_PSK_ESTABLISHED && !bridge->session.pending_used &&
        !bridge->session.send_fin && (bridge->local_used || bridge->local_eof);
}
static bool psk_poll_output_valid(const struct device_host_psk_bridge *bridge,
    const struct device_host_bridge_poll_plan *out)
{
    uintptr_t a = (uintptr_t)bridge, b = (uintptr_t)out;
    if (!out || a > UINTPTR_MAX - sizeof(*bridge) || b > UINTPTR_MAX - sizeof(*out)) return false;
    return a + sizeof(*bridge) <= b || b + sizeof(*out) <= a;
}
static bool psk_poll_carrier(const struct device_host_psk_bridge *bridge,
    struct device_host_bridge_poll_plan *plan)
{
    bool read = !bridge->carrier_eof && !bridge->unread_used && psk_io_receive_enabled(bridge);
    bool write = bridge->session.pending_used > bridge->session.pending_sent && !bridge->carrier_half_closed;
    return psk_poll_add(bridge, plan, bridge->spec.carrier_input_fd, read ? DEVICE_HOST_BRIDGE_POLL_READ : 0) &&
        psk_poll_add(bridge, plan, bridge->spec.carrier_output_fd, write ? DEVICE_HOST_BRIDGE_POLL_WRITE : 0);
}
static bool psk_poll_plaintext(const struct device_host_psk_bridge *bridge,
    struct device_host_bridge_poll_plan *plan)
{
    bool write = bridge->session.plaintext_used > bridge->session.plaintext_sent && !bridge->output_half_closed;
    return psk_poll_add(bridge, plan, psk_io_input(bridge), psk_poll_local_enabled(bridge) ? DEVICE_HOST_BRIDGE_POLL_READ : 0) &&
        psk_poll_add(bridge, plan, psk_io_output(bridge), write ? DEVICE_HOST_BRIDGE_POLL_WRITE : 0);
}
static enum device_host_bridge_result device_host_psk_bridge_poll_interest_state(
    const struct device_host_psk_bridge *bridge, struct device_host_bridge_poll_plan *out)
{
    if (!bridge || !bridge->active || !psk_poll_output_valid(bridge, out)) return DEVICE_HOST_BRIDGE_REFUSED;
    if (bridge->session.borrowed_guard) return DEVICE_HOST_BRIDGE_REFUSED;
    struct device_host_bridge_poll_plan plan = {.deadline_ns = bridge->spec.session.deadline_ns};
    plan.immediate = psk_poll_transition(bridge) || psk_poll_local_transition(bridge);
    bool ok = psk_poll_carrier(bridge, &plan) && psk_poll_plaintext(bridge, &plan) &&
        psk_poll_add(bridge, &plan, bridge->target_fd, bridge->connect_pending ? DEVICE_HOST_BRIDGE_POLL_WRITE : 0);
    if (!ok) return DEVICE_HOST_BRIDGE_REFUSED;
    *out = plan; return DEVICE_HOST_BRIDGE_READY;
}
static bool psk_poll_owned(const struct device_host_psk_bridge *bridge, int fd)
{
    return fd >= 0 && (fd == bridge->spec.carrier_input_fd || fd == bridge->spec.carrier_output_fd ||
        fd == psk_io_input(bridge) || fd == psk_io_output(bridge) || fd == bridge->target_fd);
}
static enum device_host_bridge_result device_host_psk_bridge_poll_observed_state(
    struct device_host_psk_bridge *bridge, int fd, unsigned events)
{
    if (!bridge || !bridge->active || bridge->session.borrowed_guard) return DEVICE_HOST_BRIDGE_REFUSED;
    if (!psk_poll_owned(bridge, fd) || (events & ~(DEVICE_HOST_BRIDGE_POLL_HANGUP | DEVICE_HOST_BRIDGE_POLL_ERROR)))
        return DEVICE_HOST_BRIDGE_REFUSED;
    if (events & DEVICE_HOST_BRIDGE_POLL_ERROR) bridge->poll_error = true;
    if ((events & DEVICE_HOST_BRIDGE_POLL_HANGUP) && !psk_poll_latched(bridge, fd)) {
        if (bridge->poll_hangup_count == 5) return DEVICE_HOST_BRIDGE_REFUSED;
        bridge->poll_hangup_fds[bridge->poll_hangup_count++] = fd;
    }
    return DEVICE_HOST_BRIDGE_READY;
}
static unsigned psk_poll_hints(short events)
{
    unsigned hints = 0;
    if (events & POLLHUP) hints |= DEVICE_HOST_BRIDGE_POLL_HANGUP;
    if (events & (POLLERR | POLLNVAL)) hints |= DEVICE_HOST_BRIDGE_POLL_ERROR;
    return hints;
}
static void psk_io_wait(struct device_host_psk_bridge *bridge)
{
    struct device_host_bridge_poll_plan plan;
    if (device_host_psk_bridge_poll_interest_state(bridge, &plan) != DEVICE_HOST_BRIDGE_READY) {
        device_host_psk_bridge_close(bridge, DEVICE_HOST_BRIDGE_REFUSED); return;
    }
    if (plan.immediate) return;
    struct pollfd entries[5];
    for (size_t i = 0; i < plan.count; ++i) entries[i] = (struct pollfd){.fd = plan.entries[i].fd,
        .events = (short)(((plan.entries[i].events & DEVICE_HOST_BRIDGE_POLL_READ) ? POLLIN : 0) |
                         ((plan.entries[i].events & DEVICE_HOST_BRIDGE_POLL_WRITE) ? POLLOUT : 0))};
    int ready = poll(entries, plan.count, wait_until_ms(plan.deadline_ns));
    if (ready < 0 && errno != EINTR) bridge->poll_error = true;
    for (size_t i = 0; i < plan.count; ++i) {
        unsigned hints = psk_poll_hints(entries[i].revents);
        if (ready > 0 && hints) (void)device_host_psk_bridge_poll_observed_state(bridge, entries[i].fd, hints);
    }
}
static enum device_host_bridge_result device_host_psk_bridge_run_state(struct device_host_psk_bridge *bridge)
{
    for (;;) {
        enum device_host_bridge_result result = device_host_psk_bridge_step_state(bridge);
        if (result == DEVICE_HOST_BRIDGE_WAIT) psk_io_wait(bridge);
        else if (result != DEVICE_HOST_BRIDGE_PROGRESS) return result;
    }
}
#else
static enum device_host_bridge_result device_host_psk_bridge_poll_interest_state(
    const struct device_host_psk_bridge *bridge, struct device_host_bridge_poll_plan *out)
{
    (void)bridge; (void)out; return DEVICE_HOST_BRIDGE_UNSUPPORTED;
}
static enum device_host_bridge_result device_host_psk_bridge_poll_observed_state(
    struct device_host_psk_bridge *bridge, int fd, unsigned events)
{
    (void)bridge; (void)fd; (void)events; return DEVICE_HOST_BRIDGE_UNSUPPORTED;
}
static enum device_host_bridge_result device_host_psk_bridge_set_deadline_state(
    struct device_host_psk_bridge *bridge, int64_t deadline_ns)
{
    (void)bridge; (void)deadline_ns; return DEVICE_HOST_BRIDGE_UNSUPPORTED;
}

static enum device_host_bridge_result device_host_psk_bridge_open_state(struct device_host_psk_bridge *bridge,
    const struct device_host_psk_bridge_spec *spec)
{
    (void)bridge; (void)spec; return DEVICE_HOST_BRIDGE_UNSUPPORTED;
}
static enum device_host_bridge_result device_host_psk_bridge_step_state(struct device_host_psk_bridge *bridge)
{
    (void)bridge; return DEVICE_HOST_BRIDGE_UNSUPPORTED;
}
static enum device_host_bridge_result device_host_psk_bridge_run_state(struct device_host_psk_bridge *bridge)
{
    (void)bridge; return DEVICE_HOST_BRIDGE_UNSUPPORTED;
}

static enum device_host_bridge_result device_host_bridge_open_state(struct device_host_bridge *bridge,
    const struct device_host_bridge_spec *spec)
{
    (void)bridge; (void)spec;
    return DEVICE_HOST_BRIDGE_UNSUPPORTED;
}
static enum device_host_bridge_result device_host_bridge_step_state(struct device_host_bridge *bridge)
{
    (void)bridge;
    return DEVICE_HOST_BRIDGE_UNSUPPORTED;
}
static enum device_host_bridge_result device_host_bridge_run_state(struct device_host_bridge *bridge)
{
    (void)bridge;
    return DEVICE_HOST_BRIDGE_UNSUPPORTED;
}
#endif

void device_host_bridge_close(struct device_host_bridge *bridge,
    enum device_host_bridge_result result)
{
#if defined(__linux__) || defined(__APPLE__)

    if (!bridge) return;
    if (bridge->active) {
        int descriptors[] = {bridge->spec.input_fd, bridge->spec.output_fd, bridge->transport_fd};
        close_unique(descriptors, 3);
    }
    memset(&bridge->forward, 0, sizeof(bridge->forward));
    memset(&bridge->reverse, 0, sizeof(bridge->reverse));
    bridge->transport_fd = -1;
    bridge->active = false;
    bridge->observation.result = result;
#else

    if (bridge) bridge->observation.result = result;
#endif
}

void device_host_psk_bridge_close(struct device_host_psk_bridge *bridge, enum device_host_bridge_result result)
{
#if defined(__linux__) || defined(__APPLE__)

    if (!bridge) return;
    if (bridge->active) {
        int descriptors[] = {bridge->spec.carrier_input_fd, bridge->spec.carrier_output_fd,
            bridge->spec.input_fd, bridge->spec.output_fd, bridge->target_fd};
        close_unique(descriptors, sizeof(descriptors) / sizeof(descriptors[0]));
    }
    device_host_psk_destroy(&bridge->session);
    struct device_host_psk_bridge_observation observation = bridge->observation;
    observation.result = result;
    memory_cleanse(bridge, sizeof(*bridge));
    bridge->observation = observation; bridge->target_fd = -1; bridge->started = true;
#else

    if (bridge) bridge->observation.result = result;
#endif
}

struct host_status_range { const void *bytes; size_t size; };
static bool host_status_overlap(const void *left, size_t left_size, const void *right, size_t right_size)
{
    uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;
    if (!left_size || !right_size) return false;
    if (left_size > UINTPTR_MAX - a || right_size > UINTPTR_MAX - b) return true;
    return a < b + right_size && b < a + left_size;
}
static bool host_status_storage(const void *status, size_t size,
    const struct host_status_range *ranges, size_t count)
{
    if (!status || size > UINTPTR_MAX - (uintptr_t)status) return false;
    for (size_t i = 0; i < count; ++i)
        if (ranges[i].bytes && host_status_overlap(status, size, ranges[i].bytes, ranges[i].size))
            return false;
    return true;
}

static struct zcl_result host_domain_result(enum device_host_bridge_result value, enum device_host_bridge_result *status,
    int error, const char *operation)
{
    static const char *const names[] = {"ready", "wait", "progress", "eof", "refused", "deadline", "io_error", "cancelled", "unsupported"};
    *status = value;
    if ((unsigned)value <= DEVICE_HOST_BRIDGE_EOF) return ZCL_OK;
    if (value == DEVICE_HOST_BRIDGE_IO_ERROR && error > 0)
        return ZCL_ERR(-error, "%s: host bridge IO error (error=%d)", operation, error);
    const char *name = (unsigned)value < sizeof(names) / sizeof(names[0]) ? names[value] : "invalid_state";
    int code = (unsigned)value < sizeof(names) / sizeof(names[0]) ? -100 - (int)value : -199;
    return ZCL_ERR(code, "%s: host bridge %s", operation, name);
}

struct zcl_result device_host_bridge_open(struct device_host_bridge *bridge,
    const struct device_host_bridge_spec *spec, enum device_host_bridge_result *status)
{
    const struct host_status_range ranges[] = {{bridge, sizeof(*bridge)}, {spec, sizeof(*spec)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_bridge_open: status output must be independent");
    *status = DEVICE_HOST_BRIDGE_REFUSED;
    enum device_host_bridge_result value = device_host_bridge_open_state(bridge, spec);
    return host_domain_result(value, status, bridge ? bridge->observation.error_number : 0, __func__);
}

struct zcl_result device_host_bridge_step(struct device_host_bridge *bridge, enum device_host_bridge_result *status)
{
    const struct host_status_range ranges[] = {{bridge, sizeof(*bridge)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_bridge_step: status output must be independent");
    *status = DEVICE_HOST_BRIDGE_REFUSED;
    enum device_host_bridge_result value = device_host_bridge_step_state(bridge);
    return host_domain_result(value, status, bridge ? bridge->observation.error_number : 0, __func__);
}

struct zcl_result device_host_bridge_run(struct device_host_bridge *bridge, enum device_host_bridge_result *status)
{
    const struct host_status_range ranges[] = {{bridge, sizeof(*bridge)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_bridge_run: status output must be independent");
    *status = DEVICE_HOST_BRIDGE_REFUSED;
    enum device_host_bridge_result value = device_host_bridge_run_state(bridge);
    return host_domain_result(value, status, bridge ? bridge->observation.error_number : 0, __func__);
}

struct zcl_result device_host_psk_bridge_open(struct device_host_psk_bridge *bridge,
    const struct device_host_psk_bridge_spec *spec, enum device_host_bridge_result *status)
{
    const struct host_status_range ranges[] = {{bridge, sizeof(*bridge)}, {spec, sizeof(*spec)}, {bridge ? bridge->session.borrowed_guard : NULL, sizeof(struct device_pairing_guard)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_psk_bridge_open: status output must be independent");
    *status = DEVICE_HOST_BRIDGE_REFUSED;
    enum device_host_bridge_result value = device_host_psk_bridge_open_state(bridge, spec);
    return host_domain_result(value, status, bridge ? bridge->observation.error_number : 0, __func__);
}

struct zcl_result device_host_psk_bridge_step(struct device_host_psk_bridge *bridge, enum device_host_bridge_result *status)
{
    const struct host_status_range ranges[] = {{bridge, sizeof(*bridge)}, {bridge ? bridge->session.borrowed_guard : NULL, sizeof(struct device_pairing_guard)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_psk_bridge_step: status output must be independent");
    *status = DEVICE_HOST_BRIDGE_REFUSED;
    enum device_host_bridge_result value = device_host_psk_bridge_step_state(bridge);
    return host_domain_result(value, status, bridge ? bridge->observation.error_number : 0, __func__);
}

struct zcl_result device_host_psk_bridge_set_deadline(struct device_host_psk_bridge *bridge,
    int64_t deadline_ns, enum device_host_bridge_result *status)
{
    const struct host_status_range ranges[] = {{bridge, sizeof(*bridge)}, {bridge ? bridge->session.borrowed_guard : NULL, sizeof(struct device_pairing_guard)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_psk_bridge_set_deadline: status output must be independent");
    *status = DEVICE_HOST_BRIDGE_REFUSED;
    enum device_host_bridge_result value = device_host_psk_bridge_set_deadline_state(bridge, deadline_ns);
    return host_domain_result(value, status, bridge ? bridge->observation.error_number : 0, __func__);
}

struct zcl_result device_host_psk_bridge_poll_interest(const struct device_host_psk_bridge *bridge,
    struct device_host_bridge_poll_plan *out, enum device_host_bridge_result *status)
{
    const struct host_status_range ranges[] = {{bridge, sizeof(*bridge)}, {out, sizeof(*out)}, {bridge ? bridge->session.borrowed_guard : NULL, sizeof(struct device_pairing_guard)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_psk_bridge_poll_interest: status output must be independent");
    *status = DEVICE_HOST_BRIDGE_REFUSED;
    enum device_host_bridge_result value = device_host_psk_bridge_poll_interest_state(bridge, out);
    return host_domain_result(value, status, bridge ? bridge->observation.error_number : 0, __func__);
}

struct zcl_result device_host_psk_bridge_poll_observed(struct device_host_psk_bridge *bridge,
    int fd,
    unsigned events, enum device_host_bridge_result *status)
{
    const struct host_status_range ranges[] = {{bridge, sizeof(*bridge)}, {bridge ? bridge->session.borrowed_guard : NULL, sizeof(struct device_pairing_guard)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_psk_bridge_poll_observed: status output must be independent");
    *status = DEVICE_HOST_BRIDGE_REFUSED;
    enum device_host_bridge_result value = device_host_psk_bridge_poll_observed_state(bridge, fd, events);
    return host_domain_result(value, status, bridge ? bridge->observation.error_number : 0, __func__);
}

struct zcl_result device_host_psk_bridge_run(struct device_host_psk_bridge *bridge, enum device_host_bridge_result *status)
{
    const struct host_status_range ranges[] = {{bridge, sizeof(*bridge)}, {bridge ? bridge->session.borrowed_guard : NULL, sizeof(struct device_pairing_guard)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_psk_bridge_run: status output must be independent");
    *status = DEVICE_HOST_BRIDGE_REFUSED;
    enum device_host_bridge_result value = device_host_psk_bridge_run_state(bridge);
    return host_domain_result(value, status, bridge ? bridge->observation.error_number : 0, __func__);
}
