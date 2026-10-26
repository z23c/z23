/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Foreground selected TCP carrier; authority/crypto remain in existing owners. */
#include "services/device_host_runtime.h"
#include "platform/clock.h"
#include "platform/socket_compat.h"
#include "base/bytes.h"
#include <string.h>
#include "util/log_macros.h"
#if defined(__linux__) || defined(__APPLE__)
#include <sys/stat.h>

static enum device_host_bridge_result host_call_device_host_psk_bridge_open(struct device_host_psk_bridge *bridge,
    const struct device_host_psk_bridge_spec *spec)
{
    enum device_host_bridge_result status = DEVICE_HOST_BRIDGE_REFUSED;
    struct zcl_result result = device_host_psk_bridge_open(bridge, spec, &status);
    if (!result.ok) LOG_ERROR("device_host", "%s (code=%d)", result.message, result.code);
    return status;
}

static enum device_host_bridge_result host_call_device_host_psk_bridge_step(struct device_host_psk_bridge *bridge)
{
    enum device_host_bridge_result status = DEVICE_HOST_BRIDGE_REFUSED;
    struct zcl_result result = device_host_psk_bridge_step(bridge, &status);
    if (!result.ok) LOG_ERROR("device_host", "%s (code=%d)", result.message, result.code);
    return status;
}

static enum device_host_bridge_result host_call_device_host_psk_bridge_set_deadline(struct device_host_psk_bridge *bridge,
    int64_t deadline_ns)
{
    enum device_host_bridge_result status = DEVICE_HOST_BRIDGE_REFUSED;
    struct zcl_result result = device_host_psk_bridge_set_deadline(bridge, deadline_ns, &status);
    if (!result.ok) LOG_ERROR("device_host", "%s (code=%d)", result.message, result.code);
    return status;
}

static enum device_host_bridge_result host_call_device_host_psk_bridge_poll_interest(const struct device_host_psk_bridge *bridge,
    struct device_host_bridge_poll_plan *out)
{
    enum device_host_bridge_result status = DEVICE_HOST_BRIDGE_REFUSED;
    struct zcl_result result = device_host_psk_bridge_poll_interest(bridge, out, &status);
    if (!result.ok) LOG_ERROR("device_host", "%s (code=%d)", result.message, result.code);
    return status;
}

static enum device_host_bridge_result host_call_device_host_psk_bridge_poll_observed(struct device_host_psk_bridge *bridge,
    int fd,
    unsigned events)
{
    enum device_host_bridge_result status = DEVICE_HOST_BRIDGE_REFUSED;
    struct zcl_result result = device_host_psk_bridge_poll_observed(bridge, fd, events, &status);
    if (!result.ok) LOG_ERROR("device_host", "%s (code=%d)", result.message, result.code);
    return status;
}



struct runtime_authority {
    const struct device_host_runtime_common *common;
    struct device_pairing_psk_binding binding;
    enum device_pairing_host_direction direction;
    const atomic_bool *graceful_close_requested;
};
struct runtime_slot {
    struct device_host_psk_bridge bridge;
    int64_t deadline, handshake_deadline, idle_deadline, effective_deadline, grace_deadline;
    uint64_t activity;
    bool active, authenticated, counted;
    struct runtime_reserve { uint32_t *accepted; uint32_t max; bool *counted; } reserve;
};
static int64_t runtime_slot_deadline(const struct runtime_slot *slot);
static int64_t runtime_deadline(int64_t now, uint32_t ms)
{
    int64_t span = (int64_t)ms * INT64_C(1000000);
    return now > 0 && now <= INT64_MAX - span ? now + span : 0;
}
static uint64_t runtime_wall(void)
{
    int64_t wall = clock_now_wall_ms();
    return wall > 0 ? (uint64_t)wall / 1000 : 0;
}
static bool runtime_common_valid(const struct device_host_runtime_common *common)
{
    if (!common || !common->store || !common->target_port ||
        !zcl_bytes_any_set(common->peer, 32) || !zcl_bytes_any_set(common->approved_root, 32)) return false;
    return common->handshake_ms > 0 && common->handshake_ms <= 10000 &&
        common->session_ms > 0 && common->session_ms <= DEVICE_HOST_RUNTIME_SESSION_MS_MAX &&
        common->idle_ms > 0 && common->idle_ms <= DEVICE_HOST_RUNTIME_IDLE_MS_MAX && fcntl(STDERR_FILENO, F_GETFD) >= 0;
}
static bool runtime_address_valid(uint32_t address)
{
    uint32_t host = ntohl(address), first = host >> 24;
    return first > 0 && first < 224 && host != UINT32_MAX;
}
static enum device_host_bridge_result runtime_limit(const struct device_host_runtime_common *common,
    int64_t deadline)
{
    if (common->cancelled && atomic_load_explicit(common->cancelled, memory_order_relaxed))
        return DEVICE_HOST_BRIDGE_CANCELLED;
    int64_t now = clock_now_monotonic_ns();
    if (now <= 0 || deadline <= 0) return DEVICE_HOST_BRIDGE_IO_ERROR;
    return now >= deadline ? DEVICE_HOST_BRIDGE_DEADLINE : DEVICE_HOST_BRIDGE_READY;
}
static enum device_host_bridge_result runtime_acquire(const struct runtime_authority *authority,
    int64_t deadline, struct device_pairing_guard *guard)
{
    if (authority->graceful_close_requested &&
        atomic_load_explicit(authority->graceful_close_requested, memory_order_relaxed))
        return DEVICE_HOST_BRIDGE_CANCELLED;
    enum device_host_bridge_result result = runtime_limit(authority->common, deadline);
    if (result != DEVICE_HOST_BRIDGE_READY) return result;
    const struct device_host_runtime_common *common = authority->common;
    if (!device_pairing_guard_acquire_host_psk(common->store, common->peer, common->approved_root,
        runtime_wall(), &authority->binding, authority->direction, common->target_port, guard))
        return DEVICE_HOST_BRIDGE_REFUSED;
    result = runtime_limit(common, deadline);
    if (authority->graceful_close_requested &&
        atomic_load_explicit(authority->graceful_close_requested, memory_order_relaxed))
        result = DEVICE_HOST_BRIDGE_CANCELLED;
    uint64_t now = runtime_wall();
    if (result == DEVICE_HOST_BRIDGE_READY && (now < guard->row.paired_at || now >= guard->row.expires_at))
        result = DEVICE_HOST_BRIDGE_REFUSED;
    if (result != DEVICE_HOST_BRIDGE_READY) device_pairing_guard_release(guard);
    return result;
}
static bool runtime_authority_init(struct runtime_authority *authority,
    const struct device_host_runtime_common *common, enum device_pairing_host_direction direction)
{
    struct db_device_pairing row; uint8_t root[32];
    if (!db_device_pairing_inspect(common->store, common->peer, &row, root) ||
        memcmp(root, common->approved_root, 32) ||
        row.host_scope.binding.backend_profile != DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK) return false;
    authority->common = common; authority->direction = direction;
    authority->graceful_close_requested = NULL;
    authority->binding = row.host_scope.binding.psk;
    return true;
}
static enum device_host_bridge_result runtime_current(const struct runtime_authority *authority, int64_t deadline)
{
    struct device_pairing_guard guard = {0};
    enum device_host_bridge_result result = runtime_acquire(authority, deadline, &guard);
    device_pairing_guard_release(&guard); return result;
}
static int runtime_wait_error(int error, const char *operation)
{
    LOG_RETURN((errno = error, -1), "device_host_runtime", "%s (error=%d)", operation, error);
}
static int runtime_wait(int fd, short events, int64_t deadline)
{
    int64_t now = clock_now_monotonic_ns();
    if (now <= 0 || deadline <= 0) return runtime_wait_error(EINVAL, "invalid connection wait clock or deadline");
    if (now >= deadline) return 0;
    int64_t remaining = deadline - now;
    int ms = remaining >= INT64_C(20000000) ? 20 : (int)((remaining + 999999) / 1000000);
    struct pollfd entry = {.fd = fd, .events = events};
    int result = poll(&entry, fd >= 0 ? 1 : 0, ms);
    if (result < 0) {
        int error = errno;
        if (error == EINTR) return 0;
        return runtime_wait_error(error, "connection readiness poll failed");
    }
    return result;
}
struct runtime_poll_set {
    struct pollfd entries[DEVICE_HOST_RUNTIME_ACTIVE_MAX * 5 + 1];
    struct device_host_psk_bridge *owners[DEVICE_HOST_RUNTIME_ACTIVE_MAX * 5 + 1];
    size_t count; int64_t deadline; bool immediate;
};
static short runtime_poll_events(unsigned events)
{
    return (short)(((events & DEVICE_HOST_BRIDGE_POLL_READ) ? POLLIN : 0) |
                   ((events & DEVICE_HOST_BRIDGE_POLL_WRITE) ? POLLOUT : 0));
}
static bool runtime_poll_slot(struct runtime_poll_set *set, struct runtime_slot *slot)
{
    struct device_host_bridge_poll_plan plan;
    if (host_call_device_host_psk_bridge_poll_interest(&slot->bridge, &plan) != DEVICE_HOST_BRIDGE_READY) return false;
    if (plan.deadline_ns < set->deadline) set->deadline = plan.deadline_ns;
    if (runtime_slot_deadline(slot) < set->deadline) set->deadline = runtime_slot_deadline(slot);
    set->immediate |= plan.immediate;
    for (size_t i = 0; i < plan.count; ++i) {
        if (set->count == sizeof(set->entries) / sizeof(set->entries[0])) return false;
        size_t index = set->count++;
        set->entries[index] = (struct pollfd){.fd = plan.entries[i].fd, .events = runtime_poll_events(plan.entries[i].events)};
        set->owners[index] = &slot->bridge;
    }
    return true;
}
static bool runtime_poll_observed(struct runtime_poll_set *set)
{
    for (size_t i = 0; i < set->count; ++i) {
        short ready = set->entries[i].revents; unsigned hints = 0;
        if (!set->owners[i]) {
            if (ready & (POLLERR | POLLNVAL)) return false;
            continue;
        }
        if (ready & POLLHUP) hints |= DEVICE_HOST_BRIDGE_POLL_HANGUP;
        if (ready & (POLLERR | POLLNVAL)) hints |= DEVICE_HOST_BRIDGE_POLL_ERROR;
        if (hints && host_call_device_host_psk_bridge_poll_observed(set->owners[i], set->entries[i].fd, hints) != DEVICE_HOST_BRIDGE_READY)
            return false;
    }
    return true;
}
static int runtime_poll_wait(struct runtime_poll_set *set)
{
    if (set->immediate) return 0;
    int64_t now = clock_now_monotonic_ns();
    if (now <= 0 || set->deadline <= 0) return runtime_wait_error(EINVAL, "invalid aggregate wait clock or deadline");
    if (now >= set->deadline) return 0;
    int64_t remaining = set->deadline - now;
    int milliseconds = remaining >= INT64_C(20000000) ? 20 : (int)((remaining + 999999) / 1000000);
    int ready = poll(set->entries, set->count, milliseconds);
    if (ready < 0) {
        int error = errno;
        if (error == EINTR) return 0;
        return runtime_wait_error(error, "aggregate readiness poll failed");
    }
    if (ready > 0 && !runtime_poll_observed(set)) return runtime_wait_error(EINVAL, "aggregate readiness observation rejected");
    return ready;
}
static int runtime_client_wait(struct runtime_slot *slot)
{
    struct runtime_poll_set set = {.deadline = runtime_slot_deadline(slot)};
    if (!runtime_poll_slot(&set, slot)) return runtime_wait_error(EINVAL, "client readiness interest rejected");
    return runtime_poll_wait(&set);
}
static bool runtime_app_fd(int fd)
{
    struct stat st; int flags = fcntl(fd, F_GETFL);
    if (fd < 3 || flags < 0 || !(flags & O_NONBLOCK) || fstat(fd, &st) != 0) return false;
    if (S_ISFIFO(st.st_mode)) return true;
    struct sockaddr_storage peer; socklen_t size = sizeof(peer);
    return S_ISSOCK(st.st_mode) && getpeername(fd, (struct sockaddr *)&peer, &size) == 0;
}
static bool runtime_client_valid(const struct device_host_runtime_client_spec *spec)
{
    if (!spec || !runtime_common_valid(&spec->common) || !runtime_address_valid(spec->route_address_be) ||
        !spec->route_port || !spec->connect_ms || spec->connect_ms > 10000) return false;
    if (!runtime_app_fd(spec->input_fd) || !runtime_app_fd(spec->output_fd)) return false;
    if (spec->input_fd != spec->output_fd) return true;
    struct stat st;
    return fstat(spec->input_fd, &st) == 0 && S_ISSOCK(st.st_mode);
}
static bool runtime_connected(int fd, const struct sockaddr_in *selected)
{
    int error = 0; socklen_t size = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) != 0) return false;
    if (error) { errno = error; return false; }
    struct sockaddr_in peer; size = sizeof(peer);
    return getpeername(fd, (struct sockaddr *)&peer, &size) == 0 && size == sizeof(peer) &&
        peer.sin_family == AF_INET && peer.sin_addr.s_addr == selected->sin_addr.s_addr && peer.sin_port == selected->sin_port;
}
static enum device_host_bridge_result runtime_connect_wait(int fd, const struct sockaddr_in *selected,
    const struct runtime_authority *authority, int64_t deadline, int *observed_error)
{
    for (;;) {
        enum device_host_bridge_result result = runtime_current(authority, deadline);
        if (result != DEVICE_HOST_BRIDGE_READY) return result;
        int ready = runtime_wait(fd, POLLOUT, deadline);
        if (ready < 0) { *observed_error = errno; return DEVICE_HOST_BRIDGE_IO_ERROR; }
        if (!ready) continue;
        struct device_pairing_guard guard = {0}; result = runtime_acquire(authority, deadline, &guard);
        if (result != DEVICE_HOST_BRIDGE_READY) return result;
        bool connected = runtime_connected(fd, selected); int error = errno;
        device_pairing_guard_release(&guard);
        if (!connected) { *observed_error = error; return DEVICE_HOST_BRIDGE_IO_ERROR; }
        return DEVICE_HOST_BRIDGE_READY;
    }
}
static enum device_host_bridge_result runtime_dial(const struct device_host_runtime_client_spec *spec,
    const struct runtime_authority *authority, int64_t deadline, int *carrier, int *observed_error)
{
    struct device_pairing_guard guard = {0};
    enum device_host_bridge_result result = runtime_acquire(authority, deadline, &guard);
    if (result != DEVICE_HOST_BRIDGE_READY) return result;
    struct sockaddr_in selected = {.sin_family = AF_INET, .sin_port = htons(spec->route_port),
        .sin_addr.s_addr = spec->route_address_be};
    *carrier = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    if (*carrier >= 0) (void)platform_socket_set_no_delay(*carrier, true); /* Small records must not wait on Nagle. */
    int rc = *carrier >= 0 ? connect(*carrier, (struct sockaddr *)&selected, sizeof(selected)) : -1;
    int error = errno; device_pairing_guard_release(&guard);
    if (rc == 0) return DEVICE_HOST_BRIDGE_READY;
    if (*carrier < 0 || error != EINPROGRESS) { *observed_error = error; return DEVICE_HOST_BRIDGE_IO_ERROR; }
    return runtime_connect_wait(*carrier, &selected, authority, deadline, observed_error);
}
static uint64_t runtime_activity(const struct device_host_psk_bridge_observation *observed)
{
    return observed->carrier_read_bytes + observed->carrier_written_bytes +
        observed->plaintext_read_bytes + observed->plaintext_written_bytes;
}
static void runtime_collect(struct device_host_runtime_observation *out,
    const struct device_host_psk_bridge_observation *observed)
{
    out->plaintext_read_bytes += observed->plaintext_read_bytes;
    out->plaintext_written_bytes += observed->plaintext_written_bytes;
    out->carrier_read_bytes += observed->carrier_read_bytes;
    out->carrier_written_bytes += observed->carrier_written_bytes;
    if (observed->error_number) out->error_number = observed->error_number;
}
static bool runtime_running(enum device_host_bridge_result result)
{
    return result == DEVICE_HOST_BRIDGE_READY || result == DEVICE_HOST_BRIDGE_WAIT || result == DEVICE_HOST_BRIDGE_PROGRESS;
}
#if defined(__linux__) || defined(__APPLE__)
/* Session-cap reservation at PSK success, before any target connect. */
static bool runtime_reserve_target(void *context)
{
    struct runtime_reserve *reserve = context;
    if (*reserve->accepted >= reserve->max) return false;
    ++*reserve->accepted; *reserve->counted = true; return true;
}
#endif
static void runtime_slot_init(struct runtime_slot *slot, const struct device_host_runtime_common *common,
    int64_t ceiling)
{
    memset(slot, 0, sizeof(*slot)); device_host_psk_bridge_init(&slot->bridge);
    int64_t now = clock_now_monotonic_ns(); slot->deadline = runtime_deadline(now, common->session_ms);
    if (slot->deadline > ceiling) slot->deadline = ceiling;
    slot->effective_deadline = slot->deadline;
    slot->handshake_deadline = runtime_deadline(now, common->handshake_ms);
    slot->idle_deadline = runtime_deadline(now, common->idle_ms);
}
static struct device_host_psk_bridge_spec runtime_bridge_spec(const struct device_host_runtime_common *common,
    enum device_pairing_host_direction direction, int carrier, int64_t deadline)
{
    struct device_host_psk_bridge_spec spec = {.session = {.store = common->store, .direction = direction,
        .port = common->target_port, .deadline_ns = deadline, .cancelled = common->cancelled},
        .carrier_input_fd = carrier, .carrier_output_fd = carrier, .input_fd = -1, .output_fd = -1};
    memcpy(spec.session.peer, common->peer, 32); memcpy(spec.session.approved_root, common->approved_root, 32);
    return spec;
}
static int64_t runtime_slot_deadline(const struct runtime_slot *slot)
{
    int64_t deadline = slot->deadline;
    if (!slot->authenticated && slot->handshake_deadline < deadline) deadline = slot->handshake_deadline;
    if (slot->idle_deadline < deadline) deadline = slot->idle_deadline;
    if (slot->grace_deadline > 0 && slot->grace_deadline < deadline) deadline = slot->grace_deadline;
    /* Handshake activity can refresh the proposed idle policy, but cannot
     * lengthen the already admitted bound before mutual authentication.
     * A timely ESTABLISHED transition may extend through the owning setter,
     * which checks the old bound before updating within its immutable ceiling. */
    if (!slot->authenticated && slot->effective_deadline < deadline)
        deadline = slot->effective_deadline;
    return deadline;
}
static enum device_host_bridge_result runtime_slot_step(struct runtime_slot *slot,
    const struct device_host_runtime_common *common)
{
    int64_t deadline = runtime_slot_deadline(slot);
    enum device_host_bridge_result result = runtime_limit(common, deadline);
    if (result != DEVICE_HOST_BRIDGE_READY) {
        device_host_psk_bridge_close(&slot->bridge, result); return result;
    }
    if (slot->bridge.session.phase != DEVICE_HOST_PSK_FINISHED) {
        result = host_call_device_host_psk_bridge_set_deadline(&slot->bridge, deadline);
        if (result != DEVICE_HOST_BRIDGE_READY) return result;
        slot->effective_deadline = deadline;
    }
    result = host_call_device_host_psk_bridge_step(&slot->bridge);
    int64_t now = clock_now_monotonic_ns();
    if (runtime_activity(&slot->bridge.observation) != slot->activity) {
        slot->activity = runtime_activity(&slot->bridge.observation);
        slot->idle_deadline = runtime_deadline(now, common->idle_ms);
    }
    if (!slot->authenticated && slot->bridge.session.phase == DEVICE_HOST_PSK_ESTABLISHED) {
        if (now >= slot->handshake_deadline) {
            device_host_psk_bridge_close(&slot->bridge, DEVICE_HOST_BRIDGE_DEADLINE);
            return DEVICE_HOST_BRIDGE_DEADLINE;
        }
        slot->authenticated = true;
    }
    if (runtime_running(result) && slot->bridge.session.phase == DEVICE_HOST_PSK_ESTABLISHED) {
        int64_t refreshed = runtime_slot_deadline(slot);
        enum device_host_bridge_result updated = host_call_device_host_psk_bridge_set_deadline(
            &slot->bridge, refreshed);
        if (updated != DEVICE_HOST_BRIDGE_READY) return updated;
        slot->effective_deadline = refreshed;
    }
    return result;
}
static enum device_host_bridge_result runtime_client_grace(struct runtime_slot *slot,
    const struct device_host_runtime_client_spec *spec)
{
    if (!spec->graceful_close_requested ||
        !atomic_load_explicit(spec->graceful_close_requested, memory_order_relaxed))
        return DEVICE_HOST_BRIDGE_READY;
    if (!slot->authenticated) return DEVICE_HOST_BRIDGE_CANCELLED;
    if (slot->grace_deadline) return DEVICE_HOST_BRIDGE_READY;
    int64_t now = clock_now_monotonic_ns(), bound = runtime_deadline(now, 1000);
    if (!bound) return DEVICE_HOST_BRIDGE_IO_ERROR;
    if (bound > slot->effective_deadline) bound = slot->effective_deadline;
    slot->grace_deadline = bound;
    return DEVICE_HOST_BRIDGE_READY;
}
static enum device_host_bridge_result device_host_runtime_client_run_state(
    const struct device_host_runtime_client_spec *spec, struct device_host_runtime_observation *out)
{
    if (!out) return DEVICE_HOST_BRIDGE_REFUSED;
    memset(out, 0, sizeof(*out)); out->result = DEVICE_HOST_BRIDGE_REFUSED; out->cleanup_complete = true;
    if (!runtime_client_valid(spec)) return out->result;
    struct runtime_authority authority;
    if (!runtime_authority_init(&authority, &spec->common, DEVICE_PAIRING_HOST_OUTBOUND)) return out->result;
    authority.graceful_close_requested = spec->graceful_close_requested;
    int64_t now = clock_now_monotonic_ns(), deadline = runtime_deadline(now, spec->common.session_ms);
    int64_t connect_deadline = runtime_deadline(now, spec->connect_ms);
    if (connect_deadline > deadline) connect_deadline = deadline;
    int carrier = -1;
    out->result = runtime_dial(spec, &authority, connect_deadline, &carrier, &out->error_number);
    if (out->result != DEVICE_HOST_BRIDGE_READY) { if (carrier >= 0) platform_socket_close(carrier); return out->result; }
    struct runtime_slot slot; runtime_slot_init(&slot, &spec->common, deadline);
    struct device_host_psk_bridge_spec bridge_spec = runtime_bridge_spec(&spec->common,
        DEVICE_PAIRING_HOST_OUTBOUND, carrier, slot.deadline);
    bridge_spec.input_fd = spec->input_fd; bridge_spec.output_fd = spec->output_fd;
    out->result = host_call_device_host_psk_bridge_open(&slot.bridge, &bridge_spec);
    out->io_taken = slot.bridge.observation.io_taken;
    if (!out->io_taken) platform_socket_close(carrier);
    while (runtime_running(out->result)) {
        out->result = runtime_client_grace(&slot, spec);
        if (out->result != DEVICE_HOST_BRIDGE_READY) {
            device_host_psk_bridge_close(&slot.bridge, out->result); break;
        }
        out->result = runtime_slot_step(&slot, &spec->common);
        if (out->result == DEVICE_HOST_BRIDGE_WAIT && runtime_client_wait(&slot) < 0) {
            out->error_number = errno; out->result = DEVICE_HOST_BRIDGE_IO_ERROR;
            device_host_psk_bridge_close(&slot.bridge, out->result);
        }
    }
    runtime_collect(out, &slot.bridge.observation); return out->result;
}

#if defined(__linux__) || defined(__APPLE__)
static bool runtime_receiver_valid(const struct device_host_runtime_receiver_spec *spec)
{
    if (!spec || !runtime_common_valid(&spec->common) || !runtime_address_valid(spec->listen_address_be)) return false;
    if ((ntohl(spec->listen_address_be) >> 24) != 127 && !spec->allow_external) return false;
#if defined(__APPLE__)
    /* macOS receivers are loopback-only: allow_external refuses here as well,
     * so direct runtime callers cannot bypass the entry's named refusal. */
    if (spec->allow_external) return false;
#endif
    return spec->lifetime_ms > 0 && spec->lifetime_ms <= DEVICE_HOST_RUNTIME_LIFETIME_MS_MAX &&
        spec->max_sessions > 0 && spec->max_sessions <= DEVICE_HOST_RUNTIME_ACCEPT_MAX &&
        spec->max_active > 0 && spec->max_active <= DEVICE_HOST_RUNTIME_ACTIVE_MAX;
}
static enum device_host_bridge_result runtime_listener(const struct device_host_runtime_receiver_spec *spec,
    const struct runtime_authority *authority, int64_t deadline, int *listener,
    struct device_host_runtime_observation *out)
{
    struct device_pairing_guard guard = {0};
    enum device_host_bridge_result result = runtime_acquire(authority, deadline, &guard);
    if (result != DEVICE_HOST_BRIDGE_READY) return result;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(spec->listen_port),
        .sin_addr.s_addr = spec->listen_address_be};
    *listener = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    /* SO_REUSEADDR only (never REUSEPORT): a supervised restart must rebind through TIME_WAIT. */
    bool ok = *listener >= 0 && platform_socket_set_reuse_address(*listener, true) == 0 &&
        bind(*listener, (struct sockaddr *)&address, sizeof(address)) == 0 &&
        listen(*listener, (int)spec->max_active) == 0;
    socklen_t size = sizeof(address);
    if (ok) ok = getsockname(*listener, (struct sockaddr *)&address, &size) == 0 && size == sizeof(address);
    int error = errno; device_pairing_guard_release(&guard);
    if (!ok) { out->error_number = error; return DEVICE_HOST_BRIDGE_IO_ERROR; }
    out->listen_port = ntohs(address.sin_port); return DEVICE_HOST_BRIDGE_READY;
}
static size_t runtime_free_slot(const struct runtime_slot slots[], size_t count)
{
    for (size_t i = 0; i < count; ++i) if (!slots[i].active) return i;
    return count;
}
static size_t runtime_active_count(const struct runtime_slot slots[], size_t count)
{
    size_t active = 0;
    for (size_t i = 0; i < count; ++i) if (slots[i].active) ++active;
    return active;
}
static enum device_host_bridge_result runtime_accept(int listener,
    const struct runtime_authority *authority, int64_t deadline, int *carrier, int *observed_error)
{
    struct device_pairing_guard guard = {0};
    enum device_host_bridge_result result = runtime_acquire(authority, deadline, &guard);
    if (result != DEVICE_HOST_BRIDGE_READY) return result;
    struct sockaddr_in peer; size_t size = sizeof(peer);
    *carrier = platform_socket_accept(listener, (struct sockaddr *)&peer, &size);
    int error = errno; device_pairing_guard_release(&guard);
    if (*carrier >= 0) return DEVICE_HOST_BRIDGE_READY;
    if (platform_socket_error_would_block(error) || error == EINTR) return DEVICE_HOST_BRIDGE_WAIT;
    *observed_error = error; return DEVICE_HOST_BRIDGE_IO_ERROR;
}
static void runtime_admit(const struct device_host_runtime_receiver_spec *spec,
    struct runtime_slot *slot, int carrier, int64_t deadline, struct device_host_runtime_observation *out)
{
    /* Only mutual PSK authentication consumes a session slot (see sessions_tick). */
    if (!platform_socket_set_nonblocking(carrier, true) || fcntl(carrier, F_SETFD, FD_CLOEXEC) != 0) {
        out->error_number = errno; ++out->refused; ++out->preauth_refused; platform_socket_close(carrier); return;
    }
    (void)platform_socket_set_no_delay(carrier, true);
    runtime_slot_init(slot, &spec->common, deadline);
    struct device_host_psk_bridge_spec bridge_spec = runtime_bridge_spec(&spec->common,
        DEVICE_PAIRING_HOST_INBOUND, carrier, slot->deadline);
    slot->reserve = (struct runtime_reserve){&out->accepted, spec->max_sessions, &slot->counted};
    bridge_spec.reserve_target = runtime_reserve_target; bridge_spec.reserve_context = &slot->reserve;
    enum device_host_bridge_result result = host_call_device_host_psk_bridge_open(&slot->bridge, &bridge_spec);
    if (!slot->bridge.observation.io_taken) platform_socket_close(carrier);
    slot->active = runtime_running(result);
    if (!slot->active) { ++out->refused; ++out->preauth_refused; runtime_collect(out, &slot->bridge.observation); }
}
static enum device_host_bridge_result runtime_accept_tick(const struct device_host_runtime_receiver_spec *spec,
    const struct runtime_authority *authority, struct runtime_slot slots[], int listener,
    int64_t deadline, struct device_host_runtime_observation *out)
{
    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        if (out->accepted >= spec->max_sessions) break;
        size_t index = runtime_free_slot(slots, spec->max_active);
        if (index == spec->max_active) break;
        int carrier = -1;
        enum device_host_bridge_result result = runtime_accept(listener, authority, deadline, &carrier, &out->error_number);
        if (result == DEVICE_HOST_BRIDGE_WAIT) break;
        if (result != DEVICE_HOST_BRIDGE_READY) return result;
        runtime_admit(spec, &slots[index], carrier, deadline, out);
    }
    return DEVICE_HOST_BRIDGE_READY;
}
static bool runtime_sessions_tick(const struct device_host_runtime_receiver_spec *spec,
    struct runtime_slot slots[], struct device_host_runtime_observation *out)
{
    bool progress = false;
    for (size_t i = 0; i < spec->max_active; ++i) {
        if (!slots[i].active) continue;
        enum device_host_bridge_result result = runtime_slot_step(&slots[i], &spec->common);
        if (result == DEVICE_HOST_BRIDGE_PROGRESS) progress = true;
        if (runtime_running(result)) continue;
        if (result == DEVICE_HOST_BRIDGE_EOF) ++out->completed; else ++out->refused;
        if (!slots[i].authenticated) ++out->preauth_refused;
        runtime_collect(out, &slots[i].bridge.observation); slots[i].active = false;
    }
    return progress;
}
static void runtime_stop_slots(struct runtime_slot slots[], size_t count,
    enum device_host_bridge_result result, struct device_host_runtime_observation *out)
{
    for (size_t i = 0; i < count; ++i) {
        if (!slots[i].active) continue;
        device_host_psk_bridge_close(&slots[i].bridge, result);
        runtime_collect(out, &slots[i].bridge.observation); slots[i].active = false; ++out->refused;
    }
}
static int runtime_receiver_wait(const struct device_host_runtime_receiver_spec *spec,
    struct runtime_slot slots[], int listener, int64_t deadline,
    const struct device_host_runtime_observation *out)
{
    struct runtime_poll_set set = {.deadline = deadline};
    if (listener >= 0 && out->accepted < spec->max_sessions && runtime_free_slot(slots, spec->max_active) < spec->max_active) {
        set.entries[0] = (struct pollfd){.fd = listener, .events = POLLIN}; set.count = 1;
    }
    for (size_t i = 0; i < spec->max_active; ++i) {
        if (!slots[i].active) continue;
        if (!runtime_poll_slot(&set, &slots[i])) return runtime_wait_error(EINVAL, "receiver readiness interest rejected");
    }
    return runtime_poll_wait(&set);
}
static enum device_host_bridge_result runtime_receiver_loop(const struct device_host_runtime_receiver_spec *spec,
    const struct runtime_authority *authority, struct runtime_slot slots[], int *listener,
    int64_t deadline, struct device_host_runtime_observation *out)
{
    while (*listener >= 0 || runtime_active_count(slots, spec->max_active)) {
        enum device_host_bridge_result result = runtime_current(authority, deadline);
        if (result != DEVICE_HOST_BRIDGE_READY) return result;
        if (*listener >= 0) {
            result = runtime_accept_tick(spec, authority, slots, *listener, deadline, out);
            if (result != DEVICE_HOST_BRIDGE_READY) return result;
            if (out->accepted >= spec->max_sessions || out->preauth_refused >= DEVICE_HOST_RUNTIME_PREAUTH_MAX) {
                platform_socket_close(*listener); *listener = -1;
            }
        }
        bool progress = runtime_sessions_tick(spec, slots, out);
        if (*listener >= 0 && out->preauth_refused >= DEVICE_HOST_RUNTIME_PREAUTH_MAX) {
            platform_socket_close(*listener); *listener = -1;
        }
        if (progress) continue;
        if (runtime_receiver_wait(spec, slots, *listener, deadline, out) < 0) {
            out->error_number = errno; return DEVICE_HOST_BRIDGE_IO_ERROR;
        }
    }
    /* A cancel observed by a slot deadline check can drain the loop before the top check sees it. */
    if (spec->common.cancelled && atomic_load_explicit(spec->common.cancelled, memory_order_relaxed))
        return DEVICE_HOST_BRIDGE_CANCELLED;
    /* Pre-auth flood ceiling reached: listener closed, distinct from a clean lifetime end. */
    return out->preauth_refused >= DEVICE_HOST_RUNTIME_PREAUTH_MAX ? DEVICE_HOST_BRIDGE_REFUSED : DEVICE_HOST_BRIDGE_EOF;
}
static enum device_host_bridge_result device_host_runtime_receiver_run_state(
    const struct device_host_runtime_receiver_spec *spec, struct device_host_runtime_observation *out)
{
    if (!out) return DEVICE_HOST_BRIDGE_REFUSED;
    memset(out, 0, sizeof(*out)); out->result = DEVICE_HOST_BRIDGE_REFUSED; out->cleanup_complete = true;
    if (!runtime_receiver_valid(spec)) return out->result;
    struct runtime_authority authority;
    if (!runtime_authority_init(&authority, &spec->common, DEVICE_PAIRING_HOST_INBOUND)) return out->result;
    int64_t deadline = runtime_deadline(clock_now_monotonic_ns(), spec->lifetime_ms); int listener = -1;
    out->result = runtime_listener(spec, &authority, deadline, &listener, out);
    if (out->result != DEVICE_HOST_BRIDGE_READY) { if (listener >= 0) platform_socket_close(listener); return out->result; }
    struct runtime_slot slots[DEVICE_HOST_RUNTIME_ACTIVE_MAX] = {0};
    if (spec->ready) spec->ready(spec->ready_context, out);
    out->result = runtime_receiver_loop(spec, &authority, slots, &listener, deadline, out);
    if (listener >= 0) platform_socket_close(listener);
    runtime_stop_slots(slots, spec->max_active, out->result, out); return out->result;
}
#endif
#else
static enum device_host_bridge_result device_host_runtime_client_run_state(
    const struct device_host_runtime_client_spec *spec, struct device_host_runtime_observation *out)
{
    (void)spec;
    if (out) { memset(out, 0, sizeof(*out)); out->result = DEVICE_HOST_BRIDGE_UNSUPPORTED; out->cleanup_complete = true; }
    return DEVICE_HOST_BRIDGE_UNSUPPORTED;
}
/* Shared unsupported fallback; spec is never dereferenced, so the cast is safe. */
static enum device_host_bridge_result device_host_runtime_receiver_run_state(
    const struct device_host_runtime_receiver_spec *spec, struct device_host_runtime_observation *out)
{
    return device_host_runtime_client_run_state((const struct device_host_runtime_client_spec *)spec, out);
}
#endif

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

static struct zcl_result runtime_domain_result(enum device_host_bridge_result value,
    int error, const char *operation)
{
    static const char *const names[] = {"ready", "wait", "progress", "eof", "refused",
        "deadline", "io_error", "cancelled", "unsupported"};
    if ((unsigned)value <= DEVICE_HOST_BRIDGE_EOF) return ZCL_OK;
    if (value == DEVICE_HOST_BRIDGE_IO_ERROR && error > 0)
        return ZCL_ERR(-error, "%s: host runtime IO error (error=%d)", operation, error);
    const char *name = (unsigned)value < sizeof(names) / sizeof(names[0]) ? names[value] : "invalid_state";
    int code = (unsigned)value < sizeof(names) / sizeof(names[0]) ? -100 - (int)value : -199;
    return ZCL_ERR(code, "%s: host runtime %s", operation, name);
}

struct zcl_result device_host_runtime_client_run(const struct device_host_runtime_client_spec *spec,
    struct device_host_runtime_observation *observation)
{
    const struct host_status_range ranges[] = {{spec, sizeof(*spec)}};
    if (!host_status_storage(observation, sizeof(*observation), ranges, 1))
        return ZCL_ERR(-1000, "device_host_runtime_client_run: observation must be independent");
    enum device_host_bridge_result value = device_host_runtime_client_run_state(spec, observation);
    return runtime_domain_result(value, observation->error_number, __func__);
}

struct zcl_result device_host_runtime_receiver_run(const struct device_host_runtime_receiver_spec *spec,
    struct device_host_runtime_observation *observation)
{
    const struct host_status_range ranges[] = {{spec, sizeof(*spec)}};
    if (!host_status_storage(observation, sizeof(*observation), ranges, 1))
        return ZCL_ERR(-1000, "device_host_runtime_receiver_run: observation must be independent");
    enum device_host_bridge_result value = device_host_runtime_receiver_run_state(spec, observation);
    return runtime_domain_result(value, observation->error_number, __func__);
}
