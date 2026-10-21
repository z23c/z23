/* purpose: Run strict foreground HOST roles without node boot or stream framing pollution. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/device_host_runtime_entry.h"
#include "services/device_identity.h"
#include "services/device_host_runtime.h"
#include "base/hex.h"
#include "base/bytes.h"
#include <stdio.h>
#include <errno.h>
#include "util/log_macros.h"
#include <stdlib.h>
#include <string.h>
struct entry_field { const char *key; enum json_type type; uint32_t minimum, maximum; };
static const struct entry_field common_fields[] = {
    {"directory", JSON_STR, 1, 1023}, {"peer_key", JSON_STR, 64, 64}, {"expected_root", JSON_STR, 64, 64},
    {"target_port", JSON_INT, 1, UINT16_MAX}, {"route_id", JSON_STR, 1, 64},
    {"handshake_ms", JSON_INT, 1, 10000}, {"session_ms", JSON_INT, 1, DEVICE_HOST_RUNTIME_SESSION_MS_MAX},
    {"idle_ms", JSON_INT, 1, DEVICE_HOST_RUNTIME_IDLE_MS_MAX}, {"confirm", JSON_BOOL, 0, 0}
};
static const struct entry_field client_fields[] = {
    {"route_address", JSON_STR, 1, 15}, {"route_port", JSON_INT, 1, UINT16_MAX}, {"connect_ms", JSON_INT, 1, 10000}
};
static const struct entry_field receiver_fields[] = {
    {"listen_address", JSON_STR, 1, 15}, {"listen_port", JSON_INT, 0, UINT16_MAX}, {"allow_external", JSON_BOOL, 0, 0},
    {"lifetime_ms", JSON_INT, 1, DEVICE_HOST_RUNTIME_LIFETIME_MS_MAX}, {"max_sessions", JSON_INT, 1, 64}, {"max_active", JSON_INT, 1, 4}
};
static bool entry_field_valid(const struct json_value *input, const struct entry_field *field)
{
    const struct json_value *value = json_get(input, field->key);
    if (!value || value->type != field->type) return false;
    if (field->type == JSON_BOOL) return true;
    if (field->type == JSON_STR) {
        const char *text = json_get_str(value);
        if (!text) return false;
        size_t length = strlen(text); return length >= field->minimum && length <= field->maximum;
    }
    return value->val.i >= field->minimum && (uint64_t)value->val.i <= field->maximum;
}
static bool entry_fields_valid(const struct json_value *input, const struct entry_field *fields, size_t count)
{
    for (size_t i = 0; i < count; ++i) if (!entry_field_valid(input, &fields[i])) return false;
    return true;
}
static bool entry_object_valid(const struct json_value *input, bool receiver)
{
    const struct entry_field *fields = receiver ? receiver_fields : client_fields;
    size_t count = receiver ? sizeof(receiver_fields) / sizeof(receiver_fields[0]) : sizeof(client_fields) / sizeof(client_fields[0]);
    size_t common = sizeof(common_fields) / sizeof(common_fields[0]);
    if (!input || input->type != JSON_OBJ || input->num_children != common + count) return false;
    for (size_t i = 0; i < input->num_children; ++i) {
        if (!input->keys[i]) return false;
        for (size_t j = 0; j < i; ++j) if (!strcmp(input->keys[i], input->keys[j])) return false;
    }
    return entry_fields_valid(input, common_fields, common) && entry_fields_valid(input, fields, count);
}
static bool entry_text_valid(const char *text, size_t length)
{
    if (!text || !length || length > 4096) return false;
    for (size_t i = 0; i < length; ++i) {
        if (!text[i]) return false;
        if (text[i] == '\\' && ++i < length && text[i] == 'u' && length - i > 4 && !memcmp(text + i + 1, "0000", 4))
            return false;
    }
    return true;
}
struct zcl_result device_host_runtime_entry_parse(struct json_value *out, const char *text, size_t length, bool receiver)
{
    if (!out || !entry_text_valid(text, length))
        return ZCL_ERR(-1, "missing output or invalid bounded HOST runtime input text");
    if (json_read(out, text, length) && entry_object_valid(out, receiver)) return ZCL_OK;
    json_free(out); json_init(out);
    return ZCL_ERR(-2, "cannot parse or validate HOST runtime JSON object, fields or types");
}
#if defined(__linux__) || defined(__APPLE__)
#include "platform/socket_compat.h"
#include <signal.h>
#include <sys/stat.h>
_Static_assert(ATOMIC_BOOL_LOCK_FREE == 2, "foreground signal cancellation requires lock-free atomic_bool");

struct raw_runtime {
    struct device_identity identity;
    struct device_pairing_store store;
    struct device_host_runtime_client_spec client;
    struct device_host_runtime_receiver_spec receiver;
    char route_id[65];
};
struct raw_signals {
    struct sigaction interrupt, terminate, hangup;
    sigset_t mask;
    bool interrupt_saved, terminate_saved, hangup_saved, mask_saved;
};
struct raw_stdio { int descriptors[2], flags[2]; };
static atomic_bool raw_cancelled;
static atomic_bool raw_grace_requested;
static volatile sig_atomic_t raw_hangup_cancels;
static void raw_signal(int signal_number)
{
    if (signal_number == SIGHUP && !raw_hangup_cancels)
        atomic_store_explicit(&raw_grace_requested, true, memory_order_relaxed);
    else atomic_store_explicit(&raw_cancelled, true, memory_order_relaxed);
}
static bool raw_signals_restore(const struct raw_signals *prior)
{
    if (!prior->mask_saved) return false;
    sigset_t block; sigemptyset(&block); sigaddset(&block, SIGINT); sigaddset(&block, SIGTERM); sigaddset(&block, SIGHUP);
    bool ok = sigprocmask(SIG_BLOCK, &block, NULL) == 0;
    if (prior->interrupt_saved && sigaction(SIGINT, &prior->interrupt, NULL) != 0) ok = false;
    if (prior->terminate_saved && sigaction(SIGTERM, &prior->terminate, NULL) != 0) ok = false;
    if (prior->hangup_saved && sigaction(SIGHUP, &prior->hangup, NULL) != 0) ok = false;
    if (prior->mask_saved && sigprocmask(SIG_SETMASK, &prior->mask, NULL) != 0) ok = false;
    return ok;
}
static bool raw_signals_install(struct raw_signals *prior, bool receiver)
{
    memset(prior, 0, sizeof(*prior)); atomic_store_explicit(&raw_cancelled, false, memory_order_relaxed);
    atomic_store_explicit(&raw_grace_requested, false, memory_order_relaxed); raw_hangup_cancels = receiver;
    if (sigprocmask(SIG_SETMASK, NULL, &prior->mask) != 0) return false;
    prior->mask_saved = true;
    struct sigaction action = {.sa_handler = raw_signal}; sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, &prior->interrupt) != 0) return false;
    prior->interrupt_saved = true;
    if (sigaction(SIGTERM, &action, &prior->terminate) != 0) return false;
    prior->terminate_saved = true;
    if (sigaction(SIGHUP, &action, &prior->hangup) != 0) return false;
    prior->hangup_saved = true;
    sigset_t unblock; sigemptyset(&unblock); sigaddset(&unblock, SIGINT); sigaddset(&unblock, SIGTERM); sigaddset(&unblock, SIGHUP);
    return sigprocmask(SIG_UNBLOCK, &unblock, NULL) == 0;
}
static bool raw_number(const struct json_value *input, const char *key, uint32_t maximum, uint32_t *out)
{
    const struct json_value *value = json_get(input, key);
    if (!value || value->type != JSON_INT) return false;
    int64_t number = json_get_int(value);
    if (number < 0 || (uint64_t)number > maximum) return false;
    *out = (uint32_t)number; return true;
}
static bool raw_hex(const struct json_value *input, const char *key, uint8_t out[32])
{
    const char *text = json_get_str(json_get(input, key));
    return text && zcl_hex_decode(text, out, 32) && zcl_bytes_any_set(out, 32);
}
static bool raw_route_id(const struct json_value *input, char out[65])
{
    const char *text = json_get_str(json_get(input, "route_id"));
    if (!text || !text[0] || strlen(text) > 64) return false;
    for (size_t i = 0; text[i]; ++i) {
        unsigned char c = (unsigned char)text[i];
        bool letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        bool digit = c >= '0' && c <= '9';
        if (!letter && !digit && c != '-' && c != '_' && c != '.') return false;
    }
    memcpy(out, text, strlen(text) + 1); return true;
}
static bool raw_address(const struct json_value *input, const char *key, uint32_t *out)
{
    const char *text = json_get_str(json_get(input, key)); struct in_addr address;
    if (!text || inet_pton(AF_INET, text, &address) != 1) return false;
    *out = address.s_addr; return true;
}
static bool raw_bool(const struct json_value *input, const char *key, bool *out)
{
    const struct json_value *value = json_get(input, key);
    if (!value || value->type != JSON_BOOL) return false;
    *out = json_get_bool(value); return true;
}
static bool raw_common(const struct json_value *input, struct raw_runtime *runtime,
    struct device_host_runtime_common *common)
{
    const char *directory = json_get_str(json_get(input, "directory")); bool confirmed;
    if (!directory || !raw_bool(input, "confirm", &confirmed) || !confirmed ||
        !raw_route_id(input, runtime->route_id) || !raw_hex(input, "peer_key", common->peer) ||
        !raw_hex(input, "expected_root", common->approved_root)) return false;
    uint32_t port;
    if (!raw_number(input, "target_port", UINT16_MAX, &port) || !port ||
        !raw_number(input, "handshake_ms", 10000, &common->handshake_ms) ||
        !raw_number(input, "session_ms", DEVICE_HOST_RUNTIME_SESSION_MS_MAX, &common->session_ms) ||
        !raw_number(input, "idle_ms", DEVICE_HOST_RUNTIME_IDLE_MS_MAX, &common->idle_ms)) return false;
    common->target_port = (uint16_t)port; common->cancelled = &raw_cancelled;
    struct device_identity_publication_report report;
    struct zcl_result opened = device_identity_open(&runtime->identity, directory, false, &report);
    if (!opened.ok) {
        int error = errno;
        LOG_RETURN((errno = error, false), "device_host_runtime", "owner identity admission failed: %s", opened.message);
    }
    struct zcl_result paired = device_identity_pair_store(&runtime->identity, common->peer, &runtime->store);
    if (!paired.ok) {
        int error = errno;
        LOG_RETURN((errno = error, false), "device_host_runtime", "owner pairing-store admission failed: %s", paired.message);
    }
    common->store = &runtime->store; return true;
}
static bool raw_client_input(const struct json_value *input, struct raw_runtime *runtime)
{
    uint32_t port;
    if (!raw_common(input, runtime, &runtime->client.common) ||
        !raw_address(input, "route_address", &runtime->client.route_address_be) ||
        !raw_number(input, "route_port", UINT16_MAX, &port) || !port ||
        !raw_number(input, "connect_ms", 10000, &runtime->client.connect_ms)) return false;
    runtime->client.route_port = (uint16_t)port;
    runtime->client.graceful_close_requested = &raw_grace_requested; return true;
}
static void raw_receiver_ready(void *context, const struct device_host_runtime_observation *out)
{
    const struct raw_runtime *runtime = context;
    fprintf(stderr, "event=HOST_RECEIVER_LISTENING route=%s listen_port=%u\n", runtime->route_id, (unsigned)out->listen_port);
}
static bool raw_receiver_input(const struct json_value *input, struct raw_runtime *runtime)
{
    uint32_t port; struct device_host_runtime_receiver_spec *spec = &runtime->receiver;
    if (!raw_common(input, runtime, &spec->common) ||
        !raw_address(input, "listen_address", &spec->listen_address_be) ||
        !raw_number(input, "listen_port", UINT16_MAX, &port) ||
        !raw_bool(input, "allow_external", &spec->allow_external)) return false;
    spec->listen_port = (uint16_t)port;
    if (!raw_number(input, "lifetime_ms", DEVICE_HOST_RUNTIME_LIFETIME_MS_MAX, &spec->lifetime_ms) ||
        !raw_number(input, "max_sessions", DEVICE_HOST_RUNTIME_ACCEPT_MAX, &spec->max_sessions) ||
        !raw_number(input, "max_active", DEVICE_HOST_RUNTIME_ACTIVE_MAX, &spec->max_active)) return false;
    spec->ready = raw_receiver_ready; spec->ready_context = runtime; return true;
}
static bool raw_stdio_restore(struct raw_stdio *stdio, bool taken)
{
    bool ok = true;
    for (int i = 0; i < 2; ++i) {
        if (!taken && stdio->descriptors[i] >= 0) close(stdio->descriptors[i]);
        if (stdio->flags[i] >= 0 && fcntl(i, F_SETFL, stdio->flags[i]) != 0) ok = false;
    }
    return ok;
}
static bool raw_stdio_open(struct raw_stdio *stdio)
{
    stdio->descriptors[0] = stdio->descriptors[1] = -1; stdio->flags[0] = stdio->flags[1] = -1;
    for (int i = 0; i < 2; ++i) {
        stdio->flags[i] = fcntl(i, F_GETFL);
        if (stdio->flags[i] < 0) return false;
    }
    for (int i = 0; i < 2; ++i) {
        struct stat st;
        if (fstat(i, &st) != 0 || (!S_ISFIFO(st.st_mode) && !S_ISSOCK(st.st_mode))) return false;
        stdio->descriptors[i] = fcntl(i, F_DUPFD_CLOEXEC, 3);
        if (stdio->descriptors[i] < 0 || fcntl(stdio->descriptors[i], F_SETFL, stdio->flags[i] | O_NONBLOCK) != 0) return false;
    }
    return true;
}
static const char *raw_result_name(enum device_host_bridge_result result)
{
    static const char *const names[] = {"ready", "wait", "progress", "eof", "refused", "deadline", "io_error", "cancelled", "unsupported"};
    return (unsigned)result < sizeof(names) / sizeof(names[0]) ? names[result] : "invalid";
}
static void raw_runtime_run(struct raw_runtime *runtime, bool receiver,
    const struct raw_stdio *stdio, struct device_host_runtime_observation *out)
{
    struct zcl_result result;
    if (receiver) result = device_host_runtime_receiver_run(&runtime->receiver, out);
    else {
        runtime->client.input_fd = stdio->descriptors[0];
        runtime->client.output_fd = stdio->descriptors[1];
        result = device_host_runtime_client_run(&runtime->client, out);
    }
    if (!result.ok) fprintf(stderr, "error=HOST_RUNTIME_FAILURE %s\n", result.message);
}
#if defined(__APPLE__)
/* macOS receivers stay loopback-only: allow_external=true refuses by name
 * before input validation, preserving the pre-lift ordering in which the
 * platform refusal preceded every other check. */
static bool raw_apple_external_refused(const struct json_value *input, bool receiver)
{
    const struct json_value *external = receiver ? json_get(input, "allow_external") : NULL;
    return external && external->type == JSON_BOOL && json_get_bool(external);
}
#endif
static enum device_host_runtime_entry_exit device_host_runtime_entry_run_state(const struct json_value *input, bool receiver)
{
#if defined(__APPLE__)
    if (raw_apple_external_refused(input, receiver)) {
        fprintf(stderr, "error=HOST_RUNTIME_UNSUPPORTED role=receiver allow_external=unsupported platform=darwin_loopback_only\n");
        return DEVICE_HOST_ENTRY_UNSUPPORTED;
    }
#endif

    if (!entry_object_valid(input, receiver)) {
        fprintf(stderr, "error=HOST_RUNTIME_INPUT_REFUSED\n"); return DEVICE_HOST_ENTRY_INVALID;
    }
    struct raw_runtime runtime = {0};
    bool valid = receiver ? raw_receiver_input(input, &runtime) : raw_client_input(input, &runtime);
    if (!valid) { device_identity_close(&runtime.identity); fprintf(stderr, "error=HOST_RUNTIME_INPUT_REFUSED\n"); return DEVICE_HOST_ENTRY_INVALID; }
    struct raw_signals signals; bool installed = raw_signals_install(&signals, receiver);
    struct device_host_runtime_observation out = {.result = DEVICE_HOST_BRIDGE_REFUSED, .cleanup_complete = true};
    struct raw_stdio stdio = {.descriptors = {-1, -1}, .flags = {-1, -1}};
    bool stdio_ok = receiver || raw_stdio_open(&stdio);
    if (installed && stdio_ok) raw_runtime_run(&runtime, receiver, &stdio, &out);
    bool restored = raw_stdio_restore(&stdio, out.io_taken);
    restored = raw_signals_restore(&signals) && restored;
    device_identity_close(&runtime.identity);
    fprintf(stderr, "event=HOST_RUNTIME_TERMINAL route=%s result=%s cleanup_complete=%u accepted=%u completed=%u refused=%u plaintext_read=%llu plaintext_written=%llu preauth_refused=%u\n",
        runtime.route_id, raw_result_name(out.result), (unsigned)out.cleanup_complete, out.accepted, out.completed, out.refused,
        (unsigned long long)out.plaintext_read_bytes, (unsigned long long)out.plaintext_written_bytes, out.preauth_refused);
    return installed && stdio_ok && restored && out.result == DEVICE_HOST_BRIDGE_EOF ? DEVICE_HOST_ENTRY_OK : DEVICE_HOST_ENTRY_FAILED;
}
#else
static enum device_host_runtime_entry_exit device_host_runtime_entry_run_state(const struct json_value *input, bool receiver)
{
    (void)input; (void)receiver;
    fprintf(stderr, "error=HOST_RUNTIME_UNSUPPORTED platform=unqualified\n"); return DEVICE_HOST_ENTRY_UNSUPPORTED;
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

struct zcl_result device_host_runtime_entry_run(const struct json_value *input, bool receiver,
    enum device_host_runtime_entry_exit *status)
{
    const struct host_status_range ranges[] = {{input, sizeof(*input)}};
    if (!host_status_storage(status, sizeof(*status), ranges, 1))
        return ZCL_ERR(-1000, "device_host_runtime_entry_run: exit output must be independent");
    *status = DEVICE_HOST_ENTRY_INVALID;
    *status = device_host_runtime_entry_run_state(input, receiver);
    if (*status == DEVICE_HOST_ENTRY_OK) return ZCL_OK;
    return ZCL_ERR(-100 - (int)*status, "HOST raw entry failed (exit=%d)", (int)*status);
}
