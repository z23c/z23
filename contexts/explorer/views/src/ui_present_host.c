/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: warm AF_UNIX-only native presentation host and event return. */

#define _GNU_SOURCE
#include "views/ui_present_host.h"
#include "views/ui_present_host_transport.h"

#include "platform/os_proc.h"
#include "platform/time_compat.h"
#include "presentation/presentation.h"
#include "util/log_macros.h"
#include "util/spawn.h"
#include "views/ui_present_document.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define UI_HOST_START_TIMEOUT_MS 1000
#define UI_HOST_READY_TIMEOUT_MS 3000
#define UI_HOST_EVENT_TIMEOUT_MS (10 * 60 * 1000)
#define UI_HOST_IDLE_EXIT_US (10LL * 60LL * 1000000LL)
#define UI_HOST_SESSIONS_MAX 16u

#if defined(__linux__)
static struct zcl_result ui_host_error(const char *where)
{
    return ZCL_ERR(-errno, "%s: %s", where, strerror(errno));
}

static struct zcl_result ui_host_launch(void)
{
    char executable[PATH_MAX];
    if (!os_proc_exe_path(executable, sizeof(executable)))
        return ui_host_error("presentation host executable path");
    const char *argv[] = {executable, "--ui-present-host", NULL};
    return zcl_spawn_detached(argv, NULL);
}

static ui_host_transport_t ui_host_connect(bool *reused)
{
    ui_host_transport_t fd = ui_host_transport_connect_once();
    if (fd != UI_HOST_TRANSPORT_INVALID) {
        *reused = true;
        return fd;
    }
    *reused = false;
    struct zcl_result launched = ui_host_launch();
    if (!launched.ok) {
        errno = EIO;
        return -1;
    }
    int64_t deadline = platform_time_monotonic_us() +
                       UI_HOST_START_TIMEOUT_MS * 1000LL;
    do {
        platform_sleep_ms(5);
        fd = ui_host_transport_connect_once();
        if (fd != UI_HOST_TRANSPORT_INVALID) return fd;
    } while (platform_time_monotonic_us() < deadline);
    errno = ETIMEDOUT;
    return UI_HOST_TRANSPORT_INVALID;
}

struct ui_host_ready_context {
    ui_host_transport_t fd;
    int replacement_gate;
    int64_t started_us;
    uint32_t ready_value;
    uint8_t nonce[UI_HOST_NONCE_BYTES];
};

static void ui_host_window_ready(void *context)
{
    struct ui_host_ready_context *ready = context;
    if (ready->replacement_gate >= 0) {
        const uint8_t rendered = 1u;
        uint8_t release = 0;
        if (!ui_host_transport_send_all(ready->replacement_gate,
                                        &rendered, sizeof(rendered)) ||
            !ui_host_transport_recv_all(ready->replacement_gate,
                                        &release, sizeof(release),
                                        UI_HOST_READY_TIMEOUT_MS) ||
            release != 1u)
            return;
    }
    uint8_t reply[UI_HOST_REPLY_BYTES];
    int64_t elapsed = platform_time_monotonic_us() - ready->started_us;
    ui_host_transport_reply(reply, UI_HOST_PHASE_READY, UI_HOST_STATUS_OK,
                            ready->ready_value, 0,
                            elapsed > 0 ? (uint64_t)elapsed : 0,
                            ready->nonce);
    (void)ui_host_transport_send_all(ready->fd, reply, sizeof(reply));
}

static void ui_host_send_rejected(
    ui_host_transport_t fd, uint16_t phase, uint32_t status,
    const uint8_t nonce[UI_HOST_NONCE_BYTES])
{
    uint8_t reply[UI_HOST_REPLY_BYTES];
    ui_host_transport_reply(reply, phase, status, UINT32_MAX, 0, 0, nonce);
    (void)ui_host_transport_send_all(fd, reply, sizeof(reply));
}

/* Shared model predicates: a submit action is one whose index is in range and
 * whose kind is SUBMIT; a control model is a form or a canvas. */
static bool ui_host_submit_action(const struct zcl_present_model_v1 *model,
                                  uint32_t action)
{
    return action < model->action_count &&
           model->actions[action].kind == ZCL_PRESENT_ACTION_SUBMIT;
}

static bool ui_host_model_has_controls(
    const struct zcl_present_model_v1 *model)
{
    return model &&
           (model->kind == ZCL_PRESENT_MODEL_FORM ||
            model->kind == ZCL_PRESENT_MODEL_CANVAS);
}

static bool ui_host_document_controls_ready(
    struct ui_present_document *document,
    struct zcl_present_window_form_v1 *form,
    struct zcl_present_window_canvas_v1 *canvas,
    char *why, size_t why_len)
{
    bool is_form = document->model.kind == ZCL_PRESENT_MODEL_FORM;
    bool is_canvas = document->model.kind == ZCL_PRESENT_MODEL_CANVAS;
    bool ready =
        (!is_form || zcl_present_window_form_from_model_v1(
            &document->model, form, why, why_len)) &&
        (!is_canvas || zcl_present_window_canvas_from_model_v1(
            &document->model, canvas, why, why_len));
    if (!ready)
        (void)snprintf(why, why_len,
                       "validated model could not enter bounded control state");
    return ready;
}

static bool ui_host_show_pages(
    struct ui_present_document *document,
    struct zcl_present_window_pages_v1 *pages,
    struct zcl_present_window_form_v1 *form,
    struct zcl_present_window_canvas_v1 *canvas,
    struct ui_host_ready_context *ready,
    struct zcl_present_window_event_v1 *event,
    char *why, size_t why_len)
{
    if (!ui_host_document_controls_ready(document, form, canvas,
                                         why, why_len))
        return false;
    if (document->model.kind == ZCL_PRESENT_MODEL_FORM)
        return zcl_present_window_run_pages_form_actions_v1(
            pages, document->action_count, form,
            ui_host_window_ready, ready, event, why, why_len);
    if (document->model.kind == ZCL_PRESENT_MODEL_CANVAS)
        return zcl_present_window_run_pages_canvas_actions_v1(
            pages, document->action_count, canvas,
            ui_host_window_ready, ready, event, why, why_len);
    return zcl_present_window_run_pages_actions_v1(
        pages, document->action_count,
        ui_host_window_ready, ready, event, why, why_len);
}

static bool ui_host_document_submit_payload(
    struct ui_present_document *document,
    const struct zcl_present_window_form_v1 *form,
    const struct zcl_present_window_canvas_v1 *canvas,
    uint32_t action,
    uint8_t payload[ZCL_PRESENT_MODEL_WIRE_MAX], size_t *payload_len,
    char *why, size_t why_len)
{
    if (document->model.kind == ZCL_PRESENT_MODEL_FORM &&
        ui_host_submit_action(&document->model, action)) {
        for (uint32_t i = 0; i < form->field_count; i++)
            (void)snprintf(document->model.items[i].value,
                           sizeof(document->model.items[i].value), "%s",
                           form->fields[i].value);
        return zcl_present_model_encode_v1(
            &document->model, payload, ZCL_PRESENT_MODEL_WIRE_MAX,
            payload_len, why, why_len);
    }
    if (document->model.kind == ZCL_PRESENT_MODEL_CANVAS &&
        ui_host_submit_action(&document->model, action)) {
        for (uint32_t i = 0; i < canvas->point_count; i++) {
            document->model.items[i].numerator = canvas->points[i].x;
            document->model.items[i].denominator = canvas->points[i].y;
        }
        return zcl_present_model_encode_v1(
            &document->model, payload, ZCL_PRESENT_MODEL_WIRE_MAX,
            payload_len, why, why_len);
    }
    return true;
}

/* A failed payload encode still sends its (possibly zero) payload length, so
 * the reply and any payload bytes go out before the verdict is returned. */
static bool ui_host_send_document_event(
    ui_host_transport_t client, uint32_t action, bool payload_ok,
    const uint8_t nonce[UI_HOST_NONCE_BYTES],
    const uint8_t *payload, size_t payload_len)
{
    uint8_t reply[UI_HOST_REPLY_BYTES];
    ui_host_transport_reply(reply, UI_HOST_PHASE_EVENT,
                            payload_ok ? UI_HOST_STATUS_OK
                                       : UI_HOST_STATUS_REJECTED,
                            action, (uint32_t)payload_len, 0, nonce);
    bool sent = ui_host_transport_send_all(client, reply, sizeof(reply));
    if (sent && payload_len > 0)
        sent = ui_host_transport_send_all(client, payload, payload_len);
    return payload_ok && sent;
}

static bool ui_host_show_document(
    ui_host_transport_t client,
    int replacement_gate,
    uint16_t flags,
    bool view_replaced,
    struct ui_present_document *document,
    const uint8_t nonce[UI_HOST_NONCE_BYTES])
{
    char why[192];
    struct ui_host_ready_context ready = {
        .fd = client,
        .replacement_gate = replacement_gate,
        .started_us = platform_time_monotonic_us(),
        .ready_value = view_replaced ? 1u : 0u,
    };
    memcpy(ready.nonce, nonce, UI_HOST_NONCE_BYTES);
    struct zcl_present_window_pages_v1 pages = {
        .struct_size = sizeof(pages),
        .abi_version = ZCL_PRESENT_ABI_V1,
        .pages = document->windows,
        .page_count = document->page_count,
    };
    struct zcl_present_window_event_v1 event;
    struct zcl_present_window_form_v1 form;
    struct zcl_present_window_canvas_v1 canvas;
    bool shown = ui_host_show_pages(document, &pages, &form, &canvas,
                                    &ready, &event, why, sizeof(why));
    if (!shown)
        LOG_WARN("presentation.host", "native window failed: %s", why);
    if (shown && (flags & UI_HOST_FLAG_WAIT_EVENT)) {
        uint32_t action = event.outcome == ZCL_PRESENT_WINDOW_ACTION
            ? event.action_index : UINT32_MAX;
        uint8_t payload[ZCL_PRESENT_MODEL_WIRE_MAX];
        size_t payload_len = 0;
        bool payload_ok = ui_host_document_submit_payload(
            document, &form, &canvas, action, payload, &payload_len,
            why, sizeof(why));
        shown = ui_host_send_document_event(client, action, payload_ok,
                                            nonce, payload, payload_len);
    }
    return shown;
}

static bool ui_host_worker_model(ui_host_transport_t client,
                                 int replacement_gate,
                                 uint16_t flags,
                                 bool view_replaced,
                                 const uint8_t *wire, uint32_t wire_len,
                                 const uint8_t nonce[UI_HOST_NONCE_BYTES])
{
    struct ui_present_document document;
    char why[192];
    if (!ui_present_document_from_wire(
            wire, wire_len, &document, why, sizeof(why))) {
        LOG_WARN("presentation.host", "visual model composition failed: %s",
                 why);
        return false;
    }
    bool shown = ui_host_show_document(
        client, replacement_gate, flags, view_replaced, &document, nonce);
    ui_present_document_free(&document);
    return shown;
}

static int ui_host_worker(ui_host_transport_t listener,
                          ui_host_transport_t client, int replacement_gate,
                          uint16_t flags,
                          bool view_replaced, const uint8_t *wire,
                          uint32_t wire_len,
                          const uint8_t nonce[UI_HOST_NONCE_BYTES])
{
    ui_host_transport_close(listener);
    bool shown = ui_host_worker_model(client, replacement_gate, flags,
                                      view_replaced,
                                      wire, wire_len, nonce);
    if (!shown && replacement_gate < 0)
        ui_host_send_rejected(client, UI_HOST_PHASE_READY,
                              UI_HOST_STATUS_REJECTED, nonce);
    if (replacement_gate >= 0) close(replacement_gate);
    ui_host_transport_close(client);
    return shown ? 0 : 1;
}

/* A window worker owns only pixels and input, but it must not outlive the
 * resident display host that owns its bounded session table. Bind the child
 * before any window is created and close the fork/prctl race by rechecking the
 * exact parent PID afterwards. */
static bool ui_host_worker_bind_parent(pid_t expected_parent)
{
    return prctl(PR_SET_PDEATHSIG, SIGTERM) == 0 &&
           getppid() == expected_parent;
}

struct ui_host_session {
    pid_t worker;
    bool replaceable;
    char request_id[ZCL_PRESENT_MODEL_ID_MAX + 1u];
};

enum ui_host_session_admission {
    UI_HOST_SESSION_ADMIT,
    UI_HOST_SESSION_REPLACE,
    UI_HOST_SESSION_CAPACITY,
    UI_HOST_SESSION_REQUEST_BUSY,
};

/* One admitted request as the resident host reads it off the wire. */
struct ui_host_request {
    uint16_t flags;
    uint32_t wire_len;
    uint8_t nonce[UI_HOST_NONCE_BYTES];
    char request_id[ZCL_PRESENT_MODEL_ID_MAX + 1u];
    bool replaceable;
    enum ui_host_session_admission admission;
};

static void ui_host_session_forget_worker(
    struct ui_host_session sessions[UI_HOST_SESSIONS_MAX], pid_t worker)
{
    for (size_t i = 0; i < UI_HOST_SESSIONS_MAX; i++) {
        if (sessions[i].worker == worker)
            sessions[i] = (struct ui_host_session){0};
    }
}

static void ui_host_sessions_reap(
    struct ui_host_session sessions[UI_HOST_SESSIONS_MAX])
{
    for (;;) {
        pid_t worker = waitpid(-1, NULL, WNOHANG);
        if (worker > 0) {
            ui_host_session_forget_worker(sessions, worker);
            continue;
        }
        if (worker < 0 && errno == EINTR) continue;
        break;
    }
}

/* Replace only a still-owned, unreaped display worker. Keeping children as
 * zombies until this parent reaps them prevents PID reuse from ever turning a
 * visual replacement into a signal sent to an unrelated process. */
static bool ui_host_session_replace(
    struct ui_host_session sessions[UI_HOST_SESSIONS_MAX],
    const char *request_id)
{
    ui_host_sessions_reap(sessions);
    for (size_t i = 0; i < UI_HOST_SESSIONS_MAX; i++) {
        if (sessions[i].worker <= 0 ||
            !sessions[i].replaceable ||
            strcmp(sessions[i].request_id, request_id) != 0)
            continue;
        pid_t worker = sessions[i].worker;
        if (kill(worker, SIGTERM) != 0 && errno != ESRCH)
            LOG_WARN("presentation.host",
                     "prior display worker termination failed: %s",
                     strerror(errno));
        while (waitpid(worker, NULL, 0) < 0 && errno == EINTR) {}
        sessions[i] = (struct ui_host_session){0};
        return true;
    }
    return false;
}

static bool ui_host_session_remember(
    struct ui_host_session sessions[UI_HOST_SESSIONS_MAX],
    const char *request_id, pid_t worker, bool replaceable)
{
    /* Do not reap here: this worker may have exited between fork and this
     * bookkeeping step. Leaving it waitable until a later reap prevents its
     * PID from being reused while the table records ownership. */
    for (size_t i = 0; i < UI_HOST_SESSIONS_MAX; i++) {
        if (sessions[i].worker != 0) continue;
        sessions[i].worker = worker;
        sessions[i].replaceable = replaceable;
        (void)snprintf(sessions[i].request_id,
                       sizeof(sessions[i].request_id), "%s", request_id);
        return true;
    }
    return false;
}

static enum ui_host_session_admission ui_host_session_admit(
    struct ui_host_session sessions[UI_HOST_SESSIONS_MAX],
    const char *request_id, bool replaceable)
{
    ui_host_sessions_reap(sessions);
    bool has_slot = false;
    for (size_t i = 0; i < UI_HOST_SESSIONS_MAX; i++) {
        if (sessions[i].worker == 0) {
            has_slot = true;
            continue;
        }
        if (strcmp(sessions[i].request_id, request_id) != 0) continue;
        if (replaceable && sessions[i].replaceable)
            return UI_HOST_SESSION_REPLACE;
        return UI_HOST_SESSION_REQUEST_BUSY;
    }
    return has_slot ? UI_HOST_SESSION_ADMIT : UI_HOST_SESSION_CAPACITY;
}

static void ui_host_terminate_worker(pid_t worker)
{
    (void)kill(worker, SIGTERM);
    while (waitpid(worker, NULL, 0) < 0 && errno == EINTR) {}
}

static void ui_host_discard_worker(
    struct ui_host_session sessions[UI_HOST_SESSIONS_MAX], pid_t worker)
{
    if (worker <= 0) return;
    ui_host_terminate_worker(worker);
    ui_host_session_forget_worker(sessions, worker);
}

/* The replaced display worker reports its window before the old one is
 * retired. */
static bool ui_host_await_replacement_ready(
    struct ui_host_session sessions[UI_HOST_SESSIONS_MAX],
    const char *request_id, int replacement_gate)
{
    uint8_t rendered = 0;
    bool ready = ui_host_transport_recv_all(
                     replacement_gate, &rendered, sizeof(rendered),
                     UI_HOST_READY_TIMEOUT_MS) && rendered == 1u;
    if (ready)
        (void)ui_host_session_replace(sessions, request_id);
    return ready;
}

static bool ui_host_adopt_worker(
    struct ui_host_session sessions[UI_HOST_SESSIONS_MAX],
    const struct ui_host_request *request, pid_t worker,
    int replacement_gate[2])
{
    if (replacement_gate[1] >= 0) close(replacement_gate[1]);
    bool replacing = request->admission == UI_HOST_SESSION_REPLACE;
    bool worker_ready = worker >= 0;
    if (worker_ready && replacing)
        worker_ready = ui_host_await_replacement_ready(
            sessions, request->request_id, replacement_gate[0]);
    bool remembered = worker_ready && ui_host_session_remember(
        sessions, request->request_id, worker, request->replaceable);
    if (remembered && replacing) {
        const uint8_t release = 1u;
        remembered = ui_host_transport_send_all(
            replacement_gate[0], &release, sizeof(release));
    }
    if (replacement_gate[0] >= 0) close(replacement_gate[0]);
    if (!remembered)
        ui_host_discard_worker(sessions, worker);
    return remembered;
}

static bool ui_host_spawn_worker(
    ui_host_transport_t listener, ui_host_transport_t client,
    struct ui_host_session sessions[UI_HOST_SESSIONS_MAX],
    const struct ui_host_request *request, const uint8_t *wire)
{
    int replacement_gate[2] = {-1, -1};
    bool replacing = request->admission == UI_HOST_SESSION_REPLACE;
    if (replacing &&
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0,
                   replacement_gate) != 0)
        return false;
    pid_t expected_parent = getpid();
    pid_t worker = fork();
    if (worker == 0) {
        if (replacement_gate[0] >= 0) close(replacement_gate[0]);
        if (!ui_host_worker_bind_parent(expected_parent)) _exit(1);
        _exit(ui_host_worker(listener, client, replacement_gate[1],
                             request->flags, replacing, wire,
                             request->wire_len, request->nonce));
    }
    return ui_host_adopt_worker(sessions, request, worker, replacement_gate);
}

static void ui_host_reject_client(ui_host_transport_t client, uint32_t status,
                                  const uint8_t nonce[UI_HOST_NONCE_BYTES])
{
    ui_host_send_rejected(client, UI_HOST_PHASE_READY, status, nonce);
    ui_host_transport_close(client);
}

static bool ui_host_receive_request(ui_host_transport_t client,
                                    struct ui_host_request *request,
                                    uint8_t *wire)
{
    uint8_t header[UI_HOST_REQUEST_BYTES];
    if (!ui_host_transport_recv_all(client, header, sizeof(header),
                                    UI_HOST_READY_TIMEOUT_MS) ||
        !ui_host_transport_parse_request_header(
            header, &request->flags, &request->wire_len, request->nonce))
        return false;
    return ui_host_transport_recv_all(client, wire, request->wire_len,
                                      UI_HOST_READY_TIMEOUT_MS);
}

static bool ui_host_decode_request(const uint8_t *wire,
                                   struct ui_host_request *request)
{
    struct zcl_present_model_v1 model;
    char why[192];
    if (!zcl_present_model_decode_v1(wire, request->wire_len, &model,
                                     why, sizeof(why)) ||
        (!!(request->flags & UI_HOST_FLAG_WAIT_EVENT) !=
         (model.action_count > 0))) {
        LOG_WARN("presentation.host",
                 "resident visual request rejected before fork");
        return false;
    }
    request->replaceable = model.action_count == 0;
    (void)snprintf(request->request_id, sizeof(request->request_id), "%s",
                   model.request_id);
    return true;
}

/* Returns false after rejecting the client when no window may be admitted. */
static bool ui_host_admit_request(
    struct ui_host_session sessions[UI_HOST_SESSIONS_MAX],
    ui_host_transport_t client, struct ui_host_request *request)
{
    request->admission = ui_host_session_admit(
        sessions, request->request_id, request->replaceable);
    if (request->admission != UI_HOST_SESSION_CAPACITY &&
        request->admission != UI_HOST_SESSION_REQUEST_BUSY)
        return true;
    ui_host_reject_client(client,
                          request->admission == UI_HOST_SESSION_CAPACITY
                              ? UI_HOST_STATUS_CAPACITY
                              : UI_HOST_STATUS_REQUEST_BUSY,
                          request->nonce);
    return false;
}

static void ui_host_handle_client(
    ui_host_transport_t listener, ui_host_transport_t client,
    struct ui_host_session sessions[UI_HOST_SESSIONS_MAX])
{
    struct ui_host_request request = {0};
    uint8_t wire[ZCL_PRESENT_MODEL_WIRE_MAX];
    if (!ui_host_receive_request(client, &request, wire) ||
        !ui_host_decode_request(wire, &request)) {
        ui_host_reject_client(client, UI_HOST_STATUS_REJECTED,
                              request.nonce);
        return;
    }
    if (!ui_host_admit_request(sessions, client, &request))
        return;
    if (!ui_host_spawn_worker(listener, client, sessions, &request, wire)) {
        ui_host_reject_client(client, UI_HOST_STATUS_REJECTED,
                              request.nonce);
        return;
    }
    ui_host_transport_close(client);
}

static struct zcl_result ui_host_send_request(
    ui_host_transport_t fd, uint16_t flags, const uint8_t *wire,
    size_t wire_len, uint8_t nonce[UI_HOST_NONCE_BYTES])
{
    uint8_t header[UI_HOST_REQUEST_BYTES];
    if (!ui_host_transport_nonce(nonce)) {
        ui_host_transport_close(fd);
        return ui_host_error("presentation host request nonce");
    }
    ui_host_transport_request_header(header, flags, (uint32_t)wire_len,
                                     nonce);
    if (!ui_host_transport_send_all(fd, header, sizeof(header)) ||
        !ui_host_transport_send_all(fd, wire, wire_len)) {
        int saved = errno;
        ui_host_transport_close(fd);
        errno = saved;
        return ui_host_error("presentation host request");
    }
    return ZCL_OK;
}

static bool ui_host_recv_reply(
    ui_host_transport_t fd, uint16_t phase, int timeout_ms,
    const uint8_t nonce[UI_HOST_NONCE_BYTES], uint32_t *status,
    uint32_t *value, uint32_t *payload_len, uint64_t *elapsed_us)
{
    uint8_t reply[UI_HOST_REPLY_BYTES];
    return ui_host_transport_recv_all(fd, reply, sizeof(reply),
                                      timeout_ms) &&
           ui_host_transport_parse_reply(reply, phase, status, value,
                                         payload_len, elapsed_us, nonce);
}

static struct zcl_result ui_host_ready_status_error(uint32_t status)
{
    if (status == UI_HOST_STATUS_CAPACITY)
        return ZCL_ERR(-1, "presentation host capacity exhausted");
    if (status == UI_HOST_STATUS_REQUEST_BUSY)
        return ZCL_ERR(-1,
                       "presentation request id already owns an active window");
    return ZCL_ERR(-1, "presentation host rejected the native window");
}

static struct zcl_result ui_host_read_ready(
    ui_host_transport_t fd, const uint8_t nonce[UI_HOST_NONCE_BYTES],
    bool reused, struct ui_present_host_result *result)
{
    uint32_t status = 0;
    uint32_t value = 0;
    uint32_t payload_len = 0;
    uint64_t elapsed_us = 0;
    if (!ui_host_recv_reply(fd, UI_HOST_PHASE_READY,
                            UI_HOST_READY_TIMEOUT_MS, nonce, &status,
                            &value, &payload_len, &elapsed_us) ||
        payload_len != 0) {
        ui_host_transport_close(fd);
        return ZCL_ERR(-1, "presentation host rejected the native window");
    }
    if (status != UI_HOST_STATUS_OK) {
        ui_host_transport_close(fd);
        return ui_host_ready_status_error(status);
    }
    result->resident_host = true;
    result->host_reused = reused;
    result->view_replaced = value == 1u;
    result->ready_us = elapsed_us > INT64_MAX ? INT64_MAX
                                               : (int64_t)elapsed_us;
    return ZCL_OK;
}

static struct zcl_result ui_host_read_event_header(
    ui_host_transport_t fd, const uint8_t nonce[UI_HOST_NONCE_BYTES],
    uint32_t *value, uint32_t *payload_len)
{
    uint32_t status = 0;
    uint64_t elapsed_us = 0;
    if (!ui_host_recv_reply(fd, UI_HOST_PHASE_EVENT,
                            UI_HOST_EVENT_TIMEOUT_MS, nonce, &status,
                            value, payload_len, &elapsed_us) ||
        status != UI_HOST_STATUS_OK) {
        ui_host_transport_close(fd);
        return ZCL_ERR(-1, "presentation host event channel closed");
    }
    return ZCL_OK;
}

static bool ui_host_recv_submission(
    ui_host_transport_t fd, const struct zcl_present_model_v1 *original,
    uint32_t value, uint32_t payload_len,
    uint8_t payload[ZCL_PRESENT_MODEL_WIRE_MAX],
    struct zcl_present_model_v1 *submitted, char *why, size_t why_len)
{
    bool is_form = original && original->kind == ZCL_PRESENT_MODEL_FORM;
    bool is_canvas = original &&
        original->kind == ZCL_PRESENT_MODEL_CANVAS;
    if (!ui_host_model_has_controls(original) ||
        !ui_host_submit_action(original, value) ||
        !ui_host_transport_recv_all(fd, payload, payload_len,
                                    UI_HOST_READY_TIMEOUT_MS) ||
        !zcl_present_model_decode_v1(payload, payload_len, submitted,
                                     why, why_len) ||
        (is_form && !zcl_present_model_form_submission_validate_v1(
            original, submitted, why, why_len)) ||
        (is_canvas && !zcl_present_model_canvas_submission_validate_v1(
            original, submitted, why, why_len)))
        return false;
    return true;
}

static void ui_host_store_submission(
    struct ui_present_host_result *result,
    const struct zcl_present_model_v1 *original,
    const struct zcl_present_model_v1 *submitted)
{
    if (original->kind == ZCL_PRESENT_MODEL_FORM) {
        result->form_submitted = true;
        result->form_value_count = submitted->item_count;
        for (uint32_t i = 0; i < submitted->item_count; i++) {
            (void)snprintf(result->form_values[i].id,
                           sizeof(result->form_values[i].id), "%s",
                           submitted->items[i].id);
            (void)snprintf(result->form_values[i].value,
                           sizeof(result->form_values[i].value), "%s",
                           submitted->items[i].value);
        }
        return;
    }
    for (uint32_t i = 0; i < submitted->item_count; i++) {
        if (submitted->items[i].flags & ZCL_PRESENT_ITEM_READ_ONLY)
            continue;
        result->canvas_submitted = true;
        (void)snprintf(result->canvas_point_id,
                       sizeof(result->canvas_point_id), "%s",
                       submitted->items[i].id);
        result->canvas_x = submitted->items[i].numerator;
        result->canvas_y = submitted->items[i].denominator;
    }
}

static struct zcl_result ui_host_read_submission(
    ui_host_transport_t fd, const struct zcl_present_model_v1 *original,
    uint32_t value, uint32_t payload_len,
    struct ui_present_host_result *result)
{
    uint8_t payload[ZCL_PRESENT_MODEL_WIRE_MAX];
    struct zcl_present_model_v1 submitted;
    char why[192];
    if (!ui_host_recv_submission(fd, original, value, payload_len, payload,
                                 &submitted, why, sizeof(why))) {
        ui_host_transport_close(fd);
        return ZCL_ERR(-1,
                       "presentation host control event failed exact validation");
    }
    ui_host_store_submission(result, original, &submitted);
    ui_host_transport_close(fd);
    return ZCL_OK;
}

static struct zcl_result ui_host_read_event(
    ui_host_transport_t fd, const struct zcl_present_model_v1 *original,
    const uint8_t nonce[UI_HOST_NONCE_BYTES],
    struct ui_present_host_result *result)
{
    uint32_t value = 0;
    uint32_t payload_len = 0;
    struct zcl_result header = ui_host_read_event_header(
        fd, nonce, &value, &payload_len);
    if (!header.ok) return header;
    result->event_received = true;
    result->action_index = value;
    if (payload_len > 0)
        return ui_host_read_submission(fd, original, value, payload_len,
                                       result);
    if (ui_host_model_has_controls(original) &&
        ui_host_submit_action(original, value)) {
        ui_host_transport_close(fd);
        return ZCL_ERR(-1,
                       "presentation host omitted the submitted control values");
    }
    ui_host_transport_close(fd);
    return ZCL_OK;
}

static struct zcl_result ui_host_submit_wire(
    const struct zcl_present_model_v1 *original,
    const uint8_t *wire,
    size_t wire_len,
    uint16_t flags,
    struct ui_present_host_result *result)
{
    bool reused = false;
    char display_why[96];
    if (!ui_present_host_display_ready(display_why, sizeof(display_why)))
        return ZCL_ERR(-1, "%s", display_why);
    ui_host_transport_t fd = ui_host_connect(&reused);
    if (fd == UI_HOST_TRANSPORT_INVALID)
        return ui_host_error("presentation host connect");
    uint8_t nonce[UI_HOST_NONCE_BYTES];
    struct zcl_result sent = ui_host_send_request(fd, flags, wire, wire_len,
                                                  nonce);
    if (!sent.ok) return sent;
    struct zcl_result ready = ui_host_read_ready(fd, nonce, reused, result);
    if (!ready.ok) return ready;
    if (!(flags & UI_HOST_FLAG_WAIT_EVENT)) {
        ui_host_transport_close(fd);
        return ZCL_OK;
    }
    return ui_host_read_event(fd, original, nonce, result);
}
#endif /* __linux__ */

struct zcl_result ui_present_host_submit(
    const struct zcl_present_model_v1 *model,
    bool wait_for_event,
    struct ui_present_host_result *result)
{
    if (!result) return ZCL_ERR(-1, "presentation host result is missing");
    *result = (struct ui_present_host_result){
        .action_index = UINT32_MAX,
    };
    char why[192];
    if (!zcl_present_model_validate_v1(model, why, sizeof(why)))
        return ZCL_ERR(-1, "presentation host model: %s", why);
#if !defined(__linux__)
    (void)wait_for_event;
    return ZCL_ERR(-1, "resident presentation host is not yet available on this platform");
#else
    uint8_t wire[ZCL_PRESENT_MODEL_WIRE_MAX];
    size_t wire_len = 0;
    if (!zcl_present_model_encode_v1(model, wire, sizeof(wire), &wire_len,
                                     why, sizeof(why)))
        return ZCL_ERR(-1, "presentation host model encode: %s", why);
    return ui_host_submit_wire(
        model, wire, wire_len,
        wait_for_event ? UI_HOST_FLAG_WAIT_EVENT : 0,
        result);
#endif
}

int ui_present_host_main(void)
{
#if !defined(__linux__)
    (void)fprintf(stderr, "Resident presentation host unsupported.\n"); // obs-ok:detached-child-terminal-diagnostic
    return 2;
#else
    ui_host_transport_t listener = ui_host_transport_listen();
    if (listener == UI_HOST_TRANSPORT_INVALID) return 2;
    struct ui_host_session sessions[UI_HOST_SESSIONS_MAX] = {{0}};
    int64_t last_request_us = platform_time_monotonic_us();
    for (;;) {
        ui_host_transport_t client = ui_host_transport_accept(&listener, 1000);
        if (client == UI_HOST_TRANSPORT_INVALID) {
            if (errno == EINTR) continue;
            ui_host_sessions_reap(sessions);
            if (platform_time_monotonic_us() - last_request_us >
                UI_HOST_IDLE_EXIT_US)
                break;
            continue;
        }
        last_request_us = platform_time_monotonic_us();
        if (!ui_host_transport_peer_allowed(client)) {
            ui_host_transport_close(client);
            continue;
        }
        ui_host_handle_client(listener, client, sessions);
    }
    for (size_t i = 0; i < UI_HOST_SESSIONS_MAX; i++) {
        if (sessions[i].worker <= 0) continue;
        ui_host_terminate_worker(sessions[i].worker);
    }
    ui_host_transport_close(listener);
    ui_host_transport_cleanup();
    return 0;
#endif
}
