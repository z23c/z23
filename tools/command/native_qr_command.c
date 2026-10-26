/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: typed local command for native QR presentation. */

#include "command/native_command.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "presentation/model_text.h"
#include "presentation/presentation.h"
#include "util/log_macros.h"
#include "views/ui_present.h"
#include "views/ui_present_host.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define NQR_TAG "native.qr"

static void nqr_fail(struct zcl_command_reply *reply, const char *code,
                     const char *message)
{
    LOG_ERROR(NQR_TAG, "%s: %s", code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_FAILED, code, "display", false, false, message,
        "app.qr.show");
}

void zcl_native_handle_qr_show(const struct zcl_command_request *request,
                               struct zcl_command_reply *reply)
{
    const char *payload = json_get_str(json_get(request->input, "payload"));
    const char *title = json_get_str(json_get(request->input, "title"));
    if (!payload || !payload[0]) {
        nqr_fail(reply, "MISSING_PAYLOAD", "payload must be a non-empty string");
        return;
    }
    size_t payload_len = strnlen(
        payload, ZCL_PRESENT_MODEL_QR_PAYLOAD_MAX + 1u);
    if (payload_len > ZCL_PRESENT_MODEL_QR_PAYLOAD_MAX) {
        nqr_fail(reply, "PAYLOAD_TOO_LARGE", "payload exceeds 2048 bytes");
        return;
    }
    if (title && strnlen(title, 81u) > 80u) {
        nqr_fail(reply, "TITLE_TOO_LARGE", "title exceeds 80 bytes");
        return;
    }
    struct zcl_present_model_v1 model;
    char model_why[192];
    if (!zcl_present_model_qr_from_payload_v1(
            payload, title, &model, model_why, sizeof(model_why))) {
        nqr_fail(reply, "INVALID_QR_MODEL", model_why);
        return;
    }
    zcl_native_present_model(&model, "app.qr.show", request->input, reply);
    if (reply->status == ZCL_COMMAND_STATUS_PASSED)
        (void)json_push_kv_int(&reply->data, "payload_bytes",
                               (int64_t)payload_len);
}

static void np_fail(struct zcl_command_reply *reply, const char *code,
                    const char *message, const char *leaf)
{
    LOG_ERROR("native.presentation", "%s: %s", code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_FAILED, code, "display", false, false, message,
        leaf);
}

static bool np_supported_kind(uint16_t kind)
{
    return kind == ZCL_PRESENT_MODEL_QR_CARD ||
           kind == ZCL_PRESENT_MODEL_STATUS_CARD ||
           kind == ZCL_PRESENT_MODEL_TABLE ||
           kind == ZCL_PRESENT_MODEL_PROGRESS ||
           kind == ZCL_PRESENT_MODEL_CHART ||
           kind == ZCL_PRESENT_MODEL_TIMELINE ||
           kind == ZCL_PRESENT_MODEL_CODE_DIFF ||
           kind == ZCL_PRESENT_MODEL_EVIDENCE_GRAPH ||
           kind == ZCL_PRESENT_MODEL_CHOICE ||
           kind == ZCL_PRESENT_MODEL_CONFIRMATION ||
           kind == ZCL_PRESENT_MODEL_FORM ||
           kind == ZCL_PRESENT_MODEL_CANVAS;
}

void zcl_native_handle_presentation_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    struct zcl_present_model_v1 model;
    char why[192];
    if (!ui_present_model_from_json(request->input, &model,
                                    why, sizeof(why))) {
        np_fail(reply, "INVALID_VISUAL_MODEL", why,
                "app.presentation.show");
        return;
    }
    if (model.kind == ZCL_PRESENT_MODEL_QR_CARD ||
        !np_supported_kind(model.kind)) {
        np_fail(reply, "UNSUPPORTED_PRESENTATION_KIND",
                "use app.qr.show for QR; the visual kind is not admitted",
                "app.presentation.show");
        return;
    }
    zcl_native_present_model(&model, "app.presentation.show",
                             request->input, reply);
}

static bool np_output_mode(const struct json_value *input, bool *text_only,
                           uint32_t *text_page, bool *page_explicit,
                           char *why, size_t why_cap)
{
    *text_only = false;
    *text_page = 0;
    *page_explicit = false;
    const struct json_value *output_value = json_get(input, "output");
    const char *output = json_get_str(output_value);
    if (output_value && (!output || (strcmp(output, "native") != 0 &&
                                    strcmp(output, "text") != 0))) {
        (void)snprintf(why, why_cap,
                       "output must be exactly native or text");
        return false;
    }
    *text_only = output && strcmp(output, "text") == 0;
    const struct json_value *page = json_get(input, "page");
    if (page && (page->type != JSON_INT || page->val.i < 0 ||
                 (uint64_t)page->val.i > UINT32_MAX)) {
        (void)snprintf(why, why_cap,
                       "page must be a non-negative integer");
        return false;
    }
    if (page && !*text_only) {
        (void)snprintf(why, why_cap,
                       "page is valid only when output is text");
        return false;
    }
    if (page) {
        *text_page = (uint32_t)page->val.i;
        *page_explicit = true;
    }
    return true;
}

static bool np_export_text(const struct zcl_present_model_v1 *model,
                           bool page_explicit, uint32_t *text_page,
                           char *plain_text, size_t plain_cap,
                           size_t *text_len, uint32_t *text_pages,
                           bool *text_complete, char *why, size_t why_cap)
{
    *text_complete = !page_explicit &&
        zcl_present_model_text_all_v1(
            model, plain_text, plain_cap, text_len, why, why_cap);
    if (*text_complete) {
        *text_page = 0;
        *text_pages = 1;
        return true;
    }
    return zcl_present_model_text_page_v1(
        model, *text_page, plain_text, plain_cap, text_len, text_pages,
        why, why_cap);
}

static void np_reply_text(const struct zcl_present_model_v1 *model,
                          struct zcl_command_reply *reply,
                          uint32_t text_page, uint32_t text_pages,
                          bool text_complete, size_t text_len,
                          const char *plain_text)
{
    (void)json_push_kv_bool(&reply->data, "launched", false);
    (void)json_push_kv_str(&reply->data, "delivery", "text");
    (void)json_push_kv_str(&reply->data, "presentation_kind",
                           zcl_present_model_kind_name(model->kind));
    (void)json_push_kv_str(&reply->data, "request_id", model->request_id);
    (void)json_push_kv_int(&reply->data, "item_count", model->item_count);
    (void)json_push_kv_bool(&reply->data, "text_export", true);
    (void)json_push_kv_int(&reply->data, "text_page", text_page);
    (void)json_push_kv_int(&reply->data, "text_page_count", text_pages);
    (void)json_push_kv_bool(&reply->data, "text_complete",
                            text_complete || text_pages == 1u);
    (void)json_push_kv_int(&reply->data, "text_bytes", text_len);
    (void)json_push_kv_str(&reply->data, "plain_text", plain_text);
    (void)json_push_kv_bool(&reply->data, "event_return", false);
    (void)json_push_kv_str(&reply->data, "authority", "display-only");
    (void)json_push_kv_bool(&reply->data,
                           "privileged_action_performed", false);
    (void)json_push_kv_str(&reply->data, "backend",
                           "c23-deterministic-text");
    (void)json_push_kv_str(&reply->data, "platform",
                           zcl_present_platform_name());
}

static struct zcl_result np_launch_native(
    const struct zcl_present_model_v1 *model,
    struct ui_present_host_result *host, bool *cold_fallback,
    int64_t *handoff_us)
{
    bool wait_for_event = model->action_count > 0;
    int64_t started_us = platform_time_monotonic_us();
    struct zcl_result launched = ui_present_host_submit(
        model, wait_for_event, host);
    *cold_fallback = false;
#if !defined(__linux__)
    if (!launched.ok && !wait_for_event) {
        launched = ui_present_model_launch(model);
        *cold_fallback = launched.ok;
    }
#endif
    *handoff_us = platform_time_monotonic_us() - started_us;
    return launched;
}

static void np_reply_native_event(const struct zcl_present_model_v1 *model,
                                  struct zcl_command_reply *reply,
                                  const struct ui_present_host_result *host)
{
    bool action = host->action_index < model->action_count;
    (void)json_push_kv_str(&reply->data, "event",
                           action ? "action" : "dismissed");
    if (action) {
        (void)json_push_kv_str(&reply->data, "action_id",
            model->actions[host->action_index].id);
        (void)json_push_kv_int(&reply->data, "action_index",
                               host->action_index);
        if (host->form_submitted) {
            struct json_value values;
            json_init(&values);
            json_set_object(&values);
            for (uint32_t i = 0; i < host->form_value_count; i++)
                (void)json_push_kv_str(
                    &values, host->form_values[i].id,
                    host->form_values[i].value);
            (void)json_push_kv_bool(&reply->data,
                                   "form_submitted", true);
            (void)json_push_kv(&reply->data, "form_values", &values);
            json_free(&values);
        }
        if (host->canvas_submitted) {
            (void)json_push_kv_bool(&reply->data,
                                   "canvas_submitted", true);
            (void)json_push_kv_str(&reply->data,
                                  "canvas_point_id",
                                  host->canvas_point_id);
            (void)json_push_kv_int(&reply->data,
                                  "canvas_x", host->canvas_x);
            (void)json_push_kv_int(&reply->data,
                                  "canvas_y", host->canvas_y);
        }
    }
    if (model->exact_root[0])
        (void)json_push_kv_str(&reply->data, "exact_root",
                               model->exact_root);
}

static void np_reply_native(const struct zcl_present_model_v1 *model,
                            struct zcl_command_reply *reply,
                            const struct ui_present_host_result *host,
                            bool cold_fallback, int64_t handoff_us)
{
    (void)json_push_kv_bool(&reply->data, "launched", true);
    (void)json_push_kv_str(&reply->data, "delivery", "native");
    (void)json_push_kv_str(&reply->data, "presentation_kind",
                           zcl_present_model_kind_name(model->kind));
    (void)json_push_kv_str(&reply->data, "request_id", model->request_id);
    (void)json_push_kv_int(&reply->data, "item_count", model->item_count);
    (void)json_push_kv_bool(&reply->data, "text_export_available", true);
    (void)json_push_kv_int(&reply->data, "launch_handoff_us", handoff_us);
    (void)json_push_kv_bool(&reply->data, "resident_host",
                            !cold_fallback && host->resident_host);
    (void)json_push_kv_bool(&reply->data, "host_reused",
                            !cold_fallback && host->host_reused);
    (void)json_push_kv_bool(&reply->data, "view_replaced",
                            !cold_fallback && host->view_replaced);
    (void)json_push_kv_int(&reply->data, "window_ready_us",
                           cold_fallback ? -1 : host->ready_us);
    (void)json_push_kv_bool(&reply->data, "event_return",
                            !cold_fallback && host->event_received);
    if (!cold_fallback && host->event_received) {
        np_reply_native_event(model, reply, host);
    }
    (void)json_push_kv_str(&reply->data, "authority", "display-only");
    (void)json_push_kv_bool(&reply->data,
                           "privileged_action_performed", false);
    (void)json_push_kv_str(&reply->data, "backend",
                           zcl_present_backend_name());
    (void)json_push_kv_str(&reply->data, "platform",
                           zcl_present_platform_name());
}

void zcl_native_present_model(
    const struct zcl_present_model_v1 *model, const char *leaf,
    const struct json_value *input, struct zcl_command_reply *reply)
{
    if (!model || !leaf || !reply) return;
    if (!np_supported_kind(model->kind)) {
        np_fail(reply, "UNSUPPORTED_PRESENTATION_KIND",
                "use app.qr.show for QR; raw canvas documents are not admitted",
                leaf);
        return;
    }
    bool text_only = false;
    uint32_t text_page = 0;
    bool page_explicit = false;
    char why[192];
    if (!np_output_mode(input, &text_only, &text_page, &page_explicit,
                        why, sizeof(why))) {
        np_fail(reply, "INVALID_PRESENTATION_OUTPUT", why, leaf);
        return;
    }
    if (text_only) {
        char plain_text[ZCL_PRESENT_MODEL_TEXT_MAX];
        size_t text_len = 0;
        uint32_t text_pages = 0;
        bool text_complete = false;
        if (!np_export_text(model, page_explicit, &text_page, plain_text,
                            sizeof(plain_text), &text_len, &text_pages,
                            &text_complete, why, sizeof(why))) {
            np_fail(reply, "PRESENTATION_TEXT_EXPORT_FAILED", why, leaf);
            return;
        }
        np_reply_text(model, reply, text_page, text_pages, text_complete,
                      text_len, plain_text);
        return;
    }
    char display_why[96];
    if (!ui_present_host_display_ready(display_why, sizeof(display_why))) {
        np_fail(reply, "HEADLESS_DISPLAY_UNAVAILABLE", display_why, leaf);
        return;
    }
    struct ui_present_host_result host;
    bool cold_fallback = false;
    int64_t handoff_us = 0;
    struct zcl_result launched = np_launch_native(model, &host,
                                                  &cold_fallback,
                                                  &handoff_us);
    if (!launched.ok) {
        np_fail(reply, "PRESENTATION_LAUNCH_FAILED", launched.message, leaf);
        return;
    }
    np_reply_native(model, reply, &host, cold_fallback, handoff_us);
}
