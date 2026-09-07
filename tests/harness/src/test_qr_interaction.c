/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * qr scenario checks: form bridge/focus/submission, canvas
 * reducer/host/visual/confirmation models, status facts, corpus checks,
 * and code-change/development reflex checks.
 *
 * Split out of test_qr.c (which keeps the includes and the group entry
 * point) so no family member crosses the 1,500-line ceiling. Every
 * scenario grades itself through QR_CHECK, shared via qr_failures_ptr()
 * — see test_qr_priv.h. */

#include "encoding/qr.h"
#include "command/native_command.h"
#include "json/json.h"
#include "presentation/canvas.h"
#include "presentation/model.h"
#include "presentation/model_render.h"
#include "presentation/model_text.h"
#include "presentation/presentation.h"
#include "presentation/zclassic_brand.h"
#include "views/qr_popup.h"
#include "views/ui_present.h"
#include "views/ui_present_document.h"
#include "views/ui_present_host_transport.h"
#include "vcs/zcode_work_node.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test/test_qr_priv.h"


void qr_case_form_bridge_and_typing(void)
{
    char why[128];
    struct zcl_present_model_v1 form_model;
    zcl_present_model_init_v1(&form_model, ZCL_PRESENT_MODEL_FORM);
    (void)snprintf(form_model.request_id, sizeof(form_model.request_id),
                   "release-form");
    (void)snprintf(form_model.title, sizeof(form_model.title),
                   "Describe exact release");
    memset(form_model.exact_root, 'f', ZCL_PRESENT_MODEL_ROOT_MAX);
    form_model.exact_root[ZCL_PRESENT_MODEL_ROOT_MAX] = '\0';
    form_model.item_count = 2;
    form_model.items[0].kind = ZCL_PRESENT_ITEM_FORM_FIELD;
    form_model.items[0].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    form_model.items[0].flags = ZCL_PRESENT_ITEM_REQUIRED;
    (void)snprintf(form_model.items[0].id,
                   sizeof(form_model.items[0].id), "release-note");
    (void)snprintf(form_model.items[0].label,
                   sizeof(form_model.items[0].label), "Release note");
    form_model.items[1].kind = ZCL_PRESENT_ITEM_FORM_FIELD;
    form_model.items[1].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    form_model.items[1].flags = ZCL_PRESENT_ITEM_READ_ONLY;
    (void)snprintf(form_model.items[1].id,
                   sizeof(form_model.items[1].id), "candidate-root");
    (void)snprintf(form_model.items[1].label,
                   sizeof(form_model.items[1].label), "Candidate root");
    (void)snprintf(form_model.items[1].value,
                   sizeof(form_model.items[1].value), "immutable-root");
    form_model.action_count = 2;
    form_model.actions[0].kind = ZCL_PRESENT_ACTION_CANCEL;
    (void)snprintf(form_model.actions[0].id,
                   sizeof(form_model.actions[0].id), "cancel");
    (void)snprintf(form_model.actions[0].label,
                   sizeof(form_model.actions[0].label), "Cancel");
    form_model.actions[1].kind = ZCL_PRESENT_ACTION_SUBMIT;
    (void)snprintf(form_model.actions[1].id,
                   sizeof(form_model.actions[1].id), "submit-release-note");
    (void)snprintf(form_model.actions[1].label,
                   sizeof(form_model.actions[1].label), "Submit");
    struct zcl_present_window_form_v1 form_state;
    QR_CHECK("shared form bridge preserves exact values and field policy",
             zcl_present_window_form_from_model_v1(
                 &form_model, &form_state, why, sizeof(why)) &&
             form_state.field_count == 2 &&
             form_state.fields[0].flags ==
                 ZCL_PRESENT_WINDOW_FORM_REQUIRED &&
             form_state.fields[0].value[0] == '\0' &&
             form_state.fields[1].flags ==
                 ZCL_PRESENT_WINDOW_FORM_READ_ONLY &&
             strcmp(form_state.fields[1].value, "immutable-root") == 0);
    QR_CHECK("form typing and Backspace change one exact editable value",
             zcl_present_window_form_edit_v1(
                 &form_state, 0, (uint8_t)'A', false) &&
             strcmp(form_state.fields[0].value, "A") == 0 &&
             zcl_present_window_form_edit_v1(
                 &form_state, 0, 0, true) &&
             form_state.fields[0].value[0] == '\0' &&
             !zcl_present_window_form_edit_v1(
                 &form_state, 1, (uint8_t)'x', false));
}

void qr_case_form_focus(void)
{
    char why[128];
    struct zcl_present_model_v1 form_model;
    zcl_present_model_init_v1(&form_model, ZCL_PRESENT_MODEL_FORM);
    (void)snprintf(form_model.request_id, sizeof(form_model.request_id),
                   "release-form");
    (void)snprintf(form_model.title, sizeof(form_model.title),
                   "Describe exact release");
    memset(form_model.exact_root, 'f', ZCL_PRESENT_MODEL_ROOT_MAX);
    form_model.exact_root[ZCL_PRESENT_MODEL_ROOT_MAX] = '\0';
    form_model.item_count = 2;
    form_model.items[0].kind = ZCL_PRESENT_ITEM_FORM_FIELD;
    form_model.items[0].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    form_model.items[0].flags = ZCL_PRESENT_ITEM_REQUIRED;
    (void)snprintf(form_model.items[0].id,
                   sizeof(form_model.items[0].id), "release-note");
    (void)snprintf(form_model.items[0].label,
                   sizeof(form_model.items[0].label), "Release note");
    form_model.items[1].kind = ZCL_PRESENT_ITEM_FORM_FIELD;
    form_model.items[1].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    form_model.items[1].flags = ZCL_PRESENT_ITEM_READ_ONLY;
    (void)snprintf(form_model.items[1].id,
                   sizeof(form_model.items[1].id), "candidate-root");
    (void)snprintf(form_model.items[1].label,
                   sizeof(form_model.items[1].label), "Candidate root");
    (void)snprintf(form_model.items[1].value,
                   sizeof(form_model.items[1].value), "immutable-root");
    form_model.action_count = 2;
    form_model.actions[0].kind = ZCL_PRESENT_ACTION_CANCEL;
    (void)snprintf(form_model.actions[0].id,
                   sizeof(form_model.actions[0].id), "cancel");
    (void)snprintf(form_model.actions[0].label,
                   sizeof(form_model.actions[0].label), "Cancel");
    form_model.actions[1].kind = ZCL_PRESENT_ACTION_SUBMIT;
    (void)snprintf(form_model.actions[1].id,
                   sizeof(form_model.actions[1].id), "submit-release-note");
    (void)snprintf(form_model.actions[1].label,
                   sizeof(form_model.actions[1].label), "Submit");
    struct zcl_present_window_form_v1 form_state;
    uint32_t form_focus = UINT32_MAX;
    (void)zcl_present_window_form_from_model_v1(
        &form_model, &form_state, why, sizeof(why));
    QR_CHECK("form focus skips read-only bytes then reaches both actions",
             zcl_present_window_form_focus_step_v1(
                 &form_state, 2, 0, 1, &form_focus) &&
             form_focus == form_state.field_count &&
             zcl_present_window_form_focus_step_v1(
                 &form_state, 2, form_focus, 1, &form_focus) &&
             form_focus == form_state.field_count + 1u &&
             zcl_present_window_form_focus_step_v1(
                 &form_state, 2, form_focus, 1, &form_focus) &&
             form_focus == 0);
}

void qr_case_form_submission_mutants(void)
{
    char why[128];
    struct zcl_present_model_v1 form_model;
    zcl_present_model_init_v1(&form_model, ZCL_PRESENT_MODEL_FORM);
    (void)snprintf(form_model.request_id, sizeof(form_model.request_id),
                   "release-form");
    (void)snprintf(form_model.title, sizeof(form_model.title),
                   "Describe exact release");
    memset(form_model.exact_root, 'f', ZCL_PRESENT_MODEL_ROOT_MAX);
    form_model.exact_root[ZCL_PRESENT_MODEL_ROOT_MAX] = '\0';
    form_model.item_count = 2;
    form_model.items[0].kind = ZCL_PRESENT_ITEM_FORM_FIELD;
    form_model.items[0].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    form_model.items[0].flags = ZCL_PRESENT_ITEM_REQUIRED;
    (void)snprintf(form_model.items[0].id,
                   sizeof(form_model.items[0].id), "release-note");
    (void)snprintf(form_model.items[0].label,
                   sizeof(form_model.items[0].label), "Release note");
    form_model.items[1].kind = ZCL_PRESENT_ITEM_FORM_FIELD;
    form_model.items[1].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    form_model.items[1].flags = ZCL_PRESENT_ITEM_READ_ONLY;
    (void)snprintf(form_model.items[1].id,
                   sizeof(form_model.items[1].id), "candidate-root");
    (void)snprintf(form_model.items[1].label,
                   sizeof(form_model.items[1].label), "Candidate root");
    (void)snprintf(form_model.items[1].value,
                   sizeof(form_model.items[1].value), "immutable-root");
    form_model.action_count = 2;
    form_model.actions[0].kind = ZCL_PRESENT_ACTION_CANCEL;
    (void)snprintf(form_model.actions[0].id,
                   sizeof(form_model.actions[0].id), "cancel");
    (void)snprintf(form_model.actions[0].label,
                   sizeof(form_model.actions[0].label), "Cancel");
    form_model.actions[1].kind = ZCL_PRESENT_ACTION_SUBMIT;
    (void)snprintf(form_model.actions[1].id,
                   sizeof(form_model.actions[1].id), "submit-release-note");
    (void)snprintf(form_model.actions[1].label,
                   sizeof(form_model.actions[1].label), "Submit");
    struct zcl_present_model_v1 submitted_form = form_model;
    (void)snprintf(submitted_form.items[0].value,
                   sizeof(submitted_form.items[0].value), "exact note");
    QR_CHECK("form submission may change only editable value bytes",
             zcl_present_model_form_submission_validate_v1(
                 &form_model, &submitted_form, why, sizeof(why)));
    submitted_form.items[0].label[0] = 'X';
    QR_CHECK("form submission immutable-label mutant fails closed",
             !zcl_present_model_form_submission_validate_v1(
                 &form_model, &submitted_form, why, sizeof(why)));
    submitted_form = form_model;
    (void)snprintf(submitted_form.items[1].value,
                   sizeof(submitted_form.items[1].value), "forged-root");
    QR_CHECK("form submission read-only mutant fails closed",
             !zcl_present_model_form_submission_validate_v1(
                 &form_model, &submitted_form, why, sizeof(why)));
    submitted_form = form_model;
    submitted_form.actions[0].kind = ZCL_PRESENT_ACTION_SUBMIT;
    QR_CHECK("form action-order mutant fails closed",
             !zcl_present_model_validate_v1(
                 &submitted_form, why, sizeof(why)));
}

void qr_case_canvas_model_render(void)
{
    char why[128];
    struct zcl_present_model_v1 canvas_model;
    zcl_present_model_init_v1(&canvas_model, ZCL_PRESENT_MODEL_CANVAS);
    (void)snprintf(canvas_model.request_id,
                   sizeof(canvas_model.request_id), "placement-canvas");
    (void)snprintf(canvas_model.title, sizeof(canvas_model.title),
                   "Place the exact label");
    memset(canvas_model.exact_root, 'e', ZCL_PRESENT_MODEL_ROOT_MAX);
    canvas_model.exact_root[ZCL_PRESENT_MODEL_ROOT_MAX] = '\0';
    canvas_model.item_count = 2;
    canvas_model.items[0].kind = ZCL_PRESENT_ITEM_CANVAS_POINT;
    canvas_model.items[0].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    canvas_model.items[0].flags = ZCL_PRESENT_ITEM_SELECTED;
    canvas_model.items[0].numerator = 250;
    canvas_model.items[0].denominator = 300;
    (void)snprintf(canvas_model.items[0].id,
                   sizeof(canvas_model.items[0].id), "label-origin");
    (void)snprintf(canvas_model.items[0].label,
                   sizeof(canvas_model.items[0].label), "Label origin");
    canvas_model.items[1].kind = ZCL_PRESENT_ITEM_CANVAS_POINT;
    canvas_model.items[1].status = ZCL_PRESENT_STATUS_INFO;
    canvas_model.items[1].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    canvas_model.items[1].flags = ZCL_PRESENT_ITEM_READ_ONLY;
    canvas_model.items[1].numerator = 800;
    canvas_model.items[1].denominator = 700;
    (void)snprintf(canvas_model.items[1].id,
                   sizeof(canvas_model.items[1].id), "fixed-anchor");
    (void)snprintf(canvas_model.items[1].label,
                   sizeof(canvas_model.items[1].label), "Fixed anchor");
    canvas_model.action_count = 2;
    canvas_model.actions[0].kind = ZCL_PRESENT_ACTION_CANCEL;
    (void)snprintf(canvas_model.actions[0].id,
                   sizeof(canvas_model.actions[0].id), "cancel");
    (void)snprintf(canvas_model.actions[0].label,
                   sizeof(canvas_model.actions[0].label), "Cancel");
    canvas_model.actions[1].kind = ZCL_PRESENT_ACTION_SUBMIT;
    (void)snprintf(canvas_model.actions[1].id,
                   sizeof(canvas_model.actions[1].id), "submit-placement");
    (void)snprintf(canvas_model.actions[1].label,
                   sizeof(canvas_model.actions[1].label), "Submit");
    QR_CHECK("bounded canvas fixes one editable point and safe actions",
             zcl_present_model_validate_v1(
                 &canvas_model, why, sizeof(why)));
    struct zcl_present_model_bitmap_v1 canvas_model_pixels = {0};
    QR_CHECK("bounded canvas renders a real normalized 2D instrument",
             zcl_present_model_render_v1(
                 &canvas_model, &canvas_model_pixels, why, sizeof(why)) &&
             canvas_model_pixels.pixels != NULL);
    zcl_present_model_bitmap_free_v1(&canvas_model_pixels);
    char canvas_text[ZCL_PRESENT_MODEL_TEXT_MAX];
    size_t canvas_text_len = 0;
    QR_CHECK("canvas text companion preserves exact normalized coordinates",
             zcl_present_model_text_all_v1(
                 &canvas_model, canvas_text, sizeof(canvas_text),
                 &canvas_text_len, why, sizeof(why)) &&
             strstr(canvas_text, "canvas-point-x-y: 250/300") != NULL &&
             strstr(canvas_text, "flags: selected") != NULL &&
             strstr(canvas_text, "flags: read-only") != NULL);
}

void qr_case_canvas_reducer_and_submit(void)
{
    char why[128];
    struct zcl_present_model_v1 canvas_model;
    zcl_present_model_init_v1(&canvas_model, ZCL_PRESENT_MODEL_CANVAS);
    (void)snprintf(canvas_model.request_id,
                   sizeof(canvas_model.request_id), "placement-canvas");
    (void)snprintf(canvas_model.title, sizeof(canvas_model.title),
                   "Place the exact label");
    memset(canvas_model.exact_root, 'e', ZCL_PRESENT_MODEL_ROOT_MAX);
    canvas_model.exact_root[ZCL_PRESENT_MODEL_ROOT_MAX] = '\0';
    canvas_model.item_count = 2;
    canvas_model.items[0].kind = ZCL_PRESENT_ITEM_CANVAS_POINT;
    canvas_model.items[0].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    canvas_model.items[0].flags = ZCL_PRESENT_ITEM_SELECTED;
    canvas_model.items[0].numerator = 250;
    canvas_model.items[0].denominator = 300;
    (void)snprintf(canvas_model.items[0].id,
                   sizeof(canvas_model.items[0].id), "label-origin");
    (void)snprintf(canvas_model.items[0].label,
                   sizeof(canvas_model.items[0].label), "Label origin");
    canvas_model.items[1].kind = ZCL_PRESENT_ITEM_CANVAS_POINT;
    canvas_model.items[1].status = ZCL_PRESENT_STATUS_INFO;
    canvas_model.items[1].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    canvas_model.items[1].flags = ZCL_PRESENT_ITEM_READ_ONLY;
    canvas_model.items[1].numerator = 800;
    canvas_model.items[1].denominator = 700;
    (void)snprintf(canvas_model.items[1].id,
                   sizeof(canvas_model.items[1].id), "fixed-anchor");
    (void)snprintf(canvas_model.items[1].label,
                   sizeof(canvas_model.items[1].label), "Fixed anchor");
    canvas_model.action_count = 2;
    canvas_model.actions[0].kind = ZCL_PRESENT_ACTION_CANCEL;
    (void)snprintf(canvas_model.actions[0].id,
                   sizeof(canvas_model.actions[0].id), "cancel");
    (void)snprintf(canvas_model.actions[0].label,
                   sizeof(canvas_model.actions[0].label), "Cancel");
    canvas_model.actions[1].kind = ZCL_PRESENT_ACTION_SUBMIT;
    (void)snprintf(canvas_model.actions[1].id,
                   sizeof(canvas_model.actions[1].id), "submit-placement");
    (void)snprintf(canvas_model.actions[1].label,
                   sizeof(canvas_model.actions[1].label), "Submit");
    struct zcl_present_window_canvas_v1 canvas_state = {
        .struct_size = sizeof(canvas_state),
        .abi_version = ZCL_PRESENT_ABI_V1,
        .point_count = 2,
        .editable_index = 0,
        .points = {
            {.x = 250, .y = 300, .label = "Label origin"},
            {.flags = ZCL_PRESENT_WINDOW_CANVAS_POINT_READ_ONLY,
             .status = ZCL_PRESENT_STATUS_INFO,
             .x = 800, .y = 700, .label = "Fixed anchor"},
        },
    };
    QR_CHECK("canvas reducer accepts one editable and one reference point",
             zcl_present_window_canvas_validate_v1(
                 &canvas_state, why, sizeof(why)));
    QR_CHECK("canvas arrows move only the editable point and clamp exactly",
             zcl_present_window_canvas_step_v1(
                 &canvas_state, -300, 710) &&
             canvas_state.points[0].x == 0 &&
             canvas_state.points[0].y == 1000 &&
             canvas_state.points[1].x == 800 &&
             canvas_state.points[1].y == 700);
    uint32_t canvas_focus = UINT32_MAX;
    QR_CHECK("canvas focus traverses point, Cancel, Submit, then wraps",
             zcl_present_window_canvas_focus_step_v1(
                 2, 0, 1, &canvas_focus) && canvas_focus == 1 &&
             zcl_present_window_canvas_focus_step_v1(
                 2, canvas_focus, 1, &canvas_focus) && canvas_focus == 2 &&
             zcl_present_window_canvas_focus_step_v1(
                 2, canvas_focus, 1, &canvas_focus) && canvas_focus == 0);
    uint32_t canvas_x = UINT32_MAX, canvas_y = UINT32_MAX;
    QR_CHECK("canvas hit test maps native pixels to bounded coordinates",
             zcl_present_window_canvas_point_at_v1(
                 ZCL_PRESENT_MODEL_BITMAP_WIDTH,
                 ZCL_PRESENT_MODEL_BITMAP_HEIGHT,
                 (int32_t)ZCL_PRESENT_MODEL_BITMAP_WIDTH,
                 (int32_t)ZCL_PRESENT_MODEL_BITMAP_HEIGHT,
                 359, 383, &canvas_x, &canvas_y) &&
             canvas_x == 499 && canvas_y == 498);
    struct zcl_present_model_v1 submitted_canvas = canvas_model;
    submitted_canvas.items[0].numerator = 499;
    submitted_canvas.items[0].denominator = 498;
    QR_CHECK("canvas submission may change only editable coordinates",
             zcl_present_model_canvas_submission_validate_v1(
                 &canvas_model, &submitted_canvas, why, sizeof(why)));
    submitted_canvas.items[1].numerator++;
    QR_CHECK("canvas reference-point mutant fails closed",
             !zcl_present_model_canvas_submission_validate_v1(
                 &canvas_model, &submitted_canvas, why, sizeof(why)));
    submitted_canvas = canvas_model;
    submitted_canvas.items[0].label[0] = 'X';
    QR_CHECK("canvas immutable-label mutant fails closed",
             !zcl_present_model_canvas_submission_validate_v1(
                 &canvas_model, &submitted_canvas, why, sizeof(why)));
    submitted_canvas = canvas_model;
    submitted_canvas.items[1].flags |= ZCL_PRESENT_ITEM_SELECTED;
    QR_CHECK("canvas selected-reference mutant fails closed",
             !zcl_present_model_validate_v1(
                 &submitted_canvas, why, sizeof(why)));

}

void qr_case_host_reply(void)
{
    uint8_t host_nonce[UI_HOST_NONCE_BYTES];
    memset(host_nonce, 0x5a, sizeof(host_nonce));
    uint8_t host_reply[UI_HOST_REPLY_BYTES];
    uint32_t host_status = UINT32_MAX, host_value = UINT32_MAX;
    uint32_t host_payload_len = 0;
    uint64_t host_elapsed = 0;
    ui_host_transport_reply(
        host_reply, UI_HOST_PHASE_EVENT, UI_HOST_STATUS_OK, 1,
        777, 1234, host_nonce);
    QR_CHECK("form payload length is nonce-bound in the fixed host reply",
             ui_host_transport_parse_reply(
                 host_reply, UI_HOST_PHASE_EVENT, &host_status,
                 &host_value, &host_payload_len, &host_elapsed,
                 host_nonce) && host_status == UI_HOST_STATUS_OK &&
             host_value == 1 && host_payload_len == 777 &&
             host_elapsed == 1234);
    host_reply[20] = 1;
    QR_CHECK("host reply reserved-byte mutant fails closed",
             !ui_host_transport_parse_reply(
                 host_reply, UI_HOST_PHASE_EVENT, &host_status,
                 &host_value, &host_payload_len, &host_elapsed,
                 host_nonce));
}

void qr_case_visual_model_wire(void)
{
    char why[128];
    struct zcl_present_model_v1 visual;
    zcl_present_model_init_v1(&visual, ZCL_PRESENT_MODEL_PROGRESS);
    (void)snprintf(visual.request_id, sizeof(visual.request_id),
                   "reproduce-42");
    (void)snprintf(visual.title, sizeof(visual.title),
                   "Independent reproduction");
    (void)snprintf(visual.summary, sizeof(visual.summary),
                   "Builder two is reproducing the exact candidate bytes.");
    visual.item_count = 1;
    visual.items[0].kind = ZCL_PRESENT_ITEM_PROGRESS;
    visual.items[0].status = ZCL_PRESENT_STATUS_INFO;
    visual.items[0].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    visual.items[0].numerator = 7;
    visual.items[0].denominator = 10;
    (void)snprintf(visual.items[0].id, sizeof(visual.items[0].id),
                   "builder-two");
    (void)snprintf(visual.items[0].label, sizeof(visual.items[0].label),
                   "Builder two");
    (void)snprintf(visual.items[0].value, sizeof(visual.items[0].value),
                   "Compiling");
    visual.action_count = 1;
    visual.actions[0].kind = ZCL_PRESENT_ACTION_CLOSE;
    (void)snprintf(visual.actions[0].id, sizeof(visual.actions[0].id),
                   "close");
    (void)snprintf(visual.actions[0].label,
                   sizeof(visual.actions[0].label), "Close");
    uint8_t model_wire[ZCL_PRESENT_MODEL_WIRE_MAX];
    size_t model_wire_len = 0;
    struct zcl_present_model_v1 decoded;
    QR_CHECK("visual model encodes without structure padding",
             zcl_present_model_encode_v1(
                 &visual, model_wire, sizeof(model_wire), &model_wire_len,
                 why, sizeof(why)) && model_wire_len > 0);
    QR_CHECK("visual model round-trips exactly",
             zcl_present_model_decode_v1(
                 model_wire, model_wire_len, &decoded, why, sizeof(why)) &&
             decoded.kind == visual.kind &&
             decoded.item_count == 1 &&
             decoded.items[0].numerator == 7 &&
             decoded.items[0].denominator == 10 &&
             strcmp(decoded.items[0].value, "Compiling") == 0);
    QR_CHECK("visual model rejects trailing wire bytes",
             model_wire_len + 1u < sizeof(model_wire) &&
             !zcl_present_model_decode_v1(
                 model_wire, model_wire_len + 1u, &decoded,
                 why, sizeof(why)));
}

void qr_case_confirmation_model(void)
{
    char why[128];
    struct zcl_present_model_v1 confirmation;
    zcl_present_model_init_v1(&confirmation,
                              ZCL_PRESENT_MODEL_CONFIRMATION);
    (void)snprintf(confirmation.request_id,
                   sizeof(confirmation.request_id), "publish-7");
    (void)snprintf(confirmation.title, sizeof(confirmation.title),
                   "Publish exact candidate?");
    memset(confirmation.exact_root, 'a', ZCL_PRESENT_MODEL_ROOT_MAX);
    confirmation.exact_root[ZCL_PRESENT_MODEL_ROOT_MAX] = '\0';
    confirmation.action_count = 2;
    confirmation.actions[0].kind = ZCL_PRESENT_ACTION_CANCEL;
    (void)snprintf(confirmation.actions[0].id,
                   sizeof(confirmation.actions[0].id), "cancel");
    (void)snprintf(confirmation.actions[0].label,
                   sizeof(confirmation.actions[0].label), "Cancel");
    confirmation.actions[1].kind = ZCL_PRESENT_ACTION_CONFIRM;
    (void)snprintf(confirmation.actions[1].id,
                   sizeof(confirmation.actions[1].id), "confirm");
    (void)snprintf(confirmation.actions[1].label,
                   sizeof(confirmation.actions[1].label), "Publish");
    QR_CHECK("exact confirmation binds a root and two explicit actions",
             zcl_present_model_validate_v1(
                 &confirmation, why, sizeof(why)));
    struct zcl_present_model_bitmap_v1 exact_root_a = {0};
    struct zcl_present_model_bitmap_v1 exact_root_b = {0};
    bool exact_root_a_ok = zcl_present_model_render_v1(
        &confirmation, &exact_root_a, why, sizeof(why));
    confirmation.exact_root[ZCL_PRESENT_MODEL_ROOT_MAX - 1u] = 'b';
    bool exact_root_b_ok = zcl_present_model_render_v1(
        &confirmation, &exact_root_b, why, sizeof(why));
    QR_CHECK("root suffix changes remain visible in exact confirmation pixels",
             exact_root_a_ok && exact_root_b_ok &&
             memcmp(exact_root_a.pixels, exact_root_b.pixels,
                    ZCL_PRESENT_MODEL_BITMAP_BYTES) != 0);
    zcl_present_model_bitmap_free_v1(&exact_root_a);
    zcl_present_model_bitmap_free_v1(&exact_root_b);
    confirmation.exact_root[ZCL_PRESENT_MODEL_ROOT_MAX - 1u] = 'a';
    confirmation.exact_root[0] = '\0';
    QR_CHECK("rootless publication confirmation fails closed",
             !zcl_present_model_validate_v1(
                 &confirmation, why, sizeof(why)));
    memset(confirmation.exact_root, 'a', ZCL_PRESENT_MODEL_ROOT_MAX);
    confirmation.exact_root[ZCL_PRESENT_MODEL_ROOT_MAX] = '\0';
    struct ui_present_document action_document;
    QR_CHECK("one compositor preserves exact actions and copy root",
             ui_present_document_from_model(
                 &confirmation, &action_document, why, sizeof(why)) &&
             !action_document.is_qr &&
             action_document.page_count == 1u &&
             action_document.action_count == 2u &&
             strcmp(action_document.windows[0].copy_text,
                    confirmation.exact_root) == 0);
    ui_present_document_free(&action_document);
}

void qr_case_status_facts(void)
{
    char why[128];
    struct json_value status_facts, health_facts, health_checks;
    struct json_value backup_facts, work_facts;
    json_init(&status_facts); json_set_object(&status_facts);
    json_push_kv_int(&status_facts, "provable_tip", 3216084);
    json_push_kv_bool(&status_facts, "provable_tip_published", true);
    json_push_kv_bool(&status_facts, "sync_gap_known", true);
    json_push_kv_int(&status_facts, "sync_gap", 0);
    json_push_kv_int(&status_facts, "peers", 6);
    json_init(&health_facts); json_set_object(&health_facts);
    json_init(&health_checks); json_set_object(&health_checks);
    json_push_kv_bool(&health_checks, "tor_enabled", true);
    json_push_kv_bool(&health_checks, "onion_service_ready", true);
    json_push_kv_str(&health_checks, "onion_address", "fixture.onion");
    json_push_kv(&health_facts, "checks", &health_checks);
    json_free(&health_checks);
    json_init(&backup_facts); json_set_object(&backup_facts);
    json_push_kv_int(&backup_facts, "total_runs", 3);
    json_push_kv_int(&backup_facts, "total_failures", 0);
    json_push_kv_int(&backup_facts, "last_run_unix", 1234);
    json_push_kv_str(&backup_facts, "last_error", "");
    json_init(&work_facts); json_set_object(&work_facts);
    json_push_kv_bool(&work_facts, "enabled", true);
    json_push_kv_int(&work_facts, "worker_capacity", 4);
    json_push_kv_int(&work_facts, "worker_active", 1);
    json_push_kv_int(&work_facts, "worker_available", 3);
    struct zcl_present_model_v1 status_model;
    QR_CHECK("canonical status facts build one closed native model",
             zcl_native_presentation_status_model_from_facts(
                 &status_facts, &health_facts, &backup_facts, &work_facts,
                 &status_model, why, sizeof(why)) &&
             status_model.kind == ZCL_PRESENT_MODEL_STATUS_CARD &&
             status_model.item_count == 6);
    QR_CHECK("status model labels fact authority and preserves capacity",
             strncmp(status_model.items[0].label, "NODE FACT - ", 12) == 0 &&
             strcmp(status_model.items[0].value, "3216084") == 0 &&
             strcmp(status_model.items[5].value,
                    "3 available / 4 total (1 active)") == 0);
    QR_CHECK("dark canonical sources stay unavailable, never false-disabled",
             zcl_native_presentation_status_model_from_facts(
                 &status_facts, NULL, &backup_facts, NULL,
                 &status_model, why, sizeof(why)) &&
             strcmp(status_model.items[3].value, "unavailable") == 0 &&
             strcmp(status_model.items[5].value, "unavailable") == 0);
    json_free(&work_facts);
    json_free(&backup_facts);
    json_free(&health_facts);
    json_free(&status_facts);
}

void qr_case_corpus_instrument(void)
{
    char why[128];
    struct json_value corpus_facts;
    json_init(&corpus_facts); json_set_object(&corpus_facts);
    json_push_kv_bool(&corpus_facts, "projection_ready", true);
    json_push_kv_str(&corpus_facts, "checkpoint_root",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    json_push_kv_int(&corpus_facts, "admitted_production_loc", 201600);
    json_push_kv_int(&corpus_facts, "admitted_test_loc", 390954);
    json_push_kv_int(&corpus_facts, "durably_hosted_loc", 0);
    json_push_kv_int(&corpus_facts, "unique_semantic_units", 434817);
    json_push_kv_int(&corpus_facts, "packages_admitted", 50);
    json_push_kv_int(&corpus_facts, "packages_excluded", 18);
    json_push_kv_str(&corpus_facts, "progress_stage", "below_50m");
    json_push_kv_str(&corpus_facts, "blocker",
                     "verified lower bound is 592554 LOC");
    struct zcl_present_model_v1 corpus_model;
    QR_CHECK("canonical corpus status builds one exact native instrument",
             zcl_native_presentation_corpus_model_from_facts(
                 &corpus_facts, &corpus_model, why, sizeof(why)) &&
             corpus_model.kind == ZCL_PRESENT_MODEL_STATUS_CARD &&
             strcmp(corpus_model.title, "10 Million Exact C23") == 0 &&
             strcmp(corpus_model.exact_root,
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
                == 0 &&
             corpus_model.item_count == 10);
    bool corpus_package_exact = false;
    bool corpus_used_honest = false;
    bool corpus_velocity_honest = false;
    for (uint32_t i = 0; i < corpus_model.item_count; i++) {
        const struct zcl_present_model_item_v1 *item =
            &corpus_model.items[i];
        corpus_package_exact |= strcmp(item->id, "packages") == 0 &&
                                strcmp(item->value, "50 packages") == 0;
        corpus_used_honest |= strcmp(item->id, "used-loc") == 0 &&
            strcmp(item->value, "unavailable (not checkpoint-bound)") == 0 &&
            item->status == ZCL_PRESENT_STATUS_YELLOW;
        corpus_velocity_honest |= strcmp(item->id, "velocity") == 0 &&
            strcmp(item->value,
                   "unavailable (previous checkpoint not bound)") == 0 &&
            item->status == ZCL_PRESENT_STATUS_YELLOW;
    }
    QR_CHECK("corpus instrument preserves exact package and exclusion facts",
             corpus_package_exact &&
             strcmp(corpus_model.items[6].value,
                    "18 entries; reason LOC unavailable") == 0);
    QR_CHECK("corpus instrument never fabricates used LOC or velocity",
             corpus_used_honest && corpus_velocity_honest);
}

void qr_case_corpus_text_export(void)
{
    char why[128];
    struct json_value corpus_facts;
    json_init(&corpus_facts); json_set_object(&corpus_facts);
    json_push_kv_bool(&corpus_facts, "projection_ready", true);
    json_push_kv_str(&corpus_facts, "checkpoint_root",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    json_push_kv_int(&corpus_facts, "admitted_production_loc", 201600);
    json_push_kv_int(&corpus_facts, "admitted_test_loc", 390954);
    json_push_kv_int(&corpus_facts, "durably_hosted_loc", 0);
    json_push_kv_int(&corpus_facts, "unique_semantic_units", 434817);
    json_push_kv_int(&corpus_facts, "packages_admitted", 50);
    json_push_kv_int(&corpus_facts, "packages_excluded", 18);
    json_push_kv_str(&corpus_facts, "progress_stage", "below_50m");
    json_push_kv_str(&corpus_facts, "blocker",
                     "verified lower bound is 592554 LOC");
    struct zcl_present_model_v1 corpus_model;
    (void)zcl_native_presentation_corpus_model_from_facts(
        &corpus_facts, &corpus_model, why, sizeof(why));
    char corpus_all_text[ZCL_PRESENT_MODEL_TEXT_MAX];
    size_t corpus_all_text_len = 0;
    QR_CHECK("one bounded corpus text export contains every exact fact",
             zcl_present_model_text_all_v1(
                 &corpus_model, corpus_all_text, sizeof(corpus_all_text),
                 &corpus_all_text_len, why, sizeof(why)) &&
             corpus_all_text_len < sizeof(corpus_all_text) &&
             strstr(corpus_all_text, "page: 1/1") != NULL &&
             strstr(corpus_all_text, "CORPUS FACT - Admitted production") &&
             strstr(corpus_all_text, "CORPUS FACT - Packages admitted") &&
             strstr(corpus_all_text, "CORPUS FACT - Exclusions") &&
             strstr(corpus_all_text, "CORPUS FACT - Velocity"));
    json_free(&corpus_facts);
}

void qr_case_corpus_command(void)
{
    struct json_value corpus_request_input;
    json_init(&corpus_request_input); json_set_object(&corpus_request_input);
    json_push_kv_str(&corpus_request_input, "output", "text");
    struct zcl_command_request corpus_request = {
        .input = &corpus_request_input,
    };
    struct zcl_command_reply corpus_reply;
    zcl_command_reply_init(&corpus_reply,
                           "zcl.app_presentation_corpus.v1");
    zcl_native_handle_presentation_corpus(&corpus_request, &corpus_reply);
    const char *corpus_text =
        json_get_str(json_get(&corpus_reply.data, "plain_text"));
    QR_CHECK("typed corpus instrument is headless and display-only end to end",
             corpus_reply.status == ZCL_COMMAND_STATUS_PASSED &&
             !json_get_bool(json_get(&corpus_reply.data, "launched")) &&
             json_get_bool(json_get(&corpus_reply.data, "text_complete")) &&
             json_get_int(json_get(&corpus_reply.data,
                                   "text_page_count")) == 1 &&
             corpus_text && strstr(corpus_text, "10 Million Exact C23") &&
             strstr(corpus_text, "CORPUS FACT - Admitted production") &&
             strstr(corpus_text, "CORPUS FACT - Packages admitted") &&
             strstr(corpus_text, "CORPUS FACT - Exclusions") &&
             strstr(corpus_text, "CORPUS FACT - Velocity") &&
             strstr(corpus_text, "value: unavailable") &&
             strcmp(json_get_str(json_get(&corpus_reply.data, "authority")),
                    "display-only") == 0);
    zcl_command_reply_free(&corpus_reply);
    json_free(&corpus_request_input);
}

void qr_case_code_change_model(void)
{
    char why[128];
    static const uint8_t code_before[] =
        "#include \"presentation/model.h\"\n"
        "int exact_value(void) {\n"
        "    return 1;\n"
        "}\n";
    static const uint8_t code_after[] =
        "#include \"presentation/model.h\"\n"
        "int exact_value(void) {\n"
        "    return 2;\n"
        "}\n";
    char root_a[65], root_b[65], tree_root[65];
    memset(root_a, 'a', 64u); root_a[64] = '\0';
    memset(root_b, 'b', 64u); root_b[64] = '\0';
    memset(tree_root, 'c', 64u); tree_root[64] = '\0';
    struct zcl_present_model_v1 code_model;
    QR_CHECK("exact C facts build a provenance-labeled code-change model",
             zcl_native_presentation_code_change_model_from_facts(
                 code_before, sizeof(code_before) - 1u,
                 code_after, sizeof(code_after) - 1u,
                 "tools/command/native_qr_command.c", "return two",
                 "returned one", "returns two", root_a, root_b, tree_root,
                 &code_model, why, sizeof(why)) &&
             code_model.kind == ZCL_PRESENT_MODEL_CODE_DIFF &&
             strcmp(code_model.exact_root, tree_root) == 0 &&
             strncmp(code_model.items[0].label, "AGENT SUMMARY - ", 16) == 0 &&
             strncmp(code_model.items[3].label, "LOCAL OBSERVATION - ", 20) == 0);
    bool caught_remove = false, caught_add = false, caught_include = false;
    for (uint32_t i = 0; i < code_model.item_count; i++) {
        caught_remove |= code_model.items[i].kind ==
                         ZCL_PRESENT_ITEM_DIFF_REMOVE &&
                         strcmp(code_model.items[i].value, "    return 1;") == 0;
        caught_add |= code_model.items[i].kind == ZCL_PRESENT_ITEM_DIFF_ADD &&
                      strcmp(code_model.items[i].value, "    return 2;") == 0;
        caught_include |= strcmp(code_model.items[i].id, "dependencies") == 0 &&
                          strcmp(code_model.items[i].value,
                                 "presentation/model.h") == 0;
    }
    QR_CHECK("code-change diff catches the semantic mutant in exact bytes",
             caught_remove && caught_add);
    QR_CHECK("candidate dependency row comes from exact include bytes",
             caught_include);
}

void qr_case_development_reflex_red(void)
{
    char why[128];
    char root_a[65], root_b[65], tree_root[65];
    memset(root_a, 'a', 64u); root_a[64] = '\0';
    memset(root_b, 'b', 64u); root_b[64] = '\0';
    memset(tree_root, 'c', 64u); tree_root[64] = '\0';
    (void)tree_root;
    (void)root_b;
    struct json_value development_facts;
    json_init(&development_facts); json_set_object(&development_facts);
    json_push_kv_str(&development_facts, "schema", "zcl.dev_cycle.v1");
    json_push_kv_str(&development_facts, "status", "story_red");
    json_push_kv_str(&development_facts, "phase", "STORY_RED");
    json_push_kv_str(&development_facts, "edit_epoch", root_a);
    json_push_kv_str(&development_facts, "candidate_object_root", root_b);
    json_push_kv_str(&development_facts, "affected_component",
                     "presentation.code_change");
    json_push_kv_str(&development_facts, "feedback_class",
                     "HOT_SHADOW_CORE");
    json_push_kv_str(&development_facts, "failure_capsule",
                     "expected refusal was not observed");
    json_push_kv_str(&development_facts, "agent_next_action",
                     "inspect the candidate decision core");
    json_push_kv_int(&development_facts, "changed_path_count", 1);
    json_push_kv_int(&development_facts, "elapsed_us", 87000);
    json_push_kv_int(&development_facts, "compiler_processes", 1);
    json_push_kv_int(&development_facts, "linker_processes", 1);
    struct zcl_present_model_v1 development_model;
    bool development_built =
        zcl_native_presentation_development_model_from_facts(
            &development_facts, &development_model, why, sizeof(why));
    bool development_red = false, development_unknown = false;
    bool development_next = false;
    for (uint32_t i = 0; development_built &&
                         i < development_model.item_count; i++) {
        const struct zcl_present_model_item_v1 *item =
            &development_model.items[i];
        development_red |= strcmp(item->id, "diagnostic") == 0 &&
            item->status == ZCL_PRESENT_STATUS_RED &&
            strstr(item->value, "expected refusal") != NULL;
        development_unknown |= strcmp(item->id, "unknown") == 0 &&
            strstr(item->value, "Separate signed proof") != NULL;
        development_next |= strcmp(item->id, "next") == 0 &&
            strstr(item->value, "inspect the candidate") != NULL;
    }
    QR_CHECK("canonical reflex RED becomes one exact native consequence",
             development_built &&
             development_model.kind == ZCL_PRESENT_MODEL_PROGRESS &&
             strcmp(development_model.exact_root, root_a) == 0 &&
             development_model.items[3].status == ZCL_PRESENT_STATUS_RED &&
             development_red && development_unknown && development_next);

    json_free(&development_facts);
}

void qr_case_development_pending_and_compile(void)
{
    char why[128];
    char root_a[65], root_b[65], tree_root[65];
    memset(root_a, 'a', 64u); root_a[64] = '\0';
    memset(root_b, 'b', 64u); root_b[64] = '\0';
    memset(tree_root, 'c', 64u); tree_root[64] = '\0';
    (void)tree_root;
    struct json_value development_facts;
    struct zcl_present_model_v1 development_model;
    bool development_built;
    json_init(&development_facts); json_set_object(&development_facts);
    json_push_kv_str(&development_facts, "schema", "zcl.dev_cycle.v1");
    json_push_kv_str(&development_facts, "status", "proof_pending");
    json_push_kv_str(&development_facts, "phase", "PROOF_PENDING");
    json_push_kv_str(&development_facts, "edit_epoch", root_a);
    json_push_kv_int(&development_facts, "file_count", 1);
    json_push_kv_str(&development_facts, "agent_next_action",
                     "wait for clean proof");
    development_built =
        zcl_native_presentation_development_model_from_facts(
            &development_facts, &development_model, why, sizeof(why));
    bool pending_is_honest = development_built &&
        development_model.items[1].numerator == 0 &&
        development_model.items[2].numerator == 0 &&
        development_model.items[3].numerator == 0 &&
        development_model.items[4].numerator == 0 &&
        development_model.items[4].status == ZCL_PRESENT_STATUS_INFO &&
        strstr(development_model.items[7].value, "unknown us") != NULL &&
        strstr(development_model.items[7].value,
               "compiler unknown; linker unknown") != NULL;
    QR_CHECK("proof-pending event never invents prior or resource evidence",
             pending_is_honest);
    json_free(&development_facts);

    json_init(&development_facts); json_set_object(&development_facts);
    json_push_kv_str(&development_facts, "schema", "zcl.dev_cycle.v1");
    json_push_kv_str(&development_facts, "status", "passed");
    json_push_kv_str(&development_facts, "phase", "COMPILE_GREEN");
    json_push_kv_str(&development_facts, "edit_epoch", root_a);
    json_push_kv_str(&development_facts, "candidate_object_root", root_a);
    json_push_kv_str(&development_facts, "affected_component", "package");
    json_push_kv_str(&development_facts, "feedback_class",
                     "COMPILE_ONLY_PACKAGE_RECEIPT");
    json_push_kv_str(&development_facts, "receipt_id", root_b);
    json_push_kv_str(&development_facts, "toolchain", "cc 1; build-pass");
    json_push_kv_bool(&development_facts, "candidate_bytes_executed", false);
    json_push_kv_bool(&development_facts, "proof_complete", false);
    development_built =
        zcl_native_presentation_development_model_from_facts(
            &development_facts, &development_model, why, sizeof(why));
    bool compile_only_receipt = development_built &&
        development_model.items[2].status == ZCL_PRESENT_STATUS_GREEN &&
        development_model.items[3].numerator == 0 &&
        development_model.items[4].numerator == 0;
    QR_CHECK("compile-only package receipt never becomes behavioral proof",
             compile_only_receipt);
    json_free(&development_facts);
}

