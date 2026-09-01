/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded renderer-neutral visual documents for native agent UI. */

#ifndef ZCL_PRESENTATION_MODEL_H
#define ZCL_PRESENTATION_MODEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZCL_PRESENT_MODEL_ABI_V1 1u
#define ZCL_PRESENT_MODEL_WIRE_MAX (32u * 1024u)
#define ZCL_PRESENT_MODEL_ITEMS_MAX 64u
#define ZCL_PRESENT_MODEL_ACTIONS_MAX 4u
#define ZCL_PRESENT_MODEL_FORM_FIELDS_MAX 4u
#define ZCL_PRESENT_MODEL_CANVAS_POINTS_MAX 4u
#define ZCL_PRESENT_MODEL_CANVAS_COORD_MAX 1000u
#define ZCL_PRESENT_MODEL_TITLE_MAX 80u
#define ZCL_PRESENT_MODEL_SUMMARY_MAX 240u
#define ZCL_PRESENT_MODEL_ROOT_MAX 64u
#define ZCL_PRESENT_MODEL_ID_MAX 32u
#define ZCL_PRESENT_MODEL_LABEL_MAX 80u
#define ZCL_PRESENT_MODEL_VALUE_MAX 256u
#define ZCL_PRESENT_MODEL_QR_PAYLOAD_MAX 2048u
#define ZCL_PRESENT_MODEL_QR_CHUNKS_MAX \
    (ZCL_PRESENT_MODEL_QR_PAYLOAD_MAX / ZCL_PRESENT_MODEL_VALUE_MAX)
#define ZCL_PRESENT_MODEL_ACTION_LABEL_MAX 48u
#define ZCL_PRESENT_MODEL_PARENT_NONE UINT16_MAX

enum zcl_present_model_kind {
    ZCL_PRESENT_MODEL_QR_CARD = 1,
    ZCL_PRESENT_MODEL_STATUS_CARD,
    ZCL_PRESENT_MODEL_TABLE,
    ZCL_PRESENT_MODEL_PROGRESS,
    ZCL_PRESENT_MODEL_CHART,
    ZCL_PRESENT_MODEL_TIMELINE,
    ZCL_PRESENT_MODEL_CODE_DIFF,
    ZCL_PRESENT_MODEL_EVIDENCE_GRAPH,
    ZCL_PRESENT_MODEL_CHOICE,
    ZCL_PRESENT_MODEL_CONFIRMATION,
    ZCL_PRESENT_MODEL_FORM,
    ZCL_PRESENT_MODEL_CANVAS,
};

enum zcl_present_item_kind {
    ZCL_PRESENT_ITEM_TEXT = 1,
    ZCL_PRESENT_ITEM_KEY_VALUE,
    ZCL_PRESENT_ITEM_TABLE_HEADER,
    ZCL_PRESENT_ITEM_TABLE_ROW,
    ZCL_PRESENT_ITEM_PROGRESS,
    ZCL_PRESENT_ITEM_CHART_POINT,
    ZCL_PRESENT_ITEM_TIMELINE_EVENT,
    ZCL_PRESENT_ITEM_DIFF_CONTEXT,
    ZCL_PRESENT_ITEM_DIFF_ADD,
    ZCL_PRESENT_ITEM_DIFF_REMOVE,
    ZCL_PRESENT_ITEM_GRAPH_NODE,
    ZCL_PRESENT_ITEM_CHOICE,
    ZCL_PRESENT_ITEM_FORM_FIELD,
    ZCL_PRESENT_ITEM_CANVAS_POINT,
};

enum zcl_present_status {
    ZCL_PRESENT_STATUS_NEUTRAL = 0,
    ZCL_PRESENT_STATUS_INFO,
    ZCL_PRESENT_STATUS_GREEN,
    ZCL_PRESENT_STATUS_YELLOW,
    ZCL_PRESENT_STATUS_RED,
};

enum zcl_present_action_kind {
    ZCL_PRESENT_ACTION_CLOSE = 1,
    ZCL_PRESENT_ACTION_COPY,
    ZCL_PRESENT_ACTION_SELECT,
    ZCL_PRESENT_ACTION_CONFIRM,
    ZCL_PRESENT_ACTION_CANCEL,
    ZCL_PRESENT_ACTION_SUBMIT,
};

enum zcl_present_item_flags {
    ZCL_PRESENT_ITEM_SELECTED = 1u << 0,
    ZCL_PRESENT_ITEM_REQUIRED = 1u << 1,
    ZCL_PRESENT_ITEM_READ_ONLY = 1u << 2,
};

struct zcl_present_model_item_v1 {
    uint16_t kind;
    uint16_t status;
    uint16_t parent_index;
    uint16_t flags;
    uint32_t numerator;
    uint32_t denominator;
    char id[ZCL_PRESENT_MODEL_ID_MAX + 1u];
    char label[ZCL_PRESENT_MODEL_LABEL_MAX + 1u];
    char value[ZCL_PRESENT_MODEL_VALUE_MAX + 1u];
};

struct zcl_present_model_action_v1 {
    uint16_t kind;
    uint16_t flags;
    char id[ZCL_PRESENT_MODEL_ID_MAX + 1u];
    char label[ZCL_PRESENT_MODEL_ACTION_LABEL_MAX + 1u];
};

/* A visual document is inert data. It cannot name a callback, executable,
 * filesystem path, socket, wallet, datadir, package entry point, or native
 * handle. `exact_root` is display/event correlation only; the authoritative
 * full node independently rechecks it before acting on any returned event. */
struct zcl_present_model_v1 {
    uint32_t struct_size;
    uint16_t abi_version;
    uint16_t kind;
    uint32_t item_count;
    uint32_t action_count;
    char request_id[ZCL_PRESENT_MODEL_ID_MAX + 1u];
    char title[ZCL_PRESENT_MODEL_TITLE_MAX + 1u];
    char summary[ZCL_PRESENT_MODEL_SUMMARY_MAX + 1u];
    char exact_root[ZCL_PRESENT_MODEL_ROOT_MAX + 1u];
    struct zcl_present_model_item_v1 items[ZCL_PRESENT_MODEL_ITEMS_MAX];
    struct zcl_present_model_action_v1
        actions[ZCL_PRESENT_MODEL_ACTIONS_MAX];
};

void zcl_present_model_init_v1(struct zcl_present_model_v1 *model,
                               enum zcl_present_model_kind kind);

/* QR payloads use one closed model shape: one to eight ordered text chunks.
 * This keeps the full 2 KiB payload inside the existing bounded model ABI,
 * rather than maintaining a second presentation wire protocol. */
bool zcl_present_model_qr_from_payload_v1(
    const char *payload, const char *title,
    struct zcl_present_model_v1 *model,
    char *error, size_t error_cap);
bool zcl_present_model_qr_payload_v1(
    const struct zcl_present_model_v1 *model,
    char payload[ZCL_PRESENT_MODEL_QR_PAYLOAD_MAX + 1u],
    char *error, size_t error_cap);

bool zcl_present_model_validate_v1(const struct zcl_present_model_v1 *model,
                                   char *error, size_t error_cap);

/* Stable length-prefixed binary framing for the same-binary host boundary.
 * No structure padding or host byte order crosses the process boundary. */
bool zcl_present_model_encode_v1(const struct zcl_present_model_v1 *model,
                                 uint8_t *wire, size_t wire_cap,
                                 size_t *wire_len,
                                 char *error, size_t error_cap);
bool zcl_present_model_decode_v1(const uint8_t *wire, size_t wire_len,
                                 struct zcl_present_model_v1 *model,
                                 char *error, size_t error_cap);

/* Validate a form event against the exact inert model that opened the native
 * window. Only values of non-read-only form fields may differ; all IDs,
 * labels, flags, actions, roots, and other bytes must re-encode identically.
 * This is the full node's independent recheck of an authority-free visual
 * worker result. */
bool zcl_present_model_form_submission_validate_v1(
    const struct zcl_present_model_v1 *original,
    const struct zcl_present_model_v1 *submitted,
    char *error, size_t error_cap);

/* A bounded canvas contains one editable point and up to three inert reference
 * points. Coordinates are renderer-neutral thousandths (0..1000). Only the
 * editable point coordinates may differ in a submitted canvas event. */
bool zcl_present_model_canvas_submission_validate_v1(
    const struct zcl_present_model_v1 *original,
    const struct zcl_present_model_v1 *submitted,
    char *error, size_t error_cap);

const char *zcl_present_model_kind_name(uint16_t kind);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_PRESENTATION_MODEL_H */
