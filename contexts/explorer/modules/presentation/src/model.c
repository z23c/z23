/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: validation and deterministic wire framing for visual documents. */

#include "presentation/model.h"

#include "base/serialize_le.h"

#include <stdio.h>
#include <string.h>

static const uint8_t MODEL_MAGIC[4] = {'Z', 'P', 'V', 'M'};

struct model_writer {
    uint8_t *wire;
    size_t cap;
    size_t used;
};

struct model_reader {
    const uint8_t *wire;
    size_t len;
    size_t used;
};

static bool model_error(char *error, size_t cap, const char *message)
{
    if (error && cap > 0) (void)snprintf(error, cap, "%s", message);
    return false;
}

static bool bounded_length(const char *text, size_t max, size_t *length)
{
    if (!text) return false;
    size_t n = 0;
    while (n <= max && text[n]) n++;
    if (n > max) return false;
    if (length) *length = n;
    return true;
}

static bool valid_id(const char *id, bool required)
{
    size_t length = 0;
    if (!bounded_length(id, ZCL_PRESENT_MODEL_ID_MAX, &length) ||
        (required && length == 0))
        return false;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)id[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-'))
            return false;
    }
    return true;
}

static bool valid_root(const char *root)
{
    size_t length = 0;
    if (!bounded_length(root, ZCL_PRESENT_MODEL_ROOT_MAX, &length))
        return false;
    if (length == 0) return true;
    if (length != ZCL_PRESENT_MODEL_ROOT_MAX) return false;
    for (size_t i = 0; i < length; i++) {
        char c = root[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

static bool valid_model_kind(uint16_t kind)
{
    return kind >= ZCL_PRESENT_MODEL_QR_CARD &&
           kind <= ZCL_PRESENT_MODEL_CANVAS;
}

static bool valid_item_kind(uint16_t kind)
{
    return kind >= ZCL_PRESENT_ITEM_TEXT &&
           kind <= ZCL_PRESENT_ITEM_CANVAS_POINT;
}

static bool valid_status(uint16_t status)
{
    return status <= ZCL_PRESENT_STATUS_RED;
}

static bool valid_action_kind(uint16_t kind)
{
    return kind >= ZCL_PRESENT_ACTION_CLOSE &&
           kind <= ZCL_PRESENT_ACTION_SUBMIT;
}

void zcl_present_model_init_v1(struct zcl_present_model_v1 *model,
                               enum zcl_present_model_kind kind)
{
    if (!model) return;
    memset(model, 0, sizeof(*model));
    model->struct_size = sizeof(*model);
    model->abi_version = ZCL_PRESENT_MODEL_ABI_V1;
    model->kind = (uint16_t)kind;
}

static bool action_ids_unique(const struct zcl_present_model_v1 *model)
{
    for (uint32_t i = 0; i < model->action_count; i++) {
        for (uint32_t j = i + 1u; j < model->action_count; j++) {
            if (strcmp(model->actions[i].id, model->actions[j].id) == 0)
                return false;
        }
    }
    return true;
}

static bool confirmation_shape(const struct zcl_present_model_v1 *model)
{
    if (model->kind != ZCL_PRESENT_MODEL_CONFIRMATION) return true;
    if (!model->exact_root[0] || model->action_count != 2u) return false;
    bool confirm = false;
    bool cancel = false;
    for (uint32_t i = 0; i < model->action_count; i++) {
        confirm |= model->actions[i].kind == ZCL_PRESENT_ACTION_CONFIRM;
        cancel |= model->actions[i].kind == ZCL_PRESENT_ACTION_CANCEL;
    }
    return confirm && cancel;
}

static bool choice_shape(const struct zcl_present_model_v1 *model)
{
    if (model->kind != ZCL_PRESENT_MODEL_CHOICE) return true;
    if (model->item_count == 0 ||
        model->item_count > ZCL_PRESENT_MODEL_ACTIONS_MAX ||
        model->action_count != model->item_count)
        return false;
    uint32_t selected = 0;
    for (uint32_t i = 0; i < model->item_count; i++) {
        const struct zcl_present_model_item_v1 *item = &model->items[i];
        const struct zcl_present_model_action_v1 *action =
            &model->actions[i];
        if (item->kind != ZCL_PRESENT_ITEM_CHOICE ||
            item->parent_index != ZCL_PRESENT_MODEL_PARENT_NONE ||
            (item->flags & ~(uint16_t)ZCL_PRESENT_ITEM_SELECTED) != 0 ||
            action->kind != ZCL_PRESENT_ACTION_SELECT ||
            !item->id[0] || strcmp(item->id, action->id) != 0)
            return false;
        selected += !!(item->flags & ZCL_PRESENT_ITEM_SELECTED);
    }
    return selected <= 1u;
}

static bool printable_ascii(const char *text, size_t max)
{
    size_t length = 0;
    if (!bounded_length(text, max, &length)) return false;
    for (size_t i = 0; i < length; i++) {
        unsigned char byte = (unsigned char)text[i];
        if (byte < 0x20u || byte > 0x7eu) return false;
    }
    return true;
}

static bool form_shape(const struct zcl_present_model_v1 *model)
{
    if (model->kind != ZCL_PRESENT_MODEL_FORM) return true;
    if (!model->exact_root[0] || model->item_count == 0 ||
        model->item_count > ZCL_PRESENT_MODEL_FORM_FIELDS_MAX ||
        model->action_count != 2u ||
        model->actions[0].kind != ZCL_PRESENT_ACTION_CANCEL ||
        model->actions[1].kind != ZCL_PRESENT_ACTION_SUBMIT)
        return false;
    bool editable = false;
    for (uint32_t i = 0; i < model->item_count; i++) {
        const struct zcl_present_model_item_v1 *item = &model->items[i];
        if (item->kind != ZCL_PRESENT_ITEM_FORM_FIELD || !item->id[0] ||
            !item->label[0] ||
            item->parent_index != ZCL_PRESENT_MODEL_PARENT_NONE ||
            (item->flags & ~(uint16_t)(ZCL_PRESENT_ITEM_REQUIRED |
                                      ZCL_PRESENT_ITEM_READ_ONLY)) != 0 ||
            !printable_ascii(item->value, ZCL_PRESENT_MODEL_VALUE_MAX))
            return false;
        editable |= !(item->flags & ZCL_PRESENT_ITEM_READ_ONLY);
        for (uint32_t j = i + 1u; j < model->item_count; j++)
            if (strcmp(item->id, model->items[j].id) == 0)
                return false;
    }
    return editable;
}

static bool canvas_shape(const struct zcl_present_model_v1 *model)
{
    if (model->kind != ZCL_PRESENT_MODEL_CANVAS) return true;
    if (!model->exact_root[0] || model->item_count == 0 ||
        model->item_count > ZCL_PRESENT_MODEL_CANVAS_POINTS_MAX ||
        model->action_count != 2u ||
        model->actions[0].kind != ZCL_PRESENT_ACTION_CANCEL ||
        model->actions[1].kind != ZCL_PRESENT_ACTION_SUBMIT)
        return false;
    uint32_t editable = 0;
    uint32_t selected = 0;
    for (uint32_t i = 0; i < model->item_count; i++) {
        const struct zcl_present_model_item_v1 *item = &model->items[i];
        bool read_only = (item->flags & ZCL_PRESENT_ITEM_READ_ONLY) != 0;
        bool is_selected = (item->flags & ZCL_PRESENT_ITEM_SELECTED) != 0;
        if (item->kind != ZCL_PRESENT_ITEM_CANVAS_POINT || !item->id[0] ||
            !item->label[0] ||
            item->parent_index != ZCL_PRESENT_MODEL_PARENT_NONE ||
            (item->flags & ~(uint16_t)(ZCL_PRESENT_ITEM_SELECTED |
                                      ZCL_PRESENT_ITEM_READ_ONLY)) != 0 ||
            item->numerator > ZCL_PRESENT_MODEL_CANVAS_COORD_MAX ||
            item->denominator > ZCL_PRESENT_MODEL_CANVAS_COORD_MAX ||
            !printable_ascii(item->label, ZCL_PRESENT_MODEL_LABEL_MAX) ||
            !printable_ascii(item->value, ZCL_PRESENT_MODEL_VALUE_MAX) ||
            (read_only && is_selected))
            return false;
        editable += !read_only;
        selected += is_selected;
        for (uint32_t j = i + 1u; j < model->item_count; j++)
            if (strcmp(item->id, model->items[j].id) == 0)
                return false;
    }
    return editable == 1u && selected == 1u;
}

static bool qr_shape(const struct zcl_present_model_v1 *model)
{
    if (model->kind != ZCL_PRESENT_MODEL_QR_CARD) return true;
    if (model->item_count == 0 ||
        model->item_count > ZCL_PRESENT_MODEL_QR_CHUNKS_MAX ||
        model->action_count != 0 || model->exact_root[0])
        return false;
    size_t total = 0;
    for (uint32_t i = 0; i < model->item_count; i++) {
        const struct zcl_present_model_item_v1 *item = &model->items[i];
        char expected[ZCL_PRESENT_MODEL_ID_MAX + 1u];
        (void)snprintf(expected, sizeof(expected), "payload-%u", i);
        size_t length = 0;
        if (item->kind != ZCL_PRESENT_ITEM_TEXT ||
            item->status != ZCL_PRESENT_STATUS_NEUTRAL ||
            item->parent_index != ZCL_PRESENT_MODEL_PARENT_NONE ||
            item->flags != 0 || item->numerator != 0 ||
            item->denominator != 0 || item->label[0] ||
            strcmp(item->id, expected) != 0 ||
            !bounded_length(item->value, ZCL_PRESENT_MODEL_VALUE_MAX,
                            &length) || length == 0 ||
            (i + 1u < model->item_count &&
             length != ZCL_PRESENT_MODEL_VALUE_MAX) ||
            total + length > ZCL_PRESENT_MODEL_QR_PAYLOAD_MAX)
            return false;
        total += length;
    }
    return total > 0;
}

bool zcl_present_model_qr_from_payload_v1(
    const char *payload, const char *title,
    struct zcl_present_model_v1 *model,
    char *error, size_t error_cap)
{
    if (!model)
        return model_error(error, error_cap,
                           "QR visual model output is missing");
    size_t payload_len = 0;
    if (!bounded_length(payload, ZCL_PRESENT_MODEL_QR_PAYLOAD_MAX,
                        &payload_len) || payload_len == 0)
        return model_error(error, error_cap,
                           "QR payload is empty or exceeds 2048 bytes");
    size_t title_len = 0;
    if (!title || !title[0]) title = "QR Code";
    if (!bounded_length(title, ZCL_PRESENT_MODEL_TITLE_MAX, &title_len) ||
        title_len == 0)
        return model_error(error, error_cap,
                           "QR title is empty or oversized");

    zcl_present_model_init_v1(model, ZCL_PRESENT_MODEL_QR_CARD);
    (void)snprintf(model->request_id, sizeof(model->request_id), "qr-card");
    memcpy(model->title, title, title_len + 1u);
    (void)snprintf(model->summary, sizeof(model->summary),
                   "Scan or copy the exact payload");
    model->item_count = (uint32_t)(
        (payload_len + ZCL_PRESENT_MODEL_VALUE_MAX - 1u) /
        ZCL_PRESENT_MODEL_VALUE_MAX);
    size_t offset = 0;
    for (uint32_t i = 0; i < model->item_count; i++) {
        struct zcl_present_model_item_v1 *item = &model->items[i];
        size_t length = payload_len - offset;
        if (length > ZCL_PRESENT_MODEL_VALUE_MAX)
            length = ZCL_PRESENT_MODEL_VALUE_MAX;
        item->kind = ZCL_PRESENT_ITEM_TEXT;
        item->parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
        (void)snprintf(item->id, sizeof(item->id), "payload-%u", i);
        memcpy(item->value, payload + offset, length);
        item->value[length] = '\0';
        offset += length;
    }
    return zcl_present_model_validate_v1(model, error, error_cap);
}

bool zcl_present_model_qr_payload_v1(
    const struct zcl_present_model_v1 *model,
    char payload[ZCL_PRESENT_MODEL_QR_PAYLOAD_MAX + 1u],
    char *error, size_t error_cap)
{
    if (!payload)
        return model_error(error, error_cap,
                           "QR payload output is missing");
    payload[0] = '\0';
    if (!model || !qr_shape(model))
        return model_error(error, error_cap,
                           "QR visual model shape is invalid");
    size_t used = 0;
    for (uint32_t i = 0; i < model->item_count; i++) {
        size_t length = strlen(model->items[i].value);
        memcpy(payload + used, model->items[i].value, length);
        used += length;
    }
    payload[used] = '\0';
    if (error && error_cap > 0) error[0] = '\0';
    return true;
}

bool zcl_present_model_validate_v1(const struct zcl_present_model_v1 *model,
                                   char *error, size_t error_cap)
{
    if (!model || model->struct_size != sizeof(*model) ||
        model->abi_version != ZCL_PRESENT_MODEL_ABI_V1)
        return model_error(error, error_cap,
                           "visual model ABI/structure mismatch");
    if (!valid_model_kind(model->kind))
        return model_error(error, error_cap, "visual model kind is invalid");
    if (model->item_count > ZCL_PRESENT_MODEL_ITEMS_MAX ||
        model->action_count > ZCL_PRESENT_MODEL_ACTIONS_MAX)
        return model_error(error, error_cap,
                           "visual model count exceeds its bound");
    if (!valid_id(model->request_id, true))
        return model_error(error, error_cap,
                           "visual model request id is invalid");
    size_t length = 0;
    if (!bounded_length(model->title, ZCL_PRESENT_MODEL_TITLE_MAX, &length) ||
        length == 0)
        return model_error(error, error_cap,
                           "visual model title is empty or oversized");
    if (!bounded_length(model->summary, ZCL_PRESENT_MODEL_SUMMARY_MAX, NULL))
        return model_error(error, error_cap,
                           "visual model summary is oversized");
    if (!valid_root(model->exact_root))
        return model_error(error, error_cap,
                           "visual model exact root is not lowercase SHA3 hex");

    for (uint32_t i = 0; i < model->item_count; i++) {
        const struct zcl_present_model_item_v1 *item = &model->items[i];
        if (!valid_item_kind(item->kind) || !valid_status(item->status))
            return model_error(error, error_cap,
                               "visual model item enum is invalid");
        if (item->flags & ~(uint16_t)(ZCL_PRESENT_ITEM_SELECTED |
                                     ZCL_PRESENT_ITEM_REQUIRED |
                                     ZCL_PRESENT_ITEM_READ_ONLY))
            return model_error(error, error_cap,
                               "visual model item flags are invalid");
        if (!valid_id(item->id, false) ||
            !bounded_length(item->label, ZCL_PRESENT_MODEL_LABEL_MAX, NULL) ||
            !bounded_length(item->value, ZCL_PRESENT_MODEL_VALUE_MAX, NULL))
            return model_error(error, error_cap,
                               "visual model item text is invalid or oversized");
        if (item->parent_index != ZCL_PRESENT_MODEL_PARENT_NONE &&
            item->parent_index >= model->item_count)
            return model_error(error, error_cap,
                               "visual model graph parent is out of range");
        if (item->kind == ZCL_PRESENT_ITEM_GRAPH_NODE &&
            item->parent_index != ZCL_PRESENT_MODEL_PARENT_NONE &&
            (item->parent_index >= i ||
             model->items[item->parent_index].kind !=
                 ZCL_PRESENT_ITEM_GRAPH_NODE))
            return model_error(
                error, error_cap,
                "visual model graph parent must be an earlier graph node");
        if ((item->kind == ZCL_PRESENT_ITEM_PROGRESS ||
             item->kind == ZCL_PRESENT_ITEM_CHART_POINT) &&
            (item->denominator == 0 || item->numerator > item->denominator))
            return model_error(
                error, error_cap,
                item->kind == ZCL_PRESENT_ITEM_PROGRESS
                    ? "visual model progress fraction is invalid"
                    : "visual model chart-point fraction is invalid");
    }
    for (uint32_t i = 0; i < model->action_count; i++) {
        const struct zcl_present_model_action_v1 *action = &model->actions[i];
        if (!valid_action_kind(action->kind) || action->flags != 0 ||
            !valid_id(action->id, true) ||
            !bounded_length(action->label,
                            ZCL_PRESENT_MODEL_ACTION_LABEL_MAX, &length) ||
            length == 0)
            return model_error(error, error_cap,
                               "visual model action is invalid");
    }
    if (!action_ids_unique(model))
        return model_error(error, error_cap,
                           "visual model action ids are not unique");
    if (!confirmation_shape(model))
        return model_error(error, error_cap,
                           "confirmation must bind one root and confirm/cancel");
    if (!choice_shape(model))
        return model_error(
            error, error_cap,
            "choice must bind one to four rows to matching select actions");
    if (!form_shape(model))
        return model_error(
            error, error_cap,
            "form must bind one to four unique fields to cancel then submit");
    if (!canvas_shape(model))
        return model_error(
            error, error_cap,
            "canvas must bind one editable selected point to cancel then submit");
    if (!qr_shape(model))
        return model_error(error, error_cap,
                           "QR model must contain ordered payload chunks only");
    if (error && error_cap > 0) error[0] = '\0';
    return true;
}

static bool write_bytes(struct model_writer *writer, const void *bytes,
                        size_t length)
{
    if (length > writer->cap - writer->used) return false;
    memcpy(writer->wire + writer->used, bytes, length);
    writer->used += length;
    return true;
}

static bool write_u16(struct model_writer *writer, uint16_t value)
{
    uint8_t bytes[2];
    zcl_write_u16_le(bytes, value);
    return write_bytes(writer, bytes, sizeof(bytes));
}

static bool write_u32(struct model_writer *writer, uint32_t value)
{
    uint8_t bytes[4];
    zcl_write_u32_le(bytes, value);
    return write_bytes(writer, bytes, sizeof(bytes));
}

static bool write_text(struct model_writer *writer, const char *text,
                       size_t max)
{
    size_t length = 0;
    return bounded_length(text, max, &length) && length <= UINT16_MAX &&
           write_u16(writer, (uint16_t)length) &&
           write_bytes(writer, text, length);
}

bool zcl_present_model_encode_v1(const struct zcl_present_model_v1 *model,
                                 uint8_t *wire, size_t wire_cap,
                                 size_t *wire_len,
                                 char *error, size_t error_cap)
{
    if (wire_len) *wire_len = 0;
    if (!wire || !wire_len || wire_cap == 0 ||
        wire_cap > ZCL_PRESENT_MODEL_WIRE_MAX)
        return model_error(error, error_cap,
                           "visual model output buffer is invalid");
    if (!zcl_present_model_validate_v1(model, error, error_cap)) return false;
    struct model_writer writer = {wire, wire_cap, 0};
    bool ok = write_bytes(&writer, MODEL_MAGIC, sizeof(MODEL_MAGIC)) &&
              write_u16(&writer, ZCL_PRESENT_MODEL_ABI_V1) &&
              write_u16(&writer, model->kind) &&
              write_u32(&writer, model->item_count) &&
              write_u32(&writer, model->action_count) &&
              write_text(&writer, model->request_id,
                         ZCL_PRESENT_MODEL_ID_MAX) &&
              write_text(&writer, model->title,
                         ZCL_PRESENT_MODEL_TITLE_MAX) &&
              write_text(&writer, model->summary,
                         ZCL_PRESENT_MODEL_SUMMARY_MAX) &&
              write_text(&writer, model->exact_root,
                         ZCL_PRESENT_MODEL_ROOT_MAX);
    for (uint32_t i = 0; ok && i < model->item_count; i++) {
        const struct zcl_present_model_item_v1 *item = &model->items[i];
        ok = write_u16(&writer, item->kind) &&
             write_u16(&writer, item->status) &&
             write_u16(&writer, item->parent_index) &&
             write_u16(&writer, item->flags) &&
             write_u32(&writer, item->numerator) &&
             write_u32(&writer, item->denominator) &&
             write_text(&writer, item->id, ZCL_PRESENT_MODEL_ID_MAX) &&
             write_text(&writer, item->label, ZCL_PRESENT_MODEL_LABEL_MAX) &&
             write_text(&writer, item->value, ZCL_PRESENT_MODEL_VALUE_MAX);
    }
    for (uint32_t i = 0; ok && i < model->action_count; i++) {
        const struct zcl_present_model_action_v1 *action = &model->actions[i];
        ok = write_u16(&writer, action->kind) &&
             write_u16(&writer, action->flags) &&
             write_text(&writer, action->id, ZCL_PRESENT_MODEL_ID_MAX) &&
             write_text(&writer, action->label,
                        ZCL_PRESENT_MODEL_ACTION_LABEL_MAX);
    }
    if (!ok)
        return model_error(error, error_cap,
                           "visual model exceeds its wire buffer");
    *wire_len = writer.used;
    if (error && error_cap > 0) error[0] = '\0';
    return true;
}

static bool read_bytes(struct model_reader *reader, void *out, size_t length)
{
    if (length > reader->len - reader->used) return false;
    memcpy(out, reader->wire + reader->used, length);
    reader->used += length;
    return true;
}

static bool read_u16(struct model_reader *reader, uint16_t *value)
{
    uint8_t bytes[2];
    if (!read_bytes(reader, bytes, sizeof(bytes))) return false;
    *value = zcl_read_u16_le(bytes);
    return true;
}

static bool read_u32(struct model_reader *reader, uint32_t *value)
{
    uint8_t bytes[4];
    if (!read_bytes(reader, bytes, sizeof(bytes))) return false;
    *value = zcl_read_u32_le(bytes);
    return true;
}

static bool read_text(struct model_reader *reader, char *out, size_t max)
{
    uint16_t length = 0;
    if (!read_u16(reader, &length) || length > max ||
        !read_bytes(reader, out, length))
        return false;
    out[length] = '\0';
    return true;
}

bool zcl_present_model_decode_v1(const uint8_t *wire, size_t wire_len,
                                 struct zcl_present_model_v1 *model,
                                 char *error, size_t error_cap)
{
    if (!wire || !model || wire_len == 0 ||
        wire_len > ZCL_PRESENT_MODEL_WIRE_MAX)
        return model_error(error, error_cap,
                           "visual model input is empty or oversized");
    struct model_reader reader = {wire, wire_len, 0};
    uint8_t magic[sizeof(MODEL_MAGIC)];
    uint16_t version = 0;
    uint16_t kind = 0;
    uint32_t item_count = 0;
    uint32_t action_count = 0;
    if (!read_bytes(&reader, magic, sizeof(magic)) ||
        memcmp(magic, MODEL_MAGIC, sizeof(magic)) != 0 ||
        !read_u16(&reader, &version) ||
        version != ZCL_PRESENT_MODEL_ABI_V1 ||
        !read_u16(&reader, &kind) ||
        !read_u32(&reader, &item_count) ||
        !read_u32(&reader, &action_count) ||
        item_count > ZCL_PRESENT_MODEL_ITEMS_MAX ||
        action_count > ZCL_PRESENT_MODEL_ACTIONS_MAX)
        return model_error(error, error_cap,
                           "visual model wire header is invalid");

    zcl_present_model_init_v1(model, (enum zcl_present_model_kind)kind);
    model->item_count = item_count;
    model->action_count = action_count;
    bool ok = read_text(&reader, model->request_id,
                        ZCL_PRESENT_MODEL_ID_MAX) &&
              read_text(&reader, model->title,
                        ZCL_PRESENT_MODEL_TITLE_MAX) &&
              read_text(&reader, model->summary,
                        ZCL_PRESENT_MODEL_SUMMARY_MAX) &&
              read_text(&reader, model->exact_root,
                        ZCL_PRESENT_MODEL_ROOT_MAX);
    for (uint32_t i = 0; ok && i < item_count; i++) {
        struct zcl_present_model_item_v1 *item = &model->items[i];
        ok = read_u16(&reader, &item->kind) &&
             read_u16(&reader, &item->status) &&
             read_u16(&reader, &item->parent_index) &&
             read_u16(&reader, &item->flags) &&
             read_u32(&reader, &item->numerator) &&
             read_u32(&reader, &item->denominator) &&
             read_text(&reader, item->id, ZCL_PRESENT_MODEL_ID_MAX) &&
             read_text(&reader, item->label, ZCL_PRESENT_MODEL_LABEL_MAX) &&
             read_text(&reader, item->value, ZCL_PRESENT_MODEL_VALUE_MAX);
    }
    for (uint32_t i = 0; ok && i < action_count; i++) {
        struct zcl_present_model_action_v1 *action = &model->actions[i];
        ok = read_u16(&reader, &action->kind) &&
             read_u16(&reader, &action->flags) &&
             read_text(&reader, action->id, ZCL_PRESENT_MODEL_ID_MAX) &&
             read_text(&reader, action->label,
                       ZCL_PRESENT_MODEL_ACTION_LABEL_MAX);
    }
    if (!ok || reader.used != reader.len)
        return model_error(error, error_cap,
                           "visual model wire is truncated or has trailing bytes");
    return zcl_present_model_validate_v1(model, error, error_cap);
}

bool zcl_present_model_form_submission_validate_v1(
    const struct zcl_present_model_v1 *original,
    const struct zcl_present_model_v1 *submitted,
    char *error, size_t error_cap)
{
    if (!original || !submitted ||
        original->kind != ZCL_PRESENT_MODEL_FORM ||
        submitted->kind != ZCL_PRESENT_MODEL_FORM ||
        !zcl_present_model_validate_v1(original, error, error_cap) ||
        !zcl_present_model_validate_v1(submitted, error, error_cap))
        return model_error(error, error_cap,
                           "form submission model is invalid");
    if (original->item_count != submitted->item_count)
        return model_error(error, error_cap,
                           "form submission field count changed");

    struct zcl_present_model_v1 normalized = *submitted;
    for (uint32_t i = 0; i < original->item_count; i++) {
        const struct zcl_present_model_item_v1 *before = &original->items[i];
        const struct zcl_present_model_item_v1 *after = &submitted->items[i];
        if ((before->flags & ZCL_PRESENT_ITEM_READ_ONLY) &&
            strcmp(before->value, after->value) != 0)
            return model_error(error, error_cap,
                               "form submission changed a read-only value");
        if (!printable_ascii(after->value, ZCL_PRESENT_MODEL_VALUE_MAX))
            return model_error(error, error_cap,
                               "form submission value is not printable ASCII");
        (void)snprintf(normalized.items[i].value,
                       sizeof(normalized.items[i].value), "%s",
                       before->value);
    }

    uint8_t expected[ZCL_PRESENT_MODEL_WIRE_MAX];
    uint8_t received[ZCL_PRESENT_MODEL_WIRE_MAX];
    size_t expected_len = 0, received_len = 0;
    char why[192];
    if (!zcl_present_model_encode_v1(
            original, expected, sizeof(expected), &expected_len,
            why, sizeof(why)) ||
        !zcl_present_model_encode_v1(
            &normalized, received, sizeof(received), &received_len,
            why, sizeof(why)) ||
        expected_len != received_len ||
        memcmp(expected, received, expected_len) != 0)
        return model_error(error, error_cap,
                           "form submission changed immutable model bytes");
    if (error && error_cap > 0) error[0] = '\0';
    return true;
}

bool zcl_present_model_canvas_submission_validate_v1(
    const struct zcl_present_model_v1 *original,
    const struct zcl_present_model_v1 *submitted,
    char *error, size_t error_cap)
{
    if (!original || !submitted ||
        original->kind != ZCL_PRESENT_MODEL_CANVAS ||
        submitted->kind != ZCL_PRESENT_MODEL_CANVAS ||
        !zcl_present_model_validate_v1(original, error, error_cap) ||
        !zcl_present_model_validate_v1(submitted, error, error_cap))
        return model_error(error, error_cap,
                           "canvas submission model is invalid");
    if (original->item_count != submitted->item_count)
        return model_error(error, error_cap,
                           "canvas submission point count changed");

    struct zcl_present_model_v1 normalized = *submitted;
    for (uint32_t i = 0; i < original->item_count; i++) {
        const struct zcl_present_model_item_v1 *before = &original->items[i];
        const struct zcl_present_model_item_v1 *after = &submitted->items[i];
        if ((before->flags & ZCL_PRESENT_ITEM_READ_ONLY) &&
            (before->numerator != after->numerator ||
             before->denominator != after->denominator))
            return model_error(error, error_cap,
                               "canvas submission changed a reference point");
        normalized.items[i].numerator = before->numerator;
        normalized.items[i].denominator = before->denominator;
    }

    uint8_t expected[ZCL_PRESENT_MODEL_WIRE_MAX];
    uint8_t received[ZCL_PRESENT_MODEL_WIRE_MAX];
    size_t expected_len = 0, received_len = 0;
    char why[192];
    if (!zcl_present_model_encode_v1(
            original, expected, sizeof(expected), &expected_len,
            why, sizeof(why)) ||
        !zcl_present_model_encode_v1(
            &normalized, received, sizeof(received), &received_len,
            why, sizeof(why)) ||
        expected_len != received_len ||
        memcmp(expected, received, expected_len) != 0)
        return model_error(error, error_cap,
                           "canvas submission changed immutable model bytes");
    if (error && error_cap > 0) error[0] = '\0';
    return true;
}

const char *zcl_present_model_kind_name(uint16_t kind)
{
    static const char *const names[] = {
        "invalid", "qr", "status", "table", "progress", "chart",
        "timeline", "code-diff", "evidence-graph", "choice",
        "confirmation", "form", "canvas",
    };
    return kind < sizeof(names) / sizeof(names[0]) ? names[kind] : "invalid";
}
