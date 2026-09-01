/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: deterministic bounded plain-text companion for presentation models. */

#include "presentation/model_text.h"

#include <stdio.h>
#include <string.h>

struct text_writer {
    char *out;
    size_t cap;
    size_t used;
};

static bool text_error(char *error, size_t cap, const char *message)
{
    if (error && cap > 0) (void)snprintf(error, cap, "%s", message);
    return false;
}

static bool text_bytes(struct text_writer *writer, const char *bytes,
                       size_t length)
{
    if (length >= writer->cap - writer->used) return false;
    memcpy(writer->out + writer->used, bytes, length);
    writer->used += length;
    writer->out[writer->used] = '\0';
    return true;
}

static bool text_literal(struct text_writer *writer, const char *text)
{
    return text_bytes(writer, text, strlen(text));
}

static bool text_u32(struct text_writer *writer, uint32_t value)
{
    char digits[16];
    int length = snprintf(digits, sizeof(digits), "%u", value);
    return length > 0 && (size_t)length < sizeof(digits) &&
           text_bytes(writer, digits, (size_t)length);
}

/* Keep every model string on one physical line. This preserves exact byte
 * distinctions for control characters without allowing model text to forge
 * another field or item in the export. */
static bool text_escaped(struct text_writer *writer, const char *text)
{
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        const char *escape = NULL;
        if (*p == '\n') escape = "\\n";
        else if (*p == '\r') escape = "\\r";
        else if (*p == '\t') escape = "\\t";
        else if (*p == '\\') escape = "\\\\";
        if (escape) {
            if (!text_literal(writer, escape)) return false;
        } else if (*p < 0x20u || *p == 0x7fu) {
            char escaped[6];
            int length = snprintf(escaped, sizeof(escaped), "\\d%03u", *p);
            if (length != 5 ||
                !text_bytes(writer, escaped, (size_t)length)) return false;
        } else {
            char byte = (char)*p;
            if (!text_bytes(writer, &byte, 1u)) return false;
        }
    }
    return true;
}

static const char *item_kind_name(uint16_t kind)
{
    static const char *const names[] = {
        "invalid", "text", "key-value", "table-header", "table-row",
        "progress", "chart-point", "timeline-event", "diff-context",
        "diff-add", "diff-remove", "graph-node", "choice", "form-field",
        "canvas-point",
    };
    return kind < sizeof(names) / sizeof(names[0]) ? names[kind] : "invalid";
}

static const char *status_name(uint16_t status)
{
    static const char *const names[] = {
        "neutral", "info", "green", "yellow", "red",
    };
    return status < sizeof(names) / sizeof(names[0])
        ? names[status] : "invalid";
}

static const char *action_kind_name(uint16_t kind)
{
    static const char *const names[] = {
        "invalid", "close", "copy", "select", "confirm", "cancel",
        "submit",
    };
    return kind < sizeof(names) / sizeof(names[0]) ? names[kind] : "invalid";
}

static bool field(struct text_writer *writer, const char *name,
                  const char *value)
{
    return text_literal(writer, name) && text_literal(writer, ": ") &&
           text_escaped(writer, value) && text_literal(writer, "\n");
}

static bool item_flags(struct text_writer *writer, uint16_t flags)
{
    if (!text_literal(writer, "  flags: ")) return false;
    if (flags == 0) return text_literal(writer, "none\n");
    bool separator = false;
    static const struct { uint16_t flag; const char *name; } names[] = {
        {ZCL_PRESENT_ITEM_SELECTED, "selected"},
        {ZCL_PRESENT_ITEM_REQUIRED, "required"},
        {ZCL_PRESENT_ITEM_READ_ONLY, "read-only"},
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (!(flags & names[i].flag)) continue;
        if (separator && !text_literal(writer, ",")) return false;
        if (!text_literal(writer, names[i].name)) return false;
        separator = true;
    }
    return text_literal(writer, "\n");
}

static bool text_item(struct text_writer *writer,
                      const struct zcl_present_model_item_v1 *item,
                      uint32_t index)
{
    if (!text_literal(writer, "item ") || !text_u32(writer, index + 1u) ||
        !text_literal(writer, ": ") ||
        !text_literal(writer, item_kind_name(item->kind)) ||
        !text_literal(writer, " [") ||
        !text_literal(writer, status_name(item->status)) ||
        !text_literal(writer, "]\n") ||
        !field(writer, "  id", item->id) ||
        !field(writer, "  label", item->label) ||
        !field(writer, "  value", item->value))
        return false;
    if ((item->kind == ZCL_PRESENT_ITEM_PROGRESS ||
         item->kind == ZCL_PRESENT_ITEM_CHART_POINT ||
         item->kind == ZCL_PRESENT_ITEM_CANVAS_POINT) &&
        (!text_literal(writer,
                       item->kind == ZCL_PRESENT_ITEM_PROGRESS
                           ? "  progress: "
                           : (item->kind == ZCL_PRESENT_ITEM_CHART_POINT
                                  ? "  chart-point: "
                                  : "  canvas-point-x-y: ")) ||
         !text_u32(writer, item->numerator) ||
         !text_literal(writer, "/") ||
         !text_u32(writer, item->denominator) ||
         !text_literal(writer, "\n")))
        return false;
    if (item->parent_index != ZCL_PRESENT_MODEL_PARENT_NONE &&
        (!text_literal(writer, "  parent-item: ") ||
         !text_u32(writer, (uint32_t)item->parent_index + 1u) ||
         !text_literal(writer, "\n")))
        return false;
    return item_flags(writer, item->flags);
}

static bool text_actions(struct text_writer *writer,
                         const struct zcl_present_model_v1 *model)
{
    if (!text_literal(writer, "actions: ") ||
        !text_u32(writer, model->action_count) ||
        !text_literal(writer, "\n"))
        return false;
    for (uint32_t i = 0; i < model->action_count; i++) {
        const struct zcl_present_model_action_v1 *action = &model->actions[i];
        if (!text_literal(writer, "action ") ||
            !text_u32(writer, i + 1u) || !text_literal(writer, ": ") ||
            !text_literal(writer, action_kind_name(action->kind)) ||
            !text_literal(writer, "\n") ||
            !field(writer, "  id", action->id) ||
            !field(writer, "  label", action->label))
            return false;
    }
    return true;
}

static bool text_document(
    const struct zcl_present_model_v1 *model,
    uint32_t begin, uint32_t end, uint32_t page_index, uint32_t pages,
    char *out, size_t out_cap, size_t *out_len,
    char *error, size_t error_cap)
{
    if (!out || out_cap == 0 || !out_len)
        return text_error(error, error_cap,
                          "presentation text output is incomplete");
    out[0] = '\0';
    *out_len = 0;
    char model_why[192];
    if (!zcl_present_model_validate_v1(model, model_why, sizeof(model_why)))
        return text_error(error, error_cap, model_why);
    if (page_index >= pages || begin > end || end > model->item_count)
        return text_error(error, error_cap,
                          "presentation text page is out of range");

    struct text_writer writer = {.out = out, .cap = out_cap};
    if (!text_literal(&writer, "ZClassic23 native instrument\n") ||
        !field(&writer, "kind", zcl_present_model_kind_name(model->kind)) ||
        !field(&writer, "request-id", model->request_id) ||
        !field(&writer, "title", model->title) ||
        !field(&writer, "summary", model->summary) ||
        !field(&writer, "exact-root", model->exact_root) ||
        !text_literal(&writer, "page: ") ||
        !text_u32(&writer, page_index + 1u) ||
        !text_literal(&writer, "/") || !text_u32(&writer, pages) ||
        !text_literal(&writer, "\n"))
        return text_error(error, error_cap,
                          "presentation text page exceeds its byte bound");

    if (model->kind == ZCL_PRESENT_MODEL_QR_CARD) {
        uint32_t payload_begin = 0;
        uint32_t payload_total = 0;
        for (uint32_t i = 0; i < model->item_count; i++) {
            uint32_t chunk = (uint32_t)strlen(model->items[i].value);
            if (i < begin) payload_begin += chunk;
            payload_total += chunk;
        }
        uint32_t payload_end = payload_begin;
        for (uint32_t i = begin; i < end; i++)
            payload_end += (uint32_t)strlen(model->items[i].value);
        if (!text_literal(&writer, "payload-bytes: ") ||
            !text_u32(&writer, payload_begin + 1u) ||
            !text_literal(&writer, "-") || !text_u32(&writer, payload_end) ||
            !text_literal(&writer, " of ") ||
            !text_u32(&writer, payload_total) ||
            !text_literal(&writer, "\npayload-fragment: "))
            return text_error(error, error_cap,
                              "QR text page exceeds its byte bound");
        for (uint32_t i = begin; i < end; i++)
            if (!text_escaped(&writer, model->items[i].value))
                return text_error(error, error_cap,
                                  "QR text page exceeds its byte bound");
        if (!text_literal(&writer, "\n"))
            return text_error(error, error_cap,
                              "QR text page exceeds its byte bound");
    } else {
        bool items_ok = text_literal(&writer, "items: ");
        if (model->item_count == 0)
            items_ok = items_ok && text_literal(&writer, "0 of 0\n");
        else
            items_ok = items_ok && text_u32(&writer, begin + 1u) &&
                text_literal(&writer, "-") && text_u32(&writer, end) &&
                text_literal(&writer, " of ") &&
                text_u32(&writer, model->item_count) &&
                text_literal(&writer, "\n");
        if (!items_ok)
            return text_error(error, error_cap,
                              "presentation text page exceeds its byte bound");
        for (uint32_t i = begin; i < end; i++)
            if (!text_item(&writer, &model->items[i], i))
                return text_error(error, error_cap,
                                  "presentation text page exceeds its byte bound");
    }
    if (!text_actions(&writer, model) ||
        !text_literal(&writer, "authority: display-only\n"))
        return text_error(error, error_cap,
                          "presentation text page exceeds its byte bound");
    *out_len = writer.used;
    if (error && error_cap > 0) error[0] = '\0';
    return true;
}

bool zcl_present_model_text_all_v1(
    const struct zcl_present_model_v1 *model,
    char *out, size_t out_cap, size_t *out_len,
    char *error, size_t error_cap)
{
    if (!model)
        return text_error(error, error_cap,
                          "presentation text model is missing");
    return text_document(model, 0, model->item_count, 0, 1,
                         out, out_cap, out_len, error, error_cap);
}

bool zcl_present_model_text_page_v1(
    const struct zcl_present_model_v1 *model, uint32_t page_index,
    char *out, size_t out_cap, size_t *out_len, uint32_t *page_count,
    char *error, size_t error_cap)
{
    if (!page_count)
        return text_error(error, error_cap,
                          "presentation text output is incomplete");
    *page_count = 0;
    if (!model)
        return text_error(error, error_cap,
                          "presentation text model is missing");
    uint32_t pages =
        (model->item_count + ZCL_PRESENT_MODEL_TEXT_ITEMS_PER_PAGE - 1u) /
        ZCL_PRESENT_MODEL_TEXT_ITEMS_PER_PAGE;
    if (pages == 0) pages = 1u;
    *page_count = pages;
    if (page_index >= pages)
        return text_error(error, error_cap,
                          "presentation text page is out of range");
    uint32_t begin = page_index * ZCL_PRESENT_MODEL_TEXT_ITEMS_PER_PAGE;
    uint32_t end = begin + ZCL_PRESENT_MODEL_TEXT_ITEMS_PER_PAGE;
    if (end > model->item_count) end = model->item_count;
    return text_document(model, begin, end, page_index, pages,
                         out, out_cap, out_len, error, error_cap);
}
