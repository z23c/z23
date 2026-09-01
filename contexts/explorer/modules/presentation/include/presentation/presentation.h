/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded cross-platform native bitmap presentation capability. */

#ifndef ZCL_PRESENTATION_PRESENTATION_H
#define ZCL_PRESENTATION_PRESENTATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZCL_PRESENT_ABI_V1 1u
#define ZCL_PRESENT_APPLICATION_ID "org.zclassic.ZClassic23"
#define ZCL_PRESENT_TITLE_MAX 127u
#define ZCL_PRESENT_COPY_TEXT_MAX 4096u
#define ZCL_PRESENT_DIMENSION_MAX 2048u
#define ZCL_PRESENT_WINDOW_ACTIONS_MAX 4u
#define ZCL_PRESENT_WINDOW_PAGES_MAX 16u
#define ZCL_PRESENT_WINDOW_FORM_FIELDS_MAX 4u
#define ZCL_PRESENT_WINDOW_FORM_VALUE_MAX 256u
#define ZCL_PRESENT_WINDOW_CANVAS_POINTS_MAX 4u
#define ZCL_PRESENT_WINDOW_CANVAS_COORD_MAX 1000u
#define ZCL_PRESENT_WINDOW_CANVAS_LABEL_MAX 80u

enum zcl_present_pixel_format {
    ZCL_PRESENT_RGB8 = 3,
    ZCL_PRESENT_RGBA8 = 4,
};

/* Pointer-only inputs are borrowed for the duration of the blocking call.
 * Pixels must be tightly packed, row-major, and exactly width*height*channels
 * bytes. The reviewed host decides whether an untrusted App/ZCode request may
 * receive this local-human-output capability; this API grants no process,
 * network, wallet, or filesystem authority. */
struct zcl_present_window_v1 {
    uint32_t struct_size;
    uint32_t abi_version;
    const char *title;
    const uint8_t *pixels;
    uint32_t width;
    uint32_t height;
    enum zcl_present_pixel_format pixel_format;
    const uint8_t *icon_rgba;
    uint32_t icon_width;
    uint32_t icon_height;
    const char *copy_text;
};

/* A fixed, bounded sequence of inert bitmaps shown in one native window.
 * Page selection is local display state only: it grants no capability and
 * produces no software-authority event. */
struct zcl_present_window_pages_v1 {
    uint32_t struct_size;
    uint32_t abi_version;
    const struct zcl_present_window_v1 *pages;
    uint32_t page_count;
};

enum zcl_present_window_outcome {
    ZCL_PRESENT_WINDOW_DISMISSED = 1,
    ZCL_PRESENT_WINDOW_ACTION = 2,
};

struct zcl_present_window_event_v1 {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t outcome;
    uint32_t action_index;
};

enum zcl_present_window_form_field_flags {
    ZCL_PRESENT_WINDOW_FORM_REQUIRED = 1u << 0,
    ZCL_PRESENT_WINDOW_FORM_READ_ONLY = 1u << 1,
};

/* Inert, caller-owned edit state for the closed native form path. Field IDs
 * remain in the renderer-neutral model; the backend sees only ordered values
 * and required/read-only bits. Printable Basic Latin is deliberate: the same
 * bundled font, keyboard contract, wire bytes, and text export stay exact on
 * X11, Win32, and Cocoa without an input-method runtime. */
struct zcl_present_window_form_field_v1 {
    uint16_t flags;
    char value[ZCL_PRESENT_WINDOW_FORM_VALUE_MAX + 1u];
};

struct zcl_present_window_form_v1 {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t field_count;
    struct zcl_present_window_form_field_v1
        fields[ZCL_PRESENT_WINDOW_FORM_FIELDS_MAX];
};

enum zcl_present_window_canvas_point_flags {
    ZCL_PRESENT_WINDOW_CANVAS_POINT_READ_ONLY = 1u << 0,
};

struct zcl_present_window_canvas_point_v1 {
    uint16_t flags;
    uint16_t status;
    uint32_t x;
    uint32_t y;
    char label[ZCL_PRESENT_WINDOW_CANVAS_LABEL_MAX + 1u];
};

/* One editable normalized point plus up to three display-only references.
 * The backend mutates only points[editable_index].x/y. */
struct zcl_present_window_canvas_v1 {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t point_count;
    uint32_t editable_index;
    struct zcl_present_window_canvas_point_v1
        points[ZCL_PRESENT_WINDOW_CANVAS_POINTS_MAX];
};

/* Called after the native window and software surface exist and the first
 * bitmap has been blitted. The callback belongs to the reviewed host, never
 * to the inert visual document or fetched code. */
typedef void (*zcl_present_window_ready_fn)(void *context);

/* Pure validation, suitable for package hosts before they cross the native UI
 * boundary. `error` is always a bounded human-readable explanation on false. */
bool zcl_present_window_validate_v1(
    const struct zcl_present_window_v1 *request,
    char *error, size_t error_cap);

/* Open one native, resizable software-rendered window and block until the user
 * closes it. Resizing preserves aspect ratio; Escape/Q close and C copies
 * copy_text when it is present. */
bool zcl_present_window_run_v1(
    const struct zcl_present_window_v1 *request,
    char *error, size_t error_cap);

/* Interactive host variant. Tab/Shift-Tab move one visibly outlined action;
 * Enter/Space activate it, and number keys 1..action_count activate the exact
 * numbered action directly. Escape/Q/window-close return DISMISSED. Labels
 * and authority remain outside this backend. */
bool zcl_present_window_run_actions_v1(
    const struct zcl_present_window_v1 *request,
    uint32_t action_count,
    zcl_present_window_ready_fn ready,
    void *ready_context,
    struct zcl_present_window_event_v1 *event,
    char *error, size_t error_cap);

/* Multi-page host variant. PgUp/PgDn, arrows, Home/End, and the mouse wheel
 * select among already-bounded bitmaps. Numbered actions retain their exact
 * meaning on every page. */
bool zcl_present_window_run_pages_actions_v1(
    const struct zcl_present_window_pages_v1 *request,
    uint32_t action_count,
    zcl_present_window_ready_fn ready,
    void *ready_context,
    struct zcl_present_window_event_v1 *event,
    char *error, size_t error_cap);

/* Form variant over the same pages/action row. The backend mutates only the
 * supplied bounded values. Tab/Shift-Tab traverse editable fields and then
 * actions, printable Basic Latin edits the focused field, Backspace removes
 * one byte, and Enter advances or activates the focused action. A required
 * empty field keeps Submit local and visibly invalid. */
bool zcl_present_window_run_pages_form_actions_v1(
    const struct zcl_present_window_pages_v1 *request,
    uint32_t action_count,
    struct zcl_present_window_form_v1 *form,
    zcl_present_window_ready_fn ready,
    void *ready_context,
    struct zcl_present_window_event_v1 *event,
    char *error, size_t error_cap);

/* Direct bounded 2D selection over the same safe Cancel/Submit action row.
 * Mouse clicks inside the fixed canvas and keyboard arrows move only the one
 * editable normalized point; Enter advances to harmless Cancel. */
bool zcl_present_window_run_pages_canvas_actions_v1(
    const struct zcl_present_window_pages_v1 *request,
    uint32_t action_count,
    struct zcl_present_window_canvas_v1 *canvas,
    zcl_present_window_ready_fn ready,
    void *ready_context,
    struct zcl_present_window_event_v1 *event,
    char *error, size_t error_cap);

/* Pure clamped page transition used by the backend and sensitivity tests. */
bool zcl_present_window_page_step_v1(
    uint32_t current_page, uint32_t page_count, int32_t delta,
    uint32_t *next_page);

/* Pure wrapping focus transition for the bounded native action row. This is
 * visual/input state only and never returns an authority-bearing action. */
bool zcl_present_window_action_focus_step_v1(
    uint32_t current_action, uint32_t action_count, int32_t delta,
    uint32_t *next_action);

/* Pure form reducers shared by the backend and sensitivity tests. Focus slots
 * are ordered fields first, then actions; read-only fields are skipped. */
bool zcl_present_window_form_validate_v1(
    const struct zcl_present_window_form_v1 *form,
    char *error, size_t error_cap);
struct zcl_present_model_v1;
bool zcl_present_window_form_from_model_v1(
    const struct zcl_present_model_v1 *model,
    struct zcl_present_window_form_v1 *form,
    char *error, size_t error_cap);
bool zcl_present_window_form_edit_v1(
    struct zcl_present_window_form_v1 *form, uint32_t field_index,
    uint8_t character, bool backspace);
bool zcl_present_window_form_focus_step_v1(
    const struct zcl_present_window_form_v1 *form,
    uint32_t action_count, uint32_t current_focus, int32_t delta,
    uint32_t *next_focus);

bool zcl_present_window_canvas_validate_v1(
    const struct zcl_present_window_canvas_v1 *canvas,
    char *error, size_t error_cap);
bool zcl_present_window_canvas_from_model_v1(
    const struct zcl_present_model_v1 *model,
    struct zcl_present_window_canvas_v1 *canvas,
    char *error, size_t error_cap);
bool zcl_present_window_canvas_step_v1(
    struct zcl_present_window_canvas_v1 *canvas,
    int32_t delta_x, int32_t delta_y);
bool zcl_present_window_canvas_focus_step_v1(
    uint32_t action_count, uint32_t current_focus, int32_t delta,
    uint32_t *next_focus);
bool zcl_present_window_canvas_point_at_v1(
    uint32_t source_width, uint32_t source_height,
    int32_t target_width, int32_t target_height,
    int32_t mouse_x, int32_t mouse_y,
    uint32_t *normalized_x, uint32_t *normalized_y);

/* Deterministic hit test for the standard renderer-neutral model action row.
 * Window pixels are aspect-fit, so letterboxing and resize are accounted for
 * before an action index is returned. */
bool zcl_present_window_action_at_v1(
    uint32_t source_width, uint32_t source_height,
    int32_t target_width, int32_t target_height,
    int32_t mouse_x, int32_t mouse_y, uint32_t action_count,
    uint32_t *action_index);

/* Stable diagnostic labels; neither string implies graphics acceleration. */
const char *zcl_present_backend_name(void);
const char *zcl_present_platform_name(void);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_PRESENTATION_PRESENTATION_H */
