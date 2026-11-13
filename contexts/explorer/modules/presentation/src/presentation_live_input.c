/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Translate native window events for a live presentation owner. */
#include "presentation_live_input_internal.h"
#include "presentation_validate_internal.h"

#include <stddef.h>
#if defined(__APPLE__)
#include <objc/message.h>
#include <objc/runtime.h>
#endif

#if defined(__APPLE__)
#define RGFW_NATIVE
#endif

#define RGFW_NO_API
#define RGFW_NO_IOKIT
#define RGFWDEF extern
/* Match presentation.c's boundary for RGFW's numeric _MSC_VER probes.
 * Do not define a foreign compiler identity or suppress project diagnostics. */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundef"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wundef"
#endif
#include "../../../../../vendor/rgfw/RGFW.h"
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

static enum zcl_present_input_key present_live_key(RGFW_key key)
{
    static const struct { RGFW_key native; enum zcl_present_input_key key; } keys[] = {
        {RGFW_up, ZCL_PRESENT_INPUT_UP}, {RGFW_down, ZCL_PRESENT_INPUT_DOWN},
        {RGFW_home, ZCL_PRESENT_INPUT_HOME}, {RGFW_end, ZCL_PRESENT_INPUT_END},
        {RGFW_pageUp, ZCL_PRESENT_INPUT_PAGE_UP}, {RGFW_pageDown, ZCL_PRESENT_INPUT_PAGE_DOWN},
        {RGFW_tab, ZCL_PRESENT_INPUT_TAB}, {RGFW_return, ZCL_PRESENT_INPUT_ENTER},
        {RGFW_delete, ZCL_PRESENT_INPUT_DELETE}, {RGFW_backSpace, ZCL_PRESENT_INPUT_DELETE},
        {RGFW_escape, ZCL_PRESENT_INPUT_ESCAPE},
    };
    for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); ++i)
        if (keys[i].native == key) return keys[i].key;
    return ZCL_PRESENT_INPUT_TEXT;
}

static bool present_live_event(RGFW_window *window,
    const struct zcl_present_window_v1 *page, const RGFW_event *event,
    struct zcl_present_input_v1 *input)
{
    *input = (struct zcl_present_input_v1){0};
    if (event->type == RGFW_keyPressed) {
        input->key = present_live_key(event->key.value);
        input->character = event->key.sym;
        input->shift = (event->key.mod & RGFW_modShift) != 0;
        input->command = (event->key.mod & (RGFW_modControl | RGFW_modSuper)) != 0;
        return true;
    }
    if (event->type == RGFW_mouseScroll) {
        input->key = event->scroll.y < 0 ? ZCL_PRESENT_INPUT_DOWN : ZCL_PRESENT_INPUT_UP;
        return event->scroll.y != 0;
    }
    if (event->type != RGFW_mouseButtonPressed || event->button.value != RGFW_mouseLeft)
        return false;
    i32 width = 0, height = 0, x = 0, y = 0;
    (void)RGFW_window_getSize(window, &width, &height);
    input->key = ZCL_PRESENT_INPUT_CLICK;
    return RGFW_window_getMouse(window, &x, &y) &&
        zcl_present_window_source_point_v1(page->width, page->height,
            width, height, x, y, &input->x, &input->y);
}

bool present_live_input(const struct zcl_present_window_live_view_v1 *live,
    RGFW_window *window, const struct zcl_present_window_v1 *page,
    const RGFW_event *event, uint32_t action_count, uint32_t *focus,
    struct zcl_present_window_event_v1 *result)
{
    if (!live || !live->input) return false;
    struct zcl_present_input_v1 input;
    if (!present_live_event(window, page, event, &input)) return false;
    uint32_t action = UINT32_MAX;
    bool consumed = live->input(live->owner.context, &input, focus, &action);
    if (*focus >= action_count) *focus = UINT32_MAX;
    if (action < action_count) {
        result->outcome = ZCL_PRESENT_WINDOW_ACTION;
        result->action_index = action;
        RGFW_window_setShouldClose(window, RGFW_TRUE);
    }
    return consumed;
}
static int32_t present_live_hover_key_step(const RGFW_event *event,
    uint32_t item_count, bool *absolute, uint32_t *next_hover)
{
    if (event->key.value == RGFW_right)
        return 1;
    if (event->key.value == RGFW_left)
        return -1;
    if (event->key.value == RGFW_down)
        return 1;
    if (event->key.value == RGFW_up)
        return -1;
    if (event->key.value == RGFW_pageDown)
        return 7;
    if (event->key.value == RGFW_pageUp)
        return -7;
    if (event->key.value == RGFW_home) {
        *next_hover = 0;
        *absolute = true;
    } else if (event->key.value == RGFW_end) {
        *next_hover = item_count - 1u;
        *absolute = true;
    }
    return 0;
}

int32_t present_live_hover_step(const RGFW_event *event,
    uint32_t item_count, bool *absolute, uint32_t *next_hover)
{
    if (event->type == RGFW_mouseScroll && event->scroll.y < 0) return 1;
    if (event->type == RGFW_mouseScroll && event->scroll.y > 0) return -1;
    if (event->type != RGFW_keyPressed) return 0;
    return present_live_hover_key_step(event, item_count, absolute,
                                        next_hover);
}

bool zcl_present_window_copy_ascii_v1(const char *text)
{
    size_t n = 0;
    return present_copy_ascii_length(text, &n) && zcl_present_window_copy_text_v1(text);
}

/* Retire Cocoa's window and raw callback pointers before RGFW frees the C window. */
void present_live_window_close(RGFW_window *window)
{
#if defined(__APPLE__)
    RGFW_window_src *source = RGFW_window_getSrc(window);
    id native = (id)source->window;
    id view = (id)source->view;
    id delegate = ((id (*)(id, SEL))objc_msgSend)(native, sel_registerName("delegate"));
    if (delegate) object_setInstanceVariable(delegate, "RGFW_window", NULL);
    if (view) object_setInstanceVariable(view, "RGFW_window", NULL);
    ((void (*)(id, SEL, id))objc_msgSend)(native, sel_registerName("setDelegate:"), nil);
    ((void (*)(id, SEL, BOOL))objc_msgSend)(native, sel_registerName("setReleasedWhenClosed:"), NO);
    ((void (*)(id, SEL))objc_msgSend)(native, sel_registerName("close"));
    /* RGFW allocates and explicitly retains the window, and allocates the delegate. */
    ((void (*)(id, SEL))objc_msgSend)(delegate, sel_registerName("release"));
    ((void (*)(id, SEL))objc_msgSend)(native, sel_registerName("release"));
    ((void (*)(id, SEL))objc_msgSend)(native, sel_registerName("release"));
#endif
    RGFW_window_close(window);
}
