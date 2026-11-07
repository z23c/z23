/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Native live-window failure regression; built only with ZCL_TESTING. */
#include "presentation/presentation.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if defined(__APPLE__)
#include <objc/runtime.h>
#endif
#if !defined(ZCL_TESTING)
#error "live redraw fixture requires ZCL_TESTING"
#endif
void zcl_present_test_script(unsigned first, unsigned second, bool fail_redraw);
struct zcl_present_window_event_v1 zcl_present_test_result(void);
#if defined(__linux__)
bool zcl_present_test_x11_libraries_retired(void);
#endif
struct fixture { unsigned calls; bool confirm; };
static void update(void *context, const struct zcl_present_window_event_v1 *event,
                   bool close_requested, bool *redraw, bool *allow_close)
{
    struct fixture *f = context;
    (void)close_requested;
    ++f->calls;
    *redraw = event->action_index == 1;
    *allow_close = event->outcome == ZCL_PRESENT_WINDOW_ACTION && event->action_index != 1;
    if (event->action_index == 3) f->confirm = true;
}
static bool input(void *context, const struct zcl_present_input_v1 *event,
                  uint32_t *focus, uint32_t *action)
{
    (void)context;
    if (event->key != ZCL_PRESENT_INPUT_TEXT || event->character < '1' || event->character > '4') return false;
    *focus = event->character - '1';
    /* Scripted '3' changes only focus, like Tab in the native confirm view. */
    if (event->character != '3') *action = *focus;
    return true;
}
static bool run(unsigned first, bool fail, bool expected_ok,
                unsigned expected_calls, bool expected_confirm)
{
    static uint8_t pixels[16 * 16 * 3];
    struct zcl_present_window_v1 page = {
        .struct_size = sizeof(page), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = "Live redraw regression", .pixels = pixels,
        .width = 16, .height = 16, .pixel_format = ZCL_PRESENT_RGB8,
    };
    struct zcl_present_window_pages_v1 pages = {
        .struct_size = sizeof(pages), .abi_version = ZCL_PRESENT_ABI_V1,
        .pages = &page, .page_count = 1,
    };
    struct fixture f = {0};
    const struct zcl_present_window_live_view_v1 live = {
        .owner = {.context = &f, .update = update}, .input = input,
    };
    char error[256] = {0};
    zcl_present_test_script(first, 3, fail);
    bool ok = zcl_present_window_run_live_view_v1(&pages, 4, &live, error, sizeof(error));
    struct zcl_present_window_event_v1 result = zcl_present_test_result();
#if defined(__linux__)
    if (!zcl_present_test_x11_libraries_retired()) {
        fprintf(stderr, "live redraw: last-window close retained X11 library state\n");
        return false;
    }
#endif
    if ((!expected_ok && (result.outcome != ZCL_PRESENT_WINDOW_DISMISSED || result.action_index != UINT32_MAX)) ||
        ok != expected_ok || f.calls != expected_calls || f.confirm != expected_confirm ||
        (!expected_ok && !strstr(error, "redraw"))) {
        fprintf(stderr, "live redraw: ok=%d calls=%u confirm=%d error=%s\n", ok, f.calls, f.confirm, error);
        return false;
    }
    return true;
}
#if defined(__APPLE__)
static bool initialization_failure(void)
{
    Class collision = objc_allocateClassPair(objc_getClass("NSObject"), "RGFWCustomView", 0);
    if (!collision) return false;
    objc_registerClassPair(collision);
    static uint8_t pixels[16 * 16 * 3];
    struct zcl_present_window_v1 page = {
        .struct_size = sizeof(page), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = "Collision", .pixels = pixels, .width = 16, .height = 16,
        .pixel_format = ZCL_PRESENT_RGB8,
    };
    struct zcl_present_window_pages_v1 pages = {
        .struct_size = sizeof(pages), .abi_version = ZCL_PRESENT_ABI_V1,
        .pages = &page, .page_count = 1,
    };
    struct fixture f = {0};
    const struct zcl_present_window_live_view_v1 live = {
        .owner = {.context = &f, .update = update}, .input = input,
    };
    char error[256] = {0};
    bool ok = zcl_present_window_run_live_view_v1(&pages, 4, &live, error, sizeof(error));
    objc_disposeClassPair(collision);
    return !ok && f.calls == 0 && strstr(error, "initialization failed") != NULL;
}
#endif

int main(void)
{
#if defined(__APPLE__)
    if (!initialization_failure()) return 1;
#endif
    if (!run(1, true, false, 1, false)) return 1;
    if (!run(0, false, true, 1, false)) return 1;
    if (!run(1, false, true, 2, true)) return 1;
    if (!run(2, true, false, 1, false)) return 1;
    if (!run(2, false, true, 2, true)) return 1;
    puts("live redraw: failure and terminal cancel reject queued confirm; successful redraw proceeds");
    return 0;
}
