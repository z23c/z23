/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: portable RGFW software-window backend behind the bounded ABI. */

#include "presentation/presentation.h"

#include "presentation/model_render.h"
#include "presentation_canvas_internal.h"
#include "presentation_focus_internal.h"
#include "presentation_form_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* RGFW is private implementation detail. These switches keep graphics on the
 * CPU, avoid OpenGL, and on Linux dynamically load the system X11 API instead
 * of adding a link-time dependency. Windows uses Win32; macOS uses Cocoa via
 * the Objective-C runtime from ordinary C. */
#define RGFW_IMPLEMENTATION
#define RGFW_NO_API
#define RGFW_NO_IOKIT
#if defined(__APPLE__) && defined(__clang__)
/* RGFW has two legacy numeric `_MSC_VER` probes. Do not define that macro on
 * Apple: current SDK headers use its presence to select actual MSVC syntax. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundef"
#elif !defined(_MSC_VER)
/* RGFW probes the MSVC version numerically instead of with defined(). */
#define _MSC_VER 0
#define ZCL_PRESENT_UNDEF_MSC_VER
#endif
#if defined(__linux__)
#define RGFW_USE_XDL
#define RGFW_NO_X11_CURSOR
/* The presentation surface displays a software bitmap and never changes a
 * monitor mode, reads XRandR DPI metadata, or captures raw-input deltas.
 * Keep those optional X11 extensions out of the compile closure: ordinary
 * node/test builds must not depend on host Xrandr/XInput2 development
 * headers merely because a read-only popup exists. Core Xlib is loaded at
 * runtime by the vendored XDL layer. */
#define RGFW_NO_DPI
#define RGFW_NO_XINPUT2
#define RGFW_NO_X11_XI_PRELOAD
#define XDL_NO_GLX
#define XDL_NO_XRANDR
#endif
#include "../../../vendor/rgfw/RGFW.h"
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic pop
#elif defined(ZCL_PRESENT_UNDEF_MSC_VER)
#undef _MSC_VER
#undef ZCL_PRESENT_UNDEF_MSC_VER
#endif

static bool present_error(char *error, size_t cap, const char *message)
{
    if (error && cap > 0)
        (void)snprintf(error, cap, "%s", message);
    return false;
}

static bool bounded_text(const char *text, size_t max)
{
    if (!text) return true;
    size_t n = 0;
    while (n <= max && text[n]) n++;
    return n <= max;
}

bool zcl_present_window_validate_v1(
    const struct zcl_present_window_v1 *request,
    char *error, size_t error_cap)
{
    if (!request || request->struct_size != sizeof(*request) ||
        request->abi_version != ZCL_PRESENT_ABI_V1)
        return present_error(error, error_cap,
                             "presentation ABI/structure mismatch");
    if (!bounded_text(request->title, ZCL_PRESENT_TITLE_MAX))
        return present_error(error, error_cap,
                             "presentation title is oversized");
    if (!bounded_text(request->copy_text, ZCL_PRESENT_COPY_TEXT_MAX))
        return present_error(error, error_cap,
                             "presentation clipboard text is oversized");
    if (!request->pixels || request->width == 0 || request->height == 0 ||
        request->width > ZCL_PRESENT_DIMENSION_MAX ||
        request->height > ZCL_PRESENT_DIMENSION_MAX)
        return present_error(error, error_cap,
                             "presentation bitmap dimensions are invalid");
    if (request->pixel_format != ZCL_PRESENT_RGB8 &&
        request->pixel_format != ZCL_PRESENT_RGBA8)
        return present_error(error, error_cap,
                             "presentation pixel format is unsupported");
    uint64_t pixel_bytes = (uint64_t)request->width * request->height *
                           (uint32_t)request->pixel_format;
    if (pixel_bytes == 0 || pixel_bytes > SIZE_MAX)
        return present_error(error, error_cap,
                             "presentation bitmap size overflows");
    bool any_icon = request->icon_rgba || request->icon_width ||
                    request->icon_height;
    bool complete_icon = request->icon_rgba && request->icon_width > 0 &&
                         request->icon_height > 0 &&
                         request->icon_width <= 256u &&
                         request->icon_height <= 256u;
    if (any_icon && !complete_icon)
        return present_error(error, error_cap,
                             "presentation icon is incomplete or oversized");
    if (error && error_cap > 0) error[0] = '\0';
    return true;
}

const char *zcl_present_backend_name(void)
{
    return "rgfw-1.8.1-software";
}

const char *zcl_present_platform_name(void)
{
#if defined(_WIN32)
    return "win32";
#elif defined(__APPLE__)
    return "cocoa";
#elif defined(__linux__)
    return "x11-dynamic";
#else
    return "unsupported";
#endif
}

#if defined(__linux__)
static void present_set_linux_desktop_identity(RGFW_window *window)
{
    Display *display = (Display *)RGFW_getDisplay_X11();
    if (!display || !window || !window->src.window) return;

    const unsigned char *app_id =
        (const unsigned char *)ZCL_PRESENT_APPLICATION_ID;
    int app_id_len = (int)strlen(ZCL_PRESENT_APPLICATION_ID);
    Atom utf8 = XInternAtom(display, "UTF8_STRING", False);
    static const char *const identity_properties[] = {
        "_KDE_NET_WM_DESKTOP_FILE",
        "_GTK_APPLICATION_ID",
    };
    for (size_t i = 0; i < sizeof(identity_properties) /
                            sizeof(identity_properties[0]); i++) {
        Atom property = XInternAtom(display, identity_properties[i], False);
        (void)XChangeProperty(display, window->src.window, property, utf8, 8,
                              PropModeReplace, app_id, app_id_len);
    }
    unsigned long process_id = (unsigned long)getpid();
    Atom pid_property = XInternAtom(display, "_NET_WM_PID", False);
    Atom cardinal = XInternAtom(display, "CARDINAL", False);
    (void)XChangeProperty(display, window->src.window, pid_property, cardinal,
                          32, PropModeReplace,
                          (const unsigned char *)&process_id, 1);
    XFlush(display);
}
#endif

static bool present_scale_bitmap(const struct zcl_present_window_v1 *request,
                                 i32 target_width, i32 target_height,
                                 uint8_t **out)
{
    *out = NULL;
    if (target_width <= 0 || target_height <= 0 ||
        target_width > 4096 || target_height > 4096)
        return false;
    uint32_t channels = (uint32_t)request->pixel_format;
    uint64_t bytes = (uint64_t)(uint32_t)target_width *
                     (uint32_t)target_height * channels;
    if (bytes == 0 || bytes > SIZE_MAX) return false;
    uint8_t *pixels = malloc((size_t)bytes); // raw-alloc-ok:standalone-presentation-package
    if (!pixels) return false;
    for (uint64_t i = 0; i < bytes; i += channels) {
        pixels[i] = 0x20;
        pixels[i + 1u] = 0x20;
        pixels[i + 2u] = 0x22;
        if (channels == 4u) pixels[i + 3u] = 0xff;
    }

    uint32_t draw_width = (uint32_t)target_width;
    uint32_t draw_height = (uint32_t)((uint64_t)draw_width *
                                      request->height / request->width);
    if (draw_height > (uint32_t)target_height) {
        draw_height = (uint32_t)target_height;
        draw_width = (uint32_t)((uint64_t)draw_height *
                                request->width / request->height);
    }
    if (draw_width == 0 || draw_height == 0) {
        free(pixels);
        return false;
    }
    uint32_t x0 = ((uint32_t)target_width - draw_width) / 2u;
    uint32_t y0 = ((uint32_t)target_height - draw_height) / 2u;
    for (uint32_t y = 0; y < draw_height; y++) {
        uint32_t source_y = (uint32_t)((uint64_t)y * request->height /
                                       draw_height);
        for (uint32_t x = 0; x < draw_width; x++) {
            uint32_t source_x = (uint32_t)((uint64_t)x * request->width /
                                           draw_width);
            size_t source = ((size_t)source_y * request->width + source_x) *
                            channels;
            size_t target = ((size_t)(y0 + y) * (uint32_t)target_width +
                             x0 + x) * channels;
            memcpy(pixels + target, request->pixels + source, channels);
        }
    }
    *out = pixels;
    return true;
}

static bool present_pages_validate(
    const struct zcl_present_window_pages_v1 *request,
    char *error, size_t error_cap)
{
    if (!request || request->struct_size != sizeof(*request) ||
        request->abi_version != ZCL_PRESENT_ABI_V1 || !request->pages ||
        request->page_count == 0 ||
        request->page_count > ZCL_PRESENT_WINDOW_PAGES_MAX)
        return present_error(error, error_cap,
                             "presentation pages ABI/count is invalid");
    const struct zcl_present_window_v1 *first = &request->pages[0];
    for (uint32_t i = 0; i < request->page_count; i++) {
        const struct zcl_present_window_v1 *page = &request->pages[i];
        if (!zcl_present_window_validate_v1(page, error, error_cap))
            return false;
        if (page->width != first->width || page->height != first->height ||
            page->pixel_format != first->pixel_format)
            return present_error(error, error_cap,
                                 "presentation page geometry differs");
    }
    return true;
}

static bool present_replace_surface(
    RGFW_window *window, const struct zcl_present_window_v1 *page,
    i32 width, i32 height, RGFW_surface **surface,
    uint8_t **scaled_pixels, uint32_t action_count,
    uint32_t focused_control,
    const struct zcl_present_window_form_v1 *form,
    const struct zcl_present_window_canvas_v1 *canvas,
    bool required_invalid)
{
    uint8_t *replacement_pixels = NULL;
    bool scaled = width != (i32)page->width || height != (i32)page->height;
    bool owned = scaled || action_count > 0 || form || canvas;
    uint8_t *overlay_pixels = NULL;
    struct zcl_present_window_v1 overlay_page = *page;
    if (form || canvas) {
        uint64_t bytes = (uint64_t)page->width * page->height *
                         (uint32_t)page->pixel_format;
        if (bytes == 0 || bytes > SIZE_MAX) return false;
        overlay_pixels = malloc((size_t)bytes); // raw-alloc-ok:standalone-presentation-package
        if (!overlay_pixels) return false;
        memcpy(overlay_pixels, page->pixels, (size_t)bytes);
        if (form)
            zcl_present_form_draw_state_internal(
                overlay_pixels, (size_t)bytes, form,
                focused_control, required_invalid);
        else
            zcl_present_canvas_draw_state_internal(
                overlay_pixels, (size_t)bytes, canvas, focused_control);
        overlay_page.pixels = overlay_pixels;
        page = &overlay_page;
    }
    if (scaled) {
        if (!present_scale_bitmap(page, width, height,
                                  &replacement_pixels)) {
            free(overlay_pixels);
            return false;
        }
        free(overlay_pixels);
    } else if (owned) {
        if (overlay_pixels) {
            replacement_pixels = overlay_pixels;
        } else {
            uint64_t bytes = (uint64_t)page->width * page->height *
                             (uint32_t)page->pixel_format;
            if (bytes == 0 || bytes > SIZE_MAX) return false;
            replacement_pixels = malloc((size_t)bytes); // raw-alloc-ok:standalone-presentation-package
            if (!replacement_pixels) return false;
            memcpy(replacement_pixels, page->pixels, (size_t)bytes);
        }
    }
    uint8_t *pixels = owned ? replacement_pixels
        : (uint8_t *)(uintptr_t)page->pixels;
    uint32_t focused_action = focused_control;
    bool action_focused = action_count > 0;
    if (form) {
        action_focused = focused_control >= form->field_count;
        focused_action = action_focused
            ? focused_control - form->field_count : UINT32_MAX;
    } else if (canvas) {
        action_focused = focused_control > 0;
        focused_action = action_focused
            ? focused_control - 1u : UINT32_MAX;
    }
    if (action_focused)
        zcl_present_draw_action_focus_internal(
            page, pixels, (uint32_t)width, (uint32_t)height,
            action_count, focused_action);
    RGFW_surface *replacement = RGFW_window_createSurface(
        window, pixels, width, height,
        page->pixel_format == ZCL_PRESENT_RGB8
            ? RGFW_formatRGB8 : RGFW_formatRGBA8);
    if (!replacement) {
        free(replacement_pixels);
        return false;
    }
    if (*surface) RGFW_surface_free(*surface);
    free(*scaled_pixels);
    *surface = replacement;
    *scaled_pixels = replacement_pixels;
    return true;
}

static bool present_redraw(
    RGFW_window *window, const struct zcl_present_window_v1 *page,
    RGFW_surface **surface, uint8_t **scaled_pixels,
    uint32_t action_count, uint32_t focused_control,
    const struct zcl_present_window_form_v1 *form,
    const struct zcl_present_window_canvas_v1 *canvas,
    bool required_invalid)
{
    i32 width = 0, height = 0;
    (void)RGFW_window_getSize(window, &width, &height);
    if (!present_replace_surface(
            window, page, width, height, surface, scaled_pixels,
            action_count, focused_control, form, canvas, required_invalid))
        return false;
    RGFW_window_blitSurface(window, *surface);
    return true;
}

static bool present_run_pages_actions(
    const struct zcl_present_window_pages_v1 *pages,
    uint32_t action_count,
    struct zcl_present_window_form_v1 *form,
    struct zcl_present_window_canvas_v1 *canvas,
    zcl_present_window_ready_fn ready,
    void *ready_context,
    struct zcl_present_window_event_v1 *result,
    char *error, size_t error_cap)
{
    if (!result || action_count > ZCL_PRESENT_WINDOW_ACTIONS_MAX)
        return present_error(error, error_cap,
                             "presentation action event is invalid");
    *result = (struct zcl_present_window_event_v1){
        .struct_size = sizeof(*result),
        .abi_version = ZCL_PRESENT_ABI_V1,
        .outcome = ZCL_PRESENT_WINDOW_DISMISSED,
        .action_index = UINT32_MAX,
    };
    if (!present_pages_validate(pages, error, error_cap))
        return false;
    if (form && canvas)
        return present_error(error, error_cap,
                             "presentation controls are mutually exclusive");
    if (form && (!zcl_present_window_form_validate_v1(
                     form, error, error_cap) ||
                 action_count != 2u || pages->page_count != 1u ||
                 pages->pages[0].pixel_format != ZCL_PRESENT_RGB8 ||
                 pages->pages[0].width != ZCL_PRESENT_MODEL_BITMAP_WIDTH ||
                 pages->pages[0].height != ZCL_PRESENT_MODEL_BITMAP_HEIGHT))
        return present_error(error, error_cap,
                             "presentation form geometry/actions are invalid");
    if (canvas && (!zcl_present_window_canvas_validate_v1(
                       canvas, error, error_cap) ||
                   action_count != 2u || pages->page_count != 1u ||
                   pages->pages[0].pixel_format != ZCL_PRESENT_RGB8 ||
                   pages->pages[0].width != ZCL_PRESENT_MODEL_BITMAP_WIDTH ||
                   pages->pages[0].height != ZCL_PRESENT_MODEL_BITMAP_HEIGHT))
        return present_error(error, error_cap,
                             "presentation canvas geometry/actions are invalid");
    uint32_t current_page = 0;
    const struct zcl_present_window_v1 *request = &pages->pages[current_page];
#if !defined(_WIN32) && !defined(__APPLE__) && !defined(__linux__)
    return present_error(error, error_cap,
                         "native presentation is unsupported on this platform");
#else
#if defined(__linux__)
    const char *display = getenv("DISPLAY");
    if (!display || !display[0])
        return present_error(error, error_cap,
                             "cannot open the desktop display (DISPLAY is unset)");
#endif
    const char *title = request->title && request->title[0]
        ? request->title : "ZClassic23";
    /* Keep the native window identity stable across QR, graph, Metaverse, and
     * ZCode content. Linux desktop shells match this WM_CLASS to the bundled
     * desktop entry; Win32 uses it as the grouping class. */
    RGFW_setClassName(ZCL_PRESENT_APPLICATION_ID);
    RGFW_setXInstName(ZCL_PRESENT_APPLICATION_ID);
    RGFW_windowFlags flags = (RGFW_windowFlags)(
        RGFW_windowCenter | RGFW_windowFocusOnShow);
    RGFW_window *window = RGFW_createWindow(
        title, 0, 0, (i32)request->width, (i32)request->height, flags);
    if (!window)
        return present_error(error, error_cap,
                             "native window creation failed");
    RGFW_window_setMinSize(window, 260, 300);

#if defined(__linux__)
    present_set_linux_desktop_identity(window);
#endif

    if (request->icon_rgba) {
        (void)RGFW_window_setIcon(
            window, (u8 *)(uintptr_t)request->icon_rgba,
            (i32)request->icon_width, (i32)request->icon_height,
            RGFW_formatRGBA8);
    }
    RGFW_surface *surface = NULL;
    uint8_t *scaled_pixels = NULL;
    uint32_t focused_control = 0;
    bool required_invalid = false;
    if (form) {
        while (focused_control < form->field_count &&
               (form->fields[focused_control].flags &
                ZCL_PRESENT_WINDOW_FORM_READ_ONLY))
            focused_control++;
        if (focused_control == form->field_count)
            focused_control = form->field_count;
    }
    if (!present_replace_surface(window, request,
                                 (i32)request->width,
                                 (i32)request->height,
                                 &surface, &scaled_pixels,
                                 action_count, focused_control,
                                 form, canvas, required_invalid)) {
        RGFW_window_close(window);
        return present_error(error, error_cap,
                             "native bitmap surface creation failed");
    }

    RGFW_window_setExitKey(window, RGFW_escape);
    RGFW_window_blitSurface(window, surface);
    if (ready) ready(ready_context);
    while (!RGFW_window_shouldClose(window)) {
        RGFW_event event;
        bool saw_event = false;
        while (RGFW_window_checkEvent(window, &event)) {
            saw_event = true;
            if (event.type == RGFW_windowResized) {
                i32 resized_width = 0;
                i32 resized_height = 0;
                (void)RGFW_window_getSize(window, &resized_width,
                                          &resized_height);
                (void)present_replace_surface(
                    window, request, resized_width, resized_height,
                    &surface, &scaled_pixels, action_count,
                    focused_control, form, canvas, required_invalid);
                RGFW_window_blitSurface(window, surface);
            } else if (event.type == RGFW_windowRefresh) {
                RGFW_window_blitSurface(window, surface);
            }
            if (event.type == RGFW_mouseButtonPressed &&
                event.button.value == RGFW_mouseLeft) {
                i32 window_width = 0, window_height = 0;
                i32 mouse_x = 0, mouse_y = 0;
                uint32_t action = UINT32_MAX;
                (void)RGFW_window_getSize(window, &window_width,
                                          &window_height);
                if (RGFW_window_getMouse(window, &mouse_x, &mouse_y) &&
                    zcl_present_window_action_at_v1(
                        request->width, request->height,
                        window_width, window_height, mouse_x, mouse_y,
                        action_count, &action)) {
                    if (form && action == 1u &&
                        !zcl_present_form_required_complete_internal(form)) {
                        required_invalid = true;
                        focused_control = form->field_count + action;
                        (void)present_redraw(
                            window, request, &surface, &scaled_pixels,
                            action_count, focused_control, form, canvas,
                            required_invalid);
                    } else {
                        result->outcome = ZCL_PRESENT_WINDOW_ACTION;
                        result->action_index = action;
                        RGFW_window_setShouldClose(window, RGFW_TRUE);
                    }
                } else if (canvas) {
                    uint32_t point_x = 0, point_y = 0;
                    if (zcl_present_window_canvas_point_at_v1(
                            request->width, request->height,
                            window_width, window_height, mouse_x, mouse_y,
                            &point_x, &point_y)) {
                        struct zcl_present_window_canvas_point_v1 *point =
                            &canvas->points[canvas->editable_index];
                        point->x = point_x;
                        point->y = point_y;
                        focused_control = 0;
                        (void)present_redraw(
                            window, request, &surface, &scaled_pixels,
                            action_count, focused_control, form, canvas,
                            required_invalid);
                    }
                }
            }
            uint32_t next_page = current_page;
            if (event.type == RGFW_mouseScroll && event.scroll.y < 0)
                (void)zcl_present_window_page_step_v1(
                    current_page, pages->page_count, 1, &next_page);
            else if (event.type == RGFW_mouseScroll && event.scroll.y > 0)
                (void)zcl_present_window_page_step_v1(
                    current_page, pages->page_count, -1, &next_page);
            else if (event.type == RGFW_keyPressed) {
                if (event.key.value == RGFW_pageDown ||
                    event.key.value == RGFW_down ||
                    event.key.value == RGFW_right)
                    (void)zcl_present_window_page_step_v1(
                        current_page, pages->page_count, 1, &next_page);
                else if (event.key.value == RGFW_pageUp ||
                         event.key.value == RGFW_up ||
                         event.key.value == RGFW_left)
                    (void)zcl_present_window_page_step_v1(
                        current_page, pages->page_count, -1, &next_page);
                else if (event.key.value == RGFW_home)
                    next_page = 0;
                else if (event.key.value == RGFW_end)
                    next_page = pages->page_count - 1u;
            }
            if (next_page != current_page) {
                i32 window_width = 0, window_height = 0;
                (void)RGFW_window_getSize(window, &window_width,
                                          &window_height);
                const struct zcl_present_window_v1 *next =
                    &pages->pages[next_page];
                if (present_replace_surface(
                        window, next, window_width, window_height,
                        &surface, &scaled_pixels, action_count,
                        focused_control, form, canvas, required_invalid)) {
                    current_page = next_page;
                    request = next;
                    RGFW_window_blitSurface(window, surface);
                }
            }
            if (event.type != RGFW_keyPressed) continue;
            if (event.key.value == RGFW_tab && action_count > 0) {
                uint32_t next_control = focused_control;
                int32_t direction = (event.key.mod & RGFW_modShift)
                    ? -1 : 1;
                bool stepped = form
                    ? zcl_present_window_form_focus_step_v1(
                          form, action_count, focused_control, direction,
                          &next_control)
                    : (canvas
                        ? zcl_present_window_canvas_focus_step_v1(
                              action_count, focused_control, direction,
                              &next_control)
                        : zcl_present_window_action_focus_step_v1(
                              focused_control, action_count, direction,
                              &next_control));
                if (stepped) {
                    if (present_redraw(
                            window, request, &surface, &scaled_pixels,
                            action_count, next_control, form, canvas,
                            required_invalid)) {
                        focused_control = next_control;
                    }
                }
                continue;
            }
            if (form && focused_control < form->field_count) {
                bool changed = false;
                if (event.key.value == RGFW_return) {
                    uint32_t next_control = focused_control;
                    if (zcl_present_window_form_focus_step_v1(
                            form, action_count, focused_control, 1,
                            &next_control)) {
                        focused_control = next_control;
                        changed = true;
                    }
                } else if (event.key.value == RGFW_backSpace) {
                    changed = zcl_present_window_form_edit_v1(
                        form, focused_control, 0, true);
                    required_invalid = false;
                } else if (!(event.key.mod &
                             (RGFW_modControl | RGFW_modAlt |
                              RGFW_modSuper)) &&
                           event.key.sym >= 0x20u &&
                           event.key.sym <= 0x7eu) {
                    changed = zcl_present_window_form_edit_v1(
                        form, focused_control, event.key.sym, false);
                    required_invalid = false;
                }
                if (changed) {
                    (void)present_redraw(
                        window, request, &surface, &scaled_pixels,
                        action_count, focused_control, form, canvas,
                        required_invalid);
                }
                continue;
            }
            if (canvas && focused_control == 0) {
                bool changed = false;
                int32_t step = (event.key.mod & RGFW_modShift) ? 1 : 10;
                if (event.key.value == RGFW_return) {
                    uint32_t next_control = focused_control;
                    if (zcl_present_window_canvas_focus_step_v1(
                            action_count, focused_control, 1,
                            &next_control)) {
                        focused_control = next_control;
                        changed = true;
                    }
                } else if (event.key.value == RGFW_left) {
                    changed = zcl_present_window_canvas_step_v1(
                        canvas, -step, 0);
                } else if (event.key.value == RGFW_right) {
                    changed = zcl_present_window_canvas_step_v1(
                        canvas, step, 0);
                } else if (event.key.value == RGFW_up) {
                    changed = zcl_present_window_canvas_step_v1(
                        canvas, 0, -step);
                } else if (event.key.value == RGFW_down) {
                    changed = zcl_present_window_canvas_step_v1(
                        canvas, 0, step);
                }
                if (changed) {
                    (void)present_redraw(
                        window, request, &surface, &scaled_pixels,
                        action_count, focused_control, form, canvas,
                        required_invalid);
                }
                continue;
            }
            if ((event.key.value == RGFW_return ||
                 event.key.value == RGFW_space) && action_count > 0) {
                uint32_t action = form
                    ? focused_control - form->field_count
                    : (canvas ? focused_control - 1u : focused_control);
                if (form && action == 1u &&
                    !zcl_present_form_required_complete_internal(form)) {
                    required_invalid = true;
                    (void)present_redraw(
                        window, request, &surface, &scaled_pixels,
                        action_count, focused_control, form, canvas,
                        required_invalid);
                } else {
                    result->outcome = ZCL_PRESENT_WINDOW_ACTION;
                    result->action_index = action;
                    RGFW_window_setShouldClose(window, RGFW_TRUE);
                }
            }
            if (form || canvas) continue;
            if (event.key.value == RGFW_q)
                RGFW_window_setShouldClose(window, RGFW_TRUE);
            if (event.key.value == RGFW_c && request->copy_text) {
                size_t copy_len = strlen(request->copy_text);
                RGFW_writeClipboard(request->copy_text, (u32)copy_len);
            }
            static const RGFW_key action_keys[] = {
                RGFW_1, RGFW_2, RGFW_3, RGFW_4,
            };
            /* Keep the array bound local even though entry validation already
             * rejects action_count > 4. LTO must be able to prove this read is
             * bounded without depending on a distant control-flow fact. */
            for (uint32_t i = 0;
                 i < action_count && i < ZCL_PRESENT_WINDOW_ACTIONS_MAX;
                 i++) {
                if (event.key.value != action_keys[i]) continue;
                result->outcome = ZCL_PRESENT_WINDOW_ACTION;
                result->action_index = i;
                RGFW_window_setShouldClose(window, RGFW_TRUE);
            }
        }
        if (!saw_event) RGFW_waitForEvent(100);
    }
    RGFW_surface_free(surface);
    free(scaled_pixels);
    RGFW_window_close(window);
    if (error && error_cap > 0) error[0] = '\0';
    return true;
#endif
}

bool zcl_present_window_run_pages_actions_v1(
    const struct zcl_present_window_pages_v1 *pages,
    uint32_t action_count,
    zcl_present_window_ready_fn ready,
    void *ready_context,
    struct zcl_present_window_event_v1 *result,
    char *error, size_t error_cap)
{
    return present_run_pages_actions(
        pages, action_count, NULL, NULL, ready, ready_context,
        result, error, error_cap);
}

bool zcl_present_window_run_pages_form_actions_v1(
    const struct zcl_present_window_pages_v1 *pages,
    uint32_t action_count,
    struct zcl_present_window_form_v1 *form,
    zcl_present_window_ready_fn ready,
    void *ready_context,
    struct zcl_present_window_event_v1 *result,
    char *error, size_t error_cap)
{
    return present_run_pages_actions(
        pages, action_count, form, NULL, ready, ready_context,
        result, error, error_cap);
}

bool zcl_present_window_run_pages_canvas_actions_v1(
    const struct zcl_present_window_pages_v1 *pages,
    uint32_t action_count,
    struct zcl_present_window_canvas_v1 *canvas,
    zcl_present_window_ready_fn ready,
    void *ready_context,
    struct zcl_present_window_event_v1 *result,
    char *error, size_t error_cap)
{
    return present_run_pages_actions(
        pages, action_count, NULL, canvas, ready, ready_context,
        result, error, error_cap);
}

bool zcl_present_window_run_actions_v1(
    const struct zcl_present_window_v1 *request,
    uint32_t action_count,
    zcl_present_window_ready_fn ready,
    void *ready_context,
    struct zcl_present_window_event_v1 *result,
    char *error, size_t error_cap)
{
    struct zcl_present_window_pages_v1 pages = {
        .struct_size = sizeof(pages),
        .abi_version = ZCL_PRESENT_ABI_V1,
        .pages = request,
        .page_count = 1,
    };
    return zcl_present_window_run_pages_actions_v1(
        &pages, action_count, ready, ready_context,
        result, error, error_cap);
}

bool zcl_present_window_run_v1(
    const struct zcl_present_window_v1 *request,
    char *error, size_t error_cap)
{
    struct zcl_present_window_event_v1 event;
    return zcl_present_window_run_actions_v1(
        request, 0, NULL, NULL, &event, error, error_cap);
}
