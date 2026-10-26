/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: portable RGFW software-window backend behind the bounded ABI. */

#include "presentation/presentation.h"

#include "presentation/canvas.h"
#include "presentation/model_render.h"
#include "presentation_canvas_internal.h"
#include "presentation_focus_internal.h"
#include "presentation_form_internal.h"
#include "util/png_writer.h"
#include "base/serialize_le.h"

#if defined(__linux__)
/* Not static: vendor/rgfw/RGFW.h's RGFW_XHandleClipboardSelection is an
 * external-linkage `inline` function (RGFWDEF expands to plain `inline`)
 * that calls these through the RGFW_X11_CLIPBOARD_* hook macros below.
 * Clang's -Wstatic-in-inline forbids an externally-linked inline function
 * referencing an internal-linkage symbol, so these must have external
 * linkage too even though only this translation unit calls them. */
int present_x11_clipboard_append_targets(
    void *display, unsigned long *targets, int count, int capacity);
int present_x11_clipboard_write_target(
    void *display, unsigned long requestor, unsigned long target,
    unsigned long property);
#define RGFW_X11_CLIPBOARD_APPEND_TARGETS(display, targets, count, capacity) \
    present_x11_clipboard_append_targets( \
        (display), (unsigned long *)(targets), (count), (capacity))
#define RGFW_X11_CLIPBOARD_WRITE_TARGET(display, requestor, target, property) \
    present_x11_clipboard_write_target( \
        (display), (unsigned long)(requestor), (unsigned long)(target), \
        (unsigned long)(property))
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* RGFW is private implementation detail. These switches keep graphics on the
 * CPU, avoid OpenGL, and on Linux dynamically load the system X11 API instead
 * of adding a link-time dependency. Windows uses Win32; macOS uses Cocoa via
 * the Objective-C runtime from ordinary C. */
#define RGFW_IMPLEMENTATION
#define RGFW_NO_API
#define RGFW_NO_IOKIT
#if defined(__clang__)
/* RGFW has legacy numeric `_MSC_VER` probes. Never manufacture this compiler
 * identity: Apple and MinGW system headers use its presence to select MSVC
 * declarations and intrinsics, even when its value is zero. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundef"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wundef"
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
#include "../../../../../vendor/rgfw/RGFW.h"
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

bool zcl_present_bitmap_encode_bmp_v1(
    const struct zcl_present_window_v1 *page,
    uint8_t *output, size_t output_cap, size_t *written)
{
    if (!page || !written || !page->pixels || page->width == 0 ||
        page->height == 0 ||
        (page->pixel_format != ZCL_PRESENT_RGB8 &&
         page->pixel_format != ZCL_PRESENT_RGBA8))
        return false;
    uint64_t row_bytes = ((uint64_t)page->width * 3u + 3u) & ~UINT64_C(3);
    uint64_t pixel_bytes = row_bytes * page->height;
    uint64_t total = 54u + pixel_bytes;
    if (row_bytes > SIZE_MAX || total > SIZE_MAX || total > UINT32_MAX)
        return false;
    *written = (size_t)total;
    if (!output) return true;
    if (output_cap < (size_t)total) return false;
    uint8_t *bmp = output;
    memset(bmp, 0, (size_t)total);
    bmp[0] = 'B';
    bmp[1] = 'M';
    zcl_write_u32_le(bmp + 2, (uint32_t)total);
    zcl_write_u32_le(bmp + 10, 54u);
    zcl_write_u32_le(bmp + 14, 40u);
    zcl_write_u32_le(bmp + 18, page->width);
    zcl_write_u32_le(bmp + 22, page->height);
    zcl_write_u16_le(bmp + 26, 1u);
    zcl_write_u16_le(bmp + 28, 24u);
    zcl_write_u32_le(bmp + 34, (uint32_t)pixel_bytes);
    uint32_t channels = (uint32_t)page->pixel_format;
    for (uint32_t y = 0; y < page->height; y++) {
        uint32_t source_y = page->height - 1u - y;
        const uint8_t *source = page->pixels +
            (size_t)source_y * page->width * channels;
        uint8_t *target = bmp + 54u + (size_t)y * (size_t)row_bytes;
        for (uint32_t x = 0; x < page->width; x++) {
            target[x * 3u] = source[x * channels + 2u];
            target[x * 3u + 1u] = source[x * channels + 1u];
            target[x * 3u + 2u] = source[x * channels];
        }
    }
    return true;
}

#if defined(_WIN32) || defined(__linux__)
static bool present_bmp_encode(
    const struct zcl_present_window_v1 *page,
    uint8_t **encoded, size_t *encoded_len)
{
    size_t required = 0;
    if (!encoded || !encoded_len ||
        !zcl_present_bitmap_encode_bmp_v1(
            page, NULL, 0u, &required))
        return false;
    uint8_t *bmp = malloc(required); // raw-alloc-ok:standalone-presentation-package
    if (!bmp) return false;
    if (!zcl_present_bitmap_encode_bmp_v1(
            page, bmp, required, encoded_len)) {
        free(bmp);
        return false;
    }
    *encoded = bmp;
    return true;
}
#endif

#if defined(__linux__)
static uint8_t *present_x11_clipboard_bmp;
static size_t present_x11_clipboard_bmp_len;
static uint8_t *present_x11_clipboard_png;
static size_t present_x11_clipboard_png_len;

int present_x11_clipboard_append_targets(
    void *display_ptr, unsigned long *targets, int count, int capacity)
{
    Display *display = display_ptr;
    if (!display || !targets || count < 0 || count >= capacity ||
        (!present_x11_clipboard_bmp || !present_x11_clipboard_png))
        return count;
    targets[count++] = XInternAtom(display, "image/png", False);
    if (count >= capacity) return count;
    targets[count++] = XInternAtom(display, "image/bmp", False);
    return count;
}

int present_x11_clipboard_write_target(
    void *display_ptr, unsigned long requestor_value,
    unsigned long target_value, unsigned long property_value)
{
    Display *display = display_ptr;
    Atom target = (Atom)target_value;
    Atom image_png = display
        ? XInternAtom(display, "image/png", False) : None;
    Atom image_bmp = display
        ? XInternAtom(display, "image/bmp", False) : None;
    const uint8_t *data = target == image_png
        ? present_x11_clipboard_png
        : (target == image_bmp ? present_x11_clipboard_bmp : NULL);
    size_t data_len = target == image_png
        ? present_x11_clipboard_png_len : present_x11_clipboard_bmp_len;
    if (!display || !data || data_len > INT_MAX)
        return 0;
    (void)XChangeProperty(
        display, (Window)requestor_value, (Atom)property_value,
        target, 8, PropModeReplace, data, (int)data_len);
    return 1;
}
#endif

static bool present_png_encode(
    const struct zcl_present_window_v1 *page,
    uint8_t **encoded, size_t *encoded_len)
{
    size_t required = 0;
    bool sized = page && encoded && encoded_len &&
        (page->pixel_format == ZCL_PRESENT_RGB8
            ? png_encode_rgb(page->pixels, page->width, page->height,
                             NULL, 0u, &required)
            : png_encode_rgba(page->pixels, page->width, page->height,
                              NULL, 0u, &required));
    if (!sized) return false;
    uint8_t *png = malloc(required); // raw-alloc-ok:standalone-presentation-package
    if (!png) return false;
    bool ok = page->pixel_format == ZCL_PRESENT_RGB8
        ? png_encode_rgb(page->pixels, page->width, page->height,
                         png, required, encoded_len)
        : png_encode_rgba(page->pixels, page->width, page->height,
                          png, required, encoded_len);
    if (!ok) {
        free(png);
        return false;
    }
    *encoded = png;
    return true;
}

#if defined(_WIN32)
static bool present_clipboard_write_win32(
    const struct zcl_present_window_v1 *page, uint8_t *png, size_t png_len)
{
    uint8_t *bmp = NULL;
    size_t bmp_len = 0;
    if (!present_bmp_encode(page, &bmp, &bmp_len)) {
        free(png);
        return false;
    }
    if (bmp_len <= 14u || !OpenClipboard(_RGFW->root->src.window)) {
        free(bmp);
        free(png);
        return false;
    }
    HGLOBAL storage = GlobalAlloc(GMEM_MOVEABLE, bmp_len - 14u);
    void *destination = storage ? GlobalLock(storage) : NULL;
    if (!destination) {
        if (storage) GlobalFree(storage);
        CloseClipboard();
        free(bmp);
        free(png);
        return false;
    }
    memcpy(destination, bmp + 14u, bmp_len - 14u);
    GlobalUnlock(storage);
    EmptyClipboard();
    bool dib_ok = SetClipboardData(CF_DIB, storage) != NULL;
    if (!dib_ok) GlobalFree(storage);
    HGLOBAL png_storage = GlobalAlloc(GMEM_MOVEABLE, png_len);
    void *png_destination = png_storage ? GlobalLock(png_storage) : NULL;
    bool png_ok = false;
    if (png_destination) {
        memcpy(png_destination, png, png_len);
        GlobalUnlock(png_storage);
        UINT png_format = RegisterClipboardFormatA("PNG");
        png_ok = png_format != 0u &&
                 SetClipboardData(png_format, png_storage) != NULL;
    }
    if (!png_ok && png_storage) GlobalFree(png_storage);
    CloseClipboard();
    free(bmp);
    free(png);
    return dib_ok || png_ok;
}
#elif defined(__APPLE__)
static bool present_clipboard_write_apple(
    const struct zcl_present_window_v1 *page, uint8_t *png, size_t png_len)
{
    (void)page;
    id pasteboard = NSPasteboard_generalPasteboard();
    NSPasteboardType types[] = {"public.png", NULL};
    NSPasteBoard_declareTypes(pasteboard, types, 1u, NULL);
    id data = ((id (*)(id, SEL, const void *, NSUInteger))objc_msgSend)(
        (id)objc_getClass("NSData"),
        sel_registerName("dataWithBytes:length:"), png,
        (NSUInteger)png_len);
    bool ok = data && ((bool (*)(id, SEL, id, id))objc_msgSend)(
        pasteboard, sel_registerName("setData:forType:"), data,
        NSString_stringWithUTF8String("public.png"));
    free(png);
    return ok;
}
#elif defined(__linux__)
static bool present_clipboard_write_x11(
    const struct zcl_present_window_v1 *page, uint8_t *png, size_t png_len)
{
    uint8_t *bmp = NULL;
    size_t bmp_len = 0;
    if (!present_bmp_encode(page, &bmp, &bmp_len)) {
        free(png);
        return false;
    }
    Display *display = (Display *)RGFW_getDisplay_X11();
    if (!display || !_RGFW || !_RGFW->helperWindow) {
        free(bmp);
        free(png);
        return false;
    }
    free(present_x11_clipboard_bmp);
    present_x11_clipboard_bmp = bmp;
    present_x11_clipboard_bmp_len = bmp_len;
    free(present_x11_clipboard_png);
    present_x11_clipboard_png = png;
    present_x11_clipboard_png_len = png_len;
    Atom clipboard = XInternAtom(display, "CLIPBOARD", False);
    XSetSelectionOwner(display, clipboard, _RGFW->helperWindow, CurrentTime);
    XFlush(display);
    return XGetSelectionOwner(display, clipboard) == _RGFW->helperWindow;
}
#endif

static bool present_clipboard_write_image(
    const struct zcl_present_window_v1 *page)
{
    uint8_t *png = NULL;
    size_t png_len = 0;
    if (!present_png_encode(page, &png, &png_len)) return false;
#if defined(_WIN32)
    return present_clipboard_write_win32(page, png, png_len);
#elif defined(__APPLE__)
    return present_clipboard_write_apple(page, png, png_len);
#elif defined(__linux__)
    return present_clipboard_write_x11(page, png, png_len);
#else
    free(png);
    return false;
#endif
}

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

static bool present_hover_items_valid(
    const struct zcl_present_window_hover_v1 *hover)
{
    for (uint32_t i = 0; i < hover->item_count; i++) {
        if (hover->items[i].x < hover->plot_left ||
            hover->items[i].x > hover->plot_right ||
            (i > 0 && hover->items[i - 1u].x > hover->items[i].x) ||
            !hover->items[i].text ||
            !bounded_text(hover->items[i].text,
                          ZCL_PRESENT_WINDOW_HOVER_TEXT_MAX))
            return false;
    }
    return true;
}

static bool present_hover_validate(
    const struct zcl_present_window_v1 *request,
    const struct zcl_present_window_hover_v1 *hover,
    char *error, size_t error_cap)
{
    if (!hover || hover->struct_size != sizeof(*hover) ||
        hover->abi_version != ZCL_PRESENT_ABI_V1 || !hover->items ||
        hover->item_count == 0 ||
        hover->item_count > ZCL_PRESENT_WINDOW_HOVER_ITEMS_MAX)
        return present_error(error, error_cap,
                             "presentation hover ABI/count is invalid");
    if (hover->plot_left >= hover->plot_right ||
        hover->plot_top >= hover->plot_bottom ||
        hover->plot_right > request->width ||
        hover->plot_bottom > request->height)
        return present_error(error, error_cap,
                             "presentation hover plot bounds are invalid");
    if (!present_hover_items_valid(hover))
        return present_error(error, error_cap,
                             "presentation hover item is invalid");
    return true;
}

static void present_hover_draw_text(
    struct zcl_present_canvas *canvas, int32_t panel_x, int32_t panel_y,
    const char *text)
{
    const struct zcl_present_color primary = {242, 247, 255};
    const struct zcl_present_color secondary = {169, 186, 207};
    const char *separator = strchr(text, '\n');
    size_t first_len = separator
        ? (size_t)(separator - text) : strlen(text);
    zcl_present_canvas_text_strong(canvas, panel_x + 14, panel_y + 10,
                                   text, first_len, 24u, primary);
    if (separator && separator[1])
        zcl_present_canvas_text_strong(
            canvas, panel_x + 14, panel_y + 47,
            separator + 1, strlen(separator + 1), 19u, secondary);
}

static void present_hover_draw(
    uint8_t *pixels, size_t pixels_cap,
    const struct zcl_present_window_v1 *page,
    const struct zcl_present_window_hover_v1 *hover, uint32_t item_index)
{
    if (!pixels || !page || !hover || item_index >= hover->item_count ||
        page->pixel_format != ZCL_PRESENT_RGB8)
        return;
    struct zcl_present_canvas canvas;
    if (!zcl_present_canvas_init(&canvas, pixels, pixels_cap,
                                 page->width, page->height))
        return;
    const struct zcl_present_window_hover_item_v1 *item =
        &hover->items[item_index];
    const struct zcl_present_color crosshair = {112, 240, 216};
    const struct zcl_present_color panel = {15, 24, 39};
    const struct zcl_present_color border = {76, 104, 134};
    zcl_present_canvas_line(&canvas, (int32_t)item->x,
                            (int32_t)hover->plot_top,
                            (int32_t)item->x,
                            (int32_t)hover->plot_bottom, crosshair);
    uint32_t panel_width = page->width > 936u ? 920u
        : (page->width > 16u ? page->width - 16u : page->width);
    uint32_t panel_height = 88u;
    int32_t panel_x = hover->plot_left + panel_width <= page->width
        ? (int32_t)hover->plot_left : 8;
    if ((uint32_t)panel_x + panel_width > page->width)
        panel_x = page->width > panel_width + 8u
            ? (int32_t)(page->width - panel_width - 8u) : 0;
    int32_t panel_y = hover->plot_top >= panel_height + 20u
        ? (int32_t)(hover->plot_top - panel_height - 12u)
        : (int32_t)hover->plot_top + 12;
    zcl_present_canvas_fill_rect(&canvas, panel_x, panel_y,
                                 panel_width, panel_height, panel);
    zcl_present_canvas_stroke_rect(&canvas, panel_x, panel_y,
                                   panel_width, panel_height, 1u, border);
    present_hover_draw_text(&canvas, panel_x, panel_y, item->text);
}

static const char *present_window_bitmap_problem(
    const struct zcl_present_window_v1 *request)
{
    if (!request->pixels || request->width == 0 || request->height == 0 ||
        request->width > ZCL_PRESENT_DIMENSION_MAX ||
        request->height > ZCL_PRESENT_DIMENSION_MAX)
        return "presentation bitmap dimensions are invalid";
    if (request->pixel_format != ZCL_PRESENT_RGB8 &&
        request->pixel_format != ZCL_PRESENT_RGBA8)
        return "presentation pixel format is unsupported";
    uint64_t pixel_bytes = (uint64_t)request->width * request->height *
                           (uint32_t)request->pixel_format;
    if (pixel_bytes == 0 || pixel_bytes > SIZE_MAX)
        return "presentation bitmap size overflows";
    return NULL;
}

static const char *present_window_icon_problem(
    const struct zcl_present_window_v1 *request)
{
    bool any_icon = request->icon_rgba || request->icon_width ||
                    request->icon_height;
    bool complete_icon = request->icon_rgba && request->icon_width > 0 &&
                         request->icon_height > 0 &&
                         request->icon_width <= 256u &&
                         request->icon_height <= 256u;
    if (any_icon && !complete_icon)
        return "presentation icon is incomplete or oversized";
    return NULL;
}

static const char *present_window_problem(
    const struct zcl_present_window_v1 *request)
{
    if (!request || request->struct_size != sizeof(*request) ||
        request->abi_version != ZCL_PRESENT_ABI_V1)
        return "presentation ABI/structure mismatch";
    if (!bounded_text(request->title, ZCL_PRESENT_TITLE_MAX))
        return "presentation title is oversized";
    if (!bounded_text(request->copy_text, ZCL_PRESENT_COPY_TEXT_MAX))
        return "presentation clipboard text is oversized";
    const char *bitmap = present_window_bitmap_problem(request);
    if (bitmap) return bitmap;
    return present_window_icon_problem(request);
}

bool zcl_present_window_validate_v1(
    const struct zcl_present_window_v1 *request,
    char *error, size_t error_cap)
{
    const char *problem = present_window_problem(request);
    if (problem) return present_error(error, error_cap, problem);
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

static uint8_t *present_overlay_pixels(
    const struct zcl_present_window_v1 *page,
    const struct zcl_present_window_form_v1 *form,
    const struct zcl_present_window_canvas_v1 *canvas,
    const struct zcl_present_window_hover_v1 *hover,
    uint32_t focused_control, uint32_t hover_index, bool required_invalid)
{
    uint8_t *overlay_pixels = NULL;
    uint64_t bytes = (uint64_t)page->width * page->height *
                     (uint32_t)page->pixel_format;
    if (bytes == 0 || bytes > SIZE_MAX) return NULL;
    overlay_pixels = malloc((size_t)bytes); // raw-alloc-ok:standalone-presentation-package
    if (!overlay_pixels) return NULL;
    memcpy(overlay_pixels, page->pixels, (size_t)bytes);
    if (form)
        zcl_present_form_draw_state_internal(
            overlay_pixels, (size_t)bytes, form, focused_control,
            required_invalid);
    else if (canvas)
        zcl_present_canvas_draw_state_internal(
            overlay_pixels, (size_t)bytes, canvas, focused_control);
    else
        present_hover_draw(overlay_pixels, (size_t)bytes, page, hover,
                           hover_index);
    return overlay_pixels;
}

static uint8_t *present_owned_replacement(
    const struct zcl_present_window_v1 *page, uint8_t *overlay_pixels)
{
    uint8_t *replacement_pixels = overlay_pixels;
    uint64_t bytes = (uint64_t)page->width * page->height *
                     (uint32_t)page->pixel_format;
    if (replacement_pixels) return replacement_pixels;
    if (bytes == 0 || bytes > SIZE_MAX) return NULL;
    replacement_pixels = malloc((size_t)bytes); // raw-alloc-ok:standalone-presentation-package
    if (!replacement_pixels) return NULL;
    memcpy(replacement_pixels, page->pixels, (size_t)bytes);
    return replacement_pixels;
}

static bool present_scaled_replacement(
    const struct zcl_present_window_v1 *page, i32 width, i32 height,
    uint8_t *overlay_pixels, uint8_t **replacement)
{
    bool scaled = present_scale_bitmap(page, width, height, replacement);
    free(overlay_pixels);
    return scaled;
}

static bool present_action_focus(
    const struct zcl_present_window_form_v1 *form,
    const struct zcl_present_window_canvas_v1 *canvas,
    uint32_t action_count, uint32_t focused_control,
    uint32_t *focused_action)
{
    bool action_focused = action_count > 0;
    *focused_action = focused_control;
    if (form) {
        action_focused = focused_control >= form->field_count;
        *focused_action = action_focused
            ? focused_control - form->field_count : UINT32_MAX;
    } else if (canvas) {
        action_focused = focused_control > 0;
        *focused_action = action_focused
            ? focused_control - 1u : UINT32_MAX;
    }
    return action_focused;
}

static bool present_swap_surface(
    RGFW_window *window, const struct zcl_present_window_v1 *page,
    i32 width, i32 height, bool owned, uint8_t *replacement_pixels,
    uint32_t action_count, uint32_t focused_control,
    const struct zcl_present_window_form_v1 *form,
    const struct zcl_present_window_canvas_v1 *canvas,
    RGFW_surface **surface, uint8_t **scaled_pixels)
{
    uint8_t *pixels = owned ? replacement_pixels
        : (uint8_t *)(uintptr_t)page->pixels;
    uint32_t focused_action = 0;
    if (present_action_focus(form, canvas, action_count, focused_control,
                             &focused_action))
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

static bool present_replace_surface(
    RGFW_window *window, const struct zcl_present_window_v1 *page,
    i32 width, i32 height, RGFW_surface **surface,
    uint8_t **scaled_pixels, uint32_t action_count,
    uint32_t focused_control,
    const struct zcl_present_window_form_v1 *form,
    const struct zcl_present_window_canvas_v1 *canvas,
    const struct zcl_present_window_hover_v1 *hover,
    uint32_t hover_index,
    bool required_invalid)
{
    uint8_t *replacement_pixels = NULL;
    bool scaled = width != (i32)page->width || height != (i32)page->height;
    bool owned = scaled || action_count > 0 || form || canvas || hover;
    uint8_t *overlay_pixels = NULL;
    struct zcl_present_window_v1 overlay_page = *page;
    if (form || canvas || hover) {
        overlay_pixels = present_overlay_pixels(
            page, form, canvas, hover, focused_control, hover_index,
            required_invalid);
        if (!overlay_pixels) return false;
        overlay_page.pixels = overlay_pixels;
        page = &overlay_page;
    }
    if (scaled) {
        if (!present_scaled_replacement(page, width, height,
                                        overlay_pixels, &replacement_pixels))
            return false;
    } else if (owned) {
        replacement_pixels = present_owned_replacement(page, overlay_pixels);
        if (!replacement_pixels) return false;
    }
    return present_swap_surface(window, page, width, height, owned,
                                replacement_pixels, action_count,
                                focused_control, form, canvas, surface,
                                scaled_pixels);
}

static bool present_redraw(
    RGFW_window *window, const struct zcl_present_window_v1 *page,
    RGFW_surface **surface, uint8_t **scaled_pixels,
    uint32_t action_count, uint32_t focused_control,
    const struct zcl_present_window_form_v1 *form,
    const struct zcl_present_window_canvas_v1 *canvas,
    const struct zcl_present_window_hover_v1 *hover,
    uint32_t hover_index,
    bool required_invalid)
{
    i32 width = 0, height = 0;
    (void)RGFW_window_getSize(window, &width, &height);
    if (!present_replace_surface(
            window, page, width, height, surface, scaled_pixels,
            action_count, focused_control, form, canvas, hover, hover_index,
            required_invalid))
        return false;
    RGFW_window_blitSurface(window, *surface);
    return true;
}

static void present_live_pump(
    const struct zcl_present_window_live_view_v1 *live, uint32_t action_count,
    RGFW_window *window, const struct zcl_present_window_v1 *page,
    RGFW_surface **surface, uint8_t **scaled_pixels,
    struct zcl_present_window_form_v1 *form, uint32_t focus,
    bool required_invalid, struct zcl_present_window_event_v1 *event,
    bool paint)
{
    if (!live) return;
    bool redraw = false, close = false;
    live->owner.update(live->owner.context, event, RGFW_window_shouldClose(window),
                 &redraw, &close);
    if (redraw) RGFW_window_setName(window, page->title ? page->title : "ZClassic23");
    if (redraw && paint)
        (void)present_redraw(window, page, surface, scaled_pixels, action_count,
            focus, form, NULL, NULL, UINT32_MAX, required_invalid);
    RGFW_window_setShouldClose(window, close);
    if (!close) {
        event->outcome = ZCL_PRESENT_WINDOW_DISMISSED;
        event->action_index = UINT32_MAX;
    }
}

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

static bool present_live_input(const struct zcl_present_window_live_view_v1 *live,
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

static bool present_copy_feedback_bad_args(
    RGFW_window *window, const struct zcl_present_window_v1 *page,
    const struct zcl_present_window_copy_v1 *copy,
    RGFW_surface **surface, uint8_t *scaled_pixels)
{
    return !window || !page || !copy || !surface || !*surface ||
        !scaled_pixels || page->pixel_format != ZCL_PRESENT_RGB8;
}

static bool present_show_copy_feedback(
    RGFW_window *window, const struct zcl_present_window_v1 *page,
    const struct zcl_present_window_copy_v1 *copy,
    RGFW_surface **surface, uint8_t *scaled_pixels)
{
    if (present_copy_feedback_bad_args(window, page, copy, surface,
                                       scaled_pixels))
        return false;
    i32 width = 0, height = 0;
    (void)RGFW_window_getSize(window, &width, &height);
    if (width <= 0 || height <= 0) return false;
    uint32_t draw_width = (uint32_t)width;
    uint32_t draw_height = (uint32_t)((uint64_t)draw_width * page->height /
                                      page->width);
    if (draw_height > (uint32_t)height) {
        draw_height = (uint32_t)height;
        draw_width = (uint32_t)((uint64_t)draw_height * page->width /
                                page->height);
    }
    uint32_t x0 = ((uint32_t)width - draw_width) / 2u;
    uint32_t y0 = ((uint32_t)height - draw_height) / 2u;
    uint32_t left = x0 + (uint32_t)((uint64_t)copy->left * draw_width /
                                    page->width);
    uint32_t top = y0 + (uint32_t)((uint64_t)copy->top * draw_height /
                                   page->height);
    uint32_t right = x0 + (uint32_t)((uint64_t)copy->right * draw_width /
                                     page->width);
    uint32_t bottom = y0 + (uint32_t)((uint64_t)copy->bottom * draw_height /
                                      page->height);
    if (right <= left || bottom <= top) return false;
    struct zcl_present_canvas canvas;
    if (!zcl_present_canvas_init(
            &canvas, scaled_pixels, (size_t)(uint32_t)width *
                                      (uint32_t)height * 3u,
            (uint32_t)width, (uint32_t)height))
        return false;
    const struct zcl_present_color bright = {72, 240, 197};
    const struct zcl_present_color deep = {8, 66, 63};
    const struct zcl_present_color white = {255, 255, 255};
    zcl_present_canvas_fill_vertical_gradient(
        &canvas, (int32_t)left, (int32_t)top,
        right - left, bottom - top, bright, deep);
    zcl_present_canvas_stroke_rect(
        &canvas, (int32_t)left, (int32_t)top,
        right - left, bottom - top, 2u, white);
    uint32_t font_size = (uint32_t)((uint64_t)17u * draw_height /
                                    page->height);
    if (font_size < 12u) font_size = 12u;
    if (font_size > 24u) font_size = 24u;
    zcl_present_canvas_text_strong(
        &canvas, (int32_t)left + (int32_t)((right - left) / 8u),
        (int32_t)top + (int32_t)((bottom - top) / 5u),
        "COPIED!  PASTE NOW", 18u, font_size, white);
    RGFW_surface *replacement = RGFW_window_createSurface(
        window, scaled_pixels, width, height, RGFW_formatRGB8);
    if (!replacement) return false;
    RGFW_surface_free(*surface);
    *surface = replacement;
    RGFW_window_blitSurface(window, *surface);
    return true;
}

static bool present_form_geometry(
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_form_v1 *form, uint32_t action_count,
    char *error, size_t error_cap)
{
    return !form || (zcl_present_window_form_validate_v1(form, error, error_cap) &&
        action_count == 2u && pages->page_count == 1u &&
        pages->pages[0].pixel_format == ZCL_PRESENT_RGB8 &&
        pages->pages[0].width == ZCL_PRESENT_MODEL_BITMAP_WIDTH &&
        pages->pages[0].height == ZCL_PRESENT_MODEL_BITMAP_HEIGHT);
}

static bool present_canvas_geometry(const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_canvas_v1 *canvas, uint32_t action_count,
    char *error, size_t error_cap)
{
    return !canvas || (zcl_present_window_canvas_validate_v1(canvas, error, error_cap) &&
        action_count == 2u && pages->page_count == 1u &&
        pages->pages[0].pixel_format == ZCL_PRESENT_RGB8 &&
        pages->pages[0].width == ZCL_PRESENT_MODEL_BITMAP_WIDTH &&
        pages->pages[0].height == ZCL_PRESENT_MODEL_BITMAP_HEIGHT);
}

static const char *present_hover_problem(
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_hover_v1 *hovers,
    uint32_t action_count, bool hovers_first_page_only,
    uint32_t initial_page, char *error, size_t error_cap)
{
    if (action_count != 0)
        return "presentation hover geometry/actions are invalid";
    if (hovers_first_page_only && initial_page != 0u)
        return "presentation initial page is invalid";
    uint32_t hover_page_count =
        hovers_first_page_only ? 1u : pages->page_count;
    for (uint32_t i = 0; i < hover_page_count; i++)
        if (pages->pages[i].pixel_format != ZCL_PRESENT_RGB8 ||
            !present_hover_validate(
                &pages->pages[i], &hovers[i], error, error_cap))
            return "presentation hover geometry/actions are invalid";
    return NULL;
}

static bool present_copy_bounds_invalid(
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_copy_v1 *copy)
{
    return copy->struct_size != sizeof(*copy) ||
           copy->abi_version != ZCL_PRESENT_ABI_V1 ||
           copy->left >= copy->right || copy->top >= copy->bottom ||
           copy->right > pages->pages[0].width ||
           copy->bottom > pages->pages[0].height;
}

static bool present_controls_conflict(
    const struct zcl_present_window_form_v1 *form,
    const struct zcl_present_window_canvas_v1 *canvas,
    const struct zcl_present_window_hover_v1 *hovers)
{
    return (form && canvas) || ((form || canvas) && hovers);
}

static const char *present_pages_problem(
    const struct zcl_present_window_pages_v1 *pages,
    uint32_t action_count,
    const struct zcl_present_window_form_v1 *form,
    const struct zcl_present_window_canvas_v1 *canvas,
    const struct zcl_present_window_hover_v1 *hovers,
    bool hovers_first_page_only,
    uint32_t initial_page,
    const struct zcl_present_window_copy_v1 *copy,
    const struct zcl_present_window_live_view_v1 *live,
    char *error, size_t error_cap)
{
    if (initial_page >= pages->page_count)
        return "presentation initial page is invalid";
    if (copy && present_copy_bounds_invalid(pages, copy))
        return "presentation image-copy bounds are invalid";
    if (present_controls_conflict(form, canvas, hovers))
        return "presentation controls are mutually exclusive";
    if (!present_form_geometry(pages, form, action_count, error, error_cap))
        return "presentation form geometry/actions are invalid";
    if (live && !live->owner.update)
        return "presentation live form owner is invalid";
    if (!present_canvas_geometry(pages, canvas, action_count, error,
                                 error_cap))
        return "presentation canvas geometry/actions are invalid";
    if (hovers)
        return present_hover_problem(pages, hovers, action_count,
                                     hovers_first_page_only, initial_page,
                                     error, error_cap);
    return NULL;
}

#if defined(_WIN32) || defined(__APPLE__) || defined(__linux__)
/* Everything one native pages window needs while its event loop runs. */
struct present_pages_run {
    RGFW_window *window;
    RGFW_surface *surface;
    uint8_t *scaled_pixels;
    const struct zcl_present_window_pages_v1 *pages;
    uint32_t action_count;
    struct zcl_present_window_form_v1 *form;
    struct zcl_present_window_canvas_v1 *canvas;
    const struct zcl_present_window_hover_v1 *hovers;
    bool hovers_first_page_only;
    const struct zcl_present_window_copy_v1 *copy;
    const struct zcl_present_window_live_view_v1 *live;
    struct zcl_present_window_event_v1 *result;
    const struct zcl_present_window_v1 *request;
    const struct zcl_present_window_hover_v1 *hover;
    uint32_t current_page;
    uint32_t hover_index;
    uint32_t focused_control;
    bool required_invalid;
};

static uint32_t present_pages_initial_focus(
    const struct zcl_present_window_form_v1 *form,
    const struct zcl_present_window_live_view_v1 *live)
{
    uint32_t focused_control = live && live->input ? UINT32_MAX : 0;
    if (form) {
        while (focused_control < form->field_count &&
               (form->fields[focused_control].flags &
                ZCL_PRESENT_WINDOW_FORM_READ_ONLY))
            focused_control++;
        if (focused_control == form->field_count)
            focused_control = form->field_count;
    }
    return focused_control;
}

static const char *present_pages_open(struct present_pages_run *run)
{
    const struct zcl_present_window_v1 *request = run->request;
#if defined(__linux__)
    const char *display = getenv("DISPLAY");
    if (!display || !display[0])
        return "cannot open the desktop display (DISPLAY is unset)";
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
    run->window = RGFW_createWindow(
        title, 0, 0, (i32)request->width, (i32)request->height, flags);
    if (!run->window)
        return "native window creation failed";
    RGFW_window_setMinSize(run->window, 260, 300);

#if defined(__linux__)
    present_set_linux_desktop_identity(run->window);
#endif

    if (request->icon_rgba) {
        (void)RGFW_window_setIcon(
            run->window, (u8 *)(uintptr_t)request->icon_rgba,
            (i32)request->icon_width, (i32)request->icon_height,
            RGFW_formatRGBA8);
    }
    run->focused_control = present_pages_initial_focus(run->form, run->live);
    run->hover_index = (run->hover && !run->hovers_first_page_only)
        ? run->hover->item_count - 1u : UINT32_MAX;
    run->required_invalid = false;
    if (!present_replace_surface(run->window, request,
                                 (i32)request->width,
                                 (i32)request->height,
                                 &run->surface, &run->scaled_pixels,
                                 run->action_count, run->focused_control,
                                 run->form, run->canvas, run->hover,
                                 run->hover_index, run->required_invalid)) {
        RGFW_window_close(run->window);
        return "native bitmap surface creation failed";
    }

    RGFW_window_setExitKey(run->window, RGFW_escape);
    RGFW_window_blitSurface(run->window, run->surface);
    return NULL;
}

static bool present_pages_redraw(struct present_pages_run *run,
    uint32_t focus, uint32_t hover_index)
{
    return present_redraw(run->window, run->request, &run->surface,
                          &run->scaled_pixels, run->action_count, focus,
                          run->form, run->canvas, run->hover, hover_index,
                          run->required_invalid);
}

static void present_pages_pump(struct present_pages_run *run, bool paint)
{
    present_live_pump(run->live, run->action_count, run->window,
                      run->request, &run->surface, &run->scaled_pixels,
                      run->form, run->focused_control, run->required_invalid,
                      run->result, paint);
}

static void present_pages_finish(struct present_pages_run *run,
    uint32_t action)
{
    run->result->outcome = ZCL_PRESENT_WINDOW_ACTION;
    run->result->action_index = action;
    RGFW_window_setShouldClose(run->window, RGFW_TRUE);
}

static void present_pages_copy_image(struct present_pages_run *run)
{
    bool copied = present_clipboard_write_image(run->request);
    RGFW_window_setName(
        run->window, copied ? "Z23 C23 Growth — Image copied"
                            : "Z23 C23 Growth — Copy unavailable");
    if (copied)
        (void)present_show_copy_feedback(
            run->window, run->request, run->copy, &run->surface,
            run->scaled_pixels);
}

static void present_pages_action_click(struct present_pages_run *run,
    uint32_t action)
{
    if (run->form && action == 1u &&
        !zcl_present_form_required_complete_internal(run->form)) {
        run->required_invalid = true;
        run->focused_control = run->form->field_count + action;
        (void)present_pages_redraw(run, run->focused_control,
                                   run->hover_index);
    } else {
        present_pages_finish(run, action);
    }
}

static void present_pages_canvas_click(struct present_pages_run *run,
    i32 window_width, i32 window_height, i32 mouse_x, i32 mouse_y)
{
    uint32_t point_x = 0, point_y = 0;
    if (!zcl_present_window_canvas_point_at_v1(
            run->request->width, run->request->height,
            window_width, window_height, mouse_x, mouse_y,
            &point_x, &point_y))
        return;
    struct zcl_present_window_canvas_point_v1 *point =
        &run->canvas->points[run->canvas->editable_index];
    point->x = point_x;
    point->y = point_y;
    run->focused_control = 0;
    (void)present_pages_redraw(run, run->focused_control, run->hover_index);
}

static void present_pages_pointer(struct present_pages_run *run,
    const RGFW_event *event)
{
    i32 window_width = 0, window_height = 0;
    i32 mouse_x = 0, mouse_y = 0;
    uint32_t action = UINT32_MAX;
    if (event->type != RGFW_mouseButtonPressed ||
        event->button.value != RGFW_mouseLeft)
        return;
    (void)RGFW_window_getSize(run->window, &window_width, &window_height);
    bool has_mouse = RGFW_window_getMouse(run->window, &mouse_x, &mouse_y);
    if (has_mouse && run->copy && zcl_present_window_copy_at_v1(
            run->copy, run->request->width, run->request->height,
            window_width, window_height, mouse_x, mouse_y)) {
        present_pages_copy_image(run);
    } else if (has_mouse &&
        zcl_present_window_action_at_v1(
            run->request->width, run->request->height,
            window_width, window_height, mouse_x, mouse_y,
            run->action_count, &action)) {
        present_pages_action_click(run, action);
    } else if (run->canvas) {
        present_pages_canvas_click(run, window_width, window_height,
                                   mouse_x, mouse_y);
    }
}

static bool present_pages_hover_live(const struct present_pages_run *run)
{
    return run->hover &&
           (!run->hovers_first_page_only || run->current_page == 0u);
}

static int32_t present_pages_hover_key_step(const RGFW_event *event,
    uint32_t item_count, bool *absolute, uint32_t *next_hover)
{
    if (event->key.value == RGFW_right || event->key.value == RGFW_down)
        return 1;
    if (event->key.value == RGFW_left || event->key.value == RGFW_up)
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

static int32_t present_pages_hover_step(const RGFW_event *event,
    uint32_t item_count, bool *absolute, uint32_t *next_hover)
{
    if (event->type == RGFW_mouseScroll && event->scroll.y < 0) return 1;
    if (event->type == RGFW_mouseScroll && event->scroll.y > 0) return -1;
    if (event->type != RGFW_keyPressed) return 0;
    return present_pages_hover_key_step(event, item_count, absolute,
                                        next_hover);
}

static void present_pages_hover_scroll(struct present_pages_run *run,
    const RGFW_event *event)
{
    bool absolute = false;
    uint32_t next_hover = run->hover_index;
    if (!run->hover || run->hovers_first_page_only) return;
    if (event->type != RGFW_mouseScroll && event->type != RGFW_keyPressed)
        return;
    int32_t step = present_pages_hover_step(event, run->hover->item_count,
                                            &absolute, &next_hover);
    bool moved = absolute || (step != 0 &&
        zcl_present_window_hover_step_v1(
            run->hover_index, run->hover->item_count, step, &next_hover));
    if (moved && next_hover != run->hover_index &&
        present_pages_redraw(run, run->focused_control, next_hover))
        run->hover_index = next_hover;
}

static void present_pages_hover_pointer(struct present_pages_run *run,
    const RGFW_event *event)
{
    i32 window_width = 0, window_height = 0;
    i32 mouse_x = 0, mouse_y = 0;
    uint32_t next_hover = UINT32_MAX;
    if (!present_pages_hover_live(run) ||
        event->type != RGFW_mousePosChanged)
        return;
    (void)RGFW_window_getSize(run->window, &window_width, &window_height);
    if (RGFW_window_getMouse(run->window, &mouse_x, &mouse_y))
        (void)zcl_present_window_hover_at_v1(
            run->hover, run->request->width, run->request->height,
            window_width, window_height, mouse_x, mouse_y, &next_hover);
    if (next_hover != UINT32_MAX && next_hover != run->hover_index &&
        present_pages_redraw(run, run->focused_control, next_hover))
        run->hover_index = next_hover;
}

static void present_pages_resize(struct present_pages_run *run,
    const RGFW_event *event)
{
    if (event->type == RGFW_windowResized) {
        i32 resized_width = 0;
        i32 resized_height = 0;
        (void)RGFW_window_getSize(run->window, &resized_width,
                                  &resized_height);
        bool live_hover = present_pages_hover_live(run);
        (void)present_replace_surface(
            run->window, run->request, resized_width, resized_height,
            &run->surface, &run->scaled_pixels, run->action_count,
            run->focused_control, run->form, run->canvas,
            live_hover ? run->hover : NULL,
            live_hover ? run->hover_index : UINT32_MAX,
            run->required_invalid);
        RGFW_window_blitSurface(run->window, run->surface);
    } else if (event->type == RGFW_windowRefresh) {
        RGFW_window_blitSurface(run->window, run->surface);
    }
}

static bool present_pages_live_event(struct present_pages_run *run,
    RGFW_event *event)
{
    if (!present_live_input(run->live, run->window, run->request, event,
                            run->action_count, &run->focused_control,
                            run->result))
        return false;
    present_pages_pump(run, true);
    return true;
}

static void present_pages_key_page(const struct present_pages_run *run,
    const RGFW_event *event, uint32_t *next_page)
{
    if (event->key.value == RGFW_pageDown || event->key.value == RGFW_down ||
        event->key.value == RGFW_right)
        (void)zcl_present_window_page_step_v1(
            run->current_page, run->pages->page_count, 1, next_page);
    else if (event->key.value == RGFW_pageUp ||
             event->key.value == RGFW_up || event->key.value == RGFW_left)
        (void)zcl_present_window_page_step_v1(
            run->current_page, run->pages->page_count, -1, next_page);
    else if (event->key.value == RGFW_home)
        *next_page = 0;
    else if (event->key.value == RGFW_end)
        *next_page = run->pages->page_count - 1u;
}

static void present_pages_plain_page(const struct present_pages_run *run,
    const RGFW_event *event, uint32_t *next_page)
{
    if (event->type == RGFW_mouseScroll && event->scroll.y < 0)
        (void)zcl_present_window_page_step_v1(
            run->current_page, run->pages->page_count, 1, next_page);
    else if (event->type == RGFW_mouseScroll && event->scroll.y > 0)
        (void)zcl_present_window_page_step_v1(
            run->current_page, run->pages->page_count, -1, next_page);
    else if (event->type == RGFW_keyPressed)
        present_pages_key_page(run, event, next_page);
}

static uint32_t present_pages_next_page(const struct present_pages_run *run,
    const RGFW_event *event)
{
    uint32_t next_page = run->current_page;
    int32_t render_delta = 0;
    if (run->hovers && !run->hovers_first_page_only &&
        event->type == RGFW_keyPressed &&
        zcl_present_window_hover_render_delta_v1(event->key.sym,
                                                 &render_delta))
        (void)zcl_present_window_page_step_v1(
            run->current_page, run->pages->page_count, render_delta,
            &next_page);
    else if (!run->hovers || run->hovers_first_page_only)
        present_pages_plain_page(run, event, &next_page);
    return next_page;
}

static void present_pages_change_page(struct present_pages_run *run,
    uint32_t next_page)
{
    i32 window_width = 0, window_height = 0;
    if (next_page == run->current_page) return;
    (void)RGFW_window_getSize(run->window, &window_width, &window_height);
    const struct zcl_present_window_v1 *next =
        &run->pages->pages[next_page];
    const struct zcl_present_window_hover_v1 *next_hover =
        run->hovers ? ((run->hovers_first_page_only && next_page != 0u)
                           ? NULL : &run->hovers[next_page]) : NULL;
    uint32_t next_hover_index = run->hover_index;
    if (next_hover && next_hover_index >= next_hover->item_count)
        next_hover_index = next_hover->item_count - 1u;
    if (!next_hover)
        next_hover_index = UINT32_MAX;
    if (present_replace_surface(
            run->window, next, window_width, window_height,
            &run->surface, &run->scaled_pixels, run->action_count,
            run->focused_control, run->form, run->canvas, next_hover,
            next_hover_index, run->required_invalid)) {
        run->current_page = next_page;
        run->request = next;
        run->hover = next_hover;
        run->hover_index = next_hover_index;
        RGFW_window_blitSurface(run->window, run->surface);
    }
}

static bool present_pages_tab_key(struct present_pages_run *run,
    const RGFW_event *event)
{
    uint32_t next_control = run->focused_control;
    if (event->key.value != RGFW_tab || run->action_count == 0)
        return false;
    int32_t direction = (event->key.mod & RGFW_modShift) ? -1 : 1;
    bool stepped = run->form
        ? zcl_present_window_form_focus_step_v1(
              run->form, run->action_count, run->focused_control, direction,
              &next_control)
        : (run->canvas
            ? zcl_present_window_canvas_focus_step_v1(
                  run->action_count, run->focused_control, direction,
                  &next_control)
            : zcl_present_window_action_focus_step_v1(
                  run->focused_control, run->action_count, direction,
                  &next_control));
    if (stepped && present_pages_redraw(run, next_control,
                                        run->hover_index))
        run->focused_control = next_control;
    return true;
}

static bool present_pages_form_edit(struct present_pages_run *run,
    const RGFW_event *event)
{
    bool changed = false;
    if (event->key.value == RGFW_return) {
        uint32_t next_control = run->focused_control;
        if (zcl_present_window_form_focus_step_v1(
                run->form, run->action_count, run->focused_control, 1,
                &next_control)) {
            run->focused_control = next_control;
            changed = true;
        }
    } else if (event->key.value == RGFW_backSpace) {
        changed = zcl_present_window_form_edit_v1(
            run->form, run->focused_control, 0, true);
        run->required_invalid = false;
    } else if (!(event->key.mod &
                 (RGFW_modControl | RGFW_modAlt | RGFW_modSuper)) &&
               event->key.sym >= 0x20u && event->key.sym <= 0x7eu) {
        changed = zcl_present_window_form_edit_v1(
            run->form, run->focused_control, event->key.sym, false);
        run->required_invalid = false;
    }
    return changed;
}

static bool present_pages_form_key(struct present_pages_run *run,
    const RGFW_event *event)
{
    if (!run->form || run->focused_control >= run->form->field_count)
        return false;
    if (present_pages_form_edit(run, event)) {
        present_pages_pump(run, false);
        (void)present_pages_redraw(run, run->focused_control,
                                   run->hover_index);
    }
    return true;
}

static bool present_pages_canvas_edit(struct present_pages_run *run,
    const RGFW_event *event)
{
    bool changed = false;
    int32_t step = (event->key.mod & RGFW_modShift) ? 1 : 10;
    if (event->key.value == RGFW_return) {
        uint32_t next_control = run->focused_control;
        if (zcl_present_window_canvas_focus_step_v1(
                run->action_count, run->focused_control, 1, &next_control)) {
            run->focused_control = next_control;
            changed = true;
        }
    } else if (event->key.value == RGFW_left) {
        changed = zcl_present_window_canvas_step_v1(run->canvas, -step, 0);
    } else if (event->key.value == RGFW_right) {
        changed = zcl_present_window_canvas_step_v1(run->canvas, step, 0);
    } else if (event->key.value == RGFW_up) {
        changed = zcl_present_window_canvas_step_v1(run->canvas, 0, -step);
    } else if (event->key.value == RGFW_down) {
        changed = zcl_present_window_canvas_step_v1(run->canvas, 0, step);
    }
    return changed;
}

static bool present_pages_canvas_key(struct present_pages_run *run,
    const RGFW_event *event)
{
    if (!run->canvas || run->focused_control != 0) return false;
    if (present_pages_canvas_edit(run, event))
        (void)present_pages_redraw(run, run->focused_control,
                                   run->hover_index);
    return true;
}

static void present_pages_action_key(struct present_pages_run *run,
    const RGFW_event *event)
{
    if ((event->key.value != RGFW_return && event->key.value != RGFW_space) ||
        run->action_count == 0)
        return;
    uint32_t action = run->form
        ? run->focused_control - run->form->field_count
        : (run->canvas ? run->focused_control - 1u : run->focused_control);
    if (run->form && action == 1u &&
        !zcl_present_form_required_complete_internal(run->form)) {
        run->required_invalid = true;
        (void)present_pages_redraw(run, run->focused_control,
                                   run->hover_index);
    } else {
        present_pages_finish(run, action);
    }
}

static void present_pages_number_keys(struct present_pages_run *run,
    const RGFW_event *event)
{
    static const RGFW_key action_keys[] = {
        RGFW_1, RGFW_2, RGFW_3, RGFW_4,
    };
    /* Keep the array bound local even though entry validation already
     * rejects action_count > 4. LTO must be able to prove this read is
     * bounded without depending on a distant control-flow fact. */
    for (uint32_t i = 0;
         i < run->action_count && i < ZCL_PRESENT_WINDOW_ACTIONS_MAX;
         i++) {
        if (event->key.value != action_keys[i]) continue;
        present_pages_finish(run, i);
    }
}

static void present_pages_plain_key(struct present_pages_run *run,
    const RGFW_event *event)
{
    if (event->key.value == RGFW_q)
        RGFW_window_setShouldClose(run->window, RGFW_TRUE);
    if (event->key.value == RGFW_c) {
        if (run->copy) {
            present_pages_copy_image(run);
        } else if (run->request->copy_text) {
            size_t copy_len = strlen(run->request->copy_text);
            RGFW_writeClipboard(run->request->copy_text, (u32)copy_len);
        }
    }
    present_pages_number_keys(run, event);
}

static void present_pages_event(struct present_pages_run *run,
    RGFW_event *event)
{
    if (present_pages_live_event(run, event)) return;
    present_pages_resize(run, event);
    present_pages_hover_pointer(run, event);
    present_pages_hover_scroll(run, event);
    present_pages_pointer(run, event);
    present_pages_change_page(run, present_pages_next_page(run, event));
    if (event->type != RGFW_keyPressed) return;
    if (present_pages_tab_key(run, event)) return;
    if (present_pages_form_key(run, event)) return;
    if (present_pages_canvas_key(run, event)) return;
    present_pages_action_key(run, event);
    if (run->form || run->canvas) return;
    present_pages_plain_key(run, event);
}

static void present_pages_loop(struct present_pages_run *run)
{
    while (!RGFW_window_shouldClose(run->window)) {
        RGFW_event event;
        bool saw_event = false;
        while (RGFW_window_checkEvent(run->window, &event)) {
            saw_event = true;
            present_pages_event(run, &event);
        }
        present_pages_pump(run, true);
        if (!saw_event && !RGFW_window_shouldClose(run->window))
            RGFW_waitForEvent(100);
    }
}
#endif

static bool present_run_pages_actions(
    const struct zcl_present_window_pages_v1 *pages,
    uint32_t action_count,
    struct zcl_present_window_form_v1 *form,
    struct zcl_present_window_canvas_v1 *canvas,
    const struct zcl_present_window_hover_v1 *hovers,
    bool hovers_first_page_only,
    uint32_t initial_page,
    const struct zcl_present_window_copy_v1 *copy,
    zcl_present_window_ready_fn ready,
    void *ready_context,
    const struct zcl_present_window_live_view_v1 *live,
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
    const char *problem = present_pages_problem(
        pages, action_count, form, canvas, hovers, hovers_first_page_only,
        initial_page, copy, live, error, error_cap);
    if (problem) return present_error(error, error_cap, problem);
#if !defined(_WIN32) && !defined(__APPLE__) && !defined(__linux__)
    return present_error(error, error_cap,
                         "native presentation is unsupported on this platform");
#else
    struct present_pages_run run = {
        .pages = pages,
        .action_count = action_count,
        .form = form,
        .canvas = canvas,
        .hovers = hovers,
        .hovers_first_page_only = hovers_first_page_only,
        .copy = copy,
        .live = live,
        .result = result,
        .request = &pages->pages[initial_page],
        .hover = hovers ? &hovers[initial_page] : NULL,
        .current_page = initial_page,
    };
    problem = present_pages_open(&run);
    if (problem) return present_error(error, error_cap, problem);
    if (ready) ready(ready_context);
    present_pages_loop(&run);
    RGFW_surface_free(run.surface);
    free(run.scaled_pixels);
    RGFW_window_close(run.window);
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
        pages, action_count, NULL, NULL, NULL, false, 0u, NULL,
        ready, ready_context, NULL,
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
        pages, action_count, form, NULL, NULL, false, 0u, NULL,
        ready, ready_context, NULL,
        result, error, error_cap);
}

bool zcl_present_window_run_live_form_v1(
    const struct zcl_present_window_pages_v1 *pages,
    struct zcl_present_window_form_v1 *form,
    const struct zcl_present_window_live_form_v1 *live,
    char *error, size_t error_cap)
{
    if (!live || !live->update)
        return present_error(error, error_cap, "presentation live form owner is required");
    struct zcl_present_window_event_v1 event;
    const struct zcl_present_window_live_view_v1 owner = { .owner = *live };
    return present_run_pages_actions(pages, 2u, form, NULL, NULL, false,
        0u, NULL, NULL, NULL, &owner, &event, error, error_cap);
}

bool zcl_present_window_run_live_view_v1(
    const struct zcl_present_window_pages_v1 *pages, uint32_t action_count,
    const struct zcl_present_window_live_view_v1 *live,
    char *error, size_t error_cap)
{
    if (!live || !live->owner.update || !live->input || !pages || pages->page_count != 1)
        return present_error(error, error_cap, "presentation live view owner and one page required");
    struct zcl_present_window_event_v1 event;
    return present_run_pages_actions(pages, action_count, NULL, NULL, NULL, false,
        0u, NULL, NULL, NULL, live, &event, error, error_cap);
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
        pages, action_count, NULL, canvas, NULL, false, 0u, NULL, ready,
        ready_context, NULL, result, error, error_cap);
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

bool zcl_present_window_run_pages_first_hover_v1(
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_hover_v1 *hover,
    char *error, size_t error_cap)
{
    struct zcl_present_window_event_v1 event;
    return present_run_pages_actions(
        pages, 0, NULL, NULL, hover, true, 0u, NULL, NULL, NULL,
        NULL, &event, error, error_cap);
}

bool zcl_present_window_run_pages_hover_v1(
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_hover_v1 *hovers,
    uint32_t initial_page, char *error, size_t error_cap)
{
    struct zcl_present_window_event_v1 event;
    return present_run_pages_actions(
        pages, 0, NULL, NULL, hovers, false, initial_page, NULL,
        NULL, NULL,
        NULL, &event, error, error_cap);
}

bool zcl_present_window_run_pages_hover_copy_v1(
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_hover_v1 *hovers,
    const struct zcl_present_window_copy_v1 *copy,
    uint32_t initial_page, char *error, size_t error_cap)
{
    struct zcl_present_window_event_v1 event;
    return present_run_pages_actions(
        pages, 0, NULL, NULL, hovers, false, initial_page, copy,
        NULL, NULL, NULL, &event, error, error_cap);
}
