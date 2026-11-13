/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Private test-only live-window fault and scripted native event state. */
#ifndef ZCL_PRESENTATION_LIVE_TEST_INTERNAL_H
#define ZCL_PRESENTATION_LIVE_TEST_INTERNAL_H
static bool present_test_fail_redraw;
static struct zcl_present_window_event_v1 present_test_final_event;
static bool present_test_copy_matches;
bool zcl_present_test_copy_matches(void);
bool zcl_present_test_copy_matches(void) { return present_test_copy_matches; }

#if defined(__linux__) && defined(RGFW_X11)
/* Called after the fixture's sole window closes, not merely at startup.
 * Every dynamically loaded extension must retire both handle and callables. */
bool zcl_present_test_x11_libraries_retired(void);
bool zcl_present_test_x11_libraries_retired(void)
{
    if (_RGFW != NULL) return false;
#if !defined(RGFW_NO_X11_CURSOR_PRELOAD) && !defined(RGFW_NO_X11_CURSOR)
    if (X11Cursorhandle || XcursorImageLoadCursorSRC ||
        XcursorImageCreateSRC || XcursorImageDestroySRC) return false;
#endif
#if !defined(RGFW_NO_XINPUT2) && !defined(RGFW_NO_X11_XI_PRELOAD)
    if (X11Xihandle || XISelectEventsSRC) return false;
#endif
#if !defined(RGFW_NO_X11_EXT_PRELOAD)
    if (X11XEXThandle || XSyncCreateCounterSRC || XSyncIntToValueSRC ||
        XSyncSetCounterSRC || XShapeCombineRegionSRC || XShapeCombineMaskSRC)
        return false;
#endif
    return true;
}
#endif
struct zcl_present_window_event_v1 zcl_present_test_result(void);
struct zcl_present_window_event_v1 zcl_present_test_result(void) { return present_test_final_event; }
static unsigned present_test_events[2], present_test_count, present_test_cursor;
void zcl_present_test_script(unsigned first, unsigned second, bool fail_redraw);
void zcl_present_test_script(unsigned first, unsigned second, bool fail_redraw)
{
    present_test_events[0] = first; present_test_events[1] = second;
    present_test_count = 2; present_test_cursor = 0;
    present_test_fail_redraw = fail_redraw;
}
#endif
