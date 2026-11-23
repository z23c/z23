/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Private test-only live-window fault and scripted native event state. */
#ifndef ZCL_PRESENTATION_LIVE_TEST_INTERNAL_H
#define ZCL_PRESENTATION_LIVE_TEST_INTERNAL_H
static bool present_test_fail_redraw;
static struct zcl_present_window_event_v1 present_test_final_event;
static bool present_test_copy_matches;
bool zcl_present_test_copy_matches(void);
bool zcl_present_test_copy_matches(void) { return present_test_copy_matches; }
/* After the copy key wrote `text`, read the host clipboard back and record
 * whether every byte returned. */
static void present_test_copy_readback(const char *text, size_t length)
{
#if defined(__APPLE__)
    /* RGFW's reader reports an encoding-size upper bound on macOS.
     * Verify the actual OS pasteboard UTF-8 bytes without that copy. */
    const char *copied = NSPasteboard_stringForType(
        NSPasteboard_generalPasteboard(), NSPasteboardTypeString, NULL);
    present_test_copy_matches = copied && strlen(copied) == length &&
        !memcmp(copied, text, length + 1u);
#else
    char copied[ZCL_PRESENT_COPY_TEXT_MAX + 1u] = {0};
    RGFW_ssize_t read = RGFW_readClipboardPtr(copied, sizeof(copied));
    present_test_copy_matches = read == (RGFW_ssize_t)length &&
        !memcmp(copied, text, length + 1u);
#endif
}

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
/* The next scripted key. UINT_MAX is the copy key and 0..3 a number key, as
 * before. UINT_MAX - 1 is a press of the exit key that RGFW still shows as a
 * fresh edge when it is handled; UINT_MAX - 2 is a quick tap whose release was
 * read in the same poll, so RGFW shows no edge. No scripted key starts a poll,
 * so the state stays for the keys that follow. */
static bool present_key_is_exit(unsigned scripted)
{
    return scripted == UINT_MAX - 1u || scripted == UINT_MAX - 2u;
}
static bool present_test_key(RGFW_window *window, RGFW_event *event)
{
    memset(event, 0, sizeof(*event));
    event->type = RGFW_keyPressed;
    unsigned scripted = present_test_events[present_test_cursor++];
    if (!present_key_is_exit(scripted)) {
        event->key.value = scripted == UINT_MAX ? RGFW_c : (u8)(RGFW_1 + scripted);
        event->key.sym = scripted == UINT_MAX ? 'c' : (u32)('1' + scripted);
    } else {
        window->internal.inFocus = RGFW_TRUE;
        _RGFW->keyboard[RGFW_escape] = scripted == UINT_MAX - 1u ?
            (RGFW_keyState){RGFW_TRUE, RGFW_FALSE} : (RGFW_keyState){RGFW_FALSE, RGFW_TRUE};
        event->key.value = RGFW_escape; event->key.sym = '\033';
    }
    return true;
}
#endif
