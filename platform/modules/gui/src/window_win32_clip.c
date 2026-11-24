/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Win32 clipboard (CF_UNICODETEXT) and UTF-8 to UTF-16 conversion
 * used by the window backend. Split from window_win32.c to keep each file
 * small; compiles with and without UNICODE (every API is the W form). */
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string.h>

#include "base/safe_alloc.h"
#include "gui_internal.h"

/* Always NUL-terminates out (cap >= 1); returns the UTF-16 unit count. */
int gui_win32_utf8_to_wide(const char *s, size_t len, wchar_t *out, int cap)
{
    if (cap < 1) return 0;
    out[0] = 0;
    if (len > 100000 || len == 0) return 0;
    int n = MultiByteToWideChar(CP_UTF8, 0, s, (int)len, out, cap - 1);
    if (n < 0) n = 0;
    out[n] = 0;
    return n;
}

static HGLOBAL clip_alloc(const wchar_t *wide, int n)
{
    HGLOBAL g = GlobalAlloc(GMEM_MOVEABLE, ((size_t)n + 1) * sizeof(wchar_t));
    if (!g) return NULL;
    void *p = GlobalLock(g);
    if (!p) {
        GlobalFree(g);
        return NULL;
    }
    memcpy(p, wide, ((size_t)n + 1) * sizeof(wchar_t));
    GlobalUnlock(g);
    return g;
}

bool gui_win32_clip_set(void *hwnd, const char *utf8, size_t len)
{
    wchar_t *wide = zcl_malloc((len + 1) * sizeof(wchar_t), "gui_clip_wide");
    if (!wide) return false;
    int n = gui_win32_utf8_to_wide(utf8, len, wide, (int)len + 1);
    HGLOBAL g = clip_alloc(wide, n);
    free(wide);
    if (!g) return false;
    bool ok = false;
    if (OpenClipboard((HWND)hwnd)) {
        EmptyClipboard();
        ok = SetClipboardData(CF_UNICODETEXT, g) != NULL;
        CloseClipboard();
    }
    if (!ok) GlobalFree(g);
    return ok;
}

size_t gui_win32_clip_get(void *hwnd, char *buf, size_t cap)
{
    size_t out = 0;
    buf[0] = 0;
    if (!OpenClipboard((HWND)hwnd)) return 0;
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    const wchar_t *p = h ? (const wchar_t *)GlobalLock(h) : NULL;
    if (p) {
        size_t wl = wcsnlen(p, GUI_CLIP_CAP);
        int n = WideCharToMultiByte(CP_UTF8, 0, p, (int)wl, buf, (int)cap - 1, NULL, NULL);
        out = n > 0 ? (size_t)n : 0;
        buf[out] = 0;
        GlobalUnlock(h);
    }
    CloseClipboard();
    return out;
}
#else
typedef int gui_window_win32_clip_not_built; /* Windows-only translation unit */
#endif
