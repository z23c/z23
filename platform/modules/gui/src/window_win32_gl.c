/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: WGL context for a GL-surface window. opengl32.dll is loaded at
 * run time so a CPU-only program never links or loads it. */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdio.h>
#include <string.h>

#include "base/safe_alloc.h"
#include "gui_internal.h"

typedef HGLRC (WINAPI *wgl_create_fn)(HDC);
typedef BOOL (WINAPI *wgl_delete_fn)(HGLRC);
typedef BOOL (WINAPI *wgl_make_fn)(HDC, HGLRC);
typedef PROC (WINAPI *wgl_getproc_fn)(LPCSTR);
typedef BOOL (WINAPI *wgl_swap_interval_fn)(int);

struct w32gl {
    HMODULE lib;
    HWND hwnd;
    HDC dc;
    HGLRC rc;
    wgl_create_fn create;
    wgl_delete_fn del;
    wgl_make_fn make;
    wgl_getproc_fn getproc;
};

bool gui_win32_gl_probe(void)
{
    HMODULE m = LoadLibraryW(L"opengl32.dll");
    if (!m) return false;
    FreeLibrary(m);
    return true;
}

static void gl_err(char *err, size_t cap, const char *what)
{
    if (err && cap) snprintf(err, cap, "%s (Windows error %lu)", what, GetLastError());
}

bool gui_win32_gl_create(struct gui_window *w, void *hwnd,
                         const struct gui_gl_desc *g, char *err, size_t cap)
{
    struct w32gl *s = zcl_calloc(1, sizeof(*s), "gui_win32_gl");
    if (!s) return false;
    s->hwnd = (HWND)hwnd;
    s->lib = LoadLibraryW(L"opengl32.dll");
    if (!s->lib) { gl_err(err, cap, "opengl32.dll is not available"); free(s); return false; }
    s->create = GUI_FN_CAST(wgl_create_fn, GetProcAddress(s->lib, "wglCreateContext"));
    s->del = GUI_FN_CAST(wgl_delete_fn, GetProcAddress(s->lib, "wglDeleteContext"));
    s->make = GUI_FN_CAST(wgl_make_fn, GetProcAddress(s->lib, "wglMakeCurrent"));
    s->getproc = GUI_FN_CAST(wgl_getproc_fn, GetProcAddress(s->lib, "wglGetProcAddress"));
    s->dc = GetDC(s->hwnd);
    PIXELFORMATDESCRIPTOR pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.nSize = sizeof(pfd);
    pfd.nVersion = 1;
    pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
    pfd.iPixelType = PFD_TYPE_RGBA;
    pfd.cColorBits = 32;
    pfd.cDepthBits = g && g->depth_bits ? g->depth_bits : 24;
    pfd.cStencilBits = g && g->stencil_bits ? g->stencil_bits : 8;
    int fmt = (s->create && s->dc) ? ChoosePixelFormat(s->dc, &pfd) : 0;
    if (!fmt || !SetPixelFormat(s->dc, fmt, &pfd)) {
        gl_err(err, cap, "no usable OpenGL pixel format");
    } else if (!(s->rc = s->create(s->dc))) {
        gl_err(err, cap, "cannot create an OpenGL context");
    } else if (!s->make(s->dc, s->rc)) {
        gl_err(err, cap, "cannot make the OpenGL context current");
        s->del(s->rc);
        s->rc = NULL;
    }
    w->be_gl = s;
    if (!s->rc) {
        gui_win32_gl_destroy(w);
        return false;
    }
    return true;
}

void gui_win32_gl_destroy(struct gui_window *w)
{
    struct w32gl *s = (struct w32gl *)w->be_gl;
    if (!s) return;
    if (s->rc) { s->make(NULL, NULL); s->del(s->rc); }
    if (s->dc) ReleaseDC(s->hwnd, s->dc);
    if (s->lib) FreeLibrary(s->lib);
    free(s);
    w->be_gl = NULL;
}

bool gui_win32_gl_make_current(struct gui_window *w)
{
    struct w32gl *s = (struct w32gl *)w->be_gl;
    return s && s->rc && s->make(s->dc, s->rc);
}

bool gui_win32_gl_swap(struct gui_window *w)
{
    struct w32gl *s = (struct w32gl *)w->be_gl;
    return s && SwapBuffers(s->dc);
}

bool gui_win32_gl_interval(struct gui_window *w, int interval)
{
    wgl_swap_interval_fn f = GUI_FN_CAST(wgl_swap_interval_fn, gui_win32_gl_proc(w, "wglSwapIntervalEXT"));
    return f && f(interval);
}

void *gui_win32_gl_proc(struct gui_window *w, const char *name)
{
    struct w32gl *s = (struct w32gl *)w->be_gl;
    if (!s || !s->getproc) return NULL;
    PROC p = s->getproc(name);
    uintptr_t v = (uintptr_t)p;
    if (v > 3 && v != (uintptr_t)-1) return GUI_FN_CAST(void *, p); /* real extension entry */
    return GUI_FN_CAST(void *, GetProcAddress(s->lib, name));       /* GL 1.1 export */
}
