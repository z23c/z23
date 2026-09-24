/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * purpose: Demand an X11 link symbol in a compile-valid C23 program.
 */
#include <X11/Xlib.h>

int main(void)
{
    Display *display = XOpenDisplay(NULL);
    if (display) XCloseDisplay(display);
    return display ? 0 : 1;
}
