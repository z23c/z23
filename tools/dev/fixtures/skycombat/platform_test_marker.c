/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * purpose: Verify the ordinary library test remains independent of X11.
 */
#include "marker.h"
int main(void)
{
    return qualification_marker() == 23 ? 0 : 1;
}
