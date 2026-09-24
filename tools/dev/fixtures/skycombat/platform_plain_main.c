/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * purpose: Link the same package recipe using only its own library.
 */
#include "marker.h"

int main(void)
{
    return qualification_marker() == 23 ? 0 : 1;
}
