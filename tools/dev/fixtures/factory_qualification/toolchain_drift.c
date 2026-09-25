/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * purpose: Compile-valid control for changed compiler arguments. */

#include <stdio.h>

#ifndef ZCL_FIXTURE_VALUE
#define ZCL_FIXTURE_VALUE 1
#endif

int main(void)
{
    printf("%d\n", ZCL_FIXTURE_VALUE);
    return 0;
}
