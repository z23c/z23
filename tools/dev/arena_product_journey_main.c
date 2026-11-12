/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for `make arena-product-journey`. */

#include "arena_product_journey.h"
#include "dev_script_dir.h"

#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(void)
{
#if defined(_WIN32)
    fprintf(stderr, "arena-product-journey: unavailable on Windows\n");
    return 2;
#else
    char dir[PATH_MAX];
    if (zcl_dev_script_dir(dir, sizeof dir) != 0) {
        fprintf(stderr, "arena-product-journey: cannot locate tools/dev\n");
        return 2;
    }
    return zcl_arena_product_journey_launch(dir);
#endif
}
