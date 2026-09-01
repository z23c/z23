/* Copyright 2026 Rhett Creighton - MIT License
 * Purpose: demonstrate the tiny-lines fixture API. */
#include "tiny_lines.h"

#include <stdio.h>

int main(void)
{
    size_t lines = 0;
    if (!tiny_count_lines("one\ntwo", 7, &lines))
        return 1;
    printf("%zu\n", lines);
    return 0;
}
