/* Copyright 2026 Rhett Creighton - MIT License
 * Purpose: verify the tiny-lines fixture's bounded line counting. */
#include "tiny_lines.h"

#include <stdio.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "tiny-lines failed: %s:%d: %s\n", \
            __FILE__, __LINE__, #expr); \
    return 1; \
} } while (0)

int main(void)
{
    size_t lines = 99;
    CHECK(tiny_count_lines(NULL, 0, &lines) && lines == 0);
    CHECK(tiny_count_lines("one\ntwo", 7, &lines) && lines == 2);
    CHECK(tiny_count_lines("one\n", 4, &lines) && lines == 1);
    CHECK(!tiny_count_lines(NULL, 1, &lines) && lines == 0);
    const char embedded_nul[] = {'a', '\0', 'b'};
    lines = 99;
    CHECK(!tiny_count_lines(embedded_nul, sizeof(embedded_nul), &lines) &&
          lines == 0);
    return 0;
}
