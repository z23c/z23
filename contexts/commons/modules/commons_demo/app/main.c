/* Copyright 2026 Rhett Creighton - MIT License */

#include "commons/demo.h"

#include <stdio.h>

int main(int argc, char **argv)
{
    const char *input = argc > 1
        ? argv[1] : "{\"name\":\"commons\",\"count\":3}";
    char summary[256];
    if (!commons_demo_render(input, summary, sizeof(summary))) {
        fputs("invalid commons input\n", stderr);
        return 1;
    }
    puts(summary);
    return 0;
}
