/* Copyright 2026 Rhett Creighton - MIT License */

#include "commons/demo.h"

#include <string.h>

int main(void)
{
    char output[256];
    if (!commons_demo_render(
            "{\"name\":\"commons\",\"count\":3}", output,
            sizeof(output)) ||
        strcmp(output,
               "commons|3|030000000700636f6d6d6f6e73") != 0)
        return 1;
    if (commons_demo_render(
            "{\"name\":\"commons\",\"count\":-1}", output,
            sizeof(output)) ||
        commons_demo_render("{\"count\":3}", output, sizeof(output)) ||
        commons_demo_render(
            "{\"name\":\"commons\",\"count\":3}", output, 8))
        return 2;
    return 0;
}
