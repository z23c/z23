/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: one-shot plugin executable for the span token. The packed bytes
 * are this main plus the same header the swappable leaf includes.
 */
#include "controllers/loop_span.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    const char *text = (argc > 1 && argv[1]) ? argv[1] : "";
    uint32_t token = zcl_loop_span_token(text, strlen(text));
    if (printf("token=%u\n", token) < 0)
        return 1;
    return 0;
}
