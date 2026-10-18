/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include <stdio.h>

int main(void)
{
    fputs("about to fail\n", stderr);
    return 3;
}
