/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include <limits.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    (void)argv;
    int x = INT_MAX;
    x += argc;
    printf("%d\n", x < 0);
    return 0;
}
