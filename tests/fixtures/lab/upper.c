/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include <ctype.h>
#include <stdio.h>

int main(void)
{
    int c;
    while ((c = getchar()) != EOF)
        putchar(toupper(c));
    return 0;
}
