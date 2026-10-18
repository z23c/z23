/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include <stdio.h>
#include <string.h>

int main(void)
{
    char line[4096];
    while (fgets(line, sizeof(line), stdin)) {
        size_t n = strcspn(line, "\n");
        for (size_t i = n; i > 0; i--)
            putchar(line[i - 1]);
        putchar('\n');
    }
    return 0;
}
