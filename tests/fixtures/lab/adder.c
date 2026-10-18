/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include <stdio.h>

int main(void)
{
    int a, b;
    if (scanf("%d %d", &a, &b) != 2)
        return 1;
    printf("%d\n", a + b);
    return 0;
}
