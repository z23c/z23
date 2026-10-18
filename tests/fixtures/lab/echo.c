/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include <stdio.h>

int main(int argc, char **argv)
{
    printf("args=%d", argc - 1);
    for (int i = 1; i < argc; i++)
        printf(" [%s]", argv[i]);
    putchar('\n');
    int c;
    while ((c = getchar()) != EOF)
        putchar(c);
    return 0;
}
