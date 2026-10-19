/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include <stdio.h>

int main(int argc, char **argv)
{
    char mode = argc > 1 ? argv[1][0] : 'a';
    if (mode == 'l') {
        for (int i = 0; i < 70000; i++)
            fputc(i % 3 == 0 ? '"' : i % 3 == 1 ? '\n' : '\001', stderr);
    } else {
        fprintf(stderr, "invalid record %c at byte 17\n", mode);
    }
    return 2;
}
