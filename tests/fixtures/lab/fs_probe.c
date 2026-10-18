/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include <stdio.h>

static const char *try_open(const char *path, const char *mode)
{
    FILE *f = fopen(path, mode);
    if (!f)
        return "denied";
    fclose(f);
    return "allowed";
}

int main(int argc, char **argv)
{
    printf("workdir=%s\n", try_open("probe.txt", "w"));
    printf("outside_write=%s\n", try_open(argc > 1 ? argv[1] : "/nonexistent/escape", "w"));
    printf("outside_read=%s\n", try_open("/etc/passwd", "r"));
    return 0;
}
