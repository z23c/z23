/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: implementation of lintc_text.h.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "lintc_text.h"

bool lct_is_digits(const char *s)
{
    if (!*s)
        return false;
    for (; *s; s++)
        if (*s < '0' || *s > '9')
            return false;
    return true;
}

bool lct_ends_with_paren(const char *line)
{
    size_t n = strlen(line);
    while (n && isspace((unsigned char)line[n - 1]))
        n--;
    return n > 0 && line[n - 1] == ')';
}

int lct_read_line_fd(int rfd, char *buf, size_t cap)
{
    size_t used = 0;
    while (used + 1 < cap) {
        ssize_t n = read(rfd, buf + used, 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0 || buf[used] == '\n')
            break;
        used++;
    }
    buf[used] = '\0';
    return used ? 0 : -1;
}
