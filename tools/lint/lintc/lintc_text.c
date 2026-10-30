/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: implementation of lintc_text.h.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
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

int lct_scratch_dir(char *out, size_t cap, const char *leaf)
{
    const char *home = getenv("HOME");
    if (!home || !home[0])
        return die("z23-lint: HOME unset; cannot place selftest scratch\n", "");
    char base[1024];
    if (ovf(snprintf(base, sizeof base, "%s/.local/state/zclassic23/scratch",
                     home), sizeof base))
        return 2;
    int rc = csr_mkdirs(base);
    if (rc)
        return rc;
    if (ovf(snprintf(out, cap, "%s/%s.XXXXXX", base, leaf), cap))
        return 2;
    if (!mkdtemp(out))
        return die("z23-lint: mkdtemp failed for selftest scratch\n", "");
    return 0;
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
