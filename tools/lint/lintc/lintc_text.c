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

/* One byte from rfd: 1 read, 0 end of input, -2 read error. EINTR retried. */
static int lct_read_byte(int rfd, char *c)
{
    for (;;) {
        ssize_t n = read(rfd, c, 1);
        if (n < 0 && errno == EINTR)
            continue;
        return n < 0 ? -2 : (int)n;
    }
}

/* A full buffer holds cap-1 bytes with no newline yet. Peek one more byte: a
 * newline or end of input means the line fit exactly (0); any other byte is
 * an overlong line (-3); a read error is -2. */
static int lct_line_full(int rfd, char *buf, size_t used)
{
    char c = '\0';
    int got = lct_read_byte(rfd, &c);
    if (got < 0)
        return -2;
    if (got == 0 || c == '\n') {
        buf[used] = '\0';
        return 0;
    }
    buf[0] = '\0';
    return -3;
}

int lct_read_line_fd(int rfd, char *buf, size_t cap)
{
    size_t used = 0;
    buf[0] = '\0';
    if (cap < 2)
        return -3;
    for (;;) {
        if (used + 1 >= cap)
            return lct_line_full(rfd, buf, used);
        int got = lct_read_byte(rfd, &buf[used]);
        if (got < 0) {
            buf[0] = '\0';
            return -2;
        }
        if (got == 0 || buf[used] == '\n')
            break;
        used++;
    }
    buf[used] = '\0';
    return used ? 0 : -1;
}

/* True when path can be opened for reading. */
int lct_readable(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    fclose(f);
    return 1;
}

/* Line-wise substring search over a file; 16384-byte line buffer. */
int lct_file_has(const char *path, const char *needle)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char line[16384];
    int hit = 0;
    while (!hit && fgets(line, sizeof line, f))
        hit = strstr(line, needle) != NULL;
    fclose(f);
    return hit;
}
