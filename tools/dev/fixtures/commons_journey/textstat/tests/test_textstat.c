/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance tests for textstat. They run inside the confined package
 * build, so they must need nothing but the package's own header. */

#include "textstat/textstat.h"

#include <stdio.h>
#include <string.h>

static int fail(const char *what, size_t got, size_t want)
{
    printf("textstat: FAIL %s got=%zu want=%zu\n", what, got, want);
    return 1;
}

int main(void)
{
    static const char sample[] = "one two\nthree\n";
    size_t len = strlen(sample);
    if (textstat_lines(sample, len) != 2)
        return fail("lines", textstat_lines(sample, len), 2);
    if (textstat_words(sample, len) != 3)
        return fail("words", textstat_words(sample, len), 3);
    if (textstat_bytes(sample, len) != len)
        return fail("bytes", textstat_bytes(sample, len), len);
    if (textstat_lines("no newline", 10) != 1)
        return fail("unterminated line", textstat_lines("no newline", 10), 1);
    if (textstat_lines("a\rb\r", 4) != 2)
        return fail("CR lines", textstat_lines("a\rb\r", 4), 2);
    if (textstat_lines("a\r\nb\r\nc", 7) != 3)
        return fail("CRLF lines", textstat_lines("a\r\nb\r\nc", 7), 3);
    if (textstat_lines("a\r\nb\r", 5) != 2)
        return fail("mixed lines", textstat_lines("a\r\nb\r", 5), 2);
    if (textstat_words("   ", 3) != 0)
        return fail("blank words", textstat_words("   ", 3), 0);
    if (textstat_lines(NULL, 4) != 0)
        return fail("null lines", textstat_lines(NULL, 4), 0);
    printf("textstat: OK\n");
    return 0;
}
