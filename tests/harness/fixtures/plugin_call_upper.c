/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fixture one-shot plugin (interface 2) for test_plugin_call.c, built by the
 * Makefile into build/fixtures/, never linked into a product binary. Reads
 * standard input to end of file and writes it upper-cased to standard output;
 * exits 0, or 1 when a read or write fails. */

#include <stddef.h>
#include <unistd.h>

int main(void)
{
    char buf[4096];
    ssize_t n;
    while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++)
            if (buf[i] >= 'a' && buf[i] <= 'z')
                buf[i] = (char)(buf[i] - 'a' + 'A');
        for (ssize_t off = 0; off < n;) {
            ssize_t w = write(STDOUT_FILENO, buf + off, (size_t)(n - off));
            if (w <= 0)
                return 1;
            off += w;
        }
    }
    return n < 0 ? 1 : 0;
}
