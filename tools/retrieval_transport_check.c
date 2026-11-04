/* Purpose: refuse raw NUL before retrieval output enters Bash strings. */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

enum { BLOCK_BYTES = 16384 };

/* This is a transport guard, not a JSON/schema validator. In particular,
 * escaped JSON \u0000 remains unchanged for the downstream validator. */
static bool transport_valid(FILE *stream)
{
    unsigned char block[BLOCK_BYTES];
    size_t n;
    while ((n = fread(block, 1, sizeof(block), stream)) != 0)
        if (memchr(block, 0, n)) return false;
    return !ferror(stream);
}

static bool fixture(const unsigned char *bytes, size_t length, bool valid)
{
    FILE *stream = tmpfile();
    if (!stream) return false;
    bool ok = fwrite(bytes, 1, length, stream) == length &&
        fseek(stream, 0, SEEK_SET) == 0 && transport_valid(stream) == valid;
    if (fclose(stream) != 0) ok = false;
    return ok;
}

static int selftest(void)
{
    static const unsigned char escaped[] = "{\"x\":\"\\u0000\"}\r\n";
    unsigned char bytes[BLOCK_BYTES + 2];
    memset(bytes, 'x', sizeof(bytes));
    if (!fixture(escaped, sizeof(escaped) - 1, true) ||
        !fixture(bytes, 0, true) || !fixture(bytes, sizeof(bytes), true)) return 1;
    static const size_t offsets[] = {0, BLOCK_BYTES - 1, BLOCK_BYTES, BLOCK_BYTES + 1};
    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        bytes[offsets[i]] = 0;
        if (!fixture(bytes, sizeof(bytes), false)) return 1;
        bytes[offsets[i]] = 'x';
    }
    return puts("retrieval-transport-check: 7 byte-preservation controls passed") < 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0) return selftest();
    if (argc != 1) {
        fputs("usage: retrieval-transport-check [--selftest]\n", stderr);
        return 64;
    }
#if defined(_WIN32)
    if (_setmode(_fileno(stdin), _O_BINARY) == -1) {
        perror("retrieval-transport-check: binary stdin");
        return 65;
    }
#endif
    if (!transport_valid(stdin)) {
        fputs("retrieval-transport-check: raw NUL or input read failure\n", stderr);
        return 65;
    }
    return 0;
}
