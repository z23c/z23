/* zpuny CLI: punycode encode/decode for IDNA labels.
 *
 *   zpuny enc <utf8-label>...    encode each label to punycode
 *   zpuny dec <punycode>...      decode each label back to UTF-8
 *
 * Reads from arguments, or one label per line on stdin.
 */
#include "zpuny/zpuny.h"

#include <stdio.h>
#include <string.h>

static int do_one(int enc, const char *s)
{
    char out[512];
    size_t n = 0;
    zpuny_status st = enc
        ? zpuny_encode_utf8(s, strlen(s), out, sizeof out, &n)
        : zpuny_decode_utf8(s, strlen(s), out, sizeof out, &n);
    if (st != ZPUNY_OK) {
        fprintf(stderr, "zpuny: %s: %s\n", s,
                st == ZPUNY_OVERFLOW ? "label too long" : "bad input");
        return 1;
    }
    printf("%.*s\n", (int)n, out);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2 || (strcmp(argv[1], "enc") != 0 && strcmp(argv[1], "dec") != 0)) {
        fprintf(stderr, "usage: zpuny enc|dec [label]...\n");
        return 2;
    }
    int enc = argv[1][0] == 'e';
    int rc = 0;
    if (argc > 2) {
        for (int i = 2; i < argc; i++)
            rc |= do_one(enc, argv[i]);
    } else {
        char line[512];
        while (fgets(line, sizeof line, stdin)) {
            line[strcspn(line, "\r\n")] = '\0';
            if (line[0]) rc |= do_one(enc, line);
        }
    }
    return rc;
}
