/* Purpose: Emit precise text and binary stdout for lab diff diagnostics. */
#include <stdio.h>
#include <string.h>

static void prefix(void)
{
    for (size_t index = 0; index < 256; index++)
        putchar('a');
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "short";
    if (strcmp(mode, "short") == 0) {
        fputs("alpha\n", stdout);
    } else if (strcmp(mode, "late") == 0) {
        prefix();
        fputs("Y\n", stdout);
    } else if (strcmp(mode, "line2") == 0) {
        fputs("same\n", stdout);
        prefix();
        fputs("Y\n", stdout);
    } else if (strcmp(mode, "late-eof") == 0) {
        prefix();
    } else if (strcmp(mode, "nul") == 0) {
        static const unsigned char bytes[] = {'h', 'e', 'a', 'd', 0, 'Y', '\n'};
        fwrite(bytes, 1, sizeof(bytes), stdout);
    } else if (strcmp(mode, "invalid") == 0) {
        putchar(0xff);
        putchar('\n');
    } else if (strcmp(mode, "replacement") == 0) {
        fputs("\xef\xbf\xbd\n", stdout);
    } else if (strcmp(mode, "binary") == 0) {
        for (size_t index = 0; index < 32; index++)
            putchar(0xff);
        putchar('\n');
    } else {
        return 2;
    }
    return ferror(stdout) ? 1 : 0;
}
