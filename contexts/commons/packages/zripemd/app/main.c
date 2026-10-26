/* zripemd demo: hash each argument with RIPEMD-160. */
#include "zripemd/zripemd.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    char hex[ZRIPEMD160_HEX_LEN];

    if (argc < 2) {
        fprintf(stderr, "usage: %s <string>...\n", argv[0]);
        return 2;
    }
    for (int i = 1; i < argc; i++) {
        zripemd160_hex(argv[i], strlen(argv[i]), hex);
        if (printf("%s  %s\n", hex, argv[i]) < 0)
            goto output_error;
    }
    if (fflush(stdout) != 0 || ferror(stdout))
        goto output_error;
    return 0;

output_error:
    fputs("zripemd: output write failed\n", stderr);
    return 1;
}
