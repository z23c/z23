/* zfmt CLI: format demonstration / smoke driver.
 *
 *   zfmt u64 <n> | i64 <n> | hex <n> | pad <n> <width> | double <v> <prec>
 *   zfmt template <name> <count>   "hello <name>, count=<count>"
 */
#include "zfmt/zfmt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int usage(void)
{
    fprintf(stderr,
        "usage: zfmt u64 <n> | i64 <n> | hex <n> | pad <n> <width>\n"
        "       zfmt double <v> <precision>\n"
        "       zfmt template <name> <count>\n");
    return 2;
}

int main(int argc, char **argv)
{
    if (argc < 3) return usage();
    char buf[128];
    zfmt f;
    zfmt_init(&f, buf, sizeof buf);

    if (strcmp(argv[1], "u64") == 0) {
        zfmt_u64(&f, strtoull(argv[2], NULL, 10));
    } else if (strcmp(argv[1], "i64") == 0) {
        zfmt_i64(&f, strtoll(argv[2], NULL, 10));
    } else if (strcmp(argv[1], "hex") == 0) {
        zfmt_hex64(&f, strtoull(argv[2], NULL, 10));
    } else if (strcmp(argv[1], "pad") == 0) {
        if (argc < 4) return usage();
        zfmt_u64_pad(&f, strtoull(argv[2], NULL, 10),
                     (unsigned)strtoul(argv[3], NULL, 10));
    } else if (strcmp(argv[1], "double") == 0) {
        if (argc < 4) return usage();
        zfmt_double(&f, strtod(argv[2], NULL),
                    (unsigned)strtoul(argv[3], NULL, 10));
    } else if (strcmp(argv[1], "template") == 0) {
        if (argc < 4) return usage();
        zfmt_str(&f, "hello ");
        zfmt_str(&f, argv[2]);
        zfmt_str(&f, ", count=");
        zfmt_u64(&f, strtoull(argv[3], NULL, 10));
    } else {
        return usage();
    }

    if (!zfmt_ok(&f)) {
        fprintf(stderr, "zfmt: output truncated\n");
        return 1;
    }
    puts(zfmt_cstr(&f));
    return 0;
}
