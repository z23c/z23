/* zstr CLI: small string operations over arguments.
 *
 *   zstr trim <s>          strip surrounding whitespace
 *   zstr lower <s>         ASCII lowercase
 *   zstr upper <s>         ASCII uppercase
 *   zstr count <s> <needle>
 *   zstr split <delim> <s> one field per line
 *   zstr starts <s> <prefix> / zstr ends <s> <suffix>   exit 0/1
 */
#include "zstr/zstr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int usage(void)
{
    fprintf(stderr,
        "usage: zstr <trim|lower|upper> <s>\n"
        "       zstr count <s> <needle>\n"
        "       zstr split <delim> <s>\n"
        "       zstr <starts|ends> <s> <affix>\n");
    return 2;
}

int main(int argc, char **argv)
{
    if (argc < 3) return usage();

    if (strcmp(argv[1], "trim") == 0 || strcmp(argv[1], "lower") == 0
        || strcmp(argv[1], "upper") == 0) {
        size_t cap = strlen(argv[2]) + 1;
        char *buf = malloc(cap);
        if (!buf) return 1;
        zstr_copy(buf, cap, argv[2]);
        if (argv[1][0] == 't') zstr_trim(buf);
        else if (argv[1][0] == 'l') zstr_to_lower(buf);
        else zstr_to_upper(buf);
        puts(buf);
        free(buf);
        return 0;
    }

    if (strcmp(argv[1], "count") == 0 && argc >= 4) {
        printf("%zu\n", zstr_count(argv[2], argv[3]));
        return 0;
    }

    if (strcmp(argv[1], "split") == 0 && argc >= 4) {
        if (strlen(argv[2]) != 1) return usage();
        zstr_split_it it;
        zstr_span sp;
        zstr_split_init(&it, argv[3], argv[2][0]);
        while (zstr_split_next(&it, &sp))
            printf("%.*s\n", (int)sp.len, sp.ptr);
        return 0;
    }

    if (strcmp(argv[1], "starts") == 0 && argc >= 4)
        return zstr_starts_with(argv[2], argv[3]) ? 0 : 1;

    if (strcmp(argv[1], "ends") == 0 && argc >= 4)
        return zstr_ends_with(argv[2], argv[3]) ? 0 : 1;

    return usage();
}
