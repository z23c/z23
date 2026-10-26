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

static int finish_output(int written)
{
    if (written < 0 || fflush(stdout) != 0 || ferror(stdout)) {
        fprintf(stderr, "zstr: write error\n");
        return 1;
    }
    return 0;
}

static int transform(const char *command, const char *text)
{
    size_t cap = strlen(text) + 1;
    char *buf = malloc(cap);
    if (!buf) {
        fprintf(stderr, "zstr: allocation failed\n");
        return 1;
    }
    zstr_copy(buf, cap, text);
    if (command[0] == 't') zstr_trim(buf);
    else if (command[0] == 'l') zstr_to_lower(buf);
    else zstr_to_upper(buf);
    int written = puts(buf);
    free(buf);
    return finish_output(written);
}

static int split_fields(const char *delimiter, const char *text)
{
    if (strlen(delimiter) != 1) return usage();
    zstr_split_it it;
    zstr_span sp;
    bool attempted = false;
    zstr_split_init(&it, text, delimiter[0]);
    while (zstr_split_next(&it, &sp)) {
        attempted = true;
        if (printf("%.*s\n", (int)sp.len, sp.ptr) < 0) return finish_output(-1);
    }
    return attempted ? finish_output(0) : 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) return usage();

    if (strcmp(argv[1], "trim") == 0 || strcmp(argv[1], "lower") == 0
        || strcmp(argv[1], "upper") == 0)
        return transform(argv[1], argv[2]);

    if (strcmp(argv[1], "count") == 0 && argc >= 4) {
        return finish_output(printf("%zu\n", zstr_count(argv[2], argv[3])));
    }

    if (strcmp(argv[1], "split") == 0 && argc >= 4) {
        return split_fields(argv[2], argv[3]);
    }

    if (strcmp(argv[1], "starts") == 0 && argc >= 4)
        return zstr_starts_with(argv[2], argv[3]) ? 0 : 1;

    if (strcmp(argv[1], "ends") == 0 && argc >= 4)
        return zstr_ends_with(argv[2], argv[3]) ? 0 : 1;

    return usage();
}
