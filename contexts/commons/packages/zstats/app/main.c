/* zstats CLI: streaming statistics over numbers from stdin or args.
 *
 *   zstats [n]...          reads doubles; prints n, min, max, mean,
 *                          stddev (population), total
 */
#include "zstats/zstats.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

static bool parse_number(const char *text, double *out)
{
    errno = 0;
    char *end;
    double value = strtod(text, &end);
    if (end == text || *end || errno == ERANGE) return false;
    *out = value;
    return true;
}

struct input_token { char *data; size_t len, cap; };

static bool token_append(struct input_token *token, unsigned char byte)
{
    if (token->len > SIZE_MAX - 2) return false;
    size_t need = token->len + 2;
    if (need > token->cap) {
        size_t cap = token->cap ? token->cap : 128;
        if (cap < need) cap = cap <= SIZE_MAX / 2 ? cap * 2 : SIZE_MAX;
        if (cap < need) cap = need;
        char *grown = realloc(token->data, cap); // raw-alloc-ok:checked-input-token
        if (!grown) return false;
        token->data = grown;
        token->cap = cap;
    }
    token->data[token->len++] = (char)byte;
    token->data[token->len] = '\0';
    return true;
}

static bool accept_token(zstats *s, struct input_token *token)
{
    double value;
    if (!parse_number(token->data, &value)) {
        fprintf(stderr, "zstats: bad number on stdin\n");
        return false;
    }
    zstats_add(s, value);
    token->len = 0;
    return true;
}

static int accept_byte(zstats *s, struct input_token *token, unsigned char byte)
{
    if (byte == 0) {
        fprintf(stderr, "zstats: bad number on stdin (NUL byte)\n");
        return 2;
    }
    if (isspace(byte)) {
        if (!token->len) return 0;
        return accept_token(s, token) ? 0 : 2;
    }
    if (!token_append(token, byte)) {
        fprintf(stderr, "zstats: cannot allocate input token\n");
        return 1;
    }
    return 0;
}

static int read_numbers(zstats *s)
{
    struct input_token token = {0};
    int byte, result = 0;
    while (result == 0 && (byte = fgetc(stdin)) != EOF)
        result = accept_byte(s, &token, (unsigned char)byte);
    if (result == 0) {
        if (ferror(stdin)) {
            fprintf(stderr, "zstats: read error\n");
            result = 1;
        } else if (token.len && !accept_token(s, &token)) result = 2;
    }
    free(token.data);
    return result;
}

static int print_summary(const zstats *s)
{
    if (printf("n      %llu\n", (unsigned long long)zstats_count(s)) < 0 ||
        printf("min    %.17g\n", zstats_min(s)) < 0 ||
        printf("max    %.17g\n", zstats_max(s)) < 0 ||
        printf("mean   %.17g\n", zstats_mean(s)) < 0 ||
        printf("stddev %.17g\n", zstats_stddev(s)) < 0 ||
        printf("total  %.17Lg\n", zstats_total(s)) < 0 ||
        fflush(stdout) != 0 || ferror(stdout)) {
        fprintf(stderr, "zstats: write error\n");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    zstats s;
    zstats_init(&s);

    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            double v;
            if (!parse_number(argv[i], &v)) {
                fprintf(stderr, "zstats: bad number %s\n", argv[i]);
                return 2;
            }
            zstats_add(&s, v);
        }
    } else {
        int result = read_numbers(&s);
        if (result) return result;
    }

    return print_summary(&s);
}
