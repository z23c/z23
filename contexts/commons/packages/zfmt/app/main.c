/* zfmt CLI: format demonstration / smoke driver.
 *
 *   zfmt u64 <n> | i64 <n> | hex <n> | pad <n> <width> | double <v> <prec>
 *   zfmt template <name> <count>   "hello <name>, count=<count>"
 */
#include "zfmt/zfmt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

static int usage(void)
{
    fprintf(stderr,
        "usage: zfmt u64 <n> | i64 <n> | hex <n> | pad <n> <width>\n"
        "       zfmt double <v> <precision>\n"
        "       zfmt template <name> <count>\n");
    return 2;
}

static bool parse_unsigned(const char *text, uint64_t limit, uint64_t *out)
{
    const char *sign = text;
    while (isspace((unsigned char)*sign)) sign++;
    bool negative = *sign == '-';
    errno = 0;
    char *end;
    unsigned long long value = strtoull(text, &end, 10);
    if (end == text || *end || errno == ERANGE || value > limit ||
        (negative && value != 0)) return false;
    *out = (uint64_t)value;
    return true;
}

static bool parse_signed(const char *text, int64_t *out)
{
    errno = 0;
    char *end;
    long long value = strtoll(text, &end, 10);
    if (end == text || *end || errno == ERANGE || value < INT64_MIN || value > INT64_MAX)
        return false;
    *out = (int64_t)value;
    return true;
}

static bool parse_double(const char *text, double *out)
{
    errno = 0;
    char *end;
    double value = strtod(text, &end);
    if (end == text || *end || errno == ERANGE) return false;
    *out = value;
    return true;
}

static int bad_value(const char *field)
{
    fprintf(stderr, "zfmt: bad %s\n", field);
    return 2;
}

static int format_integer(zfmt *f, const char *command, const char *text)
{
    if (strcmp(command, "i64") == 0) {
        int64_t value;
        if (!parse_signed(text, &value)) return bad_value("signed integer");
        zfmt_i64(f, value);
    } else {
        uint64_t value;
        if (!parse_unsigned(text, UINT64_MAX, &value)) return bad_value("unsigned integer");
        if (strcmp(command, "hex") == 0) zfmt_hex64(f, value);
        else zfmt_u64(f, value);
    }
    return 0;
}

static int format_option(zfmt *f, int argc, char **argv)
{
    if (argc < 4) return usage();
    uint64_t option;
    if (!parse_unsigned(argv[3], UINT_MAX, &option)) return bad_value("width or precision");
    if (strcmp(argv[1], "pad") == 0) {
        uint64_t value;
        if (!parse_unsigned(argv[2], UINT64_MAX, &value)) return bad_value("unsigned integer");
        zfmt_u64_pad(f, value, (unsigned)option);
    } else {
        double value;
        if (!parse_double(argv[2], &value)) return bad_value("double");
        zfmt_double(f, value, (unsigned)option);
    }
    return 0;
}

static int format_template(zfmt *f, int argc, char **argv)
{
    if (argc < 4) return usage();
    uint64_t count;
    if (!parse_unsigned(argv[3], UINT64_MAX, &count)) return bad_value("count");
    zfmt_str(f, "hello ");
    zfmt_str(f, argv[2]);
    zfmt_str(f, ", count=");
    zfmt_u64(f, count);
    return 0;
}

static int finish_output(int written)
{
    if (written < 0 || fflush(stdout) != 0 || ferror(stdout)) {
        fprintf(stderr, "zfmt: output write failed\n");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) return usage();
    char buf[128];
    zfmt f;
    zfmt_init(&f, buf, sizeof buf);
    int result;
    if (strcmp(argv[1], "u64") == 0 || strcmp(argv[1], "i64") == 0 || strcmp(argv[1], "hex") == 0)
        result = format_integer(&f, argv[1], argv[2]);
    else if (strcmp(argv[1], "pad") == 0 || strcmp(argv[1], "double") == 0)
        result = format_option(&f, argc, argv);
    else if (strcmp(argv[1], "template") == 0) result = format_template(&f, argc, argv);
    else return usage();
    if (result) return result;
    if (!zfmt_ok(&f)) {
        fprintf(stderr, "zfmt: output truncated\n");
        return 1;
    }
    return finish_output(puts(zfmt_cstr(&f)));
}
