/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "history.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned triangular(unsigned count)
{
    return count * (count + 1) / 2;
}

static int check_render(unsigned count, unsigned expected)
{
    char actual[64];
    char wanted[64];
    int length = snprintf(wanted, sizeof(wanted), "count=%u sum=%u\n",
                          count, expected);
    if (length < 0 || (size_t)length >= sizeof(wanted) ||
        !history_render(count, false, actual, sizeof(actual)) ||
        strcmp(actual, wanted)) {
        fprintf(stderr, "text mismatch count=%u\n", count);
        return 1;
    }
    length = snprintf(wanted, sizeof(wanted),
                      "{\"count\":%u,\"sum\":%u}\n", count, expected);
    if (length < 0 || (size_t)length >= sizeof(wanted) ||
        !history_render(count, true, actual, sizeof(actual)) ||
        strcmp(actual, wanted)) {
        fprintf(stderr, "JSON mismatch count=%u\n", count);
        return 1;
    }
    return 0;
}

static int parse_revision(int argc, char **argv, unsigned *out_limit)
{
    if (argc != 2) {
        fprintf(stderr, "usage: history-exhaustive REVISION\n");
        return 2;
    }
    char *end = NULL;
    errno = 0;
    const unsigned long parsed = strtoul(argv[1], &end, 10);
    if (errno || end == argv[1] || *end || parsed > 100) {
        fprintf(stderr, "invalid revision: %s\n", argv[1]);
        return 2;
    }
    *out_limit = (unsigned)parsed;
    return 0;
}

static int check_prefixes(unsigned limit)
{
    for (unsigned count = 0; count <= limit; count++) {
        unsigned actual = 0;
        const unsigned expected = triangular(count);
        if (!history_prefix(count, &actual) || actual != expected) {
            fprintf(stderr, "prefix mismatch count=%u\n", count);
            return 1;
        }
        if (check_render(count, expected)) return 1;
        char text[16];
        const int length = snprintf(text, sizeof(text), "%u", count);
        unsigned parsed_count = 0;
        if (length < 0 || (size_t)length >= sizeof(text) ||
            !history_parse_count(text, &parsed_count) || parsed_count != count) {
            fprintf(stderr, "parse mismatch count=%u\n", count);
            return 1;
        }
    }
    return 0;
}

static int check_ranges(unsigned limit)
{
    for (unsigned first = 0; first <= limit; first++) {
        for (unsigned count = 0; count <= limit - first; count++) {
            unsigned actual = 0;
            const unsigned expected = triangular(first + count) - triangular(first);
            if (!history_range(first, count, &actual) || actual != expected) {
                fprintf(stderr, "range mismatch first=%u count=%u\n", first, count);
                return 1;
            }
        }
    }
    return 0;
}

static int check_invalid(unsigned limit)
{
    char small[2];
    if (history_render(limit, false, small, sizeof(small)) || small[0] ||
        history_render(limit + 1, false, small, sizeof(small)) || small[0]) {
        fprintf(stderr, "invalid render was not refused\n");
        return 1;
    }
    unsigned rejected = 99;
    if (history_parse_count(" 75", &rejected) || rejected ||
        history_parse_count("+75", &rejected) || rejected ||
        history_parse_count("42949672960", &rejected) || rejected) {
        fprintf(stderr, "noncanonical count was not refused\n");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    unsigned limit = 0;
    const int input_exit = parse_revision(argc, argv, &limit);
    if (input_exit) return input_exit;
    if (check_prefixes(limit) || check_ranges(limit) || check_invalid(limit))
        return 1;
    const unsigned prefixes = limit + 1;
    const unsigned ranges = (limit + 1) * (limit + 2) / 2;
    printf("prefix=%u range=%u render=%u parse=%u invalid=5 pass\n",
           prefixes, ranges, prefixes * 2, prefixes);
    return 0;
}
