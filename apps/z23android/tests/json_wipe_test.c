/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "json/json.h"
#include <malloc.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A parsed string that outgrows its first block must not leave its text in a block that is freed unwritten, and must
 * not be moved by realloc, which frees the old block inside the C library where nothing can wipe it. */
#define MARK "SECRET!!"

void *__real_realloc(void *p, size_t n);
void __real_free(void *p);
void *__wrap_realloc(void *p, size_t n);
void __wrap_free(void *p);
static int reallocs;
static bool freed_unwiped;

void *__wrap_realloc(void *p, size_t n)
{
    ++reallocs;
    return __real_realloc(p, n);
}
void __wrap_free(void *p)
{
    if (p && malloc_usable_size(p) >= sizeof(MARK) - 1 && !memcmp(p, MARK, sizeof(MARK) - 1)) freed_unwiped = true;
    __real_free(p);
}

int main(void)
{
    static char text[2 + 8 * 200 + 1];
    struct json_value value;
    size_t length = 0;
    text[length++] = '"';
    for (int i = 0; i < 200; ++i, length += sizeof(MARK) - 1) memcpy(text + length, MARK, sizeof(MARK) - 1);
    text[length++] = '"';
    json_init(&value);
    reallocs = 0;
    if (!json_read(&value, text, length) || value.type != JSON_STR || strlen(json_get_str(&value)) != 8u * 200u) {
        fprintf(stderr, "json_wipe_test: the long string was not read\n");
        return 1;
    }
    if (reallocs != 0) {
        fprintf(stderr, "json_wipe_test: a growing string was moved by realloc %d time(s)\n", reallocs);
        return 1;
    }
    json_cleanse_strings(&value);
    json_free(&value);
    if (freed_unwiped) {
        fprintf(stderr, "json_wipe_test: a block holding the string was freed without being overwritten\n");
        return 1;
    }
    puts("json_wipe_test: ok");
    return 0;
}
