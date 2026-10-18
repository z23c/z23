/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared path and text checks. Contract in util/path_util.h. */

#include "util/path_util.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

bool zcl_path_join(char *out, size_t cap, const char *a, const char *b)
{
    if (!out || !a || !b)
        return false;
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

bool zcl_path_is_dir(const char *path)
{
    struct stat st;
    return path && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

bool zcl_is_lower_hex(const char *s, size_t len)
{
    if (!s || strlen(s) != len)
        return false;
    for (size_t i = 0; i < len; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}
