/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Compile-time acceptance for the project's portable printf annotation. */
#if defined(_WIN32)

#include "base/format_attribute.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

static int checked_format(const char *format, ...) ZCL_PRINTF_LIKE(1, 2);

static int checked_format(const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    int result = vfprintf(stderr, format, arguments); // obs-ok:test-diagnostic
    va_end(arguments);
    return result;
}

int main(void)
{
    size_t size = 23u;
    return checked_format("%zu\n", size) < 0;
}

#else
typedef int format_attribute_windows_acceptance_not_built;
#endif
