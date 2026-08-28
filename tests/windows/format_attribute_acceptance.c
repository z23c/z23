/* Compile-time acceptance for the project's portable printf annotation. */

#include "base/format_attribute.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

static int checked_format(const char *format, ...) ZCL_PRINTF_LIKE(1, 2);

static int checked_format(const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    int result = vfprintf(stderr, format, arguments);
    va_end(arguments);
    return result;
}

int main(void)
{
    size_t size = 23u;
    return checked_format("%zu\n", size) < 0;
}
