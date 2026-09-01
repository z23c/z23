/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: process environment mutation without application-level OS forks. */

#ifndef ZCL_PLATFORM_ENVIRONMENT_COMPAT_H
#define ZCL_PLATFORM_ENVIRONMENT_COMPAT_H

#include <stdlib.h>

static inline int platform_environment_set(const char *name,
                                           const char *value,
                                           int overwrite)
{
#if defined(_WIN32)
    if (!overwrite && getenv(name) != NULL)
        return 0;
    return _putenv_s(name, value);
#else
    return setenv(name, value, overwrite);
#endif
}

#endif
