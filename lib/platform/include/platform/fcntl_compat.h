/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: descriptor flag spellings shared by POSIX and native Windows. */
#ifndef ZCL_PLATFORM_FCNTL_COMPAT_H
#define ZCL_PLATFORM_FCNTL_COMPAT_H
#include <fcntl.h>
#if defined(_WIN32) && !defined(O_CLOEXEC)
#define O_CLOEXEC O_NOINHERIT
#endif
#endif
