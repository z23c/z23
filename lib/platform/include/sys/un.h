/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef ZCL_PLATFORM_SYS_UN_H
#define ZCL_PLATFORM_SYS_UN_H
#if defined(_WIN32)
#include <winsock2.h>
#include <afunix.h>
#else
#if defined(__GNUC__)
#pragma GCC system_header
#endif
#include_next <sys/un.h>
#endif
#endif
