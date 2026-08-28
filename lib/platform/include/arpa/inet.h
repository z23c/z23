/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef ZCL_PLATFORM_ARPA_INET_H
#define ZCL_PLATFORM_ARPA_INET_H
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#if defined(__GNUC__)
#pragma GCC system_header
#endif
#include_next <arpa/inet.h>
#endif
#endif
