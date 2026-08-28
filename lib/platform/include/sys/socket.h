/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: POSIX socket declarations backed by Winsock on native Windows. */

#ifndef ZCL_PLATFORM_SYS_SOCKET_H
#define ZCL_PLATFORM_SYS_SOCKET_H

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#else
#if defined(__GNUC__)
#pragma GCC system_header
#endif
#include_next <sys/socket.h>
#endif

#endif
