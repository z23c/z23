/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: receive startup wallet authentication over an inherited local stream. */
#ifndef Z23_PLATFORM_WALLET_STARTUP_AUTH_H
#define Z23_PLATFORM_WALLET_STARTUP_AUTH_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Consumes an inherited same-user local stream, closes it, and clears out on refusal. */
bool platform_wallet_startup_auth_receive(int fd, int64_t timeout_ms, char *out, size_t cap);
void platform_wallet_startup_auth_close(int fd);
#endif
