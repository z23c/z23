/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_STARTUP_AUTH_H
#define ZAPP_STARTUP_AUTH_H
#include <stdbool.h>
#include <stdint.h>
struct zapp_startup_auth;
typedef bool (*zapp_startup_auth_unwrap)(struct zapp_startup_auth *, const char *files, uint8_t secret[32]);
typedef void (*zapp_startup_auth_cancel_fn)(void *ctx);
bool zapp_startup_auth_register_cancel(struct zapp_startup_auth *, zapp_startup_auth_cancel_fn, void *ctx);
void zapp_startup_auth_unregister_cancel(struct zapp_startup_auth *);
void zapp_startup_auth_provider(zapp_startup_auth_unwrap unwrap);
struct zapp_startup_auth *zapp_startup_auth_new(void);
/* Takes ownership of fd on success only. */
bool zapp_startup_auth_start(struct zapp_startup_auth *auth, int fd, const char *files);
void zapp_startup_auth_cancel(struct zapp_startup_auth *auth);
void zapp_startup_auth_reset(struct zapp_startup_auth *auth);
bool zapp_startup_auth_ready(struct zapp_startup_auth *auth);
bool zapp_startup_auth_refused(struct zapp_startup_auth *auth);
void zapp_startup_auth_free(struct zapp_startup_auth *auth);
#endif
