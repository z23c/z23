/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_RELAY_H
#define Z23_ANDROID_RELAY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
int zapp_relay_run(const char *directory, bool (*answer)(int client_fd,
    const char *prompt, char *out, size_t cap, const char **error));
bool zapp_relay_stopping(void);
/* False once the relay is stopping or client_fd disconnected; -1 checks only stopping. */
bool zapp_relay_client_alive(int client_fd);
/* Writes line and a newline to the client before the final reply; false once the client is gone.
 * The line must be one JSON object without a newline. */
bool zapp_relay_emit(int client_fd, const char *line);
int zapp_relay_run_sized(const char *directory, bool (*answer)(int client_fd,
    const char *prompt, char *out, size_t cap, const char **error),
    size_t prompt_limit, size_t answer_limit);
/* Fixed loopback port and a pairing secret persisted in DIRECTORY/pairing-secret, so a
 * restart without a new pairing offer reconnects. The speech bridge with --adb offers pairing at
 * every start, and each offer replaces the secret. Port 0 selects an ephemeral port. */
int zapp_relay_run_persistent(const char *directory, uint16_t port, bool (*answer)(int client_fd,
    const char *prompt, char *out, size_t cap, const char **error),
    size_t prompt_limit, size_t answer_limit);

/* Replaces the pairing secret of the running relay with a fresh one and publishes the new
 * descriptor, so the next pairing is the only one that works. False when no relay is running. */
bool zapp_relay_rotate(void);
#endif
