/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_HOST_H
#define Z23_ANDROID_HOST_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

enum { ZAPP_HOST_CHAT, ZAPP_HOST_ASR, ZAPP_HOST_TTS, ZAPP_HOST_SERVERS };
struct zapp_host_servers { pid_t pid[ZAPP_HOST_SERVERS]; uint16_t port[ZAPP_HOST_SERVERS]; };
/* Starts the pinned chat, ASR and TTS models from MODELS on consecutive loopback
 * ports after base_port, logging to DIRECTORY/<role>.log, then waits for health. */
bool zapp_host_start(const char *llama_server, const char *models, const char *directory,
                     uint16_t base_port, struct zapp_host_servers *servers);
void zapp_host_stop(struct zapp_host_servers *servers);
/* Maps the phone's loopback port to the same port on this host. */
bool zapp_host_route(const char *adb, const char *serial, uint16_t port);
/* Maps the phone's loopback port to this host and offers the descriptor to the app.
 * The token reaches adb on standard input, not in laptop process arguments; on the phone
 * it is briefly visible to shell and root in the arguments of the am command. */
bool zapp_host_offer_pairing(const char *adb, const char *serial, const char *app, uint16_t port,
                             const char *directory);
/* Reads a regular file of at most cap bytes owned by this user. */
bool zapp_host_read_file(const char *path, size_t cap, unsigned char **bytes, size_t *size);
#endif
