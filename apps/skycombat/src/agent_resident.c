/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: bounded native resident frames over the inherited game socket. */
#include "sky_combat/agent_resident.h"
#include "sky_combat/agent_session.h"
#include <raylib.h>
#include <errno.h>
#include <string.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#if !defined(_WIN32)
static const char sky_run_magic[16] = "z23-res-run-v1";
static const char sky_stop_magic[16] = "z23-res-stop-v1";
static volatile sig_atomic_t sky_raise_pending;
static struct sigaction sky_raise_previous;
static bool sky_raise_installed;

static void sky_game_raise_signal(int signum)
{
    (void)signum;
    sky_raise_pending = 1;
}
#endif

bool sky_game_raise_open(void)
{
#if !defined(_WIN32)
    if (sky_raise_installed) return true;
    /* poll still wakes for the signal; restart stdio's blocking reply writes. */
    struct sigaction action = {.sa_handler = sky_game_raise_signal, .sa_flags = SA_RESTART};
    sky_raise_pending = 0;
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaction(SIGUSR1, &action, &sky_raise_previous) != 0) return false;
    sky_raise_installed = true;
#endif
    return true;
}

bool sky_game_raise_close(void)
{
#if !defined(_WIN32)
    if (sky_raise_installed && sigaction(SIGUSR1, &sky_raise_previous, NULL) != 0)
        return false;
    sky_raise_installed = false;
    sky_raise_pending = 0;
#endif
    return true;
}

void sky_game_raise_apply(void)
{
#if !defined(_WIN32)
    if (sky_raise_pending && IsWindowReady()) {
        sky_raise_pending = 0;
        RestoreWindow();
        SetWindowFocused();
    }
#endif
}

void sky_game_event_pump(void)
{
    if (!IsWindowReady()) return;
    PollInputEvents();
    sky_game_raise_apply();
}

bool sky_resident_nonce_valid(const char *nonce)
{
    if (!nonce || strlen(nonce) != RESIDENT_LAUNCH_NONCE_HEX) return false;
    for (size_t i = 0; i < RESIDENT_LAUNCH_NONCE_HEX; i++)
        if (!((nonce[i] >= '0' && nonce[i] <= '9') ||
              (nonce[i] >= 'a' && nonce[i] <= 'f'))) return false;
    return true;
}

#if !defined(_WIN32)
/* Poll between fragments, never block the window event pump in read/write.
 * No child timer can extend or replace the external launcher's watchdog. */
static bool sky_resident_ready(short events)
{
    for (;;) {
        if (IsWindowReady()) {
            sky_game_event_pump();
            if (WindowShouldClose()) return false;
        }
        struct pollfd p = {.fd = RESIDENT_LAUNCH_CHILD_FD, .events = events};
        int ready = poll(&p, 1, 16);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return false;
        if (ready) return !(p.revents & POLLNVAL);
    }
}

static int sky_resident_bytes(void *buffer, size_t length)
{
    size_t used = 0;
    while (used < length) {
        if (!sky_resident_ready(POLLIN)) return -1;
        ssize_t got = read(RESIDENT_LAUNCH_CHILD_FD, (char *)buffer + used, length - used);
        if (got < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (got < 0) return -1;
        if (!got) return used ? -2 : 0;
        used += (size_t)got;
    }
    return 1;
}

static bool sky_resident_send(const void *buffer, size_t length)
{
    size_t sent = 0;
    while (sent < length) {
        if (!sky_resident_ready(POLLOUT)) return false;
        ssize_t wrote = write(RESIDENT_LAUNCH_CHILD_FD,
                               (const char *)buffer + sent, length - sent);
        if (wrote < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (wrote <= 0) return false;
        sent += (size_t)wrote;
    }
    return true;
}
#endif

bool sky_resident_write(struct sky_resident_channel *channel,
                         const char *payload, size_t length)
{
#if defined(_WIN32)
    (void)channel; (void)payload; (void)length;
    return false;
#else
    if (!channel->active || length > SKY_AGENT_REPLY_MAX) return false;
    struct resident_result_header header = {0};
    memcpy(header.magic, sky_run_magic, sizeof(header.magic));
    memcpy(header.nonce, channel->nonce, sizeof(header.nonce));
    header.payload_len = (uint32_t)length;
    return sky_resident_send(&header, sizeof(header)) && sky_resident_send(payload, length);
#endif
}

bool sky_resident_open(struct sky_resident_channel *channel, const char *nonce)
{
#if defined(_WIN32)
    (void)channel; (void)nonce;
    return false;
#else
    int kind = 0;
    socklen_t size = sizeof(kind);
    if (!sky_resident_nonce_valid(nonce) ||
        getsockopt(RESIDENT_LAUNCH_CHILD_FD, SOL_SOCKET, SO_TYPE, &kind, &size) != 0 ||
        kind != SOCK_STREAM) return false;
    int flags = fcntl(RESIDENT_LAUNCH_CHILD_FD, F_GETFL);
    if (flags < 0 || fcntl(RESIDENT_LAUNCH_CHILD_FD, F_SETFL, flags | O_NONBLOCK) < 0)
        return false;
    channel->active = true;
    memcpy(channel->nonce, nonce, sizeof(channel->nonce));
    /* Protocol entry only: renderer initialization intentionally follows. */
    return sky_resident_write(channel, "READY", 5);
#endif
}

bool sky_resident_close(struct sky_resident_channel *channel)
{
    if (!channel->active) return true;
    channel->active = false;
#if defined(_WIN32)
    return false;
#else
    return close(RESIDENT_LAUNCH_CHILD_FD) == 0;
#endif
}

int sky_resident_read(struct sky_resident_channel *channel, char *payload,
                       size_t *length)
{
#if defined(_WIN32)
    (void)channel; (void)payload; (void)length;
    return -1;
#else
    struct resident_result_header header = {0};
    /* STOP has no native padding or payload_len: inspect its 81 bytes first. */
    const size_t prefix = sizeof(header.magic) + sizeof(header.nonce);
    int status = sky_resident_bytes(&header, prefix);
    if (status != 1) return status;
    if (memcmp(header.nonce, channel->nonce, sizeof(header.nonce))) return -4;
    if (!memcmp(header.magic, sky_stop_magic, sizeof(header.magic))) return 0;
    if (memcmp(header.magic, sky_run_magic, sizeof(header.magic))) return -4;
    status = sky_resident_bytes((char *)&header + prefix, sizeof(header) - prefix);
    if (status != 1) return status == 0 ? -2 : status;
    if (header.payload_len > SKY_AGENT_LINE_MAX) return -3;
    status = sky_resident_bytes(payload, header.payload_len);
    if (status != 1) return status == 0 ? -2 : status;
    *length = header.payload_len;
    payload[*length] = '\0';
    return 1;
#endif
}
