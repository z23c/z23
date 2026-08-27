/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: owner-only, nonce-bound local transport for inert native views. */

#define _GNU_SOURCE
#include "views/ui_present_host.h"
#include "views/ui_present_host_transport.h"

#include "base/serialize_le.h"
#include "platform/rng.h"
#include "presentation/model.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static const uint8_t UI_HOST_REQUEST_MAGIC[4] = {'Z', 'P', 'H', 'R'};
static const uint8_t UI_HOST_REPLY_MAGIC[4] = {'Z', 'P', 'H', 'A'};

static int ui_host_stream_socket(void)
{
#if defined(SOCK_CLOEXEC)
    return socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd >= 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
#endif
}

bool ui_present_host_display_ready(char *why, size_t why_cap)
{
    const char *display = getenv("DISPLAY");
    if (!display || !display[0]) {
        if (why && why_cap > 0)
            (void)snprintf(why, why_cap,
                           "native C23 presentation requires DISPLAY");
        return false;
    }
    if (why && why_cap > 0) why[0] = '\0';
    return true;
}

static uint32_t ui_host_display_hash(void)
{
    const unsigned char *display =
        (const unsigned char *)(getenv("DISPLAY") ? getenv("DISPLAY") : "");
    uint32_t hash = 2166136261u;
    while (*display) {
        hash ^= *display++;
        hash *= 16777619u;
    }
    return hash;
}

static bool ui_host_private_directory(char out[PATH_MAX])
{
    const char *runtime = getenv("XDG_RUNTIME_DIR");
    char fallback[64];
    bool using_fallback = !runtime || runtime[0] != '/';
    if (using_fallback) {
        int n = snprintf(fallback, sizeof(fallback),
                         "/tmp/zclassic23-presentation-%lu",
                         (unsigned long)geteuid());
        if (n <= 0 || (size_t)n >= sizeof(fallback)) return false;
        runtime = fallback;
    }
    int n = using_fallback
        ? snprintf(out, PATH_MAX, "%s", runtime)
        : snprintf(out, PATH_MAX, "%s/zclassic23-presentation", runtime);
    if (n <= 0 || n >= PATH_MAX) return false;
    if (mkdir(out, 0700) != 0 && errno != EEXIST) return false;
    struct stat st;
    if (lstat(out, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 077u) != 0)
        return false;
    return true;
}

static socklen_t ui_host_address(struct sockaddr_un *address)
{
    char directory[PATH_MAX];
    if (!ui_host_private_directory(directory)) return 0;
    memset(address, 0, sizeof(*address));
    address->sun_family = AF_UNIX;
    int length = snprintf(address->sun_path, sizeof(address->sun_path),
                          "%s/host-v%u-%08x.sock", directory,
                          UI_HOST_PROTOCOL_VERSION, ui_host_display_hash());
    if (length <= 0 || (size_t)length >= sizeof(address->sun_path)) return 0;
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                       (size_t)length + 1u);
}

int ui_host_transport_connect_once(void)
{
    struct sockaddr_un address;
    socklen_t address_len = ui_host_address(&address);
    if (address_len == 0) {
        errno = EINVAL;
        return -1;
    }
    int fd = ui_host_stream_socket();
    if (fd < 0) return -1;
    if (connect(fd, (const struct sockaddr *)&address, address_len) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

bool ui_host_transport_send_all(int fd, const uint8_t *bytes, size_t length)
{
    size_t sent = 0;
    while (sent < length) {
        ssize_t count = send(fd, bytes + sent, length - sent, MSG_NOSIGNAL);
        if (count > 0) {
            sent += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

bool ui_host_transport_recv_all(int fd, uint8_t *bytes, size_t length,
                                int timeout_ms)
{
    size_t received = 0;
    while (received < length) {
        struct pollfd wait = {.fd = fd, .events = POLLIN};
        int ready;
        do {
            ready = poll(&wait, 1, timeout_ms);
        } while (ready < 0 && errno == EINTR);
        if (ready <= 0 || !(wait.revents & (POLLIN | POLLHUP))) {
            if (ready == 0) errno = ETIMEDOUT;
            return false;
        }
        ssize_t count = recv(fd, bytes + received, length - received, 0);
        if (count > 0) {
            received += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        if (count == 0) errno = ECONNRESET;
        return false;
    }
    return true;
}

bool ui_host_transport_nonce(uint8_t nonce[UI_HOST_NONCE_BYTES])
{
    if (!rng_fill(nonce, UI_HOST_NONCE_BYTES))
        LOG_RETURN(false, "presentation",
                   "resident host request nonce entropy unavailable");
    uint8_t any = 0;
    for (size_t i = 0; i < UI_HOST_NONCE_BYTES; i++) any |= nonce[i];
    if (any == 0)
        LOG_RETURN(false, "presentation",
                   "resident host request nonce was all zero");
    return true;
}

void ui_host_transport_request_header(
    uint8_t out[UI_HOST_REQUEST_BYTES], uint16_t flags, uint32_t model_len,
    const uint8_t nonce[UI_HOST_NONCE_BYTES])
{
    memcpy(out, UI_HOST_REQUEST_MAGIC, sizeof(UI_HOST_REQUEST_MAGIC));
    zcl_write_u16_le(out + 4u, UI_HOST_PROTOCOL_VERSION);
    zcl_write_u16_le(out + 6u, flags);
    zcl_write_u32_le(out + 8u, model_len);
    zcl_write_u32_le(out + 12u, 0);
    memcpy(out + 16u, nonce, UI_HOST_NONCE_BYTES);
}

bool ui_host_transport_parse_request_header(
    const uint8_t in[UI_HOST_REQUEST_BYTES], uint16_t *flags,
    uint32_t *model_len, uint8_t nonce[UI_HOST_NONCE_BYTES])
{
    if (memcmp(in, UI_HOST_REQUEST_MAGIC,
               sizeof(UI_HOST_REQUEST_MAGIC)) != 0 ||
        zcl_read_u16_le(in + 4u) != UI_HOST_PROTOCOL_VERSION ||
        zcl_read_u32_le(in + 12u) != 0)
        return false;
    *flags = zcl_read_u16_le(in + 6u);
    *model_len = zcl_read_u32_le(in + 8u);
    memcpy(nonce, in + 16u, UI_HOST_NONCE_BYTES);
    uint8_t any = 0;
    for (size_t i = 0; i < UI_HOST_NONCE_BYTES; i++) any |= nonce[i];
    return any != 0 && (*flags & ~UI_HOST_FLAG_WAIT_EVENT) == 0 &&
           *model_len > 0 && *model_len <= ZCL_PRESENT_MODEL_WIRE_MAX;
}

void ui_host_transport_reply(
    uint8_t out[UI_HOST_REPLY_BYTES], uint16_t phase, uint32_t status,
    uint32_t value, uint32_t payload_len, uint64_t elapsed_us,
    const uint8_t nonce[UI_HOST_NONCE_BYTES])
{
    memcpy(out, UI_HOST_REPLY_MAGIC, sizeof(UI_HOST_REPLY_MAGIC));
    zcl_write_u16_le(out + 4u, UI_HOST_PROTOCOL_VERSION);
    zcl_write_u16_le(out + 6u, phase);
    zcl_write_u32_le(out + 8u, status);
    zcl_write_u32_le(out + 12u, value);
    zcl_write_u32_le(out + 16u, payload_len);
    zcl_write_u32_le(out + 20u, 0);
    zcl_write_u64_le(out + 24u, elapsed_us);
    memcpy(out + 32u, nonce, UI_HOST_NONCE_BYTES);
}

bool ui_host_transport_parse_reply(
    const uint8_t in[UI_HOST_REPLY_BYTES], uint16_t expected_phase,
    uint32_t *status, uint32_t *value, uint32_t *payload_len,
    uint64_t *elapsed_us,
    const uint8_t nonce[UI_HOST_NONCE_BYTES])
{
    if (memcmp(in, UI_HOST_REPLY_MAGIC, sizeof(UI_HOST_REPLY_MAGIC)) != 0 ||
        zcl_read_u16_le(in + 4u) != UI_HOST_PROTOCOL_VERSION ||
        zcl_read_u16_le(in + 6u) != expected_phase ||
        zcl_read_u32_le(in + 20u) != 0 ||
        memcmp(in + 32u, nonce, UI_HOST_NONCE_BYTES) != 0)
        return false;
    *status = zcl_read_u32_le(in + 8u);
    *value = zcl_read_u32_le(in + 12u);
    *payload_len = zcl_read_u32_le(in + 16u);
    *elapsed_us = zcl_read_u64_le(in + 24u);
    return *payload_len <= ZCL_PRESENT_MODEL_WIRE_MAX;
}

bool ui_host_transport_peer_allowed(int client)
{
#if defined(__APPLE__)
    uid_t peer_uid;
    gid_t peer_gid;
    return getpeereid(client, &peer_uid, &peer_gid) == 0 &&
           peer_uid == geteuid();
#else
    struct ucred peer;
    socklen_t peer_len = sizeof(peer);
    return getsockopt(client, SOL_SOCKET, SO_PEERCRED,
                      &peer, &peer_len) == 0 &&
           peer_len == sizeof(peer) && peer.uid == geteuid();
#endif
}

int ui_host_transport_listen(void)
{
    struct sockaddr_un address;
    socklen_t address_len = ui_host_address(&address);
    if (address_len == 0) return -1;
    int listener = ui_host_stream_socket();
    if (listener < 0) return -1;
    if (bind(listener, (const struct sockaddr *)&address, address_len) != 0) {
        int bind_error = errno;
        if (bind_error != EADDRINUSE) {
            close(listener);
            errno = bind_error;
            return -1;
        }
        struct stat st;
        int probe = ui_host_transport_connect_once();
        if (probe >= 0) {
            close(probe);
            close(listener);
            errno = EADDRINUSE;
            return -1;
        }
        if (lstat(address.sun_path, &st) != 0 || !S_ISSOCK(st.st_mode) ||
            st.st_uid != geteuid() || unlink(address.sun_path) != 0 ||
            bind(listener, (const struct sockaddr *)&address,
                 address_len) != 0) {
            int saved = errno;
            close(listener);
            errno = saved;
            return -1;
        }
    }
    if (chmod(address.sun_path, 0600) != 0 || listen(listener, 16) != 0) {
        int saved = errno;
        close(listener);
        errno = saved;
        return -1;
    }
    return listener;
}

void ui_host_transport_cleanup(void)
{
    struct sockaddr_un address;
    if (ui_host_address(&address) != 0) (void)unlink(address.sun_path);
}
