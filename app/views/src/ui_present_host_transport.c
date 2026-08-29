/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: owner-only, nonce-bound local transport for inert native views. */

#define _GNU_SOURCE
#include "views/ui_present_host.h"
#include "views/ui_present_host_transport.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "platform/time_compat.h"
#include "platform/rng.h"
#include "platform/socket_compat.h"
#include "presentation/model.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#endif

static const uint8_t UI_HOST_REQUEST_MAGIC[4] = {'Z', 'P', 'H', 'R'};
static const uint8_t UI_HOST_REPLY_MAGIC[4] = {'Z', 'P', 'H', 'A'};

#if defined(_WIN32)
static HANDLE ui_host_handle(ui_host_transport_t stream)
{
    return (HANDLE)(uintptr_t)stream;
}

static ui_host_transport_t ui_host_stream(HANDLE handle)
{
    return handle == INVALID_HANDLE_VALUE ? UI_HOST_TRANSPORT_INVALID
                                          : (ui_host_transport_t)(uintptr_t)handle;
}

static bool ui_host_pipe_name(wchar_t out[256])
{
    HANDLE token = NULL;
    DWORD bytes = 0;
    TOKEN_USER *user = NULL;
    LPWSTR sid = NULL;
    bool ok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) &&
              !GetTokenInformation(token, TokenUser, NULL, 0, &bytes) &&
              GetLastError() == ERROR_INSUFFICIENT_BUFFER;
    if (ok) user = zcl_malloc(bytes, "ui_host_token_user");
    ok = ok && user && GetTokenInformation(token, TokenUser, user, bytes,
                                            &bytes) &&
         ConvertSidToStringSidW(user->User.Sid, &sid) != 0;
    if (ok) {
        int written = swprintf(out, 256, L"\\\\.\\pipe\\z23-ui-host-v%u-%ls",
                               UI_HOST_PROTOCOL_VERSION, sid);
        ok = written > 0 && written < 256;
    }
    if (sid) LocalFree(sid);
    free(user);
    if (token) CloseHandle(token);
    return ok;
}

static HANDLE ui_host_pipe_instance(void)
{
    wchar_t name[256];
    if (!ui_host_pipe_name(name)) return INVALID_HANDLE_VALUE;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    HANDLE token = NULL;
    DWORD bytes = 0;
    TOKEN_USER *user = NULL;
    LPWSTR sid = NULL;
    wchar_t sddl[512];
    bool ok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) &&
              !GetTokenInformation(token, TokenUser, NULL, 0, &bytes) &&
              GetLastError() == ERROR_INSUFFICIENT_BUFFER;
    if (ok) user = zcl_malloc(bytes, "ui_host_pipe_token_user");
    ok = ok && user && GetTokenInformation(token, TokenUser, user, bytes,
                                            &bytes) &&
         ConvertSidToStringSidW(user->User.Sid, &sid) != 0;
    if (ok) {
        int written = swprintf(sddl, 512,
            L"D:P(A;;GA;;;SY)(A;;GA;;;%ls)", sid);
        ok = written > 0 && written < 512 &&
             ConvertStringSecurityDescriptorToSecurityDescriptorW(
                 sddl, SDDL_REVISION_1, &descriptor, NULL) != 0;
    }
    SECURITY_ATTRIBUTES security = {
        .nLength = sizeof(security),
        .lpSecurityDescriptor = descriptor,
        .bInheritHandle = FALSE,
    };
    HANDLE pipe = ok ? CreateNamedPipeW(
        name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
            PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_UNLIMITED_INSTANCES, ZCL_PRESENT_MODEL_WIRE_MAX,
        ZCL_PRESENT_MODEL_WIRE_MAX, 0, &security) : INVALID_HANDLE_VALUE;
    if (descriptor) LocalFree(descriptor);
    if (sid) LocalFree(sid);
    free(user);
    if (token) CloseHandle(token);
    return pipe;
}

static bool ui_host_overlapped_io(HANDLE pipe, bool write, void *buffer,
                                  size_t length, int timeout_ms)
{
    size_t done = 0;
    while (done < length) {
        DWORD part = length - done > UINT32_MAX ? UINT32_MAX
                                                : (DWORD)(length - done);
        OVERLAPPED overlap = {0};
        overlap.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!overlap.hEvent) return false;
        DWORD transferred = 0;
        BOOL started = write
            ? WriteFile(pipe, (uint8_t *)buffer + done, part, &transferred,
                        &overlap)
            : ReadFile(pipe, (uint8_t *)buffer + done, part, &transferred,
                       &overlap);
        DWORD error = started ? ERROR_SUCCESS : GetLastError();
        bool ok = started || error == ERROR_IO_PENDING;
        if (ok && error == ERROR_IO_PENDING) {
            DWORD wait = WaitForSingleObject(overlap.hEvent,
                timeout_ms < 0 ? INFINITE : (DWORD)timeout_ms);
            ok = wait == WAIT_OBJECT_0 &&
                 GetOverlappedResult(pipe, &overlap, &transferred, FALSE);
            if (!ok) {
                (void)CancelIoEx(pipe, &overlap);
                (void)WaitForSingleObject(overlap.hEvent, INFINITE);
            }
        }
        CloseHandle(overlap.hEvent);
        if (!ok || transferred == 0) return false;
        done += transferred;
    }
    return true;
}
#else
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
#endif

bool ui_present_host_display_ready(char *why, size_t why_cap)
{
#if defined(_WIN32)
    if (why && why_cap > 0) why[0] = '\0';
    return GetProcessWindowStation() != NULL;
#else
    const char *display = getenv("DISPLAY");
    if (!display || !display[0]) {
        if (why && why_cap > 0)
            (void)snprintf(why, why_cap,
                           "native C23 presentation requires DISPLAY");
        return false;
    }
    if (why && why_cap > 0) why[0] = '\0';
    return true;
#endif
}

#if !defined(_WIN32)
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
#endif

ui_host_transport_t ui_host_transport_connect_once(void)
{
#if defined(_WIN32)
    wchar_t name[256];
    if (!ui_host_pipe_name(name)) return UI_HOST_TRANSPORT_INVALID;
    HANDLE pipe = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                              OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    return ui_host_stream(pipe);
#else
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
#endif
}

void ui_host_transport_close(ui_host_transport_t stream)
{
#if defined(_WIN32)
    if (stream != UI_HOST_TRANSPORT_INVALID) CloseHandle(ui_host_handle(stream));
#else
    if (stream >= 0) close(stream);
#endif
}

bool ui_host_transport_send_all(ui_host_transport_t fd,
                                const uint8_t *bytes, size_t length)
{
#if defined(_WIN32)
    return ui_host_overlapped_io(ui_host_handle(fd), true, (void *)bytes,
                                 length, 3000);
#else
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
#endif
}

bool ui_host_transport_recv_all(ui_host_transport_t fd, uint8_t *bytes,
                                size_t length,
                                int timeout_ms)
{
#if defined(_WIN32)
    return ui_host_overlapped_io(ui_host_handle(fd), false, bytes, length,
                                 timeout_ms);
#else
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
#endif
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

bool ui_host_transport_peer_allowed(ui_host_transport_t client)
{
#if defined(_WIN32)
    HANDLE pipe = ui_host_handle(client);
    HANDLE process_token = NULL;
    HANDLE client_token = NULL;
    HANDLE client_process = NULL;
    ULONG client_pid = 0;
    DWORD process_bytes = 0;
    DWORD client_bytes = 0;
    TOKEN_USER *process_user = NULL;
    TOKEN_USER *client_user = NULL;
    bool ok = GetNamedPipeClientProcessId(pipe, &client_pid) &&
              client_pid != 0 &&
              (client_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                            FALSE, client_pid)) != NULL &&
              OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY,
                               &process_token) &&
              OpenProcessToken(client_process, TOKEN_QUERY, &client_token);
    if (ok) {
        (void)GetTokenInformation(process_token, TokenUser, NULL, 0,
                                  &process_bytes);
        (void)GetTokenInformation(client_token, TokenUser, NULL, 0,
                                  &client_bytes);
        process_user = zcl_malloc(process_bytes, "ui_host_process_user");
        client_user = zcl_malloc(client_bytes, "ui_host_client_user");
        ok = process_user && client_user &&
             GetTokenInformation(process_token, TokenUser, process_user,
                                 process_bytes, &process_bytes) &&
             GetTokenInformation(client_token, TokenUser, client_user,
                                 client_bytes, &client_bytes) &&
             EqualSid(process_user->User.Sid, client_user->User.Sid);
    }
    free(process_user);
    free(client_user);
    if (process_token) CloseHandle(process_token);
    if (client_token) CloseHandle(client_token);
    if (client_process) CloseHandle(client_process);
    return ok;
#elif defined(__APPLE__)
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

ui_host_transport_t ui_host_transport_listen(void)
{
#if defined(_WIN32)
    return ui_host_stream(ui_host_pipe_instance());
#else
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
#endif
}

ui_host_transport_t ui_host_transport_accept(ui_host_transport_t *listener,
                                             int timeout_ms)
{
    if (!listener || *listener == UI_HOST_TRANSPORT_INVALID)
        return UI_HOST_TRANSPORT_INVALID;
#if defined(_WIN32)
    HANDLE pipe = ui_host_handle(*listener);
    OVERLAPPED overlap = {0};
    overlap.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!overlap.hEvent) return UI_HOST_TRANSPORT_INVALID;
    BOOL connected = ConnectNamedPipe(pipe, &overlap);
    DWORD error = connected ? ERROR_SUCCESS : GetLastError();
    bool ok = connected || error == ERROR_PIPE_CONNECTED;
    if (!ok && error == ERROR_IO_PENDING) {
        DWORD wait = WaitForSingleObject(overlap.hEvent,
            timeout_ms < 0 ? INFINITE : (DWORD)timeout_ms);
        DWORD transferred = 0;
        ok = wait == WAIT_OBJECT_0 &&
             GetOverlappedResult(pipe, &overlap, &transferred, FALSE);
        if (!ok) {
            (void)CancelIoEx(pipe, &overlap);
            (void)WaitForSingleObject(overlap.hEvent, INFINITE);
        }
    }
    CloseHandle(overlap.hEvent);
    if (!ok) return UI_HOST_TRANSPORT_INVALID;
    *listener = ui_host_stream(ui_host_pipe_instance());
    return ui_host_stream(pipe);
#else
    int ready = platform_socket_wait_readable(*listener, timeout_ms);
    if (ready <= 0) return UI_HOST_TRANSPORT_INVALID;
#if defined(__linux__)
    return accept4(*listener, NULL, NULL, SOCK_CLOEXEC);
#else
    int client = accept(*listener, NULL, NULL);
    if (client < 0) return UI_HOST_TRANSPORT_INVALID;
    int flags = fcntl(client, F_GETFD);
    if (flags < 0 || fcntl(client, F_SETFD, flags | FD_CLOEXEC) != 0) {
        int saved = errno;
        close(client);
        errno = saved;
        return UI_HOST_TRANSPORT_INVALID;
    }
    return client;
#endif
#endif
}

void ui_host_transport_cleanup(void)
{
#if !defined(_WIN32)
    struct sockaddr_un address;
    if (ui_host_address(&address) != 0) (void)unlink(address.sun_path);
#endif
}
