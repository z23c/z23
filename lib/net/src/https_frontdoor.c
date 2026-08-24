/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Slow-drip-resistant public HTTP(S) admission and line reads. */

#include "net/https_frontdoor.h"

#include "platform/time_compat.h"

#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

bool https_frontdoor_deadline_start(int64_t *deadline_ms)
{
    if (!deadline_ms)
        return false;
    int64_t now_ms = platform_time_monotonic_ms();
    if (now_ms <= 0 || now_ms > INT64_MAX - HTTPS_FRONTDOOR_BUDGET_MS)
        return false;
    *deadline_ms = now_ms + HTTPS_FRONTDOOR_BUDGET_MS;
    return true;
}

bool https_frontdoor_deadline_active(int64_t deadline_ms)
{
    int64_t now_ms = platform_time_monotonic_ms();
    return now_ms > 0 && now_ms < deadline_ms;
}

bool https_frontdoor_wait(int fd, short events, short ready_mask,
                          int64_t deadline_ms)
{
    for (;;) {
        int64_t now_ms = platform_time_monotonic_ms();
        if (now_ms <= 0 || now_ms >= deadline_ms)
            return false;
        struct pollfd pfd = {.fd = fd, .events = events};
        int ready = poll(&pfd, 1, (int)(deadline_ms - now_ms));
        if (ready < 0 && errno == EINTR)
            continue;
        return ready > 0 && (pfd.revents & ready_mask) != 0;
    }
}

int https_frontdoor_fd_read_byte(void *src, char *c)
{
    struct https_frontdoor_fd_reader *reader = src;
    if (!reader || !c)
        return -1;
    for (;;) {
        if (!https_frontdoor_wait(reader->fd, POLLIN, POLLIN | POLLHUP,
                                  reader->deadline_ms))
            return -1;
        ssize_t n = recv(reader->fd, c, 1, MSG_DONTWAIT);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        return (int)n;
    }
}

int https_frontdoor_ssl_read_byte(void *src, char *c)
{
    struct https_frontdoor_ssl_reader *reader = src;
    for (;;) {
        int n = SSL_read(reader->ssl, c, 1);
        if (n > 0)
            return n;
        int error = SSL_get_error(reader->ssl, n);
        short events = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
        if ((error != SSL_ERROR_WANT_READ &&
             error != SSL_ERROR_WANT_WRITE) ||
            !https_frontdoor_wait(reader->fd, events, events | POLLHUP,
                                  reader->deadline_ms))
            return -1;
    }
}

bool https_frontdoor_ssl_accept(SSL *ssl, int fd, int64_t deadline_ms)
{
    for (;;) {
        int accepted = SSL_accept(ssl);
        if (accepted == 1)
            return true;
        int error = SSL_get_error(ssl, accepted);
        short events = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
        if ((error != SSL_ERROR_WANT_READ &&
             error != SSL_ERROR_WANT_WRITE) ||
            !https_frontdoor_wait(fd, events, events | POLLHUP, deadline_ms))
            return false;
    }
}

bool https_frontdoor_read_line(void *src, https_frontdoor_read_byte_fn read_byte,
                               char *buf, size_t max, int64_t deadline_ms)
{
    if (!src || !read_byte || !buf || max < 2)
        return false;
    size_t pos = 0;
    while (pos < max - 1) {
        if (!https_frontdoor_deadline_active(deadline_ms))
            return false;
        char c;
        int read_size = read_byte(src, &c);
        if (read_size <= 0)
            return false;
        if (c == '\n')
            break;
        if (c != '\r')
            buf[pos++] = c;
    }
    buf[pos] = '\0';
    return true;
}

static void https_frontdoor_client_close(struct https_frontdoor_client *client)
{
    if (client->fd >= 0)
        close(client->fd);
    client->fd = -1;
}

static void https_frontdoor_queue_purge_expired(
    struct https_frontdoor_queue *queue)
{
    size_t live_count = 0;
    size_t original_len = queue->len;

    for (size_t read_offset = 0; read_offset < original_len; read_offset++) {
        size_t read_index =
            (queue->head + read_offset) % HTTPS_FRONTDOOR_QUEUE_CAP;
        if (!https_frontdoor_deadline_active(
                queue->entries[read_index].deadline_ms)) {
            https_frontdoor_client_close(&queue->entries[read_index]);
            continue;
        }
        size_t write_index =
            (queue->head + live_count) % HTTPS_FRONTDOOR_QUEUE_CAP;
        if (write_index != read_index)
            queue->entries[write_index] = queue->entries[read_index];
        live_count++;
    }
    queue->len = live_count;
    queue->tail =
        (queue->head + live_count) % HTTPS_FRONTDOOR_QUEUE_CAP;
}

bool https_frontdoor_queue_push(struct https_frontdoor_queue *queue,
                                const struct https_frontdoor_client *client)
{
    if (!queue || !client || client->fd < 0)
        return false;
    https_frontdoor_queue_purge_expired(queue);
    if (queue->len >= HTTPS_FRONTDOOR_QUEUE_CAP)
        return false;
    queue->entries[queue->tail] = *client;
    queue->tail = (queue->tail + 1U) % HTTPS_FRONTDOOR_QUEUE_CAP;
    queue->len++;
    return true;
}

bool https_frontdoor_queue_pop(struct https_frontdoor_queue *queue,
                               struct https_frontdoor_client *client)
{
    if (!queue || !client || queue->len == 0)
        return false;
    *client = queue->entries[queue->head];
    queue->head = (queue->head + 1U) % HTTPS_FRONTDOOR_QUEUE_CAP;
    queue->len--;
    return true;
}

void https_frontdoor_queue_close_all(struct https_frontdoor_queue *queue)
{
    if (!queue)
        return;
    while (queue->len > 0) {
        https_frontdoor_client_close(&queue->entries[queue->head]);
        queue->head = (queue->head + 1U) % HTTPS_FRONTDOOR_QUEUE_CAP;
        queue->len--;
    }
    queue->head = 0;
    queue->tail = 0;
}
