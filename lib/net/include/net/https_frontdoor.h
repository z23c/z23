/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Absolute admission/read budget for the public HTTP(S) front door. */

#ifndef ZCL_NET_HTTPS_FRONTDOOR_H
#define ZCL_NET_HTTPS_FRONTDOOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <openssl/ssl.h>

#define HTTPS_FRONTDOOR_BUDGET_MS 15000
#define HTTPS_FRONTDOOR_QUEUE_CAP 128

typedef int (*https_frontdoor_read_byte_fn)(void *src, char *c);

struct https_frontdoor_fd_reader {
    int fd;
    int64_t deadline_ms;
};

struct https_frontdoor_ssl_reader {
    SSL *ssl;
    int fd;
    int64_t deadline_ms;
};

struct https_frontdoor_client {
    int fd;
    bool tls;
    int64_t deadline_ms;
};

struct https_frontdoor_queue {
    struct https_frontdoor_client entries[HTTPS_FRONTDOOR_QUEUE_CAP];
    size_t head;
    size_t tail;
    size_t len;
};

bool https_frontdoor_deadline_start(int64_t *deadline_ms);
bool https_frontdoor_deadline_active(int64_t deadline_ms);
bool https_frontdoor_wait(int fd, short events, short ready_mask,
                          int64_t deadline_ms);
int https_frontdoor_fd_read_byte(void *src, char *c);
int https_frontdoor_ssl_read_byte(void *src, char *c);
bool https_frontdoor_ssl_accept(SSL *ssl, int fd, int64_t deadline_ms);
bool https_frontdoor_read_line(void *src, https_frontdoor_read_byte_fn read_byte,
                               char *buf, size_t max, int64_t deadline_ms);
bool https_frontdoor_queue_push(struct https_frontdoor_queue *queue,
                                const struct https_frontdoor_client *client);
bool https_frontdoor_queue_pop(struct https_frontdoor_queue *queue,
                               struct https_frontdoor_client *client);
void https_frontdoor_queue_close_all(struct https_frontdoor_queue *queue);

#endif
