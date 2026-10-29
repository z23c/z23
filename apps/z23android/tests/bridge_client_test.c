/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "bridge_client.h"
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct fixture { int listener; atomic_bool cancel; const char *reply; };
static void *serve(void *opaque)
{
    struct fixture *f = opaque;
    int fd = accept(f->listener, NULL, NULL);
    assert(fd >= 0);
    char buf[4096];
    assert(recv(fd, buf, sizeof(buf), 0) > 0);
    if (f->reply) assert(send(fd, f->reply, strlen(f->reply), 0) == (ssize_t)strlen(f->reply));
    else {
        atomic_store(&f->cancel, true);
        assert(recv(fd, buf, sizeof(buf), 0) == 0);
    }
    close(fd);
    return NULL;
}
static void run_case(const char *dir, const char *reply, bool expected, const char *answer)
{
    struct fixture f = {.listener = socket(AF_INET, SOCK_STREAM, 0), .reply = reply};
    atomic_init(&f.cancel, false);
    assert(f.listener >= 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(f.listener, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(f.listener, 1) == 0);
    socklen_t len = sizeof(addr);
    assert(getsockname(f.listener, (struct sockaddr *)&addr, &len) == 0);
    char path[4096], descriptor[256];
    assert(snprintf(path, sizeof(path), "%s/codex-bridge.json", dir) < (int)sizeof(path));
    int n = snprintf(descriptor, sizeof(descriptor), "{\"port\":%u,\"token\":\"%064d\"}", (unsigned)ntohs(addr.sin_port), 0);
    assert(n > 0 && n < (int)sizeof(descriptor));
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    assert(fd >= 0 && write(fd, descriptor, (size_t)n) == n && close(fd) == 0);
    pthread_t thread;
    assert(pthread_create(&thread, NULL, serve, &f) == 0);
    char out[256];
    struct timespec start, end;
    assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
    assert(zapp_bridge_chat(dir, "hello", out, sizeof(out), &f.cancel) == expected);
    assert(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
    if (!reply) {
        int64_t elapsed = (int64_t)(end.tv_sec - start.tv_sec) * 1000000000 + end.tv_nsec - start.tv_nsec;
        assert(elapsed >= 0 && elapsed < 1000000000);
    }
    if (answer) assert(!strcmp(out, answer));
    assert(pthread_join(thread, NULL) == 0);
    close(f.listener);
    assert(unlink(path) == 0);
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    assert(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
    alarm(5);
    run_case(argv[1], "{\"ok\":true,\"answer\":\"hello back\"}\n", true, "hello back");
    run_case(argv[1], "not json\n", false, NULL);
    run_case(argv[1], NULL, false, "Reply cancelled.");
    atomic_bool cancelled;
    atomic_init(&cancelled, true);
    char out[128];
    assert(!zapp_bridge_chat(argv[1], "hello", out, sizeof(out), &cancelled));
    assert(!strcmp(out, "Reply cancelled."));
    alarm(0);
    puts("bridge client tests passed");
    return 0;
}
