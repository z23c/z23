/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Validate process-owned listening sockets. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#if defined(__linux__)
#include "ship_lane_guard.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int listener(unsigned *port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof addr;
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) || listen(fd, 1) ||
        getsockname(fd, (struct sockaddr *)&addr, &len)) { close(fd); return -1; }
    *port = ntohs(addr.sin_port);
    return fd;
}
#endif

int main(void)
{
#if defined(__linux__)
    unsigned first, second, other;
    int a = listener(&first), b = listener(&second);
    if (a < 0 || b < 0) return 1;
    uint64_t pid = (uint64_t)getpid();
    int ready[2];
    if (pipe(ready)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (!child) {
        close(ready[0]); close(a); close(b);
        if (write(ready[1], "R", 1) != 1) _exit(1);
        for (;;) pause();
    }
    close(ready[1]);
    char byte;
    if (read(ready[0], &byte, 1) != 1) return 1;
    close(ready[0]);
    int fail = !ship_lane_listeners_disjoint(pid, pid, 1, 2, first, second, &other) ||
               other != second ||
               ship_lane_listeners_disjoint(pid, pid, first, 2, first, second, &other) ||
               ship_lane_listeners_disjoint(pid, pid, 1, 2, 3, second, &other) ||
               ship_lane_listeners_disjoint((uint64_t)child, pid, 0, 0, first, second, &other);
    (void)kill(child, SIGTERM);
    (void)waitpid(child, NULL, 0);
    close(a); close(b);
    if (!fail) puts("ship lane socket ownership: PASS");
    return fail;
#else
    puts("ship lane socket ownership: skipped (Linux only)");
    return 0;
#endif
}
