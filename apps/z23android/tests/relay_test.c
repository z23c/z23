/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "relay.h"
#include "json/json.h"
#include <arpa/inet.h>
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static bool answer(int fd, const char *prompt, char *out, size_t cap, const char **error)
{
    (void)fd; (void)error;
    return snprintf(out, cap, "reply: %s", prompt) > 0;
}
static int connect_port(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port),
                               .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(fd >= 0 && connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    return fd;
}
static void exchange(int port, const char *wire, bool expect_reply)
{
    int fd = connect_port(port);
    size_t n = strlen(wire); assert(send(fd, wire, n, 0) == (ssize_t)n);
    char buf[512]; ssize_t got = recv(fd, buf, sizeof(buf) - 1, 0);
    if (expect_reply) { assert(got > 0); buf[got] = 0; assert(strstr(buf, "reply: hello")); }
    else assert(got <= 0);
    close(fd);
}
int main(void)
{
    alarm(10);
    char dir[] = "/tmp/z23-relay-XXXXXX"; assert(mkdtemp(dir));
    pid_t child = fork(); assert(child >= 0);
    if (!child) _exit(zapp_relay_run(dir, answer));
    char path[512]; snprintf(path, sizeof(path), "%s/codex-bridge.json", dir);
    FILE *f = NULL;
    for (int i = 0; i < 100 && !f; i++) {
        f = fopen(path, "r");
        if (!f) { struct timespec pause = {.tv_nsec = 20000000}; nanosleep(&pause, NULL); }
    }
    assert(f); char descriptor[512]; assert(fgets(descriptor, sizeof(descriptor), f)); fclose(f);
    struct stat st; assert(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    struct json_value doc = {0}; assert(json_read(&doc, descriptor, strlen(descriptor)));
    int port = (int)json_get_int(json_get(&doc, "port"));
    const char *token = json_get_str(json_get(&doc, "token")); assert(port > 0 && token && strlen(token) == 64);
    char wire[512]; snprintf(wire, sizeof(wire), "{\"token\":\"%s\",\"prompt\":\"hello\"}\n", token);
    exchange(port, wire, true);
    exchange(port, "{\"token\":\"bad\",\"prompt\":\"hello\"}\n", false);
    exchange(port, "{broken}\n", false);
    snprintf(wire, sizeof(wire), "{\"token\":\"%s\",\"prompt\":\"hello\\u0000hidden\"}\n", token);
    exchange(port, wire, false);
    snprintf(wire, sizeof(wire), "{\"token\":\"%s\",\"prompt\":\"\xff\"}\n", token);
    exchange(port, wire, false);
    json_cleanse_strings(&doc); json_free(&doc);
    assert(unlink(path) == 0);
    f = fopen(path, "w"); assert(f); assert(fputs("replacement", f) >= 0); assert(fclose(f) == 0);
    assert(kill(child, SIGTERM) == 0); int status; assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    f = fopen(path, "r"); assert(f); assert(fgets(descriptor, sizeof(descriptor), f)); fclose(f);
    assert(!strcmp(descriptor, "replacement"));
    assert(unlink(path) == 0);
    assert(symlink("missing", path) == 0);
    child = fork(); assert(child >= 0);
    if (!child) _exit(zapp_relay_run(dir, answer));
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) != 0);
    assert(lstat(path, &st) == 0 && S_ISLNK(st.st_mode));
    assert(unlink(path) == 0);
    child = fork(); assert(child >= 0);
    if (!child) _exit(zapp_relay_run(dir, answer));
    for (int i = 0; i < 100 && access(path, F_OK); i++) {
        struct timespec pause = {.tv_nsec = 20000000}; nanosleep(&pause, NULL);
    }
    assert(access(path, F_OK) == 0 && kill(child, SIGTERM) == 0);
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(access(path, F_OK) != 0 && rmdir(dir) == 0);
    puts("relay tests passed"); return 0;
}
