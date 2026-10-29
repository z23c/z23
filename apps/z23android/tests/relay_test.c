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
static pid_t relay_child;
/* A failed assertion or timeout must not leave a relay listening on loopback. */
static void reap_child(int sig)
{
    if (relay_child > 0) kill(relay_child, SIGKILL);
    signal(sig, SIG_DFL); raise(sig);
}
static pid_t start_relay(const char *dir, uint16_t port)
{
    pid_t child = fork(); assert(child >= 0);
    if (!child) _exit(port ? zapp_relay_run_persistent(dir, port, answer, 4096, 4096) : zapp_relay_run(dir, answer));
    relay_child = child; return child;
}
static int stop_relay(pid_t child, int sig)
{
    int status = 0;
    assert(kill(child, sig) == 0 && waitpid(child, &status, 0) == child);
    relay_child = 0; return status;
}
static bool wait_for(const char *path, const char *absent)
{
    for (int i = 0; i < 100; i++) {
        char text[512] = ""; FILE *f = fopen(path, "r");
        bool ready = f && fgets(text, sizeof(text), f) && (!absent || strcmp(text, absent));
        if (f) fclose(f);
        if (ready) return true;
        struct timespec pause = {.tv_nsec = 20000000}; nanosleep(&pause, NULL);
    }
    return false;
}
static int read_descriptor(const char *path, char token[65])
{
    char descriptor[512]; FILE *f = fopen(path, "r");
    assert(f && fgets(descriptor, sizeof(descriptor), f)); fclose(f);
    struct stat st; assert(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    struct json_value doc = {0}; assert(json_read(&doc, descriptor, strlen(descriptor)));
    int port = (int)json_get_int(json_get(&doc, "port"));
    const char *value = json_get_str(json_get(&doc, "token"));
    assert(port > 0 && value && strlen(value) == 64);
    memcpy(token, value, 65);
    json_cleanse_strings(&doc); json_free(&doc);
    return port;
}
static void hello(int port, const char *token)
{
    char wire[512]; snprintf(wire, sizeof(wire), "{\"token\":\"%s\",\"prompt\":\"hello\"}\n", token);
    exchange(port, wire, true);
}
static void ephemeral_cases(const char *dir, const char *path)
{
    pid_t child = start_relay(dir, 0);
    assert(wait_for(path, NULL));
    char token[65], wire[512]; int port = read_descriptor(path, token);
    hello(port, token);
    exchange(port, "{\"token\":\"bad\",\"prompt\":\"hello\"}\n", false);
    exchange(port, "{broken}\n", false);
    snprintf(wire, sizeof(wire), "{\"token\":\"%s\",\"prompt\":\"hello\\u0000hidden\"}\n", token);
    exchange(port, wire, false);
    snprintf(wire, sizeof(wire), "{\"token\":\"%s\",\"prompt\":\"\xff\"}\n", token);
    exchange(port, wire, false);
    assert(unlink(path) == 0);
    FILE *f = fopen(path, "w"); assert(f && fputs("replacement", f) >= 0 && fclose(f) == 0);
    int status = stop_relay(child, SIGTERM);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    char text[32] = ""; f = fopen(path, "r");
    assert(f && fgets(text, sizeof(text), f)); fclose(f);
    assert(!strcmp(text, "replacement") && unlink(path) == 0);
    assert(symlink("missing", path) == 0);
    child = start_relay(dir, 0);
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) != 0);
    relay_child = 0;
    struct stat st; assert(lstat(path, &st) == 0 && S_ISLNK(st.st_mode) && unlink(path) == 0);
}
static uint16_t free_port(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof(addr);
    assert(fd >= 0 && !bind(fd, (struct sockaddr *)&addr, len) && !getsockname(fd, (struct sockaddr *)&addr, &len));
    close(fd); return ntohs(addr.sin_port);
}
/* Persistent relays reuse their token and recover from stale files after an unclean exit. */
static void reuse_token(const char *dir, const char *path, const char *token_path, uint16_t port, char *first)
{
    char token[65];
    pid_t child = start_relay(dir, port);
    assert(wait_for(path, "stale") && read_descriptor(path, first) == port);
    struct stat st; assert(stat(token_path, &st) == 0 && (st.st_mode & 0777) == 0600 && st.st_size == 64);
    hello(port, first);
    int status = stop_relay(child, SIGHUP);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0 && access(path, F_OK) != 0);
    child = start_relay(dir, port);
    assert(wait_for(path, NULL) && read_descriptor(path, token) == port && !strcmp(token, first));
    status = stop_relay(child, SIGKILL);
    assert(WIFSIGNALED(status) && access(path, F_OK) == 0);
}
static void repair_token(const char *dir, const char *path, const char *token_path, uint16_t port, const char *first)
{
    char token[65];
    FILE *f = fopen(token_path, "w"); assert(f && fputs("abc", f) >= 0 && fclose(f) == 0 && chmod(token_path, 0600) == 0);
    pid_t child = start_relay(dir, port);
    for (int i = 0; i < 100 && (read_descriptor(path, token), !strcmp(token, first)); i++) {
        struct timespec pause = {.tv_nsec = 20000000}; nanosleep(&pause, NULL);
    }
    struct stat st;
    assert(strcmp(token, first) && stat(token_path, &st) == 0 && st.st_size == 64);
    hello(port, token);
    int status = stop_relay(child, SIGTERM);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0 && access(path, F_OK) != 0);
    assert(unlink(token_path) == 0);
}
static void persistent_cases(const char *dir, const char *path)
{
    char token_path[512], first[65];
    snprintf(token_path, sizeof(token_path), "%s/host-token", dir);
    FILE *f = fopen(path, "w"); assert(f && fputs("stale", f) >= 0 && fclose(f) == 0);
    uint16_t port = free_port();
    reuse_token(dir, path, token_path, port, first);
    repair_token(dir, path, token_path, port, first);
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    signal(SIGABRT, reap_child); signal(SIGALRM, reap_child); alarm(20);
    char path[512]; snprintf(path, sizeof(path), "%s/codex-bridge.json", argv[1]);
    ephemeral_cases(argv[1], path);
    persistent_cases(argv[1], path);
    puts("relay tests passed"); return 0;
}
