/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "bridge_auth.h"
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

#define WRONG_KEY "3333333333333333333333333333333333333333333333333333333333333333"
static bool answer(int fd, const char *prompt, char *out, size_t cap, const char **error)
{
    (void)error;
    if (!strcmp(prompt, "stream"))
        assert(zapp_relay_emit(fd, "{\"event\":\"text\",\"data\":\"first\"}") &&
               zapp_relay_emit(fd, "{\"event\":\"pcm\",\"rate\":24000,\"data\":\"0100\"}"));
    if (!strcmp(prompt, "rotate") && !zapp_relay_rotate()) return false;
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
/* A phone: holds a secret, takes the host's nonce, answers with its own and checks the proof. */
struct session { int fd; struct zapp_auth auth; bool proven; char nonce_line[128]; };
static bool read_line(int fd, char *line, size_t cap)
{
    size_t n = 0;
    for (;;) {
        char c;
        if (recv(fd, &c, 1, 0) != 1) return false;
        if (c == '\n') { line[n] = 0; return true; }
        assert(n + 1 < cap); line[n++] = c;
    }
}
static void read_hello(struct session *s, const char *key)
{
    char line[512];
    assert(read_line(s->fd, line, sizeof(line)));
    struct json_value hello = {0};
    assert(json_read(&hello, line, strlen(line)) && hello.num_children == 3);
    assert(json_get_int(json_get(&hello, "v")) == ZAPP_AUTH_VERSION);
    assert(strstr(json_get_str(json_get(&hello, "error")), "Pair this phone with the laptop again"));
    assert(zapp_auth_start(&s->auth, key));
    assert(zapp_auth_unhex(json_get_str(json_get(&hello, "nonce")), sizeof(s->auth.ns), s->auth.ns));
    json_free(&hello);
}
static struct session open_session(int port, const char *key)
{
    struct session s = {.fd = connect_port(port)};
    char hex[ZAPP_AUTH_HEX + 1], line[512];
    read_hello(&s, key);
    assert(zapp_auth_random(s.auth.nc, sizeof(s.auth.nc)));
    zapp_auth_hex(s.auth.nc, sizeof(s.auth.nc), hex);
    int n = snprintf(s.nonce_line, sizeof(s.nonce_line), "{\"v\":2,\"nonce\":\"%s\"}\n", hex);
    assert(send(s.fd, s.nonce_line, (size_t)n, 0) == n && read_line(s.fd, line, sizeof(line)));
    const char *body = zapp_auth_open(&s.auth, "server", 0, line);
    s.proven = body && !strcmp(body, "{\"v\":2}");
    return s;
}
/* Sends frame and reads to the end of the stream. Every line the host sends must verify. */
static unsigned read_replies(struct session *s, char *text, size_t cap)
{
    unsigned count = 0; char line[1024]; text[0] = 0;
    while (read_line(s->fd, line, sizeof(line))) {
        const char *payload = zapp_auth_open(&s->auth, "line", s->auth.seq, line);
        assert(payload && strlen(text) + strlen(payload) + 2 < cap);
        s->auth.seq++; count++;
        strcat(text, payload); strcat(text, "\n");
    }
    close(s->fd);
    return count;
}
static size_t build_frame(struct session *s, const char *prompt, char *frame)
{
    char request[256];
    int n = snprintf(request, sizeof(request), "{\"prompt\":\"%s\"}", prompt);
    size_t size = zapp_auth_seal_request(&s->auth, request, (size_t)n, frame);
    frame[size++] = '\n'; frame[size] = 0;
    return size;
}
static unsigned talk(int port, const char *key, const char *prompt, char *text, size_t cap)
{
    struct session s = open_session(port, key);
    char frame[512];
    size_t n = build_frame(&s, prompt, frame);
    assert(send(s.fd, frame, n, 0) == (ssize_t)n);
    unsigned count = read_replies(&s, text, cap);
    assert(s.proven || count == 0);
    return count;
}
static void hello(int port, const char *token)
{
    char text[256];
    assert(talk(port, token, "hello", text, sizeof(text)) == 1 && strstr(text, "reply: hello"));
    assert(!strstr(text, token));
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
/* Polls of 20 ms cover 10 s: a relay start writes and fsyncs its token, which can stall on a
 * loaded host. */
#define WAIT_POLLS 500
/* A relay that exits before publishing, for example because it cannot bind its port, fails here
 * rather than as a stale descriptor. */
static void assert_relay_running(void)
{
    pid_t done = waitpid(relay_child, NULL, WNOHANG);
    if (done == relay_child) relay_child = 0;
    assert(done == 0);
}
static bool wait_for(const char *path, const char *absent)
{
    for (int i = 0; i < WAIT_POLLS; i++) {
        assert_relay_running();
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
/* A host never answers a phone that cannot prove the secret, and never accepts a request that is
 * old, altered, replayed or sealed under another secret. */
static void refused_cases(int port, const char *token)
{
    char text[1024], frame[512];
    unsigned count;
    /* Wrong key: the proof the phone checks fails, and the request it sends anyway gets no reply. */
    assert(talk(port, WRONG_KEY, "hello", text, sizeof(text)) == 0);
    /* An old phone sends the token and the prompt at once: told to pair again, nothing else. */
    int fd = connect_port(port);
    char line[512], old[256];
    assert(read_line(fd, line, sizeof(line)));
    int n = snprintf(old, sizeof(old), "{\"token\":\"%s\",\"prompt\":\"hello\"}\n", token);
    assert(send(fd, old, (size_t)n, 0) == n && read_line(fd, line, sizeof(line)));
    assert(strstr(line, "\"ok\":false") && strstr(line, "Pair this phone with the laptop again"));
    assert(!read_line(fd, line, sizeof(line)));
    close(fd);
    fd = connect_port(port);
    assert(read_line(fd, line, sizeof(line)) && send(fd, "{broken}\n", 9, 0) == 9);
    assert(read_line(fd, line, sizeof(line)) && strstr(line, "Pair this phone with the laptop again"));
    close(fd);
    /* Replay: the nonce line and request of a genuine session do not fit a new host nonce. */
    struct session first = open_session(port, token);
    assert(first.proven);
    size_t size = build_frame(&first, "hello", frame);
    assert(send(first.fd, frame, size, 0) == (ssize_t)size);
    assert(read_replies(&first, text, sizeof(text)) == 1);
    struct session replay = {.fd = connect_port(port)};
    read_hello(&replay, token);
    assert(send(replay.fd, first.nonce_line, strlen(first.nonce_line), 0) > 0 && read_line(replay.fd, line, sizeof(line)));
    assert(send(replay.fd, frame, size, 0) == (ssize_t)size);
    assert(!read_line(replay.fd, line, sizeof(line)));
    close(replay.fd);
    /* Altered request: the tag of one request over the text of another. */
    struct session swap = open_session(port, token);
    assert(swap.proven);
    (void)build_frame(&swap, "hello", frame);
    char altered[512];
    memcpy(altered, frame, ZAPP_AUTH_HEX + 1);
    size = ZAPP_AUTH_HEX + 1 + (size_t)snprintf(altered + ZAPP_AUTH_HEX + 1, sizeof(altered) - ZAPP_AUTH_HEX - 1, "{\"prompt\":\"stream\"}\n");
    assert(send(swap.fd, altered, size, 0) == (ssize_t)size);
    assert(read_replies(&swap, text, sizeof(text)) == 0);
    /* A request tag made under the label of a reply line. */
    struct session label = open_session(port, token);
    assert(label.proven);
    n = snprintf(old, sizeof(old), "{\"prompt\":\"hello\"}");
    zapp_auth_bind(&label.auth, old, (size_t)n);
    size = zapp_auth_seal(&label.auth, "line", 0, old, (size_t)n, frame);
    frame[size++] = 0x0a;
    assert(send(label.fd, frame, size, 0) == (ssize_t)size);
    assert(read_replies(&label, text, sizeof(text)) == 0);
    /* Requests the host rejects after authentication: a NUL escape and invalid UTF-8. */
    count = talk(port, token, "hello\\u0000hidden", text, sizeof(text));
    assert(count == 0);
    count = talk(port, token, "\xff", text, sizeof(text));
    assert(count == 0);
}
static uint16_t free_port(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof(addr);
    assert(fd >= 0 && !bind(fd, (struct sockaddr *)&addr, len) && !getsockname(fd, (struct sockaddr *)&addr, &len));
    close(fd); return ntohs(addr.sin_port);
}
/* Events arrive in order before the final reply, each on its own line. */
static void streamed(int port, const char *token)
{
    char text[1024], expected[1024];
    snprintf(expected, sizeof(expected), "%s\n%s\n%s\n", "{\"event\":\"text\",\"data\":\"first\"}",
        "{\"event\":\"pcm\",\"rate\":24000,\"data\":\"0100\"}", "{\"ok\":true,\"answer\":\"reply: stream\"}");
    assert(talk(port, token, "stream", text, sizeof(text)) == 3 && !strcmp(text, expected));
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(!zapp_relay_emit(pair[0], "{}") && !zapp_relay_emit(pair[0], NULL));
    close(pair[0]); close(pair[1]);
}
static void ephemeral_cases(const char *dir, const char *path)
{
    pid_t child = start_relay(dir, 0);
    assert(wait_for(path, NULL));
    char token[65]; int port = read_descriptor(path, token);
    hello(port, token);
    streamed(port, token);
    refused_cases(port, token);
    hello(port, token);
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
/* Persistent relays reuse their secret and recover from stale files after an unclean exit. */
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
    for (int i = 0; i < WAIT_POLLS && (assert_relay_running(), read_descriptor(path, token), !strcmp(token, first)); i++) {
        struct timespec pause = {.tv_nsec = 20000000}; nanosleep(&pause, NULL);
    }
    struct stat st;
    assert(strcmp(token, first) && stat(token_path, &st) == 0 && st.st_size == 64);
    hello(port, token);
    int status = stop_relay(child, SIGTERM);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0 && access(path, F_OK) != 0);
    assert(unlink(token_path) == 0);
}
/* Pairing again replaces the secret on the host: the old one is refused, the new one works, and the
 * stored secret and the descriptor agree. */
static void rotate_token(const char *dir, const char *path, const char *token_path, uint16_t port)
{
    char old[65], fresh[65], stored[65] = "", text[256];
    pid_t child = start_relay(dir, port);
    assert(wait_for(path, NULL) && read_descriptor(path, old) == port);
    assert(talk(port, old, "rotate", text, sizeof(text)) == 1 && strstr(text, "reply: rotate"));
    assert(read_descriptor(path, fresh) == port && strcmp(old, fresh));
    FILE *f = fopen(token_path, "r"); assert(f && fgets(stored, sizeof(stored), f)); fclose(f);
    assert(!strcmp(stored, fresh));
    hello(port, fresh);
    assert(talk(port, old, "hello", text, sizeof(text)) == 0);
    int status = stop_relay(child, SIGTERM);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0 && access(path, F_OK) != 0);
    child = start_relay(dir, port);
    assert(wait_for(path, NULL) && read_descriptor(path, old) == port && !strcmp(old, fresh));
    hello(port, fresh);
    status = stop_relay(child, SIGTERM);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(unlink(token_path) == 0);
}
/* A token left by protocol 1 travelled in the clear. It is never key material: the relay starts with a
 * fresh secret, refuses the old token and removes the file. */
static void legacy_token(const char *dir, const char *path, const char *secret_path, uint16_t port)
{
    static const char legacy[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    char legacy_path[512], fresh[65], text[256];
    snprintf(legacy_path, sizeof(legacy_path), "%s/host-token", dir);
    FILE *f = fopen(legacy_path, "w"); assert(f && fputs(legacy, f) >= 0 && fclose(f) == 0 && chmod(legacy_path, 0600) == 0);
    pid_t child = start_relay(dir, port);
    assert(wait_for(path, "stale") && read_descriptor(path, fresh) == port);
    assert(strcmp(fresh, legacy) && access(legacy_path, F_OK) != 0);
    assert(talk(port, legacy, "hello", text, sizeof(text)) == 0);
    hello(port, fresh);
    int status = stop_relay(child, SIGTERM);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0 && unlink(secret_path) == 0);
}
static void persistent_cases(const char *dir, const char *path)
{
    char token_path[512], first[65];
    snprintf(token_path, sizeof(token_path), "%s/pairing-secret", dir);
    FILE *f = fopen(path, "w"); assert(f && fputs("stale", f) >= 0 && fclose(f) == 0);
    uint16_t port = free_port();
    legacy_token(dir, path, token_path, port);
    f = fopen(path, "w"); assert(f && fputs("stale", f) >= 0 && fclose(f) == 0);
    reuse_token(dir, path, token_path, port, first);
    repair_token(dir, path, token_path, port, first);
    rotate_token(dir, path, token_path, port);
    assert(!zapp_relay_rotate());
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    signal(SIGABRT, reap_child); signal(SIGALRM, reap_child); alarm(60);
    char path[512]; snprintf(path, sizeof(path), "%s/codex-bridge.json", argv[1]);
    ephemeral_cases(argv[1], path);
    persistent_cases(argv[1], path);
    puts("relay tests passed"); return 0;
}
