/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "bridge_auth.h"
#include "bridge_client.h"
#include "json/json.h"
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define KEY_A "1111111111111111111111111111111111111111111111111111111111111111"
#define KEY_B "2222222222222222222222222222222222222222222222222222222222222222"
/* Event mode: the reply carries event lines before the final line. */
struct seen { unsigned count; char last[64]; };
static struct seen *watch;
static bool lenient;
static size_t split_at;
static char saved_proof[256];
static bool on_event(const struct json_value *event, void *ctx)
{
    struct seen *s = ctx;
    s->count++;
    snprintf(s->last, sizeof(s->last), "%s", json_get_str(json_get(event, "data")));
    return strcmp(json_get_str(json_get(event, "event")), "stop") != 0;
}
static void deliver(int fd, const char *reply)
{
    size_t size = strlen(reply), first = split_at && split_at < size ? split_at : size;
    for (size_t sent = 0; sent < size;) {
        ssize_t n = send(fd, reply + sent, (sent < first ? first : size) - sent, MSG_NOSIGNAL);
        if (n <= 0) { assert(lenient); return; }
        sent += (size_t)n;
        if (sent == first && first < size) nanosleep(&(struct timespec){.tv_nsec = 20000000}, NULL);
    }
}
/* How the fixture host behaves. */
enum mode {
    GENUINE,      /* Holds the pairing secret and answers the request. */
    BAD_PROOF,    /* Sends a hello, then a proof made without the secret. */
    REPLAY_PROOF, /* Sends a hello, then the proof a genuine host gave an earlier client. */
    SWAPPED,      /* Proves the secret, then answers with replies bound to a different request. */
    OLD_HOST,     /* Closes without a hello, as a host waiting for the old request does. */
    LEGACY_REPLY, /* Answers at once with an unauthenticated reply. */
    WRONG_LABEL,  /* Seals the proof under the label of a reply line. */
    REORDERED     /* Proves the secret, then delivers the first two reply lines swapped. */
};
struct fixture {
    int listener; atomic_bool cancel; const char *reply; enum mode mode; const char *key;
    char got[8192]; size_t got_len;
};
/* Reads one line, keeping every byte the client sent. False at end of stream. */
static bool take_line(struct fixture *f, int fd, char *line, size_t cap)
{
    size_t n = 0;
    for (;;) {
        char c;
        if (recv(fd, &c, 1, 0) != 1) return false;
        assert(f->got_len < sizeof(f->got)); f->got[f->got_len++] = c;
        if (c == '\n') { line[n] = 0; return true; }
        assert(n + 1 < cap); line[n++] = c;
    }
}
/* Frames each newline-terminated segment of reply as the host does. */
static char *frame_reply(struct zapp_auth *a, const char *reply, size_t *size)
{
    size_t length = strlen(reply), used = 0, segments = 1;
    for (const char *p = reply; (p = strchr(p, 0x0a)); p++) segments++;
    char *out = malloc(length + 67 * segments);
    assert(out);
    for (const char *p = reply; *p;) {
        const char *end = strchr(p, '\n');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        used += zapp_auth_seal(a, "line", a->seq++, p, n, out + used);
        if (end) out[used++] = '\n';
        p += n + (end ? 1 : 0);
    }
    *size = used; out[used] = 0;
    return out;
}
/* Exchanges the first two newline-terminated lines of text. */
static void swap_first_lines(char *text)
{
    char *first_end = strchr(text, 0x0a), *second_end = first_end ? strchr(first_end + 1, 0x0a) : NULL;
    assert(second_end);
    size_t a = (size_t)(first_end - text) + 1, b = (size_t)(second_end - first_end);
    char *copy = malloc(a + b);
    assert(copy);
    memcpy(copy, text, a + b);
    memcpy(text, copy + a, b);
    memcpy(text + b, copy, a);
    free(copy);
}
static void send_all(int fd, const char *data, size_t size)
{
    for (size_t sent = 0; sent < size;) {
        ssize_t n = send(fd, data + sent, size - sent, MSG_NOSIGNAL);
        if (n <= 0) { assert(lenient); return; }
        sent += (size_t)n;
    }
}
static bool greet(struct fixture *f, int fd, struct zapp_auth *a)
{
    char line[512], hex[ZAPP_AUTH_HEX + 1];
    assert(zapp_auth_random(a->ns, sizeof(a->ns)));
    zapp_auth_hex(a->ns, sizeof(a->ns), hex);
    int n = snprintf(line, sizeof(line), "{\"v\":2,\"nonce\":\"%s\"}\n", hex);
    send_all(fd, line, (size_t)n);
    if (!take_line(f, fd, line, sizeof(line))) return false;
    struct json_value hello = {0};
    assert(json_read(&hello, line, strlen(line)) && hello.num_children == 2);
    assert(json_get_int(json_get(&hello, "v")) == 2);
    assert(zapp_auth_unhex(json_get_str(json_get(&hello, "nonce")), sizeof(a->nc), a->nc));
    json_free(&hello);
    return true;
}
static void send_proof(struct fixture *f, int fd, struct zapp_auth *a)
{
    char frame[256];
    size_t n;
    if (f->mode == BAD_PROOF) n = (size_t)snprintf(frame, sizeof(frame), "%064d {\"v\":2}", 7);
    else if (f->mode == REPLAY_PROOF) n = (size_t)snprintf(frame, sizeof(frame), "%s", saved_proof);
    else n = zapp_auth_seal(a, f->mode == WRONG_LABEL ? "line" : "server", 0, "{\"v\":2}", 7, frame);
    frame[n] = 0;
    if (f->mode == GENUINE && !strcmp(f->key, KEY_A) && !saved_proof[0]) memcpy(saved_proof, frame, n + 1);
    frame[n++] = '\n';
    send_all(fd, frame, n);
}
static void *serve(void *opaque)
{
    struct fixture *f = opaque;
    int fd = accept(f->listener, NULL, NULL);
    assert(fd >= 0);
    struct zapp_auth a;
    assert(zapp_auth_start(&a, f->key));
    static char request[1 << 16];
    if (f->mode == OLD_HOST) { close(fd); return NULL; }
    if (f->mode == LEGACY_REPLY) {
        deliver(fd, "{\"ok\":true,\"answer\":\"forged\"}\n");
        while (take_line(f, fd, request, sizeof(request))) {}
        close(fd); return NULL;
    }
    if (greet(f, fd, &a)) {
        send_proof(f, fd, &a);
        if (take_line(f, fd, request, sizeof(request))) {
            const char *payload = zapp_auth_open_request(&a, request);
            if (!payload) { close(fd); return NULL; }
            if (f->mode == SWAPPED) zapp_auth_bind(&a, "another request", 15);
            if (f->reply) {
                size_t size; char *framed = frame_reply(&a, f->reply, &size);
                if (f->mode == REORDERED) swap_first_lines(framed);
                deliver(fd, framed); free(framed);
            } else {
                atomic_store(&f->cancel, true);
                char buf[16]; assert(recv(fd, buf, sizeof(buf), 0) == 0);
            }
        }
    }
    zapp_auth_wipe(&a);
    close(fd);
    return NULL;
}
static void write_descriptor(const char *path, const char *text)
{
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    assert(fd >= 0 && write(fd, text, strlen(text)) == (ssize_t)strlen(text) && close(fd) == 0);
}
static struct fixture *start_fixture(const char *dir, const char *client_key, struct fixture *f, pthread_t *thread)
{
    atomic_init(&f->cancel, false);
    f->listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(f->listener >= 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(f->listener, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(f->listener, 1) == 0);
    socklen_t len = sizeof(addr);
    assert(getsockname(f->listener, (struct sockaddr *)&addr, &len) == 0);
    char path[4096], descriptor[256];
    assert(snprintf(path, sizeof(path), "%s/%s", dir, watch ? "speech-bridge.json" : "codex-bridge.json") < (int)sizeof(path));
    int n = snprintf(descriptor, sizeof(descriptor), "{\"v\":2,\"port\":%u,\"token\":\"%s\"}", (unsigned)ntohs(addr.sin_port), client_key);
    assert(n > 0 && n < (int)sizeof(descriptor));
    write_descriptor(path, descriptor);
    assert(pthread_create(thread, NULL, serve, f) == 0);
    return f;
}
static void run_fixture(const char *dir, struct fixture *f, const char *client_key, bool expected, const char *answer)
{
    pthread_t thread;
    start_fixture(dir, client_key, f, &thread);
    char out[256], path[4096];
    struct timespec start, end;
    assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
    assert((watch ? zapp_bridge_speech_events(dir, "hello", out, sizeof(out), on_event, watch, &f->cancel) :
        zapp_bridge_chat(dir, "hello", out, sizeof(out), &f->cancel)) == expected);
    assert(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
    if (!f->reply && f->mode == GENUINE) {
        int64_t elapsed = (int64_t)(end.tv_sec - start.tv_sec) * 1000000000 + end.tv_nsec - start.tv_nsec;
        assert(elapsed >= 0 && elapsed < 1000000000);
    }
    if (answer) assert(!strcmp(out, answer));
    assert(pthread_join(thread, NULL) == 0);
    close(f->listener);
    assert(snprintf(path, sizeof(path), "%s/%s", dir, watch ? "speech-bridge.json" : "codex-bridge.json") > 0);
    assert(unlink(path) == 0);
}
static void run_case(const char *dir, const char *reply, bool expected, const char *answer)
{
    struct fixture f = {.reply = reply, .mode = GENUINE, .key = KEY_A};
    run_fixture(dir, &f, KEY_A, expected, answer);
}
/* A host that fails the proof receives only the app nonce: no request and no secret. */
static void assert_only_nonce(const struct fixture *f)
{
    assert(f->got_len > 0 && memchr(f->got, '\n', f->got_len) == f->got + f->got_len - 1);
    assert(!memmem(f->got, f->got_len, "hello", 5) && !memmem(f->got, f->got_len, "prompt", 6));
    assert(!memmem(f->got, f->got_len, KEY_A, 64) && !memmem(f->got, f->got_len, KEY_B, 64));
}
static const char unverified[] =
    "The laptop host did not prove it holds this pairing. Pair the phone with the laptop again.";
static const char protocol[] =
    "The laptop host does not answer this app's bridge protocol. Update it, then pair the phone again.";
static void authentication_cases(const char *dir)
{
    const char *good = "{\"ok\":true,\"answer\":\"hello back\"}\n";
    /* The genuine host proves the secret; its proof is kept for the replay case. */
    struct fixture f = {.reply = good, .mode = GENUINE, .key = KEY_A};
    run_fixture(dir, &f, KEY_A, true, "hello back");
    assert(saved_proof[0] && f.got_len > 0);
    assert(!memmem(f.got, f.got_len, KEY_A, 64));
    /* Wrong key: a host holding another secret is refused and gets no request. */
    f = (struct fixture){.reply = good, .mode = GENUINE, .key = KEY_B};
    run_fixture(dir, &f, KEY_A, false, unverified);
    assert_only_nonce(&f);
    /* Re-paired phone against a host still on the old secret, and the reverse, are the same refusal. */
    f = (struct fixture){.reply = good, .mode = GENUINE, .key = KEY_A};
    run_fixture(dir, &f, KEY_B, false, unverified);
    assert_only_nonce(&f);
    /* An impostor that knows no secret. */
    f = (struct fixture){.reply = good, .mode = BAD_PROOF, .key = KEY_A};
    run_fixture(dir, &f, KEY_A, false, unverified);
    assert_only_nonce(&f);
    /* Replay: the proof the genuine host gave earlier does not fit a new server nonce. */
    f = (struct fixture){.reply = good, .mode = REPLAY_PROOF, .key = KEY_A};
    run_fixture(dir, &f, KEY_A, false, unverified);
    assert_only_nonce(&f);
    /* A proof sealed under another label is refused. */
    f = (struct fixture){.reply = good, .mode = WRONG_LABEL, .key = KEY_A};
    run_fixture(dir, &f, KEY_A, false, unverified);
    assert_only_nonce(&f);
    /* A reply bound to another request is refused although the host knows the secret. */
    f = (struct fixture){.reply = good, .mode = SWAPPED, .key = KEY_A};
    run_fixture(dir, &f, KEY_A, false, NULL);
    /* An old host closes without a hello; an unauthenticated reply is never accepted. */
    f = (struct fixture){.mode = OLD_HOST, .key = KEY_A};
    run_fixture(dir, &f, KEY_A, false, protocol);
    f = (struct fixture){.reply = NULL, .mode = LEGACY_REPLY, .key = KEY_A};
    run_fixture(dir, &f, KEY_A, false, protocol);
    assert(f.got_len == 0);
}
/* Two event lines delivered in swapped order are refused: each tag covers the line index. */
static void reordered_events(const char *dir)
{
    const char *two = "{\"event\":\"text\",\"data\":\"first\"}\n{\"event\":\"pcm\",\"data\":\"second\"}\n"
        "{\"ok\":true,\"answer\":\"done\"}\n";
    struct fixture f = {.reply = two, .mode = REORDERED, .key = KEY_A};
    run_fixture(dir, &f, KEY_A, false, NULL);
}
/* An old pairing (no protocol version) is refused before any connection. */
static void stale_pairing(const char *dir)
{
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(listener >= 0 && bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == 0 && listen(listener, 1) == 0);
    socklen_t len = sizeof(addr);
    assert(getsockname(listener, (struct sockaddr *)&addr, &len) == 0);
    char path[4096], text[256], out[256];
    snprintf(path, sizeof(path), "%s/codex-bridge.json", dir);
    snprintf(text, sizeof(text), "{\"port\":%u,\"token\":\"%s\"}", (unsigned)ntohs(addr.sin_port), KEY_A);
    write_descriptor(path, text);
    assert(!zapp_bridge_chat(dir, "hello", out, sizeof(out), NULL));
    assert(!strcmp(out, "This pairing is out of date. Pair the phone with the laptop again."));
    assert(unlink(path) == 0);
    snprintf(text, sizeof(text), "{\"v\":3,\"port\":%u,\"token\":\"%s\"}", (unsigned)ntohs(addr.sin_port), KEY_A);
    write_descriptor(path, text);
    assert(!zapp_bridge_chat(dir, "hello", out, sizeof(out), NULL));
    assert(!strcmp(out, "This pairing is out of date. Pair the phone with the laptop again."));
    assert(unlink(path) == 0);
    assert(accept(listener, NULL, NULL) < 0);
    close(listener);
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    assert(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
    alarm(10);
    run_case(argv[1], "{\"ok\":true,\"answer\":\"hello back\"}\n", true, "hello back");
    run_case(argv[1], "not json\n", false, NULL);
    run_case(argv[1], NULL, false, "Reply cancelled.");
    struct seen seen = {0};
    watch = &seen;
    run_case(argv[1], "{\"ok\":true,\"answer\":\"hi\"}\n", true, "hi");
    assert(seen.count == 0);
    const char *two = "{\"event\":\"text\",\"data\":\"first\"}\n{\"event\":\"pcm\",\"data\":\"second\"}\n"
        "{\"ok\":true,\"answer\":\"done\"}\n";
    run_case(argv[1], two, true, "done");
    assert(seen.count == 2 && !strcmp(seen.last, "second"));
    for (split_at = 1; split_at < strlen(two); split_at += 17) {
        seen = (struct seen){0};
        run_case(argv[1], two, true, "done");
        assert(seen.count == 2);
    }
    split_at = 0;
    reordered_events(argv[1]);
    run_case(argv[1], "{\"event\":\"text\",\"data\":\"a\"}\n{\"ok\":false,\"error\":\"boom\"}\n", false, "boom");
    run_case(argv[1], "{\"event\":\"text\",\"data\":\"a\\u0000\"}\n{\"ok\":true,\"answer\":\"x\"}\n", false, NULL);
    run_case(argv[1], "{\"event\":\"stop\",\"data\":\"a\"}\n{\"ok\":true,\"answer\":\"x\"}\n", false, NULL);
    run_case(argv[1], "{\"event\":\"text\",\"data\":\"a\"}\nnot json\n", false, NULL);
    run_case(argv[1], "{\"event\":\"text\",\"data\":\"a\"}\n{\"ok\":true,\"answer\":\"x\",\"more\":1}\n", false, NULL);
    run_case(argv[1], "{\"ok\":true,\"answer\":\"x\"}\ntrailing\n", false, NULL);
    run_case(argv[1], NULL, false, "Voice cancelled.");
    size_t big = 2200000;
    char *oversize = malloc(big + 1);
    assert(oversize);
    memset(oversize, 'a', big); oversize[big] = 0;
    memcpy(oversize, "{\"event\":\"text\",\"data\":\"", 24);
    lenient = true;
    run_case(argv[1], oversize, false, NULL);
    lenient = false; free(oversize);
    watch = NULL;
    authentication_cases(argv[1]);
    stale_pairing(argv[1]);
    atomic_bool cancelled;
    atomic_init(&cancelled, true);
    char out[128];
    assert(!zapp_bridge_chat(argv[1], "hello", out, sizeof(out), &cancelled));
    assert(!strcmp(out, "Reply cancelled."));
    alarm(0);
    puts("bridge client tests passed");
    return 0;
}
