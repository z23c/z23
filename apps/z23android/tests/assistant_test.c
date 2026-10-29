/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "assistant.c"
#include <arpa/inet.h>
#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

static char *emitted[512];
static size_t emitted_count, emit_budget = SIZE_MAX;
bool zapp_relay_client_alive(int fd) { (void)fd; return true; }
bool zapp_relay_emit(int fd, const char *line)
{
    (void)fd;
    if (!emit_budget) return false;
    emit_budget--;
    assert(emitted_count < sizeof(emitted) / sizeof(emitted[0]) && !strchr(line, '\n'));
    emitted[emitted_count++] = strdup(line);
    return true;
}
static void reset_log(void)
{
    for (size_t i = 0; i < emitted_count; i++) free(emitted[i]);
    emitted_count = 0; emit_budget = SIZE_MAX;
}
static struct respond *new_respond(const struct zapp_assistant *a, bool mute)
{
    struct respond *r = calloc(1, sizeof(*r));
    assert(r);
    r->a = a; r->client = -1; r->rate = PCM_RATE; r->mute = mute; r->start_ms = now_ms();
    r->text = calloc(1, 4096); r->text_cap = 4096;
    assert(r->text);
    return r;
}
static void free_respond(struct respond *r) { free(r->text); free(r); }
static bool feed(struct respond *r, const char *sse, size_t piece)
{
    size_t n = strlen(sse);
    for (size_t at = 0; at < n; at += piece)
        if (!sse_sink((const unsigned char *)sse + at, n - at < piece ? n - at : piece, r)) return false;
    return true;
}
static void expect_line(size_t i, const char *event, const char *data)
{
    char want[512];
    snprintf(want, sizeof(want), "{\"event\":\"%s\",\"data\":\"%s\"}", event, data);
    assert(i < emitted_count && !strcmp(emitted[i], want));
}
static size_t decode_pcm(const char *line, int16_t *out)
{
    const char *hex = strstr(line, "\"data\":\"");
    static const char prefix[] = "{\"event\":\"pcm\",\"rate\":";
    assert(hex && !strncmp(line, prefix, sizeof(prefix) - 1));
    hex += 8;
    size_t n = 0;
    for (; hex[0] != '"'; hex += 4, n++) {
        unsigned v;
        char digits[5] = {hex[0], hex[1], hex[2], hex[3], 0};
        assert(sscanf(digits, "%4x", &v) == 1);
        out[n] = (int16_t)(uint16_t)((v & 0xff) << 8 | v >> 8);
    }
    return n;
}
static const char fixture[] =
    ": keep-alive\r\n\r\n"
    "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":null}}]}\r\n\r\n"
    "data: {\"choices\":[{\"delta\":{\"content\":\"**Hello\"}}]}\n\n"
    "data: {\"choices\":[{\"delta\":{\"content\":\"** there, my friend. The fleet\"}}]}\n\n"
    "data: {\"choices\":[{\"delta\":{\"content\":\" is `fine`. Every\"}}]}\n\n"
    "data:{\"choices\":[{\"delta\":{\"content\":\"thing looks good today.\"}}]}\n\n"
    "data: {\"choices\":[{\"finish_reason\":\"stop\",\"delta\":{}}]}\n\n"
    "data: [DONE]\n\n"
    "data: {\"choices\":[{\"delta\":{\"content\":\"ignored after done\"}}]}\n\n";
static void sentence_cases(const struct zapp_assistant *a)
{
    static const size_t pieces[] = {1, 3, 7, 64, 100000};
    for (size_t p = 0; p < sizeof(pieces) / sizeof(pieces[0]); p++) {
        reset_log();
        struct respond *r = new_respond(a, true);
        assert(feed(r, fixture, pieces[p]) && r->done && respond_finish(r));
        assert(emitted_count == 2);
        expect_line(0, "text", "Hello there, my friend.");
        expect_line(1, "text", "The fleet is fine. Everything looks good today.");
        assert(!strcmp(r->text, "Hello there, my friend. The fleet is fine. Everything looks good today."));
        free_respond(r);
    }
}
static void think_cases(const struct zapp_assistant *a)
{
    reset_log();
    struct respond *r = new_respond(a, true);
    assert(feed(r, "data: {\"choices\":[{\"delta\":{\"content\":\"<thi\"}}]}\n"
        "data: {\"choices\":[{\"delta\":{\"content\":\"nk>\\nplanning, not for speech. \"}}]}\n"
        "data: {\"choices\":[{\"delta\":{\"content\":\"</think>\\n\\nThe node is running well today.\"}}]}\n"
        "data: [DONE]\n", 5) && r->done && respond_finish(r));
    assert(emitted_count == 1 && !strcmp(r->text, "The node is running well today."));
    free_respond(r);
    reset_log();
    r = new_respond(a, true);
    assert(feed(r, "data: {\"choices\":[{\"delta\":{\"content\":\"<\"}}]}\ndata: [DONE]\n", 100) && respond_finish(r));
    assert(!strcmp(r->text, "<"));
    free_respond(r);
}
static void split_cases(const struct zapp_assistant *a)
{
    char words[400] = "", delta[512], sse[1024];
    for (int i = 0; i < 60; i++) strcat(words, "word ");
    snprintf(delta, sizeof(delta), "%s", words);
    snprintf(sse, sizeof(sse), "data: {\"choices\":[{\"delta\":{\"content\":\"%s\"}}]}\ndata: [DONE]\n", delta);
    reset_log();
    struct respond *r = new_respond(a, true);
    assert(feed(r, sse, 1000) && respond_finish(r));
    assert(emitted_count == 3 && strlen(r->text) == strlen(words) - 1);
    assert(!strncmp(emitted[0], "{\"event\":\"text\",\"data\":\"word word", 33));
    const char *six = "\"data\":\"word word word word word word\"";
    assert(strstr(emitted[0], six) && !strstr(emitted[1], six));
    free_respond(r);
    const char *sentence = "Hello there, my friend. The fleet is fine. More";
    assert(ready_len("Short one.", 10, MAX_CHUNK) == 0 && ready_len(sentence, strlen(sentence), MAX_CHUNK) == 42);
    assert(ready_len("aaaaaaaaaaaaaaaaaaaaaaa. b", 26, MAX_CHUNK) == 24 && ready_len("aaaaaaaaaaaaaaaaaaaaaa. b", 25, MAX_CHUNK) == 0);
    char run[200]; memset(run, 'a', sizeof(run)); run[199] = 0; run[100] = ' ';
    assert(ready_len(run, 199, MAX_CHUNK) == 100 && ready_len(run, 100, MAX_CHUNK) == 0);
    assert(ready_len(sentence, strlen(sentence), FIRST_CHUNK) == 23 && ready_len(run, 199, FIRST_CHUNK) == 32);
    const char *counting = "one two three four five six seven eight nine ten eleven";
    assert(ready_len(counting, strlen(counting), FIRST_CHUNK) == 27 && ready_len(counting, 32, FIRST_CHUNK) == 0);
}
static void rejected_cases(const struct zapp_assistant *a)
{
    const char *bad[] = {"data: {not json}\n", "data: [DONE\n", "data: {\"choices\":[{\"delta\":{\"content\":\"\xff\"}}]}\n"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        struct respond *r = new_respond(a, true);
        assert(!feed(r, bad[i], 4));
        free_respond(r);
    }
    struct respond *r = new_respond(a, true);
    assert(!sse_sink((const unsigned char *)"data: a\0b\n", 10, r));
    free_respond(r);
    r = new_respond(a, true);
    char *long_line = malloc(SSE_CAP + 8);
    assert(long_line);
    memset(long_line, 'x', SSE_CAP + 7); long_line[SSE_CAP + 7] = 0;
    assert(!feed(r, long_line, 4096)); free(long_line); free_respond(r);
    reset_log();
    r = new_respond(a, true);
    emit_budget = 0;
    assert(!feed(r, fixture, 100000));
    assert(r->dead);
    free_respond(r);
}
static void put_float(unsigned char *p, float f) { memcpy(p, &f, 4); }
static void pcm_cases(const struct zapp_assistant *a)
{
    unsigned char bytes[9 * 4];
    const float values[9] = {0.0f, 0.5f, -0.5f, 1.0f, -1.0f, 2.0f, -2.0f, NAN, INFINITY};
    const int16_t want[9] = {0, 16383, -16383, 32767, -32768, 32767, -32768, 0, 32767};
    for (size_t i = 0; i < 9; i++) put_float(bytes + i * 4, values[i]);
    for (size_t piece = 1; piece <= 7; piece += 2) {
        reset_log();
        struct respond *r = new_respond(a, true);
        int16_t got[16]; size_t n = 0;
        for (size_t at = 0; at < sizeof(bytes); at += piece)
            assert(tts_sink(bytes + at, sizeof(bytes) - at < piece ? sizeof(bytes) - at : piece, r));
        for (size_t i = 0; i < emitted_count; i++) n += decode_pcm(emitted[i], got + n);
        assert(n == 9 && !memcmp(got, want, sizeof(want)) && r->carry_len == 0);
        free_respond(r);
    }
    reset_log();
    struct respond *r = new_respond(a, true);
    unsigned char *big = malloc(30000 * 4);
    assert(big);
    for (size_t i = 0; i < 30000; i++) put_float(big + i * 4, 0.25f);
    assert(tts_sink(big, 30000 * 4, r) && emitted_count == 3);
    int16_t *samples = malloc(12000 * sizeof(*samples));
    assert(samples && decode_pcm(emitted[0], samples) == 12000 && decode_pcm(emitted[2], samples) == 6000 && samples[0] == 8191);
    free(samples); free(big); free_respond(r);
}
static void type_cases(const struct zapp_assistant *a)
{
    const struct { const char *type; bool bad; int rate; } types[] = {
        {"audio/pcm;rate=24000;encoding=float;bits=32", false, 24000}, {"audio/pcm;rate=16000", false, 16000},
        {"audio/pcm", false, PCM_RATE}, {"audio/wav", true, 0}, {"audio/pcm;rate=99999", true, 0},
        {"audio/pcm;rate=7999", true, 0}, {"audio/pcm;rate=24000;encoding=s16", true, 0}};
    unsigned char one[4] = {0, 0, 0, 0};
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        struct respond *r = new_respond(a, true);
        tts_type(types[i].type, r);
        assert(r->pcm_bad == types[i].bad && (types[i].bad || r->rate == types[i].rate));
        assert(tts_sink(one, 4, r) == !types[i].bad);
        free_respond(r);
    }
    reset_log();
    struct respond *r = new_respond(a, true);
    emit_budget = 0;
    assert(!tts_sink(one, 4, r) && r->dead && !tts_sink(one, 4, r));
    free_respond(r);
}
struct mock { int listener; uint16_t port; unsigned connections; bool chat, fail; char body[4][4096]; };
static void send_chunk(int fd, const void *data, size_t size)
{
    char head[24];
    int n = snprintf(head, sizeof(head), "%zx\r\n", size);
    assert(send(fd, head, (size_t)n, MSG_NOSIGNAL) == n && send(fd, data, size, MSG_NOSIGNAL) == (ssize_t)size);
    assert(send(fd, "\r\n", 2, MSG_NOSIGNAL) == 2);
    usleep(1000);
}
static void read_request(int fd, char *body, size_t cap)
{
    char req[8192]; size_t used = 0;
    const char *split = NULL;
    while (req[used] = 0, !(split = memmem(req, used, "\r\n\r\n", 4))) {
        ssize_t n = recv(fd, req + used, sizeof(req) - 1 - used, 0); assert(n > 0); used += (size_t)n;
    }
    const char *length = strcasestr(req, "Content-Length:");
    size_t want = length ? strtoul(length + 15, NULL, 10) : 0, have = used - (size_t)(split + 4 - req);
    assert(want < cap);
    memcpy(body, split + 4, have);
    while (have < want) { ssize_t n = recv(fd, body + have, want - have, 0); assert(n > 0); have += (size_t)n; }
    body[want] = 0;
}
static void answer_chat(int fd)
{
    static const char head[] = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert(send(fd, head, sizeof(head) - 1, MSG_NOSIGNAL) == (ssize_t)sizeof(head) - 1);
    for (size_t at = 0; at < sizeof(fixture) - 1; at += 17)
        send_chunk(fd, fixture + at, sizeof(fixture) - 1 - at < 17 ? sizeof(fixture) - 1 - at : 17);
    assert(send(fd, "0\r\n\r\n", 5, MSG_NOSIGNAL) == 5);
}
static void answer_tts(int fd)
{
    static const char head[] = "HTTP/1.1 200 OK\r\nContent-Type: audio/pcm;rate=24000;encoding=float;bits=32\r\n"
        "Transfer-Encoding: chunked\r\n\r\n";
    unsigned char audio[8000];
    for (size_t i = 0; i < 2000; i++) put_float(audio + i * 4, 0.25f);
    assert(send(fd, head, sizeof(head) - 1, MSG_NOSIGNAL) == (ssize_t)sizeof(head) - 1);
    for (size_t at = 0; at < sizeof(audio); at += 1001)
        send_chunk(fd, audio + at, sizeof(audio) - at < 1001 ? sizeof(audio) - at : 1001);
    assert(send(fd, "0\r\n\r\n", 5, MSG_NOSIGNAL) == 5);
}
static void *serve_mock(void *opaque)
{
    struct mock *m = opaque;
    for (unsigned i = 0; i < m->connections; i++) {
        int fd = accept(m->listener, NULL, NULL); assert(fd >= 0);
        read_request(fd, m->body[i], sizeof(m->body[i]));
        if (m->fail) assert(send(fd, "HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n", 41, MSG_NOSIGNAL) == 41);
        else if (m->chat) answer_chat(fd);
        else answer_tts(fd);
        close(fd);
    }
    return NULL;
}
static void start_mock(struct mock *m, pthread_t *thread)
{
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof(addr);
    m->listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(m->listener >= 0 && !bind(m->listener, (struct sockaddr *)&addr, len) && !listen(m->listener, 4) &&
           !getsockname(m->listener, (struct sockaddr *)&addr, &len));
    m->port = ntohs(addr.sin_port);
    assert(!pthread_create(thread, NULL, serve_mock, m));
}
static size_t audio_between(size_t from, size_t to)
{
    int16_t *samples = malloc(12000 * sizeof(*samples));
    size_t total = 0;
    assert(samples);
    for (size_t i = from; i < to; i++) {
        size_t n = decode_pcm(emitted[i], samples);
        assert(n <= 12000 && samples[0] == 8191 && samples[n - 1] == 8191);
        total += n;
    }
    free(samples);
    return total;
}
static void respond_streamed(void)
{
    struct mock chat = {.chat = true, .connections = 1}, tts = {.connections = 2};
    pthread_t chat_thread, tts_thread;
    start_mock(&chat, &chat_thread); start_mock(&tts, &tts_thread);
    struct zapp_assistant a = {.chat_port = chat.port, .tts_port = tts.port, .speaker_b64 = "c3BlYWtlcg=="};
    char answer[512];
    reset_log();
    assert(zapp_assistant_respond(&a, "How is the fleet?", "ctx", -1, answer, sizeof(answer)));
    pthread_join(chat_thread, NULL); pthread_join(tts_thread, NULL);
    assert(!strcmp(answer, "Hello there, my friend. The fleet is fine. Everything looks good today."));
    assert(strstr(chat.body[0], "\"stream\":true") && strstr(chat.body[0], "\"max_tokens\":320") &&
           strstr(chat.body[0], "How is the fleet?") && strstr(chat.body[0], "ctx"));
    for (unsigned i = 0; i < 2; i++)
        assert(strstr(tts.body[i], "\"response_format\":\"pcm\"") && strstr(tts.body[i], "\"stream\":true") &&
               strstr(tts.body[i], "\"seed\":7") && strstr(tts.body[i], "\"speaker_ref_b64\":\"c3BlYWtlcg==\"") &&
               strstr(tts.body[i], "\"lang\":\"en\""));
    assert(strstr(tts.body[0], "\"input\":\"Hello there, my friend.\"") &&
           strstr(tts.body[1], "\"input\":\"The fleet is fine. Everything looks good today.\""));
    size_t second = 0;
    for (size_t i = 1; i < emitted_count; i++) if (strstr(emitted[i], "\"event\":\"text\"")) second = i;
    assert(emitted_count >= 4 && strstr(emitted[0], "\"event\":\"text\"") && second > 1);
    assert(audio_between(1, second) == 2000 && audio_between(second + 1, emitted_count) == 2000);
    close(chat.listener); close(tts.listener);
}
/* A failed synthesis silences the answer; its text still streams and completes. */
static void respond_muted(void)
{
    struct mock chat2 = {.chat = true, .connections = 1}, tts2 = {.fail = true, .connections = 1};
    pthread_t chat_thread, tts_thread;
    start_mock(&chat2, &chat_thread); start_mock(&tts2, &tts_thread);
    struct zapp_assistant a = {.chat_port = chat2.port, .tts_port = tts2.port, .speaker_b64 = "c3BlYWtlcg=="};
    char answer[512];
    reset_log();
    assert(zapp_assistant_respond(&a, "How is the fleet?", NULL, -1, answer, sizeof(answer)));
    pthread_join(chat_thread, NULL); pthread_join(tts_thread, NULL);
    assert(emitted_count == 2 && strstr(emitted[0], "\"event\":\"text\"") && strstr(emitted[1], "Everything"));
    close(chat2.listener); close(tts2.listener);
    reset_log();
    a.chat_port = 1;
    assert(!zapp_assistant_respond(&a, "Hi", NULL, -1, answer, sizeof(answer)) && strstr(answer, "unavailable"));
}
int main(void)
{
    struct zapp_assistant a = {.speaker_b64 = NULL};
    sentence_cases(&a); think_cases(&a); split_cases(&a); rejected_cases(&a);
    pcm_cases(&a); type_cases(&a); respond_streamed(); respond_muted();
    reset_log();
    puts("assistant tests passed");
    return 0;
}
