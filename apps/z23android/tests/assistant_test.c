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
static const char tool_fixture[] =
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":null}}]}\n\n"
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call-1\",\"type\":\"function\","
    "\"function\":{\"name\":\"host_blockers\",\"arguments\":\"{\"}}]}}]}\n\n"
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"host\\\":\"}}]}}]}\n\n"
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"call-2\",\"function\":{\"name\":\"x\"}}]}}]}\n\n"
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"r1\\\"}\"}}]}}]}\n\n"
    "data: {\"choices\":[{\"finish_reason\":\"tool_calls\",\"index\":0,\"delta\":{}}]}\n\n"
    "data: [DONE]\n\n";
/* Tool call pieces join in order; a second parallel call and oversized arguments are not taken. */
static void tool_cases(const struct zapp_assistant *a)
{
    struct respond *r = new_respond(a, true);
    assert(feed(r, tool_fixture, 13) && r->done && !r->text_len && !r->pending_len);
    assert(!strcmp(r->tool_id, "call-1") && !strcmp(r->tool_name, "host_blockers") && !strcmp(r->tool_args, "{\"host\":\"r1\"}"));
    free_respond(r);
    char big[600], sse[800];
    memset(big, 'a', sizeof(big) - 1); big[sizeof(big) - 1] = 0;
    snprintf(sse, sizeof(sse), "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":"
             "{\"arguments\":\"%s\"}}]}}]}\n", big);
    r = new_respond(a, true);
    assert(!feed(r, sse, 64));
    free_respond(r);
}
/* Underscores read as spaces, so identifiers such as blocker ids are spoken as words. */
static void underscore_cases(const struct zapp_assistant *a)
{
    char text[] = "r2 waits on *review_required*\nnow";
    spoken(text);
    assert(!strcmp(text, "r2 waits on review required now"));
    reset_log();
    struct respond *r = new_respond(a, true);
    assert(feed(r, "data: {\"choices\":[{\"delta\":{\"content\":\"Blocked by review_required.\"}}]}\n"
                "data: [DONE]\n", 9) && respond_finish(r) && emitted_count == 1);
    expect_line(0, "text", "Blocked by review required.");
    free_respond(r);
}
static void sentence_cases(const struct zapp_assistant *a)
{
    static const size_t pieces[] = {1, 3, 7, 64, 100000};
    for (size_t p = 0; p < sizeof(pieces) / sizeof(pieces[0]); p++) {
        reset_log();
        struct respond *r = new_respond(a, true);
        assert(feed(r, fixture, pieces[p]) && r->done && respond_finish(r));
        assert(emitted_count == 3);
        expect_line(0, "text", "Hello there, my friend.");
        expect_line(1, "text", "The fleet is fine.");
        expect_line(2, "text", "Everything looks good today.");
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
static size_t words_in(const char *line)
{
    size_t n = 0;
    for (const char *p = strstr(line, "word"); p; p = strstr(p + 4, "word")) n++;
    return n;
}
/* Unpunctuated text splits at words, each chunk within the cap the text already spoken allows. */
static void split_cases(const struct zapp_assistant *a)
{
    static const size_t counts[] = {6, 8, 10, 12, 15, 9};
    char words[400] = "", delta[512], sse[1024];
    for (int i = 0; i < 60; i++) memcpy(words + 5 * i, "word ", 5);
    snprintf(delta, sizeof(delta), "%s", words);
    snprintf(sse, sizeof(sse), "data: {\"choices\":[{\"delta\":{\"content\":\"%s\"}}]}\ndata: [DONE]\n", delta);
    reset_log();
    struct respond *r = new_respond(a, true);
    assert(feed(r, sse, 1000) && respond_finish(r));
    assert(emitted_count == 6 && strlen(r->text) == strlen(words) - 1);
    assert(!strncmp(emitted[0], "{\"event\":\"text\",\"data\":\"word word", 33));
    for (size_t i = 0; i < 6; i++) assert(words_in(emitted[i]) == counts[i]);
    free_respond(r);
    const char *sentence = "Hello there, my friend. The fleet is fine. More";
    assert(ready_len("Short one.", 10, MAX_CHUNK, false) == 0 && ready_len(sentence, strlen(sentence), MAX_CHUNK, false) == 42);
    assert(ready_len("aaaaaaaaaaaaaaaaaaaaaaa. b", 26, MAX_CHUNK, false) == 24 && ready_len("aaaaaaaaaaaaaaaaaaaaaa. b", 25, MAX_CHUNK, false) == 0);
    char run[200]; memset(run, 'a', sizeof(run)); run[199] = 0; run[100] = ' ';
    assert(ready_len(run, 199, MAX_CHUNK, false) == 100 && ready_len(run, 100, MAX_CHUNK, false) == 0);
    assert(ready_len(sentence, strlen(sentence), FIRST_CHUNK, true) == 23 && ready_len(run, 199, FIRST_CHUNK, true) == 32);
    const char *counting = "one two three four five six seven eight nine ten eleven";
    assert(ready_len(counting, strlen(counting), FIRST_CHUNK, true) == 27 && ready_len(counting, 32, FIRST_CHUNK, true) == 0);
}
static void cap_cases(const struct zapp_assistant *a)
{
    struct respond *r = new_respond(a, true);
    assert(chunk_cap(r) == FIRST_CHUNK);
    r->text_len = 4; assert(chunk_cap(r) == 33);
    r->text_len = 64; assert(chunk_cap(r) == 48);
    r->text_len = 511; assert(chunk_cap(r) == 159);
    r->text_len = 512; assert(chunk_cap(r) == MAX_CHUNK);
    r->text_len = 600; assert(chunk_cap(r) == MAX_CHUNK);
    free_respond(r);
}
/* A short first sentence speaks at once; later forced splits end at words, not short clauses. */
static void clause_cases(const struct zapp_assistant *a)
{
    static const char answer[] =
        "Yes. The node is synchronized and healthy, and the wallet balance is unchanged since this morning.";
    char sse[512];
    snprintf(sse, sizeof(sse), "data: {\"choices\":[{\"delta\":{\"content\":\"%s\"}}]}\ndata: [DONE]\n", answer);
    reset_log();
    struct respond *r = new_respond(a, true);
    assert(feed(r, sse, 7) && respond_finish(r) && emitted_count == 4 && !strcmp(r->text, answer));
    expect_line(0, "text", "Yes.");
    expect_line(1, "text", "The node is synchronized and");
    expect_line(2, "text", "healthy, and the wallet balance is");
    expect_line(3, "text", "unchanged since this morning.");
    free_respond(r);
    const char *clause = "Yes, the node is synchronized and healthy";
    assert(ready_len(clause, strlen(clause), 33, true) == 4 && ready_len(clause, strlen(clause), 33, false) == 33);
    char run[48] = {0};
    memset(run, 'a', sizeof(run) - 1);
    run[32] = ',';
    assert(ready_len(run, strlen(run), 33, false) == 33 && ready_len(run, strlen(run), 33, true) == 33);
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
struct mock { int listener; uint16_t port; unsigned connections; bool chat, fail; const char *script[4]; char body[4][4096]; };
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
static void answer_chat(int fd, const char *script)
{
    static const char head[] = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert(send(fd, head, sizeof(head) - 1, MSG_NOSIGNAL) == (ssize_t)sizeof(head) - 1);
    size_t n = strlen(script);
    for (size_t at = 0; at < n; at += 17)
        send_chunk(fd, script + at, n - at < 17 ? n - at : 17);
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
        else if (m->chat) answer_chat(fd, m->script[i] ? m->script[i] : fixture);
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
static void expect_tts(const char *body, const char *input)
{
    char want[128];
    snprintf(want, sizeof(want), "\"input\":\"%s\"", input);
    assert(strstr(body, "\"response_format\":\"pcm\"") && strstr(body, "\"stream\":true") &&
           strstr(body, "\"seed\":7") && strstr(body, "\"speaker_ref_b64\":\"c3BlYWtlcg==\"") &&
           strstr(body, "\"lang\":\"en\"") && strstr(body, want));
}
static void respond_streamed(void)
{
    struct mock chat = {.chat = true, .connections = 1}, tts = {.connections = 3};
    pthread_t chat_thread, tts_thread;
    start_mock(&chat, &chat_thread); start_mock(&tts, &tts_thread);
    struct zapp_assistant a = {.chat_port = chat.port, .tts_port = tts.port, .speaker_b64 = "c3BlYWtlcg=="};
    char answer[512];
    reset_log();
    assert(zapp_assistant_respond(&a, "How is the fleet?", NULL, "ctx", -1, answer, sizeof(answer)));
    pthread_join(chat_thread, NULL); pthread_join(tts_thread, NULL);
    assert(!strcmp(answer, "Hello there, my friend. The fleet is fine. Everything looks good today."));
    assert(strstr(chat.body[0], "\"stream\":true") && strstr(chat.body[0], "\"max_tokens\":320") &&
           strstr(chat.body[0], "How is the fleet?") && strstr(chat.body[0], "ctx") && !strstr(chat.body[0], "\"tools\""));
    expect_tts(tts.body[0], "Hello there, my friend.");
    expect_tts(tts.body[1], "The fleet is fine.");
    expect_tts(tts.body[2], "Everything looks good today.");
    size_t text[4] = {0}, texts = 0;
    for (size_t i = 0; i < emitted_count; i++)
        if (strstr(emitted[i], "\"event\":\"text\"")) { assert(texts < 3); text[texts++] = i; }
    assert(texts == 3 && text[0] == 0);
    text[3] = emitted_count;
    for (size_t t = 0; t < 3; t++) assert(text[t + 1] > text[t] + 1 && audio_between(text[t] + 1, text[t + 1]) == 2000);
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
    assert(zapp_assistant_respond(&a, "How is the fleet?", NULL, NULL, -1, answer, sizeof(answer)));
    pthread_join(chat_thread, NULL); pthread_join(tts_thread, NULL);
    assert(emitted_count == 3);
    expect_line(0, "text", "Hello there, my friend.");
    expect_line(1, "text", "The fleet is fine.");
    expect_line(2, "text", "Everything looks good today.");
    close(chat2.listener); close(tts2.listener);
    reset_log();
    a.chat_port = 1;
    assert(!zapp_assistant_respond(&a, "Hi", NULL, NULL, -1, answer, sizeof(answer)) && strstr(answer, "unavailable"));
}
static char tool_seen[2][256];
static bool tool_answers;
static bool fake_tool(const char *name, const char *arguments, char *out, size_t cap)
{
    snprintf(tool_seen[0], sizeof(tool_seen[0]), "%s", name);
    snprintf(tool_seen[1], sizeof(tool_seen[1]), "%s", arguments);
    snprintf(out, cap, "{\"host\":\"r1\",\"active\":1,\"blockers\":[{\"id\":\"boot.slow\"}]}");
    return tool_answers;
}
/* A reply that only calls a tool is answered by a second request that carries the call and its
 * result, or the refusal, and offers no tools. */
static void respond_tool(bool answers)
{
    static const char tool_schema[] = "[{\"type\":\"function\",\"function\":{\"name\":\"host_blockers\"}}]";
    struct json_value schema = {0};
    assert(json_read(&schema, tool_schema, strlen(tool_schema)));
    struct zapp_assistant_tools tools = {.schema = &schema, .guide = "Call host_blockers first.", .run = fake_tool};
    struct mock chat = {.chat = true, .connections = 2, .script = {tool_fixture}}, tts = {.connections = 3};
    pthread_t chat_thread, tts_thread;
    start_mock(&chat, &chat_thread); start_mock(&tts, &tts_thread);
    struct zapp_assistant a = {.chat_port = chat.port, .tts_port = tts.port, .speaker_b64 = "c3BlYWtlcg==",
                               .tools = &tools};
    char answer[512];
    reset_log(); tool_answers = answers;
    assert(zapp_assistant_respond(&a, "What blocks r1?", NULL, "ctx", -1, answer, sizeof(answer)));
    pthread_join(chat_thread, NULL); pthread_join(tts_thread, NULL);
    assert(!strcmp(answer, "Hello there, my friend. The fleet is fine. Everything looks good today."));
    assert(!strcmp(tool_seen[0], "host_blockers") && !strcmp(tool_seen[1], "{\"host\":\"r1\"}"));
    assert(strstr(chat.body[0], "\"tools\":[{\"type\":\"function\"") && !strstr(chat.body[1], "\"tools\""));
    assert(strstr(chat.body[0], "own laptop") && strstr(chat.body[0], "Call host_blockers first."));
    assert(strstr(chat.body[1], "{\"role\":\"assistant\",\"content\":\"\",\"tool_calls\":[{\"id\":\"call-1\","
        "\"type\":\"function\",\"function\":{\"name\":\"host_blockers\",\"arguments\":\"{\\\"host\\\":\\\"r1\\\"}\"}}]}"));
    assert(strstr(chat.body[1], "{\"role\":\"tool\",\"tool_call_id\":\"call-1\",\"content\":\""));
    assert(!strstr(chat.body[1], answers ? "refused" : "boot.slow"));
    assert(strstr(chat.body[1], answers ? "boot.slow" : "That tool call was refused."));
    assert(emitted_count > 3 && strstr(emitted[0], "\"event\":\"text\""));
    close(chat.listener); close(tts.listener);
    json_free(&schema);
}
static bool fill_call(const char *prompt, char *name, size_t name_cap, char *arguments, size_t arguments_cap)
{
    if (!strstr(prompt, "r1")) return false;
    snprintf(name, name_cap, "host_blockers"); snprintf(arguments, arguments_cap, "{\"host\":\"r1\"}");
    return true;
}
/* A call the prompt wants runs before the model answers, so one request carries its result. */
static void respond_wanted(void)
{
    static const char tool_schema[] = "[{\"type\":\"function\",\"function\":{\"name\":\"host_blockers\"}}]";
    struct json_value schema = {0};
    assert(json_read(&schema, tool_schema, strlen(tool_schema)));
    struct zapp_assistant_tools tools = {.schema = &schema, .run = fake_tool, .wanted = fill_call};
    struct mock chat = {.chat = true, .connections = 1}, tts = {.connections = 3};
    pthread_t chat_thread, tts_thread;
    start_mock(&chat, &chat_thread); start_mock(&tts, &tts_thread);
    struct zapp_assistant a = {.chat_port = chat.port, .tts_port = tts.port, .speaker_b64 = "c3BlYWtlcg==",
                               .tools = &tools};
    char answer[512];
    reset_log(); tool_answers = true; tool_seen[0][0] = tool_seen[1][0] = 0;
    assert(zapp_assistant_respond(&a, "What blocks r1?", NULL, "ctx", -1, answer, sizeof(answer)));
    pthread_join(chat_thread, NULL); pthread_join(tts_thread, NULL);
    assert(!strcmp(answer, "Hello there, my friend. The fleet is fine. Everything looks good today."));
    assert(!strcmp(tool_seen[0], "host_blockers") && !strcmp(tool_seen[1], "{\"host\":\"r1\"}"));
    assert(!strstr(chat.body[0], "\"tools\"") && strstr(chat.body[0], "\"tool_call_id\":\"call-0\""));
    assert(strstr(chat.body[0], "\"arguments\":\"{\\\"host\\\":\\\"r1\\\"}\"") && strstr(chat.body[0], "boot.slow"));
    close(chat.listener); close(tts.listener);
    json_free(&schema);
}
static void expect_message(const struct json_value *messages, size_t i, const char *role, const char *content)
{
    const struct json_value *m = json_at(messages, i);
    assert(m && !strcmp(json_get_str(json_get(m, "role")), role) &&
           !strcmp(json_get_str(json_get(m, "content")), content));
}
static bool messages_for(const char *history_json, struct json_value *messages)
{
    struct json_value history = {0};
    assert(json_read(&history, history_json, strlen(history_json)));
    bool ok = chat_messages(messages, "Q?", &history, "fleet data", NULL);
    json_free(&history);
    return ok;
}
static void message_cases(void)
{
    struct json_value messages = {0};
    assert(chat_messages(&messages, "Q?", NULL, NULL, NULL) && json_size(&messages) == 2);
    expect_message(&messages, 0, "system", system_prompt);
    expect_message(&messages, 1, "user", "Observations:\nnone\n\nQ?");
    json_free(&messages);
    char guided[sizeof(system_prompt) + 16];
    snprintf(guided, sizeof(guided), "%s Use the tool.", system_prompt);
    assert(chat_messages(&messages, "Q?", NULL, NULL, "Use the tool.") && json_size(&messages) == 2);
    expect_message(&messages, 0, "system", guided);
    json_free(&messages);
    assert(messages_for("[[\"q1\",\"a1\"],[\"q2\",\"a2\"]]", &messages) && json_size(&messages) == 6);
    expect_message(&messages, 0, "system", system_prompt);
    expect_message(&messages, 1, "user", "q1"); expect_message(&messages, 2, "assistant", "a1");
    expect_message(&messages, 3, "user", "q2"); expect_message(&messages, 4, "assistant", "a2");
    expect_message(&messages, 5, "user", "Observations:\nfleet data\n\nQ?");
    json_free(&messages);
    const char *bad[] = {"{}", "[[\"q\"]]", "[[\"q\",\"a\",\"b\"]]", "[[\"q\",1]]", "[[\"\",\"a\"]]", "[[\"q\",\"\"]]",
                         "[\"q\"]", "[[\"\xff\",\"a\"]]"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        assert(!messages_for(bad[i], &messages));
        json_free(&messages);
    }
    char many[1024] = "[";
    size_t at = 1;
    for (unsigned i = 0; i <= ZAPP_ASSISTANT_TURNS; i++, at += strlen(many + at))
        (void)snprintf(many + at, sizeof(many) - at, "%s[\"q\",\"a\"]", i ? "," : "");
    (void)snprintf(many + at, sizeof(many) - at, "]");
    assert(!messages_for(many, &messages));
    json_free(&messages);
    size_t n = strlen(many);
    many[n - 11] = ']'; many[n - 10] = 0;
    assert(messages_for(many, &messages) && json_size(&messages) == 2 + 2 * ZAPP_ASSISTANT_TURNS);
    json_free(&messages);
}
int main(void)
{
    struct zapp_assistant a = {.speaker_b64 = NULL};
    sentence_cases(&a); think_cases(&a); split_cases(&a); cap_cases(&a); clause_cases(&a);
    rejected_cases(&a); tool_cases(&a); underscore_cases(&a);
    pcm_cases(&a); type_cases(&a); respond_streamed(); respond_muted(); respond_tool(true); respond_tool(false); respond_wanted();
    message_cases();
    reset_log();
    puts("assistant tests passed");
    return 0;
}
