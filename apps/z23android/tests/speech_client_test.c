/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "speech_client.h"
#include "bridge_client.h"
#include "voice.h"
#include "json/json.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char pairing[] = "{\"port\":12345,\"token\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}";
static const int16_t capture[] = {INT16_MIN, -1, 0, 1, INT16_MAX};
static const char *mock_reply, *mock_op, *mock_scope, *mock_history;
static bool mock_success;
static unsigned calls;
static void check_string(const struct json_value *root, const char *key, const char *value)
{
    const char *s = json_get_str(json_get(root, key));
    assert(s && !strcmp(s, value));
}
/* The request carries exactly the expected history array, or none. */
static void check_history(const struct json_value *root)
{
    const struct json_value *history = json_get(root, "history");
    assert(root->num_children == (mock_history ? 4u : 3u) && !history == !mock_history);
    char text[256];
    if (history) assert(json_write(history, text, sizeof(text)) < sizeof(text) && !strcmp(text, mock_history));
}
bool zapp_bridge_speech(const char *files, const char *wire, char *out, size_t cap,
                        const atomic_bool *cancel)
{
    assert(files && wire && out && cap);
    assert(!cancel || !atomic_load(cancel));
    calls++;
    struct json_value root = {0};
    assert(json_read(&root, wire, strlen(wire)) && root.type == JSON_OBJ);
    check_history(&root);
    check_string(&root, "schema", "z23.voice/1");
    check_string(&root, "op", mock_op);
    if (!strcmp(mock_op, "transcribe")) {
        unsigned char wav[54]; size_t size = 0;
        assert(zapp_voice_wav_encode(capture, 5, wav, sizeof(wav), &size));
        const char *hex = json_get_str(json_get(&root, "wav"));
        assert(hex && strlen(hex) == size * 2);
        static const char digits[] = "0123456789abcdef";
        for (size_t i = 0; i < size; i++) {
            assert(hex[i * 2] == digits[wav[i] >> 4]);
            assert(hex[i * 2 + 1] == digits[wav[i] & 15]);
        }
    } else if (!strcmp(mock_op, "chat")) check_string(&root, "prompt", "How is my node?");
    else if (!strcmp(mock_op, "fleet")) check_string(&root, "scope", mock_scope);
    else check_string(&root, "text", "Hello.");
    assert(mock_reply && strlen(mock_reply) < cap);
    memcpy(out, mock_reply, strlen(mock_reply) + 1);
    json_cleanse_strings(&root); json_free(&root);
    return mock_success;
}
static const char *mock_events[4];
bool zapp_bridge_speech_events(const char *files, const char *wire, char *out, size_t cap,
    bool (*on_event)(const struct json_value *event, void *ctx), void *ctx, const atomic_bool *cancel)
{
    assert(files && wire && out && cap && on_event && !cancel);
    calls++;
    struct json_value root = {0};
    assert(json_read(&root, wire, strlen(wire)) && root.type == JSON_OBJ);
    check_history(&root);
    check_string(&root, "schema", "z23.voice/1"); check_string(&root, "op", "respond");
    check_string(&root, "prompt", "How is my node?");
    json_cleanse_strings(&root); json_free(&root);
    for (size_t i = 0; i < 4 && mock_events[i]; i++) {
        struct json_value event = {0};
        assert(json_read(&event, mock_events[i], strlen(mock_events[i])));
        bool more = on_event(&event, ctx);
        json_free(&event);
        if (!more) { snprintf(out, cap, "Voice cancelled."); return false; }
    }
    assert(mock_reply && strlen(mock_reply) < cap);
    memcpy(out, mock_reply, strlen(mock_reply) + 1);
    return mock_success;
}
static void path_join(char *out, size_t cap, const char *directory, const char *name)
{
    int n = snprintf(out, cap, "%s/%s", directory, name);
    assert(n > 0 && (size_t)n < cap);
}
struct pair_paths { char path[4096], stage[4096], target[4096], linked[4096]; };
static void stored_pairing(const char *directory, const struct pair_paths *p)
{
    char error[256], bytes[256] = {0};
    mode_t mask = umask(0777);
    assert(zapp_speech_client_pair(directory, pairing, error, sizeof(error)));
    umask(mask);
    struct stat st;
    assert(!lstat(p->path, &st) && S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0600);
    assert(zapp_speech_client_paired(directory, pairing) && !zapp_speech_client_paired(directory, "{}"));
    assert(!zapp_speech_client_paired(NULL, pairing) && !zapp_speech_client_paired(directory, NULL));
    int fd = open(p->path, O_RDONLY);
    assert(fd >= 0 && read(fd, bytes, sizeof(bytes)) == (ssize_t)strlen(pairing) && !strcmp(bytes, pairing));
    assert(!close(fd));
}
static void invalid_pairing(const char *directory, const struct pair_paths *p)
{
    char error[256];
    const char *invalid[] = {
        "{}", "[]", "{\"port\":12345,\"token\":\"short\"}",
        "{\"port\":65536,\"token\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}",
        "{\"port\":12345,\"token\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg\"}",
        "{\"port\":12345,\"token\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"extra\":true}",
        "{\"port\":12345,\"token\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\\u0000\"}"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        assert(!zapp_speech_client_pair(directory, invalid[i], error, sizeof(error)));
    assert(!symlink(directory, p->linked));
    assert(!zapp_speech_client_pair(p->linked, pairing, error, sizeof(error)));
    assert(!unlink(p->linked));
}
static void staged_pairing(const char *directory, const struct pair_paths *p)
{
    char error[256], bytes[256] = {0};
    struct stat st;
    int fd = open(p->target, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0 && write(fd, "keep", 4) == 4 && !close(fd));
    assert(!symlink(p->target, p->stage));
    assert(!zapp_speech_client_pair(directory, pairing, error, sizeof(error)));
    assert(!unlink(p->stage));
    fd = open(p->stage, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0 && write(fd, "{", 1) == 1 && !close(fd));
    assert(zapp_speech_client_pair(directory, pairing, error, sizeof(error)) && access(p->stage, F_OK));
    assert(!unlink(p->path) && !symlink(p->target, p->path));
    assert(zapp_speech_client_pair(directory, pairing, error, sizeof(error)));
    assert(!lstat(p->path, &st) && S_ISREG(st.st_mode));
    fd = open(p->target, O_RDONLY);
    assert(fd >= 0 && read(fd, bytes, sizeof(bytes)) == 4 && !strcmp(bytes, "keep") && !close(fd));
    assert(!unlink(p->target) && !unlink(p->path));
}
static void directory_modes(const char *directory, const struct pair_paths *p)
{
    char error[256];
    assert(!chmod(directory, 0771) && zapp_speech_client_pair(directory, pairing, error, sizeof(error)));
    assert(!unlink(p->path) && !chmod(directory, 0703));
    assert(!zapp_speech_client_pair(directory, pairing, error, sizeof(error)) && !chmod(directory, 0700));
}
static void pairing_cases(const char *directory)
{
    struct pair_paths p;
    path_join(p.path, sizeof(p.path), directory, "speech-bridge.json");
    path_join(p.stage, sizeof(p.stage), directory, ".speech-pairing");
    path_join(p.target, sizeof(p.target), directory, "target");
    path_join(p.linked, sizeof(p.linked), directory, "linked");
    stored_pairing(directory, &p);
    invalid_pairing(directory, &p);
    staged_pairing(directory, &p);
    directory_modes(directory, &p);
}
static void transcribe_cases(const char *directory)
{
    char text[256]; mock_op = "transcribe"; mock_success = true;
    mock_reply = "{\"text\":\"Hello there.\"}";
    assert(zapp_speech_client_transcribe(directory, capture, 5, text, sizeof(text), NULL));
    assert(!strcmp(text, "Hello there."));
    const char *bad[] = {"not json", "{}", "{\"text\":\"\"}", "{\"text\":42}",
        "{\"text\":\"hello\",\"extra\":1}", "{\"text\":\"hello\\u0000hidden\"}"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        mock_reply = bad[i];
        assert(!zapp_speech_client_transcribe(directory, capture, 5, text, sizeof(text), NULL));
    }
    mock_success = false; mock_reply = "Recognition refused.";
    assert(!zapp_speech_client_transcribe(directory, capture, 5, text, sizeof(text), NULL));
    assert(!strcmp(text, mock_reply));
    unsigned before = calls;
    assert(!zapp_speech_client_transcribe(directory, capture, 320001, text, sizeof(text), NULL));
    assert(!zapp_speech_client_transcribe(directory, capture, 0, text, sizeof(text), NULL));
    assert(calls == before);
}
static void speak_refused(const char *directory, const char *reply)
{
    mock_reply = reply;
    int16_t *pcm = (int16_t *)capture; size_t count = 99; int rate = 99; char error[256];
    assert(!zapp_speech_client_speak(directory, "Hello.", &pcm, &count, &rate, NULL, error, sizeof(error)));
    assert(!pcm && !count && !rate);
}
static void speak_cases(const char *directory)
{
    mock_op = "synthesize"; mock_success = true;
    unsigned char wav[54]; size_t bytes = 0;
    assert(zapp_voice_wav_encode(capture, 5, wav, sizeof(wav), &bytes));
    char reply[128]; memcpy(reply, "{\"wav\":\"", 8);
    for (size_t i = 0; i < bytes; i++) (void)snprintf(reply + 8 + i * 2, sizeof(reply) - 8 - i * 2, "%02x", wav[i]);
    memcpy(reply + 8 + bytes * 2, "\"}", 3); mock_reply = reply;
    int16_t *pcm = NULL; size_t count = 0; int rate = 0; char error[256];
    assert(zapp_speech_client_speak(directory, "Hello.", &pcm, &count, &rate, NULL, error, sizeof(error)));
    assert(count == 5 && rate == 16000 && !memcmp(pcm, capture, sizeof(capture)));
    memory_cleanse(pcm, 480000 * sizeof(*pcm)); free(pcm);
    const char *bad[] = {"not json", "{}", "{\"wav\":\"0\"}", "{\"wav\":\"zz\"}",
        "{\"wav\":\"0000\"}", "{\"wav\":false}", "{\"wav\":\"00\",\"extra\":1}"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) speak_refused(directory, bad[i]);
    char *large = malloc(1920101); assert(large);
    memcpy(large, "{\"wav\":\"", 8); memset(large + 8, '0', 1920090); memcpy(large + 1920098, "\"}", 3);
    speak_refused(directory, large); free(large);
    mock_success = false; speak_refused(directory, "Synthesis refused.");
    unsigned before = calls;
    char too_long[1002]; memset(too_long, 'a', 1001); too_long[1001] = 0;
    assert(!zapp_speech_client_speak(directory, too_long, &pcm, &count, &rate, NULL, error, sizeof(error)));
    assert(calls == before);
}
static void chat_cases(const char *directory)
{
    char answer[256]; mock_op = "chat"; mock_success = true;
    mock_reply = "{\"text\":\"Your node is in step.\"}";
    assert(zapp_speech_client_chat(directory, "How is my node?", NULL, answer, sizeof(answer), NULL));
    assert(!strcmp(answer, "Your node is in step."));
    struct json_value history = {0};
    mock_history = "[[\"hi\",\"hello\"]]";
    assert(json_read(&history, mock_history, strlen(mock_history)));
    assert(zapp_speech_client_chat(directory, "How is my node?", &history, answer, sizeof(answer), NULL));
    assert(!strcmp(answer, "Your node is in step."));
    mock_events[0] = NULL;
    assert(zapp_speech_client_respond(directory, "How is my node?", &history, NULL, NULL, NULL, answer,
                                      sizeof(answer), NULL) && !strcmp(answer, "Your node is in step."));
    mock_history = NULL; json_free(&history);
    const char *bad[] = {"{}", "{\"text\":\"\"}", "{\"text\":1}", "{\"text\":\"a\",\"b\":1}"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        mock_reply = bad[i];
        assert(!zapp_speech_client_chat(directory, "How is my node?", NULL, answer, sizeof(answer), NULL));
    }
    mock_success = false; mock_reply = "Model unavailable.";
    assert(!zapp_speech_client_chat(directory, "How is my node?", NULL, answer, sizeof(answer), NULL));
    assert(!strcmp(answer, mock_reply));
    unsigned before = calls;
    assert(!zapp_speech_client_chat(directory, "", NULL, answer, sizeof(answer), NULL) && calls == before);
}
struct heard { unsigned texts, pcms; char text[64]; int16_t samples[8]; size_t count; int rate; };
static void heard_text(const char *text, void *ctx)
{
    struct heard *h = ctx;
    h->texts++; snprintf(h->text, sizeof(h->text), "%s", text);
}
static void heard_pcm(const int16_t *samples, size_t count, int rate, void *ctx)
{
    struct heard *h = ctx;
    assert(count <= 8);
    h->pcms++; h->count = count; h->rate = rate; memcpy(h->samples, samples, count * sizeof(*samples));
}
static bool respond_with(const char *directory, const char *event, const char *final, bool success,
    struct heard *h, char *answer, size_t cap)
{
    mock_events[0] = event; mock_events[1] = NULL; mock_reply = final; mock_success = success;
    *h = (struct heard){0};
    return zapp_speech_client_respond(directory, "How is my node?", NULL, heard_text, heard_pcm, h, answer, cap, NULL);
}
static void respond_cases(const char *directory)
{
    char answer[256]; struct heard h;
    const char *final = "{\"text\":\"Hello there.\"}";
    mock_events[0] = "{\"event\":\"text\",\"data\":\"Hello there.\"}";
    mock_events[1] = "{\"event\":\"pcm\",\"rate\":24000,\"data\":\"0100ff7f0080ffff\"}";
    mock_events[2] = "{\"event\":\"mood\",\"data\":\"ignored\"}"; mock_events[3] = NULL;
    mock_reply = final; mock_success = true; h = (struct heard){0};
    assert(zapp_speech_client_respond(directory, "How is my node?", NULL, heard_text, heard_pcm, &h, answer, sizeof(answer), NULL));
    assert(!strcmp(answer, "Hello there.") && h.texts == 1 && !strcmp(h.text, "Hello there."));
    assert(h.pcms == 1 && h.count == 4 && h.rate == 24000);
    assert(h.samples[0] == 1 && h.samples[1] == INT16_MAX && h.samples[2] == INT16_MIN && h.samples[3] == -1);
    mock_events[0] = NULL;
    assert(zapp_speech_client_respond(directory, "How is my node?", NULL, NULL, NULL, NULL, answer, sizeof(answer), NULL));
    mock_events[0] = "{\"event\":\"text\",\"data\":\"x\"}"; mock_events[1] = "{\"event\":\"pcm\",\"rate\":24000,\"data\":\"0100\"}";
    mock_events[2] = NULL;
    assert(zapp_speech_client_respond(directory, "How is my node?", NULL, NULL, NULL, NULL, answer, sizeof(answer), NULL));
    const char *bad[] = {
        "{\"event\":\"pcm\",\"rate\":24000,\"data\":\"zz00\"}", "{\"event\":\"pcm\",\"rate\":24000,\"data\":\"010\"}",
        "{\"event\":\"pcm\",\"rate\":24000,\"data\":\"0100aa\"}", "{\"event\":\"pcm\",\"rate\":24000,\"data\":\"\"}",
        "{\"event\":\"pcm\",\"rate\":24000}", "{\"event\":\"pcm\",\"data\":\"0100\"}",
        "{\"event\":\"pcm\",\"rate\":7999,\"data\":\"0100\"}", "{\"event\":\"pcm\",\"rate\":48001,\"data\":\"0100\"}",
        "{\"event\":\"pcm\",\"rate\":\"24000\",\"data\":\"0100\"}",
        "{\"event\":\"text\"}", "{\"event\":\"text\",\"data\":\"\"}", "{\"event\":\"\",\"data\":\"x\"}", "{\"event\":1}",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        assert(!respond_with(directory, bad[i], final, true, &h, answer, sizeof(answer)));
        assert(!strcmp(answer, "Voice cancelled.") || !strcmp(answer, "The private assistant on your laptop is unavailable. Connect it over USB."));
        assert(!h.texts && !h.pcms);
    }
    char *large = malloc(96100); assert(large);
    int head = snprintf(large, 96100, "{\"event\":\"pcm\",\"rate\":24000,\"data\":\"");
    memset(large + head, '0', 96004); memcpy(large + head + 96004, "\"}", 3);
    assert(!respond_with(directory, large, final, true, &h, answer, sizeof(answer)) && !h.pcms); free(large);
    for (size_t i = 0; i < 2; i++) {
        const char *finals[] = {"{\"text\":\"\"}", "{\"text\":\"a\",\"b\":1}"};
        assert(!respond_with(directory, NULL, finals[i], true, &h, answer, sizeof(answer)));
    }
    assert(!respond_with(directory, NULL, "Model unavailable.", false, &h, answer, sizeof(answer)));
    assert(!strcmp(answer, "Model unavailable."));
    unsigned before = calls;
    assert(!zapp_speech_client_respond(directory, "", NULL, NULL, NULL, NULL, answer, sizeof(answer), NULL) && calls == before);
}
static void fleet_cases(const char *directory)
{
    char out[256]; mock_op = "fleet"; mock_success = true; mock_scope = "refresh";
    mock_reply = "{\"fleet\":{\"hosts\":[],\"observed_at\":1}}";
    assert(zapp_speech_client_fleet(directory, true, out, sizeof(out), NULL));
    assert(!strcmp(out, "{\"hosts\":[],\"observed_at\":1}"));
    mock_scope = "status"; mock_reply = "{\"fleet\":[1]}";
    assert(!zapp_speech_client_fleet(directory, false, out, sizeof(out), NULL));
    mock_reply = "{\"fleet\":{\"hosts\":[]}}";
    assert(!zapp_speech_client_fleet(directory, false, out, 8, NULL));
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    pairing_cases(argv[1]); transcribe_cases(argv[1]); speak_cases(argv[1]);
    chat_cases(argv[1]); respond_cases(argv[1]); fleet_cases(argv[1]);
    puts("speech client tests passed"); return 0;
}
