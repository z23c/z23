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
static const char *mock_reply, *mock_op, *mock_scope;
static bool mock_success;
static unsigned calls;
static void check_string(const struct json_value *root, const char *key, const char *value)
{
    const char *s = json_get_str(json_get(root, key));
    assert(s && !strcmp(s, value));
}
bool zapp_bridge_speech(const char *files, const char *wire, char *out, size_t cap,
                        const atomic_bool *cancel)
{
    assert(files && wire && out && cap);
    assert(!cancel || !atomic_load(cancel));
    calls++;
    struct json_value root = {0};
    assert(json_read(&root, wire, strlen(wire)) && root.type == JSON_OBJ && root.num_children == 3);
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
static void path_join(char *out, size_t cap, const char *directory, const char *name)
{
    int n = snprintf(out, cap, "%s/%s", directory, name);
    assert(n > 0 && (size_t)n < cap);
}
static void pairing_cases(const char *directory)
{
    char error[256], path[4096], stage[4096], target[4096], linked[4096];
    path_join(path, sizeof(path), directory, "speech-bridge.json");
    path_join(stage, sizeof(stage), directory, ".speech-pairing");
    path_join(target, sizeof(target), directory, "target");
    path_join(linked, sizeof(linked), directory, "linked");
    mode_t mask = umask(0777);
    assert(zapp_speech_client_pair(directory, pairing, error, sizeof(error)));
    umask(mask);
    struct stat st;
    assert(!lstat(path, &st) && S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0600);
    assert(zapp_speech_client_paired(directory, pairing) && !zapp_speech_client_paired(directory, "{}"));
    assert(!zapp_speech_client_paired(NULL, pairing) && !zapp_speech_client_paired(directory, NULL));
    char bytes[256] = {0};
    int fd = open(path, O_RDONLY);
    assert(fd >= 0 && read(fd, bytes, sizeof(bytes)) == (ssize_t)strlen(pairing) && !strcmp(bytes, pairing));
    assert(!close(fd));
    const char *invalid[] = {
        "{}", "[]", "{\"port\":12345,\"token\":\"short\"}",
        "{\"port\":65536,\"token\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}",
        "{\"port\":12345,\"token\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg\"}",
        "{\"port\":12345,\"token\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"extra\":true}",
        "{\"port\":12345,\"token\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\\u0000\"}"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        assert(!zapp_speech_client_pair(directory, invalid[i], error, sizeof(error)));
    assert(!symlink(directory, linked));
    assert(!zapp_speech_client_pair(linked, pairing, error, sizeof(error)));
    assert(!unlink(linked));
    fd = open(target, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0 && write(fd, "keep", 4) == 4 && !close(fd));
    assert(!symlink(target, stage));
    assert(!zapp_speech_client_pair(directory, pairing, error, sizeof(error)));
    assert(!unlink(stage));
    assert(!unlink(path) && !symlink(target, path));
    assert(zapp_speech_client_pair(directory, pairing, error, sizeof(error)));
    assert(!lstat(path, &st) && S_ISREG(st.st_mode));
    memset(bytes, 0, sizeof(bytes)); fd = open(target, O_RDONLY);
    assert(fd >= 0 && read(fd, bytes, sizeof(bytes)) == 4 && !strcmp(bytes, "keep") && !close(fd));
    assert(!unlink(target) && !unlink(path));
    assert(!chmod(directory, 0771) && zapp_speech_client_pair(directory, pairing, error, sizeof(error)));
    assert(!unlink(path) && !chmod(directory, 0703));
    assert(!zapp_speech_client_pair(directory, pairing, error, sizeof(error)) && !chmod(directory, 0700));
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
    char reply[128]; strcpy(reply, "{\"wav\":\"");
    for (size_t i = 0; i < bytes; i++) (void)snprintf(reply + 8 + i * 2, sizeof(reply) - 8 - i * 2, "%02x", wav[i]);
    strcpy(reply + 8 + bytes * 2, "\"}"); mock_reply = reply;
    int16_t *pcm = NULL; size_t count = 0; int rate = 0; char error[256];
    assert(zapp_speech_client_speak(directory, "Hello.", &pcm, &count, &rate, NULL, error, sizeof(error)));
    assert(count == 5 && rate == 16000 && !memcmp(pcm, capture, sizeof(capture)));
    memory_cleanse(pcm, 480000 * sizeof(*pcm)); free(pcm);
    const char *bad[] = {"not json", "{}", "{\"wav\":\"0\"}", "{\"wav\":\"zz\"}",
        "{\"wav\":\"0000\"}", "{\"wav\":false}", "{\"wav\":\"00\",\"extra\":1}"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) speak_refused(directory, bad[i]);
    char *large = malloc(1920101); assert(large);
    memcpy(large, "{\"wav\":\"", 8); memset(large + 8, '0', 1920090); strcpy(large + 1920098, "\"}");
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
    assert(zapp_speech_client_chat(directory, "How is my node?", answer, sizeof(answer), NULL));
    assert(!strcmp(answer, "Your node is in step."));
    const char *bad[] = {"{}", "{\"text\":\"\"}", "{\"text\":1}", "{\"text\":\"a\",\"b\":1}"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        mock_reply = bad[i];
        assert(!zapp_speech_client_chat(directory, "How is my node?", answer, sizeof(answer), NULL));
    }
    mock_success = false; mock_reply = "Model unavailable.";
    assert(!zapp_speech_client_chat(directory, "How is my node?", answer, sizeof(answer), NULL));
    assert(!strcmp(answer, mock_reply));
    unsigned before = calls;
    assert(!zapp_speech_client_chat(directory, "", answer, sizeof(answer), NULL) && calls == before);
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
    chat_cases(argv[1]); fleet_cases(argv[1]);
    puts("speech client tests passed"); return 0;
}
