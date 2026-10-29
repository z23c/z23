/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "speech_client.h"
#include "bridge_client.h"
#include "voice.h"
#include "json/json.h"
#include "base/cleanse.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SPEECH_CAP 2000000u
static void dispose(void *data, size_t size)
{ if (data) { memory_cleanse(data, size); free(data); } }

static bool write_all(int fd, const char *data, size_t size)
{
    size_t done = 0;
    while (done < size) {
        ssize_t n = write(fd, data + done, size - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}
bool zapp_speech_client_pair(const char *files, const char *json, char *error, size_t cap)
{
    if (!files || !json || !error || !cap) return false;
    snprintf(error, cap, "Voice pairing is invalid. Paste the host pairing JSON.");
    size_t len = strlen(json);
    struct json_value root = {0};
    bool ok = len && len < 256 && !strstr(json, "\\u") && json_read(&root, json, len);
    const char *token = json_get_str(json_get(&root, "token"));
    const struct json_value *port = json_get(&root, "port");
    ok = ok && root.type == JSON_OBJ && root.num_children == 2 && token &&
        strlen(token) == 64 && strspn(token, "0123456789abcdef") == 64 &&
        port && port->type == JSON_INT && json_get_int(port) > 0 && json_get_int(port) <= 65535;
    int dir = ok ? open(files, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW) : -1;
    struct stat st;
    ok = dir >= 0 && fstat(dir, &st) == 0 && st.st_uid == getuid() && !(st.st_mode & 0002) &&
        (!(st.st_mode & 0020) || st.st_gid == getgid());
    int fd = ok ? openat(dir, ".speech-pairing", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600) : -1;
    ok = fd >= 0 && fchmod(fd, 0600) == 0 && write_all(fd, json, len) && fsync(fd) == 0;
    if (fd >= 0 && close(fd)) ok = false;
    if (ok) ok = renameat(dir, ".speech-pairing", dir, "speech-bridge.json") == 0;
    if (fd >= 0 && !ok) (void)unlinkat(dir, ".speech-pairing", 0);
    if (dir >= 0) close(dir);
    json_cleanse_strings(&root); json_free(&root);
    if (ok) snprintf(error, cap, "Voice host paired. Keep its USB tunnel connected.");
    return ok;
}
bool zapp_speech_client_paired(const char *files, const char *json)
{
    char stored[256];
    size_t len = json ? strlen(json) : 0;
    int fd = files && len && len < sizeof(stored) ?
        open(files, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW) : -1;
    int file = fd >= 0 ? openat(fd, "speech-bridge.json", O_RDONLY | O_CLOEXEC | O_NOFOLLOW) : -1;
    ssize_t n = file >= 0 ? read(file, stored, sizeof(stored)) : -1;
    bool same = n == (ssize_t)len && !memcmp(stored, json, len);
    memory_cleanse(stored, sizeof(stored));
    if (file >= 0) close(file);
    if (fd >= 0) close(fd);
    return same;
}
static char *hex_encode(const unsigned char *data, size_t size)
{
    static const char hex[] = "0123456789abcdef";
    if (size > 640044) return NULL;
    char *out = malloc(size * 2 + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < size; i++) { out[i * 2] = hex[data[i] >> 4]; out[i * 2 + 1] = hex[data[i] & 15]; }
    out[size * 2] = 0; return out;
}
static int nibble(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    return -1;
}
static unsigned char *hex_decode(const char *hex, size_t *size)
{
    if (!hex) return NULL;
    size_t n = strlen(hex);
    if (!n || n % 2 || n > 1920088) return NULL;
    unsigned char *out = malloc(n / 2);
    if (!out) return NULL;
    for (size_t i = 0; i < n; i += 2) {
        int a = nibble(hex[i]), b = nibble(hex[i + 1]);
        if (a < 0 || b < 0) { dispose(out, n / 2); return NULL; }
        out[i / 2] = (unsigned char)((a << 4) | b);
    }
    *size = n / 2; return out;
}
static bool request(const char *files, const char *op, const char *key, const char *value,
    struct json_value *response, const atomic_bool *cancel, char *error, size_t cap)
{
    struct json_value root = {0}; json_set_object(&root);
    char *wire = calloc(1, SPEECH_CAP), *answer = calloc(1, SPEECH_CAP);
    bool ok = wire && answer && json_push_kv_str(&root, "schema", "z23.voice/1") &&
        json_push_kv_str(&root, "op", op) && json_push_kv_str(&root, key, value);
    size_t n = ok ? json_write(&root, wire, SPEECH_CAP) : SPEECH_CAP;
    ok = ok && n < SPEECH_CAP && zapp_bridge_speech(files, wire, answer, SPEECH_CAP, cancel);
    if (!ok && answer && answer[0]) snprintf(error, cap, "%s", answer);
    ok = ok && !strstr(answer, "\\u0000") && json_read(response, answer, strlen(answer)) &&
        response->type == JSON_OBJ && response->num_children == 1;
    json_cleanse_strings(&root); json_free(&root);
    dispose(wire, SPEECH_CAP); dispose(answer, SPEECH_CAP); return ok;
}
bool zapp_speech_client_transcribe(const char *files, const int16_t *samples, size_t count,
    char *text, size_t cap, const atomic_bool *cancel)
{
    if (!files || !samples || !text || !cap || count > 320000) return false;
    snprintf(text, cap, "Speech recognition is unavailable. You can still type.");
    size_t size = 0, bytes = count * 2 + 44;
    unsigned char *wav = malloc(bytes);
    bool ok = wav && zapp_voice_wav_encode(samples, count, wav, bytes, &size);
    char *hex = ok ? hex_encode(wav, size) : NULL;
    struct json_value response = {0};
    ok = hex && request(files, "transcribe", "wav", hex, &response, cancel, text, cap);
    const char *value = json_get_str(json_get(&response, "text"));
    ok = ok && value && value[0] && strlen(value) < cap;
    if (ok) memcpy(text, value, strlen(value) + 1);
    json_cleanse_strings(&response); json_free(&response);
    dispose(hex, size * 2 + 1); dispose(wav, bytes); return ok;
}
bool zapp_speech_client_speak(const char *files, const char *text, int16_t **samples,
    size_t *count, int *rate, const atomic_bool *cancel, char *error, size_t cap)
{
    if (!files || !text || !samples || !count || !rate || !error || !cap) return false;
    *samples = NULL; *count = 0; *rate = 0;
    snprintf(error, cap, "Spoken playback unavailable. Your reply is shown as text.");
    if (!text[0] || strlen(text) > 1000) return false;
    struct json_value response = {0};
    bool ok = request(files, "synthesize", "text", text, &response, cancel, error, cap);
    size_t bytes = 0, decoded = 0; uint32_t hz = 0;
    unsigned char *wav = ok ? hex_decode(json_get_str(json_get(&response, "wav")), &bytes) : NULL;
    int16_t *pcm = wav ? malloc(480000 * sizeof(*pcm)) : NULL;
    ok = pcm && zapp_voice_wav_decode(wav, bytes, pcm, 480000, &decoded, &hz);
    if (ok) { *samples = pcm; *count = decoded; *rate = (int)hz; }
    else dispose(pcm, 480000 * sizeof(*pcm));
    dispose(wav, bytes); json_cleanse_strings(&response); json_free(&response); return ok;
}
bool zapp_speech_client_chat(const char *files, const char *prompt, char *answer, size_t cap,
    const atomic_bool *cancel)
{
    if (!files || !prompt || !answer || !cap) return false;
    snprintf(answer, cap, "The private assistant on your laptop is unavailable. Connect it over USB.");
    struct json_value response = {0};
    bool ok = prompt[0] && request(files, "chat", "prompt", prompt, &response, cancel, answer, cap);
    const char *text = ok ? json_get_str(json_get(&response, "text")) : NULL;
    ok = text && text[0] && strlen(text) < cap;
    if (ok) memcpy(answer, text, strlen(text) + 1);
    json_cleanse_strings(&response); json_free(&response); return ok;
}
bool zapp_speech_client_fleet(const char *files, bool refresh, char *out, size_t cap,
    const atomic_bool *cancel)
{
    if (!files || !out || !cap) return false;
    snprintf(out, cap, "Fleet status is unavailable. Connect the laptop host over USB.");
    struct json_value response = {0};
    bool ok = request(files, "fleet", "scope", refresh ? "refresh" : "status", &response, cancel, out, cap);
    const struct json_value *fleet = ok ? json_get(&response, "fleet") : NULL;
    ok = fleet && fleet->type == JSON_OBJ && json_write(fleet, out, cap) < cap;
    json_cleanse_strings(&response); json_free(&response); return ok;
}
