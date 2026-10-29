/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "speech_client.h"
#include "voice.h"
#include "json/json.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int64_t now_ms(void)
{
    struct timespec ts;
    return clock_gettime(CLOCK_MONOTONIC, &ts) ? -1 :
        (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static void dispose(void *data, size_t size)
{
    if (data) { memory_cleanse(data, size); free(data); }
}
static void little16(unsigned char *p, uint16_t value)
{
    p[0] = (unsigned char)value; p[1] = (unsigned char)(value >> 8);
}
static void little32(unsigned char *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = (unsigned char)(value >> (i * 8));
}
static bool write_all(int fd, const unsigned char *bytes, size_t size)
{
    size_t used = 0;
    while (used < size) {
        ssize_t n = write(fd, bytes + used, size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        used += (size_t)n;
    }
    return true;
}
static bool save_wav(const char *path, const int16_t *samples, size_t count, int rate)
{
    if (!count || count > 480000 || rate < 16000 || rate > 48000) return false;
    size_t size = 44 + count * 2;
    unsigned char *wav = calloc(1, size);
    if (!wav) return false;
    memcpy(wav, "RIFF", 4); little32(wav + 4, (uint32_t)(size - 8));
    memcpy(wav + 8, "WAVEfmt ", 8); little32(wav + 16, 16);
    little16(wav + 20, 1); little16(wav + 22, 1); little32(wav + 24, (uint32_t)rate);
    little32(wav + 28, (uint32_t)rate * 2); little16(wav + 32, 2); little16(wav + 34, 16);
    memcpy(wav + 36, "data", 4); little32(wav + 40, (uint32_t)(count * 2));
    for (size_t i = 0; i < count; ++i) little16(wav + 44 + i * 2, (uint16_t)samples[i]);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    struct stat identity = {0};
    bool owned = fd >= 0 && !fstat(fd, &identity);
    bool ok = owned && !fchmod(fd, 0600) && write_all(fd, wav, size) && !fsync(fd);
    if (fd >= 0 && close(fd)) ok = false;
    if (owned && !ok) {
        struct stat current;
        if (!lstat(path, &current) && current.st_dev == identity.st_dev && current.st_ino == identity.st_ino)
            (void)unlink(path);
    }
    dispose(wav, size); return ok;
}
static bool load_capture(const char *path, int16_t *samples, size_t *count)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return false;
    struct stat st;
    bool ok = !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_size >= 44 && st.st_size <= 640044;
    size_t size = ok ? (size_t)st.st_size : 0, used = 0;
    unsigned char *wav = ok ? malloc(size) : NULL;
    ok = wav != NULL;
    while (ok && used < size) {
        ssize_t n = read(fd, wav + used, size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = false; break; }
        used += (size_t)n;
    }
    unsigned char extra; uint32_t rate = 0;
    if (ok) ok = read(fd, &extra, 1) == 0 &&
        zapp_voice_wav_decode(wav, size, samples, 320000, count, &rate) && rate == 16000;
    close(fd); dispose(wav, size); return ok;
}
static bool report(struct json_value *result, int64_t start)
{
    int64_t end = now_ms();
    bool ok = start >= 0 && end >= start && json_push_kv_int(result, "elapsed_ms", end - start);
    size_t size = ok ? json_write(result, NULL, 0) : 0;
    char *wire = size && size < 400000 ? malloc(size + 1) : NULL;
    ok = wire && json_write(result, wire, size + 1) == size;
    if (ok) ok = puts(wire) >= 0;
    dispose(wire, size + 1); return ok;
}
int main(int argc, char **argv)
{
    bool speaking = argc == 5 && !strcmp(argv[2], "speak");
    bool transcribing = argc == 4 && !strcmp(argv[2], "transcribe");
    if (!speaking && !transcribing) {
        fputs("Usage: speech-roundtrip DIRECTORY speak TEXT NEW.wav\n"
              "       speech-roundtrip DIRECTORY transcribe CAPTURE.wav\n", stderr);
        return 2;
    }
    int64_t start = now_ms();
    struct json_value result = {0}; json_set_object(&result);
    bool ok = json_push_kv_str(&result, "schema", "z23.speech-roundtrip/1") &&
        json_push_kv_str(&result, "operation", argv[2]);
    int16_t *samples = NULL; size_t count = 0; int rate = 0;
    if (ok && speaking) {
        char error[256] = {0};
        ok = zapp_speech_client_speak(argv[1], argv[3], &samples, &count, &rate,
            NULL, error, sizeof(error)) && save_wav(argv[4], samples, count, rate) &&
            json_push_kv_int(&result, "samples", (int64_t)count) &&
            json_push_kv_int(&result, "sample_rate", rate);
        memory_cleanse(error, sizeof(error));
    } else if (ok) {
        samples = malloc(320000 * sizeof(*samples));
        char *text = calloc(1, 65536);
        ok = samples && text && load_capture(argv[3], samples, &count) &&
            zapp_speech_client_transcribe(argv[1], samples, count, text, 65536, NULL) &&
            json_push_kv_str(&result, "text", text) &&
            json_push_kv_int(&result, "samples", (int64_t)count) &&
            json_push_kv_int(&result, "sample_rate", 16000);
        dispose(text, 65536);
    }
    if (ok) ok = report(&result, start);
    if (!ok) fputs("Speech integration failed; no successful result recorded.\n", stderr);
    dispose(samples, (speaking ? 480000u : 320000u) * sizeof(*samples));
    json_cleanse_strings(&result); json_free(&result);
    return ok ? 0 : 1;
}
