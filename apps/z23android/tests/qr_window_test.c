/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "quirc.h"
#include <assert.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define PATH_CAP 4096

static bool write_all(int fd, const char *data, size_t n)
{
    size_t done = 0;
    while (done < n) {
        ssize_t w = write(fd, data + done, n - done);
        if (w <= 0) return false;
        done += (size_t)w;
    }
    return true;
}
/* Runs the dump program with text on its standard input; true when it exits 0. */
static bool dump(const char *program, const char *text, size_t n, const char *file)
{
    char flag[PATH_CAP + 16];
    int in[2];
    if (snprintf(flag, sizeof(flag), "--dump=%s", file) < 0 || pipe(in)) return false;
    pid_t pid = fork();
    if (pid == 0) {
        close(in[1]);
        if (dup2(in[0], 0) < 0) _exit(127);
        char *argv[] = {(char *)program, flag, NULL};
        execv(program, argv);
        _exit(127);
    }
    close(in[0]);
    bool sent = pid > 0 && write_all(in[1], text, n);
    close(in[1]);
    int status = 0;
    while (pid > 0 && waitpid(pid, &status, 0) < 0) {}
    return sent && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
/* Reads a P4 file and fills image with 8-bit grayscale: black for dark modules. */
static bool load_image(const unsigned char *bytes, size_t n, int head, int width, int height, unsigned char *image)
{
    size_t row = ((size_t)width + 7) / 8;
    if (n != (size_t)head + row * (size_t)height) return false;
    for (int y = 0; y < height; ++y) for (int x = 0; x < width; ++x) {
        const unsigned char *p = bytes + head + (size_t)y * row + (size_t)x / 8;
        image[(size_t)y * (size_t)width + (size_t)x] = (*p >> (7 - x % 8)) & 1 ? 0 : 255;
    }
    return true;
}
/* Reads up to cap bytes of the PBM file; returns the count, or 0 when the file cannot be read. */
static size_t read_file(const char *file, unsigned char *bytes, size_t cap)
{
    FILE *f = fopen(file, "rb");
    size_t n = f ? fread(bytes, 1, cap, f) : 0;
    if (!f || fclose(f) != 0) return 0;
    return n;
}
/* Parses the P4 header; head receives the byte offset of the first pixel row. */
static bool read_header(const unsigned char *bytes, int *width, int *height, int *head)
{
    *head = 0;
    if (sscanf((const char *)bytes, "P4\n%d %d\n%n", width, height, head) != 2 || *head <= 0) return false;
    return *width > 0 && *height > 0;
}
/* Copies the one payload quirc found into out; false when there is not exactly one code. */
static bool extract_payload(struct quirc *q, char *out, size_t cap, size_t *length)
{
    struct quirc_code code; struct quirc_data data;
    if (quirc_count(q) != 1) return false;
    quirc_extract(q, 0, &code);
    if (quirc_decode(&code, &data) != QUIRC_SUCCESS || data.payload_len < 0 ||
        (size_t)data.payload_len >= cap) return false;
    memcpy(out, data.payload, (size_t)data.payload_len);
    out[data.payload_len] = 0;
    *length = (size_t)data.payload_len;
    return true;
}
static bool decode_image(const unsigned char *bytes, size_t n, int head, int width, int height,
                         char *out, size_t cap, size_t *length)
{
    struct quirc *q = quirc_new();
    int qw = 0, qh = 0;
    bool ok = q && quirc_resize(q, width, height) == 0;
    unsigned char *image = ok ? quirc_begin(q, &qw, &qh) : NULL;
    ok = image && qw == width && qh == height && load_image(bytes, n, head, width, height, image);
    if (ok) quirc_end(q);
    ok = ok && extract_payload(q, out, cap, length);
    if (q) quirc_destroy(q);
    return ok;
}
/* Decodes the one code in a PBM written by --dump; the payload goes to out. */
static bool decode_pbm(const char *file, char *out, size_t cap, size_t *length)
{
    static unsigned char bytes[65536];
    size_t n = read_file(file, bytes, sizeof(bytes));
    int width = 0, height = 0, head = 0;
    return n && read_header(bytes, &width, &height, &head) &&
        decode_image(bytes, n, head, width, height, out, cap, length);
}
/* Fills out with n characters cycling through alphabet, after the prefix already in out. */
static void pattern(char *out, size_t n, const char *alphabet)
{
    size_t k = strlen(alphabet);
    for (size_t i = 0; i < n; ++i) out[i] = alphabet[i % k];
    out[n] = 0;
}
static void round_trip(const char *program, const char *dir, const char *name, const char *payload)
{
    char file[PATH_CAP], got[QUIRC_MAX_PAYLOAD];
    size_t length = 0, n = strlen(payload);
    assert(snprintf(file, sizeof(file), "%s/%s.pbm", dir, name) > 0);
    assert(dump(program, payload, n, file));
    assert(decode_pbm(file, got, sizeof(got), &length));
    assert(length == n && memcmp(got, payload, n) == 0);
}
int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    signal(SIGPIPE, SIG_IGN);
    const char *program = argv[1], *dir = argv[2];
    static const char hex[] = "0123456789abcdef";
    static const char words[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    char pair[71], clip[138], invite[2334], big[2334], file[PATH_CAP];
    memcpy(pair, "z23:pair:", 9); pattern(pair + 9, 61, hex);
    memcpy(clip, "z23:clip:", 9); pattern(clip + 9, 128, hex);
    memcpy(invite, "z23 fleet join ", 15); pattern(invite + 15, 2000 - 15, words);
    round_trip(program, dir, "pair", pair);
    round_trip(program, dir, "clip", clip);
    round_trip(program, dir, "invitation", invite);
    pattern(invite + 15, 2332 - 15, words);
    round_trip(program, dir, "invitation-max", invite);
    assert(snprintf(file, sizeof(file), "%s/refused.pbm", dir) > 0);
    assert(!dump(program, "", 0, file));
    memset(big, 'a', 2333); big[2333] = 0;
    assert(!dump(program, big, 2333, file));
    puts("qr window dump tests passed");
    return 0;
}
