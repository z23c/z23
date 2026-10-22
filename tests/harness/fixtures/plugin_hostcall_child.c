/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fixture plugin for test_plugin_run_hostcall.c (built by the Makefile into
 * build/fixtures/, never linked into a product binary). It is a resident
 * plugin (docs/dev/PLUGINS.md): argv is `<image> --resident <launch nonce>`,
 * Z23_PLUGIN_FDS names the control and log descriptors. Before serving pings
 * it makes host calls over the control socket and writes what it got back as
 * ONE log line, so the supervisor's last_log carries the whole outcome:
 *
 *   hostcall tip=<status> height=<u32> wallet=<status>
 *
 * It encodes and decodes the 12-byte host-call frame by hand, as an oracle
 * independent of plugin_hostcall.c: u32 length, u8 version, u8 kind, u32 id,
 * u16 code, big-endian. chain.tip is method 1, wallet.request method 7. The
 * grant comes only from the signed manifest, so the same image run as two
 * plugins (one declaring chain.read, one not) shows grant and denial.
 *
 * The behaviour is a 16-byte field patched by the test:
 *   tip       the calls above, then answer pings and exit on stop
 *   paced     as tip, and the line ends " paced=1" when the second reply came a
 *             full one-second window after the first call was sent (the child
 *             times itself; the test grades only the line it logs)

 *   badframe  send a frame with an unknown version, then read supervisor frames
 *             until the control socket ends; log "hostcall badframe eof=1
 *             reply=0" when the stream ended with no host-call reply in it (eof=0
 *             when the read failed some other way, reply=1 when a reply came),
 *   flood:N   wait for the first ping, then send N wallet.request calls (12-byte
 *             PLANNED replies) -- the test passes the count that fills the
 *             supervisor's send queue (a seccomp-confined child cannot probe it
 *             itself) -- log "hostcall flooded n=<N>", then sleep without ever
 *             reading again
 * A ping or stop frame can arrive while a reply is awaited; frames are told
 * apart by their first byte ('z' for supervisor frames, 0 for host-call). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "platform/resident_launch.h"

#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((used)) static volatile const char hcc_variant[] =
    "HCC-VARIANT:tip             ;";
#define HCC_MARKER_LEN 12
#define HCC_SUP_FRAME 81

static bool hcc_io(int fd, void *buffer, size_t size, bool sending)
{
    unsigned char *bytes = buffer;
    for (size_t done = 0; done < size;) {
        ssize_t n = sending ? write(fd, bytes + done, size - done)
                            : read(fd, bytes + done, size - done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        done += (size_t)n;
    }
    return true;
}

static bool hcc_mode_is(const char *mode)
{
    return strncmp((const char *)hcc_variant + HCC_MARKER_LEN, mode, strlen(mode)) == 0;
}

static int hcc_fd_of(const char *name)
{
    const char *env = getenv("Z23_PLUGIN_FDS");
    size_t len = strlen(name);
    for (const char *p = env; p && *p;) {
        if (strncmp(p, name, len) == 0 && p[len] == '=')
            return atoi(p + len + 1);
        p = strchr(p, ',');
        if (p)
            p++;
    }
    return -1;
}

static uint32_t hcc_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static bool hcc_ping_reply(const char *nonce, const char *token)
{
    struct resident_result_header header;
    memset(&header, 0, sizeof(header));
    snprintf(header.magic, sizeof(header.magic), "%s", "z23-res-run-v1");
    snprintf(header.nonce, sizeof(header.nonce), "%s", nonce);
    header.payload_len = 64;
    return hcc_io(RESIDENT_LAUNCH_CHILD_FD, &header, sizeof(header), true) &&
           hcc_io(RESIDENT_LAUNCH_CHILD_FD, (void *)token, 64, true);
}

/* Send one request with an empty payload; version is a parameter so the bad
 * frame mode can send a refused one. */
static bool hcc_send(uint32_t id, uint16_t method, uint8_t version)
{
    uint8_t f[12] = {0, 0, 0, 8, version, 1, 0, 0, 0, 0, 0, 0};
    f[6] = (uint8_t)(id >> 24); f[7] = (uint8_t)(id >> 16);
    f[8] = (uint8_t)(id >> 8); f[9] = (uint8_t)id;
    f[10] = (uint8_t)(method >> 8); f[11] = (uint8_t)method;
    return hcc_io(RESIDENT_LAUNCH_CHILD_FD, f, sizeof(f), true);
}

/* A supervisor frame whose first byte 'z' was already read: stop exits, a ping
 * is answered. False means the connection failed. */
static bool hcc_supervisor_frame(const char *nonce, uint8_t first)
{
    char frame[HCC_SUP_FRAME];
    frame[0] = (char)first;
    if (!hcc_io(RESIDENT_LAUNCH_CHILD_FD, frame + 1, sizeof(frame) - 1, false))
        return false;
    if (strcmp(frame, "z23-res-stop-v1") == 0)
        exit(0);
    return strcmp(frame, "z23-plg-ping-v1") != 0 || hcc_ping_reply(nonce, frame + 16);
}

/* Read one host-call reply frame whose first byte (0) was already read.
 * Returns the reply status (or 0xffff on failure) and the payload. */
static unsigned hcc_reply(uint32_t id, uint8_t *payload, size_t cap, size_t *len)
{
    uint8_t head[11], body[256];
    if (!hcc_io(RESIDENT_LAUNCH_CHILD_FD, head, sizeof(head), false))
        return 0xffff;
    /* head holds length bytes 1..3, then version, kind, id (4) and code (2). */
    uint32_t length = ((uint32_t)head[0] << 16) | ((uint32_t)head[1] << 8) | head[2];
    uint32_t rid = hcc_be32(head + 5);
    unsigned code = (unsigned)((head[9] << 8) | head[10]);
    size_t plen = length >= 8 ? length - 8 : 0;
    if (plen > sizeof(body) || (plen && !hcc_io(RESIDENT_LAUNCH_CHILD_FD, body, plen, false)))
        return 0xffff;
    if (head[4] != 2 || rid != id)
        return 0xffff;
    if (plen <= cap && payload)
        memcpy(payload, body, plen);
    *len = plen;
    return code;
}

/* Read frames until the host-call reply for id arrives, answering pings on the
 * way. Returns the reply status (or 0xffff on failure) and the payload. */
static unsigned hcc_await(const char *nonce, uint32_t id, uint8_t *payload, size_t cap, size_t *len)
{
    for (;;) {
        uint8_t first;
        if (!hcc_io(RESIDENT_LAUNCH_CHILD_FD, &first, 1, false))
            return 0xffff;
        if (first == 'z') {
            if (!hcc_supervisor_frame(nonce, first))
                return 0xffff;
            continue;
        }
        return first == 0 ? hcc_reply(id, payload, cap, len) : 0xffff;
    }
}

static int hcc_serve(const char *nonce)
{
    char frame[HCC_SUP_FRAME];
    while (hcc_io(RESIDENT_LAUNCH_CHILD_FD, frame, sizeof(frame), false)) {
        if (strcmp(frame, "z23-res-stop-v1") == 0)
            return 0;
        if (strcmp(frame, "z23-plg-ping-v1") == 0 && !hcc_ping_reply(nonce, frame + 16))
            return 5;
    }
    return 0;
}

/* badframe mode: after the bad frame the supervisor must end the stream, not
 * answer it. Read whole supervisor frames until the socket ends and report
 * what ended it, so the test can tell a closed stream from a child that was
 * merely killed for missing pings. */
static int hcc_badframe(int log_fd)
{
    (void)hcc_send(1, 1, 9);
    unsigned eof = 0, reply = 0;
    for (;;) {
        uint8_t first;
        ssize_t n = read(RESIDENT_LAUNCH_CHILD_FD, &first, 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n == 0)
            eof = 1;
        if (n <= 0)
            break;
        char rest[HCC_SUP_FRAME];
        if (first == 0)
            reply = 1;
        if (first == 0 || !hcc_io(RESIDENT_LAUNCH_CHILD_FD, rest, sizeof(rest) - 1, false))
            break;
    }
    char line[64];
    int len = snprintf(line, sizeof(line), "hostcall badframe eof=%u reply=%u\n", eof, reply);
    if (log_fd >= 0 && len > 0)
        (void)hcc_io(log_fd, line, (size_t)len, true);
    return 0;
}

/* flood mode: never read again once the queue is full of replies. */
static int hcc_flood(int log_fd, unsigned want)
{
    char first[HCC_SUP_FRAME];
    if (!hcc_io(RESIDENT_LAUNCH_CHILD_FD, first, sizeof(first), false))
        return 3;
    unsigned sent = 0;
    while (sent < want && hcc_send(sent + 1, 7, 1))
        sent++;
    char line[64];
    int n = snprintf(line, sizeof(line), "hostcall flooded n=%u\n", sent);
    if (log_fd >= 0 && n > 0)
        (void)hcc_io(log_fd, line, (size_t)n, true);
    sleep(60);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3 || strcmp(argv[1], "--resident") != 0)
        return 2;
    int log_fd = hcc_fd_of("log");
    if (hcc_mode_is("flood"))
        return hcc_flood(log_fd, (unsigned)atoi((const char *)hcc_variant + HCC_MARKER_LEN + 6));
    if (hcc_mode_is("badframe"))
        return hcc_badframe(log_fd);
    struct timespec t0, t1;
    bool paced = hcc_mode_is("paced");
    (void)clock_gettime(CLOCK_MONOTONIC, &t0);
    uint8_t tip[64];
    size_t tip_len = 0, wallet_len = 0;
    unsigned tip_status = 0xffff, wallet_status = 0xffff;
    if (hcc_send(1, 1, 1))
        tip_status = hcc_await(argv[2], 1, tip, sizeof(tip), &tip_len);
    if (hcc_send(2, 7, 1))
        wallet_status = hcc_await(argv[2], 2, NULL, 0, &wallet_len);
    (void)clock_gettime(CLOCK_MONOTONIC, &t1);
    long span_ms = (long)(t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    uint32_t height = tip_status == 0 && tip_len >= 4 ? hcc_be32(tip) : 0;
    char line[96];
    int n = snprintf(line, sizeof(line), "hostcall tip=%u height=%u wallet=%u%s\n", tip_status,
                     height, wallet_status, paced ? (span_ms >= 950 ? " paced=1" : " paced=0") : "");
    if (log_fd >= 0 && n > 0)
        (void)hcc_io(log_fd, line, (size_t)n, true);
    return hcc_serve(argv[2]);
}
