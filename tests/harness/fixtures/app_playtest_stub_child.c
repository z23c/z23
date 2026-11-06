/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * v=1 agent-protocol STUB CHILD for test_app_playtest_session.c (built by
 * the Makefile into build/fixtures/, never linked into a product binary).
 * It stands in for the game image, so the playtest driver is proven
 * without raylib or a display.
 *
 * It speaks the wire of apps/skycombat/src/agent_resident.c: launched as
 * `<image> --resident <nonce> --agent --seed=N`, it sends READY on fd 3,
 * then answers each z23-res-run-v1 request with one reply frame carrying
 * {v,id,ok,frame,time,player,accepted_id}. A step advances the frame
 * counter by `frames`; a capture adds a fixed three-byte "png" ("abc").
 * STOP (81 bytes) or EOF ends it with exit 0.
 *
 * It refuses (exit 3, before READY) any environment entry outside the
 * display allowlist, so a driver that leaks its environment fails loudly.
 *
 * Build variants from this one source:
 *   (default)          the protocol as above
 *   APS_STUB_HANG      the first step forks a helper into the process group,
 *                      then both park forever (the timeout and group-reap
 *                      target)
 *   APS_STUB_HUGE      the first step answers with a 13 MiB reply frame
 * The header is the REAL struct resident_result_header, so the wire bytes
 * cannot drift from the parent side. */
#include "platform/resident_launch.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

#define APS_REQUEST_MAX 4096u
#define APS_HUGE_BYTES (13u * 1024u * 1024u)

static bool aps_io(void *buffer, size_t size, bool sending)
{
    unsigned char *bytes = buffer;
    for (size_t done = 0; done < size;) {
        ssize_t n = sending
            ? write(RESIDENT_LAUNCH_CHILD_FD, bytes + done, size - done)
            : read(RESIDENT_LAUNCH_CHILD_FD, bytes + done, size - done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        done += (size_t)n;
    }
    return true;
}

static bool aps_header(const char *nonce, uint32_t length)
{
    struct resident_result_header header;
    memset(&header, 0, sizeof(header));
    (void)snprintf(header.magic, sizeof(header.magic), "%s", "z23-res-run-v1");
    (void)snprintf(header.nonce, sizeof(header.nonce), "%s", nonce);
    header.payload_len = length;
    return aps_io(&header, sizeof(header), true);
}

static bool aps_send(const char *nonce, const char *payload, size_t length)
{
    return aps_header(nonce, (uint32_t)length) && aps_io((void *)payload, length, true);
}

static bool aps_env_allowed(void)
{
    static const char *const names[] = {"DISPLAY", "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR", "XAUTHORITY", "XDG_SESSION_TYPE"};
    for (char **entry = environ; entry && *entry; entry++) {
        bool known = false;
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
            size_t n = strlen(names[i]);
            if (strncmp(*entry, names[i], n) == 0 && (*entry)[n] == '=')
                known = true;
        }
        if (!known)
            return false;
    }
    return true;
}

static bool aps_args(int argc, char **argv)
{
    return argc == 5 && strcmp(argv[1], "--resident") == 0 &&
           strlen(argv[2]) == RESIDENT_LAUNCH_NONCE_HEX &&
           strcmp(argv[3], "--agent") == 0 &&
           strncmp(argv[4], "--seed=", 7) == 0;
}

/* 1 = a request in payload, 0 = STOP or EOF, -1 = malformed. */
static int aps_read(const char *nonce, char payload[APS_REQUEST_MAX + 1])
{
    struct resident_result_header header;
    memset(&header, 0, sizeof(header));
    const size_t prefix = sizeof(header.magic) + sizeof(header.nonce);
    ssize_t first = read(RESIDENT_LAUNCH_CHILD_FD, &header, 1);
    if (first == 0)
        return 0;
    if (first != 1 || !aps_io((char *)&header + 1, prefix - 1, false) ||
        memcmp(header.nonce, nonce, sizeof(header.nonce)) != 0)
        return -1;
    if (memcmp(header.magic, "z23-res-stop-v1", sizeof("z23-res-stop-v1")) == 0)
        return 0;
    if (memcmp(header.magic, "z23-res-run-v1", sizeof("z23-res-run-v1")) != 0 ||
        !aps_io((char *)&header + prefix, sizeof(header) - prefix, false) ||
        header.payload_len == 0 || header.payload_len > APS_REQUEST_MAX ||
        !aps_io(payload, header.payload_len, false))
        return -1;
    payload[header.payload_len] = '\0';
    return 1;
}

static unsigned long aps_number(const char *payload, const char *key)
{
    const char *at = strstr(payload, key);
    return at ? strtoul(at + strlen(key), NULL, 10) : 0;
}

#if defined(APS_STUB_HANG)
static void aps_misbehave(const char *nonce)
{
    (void)nonce;
    (void)fork(); /* a helper in the same process group */
    for (;;)
        pause();
}
#elif defined(APS_STUB_HUGE)
static void aps_misbehave(const char *nonce)
{
    static char filler[65536];
    memset(filler, ' ', sizeof(filler));
    if (!aps_header(nonce, APS_HUGE_BYTES))
        exit(5);
    for (size_t sent = 0; sent < APS_HUGE_BYTES; sent += sizeof(filler))
        if (!aps_io(filler, sizeof(filler), true))
            exit(5);
    for (;;)
        pause();
}
#endif

static bool aps_reply(const char *nonce, const char *request, unsigned *frame)
{
    unsigned long id = aps_number(request, "\"id\":");
    bool step = strstr(request, "\"op\":\"step\"") != NULL;
#if defined(APS_STUB_HANG) || defined(APS_STUB_HUGE)
    if (step)
        aps_misbehave(nonce);
#endif
    if (step)
        *frame += (unsigned)aps_number(request, "\"frames\":");
    bool capture = strstr(request, "\"capture\":true") != NULL;
    char reply[1024];
    int n = snprintf(reply, sizeof(reply),
        "{\"v\":1,\"id\":%lu,\"ok\":true,\"frame\":%u,\"time\":%.17g,"
        "\"player\":{\"x\":1.5,\"y\":%u,\"z\":-2,\"yaw\":0.25,\"speed\":3,"
        "\"health\":100},\"accepted_id\":%lu%s}\n",
        id, *frame, (double)*frame / 60.0, *frame, id,
        capture ? ",\"png\":{\"width\":1,\"height\":1,\"bytes\":3,"
                  "\"base64\":\"YWJj\"}" : "");
    return n > 0 && (size_t)n < sizeof(reply) && aps_send(nonce, reply, (size_t)n);
}

int main(int argc, char **argv)
{
    if (!aps_args(argc, argv))
        return 2;
    if (!aps_env_allowed())
        return 3;
    const char *nonce = argv[2];
    if (!aps_send(nonce, "READY", 5))
        return 4;
    unsigned frame = 0;
    char request[APS_REQUEST_MAX + 1];
    for (;;) {
        int got = aps_read(nonce, request);
        if (got == 0)
            return 0;
        if (got < 0 || !aps_reply(nonce, request, &frame))
            return 6;
    }
}
