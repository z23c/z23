/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: lab-peer-fake, the fake z23 / z23-dev program tests/harness/src/
 * test_lab_peer.c runs z23-lab-peer against. The test makes two symlinks to
 * this binary (fake-z23, fake-z23dev) in a scratch directory; the program finds
 * its files beside the name it was started under:
 *
 *   calls.log          every call: "CALL <name>" then one "\t<arg>" per argument
 *   resp/resp.<key>    the canned reply printed on stdout. key is argv[1].argv[2].
 *                      argv[3], plus .argv[4] for `fleet board post`; a
 *                      `--cursor=N` argument adds .cursorN. resp/<file>.<n>
 *                      (n = the call count for that file, from 1) wins when it
 *                      exists, so one key can answer differently per call.
 *   resp/<file>.rc     the exit status (default 0)
 *
 * With a reply containing "ok":true and exit 0, the leaf's one side effect is
 * done: --bundle_out= writes the bundle and copies resp/offer.json beside it,
 * --out= writes a bundle, --receipt_out= copies resp/receipt.json. No shell, no
 * network, no real build: a test fixture only.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { FP_DIR = 1024, FP_PATH = 4096, FP_LONG = 4224, FP_RC = 4352, FP_BODY = 1 << 16 };

static bool fp_read(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    const size_t n = fread(buf, 1, cap - 1, f);
    (void)fclose(f);
    buf[n] = '\0';
    return true;
}

static bool fp_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    const size_t n = strlen(text);
    const bool ok = fwrite(text, 1, n, f) == n;
    return fclose(f) == 0 && ok;
}

static void fp_log(const char *dir, int argc, char **argv)
{
    char path[FP_PATH];
    (void)snprintf(path, sizeof(path), "%s/calls.log", dir);
    FILE *f = fopen(path, "ab");
    if (!f)
        return;
    const char *name = strrchr(argv[0], '/');
    (void)fprintf(f, "CALL %s\n", name ? name + 1 : argv[0]);
    for (int i = 1; i < argc; i++)
        (void)fprintf(f, "\t%s\n", argv[i]);
    (void)fclose(f);
}

/* resp/resp.<key>[.cursorN] */
static void fp_base(const char *dir, int argc, char **argv, char *out, size_t cap)
{
    char key[FP_DIR];
    (void)snprintf(key, sizeof(key), "%s.%s.%s", argc > 1 ? argv[1] : "",
                   argc > 2 ? argv[2] : "", argc > 3 ? argv[3] : "");
    if (strcmp(key, "fleet.board.post") == 0 && argc > 4)
        (void)snprintf(key + strlen(key), sizeof(key) - strlen(key), ".%s", argv[4]);
    for (int i = 1; i < argc; i++)
        if (strncmp(argv[i], "--cursor=", 9) == 0)
            (void)snprintf(key + strlen(key), sizeof(key) - strlen(key),
                           ".cursor%s", argv[i] + 9);
    (void)snprintf(out, cap, "%s/resp/resp.%s", dir, key);
}

/* The call number of this base file, counted in resp/count.<n> files. */
static int fp_count(const char *base)
{
    char path[FP_LONG], buf[32] = "0";
    (void)snprintf(path, sizeof(path), "%s.count", base);
    (void)fp_read(path, buf, sizeof(buf));
    const int n = atoi(buf) + 1;
    (void)snprintf(buf, sizeof(buf), "%d", n);
    (void)fp_write(path, buf);
    return n;
}

static void fp_effects(const char *dir, int argc, char **argv)
{
    static char body[FP_BODY];
    char src[FP_PATH], dst[FP_LONG];
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--bundle_out=", 13) == 0) {
            (void)fp_write(argv[i] + 13, "bundle\n");
            (void)snprintf(src, sizeof(src), "%s/resp/offer.json", dir);
            (void)snprintf(dst, sizeof(dst), "%s.offer.json", argv[i] + 13);
            if (fp_read(src, body, sizeof(body)))
                (void)fp_write(dst, body);
        } else if (strncmp(argv[i], "--out=", 6) == 0) {
            (void)fp_write(argv[i] + 6, "bundle\n");
        } else if (strncmp(argv[i], "--receipt_out=", 14) == 0) {
            (void)snprintf(src, sizeof(src), "%s/resp/receipt.json", dir);
            if (fp_read(src, body, sizeof(body)))
                (void)fp_write(argv[i] + 14, body);
        }
    }
}

int main(int argc, char **argv)
{
    static char body[FP_BODY];
    char dir[FP_DIR], base[FP_PATH], numbered[FP_LONG], rcfile[FP_RC];
    char rcbuf[16] = "0";
    const char *slash = strrchr(argv[0], '/');
    if (!slash || (size_t)(slash - argv[0]) >= sizeof(dir))
        return 3;
    (void)snprintf(dir, sizeof(dir), "%.*s", (int)(slash - argv[0]), argv[0]);
    fp_log(dir, argc, argv);
    fp_base(dir, argc, argv, base, sizeof(base));
    (void)snprintf(numbered, sizeof(numbered), "%s.%d", base, fp_count(base));
    if (fp_read(numbered, body, sizeof(body)))
        (void)snprintf(rcfile, sizeof(rcfile), "%s.rc", numbered);
    else if (fp_read(base, body, sizeof(body)))
        (void)snprintf(rcfile, sizeof(rcfile), "%s.rc", base);
    else {
        (void)puts("{\"ok\":false,\"error\":{\"code\":\"FAKE_NO_RESP\"}}");
        return 1;
    }
    (void)fp_read(rcfile, rcbuf, sizeof(rcbuf));
    (void)fputs(body, stdout);
    if (atoi(rcbuf) == 0 && strstr(body, "\"ok\":true"))
        fp_effects(dir, argc, argv);
    return atoi(rcbuf);
}
