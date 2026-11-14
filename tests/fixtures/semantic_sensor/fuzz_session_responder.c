/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Exercise failure handling of the test-only semantic session client. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
static void fs_tree(void)
{
    pid_t child = fork();
    if (child < 0) _exit(2);
    if (!child) for (;;) pause();
    pid_t ids[2] = {getpid(), child};
    if (write(STDOUT_FILENO, ids, sizeof(ids)) != (ssize_t)sizeof(ids)) _exit(2);
    for (;;) pause();
}
static bool fs_copy(void)
{
    FILE *in = fopen("valid.zsm", "rb"), *out = fopen("out.zsm", "wb");
    if (!in || !out) { if (in) fclose(in); if (out) fclose(out); return false; }
    char buf[4096]; size_t n; bool ok = true;
    while ((n = fread(buf, 1, sizeof(buf), in)) != 0)
        if (fwrite(buf, 1, n, out) != n) { ok = false; break; }
    if (ferror(in)) ok = false;
    if (fclose(in)) ok = false;
    if (fclose(out)) ok = false;
    return ok;
}
static int fs_valid(bool extra)
{
    char reply[4096]; FILE *f = fopen("reply", "rb");
    if (!f || !fgets(reply, sizeof(reply), f)) { if (f) fclose(f); return 2; }
    if (fclose(f) || !fs_copy()) return 2;
    size_t n = strlen(reply);
    if (extra) { if (n + 3 >= sizeof(reply)) return 2; memcpy(reply + n, "{}\n", 3); n += 3; }
    if (write(STDOUT_FILENO, reply, n) != (ssize_t)n) return 2;
    for (;;) pause();
}
int main(void)
{
    FILE *mode_file = fopen("mode", "r"); char mode[32], request[4096];
    if (!mode_file || !fgets(mode, sizeof(mode), mode_file)) return 2;
    if (fclose(mode_file)) return 2;
    mode[strcspn(mode, "\r\n")] = '\0';
    if (!strcmp(mode, "exit")) return 0;
    if (!fgets(request, sizeof(request), stdin)) return 2;
    if (!strcmp(mode, "valid")) return fs_valid(false);
    if (!strcmp(mode, "valid-extra")) return fs_valid(true);
    if (!strcmp(mode, "tree")) fs_tree();
    if (!strcmp(mode, "hang")) for (;;) pause();
    if (!strcmp(mode, "partial")) { fputs("{", stdout); fflush(stdout); return 0; }
    if (!strcmp(mode, "extra")) { fputs("{}\n{}\n", stdout); fflush(stdout); return 0; }
    if (!strcmp(mode, "refuse")) { fputs("{\"seq\":1,\"ok\":false}\n", stdout); fflush(stdout); return 0; }
    return 2;
}
