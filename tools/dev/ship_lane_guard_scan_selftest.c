/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Validate isolated ship subjects and their fixture evidence. */
#define main ship_lane_guard_production_main
#include "ship_lane_guard_main.c"
#undef main

int main(int argc, char **argv)
{
    if (argc == 4) return guard_run(argv[1], 3, argv + 1);
    if (argc != 1) return 2;
    char root[] = "/tmp/z23-ship-proc-XXXXXX", dir[256], path[256];
    if (!mkdtemp(root) || snprintf(dir, sizeof dir, "%s/999999999", root) < 0 ||
        snprintf(path, sizeof path, "%s/999999999/cmdline", root) < 0 || mkdir(dir, 0700))
        return 1;
    struct ship_lane_subject selected = {.pid = 99}, others[4] = {0};
    FILE *fp = fopen(path, "wb");
    if (!fp) return 1;
    static const char args[] = "/other/renamed-node\0-datadir=/fixture/shared\0-port=8053\0";
    if (fwrite(args, 1, sizeof args, fp) != sizeof args || fclose(fp)) return 1;
    const uint64_t clients[3] = {0, 0, 0};
    int fail = no_unknown_node(root, &selected, others, 4, clients);
    others[0].active = true;
    others[0].pid = 999999999;
    if (!no_unknown_node(root, &selected, others, 4, clients)) fail++;
    if (unlink(path) || rmdir(dir) || rmdir(root)) fail++;
    if (!fail) puts("ship lane unknown-process scan: PASS");
    return fail != 0;
}
