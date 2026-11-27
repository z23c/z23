/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Validate isolated ship subjects and their fixture evidence. */
#include "ship_lane_guard.c"

int main(void)
{
    const char *dir = "/fixture/.zclassic-c23-devfleet";
    char receiver[] = "z23-dev\0dev\0agent\0receive\0run\0--receiver=r2-devfleet\0"
        "--workspace=/fixture\0--wait_ms=20\0--deadline_s=30\0"
        "-datadir=/fixture/.zclassic-c23-devfleet\0-rpcport=18260\0";
    char worker[] = "z23-dev\0dev\0agent\0worker\0run\0--worker=p0-r2\0"
        "--deadline_s=30\0--idle_limit_s=20\0--max_jobs=1\0--time_cap_s=10\0"
        "--cpu_s=10\0--mem_mb=128\0--token_cap=50\0"
        "-datadir=/fixture/.zclassic-c23-devfleet\0-rpcport=18260\0";
    char impostor[] = "z23-dev\0dev\0agent\0worker\0run\0--worker=other\0"
        "--deadline_s=30\0--idle_limit_s=20\0--max_jobs=1\0--time_cap_s=10\0"
        "--cpu_s=10\0--mem_mb=128\0--token_cap=50\0"
        "-datadir=/fixture/.zclassic-c23-devfleet\0-rpcport=18260\0";
    int fail = !client_argv(receiver, sizeof receiver - 1, dir, false) ||
               !client_argv(worker, sizeof worker - 1, dir, true) ||
               client_argv(impostor, sizeof impostor - 1, dir, true) ||
               client_argv(receiver, sizeof receiver - 1, "/other", false) ||
               client_argv(receiver, sizeof receiver - 2, dir, false);
    if (!fail) puts("ship lane client roles: PASS");
    return fail;
}
