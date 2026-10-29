/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "hosts.h"
#include "pairing.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    static const char snapshot[] = "{\"hosts\":["
        "{\"host\":\"r1\",\"reachable\":true,\"probe_ms\":1080,\"node\":\"blocked\",\"synced\":\"yes\","
        "\"blocker\":\"review_required_bootstrap_trust\",\"height\":3301130,\"reference_height\":3301130,"
        "\"load1\":9.1,\"disk_free_gb\":644},"
        "{\"host\":\"r2\",\"reachable\":true,\"probe_ms\":1346,\"node\":\"ok\",\"synced\":\"yes\","
        "\"blocker\":\"unknown\",\"height\":3301120,\"reference_height\":3301130,\"load1\":4.2,\"disk_free_gb\":null},"
        "{\"host\":\"mac\",\"reachable\":false,\"probe_ms\":25000,\"node\":\"unknown\",\"synced\":\"unknown\","
        "\"blocker\":\"unknown\",\"height\":null,\"reference_height\":null,\"load1\":-1,\"disk_free_gb\":null}"
        "],\"observed_at\":1793247494}";
    char out[4096];
    assert(zapp_hosts_format(snapshot, out, sizeof(out)));
    assert(!strncmp(out, "1 of 3 hosts in step\n", 21));
    assert(strstr(out, "\nr1 · in step · 3,301,130\n  Blocked: review required bootstrap trust · 644 GB free\n"));
    assert(strstr(out, "\nr2 · 10 blocks behind · 3,301,120\n\nmac"));
    assert(strstr(out, "\nmac · unreachable after 25.0 s\n"));
    assert(!strstr(out, "0 GB"));
    static const char small[] = "{\"hosts\":[{\"host\":\"t\",\"reachable\":true,\"height\":999,"
        "\"reference_height\":1000}]}";
    assert(zapp_hosts_format(small, out, sizeof(out)) && strstr(out, "\nt · 1 block behind · 999\n"));
    static const char large[] = "{\"hosts\":[{\"host\":\"t\",\"reachable\":true,\"height\":0,"
        "\"reference_height\":9223372036854775807}]}";
    assert(zapp_hosts_format(large, out, sizeof(out)) &&
           strstr(out, "\nt · 9,223,372,036,854,775,807 blocks behind · 0\n"));
    static const char odd[] = "{\"hosts\":[{\"host\":\"t\",\"reachable\":true,\"height\":-5,"
        "\"node\":\"STARTING_UP\",\"blocker\":\"none\",\"disk_free_gb\":7}]}";
    assert(zapp_hosts_format(odd, out, sizeof(out)) && strstr(out, "\nt · height unknown\n  Node starting up · 7 GB free\n"));
    assert(!zapp_hosts_format("{\"hosts\":[]}", out, sizeof(out)) && !out[0]);
    assert(!zapp_hosts_format("not json", out, sizeof(out)));
    assert(!zapp_hosts_format(snapshot, out, 40) && !out[0]);
    char a[7], b[7];
    assert(zapp_pair_code("{\"port\":8770,\"token\":\"00\"}\n", a));
    assert(zapp_pair_code("{\"port\":8770,\"token\":\"00\"}", b) && !strcmp(a, b));
    assert(strlen(a) == 6 && strspn(a, "0123456789abcdef") == 6);
    assert(zapp_pair_code("{\"port\":8771,\"token\":\"00\"}", b) && strcmp(a, b));
    assert(!zapp_pair_code("", a) && !zapp_pair_code(NULL, a));
    char line[96];
    assert(!strcmp(zapp_node_line(false, false, -1, -1, -1, line, sizeof(line)), "Node stopped"));
    assert(!strcmp(zapp_node_line(false, true, -1, -1, -1, line, sizeof(line)), "Node starting"));
    assert(!strcmp(zapp_node_line(true, true, -1, -1, 2, line, sizeof(line)), "Node running · 2 peers"));
    assert(!strcmp(zapp_node_line(true, true, 3301133, 0, 0, line, sizeof(line)),
                   "Node waiting for peers · 3,301,133"));
    assert(!strcmp(zapp_node_line(true, true, 3301133, 3301537, 1, line, sizeof(line)),
                   "Node catching up · 3,301,133 of 3,301,537"));
    assert(!strcmp(zapp_node_line(true, false, 3301553, 3301553, 1, line, sizeof(line)),
                   "Node in sync · 3,301,553 · 1 peer"));
    assert(!strcmp(zapp_node_line(true, true, 3301554, 3301553, -1, line, sizeof(line)),
                   "Node in sync · 3,301,554"));
    puts("hosts tests passed");
    return 0;
}
