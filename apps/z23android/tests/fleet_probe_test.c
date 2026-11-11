/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "fleet_probe.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

bool zapp_relay_stopping(void) { return false; }
static void check_parse(void)
{
    struct zapp_fleet_host hosts[4]; size_t n = 0;
    assert(zapp_fleet_hosts_parse("r1=node1.example,mac=user@node2.example", hosts, 4, &n) && n == 2);
    assert(!strcmp(hosts[0].label, "r1") && !strcmp(hosts[0].destination, "node1.example"));
    assert(!strcmp(hosts[1].label, "mac") && !strcmp(hosts[1].destination, "user@node2.example"));
    assert(!zapp_fleet_hosts_parse("R1=node1.example", hosts, 4, &n));
    assert(!zapp_fleet_hosts_parse("r1=-oProxyCommand=x", hosts, 4, &n));
    assert(!zapp_fleet_hosts_parse("r1=host;rm", hosts, 4, &n));
    assert(!zapp_fleet_hosts_parse("r1", hosts, 4, &n));
    assert(!zapp_fleet_hosts_parse("", hosts, 4, &n));
}
static void check_row(void)
{
    static const char output[] =
        "status=node=blocked synced=yes wallet=not_ready blocker=review_required_bootstrap_trust next_action=z23\n"
        "height=3301130\nreference=3301130\n"
        "uptime= 04:19:54 up 50 days,  8:15, 16 users,  load average: 88.58, 55.03, 44.75\n"
        "disk_kb=675559540\n";
    struct json_value row = {0};
    char text[1024];
    assert(zapp_fleet_row("r1", output, 1080, &row) && json_write(&row, text, sizeof(text)) < sizeof(text));
    assert(strstr(text, "\"reachable\":true") && strstr(text, "\"node\":\"blocked\"") && strstr(text, "\"synced\":\"yes\""));
    assert(strstr(text, "\"blocker\":\"review_required_bootstrap_trust\"") && strstr(text, "\"height\":3301130"));
    assert(strstr(text, "\"reference_height\":3301130") && strstr(text, "\"disk_free_gb\":644") && strstr(text, "\"load1\":88.5"));
    json_free(&row);
    assert(zapp_fleet_row("mac", "status=\nheight=\nreference=\nuptime=21:20 up, load averages: 4.25 3.58\ndisk_kb=x\n", 14320, &row));
    assert(json_write(&row, text, sizeof(text)) < sizeof(text));
    assert(strstr(text, "\"height\":null") && strstr(text, "\"disk_free_gb\":null") && strstr(text, "\"node\":\"unknown\""));
    json_free(&row);
    assert(zapp_fleet_row("r2", NULL, 25000, &row) && json_write(&row, text, sizeof(text)) < sizeof(text));
    assert(strstr(text, "\"reachable\":false") && strstr(text, "\"load1\":-1"));
    json_free(&row);
}
static const char onion_address[] = "kfs4ogq3dtwseahgzz2grizug2wiwey2jhxmmnjeuqh64rs7fkl666qd";
/* Row JSON for a probe whose onion status reply has the given readiness, address, route and port. */
static void onion_row(bool ok, bool service, bool publish, const char *address, const char *route,
                      bool installed, int port, char *text, size_t cap)
{
    char output[2048];
    snprintf(output, sizeof(output), "status=node=ready synced=yes\nheight=5\nreference=5\nonion={\"ok\":%s,"
        "\"data\":{\"onion_service_ready\":%s,\"p2p_publish_ready\":%s,\"onion_address\":\"%s\",\"port_mapping\":"
        "{\"routes\":[{\"name\":\"application_dynhost\",\"virtual_port\":80,\"installed\":true},"
        "{\"name\":\"%s\",\"virtual_port\":%d,\"installed\":%s}]}}}\ndisk_kb=1\n",
        ok ? "true" : "false", service ? "true" : "false", publish ? "true" : "false", address, route, port,
        installed ? "true" : "false");
    struct json_value row = {0};
    assert(zapp_fleet_row("r1", output, 5, &row) && json_write(&row, text, cap) < cap);
    json_free(&row);
}
static void check_onion(void)
{
    char text[1024], want[160];
    snprintf(want, sizeof(want), "\"onion\":\"%s.onion:8033\"", onion_address);
    char address[80];
    snprintf(address, sizeof(address), "%s.onion", onion_address);
    onion_row(true, true, true, address, "p2p_tcp", true, 8033, text, sizeof(text));
    assert(strstr(text, want));
    onion_row(true, true, true, address, "p2p_tcp", true, 18033, text, sizeof(text));
    assert(strstr(text, ".onion:18033\""));
    onion_row(false, true, true, address, "p2p_tcp", true, 8033, text, sizeof(text)); assert(!strstr(text, "onion\""));
    onion_row(true, false, true, address, "p2p_tcp", true, 8033, text, sizeof(text)); assert(!strstr(text, "onion\""));
    onion_row(true, true, false, address, "p2p_tcp", true, 8033, text, sizeof(text)); assert(!strstr(text, "onion\""));
    onion_row(true, true, true, address, "p2p_tcp", false, 8033, text, sizeof(text)); assert(!strstr(text, "onion\""));
    onion_row(true, true, true, address, "other", true, 8033, text, sizeof(text)); assert(!strstr(text, "onion\""));
    onion_row(true, true, true, address, "p2p_tcp", true, 0, text, sizeof(text)); assert(!strstr(text, "onion\""));
    onion_row(true, true, true, address, "p2p_tcp", true, 65536, text, sizeof(text)); assert(!strstr(text, "onion\""));
    onion_row(true, true, true, "short.onion", "p2p_tcp", true, 8033, text, sizeof(text)); assert(!strstr(text, "onion\""));
    snprintf(address, sizeof(address), "%.55sA.onion", onion_address);
    onion_row(true, true, true, address, "p2p_tcp", true, 8033, text, sizeof(text)); assert(!strstr(text, "onion\""));
    snprintf(address, sizeof(address), "%s.onion:8033\"}", onion_address);
    onion_row(true, true, true, address, "p2p_tcp", true, 8033, text, sizeof(text)); assert(!strstr(text, "onion\""));
    struct json_value row = {0};
    assert(zapp_fleet_row("r1", "status=node=ready\nonion=\ndisk_kb=1\n", 5, &row) && json_write(&row, text, sizeof(text)) < sizeof(text));
    assert(!strstr(text, "onion\""));
    json_free(&row);
}
/* The probe's three onion status replies as the paged default view returns them: page 1 without
 * port_mapping, the cursor-12 page that skips recent_dials, and the cursor-13 page with port_mapping. */
static void onion_pages_row(const char *page1, const char *page3, char *text, size_t cap)
{
    static const char page2[] = "{\"ok\":true,\"data\":{\"_page\":{\"view\":\"normal\",\"total_fields\":15,"
        "\"included\":0,\"truncated\":true,\"next_cursor\":13,\"skipped_oversize\":\"recent_dials\"}},\"next\":[]}";
    char output[8192];
    snprintf(output, sizeof(output), "status=node=ready synced=yes\nheight=5\nreference=5\nonion=%s\n"
        "onion_2=%s\nonion_3=%s\ndisk_kb=1\n", page1, page2, page3);
    struct json_value row = {0};
    assert(zapp_fleet_row("r1", output, 5, &row) && json_write(&row, text, cap) < cap);
    json_free(&row);
}
static void check_onion_pages(void)
{
    char page1[1024], page3[1024], text[1024];
    char address[80];
    snprintf(address, sizeof(address), "%s.onion", onion_address);
    /* The real first page: readiness and address, no port_mapping, so no onion field. */
    snprintf(page1, sizeof(page1), "{\"ok\":true,\"data\":{\"schema\":\"zcl.onion_status.v1\",\"bootstrap_state\":\"ready\","
        "\"onion_service_ready\":true,\"onion_address\":\"%s\",\"p2p_publish_ready\":true,\"setup_state\":\"ready\","
        "\"_page\":{\"view\":\"normal\",\"total_fields\":15,\"included\":12,\"truncated\":true,\"next_cursor\":12,"
        "\"skipped_oversize\":\"recent_dials\"}},\"next\":[]}", address);
    snprintf(page3, sizeof(page3), "{\"ok\":true,\"data\":{\"port_mapping\":{\"state\":\"installed\",\"complete\":true,"
        "\"routes\":[{\"name\":\"application_dynhost\",\"virtual_port\":80,\"installed\":true},{\"name\":\"p2p_tcp\","
        "\"virtual_port\":8033,\"target_host\":\"127.0.0.1\",\"target_port\":8033,\"installed\":true}]},\"_page\":"
        "{\"view\":\"normal\",\"total_fields\":15,\"included\":2,\"truncated\":false}},\"next\":[]}");
    onion_pages_row(page1, "", text, sizeof(text)); assert(!strstr(text, "onion\""));
    char want[160];
    snprintf(want, sizeof(want), "\"onion\":\"%s:8033\"", address);
    onion_pages_row(page1, page3, text, sizeof(text)); assert(strstr(text, want));
    /* The probe asks for the cursor chain that reaches port_mapping and never for recent_dials. */
    assert(strstr(zapp_fleet_probe_command, "onion status --cursor=$c") && strstr(zapp_fleet_probe_command, "next_cursor"));
    assert(!strstr(zapp_fleet_probe_command, "recent_dials"));
}
static void check_blockers(void)
{
    char report[4096], want[2048], out[2048];
    size_t used = (size_t)snprintf(report, sizeof(report), "{\"ok\":true,\"data\":{\"blockers\":[");
    size_t wanted = (size_t)snprintf(want, sizeof(want), "{\"host\":\"r2\",\"active\":7,\"blockers\":[");
    for (int i = 0; i < 7; i++) {
        used += (size_t)snprintf(report + used, sizeof(report) - used, "%s{\"id\":\"b%d\",\"owner\":\"o\","
            "\"class\":\"dependency\",\"age_us\":5,\"reason\":\"reason %d\"}", i ? "," : "", i, i);
        if (i < 6) wanted += (size_t)snprintf(want + wanted, sizeof(want) - wanted,
            "%s{\"id\":\"b%d\",\"class\":\"dependency\",\"reason\":\"reason %d\"}", i ? "," : "", i, i);
    }
    snprintf(report + used, sizeof(report) - used, "],\"active_count\":7}}");
    snprintf(want + wanted, sizeof(want) - wanted, "]}");
    assert(zapp_fleet_blockers_summary("r2", report, out, sizeof(out)) && !strcmp(out, want));
    assert(!zapp_fleet_blockers_summary("r2", report, out, strlen(want)));
    static const char failed[] = "{\"ok\":false,\"error\":{\"message\":\"node did not answer\",\"blockers\":[]}}";
    assert(zapp_fleet_blockers_summary("mac", failed, out, sizeof(out)));
    assert(!strcmp(out, "{\"host\":\"mac\",\"error\":\"node did not answer\"}"));
    assert(zapp_fleet_blockers_summary("r1", NULL, out, sizeof(out)));
    assert(!strcmp(out, "{\"host\":\"r1\",\"error\":\"The host did not answer.\"}"));
    assert(zapp_fleet_blockers_summary("r1", "{\"ok\":tr", out, sizeof(out)) && strstr(out, "could not be read"));
    assert(zapp_fleet_blockers_summary("r1", "{\"ok\":\"\xff\"}", out, sizeof(out)) && strstr(out, "could not be read"));
    assert(zapp_fleet_blockers_summary("r1", "{\"ok\":true,\"data\":{}}", out, sizeof(out)) && strstr(out, "no blocker list"));
    static const char sparse[] = "{\"ok\":true,\"data\":{\"blockers\":[{\"reason\":\"x\"},{\"id\":\"b\"}],\"active_count\":2}}";
    assert(zapp_fleet_blockers_summary("r1", sparse, out, sizeof(out)));
    assert(!strcmp(out, "{\"host\":\"r1\",\"active\":2,\"blockers\":[{\"id\":\"b\",\"class\":\"unknown\",\"reason\":\"\"}]}"));
}
static void check_tool(void)
{
    struct zapp_fleet_host hosts[2]; size_t n = 0;
    struct json_value schema = {0};
    char text[2048];
    assert(zapp_fleet_hosts_parse("r1=node1.example,mac=user@node2.example", hosts, 2, &n) && n == 2);
    assert(zapp_fleet_tool_schema(hosts, n, &schema) && json_write(&schema, text, sizeof(text)) < sizeof(text));
    assert(json_size(&schema) == 1 && strstr(text, "\"name\":\"host_blockers\"") && strstr(text, "\"enum\":[\"r1\",\"mac\"]"));
    json_free(&schema);
    assert(!zapp_fleet_tool_schema(hosts, 0, &schema));
    json_free(&schema);
    assert(zapp_fleet_tool_host(hosts, n, "host_blockers", "{\"host\":\"mac\"}") == &hosts[1]);
    assert(zapp_fleet_tool_host(hosts, n, "host_blockers", "{\"host\":\"R1\"}") == &hosts[0]);
    assert(!zapp_fleet_tool_host(hosts, n, "host_blockers", "{\"host\":\"r3\"}"));
    assert(!zapp_fleet_tool_host(hosts, n, "restart", "{\"host\":\"r1\"}"));
    assert(!zapp_fleet_tool_host(hosts, n, "host_blockers", "{\"host\":"));
    assert(!zapp_fleet_tool_host(hosts, n, "host_blockers", "{\"host\":1}"));
    assert(!zapp_fleet_tool_host(hosts, n, "host_blockers", NULL));
}
static void check_wanted(void)
{
    struct zapp_fleet_host hosts[3]; size_t n = 0;
    char name[32], args[64];
    assert(zapp_fleet_hosts_parse("r1=node1.example,r2=node2.example,mac=user@node3.example", hosts, 3, &n));
    const char *wanted[][2] = {{"Question: What are the blockers on R One?", "r1"}, {"Question: why is r 2 blocked", "r2"},
        {"Question: What's wrong with the Mac?", "mac"}, {"Question: Is r1 stuck?", "r1"},
        {"Question: any issues on R2 or r1", "r1"}, {"what blocks... Question: what is wrong on r2", "r2"},
        {"Question: Why is the Mac's height unknown?", "mac"}};
    for (size_t i = 0; i < sizeof(wanted) / sizeof(wanted[0]); i++) {
        char want[64];
        snprintf(want, sizeof(want), "{\"host\":\"%s\"}", wanted[i][1]);
        assert(zapp_fleet_tool_wanted(hosts, n, wanted[i][0], name, sizeof(name), args, sizeof(args)));
        assert(!strcmp(name, "host_blockers") && !strcmp(args, want));
    }
    const char *not_wanted[] = {"Question: What block height is r1 at?", "Question: Is there a problem with my wallet?",
        "Question: Is the machine stuck?", "Question: is r12 blocked?", "Node blocked on r1.\n\nQuestion: How is r1?",
        "How is the fleet?", "Question: Why is my balance unknown?", "", NULL};
    for (size_t i = 0; i < sizeof(not_wanted) / sizeof(not_wanted[0]); i++)
        assert(!zapp_fleet_tool_wanted(hosts, n, not_wanted[i], name, sizeof(name), args, sizeof(args)));
    assert(!zapp_fleet_tool_wanted(hosts, 0, wanted[0][0], name, sizeof(name), args, sizeof(args)));
    assert(!zapp_fleet_tool_wanted(hosts, n, wanted[0][0], name, sizeof(name), args, 13));
}
static void check_runner(void)
{
    char directory[] = "/tmp/z23-fleet-runner.XXXXXX", script[256], original[4096];
    assert(mkdtemp(directory));
    const char *environment = getenv("PATH");
    snprintf(original, sizeof(original), "%s", environment ? environment : "/usr/bin:/bin");
    snprintf(script, sizeof(script), "%s/ssh", directory);
    assert(setenv("PATH", directory, 1) == 0);
    FILE *file = fopen(script, "w");
    assert(file);
    assert(fputs("#!/bin/sh\nprintf '{\"ok\":true}'\n", file) >= 0);
    assert(fclose(file) == 0);
    assert(chmod(script, 0700) == 0);
    const struct zapp_fleet_host host = {"r1", "fixture"};
    char output[256];
    assert(zapp_fleet_run(&host, "ignored", 1000, output, sizeof(output)) && !strcmp(output, "{\"ok\":true}"));
    file = fopen(script, "w");
    assert(file);
    assert(fputs("#!/bin/sh\nprintf '{\"ok\":true}\\0ignored'\n", file) >= 0);
    assert(fclose(file) == 0);
    assert(!zapp_fleet_run(&host, "ignored", 1000, output, sizeof(output)));
    assert(setenv("PATH", original, 1) == 0);
    assert(unlink(script) == 0);
    assert(rmdir(directory) == 0);
}
int main(void)
{
    check_parse();
    check_row();
    check_onion();
    check_onion_pages();
    check_blockers();
    check_tool();
    check_wanted();
    check_runner();
    puts("fleet probe tests passed");
    return 0;
}
