/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "fleet_probe.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

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
        {"Question: any issues on R2 or r1", "r1"}, {"what blocks... Question: what is wrong on r2", "r2"}};
    for (size_t i = 0; i < sizeof(wanted) / sizeof(wanted[0]); i++) {
        char want[64];
        snprintf(want, sizeof(want), "{\"host\":\"%s\"}", wanted[i][1]);
        assert(zapp_fleet_tool_wanted(hosts, n, wanted[i][0], name, sizeof(name), args, sizeof(args)));
        assert(!strcmp(name, "host_blockers") && !strcmp(args, want));
    }
    const char *not_wanted[] = {"Question: What block height is r1 at?", "Question: Is there a problem with my wallet?",
        "Question: Is the machine stuck?", "Question: is r12 blocked?", "Node blocked on r1.\n\nQuestion: How is r1?",
        "How is the fleet?", "", NULL};
    for (size_t i = 0; i < sizeof(not_wanted) / sizeof(not_wanted[0]); i++)
        assert(!zapp_fleet_tool_wanted(hosts, n, not_wanted[i], name, sizeof(name), args, sizeof(args)));
    assert(!zapp_fleet_tool_wanted(hosts, 0, wanted[0][0], name, sizeof(name), args, sizeof(args)));
    assert(!zapp_fleet_tool_wanted(hosts, n, wanted[0][0], name, sizeof(name), args, 13));
}
int main(void)
{
    check_parse();
    check_row();
    check_blockers();
    check_tool();
    check_wanted();
    puts("fleet probe tests passed");
    return 0;
}
