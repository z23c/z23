/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "fleet_probe.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

bool zapp_relay_stopping(void) { return false; }
static void check_parse(void)
{
    struct zapp_fleet_host hosts[4]; size_t n = 0;
    assert(zapp_fleet_hosts_parse("r1=rhett.dev,mac=user@rentamac", hosts, 4, &n) && n == 2);
    assert(!strcmp(hosts[0].label, "r1") && !strcmp(hosts[0].destination, "rhett.dev"));
    assert(!strcmp(hosts[1].label, "mac") && !strcmp(hosts[1].destination, "user@rentamac"));
    assert(!zapp_fleet_hosts_parse("R1=rhett.dev", hosts, 4, &n));
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
int main(void)
{
    check_parse();
    check_row();
    puts("fleet probe tests passed");
    return 0;
}
