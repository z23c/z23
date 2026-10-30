/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "hosts.h"
#include "pairing.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* A busy node may answer its status without the synced field; only "no" holds a host apart. A host
 * that answers the probe while its node gives no height says that its node is not answering. */
static void sync_rule_tests(void)
{
    static const char unsure[] = "{\"hosts\":["
        "{\"host\":\"a\",\"reachable\":true,\"synced\":\"unknown\",\"blocker\":\"STATUS_SOURCE_UNAVAILABLE\","
        "\"height\":3301698,\"reference_height\":3301698,\"disk_free_gb\":50},"
        "{\"host\":\"b\",\"reachable\":true,\"height\":3301697,\"reference_height\":3301698},"
        "{\"host\":\"c\",\"reachable\":true,\"synced\":\"no\",\"height\":3301698,\"reference_height\":3301698,"
        "\"disk_free_gb\":49}]}";
    char out[1024];
    assert(zapp_hosts_format(unsure, out, sizeof(out)) && !strncmp(out, "2 of 3 hosts in sync\n", 21));
    assert(strstr(out, "\na · in sync · 3,301,698\n\nb · in sync · 3,301,697\n\n"));
    assert(strstr(out, "\nc · not synced · 3,301,698\n  Low on disk · 49 GB free\n"));
    assert(!strstr(out, "STATUS") && !strstr(out, "50 GB"));
    static const char silent[] = "{\"hosts\":[{\"host\":\"m\",\"reachable\":true,\"height\":null,"
        "\"reference_height\":3301698,\"disk_free_gb\":23}]}";
    assert(zapp_hosts_format(silent, out, sizeof(out)));
    assert(strstr(out, "\nm · node not answering\n  Low on disk · 23 GB free\n"));
}
/* The 2026-10-29 fleet: r2 in sync with its zclassicd, r1 synced by its own report but with no zclassicd
 * height, the Mac's node unavailable after 13.6 s. One host counts, and every other row says why not. */
static void unverified_host_tests(void)
{
    static const char fleet[] = "{\"hosts\":["
        "{\"host\":\"r1\",\"reachable\":true,\"probe_ms\":900,\"node\":\"blocked\",\"synced\":\"yes\","
        "\"blocker\":\"review_required_bootstrap_trust\",\"height\":3302089,\"reference_height\":null},"
        "{\"host\":\"r2\",\"reachable\":true,\"probe_ms\":950,\"node\":\"blocked\",\"synced\":\"yes\","
        "\"blocker\":\"review_required_bootstrap_trust\",\"height\":3302089,\"reference_height\":3302089},"
        "{\"host\":\"mac\",\"reachable\":true,\"probe_ms\":13600,\"node\":\"unknown\",\"synced\":\"unknown\","
        "\"blocker\":\"STATUS_SOURCE_UNAVAILABLE\",\"height\":null,\"reference_height\":null}]}";
    char out[1024];
    assert(zapp_hosts_format(fleet, out, sizeof(out)) && !strncmp(out, "1 of 3 hosts in sync\n", 21));
    assert(strstr(out, "\nr1 · reports synced but zclassicd height unknown, not counted in sync · 3,302,089\n"));
    assert(strstr(out, "\nr2 · in sync · 3,302,089\n") && strstr(out, "\nmac · node not answering\n"));
    assert(zapp_fleet_attention(out) == 2);
    assert(!strstr(out, "bootstrap") && !strstr(out, "STATUS_SOURCE"));
    static const char unsynced[] = "{\"hosts\":[{\"host\":\"t\",\"reachable\":true,\"synced\":\"no\",\"height\":5}]}";
    assert(zapp_hosts_format(unsynced, out, sizeof(out)) &&
           strstr(out, "\nt · zclassicd height unknown, not counted in sync · 5\n"));
}
/* The model gets one verdict per host from the headline's rule, no heights, so a host one block ahead
 * of its zclassicd reads "in sync" and the model has no arithmetic to get wrong. */
static void verdict_tests(void)
{
    static const char fleet[] = "{\"hosts\":["
        "{\"host\":\"r1\",\"reachable\":true,\"synced\":\"yes\",\"height\":3302090,\"reference_height\":3302089},"
        "{\"host\":\"r2\",\"reachable\":true,\"synced\":\"yes\",\"height\":3302089,\"reference_height\":null},"
        "{\"host\":\"r3\",\"reachable\":true,\"synced\":\"yes\",\"height\":3302000,\"reference_height\":3302089,"
        "\"disk_free_gb\":23},"
        "{\"host\":\"r4\",\"reachable\":true,\"synced\":\"no\",\"height\":3302089,\"reference_height\":3302089},"
        "{\"host\":\"r5\",\"reachable\":true,\"synced\":\"yes\",\"height\":3302095,\"reference_height\":3302089},"
        "{\"host\":\"mac\",\"reachable\":true,\"height\":null,\"reference_height\":null},"
        "{\"host\":\"r6\",\"reachable\":false,\"probe_ms\":13600}]}";
    char out[1024];
    assert(zapp_hosts_verdicts(fleet, out, sizeof(out)) && !strncmp(out, "1 of 7 hosts in sync\n", 21));
    assert(strstr(out, "\nr1: in sync\n"));
    assert(strstr(out, "\nr2: not counted in sync: zclassicd height unknown although the node reports itself synced\n"));
    assert(strstr(out, "\nr3: not in sync: 89 blocks behind; low on disk, 23 GB free\n"));
    assert(strstr(out, "\nr4: not in sync: the node reports itself not synced\n"));
    assert(strstr(out, "\nr5: not in sync: 6 blocks ahead of its zclassicd\n"));
    assert(strstr(out, "\nmac: not counted in sync: its node is not answering\n"));
    assert(strstr(out, "\nr6: host not answering after 13.6 s\n"));
    assert(!strstr(out, "3,302") && !strstr(out, "3302"));
    assert(!zapp_hosts_verdicts("not json", out, sizeof(out)) && !out[0]);
}
/* The fleet line keeps its place from launch while a laptop host is paired. */
static void fleet_line_tests(void)
{
    char line[160];
    const char *report = "2 of 3 hosts in sync\n\nr1 · in sync · 3,301,702\n";
    assert(!strcmp(zapp_fleet_line(report, false, true, line, sizeof(line)), "Fleet · 2 of 3 hosts in sync"));
    assert(!strcmp(zapp_fleet_line(report, false, false, line, sizeof(line)), "Fleet · 2 of 3 hosts in sync"));
    assert(!strcmp(zapp_fleet_line(report, true, false, line, sizeof(line)), "Fleet · no current report"));
    assert(!strcmp(zapp_fleet_line("", false, true, line, sizeof(line)), "Fleet · checking"));
    assert(!strcmp(zapp_fleet_line(NULL, true, true, line, sizeof(line)), "Fleet · no current report"));
    assert(!strcmp(zapp_fleet_line("", true, false, line, sizeof(line)), ""));
    assert(!strcmp(zapp_fleet_line("", false, false, line, sizeof(line)), ""));
}
/* One informational question per state; the node's trouble outranks the fleet's, and nothing is offered
 * without a paired host. */
static void suggestion_tests(void)
{
    char q[96];
    const char *report = "2 of 3 hosts in sync\n\nr1 · in sync · 3,301,702\n";
    assert(zapp_fleet_attention(report) == 1);
    assert(zapp_fleet_attention("3 of 3 hosts in sync\n") == 0);
    assert(zapp_fleet_attention("0 of 2 hosts in sync\n") == 2);
    assert(zapp_fleet_attention("") == 0 && zapp_fleet_attention(NULL) == 0);
    assert(zapp_fleet_attention("Fleet status is unavailable.") == 0);
    assert(zapp_fleet_attention("5 of 3 hosts in sync\n") == 0);
    static const char calm[] = "2 of 2 hosts in sync\n\nr1 · in sync · 3,301,702\n\nr2 · in sync · 3,301,702\n";
    static const char trouble[] = "1 of 3 hosts in sync\n\nr2 · in sync · 3,301,932\n\n"
        "r1 · zclassicd height unknown, not counted in sync · 3,301,932\n\nmac · node not answering\n  Low on disk · 23 GB free\n";
    static const char *const offline = "0 of 1 hosts in sync\n\nmac · host not answering after 25.0 s\n";
    assert(!strcmp(zapp_suggestion(false, true, 10, 100, 0, trouble, NULL, q, sizeof(q)), ""));
    assert(!strcmp(zapp_suggestion(true, true, 100, 100, 0, calm, NULL, q, sizeof(q)), "Why is my node waiting for peers?"));
    assert(!strcmp(zapp_suggestion(true, true, 100, 0, 3, calm, NULL, q, sizeof(q)), "Why is my node waiting for peers?"));
    assert(!strcmp(zapp_suggestion(true, true, 10, 100, 4, calm, NULL, q, sizeof(q)), "How long until my node catches up?"));
    assert(!strcmp(zapp_suggestion(true, true, 10, 100, 4, trouble, NULL, q, sizeof(q)), "How long until my node catches up?"));
    assert(!strcmp(zapp_suggestion(true, true, 100, 100, 4, trouble, NULL, q, sizeof(q)), "Which hosts need attention?"));
    assert(!strcmp(zapp_suggestion(true, false, -1, -1, -1, trouble, "", q, sizeof(q)), "Which hosts need attention?"));
    assert(!strcmp(zapp_suggestion(true, true, 100, 100, 4, calm, NULL, q, sizeof(q)), "How is my fleet?"));
    assert(!strcmp(zapp_suggestion(true, false, -1, -1, -1, NULL, NULL, q, sizeof(q)), "How is my fleet?"));
    /* An answered question gives way to the next one: the first host out of sync, skipping detail
     * lines and hosts in sync, then the whole fleet, then back to the top of the order. */
    assert(!strcmp(zapp_suggestion(true, false, -1, -1, -1, trouble, "which hosts need attention?", q, sizeof(q)),
                   "What is wrong with r1?"));
    assert(!strcmp(zapp_suggestion(true, false, -1, -1, -1, trouble, "What is wrong with r1?", q, sizeof(q)),
                   "How is my fleet?"));
    assert(!strcmp(zapp_suggestion(true, false, -1, -1, -1, trouble, "How is my fleet?", q, sizeof(q)),
                   "Which hosts need attention?"));
    assert(!strcmp(zapp_suggestion(true, true, 100, 100, 0, trouble, "Why is my node waiting for peers?", q, sizeof(q)),
                   "Which hosts need attention?"));
    assert(!strcmp(zapp_suggestion(true, false, -1, -1, -1, offline, "Which hosts need attention?", q, sizeof(q)),
                   "What is wrong with mac?"));
    assert(!strcmp(zapp_suggestion(true, false, -1, -1, -1, trouble, "Is r2 healthy?", q, sizeof(q)),
                   "Which hosts need attention?"));
    /* Nothing new to ask once the only question is answered. */
    assert(!strcmp(zapp_suggestion(true, true, 100, 100, 4, calm, "How is my fleet?", q, sizeof(q)), ""));
    assert(!strcmp(zapp_suggestion(true, false, -1, -1, -1, "1 of 2 hosts in sync\n\nr1 · in sync · 5\n\n"
                                   "  Low on disk · 3 GB free\n", "Which hosts need attention?", q, sizeof(q)),
                   "How is my fleet?"));
}
/* The host controls pick a host from the report's rows and show the host's reply as text. */
static void ops_view_tests(void)
{
    static const char report[] = "1 of 3 hosts in sync\n\nr1 · in sync · 3,302,089\n\n"
        "r2 · 10 blocks behind · 3,302,000\n  Low on disk · 23 GB free\n\nmac · host not answering after 25.0 s\n";
    char label[16];
    assert(zapp_hosts_label(report, 0, label) && !strcmp(label, "r1"));
    assert(zapp_hosts_label(report, 1, label) && !strcmp(label, "r2"));
    assert(zapp_hosts_label(report, 2, label) && !strcmp(label, "mac"));
    assert(!zapp_hosts_label(report, 3, label) && !zapp_hosts_label(NULL, 0, label) && !zapp_hosts_label("", 0, label));
}
static void ops_reply_tests(void)
{
    char text[512], plan[33];
    assert(zapp_ops_view("{\"host\":\"r1\",\"action\":\"errors\",\"text\":\"a ERROR\\nb ERROR\"}", text, sizeof(text), plan));
    assert(!strcmp(text, "r1 · recent errors\na ERROR\nb ERROR") && !plan[0]);
    assert(zapp_ops_view("{\"host\":\"r1\",\"action\":\"plan\",\"plan_id\":\"0123456789abcdef0123456789abcdef\","
        "\"text\":\"Restart the z23 node on r1? It is at height 5.\"}", text, sizeof(text), plan));
    assert(!strcmp(plan, "0123456789abcdef0123456789abcdef") && strstr(text, "Restart the z23 node on r1?") &&
           strstr(text, "Tap Confirm restart"));
    assert(zapp_ops_view("{\"host\":\"r1\",\"action\":\"confirm\",\"text\":\"restarted, answering at height 6\"}",
                         text, sizeof(text), plan) && !strcmp(text, "r1 · restarted, answering at height 6") && !plan[0]);
    assert(!zapp_ops_view("{\"host\":\"r2\",\"error\":\"The host did not answer.\"}", text, sizeof(text), plan) &&
           !strcmp(text, "r2: The host did not answer.") && !plan[0]);
    assert(!zapp_ops_view("{\"error\":\"That request is not allowed.\"}", text, sizeof(text), plan) &&
           !strcmp(text, "That request is not allowed."));
    assert(!zapp_ops_view("{\"host\":\"r1\",\"action\":\"plan\",\"plan_id\":\"short\",\"text\":\"x\"}", text, sizeof(text), plan) && !plan[0]);
    assert(!zapp_ops_view("nope", text, sizeof(text), plan) && !zapp_ops_view(NULL, text, sizeof(text), plan));
}
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
    assert(!strncmp(out, "1 of 3 hosts in sync\n", 21));
    assert(strstr(out, "\nr1 · in sync · 3,301,130\n\nr2"));
    assert(strstr(out, "\nr2 · 10 blocks behind · 3,301,120\n\nmac"));
    assert(strstr(out, "\nmac · host not answering after 25.0 s\n"));
    assert(!strstr(out, "Blocked") && !strstr(out, "bootstrap") && !strstr(out, "GB"));
    sync_rule_tests();
    unverified_host_tests();
    verdict_tests();
    ops_view_tests();
    ops_reply_tests();
    fleet_line_tests();
    suggestion_tests();
    static const char skew[] = "{\"hosts\":["
        "{\"host\":\"r2\",\"reachable\":true,\"synced\":\"yes\",\"height\":3301630,\"reference_height\":3301631},"
        "{\"host\":\"r1\",\"reachable\":true,\"synced\":\"yes\",\"height\":3301633,\"reference_height\":3301631},"
        "{\"host\":\"r3\",\"reachable\":true,\"synced\":\"yes\",\"height\":3301628,\"reference_height\":3301631}]}";
    assert(zapp_hosts_format(skew, out, sizeof(out)) && !strncmp(out, "2 of 3 hosts in sync\n", 21));
    assert(strstr(out, "\nr2 · in sync · 3,301,630\n") && strstr(out, "\nr1 · in sync · 3,301,633\n"));
    assert(strstr(out, "\nr3 · 3 blocks behind · 3,301,628\n"));
    static const char small[] = "{\"hosts\":[{\"host\":\"t\",\"reachable\":true,\"synced\":\"no\",\"height\":999,"
        "\"reference_height\":1000}]}";
    assert(zapp_hosts_format(small, out, sizeof(out)) && strstr(out, "\nt · 1 block behind · 999\n"));
    static const char large[] = "{\"hosts\":[{\"host\":\"t\",\"reachable\":true,\"height\":0,"
        "\"reference_height\":9223372036854775807}]}";
    assert(zapp_hosts_format(large, out, sizeof(out)) &&
           strstr(out, "\nt · 9,223,372,036,854,775,807 blocks behind · 0\n"));
    static const char odd[] = "{\"hosts\":[{\"host\":\"t\",\"reachable\":true,\"height\":-5,"
        "\"node\":\"STARTING_UP\",\"blocker\":\"none\",\"disk_free_gb\":7}]}";
    assert(zapp_hosts_format(odd, out, sizeof(out)) && strstr(out, "\nt · height unknown\n  Low on disk · 7 GB free\n"));
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
    assert(!strcmp(zapp_node_line(false, false, false, false, -1, -1, -1, line, sizeof(line)), "Node stopped"));
    assert(!strcmp(zapp_node_line(true, true, true, true, 3301553, 3301553, 4, line, sizeof(line)), "Node stopping"));
    assert(!strcmp(zapp_node_line(false, true, false, true, -1, -1, -1, line, sizeof(line)), "Node starting"));
    assert(!strcmp(zapp_node_line(true, true, false, false, -1, -1, 2, line, sizeof(line)),
                   "Node running · 2 peers · onion starting"));
    assert(!strcmp(zapp_node_line(true, true, false, true, -1, -1, 2, line, sizeof(line)),
                   "Node running · 2 peers · onion ready"));
    assert(!strcmp(zapp_node_line(true, true, false, false, 3301133, 0, 0, line, sizeof(line)),
                   "Node waiting for peers · 3,301,133 · onion starting"));
    assert(!strcmp(zapp_node_line(true, true, false, true, 3301133, 3301537, 1, line, sizeof(line)),
                   "Node catching up · 3,301,133 of 3,301,537 · onion ready"));
    assert(!strcmp(zapp_node_line(true, false, false, true, 3301553, 3301553, 1, line, sizeof(line)),
                   "Node in sync · 3,301,553 · 1 peer · onion ready"));
    assert(!strcmp(zapp_node_line(true, true, false, false, 3301554, 3301553, -1, line, sizeof(line)),
                   "Node in sync · 3,301,554 · onion starting"));
    const char *sync_text = "Node catching up · 3,301,133 of 3,301,537";
    const char *gentle_reply = "{\"ok\":true,\"data\":{\"provable_tip\":5,\"pace\":\"gentle\"}}";
    const char *old_reply = "{\"ok\":true,\"data\":{\"provable_tip\":5}}";
    assert(!strcmp(zapp_paced_line(zapp_status_pace(gentle_reply), true, sync_text, line, sizeof(line)),
                   "Syncing gently · phone is warm"));
    assert(!strcmp(zapp_paced_line(zapp_status_pace(old_reply), true, sync_text, line, sizeof(line)), sync_text));
    assert(zapp_status_pace("{\"data\":{\"pace\":\"pause\"}}") == ZAPP_PACE_PAUSE);
    assert(zapp_status_pace("{\"data\":{\"pace\":\"unknown\"}}") == ZAPP_PACE_NORMAL);
    assert(zapp_status_pace("not json") == ZAPP_PACE_NORMAL && zapp_status_pace(NULL) == ZAPP_PACE_NORMAL);
    assert(!strcmp(zapp_paced_line(ZAPP_PACE_NORMAL, true, sync_text, line, sizeof(line)), sync_text));
    assert(!strcmp(zapp_paced_line(ZAPP_PACE_GENTLE, true, sync_text, line, sizeof(line)),
                   "Syncing gently · phone is warm"));
    assert(!strcmp(zapp_paced_line(ZAPP_PACE_PAUSE, true, sync_text, line, sizeof(line)),
                   "Sync paused · phone is cooling down"));
    assert(!strcmp(zapp_paced_line(ZAPP_PACE_PAUSE, false, "Node stopped", line, sizeof(line)), "Node stopped"));
    assert(!strcmp(zapp_paced_line(ZAPP_PACE_GENTLE, true, sync_text, line, 8), "Syncing"));
    assert(!strcmp(zapp_sync_line(false, false, -1, -1, line, sizeof(line)),
                   "Start the node to begin synchronization."));
    assert(!strcmp(zapp_sync_line(false, true, -1, -1, line, sizeof(line)), "Waiting for the node to answer."));
    assert(!strcmp(zapp_sync_line(true, true, -1, 3301553, line, sizeof(line)),
                   "Waiting for the node to report its height."));
    assert(!strcmp(zapp_sync_line(true, true, 3301133, 0, line, sizeof(line)),
                   "Waiting for a peer that reports the current chain."));
    assert(!strcmp(zapp_sync_line(true, true, 3301900, 3301812, line, sizeof(line)),
                   "Your node has every block its peers report."));
    assert(!strcmp(zapp_sync_line(true, true, 3300133, 3301537, line, sizeof(line)), "1,404 blocks to go."));
    assert(!strcmp(zapp_sync_line(true, true, 3301536, 3301537, line, sizeof(line)), "1 block to go."));
    puts("hosts tests passed");
    return 0;
}
