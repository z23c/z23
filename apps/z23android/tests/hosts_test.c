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
    assert(!strcmp(zapp_suggestion(true, true, 100, 100, 1, calm, NULL, q, sizeof(q)), "Why is my node waiting for peers?"));
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
/* Node and sync lines when the chain's liveness is uncertain: peers, a still tip and the fleet's height. */
static void chain_evidence_tests(void)
{
    char line[96];
    char long_line[160];
    /* The phone case of 2026-10-31: one stuck peer reports the node's own height and the chain moved on. */
    assert(!strcmp(zapp_node_line(true, true, false, true, 3304001, 3304001, 1, NULL, line, sizeof(line)),
                   "Height 3,304,001 · only 1 peer, cannot confirm it is current · onion ready"));
    assert(!strcmp(zapp_node_line(true, true, false, true, 3304001, 3304001, 0, NULL, line, sizeof(line)),
                   "Height 3,304,001 · no peers, cannot confirm it is current · onion ready"));
    assert(!strcmp(zapp_node_line(true, true, false, true, 3304001, 3304001, -1, NULL, line, sizeof(line)),
                   "Height 3,304,001 · peer count unknown, cannot confirm it is current · onion ready"));
    assert(!strcmp(zapp_node_line(true, true, false, true, 3304001, 3304001, 2, NULL, line, sizeof(line)),
                   "Node in sync · 3,304,001 · 2 peers · onion ready"));
    {
        /* Fleet height: behind by it, or confirmed by it when one peer agrees with it. */
        const struct zapp_chain_evidence ahead = {.fleet_height = 3304010, .quiet_secs = 0};
        const struct zapp_chain_evidence agrees = {.fleet_height = 3304002, .quiet_secs = 5000};
        const struct zapp_chain_evidence quiet = {.fleet_height = -1, .quiet_secs = ZAPP_CHAIN_QUIET_SECS + 1};
        const struct zapp_chain_evidence brief = {.fleet_height = -1, .quiet_secs = ZAPP_CHAIN_QUIET_SECS};
        assert(!strcmp(zapp_node_line(true, true, false, false, 3304001, 3304001, 1, &ahead, line, sizeof(line)),
                       "Behind · 3,304,001 of 3,304,010 · onion starting"));
        assert(!strcmp(zapp_node_line(true, true, false, false, 3304001, 3304001, 1, &agrees, line, sizeof(line)),
                       "Node in sync · 3,304,001 · 1 peer · onion starting"));
        assert(!strcmp(zapp_node_line(true, true, false, false, 3304001, 0, 0, &agrees, line, sizeof(line)),
                       "Node in sync · 3,304,001 · 0 peers · onion starting"));
        assert(!strcmp(zapp_node_line(true, true, false, false, 3304001, 3304001, 5, &quiet, line, sizeof(line)),
                       "Height 3,304,001 · no new block for 15 min, cannot confirm it is current · onion starting"));
        assert(!strcmp(zapp_node_line(true, true, false, false, 3304001, 3304001, 5, &brief, line, sizeof(line)),
                       "Node in sync · 3,304,001 · 5 peers · onion starting"));
        /* Two blocks apart is within the skew; three is behind. */
        assert(!strncmp(zapp_node_line(true, true, false, false, 3304001, 3304003, 5, NULL, line, sizeof(line)),
                        "Node in sync", 12));
        assert(!strncmp(zapp_node_line(true, true, false, false, 3304001, 3304004, 5, NULL, line, sizeof(line)),
                        "Behind · 3,304,001 of 3,304,004", 31));
        assert(!strcmp(zapp_sync_line(true, true, 3304001, 3304001, 1, NULL, long_line, sizeof(long_line)),
                       "Your node has every block it can see, but with only 1 peer it cannot confirm it is current."));
        assert(!strcmp(zapp_sync_line(true, true, 3304001, 3304001, 1, &ahead, long_line, sizeof(long_line)), "9 blocks to go."));
        assert(!strcmp(zapp_sync_line(true, true, 3304001, 3304001, 5, &quiet, long_line, sizeof(long_line)),
                       "Your node has every block it can see, but with no new block for 15 min it cannot confirm it is current."));
    }
    {
        static const char rows[] = "\"hosts\":[{\"host\":\"r1\",\"reachable\":true,\"height\":3304010,\"reference_height\":3304011},"
            "{\"host\":\"r2\",\"reachable\":true,\"height\":3304009},{\"host\":\"mac\",\"reachable\":false,\"height\":9999999}]";
        char fleet[400];
        const int64_t now = 1793250000;
        snprintf(fleet, sizeof(fleet), "{%s,\"observed_at\":%lld}", rows, (long long)now - 10);
        assert(zapp_fleet_height(fleet, now) == 3304011);
        /* A snapshot the laptop host keeps serving after its refreshes fail is no evidence: old, missing or dated ahead. */
        snprintf(fleet, sizeof(fleet), "{%s,\"observed_at\":%lld}", rows, (long long)now - ZAPP_FLEET_MAX_AGE_SECS);
        assert(zapp_fleet_height(fleet, now) == 3304011);
        snprintf(fleet, sizeof(fleet), "{%s,\"observed_at\":%lld}", rows, (long long)now - ZAPP_FLEET_MAX_AGE_SECS - 1);
        assert(zapp_fleet_height(fleet, now) == -1);
        snprintf(fleet, sizeof(fleet), "{%s}", rows);
        assert(zapp_fleet_height(fleet, now) == -1);
        snprintf(fleet, sizeof(fleet), "{%s,\"observed_at\":%lld}", rows, (long long)now + ZAPP_FLEET_FUTURE_SECS);
        assert(zapp_fleet_height(fleet, now) == 3304011);
        snprintf(fleet, sizeof(fleet), "{%s,\"observed_at\":%lld}", rows, (long long)now + ZAPP_FLEET_FUTURE_SECS + 1);
        assert(zapp_fleet_height(fleet, now) == -1);
        snprintf(fleet, sizeof(fleet), "{\"hosts\":[{\"host\":\"r1\",\"reachable\":false,\"height\":5}],\"observed_at\":%lld}", (long long)now);
        assert(zapp_fleet_height(fleet, now) == -1);
        assert(zapp_fleet_height("not json", now) == -1 && zapp_fleet_height(NULL, now) == -1 && zapp_fleet_height("{}", now) == -1);
        /* The node line and the sentence under More agree inside the skew: two blocks short is in sync, three is behind. */
        assert(!strncmp(zapp_node_line(true, true, false, false, 3304001, 3304003, 5, NULL, line, sizeof(line)), "Node in sync", 12));
        assert(!strcmp(zapp_sync_line(true, true, 3304001, 3304003, 5, NULL, long_line, sizeof(long_line)),
                       "Your node has every block its peers report."));
        assert(!strcmp(zapp_sync_line(true, true, 3304001, 3304004, 5, NULL, long_line, sizeof(long_line)), "3 blocks to go."));
    }
}
/* Private mode dials only onion peers, so a shortage of peers is said as a shortage of onion peers. */
static void private_line_tests(void)
{
    char line[96], long_line[160];
    const struct zapp_chain_evidence tor = {.fleet_height = -1, .quiet_secs = 0, .onion_only = true};
    const struct zapp_chain_evidence tor_fleet = {.fleet_height = 3304002, .quiet_secs = 0, .onion_only = true};
    assert(!strcmp(zapp_node_line(true, true, false, false, 3304001, 3304001, 1, &tor, line, sizeof(line)),
                   "Private · waiting for onion peers (1 of 2) · onion starting"));
    assert(!strcmp(zapp_node_line(true, true, false, true, 3304001, 3304001, 0, &tor, line, sizeof(line)),
                   "Private · waiting for onion peers (0 of 2) · onion ready"));
    assert(!strcmp(zapp_node_line(true, true, false, true, 3304001, 0, 1, &tor, line, sizeof(line)),
                   "Private · waiting for onion peers (1 of 2) · onion ready"));
    assert(!strcmp(zapp_node_line(true, true, false, true, 3304001, 3304020, 1, &tor, line, sizeof(line)),
                   "Private · waiting for onion peers (1 of 2) · onion ready"));
    assert(!strcmp(zapp_node_line(true, true, false, true, 3304001, 3304001, -1, &tor, line, sizeof(line)),
                   "Private · waiting for onion peers (count unknown) · onion ready"));
    assert(!strcmp(zapp_sync_line(true, true, 3304001, 3304001, -1, &tor, long_line, sizeof(long_line)),
                   "Private mode dials only onion peers. The node has not reported its peer count."));
    /* At the floor the ordinary rule applies; so does a fleet height that agrees. */
    assert(!strcmp(zapp_node_line(true, true, false, true, 3304001, 3304001, 2, &tor, line, sizeof(line)),
                   "Node in sync · 3,304,001 · 2 peers · onion ready"));
    assert(!strcmp(zapp_node_line(true, true, false, true, 3304001, 3304001, 1, &tor_fleet, line, sizeof(line)),
                   "Node in sync · 3,304,001 · 1 peer · onion ready"));
    assert(!strcmp(zapp_node_line(true, true, false, true, 3304001, 3304020, 2, &tor, line, sizeof(line)),
                   "Behind · 3,304,001 of 3,304,020 · onion ready"));
    /* Not private: the wording is the plain one. */
    assert(!strncmp(zapp_node_line(true, true, false, true, 3304001, 3304001, 1, NULL, line, sizeof(line)), "Height ", 7));
    assert(!strcmp(zapp_node_line(true, true, false, false, 3301133, 0, 0, NULL, line, sizeof(line)),
                   "Node waiting for peers · 3,301,133 · onion starting"));
    assert(!strcmp(zapp_sync_line(true, true, 3304001, 3304001, 1, &tor, long_line, sizeof(long_line)),
                   "Private mode dials only onion peers. This node has 1 of 2."));
    assert(!strcmp(zapp_sync_line(true, true, 3304001, 3304001, 2, &tor, long_line, sizeof(long_line)),
                   "Your node has every block its peers report."));
}
static void chain_state_reasons(void)
{
    struct zapp_chain_status s;
    const struct zapp_chain_evidence moving = {.fleet_height = -1, .quiet_secs = 10, .onion_only = true};
    const struct zapp_chain_evidence silent = {.fleet_height = -1, .quiet_secs = 1000, .onion_only = true};
    const struct zapp_chain_evidence fleet_ahead = {.fleet_height = 2000, .quiet_secs = 10, .onion_only = true};
    s = zapp_chain_check(1000, 1000, 1, &moving);
    assert(s.state == ZAPP_CHAIN_UNCONFIRMED && !strcmp(s.reason, "only 1 peer") && s.reference == 1000);
    s = zapp_chain_check(1000, 1000, 0, &moving);
    assert(s.state == ZAPP_CHAIN_UNCONFIRMED && !strcmp(s.reason, "no peers"));
    s = zapp_chain_check(1000, 1000, -1, &moving);
    assert(s.state == ZAPP_CHAIN_UNCONFIRMED && !strcmp(s.reason, "peer count unknown"));
    s = zapp_chain_check(1000, 1000, 5, &silent);
    assert(s.state == ZAPP_CHAIN_UNCONFIRMED && !strcmp(s.reason, "no new block for 16 min"));
    s = zapp_chain_check(1000, 1000, 5, &moving);
    assert(s.state == ZAPP_CHAIN_CURRENT && !s.reason[0] && s.reference == 1000);
    s = zapp_chain_check(1000, 0, 5, &moving);
    assert(s.state == ZAPP_CHAIN_WAITING && !strcmp(s.reason, "No peer has reported a block height yet") && s.reference == -1);
    s = zapp_chain_check(1000, 1000, 5, &fleet_ahead);
    assert(s.state == ZAPP_CHAIN_BEHIND && s.reference == 2000);
    s = zapp_chain_check(-1, 1000, 5, &moving);
    assert(s.state == ZAPP_CHAIN_NONE && s.reference == -1 && !s.reason[0]);
}

int main(void)
{
    chain_state_reasons();
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
    assert(!strcmp(zapp_node_line(false, false, false, false, -1, -1, -1, NULL, line, sizeof(line)), "Node stopped"));
    assert(!strcmp(zapp_node_line(true, true, true, true, 3301553, 3301553, 4, NULL, line, sizeof(line)), "Node stopping"));
    assert(!strcmp(zapp_node_line(false, true, false, true, -1, -1, -1, NULL, line, sizeof(line)), "Node starting"));
    assert(!strcmp(zapp_node_line(true, true, false, false, -1, -1, 2, NULL, line, sizeof(line)),
                   "Node running · 2 peers · onion starting"));
    assert(!strcmp(zapp_node_line(true, true, false, true, -1, -1, 2, NULL, line, sizeof(line)),
                   "Node running · 2 peers · onion ready"));
    assert(!strcmp(zapp_node_line(true, true, false, false, 3301133, 0, 0, NULL, line, sizeof(line)),
                   "Node waiting for peers · 3,301,133 · onion starting"));
    assert(!strcmp(zapp_node_line(true, true, false, true, 3301133, 3301537, 4, NULL, line, sizeof(line)),
                   "Behind · 3,301,133 of 3,301,537 · onion ready"));
    assert(!strcmp(zapp_node_line(true, false, false, true, 3301553, 3301553, 4, NULL, line, sizeof(line)),
                   "Node in sync · 3,301,553 · 4 peers · onion ready"));
    assert(!strcmp(zapp_node_line(true, true, false, false, 3301554, 3301553, 4, NULL, line, sizeof(line)),
                   "Node in sync · 3,301,554 · 4 peers · onion starting"));
    chain_evidence_tests();
    private_line_tests();
    const char *sync_text = "Behind · 3,301,133 of 3,301,537";
    const char *gentle_reply = "{\"result\":{\"pace\":\"gentle\"},\"error\":null,\"id\":1}";
    const char *old_reply = "{\"ok\":true,\"data\":{\"provable_tip\":5}}";
    assert(!strcmp(zapp_paced_line(zapp_getnodepace_pace(gentle_reply), true, sync_text, line, sizeof(line)),
                   "Syncing gently · phone is warm"));
    assert(!strcmp(zapp_paced_line(zapp_getnodepace_pace(old_reply), true, sync_text, line, sizeof(line)), sync_text));
    const char *pause_reply = "{\"result\":{\"pace\":\"pause\"},\"error\":null,\"id\":1}";
    assert(zapp_getnodepace_pace(pause_reply) == ZAPP_PACE_PAUSE);
    assert(zapp_getnodepace_pace("{\"result\":{\"pace\":\"gentle\"},\"error\":null,\"id\":1}") == ZAPP_PACE_GENTLE);
    assert(zapp_getnodepace_pace("{\"result\":{\"pace\":\"normal\"},\"error\":null,\"id\":1}") == ZAPP_PACE_NORMAL);
    assert(zapp_getnodepace_pace("{\"result\":{\"pace\":\"unknown\"},\"error\":null,\"id\":1}") == ZAPP_PACE_NORMAL);
    assert(zapp_getnodepace_pace("{\"result\":null,\"error\":{\"code\":-28,\"message\":\"loading\"},\"id\":1}") == ZAPP_PACE_NORMAL);
    assert(zapp_getnodepace_pace("{\"data\":{\"pace\":\"pause\"}}") == ZAPP_PACE_NORMAL);
    assert(zapp_getnodepace_pace("not json") == ZAPP_PACE_NORMAL && zapp_getnodepace_pace(NULL) == ZAPP_PACE_NORMAL);
    assert(!strcmp(zapp_paced_line(ZAPP_PACE_NORMAL, true, sync_text, line, sizeof(line)), sync_text));
    assert(!strcmp(zapp_paced_line(ZAPP_PACE_GENTLE, true, sync_text, line, sizeof(line)),
                   "Syncing gently · phone is warm"));
    assert(!strcmp(zapp_paced_line(ZAPP_PACE_PAUSE, true, sync_text, line, sizeof(line)),
                   "Paused while the phone cools down. It picks up again by itself."));
    assert(!strcmp(zapp_paced_line(ZAPP_PACE_PAUSE, false, "Node stopped", line, sizeof(line)), "Node stopped"));
    assert(!strcmp(zapp_paced_line(ZAPP_PACE_GENTLE, true, sync_text, line, 8), "Syncing"));
    /* A synced or stopping node keeps its true line; only a node that is starting or catching up shows the pace. */
    {
        const char *synced = "Node in sync · 3,301,553 · 1 peer", *stopping = "Node stopping";
        assert(!strcmp(zapp_paced_line(ZAPP_PACE_GENTLE, true, synced, line, sizeof(line)), synced));
        assert(!strcmp(zapp_paced_line(ZAPP_PACE_PAUSE, true, synced, line, sizeof(line)), synced));
        assert(!strcmp(zapp_paced_line(ZAPP_PACE_GENTLE, true, stopping, line, sizeof(line)), stopping));
        assert(!strcmp(zapp_paced_line(ZAPP_PACE_PAUSE, true, stopping, line, sizeof(line)), stopping));
    }
    assert(!strcmp(zapp_sync_line(false, false, -1, -1, 4, NULL, line, sizeof(line)),
                   "Start the node to begin synchronization."));
    assert(!strcmp(zapp_sync_line(false, true, -1, -1, 4, NULL, line, sizeof(line)), "Waiting for the node to answer."));
    assert(!strcmp(zapp_sync_line(true, true, -1, 3301553, 4, NULL, line, sizeof(line)),
                   "Waiting for the node to report its height."));
    assert(!strcmp(zapp_sync_line(true, true, 3301133, 0, 4, NULL, line, sizeof(line)),
                   "Waiting for a peer that reports the current chain."));
    assert(!strcmp(zapp_sync_line(true, true, 3301900, 3301812, 4, NULL, line, sizeof(line)),
                   "Your node has every block its peers report."));
    assert(!strcmp(zapp_sync_line(true, true, 3300133, 3301537, 4, NULL, line, sizeof(line)), "1,404 blocks to go."));
    assert(!strcmp(zapp_sync_line(true, true, 3301536, 3301537, 4, NULL, line, sizeof(line)),
                   "Your node has every block its peers report."));
    /* Only this app, the adb shell and root may launch the app with a pairing offer. */
    assert(zapp_pair_caller_allowed(10234, 10234));
    assert(zapp_pair_caller_allowed(2000, 10234));
    assert(zapp_pair_caller_allowed(0, 10234));
    assert(!zapp_pair_caller_allowed(10235, 10234));
    assert(!zapp_pair_caller_allowed(1000, 10234));
    assert(!zapp_pair_caller_allowed(-1, 10234));
    assert(!zapp_pair_caller_allowed(-1, -1));
    puts("hosts tests passed");
    return 0;
}
