/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#undef NDEBUG
#include "host_ops.h"
#include "json/json.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define ID "0123456789abcdef0123456789abcdef"
#define PLAN_REPLY "{\"ok\":true,\"data\":{\"plan_id\":\"" ID "\",\"height_now\":3302089,\"uptime_s_now\":86400}}"
#define DONE_REPLY "{\"ok\":true,\"data\":{\"restarted\":true,\"note\":\"restarted, answering at height 3302090\"}}"
#define MISMATCH_REPLY "{\"ok\":false,\"error\":{\"code\":\"PLAN_MISMATCH\",\"message\":\"plan_id is wrong or used\"}}"

struct fake { int calls; char command[256]; int timeout_ms; size_t cap; const char *reply; };
static bool fake_exec(const struct zapp_fleet_host *host, const char *command, int timeout_ms,
                      char *out, size_t cap, void *ctx)
{
    struct fake *f = ctx;
    (void)host;
    f->calls++; f->timeout_ms = timeout_ms; f->cap = cap;
    snprintf(f->command, sizeof(f->command), "%s", command);
    if (!f->reply) return false;
    snprintf(out, cap, "%s", f->reply);
    return true;
}
static const struct zapp_fleet_host hosts[] = {{"r1", "host-a.example"}, {"r2", "host-b.example"}};
static char reply[4096];
static struct json_value doc;

static const char *ask(struct zapp_ops *ops, const char *scope, int64_t now)
{
    json_free(&doc);
    doc = (struct json_value){0};
    assert(zapp_ops_handle(ops, hosts, 2, scope, now, reply, sizeof(reply)));
    assert(json_read(&doc, reply, strlen(reply)));
    return reply;
}
static const char *field(const char *key) { return json_get_str(json_get(&doc, key)); }

static void refusals(void)
{
    static const char *const refused[] = {
        "restart r1", "reboot r1", "errors", "", "errors r3", "errors R1", "errors r1 ", "errors r1 extra",
        "errors r1;id", "errors r1 && id", "errors r1\nid", "errors $(id)", "errors `id`", "errors r1|id",
        "errors -oProxyCommand=x", "errors r1 " ID, "plan r1 " ID, "confirm r1", "confirm r1 ",
        "confirm r1 0123456789abcdef0123456789abcde", "confirm r1 0123456789ABCDEF0123456789ABCDEF",
        "confirm r1 0123456789abcdef0123456789abcdef0", "confirm r1 '; touch x; '0123456789abcdef",
        "confirm r1  " ID, "confirm  r1 " ID, "errors r1111111111111111",
        "plugins", "plugins r3", "plugins r1 ", "plugins r1;id", "plugin r1"};
    struct fake f = {0};
    struct zapp_ops ops = {.exec = fake_exec, .ctx = &f};
    for (size_t i = 0; i < sizeof(refused) / sizeof(*refused); i++) {
        ask(&ops, refused[i], 1000);
        assert(field("error")[0] && !field("text")[0]);
    }
    assert(f.calls == 0);
    enum zapp_ops_action action;
    char id[ZAPP_OPS_PLAN_ID + 1];
    assert(zapp_ops_parse(hosts, 2, "confirm r2 " ID, &action, id) == &hosts[1] &&
           action == ZAPP_OPS_CONFIRM && !strcmp(id, ID));
    assert(zapp_ops_parse(hosts, 2, "errors r1", &action, id) == &hosts[0] && !id[0]);
    assert(zapp_ops_parse(hosts, 2, "plugins r2", &action, id) == &hosts[1] &&
           action == ZAPP_OPS_PLUGINS && !id[0]);
}
static void errors_view(void)
{
    struct fake f = {.reply = "{\"ok\":true,\"data\":{\"lines\":[\"a \\\"quoted\\\" ERROR\",\"b\\u0001\\u00e9\",\"c\",\"d\",\"e\",\"f\"]}}"};
    struct zapp_ops ops = {.exec = fake_exec, .ctx = &f};
    ask(&ops, "errors r2", 1000);
    assert(f.calls == 1 && !strcmp(field("host"), "r2") && !strcmp(field("action"), "errors"));
    assert(strstr(f.command, "z23 ops logs --pattern=ERROR") && !strchr(f.command, ';'));
    assert(!strcmp(field("text"), "a \"quoted\" ERROR\nb???\nc\nd\ne"));
    f.reply = "{\"ok\":true,\"data\":{\"lines\":[]}}";
    ask(&ops, "errors r1", 1000);
    assert(!strcmp(field("text"), "No errors in the last 24 hours."));
    f.reply = NULL;
    ask(&ops, "errors r1", 1000);
    assert(!strcmp(field("error"), "The host did not answer.") && !strcmp(field("host"), "r1"));
    f.reply = "not json";
    ask(&ops, "errors r1", 1000);
    assert(!strcmp(field("error"), "The host's reply could not be read."));
    f.reply = MISMATCH_REPLY;
    ask(&ops, "errors r1", 1000);
    assert(!strcmp(field("error"), "plan_id is wrong or used"));
}
static void restart_flow(void)
{
    struct fake f = {.reply = PLAN_REPLY};
    struct zapp_ops ops = {.exec = fake_exec, .ctx = &f};
    ask(&ops, "confirm r1 " ID, 1000);
    assert(f.calls == 0 && strstr(field("error"), "Plan the restart again"));
    ask(&ops, "plan r1", 1000);
    assert(f.calls == 1 && !strcmp(f.command, "z23 ops node restart") && !strcmp(field("plan_id"), ID));
    assert(strstr(field("text"), "Restart the z23 node on r1?") && strstr(field("text"), "height 3302089"));
    ask(&ops, "confirm r2 " ID, 1001);
    assert(f.calls == 1 && field("error")[0]);
    ask(&ops, "plan r1", 2000);
    f.reply = DONE_REPLY;
    ask(&ops, "confirm r1 ffffffffffffffffffffffffffffffff", 2001);
    assert(f.calls == 2 && field("error")[0]);
    ask(&ops, "confirm r1 " ID, 2002);
    assert(f.calls == 2 && field("error")[0]);
    f.reply = PLAN_REPLY;
    ask(&ops, "plan r1", 3000);
    f.reply = DONE_REPLY;
    ask(&ops, "confirm r1 " ID, 3010);
    assert(f.calls == 4 && !strcmp(field("text"), "restarted, answering at height 3302090"));
    assert(!strcmp(f.command, "z23 ops node restart --input='{\"plan_id\":\"" ID "\",\"confirm\":true,\"wait_s\":60}'"));
    assert(f.timeout_ms > 60000);
    ask(&ops, "confirm r1 " ID, 3011);
    assert(f.calls == 4 && field("error")[0]);
}
static void stale_and_failed(void)
{
    struct fake f = {.reply = PLAN_REPLY};
    struct zapp_ops ops = {.exec = fake_exec, .ctx = &f};
    ask(&ops, "plan r2", 5000);
    ask(&ops, "confirm r2 " ID, 5000 + ZAPP_OPS_PLAN_TTL_S + 1);
    assert(f.calls == 1 && field("error")[0]);
    ask(&ops, "plan r2", 6000);
    f.reply = MISMATCH_REPLY;
    ask(&ops, "confirm r2 " ID, 6000 + ZAPP_OPS_PLAN_TTL_S);
    assert(f.calls == 3 && !strcmp(field("error"), "plan_id is wrong or used"));
    ask(&ops, "confirm r2 " ID, 6001);
    assert(f.calls == 3);
    f.reply = "{\"ok\":true,\"data\":{\"plan_id\":\"short\"}}";
    ask(&ops, "plan r1", 7000);
    assert(!strcmp(field("error"), "The host sent no restart plan."));
    ask(&ops, "confirm r1 " ID, 7001);
    assert(f.calls == 4);
}
#define HEX16 "0123456789abcdef"
#define PLUGIN_GEN HEX16 HEX16 HEX16 HEX16 HEX16 HEX16 HEX16 HEX16
static void saved_generations_view(void)
{
    char a[] = PLUGIN_GEN, b[] = PLUGIN_GEN, c[] = PLUGIN_GEN, d[] = PLUGIN_GEN;
    a[0] = 'a'; b[0] = 'b'; c[0] = 'c'; d[0] = 'd';
    char rich[2048];
    int rich_len = snprintf(rich, sizeof(rich), "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v1\",\"count\":1,\"plugins\":[{"
        "\"name\":\"clips\",\"current\":\"" PLUGIN_GEN "\",\"last_good\":\"%s\",\"current_state\":\"ok\","
        "\"last_good_state\":\"ok\",\"generations_state\":\"ok\",\"generations\":[\"" PLUGIN_GEN "\",\"%s\",\"%s\",\"%s\",\"%s\"]}]}}",
        a, a, b, c, d);
    assert(rich_len > 0 && (size_t)rich_len < sizeof(rich));
    struct fake f = {.reply = rich};
    struct zapp_ops ops = {.exec = fake_exec, .ctx = &f};
    ask(&ops, "plugins r2", 1000);
    const char *saved = strstr(field("text"), "\n other saved IDs: ");
    assert(saved && !strstr(saved, "a123456789ab") && !strstr(saved, "d123456789ab"));
    assert(!strcmp(saved, "\n other saved IDs: b123456789ab, c123456789ab (+1 more)"));
    const char *ids = field("ids");
    assert(strstr(ids, PLUGIN_GEN));
    assert(strstr(ids, a));
    assert(!strstr(ids, b));
}
static void plugin_id_fields(void)
{
    struct fake f = {.reply = "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v1\",\"count\":1,\"plugins\":[{"
        "\"name\":\"clips\",\"current\":\"" PLUGIN_GEN "\",\"last_good\":\"\",\"current_state\":\"ok\","
        "\"last_good_state\":\"missing\",\"generations_state\":\"ok\",\"generations\":[\"" PLUGIN_GEN "\"]}]}}"};
    struct zapp_ops ops = {.exec = fake_exec, .ctx = &f};
    ask(&ops, "plugins r1", 1000);
    assert(strstr(field("ids"), PLUGIN_GEN));
    assert(strstr(field("ids"), "last-good - (missing)"));
    f.reply = "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v1\",\"count\":0,\"plugins\":[]}}";
    ask(&ops, "plugins r1", 1000);
    assert(!field("ids")[0]);
    f.reply = "not json";
    ask(&ops, "plugins r1", 1000);
    const char *ids = field("ids");
    assert(!ids || !ids[0]);
}
static void ids_omit_hidden(const char *ids)
{
    assert(strstr(ids, "p7"));
    assert(!strstr(ids, "p8"));
    assert(strstr(ids, "2 more plugins not copied."));
}
static void plugins_view(void)
{
    struct fake f = {.reply = "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v1\",\"count\":1,\"plugins\":[{"
        "\"name\":\"clips\",\"current\":\"" PLUGIN_GEN "\",\"last_good\":\"\",\"current_state\":\"ok\","
        "\"last_good_state\":\"missing\",\"generations_state\":\"ok\",\"generations\":[\"" PLUGIN_GEN "\"]}]}}"};
    struct zapp_ops ops = {.exec = fake_exec, .ctx = &f};
    ask(&ops, "plugins r2", 1000);
    assert(f.calls == 1 && !strcmp(f.command, "z23 plugin list") && f.timeout_ms == 15000 && f.cap == 16384);
    assert(!strcmp(field("host"), "r2") && !strcmp(field("action"), "plugins"));
    assert(strstr(field("text"), "Inventory scan only; signatures are not rechecked."));
    assert(strstr(field("text"), "clips\n current 0123456789ab (ok) · last-good - (missing)"));
    assert(!strstr(field("text"), "other saved IDs"));
    saved_generations_view();
    plugin_id_fields();
    f.reply = "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v1\",\"count\":1,\"plugins\":[{"
        "\"name\":\"clips\",\"current\":\"\",\"last_good\":\"\",\"current_state\":\"unreadable\","
        "\"last_good_state\":\"corrupt\",\"generations_state\":\"corrupt\",\"generations\":[]}]}}";
    ask(&ops, "plugins r1", 1000);
    assert(strstr(field("text"), "current unknown (unreadable) · last-good unknown (corrupt) · store corrupt"));
    f.reply = "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v1\",\"count\":0,\"plugins\":[]}}";
    ask(&ops, "plugins r1", 1000);
    assert(strstr(field("text"), "No plugins installed."));
    static const char *const invalid[] = {
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v2\",\"count\":0,\"plugins\":[]}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v1\",\"count\":1,\"plugins\":[]}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v1\",\"count\":\"0\",\"plugins\":[]}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v1\",\"count\":1,\"plugins\":[{"
            "\"name\":\"bad name\",\"current\":\"\",\"last_good\":\"\",\"current_state\":\"missing\","
            "\"last_good_state\":\"missing\",\"generations_state\":\"ok\"}]}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v1\",\"count\":1,\"plugins\":[{"
            "\"name\":\"clips\",\"current\":\"\",\"last_good\":\"\",\"current_state\":\"ok\","
            "\"last_good_state\":\"missing\",\"generations_state\":\"ok\"}]}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v1\",\"count\":1,\"plugins\":[{"
            "\"name\":\"clips\",\"current\":\"\",\"last_good\":\"" PLUGIN_GEN "\",\"current_state\":\"missing\","
            "\"last_good_state\":\"missing\",\"generations_state\":\"ok\"}]}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v1\",\"count\":1,\"plugins\":[{"
            "\"name\":\"clips\",\"current\":\"\",\"last_good\":\"\",\"current_state\":\"missing\","
            "\"last_good_state\":\"missing\",\"generations_state\":\"verified\"}]}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v1\",\"count\":1,\"plugins\":[{"
            "\"name\":\"Bad_Name\",\"current\":\"\",\"last_good\":\"\",\"current_state\":\"missing\","
            "\"last_good_state\":\"missing\",\"generations_state\":\"ok\",\"generations\":[]}]}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v1\",\"count\":1,\"plugins\":[{"
            "\"name\":\"clips\",\"current\":\"\",\"last_good\":\"\",\"current_state\":\"missing\","
            "\"last_good_state\":\"missing\",\"generations_state\":\"ok\"}]}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v1\",\"count\":1,\"plugins\":[{"
            "\"name\":\"clips\",\"current\":\"\",\"last_good\":\"\",\"current_state\":\"missing\","
            "\"last_good_state\":\"missing\",\"generations_state\":\"ok\",\"generations\":[\"short\"]}]}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v1\",\"count\":1,\"plugins\":[{"
            "\"name\":\"clips\",\"current\":\"\",\"last_good\":\"\",\"current_state\":\"missing\","
            "\"last_good_state\":\"missing\",\"generations_state\":\"corrupt\",\"generations\":[\"" PLUGIN_GEN "\"]}]}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v1\",\"count\":1,\"plugins\":[{"
            "\"name\":\"clips\",\"current\":\"\",\"last_good\":\"\",\"current_state\":\"missing\","
            "\"last_good_state\":\"missing\",\"generations_state\":\"ok\",\"generations\":{}}]}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v1\",\"count\":1,\"plugins\":[{"
            "\"name\":\"clips\",\"current\":\"\",\"last_good\":\"\",\"current_state\":\"missing\","
            "\"last_good_state\":\"missing\",\"generations_state\":\"ok\",\"generations\":[42]}]}}",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); ++i) {
        f.reply = invalid[i];
        ask(&ops, "plugins r1", 1000);
        assert(!strcmp(field("error"), "The host's plugin inventory was not understood.") && !field("text")[0]);
    }
    char large[16384];
    int n = snprintf(large, sizeof(large), "{\"ok\":true,\"data\":{\"schema\":\"zcl.plugin_list.v1\",\"count\":10,\"plugins\":[");
    assert(n > 0 && (size_t)n < sizeof(large));
    size_t used = (size_t)n;
    for (size_t i = 0; i < 10; ++i) {
        n = snprintf(large + used, sizeof(large) - used,
            "%s{\"name\":\"p%zu\",\"current\":\"\",\"last_good\":\"\",\"current_state\":\"missing\","
            "\"last_good_state\":\"missing\",\"generations_state\":\"ok\",\"generations\":[]}", i ? "," : "", i);
        assert(n > 0 && (size_t)n < sizeof(large) - used);
        used += (size_t)n;
    }
    n = snprintf(large + used, sizeof(large) - used, "]}}");
    assert(n > 0 && (size_t)n < sizeof(large) - used);
    f.reply = large;
    ask(&ops, "plugins r1", 1000);
    assert(strstr(field("text"), "\np0\n") && strstr(field("text"), "\np7\n"));
    assert(strstr(field("text"), "2 more not shown.") && !strstr(field("text"), "p8"));
    ids_omit_hidden(field("ids"));
    char *hidden = strstr(large, "\"name\":\"p8\"");
    assert(hidden);
    hidden[8] = ' ';
    f.reply = large;
    ask(&ops, "plugins r1", 1000);
    assert(!strcmp(field("error"), "The host's plugin inventory was not understood."));
    char too_big[16385];
    memset(too_big, 'x', sizeof(too_big) - 1);
    too_big[sizeof(too_big) - 1] = 0;
    f.reply = too_big;
    ask(&ops, "plugins r1", 1000);
    assert(!strcmp(field("error"), "The plugin inventory is too large to read safely."));
}
#undef PLUGIN_GEN
#undef HEX16
int main(void)
{
    refusals();
    errors_view();
    plugins_view();
    restart_flow();
    stale_and_failed();
    json_free(&doc);
    puts("host ops tests passed");
    return 0;
}
