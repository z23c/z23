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

struct fake { int calls; char command[256]; int timeout_ms; const char *reply; };
static bool fake_exec(const struct zapp_fleet_host *host, const char *command, int timeout_ms,
                      char *out, size_t cap, void *ctx)
{
    struct fake *f = ctx;
    (void)host;
    f->calls++; f->timeout_ms = timeout_ms;
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
        "confirm r1  " ID, "confirm  r1 " ID, "errors r1111111111111111"};
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
int main(void)
{
    refusals();
    errors_view();
    restart_flow();
    stale_and_failed();
    json_free(&doc);
    puts("host ops tests passed");
    return 0;
}
