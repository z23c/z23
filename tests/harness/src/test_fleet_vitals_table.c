/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: contract coverage for fleet.vitals.table
 * (tools/command/native_fleet_vitals_table.c) through the registered
 * dispatch: a table of one local row and
 * fake-ssh remotes (one answers, one hangs past its deadline and is cut with
 * the DEADLINE outcome), and every malformed input refused before any ssh
 * is spawned. The fake ssh is a script in a private PATH directory, so no
 * network is touched. */

#include "test/test_core.h"

#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern int read_entire_file(const char *path, char **out_buf);

#define VT_TEXT_MAX 131072u

struct vt_reply {
    struct json_value root;
    bool parsed;
};

static char g_vt_text[VT_TEXT_MAX];

static bool vt_call(const char *path, struct json_value *input, struct vt_reply *r)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, path, NULL);
    struct zcl_command_context ctx = { .registry = reg,
                                       .granted_capabilities = ~(uint64_t)0,
                                       .authority_ceiling = ZCL_COMMAND_AUTH_OWNER };
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_OK;
    json_init(&r->root);
    r->parsed = false;
    if (!spec)
        return false;
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, input, false, path,
                                                 "full", 0, 0, NULL, g_vt_text,
                                                 sizeof(g_vt_text), &exit_code);
    r->parsed = n > 0 && n < sizeof(g_vt_text) && json_read(&r->root, g_vt_text, n);
    return r->parsed;
}

static const struct json_value *vt_data(const struct vt_reply *r)
{
    return json_get(&r->root, "data");
}

static bool vt_ok(const struct vt_reply *r)
{
    const struct json_value *ok = json_get(&r->root, "ok");
    return ok && ok->type == JSON_BOOL && json_get_bool(ok);
}

static const char *vt_str(const struct json_value *obj, const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : "";
}

static int64_t vt_int(const struct json_value *obj, const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return v && v->type == JSON_INT ? json_get_int(v) : INT64_MIN;
}

static const char *vt_error(const struct vt_reply *r)
{
    return vt_str(json_get(&r->root, "error"), "code");
}

static bool vt_write(const char *path, const char *text, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    size_t length = strlen(text);
    bool ok = write(fd, text, length) == (ssize_t)length && fchmod(fd, mode) == 0;
    return close(fd) == 0 && ok;
}

static struct json_value vt_local(const char *label)
{
    struct json_value m = {0};
    json_set_object(&m);
    (void)json_push_kv_str(&m, "label", label);
    (void)json_push_kv_bool(&m, "local", true);
    return m;
}

static struct json_value vt_remote(const char *label, const char *route, const char *slot,
                                   const char *alias)
{
    struct json_value m = {0};
    json_set_object(&m);
    (void)json_push_kv_str(&m, "label", label);
    (void)json_push_kv_str(&m, "route_file", route);
    (void)json_push_kv_str(&m, "slot", slot);
    (void)json_push_kv_str(&m, "host_alias", alias);
    return m;
}

static void vt_add(struct json_value *list, struct json_value *m)
{
    (void)json_push_back(list, m);
    json_free(m);
}

/* machines list, deadline 1000; consumes nothing, the caller frees both. */
static void vt_input(struct json_value *input, struct json_value *list)
{
    json_set_object(input);
    json_set_array(list);
}

static const char k_fake_ssh[] =
    "#!/bin/sh\n"
    ": > \"$FAKE_DIR/spawned\"\n"
    "while [ \"$1\" != \"--\" ]; do shift; done\n"
    "shift\n"
    "printf '%s\\n' \"$@\" > \"$FAKE_DIR/argv-$1\"\n"
    "case \"$1\" in\n"
    "  quick) printf 'banner\\n{\"schema\":\"zcl.result.v1\",\"ok\":true,\"data\":"
    "{\"schema\":\"zcl.fleet_vitals_read.v1\",\"host\":\"quick\",\"cpus\":4,"
    "\"load1_centi\":125,\"load5_centi\":100,\"load15_centi\":90,"
    "\"mem_total_mib\":8192,\"mem_avail_mib\":4096,\"mem_used_mib\":4096,"
    "\"disk_total_mib\":102400,\"disk_used_mib\":51200,\"disk_free_mib\":51200,"
    "\"uptime_s\":3600}}\\n'; exit 0;;\n"
    "  hang) exec sleep 30;;\n"
    "  oldslot) printf '{\"schema\":\"zcl.result.v1\",\"ok\":false,\"error\":{\"code\":\"UNKNOWN_COMMAND\"}}\\n'; exit 2;;\n"
    "esac\n"
    "exit 3\n";

struct vt_fixture {
    char dir[512], bin[600], route[640], marker[640];
    char *prior_path;
};

static bool vt_fixture_open(struct vt_fixture *f, const char *prefix)
{
    memset(f, 0, sizeof *f);
    if (!test_mkdtemp(f->dir, sizeof f->dir, prefix))
        return false;
    char ssh[700];
    snprintf(f->bin, sizeof f->bin, "%s/bin", f->dir);
    snprintf(f->route, sizeof f->route, "%s/client.json", f->dir);
    snprintf(f->marker, sizeof f->marker, "%s/spawned", f->dir);
    snprintf(ssh, sizeof ssh, "%s/ssh", f->bin);
    char path[1400];
    snprintf(path, sizeof path, "%s:/usr/bin:/bin", f->bin);
    f->prior_path = getenv("PATH") ? strdup(getenv("PATH")) : NULL;
    return mkdir(f->bin, 0700) == 0 && vt_write(ssh, k_fake_ssh, 0700) &&
           vt_write(f->route, "{}", 0600) && setenv("FAKE_DIR", f->dir, 1) == 0 &&
           setenv("PATH", path, 1) == 0;
}

static void vt_fixture_close(struct vt_fixture *f)
{
    if (f->prior_path) {
        (void)setenv("PATH", f->prior_path, 1);
        free(f->prior_path);
    }
    (void)unsetenv("FAKE_DIR");
    if (f->dir[0])
        test_rm_rf(f->dir);
}

static int vt_table_mixed(void)
{
    int failures = 0;
    struct vt_fixture f;
    bool open = vt_fixture_open(&f, "fleet_vitals_table");
    TEST_CASE("fleet_vitals_table: local + answering + hanging remote gives 2 reachable and a DEADLINE row") {
        ASSERT(open);
        struct json_value input = {0}, list = {0}, m;
        vt_input(&input, &list);
        m = vt_local("here");
        vt_add(&list, &m);
        m = vt_remote("quick-box", f.route, "/opt/z23/bin/z23", "quick");
        vt_add(&list, &m);
        m = vt_remote("hang-box", f.route, "/opt/z23/bin/z23", "hang");
        vt_add(&list, &m);
        (void)json_push_kv(&input, "machines", &list);
        (void)json_push_kv_int(&input, "deadline_ms", 1000);
        struct vt_reply r;
        ASSERT(vt_call("fleet.vitals.table", &input, &r));
        json_free(&input);
        json_free(&list);
        ASSERT(vt_ok(&r));
        const struct json_value *d = vt_data(&r);
        const struct json_value *rows = json_get(d, "rows");
        ASSERT(rows && rows->type == JSON_ARR && json_size(rows) == 3);
        const struct json_value *a = json_at(rows, 0), *b = json_at(rows, 1), *c = json_at(rows, 2);
        ASSERT_STR_EQ(vt_str(a, "label"), "here");
        ASSERT(json_get_bool(json_get(a, "reachable")));
        ASSERT(vt_int(a, "mem_total_mib") > 0);
        ASSERT(json_get_bool(json_get(b, "reachable")));
        ASSERT_EQ(vt_int(b, "cpus"), 4);
        ASSERT_EQ(vt_int(b, "mem_used_mib"), 4096);
        ASSERT(!json_get_bool(json_get(c, "reachable")));
        ASSERT_STR_EQ(vt_str(c, "error"), "DEADLINE");
        const char *screen = vt_str(d, "screen");
        ASSERT(strstr(screen, "quick-box") != NULL);
        ASSERT(strstr(screen, "unreachable: DEADLINE") != NULL);
        ASSERT(strstr(screen, "\xE2\x96\x88") != NULL);
        ASSERT(strstr(screen, "\xE2\x96\x91") != NULL);
        ASSERT(strstr(screen, "\xE2\x94\x8C") != NULL);
        json_free(&r.root);
        /* the fixed argv reached ssh, ending in the fixed remote command */
        char argv_path[700], *text = NULL;
        snprintf(argv_path, sizeof argv_path, "%s/argv-quick", f.dir);
        ASSERT(read_entire_file(argv_path, &text) == 0);
        ASSERT(strcmp(text, "quick\n/opt/z23/bin/z23\nfleet\nvitals\nread\n--json\n") == 0);
        free(text);
    } TEST_END
    vt_fixture_close(&f);
    return failures;
}

static int vt_refusals(void)
{
    int failures = 0;
    struct vt_fixture f;
    bool open = vt_fixture_open(&f, "fleet_vitals_refuse");
    TEST_CASE("fleet_vitals_table: bad label, alias, route, slot, count and deadline refuse before any spawn") {
        ASSERT(open);
        struct {
            const char *label, *route, *slot, *alias;
            const char *want;
        } cases[] = {
            {"Bad", NULL, "/opt/z23/z23", "quick", "TABLE_LABEL_REFUSED"},
            {"has space", NULL, "/opt/z23/z23", "quick", "TABLE_LABEL_REFUSED"},
            {"seventeen-chars-xx", NULL, "/opt/z23/z23", "quick", "TABLE_LABEL_REFUSED"},
            {"ok", NULL, "/opt/z23/z23", "a b", "TABLE_ALIAS_REFUSED"},
            {"ok", NULL, "/opt/z23/z23", "-oProxyCommand=x", "TABLE_ALIAS_REFUSED"},
            {"ok", NULL, "/opt/z23/z23", "a;b", "TABLE_ALIAS_REFUSED"},
            {"ok", "relative.json", "/opt/z23/z23", "quick", "TABLE_ROUTE_REFUSED"},
            {"ok", "/nonexistent/route.json", "/opt/z23/z23", "quick", "TABLE_ROUTE_REFUSED"},
            {"ok", NULL, "z23", "quick", "TABLE_SLOT_REFUSED"},
            {"ok", NULL, "/opt/z 23/z23", "quick", "TABLE_SLOT_REFUSED"},
            {"ok", NULL, "/opt/../z23", "quick", "TABLE_SLOT_REFUSED"},
        };
        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
            struct json_value input = {0}, list = {0}, m;
            vt_input(&input, &list);
            m = vt_remote(cases[i].label, cases[i].route ? cases[i].route : f.route,
                          cases[i].slot, cases[i].alias);
            vt_add(&list, &m);
            (void)json_push_kv(&input, "machines", &list);
            struct vt_reply r;
            ASSERT(vt_call("fleet.vitals.table", &input, &r));
            json_free(&input);
            json_free(&list);
            ASSERT(!vt_ok(&r));
            ASSERT_STR_EQ(vt_error(&r), cases[i].want);
            json_free(&r.root);
        }
        /* 17 machines, a duplicate label and a short deadline */
        for (int variant = 0; variant < 3; ++variant) {
            struct json_value input = {0}, list = {0}, m;
            vt_input(&input, &list);
            int n = variant == 0 ? 17 : 2;
            for (int i = 0; i < n; ++i) {
                char label[16];
                snprintf(label, sizeof label, variant == 1 ? "dup" : "m%d", i);
                m = vt_remote(label, f.route, "/opt/z23/z23", "quick");
                vt_add(&list, &m);
            }
            (void)json_push_kv(&input, "machines", &list);
            if (variant == 2)
                (void)json_push_kv_int(&input, "deadline_ms", 999);
            struct vt_reply r;
            ASSERT(vt_call("fleet.vitals.table", &input, &r));
            json_free(&input);
            json_free(&list);
            ASSERT(!vt_ok(&r));
            ASSERT_STR_EQ(vt_error(&r), variant == 0   ? "TABLE_TOO_MANY_MACHINES"
                                        : variant == 1 ? "TABLE_LABEL_REFUSED"
                                                       : "TABLE_DEADLINE_REFUSED");
            json_free(&r.root);
        }
        struct stat st;
        ASSERT(lstat(f.marker, &st) != 0); /* no ssh was ever spawned */
    } TEST_END
    vt_fixture_close(&f);
    return failures;
}

static int vt_no_route(void)
{
    int failures = 0;
    struct vt_fixture f;
    bool open = vt_fixture_open(&f, "fleet_vitals_noroute");
    TEST_CASE("fleet_vitals_table: a machine without a route is shown as no_route, not an error, and never probed") {
        ASSERT(open);
        struct json_value input = {0}, list = {0}, m;
        vt_input(&input, &list);
        m = vt_local("here");
        vt_add(&list, &m);
        json_set_object(&m);
        (void)json_push_kv_str(&m, "label", "r3");
        vt_add(&list, &m);
        (void)json_push_kv(&input, "machines", &list);
        struct vt_reply r;
        ASSERT(vt_call("fleet.vitals.table", &input, &r));
        json_free(&input);
        json_free(&list);
        ASSERT(vt_ok(&r));
        const struct json_value *rows = json_get(vt_data(&r), "rows");
        ASSERT(rows && json_size(rows) == 2);
        ASSERT_STR_EQ(vt_str(json_at(rows, 0), "source"), "local");
        ASSERT_STR_EQ(vt_str(json_at(rows, 1), "source"), "no_route");
        ASSERT(!json_get_bool(json_get(json_at(rows, 1), "reachable")));
        const char *screen = vt_str(vt_data(&r), "screen");
        ASSERT(strstr(screen, "no tunnel route") != NULL);
        ASSERT(strstr(screen, "1/2 machines reachable") != NULL);
        json_free(&r.root);
        struct stat st;
        ASSERT(lstat(f.marker, &st) != 0);
    } TEST_END
    vt_fixture_close(&f);
    return failures;
}

static int vt_leaf_missing(void)
{
    int failures = 0;
    struct vt_fixture f;
    bool open = vt_fixture_open(&f, "fleet_vitals_oldslot");
    TEST_CASE("fleet_vitals_table: a slot that predates fleet vitals read is REMOTE_LEAF_MISSING") {
        ASSERT(open);
        struct json_value input = {0}, list = {0}, m;
        vt_input(&input, &list);
        m = vt_remote("old", f.route, "/opt/z23/bin/z23", "oldslot");
        vt_add(&list, &m);
        (void)json_push_kv(&input, "machines", &list);
        struct vt_reply r;
        ASSERT(vt_call("fleet.vitals.table", &input, &r));
        json_free(&input);
        json_free(&list);
        ASSERT(vt_ok(&r));
        const struct json_value *row = json_at(json_get(vt_data(&r), "rows"), 0);
        ASSERT_STR_EQ(vt_str(row, "source"), "live");
        ASSERT(!json_get_bool(json_get(row, "reachable")));
        ASSERT_STR_EQ(vt_str(row, "error"), "REMOTE_LEAF_MISSING");
        json_free(&r.root);
    } TEST_END
    vt_fixture_close(&f);
    return failures;
}

/* fake-ssh replies that differ only in load, queue and a missing queue field */
static const char k_fake_ssh_rank[] =
    "#!/bin/sh\n"
    "while [ \"$1\" != \"--\" ]; do shift; done\n"
    "shift\n"
    "case \"$1\" in\n"
    "  idle) printf '{\"schema\":\"zcl.result.v1\",\"ok\":true,\"data\":"
    "{\"schema\":\"zcl.fleet_vitals_read.v1\",\"host\":\"idle\",\"cpus\":32,"
    "\"load1_centi\":300,\"mem_total_mib\":8192,\"mem_used_mib\":4096,"
    "\"disk_total_mib\":102400,\"disk_used_mib\":51200,\"jobs_running\":1,"
    "\"jobs_queued\":0}}\n'; exit 0;;\n"
    "  busy) printf '{\"schema\":\"zcl.result.v1\",\"ok\":true,\"data\":"
    "{\"schema\":\"zcl.fleet_vitals_read.v1\",\"host\":\"busy\",\"cpus\":32,"
    "\"load1_centi\":7500,\"mem_total_mib\":8192,\"mem_used_mib\":4096,"
    "\"disk_total_mib\":102400,\"disk_used_mib\":51200,\"jobs_running\":4,"
    "\"jobs_queued\":6}}\n'; exit 0;;\n"
    "  oldq) printf '{\"schema\":\"zcl.result.v1\",\"ok\":true,\"data\":"
    "{\"schema\":\"zcl.fleet_vitals_read.v1\",\"host\":\"oldq\",\"cpus\":24,"
    "\"load1_centi\":1200}}\n'; exit 0;;\n"
    "esac\n"
    "exit 3\n";

static int vt_spare_rank(void)
{
    int failures = 0;
    struct vt_fixture f;
    bool open = vt_fixture_open(&f, "fleet_vitals_rank");
    char ssh[700];
    snprintf(ssh, sizeof ssh, "%s/ssh", f.bin);
    TEST_CASE("fleet_vitals_table: machines rank by spare cores, unreachable last, every row age 0") {
        ASSERT(open && vt_write(ssh, k_fake_ssh_rank, 0700));
        struct json_value input = {0}, list = {0}, m;
        vt_input(&input, &list);
        const char *names[] = {"busy", "idle", "oldq", "gone"};
        for (size_t i = 0; i < 4; ++i) {
            m = vt_remote(names[i], f.route, "/opt/z23/bin/z23", i == 3 ? "nosuch" : names[i]);
            vt_add(&list, &m);
        }
        (void)json_push_kv(&input, "machines", &list);
        struct vt_reply r;
        ASSERT(vt_call("fleet.vitals.table", &input, &r));
        json_free(&input);
        json_free(&list);
        ASSERT(vt_ok(&r));
        const struct json_value *d = vt_data(&r), *rows = json_get(d, "rows");
        ASSERT(rows && json_size(rows) == 4);
        /* rows keep input order; spare_rank carries the ordering */
        const struct json_value *busy = json_at(rows, 0), *idle = json_at(rows, 1),
                                *oldq = json_at(rows, 2), *gone = json_at(rows, 3);
        ASSERT_EQ(vt_int(idle, "spare_cores_centi"), 2900);
        ASSERT_EQ(vt_int(oldq, "spare_cores_centi"), 2400 - 1200);
        ASSERT_EQ(vt_int(busy, "spare_cores_centi"), 3200 - 7500); /* over-committed: negative */
        ASSERT_EQ(vt_int(idle, "spare_rank"), 1);
        ASSERT_EQ(vt_int(oldq, "spare_rank"), 2);
        ASSERT_EQ(vt_int(busy, "spare_rank"), 3);
        ASSERT_EQ(vt_int(idle, "load1_per_core_centi"), 9);
        ASSERT_EQ(vt_int(idle, "age_s"), 0);
        ASSERT_EQ(vt_int(busy, "jobs_queued"), 6);
        ASSERT(json_get(oldq, "jobs_queued") && json_get(oldq, "jobs_queued")->type == JSON_NULL);
        ASSERT(!json_get_bool(json_get(gone, "reachable")));
        ASSERT(json_get(gone, "spare_rank") == NULL);
        ASSERT_STR_EQ(vt_str(d, "best"), "idle");
        ASSERT(strstr(vt_str(d, "advice"), "idle") != NULL);
        ASSERT(strstr(vt_str(d, "age_note"), "measured during this call") != NULL);
        /* the screen lists machines in rank order, the unreachable one last */
        const char *screen = vt_str(d, "screen");
        const char *p_idle = strstr(screen, "idle"), *p_old = strstr(screen, "oldq"),
                   *p_busy = strstr(screen, "busy"), *p_gone = strstr(screen, "gone");
        ASSERT(p_idle && p_old && p_busy && p_gone);
        ASSERT(p_idle < p_old && p_old < p_busy && p_busy < p_gone);
        ASSERT(strstr(screen, "4 run 6 wait") != NULL);
        json_free(&r.root);
    } TEST_END
    vt_fixture_close(&f);
    return failures;
}

/* fake-ssh replies for the no-recommendation cases: two over-committed hosts and
 * one reachable host that reports no cpu count */
static const char k_fake_ssh_hot[] =
    "#!/bin/sh\n"
    "while [ \"$1\" != \"--\" ]; do shift; done\n"
    "shift\n"
    "case \"$1\" in\n"
    "  hot1) printf '{\"schema\":\"zcl.result.v1\",\"ok\":true,\"data\":"
    "{\"schema\":\"zcl.fleet_vitals_read.v1\",\"host\":\"hot1\",\"cpus\":32,"
    "\"load1_centi\":6800}}\n'; exit 0;;\n"
    "  hot2) printf '{\"schema\":\"zcl.result.v1\",\"ok\":true,\"data\":"
    "{\"schema\":\"zcl.fleet_vitals_read.v1\",\"host\":\"hot2\",\"cpus\":32,"
    "\"load1_centi\":7500}}\n'; exit 0;;\n"
    "  nocpu) printf '{\"schema\":\"zcl.result.v1\",\"ok\":true,\"data\":"
    "{\"schema\":\"zcl.fleet_vitals_read.v1\",\"host\":\"nocpu\"}}\n'; exit 0;;\n"
    "  idle) printf '{\"schema\":\"zcl.result.v1\",\"ok\":true,\"data\":"
    "{\"schema\":\"zcl.fleet_vitals_read.v1\",\"host\":\"idle\",\"cpus\":32,"
    "\"load1_centi\":300}}\n'; exit 0;;\n"
    "esac\n"
    "exit 3\n";

static bool vt_call_remotes(const struct vt_fixture *f, const char *const *names, size_t n,
                            struct vt_reply *r)
{
    struct json_value input = {0}, list = {0}, m;
    vt_input(&input, &list);
    for (size_t i = 0; i < n; ++i) {
        m = vt_remote(names[i], f->route, "/opt/z23/bin/z23", names[i]);
        vt_add(&list, &m);
    }
    (void)json_push_kv(&input, "machines", &list);
    bool ok = vt_call("fleet.vitals.table", &input, r);
    json_free(&input);
    json_free(&list);
    return ok;
}

static bool vt_best_is_null(const struct json_value *d)
{
    const struct json_value *best = json_get(d, "best");
    return best && best->type == JSON_NULL;
}

static bool vt_hot_fixture(struct vt_fixture *f, const char *prefix)
{
    char ssh[700];
    if (!vt_fixture_open(f, prefix))
        return false;
    snprintf(ssh, sizeof ssh, "%s/ssh", f->bin);
    return vt_write(ssh, k_fake_ssh_hot, 0700);
}

static int vt_one_machine(void)
{
    int failures = 0;
    struct vt_fixture f;
    bool open = vt_hot_fixture(&f, "fleet_vitals_one");
    TEST_CASE("fleet_vitals_table: one measured machine is never named best") {
        ASSERT(open);
        const char *names[] = {"idle", "nosuchhost"};
        struct vt_reply r;
        ASSERT(vt_call_remotes(&f, names, 2, &r));
        ASSERT(vt_ok(&r));
        const struct json_value *d = vt_data(&r);
        ASSERT(vt_best_is_null(d));
        ASSERT(strstr(vt_str(d, "advice"), "only idle was measured") != NULL);
        ASSERT(strstr(vt_str(d, "advice"), "fleet vitals table --machines=") != NULL);
        ASSERT(strstr(vt_str(d, "advice"), "most spare capacity") == NULL);
        ASSERT(strstr(vt_str(d, "screen"), "most spare capacity") == NULL);
        json_free(&r.root);
    } TEST_END
    vt_fixture_close(&f);
    return failures;
}

static int vt_all_overloaded(void)
{
    int failures = 0;
    struct vt_fixture f;
    bool open = vt_hot_fixture(&f, "fleet_vitals_hot");
    TEST_CASE("fleet_vitals_table: when every measured machine is over-committed none is recommended") {
        ASSERT(open);
        const char *names[] = {"hot1", "hot2", "nocpu"};
        struct vt_reply r;
        ASSERT(vt_call_remotes(&f, names, 3, &r));
        ASSERT(vt_ok(&r));
        const struct json_value *d = vt_data(&r), *rows = json_get(d, "rows");
        ASSERT(vt_int(json_at(rows, 0), "spare_cores_centi") < 0);
        ASSERT(vt_int(json_at(rows, 1), "spare_cores_centi") < 0);
        ASSERT(vt_best_is_null(d));
        ASSERT(strstr(vt_str(d, "advice"), "no measured machine has spare capacity") != NULL);
        ASSERT(strstr(vt_str(d, "advice"), "most spare capacity") == NULL);
        /* reachable but unmeasurable load is unranked: null, not 0 */
        const struct json_value *rank = json_get(json_at(rows, 2), "spare_rank");
        ASSERT(rank && rank->type == JSON_NULL);
        ASSERT_EQ(vt_int(json_at(rows, 0), "spare_rank"), 1);
        json_free(&r.root);
    } TEST_END
    vt_fixture_close(&f);
    return failures;
}

static int vt_normal_comparison(void)
{
    int failures = 0;
    struct vt_fixture f;
    bool open = vt_hot_fixture(&f, "fleet_vitals_cmp");
    TEST_CASE("fleet_vitals_table: a comparison with headroom names the machine with the most spare cores") {
        ASSERT(open);
        const char *names[] = {"hot1", "idle"};
        struct vt_reply r;
        ASSERT(vt_call_remotes(&f, names, 2, &r));
        ASSERT(vt_ok(&r));
        const struct json_value *d = vt_data(&r);
        ASSERT_STR_EQ(vt_str(d, "best"), "idle");
        ASSERT(strstr(vt_str(d, "advice"), "most spare capacity: idle") != NULL);
        json_free(&r.root);
    } TEST_END
    vt_fixture_close(&f);
    return failures;
}

static int vt_no_input(void)
{
    int failures = 0;
    TEST_CASE("fleet_vitals_table: no machines key shows this box alone with queue, age and a remote note") {
        struct json_value input = {0};
        json_set_object(&input);
        struct vt_reply r;
        ASSERT(vt_call("fleet.vitals.table", &input, &r));
        json_free(&input);
        ASSERT(vt_ok(&r));
        const struct json_value *d = vt_data(&r), *rows = json_get(d, "rows");
        ASSERT(rows && json_size(rows) == 1);
        const struct json_value *row = json_at(rows, 0);
        ASSERT_STR_EQ(vt_str(row, "source"), "local");
        ASSERT(json_get_bool(json_get(row, "reachable")));
        ASSERT_EQ(vt_int(row, "age_s"), 0);
        ASSERT(vt_int(row, "cpus") > 0);
        ASSERT(json_get(row, "jobs_running") != NULL && json_get(row, "jobs_queued") != NULL);
        ASSERT(strstr(vt_str(d, "note"), "never reads recorded fleet vitals ledger rows") != NULL);
        ASSERT(strstr(vt_str(d, "note"), "replicate") == NULL);
        /* one machine, nothing compared: no recommendation */
        ASSERT(vt_best_is_null(d));
        ASSERT(strstr(vt_str(d, "advice"), "most spare capacity") == NULL);
        ASSERT(strstr(vt_str(d, "advice"), "nothing was compared") != NULL);
        ASSERT(strstr(vt_str(d, "screen"), "build queue") != NULL);
        json_free(&r.root);
    } TEST_END
    return failures;
}

static int vt_empty_list(void)
{
    int failures = 0;
    TEST_CASE("fleet_vitals_table: an explicit empty machines list is still refused") {
        struct json_value input = {0}, list = {0};
        vt_input(&input, &list);
        (void)json_push_kv(&input, "machines", &list);
        struct vt_reply r;
        ASSERT(vt_call("fleet.vitals.table", &input, &r));
        json_free(&input);
        json_free(&list);
        ASSERT(!vt_ok(&r));
        ASSERT_STR_EQ(vt_error(&r), "TABLE_INPUT_REFUSED");
        json_free(&r.root);
    } TEST_END
    return failures;
}

int test_fleet_vitals_table(void);
int test_fleet_vitals_table(void)
{
    int failures = 0;
    failures += vt_table_mixed();
    failures += vt_refusals();
    failures += vt_no_route();
    failures += vt_leaf_missing();
    failures += vt_spare_rank();
    failures += vt_one_machine();
    failures += vt_all_overloaded();
    failures += vt_normal_comparison();
    failures += vt_no_input();
    failures += vt_empty_list();
    if (failures == 0)
        printf("test_fleet_vitals_table: all passed\n");
    else
        printf("test_fleet_vitals_table: %d FAILED\n", failures);
    return failures;
}
