/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: contract coverage for fleet.vitals.read
 * (tools/command/native_fleet_vitals_read.c) through the registered
 * dispatch: sane numbers, and nothing written to the measured home. */

#include "test/test_core.h"

#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define VR_TEXT_MAX 16384u

static char g_vr_text[VR_TEXT_MAX];

static const char *vr_str(const struct json_value *obj, const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : "";
}

static int64_t vr_int(const struct json_value *obj, const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return v && v->type == JSON_INT ? json_get_int(v) : INT64_MIN;
}

/* One entry per line: name and size. Equal listings mean nothing was written. */
static bool vr_listing(const char *dir, char *out, size_t cap)
{
    DIR *d = opendir(dir);
    size_t len = 0;
    out[0] = '\0';
    if (!d)
        return false;
    for (struct dirent *e = readdir(d); e; e = readdir(d)) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        struct stat st;
        char path[1100];
        snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        if (stat(path, &st) != 0)
            continue;
        int n = snprintf(out + len, cap - len, "%s:%lld;", e->d_name, (long long)st.st_size);
        if (n < 0 || (size_t)n >= cap - len)
            break;
        len += (size_t)n;
    }
    closedir(d);
    return true;
}

static bool vr_touch(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    return fd >= 0 && close(fd) == 0;
}

/* A sibling is outside the measured home; real entries remain observable. */
static int vr_listing_fixture(void)
{
    int failures = 0;
    char parent[512] = {0}, home[640], sibling[640], entry[800];
    char before[2048], after[2048];
    TEST_CASE("fleet_vitals_read: listing excludes navigation entries") {
        ASSERT(test_mkdtemp(parent, sizeof parent, "vitals_listing"));
        snprintf(home, sizeof home, "%s/home", parent);
        snprintf(sibling, sizeof sibling, "%s/sibling", parent);
        ASSERT(mkdir(home, 0700) == 0);
        ASSERT(vr_listing(home, before, sizeof before));
        ASSERT_STR_EQ(before, "");
        ASSERT(vr_touch(sibling));
        ASSERT(vr_listing(home, after, sizeof after));
        ASSERT_STR_EQ(after, before);
        snprintf(entry, sizeof entry, "%s/.visible", home);
        ASSERT(vr_touch(entry));
        ASSERT(vr_listing(home, after, sizeof after));
        ASSERT(strcmp(after, before) != 0);
        ASSERT_STR_EQ(after, ".visible:0;");
    } TEST_END
    if (parent[0]) test_rm_rf(parent);
    return failures;
}

static int vr_read_leaf(void)
{
    int failures = 0;
    char home[512] = {0}, before[2048], after[2048];
    char *prior = getenv("HOME") ? strdup(getenv("HOME")) : NULL;
    TEST_CASE("fleet_vitals_read: sane numbers and nothing written") {
        ASSERT(test_mkdtemp(home, sizeof(home), "fleet_vitals_read"));
        char marker[640];
        snprintf(marker, sizeof marker, "%s/keep", home);
        ASSERT(vr_touch(marker));
        ASSERT(setenv("HOME", home, 1) == 0);
        ASSERT(vr_listing(home, before, sizeof before));
        const struct zcl_command_registry *reg = zcl_command_catalog();
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(reg, "fleet.vitals.read", NULL);
        ASSERT(spec != NULL);
        struct zcl_command_context ctx = { .registry = reg,
                                           .granted_capabilities = ~(uint64_t)0,
                                           .authority_ceiling = ZCL_COMMAND_AUTH_OWNER };
        enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_OK;
        struct json_value input = {0}, root = {0};
        json_set_object(&input);
        size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input, false,
                                                     "fleet.vitals.read", "full", 0, 0, NULL,
                                                     g_vr_text, sizeof(g_vr_text), &exit_code);
        json_free(&input);
        ASSERT(n > 0 && n < sizeof(g_vr_text) && json_read(&root, g_vr_text, n));
        const struct json_value *ok = json_get(&root, "ok");
        ASSERT(ok && ok->type == JSON_BOOL && json_get_bool(ok));
        const struct json_value *d = json_get(&root, "data");
        ASSERT_STR_EQ(vr_str(d, "schema"), "zcl.fleet_vitals_read.v1");
        ASSERT(strlen(vr_str(d, "host")) <= 64);
        ASSERT(vr_int(d, "cpus") > 0);
        ASSERT(vr_int(d, "mem_total_mib") > 0);
        ASSERT(vr_int(d, "mem_used_mib") <= vr_int(d, "mem_total_mib"));
        ASSERT(vr_int(d, "disk_total_mib") > 0);
        ASSERT(vr_int(d, "disk_used_mib") <= vr_int(d, "disk_total_mib"));
        ASSERT(vr_int(d, "disk_free_mib") <= vr_int(d, "disk_total_mib"));
        ASSERT(vr_int(d, "load1_centi") >= 0);
        json_free(&root);
        ASSERT(vr_listing(home, after, sizeof after));
        ASSERT_STR_EQ(after, before);
    } TEST_END
    if (prior) {
        (void)setenv("HOME", prior, 1);
        free(prior);
    }
    if (home[0])
        test_rm_rf(home);
    return failures;
}

int test_fleet_vitals_read(void);
int test_fleet_vitals_read(void)
{
    int failures = vr_listing_fixture();
    failures += vr_read_leaf();
    if (failures == 0)
        printf("test_fleet_vitals_read: all passed\n");
    else
        printf("test_fleet_vitals_read: %d FAILED\n", failures);
    return failures;
}
