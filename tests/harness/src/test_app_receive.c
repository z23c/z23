/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* purpose: Exercise native owner receive confirmation without executing shared code. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"
#include "command/native_app_receive_command.h"
#include "command/native_app_confirm.h"
#include "command/native_command.h"
#include "command/native_zcode_package_bundle.h"
#include "command/native_zcode_package_copy.h"
#include "base/hex.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "plugin/plugin_pack.h"
#include "plugin/plugin_dist.h"
#include "vcs/package_prepare.h"
#include "vcs/package_release.h"
#include "vcs/vcs.h"
#include "util/file_tree_ops.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32) && defined(ZCL_TESTING)
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#define ABC_PATH 900
struct abc_world { char root[512], src[600]; };
static bool abc_put(const char *dir, const char *rel, const char *text)
{
    char path[ABC_PATH];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, rel);
    if (n < 0 || (size_t)n >= sizeof(path)) return false;
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    size_t len = strlen(text);
    bool written = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && written;
}

static const char k_makefile[] =
    "APP_CFLAGS = -std=c2x -O2 -Iinclude\n"
    ".PHONY: app print-app-closure\n"
    "print-app-closure:\n"
    "\t@printf '%s\\n' Makefile include/boost.h src/main.c\n"
    "app:\n"
    "\t@echo run >> $(APP_OUT)/../make-runs\n"
    "\tcc $(APP_CFLAGS) -MD -MF $(APP_OUT)/main.d -c src/main.c "
    "-o $(APP_OUT)/main.o\n"
    "\tcc -o $(APP_OUT)/app $(APP_OUT)/main.o\n";

static const char k_meta[] =
    "{\n  \"schema\": 1,\n  \"name\": \"stub/tinyapp\",\n"
    "  \"semver\": \"0.1.0\",\n  \"language\": \"c23\",\n"
    "  \"license\": \"Apache-2.0\",\n  \"include_dir\": \"include\",\n"
    "  \"source_dir\": \"src\",\n  \"dependencies\": []\n}\n";

static bool abc_license(const char *dir)
{
    char path[ABC_PATH];
    int n = snprintf(path, sizeof(path), "%s/LICENSE", dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return false;
    return zcl_tree_copy("apps/skycombat/LICENSE", path, 0, NULL, NULL).ok;
}

static const char k_main[] = "int main(void) { return 0; }\n";

static bool abc_stub_source(struct abc_world *w)
{
    static const char *const dirs[] = {"include", "src"};
    if (mkdir(w->src, 0700) != 0 || !abc_license(w->src)) return false;
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); ++i) {
        char dir[ABC_PATH];
        int n = snprintf(dir, sizeof(dir), "%s/%s", w->src, dirs[i]);
        if (n < 0 || (size_t)n >= sizeof(dir) || mkdir(dir, 0700) != 0) return false;
    }
    return abc_put(w->src, "zcode-package.json", k_meta) &&
           abc_put(w->src, "Makefile", k_makefile) &&
           abc_put(w->src, "include/boost.h", "#define BOOST 1\n") &&
           abc_put(w->src, "src/main.c", k_main);
}


struct receive_fixture {
    struct abc_world world;
    char datadir[900], destination[900], file[900], alternate[900], backup[900], key[900];
    char publisher[67], package[65], release[65];
};
static bool rt_bundle(struct receive_fixture *f, const char *output, uint64_t sequence)
{
    struct vcs_package_prepare_options options = {
        .dir = f->world.src, .publisher_sequence = sequence,
        .reward_address = "", .chain_id = "zclassic-main",
    };
    struct plugin_dist_published why;
    struct vcs_package_prepared prepared;
    vcs_package_prepared_init(&prepared);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t tree[32];
    char detail[256] = {0};
    bool ok = plugin_dist_release_key_sign(f->key, NULL, options.publisher_pubkey, NULL, &why) == PLUGIN_DIST_OK &&
        vcs_package_prepare(&options, &prepared, detail, sizeof(detail)) == VCS_PACKAGE_PREPARE_OK &&
        plugin_dist_release_key_sign(f->key, prepared.signing_digest,
            options.publisher_pubkey, prepared.release.signature, &why) == PLUGIN_DIST_OK &&
        vcs_package_release_serialize(&prepared.release, &wire, &wire_len) == VCS_PACKAGE_RELEASE_OK &&
        vcs_tree_capture_path(f->world.src, tree) == VCS_OK;
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.receive.v1");
    const struct zcl_package_bundle_wires wires = {
        .release = wire, .release_len = wire_len,
        .manifest = prepared.manifest_wire, .manifest_len = prepared.manifest_wire_len,
        .recipe = prepared.recipe_wire, .recipe_len = prepared.recipe_wire_len,
    };
    if (ok) ok = zcl_package_bundle_write(output, f->world.src, tree, &wires, &reply);
    if (ok && sequence == 1) {
        zcl_hex_encode(prepared.release.publisher_pubkey, 33, f->publisher);
        zcl_hex_encode(prepared.package_root, 32, f->package);
        zcl_hex_encode(prepared.signing_digest, 32, f->release);
    }
    zcl_command_reply_free(&reply);
    free(wire);
    vcs_package_prepared_free(&prepared);
    return ok;
}
static bool rt_setup(struct receive_fixture *f)
{
    memset(f, 0, sizeof(*f));
    if (!test_mkdtemp(f->world.root, sizeof(f->world.root), "app_receive")) return false;
    (void)snprintf(f->world.src, sizeof(f->world.src), "%s/source", f->world.root);
    (void)snprintf(f->datadir, sizeof(f->datadir), "%s/bob-data", f->world.root);
    (void)snprintf(f->destination, sizeof(f->destination), "%s/bob-copy", f->world.root);
    (void)snprintf(f->file, sizeof(f->file), "%s/first.z23share", f->world.root);
    (void)snprintf(f->alternate, sizeof(f->alternate), "%s/second.z23share", f->world.root);
    (void)snprintf(f->backup, sizeof(f->backup), "%s/first.saved", f->world.root);
    (void)snprintf(f->key, sizeof(f->key), "%s/sender.key", f->world.root);
    char publisher[PLUGIN_HEX_PUBLIC_KEY + 1];
    return abc_stub_source(&f->world) && plugin_keygen(f->key, publisher) == PLUGIN_OK &&
        rt_bundle(f, f->file, 1) &&
        abc_put(f->world.src, "src/main.c", "int main(void) { return 1; }\n") &&
        rt_bundle(f, f->alternate, 2);
}
enum rt_decision { RT_CANCEL, RT_CLOSE, RT_EARLY, RT_HEADLESS, RT_PAINT_FAIL,
    RT_CANCEL_AFTER, RT_CLOSE_AFTER, RT_STALE, RT_CONFIRM };
struct rt_presenter {
    struct receive_fixture *fixture;
    enum rt_decision decision;
    bool observed, visited, swapped;
};
static bool rt_absent(const struct receive_fixture *f);
static bool rt_action(const struct zcl_present_window_live_view_v1 *live,
    unsigned index, bool *close, bool *redraw)
{
    struct zcl_present_input_v1 input = {.key = ZCL_PRESENT_INPUT_TEXT, .character = '1' + index};
    uint32_t focus = UINT32_MAX, action = UINT32_MAX;
    if (!live->input(live->owner.context, &input, &focus, &action) || action != index) return false;
    struct zcl_present_window_event_v1 event = {.outcome = ZCL_PRESENT_WINDOW_ACTION, .action_index = action};
    live->owner.update(live->owner.context, &event, true, redraw, close);
    return true;
}
static bool rt_field(const struct zcl_present_model_v1 *m, const char *label, const char *expected)
{
    char actual[4400] = {0};
    size_t used = 0;
    bool found = false;
    for (uint32_t i = 0; i < m->item_count; ++i) {
        const char *text = m->items[i].value;
        if (!found) {
            if (strncmp(text, label, strlen(label))) continue;
            text += strlen(label); found = true;
        } else {
            if (strncmp(text, "  ", 2)) break;
            text += 2;
        }
        size_t len = strlen(text);
        if (len >= sizeof(actual) - used) return false;
        memcpy(actual + used, text, len + 1); used += len;
    }
    return found && !strcmp(actual, expected);
}
static bool rt_finish(struct rt_presenter *p, const struct zcl_present_window_live_view_v1 *live)
{
    bool close = false, redraw = false;
    if (p->decision == RT_STALE) {
        if (rename(p->fixture->file, p->fixture->backup)) return false;
        p->swapped = true;
        if (rename(p->fixture->alternate, p->fixture->file)) return false;
    }
    if (!rt_action(live, 3, &close, &redraw) || !close) return false;
    if (p->decision == RT_CANCEL_AFTER) return rt_action(live, 0, &close, &redraw) && close;
    if (p->decision == RT_CLOSE_AFTER) {
        struct zcl_present_window_event_v1 event = {.outcome = ZCL_PRESENT_WINDOW_DISMISSED};
        live->owner.update(live->owner.context, &event, true, &redraw, &close);
    }
    return p->decision != RT_PAINT_FAIL;
}
static bool rt_observe(struct rt_presenter *p, const struct zcl_present_model_v1 *m,
    const struct zcl_present_window_pages_v1 *pages, uint32_t *count, char *why, size_t cap)
{
    return pages && pages->page_count == 1 && pages->pages->pixels &&
        zcl_present_model_page_count_v1(m, count, why, cap) && *count > 1 &&
        rt_field(m, "Publisher: ", p->fixture->publisher) &&
        rt_field(m, "Release: ", p->fixture->release) &&
        rt_field(m, "Package: ", p->fixture->package) &&
        rt_field(m, "Destination: ", p->fixture->destination) &&
        rt_field(m, "Parent release: ", "None (first release)") &&
        rt_field(m, "Changes: ", "No parent to compare");
}
static bool rt_present(void *context, const struct zcl_present_model_v1 *m,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    struct rt_presenter *p = context;
    uint32_t count = 0;
    p->observed = rt_observe(p, m, pages, &count, why, cap);
    if (!p->observed || !rt_absent(p->fixture) || p->decision == RT_HEADLESS) return false;
    bool close = false, redraw = false;
    if (p->decision == RT_CANCEL) return rt_action(live, 0, &close, &redraw) && close;
    if (p->decision == RT_CLOSE) {
        struct zcl_present_window_event_v1 event = {.outcome = ZCL_PRESENT_WINDOW_DISMISSED};
        live->owner.update(live->owner.context, &event, true, &redraw, &close);
        return close;
    }
    if (!rt_action(live, 3, &close, &redraw) || close) return false;
    if (p->decision == RT_EARLY) return true;
    for (uint32_t i = 1; i < count; ++i)
        if (!rt_action(live, 2, &close, &redraw) || close || !redraw) return false;
    p->visited = true;
    return rt_finish(p, live);
}
static bool rt_input(struct json_value *input, const struct receive_fixture *f)
{
    json_init(input); json_set_object(input);
    return json_push_kv_str(input, "file", f->file) &&
        json_push_kv_str(input, "datadir", f->datadir) &&
        json_push_kv_str(input, "destination", f->destination) &&
        json_push_kv_int(input, "day", 20400);
}
static bool rt_absent(const struct receive_fixture *f)
{
    struct stat st;
    return lstat(f->destination, &st) != 0 && errno == ENOENT &&
        lstat(f->datadir, &st) != 0 && errno == ENOENT;
}
static bool rt_failed_with(const struct zcl_command_reply *reply, const char *code)
{
    return reply->status != ZCL_COMMAND_STATUS_PASSED && !strcmp(reply->error.code, code);
}
static bool rt_expected_reply(const struct rt_presenter *p, const struct zcl_command_reply *reply)
{
    if (p->decision == RT_HEADLESS || p->decision == RT_PAINT_FAIL)
        return rt_failed_with(reply, "CONFIRMATION_UNAVAILABLE");
    if (p->decision == RT_STALE) return rt_failed_with(reply, "PLAN_MISMATCH");
    if (p->decision == RT_CONFIRM)
        return p->visited && reply->status == ZCL_COMMAND_STATUS_PASSED && reply->error.mutated;
    const char *status = json_get_str(json_get(&reply->data, "status"));
    return reply->status == ZCL_COMMAND_STATUS_PASSED && status && !strcmp(status, "canceled");
}
static bool rt_attempt(struct receive_fixture *f, enum rt_decision decision)
{
    struct json_value input;
    json_init(&input);
    if (!rt_input(&input, f)) { json_free(&input); return false; }
    struct zcl_command_request request = {.input = &input};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.app_receive.v1");
    struct rt_presenter p = {.fixture = f, .decision = decision};
    zcl_test_app_receive_run(&request, &reply, rt_present, &p);
    bool ok = p.observed && rt_expected_reply(&p, &reply);
    if (decision != RT_CONFIRM) ok = ok && !reply.error.mutated && rt_absent(f);
    if (p.swapped) {
        if (rename(f->file, f->alternate) || rename(f->backup, f->file)) ok = false;
    }
    zcl_command_reply_free(&reply); json_free(&input);
    return ok;
}
static bool rt_received_trust(const struct receive_fixture *f, const struct zcl_package_copy *copy)
{
    struct zcl_package_receive_trust trust;
    uint8_t root[32], publisher[33];
    return zcl_hex_decode_lower(f->release, root, 32) &&
        !memcmp(copy->parent_release, root, 32) &&
        zcl_package_receive_trust_read(f->datadir, copy->fork_version, root, &trust) &&
        zcl_hex_decode_lower(f->publisher, publisher, 33) && !memcmp(trust.publisher, publisher, 33) &&
        zcl_hex_decode_lower(f->package, root, 32) && !memcmp(trust.package_root, root, 32);
}
static bool rt_received_source(const struct receive_fixture *f, bool ok)
{
    char path[1000], bytes[128];
    int n = snprintf(path, sizeof(path), "%s/src/main.c", f->destination);
    FILE *file = n > 0 && (size_t)n < sizeof(path) ? fopen(path, "rb") : NULL;
    size_t got = file ? fread(bytes, 1, sizeof(bytes), file) : 0;
    ok = ok && file && !ferror(file) && got == strlen(k_main) && !memcmp(bytes, k_main, got);
    if (file && fclose(file)) ok = false;
    return ok;
}
static bool rt_received(const struct receive_fixture *f)
{
    struct zcl_package_copy copy;
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.receive.v1");
    bool opened = zcl_package_copy_open_selected_as(f->destination, ZCL_PACKAGE_COPY_READ,
        &copy, &reply, "test", NULL);
    bool ok = opened && rt_received_trust(f, &copy);
    if (opened) zcl_package_copy_close(&copy);
    ok = rt_received_source(f, ok);
    zcl_command_reply_free(&reply);
    return ok;
}
/* File-only defaults use the command binding, never the sender's identity.
 * All artifacts and HOME are isolated; existing explicit-path cases remain. */
enum rd_change { RD_UNCHANGED, RD_COLLISION, RD_PARENT_LINK };
struct rd_presenter { struct rt_presenter native; enum rd_change change; };
static bool rd_absent_path(const char *path)
{
    struct stat st;
    return lstat(path, &st) != 0 && errno == ENOENT;
}
static bool rd_no_extra_effects(const struct receive_fixture *f)
{
    static const char *const names[] = {"bob-home/.z23/zcode_publisher.key", "bob-home/.config", "make-runs", "unused-binding"};
    for (size_t i = 0; i < sizeof(names)/sizeof(names[0]); ++i) {
        char path[1100];
        int n = snprintf(path, sizeof(path), "%s/%s", f->world.root, names[i]);
        if (n <= 0 || (size_t)n >= sizeof(path) || !rd_absent_path(path)) return false;
    }
    return true;
}
static bool rd_collision(struct receive_fixture *f)
{
    char parent[1100];
    int n = snprintf(parent, sizeof(parent), "%s/copies", f->datadir);
    return n > 0 && (size_t)n < sizeof(parent) && mkdir(f->datadir, 0700) == 0 &&
        mkdir(parent, 0700) == 0 && mkdir(f->destination, 0700) == 0;
}
static bool rd_present(void *context, const struct zcl_present_model_v1 *m,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    struct rd_presenter *p = context;
    if (!rt_present(&p->native, m, pages, live, why, cap)) return false;
    if (p->change == RD_COLLISION) return rd_collision(p->native.fixture);
    if (p->change == RD_PARENT_LINK)
        return symlink(p->native.fixture->world.src, p->native.fixture->datadir) == 0;
    return true;
}
static bool rd_invoke(struct receive_fixture *f, struct json_value *args,
    struct rd_presenter *p, struct zcl_command_reply *reply)
{
    const char *home = getenv("HOME");
    char *old_home = home ? strdup(home) : NULL;
    const char *bound = zcl_native_command_datadir();
    char *old_dir = strdup(bound ? bound : "");
    int port = zcl_native_command_rpc_port();
    char private_home[1100], unused_binding[1100];
    int n = snprintf(private_home, sizeof(private_home), "%s/bob-home", f->world.root);
    bool ok = old_dir && (!home || old_home) && n > 0 && (size_t)n < sizeof(private_home);
    int b = snprintf(unused_binding, sizeof(unused_binding), "%s/unused-binding", f->world.root);
    ok = ok && b > 0 && (size_t)b < sizeof(unused_binding);
    if (ok) ok = setenv("HOME", private_home, 1) == 0;
    if (ok) {
        zcl_native_bridge_bind_rpc(json_get(args, "datadir") ? unused_binding : f->datadir, 0);
        struct zcl_command_request request = {.input = args};
        zcl_test_app_receive_run(&request, reply, rd_present, p);
        zcl_native_bridge_bind_rpc(old_dir, port);
        int restored = home ? setenv("HOME", old_home, 1) : unsetenv("HOME");
        ok = restored == 0;
    }
    free(old_dir); free(old_home); return ok;
}
static bool rd_setup(struct receive_fixture *f, bool explicit_destination)
{
    if (!rt_setup(f)) return false;
    char root[PATH_MAX];
    if (!realpath(f->world.root, root)) return false;
    int n = snprintf(f->datadir, sizeof(f->datadir), "%s/bob-data", root);
    if (n <= 0 || (size_t)n >= sizeof(f->datadir)) return false;
    n = snprintf(f->destination, sizeof(f->destination), "%s/%s", root,
        explicit_destination ? "bob-copy" : "bob-data/copies/tinyapp-1");
    return n > 0 && (size_t)n < sizeof(f->destination);
}
static bool rd_args(struct json_value *args, const struct receive_fixture *f, unsigned overrides)
{
    json_init(args); json_set_object(args);
    return json_push_kv_str(args, "file", f->file) &&
        (!(overrides & 1u) || json_push_kv_str(args, "datadir", f->datadir)) &&
        (!(overrides & 2u) || json_push_kv_str(args, "destination", f->destination));
}
static bool rd_home_setup(struct receive_fixture *f)
{
    if (!rd_setup(f, false)) return false;
    char root[PATH_MAX], home[PATH_MAX];
    if (!realpath(f->world.root, root)) return false;
    int n = snprintf(home, sizeof(home), "%s/bob-home", root);
    if (n <= 0 || (size_t)n >= sizeof(home) || mkdir(home, 0755) != 0 || chmod(home, 0755) != 0) return false;
    n = snprintf(f->datadir, sizeof(f->datadir), "%s/.z23", home);
    if (n <= 0 || (size_t)n >= sizeof(f->datadir)) return false;
    n = snprintf(f->destination, sizeof(f->destination), "%s/copies/tinyapp-1", f->datadir);
    return n > 0 && (size_t)n < sizeof(f->destination);
}
static bool rd_home_mode(const struct receive_fixture *f, mode_t mode)
{
    char home[1100]; struct stat info;
    int n = snprintf(home, sizeof(home), "%s/bob-home", f->world.root);
    return n > 0 && (size_t)n < sizeof(home) && lstat(home, &info) == 0 &&
        S_ISDIR(info.st_mode) && (info.st_mode & 0777) == mode;
}
static bool rd_collision_refused(const struct receive_fixture *f, const struct zcl_command_reply *reply)
{
    char second[1100], trust[1100]; struct stat st;
    (void)snprintf(second, sizeof(second), "%s/copies/tinyapp-2", f->datadir);
    (void)snprintf(trust, sizeof(trust), "%s/zcode", f->datadir);
    return rt_failed_with(reply, "DESTINATION_EXISTS") && !reply->error.mutated &&
        lstat(f->destination, &st) == 0 && S_ISDIR(st.st_mode) &&
        rd_absent_path(second) && rd_absent_path(trust);
}
static bool rd_result(struct receive_fixture *f, struct rd_presenter *p,
    const struct zcl_command_reply *reply)
{
    if (!p->native.observed || !rd_no_extra_effects(f)) return false;
    if (p->change == RD_COLLISION) return rd_collision_refused(f, reply);
    if (p->change == RD_PARENT_LINK) {
        char copies[1100]; (void)snprintf(copies, sizeof(copies), "%s/copies", f->world.src);
        return rt_failed_with(reply, "UNSAFE_RECEIVE_PARENT") && !reply->error.mutated && rd_absent_path(copies);
    }
    if (!rt_expected_reply(&p->native, reply)) return false;
    if (p->native.decision != RT_CONFIRM) return !reply->error.mutated && rt_absent(f);
    const struct json_value *executed = json_get(&reply->data, "executed");
    const char *destination = zcl_package_copy_str(&reply->data, "destination");
    return executed && executed->type == JSON_BOOL && !json_get_bool(executed) &&
        destination && !strcmp(destination, f->destination) && rt_received(f);
}
static bool rd_attempt(struct receive_fixture *f, enum rt_decision decision,
    unsigned overrides, enum rd_change change)
{
    struct json_value args; struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.app_receive.v1");
    struct rd_presenter p = {.native = {.fixture = f, .decision = decision}, .change = change};
    bool ok = rd_args(&args, f, overrides);
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), "app.receive", NULL);
    char why[256];
    ok = ok && spec && zcl_command_registry_input_validate(spec, &args, why, sizeof(why));
    ok = ok && rd_invoke(f, &args, &p, &reply) && rd_result(f, &p, &reply);
    if (!ok) printf("file-only receive: decision=%d overrides=%u observed=%d code=%s message=%s\n",
        decision, overrides, p.native.observed, reply.error.code, reply.error.message);
    if (p.native.swapped && (rename(f->file, f->alternate) || rename(f->backup, f->file))) ok = false;
    zcl_command_reply_free(&reply); json_free(&args); return ok;
}
static int rd_defaults(void)
{
    int failures = 0; struct receive_fixture f;
    TEST("file-only receive plans first use without writes and confirms the frozen default path") {
        ASSERT(rd_home_setup(&f));
        for (enum rt_decision d = RT_CANCEL; d < RT_CONFIRM; ++d) {
            ASSERT(rd_attempt(&f, d, 0, RD_UNCHANGED));
            ASSERT(rd_home_mode(&f, 0755));
        }
        ASSERT(rd_attempt(&f, RT_CONFIRM, 0, RD_UNCHANGED));
        ASSERT(rd_home_mode(&f, 0755));
        struct stat info;
        ASSERT(lstat(f.datadir, &info) == 0 && S_ISDIR(info.st_mode) && (info.st_mode & 0777) == 0700);
        PASS();
    } _test_next:;
    return failures;
}
static int rd_overrides(void)
{
    int failures = 0; struct receive_fixture f;
    TEST("receive accepts independent path overrides and never repicks after displayed collision") {
        for (unsigned overrides = 1; overrides <= 3; ++overrides) {
            ASSERT(rd_setup(&f, (overrides & 2u) != 0));
            ASSERT(rd_attempt(&f, RT_CONFIRM, overrides, RD_UNCHANGED));
        }
        ASSERT(rd_setup(&f, false));
        ASSERT(rd_attempt(&f, RT_CONFIRM, 0, RD_COLLISION));
        ASSERT(rd_setup(&f, false));
        ASSERT(rd_attempt(&f, RT_CONFIRM, 0, RD_PARENT_LINK));
        PASS();
    } _test_next:;
    return failures;
}
static bool rd_refused(struct receive_fixture *f, struct json_value *args, const char *code)
{
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_receive.v1");
    struct rd_presenter p = {.native = {.fixture = f, .decision = RT_CONFIRM}};
    bool ok = rd_invoke(f, args, &p, &reply) && !p.native.observed &&
        rt_failed_with(&reply, code) && !reply.error.mutated && rd_no_extra_effects(f);
    if (!ok) printf("file-only refusal: want=%s actual=%s observed=%d\n", code, reply.error.code, p.native.observed);
    zcl_command_reply_free(&reply); return ok;
}
static bool rd_bad_input(struct receive_fixture *f, const char *tail)
{
    char wire[2200];
    int n = snprintf(wire, sizeof(wire), "{\"file\":\"%s\",%s}", f->file, tail);
    struct json_value args; json_init(&args);
    bool ok = n > 0 && (size_t)n < sizeof(wire) && json_read(&args, wire, (size_t)n) &&
        rd_refused(f, &args, "BAD_INPUT") && rt_absent(f);
    json_free(&args); return ok;
}
static int rd_inputs(void)
{
    int failures = 0; struct receive_fixture f;
    static const char *const bad[] = {"\"datadir\":null", "\"datadir\":\"\"", "\"datadir\":\"relative\"",
        "\"destination\":false", "\"destination\":\"\"", "\"destination\":\"relative\"",
        "\"confirm\":true", "\"trust_publisher\":\"x\"", "\"trust_root\":\"x\"",
        "\"file\":\"/duplicate\"", "\"day\":-1", "\"day\":false"};
    TEST("file-only receive rejects malformed and injected authority instead of defaulting it") {
        ASSERT(rd_setup(&f, false));
        for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i) ASSERT(rd_bad_input(&f, bad[i]));
        struct json_value args; json_init(&args); json_set_object(&args);
        bool missing = rd_refused(&f, &args, "BAD_INPUT") && rt_absent(&f);
        json_free(&args); ASSERT(missing);
        PASS();
    } _test_next:;
    return failures;
}
/* The default parent is an admission boundary even when pick_name reports
 * ENOTDIR as missing. Existing symlinks, files and permissive dirs refuse. */
static bool rd_unsafe(struct receive_fixture *f, unsigned which)
{
    char path[1100];
    (void)snprintf(path, sizeof(path), "%s/copies", f->datadir);
    if (which == 0) return symlink(f->world.src, f->datadir) == 0;
    if (which == 1) return abc_put(f->world.root, "bob-data", "not a directory\n");
    if (mkdir(f->datadir, 0700)) return false;
    if (which == 2) return chmod(f->datadir, 0777) == 0;
    return symlink(f->world.src, path) == 0;
}
static int rd_parents(void)
{
    int failures = 0; struct receive_fixture f;
    TEST("default receive refuses unsafe parents without following links or creating trust") {
        for (unsigned which = 0; which < 4; ++which) {
            ASSERT(rd_setup(&f, false)); ASSERT(rd_unsafe(&f, which));
            struct json_value args; bool built = rd_args(&args, &f, 0);
            bool refused = built && rd_refused(&f, &args, "UNSAFE_RECEIVE_PARENT");
            json_free(&args); ASSERT(refused);
            char trust[1100]; (void)snprintf(trust, sizeof(trust), "%s/zcode", f.world.src);
            ASSERT(rd_absent_path(trust));
        }
        PASS();
    } _test_next:;
    return failures;
}

static bool rd_home_refused(struct receive_fixture *f)
{
    struct json_value args;
    bool ok = rd_args(&args, f, 0) && rd_refused(f, &args, "UNSAFE_RECEIVE_PARENT");
    char child[1100];
    int n = snprintf(child, sizeof(child), "%s/bob-home/.z23", f->world.root);
    ok = ok && n > 0 && (size_t)n < sizeof(child) && rd_absent_path(child);
    json_free(&args); return ok;
}
static int rd_home_permissions(void)
{
    int failures = 0; struct receive_fixture f;
    static const mode_t modes[] = {0775, 0777};
    TEST("file-only first use refuses group/world writable HOME without creating datadir") {
        for (size_t i = 0; i < sizeof(modes)/sizeof(modes[0]); ++i) {
            ASSERT(rd_home_setup(&f));
            char home[1100]; int n = snprintf(home, sizeof(home), "%s/bob-home", f.world.root);
            ASSERT(n > 0 && (size_t)n < sizeof(home) && chmod(home, modes[i]) == 0);
            ASSERT(rd_home_refused(&f) && rd_home_mode(&f, modes[i]));
        }
        PASS();
    } _test_next:;
    return failures;
}
static bool rd_alias_datadir(struct receive_fixture *f, unsigned which)
{
    char home[1100], link[1100];
    int n = snprintf(home, sizeof(home), "%s/bob-home", f->world.root);
    int m = snprintf(link, sizeof(link), "%s/home-alias", f->world.root);
    if (n <= 0 || (size_t)n >= sizeof(home) || m <= 0 || (size_t)m >= sizeof(link)) return false;
    if (which == 1 && symlink(home, link) != 0) return false;
    const char *base = which == 1 ? link : home;
    const char *suffix = which == 0 ? "./.z23" : which == 1 ? ".z23" : ".z23/bad:leaf";
    n = snprintf(f->datadir, sizeof(f->datadir), "%s/%s", base, suffix);
    return n > 0 && (size_t)n < sizeof(f->datadir);
}
static int rd_home_aliases(void)
{
    int failures = 0; struct receive_fixture f;
    TEST("default path aliases refuse explicitly and every missing component is checked before writes") {
        for (unsigned which = 0; which < 3; ++which) {
            ASSERT(rd_home_setup(&f) && rd_alias_datadir(&f, which));
            ASSERT(rd_home_refused(&f) && rd_home_mode(&f, 0755));
        }
        PASS();
    } _test_next:;
    return failures;
}

int test_app_receive(void)
{
    int failures = 0;
    struct receive_fixture f;
    TEST("app.receive requires all-page native confirmation and rechecks the exact signed file") {
        ASSERT(rt_setup(&f));
        for (enum rt_decision d = RT_CANCEL; d < RT_CONFIRM; ++d)
            ASSERT(rt_attempt(&f, d));
        ASSERT(rt_attempt(&f, RT_CONFIRM));
        ASSERT(rt_received(&f));
        PASS();
    } _test_next:;
    failures += rd_defaults();
    failures += rd_overrides();
    failures += rd_inputs();
    failures += rd_parents();
    failures += rd_home_permissions();
    failures += rd_home_aliases();
    /* Native harness owns fixture retirement; preserve failed state for diagnosis. */
    return failures;
}
/* Real Linux native window, over the actual stdio MCP adapter. No package
 * code is executed. Display/processes belong exclusively to this fixture. */
#if defined(__linux__) && defined(ZCL_TESTING)
#include "command/native_app_launch.h"
#include "platform/process_lifecycle.h"
#include "platform/time_compat.h"
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <dirent.h>
#include <signal.h>
#include <sys/wait.h>

struct ru_child {
    pid_t pid;
    uint64_t token;
    char before[APP_LAUNCH_PATH_MAX], image[PATH_MAX];
};
struct ru_env { const char *key; char *saved; };
struct ru_run {
    struct ru_child display, server, driver;
    int input, output;
    char display_name[32], driver_image[PATH_MAX], line[65536];
    const struct receive_fixture *fixture;
    bool file_only;
};
static bool ru_pipe(int fd[2])
{
    if (pipe(fd) != 0) return false;
    if (fcntl(fd[0], F_SETFD, FD_CLOEXEC) == 0 && fcntl(fd[1], F_SETFD, FD_CLOEXEC) == 0) return true;
    close(fd[0]); close(fd[1]); return false;
}
static bool ru_read_line(int fd, char *out, size_t cap, int timeout)
{
    size_t used = 0;
    int64_t end = platform_time_monotonic_ms() + timeout;
    while (used + 1 < cap) {
        int64_t left = end - platform_time_monotonic_ms();
        if (left <= 0) return false;
        struct pollfd p = {.fd = fd, .events = POLLIN};
        int ready = poll(&p, 1, (int)left);
        if (ready < 0 && errno == EINTR) continue;
        char c;
        if (ready <= 0 || read(fd, &c, 1) != 1) return false;
        if (c == '\n') { out[used] = 0; return true; }
        out[used++] = c;
    }
    return false;
}
static bool ru_write(int fd, const char *text)
{
    size_t len = strlen(text), at = 0;
    int64_t end = platform_time_monotonic_ms() + 5000;
    while (at < len) {
        int64_t left = end - platform_time_monotonic_ms();
        if (left <= 0) return false;
        struct pollfd p = {.fd = fd, .events = POLLOUT};
        int ready = poll(&p, 1, (int)left);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return false;
        ssize_t n = write(fd, text + at, len - at);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0) return false;
        at += (size_t)n;
    }
    return true;
}
/* The fork child blocks before exec until its start token and inherited
 * harness executable are observed. Fast driver exits retain direct-child
 * custody, without pretending a post-exec /proc observation occurred. */
static void ru_exec(const char *const *argv, int in, int out, int err, int gate)
{
    char go = 0;
    if (read(gate, &go, 1) != 1 || go != 'G') _exit(126);
    close(gate);
    if (dup2(in, 0) < 0 || dup2(out, 1) < 0 || dup2(err, 2) < 0) _exit(126);
    execv(argv[0], (char *const *)argv);
    _exit(127);
}
static bool ru_spawn(struct ru_child *c, const char *const *argv, int in, int out, int err)
{
    int gate[2];
    if (!realpath(argv[0], c->image) || !ru_pipe(gate)) return false;
    c->pid = fork();
    if (c->pid == 0) { close(gate[1]); ru_exec(argv, in, out, err, gate[0]); }
    close(gate[0]);
    bool pinned = c->pid > 1 && app_proc_identity(c->pid, c->before, &c->token) && c->token;
    bool sent = pinned && write(gate[1], "G", 1) == 1;
    close(gate[1]);
    return sent;
}
/* Identity failure may reap a zombie internally; ECHILD is accepted only for
 * this retained direct child, never for unrelated or adopted grandchildren. */
static bool ru_matches(struct ru_child *c)
{
    char exe[APP_LAUNCH_PATH_MAX]; uint64_t token = 0;
    return app_proc_identity(c->pid, exe, &token) && token == c->token &&
        (!strcmp(exe, c->image) || !strcmp(exe, c->before));
}
static enum platform_process_wait_result ru_wait(struct ru_child *c, unsigned ms, uint32_t *code)
{
    if (c->pid <= 1) return PLATFORM_PROCESS_WAIT_EXITED;
    struct platform_process p; platform_process_init(&p);
    p.native = (uintptr_t)c->pid; p.pid = (uint64_t)c->pid;
    enum platform_process_wait_result rc = platform_process_wait(&p, ms, code);
    if (rc == PLATFORM_PROCESS_WAIT_EXITED) c->pid = -1;
    return rc;
}
static bool ru_reaped_identity_failure(struct ru_child *c)
{
    pid_t done;
    do { done = waitpid(c->pid, NULL, WNOHANG); } while (done < 0 && errno == EINTR);
    if (done == c->pid || (done < 0 && errno == ECHILD)) { c->pid = -1; return true; }
    return false;
}
static bool ru_stop(struct ru_child *c)
{
    if (c->pid <= 1) return true;
    enum platform_process_wait_result rc = ru_wait(c, c->token ? 0 : 2000, NULL);
    if (rc == PLATFORM_PROCESS_WAIT_EXITED) return true;
    if (rc != PLATFORM_PROCESS_WAIT_RUNNING) return ru_reaped_identity_failure(c);
    const int signals[] = {SIGTERM, SIGKILL};
    for (size_t i = 0; i < 2; ++i) {
        if (!ru_matches(c)) return ru_reaped_identity_failure(c);
        if (kill(c->pid, signals[i]) != 0 && errno != ESRCH) return false;
        rc = ru_wait(c, 2000, NULL);
        if (rc == PLATFORM_PROCESS_WAIT_EXITED) return true;
        if (rc != PLATFORM_PROCESS_WAIT_RUNNING) return ru_reaped_identity_failure(c);
    }
    return false;
}
static bool ru_image_live(struct ru_child *c)
{
    char exe[APP_LAUNCH_PATH_MAX]; uint64_t token = 0;
    return app_proc_identity(c->pid, exe, &token) && token == c->token && !strcmp(exe, c->image);
}
static int ru_log(const struct ru_run *r, const char *name)
{
    char path[1100];
    int n = snprintf(path, sizeof(path), "%s/%s", r->fixture->world.root, name);
    return n > 0 && (size_t)n < sizeof(path) ? open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600) : -1;
}
static bool ru_xvfb(struct ru_run *r)
{
    int fd[2];
    if (!ru_pipe(fd)) return false;
    int log = ru_log(r, "native-window-xvfb.log");
    /* Xvfb writes displayfd on stdout, which is the private readiness pipe. */
    const char *argv[] = {"/usr/bin/Xvfb", "-displayfd", "1", "-nolisten", "tcp",
        "-screen", "0", "1280x800x24", NULL};
    bool ok = log >= 0 && ru_spawn(&r->display, argv, log, fd[1], log);
    close(fd[1]); if (log >= 0) close(log);
    char number[12];
    ok = ok && ru_read_line(fd[0], number, sizeof(number), 15000);
    close(fd[0]);
    if (!ok || !number[0]) return false;
    for (const char *p = number; *p; ++p) if (*p < '0' || *p > '9') return false;
    int n = snprintf(r->display_name, sizeof(r->display_name), ":%s", number);
    return n > 0 && (size_t)n < sizeof(r->display_name) && ru_image_live(&r->display) &&
        setenv("DISPLAY", r->display_name, 1) == 0 && unsetenv("WAYLAND_DISPLAY") == 0;
}
static bool ru_server(struct ru_run *r)
{
    int in[2], out[2]; char image[PATH_MAX];
    if (!realpath("build/bin/z23-dev", image) || !ru_pipe(in)) return false;
    if (!ru_pipe(out)) { close(in[0]); close(in[1]); return false; }
    int log = ru_log(r, "native-window-mcp.log");
    char binding[sizeof(r->fixture->datadir) + 16];
    int n = snprintf(binding, sizeof(binding), "--datadir=%s", r->fixture->datadir);
    const char *argv[] = {image, "mcp", "serve", r->file_only ? binding : NULL, NULL};
    bool ok = n > 0 && (size_t)n < sizeof(binding) && log >= 0 &&
        ru_spawn(&r->server, argv, in[0], out[1], log);
    close(in[0]); close(out[1]); if (log >= 0) close(log);
    r->input = in[1]; r->output = out[0];
    return ok && fcntl(r->input, F_SETFL, O_NONBLOCK) == 0;
}
static bool ru_initialize(struct ru_run *r)
{
    static const char init[] = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"receive-window-test\",\"version\":\"1\"}}}\n";
    if (!ru_write(r->input, init) || !ru_read_line(r->output, r->line, sizeof(r->line), 15000)) return false;
    struct json_value doc; json_init(&doc);
    bool ok = json_read(&doc, r->line, strlen(r->line)) && json_get(json_get(&doc, "result"), "serverInfo");
    json_free(&doc);
    return ok && ru_image_live(&r->server) && ru_write(r->input,
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n");
}
static bool ru_request_fields(const struct ru_run *r, int id,
    struct json_value *args, struct json_value *params, struct json_value *req)
{
    const struct receive_fixture *f = r->fixture;
    bool ok = json_push_kv_str(args, "file", f->file);
    if (!r->file_only) ok = ok && json_push_kv_str(args, "datadir", f->datadir) &&
        json_push_kv_str(args, "destination", f->destination);
    ok = ok && json_push_kv_str(params, "name", "apps_receive") && json_push_kv(params, "arguments", args);
    return ok && json_push_kv_str(req, "jsonrpc", "2.0") && json_push_kv_int(req, "id", id) &&
        json_push_kv_str(req, "method", "tools/call") && json_push_kv(req, "params", params);
}
static bool ru_request(struct ru_run *r, int id)
{
    struct json_value args, params, req;
    json_init(&args); json_init(&params); json_init(&req);
    json_set_object(&args); json_set_object(&params); json_set_object(&req);
    bool ok = ru_request_fields(r, id, &args, &params, &req);
    char wire[8192]; size_t n = ok ? json_write(&req, wire, sizeof(wire) - 1) : 0;
    if (n && n < sizeof(wire) - 1) { wire[n++] = '\n'; wire[n] = 0; ok = ru_write(r->input, wire); }
    else ok = false;
    json_free(&req); json_free(&params); json_free(&args); return ok;
}
static bool ru_driver(struct ru_run *r, const char *action, bool pixels)
{
    int log = ru_log(r, "native-window-driver.log");
    const char *argv[] = {r->driver_image, "--title=Receive this app copy?", action,
        "--timeout-ms=5000", pixels ? "--expect-pixels-change" : NULL, NULL};
    bool ok = log >= 0 && ru_spawn(&r->driver, argv, log, log, log);
    if (log >= 0) close(log);
    uint32_t code = UINT32_MAX;
    ok = ok && ru_wait(&r->driver, 7000, &code) == PLATFORM_PROCESS_WAIT_EXITED && code == 0;
    bool stopped = ru_stop(&r->driver);
    return ok && stopped;
}
/* The title is unique on this fixture's display; no shared desktop is ever
 * addressed. Driver count checks bracket all physical keyboard actions. */
static bool ru_window(struct ru_run *r, bool exists)
{
    return ru_driver(r, exists ? "--expect-count=1" : "--expect-count=0", false);
}
/* Before consent, the 0755 operator HOME remains empty and unchanged; it is
 * distinct from the missing private app datadir beneath it. */
static bool ru_home_unchanged(const struct ru_run *r)
{
    if (!r->file_only) return true;
    const char *home = getenv("HOME"); struct stat st;
    if (!home || lstat(home, &st) != 0 || !S_ISDIR(st.st_mode) || (st.st_mode & 0777) != 0755) return false;
    DIR *dir = opendir(home);
    if (!dir) return false;
    bool empty = true; struct dirent *entry;
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) { empty = false; break; }
    }
    bool ok = empty && errno == 0;
    return closedir(dir) == 0 && ok;
}
static bool ru_pending(struct ru_run *r)
{
    struct pollfd p = {.fd = r->output, .events = POLLIN};
    int rc; do { rc = poll(&p, 1, 0); } while (rc < 0 && errno == EINTR);
    return rc == 0 && ru_image_live(&r->server) && rt_absent(r->fixture) && ru_home_unchanged(r);
}
static bool ru_pages(struct ru_run *r, uint32_t count)
{
    /* Live input starts unfocused; first Tab selects Cancel=0. */
    if (!ru_driver(r, "--key=tab", true)) return false;
    /* Three more Tabs reach Confirm=3. */
    for (unsigned i = 0; i < 3; ++i) if (!ru_driver(r, "--key=tab", true)) return false;
    if (!ru_driver(r, "--key=enter", false) || !ru_window(r, true) || !ru_pending(r)) return false;
    /* From Confirm, wrap Cancel -> Back -> Next. Enter keeps Next focus. */
    for (unsigned i = 0; i < 3; ++i) if (!ru_driver(r, "--key=tab", true)) return false;
    for (uint32_t page = 1; page < count; ++page)
        if (!ru_driver(r, "--key=enter", true) || !ru_pending(r)) return false;
    return ru_driver(r, "--key=tab", true) && ru_driver(r, "--key=enter", false);
}
static const char *ru_string(const struct json_value *d, const char *key)
{
    const char *s = json_get_str(json_get(d, key)); return s ? s : "";
}
static bool ru_directory_mode(const char *path, mode_t mode)
{
    struct stat st;
    return path && lstat(path, &st) == 0 && S_ISDIR(st.st_mode) &&
        (st.st_mode & 07777) == mode;
}
static bool ru_committed_modes(const struct ru_run *r)
{
    if (!r->file_only) return true;
    char copies[sizeof(r->fixture->datadir) + 16];
    int n = snprintf(copies, sizeof(copies), "%s/copies", r->fixture->datadir);
    return n > 0 && (size_t)n < sizeof(copies) &&
        ru_directory_mode(getenv("HOME"), 0755) &&
        ru_directory_mode(r->fixture->datadir, 0700) && ru_directory_mode(copies, 0700);
}
static bool ru_commit_data(const struct ru_run *r, const struct json_value *d)
{
    const struct receive_fixture *f = r->fixture;
    const struct json_value *executed = json_get(d, "executed");
    return executed && executed->type == JSON_BOOL && !json_get_bool(executed) &&
        !strcmp(ru_string(d, "stage"), "commit") &&
        !strcmp(ru_string(d, "release_id"), f->release) && !strcmp(ru_string(d, "package_root"), f->package) &&
        !strcmp(ru_string(d, "publisher_fingerprint"), f->publisher) &&
        !strcmp(ru_string(d, "destination"), f->destination) && ru_string(d, "trust_record")[0] && rt_received(f);
}
static bool ru_reply_decode(const struct json_value *outer, int id, struct json_value *inner)
{
    const struct json_value *result = json_get(outer, "result");
    const struct json_value *error = json_get(result, "isError"), *reply_id = json_get(outer, "id");
    const char *text = json_get_str(json_get(json_at(json_get(result, "content"), 0), "text"));
    return reply_id && reply_id->type == JSON_INT && reply_id->val.i == id &&
        error && error->type == JSON_BOOL && !json_get_bool(error) && text &&
        json_read(inner, text, strlen(text)) && !strcmp(ru_string(inner, "status"), "passed");
}
static bool ru_result(struct ru_run *r, int id, bool committed)
{
    if (!ru_read_line(r->output, r->line, sizeof(r->line), 15000)) return false;
    struct json_value outer, inner; json_init(&outer); json_init(&inner);
    bool ok = json_read(&outer, r->line, strlen(r->line)) && ru_reply_decode(&outer, id, &inner);
    const struct json_value *data = json_get(&inner, "data");
    if (ok) ok = committed ? ru_commit_data(r, data) :
        (!strcmp(ru_string(data, "status"), "canceled") && rt_absent(r->fixture) && ru_home_unchanged(r));
    printf("APP_RECEIVE_UI id=%d committed=%d result=%s\n", id, committed, r->line);
    json_free(&inner); json_free(&outer);
    return ok && ru_window(r, false);
}
struct ru_count { struct rt_presenter present; uint32_t count; };
static bool ru_count_cancel(void *context, const struct zcl_present_model_v1 *m,
    const struct zcl_present_window_pages_v1 *pages, const struct zcl_present_window_live_view_v1 *live,
    char *why, size_t cap)
{
    struct ru_count *c = context;
    return zcl_present_model_page_count_v1(m, &c->count, why, cap) &&
        rt_present(&c->present, m, pages, live, why, cap);
}
static bool ru_page_count(struct receive_fixture *f, uint32_t *count)
{
    struct json_value input;
    json_init(&input);
    if (!rt_input(&input, f)) { json_free(&input); return false; }
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.receive-count.v1");
    struct zcl_command_request req = {.input = &input};
    struct ru_count c = {.present = {.fixture = f, .decision = RT_CANCEL}};
    zcl_test_app_receive_run(&req, &reply, ru_count_cancel, &c);
    bool ok = c.present.observed && c.count > 1 && c.count <= ZCL_PRESENT_MODEL_PAGES_MAX &&
        reply.status == ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated &&
        !strcmp(ru_string(&reply.data, "status"), "canceled") && rt_absent(f);
    *count = c.count;
    zcl_command_reply_free(&reply); json_free(&input); return ok;
}
static bool ru_env_save(struct ru_env *env, size_t count, size_t *saved)
{
    *saved = 0;
    for (size_t i = 0; i < count; ++i) {
        const char *s = getenv(env[i].key); env[i].saved = s ? strdup(s) : NULL;
        if (s && !env[i].saved) return false;
        *saved = i + 1;
    }
    return true;
}
static bool ru_env_restore(struct ru_env *env, size_t count)
{
    bool ok = true;
    for (size_t i = 0; i < count; ++i) {
        int rc = env[i].saved ? setenv(env[i].key, env[i].saved, 1) : unsetenv(env[i].key);
        if (rc) ok = false;
        free(env[i].saved);
    }
    return ok;
}
static bool ru_environment(struct receive_fixture *f)
{
    const char *keys[] = {"HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR", "XDG_CACHE_HOME", "XDG_DATA_HOME"};
    const char *names[] = {"home", "config", "state", "runtime", "cache", "data"};
    for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); ++i) {
        char path[1100]; int n = snprintf(path, sizeof(path), "%s/%s", f->world.root, names[i]);
        if (n <= 0 || (size_t)n >= sizeof(path) || mkdir(path, 0700) != 0 || setenv(keys[i], path, 1) != 0) return false;
    }
    return unsetenv("XAUTHORITY") == 0 && setenv("ZCL_CLI_TEST_NO_SERVICE_LOOKUP", "1", 1) == 0;
}
static bool ru_file_only_setup(struct receive_fixture *f)
{
    const char *home = getenv("HOME");
    if (!home || chmod(home, 0755) != 0) return false;
    int n = snprintf(f->datadir, sizeof(f->datadir), "%s/private-app-data", home);
    if (n <= 0 || (size_t)n >= sizeof(f->datadir) || n > 511) return false;
    n = snprintf(f->destination, sizeof(f->destination), "%s/copies/tinyapp-1", f->datadir);
    return n > 0 && (size_t)n < sizeof(f->destination) && rt_absent(f);
}
static bool ru_cleanup(struct ru_run *r)
{
    if (r->input >= 0) close(r->input);
    if (r->output >= 0) close(r->output);
    r->input = r->output = -1;
    bool driver = ru_stop(&r->driver), server = ru_stop(&r->server), display = ru_stop(&r->display);
    return driver && server && display;
}
static int ru_case(bool file_only)
{
    int failures = 0; size_t saved = 0;
    struct ru_env env[] = {{"HOME", NULL}, {"XDG_CONFIG_HOME", NULL}, {"XDG_STATE_HOME", NULL},
        {"XDG_RUNTIME_DIR", NULL}, {"XDG_CACHE_HOME", NULL}, {"XDG_DATA_HOME", NULL},
        {"DISPLAY", NULL}, {"WAYLAND_DISPLAY", NULL},
        {"XAUTHORITY", NULL}, {"ZCL_CLI_TEST_NO_SERVICE_LOOKUP", NULL}};
    struct receive_fixture f = {0};
    struct ru_run r = {.input = -1, .output = -1, .fixture = &f, .file_only = file_only};
    struct sigaction old_pipe, ignore_pipe = {.sa_handler = SIG_IGN}; bool signal_saved = false;
    uint32_t pages = 0;
    printf("APP_RECEIVE_UI request=%s\n", file_only ? "file-only" : "explicit-paths");
    TEST("actual stdio MCP receive uses native Xvfb confirmation, cancel and exact trusted checkout") {
        ASSERT(ru_env_save(env, sizeof(env)/sizeof(env[0]), &saved));
        ASSERT(sigemptyset(&ignore_pipe.sa_mask) == 0 && sigaction(SIGPIPE, &ignore_pipe, &old_pipe) == 0);
        signal_saved = true;
        ASSERT(rt_setup(&f));
        ASSERT(ru_environment(&f));
        ASSERT(!file_only || ru_file_only_setup(&f));
        ASSERT(ru_home_unchanged(&r));
        ASSERT(ru_page_count(&f, &pages));
        ASSERT(ru_home_unchanged(&r));
        ASSERT(realpath("build/bin/native_ui_driver", r.driver_image));
        ASSERT(ru_xvfb(&r));
        ASSERT(ru_server(&r) && ru_initialize(&r));
        ASSERT(ru_request(&r, 2) && ru_window(&r, true) && ru_pending(&r));
        ASSERT(ru_driver(&r, "--key=enter", false)); /* initial Cancel */
        ASSERT(ru_result(&r, 2, false));
        ASSERT(ru_request(&r, 3) && ru_window(&r, true) && ru_pending(&r));
        ASSERT(ru_pages(&r, pages));
        ASSERT(ru_result(&r, 3, true));
        ASSERT(ru_committed_modes(&r));
        PASS();
    } _test_next:;
    bool clean = ru_cleanup(&r);
    if (signal_saved && sigaction(SIGPIPE, &old_pipe, NULL) != 0) clean = false;
    if (!ru_env_restore(env, saved)) clean = false;
    printf("APP_RECEIVE_UI request=%s fixture=%s display=%s pages=%u cleanup=%d\n",
        file_only ? "file-only" : "explicit-paths", f.world.root, r.display_name, pages, clean);
    if (!clean) failures++;
    return failures;
}
int test_app_receive_ui(void)
{
    if (access("/usr/bin/Xvfb", X_OK) != 0) { puts("SKIP (app_receive_ui requires Linux Xvfb)"); return 0; }
    int failures = ru_case(false);
    return failures + ru_case(true);
}
#else
int test_app_receive_ui(void)
{
    puts("SKIP (app_receive_ui requires Linux Xvfb and native test seams)"); return 0;
}
#endif
#else
int test_app_receive(void)
{
    printf("SKIP (app_receive requires POSIX native presenter fixtures)\n");
    return 0;
}
int test_app_receive_ui(void)
{
    puts("SKIP (app_receive_ui requires Linux Xvfb and native test seams)"); return 0;
}
#endif
