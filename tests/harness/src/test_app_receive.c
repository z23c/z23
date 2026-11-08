/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* purpose: Exercise native owner receive confirmation without executing shared code. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"
#include "command/native_app_receive_command.h"
#include "command/native_app_confirm.h"
#include "presentation/canvas.h"
#include "command/native_command.h"
#include "command/native_zcode_package_bundle.h"
#include "command/native_zcode_package_copy.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
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
#include <pthread.h>
#include <time.h>
#include "platform/time_compat.h"
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
    return pages && pages->page_count == 1 && pages->pages->pixels && !m->exact_root[0] &&
        zcl_present_model_page_count_v1(m, count, why, cap) && *count > 1 &&
        rt_field(m, "Publisher: ", p->fixture->publisher) &&
        rt_field(m, "Release: ", p->fixture->release) &&
        rt_field(m, "Package: ", p->fixture->package) &&
        rt_field(m, "Destination: ", p->fixture->destination) &&
        rt_field(m, "Parent release: ", "None (first release)") &&
        rt_field(m, "Changes: ", "No parent to compare");
}
/* real-clock: existing native commit is joined by its owner; this presenter
 * only polls its completion and never enters storage/JSON on the worker. */
static bool rt_progress_present(const struct zcl_present_model_v1 *m,
    const struct zcl_present_window_pages_v1 *pages, const struct zcl_present_window_live_view_v1 *live)
{
    if (strcmp(m->title, "Receiving your copy") || pages->page_count != 1 || !pages->pages[0].pixels) return false;
    int64_t end = platform_time_monotonic_ms() + 5000;
    do {
        bool redraw = false, close = false;
        live->owner.update(live->owner.context, NULL, false, &redraw, &close);
        if (close) return true;
        platform_sleep_ms(1); /* real-clock: poll actual native commit completion */
    } while (platform_time_monotonic_ms() < end);
    return false;
}
static bool rt_present(void *context, const struct zcl_present_model_v1 *m,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    if (!strcmp(m->request_id, "receive-copy")) return rt_progress_present(m, pages, live);
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
    if (!strcmp(m->request_id, "receive-copy")) return rt_progress_present(m, pages, live);
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

/* Long escaped POSIX paths fit the filesystem and raw input limits, but their
 * complete committed receipt must fit before optional preview can be offered. */
static bool rpb_paths(struct receive_fixture *f)
{
    char parent[850], leaf[129];
    int n = snprintf(parent, sizeof(parent), "%s", f->world.root);
    if (n <= 0 || (size_t)n >= sizeof(parent)) return false;
    memset(leaf, 1, sizeof(leaf) - 1); leaf[0] = 'p'; leaf[sizeof(leaf) - 1] = 0;
    for (unsigned i = 0; i < 5; ++i) {
        size_t at = strlen(parent);
        n = snprintf(parent + at, sizeof(parent) - at, "/%s", leaf);
        if (n <= 0 || (size_t)n >= sizeof(parent) - at || mkdir(parent, 0700)) return false;
    }
    n = snprintf(f->datadir, sizeof(f->datadir), "%s/data", parent);
    if (n <= 0 || (size_t)n >= sizeof(f->datadir)) return false;
    n = snprintf(f->destination, sizeof(f->destination), "%s/copy", parent);
    return n > 0 && (size_t)n < sizeof(f->destination);
}
static bool rpb_no_window(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    (void)model; (void)pages; (void)live; (void)why; (void)cap;
    ++*(unsigned *)context;
    return false;
}
static bool rpb_attempt(struct receive_fixture *f, int preview)
{
    struct json_value input; json_init(&input);
    bool ok = rt_input(&input, f);
    if (ok && preview >= 0) ok = json_push_kv_bool(&input, "preview", preview != 0);
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_receive.v1");
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), "app.receive", NULL);
    char why[256] = {0}; unsigned calls = 0;
    ok = ok && spec && zcl_command_registry_input_validate(spec, &input, why, sizeof(why));
    if (ok) {
        struct zcl_command_request request = {.input = &input, .spec = spec, .invoked_name = "app.receive"};
        zcl_test_app_receive_run(&request, &reply, rpb_no_window, &calls);
        const char *code = preview == 1 ? "PREVIEW_RECEIPT_TOO_LARGE" : "CONFIRMATION_UNAVAILABLE";
        ok = rt_failed_with(&reply, code) && !reply.error.mutated && rt_absent(f);
        if (preview == 1) ok = ok && calls == 0;
    }
    json_free(&input); zcl_command_reply_free(&reply); return ok;
}
static bool rpb_short_cancel(struct receive_fixture *f)
{
    struct json_value input; json_init(&input);
    bool ok = rt_input(&input, f) && json_push_kv_bool(&input, "preview", true);
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_receive.v1");
    struct rt_presenter p = {.fixture = f, .decision = RT_CANCEL};
    if (ok) {
        struct zcl_command_request request = {.input = &input};
        zcl_test_app_receive_run(&request, &reply, rt_present, &p);
        ok = p.observed && rt_expected_reply(&p, &reply) && !reply.error.mutated && rt_absent(f);
    }
    json_free(&input); zcl_command_reply_free(&reply); return ok;
}
static int rpb_receipt_reserve(void)
{
    int failures = 0; struct receive_fixture f = {0};
    TEST("preview bounds escaped receipt before any receive write; default receive is unaffected") {
        ASSERT(rt_setup(&f));
        ASSERT(rpb_short_cancel(&f));
        ASSERT(rpb_paths(&f));
        ASSERT(rpb_attempt(&f, 1));
        ASSERT(rpb_attempt(&f, 0));
        ASSERT(rpb_attempt(&f, -1));
        ASSERT(rt_absent(&f));
        PASS();
    } _test_next:;
    return failures;
}

/* real-clock: bounded conditions observe an actual commit thread; no sleep
 * constitutes acceptance. Every presenter path releases the blocked worker. */
enum rp_case { RP_NORMAL, RP_CLOSE, RP_UI_FAIL, RP_PARTIAL, RP_ALLOC, RP_START, RP_PREPARE };
struct rp_fixture {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool entered, released, finished, observed, waited;
    unsigned calls;
    enum rp_case mode;
};
static bool rp_wait(struct rp_fixture *f, const bool *flag)
{
    struct timespec end;
    if (clock_gettime(CLOCK_REALTIME, &end) != 0) return false;
    end.tv_sec += 5;
    while (!*flag)
        if (pthread_cond_timedwait(&f->cond, &f->mutex, &end) != 0) return false;
    return true;
}
static void rp_worker(void *context, const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    struct rp_fixture *f = context;
    pthread_mutex_lock(&f->mutex);
    ++f->calls; f->entered = true; pthread_cond_broadcast(&f->cond);
    f->waited = rp_wait(f, &f->released);
    pthread_mutex_unlock(&f->mutex);
    void *allocation = zcl_calloc(1, 1, "receive-progress-fixture");
    free(allocation); /* Worker-local failure counter must override PASSED. */
    bool saved = json_push_kv_str(&reply->data, "stage", "commit") &&
        json_push_kv_str(&reply->data, "destination", zcl_package_copy_str(request->input, "destination")) &&
        json_push_kv_str(&reply->data, "trust_record", "/fixture/trust") &&
        json_push_kv_bool(&reply->data, "executed", false);
    reply->error.mutated = true;
    if (!saved) zcl_package_copy_fail(reply, "OUT_OF_MEMORY", true, "fixture receipt", "receive progress");
    if (f->mode == RP_PARTIAL)
        zcl_package_copy_fail(reply, "FIXTURE_PARTIAL", true, "saved before controlled refusal", "receive progress");
    pthread_mutex_lock(&f->mutex);
    f->finished = true; pthread_cond_broadcast(&f->cond);
    pthread_mutex_unlock(&f->mutex);
}
static bool rp_pending(struct rp_fixture *f, const struct zcl_present_model_v1 *m,
    const struct zcl_present_window_pages_v1 *pages, const struct zcl_present_window_live_view_v1 *live)
{
    bool redraw = false, close = true;
    live->owner.update(live->owner.context, NULL, false, &redraw, &close);
    bool ok = !close && !redraw && !strcmp(m->title, "Receiving your copy") &&
        pages->page_count == 1 && pages->pages[0].pixels;
    if (f->mode == RP_CLOSE) {
        live->owner.update(live->owner.context, NULL, true, &redraw, &close);
        ok = ok && !close && redraw && !strcmp(m->summary, "Finishing your copy");
    }
    return ok;
}
static bool rp_present(void *context, const struct zcl_present_model_v1 *m,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    (void)why; (void)cap;
    struct rp_fixture *f = context;
    pthread_mutex_lock(&f->mutex);
    bool entered = rp_wait(f, &f->entered);
    pthread_mutex_unlock(&f->mutex);
    bool ok = entered && rp_pending(f, m, pages, live);
    pthread_mutex_lock(&f->mutex);
    f->observed = ok; f->released = true; pthread_cond_broadcast(&f->cond);
    pthread_mutex_unlock(&f->mutex);
    return ok && f->mode != RP_UI_FAIL;
}
static bool rp_text(const struct json_value *data, const char *key, const char *expected)
{
    const char *value = zcl_package_copy_str(data, key);
    return value && !strcmp(value, expected);
}
static bool rp_saved(const struct rp_fixture *f, const struct zcl_command_reply *reply)
{
    const struct json_value *executed = json_get(&reply->data, "executed");
    return f->calls == 1 && f->finished && f->waited && f->observed && reply->error.mutated &&
        rp_text(&reply->data, "destination", "/fixture/received-copy") &&
        rp_text(&reply->data, "trust_record", "/fixture/trust") &&
        executed && executed->type == JSON_BOOL && !json_get_bool(executed);
}
static bool rp_not_started(const struct rp_fixture *f, const struct zcl_command_reply *reply, bool offer)
{
    return !offer && !f->calls && !reply->error.mutated &&
        reply->status != ZCL_COMMAND_STATUS_PASSED && !json_get(&reply->data, "destination");
}
static bool rp_retained(const struct rp_fixture *f, const struct zcl_command_reply *reply, bool offer)
{
    const struct json_value *executed = json_get(&reply->data, "continuation_executed");
    const struct json_value *ui_failed = json_get(&reply->data, "receive_progress_ui_failed");
    return !offer && rp_text(&reply->data, "continuation", "received") &&
        executed && executed->type == JSON_BOOL && !json_get_bool(executed) &&
        ui_failed && ui_failed->type == JSON_BOOL && json_get_bool(ui_failed) == (f->mode == RP_UI_FAIL);
}
static bool rp_result(const struct rp_fixture *f, const struct zcl_command_reply *reply, bool offer)
{
    if (f->mode == RP_START || f->mode == RP_PREPARE) return rp_not_started(f, reply, offer);
    if (!rp_saved(f, reply)) return false;
    if (f->mode == RP_PARTIAL) return !offer && rt_failed_with(reply, "FIXTURE_PARTIAL");
    if (f->mode == RP_ALLOC) return !offer && rt_failed_with(reply, "OUT_OF_MEMORY");
    if (reply->status != ZCL_COMMAND_STATUS_PASSED) return false;
    if (f->mode == RP_NORMAL) return offer && !json_get(&reply->data, "continuation");
    return rp_retained(f, reply, offer);
}
static bool rp_run(enum rp_case mode)
{
    struct rp_fixture f = {.mode = mode};
    if (pthread_mutex_init(&f.mutex, NULL) != 0) return false;
    if (pthread_cond_init(&f.cond, NULL) != 0) { pthread_mutex_destroy(&f.mutex); return false; }
    struct json_value input; json_init(&input); json_set_object(&input);
    bool ok = json_push_kv_str(&input, "destination", "/fixture/received-copy");
    struct zcl_command_request request = {.input = &input};
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_receive.v1");
    const struct app_commit_progress_test_hooks hooks = {
        .commit = rp_worker, .context = &f, .refuse_start = mode == RP_START,
        .worker_alloc_label = mode == RP_ALLOC ? "receive-progress-fixture" : NULL,
    };
    if (mode == RP_PREPARE) zcl_alloc_fault_fail_next("receive-copy/progress");
    bool offer = ok && zcl_test_app_receive_progress(&request, &reply, rp_present, &f, &hooks);
    zcl_alloc_fault_clear();
    ok = ok && rp_result(&f, &reply, offer);
    zcl_command_reply_free(&reply); json_free(&input);
    if (pthread_cond_destroy(&f.cond) != 0) ok = false;
    if (pthread_mutex_destroy(&f.mutex) != 0) ok = false;
    return ok;
}
static int rp_cases(void)
{
    int failures = 0;
    TEST("receive commit progress joins normal/close/UI-failed/partial/TLS-failed work and refuses prestart without mutation") {
        for (int mode = RP_NORMAL; mode <= RP_PREPARE; ++mode)
            ASSERT(rp_run((enum rp_case)mode));
        PASS();
    } _test_next:;
    return failures;
}

static bool rt_wrap_value(const char *value, bool words)
{
    struct zcl_present_model_v1 m;
    zcl_present_model_init_v1(&m, ZCL_PRESENT_MODEL_STATUS_CARD);
    if (!app_confirm_field(&m, "Text: ", value) || !rt_field(&m, "Text: ", value)) return false;
    size_t offset = 0, total = strlen(value);
    for (uint32_t i = 0; i < m.item_count; ++i) {
        const char *line = m.items[i].value, *part = line + (i ? 2 : 6);
        size_t n = strlen(part);
        if (!n || n > 40 || zcl_present_canvas_text_width(line, strlen(line), 16u) > 636u) return false;
        offset += n;
        if (words && offset < total && part[n - 1] != ' ' && value[offset] != ' ') return false;
    }
    return offset == total;
}
static int rt_wrap_cases(void)
{
    int failures = 0;
    TEST("confirmation wrapping preserves words, spaces and every long-identifier byte") {
        ASSERT(rt_wrap_value("Allow future requested builds and runs of this exact publisher and package. Receiving this copy runs nothing.", true));
        ASSERT(rt_wrap_value("  A path with  repeated spaces /fixture/My games/blue plane %shared.z23share  ", true));
        ASSERT(rt_wrap_value("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", false));
        ASSERT(rt_wrap_value("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW", false));
        ASSERT(rt_wrap_value("short", true));
        PASS();
    } _test_next:;
    return failures;
}
int test_app_receive(void)
{
    int failures = rt_wrap_cases();
    struct receive_fixture f;
    TEST("app.receive requires all-page native confirmation and rechecks the exact signed file") {
        ASSERT(rt_setup(&f));
        for (enum rt_decision d = RT_CANCEL; d < RT_CONFIRM; ++d)
            ASSERT(rt_attempt(&f, d));
        ASSERT(rt_attempt(&f, RT_CONFIRM));
        ASSERT(rt_received(&f));
        PASS();
    } _test_next:;
    failures += rp_cases();
    failures += rpb_receipt_reserve();
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
    bool cli_default;
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
    /* Only retained/enumerated direct children reach this fallback. Identity
     * may disappear during exit before waitpid can reap. Observe that exact
     * child with the existing bounded wait; never signal without identity. */
    if (ru_wait(c, 2000, NULL) == PLATFORM_PROCESS_WAIT_EXITED) return true;
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
/* Direct exec, not a shell or the positional receive/build/run shortcut.
 * --json is only a response control; datadir is a private fixture override. */
static bool ru_cli_option(char *out, size_t cap, const char *key, const char *value)
{
    int n = snprintf(out, cap, "--%s=%s", key, value);
    return n > 0 && (size_t)n < cap;
}
static bool ru_cli_start(struct ru_run *r)
{
    int out[2]; char image[PATH_MAX];
    char file[sizeof(r->fixture->file) + 8], datadir[sizeof(r->fixture->datadir) + 16];
    if (!ru_cli_option(file, sizeof(file), "file", r->fixture->file) ||
        !ru_cli_option(datadir, sizeof(datadir), "datadir", r->fixture->datadir) ||
        !realpath("build/bin/z23-dev", image) || !ru_pipe(out)) return false;
    int log = ru_log(r, "native-window-cli.log");
    int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const char *argv[] = {image, "app", "receive", file, "--json",
        r->cli_default ? NULL : datadir, NULL};
    bool ok = log >= 0 && input >= 0 && ru_spawn(&r->server, argv, input, out[1], log);
    close(out[1]); if (log >= 0) close(log); if (input >= 0) close(input);
    r->output = out[0];
    return ok;
}
static bool ru_cli_no_build(const struct ru_run *r)
{
    char path[sizeof(r->fixture->datadir) + 16];
    int n = snprintf(path, sizeof(path), "%s/app_build", r->fixture->datadir);
    return n > 0 && (size_t)n < sizeof(path) && rd_absent_path(path);
}
static bool ru_cli_result(struct ru_run *r, bool committed)
{
    if (!ru_read_line(r->output, r->line, sizeof(r->line), 15000)) return false;
    struct json_value reply; json_init(&reply);
    bool ok = json_read(&reply, r->line, strlen(r->line)) &&
        !strcmp(ru_string(&reply, "command"), "app.receive") &&
        !strcmp(ru_string(&reply, "status"), "passed");
    const struct json_value *success = json_get(&reply, "ok");
    ok = ok && success && success->type == JSON_BOOL && json_get_bool(success);
    const struct json_value *data = json_get(&reply, "data");
    if (ok) ok = committed ? ru_commit_data(r, data) :
        (!strcmp(ru_string(data, "status"), "canceled") && rt_absent(r->fixture) && ru_home_unchanged(r));
    printf("APP_RECEIVE_UI transport=cli committed=%d result=%s\n", committed, r->line);
    json_free(&reply);
    uint32_t code = UINT32_MAX;
    bool exited = ru_wait(&r->server, 5000, &code) == PLATFORM_PROCESS_WAIT_EXITED && code == 0;
    close(r->output); r->output = -1;
    return ok && exited && ru_window(r, false) && ru_cli_no_build(r);
}
static bool ru_cli_filename(struct receive_fixture *f)
{
    char path[sizeof(f->file)];
    int n = snprintf(path, sizeof(path), "%s/space %% \"quote\" 'single' $(touch PWNED);literal.z23share", f->world.root);
    if (n <= 0 || (size_t)n >= sizeof(path) || rename(f->file, path) != 0) return false;
    memcpy(f->file, path, (size_t)n + 1);
    return true;
}
static bool ru_transport_start(struct ru_run *r, bool cli)
{
    return cli || (ru_server(r) && ru_initialize(r));
}
static bool ru_transport_request(struct ru_run *r, bool cli, int id)
{
    return cli ? ru_cli_start(r) : ru_request(r, id);
}
static bool ru_transport_result(struct ru_run *r, bool cli, int id, bool committed)
{
    return cli ? ru_cli_result(r, committed) : ru_result(r, id, committed);
}

static bool ru_cli_default_setup(struct receive_fixture *f)
{
    const char *home = getenv("HOME");
    if (!home || unsetenv("ZCL_DATADIR") != 0) return false;
    /* z23-dev startup uses ZCL_CLI_DEFAULT_DATADIR under ZCL_DEV_BUILD.
     * This is an expectation only: no input or bridge binding is installed. */
    int n = snprintf(f->datadir, sizeof(f->datadir), "%s/.zclassic-c23-dev", home);
    if (n <= 0 || (size_t)n >= sizeof(f->datadir)) return false;
    n = snprintf(f->destination, sizeof(f->destination), "%s/copies/tinyapp-1", f->datadir);
    return n > 0 && (size_t)n < sizeof(f->destination) && rt_absent(f);
}
/* Preserve mode setup order; each failed setup still aborts before display
 * or child launch and flows through ru_case cleanup. */
static bool ru_case_modes(struct receive_fixture *f, bool file_only,
    bool cli, bool cli_default)
{
    if (cli && !ru_cli_filename(f)) return false;
    if (file_only && !ru_file_only_setup(f)) return false;
    return !cli_default || ru_cli_default_setup(f);
}
static int ru_case(bool file_only, bool cli, bool cli_default)
{
    int failures = 0; size_t saved = 0;
    struct ru_env env[] = {{"HOME", NULL}, {"XDG_CONFIG_HOME", NULL}, {"XDG_STATE_HOME", NULL},
        {"XDG_RUNTIME_DIR", NULL}, {"XDG_CACHE_HOME", NULL}, {"XDG_DATA_HOME", NULL},
        {"DISPLAY", NULL}, {"WAYLAND_DISPLAY", NULL},
        {"XAUTHORITY", NULL}, {"ZCL_CLI_TEST_NO_SERVICE_LOOKUP", NULL}, {"ZCL_DATADIR", NULL}};
    struct receive_fixture f = {0};
    struct ru_run r = {.input = -1, .output = -1, .fixture = &f, .file_only = file_only, .cli_default = cli_default};
    struct sigaction old_pipe, ignore_pipe = {.sa_handler = SIG_IGN}; bool signal_saved = false;
    uint32_t pages = 0;
    printf("APP_RECEIVE_UI transport=%s request=%s default_home=%d\n", cli ? "cli" : "mcp", file_only ? "file-only" : "explicit-paths", cli_default);
    TEST("actual MCP or typed CLI receive uses native Xvfb confirmation, cancel and exact trusted checkout") {
        ASSERT(ru_env_save(env, sizeof(env)/sizeof(env[0]), &saved));
        ASSERT(sigemptyset(&ignore_pipe.sa_mask) == 0 && sigaction(SIGPIPE, &ignore_pipe, &old_pipe) == 0);
        signal_saved = true;
        ASSERT(rt_setup(&f));
        ASSERT(ru_environment(&f));
        ASSERT(ru_case_modes(&f, file_only, cli, cli_default));
        ASSERT(ru_home_unchanged(&r));
        ASSERT(ru_page_count(&f, &pages));
        ASSERT(ru_home_unchanged(&r));
        ASSERT(realpath("build/bin/native_ui_driver", r.driver_image));
        ASSERT(ru_xvfb(&r));
        ASSERT(ru_transport_start(&r, cli));
        ASSERT(ru_transport_request(&r, cli, 2) && ru_window(&r, true) && ru_pending(&r));
        ASSERT(ru_driver(&r, "--key=enter", false)); /* initial Cancel */
        ASSERT(ru_transport_result(&r, cli, 2, false));
        ASSERT(ru_transport_request(&r, cli, 3) && ru_window(&r, true) && ru_pending(&r));
        ASSERT(ru_pages(&r, pages));
        ASSERT(ru_transport_result(&r, cli, 3, true));
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
/* Reuse the real-game journey's subreaper reconciliation. Before launching
 * CLI, require no unrelated direct children. After stopping CLI, adopted
 * workers must match the fixed trusted CLI/make/shell images. Unknown live
 * children are reported, never signaled. No competing fixture child reaper. */
#include <sys/prctl.h>
static bool ruf_children(pid_t pids[32], size_t *count)
{
    char path[96], text[4096]; *count = 0;
    (void)snprintf(path, sizeof(path), "/proc/self/task/%ld/children", (long)getpid());
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t n = read(fd, text, sizeof(text) - 1); bool closed = close(fd) == 0;
    if (!closed || n < 0 || (size_t)n == sizeof(text) - 1) return false;
    text[n] = 0; char *cursor = text;
    while (*cursor) {
        while (*cursor == ' ') ++cursor;
        if (!*cursor) break;
        char *end = NULL; errno = 0; long value = strtol(cursor, &end, 10);
        if (errno || end == cursor || value <= 1 || value > INT_MAX || *count == 32) return false;
        pids[(*count)++] = (pid_t)value; cursor = end;
    }
    return true;
}
static bool ruf_child_baseline(const struct ru_run *r)
{
    pid_t pids[32]; size_t count;
    if (!ruf_children(pids, &count)) return false;
    for (size_t i = 0; i < count; ++i)
        if (pids[i] != r->display.pid && pids[i] != r->driver.pid) return false;
    return true;
}
static bool ruf_adopted_stop(pid_t pid, const struct ru_run *r)
{
    struct ru_child child = {.pid = pid};
    if (!app_proc_identity(pid, child.image, &child.token))
        return ru_reaped_identity_failure(&child); /* enumerated direct child */
    char make[PATH_MAX], shell[PATH_MAX];
    if (!realpath("/usr/bin/make", make) || !realpath("/bin/sh", shell)) return false;
    if (!child.token || (strcmp(child.image, r->server.image) &&
        strcmp(child.image, make) && strcmp(child.image, shell))) return false;
    return ru_stop(&child); /* Rechecks executable+token before each signal. */
}
static bool ruf_workers_stop(struct ru_run *r)
{
    /* Stopping each direct adopted owner can expose another generation.
     * Bound scans; overflow/unknown/remaining children cannot be cleanup1. */
    for (unsigned pass = 0; pass < 8; ++pass) {
        pid_t pids[32]; size_t count; bool found = false;
        if (!ruf_children(pids, &count)) return false;
        for (size_t i = 0; i < count; ++i) {
            if (pids[i] == r->display.pid || pids[i] == r->driver.pid) continue;
            found = true;
            if (!ruf_adopted_stop(pids[i], r)) {
                char image[APP_LAUNCH_PATH_MAX] = {0}; uint64_t token = 0;
                bool observed = app_proc_identity(pids[i], image, &token);
                fprintf(stderr, "RECEIVE_CLEANUP unresolved pid=%ld observed=%d token=%llu image=%s\n",
                    (long)pids[i], observed, (unsigned long long)token, image);
                return false;
            }
        }
        if (!found) return true;
    }
    return false;
}
static bool ruf_cleanup(struct ru_run *r, bool custody, int old_subreaper)
{
    bool server = ru_stop(&r->server);
    bool workers = custody && server && ruf_workers_stop(r);
    bool direct = ru_cleanup(r);
    bool empty = custody && ruf_child_baseline(r);
    /* If descendants remain, retain subreaper mode and report failure rather
     * than relinquishing custody or claiming that direct-child cleanup sufficed. */
    bool restored = !custody || (workers && empty && prctl(PR_SET_CHILD_SUBREAPER, old_subreaper) == 0);
    fprintf(stderr, "RECEIVE_CLEANUP custody=%d server=%d workers=%d direct=%d empty=%d restored=%d\n",
        custody, server, workers, direct, empty, restored);
    return server && direct && (!custody || (workers && empty)) && restored;
}
/* Optional continuation is qualified through the shipping typed CLI and real
 * private windows. No injected presenter authorizes these operations. */
enum ruf_case { RUF_CLOSE, RUF_INVALID, RUF_BUILD_FAILURE, RUF_CUSTODY_FAILURE, RUF_PROGRESS_CLOSE, RUF_PROGRESS_CLOSE_OK, RUF_PLAN_CLOSE };
static bool ruf_driver(struct ru_run *r, const char *title, const char *action, bool pixels)
{
    char option[160];
    if (!ru_cli_option(option, sizeof(option), "title", title)) return false;
    int log = ru_log(r, "receive-flow-driver.log");
    const char *argv[] = {r->driver_image, option, action, "--timeout-ms=5000",
        pixels ? "--expect-pixels-change" : NULL, NULL};
    bool ok = log >= 0 && ru_spawn(&r->driver, argv, log, log, log);
    if (log >= 0) close(log);
    uint32_t code = UINT32_MAX;
    ok = ok && ru_wait(&r->driver, 7000, &code) == PLATFORM_PROCESS_WAIT_EXITED && code == 0;
    bool stopped = ru_stop(&r->driver);
    return ok && stopped;
}
static bool ruf_cli(struct ru_run *r, enum ruf_case which)
{
    int out[2]; char image[PATH_MAX];
    char file[sizeof(r->fixture->file) + 8], datadir[sizeof(r->fixture->datadir) + 16];
    if (!ru_cli_option(file, sizeof(file), "file", r->fixture->file) ||
        !ru_cli_option(datadir, sizeof(datadir), "datadir", r->fixture->datadir) ||
        !realpath("build/bin/z23-dev", image) || !ru_pipe(out)) return false;
    int log = ru_log(r, "receive-flow-cli.log");
    int in = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const char *argv[] = {image, "app", "receive", file, datadir,
        which == RUF_INVALID ? "--preview=not-a-boolean" : "--preview", "--json", NULL};
    bool ok = log >= 0 && in >= 0 && ru_spawn(&r->server, argv, in, out[1], log);
    close(out[1]); if (log >= 0) close(log); if (in >= 0) close(in);
    r->output = out[0]; return ok;
}
static bool ruf_unbuildable(struct receive_fixture *f)
{
    char makefile[ABC_PATH];
    int n = snprintf(makefile, sizeof(makefile), "%s/Makefile", f->world.src);
    if (n <= 0 || (size_t)n >= sizeof(makefile) || unlink(makefile)) return false;
    n = snprintf(f->file, sizeof(f->file), "%s/no-make.z23share", f->world.root);
    /* Re-sign the selected source, not a post-receive mutable-copy sabotage.
     * rt_setup's later source was return1; restore the exact k_main oracle. */
    return n > 0 && (size_t)n < sizeof(f->file) && abc_put(f->world.src, "src/main.c", k_main) &&
        rt_bundle(f, f->file, 1);
}
static bool ruf_empty_directory(const char *path)
{
    DIR *dir = path ? opendir(path) : NULL;
    if (!dir) return false;
    bool empty = true; struct dirent *entry;
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) { empty = false; break; }
    }
    bool ok = empty && errno == 0;
    return closedir(dir) == 0 && ok;
}
/* Derive the native choice's page count from its exact model and the actual
 * received saved version, never from an assumed number of Tab presses. */
static bool ruf_choice_count(const struct receive_fixture *f, uint32_t *count)
{
    struct zcl_package_copy copy = {0}; struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.receive-flow.v1");
    bool opened = zcl_package_copy_open_selected_as(f->destination, ZCL_PACKAGE_COPY_READ,
        &copy, &reply, "receive-flow-test", NULL);
    char version[65]; zcl_hex_encode(copy.selected_version, 32, version);
    struct app_confirm *view = zcl_calloc(1, sizeof(*view), "receive-flow-test/model");
    bool ok = opened && view;
    if (ok) {
        zcl_present_model_init_v1(&view->model, ZCL_PRESENT_MODEL_STATUS_CARD);
        (void)snprintf(view->model.request_id, sizeof(view->model.request_id), "received-app");
        (void)snprintf(view->model.title, sizeof(view->model.title), "Your copy is ready");
        (void)snprintf(view->model.summary, sizeof(view->model.summary),
            "Build and run this received version to preview it. Keep remains a separate choice.");
        view->model.action_count = 4;
        app_confirm_action(&view->model.actions[0], ZCL_PRESENT_ACTION_CANCEL, "close", "Close");
        app_confirm_action(&view->model.actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
        app_confirm_action(&view->model.actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
        app_confirm_action(&view->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "continue", "Build and preview");
        char why[128];
        ok = app_confirm_field(&view->model, "App: ", "stub/tinyapp") &&
            app_confirm_field(&view->model, "Saved version: ", version) &&
            zcl_present_model_page_count_v1(&view->model, count, why, sizeof(why));
    }
    free(view); zcl_package_copy_close(&copy); zcl_command_reply_free(&reply);
    return ok && *count > 0 && *count <= ZCL_PRESENT_MODEL_PAGES_MAX;
}
static bool ruf_choose_build(struct ru_run *r)
{
    static const char title[] = "Your copy is ready";
    uint32_t count = 0;
    if (!ruf_choice_count(r->fixture, &count)) return false;
    /* Initially unfocused: Close -> Back -> Next. */
    for (unsigned i = 0; i < 3; ++i)
        if (!ruf_driver(r, title, "--key=tab", true)) return false;
    for (uint32_t page = 1; page < count; ++page)
        if (!ruf_driver(r, title, "--key=enter", true)) return false;
    return ruf_driver(r, title, "--key=tab", true) && ruf_driver(r, title, "--key=enter", false);
}
static bool ruf_bool(const struct json_value *data, const char *key, bool expected)
{
    const struct json_value *v = json_get(data, key);
    return v && v->type == JSON_BOOL && json_get_bool(v) == expected;
}
static bool ruf_failed_operation(const struct json_value *data)
{
    const struct json_value *ops = json_get(data, "operations");
    if (!ops || ops->type != JSON_ARR || json_size(ops) != 1) return false;
    const struct json_value *op = json_at(ops, 0);
    const struct json_value *code = json_get(op, "exit_code");
    return ruf_bool(op, "exit_observed", true) &&
        code && code->type == JSON_INT && json_get_int(code) != 0 &&
        ruf_bool(op, "stdout_complete", true) && ruf_bool(op, "stdout_truncated", false) &&
        ruf_bool(op, "result_is_summary", true) && ruf_bool(op, "result_parsed", true) &&
        !json_get(op, "result") && !strcmp(ru_string(op, "status"), "failed") &&
        strstr(ru_string(op, "error_excerpt"), "Makefile") != NULL;
}
static bool ruf_stderr_summary(const struct json_value *data)
{
    const struct json_value *op = json_at(json_get(data, "operations"), 0);
    const struct json_value *omitted = json_get(op, "stderr_bytes_omitted");
    const struct json_value *hex = json_get(op, "stderr_tail_hex");
    if (!omitted || omitted->type != JSON_INT || json_get_int(omitted) < 0 ||
        !hex || hex->type != JSON_STR) return false;
    const char *text = json_get_str(hex); size_t n = strlen(text);
    if (n > 256 || n % 2) return false;
    for (size_t i = 0; i < n; ++i)
        if (!strchr("0123456789abcdef", text[i])) return false;
    return true;
}
static bool ruf_no_outputs(const struct ru_run *r, enum ruf_case which)
{
    if (!ruf_empty_directory(getenv("XDG_STATE_HOME"))) return false;
    if (which != RUF_BUILD_FAILURE) return ru_cli_no_build(r);
    /* A failed plan may create and retire selected-source scratch, but must
     * not publish a built image or record, or launch an application. */
    char images[1024], records[1024];
    int a = snprintf(images, sizeof(images), "%s/app_build/images", r->fixture->datadir);
    int b = snprintf(records, sizeof(records), "%s/app_build/records", r->fixture->datadir);
    return a > 0 && (size_t)a < sizeof(images) && b > 0 && (size_t)b < sizeof(records) &&
        rd_absent_path(images) && rd_absent_path(records);
}
static bool ruf_closed_data(const struct json_value *reply, const struct json_value *data)
{
    const struct json_value *ops = json_get(data, "operations");
    return ruf_bool(reply, "ok", true) && !strcmp(ru_string(reply, "status"), "passed") &&
        !strcmp(ru_string(data, "continuation"), "received") &&
        ruf_bool(data, "continuation_executed", false) &&
        ops && ops->type == JSON_ARR && json_size(ops) == 0;
}
static bool ruf_invalid_data(const struct ru_run *r, const struct json_value *reply)
{
    return ruf_bool(reply, "ok", false) && strcmp(ru_string(reply, "status"), "passed") &&
        !strcmp(ru_string(json_get(reply, "error"), "code"), "INVALID_INPUT") &&
        strstr(ru_string(json_get(reply, "error"), "message"), "preview") &&
        rt_absent(r->fixture) && ru_home_unchanged(r);
}
static bool ruf_failed_data(const struct json_value *reply, const struct json_value *data)
{
    const struct json_value *error = json_get(data, "continuation_error");
    return ruf_bool(reply, "ok", true) && !strcmp(ru_string(reply, "status"), "passed") &&
        !strcmp(ru_string(data, "continuation"), "failed") &&
        ruf_bool(data, "continuation_executed", false) &&
        !strcmp(ru_string(error, "code"), "PREVIEW_WORKER_FAILED") &&
        ruf_bool(error, "received_copy_retained", true) && ruf_bool(error, "automatic_retry", false) &&
        ruf_failed_operation(data) && ruf_stderr_summary(data);
}
static bool ruf_reply_data(struct ru_run *r, enum ruf_case which, const struct json_value *reply)
{
    const struct json_value *data = json_get(reply, "data"), *success = json_get(reply, "ok");
    if (!success || success->type != JSON_BOOL || strcmp(ru_string(reply, "command"), "app.receive")) return false;
    if (which == RUF_INVALID) return ruf_invalid_data(r, reply);
    if (!ru_commit_data(r, data) || !ru_committed_modes(r)) return false;
    if (which == RUF_BUILD_FAILURE) return ruf_failed_data(reply, data);
    return ruf_closed_data(reply, data);
}
static bool ruf_result(struct ru_run *r, enum ruf_case which)
{
    if (!ru_read_line(r->output, r->line, sizeof(r->line), 15000)) return false;
    struct json_value reply; json_init(&reply);
    bool ok = json_read(&reply, r->line, strlen(r->line)) && ruf_reply_data(r, which, &reply);
    printf("APP_RECEIVE_FLOW case=%d reply=%s\n", which, r->line);
    json_free(&reply);
    uint32_t code = UINT32_MAX;
    bool exited = ru_wait(&r->server, 5000, &code) == PLATFORM_PROCESS_WAIT_EXITED &&
        ((which != RUF_INVALID && code == 0) || (which == RUF_INVALID && code != 0));
    close(r->output); r->output = -1;
    return ok && exited && ru_window(r, false) &&
        ruf_driver(r, "Your copy is ready", "--expect-count=0", false) &&
        ruf_driver(r, "The next step did not finish", "--expect-count=0", false) &&
        ruf_no_outputs(r, which);
}
static bool ruf_gate_bundle(struct receive_fixture *f, bool success)
{
    /* Existing app_build_copy FIFO pattern. No compilation occurs before the
     * handshake; cleanup test intentionally interrupts this blocked recipe. */
    char makefile[2048];
    int n = snprintf(makefile, sizeof(makefile), "%s"
        ".PHONY: before\napp: before\nbefore:\n"
        "\t@printf R > $(APP_OUT)/../flow-ready\n"
        "\t@read ack < $(APP_OUT)/../flow-go\n"
        "\t@%s\n", k_makefile, success ? "true" : "false");
    if (n <= 0 || (size_t)n >= sizeof(makefile)) return false;
    n = snprintf(f->file, sizeof(f->file), "%s/gated.z23share", f->world.root);
    return n > 0 && (size_t)n < sizeof(f->file) &&
        abc_put(f->world.src, "src/main.c", k_main) && abc_put(f->world.src, "Makefile", makefile) &&
        rt_bundle(f, f->file, 1);
}
static bool ruf_gate_open(const struct receive_fixture *f, int gate[2])
{
    struct zcl_package_copy copy = {0}; struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.receive-flow.v1");
    bool ok = zcl_package_copy_open_selected_as(f->destination, ZCL_PACKAGE_COPY_READ,
        &copy, &reply, "receive-flow-gate", NULL);
    char hex[65], work[1100], ready[1150], go[1150];
    zcl_hex_encode(copy.fork_version, 32, hex);
    int n = snprintf(work, sizeof(work), "%s/app_build/work/%s", f->datadir, hex);
    ok = ok && n > 0 && (size_t)n < sizeof(work) && zcl_mkdir_p(work, 0700).ok;
    zcl_package_copy_close(&copy); zcl_command_reply_free(&reply);
    if (!ok) return false;
    (void)snprintf(ready, sizeof(ready), "%s/flow-ready", work);
    (void)snprintf(go, sizeof(go), "%s/flow-go", work);
    if (mkfifo(ready, 0600) || mkfifo(go, 0600)) return false;
    gate[0] = open(ready, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    gate[1] = open(go, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    return gate[0] >= 0 && gate[1] >= 0;
}
static bool ruf_gate_failure(struct ru_run *r, int gate[2])
{
    if (!ruf_gate_open(r->fixture, gate) || !ruf_choose_build(r)) return false;
    struct pollfd event = {.fd = gate[0], .events = POLLIN};
    int ready; do { ready = poll(&event, 1, 30000); } while (ready < 0 && errno == EINTR);
    char byte = 0;
    if (ready != 1 || read(gate[0], &byte, 1) != 1 || byte != 'R') return false;
    /* The fixture's make child is now blocked waiting for our FIFO, not a
     * wall-clock guess. Force the driver's error branch and hand live CLI /
     * build-worker/make/shell custody to the normal failure cleanup below. */
    return ru_image_live(&r->server) &&
        !ruf_driver(r, "Deliberately absent cleanup-control window", "--expect-count=1", false);
}
/* Close is deferred while a real make child is held by the existing FIFO.
 * The driver's escape means WM_DELETE_WINDOW, not a physical Escape key. */
static bool rfp_wait_ready(struct ru_run *r, int gate[2])
{
    if (!ruf_gate_open(r->fixture, gate) || !ruf_choose_build(r)) return false;
    struct pollfd event = {.fd = gate[0], .events = POLLIN};
    int ready; do { ready = poll(&event, 1, 30000); } while (ready < 0 && errno == EINTR);
    char byte = 0;
    return ready == 1 && read(gate[0], &byte, 1) == 1 && byte == 'R';
}
static bool rfp_pin_receipt(const struct receive_fixture *f, struct zcl_package_copy *pins)
{
    /* Only immutable identity fields survive; no live VCS handle is shared. */
    memset(pins, 0, sizeof(*pins));
    struct zcl_package_copy copy = {0}; struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.receive-progress.v1");
    bool opened = zcl_package_copy_open_selected_as(f->destination, ZCL_PACKAGE_COPY_READ,
        &copy, &reply, "receive-progress", NULL);
    bool ok = opened && rt_received_trust(f, &copy);
    if (ok) {
        memcpy(pins->fork_version, copy.fork_version, 32);
        memcpy(pins->parent_release, copy.parent_release, 32);
    }
    if (opened) zcl_package_copy_close(&copy);
    zcl_command_reply_free(&reply); return ok;
}
static bool rfp_blocked_close(struct ru_run *r, int gate[2])
{
    struct zcl_package_copy pins;
    if (!rfp_pin_receipt(r->fixture, &pins)) return false;
    if (!rfp_wait_ready(r, gate)) return false;
    if (!ruf_driver(r, "Building your app", "--key=escape", true) ||
        !ruf_driver(r, "Building your app", "--expect-count=1", false)) return false;
    struct pollfd output = {.fd = r->output, .events = POLLIN};
    int pending; do { pending = poll(&output, 1, 0); } while (pending < 0 && errno == EINTR);
    /* Build holds commits.log: inspect immutable trust and unchanged bytes,
     * not a competing history handle. rfp_result/ru_commit_data reopens and
     * validates the full receipt once the worker has completed. */
    bool live = ru_image_live(&r->server);
    bool trust = rt_received_trust(r->fixture, &pins);
    bool source = rt_received_source(r->fixture, true);
    fprintf(stderr, "RECEIVE_PROGRESS blocked pending=%d revents=%d live=%d trust=%d source=%d\n",
        pending, output.revents, live, trust, source);
    return pending == 0 && live && trust && source;
}
static bool rfp_operation(const struct json_value *op, const char *stage, bool failed)
{
    const struct json_value *code = json_get(op, "exit_code");
    if (!code || code->type != JSON_INT) return false;
    bool exit_ok = failed ? json_get_int(code) != 0 : json_get_int(code) == 0;
    return exit_ok && !strcmp(ru_string(op, "operation"), stage) &&
        !strcmp(ru_string(op, "status"), failed ? "failed" : "passed") &&
        ruf_bool(op, "exit_observed", true) && ruf_bool(op, "timed_out", false) &&
        ruf_bool(op, "stdout_complete", true) && ruf_bool(op, "stdout_truncated", false) &&
        ruf_bool(op, "progress_displayed", true) && ruf_bool(op, "close_notice_failed", false);
}
static bool rfp_data(struct ru_run *r, const struct json_value *reply)
{
    const struct json_value *data = json_get(reply, "data"), *ops = json_get(data, "operations");
    const struct json_value *error = json_get(data, "continuation_error");
    return ruf_bool(reply, "ok", true) && !strcmp(ru_string(reply, "status"), "passed") &&
        !strcmp(ru_string(reply, "command"), "app.receive") && ru_commit_data(r, data) &&
        !strcmp(ru_string(data, "continuation"), "failed") && ruf_bool(data, "continuation_executed", false) &&
        !strcmp(ru_string(error, "code"), "PREVIEW_WORKER_FAILED") &&
        ruf_bool(error, "received_copy_retained", true) && ruf_bool(error, "automatic_retry", false) &&
        ops && ops->type == JSON_ARR && json_size(ops) == 2 && !json_get(data, "kept");
}
static bool rfp_no_publication(const struct ru_run *r)
{
    static const char *const names[] = {"images", "records"};
    if (!ruf_empty_directory(getenv("XDG_STATE_HOME"))) return false;
    for (size_t i = 0; i < 2; ++i) {
        char path[1024]; int n = snprintf(path, sizeof(path), "%s/app_build/%s", r->fixture->datadir, names[i]);
        if (n <= 0 || (size_t)n >= sizeof(path)) return false;
        if (!rd_absent_path(path) && !ruf_empty_directory(path)) return false;
    }
    return true;
}
static bool rfp_result(struct ru_run *r)
{
    if (!ru_read_line(r->output, r->line, sizeof(r->line), 15000)) return false;
    struct json_value reply; json_init(&reply);
    bool ok = json_read(&reply, r->line, strlen(r->line)) && rfp_data(r, &reply);
    const struct json_value *ops = json_get(json_get(&reply, "data"), "operations");
    ok = ok && rfp_operation(json_at(ops, 0), "Checking the received version", false) &&
        rfp_operation(json_at(ops, 1), "Building your app", true);
    printf("APP_RECEIVE_PROGRESS_CLOSE reply=%s\n", r->line);
    json_free(&reply);
    uint32_t code = UINT32_MAX;
    bool exited = ru_wait(&r->server, 5000, &code) == PLATFORM_PROCESS_WAIT_EXITED && code == 0;
    close(r->output); r->output = -1;
    return ok && exited && ru_committed_modes(r) && rfp_no_publication(r);
}
static bool rfp_actions(struct ru_run *r, int gate[2])
{
    if (!rfp_blocked_close(r, gate)) return false;
    /* Release exactly one blocked recipe; its maintained final false produces
     * the visible failure. No retry, kill, cancellation or command rerun. */
    ssize_t sent; do { sent = write(gate[1], "go\n", 3); } while (sent < 0 && errno == EINTR);
    if (sent != 3) return false;
    return ruf_driver(r, "The next step did not finish", "--expect-count=1", false) &&
        ruf_driver(r, "Building your app", "--expect-count=0", false) &&
        ruf_driver(r, "The next step did not finish", "--key=enter", false) &&
        rfp_result(r) && ruf_driver(r, "The next step did not finish", "--expect-count=0", false);
}
static bool rfp_bundle(struct receive_fixture *f, enum ruf_case which)
{
    if (which == RUF_PLAN_CLOSE) {
        char makefile[2048];
        int n = snprintf(makefile, sizeof(makefile), "%s\nprint-app-closure: slow-plan\n"
            ".PHONY: slow-plan\nslow-plan:\n\t@sleep 10\n", k_makefile);
        if (n <= 0 || (size_t)n >= sizeof(makefile)) return false;
        n = snprintf(f->file, sizeof(f->file), "%s/slow-plan.z23share", f->world.root);
        return n > 0 && (size_t)n < sizeof(f->file) &&
            abc_put(f->world.src, "src/main.c", k_main) &&
            abc_put(f->world.src, "Makefile", makefile) && rt_bundle(f, f->file, 1);
    }
    if (which == RUF_CUSTODY_FAILURE || which == RUF_PROGRESS_CLOSE || which == RUF_PROGRESS_CLOSE_OK)
        return ruf_gate_bundle(f, which == RUF_PROGRESS_CLOSE_OK);
    return true;
}
static bool rfp_success_data(struct ru_run *r, const struct json_value *reply, size_t count)
{
    const struct json_value *data = json_get(reply, "data"), *ops = json_get(data, "operations");
    bool ok = ruf_bool(reply, "ok", true) && ru_commit_data(r, data) &&
        !strcmp(ru_string(data, "continuation"), "received") &&
        ruf_bool(data, "continuation_executed", false) && !json_get(data, "kept") &&
        ops && ops->type == JSON_ARR && json_size(ops) == count &&
        rfp_operation(json_at(ops, 0), "Checking the received version", false);
    if (ok && count == 2) ok = rfp_operation(json_at(ops, 1), "Building your app", false);
    return ok;
}
static bool rfp_success_reply(struct ru_run *r, size_t count)
{
    if (!ru_read_line(r->output, r->line, sizeof(r->line), 30000)) return false;
    struct json_value reply; json_init(&reply);
    bool ok = json_read(&reply, r->line, strlen(r->line)) && rfp_success_data(r, &reply, count);
    json_free(&reply);
    uint32_t code = UINT32_MAX;
    bool exited = ru_wait(&r->server, 5000, &code) == PLATFORM_PROCESS_WAIT_EXITED && code == 0;
    close(r->output); r->output = -1;
    return ok && exited && ru_committed_modes(r);
}
static bool rfp_success_actions(struct ru_run *r, int gate[2])
{
    if (!rfp_blocked_close(r, gate)) return false;
    ssize_t sent; do { sent = write(gate[1], "go\n", 3); } while (sent < 0 && errno == EINTR);
    return sent == 3 && rfp_success_reply(r, 2) && ruf_empty_directory(getenv("XDG_STATE_HOME")) &&
        ruf_driver(r, "Opening the built version", "--expect-count=0", false) &&
        ruf_driver(r, "Preview opened", "--expect-count=0", false);
}
static bool rfp_plan_close(struct ru_run *r)
{
    if (!ruf_choose_build(r) ||
        !ruf_driver(r, "Checking the received version", "--key=escape", true)) return false;
    struct pollfd output = {.fd = r->output, .events = POLLIN};
    int pending; do { pending = poll(&output, 1, 0); } while (pending < 0 && errno == EINTR);
    return pending == 0 && ru_image_live(&r->server) && rfp_success_reply(r, 1) &&
        rfp_no_publication(r) && ruf_driver(r, "Building your app", "--expect-count=0", false);
}
static bool ruf_progress_actions(struct ru_run *r, enum ruf_case which, int gate[2])
{
    switch (which) {
    case RUF_CUSTODY_FAILURE: return ruf_gate_failure(r, gate);
    case RUF_PROGRESS_CLOSE: return rfp_actions(r, gate);
    case RUF_PROGRESS_CLOSE_OK: return rfp_success_actions(r, gate);
    case RUF_PLAN_CLOSE: return rfp_plan_close(r);
    default: return false;
    }
}

static bool ruf_actions(struct ru_run *r, enum ruf_case which, uint32_t pages, int gate[2])
{
    if (!ruf_cli(r, which)) return false;
    if (which == RUF_INVALID) return ruf_result(r, which);
    if (!ru_window(r, true) || !ru_pending(r) || !ru_pages(r, pages) ||
        !ruf_driver(r, "Your copy is ready", "--expect-count=1", false) || !rt_received(r->fixture)) return false;
    if (which >= RUF_CUSTODY_FAILURE) return ruf_progress_actions(r, which, gate);
    if (which == RUF_CLOSE) {
        if (!ruf_driver(r, "Your copy is ready", "--key=enter", false)) return false;
    } else {
        if (!ruf_choose_build(r) ||
            !ruf_driver(r, "The next step did not finish", "--expect-count=1", false) ||
            !ruf_driver(r, "The next step did not finish", "--key=enter", false)) return false;
    }
    return ruf_result(r, which);
}
static void rfp_failure_wire(struct ru_run *r)
{
    if (r->output < 0) return;
    struct pollfd p = {.fd = r->output, .events = POLLIN};
    int ready; do { ready = poll(&p, 1, 0); } while (ready < 0 && errno == EINTR);
    fprintf(stderr, "RECEIVE_PROGRESS failed-output ready=%d revents=%d\n", ready, p.revents);
    if (ready <= 0 || !(p.revents & POLLIN)) return;
    r->line[0] = 0;
    bool complete = ru_read_line(r->output, r->line, sizeof(r->line), 250);
    fprintf(stderr, "RECEIVE_PROGRESS failed-output complete=%d wire=%s\n",
        complete, complete ? r->line : "<incomplete line; bounded capture expired>");
}
static int ruf_case_run(enum ruf_case which)
{
    int failures = 0; size_t saved = 0;
    struct ru_env env[] = {{"HOME", NULL}, {"XDG_CONFIG_HOME", NULL}, {"XDG_STATE_HOME", NULL},
        {"XDG_RUNTIME_DIR", NULL}, {"XDG_CACHE_HOME", NULL}, {"XDG_DATA_HOME", NULL},
        {"DISPLAY", NULL}, {"WAYLAND_DISPLAY", NULL}, {"XAUTHORITY", NULL},
        {"ZCL_CLI_TEST_NO_SERVICE_LOOKUP", NULL}, {"ZCL_DATADIR", NULL}};
    struct receive_fixture f = {0};
    struct ru_run r = {.input = -1, .output = -1, .fixture = &f, .file_only = true};
    struct sigaction old_pipe, ignore_pipe = {.sa_handler = SIG_IGN}; bool signal_saved = false;
    int old_subreaper = 0, gate[2] = {-1, -1}; bool custody = false;
    uint32_t pages = 0;
    TEST("typed CLI preview opt-in preserves committed Receive on Close and visible build failure") {
        ASSERT(ru_env_save(env, sizeof(env)/sizeof(env[0]), &saved));
        ASSERT(sigemptyset(&ignore_pipe.sa_mask) == 0 && sigaction(SIGPIPE, &ignore_pipe, &old_pipe) == 0);
        signal_saved = true;
        ASSERT(rt_setup(&f));
        ASSERT(which != RUF_BUILD_FAILURE || ruf_unbuildable(&f));
        ASSERT(rfp_bundle(&f, which));
        ASSERT(ru_environment(&f) && ru_file_only_setup(&f));
        ASSERT(ru_page_count(&f, &pages) && ru_home_unchanged(&r));
        ASSERT(realpath("build/bin/native_ui_driver", r.driver_image));
        ASSERT(ru_xvfb(&r));
        ASSERT(ruf_child_baseline(&r));
        ASSERT(prctl(PR_GET_CHILD_SUBREAPER, &old_subreaper) == 0);
        ASSERT(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0);
        custody = true;
        ASSERT(ruf_actions(&r, which, pages, gate));
        PASS();
    } _test_next:;
    if (failures) rfp_failure_wire(&r);
    bool clean = ruf_cleanup(&r, custody, old_subreaper);
    if (gate[0] >= 0) close(gate[0]);
    if (gate[1] >= 0) close(gate[1]);
    if (signal_saved && sigaction(SIGPIPE, &old_pipe, NULL) != 0) clean = false;
    if (!ru_env_restore(env, saved)) clean = false;
    printf("APP_RECEIVE_FLOW case=%d fixture=%s cleanup=%d\n", which, f.world.root, clean);
    if (!clean) failures++;
    return failures;
}
/* Actual tiny-app continuation. Native dialogs are real; app readiness uses
 * the maintained kept-route alive contract, not a rendered-game claim. */
#include "command/app_selection.h"
#include "command/app_image.h"
static const char rus_main[] =
    "#define _POSIX_C_SOURCE 200809L\n#include <stdio.h>\n#include <unistd.h>\n"
    "int main(void){puts(\"RECEIVE-FLOW-ALIVE\");fflush(stdout);for(;;)pause();}\n";
static const char rus_dirty[] = "#error unsaved live source must never be built\n";
struct rus_identity {
    char version[65], route[33], image[65], record[65], image_path[PATH_MAX];
    uint8_t fork[32];
    struct app_launch_env env;
    struct ru_child running;
};
static bool rus_bundle(struct receive_fixture *f)
{
    int n = snprintf(f->file, sizeof(f->file), "%s/alive.z23share", f->world.root);
    return n > 0 && (size_t)n < sizeof(f->file) && abc_put(f->world.src, "src/main.c", rus_main) &&
        rt_bundle(f, f->file, 1);
}
static bool rus_source(const struct receive_fixture *f, const char *expected)
{
    char path[1024], bytes[256];
    int n = snprintf(path, sizeof(path), "%s/src/main.c", f->destination);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    FILE *file = fopen(path, "rb"); if (!file) return false;
    size_t got = fread(bytes, 1, sizeof(bytes), file);
    bool ok = !ferror(file) && feof(file) && got == strlen(expected) && !memcmp(bytes, expected, got);
    return fclose(file) == 0 && ok;
}
static bool rus_received(struct receive_fixture *f, struct rus_identity *id, bool first)
{
    struct zcl_package_copy copy = {0}; struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.receive-success.v1");
    bool ok = zcl_package_copy_open_selected_as(f->destination, ZCL_PACKAGE_COPY_READ,
        &copy, &reply, "receive-success", first ? NULL : id->version);
    char version[65]; zcl_hex_encode(copy.head_version, 32, version);
    if (ok && first) {
        memcpy(id->version, version, sizeof(version)); memcpy(id->fork, copy.fork_version, 32);
    }
    ok = ok && !strcmp(version, id->version) && !memcmp(id->fork, copy.fork_version, 32) &&
        rt_received_trust(f, &copy);
    zcl_package_copy_close(&copy); zcl_command_reply_free(&reply);
    return ok && rus_source(f, first ? rus_main : rus_dirty);
}
static bool rus_wait_keep_window(struct ru_run *r)
{
    int log = ru_log(r, "receive-success-driver.log");
    const char *argv[] = {r->driver_image, "--title=Preview opened", "--expect-count=1",
        "--timeout-ms=30000", NULL};
    bool ok = log >= 0 && ru_spawn(&r->driver, argv, log, log, log);
    if (log >= 0) close(log);
    uint32_t code = UINT32_MAX;
    ok = ok && ru_wait(&r->driver, 32000, &code) == PLATFORM_PROCESS_WAIT_EXITED && code == 0;
    bool stopped = ru_stop(&r->driver); return ok && stopped;
}
static bool rus_keep_pages(const struct rus_identity *id, uint32_t *count)
{
    struct app_confirm *view = zcl_calloc(1, sizeof(*view), "receive-success/model");
    if (!view) return false;
    zcl_present_model_init_v1(&view->model, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(view->model.request_id, sizeof(view->model.request_id), "received-app");
    (void)snprintf(view->model.title, sizeof(view->model.title), "Preview opened");
    (void)snprintf(view->model.summary, sizeof(view->model.summary),
        "Check the app before choosing Keep. Closing leaves your received copy available.");
    view->model.action_count = 4;
    app_confirm_action(&view->model.actions[0], ZCL_PRESENT_ACTION_CANCEL, "close", "Close");
    app_confirm_action(&view->model.actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
    app_confirm_action(&view->model.actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
    app_confirm_action(&view->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "continue", "Keep this version");
    char why[128];
    bool ok = app_confirm_field(&view->model, "App: ", "stub/tinyapp") &&
        app_confirm_field(&view->model, "Saved version: ", id->version) &&
        zcl_present_model_page_count_v1(&view->model, count, why, sizeof(why));
    free(view); return ok && *count > 0 && *count <= ZCL_PRESENT_MODEL_PAGES_MAX;
}
static bool rus_keep_action(struct ru_run *r, const struct rus_identity *id, bool keep)
{
    if (!keep) return ruf_driver(r, "Preview opened", "--key=enter", false);
    uint32_t count = 0;
    if (!rus_keep_pages(id, &count)) return false;
    for (unsigned i = 0; i < 3; ++i)
        if (!ruf_driver(r, "Preview opened", "--key=tab", true)) return false;
    for (uint32_t page = 1; page < count; ++page)
        if (!ruf_driver(r, "Preview opened", "--key=enter", true)) return false;
    return ruf_driver(r, "Preview opened", "--key=tab", true) &&
        ruf_driver(r, "Preview opened", "--key=enter", false);
}
static bool rus_routes(const struct rus_identity *id, bool kept)
{
    struct app_selection_routes routes;
    if (app_selection_routes_load(id->env.state_dir, &routes) != APP_SELECTION_OK) return false;
    return kept ? routes.count == 1 && !strcmp(routes.names[0], id->route) : routes.count == 0;
}
static bool rus_read(struct ru_run *r, const char *command, struct json_value *reply)
{
    json_init(reply);
    bool got = ru_read_line(r->output, r->line, sizeof(r->line), 15000);
    uint32_t code = UINT32_MAX;
    bool exited = ru_wait(&r->server, 5000, &code) == PLATFORM_PROCESS_WAIT_EXITED && code == 0;
    close(r->output); r->output = -1;
    if (!got || !exited) return false;
    printf("APP_RECEIVE_SUCCESS command=%s wire=%s\n", command, r->line);
    return json_read(reply, r->line, strlen(r->line)) && !strcmp(ru_string(reply, "command"), command) &&
        !strcmp(ru_string(reply, "status"), "passed") && ruf_bool(reply, "ok", true);
}
static bool rus_root(const struct json_value *d, const char *key, char out[65])
{
    const char *s = ru_string(d, key); uint8_t root[32];
    if (strlen(s) != 64 || !zcl_hex_decode_lower(s, root, 32)) return false;
    memcpy(out, s, 65); return true;
}
static bool rus_operation(const struct json_value *op, const struct receive_fixture *f,
    const struct rus_identity *id)
{
    const struct json_value *code = json_get(op, "exit_code");
    return code && code->type == JSON_INT && json_get_int(code) == 0 &&
        ruf_bool(op, "exit_observed", true) && ruf_bool(op, "stdout_complete", true) &&
        ruf_bool(op, "stdout_truncated", false) && ruf_bool(op, "result_parsed", true) &&
        !strcmp(ru_string(op, "status"), "passed") &&
        !strcmp(ru_string(op, "version"), id->version) && !strcmp(ru_string(op, "package_root"), f->package);
}
static bool rus_process(const struct json_value *d, struct rus_identity *id)
{
    const struct json_value *pid = json_get(d, "pid");
    const char *start = ru_string(d, "start_token"); char *end = NULL; errno = 0;
    unsigned long long token = strtoull(start, &end, 10);
    if (!pid || pid->type != JSON_INT || json_get_int(pid) <= 1 || json_get_int(pid) > INT_MAX ||
        errno || !*start || !end || *end || !token) return false;
    id->running.pid = (pid_t)json_get_int(pid); id->running.token = token;
    (void)snprintf(id->running.image, sizeof(id->running.image), "%s", id->image_path);
    return ru_image_live(&id->running) && ruf_bool(d, "ready", true) &&
        !strcmp(ru_string(d, "ready_basis"), "alive") && ru_string(d, "mapped_proof")[0];
}
static bool rus_image(const struct receive_fixture *f, struct rus_identity *id, const struct json_value *built)
{
    if (!rus_root(built, "image_sha3", id->image) || !rus_root(built, "record_id", id->record)) return false;
    int n = snprintf(id->image_path, sizeof(id->image_path), "%s/app_build/images/%s", f->datadir, id->image);
    if (n <= 0 || (size_t)n >= sizeof(id->image_path)) return false;
    struct app_image_build captured = {0}; char hex[65];
    if (!app_image_capture(id->image_path, &captured).ok) return false;
    zcl_hex_encode(captured.image_sha3, 32, hex); return !strcmp(hex, id->image);
}
static bool rus_opened_summary(struct rus_identity *id, const struct json_value *opened)
{
    const char *route = ru_string(opened, "name");
    if (!app_selection_route_valid(route) || strlen(route) >= sizeof(id->route)) return false;
    memcpy(id->route, route, strlen(route) + 1);
    return !strcmp(ru_string(opened, "image_sha3"), id->image) &&
        !strcmp(ru_string(opened, "record_id"), id->record) && rus_process(opened, id);
}
static bool rus_kept_receipt(const struct json_value *d, const struct rus_identity *id, bool keep)
{
    const struct json_value *kept = json_get(d, "kept");
    if (!keep) return !kept;
    const struct json_value *revision = json_get(kept, "selection_revision");
    return revision && revision->type == JSON_INT && json_get_int(revision) == 1 &&
        !strcmp(ru_string(kept, "name"), id->route) &&
        !strcmp(ru_string(kept, "version"), id->version) &&
        !strcmp(ru_string(kept, "image_sha3"), id->image) &&
        !strcmp(ru_string(kept, "record_id"), id->record);
}
static bool rus_receipt(struct ru_run *r, struct rus_identity *id, bool keep, const struct json_value *reply)
{
    const struct receive_fixture *f = r->fixture;
    const struct json_value *d = json_get(reply, "data"), *ops = json_get(d, "operations");
    if (!ops || ops->type != JSON_ARR || json_size(ops) != 3) return false;
    for (size_t i = 0; i < 3; ++i) if (!rus_operation(json_at(ops, i), f, id)) return false;
    const struct json_value *built = json_at(ops, 1), *opened = json_at(ops, 2);
    if (!rus_image(f, id, built)) return false;
    return !strcmp(ru_string(built, "stage"), "commit") &&
        rus_opened_summary(id, opened) &&
        !strcmp(ru_string(d, "continuation"), keep ? "kept" : "previewed") &&
        ruf_bool(d, "continuation_executed", true) && !json_get(d, "continuation_error") &&
        rus_kept_receipt(d, id, keep);
}
static bool rus_original_receipt(const struct receive_fixture *f, const struct rus_identity *id,
    const struct json_value *reply)
{
    const struct json_value *d = json_get(reply, "data");
    return ruf_bool(d, "executed", false) && !strcmp(ru_string(d, "stage"), "commit") &&
        !strcmp(ru_string(d, "release_id"), f->release) && !strcmp(ru_string(d, "package_root"), f->package) &&
        !strcmp(ru_string(d, "publisher_fingerprint"), f->publisher) &&
        !strcmp(ru_string(d, "destination"), f->destination) &&
        !strcmp(ru_string(d, "version"), id->version) && ru_string(d, "trust_record")[0];
}
static bool rus_selection_record(const struct receive_fixture *f, const struct app_selection *s)
{
    char store[1024]; int n = snprintf(store, sizeof(store), "%s/app_build/records", f->datadir);
    struct app_image_build rec; bool hit = false; uint8_t root[32];
    if (n <= 0 || (size_t)n >= sizeof(store) ||
        !app_image_build_load(store, s->package, s->env, s->dependencies, &rec, &hit).ok || !hit) return false;
    return app_image_build_id(&rec, root).ok && !memcmp(root, s->record, 32) &&
        !memcmp(rec.image_sha3, s->image, 32);
}
static bool rus_selection(const struct receive_fixture *f, const struct rus_identity *id)
{
    struct app_selection s; uint8_t root[32];
    if (app_selection_load(id->env.state_dir, id->route, &s) != APP_SELECTION_OK || s.revision != 1) return false;
    if (strcmp(s.copy, f->destination) || strcmp(s.datadir, f->datadir) || memcmp(s.fork, id->fork, 32)) return false;
    const char *values[] = {id->version, f->package, f->release, id->image, id->record};
    const uint8_t *roots[] = {s.version, s.package, s.parent, s.image, s.record};
    for (size_t i = 0; i < sizeof(values)/sizeof(values[0]); ++i)
        if (!zcl_hex_decode_lower(values[i], root, 32) || memcmp(root, roots[i], 32)) return false;
    return rus_selection_record(f, &s);
}
static bool rus_cli(struct ru_run *r, const char *verb, const char *route)
{
    int out[2]; char image[PATH_MAX], datadir[1024];
    if (!realpath("build/bin/z23-dev", image) ||
        !ru_cli_option(datadir, sizeof(datadir), "datadir", r->fixture->datadir) || !ru_pipe(out)) return false;
    int log = ru_log(r, "receive-success-cli.log"), in = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const char *argv[] = {image, "app", verb, datadir, "--json", route, NULL};
    bool ok = log >= 0 && in >= 0 && ru_spawn(&r->server, argv, in, out[1], log);
    close(out[1]); if (log >= 0) close(log); if (in >= 0) close(in);
    r->output = out[0]; return ok;
}
static bool rus_list(struct ru_run *r, const struct rus_identity *id)
{
    struct json_value reply; json_init(&reply);
    bool ok = rus_cli(r, "list", NULL) && rus_read(r, "app.list", &reply);
    const struct json_value *list = json_get(json_get(&reply, "data"), "launchable");
    size_t found = 0;
    if (!list || list->type != JSON_ARR) ok = false;
    else for (size_t i = 0; i < json_size(list); ++i) {
        const struct json_value *row = json_at(list, i);
        if (strcmp(ru_string(row, "id"), id->route)) continue;
        ++found;
        ok = ok && !strcmp(ru_string(row, "source"), "kept") &&
            !strcmp(ru_string(row, "validation"), "required-on-open");
    }
    json_free(&reply); return ok && found == 1;
}
static bool rus_reopened(struct ru_run *r, struct rus_identity *id, const struct json_value *reply)
{
    const struct json_value *d = json_get(reply, "data");
    return !strcmp(ru_string(d, "name"), id->route) &&
        !strcmp(ru_string(d, "version"), id->version) &&
        !strcmp(ru_string(d, "package_root"), r->fixture->package) &&
        !strcmp(ru_string(d, "image_sha3"), id->image) &&
        !strcmp(ru_string(d, "record_id"), id->record) &&
        !strcmp(ru_string(d, "image_path"), id->image_path) && rus_process(d, id);
}
static bool rus_reopen(struct ru_run *r, struct rus_identity *id)
{
    /* End the preview first; the new CLI must resolve only the kept route. */
    if (!ru_stop(&id->running)) return false;
    struct json_value reply; json_init(&reply);
    bool ok = rus_cli(r, "open", id->route) && rus_read(r, "app.open", &reply) &&
        rus_reopened(r, id, &reply);
    json_free(&reply);
    bool stopped = ru_stop(&id->running); return ok && stopped;
}
/* Only adopted direct descendants in this isolated fixture qualify. A live
 * image must be the fixture's content-addressed build image, checked by bytes,
 * PID start token and executable again by ru_stop. Unknown children fail closed. */
static bool rus_owned_image(const struct ru_run *r, const char *image)
{
    char prefix[1024], canonical[PATH_MAX], hex[65]; uint8_t root[32];
    int n = snprintf(prefix, sizeof(prefix), "%s/app_build/images/", r->fixture->datadir);
    if (n <= 0 || (size_t)n >= sizeof(prefix) || strncmp(image, prefix, (size_t)n)) return false;
    const char *tail = image + n;
    if (strlen(tail) != 64 || !zcl_hex_decode_lower(tail, root, 32) ||
        !realpath(image, canonical) || strcmp(canonical, image)) return false;
    struct app_image_build rec = {0};
    if (!app_image_capture(image, &rec).ok) return false;
    zcl_hex_encode(rec.image_sha3, 32, hex); return !strcmp(hex, tail);
}
static bool rus_adopted_stop(pid_t pid, const struct ru_run *r)
{
    struct ru_child child = {.pid = pid};
    if (!app_proc_identity(pid, child.image, &child.token)) return ru_reaped_identity_failure(&child);
    if (child.token && rus_owned_image(r, child.image)) return ru_stop(&child);
    return ruf_adopted_stop(pid, r); /* Existing fixed CLI/make/shell custody. */
}
static bool rus_workers_stop(struct ru_run *r)
{
    for (unsigned pass = 0; pass < 8; ++pass) {
        pid_t pids[32]; size_t count; bool found = false;
        if (!ruf_children(pids, &count)) return false;
        for (size_t i = 0; i < count; ++i) {
            if (pids[i] == r->display.pid || pids[i] == r->driver.pid) continue;
            found = true;
            if (!rus_adopted_stop(pids[i], r)) return false;
        }
        if (!found) return true;
    }
    return false;
}
static bool rus_cleanup(struct ru_run *r, bool custody, int old_subreaper)
{
    bool server = ru_stop(&r->server);
    bool workers = custody && server && rus_workers_stop(r);
    bool direct = ru_cleanup(r);
    bool empty = custody && ruf_child_baseline(r);
    bool restored = !custody || (workers && empty && prctl(PR_SET_CHILD_SUBREAPER, old_subreaper) == 0);
    return server && direct && (!custody || (workers && empty)) && restored;
}
static bool rus_start(struct ru_run *r, struct receive_fixture *f, struct rus_identity *id, uint32_t pages)
{
    if (!ruf_cli(r, RUF_CLOSE) || !ru_window(r, true) || !ru_pending(r) || !ru_pages(r, pages) ||
        !ruf_driver(r, "Your copy is ready", "--expect-count=1", false)) return false;
    char why[256];
    return rus_received(f, id, true) && app_launch_env_from_process(&id->env, why, sizeof(why)) &&
        rus_routes(id, false) && abc_put(f->destination, "src/main.c", rus_dirty) &&
        ruf_choose_build(r) && rus_wait_keep_window(r);
}
static bool rus_after_reply(struct ru_run *r, struct receive_fixture *f, struct rus_identity *id, bool keep)
{
    if (!ru_committed_modes(r) || !rus_received(f, id, false) || !rus_routes(id, keep)) return false;
    if (!ruf_driver(r, "Preview opened", "--expect-count=0", false)) return false;
    if (!keep) return ru_stop(&id->running);
    return rus_selection(f, id) && rus_list(r, id) && rus_reopen(r, id) &&
        rus_selection(f, id) && rus_received(f, id, false);
}
static bool rus_finish(struct ru_run *r, struct receive_fixture *f, struct rus_identity *id, bool keep)
{
    if (!rus_routes(id, false) || !rus_keep_action(r, id, keep)) return false;
    struct json_value reply; json_init(&reply);
    bool ok = rus_read(r, "app.receive", &reply) && rus_original_receipt(f, id, &reply) &&
        rus_receipt(r, id, keep, &reply);
    json_free(&reply);
    return ok && rus_after_reply(r, f, id, keep);
}
static int rus_case(bool keep)
{
    int failures = 0; size_t saved = 0;
    struct ru_env env[] = {{"HOME", NULL}, {"XDG_CONFIG_HOME", NULL}, {"XDG_STATE_HOME", NULL},
        {"XDG_RUNTIME_DIR", NULL}, {"XDG_CACHE_HOME", NULL}, {"XDG_DATA_HOME", NULL},
        {"DISPLAY", NULL}, {"WAYLAND_DISPLAY", NULL}, {"XAUTHORITY", NULL},
        {"ZCL_CLI_TEST_NO_SERVICE_LOOKUP", NULL}, {"ZCL_DATADIR", NULL}};
    struct receive_fixture f = {0}; struct rus_identity id = {0};
    struct ru_run r = {.input = -1, .output = -1, .fixture = &f, .file_only = true};
    struct sigaction old_pipe, ignore_pipe = {.sa_handler = SIG_IGN}; bool signal_saved = false;
    int old_subreaper = 0; bool custody = false; uint32_t pages = 0;
    TEST("received saved version builds and previews; Close does not Keep, explicit Keep lists and reopens") {
        ASSERT(ru_env_save(env, sizeof(env)/sizeof(env[0]), &saved));
        ASSERT(sigemptyset(&ignore_pipe.sa_mask) == 0 && sigaction(SIGPIPE, &ignore_pipe, &old_pipe) == 0);
        signal_saved = true;
        ASSERT(rt_setup(&f) && rus_bundle(&f));
        ASSERT(ru_environment(&f) && ru_file_only_setup(&f));
        ASSERT(ru_page_count(&f, &pages) && ru_home_unchanged(&r));
        ASSERT(realpath("build/bin/native_ui_driver", r.driver_image));
        ASSERT(ru_xvfb(&r) && ruf_child_baseline(&r));
        ASSERT(prctl(PR_GET_CHILD_SUBREAPER, &old_subreaper) == 0);
        ASSERT(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0);
        custody = true;
        ASSERT(rus_start(&r, &f, &id, pages));
        ASSERT(rus_finish(&r, &f, &id, keep));
        PASS();
    } _test_next:;
    bool clean = rus_cleanup(&r, custody, old_subreaper);
    if (signal_saved && sigaction(SIGPIPE, &old_pipe, NULL) != 0) clean = false;
    if (!ru_env_restore(env, saved)) clean = false;
    printf("APP_RECEIVE_SUCCESS keep=%d fixture=%s version=%s image=%s cleanup=%d\n",
        keep, f.world.root, id.version, id.image, clean);
    if (!clean) failures++;
    return failures;
}
/* Deterministic real-X11 controls for the included maintained UI driver.
 * Reuse this group's private display and exact direct-child custody. */
static bool rud_one(struct ru_run *r, const char *mode, uint32_t expected)
{
    int log = ru_log(r, "driver-readiness.log");
    const char *args[] = {r->driver_image, mode, NULL};
    bool ok = log >= 0 && ru_spawn(&r->driver, args, log, log, log);
    if (log >= 0) close(log);
    uint32_t code = UINT32_MAX;
    ok = ok && ru_wait(&r->driver, 5000, &code) == PLATFORM_PROCESS_WAIT_EXITED && code == expected;
    bool stopped = ru_stop(&r->driver);
    printf("UI_DRIVER_READINESS mode=%s exit=%u expected=%u cleanup=%d\n", mode, code, expected, stopped);
    return ok && stopped;
}
static bool rud_cases(struct ru_run *r)
{
    static const char *const modes[] = {"delayed", "unmapped", "unchanged", "unexpected", "race"};
    bool ok = true;
    for (size_t i = 0; i < sizeof(modes)/sizeof(modes[0]); ++i) {
        bool passed = rud_one(r, modes[i], i == 3 ? 77u : 0u);
        ok = passed && ok;
    }
    return ok;
}
static int rud_readiness(void)
{
    int failures = 0; size_t saved = 0;
    struct ru_env env[] = {{"HOME", NULL}, {"XDG_CONFIG_HOME", NULL}, {"XDG_STATE_HOME", NULL},
        {"XDG_RUNTIME_DIR", NULL}, {"XDG_CACHE_HOME", NULL}, {"XDG_DATA_HOME", NULL},
        {"DISPLAY", NULL}, {"WAYLAND_DISPLAY", NULL}, {"XAUTHORITY", NULL},
        {"ZCL_CLI_TEST_NO_SERVICE_LOOKUP", NULL}};
    struct receive_fixture f = {0};
    struct ru_run r = {.input = -1, .output = -1, .fixture = &f};
    TEST("native UI driver waits for drawable readiness without weakening pixel assertions") {
        ASSERT(ru_env_save(env, sizeof(env)/sizeof(env[0]), &saved));
        ASSERT(test_mkdtemp(f.world.root, sizeof(f.world.root), "ui_driver_readiness"));
        ASSERT(ru_environment(&f));
        ASSERT(realpath("build/bin/native_ui_driver_readiness", r.driver_image));
        ASSERT(ru_xvfb(&r));
        ASSERT(rud_cases(&r));
        PASS();
    } _test_next:;
    bool clean = ru_cleanup(&r);
    if (!ru_env_restore(env, saved)) clean = false;
    printf("UI_DRIVER_READINESS fixture=%s display=%s cleanup=%d\n", f.world.root, r.display_name, clean);
    if (!clean) ++failures;
    /* Retained log distinguishes driver rejection from fixture/setup failure. */
    return failures;
}

int test_app_receive_ui(void)
{
    if (access("/usr/bin/Xvfb", X_OK) != 0) { puts("SKIP (app_receive_ui requires Linux Xvfb)"); return 0; }
    int failures = rud_readiness();
    failures += ru_case(false, false, false);
    failures += ru_case(true, false, false);
    failures += ru_case(true, true, false);
    failures += ru_case(true, true, true);
    failures += ruf_case_run(RUF_CLOSE);
    failures += ruf_case_run(RUF_INVALID);
    failures += ruf_case_run(RUF_BUILD_FAILURE);
    failures += ruf_case_run(RUF_CUSTODY_FAILURE);
    failures += ruf_case_run(RUF_PROGRESS_CLOSE);
    failures += ruf_case_run(RUF_PROGRESS_CLOSE_OK);
    failures += ruf_case_run(RUF_PLAN_CLOSE);
    failures += rus_case(false);
    return failures + rus_case(true);
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
