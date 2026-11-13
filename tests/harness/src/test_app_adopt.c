/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"
#include "command/native_app_adopt.h"
#include "command/native_app_confirm.h"
#include "command/native_command.h"
#include "command/native_zcode_package_copy.h"
#include "base/hex.h"
#include "chain/chainparams.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "presentation/model.h"
#include "presentation/model_render.h"
#include "presentation/presentation.h"
#include "json/json.h"
#include "plugin/plugin_dist.h"
#include "plugin/plugin_pack.h"
#include "vcs/package_prepare.h"
#include "vcs/package_release.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32) && defined(ZCL_TESTING)
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#define ABC_DAY 20400
#define ABC_PATH 900
struct abc_world { char root[512], src[600], alice_datadir[600], origin_release[65]; };
static bool abc_put(const char *dir, const char *rel, const char *text)
{
    char path[ABC_PATH];
    if (snprintf(path, sizeof(path), "%s/%s", dir, rel) >= (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "wb");
    bool ok = f && fputs(text, f) >= 0;
    return f ? fclose(f) == 0 && ok : false;
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
    char text[4096];
    FILE *f = fopen("apps/skycombat/LICENSE", "rb");
    if (!f)
        return false;
    size_t n = fread(text, 1, sizeof(text) - 1u, f);
    (void)fclose(f);
    text[n] = '\0';
    return n > 0 && abc_put(dir, "LICENSE", text);
}

static const char k_main[] = "int main(void) { return 0; }\n";

static bool abc_stub_source(struct abc_world *w)
{
    char dir[ABC_PATH];
    bool ok = mkdir(w->src, 0700) == 0 && abc_license(w->src);
    (void)snprintf(dir, sizeof(dir), "%s/include", w->src);
    ok = ok && mkdir(dir, 0700) == 0;
    (void)snprintf(dir, sizeof(dir), "%s/src", w->src);
    ok = ok && mkdir(dir, 0700) == 0;
    return ok && abc_put(w->src, "zcode-package.json", k_meta) &&
           abc_put(w->src, "Makefile", k_makefile) &&
           abc_put(w->src, "include/boost.h", "#define BOOST 1\n") &&
           abc_put(w->src, "src/main.c", k_main);
}

/* The original publisher signs the stub with its own release key. */
static bool abc_publish_origin(struct abc_world *w)
{
    char key[700], pubhex[PLUGIN_HEX_PUBLIC_KEY + 1];
    struct plugin_dist_published why;
    struct vcs_package_prepare_options o = {
        .dir = w->src, .publisher_sequence = 1, .reward_address = "",
        .chain_id = "zclassic-main",
    };
    struct vcs_package_prepared p;
    char detail[256] = {0};
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    (void)snprintf(key, sizeof(key), "%s/origin.key", w->root);
    if (plugin_keygen(key, pubhex) != PLUGIN_OK ||
        plugin_dist_release_key_sign(key, NULL, o.publisher_pubkey, NULL,
                                     &why) != PLUGIN_DIST_OK ||
        vcs_package_prepare(&o, &p, detail, sizeof(detail)) !=
            VCS_PACKAGE_PREPARE_OK) {
        printf("  [stub publish setup: %s]\n", detail);
        return false;
    }
    bool ok = plugin_dist_release_key_sign(key, p.signing_digest,
                                           o.publisher_pubkey,
                                           p.release.signature,
                                           &why) == PLUGIN_DIST_OK &&
              vcs_package_release_serialize(&p.release, &wire, &wire_len) ==
                  VCS_PACKAGE_RELEASE_OK;
    struct zcl_command_reply r;
    zcl_command_reply_init(&r, "zcl.test.app_build_copy.v1");
    const struct zcl_native_local_publication pub = {
        .datadir = w->alice_datadir, .source_directory = w->src,
        .release_wire = wire, .release_wire_len = wire_len,
        .manifest_wire = p.manifest_wire,
        .manifest_wire_len = p.manifest_wire_len,
        .recipe_wire = p.recipe_wire, .recipe_wire_len = p.recipe_wire_len,
        .has_day = true, .day = ABC_DAY,
    };
    if (ok)
        zcl_native_zcode_local_publication_commit(&pub, &r);
    ok = ok && r.status == ZCL_COMMAND_STATUS_PASSED;
    if (!ok)
        printf("  [stub publish: %s %s]\n", r.error.code, r.error.message);
    zcl_hex_encode(p.signing_digest, 32, w->origin_release);
    zcl_command_reply_free(&r);
    free(wire);
    vcs_package_prepared_free(&p);
    return ok;
}


static bool ad_setup(struct abc_world *w)
{
    memset(w, 0, sizeof(*w));
    if (!test_mkdtemp(w->root, sizeof(w->root), "app_adopt")) return false;
    if (setenv("HOME", w->root, 1) != 0) return false;
    (void)snprintf(w->src, sizeof(w->src), "%s/source", w->root);
    /* Force the displayed destination to span pages even under a short TMPROOT. */
    char component[181], parent[ABC_PATH];
    memset(component, 'd', sizeof(component) - 1); component[sizeof(component) - 1] = 0;
    int n = snprintf(parent, sizeof(parent), "%s/%s", w->root, component);
    if (n <= 0 || (size_t)n >= sizeof(parent) || mkdir(parent, 0700) != 0) return false;
    n = snprintf(w->alice_datadir, sizeof(w->alice_datadir), "%s/data", parent);
    return n > 0 && (size_t)n < sizeof(w->alice_datadir) && abc_stub_source(w) &&
           mkdir(w->alice_datadir, 0700) == 0 && abc_publish_origin(w);
}
static bool ad_item_has(const struct zcl_present_model_v1 *m, const char *text)
{
    for (uint32_t i = 0; i < m->item_count; ++i)
        if (strstr(m->items[i].value, text)) return true;
    return false;
}
static bool ad_plan_identity(struct json_value *plan, const char *root,
                             const char *name, const char *destination)
{
    static const char publisher[] = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static const char plan_id[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    return json_push_kv_str(plan, "plan_id", plan_id) && json_push_kv_str(plan, "release_root", root) &&
        json_push_kv_str(plan, "package_root", root) && json_push_kv_str(plan, "publisher", publisher) &&
        json_push_kv_str(plan, "name", name) && json_push_kv_str(plan, "semver", "1.0.0") &&
        json_push_kv_str(plan, "copy", destination);
}
static bool ad_plan_json(struct json_value *plan, int kind, const char *name, const char *destination)
{
    static const char h[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    json_init(plan); json_set_object(plan);
    bool ok = ad_plan_identity(plan, h, name, destination) &&
        json_push_kv_bool(plan, "has_parent", kind != 0);
    if (kind == 0) return ok;
    ok = ok && json_push_kv_str(plan, "parent_release_root", h);
    if (kind == 2) return ok && json_push_kv_str(plan, "changes_unavailable", "parent manifest unavailable");
    struct json_value rows, row; json_init(&rows); json_init(&row);
    json_set_array(&rows); json_set_object(&row);
    ok = ok && json_push_kv_str(plan, "parent_package_root", h) &&
         json_push_kv_str(&row, "path", "src/important.c") &&
         json_push_kv_str(&row, "change", "modified") && json_push_back(&rows, &row) &&
         json_push_kv_int(plan, "changes", 2) && json_push_kv(plan, "changed_paths", &rows) &&
         json_push_kv_bool(plan, "changed_paths_truncated", true);
    json_free(&row); json_free(&rows); return ok;
}
static bool ad_field_exact(const struct zcl_present_model_v1 *m,
                           const char *label, const char *expected)
{
    size_t used = 0, total = strlen(expected); bool found = false;
    for (uint32_t i = 0; i < m->item_count; ++i) {
        const char *part = m->items[i].value;
        if (!found) {
            if (strncmp(part, label, strlen(label))) continue;
            part += strlen(label); found = true;
        } else {
            if (strncmp(part, "  ", 2)) break;
            part += 2;
        }
        size_t n = strlen(part);
        if (n > total - used || memcmp(part, expected + used, n)) return false;
        used += n;
    }
    return found && used == total;
}
static int ad_model_cases(void)
{
    int failures = 0; struct json_value plan; json_init(&plan);
    struct zcl_present_model_v1 model; uint32_t pages;
    TEST("adoption model shows parent, bounded changes, truncation and unavailable") {
        ASSERT(ad_plan_json(&plan, 0, "demo/app", "/safe/copies/app"));
        ASSERT(zcl_test_app_adopt_model(&plan, &model, &pages));
        ASSERT(!model.exact_root[0]);
        ASSERT_STR_EQ(model.request_id, "adopt-bbbbbbbbbbbb");
        ASSERT(ad_field_exact(&model, "Package: ", json_get_str(json_get(&plan, "package_root"))));
        ASSERT(ad_field_exact(&model, "Release: ", json_get_str(json_get(&plan, "release_root"))));
        ASSERT(ad_field_exact(&model, "Publisher: ", json_get_str(json_get(&plan, "publisher"))));
        ASSERT(ad_item_has(&model, "None (first release)"));
        json_free(&plan);
        ASSERT(ad_plan_json(&plan, 1, "demo/app", "/safe/copies/app"));
        ASSERT(zcl_test_app_adopt_model(&plan, &model, &pages));
        ASSERT(pages > 1 && ad_item_has(&model, "Parent release:") &&
               ad_item_has(&model, "Parent package:") && ad_item_has(&model, "modified:") &&
               ad_item_has(&model, "important.c") && ad_item_has(&model, "(truncated)"));
        json_free(&plan);
        ASSERT(ad_plan_json(&plan, 2, "demo/app", "/safe/copies/app"));
        ASSERT(zcl_test_app_adopt_model(&plan, &model, &pages));
        ASSERT(ad_item_has(&model, "Unavailable") && ad_item_has(&model, "parent manifest"));
        json_free(&plan);
        ASSERT(ad_plan_json(&plan, 0, "bad\nname", "/safe/copies/app"));
        ASSERT(!zcl_test_app_adopt_model(&plan, &model, &pages));
        json_free(&plan);
        char huge[4500]; memset(huge, 'x', sizeof(huge)-1); huge[0] = '/'; huge[sizeof(huge)-1] = 0;
        ASSERT(ad_plan_json(&plan, 0, "demo/app", huge));
        ASSERT(!zcl_test_app_adopt_model(&plan, &model, &pages));
        PASS();
    } _test_next:;
    json_free(&plan); return failures;
}

enum ad_decision { AD_CANCEL, AD_CLOSE, AD_HEADLESS, AD_EARLY, AD_PAINT_FAIL, AD_CANCEL_AFTER_CONFIRM, AD_CLOSE_AFTER_CONFIRM, AD_STALE, AD_CONFIRM };
struct ad_fake {
    enum ad_decision decision;
    bool observed, safe, all_pages, complete_details;
    char destination[1024], parent[1024];
};
static bool ad_destination(const struct zcl_present_model_v1 *m, char *out, size_t cap)
{
    bool collecting = false; size_t used = 0;
    for (uint32_t i = 0; i < m->item_count; ++i) {
        const char *line = m->items[i].value, *part;
        if (!collecting) {
            if (strncmp(line, "Destination: ", 13)) continue;
            part = line + 13; collecting = true;
        } else {
            if (strncmp(line, "  ", 2)) break;
            part = line + 2;
        }
        size_t n = strlen(part);
        if (used + n >= cap) return false;
        memcpy(out + used, part, n); used += n; out[used] = 0;
    }
    return collecting && used;
}
/* Exercise the actual input translation and trusted live controller, not a
 * serialized action value or a production-global hook. */
static bool ad_action(const struct zcl_present_window_live_view_v1 *live,
                      unsigned action, bool *close, bool *redraw)
{
    struct zcl_present_input_v1 input = {.key = ZCL_PRESENT_INPUT_TEXT, .character = '1' + action};
    uint32_t focus = UINT32_MAX, selected = UINT32_MAX;
    if (!live->input(live->owner.context, &input, &focus, &selected) || selected != action) return false;
    struct zcl_present_window_event_v1 event = {.outcome = ZCL_PRESENT_WINDOW_ACTION, .action_index = selected};
    live->owner.update(live->owner.context, &event, true, redraw, close);
    return true;
}
static bool ad_default_enter(const struct zcl_present_window_live_view_v1 *live)
{
    struct zcl_present_input_v1 input = {.key = ZCL_PRESENT_INPUT_ENTER};
    uint32_t focus = UINT32_MAX, action = UINT32_MAX;
    if (!live->input(live->owner.context, &input, &focus, &action) || focus != 0 || action != 0)
        return false;
    struct zcl_present_window_event_v1 event = {.outcome = ZCL_PRESENT_WINDOW_ACTION, .action_index = action};
    bool redraw = false, close = false;
    live->owner.update(live->owner.context, &event, true, &redraw, &close);
    return close;
}
/* UP/DOWN are also the live backend's translated wheel events. Navigation
 * must preserve the focused consent button without activating it. */
static bool ad_nav(const struct zcl_present_window_live_view_v1 *live,
                   uint32_t key, uint32_t expected, bool changed)
{
    struct zcl_present_input_v1 input = {.key = key};
    uint32_t focus = 3, action = UINT32_MAX;
    if (!live->input(live->owner.context, &input, &focus, &action) ||
        focus != 3 || action != expected) return false;
    struct zcl_present_window_event_v1 event = {
        .outcome = ZCL_PRESENT_WINDOW_ACTION, .action_index = action};
    bool close = true, redraw = false;
    live->owner.update(live->owner.context, &event, false, &redraw, &close);
    return !close && redraw == changed;
}
static bool ad_visit(const struct zcl_present_window_live_view_v1 *live, uint32_t pages)
{
    if (!ad_nav(live, ZCL_PRESENT_INPUT_PAGE_UP, 1, true)) return false;
    if (!ad_nav(live, ZCL_PRESENT_INPUT_PAGE_UP, 1, false)) return false;
    for (uint32_t i = 1; i < pages; ++i) {
        if (!ad_nav(live, ZCL_PRESENT_INPUT_PAGE_DOWN, 2, true)) return false;
    }
    if (!ad_nav(live, ZCL_PRESENT_INPUT_DOWN, 2, false)) return false;
    if (!ad_nav(live, ZCL_PRESENT_INPUT_PAGE_UP, 1, true)) return false;
    if (!ad_nav(live, ZCL_PRESENT_INPUT_DOWN, 2, true)) return false;
    if (!ad_nav(live, ZCL_PRESENT_INPUT_UP, 1, true)) return false;
    return ad_nav(live, ZCL_PRESENT_INPUT_PAGE_DOWN, 2, true);
}
static bool ad_observe(struct ad_fake *f, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *page, uint32_t *pages, char *why, size_t cap)
{
    f->observed = page && page->page_count == 1 && page->pages && page->pages->pixels &&
        zcl_present_model_page_count_v1(model, pages, why, cap) && *pages > 1 &&
        model->action_count == 4 && model->actions[0].kind == ZCL_PRESENT_ACTION_CANCEL &&
        ad_destination(model, f->destination, sizeof(f->destination));
    f->complete_details = ad_item_has(model, "Name:") && ad_item_has(model, "Version:") &&
        ad_item_has(model, "Publisher:") && ad_item_has(model, "Release:") &&
        ad_item_has(model, "Package:") && ad_item_has(model, "Destination:");
    return f->observed && f->complete_details;
}
/* Preserve the deliberate post-confirm callbacks used to test revocation. */
static bool ad_after_confirm(const struct ad_fake *f,
    const struct zcl_present_window_live_view_v1 *live, bool *close, bool *redraw)
{
    if (f->decision == AD_CANCEL_AFTER_CONFIRM)
        return ad_action(live, 0, close, redraw) && *close;
    if (f->decision == AD_CLOSE_AFTER_CONFIRM) {
        struct zcl_present_window_event_v1 event = {.outcome = ZCL_PRESENT_WINDOW_DISMISSED};
        live->owner.update(live->owner.context, &event, true, redraw, close);
        return *close;
    }
    return f->decision != AD_PAINT_FAIL;
}
static bool ad_present_confirmation(struct ad_fake *f,
    const struct zcl_present_window_live_view_v1 *live, uint32_t pages)
{
    bool close = false, redraw = false;
    if (!ad_action(live, 3, &close, &redraw) || close || !redraw) return false;
    const struct app_confirm *view = live->owner.context;
    if (view->confirmed || view->page_index != 1 || (view->visited & 3u) != 3u) return false;
    f->safe = true;
    if (f->decision == AD_EARLY) return true;
    f->all_pages = ad_visit(live, pages);
    if (!f->all_pages) return false;
    if (f->decision == AD_STALE) {
        if (mkdir(f->parent, 0700) != 0 && errno != EEXIST) return false;
        if (mkdir(f->destination, 0700) != 0) return false;
    }
    if (!ad_action(live, 3, &close, &redraw) || !close) return false;
    return ad_after_confirm(f, live, &close, &redraw);
}
static bool ad_present(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *page,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    struct ad_fake *f = context;
    uint32_t pages = 0;
    if (!ad_observe(f, model, page, &pages, why, cap) || f->decision == AD_HEADLESS)
        return false;
    if (f->decision == AD_CLOSE) {
        bool close = false, redraw = false;
        struct zcl_present_window_event_v1 event = {.outcome = ZCL_PRESENT_WINDOW_DISMISSED};
        live->owner.update(live->owner.context, &event, true, &redraw, &close);
        return close;
    }
    if (f->decision == AD_CANCEL) return ad_default_enter(live);
    return ad_present_confirmation(f, live, pages);
}
static bool ad_invoke(const struct abc_world *w, struct ad_fake *fake,
                      struct zcl_command_reply *reply)
{
    struct json_value input; json_init(&input); json_set_object(&input);
    bool ok = json_push_kv_str(&input, "release_root", w->origin_release) &&
              json_push_kv_str(&input, "datadir", w->alice_datadir);
    struct zcl_command_request req = {.input = &input};
    zcl_command_reply_init(reply, "zcl.test.app_adopt.v1");
    (void)snprintf(fake->parent, sizeof(fake->parent), "%s/copies", w->alice_datadir);
    if (ok) zcl_test_app_adopt_run(&req, reply, ad_present, fake);
    json_free(&input); return ok;
}

static bool ad_reply_uncommitted(const struct zcl_command_reply *reply, bool rejected)
{
    const char *status = json_get_str(json_get(&reply->data, "status"));
    return (rejected && reply->status != ZCL_COMMAND_STATUS_PASSED) ||
        (!rejected && reply->status == ZCL_COMMAND_STATUS_PASSED && status &&
         !strcmp(status, "canceled"));
}
static bool ad_no_commit(const struct abc_world *w, enum ad_decision decision)
{
    struct ad_fake fake = {.decision = decision}; struct zcl_command_reply reply;
    if (!ad_invoke(w, &fake, &reply)) return false;
    bool rejected = decision == AD_HEADLESS || decision == AD_PAINT_FAIL;
    char key[ABC_PATH];
    (void)snprintf(key, sizeof(key), "%s/.z23/zcode_publisher.key", w->root);
    bool ok = fake.observed && fake.complete_details && access(key, F_OK) != 0 &&
        ad_reply_uncommitted(&reply, rejected) &&
        access(fake.destination, F_OK) != 0;
    if (decision == AD_EARLY || decision == AD_PAINT_FAIL) ok = ok && fake.safe;
    if (decision == AD_PAINT_FAIL) ok = ok && fake.all_pages;
    zcl_command_reply_free(&reply); return ok;
}
static bool ad_stale(const struct abc_world *w)
{
    struct ad_fake fake = {.decision = AD_STALE}; struct zcl_command_reply reply;
    if (!ad_invoke(w, &fake, &reply)) return false;
    bool ok = fake.observed && fake.safe && fake.all_pages &&
        reply.status != ZCL_COMMAND_STATUS_PASSED && !strcmp(reply.error.code, "PLAN_MISMATCH");
    zcl_command_reply_free(&reply);
    if (fake.destination[0] && rmdir(fake.destination) != 0) ok = false;
    return ok;
}
static bool ad_result_adopted(const struct abc_world *w, const char *path,
                              const char *root)
{
    struct zcl_package_copy copy = {0}; struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.app_adopt.v1");
    bool opened = zcl_package_copy_open_as(path, ZCL_PACKAGE_COPY_READ, &copy, &reply, "test");
    char actual[65] = {0};
    if (opened) zcl_hex_encode(copy.fork_version, 32, actual);
    bool ok = opened && !strcmp(actual, root) &&
        zcl_package_copy_adopted(w->alice_datadir, &copy, NULL) == ZCL_PACKAGE_COPY_ADOPTED;
    zcl_package_copy_close(&copy); zcl_command_reply_free(&reply); return ok;
}
static bool ad_personal_result(const struct json_value *data, const char *root)
{
    const char *version = json_get_str(json_get(data, "version"));
    const char *publisher = json_get_str(json_get(data, "namespace"));
    return version && strlen(version) == 64 && root && strcmp(version, root) &&
        publisher && !strncmp(publisher, "p-", 2);
}
static bool ad_confirm(const struct abc_world *w)
{
    struct ad_fake fake = {.decision = AD_CONFIRM}; struct zcl_command_reply reply;
    if (!ad_invoke(w, &fake, &reply)) return false;
    const char *copy = json_get_str(json_get(&reply.data, "copy"));
    const char *root = json_get_str(json_get(&reply.data, "root_commit"));
    const char *release = json_get_str(json_get(&reply.data, "release_root"));
    bool ok = fake.observed && fake.safe && fake.all_pages && reply.status == ZCL_COMMAND_STATUS_PASSED &&
        copy && root && !strcmp(copy, fake.destination) && strlen(root) == 64 &&
        ad_result_adopted(w, copy, root) && release && !strcmp(release, w->origin_release);
    ok = ok && ad_personal_result(&reply.data, root);
    zcl_command_reply_free(&reply); return ok;
}
int test_app_adopt(void)
{
    const char *original = getenv("HOME");
    char *saved_home = original ? strdup(original) : NULL;
    if (original && !saved_home) return 1;
    int failures = ad_model_cases(); struct abc_world world = {0};
    if (!failures) {
        TEST("adoption dialog requires complete locally confirmed decision") {
            chain_params_select(CHAIN_MAIN);
            ASSERT(ad_setup(&world));
            ASSERT(ad_no_commit(&world, AD_CANCEL));
            ASSERT(ad_no_commit(&world, AD_CLOSE));
            ASSERT(ad_no_commit(&world, AD_HEADLESS));
            ASSERT(ad_no_commit(&world, AD_EARLY));
            ASSERT(ad_no_commit(&world, AD_PAINT_FAIL));
            ASSERT(ad_no_commit(&world, AD_CANCEL_AFTER_CONFIRM));
            ASSERT(ad_no_commit(&world, AD_CLOSE_AFTER_CONFIRM));
            ASSERT(ad_stale(&world));
            ASSERT(ad_confirm(&world));
            PASS();
        } _test_next:;
    }
    if (saved_home) {
        if (setenv("HOME", saved_home, 1) != 0) failures++;
    } else if (unsetenv("HOME") != 0) failures++;
    free(saved_home);
    if (world.root[0]) (void)test_rm_rf_recursive(world.root);
    return failures;
}
#else
int test_app_adopt(void) { return 0; }
#endif
