/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
#include "test/test_core.h"
#include "command/app_selection.h"
#include "command/native_app_launch.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>

static void sel_fixture(struct app_selection *s, const char *dir)
{
    memset(s, 0, sizeof(*s));
    (void)snprintf(s->app, sizeof(s->app), "skycombat");
    (void)snprintf(s->copy, sizeof(s->copy), "%s", dir);
    (void)snprintf(s->datadir, sizeof(s->datadir), "%s", dir);
    uint8_t *roots[] = {s->fork, s->parent, s->version, s->package,
                        s->env, s->dependencies, s->record, s->image};
    for (size_t i = 0; i < 8; ++i) memset(roots[i], (int)i + 1, 32);
}
static int sel_child(const char *dir, const struct app_selection *s, int gate, int slot)
{
    char byte;
    if (read(gate, &byte, 1) != 1) return 2;
    struct app_selection next = *s, out;
    next.version[0] = (uint8_t)slot;
    enum app_selection_result r = app_selection_save(dir, 1, &next, &out);
    return r == APP_SELECTION_OK ? 0 : r == APP_SELECTION_STALE ? 1 : 2;
}
static bool sel_wait(pid_t pid, int *code)
{
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) return false;
    if (!WIFEXITED(status)) return false;
    *code = WEXITSTATUS(status); return true;
}
static bool sel_race(const char *dir, const struct app_selection *s)
{
    int gate[2];
    if (pipe(gate) != 0) return false;
    pid_t first = fork();
    if (first == 0) { close(gate[1]); _exit(sel_child(dir, s, gate[0], 11)); }
    pid_t second = first > 0 ? fork() : -1;
    if (second == 0) { close(gate[1]); _exit(sel_child(dir, s, gate[0], 12)); }
    close(gate[0]);
    bool sent = first > 0 && second > 0 && write(gate[1], "xx", 2) == 2;
    close(gate[1]);
    int a = -1, b = -1;
    bool done_a = first > 0 && sel_wait(first, &a);
    bool done_b = second > 0 && sel_wait(second, &b);
    return sent && done_a && done_b && ((a == 0 && b == 1) || (a == 1 && b == 0));
}
struct sel_thread { const char *dir; struct app_selection selection; atomic_bool *go; enum app_selection_result result; };
static void *sel_first_thread(void *opaque)
{
    struct sel_thread *t = opaque; struct app_selection out;
    while (!atomic_load(t->go)) sched_yield();
    t->result = app_selection_save(t->dir, 0, &t->selection, &out);
    return NULL;
}
static bool sel_first_threads(const char *dir)
{
    atomic_bool go = false;
    struct sel_thread t[2] = {{.dir=dir, .go=&go}, {.dir=dir, .go=&go}};
    sel_fixture(&t[0].selection, dir); sel_fixture(&t[1].selection, dir);
    (void)snprintf(t[0].selection.app, sizeof(t[0].selection.app), "parallel-a");
    (void)snprintf(t[1].selection.app, sizeof(t[1].selection.app), "parallel-b");
    pthread_t a, b;
    if (pthread_create(&a, NULL, sel_first_thread, &t[0]) != 0) return false;
    if (pthread_create(&b, NULL, sel_first_thread, &t[1]) != 0) {
        atomic_store(&go, true); pthread_join(a, NULL); return false;
    }
    atomic_store(&go, true);
    pthread_join(a, NULL); pthread_join(b, NULL);
    return t[0].result == APP_SELECTION_OK && t[1].result == APP_SELECTION_OK;
}
#if defined(ZCL_TESTING)
static struct app_selection sel_swap_value;
static char sel_swap_old[600];
static bool sel_swap_done;
static void sel_swap(const char *dir)
{
    app_selection_test_swap_hook(NULL);
    struct app_selection out;
    if (rename(dir, sel_swap_old) != 0 || mkdir(dir, 0700) != 0) return;
    sel_swap_value.version[0] = 42;
    bool ok = app_selection_save(dir, 0, &sel_swap_value, &out) == APP_SELECTION_OK;
    sel_swap_value.version[0] = 43;
    sel_swap_done = ok && app_selection_save(dir, 1, &sel_swap_value, &out) == APP_SELECTION_OK;
}
static bool sel_directory_swap(const char *dir, struct app_selection *input)
{
    struct app_selection old, replacement, out;
    (void)snprintf(sel_swap_old, sizeof(sel_swap_old), "%s.moved", dir);
    sel_swap_value = *input; sel_swap_done = false;
    app_selection_test_swap_hook(sel_swap);
    enum app_selection_result result = app_selection_save(dir, 2, input, &out);
    app_selection_test_swap_hook(NULL);
    bool ok = sel_swap_done && result == APP_SELECTION_IO &&
        app_selection_load(dir, input->app, &replacement) == APP_SELECTION_OK &&
        replacement.revision == 2 && replacement.version[0] == 43 &&
        app_selection_load(sel_swap_old, input->app, &old) == APP_SELECTION_OK && old.revision == 2;
    (void)test_rm_rf_recursive(sel_swap_old);
    return ok;
}
static bool sel_sync_failure(const char *dir, struct app_selection *input)
{
    struct app_selection out;
    app_selection_test_fail_directory_sync(true);
    enum app_selection_result result = app_selection_save(dir, 2, input, &out);
    app_selection_test_fail_directory_sync(false);
    return result == APP_SELECTION_IO && app_selection_load(dir, input->app, &out) == APP_SELECTION_OK &&
        out.revision == 3 && app_selection_save(dir, 2, input, &out) == APP_SELECTION_STALE;
}
#endif

static int sel_persistence(char dir[512], struct app_selection *fixture)
{
    int failures = 0;
    struct app_selection input, saved, loaded;
    TEST("selection persists and serializes competing revisions") {
        ASSERT(test_mkdtemp(dir, 512, "app_selection"));
        ASSERT(sel_first_threads(dir));
        sel_fixture(&input, dir);
        ASSERT(app_selection_load(dir, input.app, &loaded) == APP_SELECTION_ABSENT);
        ASSERT(app_selection_save(dir, 0, &input, &saved) == APP_SELECTION_OK && saved.revision == 1);
        memset(&loaded, 0, sizeof(loaded));
        ASSERT(app_selection_load(dir, input.app, &loaded) == APP_SELECTION_OK);
        ASSERT(loaded.revision == 1 && !strcmp(loaded.copy, input.copy) &&
               !strcmp(loaded.datadir, input.datadir) && !memcmp(loaded.version, input.version, 32) &&
               !memcmp(loaded.image, input.image, 32));
        ASSERT(app_selection_save(dir, 0, &input, &saved) == APP_SELECTION_STALE);
        ASSERT(sel_race(dir, &input));
        ASSERT(app_selection_load(dir, input.app, &loaded) == APP_SELECTION_OK && loaded.revision == 2);
        ASSERT(loaded.version[0] == 11 || loaded.version[0] == 12);
        *fixture = input;
        PASS();
    } _test_next:;
    return failures;
}
#if defined(ZCL_TESTING)
static int sel_durability(const char *dir, struct app_selection *input)
{
    int failures = 0;
        TEST("selection uses one directory for CAS and reports sync uncertainty") {
            ASSERT(sel_directory_swap(dir, input));
            ASSERT(sel_sync_failure(dir, input));
            PASS();
        } _test_next:;
    return failures;
}
#endif
static int sel_invalid(const char *dir, struct app_selection input)
{
    int failures = 0;
    char file[600];
    struct app_selection saved, loaded;
        TEST("selection refuses invalid fields and corrupt records without replacing them") {
            struct app_selection bad = input;
            (void)snprintf(bad.app, sizeof(bad.app), "../bad");
            ASSERT(app_selection_save(dir, 0, &bad, &saved) == APP_SELECTION_INVALID);
            bad = input; memset(bad.copy, 'x', sizeof(bad.copy));
            ASSERT(app_selection_save(dir, 0, &bad, &saved) == APP_SELECTION_INVALID);
            bad = input; memset(bad.image, 0, sizeof(bad.image));
            ASSERT(app_selection_save(dir, 3, &bad, &saved) == APP_SELECTION_INVALID);
            (void)snprintf(file, sizeof(file), "%s/skycombat.selection", dir);
            int fd = open(file, O_WRONLY);
            ASSERT(fd >= 0 && write(fd, "x", 1) == 1 && close(fd) == 0);
            ASSERT(app_selection_load(dir, input.app, &loaded) == APP_SELECTION_INVALID);
            fd = open(file, O_WRONLY | O_TRUNC);
            ASSERT(fd >= 0 && write(fd, "bad", 3) == 3 && close(fd) == 0);
            ASSERT(app_selection_load(dir, input.app, &loaded) == APP_SELECTION_INVALID);
            ASSERT(app_selection_save(dir, 3, &input, &saved) == APP_SELECTION_INVALID);
            ASSERT(unlink(file) == 0);
            ASSERT(app_selection_load(dir, input.app, &loaded) == APP_SELECTION_ABSENT);
            PASS();
        } _test_next:;
    return failures;
}

static bool sel_route_files(const char *dir)
{
    char path[600]; struct stat st;
    (void)snprintf(path, sizeof(path), "%s/@kept-skycombat.selection", dir);
    if (stat(path, &st) || !S_ISREG(st.st_mode)) return false;
    (void)snprintf(path, sizeof(path), "%s/@kept-skycombat.selection.lock", dir);
    if (stat(path, &st) || !S_ISREG(st.st_mode)) return false;
    (void)snprintf(path, sizeof(path), "%s/kept:skycombat.selection", dir);
    return lstat(path, &st) != 0 && errno == ENOENT;
}
static int sel_route_persistence(const char *dir)
{
    int failures = 0; struct app_selection input, out, legacy;
    struct app_selection_routes routes;
    struct app_launch_entry entry;
    TEST("kept routes retain full wire identity and disjoint filenames and revision CAS") {
        sel_fixture(&input, dir);
        ASSERT(app_selection_save(dir, 0, &input, &legacy) == APP_SELECTION_OK);
        (void)snprintf(input.app, sizeof(input.app), "kept:skycombat");
        memset(&entry, 0xff, sizeof(entry));
        ASSERT(app_launch_kept_entry(input.app, &entry));
        ASSERT(!strcmp(entry.id, input.app) && !entry.arg_count && !entry.alias_count);
        ASSERT(!entry.executable[0] && !entry.ready_marker[0] && !entry.raise_sigusr1);
        ASSERT(app_selection_save(dir, 0, &input, &out) == APP_SELECTION_OK);
        ASSERT(sel_route_files(dir));
        ASSERT(app_selection_load(dir, input.app, &out) == APP_SELECTION_OK);
        ASSERT(!strcmp(out.app, input.app) && out.revision == 1);
        ASSERT(sel_race(dir, &input));
        ASSERT(app_selection_load(dir, "skycombat", &out) == APP_SELECTION_OK && out.revision == 1);
        ASSERT(app_selection_routes_load(dir, &routes) == APP_SELECTION_OK && routes.count == 1);
        ASSERT(!strcmp(routes.names[0], input.app));
        PASS();
    } _test_next:;
    return failures;
}
static int sel_route_damage(const char *dir)
{
    int failures = 0; char path[600]; struct app_selection loaded;
    struct app_selection_routes routes;
    TEST("kept enumeration refuses damaged records and never returns a partial list") {
        (void)snprintf(path, sizeof(path), "%s/@kept-skycombat.selection", dir);
        int fd = open(path, O_WRONLY | O_TRUNC);
        ASSERT(fd >= 0);
        bool written = write(fd, "bad", 3) == 3;
        ASSERT(close(fd) == 0 && written);
        ASSERT(app_selection_load(dir, "kept:skycombat", &loaded) == APP_SELECTION_INVALID);
        ASSERT(app_selection_routes_load(dir, &routes) == APP_SELECTION_INVALID && routes.count == 0);
        ASSERT(unlink(path) == 0);
        ASSERT(app_selection_load(dir, "kept:skycombat", &loaded) == APP_SELECTION_ABSENT);
        ASSERT(app_selection_routes_load(dir, &routes) == APP_SELECTION_OK && routes.count == 0);
        PASS();
    } _test_next:;
    return failures;
}
static bool sel_route_fill(const char *dir, unsigned count)
{
    struct app_selection input, out; sel_fixture(&input, dir);
    for (unsigned i = 0; i < count; ++i) {
        (void)snprintf(input.app, sizeof(input.app), "kept:route-%02u", i);
        if (app_selection_save(dir, 0, &input, &out) != APP_SELECTION_OK) return false;
    }
    return true;
}
static int sel_route_bounds(const char *dir)
{
    int failures = 0; struct app_selection_routes routes;
    TEST("kept grammar and enumeration limits refuse rather than truncate") {
        ASSERT(app_selection_route_valid("kept:abcdefghijklmnopqrstuvwxyz0"));
        ASSERT(!app_selection_route_valid("kept:abcdefghijklmnopqrstuvwxyz01"));
        const char *bad[] = {"kept:", "kept:-x", "kept:A", "kept:../a", "kept:a:b", "kept:@a"};
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
            ASSERT(app_selection_route_reserved(bad[i]) && !app_selection_route_valid(bad[i]));
        ASSERT(sel_route_fill(dir, APP_SELECTION_ROUTES_MAX + 1));
        ASSERT(app_selection_routes_load(dir, &routes) == APP_SELECTION_INVALID && routes.count == 0);
        PASS();
    } _test_next:;
    return failures;
}
static int sel_routes(void)
{
    char dir[512] = {0};
    if (!test_mkdtemp(dir, sizeof(dir), "kept_routes")) return 1;
    int failures = sel_route_persistence(dir);
    if (!failures) failures += sel_route_damage(dir);
    if (!failures) failures += sel_route_bounds(dir);
    (void)test_rm_rf_recursive(dir);
    return failures;
}
int test_app_selection(void)
{
    char dir[512] = {0};
    struct app_selection input;
    int failures = sel_persistence(dir, &input);
#if defined(ZCL_TESTING)
    if (!failures) failures += sel_durability(dir, &input);
#endif
    if (!failures) failures += sel_invalid(dir, input);
    if (dir[0]) (void)test_rm_rf_recursive(dir);
    failures += sel_routes();
    return failures;
}
