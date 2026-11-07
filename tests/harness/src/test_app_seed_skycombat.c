/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_app_seed_skycombat - the real game, seeded from this checkout and
 * built from its copy alone:
 *
 *   app.seed skycombat      -> a release whose tree carries the trimmed
 *                              raylib, the support sources and the Makefile
 *   zcode.package.adopt     -> a copy under <datadir>/copies
 *   app.build {copy}        -> an image and a zcl.app_build.v1 record
 *   <image> --qa-frames=120 -> exit 0 on a private Xvfb display
 *
 * HOME and the datadir are temporary, so the owner key it makes is a
 * throwaway. The seed runs everywhere and prints its package root, so two
 * hosts at one commit can compare roots. The build needs the game's X11/GL
 * headers and the run needs Xvfb; each prints SKIP where its need is
 * missing, and the host-need row keeps the group out of universal
 * selection unless the operator sets ZCL_TEST_DISPLAY_APPS.
 *
 * make t-fast-exact ONLY=app_seed_skycombat ZCL_TEST_DISPLAY_APPS=1 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"
#include "test/app_seed_fixture.h"

#include "chain/chainparams.h"

#if defined(__linux__)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ASS_PATH 1200

struct ass_world {
    char root[512];
    char home[600], datadir[600];
    char source[ASS_PATH];
    char release[65];
    char copy[ASS_PATH];
    char image[ASS_PATH];
    char image_sha3[65];
    char saved_home[1024], saved_display[256];
    bool had_display;
    pid_t xvfb;
};

static bool ass_world_init(struct ass_world *w)
{
    memset(w, 0, sizeof(*w));
    const char *home = getenv("HOME"), *display = getenv("DISPLAY");
    (void)snprintf(w->saved_home, sizeof(w->saved_home), "%s",
                   home ? home : "");
    w->had_display = display != NULL;
    (void)snprintf(w->saved_display, sizeof(w->saved_display), "%s",
                   display ? display : "");
    if (!getcwd(w->source, sizeof(w->source)) ||
        !test_mkdtemp(w->root, sizeof(w->root), "app_seed_skycombat"))
        return false;
    (void)snprintf(w->home, sizeof(w->home), "%s/home", w->root);
    (void)snprintf(w->datadir, sizeof(w->datadir), "%s/datadir", w->root);
    return mkdir(w->home, 0700) == 0 && mkdir(w->datadir, 0700) == 0 &&
           setenv("HOME", w->home, 1) == 0;
}

static void ass_world_restore(const struct ass_world *w)
{
    if (w->saved_home[0])
        (void)setenv("HOME", w->saved_home, 1);
    if (w->had_display)
        (void)setenv("DISPLAY", w->saved_display, 1);
    else
        (void)unsetenv("DISPLAY");
}

/* Seeding reads no window-system header, so every host prints the package
 * root: equal roots across hosts at one commit are the determinism claim. */
static int ass_seed(struct ass_world *w)
{
    int failures = 0;
    TEST("app.seed skycombat: seed the game from this checkout") {
        struct asf_leaf l;
        ASSERT(asf_seed(&l, "skycombat", w->source, w->datadir));
        (void)snprintf(w->release, sizeof(w->release), "%s",
                       asf_get(&l, "release_id"));
        printf("  [seeded skycombat: release %s package_root %s files %lld]\n",
               w->release, asf_get(&l, "package_root"),
               (long long)json_get_int(json_get(&l.out.data, "file_count")));
        asf_close(&l);
        ASSERT(strlen(w->release) == 64);
        PASS();
    } _test_next:;
    return failures;
}

static int ass_adopt_build(struct ass_world *w)
{
    int failures = 0;
    TEST("app.seed skycombat: adopt and build the copy alone") {
        struct asf_leaf l;
        ASSERT(asf_adopt(w->release, w->datadir, w->copy, sizeof(w->copy)));
        bool built = asf_build(&l, w->copy, w->datadir);
        if (!built)
            printf("  [app.build log tail: %s]\n", asf_get(&l, "log_tail"));
        (void)snprintf(w->image, sizeof(w->image), "%s",
                       asf_get(&l, "image_path"));
        (void)snprintf(w->image_sha3, sizeof(w->image_sha3), "%s",
                       asf_get(&l, "image_sha3"));
        printf("  [built skycombat copy: image_sha3 %s confinement %s]\n",
               w->image_sha3, asf_get(&l, "confinement"));
        asf_close(&l);
        ASSERT(built && strlen(w->image_sha3) == 64 && w->image[0] == '/');
        PASS();
    } _test_next:;
    return failures;
}

static int ass_runs_qa_frames(struct ass_world *w, const char *xvfb)
{
    int failures = 0;
    TEST("app.seed skycombat: the built image runs 120 QA frames and exits "
         "0 on a private Xvfb") {
        ASSERT(asf_xvfb_start(xvfb, w->root, &w->xvfb));
        int rc = asf_qa_frames(w->image);
        asf_xvfb_stop(&w->xvfb);
        ASSERT_EQ(rc, 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_app_seed_skycombat(void);
int test_app_seed_skycombat(void)
{
    int failures = 0;
    const char *xvfb = asf_xvfb_path(), *missing = asf_missing_game_header();
    struct ass_world w;
    chain_params_select(CHAIN_MAIN);
    TEST("app.seed skycombat: a temporary HOME and datadir") {
        ASSERT(ass_world_init(&w));
        PASS();
    } _test_next:;
    if (!failures)
        failures += ass_seed(&w);
    if (!failures && missing)
        printf("app.seed skycombat: build and run... SKIP (no "
               "/usr/include/%s: the game cannot build on this host)\n",
               missing);
    if (!failures && !missing)
        failures += ass_adopt_build(&w);
    if (!failures && !missing && !xvfb)
        printf("app.seed skycombat: 120 QA frames... SKIP (no Xvfb on this "
               "host)\n");
    if (!failures && !missing && xvfb)
        failures += ass_runs_qa_frames(&w, xvfb);
    asf_xvfb_stop(&w.xvfb);
    ass_world_restore(&w);
    if (!failures)
        (void)test_rm_rf_recursive(w.root);
    return failures;
}

#else

int test_app_seed_skycombat(void);
int test_app_seed_skycombat(void)
{
    printf("app_seed_skycombat... SKIP (Linux only: Xvfb)\n");
    return 0;
}

#endif
