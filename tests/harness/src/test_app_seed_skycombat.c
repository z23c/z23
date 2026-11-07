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
 * throwaway. Needs Xvfb and the game's X11/GL headers: the host-need row
 * keeps it out of universal selection unless the operator sets
 * ZCL_TEST_DISPLAY_APPS; without Xvfb it prints SKIP.
 *
 * make t-fast-exact ONLY=app_seed_skycombat ZCL_TEST_DISPLAY_APPS=1 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"
#include "test/app_seed_fixture.h"
#include "test/host_tool_capture.h"

#include "chain/chainparams.h"

#if defined(__linux__)
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define ASS_PATH 1200
#define ASS_OUT 65536

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

static const char *ass_xvfb_path(void)
{
    static const char *const paths[] = {"/usr/bin/Xvfb", "/usr/local/bin/Xvfb"};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++)
        if (access(paths[i], X_OK) == 0)
            return paths[i];
    return NULL;
}

/* Xvfb picks a free display itself (-displayfd), so parallel runs never
 * race for a number; DISPLAY is set to it. */
static bool ass_xvfb_start(struct ass_world *w, const char *xvfb)
{
    int fds[2];
    char log[ASS_PATH], display[32];
    posix_spawn_file_actions_t fa;
    char *argv[] = {(char *)xvfb, (char *)"-displayfd", (char *)"3",
                    (char *)"-nolisten", (char *)"tcp", (char *)"-screen",
                    (char *)"0", (char *)"1280x800x24", NULL};
    (void)snprintf(log, sizeof(log), "%s/xvfb.log", w->root);
    if (pipe(fds) != 0 || posix_spawn_file_actions_init(&fa) != 0)
        return false;
    bool ok =
        posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0) == 0 &&
        posix_spawn_file_actions_addopen(&fa, 1, log, O_WRONLY | O_CREAT |
                                         O_TRUNC, 0600) == 0 &&
        posix_spawn_file_actions_adddup2(&fa, 1, 2) == 0 &&
        posix_spawn_file_actions_adddup2(&fa, fds[1], 3) == 0 &&
        posix_spawn(&w->xvfb, xvfb, &fa, NULL, argv, environ) == 0;
    (void)posix_spawn_file_actions_destroy(&fa);
    close(fds[1]);
    display[0] = ':';
    size_t used = 1;
    while (ok && used + 1 < sizeof(display)) {
        struct pollfd p = {.fd = fds[0], .events = POLLIN};
        char c;
        if (poll(&p, 1, 15000) <= 0 || read(fds[0], &c, 1) != 1 || c == '\n')
            break;
        display[used++] = c;
    }
    close(fds[0]);
    display[used] = '\0';
    return ok && used > 1 && setenv("DISPLAY", display, 1) == 0;
}

static void ass_xvfb_stop(struct ass_world *w)
{
    int status;
    if (w->xvfb <= 0)
        return;
    (void)kill(w->xvfb, SIGTERM);
    (void)waitpid(w->xvfb, &status, 0);
    w->xvfb = 0;
}

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

static int ass_seed_adopt_build(struct ass_world *w)
{
    int failures = 0;
    TEST("app.seed skycombat: seed, adopt and build the copy alone") {
        struct asf_leaf l;
        ASSERT(asf_seed(&l, "skycombat", w->source, w->datadir));
        (void)snprintf(w->release, sizeof(w->release), "%s",
                       asf_get(&l, "release_id"));
        printf("  [seeded skycombat: release %s package_root %s files %lld]\n",
               w->release, asf_get(&l, "package_root"),
               (long long)json_get_int(json_get(&l.out.data, "file_count")));
        asf_close(&l);
        ASSERT(strlen(w->release) == 64);
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
    static char out[ASS_OUT];
    TEST("app.seed skycombat: the built image runs 120 QA frames and exits "
         "0 on a private Xvfb") {
        const char *argv[] = {w->image, "--qa-frames=120", NULL};
        ASSERT(ass_xvfb_start(w, xvfb));
        int rc = test_host_tool_capture(argv, out, sizeof(out), 120000);
        ass_xvfb_stop(w);
        ASSERT_EQ(rc, 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_app_seed_skycombat(void);
int test_app_seed_skycombat(void)
{
    int failures = 0;
    const char *xvfb = ass_xvfb_path();
    struct ass_world w;
    if (!xvfb) {
        printf("app_seed_skycombat... SKIP (no Xvfb on this host)\n");
        return 0;
    }
    chain_params_select(CHAIN_MAIN);
    TEST("app.seed skycombat: a temporary HOME and datadir") {
        ASSERT(ass_world_init(&w));
        PASS();
    } _test_next:;
    if (!failures)
        failures += ass_seed_adopt_build(&w);
    if (!failures)
        failures += ass_runs_qa_frames(&w, xvfb);
    ass_xvfb_stop(&w);
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
