/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the whole app journey on the real game, with ONE owner key in
 * ONE ISO week, every step a `z23 app` front-door verb as typed:
 *
 *   A (in this checkout)  copy skycombat   app.seed publishes the game with
 *                                          A's key, then the copy adopts it
 *                         edit             DEFAULT_FOV 60 -> 65 in
 *                                          src/views/camera_controller.c
 *                         save, build      the copy's own image
 *                         open             the game on a private Xvfb
 *                         <image> --qa-frames=120 exits 0
 *                         share            skycombat-1.z23share, the second
 *                                          publish with A's key this week
 *   B (own HOME)          open skycombat-1.z23share   receive, build, open
 *                         <image> --qa-frames=120 exits 0
 *                         open retained copy, confirm execution, same image
 *
 * B's image_sha3 equals A's for the shared version. The build needs no
 * system -dev package (the X11/GL headers are vendored); the runs need
 * Xvfb. Without it the group prints SKIP, and the host-need row keeps it
 * out of universal selection unless the operator sets ZCL_TEST_DISPLAY_APPS.
 *
 * make t-fast-exact ONLY=app_journey_skycombat ZCL_TEST_DISPLAY_APPS=1 */

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
#include <unistd.h>

struct ajs_world {
    char root[512];
    char source[1200];
    char saved_home[1024], saved_cwd[1200], saved_display[256];
    bool had_display;
    pid_t xvfb;
    struct asf_journey j;
};

static bool ajs_world_init(struct ajs_world *w)
{
    memset(w, 0, sizeof(*w));
    const char *home = getenv("HOME"), *display = getenv("DISPLAY");
    (void)snprintf(w->saved_home, sizeof(w->saved_home), "%s",
                   home ? home : "");
    w->had_display = display != NULL;
    (void)snprintf(w->saved_display, sizeof(w->saved_display), "%s",
                   display ? display : "");
    if (!getcwd(w->source, sizeof(w->source)) ||
        !test_mkdtemp(w->root, sizeof(w->root), "app_journey_skycombat"))
        return false;
    (void)snprintf(w->saved_cwd, sizeof(w->saved_cwd), "%s", w->source);
    return asf_journey_init(&w->j, "skycombat", w->source, w->root);
}

static void ajs_world_restore(const struct ajs_world *w)
{
    if (w->saved_cwd[0] && chdir(w->saved_cwd) != 0)
        printf("  [could not return to %s]\n", w->saved_cwd);
    if (w->saved_home[0])
        (void)setenv("HOME", w->saved_home, 1);
    if (w->had_display)
        (void)setenv("DISPLAY", w->saved_display, 1);
    else
        (void)unsetenv("DISPLAY");
}

static int ajs_a(struct ajs_world *w)
{
    int failures = 0;
    TEST("app journey skycombat A: copy seeds the game with the owner key, "
         "edit one constant, save, build, open, 120 QA frames, share") {
        ASSERT(asf_journey_copy(&w->j));
        ASSERT(asf_replace(w->j.a_copy, "src/views/camera_controller.c",
                           "#define DEFAULT_FOV 60.0f",
                           "#define DEFAULT_FOV 65.0f"));
        ASSERT(asf_journey_save_build_open(&w->j));
        ASSERT(asf_journey_share(&w->j));
        ASSERT_EQ(asf_qa_frames(w->j.path_shared), 0);
        PASS();
    } _test_next:;
    return failures;
}

/* The front-door handler runs in process; this does not claim a fresh CLI
 * process or My Apps recovery. Stop the launched game before assertions. */
static bool ajs_b_reopen(struct asf_journey *j)
{
    struct asf_door run;
    char image[80], question[512];
    asf_door_run(j->b_home, j->b_home, j->b_datadir, "open", j->b_copy,
                 ZCL_CLI_CONFIRM_ASK, &run);
    ++j->commands_b;
    bool stopped = asf_alive_then_stop(asf_door_pid(run.text));
    (void)asf_door_line(&run, "image_sha3", image, sizeof(image));
    int n = snprintf(question, sizeof(question), "Run %s's build %.16s?",
                     j->b_copy, j->image_b);
    bool consent = n > 0 && (size_t)n < sizeof(question) && run.asked &&
                   strcmp(run.question, question) == 0;
    bool same = !strcmp(image, j->image_b) && !strcmp(image, j->image_shared);
    if (run.rc || !stopped || !consent || !same)
        printf("  [receiver reopen: rc=%d stopped=%d consent=%d same=%d]\n%s",
               run.rc, stopped, consent, same, run.text);
    return run.rc == 0 && stopped && consent && same;
}

static int ajs_b(struct ajs_world *w)
{
    int failures = 0;
    TEST("app journey skycombat B: open the share file receives, builds A's "
         "image, opens it; 120 QA frames") {
        ASSERT(asf_journey_receive(&w->j));
        ASSERT_EQ(asf_qa_frames(w->j.path_b), 0);
        ASSERT(ajs_b_reopen(&w->j));
        PASS();
    } _test_next:;
    return failures;
}

int test_app_journey_skycombat(void);
int test_app_journey_skycombat(void)
{
    int failures = 0;
    const char *xvfb = asf_xvfb_path();
    struct ajs_world w;
    chain_params_select(CHAIN_MAIN);
    if (!xvfb) {
        printf("app journey skycombat... SKIP (no Xvfb: the game cannot run "
               "here)\n");
        return 0;
    }
    TEST("app journey skycombat: two HOMEs and datadirs, a private Xvfb") {
        ASSERT(ajs_world_init(&w));
        ASSERT(asf_xvfb_start(xvfb, w.root, &w.xvfb));
        PASS();
    } _test_next:;
    if (!failures)
        failures += ajs_a(&w);
    if (!failures)
        failures += ajs_b(&w);
    asf_xvfb_stop(&w.xvfb);
    printf("app journey skycombat: %s image_sha3 A=%s B=%s; A typed %d "
           "commands, B typed %d\n", failures ? "FAIL" : "PASS",
           w.j.image_shared, w.j.image_b, w.j.commands_a, w.j.commands_b);
    ajs_world_restore(&w);
    if (!failures)
        (void)test_rm_rf_recursive(w.root);
    return failures;
}

#else

int test_app_journey_skycombat(void);
int test_app_journey_skycombat(void)
{
    printf("app_journey_skycombat... SKIP (Linux only: Xvfb)\n");
    return 0;
}

#endif
