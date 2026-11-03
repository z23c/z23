/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "camera_access.h"
#include <assert.h>
#include <stddef.h>
#include <string.h>

/* Every combination of the three inputs, with the state the app acts on. */
static void states(void)
{
    static const struct { bool granted, rationale, asked; enum zapp_camera_access want; } cases[] = {
        {true,  true,  true,  ZAPP_CAMERA_GRANTED},
        {true,  true,  false, ZAPP_CAMERA_GRANTED},
        {true,  false, true,  ZAPP_CAMERA_GRANTED},
        {true,  false, false, ZAPP_CAMERA_GRANTED},
        {false, false, false, ZAPP_CAMERA_ASK},
        {false, true,  false, ZAPP_CAMERA_ASK},
        {false, true,  true,  ZAPP_CAMERA_ASK_AGAIN},
        {false, false, true,  ZAPP_CAMERA_SETTINGS},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        enum zapp_camera_access got = zapp_camera_access_state(cases[i].granted, cases[i].rationale, cases[i].asked);
        assert(got == cases[i].want);
        assert(zapp_camera_screen(got).preview == (got != ZAPP_CAMERA_SETTINGS));
    }
}

/* The scan screen for each state: the camera with Cancel, or the settings words and the two buttons. */
static void screens(void)
{
    const enum zapp_camera_access camera[] = {ZAPP_CAMERA_GRANTED, ZAPP_CAMERA_ASK, ZAPP_CAMERA_ASK_AGAIN};
    for (size_t i = 0; i < sizeof(camera) / sizeof(camera[0]); ++i) {
        struct zapp_camera_screen s = zapp_camera_screen(camera[i]);
        assert(s.preview && !s.text && !s.open && !s.paste);
    }
    struct zapp_camera_screen s = zapp_camera_screen(ZAPP_CAMERA_SETTINGS);
    assert(!s.preview);
    assert(!strcmp(s.text, "Camera access is off. Open Settings to allow it, or paste an address."));
    assert(!strcmp(s.open, "Open settings"));
    assert(!strcmp(s.paste, "Paste instead"));
}

/* The wait for the system dialog: it goes on while the dialog is up, ends once the dialog has reported, and ends
 * after the first second when the activity never paused for a dialog. */
static void waits(void)
{
    assert(!zapp_camera_wait_goes_on(1, false, false));
    assert(!zapp_camera_wait_goes_on(7, true, false));
    assert(zapp_camera_wait_goes_on(1, false, true));
    assert(zapp_camera_wait_goes_on(4, false, true));
    assert(!zapp_camera_wait_goes_on(5, false, true));
    assert(!zapp_camera_wait_goes_on(6, false, true));
    assert(zapp_camera_wait_goes_on(5, true, true));
    assert(zapp_camera_wait_goes_on(1000, true, true));
}

int main(void)
{
    states();
    screens();
    waits();
    return 0;
}
