#ifndef SKY_COMBAT_AGENT_SESSION_H
#define SKY_COMBAT_AGENT_SESSION_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "sky_combat/views/input_view_fast.h"
#include "sky_combat/agent_resident.h"

#define SKY_AGENT_LINE_MAX 4096u
#define SKY_AGENT_STEP_MAX 120u
#define SKY_AGENT_FRAME_MAX 36000u
#define SKY_AGENT_REQUEST_MAX 4096u
#define SKY_AGENT_PNG_MAX (1024u * 1024u)
#define SKY_AGENT_REPLY_MAX (2u * 1024u * 1024u)

struct sky_agent_capture {
    unsigned char *png;
    size_t size;
    int width, height;
    const char *error;
    /* Optional colour probe for --capture: the caller sets probe_want and the
     * render-pixel position (probe_x, probe_y); the frame readback then fills
     * probe_ok, probe_rgb (3x3 average) and the position in the saved PNG. */
    bool probe_want, probe_ok;
    int probe_x, probe_y, probe_out_x, probe_out_y;
    unsigned char probe_rgb[3];
};

struct sky_agent_observation {
    unsigned frame;
    double time;
    bool player_present;
    float x, y, z, yaw, speed, health;
};

struct sky_agent_session {
    FILE *reply;
    struct sky_resident_channel resident;
    unsigned resident_closed_stdio;
    bool has_accepted_id;
    uint32_t accepted_id;
#if defined(_WIN32)
    int previous_stdin_mode;
#else
    void (*previous_sigpipe)(int);
#endif
};

/* The callback uses the maintained simulation/render path. NULL input renders
 * without advancing. Capture, when requested, occurs before the buffer swap. */
typedef void (*sky_agent_frame_fn)(void *context, const input_state_fast_t *input,
    struct sky_agent_observation *observation, struct sky_agent_capture *capture);

bool sky_agent_open(struct sky_agent_session *session);
bool sky_agent_open_resident(struct sky_agent_session *session, const char *nonce);
bool sky_agent_close(struct sky_agent_session *session);
int sky_agent_run(struct sky_agent_session *session, void *context,
                  sky_agent_frame_fn frame);
void sky_agent_capture_frame(struct sky_agent_capture *capture);

#endif
