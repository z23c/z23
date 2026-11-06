/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * app_playtest_session — drive one built app image through a scripted
 * playtest and return what it did, step by step.
 *
 * The caller names an image by path AND by the SHA3-256 of its bytes. The
 * session captures the image's positioned-file identity, then hands both to
 * resident_launch_prepare(), which re-hashes the live bytes through its own
 * pinned handle: an image whose bytes differ is refused before any process
 * exists (IMAGE_HASH_MISMATCH). The child is executed from that pinned
 * descriptor (fexecve on Linux, the cdhash proof on macOS), never by path,
 * as `<image> --resident <nonce> --agent --seed=<seed>`, with a display-only
 * environment (app_playtest_display_env) and nothing else inherited.
 *
 * Wire: the v=1 agent protocol (docs/commons/GAME.md, "Agent resident
 * transport") in z23-res-run-v1 frames on fd 3. The child sends READY,
 * then answers one reply per request. Script step ids are caller labels;
 * the wire ids are 1..n in script order, so the protocol's strictly
 * increasing id rule always holds. Every reply must echo its wire id.
 *
 * Refusals are typed results, never crashes:
 *   DUPLICATE_STEP_ID     two script steps share a label (before any spawn)
 *   INVALID_REQUEST       malformed request or step (before any spawn)
 *   IMAGE_HASH_MISMATCH   live bytes or identity differ from image_sha3
 *   PLAYTEST_TIMEOUT      no READY or no reply in time; the child's whole
 *                         process group is killed and the child reaped
 *   REPLY_TOO_LARGE       a reply frame advertises more than
 *                         APP_PLAYTEST_REPLY_MAX bytes; never allocated
 * Every path that spawned ends with resident_launch_cancel(): the STOP
 * frame, then SIGKILL of the process group, then the reap.
 *
 * The trace is one JSON line per completed step, capped at
 * APP_PLAYTEST_TRACE_MAX bytes (whole lines only, `trace_truncated` set when
 * a line did not fit). It carries simulation state and capture digests,
 * never a pid, a nonce or wall time, so two runs of one image with one seed
 * and one script can be compared byte for byte. */
#ifndef ZCL_TOOLS_COMMAND_APP_PLAYTEST_SESSION_H
#define ZCL_TOOLS_COMMAND_APP_PLAYTEST_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "platform/resident_launch.h"

#define APP_PLAYTEST_STEP_MAX 64u
/* The v=1 protocol's per-step and per-session tick limits. */
#define APP_PLAYTEST_STEP_FRAMES_MAX 120u
#define APP_PLAYTEST_REQUEST_MAX 4096u
/* The v=1 reply cap (2 MiB); a larger advertised frame is refused. */
#define APP_PLAYTEST_REPLY_MAX (2u * 1024u * 1024u)
#define APP_PLAYTEST_PNG_MAX (1024u * 1024u)
#define APP_PLAYTEST_TRACE_MAX 16384u
#define APP_PLAYTEST_ERROR_MAX 256u
#define APP_PLAYTEST_CHILD_ERROR_MAX 32u
/* Most display variables the child can receive (see the allowlist). */
#define APP_PLAYTEST_ENV_MAX 8u

enum app_playtest_code {
    APP_PLAYTEST_OK = 0,
    APP_PLAYTEST_INVALID_REQUEST,
    APP_PLAYTEST_DUPLICATE_STEP_ID,
    APP_PLAYTEST_IMAGE_UNAVAILABLE,
    APP_PLAYTEST_IMAGE_HASH_MISMATCH,
    APP_PLAYTEST_SPAWN_REFUSED,
    APP_PLAYTEST_TIMEOUT,
    APP_PLAYTEST_REPLY_TOO_LARGE,
    APP_PLAYTEST_CHILD_EXITED,
    APP_PLAYTEST_PROTOCOL_ERROR,
    APP_PLAYTEST_ALLOC_FAILED,
    APP_PLAYTEST_UNSUPPORTED_PLATFORM
};

enum app_playtest_op { APP_PLAYTEST_OBSERVE = 0, APP_PLAYTEST_STEP };

/* v=1 controls; axes are finite and within [-1, 1]. */
struct app_playtest_input {
    float move_x, move_y, camera_x;
    bool fire_guns, speed_boost, throttle;
};

struct app_playtest_step {
    uint32_t id;                    /* caller label, unique in the script */
    enum app_playtest_op op;
    uint32_t frames;                /* STEP: 1..120; OBSERVE: 0 */
    struct app_playtest_input input;/* STEP only */
    bool capture;
};

struct app_playtest_request {
    const char *image_path;
    const char *image_sha3_hex;     /* 64 lowercase hex */
    const struct app_playtest_step *steps;
    size_t n_steps;                 /* 1..APP_PLAYTEST_STEP_MAX */
    uint32_t seed;
    uint32_t step_timeout_ms;       /* 0: RESIDENT_RESULT_DEADLINE_MS */
};

struct app_playtest_capture {
    bool present;
    char sha3_hex[RESIDENT_LAUNCH_DIGEST_HEX + 1u]; /* of the decoded PNG */
    uint32_t width, height;
    size_t bytes;
    uint8_t *png;                   /* owned; app_playtest_result_free */
};

struct app_playtest_step_state {
    uint32_t id;                    /* the script label */
    uint32_t wire_id;
    bool ok;
    char error[APP_PLAYTEST_CHILD_ERROR_MAX]; /* the child's named error */
    uint32_t frame;
    double time;
    bool player_present;
    double x, y, z, yaw, speed, health;
    struct app_playtest_capture capture;
};

struct app_playtest_result {
    enum app_playtest_code code;
    char error[APP_PLAYTEST_ERROR_MAX];
    bool spawned;
    uint64_t pid;                   /* process (and group) id, 0 if none */
    uint64_t start_token;
    char mapped_proof[24];
    size_t n_steps;                 /* steps completed */
    struct app_playtest_step_state steps[APP_PLAYTEST_STEP_MAX];
    char trace[APP_PLAYTEST_TRACE_MAX + 1u];
    size_t trace_len;
    bool trace_truncated;
};

/* "PLAYTEST_TIMEOUT", "REPLY_TOO_LARGE", ...; "OK" for success. */
const char *app_playtest_code_name(enum app_playtest_code code);

/* Fills env[0..n) with this process's entries for the display allowlist
 * (DISPLAY, WAYLAND_DISPLAY, XDG_RUNTIME_DIR, XAUTHORITY, XDG_SESSION_TYPE),
 * NULL-terminates it and returns n. env must hold APP_PLAYTEST_ENV_MAX + 1
 * pointers. The entries alias the environment; do not modify it while the
 * vector is in use. */
size_t app_playtest_display_env(char *env[APP_PLAYTEST_ENV_MAX + 1u]);

/* Runs the whole session. Returns true only for APP_PLAYTEST_OK; on any
 * refusal `out->code` names it, `out->error` explains it and the steps
 * completed before it stay in `out`. Always call app_playtest_result_free. */
bool app_playtest_run(const struct app_playtest_request *request,
                      struct app_playtest_result *out);
void app_playtest_result_free(struct app_playtest_result *out);

#endif
