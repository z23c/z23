/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: execute the actual game entrypoint against a bounded window/draw
 * fixture. No GPU, window system, live input or model correctness is claimed.
 * Missing QA loop bounds stop at 64 frames so regressions cannot hang tests. */
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <external/stb_image_resize2.h>
#if defined(_WIN32)
#include <io.h>
#include <fcntl.h>
#define qa_dup2 _dup2
#define qa_fileno _fileno
#define qa_close _close
#else
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#define qa_dup2 dup2
#define qa_fileno fileno
#define qa_close close
#endif
static unsigned qa_windows, qa_frames, qa_closed, qa_destroyed, qa_unloads;
static unsigned qa_keys, qa_polls, qa_ticks;
static unsigned qa_events;
static bool qa_resident;
static unsigned qa_original_closed;
static bool qa_bad_stdio;
static float qa_stick_x, qa_stick_y;
static bool qa_agent;
static bool qa_resize_fails;
static bool qa_capture_ok;
static bool qa_broken_reply;
static unsigned qa_close_after = 64;
static bool qa_window_failed;
static bool qa_hud_keys;
#if !defined(_WIN32)
static bool qa_raise_test;
static volatile sig_atomic_t qa_prior_seen, qa_in_signal, qa_bad_raise;
static unsigned qa_restores, qa_focuses;
static struct sigaction qa_original_signal;
static void qa_prior_signal(int signum) { (void)signum; qa_prior_seen = 1; }
static void qa_self_signal(void)
{
    qa_in_signal = 1;
    if (raise(SIGUSR1) != 0) qa_bad_raise = 1;
    qa_in_signal = 0;
}
#endif
static unsigned qa_random_calls, qa_seed_calls, qa_last_seed;
static int sky_qa_entry(int argc, char **argv);
/* Adapt only the entry signature for the pre-fix main(void) removal witness.
 * The entire production function body, argument admission and loop are used. */
#define main(...) sky_qa_entry([[maybe_unused]] int argc, [[maybe_unused]] char **argv)
#include "../../../apps/skycombat/src/sky_combat_multiplayer_ultimate.c"
#undef main

static aircraft_manager_t qa_aircraft;
static powerup_manager_t qa_powerups;
static match_state_t qa_match;
static cyberpunk_world_t qa_world;
static input_mvc_fast_t qa_input;
static effects_manager_t qa_effects;
static weapons_system_t qa_weapons;
static aircraft_t qa_player_aircraft;
static managed_aircraft_t qa_player = {.aircraft = &qa_player_aircraft};

void camera_update_responsive([[maybe_unused]] Camera3D* camera, [[maybe_unused]] Vector3 target, [[maybe_unused]] float yaw, [[maybe_unused]] float distance, [[maybe_unused]] float height, [[maybe_unused]] float dt) {  }
int GetScreenWidth(void) { return 640; }
int GetScreenHeight(void) { return 480; }
int GetRenderWidth(void) { return 640; }
int GetRenderHeight(void) { return 480; }
void PollInputEvents(void) {
    ++qa_events;
#if !defined(_WIN32)
    if (qa_raise_test && qa_agent && !qa_resident && (qa_events == 1 || qa_events == 8))
        qa_self_signal();
#endif
}
void RestoreWindow(void) {
#if !defined(_WIN32)
    if (qa_in_signal || !qa_windows || qa_restores != qa_focuses) qa_bad_raise = 1;
    ++qa_restores;
#endif
}
void SetWindowFocused(void) {
#if !defined(_WIN32)
    if (qa_in_signal || qa_restores != qa_focuses + 1) qa_bad_raise = 1;
    ++qa_focuses;
    if (qa_raise_test) { fputs("QA_RAISE applied\n", stderr); fflush(stderr); }
#endif
}
void rlDrawRenderBatchActive(void) { }
Image LoadImageFromScreen(void)
{
    if (!qa_resize_fails && !qa_capture_ok) return (Image){0};
    return (Image){.data = calloc(640u * 480u, 4), .width = 640, .height = 480,
                    .mipmaps = 1, .format = PIXELFORMAT_UNCOMPRESSED_R8G8B8A8};
}
unsigned char *stbir_resize_uint8_linear([[maybe_unused]] const unsigned char *input,
    [[maybe_unused]] int input_width, [[maybe_unused]] int input_height,
    [[maybe_unused]] int input_stride, [[maybe_unused]] unsigned char *output,
    int output_width, int output_height,
    [[maybe_unused]] int output_stride, [[maybe_unused]] stbir_pixel_layout layout)
{ return qa_capture_ok ? calloc((size_t)output_width * (size_t)output_height, 4) : NULL; }
void UnloadImage(Image image) { free(image.data); }
int GetRandomValue([[maybe_unused]] int min, [[maybe_unused]] int max) { ++qa_random_calls; return (int){0}; }
Color Fade([[maybe_unused]] Color color, [[maybe_unused]] float alpha) { return (Color){0}; }
void DrawLineEx([[maybe_unused]] Vector2 startPos, [[maybe_unused]] Vector2 endPos, [[maybe_unused]] float thick, [[maybe_unused]] Color color) {  }
void rlPushMatrix(void) {  }
void rlTranslatef([[maybe_unused]] float x, [[maybe_unused]] float y, [[maybe_unused]] float z) {  }
void rlRotatef([[maybe_unused]] float angle, [[maybe_unused]] float x, [[maybe_unused]] float y, [[maybe_unused]] float z) {  }
void DrawCube([[maybe_unused]] Vector3 position, [[maybe_unused]] float width, [[maybe_unused]] float height, [[maybe_unused]] float length, [[maybe_unused]] Color color) {  }
void DrawCubeWires([[maybe_unused]] Vector3 position, [[maybe_unused]] float width, [[maybe_unused]] float height, [[maybe_unused]] float length, [[maybe_unused]] Color color) {  }
void DrawSphere([[maybe_unused]] Vector3 centerPos, [[maybe_unused]] float radius, [[maybe_unused]] Color color) {  }
void DrawCircle3D([[maybe_unused]] Vector3 center, [[maybe_unused]] float radius, [[maybe_unused]] Vector3 rotationAxis, [[maybe_unused]] float rotationAngle, [[maybe_unused]] Color color) {  }
void rlPopMatrix(void) {  }
void effects_spawn_explosion([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] Vector3 pos, [[maybe_unused]] float radius, [[maybe_unused]] Color color) {  }
managed_aircraft_t* aircraft_manager_get([[maybe_unused]] aircraft_manager_t* manager, [[maybe_unused]] int id) { return qa_agent ? &qa_player : NULL; }
void DrawFPS([[maybe_unused]] int posX, [[maybe_unused]] int posY) {  }
void DrawText([[maybe_unused]] const char *text, [[maybe_unused]] int posX, [[maybe_unused]] int posY, [[maybe_unused]] int fontSize, [[maybe_unused]] Color color) {  }
Font GetFontDefault(void) { return (Font){0}; }
Vector2 MeasureTextEx([[maybe_unused]] Font font, [[maybe_unused]] const char *text, [[maybe_unused]] float fontSize, [[maybe_unused]] float spacing) { return (Vector2){0}; }
void DrawTextEx([[maybe_unused]] Font font, const char *text, [[maybe_unused]] Vector2 position, [[maybe_unused]] float fontSize, [[maybe_unused]] float spacing, [[maybe_unused]] Color color) { printf("QA_HUD_TEXT frame=%u text=%s\n", qa_frames, text); }
void DrawRectangleRec(Rectangle rect, Color color) { printf("QA_HUD_RECT frame=%u rgba=%u,%u,%u,%u rect=%.0f,%.0f,%.0f,%.0f\n", qa_frames, color.r, color.g, color.b, color.a, (double)rect.x, (double)rect.y, (double)rect.width, (double)rect.height); }
void DrawRectangleLinesEx([[maybe_unused]] Rectangle rect, [[maybe_unused]] float thickness, [[maybe_unused]] Color color) { }
int MeasureText([[maybe_unused]] const char *text, [[maybe_unused]] int fontSize) { return (int){0}; }
void DrawRectangle([[maybe_unused]] int posX, [[maybe_unused]] int posY, [[maybe_unused]] int width, [[maybe_unused]] int height, [[maybe_unused]] Color color) {  }
const char * TextFormat([[maybe_unused]] const char *text, ...) { return ""; }
void DrawRectangleLines([[maybe_unused]] int posX, [[maybe_unused]] int posY, [[maybe_unused]] int width, [[maybe_unused]] int height, [[maybe_unused]] Color color) {  }
bool match_state_finish([[maybe_unused]] match_state_t* state) { return (bool){0}; }
void input_mvc_fast_destroy(input_mvc_fast_t* mvc) { qa_destroyed |= 1u; if (qa_agent) free(mvc); }
void cyberpunk_world_destroy([[maybe_unused]] cyberpunk_world_t* world) { qa_destroyed |= 2u; }
void match_state_destroy([[maybe_unused]] match_state_t* state) { qa_destroyed |= 4u; }
void powerup_manager_destroy([[maybe_unused]] powerup_manager_t* manager) { qa_destroyed |= 8u; }
void aircraft_manager_destroy([[maybe_unused]] aircraft_manager_t* manager) { qa_destroyed |= 16u; }
void effects_destroy([[maybe_unused]] effects_manager_t* manager) { qa_destroyed |= 32u; }
void weapons_destroy([[maybe_unused]] weapons_system_t* weapons) { qa_destroyed |= 64u; }
bool match_state_set_team_scores([[maybe_unused]] match_state_t* state, [[maybe_unused]] const int scores[4]) { return true; }
void match_state_update([[maybe_unused]] match_state_t* state, [[maybe_unused]] float dt) {  }
void SetConfigFlags([[maybe_unused]] unsigned int flags) {  }
static TraceLogCallback qa_trace_callback;
void SetTraceLogCallback(TraceLogCallback callback) { qa_trace_callback = callback; }
/* Mimic raylib's TraceLog: the registered callback, else its stdout default. */
static void qa_raylib_info(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (qa_trace_callback) qa_trace_callback(LOG_INFO, format, args);
    else { printf("INFO: "); vprintf(format, args); printf("\n"); }
    va_end(args);
}
void InitWindow([[maybe_unused]] int width, [[maybe_unused]] int height, [[maybe_unused]] const char *title) {
    ++qa_windows;
    if (qa_agent) qa_raylib_info("QA_TRACE");
#if !defined(_WIN32)
    if (qa_original_closed) {
        for (int fd = 0; fd < 3; fd++) {
            int flags = fcntl(fd, F_GETFL);
            if (flags < 0 || ((qa_original_closed & (1u << fd)) &&
                (flags & O_ACCMODE) != (fd == 0 ? O_RDONLY : O_WRONLY))) qa_bad_stdio = true;
        }
    }
#endif
    if (qa_resident) puts("QA_RESIDENT window stdout");
}
void SetRandomSeed(unsigned int seed) { ++qa_seed_calls; qa_last_seed = seed; }
void SetTargetFPS([[maybe_unused]] int fps) {  }
aircraft_manager_t* aircraft_manager_create(void) { return &qa_aircraft; }
powerup_manager_t* powerup_manager_create(void) { return &qa_powerups; }
match_state_t* match_state_create([[maybe_unused]] match_type_t type) { return &qa_match; }
cyberpunk_world_t* cyberpunk_world_create(void) { return &qa_world; }
input_mvc_fast_t* input_mvc_fast_create(void) { qa_input.view.model = &qa_input.model; return &qa_input; }
void input_model_fast_init(input_model_fast_t *model) { memset(model, 0, sizeof(*model)); }
effects_manager_t* effects_create([[maybe_unused]] int max_effects, [[maybe_unused]] int max_particles) { return &qa_effects; }
weapons_system_t* weapons_create(void) { return &qa_weapons; }
bool match_state_begin([[maybe_unused]] match_state_t* state) { return true; }
void CloseWindow(void) {
    ++qa_closed;
    if (qa_resident) puts("QA_RESIDENT close stdout");
}
int aircraft_manager_add_with_team([[maybe_unused]] aircraft_manager_t* manager, [[maybe_unused]] const char* name, [[maybe_unused]] Color color, [[maybe_unused]] bool is_ai, [[maybe_unused]] bool is_local, [[maybe_unused]] int team_id) { return (int){0}; }
void powerup_manager_add_spawn_point([[maybe_unused]] powerup_manager_t* manager, [[maybe_unused]] Vector3 position, [[maybe_unused]] powerup_type_t type, [[maybe_unused]] float respawn_time) {  }
void cyberpunk_world_generate([[maybe_unused]] cyberpunk_world_t* world, [[maybe_unused]] int seed) {  }
void cyberpunk_set_theme_blade_runner([[maybe_unused]] cyberpunk_world_t* world) {  }
RenderTexture2D LoadRenderTexture([[maybe_unused]] int width, [[maybe_unused]] int height) { return (RenderTexture2D){0}; }
bool WindowShouldClose(void) { return qa_frames >= qa_close_after; }
float GetFrameTime(void) { return 1.0f / 60.0f; }
double GetTime(void) { return (double)qa_frames / 60.0; }
bool IsKeyDown([[maybe_unused]] int key) { ++qa_keys; return qa_agent; }
void aircraft_update_responsive([[maybe_unused]] aircraft_t* aircraft, float stick_x, float stick_y, [[maybe_unused]] float dt) { ++qa_ticks; qa_stick_x = stick_x; qa_stick_y = stick_y; }
bool IsKeyPressed(int key) {
    ++qa_keys;
    if (qa_agent) return true;
    return qa_hud_keys && ((key == KEY_F6 && qa_frames == 1) ||
        (key == KEY_F7 && (qa_frames == 2 || qa_frames == 3)));
}
void effects_sonic_boom([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] Vector3 pos, [[maybe_unused]] Vector3 direction) {  }
Vector3 aircraft_get_forward_vector([[maybe_unused]] aircraft_t* aircraft) { return (Vector3){0}; }
void effects_screen_shake([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] float intensity, [[maybe_unused]] float duration) {  }
void effects_screen_flash([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] Color color, [[maybe_unused]] float duration) {  }
void effects_spawn_powerup_collect([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] Vector3 pos, [[maybe_unused]] Color color) {  }
void aircraft_manager_fire_weapon([[maybe_unused]] aircraft_manager_t* manager, [[maybe_unused]] int aircraft_id) {  }
void weapons_fire_bullet([[maybe_unused]] weapons_system_t* weapons, [[maybe_unused]] Vector3 position, [[maybe_unused]] Vector3 direction, [[maybe_unused]] float yaw) {  }
void effects_spawn_laser_hit([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] Vector3 pos, [[maybe_unused]] Vector3 normal, [[maybe_unused]] Color color) {  }
void aircraft_manager_update([[maybe_unused]] aircraft_manager_t* manager, [[maybe_unused]] float dt) {  }
void powerup_manager_update([[maybe_unused]] powerup_manager_t* manager, [[maybe_unused]] float dt) {  }
void weapons_update([[maybe_unused]] weapons_system_t* weapons, [[maybe_unused]] float dt) {  }
void effects_update([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] float dt) {  }
bool powerup_manager_check_collection([[maybe_unused]] powerup_manager_t* manager, [[maybe_unused]] Vector3 position, [[maybe_unused]] float radius, [[maybe_unused]] powerup_type_t* collected_type) { return (bool){0}; }
void effects_show_achievement([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] const char* text) {  }
void BeginTextureMode([[maybe_unused]] RenderTexture2D target) {  }
void ClearBackground([[maybe_unused]] Color color) {  }
void BeginMode3D([[maybe_unused]] Camera3D camera) {  }
void cyberpunk_world_draw([[maybe_unused]] cyberpunk_world_t* world, [[maybe_unused]] Camera3D camera) {  }
void weapons_draw([[maybe_unused]] weapons_system_t* weapons) {  }
void effects_draw([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] Camera3D camera) {  }
void EndMode3D(void) {  }
void EndTextureMode(void) {  }
void BeginDrawing(void) {
#if !defined(_WIN32)
    if (qa_raise_test && !qa_agent && !qa_frames) qa_self_signal();
#endif
}
void DrawTextureRec([[maybe_unused]] Texture2D texture, [[maybe_unused]] Rectangle rec, [[maybe_unused]] Vector2 position, [[maybe_unused]] Color tint) {  }
void effects_draw_ui([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] int screen_width, [[maybe_unused]] int screen_height) {  }
void EndDrawing(void) { ++qa_frames; }
void UnloadRenderTexture([[maybe_unused]] RenderTexture2D target) { ++qa_unloads; }
void input_controller_fast_update([[maybe_unused]] input_controller_fast_t* controller) { ++qa_polls; }
bool IsWindowReady(void) { return qa_windows > 0 && !qa_window_failed; }

static bool qa_agent_flag(const char *arg, int *prefix)
{
    if (strcmp(arg, "--fixture-resize-fails") == 0) qa_resize_fails = true;
    else if (strcmp(arg, "--fixture-capture-ok") == 0) qa_capture_ok = true;
    else if (strcmp(arg, "--fixture-prefix-nul") == 0) *prefix = 0;
    else if (strcmp(arg, "--fixture-prefix-sub") == 0) *prefix = 26;
    else if (strcmp(arg, "--fixture-broken-reply") == 0) qa_broken_reply = true;
    else return false;
    return true;
}

static FILE *qa_agent_input(const char *script, int prefix)
{
    FILE *input = tmpfile();
    if (!input) return NULL;
    bool ok = true;
    if (prefix >= 0) ok = fputc(prefix, input) != EOF && fputc('\n', input) != EOF;
    if (!ok || fputs(script, input) == EOF || fflush(input) != 0 ||
        fseek(input, 0, SEEK_SET) != 0 || qa_dup2(qa_fileno(input), qa_fileno(stdin)) < 0) {
        fclose(input);
        return NULL;
    }
#if defined(_WIN32)
    /* Force the default CRT mode: production must switch physical-byte reads
     * to binary and restore this exact mode after close/failure. */
    if (_setmode(qa_fileno(stdin), _O_TEXT) < 0) {
        fclose(input);
        return NULL;
    }
#endif
    return input;
}

static bool qa_close_reply_reader(void)
{
    int descriptors[2];
#if defined(_WIN32)
    if (_pipe(descriptors, 4096, _O_BINARY) < 0) return false;
#else
    if (pipe(descriptors) < 0) return false;
#endif
    qa_close(descriptors[0]);
    bool ok = qa_dup2(descriptors[1], qa_fileno(stdout)) >= 0;
    qa_close(descriptors[1]);
    return ok;
}

static void qa_window_options(int *argc, char ***argv)
{
    if (*argc <= 1) return;
    const char *option = (*argv)[1];
    if (strcmp(option, "--fixture-hud-keys") == 0) qa_hud_keys = true;
    else if (strcmp(option, "--fixture-close=2") == 0) qa_close_after = 2;
    else if (strcmp(option, "--fixture-window-fails") == 0) qa_window_failed = true;
    else return;
    --*argc;
    ++*argv;
}

int main(int argc, char **argv)
{
    FILE *agent_input = NULL;
    int prefix = -1;
    if (argc > 1 && qa_agent_flag(argv[1], &prefix)) {
        --argc; ++argv;
    }
    if (argc > 1 && strncmp(argv[1], "--fixture-agent=", 16) == 0) {
        qa_agent = true;
        agent_input = qa_agent_input(argv[1] + 16, prefix);
        if (!agent_input) return 3;
        --argc; ++argv;
    }
    qa_window_options(&argc, &argv);
    if (argc > 1) {
        static const char closed_prefix[] = "--fixture-closed-stdio=";
        size_t length = sizeof(closed_prefix) - 1;
        if (!strncmp(argv[1], closed_prefix, length)) {
            if (argv[1][length] < '1' || argv[1][length] > '7' || argv[1][length + 1]) return 3;
            qa_original_closed = (unsigned)(argv[1][length] - '0');
            --argc; ++argv;
        }
    }
#if !defined(_WIN32)
    if (argc > 1 && !strcmp(argv[1], "--fixture-raise")) {
        qa_raise_test = true;
        --argc; ++argv;
        struct sigaction prior = {.sa_handler = qa_prior_signal, .sa_flags = SA_RESTART};
        if (sigemptyset(&prior.sa_mask) != 0 || sigaddset(&prior.sa_mask, SIGUSR2) != 0 ||
            sigaction(SIGUSR1, &prior, &qa_original_signal) != 0) return 3;
    }
#endif
    if (argc > 1 && strcmp(argv[1], "--fixture-resident") == 0) {
        qa_agent = qa_resident = true;
        --argc; ++argv;
    }
    if (qa_broken_reply && !qa_close_reply_reader()) {
        if (agent_input) fclose(agent_input);
        return 3;
    }
    int result = sky_qa_entry(argc, argv);
#if !defined(_WIN32)
    if (qa_raise_test) {
        bool pure = true;
        if (qa_agent && qa_windows && !qa_window_failed && !qa_ticks) {
            int actual = rand(); srand(qa_last_seed);
            pure = actual == rand() && !qa_random_calls && qa_seed_calls == 2 &&
                   sky_game_runtime_ticks() == 0;
        }
        struct sigaction restored;
        bool prior = sigaction(SIGUSR1, NULL, &restored) == 0 &&
            restored.sa_handler == qa_prior_signal && (restored.sa_flags & SA_RESTART) &&
            sigismember(&restored.sa_mask, SIGUSR2) == 1;
        if (!prior || raise(SIGUSR1) != 0 || !qa_prior_seen || qa_bad_raise || !pure) result = 5;
        if (sigaction(SIGUSR1, &qa_original_signal, NULL) != 0) result = 5;
        if (!(qa_original_closed & 4u))
            fprintf(stderr, "QA_RAISE restore=%u focus=%u prior=%d pure=%d events=%u\n",
                    qa_restores, qa_focuses, (int)qa_prior_seen, pure, qa_events);
    }
    if (qa_original_closed) {
        for (int fd = 0; fd < 3; fd++) {
            int status = fcntl(fd, F_GETFD);
            bool closed = status < 0 && errno == EBADF;
            if ((status < 0 && !closed) || closed != ((qa_original_closed & (1u << fd)) != 0))
                qa_bad_stdio = true;
        }
    }
#endif
    if (qa_bad_stdio) result = 4;
    if (qa_resident && !(qa_original_closed & 2u)) {
        /* The production main must restore its caller's stdout, including
         * failure after READY but before a usable renderer exists. */
        if (puts("QA_RESIDENT stdout restored") == EOF || fflush(stdout) != 0) result = 3;
    }
#if defined(_WIN32)
    if (qa_agent && _setmode(qa_fileno(stdin), _O_TEXT) != _O_TEXT) result = 3;
#endif
    if (agent_input) fclose(agent_input);
    if (!(qa_original_closed & 4u)) fprintf(qa_agent ? stderr : stdout, "QA_TEST status=%d windows=%u frames=%u closed=%u destroyed=%u unloads=%u\n",
        result, qa_windows, qa_frames, qa_closed, qa_destroyed, qa_unloads);
    if (qa_agent && !(qa_original_closed & 4u)) fprintf(stderr, "QA_AGENT ticks=%u keys=%u polls=%u stick=%.3f,%.3f\n",
        qa_ticks, qa_keys, qa_polls, (double)qa_stick_x, (double)qa_stick_y);
    if (qa_resident && !(qa_original_closed & 4u)) fprintf(stderr, "QA_RESIDENT events=%u\n", qa_events);
    return result;
}
