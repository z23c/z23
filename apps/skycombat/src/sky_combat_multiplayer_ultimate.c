/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: five-player split-screen game with checked bounded QA launches.
 */

/* GCC uses the build's -ffp-contract=off; Clang also enforces it here. */
#if defined(__clang__)
#pragma STDC FP_CONTRACT OFF
#endif

#if defined(_WIN32)
#undef WIN32_LEAN_AND_MEAN
#include <external/fix_win32_compatibility.h>
#endif
#include <raylib.h>
#include <raymath.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#if defined(_WIN32)
#include <direct.h>
#include <io.h>
#else
#include <sys/file.h>
#include <unistd.h>
#endif
#include <rlgl.h>

#include "sky_combat/models/aircraft_manager.h"
#include "sky_combat/models/match_rules.h"
#include "sky_combat/models/powerups.h"
#include "sky_combat/models/cyberpunk_world.h"
#include "sky_combat/models/weapons.h"
#include "sky_combat/models/enemies.h"
#include "sky_combat/controllers/input_mvc_fast.h"
#include "sky_combat/views/combat_effects.h"
#include "sky_combat/qa_frames.h"
#include "sky_combat/qa_timing.h"
#include "sky_combat/agent_session.h"
#include "sky_combat/game_runtime.h"

#include "../part/expr_use.h"

#define SCREEN_WIDTH 1920
#define SCREEN_HEIGHT 1080
#define TARGET_FPS 60

/* Forward declarations */
static void render_aircraft_ultimate(const managed_aircraft_t* aircraft, 
                                   float game_time);
static void render_powerup_ultimate(const powerup_t* powerup, 
                                  effects_manager_t* effects, float game_time);
void camera_update_responsive(Camera3D* camera, Vector3 target, float yaw, 
                            float distance, float height, float dt);

/* Game state */
typedef enum {
    GAME_FLOW_START,
    GAME_FLOW_PLAYING,
    GAME_FLOW_ENDED
} game_flow_t;

typedef struct {
    /* Core systems */
    aircraft_manager_t* aircraft_mgr;
    powerup_manager_t* powerup_mgr;
    match_state_t* match;
    cyberpunk_world_t* world;
    input_mvc_fast_t* input_system;
    effects_manager_t* effects;
    weapons_system_t* weapons;
    
    /* Camera with smooth following */
    Camera3D camera;
    float camera_yaw;
    float camera_distance;
    
    /* Local player */
    int local_player_id;
    float boost_timer;
    float damage_flash;
    
    /* Visual settings */
    float speed_lines_intensity;
    bool motion_blur_enabled;

    /* --capture run: fixed time step and a chase view centred on the player */
    bool capture_view;

    /* --qa-frames run: fixed 1/60 s step and the explicit tick clock (one tick per
     * frame), so simulation time is a function of the frame number; with the fixed
     * RNG seed (default 1) two runs do identical work and end on the same state_digest */
    bool fixed_step;
    game_flow_t flow;
    int best_score;
    bool score_save_failed;
    bool action_latched;
    bool agent_mode;
    bool qa_mode;
    bool metrics_enabled;
    double metric_previous;
    double metric_start;
    float metric_work_ms;
} multiplayer_game_t;
static void render_match_flow(const multiplayer_game_t *game);

/* Draw speed lines effect */
static void draw_speed_effects(multiplayer_game_t* game) {
    if (game->speed_lines_intensity <= 0) return;
    
    int line_count = (int)(game->speed_lines_intensity * 30);
    Vector2 center = {GetScreenWidth() / 2.0f, GetScreenHeight() / 2.0f};
    
    for (int i = 0; i < line_count; i++) {
        float angle = (float)i / line_count * 360.0f;
        float length = (float)sky_game_visual_sample(SKY_VISUAL_SPEED, (uint32_t)i * 2u, 100, 300) * game->speed_lines_intensity;
        float offset = (float)sky_game_visual_sample(SKY_VISUAL_SPEED, (uint32_t)i * 2u + 1u, 50, 150);
        
        Vector2 start = {
            center.x + cosf(angle * DEG2RAD) * offset,
            center.y + sinf(angle * DEG2RAD) * offset
        };
        Vector2 end = {
            center.x + cosf(angle * DEG2RAD) * (offset + length),
            center.y + sinf(angle * DEG2RAD) * (offset + length)
        };
        
        Color color = Fade(WHITE, 0.3f * game->speed_lines_intensity);
        DrawLineEx(start, end, 2.0f, color);
    }
}

/* Render aircraft with effects */
static void render_aircraft_ultimate(const managed_aircraft_t* aircraft, 
                                   float game_time) {
    if (!aircraft || !aircraft->aircraft) return;
    
    Vector3 pos = aircraft->aircraft->position;
    float scale = 3.0f;
    
    /* Save transform */
    rlPushMatrix();
    rlTranslatef(pos.x, pos.y, pos.z);
    
    /* Apply rotation based on yaw/pitch/roll */
    rlRotatef(aircraft->aircraft->yaw, 0, 1, 0);
    rlRotatef(aircraft->aircraft->pitch, 1, 0, 0);
    rlRotatef(aircraft->aircraft->roll, 0, 0, 1);
    
    /* Fuselage with team color */
    DrawCube((Vector3){0, 0, 0}, scale * 2.0f, scale * 0.5f, scale * 0.5f, aircraft->color);
    DrawCubeWires((Vector3){0, 0, 0}, scale * 2.0f, scale * 0.5f, scale * 0.5f, BLACK);
    
    /* Wings with detail */
    DrawCube((Vector3){0, 0, 0}, scale * 0.2f, scale * 0.1f, scale * 3.0f, aircraft->color);
    DrawCubeWires((Vector3){0, 0, 0}, scale * 0.2f, scale * 0.1f, scale * 3.0f, BLACK);
    
    /* Tail */
    DrawCube((Vector3){-scale, scale * 0.3f, 0}, scale * 0.1f, scale * 0.8f, scale * 0.8f, aircraft->color);
    
    /* Engine glow with pulsing effect */
    if (aircraft->aircraft->speed > AIRCRAFT_BASE_SPEED) {
        float glow = 1.0f + sinf(game_time * 10.0f) * 0.2f;
        DrawSphere((Vector3){-scale, 0, 0}, scale * 0.3f * glow, ORANGE);
        DrawSphere((Vector3){-scale, 0, 0}, scale * 0.5f, Fade(ORANGE, 0.3f));
        
        /* Engine particles - TODO: Add when effects_spawn_debris is implemented */
    }
    
    /* Shield effect */
    if (aircraft->powerup_effects.shield_active) {
        DrawSphere((Vector3){0, 0, 0}, scale * 2.5f, Fade(SKYBLUE, 0.2f + sinf(game_time * 5) * 0.1f));
        DrawCircle3D(pos, scale * 2.5f, (Vector3){1, 0, 0}, 90, Fade(SKYBLUE, 0.5f));
        DrawCircle3D(pos, scale * 2.5f, (Vector3){0, 1, 0}, 90, Fade(SKYBLUE, 0.5f));
    }
    
    rlPopMatrix();
    
}

/* Effects are created only by simulation ticks, never by observe/capture. */
static void update_damage_smoke(multiplayer_game_t *game)
{
    for (int i = 0; i < game->aircraft_mgr->aircraft_count; i++) {
        const managed_aircraft_t *aircraft = &game->aircraft_mgr->aircraft[i];
        if (aircraft->aircraft && aircraft->health < aircraft->max_health * 0.5f &&
            GetRandomValue(0, 100) < 10) {
            Vector3 smoke_pos = aircraft->aircraft->position;
            smoke_pos.y += 1.0f;
            effects_spawn_explosion(game->effects, smoke_pos, 0.5f, DARKGRAY);
        }
    }
}

/* Render power-up with effects */
static void render_powerup_ultimate(const powerup_t* powerup,[[maybe_unused]] effects_manager_t* effects, float game_time) {
    if (!powerup->active) return;
    
    /* Floating animation */
    float bob = sinf(game_time * 2.0f) * 2.0f;
    Vector3 pos = powerup->position;
    pos.y += bob;
    
    /* Rotating cube with glow */
    rlPushMatrix();
    rlTranslatef(pos.x, pos.y, pos.z);
    rlRotatef(game_time * 100, 0, 1, 0);
    rlRotatef(game_time * 70, 1, 0, 0);
    
    DrawCube((Vector3){0, 0, 0}, 3.0f, 3.0f, 3.0f, powerup->color);
    DrawCubeWires((Vector3){0, 0, 0}, 3.5f, 3.5f, 3.5f, WHITE);
    
    rlPopMatrix();
    
    /* Glow effect */
    DrawSphere(pos, 4.0f + sinf(game_time * 3) * 0.5f, Fade(powerup->color, 0.3f));
    
    /* Particle ring */
    for (int i = 0; i < 8; i++) {
        float angle = (i / 8.0f) * PI * 2 + game_time;
        Vector3 particle_pos = {
            pos.x + cosf(angle) * 5,
            pos.y,
            pos.z + sinf(angle) * 5
        };
        DrawSphere(particle_pos, 0.5f, Fade(powerup->color, 0.8f));
    }
}

static void render_host_debug(multiplayer_game_t *game) {
    /* FPS and debug */
    DrawFPS(10, 10);

    /* Debug controls - show stick values */
    if (game->input_system->model.connected) {
        char debug[256];
        snprintf(debug, sizeof(debug), "LX: %.2f LY: %.2f", 
                game->input_system->model.normalized.move_x,
                game->input_system->model.normalized.move_y);
        DrawText(debug, 10, 40, 16, LIME);
    }

}

/* Advanced HUD */
static void render_hud_ultimate(void *context) {
    multiplayer_game_t *game=context;
    const managed_aircraft_t* player = aircraft_manager_get(game->aircraft_mgr, game->local_player_id);
    if (!player) return;
    
    render_host_debug(game);

    /* Match timer with style */
    int minutes = (int)(game->match->elapsed_time / 60.0f);
    int seconds = (int)game->match->elapsed_time % 60;
    char timer[32];
    snprintf(timer, sizeof(timer), "%02d:%02d", minutes, seconds);
    
    int timer_width = MeasureText(timer, 50);
    DrawRectangle(GetScreenWidth()/2 - timer_width/2 - 20, 5, timer_width + 40, 60, Fade(BLACK, 0.5f));
    DrawText(timer, GetScreenWidth()/2 - timer_width/2, 10, 50, WHITE);
    
    /* Team scores with bars */
    int y_offset = 80;
    for (int i = 0; i < game->match->rules.team_count && i < 4; i++) {
        Color team_color = (Color[]){RED, BLUE, GREEN, YELLOW}[i];
        char score[64];
        snprintf(score, sizeof(score), "TEAM %d", i+1);
        
        DrawRectangle(GetScreenWidth() - 250, y_offset + i * 35, 240, 30, Fade(BLACK, 0.5f));
        DrawRectangle(GetScreenWidth() - 250, y_offset + i * 35, 
                     (int)(240.0f * game->match->team_scores[i] / game->match->rules.score_limit), 
                     30, Fade(team_color, 0.7f));
        DrawText(score, GetScreenWidth() - 240, y_offset + i * 35 + 5, 20, WHITE);
        DrawText(TextFormat("%d", game->match->team_scores[i]), 
                GetScreenWidth() - 50, y_offset + i * 35 + 5, 20, WHITE);
    }
    
    /* Player status with style */
    int status_y = GetScreenHeight() - 150;
    
    /* Health bar */
    float health_percent = player->health / player->max_health;
    DrawRectangle(50, status_y, 300, 30, Fade(BLACK, 0.7f));
    DrawRectangle(50, status_y, (int)(300 * health_percent), 30, 
                 health_percent > 0.3f ? GREEN : (game->damage_flash > 0 ? WHITE : RED));
    DrawRectangleLines(50, status_y, 300, 30, WHITE);
    DrawText("HULL", 10, status_y + 5, 20, WHITE);
    
    /* Shield indicator */
    if (player->powerup_effects.shield_active) {
        DrawRectangle(50, status_y + 35, 300, 15, Fade(BLACK, 0.7f));
        DrawRectangle(50, status_y + 35, 300, 15, Fade(SKYBLUE, 0.8f));
        DrawText("SHIELD", 10, status_y + 35, 15, SKYBLUE);
    }
    
    /* Boost indicator */
    if (game->boost_timer > 0) {
        DrawText("BOOST!", 50, status_y - 40, 40, ORANGE);
        DrawRectangle(50, status_y - 10, (int)(300 * (game->boost_timer / 0.75f)), 5, ORANGE);
    }
    
    /* Kill feed style */
    int feed_y = 150;
    DrawText("COMBAT LOG", 10, feed_y - 25, 18, WHITE);
    
    /* Weapon indicator */
    if (player->weapons) {
        const char* weapon_names[] = {"MACHINE GUN", "MISSILES", "LASER", "PLASMA"};
        DrawText(weapon_names[player->weapons->current_weapon % 4], 
                10, GetScreenHeight() - 200, 24, YELLOW);
    }
    
    /* Controls (smaller) */
    if (game->input_system->model.connected) {
        DrawText("ASTRO C40 CONNECTED", 10, GetScreenHeight() - 30, 16, GREEN);
    } else {
        DrawText("KEYBOARD MODE", 10, GetScreenHeight() - 30, 16, GRAY);
    }
}

static void render_game_hud(const struct sky_expr_hud *hud,const struct sky_expr_notice *notice,multiplayer_game_t *game)
{
    if(sky_expr_custom_selected(hud))render_host_debug(game);
    sky_expr_render(hud,render_hud_ultimate,game);
    sky_expr_notice_render(notice,hud);
}

/* Update camera with smooth following */
static void update_camera_ultimate(multiplayer_game_t* game, float dt) {
    const managed_aircraft_t* player = aircraft_manager_get(game->aircraft_mgr, game->local_player_id);
    if (!player || !player->aircraft) return;
    
    /* Dynamic camera distance based on speed */
    float cam_distance = 35.0f + player->aircraft->speed * 0.1f;
    float cam_height = 15.0f;
    
    /* Use the same camera update as ultimate */
    camera_update_responsive(&game->camera, player->aircraft->position,
                           player->aircraft->yaw + game->camera_yaw,
                           cam_distance, cam_height, dt);
    if (game->capture_view) {
        /* A step of 0.2 s makes the camera's own smoothing (5 per second) land
         * exactly on its chase spot; then frame the aircraft, not the point
         * ahead of it, so the player sits at the centre of the image. */
        camera_update_responsive(&game->camera, player->aircraft->position,
                               player->aircraft->yaw + game->camera_yaw,
                               cam_distance, cam_height, 0.2f);
        game->camera.target = player->aircraft->position;
    }
}

static void destroy_game_systems(multiplayer_game_t *game) {
    if (game->match && game->match->match_started && !game->match->match_ended)
        (void)match_state_finish(game->match);
    input_mvc_fast_destroy(game->input_system);
    cyberpunk_world_destroy(game->world);
    match_state_destroy(game->match);
    powerup_manager_destroy(game->powerup_mgr);
    aircraft_manager_destroy(game->aircraft_mgr);
    effects_destroy(game->effects);
    weapons_destroy(game->weapons);
}

static void update_match_ledger(multiplayer_game_t *game, float dt) {
    if (!game->match->match_started || game->match->match_ended) return;
    int scores[4] = {0};
    for (int i = 0; i < game->aircraft_mgr->aircraft_count; ++i) {
        const managed_aircraft_t *aircraft = &game->aircraft_mgr->aircraft[i];
        int team = aircraft->team_id;
        if (team >= 0 && team < 4) {
            if (aircraft->kills < 0 || aircraft->kills > 1000000 - scores[team]) {
                fprintf(stderr, "match roster: invalid or overflowing kill total\n"); return;
            }
            scores[team] += aircraft->kills;
        }
    }
    if (match_state_set_team_scores(game->match, scores)) match_state_update(game->match, dt);
}

static void report_game_input(const multiplayer_game_t *game)
{
    printf("Sky Combat Multiplayer Ultimate\n");
    printf("Joystick: %s\n", game->input_system->model.connected ? "CONNECTED" : "Keyboard Mode");
    if (game->input_system->model.is_astro_c40)printf("ASTRO C40 TR Controller detected!\n");
}

static bool score_directory(const char *path)
{
    struct stat st;
#if defined(_WIN32)
    if (_mkdir(path) != 0 && errno != EEXIST) return false;
#else
    if (mkdir(path, 0700) != 0 && errno != EEXIST) return false;
#endif
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static bool score_directories(char *path)
{
    for (char *at = path + 1; *at; ++at) {
        if (*at != '/') continue;
        *at = 0;
        bool ok = at[-1] == ':' || score_directory(path);
        *at = '/';
        if (!ok) return false;
    }
    return score_directory(path);
}

static bool score_join(char *out, size_t cap, const char *left, const char *right)
{
    int n = snprintf(out, cap, "%s%s", left, right);
    return n > 0 && (size_t)n < cap;
}

static bool score_root(char *dir, size_t cap)
{
    const char *state = getenv("XDG_STATE_HOME");
    if (state && state[0]) return score_join(dir, cap, state, "/z23");
#if defined(_WIN32)
    const char *home = getenv("APPDATA");
    if (!home || !home[0]) home = getenv("USERPROFILE");
    const char *suffix = "";
#else
    const char *home = getenv("HOME");
    const char *suffix = "/.local/state";
#endif
    if (!home || !home[0]) return false;
    char root[512];
    return score_join(root, sizeof(root), home, suffix) &&
        score_join(dir, cap, root, "/z23");
}

static bool score_store_path(char *out, size_t cap, bool create)
{
    char dir[512];
    if (!score_root(dir, sizeof(dir))) return false;
    if (create && !score_directories(dir)) return false;
    if (!score_join(out, cap, dir, "/skycombat")) return false;
    if (create && !score_directory(out)) return false;
    size_t used = strlen(out);
    if (used >= cap) return false;
    int n = snprintf(out + used, cap - used, "/best-score");
    return n > 0 && (size_t)n < cap - used;
}

static int score_store_load(void)
{
    char path[512], line[64], extra;
    if (!score_store_path(path, sizeof(path), false)) return 0;
    FILE *file = fopen(path, "rb");
    if (!file) return 0;
    bool ok = fgets(line, sizeof(line), file) != NULL;
    if (file && fclose(file) != 0) ok = false;
    int score = 0;
    return ok && sscanf(line, "v1 %d %c", &score, &extra) == 1 &&
        score >= 0 && score <= 1000000 ? score : 0;
}

static int score_lock(const char *path)
{
    char lock[520];
    int n = snprintf(lock, sizeof(lock), "%s.lock", path);
    if (n <= 0 || (size_t)n >= sizeof(lock)) return -1;
#if defined(_WIN32)
    int fd = _open(lock, _O_CREAT | _O_WRONLY | _O_BINARY, 0600);
    OVERLAPPED overlap = {0};
    if (fd >= 0 && !LockFileEx((HANDLE)_get_osfhandle(fd),
                               LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                               0, MAXDWORD, 0, &overlap)) {
        _close(fd);
        return -1;
    }
    return fd;
#else
    int fd = open(lock, O_CREAT | O_WRONLY, 0600);
    if (fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) != 0) {
        close(fd);
        return -1;
    }
    return fd;
#endif
}

static void score_unlock(int fd, const char *path)
{
    (void)path;
#if defined(_WIN32)
    OVERLAPPED overlap = {0};
    (void)UnlockFileEx((HANDLE)_get_osfhandle(fd), 0, MAXDWORD, 0, &overlap);
    (void)_close(fd);
#else
    (void)flock(fd, LOCK_UN);
    (void)close(fd);
#endif
}

static bool score_store_save(int score)
{
    char path[512], temp[520];
    if (score < 0 || score > 1000000 ||
        !score_store_path(path, sizeof(path), true)) return false;
    int lock = score_lock(path);
    if (lock < 0) return false;
    if (score_store_load() >= score) {
        score_unlock(lock, path);
        return true;
    }
    int n = snprintf(temp, sizeof(temp), "%s.tmp", path);
    if (n <= 0 || (size_t)n >= sizeof(temp)) {
        score_unlock(lock, path);
        return false;
    }
    FILE *file = fopen(temp, "wb");
    bool ok = file && fprintf(file, "v1 %d\n", score) > 0;
    if (file && fclose(file) != 0) ok = false;
#if defined(_WIN32)
    ok = ok && MoveFileExA(temp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    ok = ok && rename(temp, path) == 0;
#endif
    if (!ok && file) (void)remove(temp);
    score_unlock(lock, path);
    return ok;
}

static void update_part_hud(const struct sky_expr_option *option,multiplayer_game_t *game,struct sky_expr_hud *hud,bool reload,struct sky_expr_notice *notice)
{
    const managed_aircraft_t *player=aircraft_manager_get(game->aircraft_mgr,game->local_player_id);
    double fields[XF_COUNT]={0};
    fields[XF_SCREEN_W]=GetScreenWidth();fields[XF_SCREEN_H]=GetScreenHeight();
    fields[XF_ELAPSED_SECONDS]=floor((double)game->match->elapsed_time);
    fields[XF_TEAM_COUNT]=game->match->rules.team_count;
    for(unsigned i=0;i<4;i++)fields[XF_SCORE_0+i]=game->match->team_scores[i];
    fields[XF_SCORE_LIMIT]=game->match->rules.score_limit;
    if(player) {
        fields[XF_HEALTH_MILLI]=floor((double)player->health*1000.0);
        fields[XF_MAX_HEALTH_MILLI]=floor((double)player->max_health*1000.0);
        fields[XF_SHIELD]=player->powerup_effects.shield_active;
        if(player->weapons)fields[XF_WEAPON_INDEX]=player->weapons->current_weapon;
    }
    fields[XF_BOOST_MS]=floor((double)game->boost_timer*1000.0);
    fields[XF_CONNECTED]=game->input_system->model.connected;
    fields[XF_FLASH]=game->damage_flash>0;
    if(reload)sky_expr_notice_set(notice,sky_expr_reload(option,fields,hud));else sky_expr_start(option,fields,hud);
}

static void poll_part_hud(const struct sky_expr_option *option,multiplayer_game_t *game,struct sky_expr_hud *hud,struct sky_expr_notice *notice,float dt)
{
    sky_expr_notice_tick(notice,dt);
    if(option->pin_path && IsKeyPressed(KEY_F6))update_part_hud(option,game,hud,true,notice);
    if(IsKeyPressed(KEY_F7))sky_expr_toggle(hud);
}

struct game_option_input {
    char *hud_argv[3];
    int hud_argc;
    unsigned frames;
    bool seen_frames, agent, resident_agent, seen_seed;
    const char *capture_path;
    const char *nonce;
    uint32_t seed;
};

static bool parse_game_seed(const char *number, uint32_t *seed)
{
    if (!number[0] || (number[0] == '0' && number[1])) return false;
    uint32_t candidate = 0;
    for (size_t k = 0; number[k]; k++) {
        if (number[k] < '0' || number[k] > '9') return false;
        unsigned digit = (unsigned)(number[k] - '0');
        if (candidate > (UINT32_MAX - digit) / 10u) return false;
        candidate = candidate * 10u + digit;
    }
    *seed = candidate;
    return true;
}

static bool parse_game_transport(int argc, char **argv, int *index,
                                 struct game_option_input *input, bool *matched)
{
    const char *argument = argv[*index];
    *matched = true;
    if (strcmp(argument, "--agent-stdio") == 0) {
        if (input->agent) return false;
        input->agent = true;
    } else if (strcmp(argument, "--agent") == 0) {
        if (input->agent) return false;
        input->resident_agent = input->agent = true;
    } else if (strcmp(argument, "--resident") == 0) {
        if (input->nonce || *index + 1 == argc ||
            !sky_resident_nonce_valid(argv[*index + 1])) return false;
        input->nonce = argv[++*index];
    } else *matched = false;
    return true;
}

/* --capture=PATH: one non-empty path; it needs --qa-frames, checked later. */
static bool parse_game_capture(const char *argument, struct game_option_input *input)
{
    if (input->capture_path || !argument[10]) return false;
    input->capture_path = argument + 10;
    return true;
}

static bool parse_game_argument(int argc, char **argv, int *index,
                                struct game_option_input *input)
{
    const char *argument = argv[*index];
    if (!argument) return false;
    if (strncmp(argument, "--capture=", 10) == 0) {
        if (!parse_game_capture(argument, input)) return false;
    } else if (strncmp(argument, "--qa-frames=", 12) == 0) {
        char *qa_argv[2] = {argv[0], argv[*index]};
        if (input->seen_frames || !sky_combat_qa_frames_parse(2, qa_argv, &input->frames))
            return false;
        input->seen_frames = true;
    } else if (strncmp(argument, "--seed=", 7) == 0) {
        if (input->seen_seed || !parse_game_seed(argument + 7, &input->seed)) return false;
        input->seen_seed = true;
    } else {
        bool matched;
        if (!parse_game_transport(argc, argv, index, input, &matched)) return false;
        if (!matched) {
            if (input->hud_argc == 3) return false;
            input->hud_argv[input->hud_argc++] = argv[*index];
        }
    }
    return true;
}

/* Compose strict option contracts without opening a window on refusal.
 * Caller outputs change only after every option has been accepted. */
static bool parse_game_options(int argc, char **argv,
                               struct sky_expr_option *option, unsigned *frames,
                               bool *agent_mode, const char **nonce, uint32_t *seed,
                               const char **capture_path)
{
    struct game_option_input input = {.hud_argv = {argv[0]}, .hud_argc = 1, .seed = 1};
    for (int i = 1; i < argc; ++i)
        if (!parse_game_argument(argc, argv, &i, &input)) return false;
    struct sky_expr_option candidate;
    if (input.agent && input.seen_frames) return false;
    if (input.capture_path && (input.agent || !input.seen_frames)) return false;
    if (input.resident_agent != (input.nonce != NULL) || (input.seen_seed && !input.agent && !input.seen_frames)) return false;
    if (!sky_expr_option_parse(input.hud_argc, input.hud_argv, &candidate)) return false;
    *option = candidate;
    *frames = input.frames;
    *agent_mode = input.agent;
    *nonce = input.nonce;
    *seed = input.seed;
    *capture_path = input.capture_path;
    return true;
}

/* Agent modes keep stdout for protocol replies: raylib's default trace log
 * writes to stdout, so route it to stderr explicitly instead of relying only
 * on the descriptor redirect. */
static void agent_trace_to_stderr(int level, const char *format, va_list args)
{
    const char *name = level == LOG_ERROR ? "ERROR" : level == LOG_WARNING ? "WARNING" :
        level == LOG_DEBUG ? "DEBUG" : level == LOG_TRACE ? "TRACE" : "INFO";
    fprintf(stderr, "Sky Combat raylib [%s] ", name);
    vfprintf(stderr, format, args);
    fputc('\n', stderr);
}

/* Write the captured PNG to PATH through a temp file in the same directory,
 * then rename, so a failure never leaves a partial PATH behind. */
static bool game_capture_save(const char *path, const struct sky_agent_capture *shot)
{
    if (!shot->png || shot->size == 0) {
        fprintf(stderr, "Sky Combat: no frame captured for %s (%s)\n", path,
                shot->error ? shot->error : "NO_FRAME");
        return false;
    }
    size_t length = strlen(path);
    char *temp = malloc(length + 5);
    if (!temp) {
        fprintf(stderr, "Sky Combat: out of memory writing %s\n", path);
        return false;
    }
    memcpy(temp, path, length);
    memcpy(temp + length, ".tmp", 5);
    FILE *file = fopen(temp, "wb");
    bool ok = file && fwrite(shot->png, 1, shot->size, file) == shot->size;
    if (file && fclose(file) != 0) ok = false;
#if defined(_WIN32)
    if (ok) (void)remove(path); /* Windows rename does not replace */
#endif
    ok = ok && rename(temp, path) == 0;
    if (!ok) {
        fprintf(stderr, "Sky Combat: cannot write %s\n", path);
        if (file) (void)remove(temp);
    } else {
        printf("Sky Combat: captured %s (%zu bytes)\n", path, shot->size);
        if (shot->probe_ok)
            printf("Sky Combat: player colour %u,%u,%u at %d,%d\n", shot->probe_rgb[0],
                   shot->probe_rgb[1], shot->probe_rgb[2], shot->probe_out_x, shot->probe_out_y);
        else puts("Sky Combat: player colour unavailable (aircraft not on screen)");
    }
    free(temp);
    return ok;
}

/* Keep admission and completion checks separate from the gameplay loop. */
static int prepare_game_window(int argc, char **argv, unsigned *qa_frames,
                               struct sky_expr_option *option, bool *agent_mode,
                               struct sky_agent_session *session,
                               const char **capture_path)
{
    const char *nonce = NULL;
    uint32_t seed;
    if (!parse_game_options(argc, argv, option, qa_frames, agent_mode, &nonce, &seed,
                            capture_path)) {
        fprintf(stderr, "Usage: z23-skycombat [--agent-stdio | --resident <64 lower hex nonce> --agent | --qa-frames=1..%u [--capture=PATH, needs --qa-frames]] [--seed=UINT32, default 1; agent or --qa-frames only] [--hud-part=<64 hex SHA-256>:<file> [--hud-pin-file=<file>]]\n",
                SKY_COMBAT_QA_FRAMES_MAX);
        return 2;
    }
#if defined(_WIN32)
    if (nonce) {
        fputs("Sky Combat: RESIDENT_UNSUPPORTED_WINDOWS; use --agent-stdio\n", stderr);
        return 2;
    }
#endif
    if (!sky_game_raise_open()) {
        fputs("Sky Combat: SIGUSR1 handler initialization failed\n", stderr);
        return 1;
    }
    if (*agent_mode && !(nonce ? sky_agent_open_resident(session, nonce) : sky_agent_open(session))) {
        fputs("Sky Combat: agent transport initialization failed\n", stderr);
        return 1;
    }
    if (*agent_mode) SetTraceLogCallback(agent_trace_to_stderr);
    /* Initialize window */
    SetConfigFlags(FLAG_WINDOW_RESIZABLE | FLAG_VSYNC_HINT | FLAG_MSAA_4X_HINT);
    InitWindow((*agent_mode || *qa_frames) ? 960 : SCREEN_WIDTH,
               (*agent_mode || *qa_frames) ? 540 : SCREEN_HEIGHT,
               "Sky Combat - Multiplayer Ultimate");
    if (!IsWindowReady()) {
        fprintf(stderr, "Sky Combat: window initialization failed\n");
        return 1;
    }
    SetTargetFPS(TARGET_FPS);
    sky_game_runtime_begin(*agent_mode, seed);
    if (*qa_frames) sky_game_runtime_fix_step();
    return 0;
}
static bool game_systems_ready(const multiplayer_game_t *game)
{
    return game->aircraft_mgr && game->powerup_mgr && game->match &&
        game->world && game->input_system && game->effects && game->weapons;
}
static bool game_frame_pending(unsigned limit, unsigned rendered)
{
    return (!limit || rendered < limit) && !WindowShouldClose();
}
static int game_frame_result(unsigned limit, unsigned rendered)
{
    if (limit && rendered != limit) {
        fprintf(stderr, "Sky Combat: closed after %u of %u QA frames\n",
                rendered, limit);
        return 1;
    }
    return 0;
}

static void read_keyboard_flight_stick(const multiplayer_game_t *game,
                                       float *stick_x, float *stick_y)
{
    if (!game->input_system->model.connected) {
        *stick_x = 0.0f;
        *stick_y = 0.0f;
        if (IsKeyDown(KEY_LEFT) || IsKeyDown(KEY_A)) *stick_x = -1.0f;
        if (IsKeyDown(KEY_RIGHT) || IsKeyDown(KEY_D)) *stick_x = 1.0f;
        if (IsKeyDown(KEY_UP) || IsKeyDown(KEY_W)) *stick_y = -1.0f;  /* Up = negative Y */
        if (IsKeyDown(KEY_DOWN) || IsKeyDown(KEY_S)) *stick_y = 1.0f;   /* Down = positive Y */
    }
}

static void apply_boost_and_throttle(multiplayer_game_t *game,
                                     managed_aircraft_t *player,
                                     input_state_fast_t input, float dt, bool external)
{
    /* Mario Kart boost system - UR button (speed_boost) is mushroom boost */
    game->boost_timer -= dt;

    bool boost_pressed = input.speed_boost || 
                       (!external && !game->input_system->model.connected && IsKeyPressed(KEY_SPACE));

    if (boost_pressed && game->boost_timer <= 0) {
        game->boost_timer = 0.75f;
        /* INSTANT massive speed increase (like mushroom boost) */
        player->aircraft->speed = AIRCRAFT_MAX_SPEED * 2.5f;

        /* Epic boost effects */
        effects_sonic_boom(game->effects, player->aircraft->position,
                         aircraft_get_forward_vector(player->aircraft));
        effects_screen_shake(game->effects, 3.0f, 0.5f);
        effects_screen_flash(game->effects, SKYBLUE, 0.3f);
        effects_spawn_powerup_collect(game->effects, player->aircraft->position, SKYBLUE);
    }

    /* Boost decay - rapid falloff like Mario Kart */
    if (game->boost_timer > 0) {
        /* Keep speed lines at max during boost */
        game->speed_lines_intensity = 1.0f;

        /* Only start decaying speed after 0.25 seconds */
        if (game->boost_timer < 0.5f) {
            /* Rapid decay back to normal max speed */
            float decay_rate = 300.0f * dt;
            player->aircraft->speed = fmaxf(player->aircraft->speed - decay_rate,
                                          AIRCRAFT_MAX_SPEED * 1.2f);
        }
    }
    /* UL button (brake) = normal throttle (SWAPPED) */
    else if (input.brake || (!external && !game->input_system->model.connected && IsKeyDown(KEY_LEFT_SHIFT))) {
        player->aircraft->speed = fminf(player->aircraft->speed + 60.0f * dt,
                                      AIRCRAFT_MAX_SPEED * 1.2f);
        game->speed_lines_intensity = 0.6f;
    }
    /* No throttle = gradual speed decrease */
    else {
        player->aircraft->speed = fmaxf(player->aircraft->speed - 25.0f * dt,
                                      AIRCRAFT_MIN_SPEED);
        game->speed_lines_intensity = fmaxf(0, game->speed_lines_intensity - dt * 2);
    }
}

static void control_local_player(multiplayer_game_t *game, input_state_fast_t input,
                                 float dt, bool external)
{
    /* Handle input for local player */
    managed_aircraft_t* player = aircraft_manager_get(game->aircraft_mgr, game->local_player_id);
    if (player && player->aircraft) {
        /* Get input from joystick or keyboard */
        float stick_x = input.move_x;
        float stick_y = input.move_y;

        if (!external) read_keyboard_flight_stick(game, &stick_x, &stick_y);

        /* Responsive aircraft control */
        aircraft_update_responsive(player->aircraft, stick_x, stick_y, dt);

        apply_boost_and_throttle(game, player, input, dt, external);

        /* Weapons */
        if (input.fire_guns || (!external && !game->input_system->model.connected && IsKeyDown(KEY_LEFT_CONTROL))) {
            aircraft_manager_fire_weapon(game->aircraft_mgr, game->local_player_id);

            /* Weapon effects */
            Vector3 pos = player->aircraft->position;
            Vector3 forward = aircraft_get_forward_vector(player->aircraft);
            weapons_fire_bullet(game->weapons, pos, forward, player->aircraft->yaw);
            effects_spawn_laser_hit(game->effects, pos, forward, YELLOW);
        }

        /* Camera control from right stick */
        game->camera_yaw += input.camera_x * 100.0f * dt;
    }
}

static void apply_collected_powerup(managed_aircraft_t *aircraft, powerup_type_t type)
{
    /* Apply effect */
    switch (type) {
        case POWERUP_HEALTH:
            aircraft->health = aircraft->max_health;
            break;
        case POWERUP_SHIELD:
            aircraft->powerup_effects.shield_active = true;
            break;
        case POWERUP_RAPID_FIRE:
            aircraft->powerup_effects.rapid_fire_active = true;
            break;
        case POWERUP_SPEED_BOOST:
            aircraft->powerup_effects.speed_boost_active = true;
            break;
        default:
            break;
    }
}

static void collect_aircraft_powerups(multiplayer_game_t *game)
{
    /* Check collisions */
    for (int i = 0; i < game->aircraft_mgr->aircraft_count; i++) {
        managed_aircraft_t* aircraft = &game->aircraft_mgr->aircraft[i];
        if (!aircraft->aircraft) continue;

        /* Power-up collection */
        for (int j = 0; j < game->powerup_mgr->spawn_point_count; j++) {
            powerup_t* powerup = &game->powerup_mgr->powerups[j];
            if (!powerup->active) continue;

            float dist = Vector3Distance(aircraft->aircraft->position, powerup->position);
            if (dist < 10.0f) {
                powerup_type_t type;
                if (powerup_manager_check_collection(game->powerup_mgr, 
                                                   aircraft->aircraft->position, 10.0f, &type)) {
                    apply_collected_powerup(aircraft, type);

                    /* Collection effect */
                    effects_spawn_powerup_collect(game->effects, powerup->position, powerup->color);
                    effects_show_achievement(game->effects, "POWER-UP!");
                }
            }
        }
    }
}

/* --capture only: ask the readback to sample the pixels at the player's
 * aircraft, projected through the camera that drew this frame. */
static void set_capture_probe(const multiplayer_game_t *game, struct sky_agent_capture *capture)
{
    if (!game->capture_view) return;
    const managed_aircraft_t *player = aircraft_manager_get(game->aircraft_mgr, game->local_player_id);
    int screen_width = GetScreenWidth(), screen_height = GetScreenHeight();
    if (!player || !player->aircraft || screen_width < 1 || screen_height < 1) return;
    Vector2 at = GetWorldToScreen(player->aircraft->position, game->camera);
    capture->probe_want = true;
    capture->probe_x = (int)(at.x * (float)GetRenderWidth() / (float)screen_width);
    capture->probe_y = (int)(at.y * (float)GetRenderHeight() / (float)screen_height);
}

static void render_ultimate_frame(multiplayer_game_t *game, float game_time,
                                  const struct sky_expr_hud *part_hud,
                                  const struct sky_expr_notice *notice,
                                  struct sky_agent_capture *capture)
{
    BeginDrawing();
    ClearBackground(BLACK);
    BeginMode3D(game->camera);

    /* Draw world */
    cyberpunk_world_draw(game->world, game->camera);

    /* Draw aircraft with effects */
    for (int i = 0; i < game->aircraft_mgr->aircraft_count; i++) {
        render_aircraft_ultimate(&game->aircraft_mgr->aircraft[i], game_time);
    }

    /* Draw power-ups */
    for (int i = 0; i < game->powerup_mgr->spawn_point_count; i++) {
        render_powerup_ultimate(&game->powerup_mgr->powerups[i], game->effects, game_time);
    }

    /* Draw weapons */
    weapons_draw(game->weapons);

    /* Draw effects */
    effects_draw(game->effects, game->camera);

    EndMode3D();

    /* Speed effects */
    draw_speed_effects(game);

    /* UI and effects */
    effects_draw_ui(game->effects, GetScreenWidth(), GetScreenHeight());
    render_game_hud(part_hud,notice,game);

    /* Damage flash */
    if (game->damage_flash > 0) {
        DrawRectangle(0, 0, GetScreenWidth(), GetScreenHeight(), 
                     Fade(RED, game->damage_flash * 0.3f));
    }
    render_match_flow(game);

    if (capture) {
        set_capture_probe(game, capture);
        sky_agent_capture_frame(capture);
    }
    if (game->metric_start > 0)
        game->metric_work_ms = (float)((GetTime() - game->metric_start) * 1000.0);
    EndDrawing();
}

static bool game_action_pressed(multiplayer_game_t *game,
                                const input_state_fast_t *input, bool external)
{
    bool down = input->fire_guns;
    if (!external)
        down = down || IsKeyPressed(KEY_ENTER) || IsKeyPressed(KEY_R) ||
            IsKeyPressed(KEY_LEFT_CONTROL);
    if (!down) {
        game->action_latched = false;
        return false;
    }
    if (game->action_latched) return false;
    game->action_latched = true;
    return true;
}

static void game_reset_effects(effects_manager_t *effects)
{
    for (int i = 0; i < effects->max_effects; ++i)
        effects->effects[i].active = false;
    for (int i = 0; i < effects->max_particles; ++i)
        effects->global_particles[i].active = false;
    memset(effects->feedbacks, 0, (size_t)effects->max_feedbacks * sizeof(effects->feedbacks[0]));
    effects->active_effects = 0;
    effects->active_particles = 0;
    effects->active_feedbacks = 0;
    effects->screen_shake = 0;
    effects->motion_blur = 0;
    effects->chromatic_aberration = 0;
    effects->flash_intensity = 0;
    effects->time_scale = 1.0f;
    effects->bullet_time_active = false;
    effects->bullet_time_remaining = 0;
}

static bool game_restart_match(multiplayer_game_t *game)
{
    aircraft_manager_reset_match(game->aircraft_mgr);
    weapons_reset(game->weapons);
    memset(game->powerup_mgr->powerups, 0, sizeof(game->powerup_mgr->powerups));
    game->powerup_mgr->powerup_count = 0;
    game->powerup_mgr->spawn_check_timer = 0;
    game_reset_effects(game->effects);
    game->boost_timer = 0;
    game->damage_flash = 0;
    game->speed_lines_intensity = 0;
    game->camera_yaw = 0;
    sky_game_runtime_reseed();
    return match_state_restart(game->match);
}

static void game_finish_match(multiplayer_game_t *game)
{
    game->flow = GAME_FLOW_ENDED;
    int score = game->match->team_scores[0];
    if (!game->qa_mode && score > game->best_score) {
        game->best_score = score;
        if (!score_store_save(score)) {
            game->score_save_failed = true;
            fprintf(stderr, "Sky Combat: could not save best score %d\n", score);
        }
    }
    printf("Sky Combat: match ended red=%d blue=%d winner_team=%d best=%d\n",
           game->match->team_scores[0], game->match->team_scores[1],
           game->match->winning_team, game->best_score);
}

static void render_match_flow(const multiplayer_game_t *game)
{
    if (game->flow == GAME_FLOW_PLAYING) return;
    int width = GetScreenWidth(), height = GetScreenHeight();
    DrawRectangle(0, 0, width, height, Fade(BLACK, 0.72f));
    const char *title = "SKY COMBAT";
    const char *result = NULL;
    if (game->flow == GAME_FLOW_ENDED) {
        if (game->match->winning_team < 0) result = "DRAW";
        else result = game->match->winning_team == 0 ? "YOU WIN" : "YOU LOSE";
    }
    int title_size = result ? 64 : 76;
    DrawText(title, width / 2 - MeasureText(title, title_size) / 2,
             height / 2 - 190, title_size, SKYBLUE);
    if (result)
        DrawText(result, width / 2 - MeasureText(result, 56) / 2,
                 height / 2 - 105, 56,
                 game->match->winning_team == 0 ? GOLD : WHITE);
    char score[128];
    snprintf(score, sizeof(score), "RED %d  -  BLUE %d     BEST %d",
             game->match->team_scores[0], game->match->team_scores[1],
             game->best_score);
    DrawText(score, width / 2 - MeasureText(score, 30) / 2,
             height / 2 - 30, 30, WHITE);
    const char *action = game->flow == GAME_FLOW_START
        ? "ENTER / FIRE TO START" : "R / FIRE TO RESTART";
    DrawText(action, width / 2 - MeasureText(action, 32) / 2,
             height / 2 + 45, 32, GOLD);
    DrawText("WASD / ARROWS: FLY   LCTRL: GUNS   SPACE: BOOST   SHIFT: THROTTLE",
             width / 2 - MeasureText("WASD / ARROWS: FLY   LCTRL: GUNS   SPACE: BOOST   SHIFT: THROTTLE", 20) / 2,
             height / 2 + 105, 20, GRAY);
    if (game->score_save_failed)
        DrawText("BEST SCORE SAVE UNAVAILABLE", 20, height - 35, 20, RED);
}

static double game_metrics_begin(multiplayer_game_t *game, float *interval_ms)
{
    double started = game->metrics_enabled ? GetTime() : 0;
    game->metric_start = started;
    *interval_ms = game->metrics_enabled && game->metric_previous > 0
        ? (float)((started - game->metric_previous) * 1000.0) : -1.0f;
    if (game->metrics_enabled) game->metric_previous = started;
    return started;
}

static void game_metrics_end(multiplayer_game_t *game, double started,
                             float interval_ms, bool external_input)
{
    if (game->metrics_enabled)
        sky_game_metrics_record(game->metric_work_ms,
                                (float)((GetTime() - started) * 1000.0),
                                interval_ms, external_input);
}

static input_state_fast_t game_read_input(multiplayer_game_t *game,
                                          const input_state_fast_t *external_input)
{
    if (external_input) return *external_input;
    input_view_fast_t view = input_mvc_fast_update(game->input_system);
    return input_view_get_state(view);
}

static void game_handle_action(multiplayer_game_t *game,
                               const struct sky_expr_option *option,
                               struct sky_expr_hud *part_hud,
                               struct sky_expr_notice *notice,
                               const input_state_fast_t *input, bool external,
                               float *game_time)
{
    bool action = game_action_pressed(game, input, external);
    if (game->flow == GAME_FLOW_START && action) {
        if (match_state_begin(game->match)) game->flow = GAME_FLOW_PLAYING;
        else fprintf(stderr, "Sky Combat: could not start match\n");
    } else if (game->flow == GAME_FLOW_ENDED && (action || game->qa_mode)) {
        if (game_restart_match(game)) {
            game->flow = GAME_FLOW_PLAYING;
            *game_time = 0;
            update_part_hud(option, game, part_hud, false, notice);
        } else {
            fprintf(stderr, "Sky Combat: could not restart match\n");
        }
    }
}

static void game_simulate(multiplayer_game_t *game, input_state_fast_t input,
                          float dt, bool external)
{
    if (game->flow != GAME_FLOW_PLAYING) return;
    control_local_player(game, input, dt, external);
    aircraft_manager_update(game->aircraft_mgr, dt);
    powerup_manager_update(game->powerup_mgr, dt);
    weapons_update(game->weapons, dt);
    effects_update(game->effects, dt);
    update_camera_ultimate(game, dt);
    collect_aircraft_powerups(game);
    update_match_ledger(game, dt);
    if (game->damage_flash > 0) game->damage_flash -= dt;
    update_damage_smoke(game);
    if (game->match->match_ended) game_finish_match(game);
}

static void advance_ultimate_frame(multiplayer_game_t *game,
                                   const struct sky_expr_option *option,
                                   struct sky_expr_hud *part_hud,
                                   struct sky_expr_notice *notice,
                                   float *game_time, unsigned *rendered_frames,
                                   const input_state_fast_t *external_input,
                                   struct sky_agent_capture *capture)
{
    float interval_ms;
    double metric_start = game_metrics_begin(game, &interval_ms);
    float dt = external_input || game->capture_view || game->fixed_step ? 1.0f / 60.0f : GetFrameTime();
    if (external_input || game->fixed_step) {
        sky_game_runtime_tick();
        *game_time = (float)sky_game_runtime_time();
    } else *game_time += dt;
    if (!external_input) poll_part_hud(option,game,part_hud,notice,dt);
    else sky_expr_notice_tick(notice, dt);
    input_state_fast_t input = game_read_input(game, external_input);
    game_handle_action(game, option, part_hud, notice, &input,
                       external_input != NULL, game_time);
    game_simulate(game, input, dt, external_input != NULL);
    render_ultimate_frame(game, *game_time, part_hud, notice, capture);
    game_metrics_end(game, metric_start, interval_ms, external_input != NULL);
    ++*rendered_frames;
}

#ifndef ZCL_BUILD_SOURCE_ID
#define ZCL_BUILD_SOURCE_ID "unknown"
#endif
#define SKY_COMBAT_PROGRAM_VERSION 1

/* One monotonic origin per process, sampled at main entry. */
static struct sky_qa_timing qa_timing;

/* `--version` alone: identity only, before any window or option parsing. */
static bool game_version_requested(int argc, char **argv)
{
    return argc == 2 && argv[1] && strcmp(argv[1], "--version") == 0;
}

/* Same build identity the node reports: ZCL_BUILD_SOURCE_ID, the 64-hex
 * source-tree digest the Makefile stamps (`z23 --version` prints its first 12). */
static int game_print_version(void)
{
    printf("z23-skycombat v%d (source %.12s)\n", SKY_COMBAT_PROGRAM_VERSION,
           ZCL_BUILD_SOURCE_ID);
    printf("source-id %s\n", ZCL_BUILD_SOURCE_ID);
    return fflush(stdout) == 0 ? 0 : 1;
}

/* Simulation state at the last frame: every aircraft pose, health and tally
 * plus the team scores. Two --qa-frames runs agree on it iff they did the same work. */
static uint64_t game_state_digest(const multiplayer_game_t *game)
{
    uint64_t digest = SKY_QA_DIGEST_SEED;
    int count = game->aircraft_mgr->aircraft_count;
    digest = sky_qa_digest_i32(digest, count);
    for (int i = 0; i < count && i < MAX_MANAGED_AIRCRAFT; ++i) {
        const managed_aircraft_t *ship = &game->aircraft_mgr->aircraft[i];
        const float pose[] = {ship->aircraft->position.x, ship->aircraft->position.y,
                              ship->aircraft->position.z, ship->aircraft->yaw,
                              ship->aircraft->pitch, ship->aircraft->roll, ship->health};
        for (size_t k = 0; k < sizeof(pose) / sizeof(pose[0]); ++k)
            digest = sky_qa_digest_f32(digest, pose[k]);
        digest = sky_qa_digest_i32(digest, ship->kills);
        digest = sky_qa_digest_i32(digest, ship->deaths);
    }
    for (int team = 0; team < 4; ++team)
        digest = sky_qa_digest_i32(digest, game->match->team_scores[team]);
    return digest;
}

static void qa_timing_report(const multiplayer_game_t *game)
{
    struct sky_qa_summary summary;
    char line[256];
    if (!sky_qa_timing_summarize(&qa_timing, &summary)) return;
    summary.state_digest = game_state_digest(game);
    if (!sky_qa_summary_format(&summary, line, sizeof(line))) {
        fputs("Sky Combat: QA frame-time line did not fit\n", stderr);
        return;
    }
    puts(line);
}

/* The windowed (non-agent) loop. QA runs time each frame with a monotonic
 * clock into fixed storage; interactive runs take no timing at all. */
static int run_frame_loop(multiplayer_game_t *game, const struct sky_expr_option *option,
                          struct sky_expr_hud *part_hud, struct sky_expr_notice *notice,
                          unsigned qa_frames,
                          const char *capture_path)
{
    struct sky_agent_capture shot = {0};
    float game_time = 0;
    unsigned rendered_frames = 0;
    while (game_frame_pending(qa_frames, rendered_frames)) {
        sky_game_raise_apply();
        bool last = capture_path && rendered_frames + 1 == qa_frames;
        uint64_t began = qa_frames ? sky_qa_now_us() : 0;
        advance_ultimate_frame(game, option, part_hud, notice,
                               &game_time, &rendered_frames, NULL, last ? &shot : NULL);
        if (qa_frames) sky_qa_timing_record(&qa_timing, began, sky_qa_now_us());
    }
    int result = game_frame_result(qa_frames, rendered_frames);
    if (!result && capture_path && !game_capture_save(capture_path, &shot)) result = 1;
    free(shot.png);
    if (qa_frames) qa_timing_report(game);
    return result;
}

struct game_agent_context {
    multiplayer_game_t *game;
    const struct sky_expr_option *option;
    struct sky_expr_hud *hud;
    struct sky_expr_notice *notice;
    float time;
    unsigned frames;
};

static input_mvc_fast_t *game_input_create(bool external)
{
    if (!external) return input_mvc_fast_create();
    /* External sessions need the model/view for HUD state, but never open or
     * poll a hardware controller. The normal destructor accepts NULL controller. */
    input_mvc_fast_t *input = calloc(1, sizeof(*input));
    if (!input) return NULL;
    input_model_fast_init(&input->model);
    input->view = input_view_fast_create(&input->model);
    return input;
}

static void game_agent_frame(void *context, const input_state_fast_t *input,
    struct sky_agent_observation *state, struct sky_agent_capture *capture)
{
    struct game_agent_context *agent = context;
    if (input) {
        advance_ultimate_frame(agent->game, agent->option, agent->hud, agent->notice,
            &agent->time, &agent->frames, input, capture);
    } else {
        render_ultimate_frame(agent->game, agent->time,
                               agent->hud, agent->notice, capture);
    }
    *state = (struct sky_agent_observation){.frame = agent->frames, .time = sky_game_runtime_time()};
    managed_aircraft_t *player = aircraft_manager_get(agent->game->aircraft_mgr,
                                                      agent->game->local_player_id);
    if (player && player->aircraft) {
        state->player_present = true;
        state->x = player->aircraft->position.x;
        state->y = player->aircraft->position.y;
        state->z = player->aircraft->position.z;
        state->yaw = player->aircraft->yaw;
        state->speed = player->aircraft->speed;
        state->health = player->health;
    }
    state->match_started = agent->game->match->match_started;
    state->match_ended = agent->game->match->match_ended;
    state->score_red = agent->game->match->team_scores[0];
    state->score_blue = agent->game->match->team_scores[1];
    state->winning_team = agent->game->match->winning_team;
    state->best_score = agent->game->best_score;
}

static bool game_init(multiplayer_game_t *game, unsigned qa_frames,
                      bool agent_mode, const struct sky_expr_option *option,
                      struct sky_expr_hud *part_hud, struct sky_expr_notice *notice,
                      const char *capture_path)
{
    game->agent_mode = agent_mode;
    game->metrics_enabled = true;
    game->aircraft_mgr = aircraft_manager_create();
    game->powerup_mgr = powerup_manager_create();
    game->match = match_state_create(MATCH_TYPE_TEAM_DEATHMATCH);
    game->world = cyberpunk_world_create();
    game->input_system = game_input_create(agent_mode);
    game->effects = effects_create(1000, 10000);
    game->weapons = weapons_create();
    if (!game_systems_ready(game)) {
        fprintf(stderr, "Failed to create game systems\n");
        return false;
    }
    report_game_input(game);
    game->match->rules.score_limit = 3;
    game->match->rules.time_limit = 15.0f;
    game->match->rules.respawn_time = 3.0f;
    game->match->rules.friendly_fire = false;
    game->match->rules.team_count = 2;
    game->qa_mode = qa_frames != 0;
    game->best_score = game->qa_mode ? 0 : score_store_load();
    game->flow = qa_frames || agent_mode ? GAME_FLOW_PLAYING : GAME_FLOW_START;
    if (game->flow == GAME_FLOW_PLAYING && !match_state_begin(game->match)) {
        fprintf(stderr, "Could not begin match\n");
        return false;
    }
    game->local_player_id = aircraft_manager_add_with_team(game->aircraft_mgr, "PLAYER 1", RED, false, true, 0);
    aircraft_manager_add_with_team(game->aircraft_mgr, "BLUE LEADER", BLUE, true, false, 1);
    aircraft_manager_add_with_team(game->aircraft_mgr, "BLUE WING", SKYBLUE, true, false, 1);
    aircraft_manager_add_with_team(game->aircraft_mgr, "RED LEADER", MAROON, true, false, 0);
    aircraft_manager_add_with_team(game->aircraft_mgr, "RED WING", ORANGE, true, false, 0);
    for (int i = 1; i < game->aircraft_mgr->aircraft_count; i++)
        game->aircraft_mgr->aircraft[i].ai_skill = 0.6f + (float)(rand() % 40) / 100.0f;
    Vector3 spawn_points[] = {
        {0, 100, 0}, {150, 50, 150}, {-150, 50, 150}, {150, 50, -150},
        {-150, 50, -150}, {0, 150, 200}, {0, 150, -200}, {200, 75, 0}, {-200, 75, 0}
    };
    for (int i = 0; i < 9; i++)
        powerup_manager_add_spawn_point(game->powerup_mgr, spawn_points[i],
                                        POWERUP_HEALTH + (i % 8), 20.0f);
    game->camera.position = (Vector3){0, 50, -50};
    game->camera.target = (Vector3){0, 50, 0};
    game->camera.up = (Vector3){0, 1, 0};
    game->camera.fovy = 65.0f;
    game->camera.projection = CAMERA_PERSPECTIVE;
    game->camera_distance = 35.0f;
    game->motion_blur_enabled = true;
    game->capture_view = capture_path != NULL;
    game->fixed_step = qa_frames != 0;
    cyberpunk_world_generate(game->world, 42);
    cyberpunk_set_theme_blade_runner(game->world);
    sky_game_runtime_reseed();
    update_part_hud(option, game, part_hud, false, notice);
    return true;
}

static int game_run(multiplayer_game_t *game, unsigned qa_frames,
                    bool agent_mode, struct sky_agent_session *session,
                    const struct sky_expr_option *option,
                    struct sky_expr_hud *part_hud, struct sky_expr_notice *notice,
                    const char *capture_path)
{
    sky_game_metrics_reset();
    int result;
    if (agent_mode) {
        struct game_agent_context context = {game, option, part_hud, notice, 0, 0};
        result = sky_agent_run(session, &context, game_agent_frame);
    } else {
        result = run_frame_loop(game, option, part_hud, notice, qa_frames, capture_path);
    }
    sky_game_metrics_report();
    return result;
}

int main(int argc, char **argv) {
    sky_qa_timing_begin(&qa_timing, sky_qa_now_us());
    if (game_version_requested(argc, argv)) return game_print_version();
    unsigned qa_frames;
    bool agent_mode = false;
    struct sky_agent_session session = {0};
    struct sky_expr_option option;
    static struct sky_expr_hud part_hud;
    struct sky_expr_notice notice={0};
    const char *capture_path = NULL;
    int launch = prepare_game_window(argc, argv, &qa_frames, &option, &agent_mode, &session,
                                     &capture_path);
    if (launch) { sky_agent_close(&session); return launch; }
    multiplayer_game_t game = {0};
    if (!game_init(&game, qa_frames, agent_mode, &option, &part_hud, &notice, capture_path)) {
        destroy_game_systems(&game);
        CloseWindow();
        sky_agent_close(&session);
        return 1;
    }
    int result = game_run(&game, qa_frames, agent_mode, &session, &option,
                          &part_hud, &notice, capture_path);
    destroy_game_systems(&game);
    CloseWindow();
    if (!sky_agent_close(&session)) result = 1;
    return result;
}
