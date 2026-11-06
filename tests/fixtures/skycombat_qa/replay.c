/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* purpose: source-bound actual Sky Combat model replay.
 * Compile with the maintained game/support sources, excluding its main and
 * raylib implementation objects. No product source is replaced. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <math.h>
#include <float.h>
#include <raylib.h>
#include <external/stb_image_resize2.h>
#include "zsha256/zsha256.h"
#define RPRAND_IMPLEMENTATION
#include <external/rprand.h>

#define main sky_replay_product_main
#include "apps/skycombat/src/sky_combat_multiplayer_ultimate.c"
#undef main

#define REPLAY_TICKS 120u
#define REPLAY_GROUPS 7u
static_assert(sizeof(float) == sizeof(uint32_t) && FLT_MANT_DIG == 24,
              "game replay requires binary32");

/* Platform/render boundary only. Model, clock, effects and game callbacks
 * below remain production code. A failed readback is intentional; no image
 * or rendering correctness is claimed by this headless fixture. */
static double replay_wall_time;
static unsigned replay_wall_reads, replay_draws, replay_readbacks;
static unsigned replay_unexpected_window_calls;
static unsigned replay_unexpected_model_calls;

void RestoreWindow(void) { ++replay_unexpected_window_calls; }
void SetWindowFocused(void) { ++replay_unexpected_window_calls; }

double GetTime(void) { ++replay_wall_reads; return replay_wall_time; }
float GetFrameTime(void) { ++replay_unexpected_model_calls; return 1.0f / 60.0f; }
void SetRandomSeed(unsigned int seed) { rprand_set_seed(seed); }
int GetRandomValue(int minimum, int maximum)
{
    if (minimum > maximum) {
        int temporary = minimum;
        minimum = maximum;
        maximum = temporary;
    }
    return rprand_get_value(minimum, maximum);
}
int GetScreenWidth(void) { return 960; }
int GetScreenHeight(void) { return 540; }
int GetRenderWidth(void) { return 960; }
int GetRenderHeight(void) { return 540; }
bool IsKeyDown([[maybe_unused]] int key) { return false; }
bool IsKeyPressed([[maybe_unused]] int key) { return false; }
bool IsMouseButtonDown([[maybe_unused]] int button) { return false; }
Vector2 GetMouseDelta(void) { return (Vector2){0}; }
void PollInputEvents(void) { }
void SetConfigFlags([[maybe_unused]] unsigned flags) { }
void SetTraceLogCallback([[maybe_unused]] TraceLogCallback callback) { }
void SetTargetFPS([[maybe_unused]] int fps) { }
void InitWindow([[maybe_unused]] int width, [[maybe_unused]] int height,
                [[maybe_unused]] const char *title) { ++replay_unexpected_window_calls; }
void CloseWindow(void) { ++replay_unexpected_window_calls; }
bool IsWindowReady(void) { return true; }
bool WindowShouldClose(void) { return true; }
void BeginDrawing(void) { ++replay_draws; }
void EndDrawing(void) { }
void BeginTextureMode([[maybe_unused]] RenderTexture2D texture) { }
void EndTextureMode(void) { }
void BeginMode3D([[maybe_unused]] Camera3D camera) { }
void EndMode3D(void) { }
void BeginBlendMode([[maybe_unused]] int mode) { }
void EndBlendMode(void) { }
void ClearBackground([[maybe_unused]] Color color) { }
void rlDrawRenderBatchActive(void) { }
void rlPushMatrix(void) { }
void rlPopMatrix(void) { }
void rlTranslatef([[maybe_unused]] float x, [[maybe_unused]] float y,
                  [[maybe_unused]] float z) { }
void rlRotatef([[maybe_unused]] float angle, [[maybe_unused]] float x,
               [[maybe_unused]] float y, [[maybe_unused]] float z) { }
Image LoadImageFromScreen(void) { ++replay_readbacks; return (Image){0}; }
Image GenImageColor(int width, int height, Color color)
{
    if (width != 1 || height != 1) return (Image){0};
    unsigned char *pixel = malloc(4);
    if (!pixel) return (Image){0};
    pixel[0] = color.r; pixel[1] = color.g; pixel[2] = color.b; pixel[3] = color.a;
    return (Image){pixel, 1, 1, 1, PIXELFORMAT_UNCOMPRESSED_R8G8B8A8};
}
void UnloadImage(Image image) { free(image.data); }
Texture2D LoadTextureFromImage(Image image)
{
    return (Texture2D){image.data ? 1u : 0u, image.width, image.height, 1, image.format};
}
void UnloadTexture([[maybe_unused]] Texture2D texture) { }
RenderTexture2D LoadRenderTexture([[maybe_unused]] int width,
                                 [[maybe_unused]] int height) { return (RenderTexture2D){0}; }
void UnloadRenderTexture([[maybe_unused]] RenderTexture2D texture) { }
unsigned char *stbir_resize_uint8_linear([[maybe_unused]] const unsigned char *input,
    [[maybe_unused]] int width, [[maybe_unused]] int height, [[maybe_unused]] int stride,
    [[maybe_unused]] unsigned char *output, [[maybe_unused]] int out_width,
    [[maybe_unused]] int out_height, [[maybe_unused]] int out_stride,
    [[maybe_unused]] stbir_pixel_layout layout) { return NULL; }
Color Fade(Color color, float alpha)
{
    color.a = (unsigned char)(255.0f * fminf(1.0f, fmaxf(0.0f, alpha)));
    return color;
}
Color ColorLerp(Color a, Color b, float fraction)
{
    float t = fminf(1.0f, fmaxf(0.0f, fraction));
    return (Color){(unsigned char)(a.r + (b.r - a.r) * t),
                   (unsigned char)(a.g + (b.g - a.g) * t),
                   (unsigned char)(a.b + (b.b - a.b) * t),
                   (unsigned char)(a.a + (b.a - a.a) * t)};
}
Font GetFontDefault(void) { return (Font){0}; }
int MeasureText(const char *text, int size) { return (int)strlen(text) * size / 2; }
Vector2 MeasureTextEx([[maybe_unused]] Font font, const char *text, float size,
                      [[maybe_unused]] float spacing)
{ return (Vector2){(float)strlen(text) * size / 2.0f, size}; }
const char *TextFormat(const char *format, ...)
{
    static char text[1024];
    va_list arguments;
    va_start(arguments, format);
    int result = vsnprintf(text, sizeof(text), format, arguments);
    va_end(arguments);
    if (result < 0 || (size_t)result >= sizeof(text)) text[0] = '\0';
    return text;
}
Vector2 GetWorldToScreen(Vector3 point, [[maybe_unused]] Camera camera)
{ return (Vector2){point.x, point.y}; }
void UpdateCameraPro([[maybe_unused]] Camera *camera, [[maybe_unused]] Vector3 movement,
                      [[maybe_unused]] Vector3 rotation, [[maybe_unused]] float zoom)
{ ++replay_unexpected_model_calls; }
void DrawFPS([[maybe_unused]] int x, [[maybe_unused]] int y) { }
void DrawText([[maybe_unused]] const char *text, [[maybe_unused]] int x,
              [[maybe_unused]] int y, [[maybe_unused]] int size, [[maybe_unused]] Color tint) { }
void DrawTextEx([[maybe_unused]] Font font, [[maybe_unused]] const char *text,
                [[maybe_unused]] Vector2 position, [[maybe_unused]] float size,
                [[maybe_unused]] float spacing, [[maybe_unused]] Color tint) { }
void DrawRectangle([[maybe_unused]] int x, [[maybe_unused]] int y,
                   [[maybe_unused]] int width, [[maybe_unused]] int height,
                   [[maybe_unused]] Color color) { }
void DrawRectangleRec([[maybe_unused]] Rectangle rectangle, [[maybe_unused]] Color color) { }
void DrawRectangleLines([[maybe_unused]] int x, [[maybe_unused]] int y,
                        [[maybe_unused]] int width, [[maybe_unused]] int height,
                        [[maybe_unused]] Color color) { }
void DrawRectangleLinesEx([[maybe_unused]] Rectangle rectangle,
                          [[maybe_unused]] float width, [[maybe_unused]] Color color) { }
void DrawRectangleGradientV([[maybe_unused]] int x, [[maybe_unused]] int y,
                            [[maybe_unused]] int width, [[maybe_unused]] int height,
                            [[maybe_unused]] Color top, [[maybe_unused]] Color bottom) { }
void DrawLineEx([[maybe_unused]] Vector2 start, [[maybe_unused]] Vector2 end,
                [[maybe_unused]] float width, [[maybe_unused]] Color color) { }
void DrawLine3D([[maybe_unused]] Vector3 start, [[maybe_unused]] Vector3 end,
                [[maybe_unused]] Color color) { }
void DrawCube([[maybe_unused]] Vector3 position, [[maybe_unused]] float width,
              [[maybe_unused]] float height, [[maybe_unused]] float length,
              [[maybe_unused]] Color color) { }
void DrawCubeWires([[maybe_unused]] Vector3 position, [[maybe_unused]] float width,
                   [[maybe_unused]] float height, [[maybe_unused]] float length,
                   [[maybe_unused]] Color color) { }
void DrawSphere([[maybe_unused]] Vector3 center, [[maybe_unused]] float radius,
                [[maybe_unused]] Color color) { }
void DrawSphereWires([[maybe_unused]] Vector3 center, [[maybe_unused]] float radius,
                     [[maybe_unused]] int rings, [[maybe_unused]] int slices,
                     [[maybe_unused]] Color color) { }
void DrawCapsule([[maybe_unused]] Vector3 start, [[maybe_unused]] Vector3 end,
                 [[maybe_unused]] float radius, [[maybe_unused]] int rings,
                 [[maybe_unused]] int slices, [[maybe_unused]] Color color) { }
void DrawCylinder([[maybe_unused]] Vector3 position, [[maybe_unused]] float top,
                  [[maybe_unused]] float bottom, [[maybe_unused]] float height,
                  [[maybe_unused]] int sides, [[maybe_unused]] Color color) { }
void DrawCylinderEx([[maybe_unused]] Vector3 start, [[maybe_unused]] Vector3 end,
                    [[maybe_unused]] float start_radius, [[maybe_unused]] float end_radius,
                    [[maybe_unused]] int sides, [[maybe_unused]] Color color) { }
void DrawCircle3D([[maybe_unused]] Vector3 center, [[maybe_unused]] float radius,
                  [[maybe_unused]] Vector3 axis, [[maybe_unused]] float angle,
                  [[maybe_unused]] Color color) { }
void DrawTextureRec([[maybe_unused]] Texture2D texture, [[maybe_unused]] Rectangle source,
                    [[maybe_unused]] Vector2 position, [[maybe_unused]] Color tint) { }
void DrawBillboard([[maybe_unused]] Camera camera, [[maybe_unused]] Texture2D texture,
                   [[maybe_unused]] Vector3 position, [[maybe_unused]] float scale,
                   [[maybe_unused]] Color tint) { }

struct replay_snapshot { unsigned char group[REPLAY_GROUPS][ZSHA256_DIGEST_LEN]; };
struct replay_writer { zsha256_ctx hash; bool valid; };
static const char *const replay_group_names[] = {
    "game-clock-input", "roster", "weapons", "pickups", "match", "effects", "world"
};

static void replay_integer(struct replay_writer *writer, uint64_t value)
{
    unsigned char bytes[8];
    for (unsigned i = 0; i < 8; ++i) bytes[i] = (unsigned char)(value >> (8u * i));
    zsha256_update(&writer->hash, bytes, sizeof(bytes));
}
static void replay_float(struct replay_writer *writer, float value)
{
    uint32_t bits;
    if (!isfinite(value)) writer->valid = false;
    memcpy(&bits, &value, sizeof(bits));
    replay_integer(writer, bits);
}
static void replay_vector(struct replay_writer *writer, Vector3 value)
{
    replay_float(writer, value.x);
    replay_float(writer, value.y);
    replay_float(writer, value.z);
}
static void replay_color(struct replay_writer *writer, Color value)
{
    replay_integer(writer, value.r);
    replay_integer(writer, value.g);
    replay_integer(writer, value.b);
    replay_integer(writer, value.a);
}
#define RF(member) replay_float(writer, value->member)
#define RI(member) replay_integer(writer, (uint64_t)value->member)
#define RV(member) replay_vector(writer, value->member)
#define RC(member) replay_color(writer, value->member)

static void replay_powerup_effects(struct replay_writer *writer, const powerup_effects_t *value)
{
    RI(shield_active); RF(shield_timer);
    RI(rapid_fire_active); RF(rapid_fire_timer); RF(fire_rate_multiplier);
    RI(speed_boost_active); RF(speed_boost_timer); RF(speed_multiplier);
    RI(double_damage_active); RF(double_damage_timer);
    RI(missile_count); RI(laser_equipped); RF(laser_ammo);
}
static void replay_aircraft(struct replay_writer *writer, const aircraft_t *value)
{
    RV(position); RF(yaw); RF(pitch); RF(roll); RF(speed); RF(altitude);
    RI(score); RI(rings); RF(fireTimer); RF(missileTimer); RI(missileSide);
}
static void replay_roster(struct replay_writer *writer, const aircraft_manager_t *value)
{
    RI(aircraft_count); RI(spawn_count); RF(collision_radius); RF(projectile_radius);
    if (value->aircraft_count != 3 || value->spawn_count < 0 ||
        value->spawn_count > MAX_SPAWN_POINTS) { writer->valid = false; return; }
    for (int i = 0; i < value->spawn_count; ++i) replay_vector(writer, value->spawn_points[i]);
    for (int i = 0; i < value->aircraft_count; ++i) {
        const managed_aircraft_t *aircraft = &value->aircraft[i];
        if (!aircraft->aircraft || !aircraft->weapons) { writer->valid = false; return; }
        replay_aircraft(writer, aircraft->aircraft);
        replay_powerup_effects(writer, &aircraft->powerup_effects);
        replay_integer(writer, (uint64_t)aircraft->id);
        replay_color(writer, aircraft->color);
        replay_integer(writer, aircraft->is_ai);
        replay_integer(writer, aircraft->is_local_player);
        replay_float(writer, aircraft->health);
        replay_float(writer, aircraft->max_health);
        replay_integer(writer, (uint64_t)aircraft->kills);
        replay_integer(writer, (uint64_t)aircraft->deaths);
        replay_integer(writer, (uint64_t)aircraft->assists);
        replay_float(writer, aircraft->respawn_timer);
        replay_integer(writer, (uint64_t)aircraft->team_id);
        replay_integer(writer, (uint64_t)aircraft->target_id);
        replay_float(writer, aircraft->ai_skill);
        replay_float(writer, aircraft->ai_aggression);
    }
}
static void replay_weapons(struct replay_writer *writer, const weapons_system_t *value)
{
    RI(bullet_count); RI(fire_pattern); RI(current_weapon); RI(current_upgrade);
    RF(upgrade_timer); RF(damage_multiplier); RF(fire_rate_multiplier);
    RF(recoil_amount); RF(muzzle_flash_timer); RV(last_fire_position); RV(last_fire_direction);
    RF(bullet_bend_x); RF(bullet_bend_y); RF(bend_strength);
    for (int i = 0; i < WEAPON_COUNT; ++i) {
        replay_float(writer, value->fire_cooldown[i]);
        replay_float(writer, value->weapon_heat[i]);
        replay_integer(writer, (uint64_t)value->ammo[i]);
    }
    const bullet_t *bullet = value->bullets_head;
    unsigned count = 0;
    while (bullet && count < MAX_BULLETS) {
        replay_vector(writer, bullet->position);
        replay_vector(writer, bullet->velocity);
        replay_vector(writer, bullet->bend_force);
        replay_float(writer, bullet->life);
        replay_integer(writer, bullet->active);
        replay_integer(writer, (uint64_t)bullet->damage);
        replay_color(writer, bullet->color);
        replay_float(writer, bullet->size);
        bullet = bullet->next;
        ++count;
    }
    if (bullet || value->bullet_count != (int)count) writer->valid = false;
    for (int i = 0; i < MAX_MISSILES; ++i) {
        const missile_t *missile = &value->missiles[i];
        replay_integer(writer, missile->active);
        if (!missile->active) continue;
        if (missile->target) writer->valid = false; /* No ring targets in this scenario. */
        replay_vector(writer, missile->position);
        replay_vector(writer, missile->velocity);
        replay_float(writer, missile->life);
        replay_integer(writer, missile->is_rocket);
        replay_integer(writer, (uint64_t)missile->damage);
    }
    for (int i = 0; i < MAX_LASERS; ++i) {
        const laser_t *laser = &value->lasers[i];
        replay_integer(writer, laser->active);
        if (!laser->active) continue;
        replay_vector(writer, laser->position);
        replay_vector(writer, laser->velocity);
        replay_vector(writer, laser->end_position);
        replay_float(writer, laser->life);
        replay_float(writer, laser->charge);
        replay_integer(writer, (uint64_t)laser->damage);
    }
    for (int i = 0; i < MAX_PLASMA; ++i) {
        const plasma_t *plasma = &value->plasma[i];
        replay_integer(writer, plasma->active);
        if (!plasma->active) continue;
        replay_vector(writer, plasma->position);
        replay_vector(writer, plasma->velocity);
        replay_float(writer, plasma->life);
        replay_float(writer, plasma->size);
        replay_integer(writer, (uint64_t)plasma->damage);
    }
}
static void replay_pickups(struct replay_writer *writer, const powerup_manager_t *value)
{
    RI(powerup_count); RI(spawn_point_count); RF(spawn_check_timer); RF(spawn_check_interval);
    if (value->powerup_count < 0 || value->powerup_count > 32 ||
        value->spawn_point_count < 0 || value->spawn_point_count > 16) {
        writer->valid = false;
        return;
    }
    for (int i = 0; i < value->powerup_count; ++i) {
        const powerup_t *powerup = &value->powerups[i];
        replay_integer(writer, (uint64_t)powerup->type);
        replay_vector(writer, powerup->position);
        replay_float(writer, powerup->rotation);
        replay_float(writer, powerup->bob_offset);
        replay_integer(writer, powerup->active);
        replay_float(writer, powerup->respawn_timer);
        replay_integer(writer, (uint64_t)powerup->spawn_point_id);
        replay_color(writer, powerup->color);
        replay_float(writer, powerup->size);
        replay_float(writer, powerup->duration);
        replay_float(writer, powerup->value);
    }
    for (int i = 0; i < value->spawn_point_count; ++i) {
        replay_vector(writer, value->spawn_points[i].position);
        replay_integer(writer, (uint64_t)value->spawn_points[i].preferred_type);
        replay_float(writer, value->spawn_points[i].respawn_time);
    }
}
static void replay_match(struct replay_writer *writer, const match_state_t *value)
{
    RI(rules.type); RI(rules.score_limit); RF(rules.time_limit); RF(rules.respawn_time);
    RI(rules.allow_respawn); RI(rules.lives_per_player); RI(rules.teams_enabled);
    RI(rules.team_count); RI(rules.friendly_fire); RI(rules.points_per_kill);
    RI(rules.points_per_death); RI(rules.points_per_assist); RI(rules.points_per_objective);
    RF(rules.zone_capture_time); RF(rules.zone_points_per_second);
    RF(elapsed_time); RI(match_started); RI(match_ended); RI(winning_team); RI(winning_player);
    RI(zone_controller); RF(zone_control_time); RF(zone_contest_time);
    for (int i = 0; i < 4; ++i) replay_integer(writer, (uint64_t)value->team_scores[i]);
}
static void replay_particle(struct replay_writer *writer, const particle_t *value)
{
    RI(active);
    if (!value->active) return;
    RV(position); RV(velocity); RC(color); RF(size); RF(life); RF(max_life);
    RI(has_gravity); RI(emits_light); RF(glow_radius);
}
static void replay_effects(struct replay_writer *writer, const effects_manager_t *value)
{
    RI(max_effects); RI(active_effects); RI(max_particles); RI(active_particles);
    RI(max_feedbacks); RI(active_feedbacks);
    RF(screen_shake); RF(motion_blur); RF(chromatic_aberration);
    RC(screen_flash); RF(flash_intensity); RF(time_scale);
    RI(bullet_time_active); RF(bullet_time_remaining);
    if (value->max_effects != 128 || value->max_particles != 256 ||
        value->max_feedbacks != 100 || !value->effects || !value->global_particles ||
        !value->feedbacks) { writer->valid = false; return; }
    for (int i = 0; i < value->max_effects; ++i) {
        const visual_effect_t *effect = &value->effects[i];
        replay_integer(writer, effect->active);
        if (!effect->active) continue;
        replay_integer(writer, (uint64_t)effect->type);
        replay_vector(writer, effect->position);
        replay_vector(writer, effect->scale);
        replay_float(writer, effect->duration);
        replay_float(writer, effect->elapsed);
        replay_color(writer, effect->color_start);
        replay_color(writer, effect->color_end);
        replay_float(writer, effect->intensity);
        replay_float(writer, effect->radius);
        replay_float(writer, effect->animation_speed);
        replay_integer(writer, (uint64_t)effect->frame_count);
        replay_integer(writer, (uint64_t)effect->current_frame);
        replay_integer(writer, (uint64_t)effect->particle_count);
        replay_integer(writer, effect->screen_shake);
        replay_float(writer, effect->shake_intensity);
        replay_integer(writer, effect->time_dilation);
        replay_float(writer, effect->slow_factor);
        /* Actual combat_effects.c allocates 50 particles per effect. */
        if (effect->particle_count < 0 || effect->particle_count > 50 || !effect->particles) {
            writer->valid = false;
            return;
        }
        for (int p = 0; p < effect->particle_count; ++p)
            replay_particle(writer, &effect->particles[p]);
    }
    for (int i = 0; i < value->max_particles; ++i)
        replay_particle(writer, &value->global_particles[i]);
    for (int i = 0; i < value->max_feedbacks; ++i) {
        const combat_feedback_t *feedback = &value->feedbacks[i];
        replay_vector(writer, feedback->hit_position);
        replay_float(writer, feedback->hit_timer);
        replay_integer(writer, feedback->hit_critical);
        replay_integer(writer, (uint64_t)feedback->damage_amount);
        replay_integer(writer, (uint64_t)feedback->combo_count);
        replay_float(writer, feedback->combo_timer);
        replay_float(writer, feedback->combo_multiplier);
        replay_vector(writer, feedback->score_position);
        replay_integer(writer, (uint64_t)feedback->score_value);
        replay_float(writer, feedback->score_timer);
        replay_color(writer, feedback->score_color);
    }
    /* Texture handles are renderer resources, not replay model identity. */
}
static void replay_world(struct replay_writer *writer, const cyberpunk_world_t *value)
{
    RI(element_count); RI(max_elements); RI(particle_count);
    RC(sky_gradient_top); RC(sky_gradient_bottom); RF(fog_density); RC(fog_color);
    RV(sun_direction); RC(ambient_light); RF(global_glow);
    RF(time); RF(weather_cycle); RI(is_raining_data); RI(use_instancing); RI(visible_elements);
    if (value->element_count < 0 || value->element_count > value->max_elements ||
        value->max_elements > 1000 || value->particle_count < 0 || value->particle_count > 5000) {
        writer->valid = false;
        return;
    }
    for (int i = 0; i < value->element_count; ++i) {
        const world_element_t *element = &value->elements[i];
        replay_integer(writer, (uint64_t)element->type);
        replay_vector(writer, element->position);
        replay_vector(writer, element->scale);
        replay_vector(writer, element->rotation);
        replay_float(writer, element->animation_time);
        replay_float(writer, element->pulse_speed);
        replay_float(writer, element->glow_intensity);
        replay_color(writer, element->primary_color);
        replay_color(writer, element->secondary_color);
        replay_color(writer, element->emission_color);
        replay_integer(writer, element->is_interactive);
        replay_integer(writer, element->is_hazard);
        replay_integer(writer, element->gives_powerup);
        replay_float(writer, element->effect_radius);
        replay_float(writer, element->neon_flicker);
        replay_integer(writer, element->has_trail);
        for (int j = 0; j < 10; ++j) replay_vector(writer, element->trail_positions[j]);
    }
    for (int i = 0; i < value->particle_count; ++i) {
        replay_vector(writer, value->particle_positions[i]);
        replay_vector(writer, value->particle_velocities[i]);
        replay_color(writer, value->particle_colors[i]);
    }
}
static void replay_game(struct replay_writer *writer, const struct game_agent_context *context)
{
    const multiplayer_game_t *value = context->game;
    RI(local_player_id); RF(boost_timer); RF(damage_flash);
    RF(speed_lines_intensity); RI(motion_blur_enabled);
    RF(camera_yaw); RF(camera_distance);
    RV(camera.position); RV(camera.target); RV(camera.up); RF(camera.fovy); RI(camera.projection);
    replay_integer(writer, sky_game_runtime_agent());
    replay_integer(writer, sky_game_runtime_ticks());
    replay_integer(writer, context->frames);
    replay_float(writer, context->time);
    double time = sky_game_runtime_time();
    if (time != (double)sky_game_runtime_ticks() / 60.0) writer->valid = false;
    const input_model_fast_t *input = &value->input_system->model;
    for (int i = 0; i < 8; ++i) replay_integer(writer, (uint64_t)input->raw.axes[i]);
    for (int i = 0; i < 16; ++i) replay_integer(writer, input->raw.buttons[i]);
    replay_float(writer, input->normalized.move_x);
    replay_float(writer, input->normalized.move_y);
    replay_float(writer, input->normalized.camera_x);
    replay_float(writer, input->normalized.camera_y);
    replay_float(writer, input->normalized.left_trigger);
    replay_float(writer, input->normalized.right_trigger);
    replay_integer(writer, input->actions);
    replay_integer(writer, input->connected);
    replay_integer(writer, input->is_astro_c40);
    replay_integer(writer, input->frame_count);
    replay_float(writer, input->deadzone_threshold);
    replay_float(writer, input->inv_axis_range);
    replay_float(writer, input->response_curve);
    /* Preserve the real RPRAND stream without consuming it. libc's stream
     * is compared by its next draws after each complete run. */
    for (unsigned i = 0; i < 4; ++i) replay_integer(writer, rprand_state[i]);
}
#undef RF
#undef RI
#undef RV
#undef RC

static bool replay_snapshot_take(const struct game_agent_context *context,
                                 struct replay_snapshot *snapshot)
{
    for (unsigned group = 0; group < REPLAY_GROUPS; ++group) {
        struct replay_writer writer = {.valid = true};
        zsha256_init(&writer.hash);
        const multiplayer_game_t *game = context->game;
        switch (group) {
        case 0: replay_game(&writer, context); break;
        case 1: replay_roster(&writer, game->aircraft_mgr); break;
        case 2:
            replay_weapons(&writer, game->weapons);
            for (int i = 0; i < game->aircraft_mgr->aircraft_count; ++i)
                replay_weapons(&writer, game->aircraft_mgr->aircraft[i].weapons);
            break;
        case 3: replay_pickups(&writer, game->powerup_mgr); break;
        case 4: replay_match(&writer, game->match); break;
        case 5: replay_effects(&writer, game->effects); break;
        case 6: replay_world(&writer, game->world); break;
        default: writer.valid = false; break;
        }
        if (!writer.valid) {
            fprintf(stderr, "replay: invalid state in %s at tick %u\n",
                    replay_group_names[group], context->frames);
            return false;
        }
        zsha256_final(&writer.hash, snapshot->group[group]);
    }
    return true;
}
static bool replay_snapshot_equal(const struct replay_snapshot *expected,
                                  const struct replay_snapshot *actual,
                                  unsigned tick, const char *phase)
{
    for (unsigned group = 0; group < REPLAY_GROUPS; ++group) {
        if (memcmp(expected->group[group], actual->group[group], ZSHA256_DIGEST_LEN) != 0) {
            fprintf(stderr, "replay: %s changed %s at tick %u\n",
                    phase, replay_group_names[group], tick);
            return false;
        }
    }
    return true;
}

struct replay_session {
    multiplayer_game_t game;
    struct sky_expr_option option;
    struct sky_expr_hud hud;
    struct sky_expr_notice notice;
    struct game_agent_context context;
    Vector3 initial_patrol, initial_chase;
};
struct replay_result {
    struct replay_snapshot ticks[REPLAY_TICKS + 1u];
    int next_libc[8], next_raylib[8];
};
static struct timespec replay_began;
static bool replay_within_deadline(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return false;
    return now.tv_sec - replay_began.tv_sec < 50;
}
static bool replay_setup(struct replay_session *session, uint32_t seed)
{
    memset(session, 0, sizeof(*session));
    sky_game_runtime_begin(true, seed);
    multiplayer_game_t *game = &session->game;
    game->aircraft_mgr = aircraft_manager_create();
    game->powerup_mgr = powerup_manager_create();
    game->match = match_state_create(MATCH_TYPE_TEAM_DEATHMATCH);
    game->world = cyberpunk_world_create();
    game->input_system = game_input_create(true);
    game->effects = effects_create(128, 256);
    game->weapons = weapons_create();
    if (!game_systems_ready(game) || !game->effects->white_texture.id ||
        !game->effects->effects || !game->effects->global_particles || !game->effects->feedbacks)
        return false;
    for (int i = 0; i < game->effects->max_effects; ++i)
        if (!game->effects->effects[i].particles) return false;
    game->match->rules.score_limit = 30;
    game->match->rules.time_limit = 300;
    game->match->rules.team_count = 2;
    if (!match_state_begin(game->match)) return false;
    if (aircraft_manager_add_with_team(game->aircraft_mgr, "player", RED, false, true, 0) != 0 ||
        aircraft_manager_add_with_team(game->aircraft_mgr, "chase", BLUE, true, false, 1) != 1 ||
        aircraft_manager_add_with_team(game->aircraft_mgr, "patrol", SKYBLUE, true, false, 1) != 2)
        return false;
    game->local_player_id = 0;
    managed_aircraft_t *player = &game->aircraft_mgr->aircraft[0];
    managed_aircraft_t *chase = &game->aircraft_mgr->aircraft[1];
    managed_aircraft_t *patrol = &game->aircraft_mgr->aircraft[2];
    player->aircraft->position = (Vector3){0, 200, 0};
    chase->aircraft->position = (Vector3){400, 200, 400};
    patrol->aircraft->position = (Vector3){-400, 200, -400};
    chase->target_id = 0;
    patrol->target_id = -1;
    session->initial_chase = chase->aircraft->position;
    session->initial_patrol = patrol->aircraft->position;
    aircraft_manager_damage_aircraft(game->aircraft_mgr, 0, 75.0f, -1);
    if (!(player->health > 0 && player->health < player->max_health * 0.5f) ||
        !chase->is_ai || !patrol->is_ai || chase->id % 4 != 1 || patrol->id % 4 != 2)
        return false;
    powerup_manager_add_spawn_point(game->powerup_mgr, (Vector3){800, 200, 800},
                                    POWERUP_HEALTH, 0.5f);
    powerup_manager_spawn_at_point(game->powerup_mgr, 0);
    powerup_manager_collect(game->powerup_mgr, 0);
    game->powerup_mgr->spawn_check_interval = 0.25f;
    cyberpunk_world_generate(game->world, 42);
    cyberpunk_set_theme_blade_runner(game->world);
    sky_game_runtime_reseed();
    effects_screen_shake(game->effects, 8.0f, 2.0f);
    game->camera = (Camera3D){.position = {0, 220, -35}, .target = {0, 200, 0},
                              .up = {0, 1, 0}, .fovy = 60, .projection = CAMERA_PERSPECTIVE};
    session->context = (struct game_agent_context){
        .game = game, .option = &session->option, .hud = &session->hud,
        .notice = &session->notice, .screen = {0}, .time = 0, .frames = 0
    };
    return game->effects->screen_shake > 0 && game->powerup_mgr->powerup_count == 1;
}

static bool replay_observe(struct replay_session *session, bool capture_failure)
{
    struct replay_snapshot before, after;
    if (!replay_snapshot_take(&session->context, &before)) return false;
    struct sky_agent_capture capture = {0};
    struct sky_agent_observation observation = {0};
    unsigned readbacks = replay_readbacks;
    game_agent_frame(&session->context, NULL, &observation, capture_failure ? &capture : NULL);
    bool valid = observation.frame == session->context.frames &&
                 observation.time == (double)session->context.frames / 60.0 &&
                 sky_game_runtime_ticks() == session->context.frames;
    if (capture_failure) {
        valid = valid && replay_readbacks == readbacks + 1 && capture.error &&
                strcmp(capture.error, "CAPTURE_READBACK") == 0 && !capture.png && capture.size == 0;
    }
    free(capture.png);
    return valid && replay_snapshot_take(&session->context, &after) &&
           replay_snapshot_equal(&before, &after, session->context.frames,
                                 capture_failure ? "failed capture" : "observe");
}

static bool replay_has_smoke(const effects_manager_t *effects)
{
    for (int i = 0; i < effects->max_effects; ++i) {
        const visual_effect_t *effect = &effects->effects[i];
        if (effect->active && effect->type == EFFECT_EXPLOSION && effect->radius == 0.5f &&
            effect->particle_count > 0) return true;
    }
    return false;
}
static bool replay_run(uint32_t seed, bool partitioned, bool changed_input,
                       double wall_time, const struct replay_result *expected,
                       struct replay_result *result)
{
    struct replay_session *session = calloc(1, sizeof(*session));
    if (!session) return false;
    replay_wall_time = wall_time;
    replay_wall_reads = replay_draws = replay_readbacks = replay_unexpected_window_calls = 0;
    replay_unexpected_model_calls = 0;
    bool valid = replay_setup(session, seed);
    bool smoke_seen = false, patrol_moved = false, chase_moved = false;
    unsigned failed_captures = 0;
    if (valid) valid = replay_snapshot_take(&session->context, &result->ticks[0]);
    if (valid && expected)
        valid = replay_snapshot_equal(&expected->ticks[0], &result->ticks[0], 0, "initialization");
    /* Identical inputs and one tick per call; only batching/observation differs.
     * Unequal partitions exercise boundaries at 17, 60, 91 and 120 ticks. */
    for (unsigned tick = 0; valid && tick <= REPLAY_TICKS; ++tick) {
        if (!replay_within_deadline()) { valid = false; break; }
        bool boundary = tick == 0 || tick == 17 || tick == 60 || tick == 91 || tick == REPLAY_TICKS;
        if (partitioned && boundary) {
            valid = replay_observe(session, false) && replay_observe(session, true) &&
                    replay_observe(session, false);
            ++failed_captures;
        }
        if (!valid || tick == REPLAY_TICKS) break;
        input_state_fast_t input = {
            .move_x = changed_input ? -0.35f : 0.35f,
            .move_y = tick < 60 ? -0.1f : 0.1f,
            .fire_guns = true, .speed_normal = true
        };
        struct sky_agent_observation observation = {0};
        game_agent_frame(&session->context, &input, &observation, NULL);
        replay_wall_time += partitioned ? 0.91 : 0.003;
        valid = observation.frame == tick + 1 &&
                observation.time == (double)(tick + 1) / 60.0 &&
                sky_game_runtime_ticks() == tick + 1 && observation.player_present;
        const managed_aircraft_t *chase = &session->game.aircraft_mgr->aircraft[1];
        const managed_aircraft_t *patrol = &session->game.aircraft_mgr->aircraft[2];
        if (tick == 0) {
            chase_moved = chase->target_id == 0 && chase->health > 0 &&
                Vector3Distance(chase->aircraft->position, session->initial_chase) > 0;
            patrol_moved = patrol->health > 0 &&
                Vector3Distance(patrol->aircraft->position, session->initial_patrol) > 0;
        }
        smoke_seen = smoke_seen || replay_has_smoke(session->game.effects);
        valid = valid && replay_snapshot_take(&session->context, &result->ticks[tick + 1]);
        if (valid && expected)
            valid = replay_snapshot_equal(&expected->ticks[tick + 1], &result->ticks[tick + 1],
                                          tick + 1, partitioned ? "partitioned replay" : "repeat");
    }
    valid = valid && smoke_seen && patrol_moved && chase_moved && replay_draws >= REPLAY_TICKS &&
            replay_unexpected_window_calls == 0 && replay_unexpected_model_calls == 0 &&
            replay_wall_reads == 0 &&
            (!partitioned || (failed_captures == 5 && replay_readbacks == 5));
    for (unsigned i = 0; i < 8; ++i) {
        result->next_libc[i] = rand();
        result->next_raylib[i] = GetRandomValue(-1000, 1000);
        if (expected && (result->next_libc[i] != expected->next_libc[i] ||
                         result->next_raylib[i] != expected->next_raylib[i])) valid = false;
    }
    if (!valid) fprintf(stderr,
        "replay: refused seed=%u partitioned=%d changed_input=%d tick=%u smoke=%d patrol=%d chase=%d wall_reads=%u readbacks=%u unexpected_model_calls=%u\n",
        seed, partitioned, changed_input, session->context.frames, smoke_seen,
        patrol_moved, chase_moved, replay_wall_reads, replay_readbacks,
        replay_unexpected_model_calls);
    destroy_game_systems(&session->game);
    free(session);
    return valid;
}
int main(void)
{
    if (clock_gettime(CLOCK_MONOTONIC, &replay_began) != 0) return 1;
    struct replay_result *baseline = calloc(1, sizeof(*baseline));
    struct replay_result *actual = calloc(1, sizeof(*actual));
    if (!baseline || !actual) { free(baseline); free(actual); return 1; }
    bool valid = replay_run(12345, false, false, 1000.0, NULL, baseline) &&
                 replay_run(12345, false, false, 90000.0, baseline, actual) &&
                 replay_run(12345, true, false, 500000.0, baseline, actual);
    if (valid) {
        valid = replay_run(54321, false, false, 1000.0, NULL, actual) &&
                memcmp(baseline->ticks[REPLAY_TICKS].group[1], actual->ticks[REPLAY_TICKS].group[1],
                       ZSHA256_DIGEST_LEN) != 0;
        if (!valid) fputs("replay: seed negative control did not establish changed roster\n", stderr);
    }
    if (valid) {
        valid = replay_run(12345, false, true, 1000.0, NULL, actual) &&
                memcmp(baseline->ticks[REPLAY_TICKS].group[1], actual->ticks[REPLAY_TICKS].group[1],
                       ZSHA256_DIGEST_LEN) != 0;
        if (!valid) fputs("replay: input negative control did not establish changed roster\n", stderr);
    }
    free(baseline);
    free(actual);
    if (!valid) return 1;
    puts("skycombat actual-model replay: PASS ticks=120 repeat=1 partitions=17,43,31,29 observes=10 capture_failures=5 groups=7 seed_control=changed input_control=changed smoke=observed patrol=observed chase=observed");
    return 0;
}
