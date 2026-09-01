/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_compile_render — see rom_compile_render.h. Pure string formatting over
 * an already-parsed zcl.rom_compile.v1 body; no I/O. */

#include "command/rom_compile_render.h"

#include "json/json.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Append without ever advancing past the last writable byte (mirrors
 * native_command.c's nc_text_append; kept local — one tiny helper, no new
 * cross-TU coupling for a single caller). */
static void rcr_append(char *out, size_t cap, size_t *len, const char *fmt,
                       ...)
{
    if (!out || cap == 0 || !len || *len >= cap)
        return;
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(out + *len, cap - *len, fmt, args);
    va_end(args);
    if (n < 0)
        return;
    size_t available = cap - *len;
    if ((size_t)n >= available) {
        *len = cap - 1;
        return;
    }
    *len += (size_t)n;
}

#define RCR_BAR_WIDTH 30U
#define RCR_STAGE_BAR_WIDTH 24U

static void rcr_bar(char *out, size_t cap, double frac, unsigned width)
{
    if (frac < 0.0) frac = 0.0;
    if (frac > 1.0) frac = 1.0;
    unsigned filled = (unsigned)(frac * (double)width + 0.5);
    if (filled > width) filled = width;
    size_t w = 0;
    if (w < cap) out[w++] = '[';
    for (unsigned i = 0; i < width && w < cap; i++)
        out[w++] = (i < filled) ? '#' : '.';
    if (w < cap) out[w++] = ']';
    if (w >= cap) w = cap - 1;
    out[w] = '\0';
}

static void rcr_progress_bar(const struct json_value *fold, char *out,
                             size_t cap, size_t *len)
{
    double percent = json_get_real(json_get(fold, "percent"));
    bool active = json_get_bool(json_get(fold, "active"));
    const char *mode = json_get_str(json_get(fold, "mode"));
    int64_t height = json_get_int(json_get(fold, "height"));
    int64_t target = json_get_int(json_get(fold, "target"));
    double rate = json_get_real(json_get(fold, "rate_blk_s"));
    const char *eta = json_get_str(json_get(fold, "eta_human"));

    char bar[RCR_BAR_WIDTH + 3];
    rcr_bar(bar, sizeof(bar), percent / 100.0, RCR_BAR_WIDTH);
    rcr_append(out, cap, len, "ROM compile %s  %6.2f%%\n", bar, percent);
    rcr_append(out, cap, len, "  mode=%s height=%lld target=%lld\n",
              mode && mode[0] ? mode : "idle", (long long)height,
              (long long)target);
    if (active) {
        rcr_append(out, cap, len, "  rate=%.1f blk/s eta=%s\n", rate,
                  eta && eta[0] ? eta : "unknown");
    } else {
        rcr_append(out, cap, len,
                  "  no fold active — ROM already compiled at/above the "
                  "anchor on this node\n");
    }
}

static void rcr_stage_bars(const struct json_value *state, char *out,
                           size_t cap, size_t *len)
{
    const struct json_value *stages = json_get(state, "stages");
    const char *bottleneck = json_get_str(json_get(state, "bottleneck_stage"));
    if (!stages || stages->type != JSON_ARR)
        return;

    int64_t max_us = 1;
    for (size_t i = 0; i < stages->num_children; i++) {
        int64_t v = json_get_int(json_get(json_at(stages, i), "step_us_ewma"));
        if (v > max_us) max_us = v;
    }

    rcr_append(out, cap, len, "stage step_us_ewma (bottleneck marked *):\n");
    for (size_t i = 0; i < stages->num_children; i++) {
        const struct json_value *s = json_at(stages, i);
        const char *abbrev = json_get_str(json_get(s, "abbrev"));
        int64_t us = json_get_int(json_get(s, "step_us_ewma"));
        bool slow = abbrev && bottleneck && strcmp(abbrev, bottleneck) == 0;

        char bar[RCR_STAGE_BAR_WIDTH + 3];
        rcr_bar(bar, sizeof(bar), (double)us / (double)max_us,
               RCR_STAGE_BAR_WIDTH);
        rcr_append(out, cap, len, "  %-2s %s %7lldus%s\n",
                  abbrev ? abbrev : "??", bar, (long long)us,
                  slow ? " *" : "");
    }
}

static void rcr_ladder_row(char *out, size_t cap, size_t *len,
                           const char *label, bool present,
                           const char *detail)
{
    rcr_append(out, cap, len, "  [%c] %-24s %s\n", present ? '#' : ' ', label,
              detail ? detail : "");
}

static void rcr_layer_ladder(const struct json_value *state, char *out,
                             size_t cap, size_t *len)
{
    const struct json_value *layers = json_get(state, "layers");
    rcr_append(out, cap, len, "layer ladder (genesis -> tip):\n");
    if (!layers || layers->type != JSON_OBJ)
        return;

    {
        const struct json_value *l = json_get(layers, "rom_checkpoint");
        char detail[64];
        snprintf(detail, sizeof(detail), "h=%lld sha3=%s",
                (long long)json_get_int(json_get(l, "height")),
                json_get_str(json_get(l, "sha3_prefix"))
                    ? json_get_str(json_get(l, "sha3_prefix")) : "");
        rcr_ladder_row(out, cap, len, "ROM checkpoint",
                      json_get_bool(json_get(l, "present")), detail);
    }
    {
        const struct json_value *l = json_get(layers, "sealed_history");
        char detail[96];
        snprintf(detail, sizeof(detail), "segments=%lld present=%lld range=%lld-%lld",
                (long long)json_get_int(json_get(l, "segment_count")),
                (long long)json_get_int(json_get(l, "present_count")),
                (long long)json_get_int(json_get(l, "min_height")),
                (long long)json_get_int(json_get(l, "max_height")));
        rcr_ladder_row(out, cap, len, "Sealed history",
                      json_get_bool(json_get(l, "present")), detail);
    }
    {
        const struct json_value *l = json_get(layers, "sealed_base_receipt");
        char detail[64];
        bool present = json_get_bool(json_get(l, "present"));
        if (present)
            snprintf(detail, sizeof(detail), "ratified_height=%lld",
                    (long long)json_get_int(json_get(l, "ratified_height")));
        else
            snprintf(detail, sizeof(detail), "no ratified seal yet");
        rcr_ladder_row(out, cap, len, "Sealed base+receipt", present, detail);
    }
    {
        const struct json_value *l = json_get(layers, "delta");
        char detail[48];
        snprintf(detail, sizeof(detail), "coins_best=%lld",
                (long long)json_get_int(json_get(l, "coins_best_height")));
        rcr_ladder_row(out, cap, len, "Delta frontier",
                      json_get_bool(json_get(l, "present")), detail);
    }
    {
        const struct json_value *l = json_get(layers, "tip_ring");
        char detail[64];
        snprintf(detail, sizeof(detail), "hstar=%lld external_tip=%lld",
                (long long)json_get_int(json_get(l, "hstar")),
                (long long)json_get_int(json_get(l, "external_tip_height")));
        rcr_ladder_row(out, cap, len, "Tip ring",
                      json_get_bool(json_get(l, "present")), detail);
    }
}

/* The ROM pipeline as first-class rows: fold -> seal -> manifest -> bundle
 * export. This is the compile-and-publish spine (fold the chain, seal the
 * bodies, verify the manifest, export a re-servable bundle), rendered above the
 * raw layer ladder so the operator reads the pipeline stages at a glance. Reads
 * the SAME fold / layers.sealed_history / layers.bundle_export the ladder reads;
 * no second data path. A missing bundle_export renders 'absent' gracefully. */
static void rcr_rom_pipeline(const struct json_value *state, char *out,
                             size_t cap, size_t *len)
{
    const struct json_value *fold = json_get(state, "fold");
    const struct json_value *layers = json_get(state, "layers");
    const struct json_value *seal = layers ? json_get(layers, "sealed_history")
                                           : NULL;
    const struct json_value *bx = layers ? json_get(layers, "bundle_export")
                                         : NULL;

    rcr_append(out, cap, len,
              "ROM pipeline (fold -> seal -> manifest -> bundle):\n");

    {
        int64_t height = fold ? json_get_int(json_get(fold, "height")) : 0;
        int64_t target = fold ? json_get_int(json_get(fold, "target")) : 0;
        double percent = fold ? json_get_real(json_get(fold, "percent")) : 0.0;
        char detail[64];
        snprintf(detail, sizeof(detail), "height=%lld/%lld (%.2f%%)",
                (long long)height, (long long)target, percent);
        rcr_ladder_row(out, cap, len, "fold", height > 0, detail);
    }
    {
        bool present = seal && json_get_bool(json_get(seal, "present"));
        int64_t sealed = seal ? json_get_int(json_get(seal, "present_count"))
                              : 0;
        int64_t total = seal ? json_get_int(json_get(seal, "segment_count"))
                             : 0;
        char detail[64];
        snprintf(detail, sizeof(detail), "%lld/%lld segments sealed",
                (long long)sealed, (long long)total);
        rcr_ladder_row(out, cap, len, "seal", present, detail);
    }
    {
        int64_t verified = seal ? json_get_int(json_get(seal, "verified_count"))
                               : 0;
        int64_t total = seal ? json_get_int(json_get(seal, "segment_count"))
                             : 0;
        char detail[64];
        snprintf(detail, sizeof(detail), "verified=%lld/%lld",
                (long long)verified, (long long)total);
        rcr_ladder_row(out, cap, len, "manifest", verified > 0, detail);
    }
    {
        bool present = bx && json_get_bool(json_get(bx, "present"));
        char detail[80];
        if (present)
            snprintf(detail, sizeof(detail), "last_height=%lld generations=%lld",
                    (long long)json_get_int(json_get(bx, "last_height")),
                    (long long)json_get_int(json_get(bx, "generations")));
        else if (bx && json_get_str(json_get(bx, "note")))
            snprintf(detail, sizeof(detail), "absent (%s)",
                    json_get_str(json_get(bx, "note")));
        else
            snprintf(detail, sizeof(detail), "absent");
        rcr_ladder_row(out, cap, len, "bundle export", present, detail);
    }
}

/* shielded_import section (engine/jobs/src/rom_compile_status.c): makes the
 * -import-complete-shielded import -> resume transition visible in the
 * human ops.rom view, not just the JSON. A healthy node (no gap on either
 * pool) gets one compact line; a node still behind an anchor or nullifier
 * backfill gap gets the per-pool cursor/blocker/imported-count detail so an
 * operator can see the cure land without a log-grep. */
static void rcr_shielded_import(const struct json_value *state, char *out,
                                size_t cap, size_t *len)
{
    const struct json_value *si = json_get(state, "shielded_import");
    if (!si || si->type != JSON_OBJ)
        return;

    const char *status = json_get_str(json_get(si, "status"));
    int64_t next_h = json_get_int(json_get(si, "utxo_apply_next_height"));
    rcr_append(out, cap, len,
              "shielded history: %s (utxo_apply resumes from height=%lld)\n",
              status && status[0] ? status : "unknown", (long long)next_h);

    const struct json_value *anchor = json_get(si, "anchor");
    const struct json_value *nf = json_get(si, "nullifier");
    bool anchor_gap = anchor && json_get_bool(json_get(anchor, "gap"));
    bool nf_gap = nf && json_get_bool(json_get(nf, "gap"));
    if (!anchor_gap && !nf_gap)
        return;  /* healthy node: the one-line status above is enough */

    if (anchor) {
        rcr_append(out, cap, len,
                  "  anchor:    sprout_cursor=%lld sapling_cursor=%lld "
                  "gap_blocker=%s imported(sprout=%lld sapling=%lld)\n",
                  (long long)json_get_int(
                      json_get(anchor, "sprout_activation_cursor")),
                  (long long)json_get_int(
                      json_get(anchor, "sapling_activation_cursor")),
                  json_get_bool(json_get(anchor, "gap_blocker_active"))
                      ? "active" : "clear",
                  (long long)json_get_int(
                      json_get(anchor, "sprout_anchors_imported")),
                  (long long)json_get_int(
                      json_get(anchor, "sapling_anchors_imported")));
    }
    if (nf) {
        rcr_append(out, cap, len,
                  "  nullifier: activation_cursor=%lld gap_blocker=%s "
                  "imported(sprout=%lld sapling=%lld)\n",
                  (long long)json_get_int(
                      json_get(nf, "activation_cursor")),
                  json_get_bool(json_get(nf, "gap_blocker_active"))
                      ? "active" : "clear",
                  (long long)json_get_int(
                      json_get(nf, "sprout_nullifiers_imported")),
                  (long long)json_get_int(
                      json_get(nf, "sapling_nullifiers_imported")));
    }
}

void rom_compile_render_ascii(const struct json_value *state, char *out,
                              size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = '\0';
    if (!state || state->type != JSON_OBJ) {
        snprintf(out, cap, "rom_compile: no state body\n");
        return;
    }

    size_t len = 0;
    const struct json_value *fold = json_get(state, "fold");
    if (fold && fold->type == JSON_OBJ)
        rcr_progress_bar(fold, out, cap, &len);
    else
        rcr_append(out, cap, &len, "ROM compile — no fold section\n");
    rcr_stage_bars(state, out, cap, &len);
    rcr_rom_pipeline(state, out, cap, &len);
    rcr_layer_ladder(state, out, cap, &len);
    rcr_shielded_import(state, out, cap, &len);
}
