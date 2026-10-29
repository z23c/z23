/* arena_present — bridge a zdogfight replay stream into the native C23
 * presentation system (M6).
 *
 * Reads one canonical replay file (as written by arena_runner:
 * "ZDOGREPL" magic, u32 LE version, u64 LE seed, u8 planes_per_team,
 * 7-byte ctl frames for every plane in index order for every tick,
 * then the trailing 2163-byte canonical final state), RE-SIMULATES the
 * match from the seed and the recorded controls, and refuses to present
 * anything whose recomputed final state differs from the trailing
 * state block (named mismatch, exit 1).
 *
 * The narrative (kill events) is derived from deterministic alive->dead
 * transitions during the re-simulation, never from a separate event
 * log, so the presentation can never diverge from the authoritative
 * replay.
 *
 * Output: one bounded renderer-neutral model document
 * (ZCL_PRESENT_MODEL_TIMELINE) encoded with zcl_present_model_encode_v1
 * — inert text, exact-root label, one CLOSE action, no callbacks, no
 * paths, no handles. The existing presentation host renders it; pixels
 * never feed back into match state.
 *
 * Defensive rules: every allocation checked, every error logged with
 * context, bounded everything.
 *
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "presentation/model.h"
#include "sha3/sha3.h"
#include "zdogfight/zdogfight.h"

#define AP_LOG "arena_present"
#define AP_MAX_TICKS (ZDOG_TICK_LIMIT + 1u)

struct ap_replay {
    uint64_t seed;
    unsigned ppt;
    unsigned np;
    size_t frame;
    size_t ticks;
    const uint8_t *body;
    const uint8_t *tail;
};

struct ap_sim {
    zdog_match m;
    struct zcl_present_model_v1 model;
    uint32_t kills_recorded;
    uint32_t kills_total;
    uint8_t state[ZDOG_STATE_WIRE_MAX];
    uint8_t root_bin[32];
    char root_hex[65];
};

static int ap_fail(const char *what)
{
    fprintf(stderr, "%s: %s\n", AP_LOG, what);
    return 1;
}

static const char *ap_parse_args(int argc, char **argv,
                                 const char **replay_path,
                                 const char **out_path)
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--replay") == 0 && i + 1 < argc)
            *replay_path = argv[++i];
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)
            *out_path = argv[++i];
        else
            return "usage: arena_present --replay <file> "
                   "[--out <model-wire-file>]";
    }
    return NULL;
}

static const char *ap_read_replay_file(const char *replay_path,
                                       uint8_t **out_buf, size_t *out_len)
{
    /* Bounded read: header + 36000*8*7 ctl + 2163 state < 2.1 MiB. */
    static const size_t cap =
        8 + 4 + 8 + 1 + (size_t)AP_MAX_TICKS *ZDOG_MAX_PLANES *
                            ZDOG_CTL_WIRE_LEN +
        ZDOG_STATE_WIRE_MAX;
    FILE *f = fopen(replay_path, "rb");
    if (!f)
        return "cannot open replay file";
    uint8_t *buf = zcl_malloc(cap, "arena_present.replay");
    if (!buf) {
        fclose(f);
        return "cannot allocate the bounded replay buffer";
    }
    size_t len = fread(buf, 1, cap, f);
    int read_err = ferror(f);
    int too_big = !feof(f);
    fclose(f);
    if (read_err) {
        free(buf);
        return "cannot read replay file";
    }
    if (too_big) {
        free(buf);
        return "replay exceeds its bounded maximum size";
    }
    *out_buf = buf;
    *out_len = len;
    return NULL;
}

static const char *ap_parse_replay(const uint8_t *buf, size_t len,
                                   struct ap_replay *r)
{
    const size_t hdr = 8 + 4 + 8 + 1;
    if (len < hdr + ZDOG_STATE_WIRE_MAX ||
        memcmp(buf, "ZDOGREPL", 8) != 0)
        return "MISMATCH replay-magic: not a zdogfight replay";
    if (zcl_read_u32_le(buf + 8) != 1)
        return "MISMATCH replay-version: unsupported version";
    r->seed = zcl_read_u64_le(buf + 12);
    unsigned ppt = buf[20];
    if (ppt < 1 || ppt > 4)
        return "MISMATCH replay-header: planes-per-team out of range";
    r->ppt = ppt;
    r->np = 2 * ppt;
    r->frame = (size_t)r->np * ZDOG_CTL_WIRE_LEN;
    size_t body = len - hdr - ZDOG_STATE_WIRE_MAX;
    if (body % r->frame != 0)
        return "MISMATCH replay-body: truncated control frame";
    r->ticks = body / r->frame;
    if (r->ticks > ZDOG_TICK_LIMIT)
        return "MISMATCH replay-body: more ticks than the rules allow";
    r->body = buf + hdr;
    r->tail = buf + hdr + body;
    return NULL;
}

static const char *ap_decode_tick_ctls(const uint8_t *fp, unsigned np,
                                       zdog_ctl *ctls)
{
    for (unsigned i = 0; i < np; i++) {
        if (!zdog_ctl_decode(fp + i * ZDOG_CTL_WIRE_LEN,
                             ZDOG_CTL_WIRE_LEN, &ctls[i]))
            return "MISMATCH replay-body: undecodable control";
    }
    for (unsigned i = np; i < ZDOG_MAX_PLANES; i++)
        ctls[i] = (zdog_ctl){0, 0, 0, 0};
    return NULL;
}

static void ap_add_kill_event(struct ap_sim *s, unsigned i)
{
    struct zcl_present_model_item_v1 *it =
        &s->model.items[s->model.item_count++];
    memset(it, 0, sizeof(*it));
    it->kind = ZCL_PRESENT_ITEM_TIMELINE_EVENT;
    it->status = ZCL_PRESENT_STATUS_INFO;
    it->parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    (void)snprintf(it->label, sizeof(it->label),
                   "tick %llu", (unsigned long long)s->m.tick);
    (void)snprintf(it->value, sizeof(it->value),
                   "%s plane %u down (score %u-%u)",
                   s->m.planes[i].team == 0 ? "red" : "blue", i,
                   s->m.score[0], s->m.score[1]);
}

static void ap_record_tick_kills(struct ap_sim *s, uint8_t *alive_before,
                                 unsigned np)
{
    for (unsigned i = 0; i < np; i++) {
        if (alive_before[i] && !s->m.planes[i].alive) {
            s->kills_total++;
            if (s->kills_recorded < ZCL_PRESENT_MODEL_ITEMS_MAX - 1u) {
                ap_add_kill_event(s, i);
                s->kills_recorded++;
            }
        }
        alive_before[i] = s->m.planes[i].alive;
    }
}

static const char *ap_simulate_replay(const struct ap_replay *r,
                                      struct ap_sim *s)
{
    /* Re-simulate, deriving the kill narrative from alive->dead
     * transitions. */
    zdog_match_init(&s->m, r->seed, r->ppt);
    zdog_ctl *ctls = zcl_malloc(sizeof(*ctls) * ZDOG_MAX_PLANES,
                                "arena_present.ctls");
    if (!ctls)
        return "cannot allocate the control frame";
    zcl_present_model_init_v1(&s->model, ZCL_PRESENT_MODEL_TIMELINE);
    (void)snprintf(s->model.request_id, sizeof(s->model.request_id),
                   "arena-replay");
    (void)snprintf(s->model.title, sizeof(s->model.title), "zdogfight match");
    s->kills_recorded = 0;
    s->kills_total = 0;

    uint8_t alive_before[ZDOG_MAX_PLANES];
    for (unsigned i = 0; i < r->np; i++)
        alive_before[i] = s->m.planes[i].alive;
    for (size_t t = 0; t < r->ticks; t++) {
        const char *err = ap_decode_tick_ctls(r->body + t * r->frame,
                                              r->np, ctls);
        if (err) {
            free(ctls);
            return err;
        }
        zdog_tick(&s->m, ctls);
        ap_record_tick_kills(s, alive_before, r->np);
    }
    free(ctls);
    return NULL;
}

static const char *ap_check_final_state(struct ap_sim *s, const uint8_t *tail)
{
    size_t state_len = zdog_state_encode(&s->m, s->state, sizeof(s->state));
    if (state_len != ZDOG_STATE_WIRE_MAX ||
        memcmp(s->state, tail, ZDOG_STATE_WIRE_MAX) != 0)
        return "MISMATCH final-state: replay does not re-simulate "
               "to its trailing state";
    if (s->m.phase != ZDOG_PHASE_DONE)
        return "MISMATCH match-incomplete: replay ends before the "
               "match is done";
    zcl_sha3_256(s->state, sizeof(s->state), s->root_bin);
    zcl_hex_encode(s->root_bin, 32, s->root_hex);
    return NULL;
}

static const char *ap_winner_name(const zdog_match *m)
{
    return m->winner == ZDOG_WINNER_RED    ? "red"
           : m->winner == ZDOG_WINNER_BLUE ? "blue"
                                           : "draw";
}

static void ap_add_elided_item(struct ap_sim *s)
{
    if (s->kills_total > s->kills_recorded) {
        struct zcl_present_model_item_v1 *it =
            &s->model.items[s->model.item_count++];
        memset(it, 0, sizeof(*it));
        it->kind = ZCL_PRESENT_ITEM_TEXT;
        it->status = ZCL_PRESENT_STATUS_NEUTRAL;
        it->parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
        (void)snprintf(it->label, sizeof(it->label), "…");
        (void)snprintf(it->value, sizeof(it->value),
                       "%u further events elided (bounded model)",
                       s->kills_total - s->kills_recorded);
    }
}

static void ap_finish_model(struct ap_sim *s)
{
    (void)snprintf(s->model.summary, sizeof(s->model.summary),
                   "winner %s — score %u-%u in %llu ticks",
                   ap_winner_name(&s->m), s->m.score[0], s->m.score[1],
                   (unsigned long long)s->m.tick);
    (void)snprintf(s->model.exact_root, sizeof(s->model.exact_root),
                   "%s", s->root_hex);
    s->model.actions[0].kind = ZCL_PRESENT_ACTION_CLOSE;
    (void)snprintf(s->model.actions[0].id, sizeof(s->model.actions[0].id),
                   "close");
    (void)snprintf(s->model.actions[0].label,
                   sizeof(s->model.actions[0].label), "Close");
    s->model.action_count = 1;
}

static const char *ap_write_model(const char *out_path, const uint8_t *wire,
                                  size_t wire_len)
{
    FILE *of = stdout;
    if (out_path) {
        of = fopen(out_path, "wb");
        if (!of)
            return "cannot open the model output file";
    }
    size_t put = fwrite(wire, 1, wire_len, of);
    if (out_path)
        fclose(of);
    if (put != wire_len)
        return "cannot write the model wire";
    return NULL;
}

int main(int argc, char **argv)
{
    const char *replay_path = NULL;
    const char *out_path = NULL;
    const char *err = ap_parse_args(argc, argv, &replay_path, &out_path);
    if (err)
        return ap_fail(err);
    if (!replay_path)
        return ap_fail("--replay is required");

    uint8_t *buf = NULL;
    size_t len = 0;
    err = ap_read_replay_file(replay_path, &buf, &len);
    if (err)
        return ap_fail(err);
    struct ap_replay r;
    err = ap_parse_replay(buf, len, &r);
    if (err) {
        free(buf);
        return ap_fail(err);
    }

    struct ap_sim sim;
    err = ap_simulate_replay(&r, &sim);
    if (err) {
        free(buf);
        return ap_fail(err);
    }

    /* The bridge is a verifier first: refuse any replay whose trailing
     * state is not exactly the re-simulated final state. */
    err = ap_check_final_state(&sim, r.tail);
    if (err) {
        free(buf);
        return ap_fail(err);
    }
    ap_add_elided_item(&sim);
    ap_finish_model(&sim);

    char merr[160];
    if (!zcl_present_model_validate_v1(&sim.model, merr, sizeof(merr))) {
        free(buf);
        fprintf(stderr, "%s: model invalid: %s\n", AP_LOG, merr);
        return 1;
    }
    uint8_t *wire = zcl_malloc(ZCL_PRESENT_MODEL_WIRE_MAX,
                               "arena_present.wire");
    if (!wire) {
        free(buf);
        return ap_fail("cannot allocate the model wire buffer");
    }
    size_t wire_len = 0;
    if (!zcl_present_model_encode_v1(&sim.model, wire,
                                     ZCL_PRESENT_MODEL_WIRE_MAX,
                                     &wire_len, merr, sizeof(merr))) {
        free(wire);
        free(buf);
        fprintf(stderr, "%s: model encode failed: %s\n", AP_LOG, merr);
        return 1;
    }
    err = ap_write_model(out_path, wire, wire_len);
    free(wire);
    free(buf);
    if (err)
        return ap_fail(err);
    fprintf(stderr, "%s: events=%u winner=%s score=%u-%u ticks=%llu "
                    "final_state_root=%s wire_bytes=%zu\n",
            AP_LOG, sim.kills_total, ap_winner_name(&sim.m),
            sim.m.score[0], sim.m.score[1],
            (unsigned long long)sim.m.tick, sim.root_hex, wire_len);
    return 0;
}
