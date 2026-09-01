/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * postmortem_to_scenario — postmortem-capsule -> chaos-scenario skeleton
 * bridge (Super-Reliability / Detective Node program, lane B5).
 *
 * Converts a postmortem crash capsule (engine/modules/sim/include/sim/postmortem.h,
 * an unpacked `.cap` directory: tape.bin + manifest.json + log.txt + ...)
 * into a `.scenario` skeleton for the chaos DSL (tools/sim/chaos.c,
 * docs/CHAOS_HARNESS.md "Simulation chaos engine"). This automates ONLY
 * steps 1-2 of docs/CHAOS_HARNESS.md's manual "From Capsule To Scenario"
 * workflow:
 *
 *   1. Use the capsule's recorded tape state as the scenario `seed`.
 *   2. Best-effort map of the recorded boot state (from a `[boot-stage]`
 *      trace line in log.txt, if present) to the DSL's `boot_phase`.
 *
 * Steps 3-5 — translate the recorded events into chaos commands, add the
 * assertion that would have caught the bug, and check the scenario in as
 * a permanent regression — stay MANUAL. The tool emits a `# TODO (manual
 * steps 3-5...)` block listing the recorded events in order to make that
 * manual step fast, not to skip it.
 *
 * HONEST SCOPE — read before trusting the output:
 *   A postmortem capsule records ONE node's RNG stream, simulated clock,
 *   and injected-event log (sim/seed_tape.h). A `.scenario` can describe
 *   an N-node cluster (`mode simnet`). Reconstructing a full multi-node
 *   scenario from a single-node capsule is lossy by construction — this
 *   tool produces a labeled STARTING POINT (seed fingerprint + event
 *   inventory + a parseable no-op body), not a proven reproduction.
 *
 *   The `seed 0x...` line the tool emits is the tape's "informational
 *   seed slot" (engine/modules/sim/src/seed_tape.c: seed_tape_save_to_memory), i.e.
 *   the live xoshiro256++ register `rng.s[0]` at capture time — NOT the
 *   original scalar seed passed to `seed_tape_open()`. Feeding it into a
 *   FRESH `zclassic23-chaos` run will NOT reproduce the capsule's exact
 *   RNG stream (xoshiro state isn't invertible from one register). For an
 *   EXACT deterministic replay of the captured run, load the capsule
 *   directly via `postmortem_capsule_load_tape()` /
 *   `z23 ops postmortem replay <id>`
 *   — see examples/09_seed_replay.c. The emitted `seed` line is a labeled
 *   fingerprint for manual reduction, documented as such in the output.
 *
 * Standalone-build discipline (mirrors tools/gen_sha3_windows.c): links
 * only the libs it directly uses (sim/postmortem + sim/seed_tape,
 * platform/clock + platform/rng, util/signal_handler + util/clientversion
 * + util/safe_alloc, platform/modules/json) — no DB, no node libs, no Tor.
 *
 * Test-friendly shape (mirrors tools/sim/chaos.c / test_chaos_harness.c):
 * the conversion logic lives in `postmortem_to_scenario_convert()`, a
 * plain linkable function with no globals; `main()` is a thin CLI wrapper.
 * A test can `#define POSTMORTEM_TO_SCENARIO_NO_MAIN` then
 * `#include "../../../tools/postmortem_to_scenario.c"` to call it
 * in-process against a synthetic capsule built with the real
 * `postmortem_capture_write()` API (see tests/harness/src/test_postmortem_to_scenario.c).
 */

#define _POSIX_C_SOURCE 200809L

#include "sim/postmortem.h"
#include "sim/seed_tape.h"
#include "json/json.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#if defined(_WIN32)
/* strsignal(3) has no UCRT analogue; the postmortem capsules this renders
 * carry POSIX signal numbers, so name the common ones by number. */
static const char *strsignal(int sig)
{
    switch (sig) {
    case 1:  return "Hangup";
    case 2:  return "Interrupt";
    case 4:  return "Illegal instruction";
    case 6:  return "Aborted";
    case 8:  return "Floating point exception";
    case 9:  return "Killed";
    case 11: return "Segmentation fault";
    case 13: return "Broken pipe";
    case 15: return "Terminated";
    default: return NULL;
    }
}
#endif

/* ── Bounds ──────────────────────────────────────────────────────────── */

#define P2S_MANIFEST_MAX      (64u * 1024u)  /* generous cap for a small JSON file */
#define P2S_PAYLOAD_MAX       (64u * 1024u)  /* sim/seed_tape.h documented per-event cap */
#define P2S_EVENTS_SHOWN_MAX  200u           /* bounded skeleton listing */
#define P2S_OUTPUT_BUF_CAP    (256u * 1024u) /* header + up to 200 short lines, generous */
#define P2S_REASON_MAX        256u
#define P2S_BOOT_PHASE_MAX    32u

/* ── Result / stats ──────────────────────────────────────────────────── */

struct p2s_event_row {
    uint8_t type;
    uint32_t len;
};

struct postmortem_to_scenario_stats {
    char cap_dir[512];
    char out_path[600];

    int crash_signal;
    int64_t crash_unix;
    char reason[P2S_REASON_MAX];
    size_t tape_size_bytes;
    uint64_t rng_count;
    uint64_t clock_advance_count;
    uint64_t inject_count_manifest; /* as recorded in manifest.json */
    uint64_t inject_count_walked;   /* actually observed walking the tape */

    bool seed_slot_valid;
    uint64_t seed_slot;

    bool boot_phase_derived;
    char boot_phase[P2S_BOOT_PHASE_MAX];

    size_t events_shown;
    struct p2s_event_row events[P2S_EVENTS_SHOWN_MAX];
    size_t type_hist[256];
};

/* ── Small helpers ───────────────────────────────────────────────────── */

static int p2s_errf(char *err_out, size_t err_cap, const char *fmt, ...)
{
    if (err_out && err_cap > 0) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err_out, err_cap, fmt, ap);
        va_end(ap);
    }
    return -1;
}

static void p2s_appendf(char *buf, size_t cap, size_t *off, const char *fmt, ...)
{
    if (!buf || !off || *off >= cap) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *off, cap - *off, fmt, ap);
    va_end(ap);
    if (n > 0) *off += (size_t)n;
}

/* Replace control characters with spaces so a free-text manifest field
 * (e.g. "reason") can never split a `#`-comment line the scenario parser
 * would then choke on (tools/sim/chaos.c reads line-by-line; anything
 * not starting with `#` is a command). */
static void p2s_sanitize_line(const char *in, char *out, size_t out_cap)
{
    size_t w = 0;
    if (!in) in = "";
    for (size_t r = 0; in[r] && w + 1 < out_cap; r++) {
        unsigned char c = (unsigned char)in[r];
        if (c == '\n' || c == '\r' || c == '\t') {
            out[w++] = ' ';
        } else if (c >= 0x20 && c < 0x7f) {
            out[w++] = (char)c;
        }
        /* other control / non-ASCII bytes dropped silently. */
    }
    out[w] = '\0';
}

static const char *p2s_type_label(uint8_t type)
{
    /* Reserved taxonomy from sim/seed_tape.h's seed_tape_inject() doc. */
    switch (type) {
    case 1: return "PEER_MESSAGE";
    case 2: return "BLOCK_RECEIVED";
    case 3: return "DISK_DELAY";
    case 4: return "TIMER_FIRE";
    default: return (type < 128) ? "reserved-unassigned" : "app-defined";
    }
}

/* ── Manifest (JSON) reader ──────────────────────────────────────────── */

static bool p2s_read_manifest(const char *cap_dir,
                              struct postmortem_to_scenario_stats *st)
{
    char path[560];
    int n = snprintf(path, sizeof(path), "%s/manifest.json", cap_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return false;

    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    char *buf = (char *)zcl_malloc(P2S_MANIFEST_MAX, "postmortem_to_scenario.manifest");
    if (!buf) {
        fclose(fp);
        return false;
    }
    size_t got = fread(buf, 1, P2S_MANIFEST_MAX - 1, fp);
    fclose(fp);
    buf[got] = '\0';

    struct json_value v;
    json_init(&v);
    bool ok = json_read(&v, buf, got);
    free(buf);
    if (!ok) {
        json_free(&v);
        return false;
    }

    st->crash_signal = (int)json_get_int(json_get(&v, "crash_signal"));
    st->crash_unix = json_get_int(json_get(&v, "crash_unix"));
    snprintf(st->reason, sizeof(st->reason), "%s",
             json_get_str(json_get(&v, "reason")));
    st->tape_size_bytes = (size_t)json_get_int(json_get(&v, "tape_size_bytes"));
    st->rng_count = (uint64_t)json_get_int(json_get(&v, "rng_count"));
    st->clock_advance_count =
        (uint64_t)json_get_int(json_get(&v, "clock_advance_count"));
    st->inject_count_manifest =
        (uint64_t)json_get_int(json_get(&v, "inject_count"));

    json_free(&v);
    return true;
}

/* ── Tape header seed slot (raw, read-only) ──────────────────────────── */

/* Reads the 8-byte "informational seed slot" straight out of tape.bin's
 * documented header layout (engine/modules/sim/src/seed_tape.c:
 * seed_tape_save_to_memory — TAPE_HEADER_SIZE=32, magic "ZCLTAPE!" at
 * [0..8), version at [8], flags at [9], reserved [10..16), seed slot
 * [16..24) little-endian, wall_unix_start [24..32)). There is no public
 * seed_tape_* getter for this field (seed_tape_load_from_memory discards
 * it — see the "informational only" comment at that call site), so this
 * tool reads the versioned, documented byte layout directly rather than
 * adding a new library accessor. Full magic/CRC validation of the whole
 * tape happens separately via postmortem_capsule_load_tape(). */
static int p2s_read_tape_seed_slot(const char *cap_dir, uint64_t *seed_out)
{
    char path[560];
    int n = snprintf(path, sizeof(path), "%s/tape.bin", cap_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return -ENAMETOOLONG;

    FILE *fp = fopen(path, "rb");
    if (!fp) return -errno;
    uint8_t header[32];
    size_t got = fread(header, 1, sizeof(header), fp);
    fclose(fp);
    if (got != sizeof(header)) return -EIO;
    if (memcmp(header, "ZCLTAPE!", 8) != 0) return -EINVAL;

    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t)header[16 + i] << (8 * i);
    *seed_out = v;
    return 0;
}

/* ── Boot-phase best-effort derivation ────────────────────────────────── */

/* Scans a capsule's log.txt tail for the LAST "[boot-stage] X -> Y" trace
 * line (platform/modules/util/src/boot_phase.c: boot_stage_advance_to()) and maps the
 * real `enum boot_stage` name (platform/modules/util/include/util/boot_phase.h) to the
 * chaos DSL's 3-value boot_phase (idb_complete|listening|mempool_open).
 * The two vocabularies have no 1:1 relationship — this is a coarse,
 * best-effort hint, not a verified fact. Returns false (nothing written
 * to `out`) when no trace line was found, e.g. log.txt is missing or the
 * node never reached a logged boot-stage transition before the crash. */
static bool p2s_derive_boot_phase(const char *cap_dir, char *out, size_t out_cap)
{
    char path[560];
    int n = snprintf(path, sizeof(path), "%s/log.txt", cap_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return false;

    FILE *fp = fopen(path, "rb");
    if (!fp) return false;

    char line[512];
    char last_stage[64];
    last_stage[0] = '\0';
    while (fgets(line, sizeof(line), fp)) {
        const char *tag = strstr(line, "[boot-stage] ");
        if (!tag) continue;
        const char *arrow = strstr(tag, " -> ");
        if (!arrow) continue;
        const char *stage = arrow + 4;
        size_t i = 0;
        while (stage[i] && stage[i] != ' ' && stage[i] != '\n' &&
               stage[i] != '\r' && i + 1 < sizeof(last_stage)) {
            last_stage[i] = stage[i];
            i++;
        }
        last_stage[i] = '\0';
    }
    fclose(fp);
    if (!last_stage[0]) return false;

    if (strcmp(last_stage, "network_ready") == 0 ||
        strcmp(last_stage, "services_running") == 0 ||
        strcmp(last_stage, "ready") == 0) {
        snprintf(out, out_cap, "listening");
        return true;
    }
    if (strcmp(last_stage, "shutdown_requested") == 0 ||
        strcmp(last_stage, "shutdown_complete") == 0) {
        return false; /* no meaningful DSL equivalent */
    }
    /* init / datadir_locked / crypto_ready / db_open / wallet_loaded /
     * block_index_loaded / chain_tip_resolved: pre-network stages, all
     * map to the DSL's own default. */
    snprintf(out, out_cap, "idb_complete");
    return true;
}

/* ── Event log walk (read-only) ───────────────────────────────────────── */

static void p2s_walk_events(seed_tape_t *tape,
                            struct postmortem_to_scenario_stats *st)
{
    uint8_t *payload =
        (uint8_t *)zcl_malloc(P2S_PAYLOAD_MAX, "postmortem_to_scenario.payload");
    if (!payload) return;

    for (;;) {
        uint8_t type = 0;
        size_t len = 0;
        int rc = seed_tape_next_event(tape, &type, payload, P2S_PAYLOAD_MAX, &len);
        if (rc == -ENOENT) break;
        if (rc != 0) {
            /* -ENOSPC (payload exceeds the documented 64 KiB per-event
             * cap) or any other unexpected error: stop walking rather
             * than loop on an unconsumable event. Counts gathered so
             * far remain accurate and are reported as a partial
             * inventory (see events_shown vs inject_count_walked). */
            fprintf(stderr,
                "[postmortem_to_scenario] event walk stopped early rc=%d "
                "after %" PRIu64 " event(s)\n", rc, st->inject_count_walked);
            break;
        }
        st->type_hist[type]++;
        st->inject_count_walked++;
        if (st->events_shown < P2S_EVENTS_SHOWN_MAX) {
            st->events[st->events_shown].type = type;
            st->events[st->events_shown].len = (uint32_t)len;
            st->events_shown++;
        }
    }
    free(payload);
}

/* ── Skeleton renderer ────────────────────────────────────────────────── */

static void p2s_render_skeleton(const struct postmortem_to_scenario_stats *st,
                                char *buf, size_t cap, size_t *off)
{
    char reason_safe[P2S_REASON_MAX + 32];
    p2s_sanitize_line(st->reason, reason_safe, sizeof(reason_safe));

    char sig_buf[64];
    const char *sig_name;
    if (st->crash_signal == 0) {
        sig_name = "none (manual/non-signal capture)";
    } else {
        const char *s = strsignal(st->crash_signal);
        snprintf(sig_buf, sizeof(sig_buf), "%s", s ? s : "unknown");
        sig_name = sig_buf;
    }

    p2s_appendf(buf, cap, off,
        "# Generated by tools/postmortem_to_scenario.c -- postmortem-capsule\n"
        "# to chaos-scenario skeleton bridge (Super-Reliability program,\n"
        "# lane B5). Automates steps 1-2 of docs/CHAOS_HARNESS.md's \"From\n"
        "# Capsule To Scenario\" workflow ONLY. Steps 3-5 (translate events\n"
        "# into chaos commands, add the catching assertion, check in as a\n"
        "# regression) are MANUAL -- see the TODO block below.\n"
        "#\n"
        "# HONEST SCOPE: a postmortem capsule records ONE node's RNG stream,\n"
        "# clock, and injected-event log. A .scenario can describe an\n"
        "# N-node cluster (mode simnet). Reconstructing a full multi-node\n"
        "# scenario from a single-node capsule is lossy by construction --\n"
        "# this is a labeled STARTING POINT, not a proven reproduction.\n"
        "#\n"
        "# Capsule path:    %s\n"
        "# Crash signal:    %d (%s)\n"
        "# Crash time:      %lld (unix)\n"
        "# Reason:          %s\n"
        "# Tape:            %zu bytes on disk, rng_count=%" PRIu64
        ", clock_advance_count=%" PRIu64 "\n"
        "# Injected events: manifest says %" PRIu64 ", walked %" PRIu64
        " via seed_tape_next_event (read-only)\n"
        "#\n",
        st->cap_dir, st->crash_signal, sig_name, (long long)st->crash_unix,
        reason_safe[0] ? reason_safe : "(none recorded)",
        st->tape_size_bytes, st->rng_count, st->clock_advance_count,
        st->inject_count_manifest, st->inject_count_walked);

    p2s_appendf(buf, cap, off,
        "# Informational seed slot: 0x%016" PRIx64 "\n"
        "#   This is the tape's live xoshiro256++ rng.s[0] register at\n"
        "#   capture time (engine/modules/sim/src/seed_tape.c: seed_tape_save_to_memory,\n"
        "#   \"informational seed slot\"), NOT the original scalar seed passed\n"
        "#   to seed_tape_open(). Feeding `seed 0x%016" PRIx64 "` below into a\n"
        "#   FRESH zclassic23-chaos run will NOT reproduce this capsule's\n"
        "#   exact RNG stream -- xoshiro state is not invertible from one\n"
        "#   register. It is recorded here as a labeled fingerprint / manual\n"
        "#   reduction starting point (steps 3-5), not a proven bit-identical\n"
        "#   repro. For an EXACT deterministic replay of this run, load the\n"
        "#   capsule directly via postmortem_capsule_load_tape() /\n"
        "#   `z23 ops postmortem replay <id>` -- see examples/09_seed_replay.c.\n"
        "#\n",
        st->seed_slot, st->seed_slot);

    if (st->inject_count_walked > 0) {
        p2s_appendf(buf, cap, off, "# Injected event category summary:\n");
        for (int t = 0; t < 256; t++) {
            if (st->type_hist[t] == 0) continue;
            p2s_appendf(buf, cap, off, "#   type=%-3d %-20s %zu\n",
                       t, p2s_type_label((uint8_t)t), st->type_hist[t]);
        }
        p2s_appendf(buf, cap, off, "#\n");
    }

    p2s_appendf(buf, cap, off,
        "# Boot phase: %s (%s)\n"
        "#   enum boot_stage has 12 real stages (platform/modules/util/include/util/\n"
        "#   boot_phase.h); the chaos DSL's boot_phase only distinguishes\n"
        "#   idb_complete|listening|mempool_open. This mapping is a coarse,\n"
        "#   best-effort hint from the last \"[boot-stage] X -> Y\" line in\n"
        "#   log.txt (if any) -- verify manually against BOOT_INVARIANTS.md.\n"
        "#\n",
        st->boot_phase,
        st->boot_phase_derived ? "derived from log.txt" : "UNDETECTED, defaulted");

    p2s_appendf(buf, cap, off,
        "seed        0x%016" PRIx64 "\n"
        "boot_phase  %s\n"
        "\n",
        st->seed_slot, st->boot_phase);

    p2s_appendf(buf, cap, off,
        "# TODO (manual steps 3-5, docs/CHAOS_HARNESS.md \"From Capsule To\n"
        "# Scenario\"): translate the events below into chaos commands\n"
        "# (kill_peer, random_kill_peers, send_block, send_malformed_block,\n"
        "# advance_clock, partition_network, trigger_oom_at, ...) that\n"
        "# reproduce the causal shape of the crash, in order, then replace\n"
        "# the placeholder `expect no_crash` below with the assertion that\n"
        "# would have caught the bug (usually `expect no_crash` plus a\n"
        "# specific metric -- see \"expect METRIC OP VALUE\" in\n"
        "# docs/CHAOS_HARNESS.md). The placeholder body only proves this\n"
        "# skeleton PARSES; it is NOT a regression test until this is done.\n"
        "#\n");

    if (st->inject_count_walked == 0) {
        p2s_appendf(buf, cap, off,
            "# No injected events were recorded on this tape (rng draws\n"
            "# and/or clock advances only -- see the counts above).\n");
    } else {
        p2s_appendf(buf, cap, off,
            "# Recorded event log (%" PRIu64 " total, showing first %zu):\n",
            st->inject_count_walked, st->events_shown);
        for (size_t i = 0; i < st->events_shown; i++) {
            p2s_appendf(buf, cap, off,
                "#   [%04zu] type=%-3u %-20s len=%u\n",
                i, (unsigned)st->events[i].type,
                p2s_type_label(st->events[i].type), st->events[i].len);
        }
        if (st->inject_count_walked > (uint64_t)st->events_shown) {
            p2s_appendf(buf, cap, off,
                "#   ... %" PRIu64 " more event(s) not shown (see the "
                "category summary above and tape.bin for the full log)\n",
                st->inject_count_walked - (uint64_t)st->events_shown);
        }
    }

    p2s_appendf(buf, cap, off,
        "\n"
        "expect      no_crash\n");
}

/* ── Public entry point ───────────────────────────────────────────────── */

int postmortem_to_scenario_convert(const char *cap_dir_in, const char *out_path_in,
                                   struct postmortem_to_scenario_stats *stats_out,
                                   char *err_out, size_t err_cap)
{
    struct postmortem_to_scenario_stats local_stats;
    struct postmortem_to_scenario_stats *st = stats_out ? stats_out : &local_stats;
    memset(st, 0, sizeof(*st));

    if (!cap_dir_in || !*cap_dir_in)
        return p2s_errf(err_out, err_cap, "capsule path is required");

    struct stat cst;
    if (stat(cap_dir_in, &cst) != 0) {
        return p2s_errf(err_out, err_cap, "cannot stat capsule path '%s': %s",
                        cap_dir_in, strerror(errno));
    }
    if (!S_ISDIR(cst.st_mode)) {
        return p2s_errf(err_out, err_cap,
            "'%s' is not a directory -- this tool converts an UNPACKED "
            ".cap directory (tape.bin + manifest.json). A compressed "
            ".cap.gz capsule must be inspected via "
            "postmortem_capsule_load_tape() directly (see "
            "docs/examples/09_seed_replay.c) -- decompression is out of scope "
            "for this tool.", cap_dir_in);
    }
    snprintf(st->cap_dir, sizeof(st->cap_dir), "%s", cap_dir_in);

    if (!p2s_read_manifest(cap_dir_in, st)) {
        return p2s_errf(err_out, err_cap,
            "failed to read/parse %s/manifest.json", cap_dir_in);
    }

    int rc = p2s_read_tape_seed_slot(cap_dir_in, &st->seed_slot);
    if (rc != 0) {
        return p2s_errf(err_out, err_cap,
            "failed to read tape.bin header in '%s': %s (is this a valid "
            "unpacked postmortem capsule?)", cap_dir_in, strerror(-rc));
    }
    st->seed_slot_valid = true;

    seed_tape_t *tape = postmortem_capsule_load_tape(cap_dir_in);
    if (tape) {
        p2s_walk_events(tape, st);
        seed_tape_close(tape);
    } else {
        fprintf(stderr,
            "[postmortem_to_scenario] WARNING: could not load %s/tape.bin "
            "for the full event walk (magic/CRC validation failed) -- the "
            "skeleton will have a seed but no event inventory\n", cap_dir_in);
    }

    st->boot_phase_derived =
        p2s_derive_boot_phase(cap_dir_in, st->boot_phase, sizeof(st->boot_phase));
    if (!st->boot_phase_derived)
        snprintf(st->boot_phase, sizeof(st->boot_phase), "idb_complete");

    if (out_path_in && *out_path_in) {
        snprintf(st->out_path, sizeof(st->out_path), "%s", out_path_in);
    } else {
        snprintf(st->out_path, sizeof(st->out_path),
                 "tools/sim/scenarios/repro_%016" PRIx64 ".scenario",
                 st->seed_slot);
    }

    char *text = (char *)zcl_malloc(P2S_OUTPUT_BUF_CAP,
                                    "postmortem_to_scenario.output");
    if (!text)
        return p2s_errf(err_out, err_cap, "out of memory building skeleton");
    size_t off = 0;
    p2s_render_skeleton(st, text, P2S_OUTPUT_BUF_CAP, &off);

    FILE *fp = fopen(st->out_path, "wb");
    if (!fp) {
        int e = errno;
        free(text);
        return p2s_errf(err_out, err_cap,
            "failed to open output '%s' for write: %s",
            st->out_path, strerror(e));
    }
    size_t wrote = fwrite(text, 1, off, fp);
    int close_rc = fclose(fp);
    free(text);
    if (wrote != off || close_rc != 0) {
        return p2s_errf(err_out, err_cap,
            "short write or close failure on '%s'", st->out_path);
    }

    return 0;
}

/* ── CLI ───────────────────────────────────────────────────────────────
 *
 * Compiled out when this file is #include-d into a test with
 * POSTMORTEM_TO_SCENARIO_NO_MAIN defined first (mirrors CHAOS_NO_MAIN in
 * tools/sim/chaos.c / tests/harness/src/test_chaos_harness.c). */
#ifndef POSTMORTEM_TO_SCENARIO_NO_MAIN

static void p2s_usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s --cap=DIR [--out=PATH]\n\n"
        "  Converts a postmortem crash capsule (an UNPACKED .cap directory)\n"
        "  into a .scenario skeleton for zclassic23-chaos. Automates ONLY\n"
        "  the seed + best-effort boot-phase steps of docs/CHAOS_HARNESS.md's\n"
        "  \"From Capsule To Scenario\" workflow -- translating the recorded\n"
        "  events into chaos commands and adding the catching assertion stays\n"
        "  manual; the tool leaves a TODO block listing the events in order.\n\n"
        "  Default --out: tools/sim/scenarios/repro_<seed_hex>.scenario\n",
        argv0);
}

int main(int argc, char **argv)
{
    const char *cap_dir = NULL;
    const char *out_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--cap=", 6) == 0) {
            cap_dir = argv[i] + 6;
        } else if (strncmp(argv[i], "--out=", 6) == 0) {
            out_path = argv[i] + 6;
        } else {
            p2s_usage(argv[0]);
            return 2;
        }
    }
    if (!cap_dir || !*cap_dir) {
        p2s_usage(argv[0]);
        return 2;
    }

    struct postmortem_to_scenario_stats st;
    char err[512];
    err[0] = '\0';
    int rc = postmortem_to_scenario_convert(cap_dir, out_path, &st, err, sizeof(err));
    if (rc != 0) {
        fprintf(stderr, "postmortem_to_scenario: FAILED: %s\n", err);
        return 1;
    }

    printf("postmortem_to_scenario: wrote %s\n", st.out_path);
    printf("  capsule:       %s\n", st.cap_dir);
    printf("  crash_signal:  %d\n", st.crash_signal);
    printf("  crash_unix:    %lld\n", (long long)st.crash_unix);
    printf("  reason:        %s\n", st.reason);
    printf("  seed slot:     0x%016" PRIx64
           " (informational -- see the NOTE in the generated file)\n",
           st.seed_slot);
    printf("  events walked: %" PRIu64 " (showing %zu in the skeleton)\n",
           st.inject_count_walked, st.events_shown);
    printf("  boot_phase:    %s (%s)\n", st.boot_phase,
           st.boot_phase_derived ? "derived from log.txt" : "default, undetected");
    printf("  MANUAL STEPS REMAINING: translate the events into chaos "
           "commands and add the assertion that would have caught the bug "
           "(docs/CHAOS_HARNESS.md \"From Capsule To Scenario\", steps 3-5) "
           "before checking this in as a regression.\n");
    return 0;
}

#endif /* POSTMORTEM_TO_SCENARIO_NO_MAIN */
