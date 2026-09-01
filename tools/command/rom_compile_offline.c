/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_compile_offline — see rom_compile_offline.h. Pure read-only composition
 * over three on-disk seams of an offline producer datadir; no writes, no node,
 * no RPC. */

#include "command/rom_compile_offline.h"

#include "config/consensus_state_producer_receipt.h"
#include "storage/chain_segment.h"
#include "chain/checkpoints.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Pipeline order + abbreviations shared with the live dumper and the
 * mint-progress.log writer (engine/composition/src/boot_mint_anchor_log.c). */
static const char *const k_off_abbrev[8] = {
    "ha", "vh", "bf", "bp", "sv", "pv", "ua", "tf" };
static const char *const k_off_name[8] = {
    "header_admit", "validate_headers", "body_fetch",  "body_persist",
    "script_validate", "proof_validate", "utxo_apply", "tip_finalize" };

static void off_eta_human(int64_t eta_s, char *out, size_t cap)
{
    if (eta_s < 0) {
        (void)snprintf(out, cap, "unknown");
        return;
    }
    (void)snprintf(out, cap, "%lldh%02lldm%02llds",
                   (long long)(eta_s / 3600), (long long)((eta_s % 3600) / 60),
                   (long long)(eta_s % 60));
}

/* A finalized receipt is the completion authority; else fall back to the live
 * stage cursors. Mirrors nc_producer_applied_height in native_command.c so the
 * offline height matches `ops producer status` on the same datadir. */
static int64_t off_applied_height(const struct producer_status_read *st)
{
    if (st->receipt_finalized)
        return st->fold_cursor > 0 ? st->fold_cursor - 1 : -1;
    if (st->utxo_apply_cursor > 0)
        return st->utxo_apply_cursor - 1;
    if (st->utxo_apply_cursor == 0)
        return -1;
    return st->tip_finalize_cursor;
}

/* Read the last non-empty line of `path` into `buf` (best-effort tail: seek to
 * the last cap-1 bytes and keep the final line). Returns false when the file is
 * absent / unreadable / empty — the caller then zeroes the stage EWMAs. */
static bool off_read_last_line(const char *path, char *buf, size_t cap)
{
    if (cap == 0)
        return false;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return false;
    }
    long sz = ftell(f);
    if (sz <= 0) {
        fclose(f);
        return false;
    }
    long want = sz > (long)(cap - 1) ? (long)(cap - 1) : sz;
    if (fseek(f, sz - want, SEEK_SET) != 0) {
        fclose(f);
        return false;
    }
    size_t got = fread(buf, 1, (size_t)want, f);
    fclose(f);
    buf[got] = '\0';
    while (got > 0 && (buf[got - 1] == '\n' || buf[got - 1] == '\r'))
        buf[--got] = '\0';
    char *nl = strrchr(buf, '\n');
    if (nl)
        memmove(buf, nl + 1, strlen(nl + 1) + 1);
    return buf[0] != '\0';
}

/* Find "<ab>:<int>us" in `region` and return the integer, or -1 if absent. */
static int64_t off_parse_stage(const char *region, const char *ab)
{
    char tok[8];
    (void)snprintf(tok, sizeof(tok), "%s:", ab);
    const char *p = strstr(region, tok);
    if (!p)
        return -1;
    p += strlen(tok);
    return (int64_t)strtoll(p, NULL, 10);
}

/* Parse the eight stage EWMAs and the batch-commit EWMA from one progress line.
 * Restricts stage parsing to the `stages=[...]` bracket so tokens like `slow=`
 * or `pvla=` never bleed into a stage value. Absent/malformed => all zero. */
static void off_parse_stages(const char *line, int64_t ewma[8],
                             int64_t *commit_us)
{
    for (int i = 0; i < 8; i++)
        ewma[i] = 0;
    *commit_us = 0;
    if (!line || !line[0])
        return;

    const char *br = strstr(line, "stages=[");
    if (br) {
        const char *end = strchr(br, ']');
        char region[256];
        size_t rlen = end ? (size_t)(end - br) : strlen(br);
        if (rlen >= sizeof(region))
            rlen = sizeof(region) - 1;
        memcpy(region, br, rlen);
        region[rlen] = '\0';
        for (int i = 0; i < 8; i++) {
            int64_t v = off_parse_stage(region, k_off_abbrev[i]);
            ewma[i] = v > 0 ? v : 0;
        }
    }
    const char *cm = strstr(line, "cm:");
    if (cm) {
        int64_t v = (int64_t)strtoll(cm + 3, NULL, 10);
        *commit_us = v > 0 ? v : 0;
    }
}

/* fold{} section from the producer status read + compiled checkpoint. */
static void off_push_fold(struct json_value *out,
                          const struct producer_status_read *st)
{
    int64_t height = off_applied_height(st);
    if (height < 0)
        height = 0;

    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    int64_t target = cp ? (int64_t)cp->height : 0;

    double percent = 0.0;
    if (target > 0) {
        percent = 100.0 * (double)height / (double)target;
        if (percent < 0.0) percent = 0.0;
        if (percent > 100.0) percent = 100.0;
    }
    int64_t remaining = target > height ? target - height : 0;

    double rate_blk_s = 0.0;
    if (st->durable_rate_available && st->rate_blocks_per_second_milli > 0)
        rate_blk_s = (double)st->rate_blocks_per_second_milli / 1000.0;
    int64_t eta_s = (rate_blk_s > 0.0 && remaining > 0)
                        ? (int64_t)((double)remaining / rate_blk_s)
                        : -1;
    char eta_str[32];
    off_eta_human(eta_s, eta_str, sizeof(eta_str));

    bool active = st->session_open && !st->receipt_finalized && remaining > 0;
    const char *mode = st->receipt_finalized ? "idle"
                     : st->session_open      ? "producing"
                                             : "idle";

    struct json_value fold;
    json_init(&fold);
    json_set_object(&fold);
    json_push_kv_bool(&fold, "active", active);
    json_push_kv_str(&fold, "mode", mode);
    json_push_kv_int(&fold, "height", height);
    json_push_kv_int(&fold, "target", target);
    json_push_kv_real(&fold, "percent", percent);
    json_push_kv_int(&fold, "remaining_blocks", remaining);
    json_push_kv_real(&fold, "rate_blk_s", rate_blk_s);
    json_push_kv_int(&fold, "eta_seconds", eta_s);
    json_push_kv_str(&fold, "eta_human", eta_str);
    json_push_kv(out, "fold", &fold);
    json_free(&fold);
}

/* stages[] + bottleneck_stage + commit_us_ewma from the mint-progress.log
 * tail. Bottleneck is the max-EWMA stage (self-consistent with the bar chart),
 * defaulting to "ha" when every EWMA is zero (absent log). */
static void off_push_stages(struct json_value *out, const char *datadir)
{
    char logpath[1200];
    (void)snprintf(logpath, sizeof(logpath), "%s/mint-progress.log", datadir);
    char line[512];
    bool have = off_read_last_line(logpath, line, sizeof(line));

    int64_t ewma[8];
    int64_t commit_us = 0;
    off_parse_stages(have ? line : NULL, ewma, &commit_us);

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    size_t slow = 0;
    int64_t slow_ewma = -1;
    for (size_t i = 0; i < 8; i++) {
        if (ewma[i] > slow_ewma) {
            slow_ewma = ewma[i];
            slow = i;
        }
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        json_push_kv_str(&item, "abbrev", k_off_abbrev[i]);
        json_push_kv_str(&item, "stage", k_off_name[i]);
        json_push_kv_int(&item, "cursor", 0);
        json_push_kv_int(&item, "step_us_ewma", ewma[i]);
        json_push_kv_int(&item, "steps_per_sec",
                         ewma[i] > 0
                             ? (int64_t)(1000000.0 / (double)ewma[i] + 0.5)
                             : 0);
        json_push_back(&arr, &item);
        json_free(&item);
    }
    json_push_kv(out, "stages", &arr);
    json_free(&arr);

    json_push_kv_str(out, "bottleneck_stage", k_off_abbrev[slow]);
    json_push_kv_int(out, "commit_us_ewma", commit_us);
}

/* One node-only layer: absent/false with a note the renderer can surface. */
static void off_push_absent_layer(struct json_value *layers, const char *key,
                                  const char *note)
{
    struct json_value l;
    json_init(&l);
    json_set_object(&l);
    json_push_kv_bool(&l, "present", false);
    json_push_kv_str(&l, "note", note);
    json_push_kv(layers, key, &l);
    json_free(&l);
}

static void off_push_layers(struct json_value *out, const char *datadir)
{
    struct json_value layers;
    json_init(&layers);
    json_set_object(&layers);

    /* ROM checkpoint — compiled into the binary, so present even offline. */
    {
        struct json_value l;
        json_init(&l);
        json_set_object(&l);
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        json_push_kv_bool(&l, "present", cp != NULL);
        json_push_kv_int(&l, "height", cp ? (int64_t)cp->height : 0);
        char prefix[9] = {0};
        if (cp) {
            size_t w = 0;
            for (size_t i = 0; i < 4 && w + 2 < sizeof(prefix); i++)
                w += (size_t)snprintf(prefix + w, sizeof(prefix) - w, "%02x",
                                      cp->sha3_hash[i]);
        }
        json_push_kv_str(&l, "sha3_prefix", prefix);
        json_push_kv(&layers, "rom_checkpoint", &l);
        json_free(&l);
    }

    /* Sealed history — read the foreign <datadir>/segments store directly. */
    {
        char dir[1200];
        (void)snprintf(dir, sizeof(dir), "%s/segments", datadir);
        struct chain_segment_stat stt;
        memset(&stt, 0, sizeof(stt));
        char why[256];
        enum cseg_status s =
            chain_segment_store_stat(dir, false, &stt, why, sizeof(why));
        bool ok = (s == CSEG_OK);

        struct json_value l;
        json_init(&l);
        json_set_object(&l);
        json_push_kv_bool(&l, "present", ok && stt.segment_count > 0);
        json_push_kv_int(&l, "segment_count", ok ? stt.segment_count : 0);
        json_push_kv_int(&l, "present_count", ok ? stt.verified_count : 0);
        json_push_kv_int(&l, "verified_count", ok ? stt.verified_count : 0);
        json_push_kv_int(&l, "min_height",
                         ok && stt.have_range ? (int64_t)stt.min_height : -1);
        json_push_kv_int(&l, "max_height",
                         ok && stt.have_range ? (int64_t)stt.max_height : -1);
        json_push_kv(&layers, "sealed_history", &l);
        json_free(&l);
    }

    off_push_absent_layer(&layers, "sealed_base_receipt",
                          "offline: state-seal ring needs the running reducer");
    off_push_absent_layer(&layers, "delta",
                          "offline: coins-applied frontier needs the reducer");
    off_push_absent_layer(&layers, "tip_ring",
                          "offline: provable tip needs the running node");
    off_push_absent_layer(&layers, "bundle_export",
                          "offline: exporter state needs the running node");

    json_push_kv(out, "layers", &layers);
    json_free(&layers);
}

bool rom_compile_offline_compose(const char *datadir, struct json_value *out,
                                 char *err, size_t errlen)
{
    if (!out) {
        if (err && errlen)
            (void)snprintf(err, errlen, "rom offline: null out");
        LOG_FAIL("rom_offline", "null out");
    }
    if (!datadir || !datadir[0]) {
        if (err && errlen)
            (void)snprintf(err, errlen, "rom offline: empty datadir");
        LOG_FAIL("rom_offline", "empty datadir");
    }
    if (strlen(datadir) >= 1024) {
        if (err && errlen)
            (void)snprintf(err, errlen, "rom offline: datadir too long");
        LOG_FAIL("rom_offline", "datadir too long: %zu", strlen(datadir));
    }

    struct producer_status_read st;
    char why[256];
    why[0] = '\0';
    if (!consensus_state_producer_status_read(datadir, &st, why, sizeof(why))) {
        if (err && errlen)
            (void)snprintf(err, errlen, "%s",
                           why[0] ? why : "producer status unreadable");
        LOG_FAIL("rom_offline", "producer status unreadable: %s",
                 why[0] ? why : "?");
    }

    json_set_object(out);
    json_push_kv_str(out, "schema", "zcl.rom_compile.v1");
    json_push_kv_int(out, "captured_at", (int64_t)platform_time_wall_unix());
    off_push_fold(out, &st);
    off_push_stages(out, datadir);
    off_push_layers(out, datadir);
    return true;
}
