/* purpose: Load a digest-bound, owned miner ballot catalog. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/miner_signal_catalog_pin.h"
#include "base/hex.h"
#include "json/json.h"
#include "util/safe_alloc.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 256 entries of two typed fields fit comfortably within this bound. */
#define BALLOT_MANIFEST_MAX_BYTES 32768u
#define BALLOT_WINDOW_MAX 256

static bool pin_int(const struct json_value *v, int32_t max, int32_t *out)
{
    if (!v || v->type != JSON_INT) return false;
    int64_t n = json_get_int(v);
    if (n < 1 || n > max) return false;
    *out = (int32_t)n;
    return true;
}

static struct zcl_result pin_entry(const struct json_value *v,
                                    struct miner_signal_catalog_entry *out)
{
    if (!v || v->type != JSON_ARR || json_size(v) != 2)
        return ZCL_ERR(-1, "Catalog rule must contain revision and activation");
    const struct json_value *revision = json_at(v, 0);
    if (!revision || revision->type != JSON_STR ||
        !zcl_hex_decode(json_get_str(revision), out->rule_revision, 32))
        return ZCL_ERR(-2, "Invalid catalog rule revision");
    if (!pin_int(json_at(v, 1), INT32_MAX, &out->activation))
        return ZCL_ERR(-3, "Invalid catalog activation height");
    return ZCL_OK;
}

static struct miner_signal_catalog pin_catalog(const struct miner_signal_catalog_pin *pin)
{
    struct miner_signal_catalog c = {
        .start = pin->start, .window = pin->window,
        .count = pin->count, .entries = pin->entries,
    };
    memcpy(c.network_id, pin->network_id, 32);
    memcpy(c.genesis, pin->genesis, 32);
    return c;
}

struct zcl_result miner_signal_catalog_pin_parse(
    const struct json_value *fork, const struct json_value *start,
    const struct json_value *window, const struct json_value *rules,
    const uint8_t genesis[32], struct miner_signal_catalog_pin *out)
{
    if (!out || !genesis) return ZCL_ERR(-4, "Missing catalog output or genesis");
    struct miner_signal_catalog_pin next = {0};
    if (!fork || fork->type != JSON_STR ||
        !zcl_hex_decode(json_get_str(fork), next.network_id, 32))
        return ZCL_ERR(-5, "Invalid catalog fork identity");
    if (!pin_int(start, INT32_MAX, &next.start) ||
        !pin_int(window, BALLOT_WINDOW_MAX, &next.window))
        return ZCL_ERR(-6, "Invalid catalog window");
    if (!rules || rules->type != JSON_ARR || !json_size(rules) || json_size(rules) > 256)
        return ZCL_ERR(-7, "Catalog must have 1..256 rules");
    next.count = json_size(rules);
    memcpy(next.genesis, genesis, 32);
    for (size_t i = 0; i < next.count; ++i) {
        struct zcl_result r = pin_entry(json_at(rules, i), &next.entries[i]);
        if (!r.ok) return r;
    }
    struct miner_signal_catalog catalog = pin_catalog(&next);
    struct miner_signal_schedule schedule = {0};
    struct zcl_result r = miner_signal_catalog_select(&catalog, 0, &schedule);
    if (!r.ok) return r;
    memcpy(next.digest, schedule.catalog, 32);
    *out = next;
    return ZCL_OK;
}

struct zcl_result miner_signal_catalog_pin_select(
    const struct miner_signal_catalog_pin *pin, size_t slot,
    struct miner_signal_schedule *out)
{
    if (!pin || !out) return ZCL_ERR(-8, "Missing catalog pin or schedule output");
    struct miner_signal_catalog catalog = pin_catalog(pin);
    struct miner_signal_schedule selected = {0};
    struct zcl_result r = miner_signal_catalog_select(&catalog, slot, &selected);
    if (!r.ok) return r;
    if (memcmp(selected.catalog, pin->digest, 32))
        return ZCL_ERR(-9, "Catalog pin contents do not match its digest");
    *out = selected;
    return ZCL_OK;
}

static struct zcl_result pin_read(const char *path, char **out, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return ZCL_ERR(-10, "Cannot open ballot catalog file");
    char *buf = zcl_malloc(BALLOT_MANIFEST_MAX_BYTES + 1u, "ballot catalog file");
    if (!buf) { fclose(f); return ZCL_ERR(-11, "Cannot allocate ballot catalog buffer"); }
    size_t n = fread(buf, 1, BALLOT_MANIFEST_MAX_BYTES + 1u, f);
    bool failed = ferror(f) != 0;
    if (fclose(f) != 0) failed = true;
    if (failed || n > BALLOT_MANIFEST_MAX_BYTES) {
        free(buf);
        return ZCL_ERR(-12, "Ballot catalog read failed or exceeds size limit");
    }
    *out = buf;
    *out_len = n;
    return ZCL_OK;
}

struct zcl_result miner_signal_catalog_pin_load(
    const char *datadir, const char *digest_hex, const uint8_t genesis[32],
    struct miner_signal_catalog_pin *out)
{
    uint8_t expected[32];
    if (!datadir || !datadir[0] || !genesis || !out ||
        !zcl_hex_decode_lower(digest_hex, expected, sizeof(expected)))
        return ZCL_ERR(-13, "Invalid datadir, genesis, or lowercase catalog digest");
    char path[4096];
    int len = snprintf(path, sizeof(path), "%s/ballots/%s.json", datadir, digest_hex);
    if (len < 0 || (size_t)len >= sizeof(path)) return ZCL_ERR(-14, "Ballot catalog path too long");
    char *bytes = NULL; size_t size = 0;
    struct zcl_result r = pin_read(path, &bytes, &size);
    if (!r.ok) return r;
    struct json_value manifest = {0};
    bool valid = json_read(&manifest, bytes, size);
    free(bytes);
    if (!valid || manifest.type != JSON_ARR || json_size(&manifest) != 4) {
        json_free(&manifest);
        return ZCL_ERR(-15, "Invalid ballot catalog manifest JSON");
    }
    struct miner_signal_catalog_pin next = {0};
    r = miner_signal_catalog_pin_parse(json_at(&manifest, 0), json_at(&manifest, 1),
                                       json_at(&manifest, 2), json_at(&manifest, 3),
                                       genesis, &next);
    json_free(&manifest);
    if (!r.ok) return r;
    if (memcmp(expected, next.digest, 32)) return ZCL_ERR(-16, "Ballot catalog digest mismatch");
    *out = next;
    return ZCL_OK;
}
