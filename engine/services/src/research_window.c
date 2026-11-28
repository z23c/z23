/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood release ballot window. */

#include "services/research_window.h"

#include "chain/chainparams.h"
#include "json/json.h"
#include "services/miner_signal_catalog_pin.h"
#include "services/miner_signal_round.h"

#include <stdio.h>
#include <string.h>

#define WINDOW_MANIFEST_MAX 4096u

static struct zcl_result read_bytes(const char *path, unsigned char *buf,
                                    size_t cap, size_t *out_n)
{
    FILE *f;
    size_t n;

    f = fopen(path, "rb");
    if (!f)
        return ZCL_ERR(-4, "Window manifest unreadable");
    n = fread(buf, 1, cap, f);
    if (ferror(f) != 0) {
        fclose(f);
        return ZCL_ERR(-5, "Window manifest unreadable");
    }
    if (fclose(f) != 0)
        return ZCL_ERR(-5, "Window manifest unreadable");
    if (n == 0)
        return ZCL_ERR(-6, "Window manifest empty");
    if (n == cap)
        return ZCL_ERR(-7, "Window manifest too large");
    *out_n = n;
    return ZCL_OK;
}

static struct zcl_result schedules(const struct miner_signal_catalog_pin *pin,
                                   struct research_window *out)
{
    struct miner_signal_schedule first;
    struct miner_signal_schedule second;
    struct zcl_result r;

    r = miner_signal_catalog_pin_select(pin, 0, &first);
    if (!r.ok)
        return r;
    r = miner_signal_catalog_pin_select(pin, 1, &second);
    if (!r.ok)
        return r;
    if (first.start != second.start || first.window != second.window)
        return ZCL_ERR(-8, "Window slots disagree");
    out->start = first.start;
    out->window = first.window;
    out->votes = miner_signal_required_votes(first.window);
    out->slot0_activation = first.activation;
    out->slot1_activation = second.activation;
    return ZCL_OK;
}

static struct zcl_result window_from_bytes(const unsigned char *bytes, size_t n,
                                           const uint8_t genesis[32],
                                           struct research_window *out)
{
    struct json_value manifest = {0};
    struct miner_signal_catalog_pin pin = {0};
    struct research_window got;
    struct zcl_result r;

    if (!json_read(&manifest, (const char *)bytes, n) ||
        manifest.type != JSON_ARR || json_size(&manifest) != 4) {
        json_free(&manifest);
        return ZCL_ERR(-9, "Window manifest refused");
    }
    r = miner_signal_catalog_pin_parse(json_at(&manifest, 0),
                                       json_at(&manifest, 1),
                                       json_at(&manifest, 2),
                                       json_at(&manifest, 3),
                                       genesis, &pin);
    json_free(&manifest);
    if (!r.ok)
        return r;
    r = schedules(&pin, &got);
    if (!r.ok)
        return r;
    *out = got;
    return ZCL_OK;
}

struct zcl_result research_window_read(const char *path,
                                       struct research_window *out)
{
    const struct chain_research_descriptor *d;
    unsigned char buf[WINDOW_MANIFEST_MAX];
    struct research_window got;
    struct zcl_result r;
    size_t n = 0;

    if (!out)
        return ZCL_ERR(-1, "Missing window");
    if (!path || path[0] == '\0')
        return ZCL_ERR(-2, "Missing window path");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->chain)
        return ZCL_ERR(-3, "Research window missing");
    r = read_bytes(path, buf, sizeof buf, &n);
    if (!r.ok)
        return r;
    r = window_from_bytes(buf, n, d->chain->consensus.hashGenesisBlock.data,
                          &got);
    if (!r.ok)
        return r;
    *out = got;
    return ZCL_OK;
}
