/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood release ballot window. */

#include "services/research_window.h"

#include "chain/chainparams.h"
#include "json/json.h"
#include "services/miner_signal_catalog_pin.h"
#include "services/miner_signal_round.h"

#include <stdio.h>
#include <string.h>

static const char window_path[] =
    "tests/fixtures/ironwood/selected-manifest.json";

static int window_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_window: %s\n", cond);
        return 1;
    }
    return 0;
}

static void window_sentinel(struct research_window *w)
{
    w->start = -1;
    w->window = -1;
    w->votes = -1;
    w->slot0_activation = -1;
    w->slot1_activation = -1;
}

static int window_untouched(const struct research_window *w)
{
    return w->start == -1 && w->window == -1 && w->votes == -1 &&
           w->slot0_activation == -1 && w->slot1_activation == -1;
}

static int refuse_null(void)
{
    struct zcl_result r = research_window_read(window_path, NULL);

    return window_check("null window refused",
                        !r.ok && strcmp(r.message, "Missing window") == 0);
}

static int refuse_path(void)
{
    struct research_window w;
    struct zcl_result r;

    window_sentinel(&w);
    r = research_window_read(NULL, &w);
    if (window_check("null path refused",
                     !r.ok && strcmp(r.message, "Missing window path") == 0 &&
                     window_untouched(&w)))
        return 1;
    r = research_window_read("", &w);
    if (window_check("empty path refused",
                     !r.ok && strcmp(r.message, "Missing window path") == 0 &&
                     window_untouched(&w)))
        return 1;
    r = research_window_read("tests/fixtures/ironwood/not-a-window.json", &w);
    if (window_check("missing file refused",
                     !r.ok &&
                     strcmp(r.message, "Window manifest unreadable") == 0 &&
                     window_untouched(&w)))
        return 1;
    r = research_window_read("tests/fixtures/ironwood", &w);
    return window_check("directory refused",
                        !r.ok &&
                        strcmp(r.message, "Window manifest unreadable") == 0 &&
                        window_untouched(&w));
}

static int read_fixture(unsigned char *buf, size_t cap, size_t *out_n)
{
    FILE *f;
    size_t n;

    f = fopen(window_path, "rb");
    if (!f)
        return 0;
    n = fread(buf, 1, cap, f);
    if (ferror(f) != 0) {
        fclose(f);
        return 0;
    }
    if (fclose(f) != 0 || n == 0 || n == cap)
        return 0;
    *out_n = n;
    return 1;
}

static int manifest_four(struct json_value *manifest, const char *raw, size_t n)
{
    if (!json_read(manifest, raw, n) || manifest->type != JSON_ARR ||
        json_size(manifest) != 4) {
        json_free(manifest);
        return 0;
    }
    return 1;
}

static int window_fields_match(const struct research_window *w,
                               const struct miner_signal_schedule *first,
                               const struct miner_signal_schedule *second)
{
    return w->start == first->start && w->window == first->window &&
           w->slot0_activation == first->activation &&
           w->slot1_activation == second->activation &&
           w->votes == miner_signal_required_votes(first->window);
}

static int matches_loader(const struct chain_research_descriptor *d,
                          const struct research_window *w)
{
    unsigned char buf[512];
    struct json_value manifest = {0};
    struct miner_signal_catalog_pin pin = {0};
    struct miner_signal_schedule first;
    struct miner_signal_schedule second;
    size_t n = 0;
    int ok;

    if (!d || !d->chain)
        return 0;
    if (!read_fixture(buf, sizeof buf, &n))
        return 0;
    if (!manifest_four(&manifest, (const char *)buf, n))
        return 0;
    ok = miner_signal_catalog_pin_parse(json_at(&manifest, 0),
                                        json_at(&manifest, 1),
                                        json_at(&manifest, 2),
                                        json_at(&manifest, 3),
                                        d->chain->consensus.hashGenesisBlock.data,
                                        &pin).ok &&
         miner_signal_catalog_pin_select(&pin, 0, &first).ok &&
         miner_signal_catalog_pin_select(&pin, 1, &second).ok;
    json_free(&manifest);
    if (!ok)
        return 0;
    return window_fields_match(w, &first, &second);
}

static int read_published(const struct chain_research_descriptor *d)
{
    struct research_window w;
    int end;

    window_sentinel(&w);
    if (window_check("window read ok", research_window_read(window_path, &w).ok))
        return 1;
    end = w.start + w.window - 1;
    printf("release_start=%d\n", (int)w.start);
    printf("release_window=%d\n", (int)w.window);
    printf("release_end=%d\n", end);
    printf("release_votes=%d\n", (int)w.votes);
    printf("release_slot0=%d\n", (int)w.slot0_activation);
    printf("release_slot1=%d\n", (int)w.slot1_activation);
    if (window_check("window matches loader", matches_loader(d, &w)))
        return 1;
    if (window_check("window published",
                     w.start == 121 && w.window == 20 && end == 140 &&
                     w.votes == 19 && w.slot0_activation == 143 &&
                     w.slot1_activation == 144))
        return 1;
    return 0;
}

int test_research_window(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *d;
    const struct chain_research_descriptor *current;

    main = chain_params_get();
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    current = chain_research_profile_current();
    if (window_check("lookup starts unselected",
                     main && d && d->chain && !current))
        return 1;
    if (refuse_null() || refuse_path() || read_published(d))
        return 1;
    if (window_check("read does not select",
                     chain_params_get() == main &&
                     !chain_research_profile_current()))
        return 1;
    printf("research_window: ironwood release window pinned\n");
    return 0;
}
