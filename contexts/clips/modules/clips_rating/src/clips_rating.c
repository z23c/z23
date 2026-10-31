/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Clips content-rating viewer and serve decisions over plain evidence structs. */

#include "clips_rating/clips_rating.h"

#include <string.h>

static bool clips_level_valid(uint8_t level)
{
    return level >= CLIPS_LEVEL_GENERAL && level <= CLIPS_LEVEL_MAX;
}

static uint8_t clips_rating_effective(const struct clips_rating_input *in)
{
    uint8_t effective = in->declared_level;

    if (in->text_level > effective)
        effective = in->text_level;
    for (size_t i = 0; i < in->rater_count; i++) {
        if (in->rater_levels[i] > effective)
            effective = in->rater_levels[i];
    }
    return effective;
}

static bool clips_rating_rater_rated(const struct clips_rating_input *in)
{
    for (size_t i = 0; i < in->rater_count; i++) {
        if (clips_level_valid(in->rater_levels[i]))
            return true;
    }
    return false;
}

static enum clips_evidence clips_rating_evidence(const struct clips_rating_input *in)
{
    if (clips_rating_rater_rated(in))
        return CLIPS_EVIDENCE_RATER;
    if (in->accepted_author)
        return CLIPS_EVIDENCE_AUTHOR;
    if (in->is_comment && in->text_level != 0)
        return CLIPS_EVIDENCE_TEXT;
    return CLIPS_EVIDENCE_NONE;
}

static void clips_rating_settings(const struct clips_rating_input *in,
                                  uint8_t *viewer, bool *show_unrated)
{
    if (!clips_level_valid(in->viewer_level)) {
        *viewer = CLIPS_LEVEL_GENERAL;
        *show_unrated = false;
        return;
    }
    *viewer = in->viewer_level;
    *show_unrated = in->show_unrated;
}

/* The ordered rows of spec 6.6. The first row that applies decides. */
static void clips_rating_rows(const struct clips_rating_input *in,
                              uint8_t viewer, bool show_unrated,
                              struct clips_rating_decision *out)
{
    if ((in->is_reshare || in->is_comment) && !in->target_shown) {
        out->target_hidden = true;
        return;
    }
    if (in->illegal_match)
        return;
    if (in->owner_blocked)
        return;
    if (in->own_key) {
        out->own = true;
        out->shown = true;
        return;
    }
    if (in->owner_allowed) {
        out->owner_allowed = true;
        out->shown = true;
        return;
    }
    if (in->on_block_list) {
        out->blocked_by_list = true;
        return;
    }
    if (in->report_held) {
        out->reported = true;
        return;
    }
    if (out->effective_level > viewer) {
        out->rating_above_level = true;
        return;
    }
    if (out->evidence == CLIPS_EVIDENCE_NONE && !show_unrated) {
        out->rating_unverified = true;
        return;
    }
    out->shown = true;
}

bool clips_rating_decide(const struct clips_rating_input *in,
                         struct clips_rating_decision *out)
{
    uint8_t viewer = CLIPS_LEVEL_GENERAL;
    bool show_unrated = false;

    if (!in || !out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!clips_level_valid(in->declared_level) || in->rater_count > CLIPS_RATER_MAX)
        return false;
    out->effective_level = clips_rating_effective(in);
    out->evidence = clips_rating_evidence(in);
    show_unrated = in->show_unrated;
    clips_rating_settings(in, &viewer, &show_unrated);
    clips_rating_rows(in, viewer, show_unrated, out);
    return true;
}

bool clips_rating_decide_serve(const struct clips_rating_input *in, uint8_t serve_level,
                               struct clips_rating_decision *out)
{
    uint8_t serve = serve_level;

    if (!in || !out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!clips_level_valid(in->declared_level) || in->rater_count > CLIPS_RATER_MAX)
        return false;
    if (!clips_level_valid(serve))
        serve = CLIPS_LEVEL_GENERAL;
    out->effective_level = clips_rating_effective(in);
    out->evidence = clips_rating_evidence(in);
    if (in->illegal_match)
        return true;
    if (in->owner_blocked)
        return true;
    if (in->on_block_list) {
        out->blocked_by_list = true;
        return true;
    }
    if (out->effective_level > serve) {
        out->rating_above_level = true;
        return true;
    }
    out->shown = true;
    return true;
}
