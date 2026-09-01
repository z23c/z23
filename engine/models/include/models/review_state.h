/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Local-only marketplace review state — the pure policy enum shared by
 * the models layer (file_offers / shop_wants rows) and the services
 * layer (market moderation). Community content moderation metadata:
 * set by the node's own curation action, never gossiped, and never
 * part of the signed wire. Kept in models so model code can validate
 * rows without an upward include into services. */

#ifndef ZCL_MODELS_REVIEW_STATE_H
#define ZCL_MODELS_REVIEW_STATE_H

#include <stdbool.h>
#include <string.h>

enum market_review_state {
    MARKET_REVIEW_UNREVIEWED = 0,   /* ingest default — never set on wire */
    MARKET_REVIEW_REVIEWED_OK = 1,
    MARKET_REVIEW_SENSITIVE = 2,
    MARKET_REVIEW_STATE_COUNT = 3
};

static inline const char *market_review_state_string(
    enum market_review_state state)
{
    switch (state) {
    case MARKET_REVIEW_UNREVIEWED: return "unreviewed";
    case MARKET_REVIEW_REVIEWED_OK: return "reviewed_ok";
    case MARKET_REVIEW_SENSITIVE: return "sensitive";
    default: return "unknown";
    }
}

/* -1 when the text is not one of the three canonical states. */
static inline int market_review_state_from_string(const char *text)
{
    if (!text) return -1; // raw-return-ok:null-parse-input-is-a-sentinel-not-an-error
    for (int i = 0; i < MARKET_REVIEW_STATE_COUNT; i++)
        if (strcmp(text, market_review_state_string(
                             (enum market_review_state)i)) == 0)
            return i;
    return -1; // raw-return-ok:unknown-state-name-is-a-sentinel-caller-logs
}

static inline bool market_review_state_valid(int state)
{
    return state >= 0 && state < MARKET_REVIEW_STATE_COUNT;
}

#endif /* ZCL_MODELS_REVIEW_STATE_H */
