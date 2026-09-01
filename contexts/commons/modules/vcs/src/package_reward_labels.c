/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_reward_labels — the placeholder-token accessor and the
 * enum-to-string / category-band lookup helpers for the ZCODE reward
 * ledger declared in vcs/package_reward.h. Split out of package_reward.c:
 * every function here is a pure, stateless presentation-layer lookup —
 * none of them touch `struct vcs_reward_ledger` or any other file-scope
 * state owned by package_reward.c, so this module shares nothing with it
 * beyond the public header. */

#include "vcs/package_reward.h"

#include "base/hex.h"
#include "vcs/package_score.h"

/* ── the placeholder token (SIMULATION ONLY) ────────────────────────── */

const uint8_t *vcs_reward_placeholder_token_id(void)
{
    /* Exactly 32 bytes: "zcode-placeholder-token-v1-sim!!". */
    static const uint8_t id[33] = VCS_REWARD_PLACEHOLDER_TOKEN_ID_TEXT;
    return id;
}

void vcs_reward_placeholder_token_id_hex(char out[65])
{
    zcl_hex_encode(vcs_reward_placeholder_token_id(), 32, out);
}

/* ── strings + bands ────────────────────────────────────────────────── */

const char *vcs_reward_category_string(enum vcs_reward_category category)
{
    size_t count = 0;
    const struct vcs_score_category_constant *table =
        vcs_score_category_table(&count);
    if ((size_t)category >= count)
        return "unknown";
    /* The enum order mirrors the frozen scoring table order. */
    return table[category].name;
}

void vcs_reward_category_band(enum vcs_reward_category category,
                              uint32_t *min_out, uint32_t *max_out,
                              bool *automatic_out)
{
    size_t count = 0;
    const struct vcs_score_category_constant *table =
        vcs_score_category_table(&count);
    if ((size_t)category >= count) {
        *min_out = 0;
        *max_out = 0;
        *automatic_out = false;
        return;
    }
    *min_out = table[category].min_points;
    *max_out = table[category].max_points;
    *automatic_out = table[category].automatic;
}

const char *vcs_reward_kind_string(enum vcs_reward_kind kind)
{
    switch (kind) {
    case VCS_REWARD_KIND_AUTO: return "auto";
    case VCS_REWARD_KIND_CLAIM: return "claim";
    }
    return "unknown";
}

const char *vcs_reward_state_string(enum vcs_reward_state state)
{
    switch (state) {
    case VCS_REWARD_STATE_QUEUED: return "queued";
    case VCS_REWARD_STATE_PLANNED: return "planned";
    case VCS_REWARD_STATE_SETTLED: return "settled";
    case VCS_REWARD_STATE_REJECTED: return "rejected";
    }
    return "unknown";
}

const char *vcs_reward_disposition_string(enum vcs_reward_disposition d)
{
    switch (d) {
    case VCS_REWARD_DISP_PLANNED: return "planned";
    case VCS_REWARD_DISP_DEFERRED: return "deferred";
    case VCS_REWARD_DISP_BLOCKED: return "blocked";
    case VCS_REWARD_DISP_DUPLICATE: return "duplicate";
    }
    return "unknown";
}

const char *vcs_reward_enqueue_error_string(
    enum vcs_reward_enqueue_error err)
{
    switch (err) {
    case VCS_REWARD_ENQUEUE_OK: return "ok";
    case VCS_REWARD_ENQUEUE_DUPLICATE: return "duplicate";
    case VCS_REWARD_ENQUEUE_BAD_CATEGORY: return "bad-category";
    case VCS_REWARD_ENQUEUE_BAND: return "points-outside-band";
    case VCS_REWARD_ENQUEUE_ZERO_POINTS: return "zero-points";
    case VCS_REWARD_ENQUEUE_EVIDENCE: return "missing-evidence-root";
    case VCS_REWARD_ENQUEUE_BAD_INPUT: return "bad-input";
    case VCS_REWARD_ENQUEUE_FULL: return "queue-full";
    case VCS_REWARD_ENQUEUE_IO: return "io-error";
    }
    return "unknown";
}

const char *vcs_reward_commit_error_string(enum vcs_reward_commit_error e)
{
    switch (e) {
    case VCS_REWARD_COMMIT_OK: return "ok";
    case VCS_REWARD_COMMIT_UNKNOWN_PLAN: return "unknown-plan";
    case VCS_REWARD_COMMIT_ALREADY_SETTLED: return "already-settled";
    case VCS_REWARD_COMMIT_STALE: return "stale-plan";
    case VCS_REWARD_COMMIT_CAPS_CHANGED: return "caps-changed";
    case VCS_REWARD_COMMIT_IO: return "io-error";
    }
    return "unknown";
}
