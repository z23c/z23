/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_policy — the ZCODE local P2P ratio + anti-spam policy (slice 11).
 * Pure decision functions over explicit facts; see the header for the
 * owner-directive rules. No wall-clock, no filesystem, no network. */

#include "vcs/package_policy.h"

#include "base/log_macros.h"

#define POLICY_LOG "vcs.policy"

/* ── tiers ──────────────────────────────────────────────────────────── */

static const char *const k_tier_names[VCS_POLICY_TIER_COUNT] = { /* hotswap-static-ok: read-only enum-name tables */
    "new-user",
    "earned-contributor",
    "verified-seeder",
};

const char *vcs_policy_tier_string(enum vcs_policy_tier tier)
{
    if (tier < 0 || tier >= VCS_POLICY_TIER_COUNT)
        return "unknown";
    return k_tier_names[tier];
}

/* The frozen policy table. The new-user row IS the free allowance: a
 * zero-score user can always download public packages and publish once
 * per week — and announce a bounded unique-root serving set (the
 * NEW_USER inventory bound), otherwise a free publish would be
 * undeliverable over the swarm. */
static const struct vcs_policy_limits
    k_limits[VCS_POLICY_TIER_COUNT] = {
    /* NEW_USER */
    {
        VCS_POLICY_FREE_PUBLISH_PER_WEEK,      /* publish_per_week */
        VCS_POLICY_FREE_WEEKLY_DOWNLOAD_BYTES, /* weekly_download_bytes */
        1u,                                    /* max_concurrent_downloads */
        0u,                                    /* queue_priority */
        0u,                                    /* pin_allowance_bytes */
        VCS_POLICY_FREE_ANNOUNCE_PER_HOUR,     /* announces_per_hour */
        VCS_POLICY_FREE_REQUEST_BURST_PER_WINDOW,
                                                /* request_burst_per_window */
    },
    /* EARNED_CONTRIBUTOR */
    {
        4u,                                        /* publish_per_week */
        UINT64_C(4) * 1024u * 1024u * 1024u,       /* weekly download: 4 GiB */
        4u,                                        /* concurrent downloads */
        1u,                                        /* queue_priority */
        UINT64_C(256) * 1024u * 1024u,             /* pin allowance: 256 MiB */
        VCS_POLICY_FREE_ANNOUNCE_PER_HOUR,         /* announces_per_hour */
        1024u,                                     /* request burst */
    },
    /* VERIFIED_SEEDER */
    {
        16u,                                       /* publish_per_week */
        UINT64_C(16) * 1024u * 1024u * 1024u,      /* weekly download: 16 GiB */
        8u,                                        /* concurrent downloads */
        2u,                                        /* queue_priority */
        UINT64_C(1) * 1024u * 1024u * 1024u,       /* pin allowance: 1 GiB */
        64u,                                       /* announces_per_hour */
        2048u,                                     /* request burst */
    },
};

const struct vcs_policy_limits *vcs_policy_limits_for(
    enum vcs_policy_tier tier)
{
    if (tier < 0 || tier >= VCS_POLICY_TIER_COUNT)
        tier = VCS_POLICY_TIER_NEW_USER;
    return &k_limits[tier];
}

/* ── the local ratio ────────────────────────────────────────────────── */

uint64_t vcs_policy_ratio_milli(uint64_t verified_bytes_uploaded,
                                uint64_t verified_bytes_downloaded)
{
    uint64_t divisor = verified_bytes_downloaded;
    if (divisor == 0)
        divisor = 1;
    if (verified_bytes_uploaded > UINT64_MAX / 1000u)
        return UINT64_MAX; /* saturate, never wrap */
    return (verified_bytes_uploaded * 1000u) / divisor;
}

enum vcs_policy_tier vcs_policy_tier_for(uint64_t earned_score,
                                         uint64_t verified_bytes_uploaded,
                                         uint64_t verified_bytes_downloaded)
{
    /* The earned-score gate comes FIRST: bandwidth alone buys nothing
     * (no global ZCODE mint for bandwidth — a Sybil pair uploading to
     * each other with zero earned score stays NEW_USER). */
    if (earned_score < VCS_POLICY_TIER_CONTRIBUTOR_MIN_SCORE)
        return VCS_POLICY_TIER_NEW_USER;
    if (earned_score >= VCS_POLICY_TIER_SEEDER_MIN_SCORE &&
        verified_bytes_uploaded >= VCS_POLICY_TIER_SEEDER_MIN_UPLOAD_BYTES &&
        vcs_policy_ratio_milli(verified_bytes_uploaded,
                               verified_bytes_downloaded) >=
            VCS_POLICY_TIER_SEEDER_MIN_RATIO_MILLI)
        return VCS_POLICY_TIER_VERIFIED_SEEDER;
    return VCS_POLICY_TIER_EARNED_CONTRIBUTOR;
}

/* ── window arithmetic ──────────────────────────────────────────────── */

/* ISO-8601 weekday of a civil day: 1 = Monday .. 7 = Sunday. Day 0
 * (1970-01-01) was a Thursday (= 4). Floor-mod arithmetic keeps pre-epoch
 * days correct. */
static unsigned policy_iso_weekday(int64_t day)
{
    int64_t m = day % 7;
    if (m < 0)
        m += 7;
    return (unsigned)((m + 3) % 7) + 1u;
}

int64_t vcs_policy_week_start(int64_t day)
{
    return day - ((int64_t)policy_iso_weekday(day) - 1);
}

/* ── decisions ──────────────────────────────────────────────────────── */

static struct vcs_policy_decision policy_allow(void)
{
    struct vcs_policy_decision d;
    d.allow = true;
    d.rule = NULL;
    return d;
}

static struct vcs_policy_decision policy_deny(const char *rule)
{
    struct vcs_policy_decision d;
    d.allow = false;
    d.rule = rule;
    return d;
}

struct vcs_policy_decision vcs_policy_check_publish(
    enum vcs_policy_tier tier, uint32_t publishes_this_week)
{
    if (publishes_this_week >= vcs_policy_limits_for(tier)->publish_per_week)
        return policy_deny(VCS_POLICY_RULE_PUBLISH_FREQUENCY);
    return policy_allow();
}

struct vcs_policy_decision vcs_policy_check_download(
    enum vcs_policy_tier tier, uint64_t downloaded_this_week,
    uint64_t bytes_requested)
{
    uint64_t allowance = vcs_policy_limits_for(tier)->weekly_download_bytes;
    if (downloaded_this_week >= allowance ||
        bytes_requested > allowance - downloaded_this_week)
        return policy_deny(VCS_POLICY_RULE_DOWNLOAD_ALLOWANCE);
    return policy_allow();
}

struct vcs_policy_decision vcs_policy_check_concurrent_downloads(
    enum vcs_policy_tier tier, uint32_t active_downloads)
{
    if (active_downloads >=
        vcs_policy_limits_for(tier)->max_concurrent_downloads)
        return policy_deny(VCS_POLICY_RULE_CONCURRENT_DOWNLOADS);
    return policy_allow();
}

struct vcs_policy_decision vcs_policy_check_pin(
    enum vcs_policy_tier tier, uint64_t pinned_bytes, uint64_t add_bytes)
{
    uint64_t allowance = vcs_policy_limits_for(tier)->pin_allowance_bytes;
    if (pinned_bytes >= allowance || add_bytes > allowance - pinned_bytes)
        return policy_deny(VCS_POLICY_RULE_PIN_ALLOWANCE);
    return policy_allow();
}

struct vcs_policy_decision vcs_policy_check_announce(
    enum vcs_policy_tier tier, uint32_t announces_this_hour)
{
    if (announces_this_hour >=
        vcs_policy_limits_for(tier)->announces_per_hour)
        return policy_deny(VCS_POLICY_RULE_ANNOUNCE_RATE);
    return policy_allow();
}

struct vcs_policy_decision vcs_policy_check_request_burst(
    enum vcs_policy_tier tier, uint32_t requests_in_window)
{
    if (requests_in_window >=
        vcs_policy_limits_for(tier)->request_burst_per_window)
        return policy_deny(VCS_POLICY_RULE_REQUEST_BURST);
    return policy_allow();
}

uint32_t vcs_policy_queue_priority(enum vcs_policy_tier tier)
{
    return vcs_policy_limits_for(tier)->queue_priority;
}

struct vcs_policy_decision vcs_policy_check_verifier(
    uint64_t earned_score, bool approved_key, bool is_self)
{
    if (is_self)
        return policy_deny(VCS_POLICY_RULE_SELF_VERIFICATION);
    if (earned_score < VCS_POLICY_VERIFIER_MIN_SCORE)
        return policy_deny(VCS_POLICY_RULE_VERIFIER_SCORE);
    if (!approved_key)
        return policy_deny(VCS_POLICY_RULE_VERIFIER_APPROVED);
    return policy_allow();
}

/* ── what never earns credit ────────────────────────────────────────── */

static const char *const k_no_credit_names[VCS_POLICY_NO_CREDIT_COUNT] = { /* hotswap-static-ok: read-only enum-name tables */
    "announcement-bytes",
    "unverified-bytes",
    "duplicate-request-replay",
    "unrequested-bytes",
    "invalid-chunk",
    "incomplete-staging",
};

const char *vcs_policy_no_credit_string(enum vcs_policy_no_credit kind)
{
    if (kind < 0 || kind >= VCS_POLICY_NO_CREDIT_COUNT)
        return "unknown";
    return k_no_credit_names[kind];
}

/* ── offence kinds ──────────────────────────────────────────────────── */

static const char *const k_offence_names[VCS_POLICY_OFFENCE_COUNT] = { /* hotswap-static-ok: read-only enum-name tables */
    "duplicate-request",
    "unrequested-bytes",
    "invalid-chunk",
    "announce-flood",
    "request-flood",
};

const char *vcs_policy_offence_string(enum vcs_policy_offence kind)
{
    if (kind < 0 || kind >= VCS_POLICY_OFFENCE_COUNT)
        return "unknown";
    return k_offence_names[kind];
}
