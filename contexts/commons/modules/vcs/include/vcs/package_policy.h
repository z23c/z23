/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_policy — the ZCODE local P2P ratio + anti-spam policy (slice 11:
 * LOCAL POLICY ONLY — the swarm transport that consumes these decisions is
 * slice 12). Pure decision functions over explicit facts: given a
 * contributor's tier and usage, allow or deny — and EVERY denial names the
 * exact failed rule. Deterministic: no wall-clock, no filesystem, no
 * network; the caller passes civil day numbers and usage tallies.
 *
 * THE OWNER-DIRECTIVE RULES this layer encodes:
 *
 *   FREE ALLOWANCE (absolute): a brand-new user with zero ZCODE Score can
 *   still download public packages. No check here may PERMANENTLY deny
 *   public code solely for lacking tokens — the download allowance is a
 *   per-week rate limit (deny names the rule; the next window allows
 *   again), never a ban.
 *
 *   ZCODE + SERVICE ACTIVITY CONTROL: publishing frequency, concurrent
 *   package downloads, queue priority, package pin allowance, package
 *   announcement rate, request burst allowance, and verifier eligibility
 *   all scale with the tier:
 *     new user           — small queue, 1 publication/week, bounded
 *                          unique-root serving-set inventory so one
 *                          library shelf is deliverable over the swarm
 *     earned contributor — larger queue, more frequent publication, pin
 *                          allowance, unique-root inventory at least the
 *                          serving-set size (earned score >= the threshold)
 *     active verified seeder — best local bandwidth ratio, highest request
 *                          priority (earned score + verified upload volume
 *                          + local ratio >= 1)
 *
 *   RATIO CREDIT IS LOCAL: verified_bytes_uploaded / max(verified_bytes_
 *   downloaded, 1), per contributor key, on THIS node's own accounting
 *   (contexts/commons/modules/vcs/package_service.*). There is NO global ZCODE mint for
 *   bandwidth — two Sybil nodes uploading to each other earn nothing:
 *   bandwidth alone never reaches the earned-contributor tier (the tier
 *   gate requires EARNED SCORE first), and the ratio is a local service
 *   fact, never a ledger fact.
 *
 *   PEERS NEVER EARN CREDIT FOR (the frozen no-credit list): announcements,
 *   unverified bytes, repeated copies of the same request, bytes not
 *   requested, invalid chunks, incomplete staging data. Only bytes that
 *   were (a) requested by a distinct request id, (b) delivered, and (c)
 *   passed SHA3 chunk verification count as verified.
 *
 * This layer computes; the durable per-key accounting lives in
 * package_service.* and the transport-time offence accounting consumes
 * vcs_policy_offence. */

#ifndef ZCL_VCS_PACKAGE_POLICY_H
#define ZCL_VCS_PACKAGE_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── tiers ──────────────────────────────────────────────────────────── */

/* The enum order is frozen: it appears in typed JSON. */
enum vcs_policy_tier {
    VCS_POLICY_TIER_NEW_USER = 0,      /* zero/little earned score */
    VCS_POLICY_TIER_EARNED_CONTRIBUTOR,/* earned score >= the threshold */
    VCS_POLICY_TIER_VERIFIED_SEEDER,   /* contributor + proven local seeding */
    VCS_POLICY_TIER_COUNT
};

const char *vcs_policy_tier_string(enum vcs_policy_tier tier);

/* Tier thresholds (named constants — the policy table). */
#define VCS_POLICY_TIER_CONTRIBUTOR_MIN_SCORE UINT64_C(100)
#define VCS_POLICY_TIER_SEEDER_MIN_SCORE UINT64_C(500)
#define VCS_POLICY_TIER_SEEDER_MIN_UPLOAD_BYTES \
    (UINT64_C(256) * 1024u * 1024u) /* 256 MiB verified served */
#define VCS_POLICY_TIER_SEEDER_MIN_RATIO_MILLI UINT64_C(1000) /* ratio >= 1 */

/* Verifier eligibility: the earned-score floor for acting as an external
 * verifier (the approved-key allowlist and the self-verification ban are
 * separate checks — slice 6 owns the allowlist; the decision here names
 * every rule). */
#define VCS_POLICY_VERIFIER_MIN_SCORE UINT64_C(1000)

/* The FREE allowance: what a zero-score new user always gets. The weekly
 * download allowance is a RATE LIMIT per window, never a permanent denial
 * of public code. */
#define VCS_POLICY_FREE_WEEKLY_DOWNLOAD_BYTES \
    (UINT64_C(256) * 1024u * 1024u) /* 256 MiB / week */
#define VCS_POLICY_FREE_PUBLISH_PER_WEEK 1u
#define VCS_POLICY_FREE_REQUEST_BURST_PER_WINDOW 512u
/* 512 maximum-sized WANTs are at most 64 MiB per 10-minute window. The
 * separate 256 MiB weekly byte allowance remains the absolute free cap; this
 * request bound lets a path-sharded source carrier arrive without classifying
 * its ordinary manifest/chunk fan-out as a flood. */
/* The NEW_USER serving-set inventory bound: DISTINCT package_root values
 * advertised per hour. Matches VCS_SWARM_MAX_LOCAL_ANNOUNCES so one
 * bounded library shelf is deliverable. Repeats of a root the peer
 * already advertises are keep-alives and do not consume this bound.
 * Announces still never earn credit; over-quota unique roots remain the
 * ANNOUNCE_FLOOD offence. This is an inventory bound, not a reward. */
#define VCS_POLICY_FREE_ANNOUNCE_PER_HOUR 64u

/* The per-tier limit table (the policy table, frozen). */
struct vcs_policy_limits {
    uint32_t publish_per_week;          /* publication frequency */
    uint64_t weekly_download_bytes;     /* download allowance / week */
    uint32_t max_concurrent_downloads;  /* simultaneous package downloads */
    uint32_t queue_priority;            /* request queue priority (higher
                                           is better; 0 = best effort) */
    uint64_t pin_allowance_bytes;       /* contributor-requested pin budget */
    uint32_t announces_per_hour;        /* package announcement rate */
    uint32_t request_burst_per_window;  /* chunk requests / 10-min window */
};

/* The frozen limits of one tier (never NULL). */
const struct vcs_policy_limits *vcs_policy_limits_for(
    enum vcs_policy_tier tier);

/* ── the local ratio ────────────────────────────────────────────────── */

/* verified_bytes_uploaded / max(verified_bytes_downloaded, 1), expressed
 * in milli (1000 = 1.0), saturating at UINT64_MAX. Pure integer arithmetic
 * — deterministic, no floating point. */
uint64_t vcs_policy_ratio_milli(uint64_t verified_bytes_uploaded,
                                uint64_t verified_bytes_downloaded);

/* Tier resolution from earned score + local service facts. Bandwidth
 * alone NEVER earns the contributor tier: the earned-score gate comes
 * first, so a Sybil pair uploading to each other with zero earned score
 * stays NEW_USER. */
enum vcs_policy_tier vcs_policy_tier_for(uint64_t earned_score,
                                         uint64_t verified_bytes_uploaded,
                                         uint64_t verified_bytes_downloaded);

/* ── window arithmetic (pure; civil days, ISO weeks) ────────────────── */

/* The Monday (civil day number) of the ISO-8601 week containing `day`.
 * Two days share a publication/announcement window exactly when their
 * week starts agree. */
int64_t vcs_policy_week_start(int64_t day);

/* ── decisions (given facts → allow/deny + the exact rule name) ─────── */

struct vcs_policy_decision {
    bool allow;
    const char *rule; /* NULL when allow; the exact failed rule on deny */
};

/* The frozen rule names (they appear in typed JSON and tests). */
#define VCS_POLICY_RULE_PUBLISH_FREQUENCY "publish-frequency-limit"
#define VCS_POLICY_RULE_DOWNLOAD_ALLOWANCE "download-allowance-exhausted"
#define VCS_POLICY_RULE_CONCURRENT_DOWNLOADS "concurrent-download-limit"
#define VCS_POLICY_RULE_PIN_ALLOWANCE "pin-allowance-exceeded"
#define VCS_POLICY_RULE_ANNOUNCE_RATE "announce-rate-limit"
#define VCS_POLICY_RULE_REQUEST_BURST "request-burst-limit"
#define VCS_POLICY_RULE_VERIFIER_SCORE "verifier-score-too-low"
#define VCS_POLICY_RULE_VERIFIER_APPROVED "verifier-not-approved"
#define VCS_POLICY_RULE_SELF_VERIFICATION "self-verification"

/* Publication frequency: publishes_this_week is the contributor's count
 * of DISTINCT releases already published in the current ISO week (the
 * caller counts; re-deliveries of the same release id dedup before they
 * reach this count). A new user gets VCS_POLICY_FREE_PUBLISH_PER_WEEK. */
struct vcs_policy_decision vcs_policy_check_publish(
    enum vcs_policy_tier tier, uint32_t publishes_this_week);

/* Download allowance: downloaded_this_week + bytes_requested against the
 * tier's weekly allowance (the new-user allowance is the FREE allowance —
 * a zero-score user always has it). A denial is a per-window rate limit,
 * never a permanent ban: the next ISO week allows again. */
struct vcs_policy_decision vcs_policy_check_download(
    enum vcs_policy_tier tier, uint64_t downloaded_this_week,
    uint64_t bytes_requested);

/* Concurrent package downloads: active_downloads is the count ALREADY
 * in flight; the check admits one more. */
struct vcs_policy_decision vcs_policy_check_concurrent_downloads(
    enum vcs_policy_tier tier, uint32_t active_downloads);

/* Contributor-requested pin allowance: pinned_bytes is the contributor's
 * current pin usage; the check admits add_bytes more. New users have no
 * pin allowance (pins are earned). The operator's own pins are a separate
 * store path and are NOT subject to this check. */
struct vcs_policy_decision vcs_policy_check_pin(
    enum vcs_policy_tier tier, uint64_t pinned_bytes, uint64_t add_bytes);

/* Package announcement rate (per hour window), counted on DISTINCT
 * package_root values first added to a peer's advertisement set. New
 * users get VCS_POLICY_FREE_ANNOUNCE_PER_HOUR unique roots per hour so
 * one bounded library shelf is deliverable; over-quota unique roots
 * name announce-rate-limit. */
struct vcs_policy_decision vcs_policy_check_announce(
    enum vcs_policy_tier tier, uint32_t announces_this_hour);

/* Chunk-request burst allowance (per 10-minute window). */
struct vcs_policy_decision vcs_policy_check_request_burst(
    enum vcs_policy_tier tier, uint32_t requests_in_window);

/* Request queue priority for a tier (higher dequeues first). */
uint32_t vcs_policy_queue_priority(enum vcs_policy_tier tier);

/* Verifier eligibility: earned score floor + approved-key allowlist +
 * the self-verification ban, each a separately named rule. Evaluation
 * order is self-verification, then score, then approval — the FIRST
 * failed rule is named. */
struct vcs_policy_decision vcs_policy_check_verifier(
    uint64_t earned_score, bool approved_key, bool is_self);

/* ── what never earns credit (the frozen no-credit list) ────────────── */

/* The enum order is frozen: it appears in typed JSON. */
enum vcs_policy_no_credit {
    VCS_POLICY_NO_CREDIT_ANNOUNCEMENT = 0,  /* announcement bytes */
    VCS_POLICY_NO_CREDIT_UNVERIFIED,        /* failed SHA3 verification */
    VCS_POLICY_NO_CREDIT_DUPLICATE_REQUEST, /* a repeated copy of the same
                                               request id */
    VCS_POLICY_NO_CREDIT_UNREQUESTED,       /* bytes never requested */
    VCS_POLICY_NO_CREDIT_INVALID_CHUNK,     /* chunk hash mismatch */
    VCS_POLICY_NO_CREDIT_INCOMPLETE_STAGING,/* incomplete staging data */
    VCS_POLICY_NO_CREDIT_COUNT
};

const char *vcs_policy_no_credit_string(enum vcs_policy_no_credit kind);

/* ── offence kinds (local per-key accounting; named, accumulating) ──── */

/* The enum order is frozen: it appears in typed JSON. Weights live with
 * the transport (slice 12); this slice names and counts. */
enum vcs_policy_offence {
    VCS_POLICY_OFFENCE_DUPLICATE_REQUEST = 0, /* replayed request id */
    VCS_POLICY_OFFENCE_UNREQUESTED_BYTES,     /* data we never asked for */
    VCS_POLICY_OFFENCE_INVALID_CHUNK,         /* chunk hash mismatch */
    VCS_POLICY_OFFENCE_ANNOUNCE_FLOOD,        /* over the announce rate */
    VCS_POLICY_OFFENCE_REQUEST_FLOOD,         /* over the burst allowance */
    VCS_POLICY_OFFENCE_COUNT
};

const char *vcs_policy_offence_string(enum vcs_policy_offence kind);

/* The local disconnect threshold the transport (slice 12) applies: a peer
 * whose accumulated offence total reaches this count is disconnected. */
#define VCS_POLICY_OFFENCE_DISCONNECT_THRESHOLD 100u

#endif /* ZCL_VCS_PACKAGE_POLICY_H */
