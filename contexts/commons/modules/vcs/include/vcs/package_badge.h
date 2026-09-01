/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_badge — the ZCODE Badge: PERMANENT achievement evidence
 * (slice 10). One badge binds a badge type, the recipient contributor's
 * secp256k1 public key, the achievement period, the package-or-evidence
 * root, the issuing policy id, a unique per-issuer sequence, and the
 * issuer's secp256k1 key — all under one issuer signature. A badge is
 * permanent historical evidence: losing a leaderboard position later
 * NEVER revokes it, and the same badge is never issued twice for the
 * same contributor + achievement period (the dedup rule — the core
 * adversarial case).
 *
 * SIMULATION ONLY (owner directive): badges are SIMULATED ZSLP-based
 * assets in v1 — there is no real ZSLP mint, no wallet call, no on-chain
 * asset; the owner-reviewed real on-chain issuance is slice 15 and is
 * NOT built here. Issuance follows the plan/commit discipline:
 * `zcode badge plan` assembles a dedup-checked batch (the only mutation
 * is the persisted plan id) and `zcode badge issue` commits it by
 * persisting the signed badge records, idempotently.
 *
 * Canonical wire encoding (all integers little-endian, exactly one legal
 * encoding per badge):
 *   [8  magic = "ZCLBDG\r\n"]
 *   [2  schema_version = 1]
 *   [1  badge_type]              enum vcs_badge_type
 *   [33 recipient_pubkey]        compressed secp256k1
 *   [8  period_first_day]        i64 civil day, or -1 when non-periodic
 *   [8  period_last_day]         i64 civil day (inclusive), -1 when
 *                                non-periodic (both -1 or neither)
 *   [32 evidence_root]           package root or evidence hash (nonzero)
 *   [32 policy_id]               the issuing policy id (nonzero)
 *   [8  sequence]                unique per issuer, >= 1
 *   [33 issuer_pubkey]           compressed secp256k1
 *   [64 signature]               secp256k1 ECDSA compact r||s, low-S,
 *                                over the badge id
 *
 * The BADGE ID is SHA3-256 over (domain || the canonical encoding above
 * minus the trailing 64-byte signature). The domain is the ASCII string
 * "zcl.zcode_badge.v1" hashed WITH its single trailing 0x00 byte (sizeof
 * the string literal), the slice-1 package_manifest convention. JSON is
 * display-only and is never signed or hashed.
 *
 * THE STORE (the package_reward persistence convention — durable wires,
 * NOT SQLite/AR):
 *
 *   <datadir>/zcode/badges/<badge-id-hex>     signed badge wires
 *   <datadir>/zcode/badges/plans/<plan-id>    issuance batch plans
 *   <datadir>/zcode/badges/commits/<plan-id>  commit records — the
 *                                             idempotence authority
 *
 * Every write is temp + fsync + atomic rename. The whole store is
 * replayed (rebuilt in memory) on every load, so a one-shot CLI and a
 * node agree. Every badge is SIGNATURE-VERIFIED at load: a forged or
 * corrupt wire is skipped, logged, and counted, never listed. The commit
 * record is written LAST, so a crash mid-issue leaves a resumable
 * partial state — re-issuing the same plan id finishes it (badge writes
 * dedup by badge id) instead of double-issuing, and a completed issue is
 * a named duplicate, never a double-issue.
 *
 * This layer parses, serializes, hashes, verifies, and persists only.
 * Signing happens outside this layer (the command handler signs through
 * a callback); private keys never enter contexts/commons/modules/vcs. The store is the
 * INTRINSIC truth (signature-verified wires); whether a badge COUNTS
 * (issuer + policy id match the operator's configured policy) is the
 * policy lens applied by the caller — a foreign-issuer badge never
 * satisfies dedup and never lists as an earned badge.
 *
 * Eligibility (which badge a contributor qualifies for) lives in
 * contexts/commons/modules/vcs/package_badge_eligible.* — it derives from the slice-8 reward
 * ledger, the slice-9 rankings, and the slice-3 publish history. */

#ifndef ZCL_VCS_PACKAGE_BADGE_H
#define ZCL_VCS_PACKAGE_BADGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── badge types (the enum order is frozen: it appears on the wire and
 *    in typed JSON) ────────────────────────────────────────────────── */

enum vcs_badge_type {
    VCS_BADGE_FIRST_PACKAGE = 0,      /* published >= 1 package */
    VCS_BADGE_TEN_PACKAGES,           /* published >= 10 distinct packages */
    VCS_BADGE_HUNDRED_TESTS,          /* >= 100 settled test points */
    VCS_BADGE_BUG_HUNTER,             /* >= 1 settled bug-fix reward */
    VCS_BADGE_SECURITY_RESEARCHER,    /* >= 1 settled security-fix reward */
    VCS_BADGE_REPRODUCIBLE_BUILDER,   /* >= 1 settled build reproduction */
    VCS_BADGE_TOP_DAILY,              /* rank 1 overall, one UTC day */
    VCS_BADGE_TOP_WEEKLY,             /* rank 1 overall, one ISO week */
    VCS_BADGE_TOP_MONTHLY,            /* rank 1 overall, one month */
    VCS_BADGE_ONE_YEAR_MAINTAINER,    /* settled facts span >= 365 days */
    VCS_BADGE_POPULAR_PACKAGE,        /* UNAVAILABLE: P2P fact (slices
                                         11-12) — never faked */
    VCS_BADGE_RARE_PACKAGE_SEEDER,    /* UNAVAILABLE: P2P fact (slices
                                         11-12) — never faked */
    VCS_BADGE_EARLY_ZCODE_CONTRIBUTOR,/* settled within the pioneer window
                                         of the local ledger */
    VCS_BADGE_TYPE_COUNT
};

/* The wire/JSON name ("first-package", ...); "unknown" out of range. */
const char *vcs_badge_type_string(enum vcs_badge_type type);

/* Parse a type string. False on an unknown name (no logging). */
bool vcs_badge_type_from_string(const char *name, enum vcs_badge_type *out);

/* True when the badge type has a fact source in v1. POPULAR_PACKAGE and
 * RARE_PACKAGE_SEEDER need P2P facts that do not exist until slices
 * 11-12: they are UNAVAILABLE and surfaces must say so honestly. */
bool vcs_badge_type_available(enum vcs_badge_type type);

/* ── the achievement period ─────────────────────────────────────────── */

/* The non-periodic sentinel: once-ever badges (FIRST_PACKAGE,
 * TEN_PACKAGES, EARLY_ZCODE_CONTRIBUTOR) carry (-1, -1). A periodic
 * badge carries 0 <= first <= last (inclusive civil days). */
#define VCS_BADGE_PERIOD_NONE ((int64_t)-1)

/* ── bounds (frozen; every wire and report is bounded) ──────────────── */

#define VCS_PACKAGE_BADGE_VERSION 1u
#define VCS_PACKAGE_BADGE_ID_DOMAIN "zcl.zcode_badge.v1"
#define VCS_PACKAGE_BADGE_WIRE_MAGIC_BYTES 8u
#define VCS_PACKAGE_BADGE_PUBKEY_BYTES 33u
#define VCS_PACKAGE_BADGE_SIGNATURE_BYTES 64u
#define VCS_PACKAGE_BADGE_ID_BYTES 32u
#define VCS_PACKAGE_BADGE_WIRE_BYTES                                     \
    (VCS_PACKAGE_BADGE_WIRE_MAGIC_BYTES + 2u + 1u +                      \
     VCS_PACKAGE_BADGE_PUBKEY_BYTES + 8u + 8u + 32u + 32u + 8u +         \
     VCS_PACKAGE_BADGE_PUBKEY_BYTES + VCS_PACKAGE_BADGE_SIGNATURE_BYTES)

#define VCS_BADGE_MAX_BADGES 4096u
#define VCS_BADGE_MAX_PLANS 1024u
#define VCS_BADGE_MAX_COMMITS 1024u
#define VCS_BADGE_MAX_PLAN_ROWS 256u
#define VCS_BADGE_MAX_PLAN_WIRE_BYTES (64u * 1024u)
#define VCS_BADGE_MAX_COMMIT_WIRE_BYTES (64u * 1024u)
#define VCS_BADGE_RULE_MAX 48u /* NUL-padded rule strings */

/* Named rules (the exact strings that appear in plans and rejections). */
#define VCS_BADGE_RULE_DUPLICATE "duplicate-badge"
#define VCS_BADGE_RULE_NOT_ELIGIBLE "not-eligible"
#define VCS_BADGE_RULE_UNAVAILABLE "unavailable"
#define VCS_BADGE_RULE_PERIOD_CHANGED "period-changed"
#define VCS_BADGE_RULE_EVIDENCE_CHANGED "evidence-changed"

/* ── the badge (value type) ─────────────────────────────────────────── */

/* Fixed-size value type, no heap. Zeroing the whole struct is a defined
 * (invalid) state — validate() rejects it. */
struct vcs_badge {
    uint16_t schema_version; /* must be VCS_PACKAGE_BADGE_VERSION */
    uint8_t type;            /* enum vcs_badge_type */
    uint8_t recipient[VCS_PACKAGE_BADGE_PUBKEY_BYTES];
    int64_t period_first_day; /* VCS_BADGE_PERIOD_NONE when non-periodic */
    int64_t period_last_day;
    uint8_t evidence_root[32];
    uint8_t policy_id[32];
    uint64_t sequence; /* unique per issuer, >= 1 */
    uint8_t issuer_pubkey[VCS_PACKAGE_BADGE_PUBKEY_BYTES];
    uint8_t signature[VCS_PACKAGE_BADGE_SIGNATURE_BYTES];
};

/* True when the badge carries the non-periodic sentinel. */
bool vcs_badge_is_non_periodic(const struct vcs_badge *badge);

/* Every rejection names the failed rule. The enum order is frozen. */
enum vcs_badge_error {
    VCS_BADGE_OK = 0,
    VCS_BADGE_ERR_NULL,            /* null argument */
    VCS_BADGE_ERR_ALLOC,           /* allocation failure */
    VCS_BADGE_ERR_SCHEMA_VERSION,  /* schema_version != 1 */
    VCS_BADGE_ERR_WIRE_MAGIC,      /* bad magic */
    VCS_BADGE_ERR_WIRE_OVERSIZE,   /* wrong wire length */
    VCS_BADGE_ERR_TYPE,            /* unknown badge type */
    VCS_BADGE_ERR_PERIOD,          /* first > last, or exactly one of the
                                      period bounds is the sentinel */
    VCS_BADGE_ERR_EVIDENCE_ROOT,   /* all-zero evidence root */
    VCS_BADGE_ERR_POLICY_ID,       /* all-zero policy id */
    VCS_BADGE_ERR_SEQUENCE,        /* sequence 0 */
    VCS_BADGE_ERR_RECIPIENT,       /* recipient not a compressed curve
                                      point */
    VCS_BADGE_ERR_ISSUER,          /* issuer not a compressed curve point */
    VCS_BADGE_ERR_SIG_LOW_S,       /* high-S (malleated) signature */
    VCS_BADGE_ERR_SIG_VERIFY,      /* ECDSA verification failed */
};

const char *vcs_badge_error_string(enum vcs_badge_error error);

/* Validate every field against the v1 rules above. Does NOT look at the
 * signature. */
enum vcs_badge_error vcs_badge_validate(const struct vcs_badge *badge);

/* Compute the badge id: SHA3-256 over the frozen domain (with its NUL)
 * and the canonical encoding of every field except the signature.
 * Fields are validated first; an invalid badge has no id. */
enum vcs_badge_error vcs_badge_id(const struct vcs_badge *badge,
                                  uint8_t out[VCS_PACKAGE_BADGE_ID_BYTES]);

/* Canonically serialize a validated badge (signature included; exactly
 * VCS_PACKAGE_BADGE_WIRE_BYTES bytes into out). */
enum vcs_badge_error vcs_badge_serialize(const struct vcs_badge *badge,
                                         uint8_t *out, size_t out_cap);

/* Parse only the exact canonical wire form (fixed length). *out is
 * zeroed on entry and on every rejection. The signature is NOT verified
 * here — call vcs_badge_verify() after parsing. */
enum vcs_badge_error vcs_badge_parse(const uint8_t *wire, size_t wire_len,
                                     struct vcs_badge *out);

/* Full check: validate fields, recompute the badge id, require the low-S
 * canonical form, and verify the secp256k1 ECDSA signature over the id
 * against the embedded issuer pubkey. This proves the issuer signed
 * these exact bytes only; whether the issuer COUNTS (the configured
 * policy issuer) is the policy lens, not this codec's rule. */
enum vcs_badge_error vcs_badge_verify(const struct vcs_badge *badge);

/* ── the issuing policy (the operator-configured lens) ──────────────── */

struct vcs_badge_policy {
    uint8_t policy_id[32];
    uint8_t issuer_pubkey[VCS_PACKAGE_BADGE_PUBKEY_BYTES];
};

/* Load the operator's badge policy from <zcode_dir>/badge_policy: line 1
 * is the 64-hex policy id, line 2 the 66-hex issuer pubkey ('#' comment
 * and blank lines skipped). False when the file is missing or malformed
 * (logged) — the plan/issue commands name NO_BADGE_POLICY. */
bool vcs_badge_policy_load(const char *zcode_dir,
                           struct vcs_badge_policy *out);

/* The policy lens: true when the badge commits to this policy id and
 * this issuer key. Only recognized badges satisfy dedup and list as
 * earned badges. */
bool vcs_badge_recognized(const struct vcs_badge *badge,
                          const struct vcs_badge_policy *policy);

/* ── the badge store (durable wires, replayed on every load) ────────── */

struct vcs_badge_store;

/* Load and replay <zcode_dir>/badges. Missing directories are an empty
 * store, never an error. Every badge wire is parsed and SIGNATURE-
 * VERIFIED: forged/corrupt/oversize wires are skipped, logged, and
 * counted; over-bound directories stop the scan and set the truncated
 * flags. NULL only on allocation failure (logged). */
struct vcs_badge_store *vcs_badge_store_load(const char *zcode_dir);
void vcs_badge_store_free(struct vcs_badge_store *store);

size_t vcs_badge_store_badge_count(const struct vcs_badge_store *s);
uint32_t vcs_badge_store_corrupt_count(const struct vcs_badge_store *s);
bool vcs_badge_store_truncated(const struct vcs_badge_store *s);

/* Badges in ascending badge-id order (deterministic). Borrowed; invalid
 * after any mutation or free of the store. */
const struct vcs_badge *vcs_badge_store_at(const struct vcs_badge_store *s,
                                           size_t index);

/* The badge id of the badge at `index` (computed once at load). */
void vcs_badge_store_id_at(const struct vcs_badge_store *s, size_t index,
                           uint8_t out[32]);

const struct vcs_badge *vcs_badge_store_find(
    const struct vcs_badge_store *s, const uint8_t badge_id[32]);

/* THE DEDUP RULE: true when a RECOGNIZED badge (matching the policy id
 * and issuer) already exists for this exact (contributor, type, period).
 * Issuance must never produce a second one; a foreign-issuer badge never
 * satisfies dedup. `policy` may be NULL (no recognition: always false). */
bool vcs_badge_store_dedup_hit(const struct vcs_badge_store *s,
                               const struct vcs_badge_policy *policy,
                               const uint8_t contributor[33],
                               enum vcs_badge_type type,
                               int64_t period_first, int64_t period_last);

/* The highest sequence any badge by `issuer` carries (0 when none): the
 * plan layer assigns sequences from this + 1. */
uint64_t vcs_badge_store_max_sequence(const struct vcs_badge_store *s,
                                      const uint8_t issuer_pubkey[33]);

/* Copy the RECOGNIZED badges earned by `contributor` into `out` (cap
 * entries), ascending by (sequence, badge id) — issuance order. Returns
 * the TOTAL recognized count (may exceed cap — page with it). */
size_t vcs_badge_store_contributor_badges(
    const struct vcs_badge_store *s, const struct vcs_badge_policy *policy,
    const uint8_t contributor[33], struct vcs_badge *out, size_t cap);

/* ── persistence primitives (the eligible layer's plan/commit builds
 *    on these) ──────────────────────────────────────────────────────── */

enum vcs_badge_persist_error {
    VCS_BADGE_PERSIST_OK = 0,
    VCS_BADGE_PERSIST_DUPLICATE, /* identical wire already durable */
    VCS_BADGE_PERSIST_FULL,      /* VCS_BADGE_MAX_BADGES */
    VCS_BADGE_PERSIST_INVALID,   /* the badge failed validation/verify */
    VCS_BADGE_PERSIST_IO,        /* durable write failed (logged) */
};

const char *vcs_badge_persist_error_string(
    enum vcs_badge_persist_error err);

/* Persist one signed badge wire under badges/<badge-id-hex>: validates,
 * verifies the signature, computes the id, writes durably (temp + fsync
 * + atomic rename), and registers it in memory. Re-persisting an
 * identical badge is a dedup no-op (DUPLICATE, with id_out filled).
 * id_out always receives the badge id on OK/DUPLICATE. */
enum vcs_badge_persist_error vcs_badge_store_persist(
    struct vcs_badge_store *s, const struct vcs_badge *badge,
    uint8_t id_out[32]);

/* ── the issuance plan (one badge batch, plan/commit discipline) ────── */

struct vcs_badge_plan_row {
    uint8_t contributor[33];
    enum vcs_badge_type type;
    int64_t period_first;
    int64_t period_last;
    uint8_t evidence_root[32];
    uint64_t sequence;
};

struct vcs_badge_plan {
    uint8_t policy_id[32];
    uint8_t issuer_pubkey[33];
    int64_t planned_day; /* the "today" the eligibility facts were
                            computed against — issue re-validates against
                            this same day, never the wall clock */
    struct vcs_badge_plan_row rows[VCS_BADGE_MAX_PLAN_ROWS];
    size_t row_count;
    uint8_t plan_id[32]; /* domain-separated hash of the content above */
};

/* Assemble a plan from explicit rows (the eligible layer derives them;
 * exposed so the exact plan content is testable). Rows are sorted into
 * the canonical order (contributor, type, period, sequence) before the
 * id is computed. False (logged) on bad input or too many rows. */
bool vcs_badge_plan_assemble(const uint8_t policy_id[32],
                             const uint8_t issuer_pubkey[33],
                             int64_t planned_day,
                             const struct vcs_badge_plan_row *rows,
                             size_t row_count, struct vcs_badge_plan *out);

enum vcs_badge_plan_persist_error {
    VCS_BADGE_PLAN_PERSIST_OK = 0,
    VCS_BADGE_PLAN_PERSIST_DUPLICATE, /* identical plan already durable */
    VCS_BADGE_PLAN_PERSIST_FULL,      /* VCS_BADGE_MAX_PLANS */
    VCS_BADGE_PLAN_PERSIST_IO,        /* durable write failed (logged) */
};

/* Persist the plan wire under badges/plans/<plan-id-hex> (the ONLY
 * mutation planning ever makes). The same content re-planned yields the
 * same plan id and is a dedup no-op. */
enum vcs_badge_plan_persist_error vcs_badge_plan_persist(
    struct vcs_badge_store *s, const struct vcs_badge_plan *plan);

/* Read a plan wire fresh from disk (the file is the plan truth) and
 * require its content id to equal `plan_id`. Returns:
 *   0  plan loaded into `out`
 *   1  no plan wire names this id (UNKNOWN_PLAN)
 *  -1  present but corrupt/mismatched (logged)
 */
int vcs_badge_plan_read(const struct vcs_badge_store *s,
                        const uint8_t plan_id[32],
                        struct vcs_badge_plan *out);

/* ── the commit record (the idempotence authority) ──────────────────── */

/* True when the commit record for `plan_id` is durable — a completed
 * issue; re-issuing is a named duplicate, never a double-issue. */
bool vcs_badge_commit_known(const struct vcs_badge_store *s,
                            const uint8_t plan_id[32]);

/* Write the commit record for `plan_id` LAST (after every badge wire is
 * durable): plan id + the issued badge ids. False on I/O failure
 * (logged). */
bool vcs_badge_commit_record_write(struct vcs_badge_store *s,
                                   const uint8_t plan_id[32],
                                   const uint8_t (*badge_ids)[32],
                                   size_t badge_count);

/* The badge ids a commit record names (the durable receipt of an issue).
 * Fills out (cap entries), returns the total named count, or 0 when no
 * commit record exists (or it is corrupt — logged). */
size_t vcs_badge_commit_record_badges(const struct vcs_badge_store *s,
                                      const uint8_t plan_id[32],
                                      uint8_t (*out)[32], size_t cap);

#endif /* ZCL_VCS_PACKAGE_BADGE_H */
