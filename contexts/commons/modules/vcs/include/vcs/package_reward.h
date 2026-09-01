/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_reward — the simulated ZCODE reward ledger and daily settlement
 * queue (slice 8). SIMULATION ONLY: every settled batch is recorded under
 * the configured PLACEHOLDER token id; the real ZCODE ZSLP token is never
 * created, minted, or sent here, and v1 has no automatic on-chain payout
 * (the real transfer is the owner-reviewed slice-14 flow). Rewards accrue
 * as off-chain score facts into a DAILY SETTLEMENT QUEUE: N payouts settle
 * in ONE batched (simulated) send per settlement window, never one per
 * reward (owner directive, docs/work/ZCODE_PLAN.md "ZCL fuel economics").
 *
 * WHAT IS AUTHORITATIVE (persistence convention — the file-based store
 * discipline, NOT SQLite/AR: the ZCODE branch's canonical truth lives
 * under <datadir>/zcode as durable wires, and the ledger follows it):
 *
 *   <datadir>/zcode/rewards/queue/<entry_id>   queue records (workflow
 *                                              state: queued, settled,
 *                                              rejected)
 *   <datadir>/zcode/rewards/plans/<plan_id>    settlement-window batches
 *                                              (every exclusion rule named)
 *   <datadir>/zcode/rewards/ledger/<entry_id>  SETTLED score facts — THE
 *                                              reward-history ledger; this
 *                                              is what the slice-7 period
 *                                              caps (per contributor per
 *                                              week, rewarded releases per
 *                                              day) read
 *   <datadir>/zcode/rewards/commits/<plan_id>  commit records — the
 *                                              idempotence authority and
 *                                              the durable receipt
 *
 * Every write is temp + fsync + atomic rename (the package_store_io
 * discipline); a crash anywhere leaves either the old file or the new
 * one, never a torn one. The whole store is replayed (rebuilt in memory)
 * on every load, so a one-shot CLI and a node agree, and a crash between
 * commit and ledger write is replay-safe: the commit record is written
 * LAST, so an interrupted commit has no record and re-committing the same
 * plan id resumes (facts dedup by entry id, already-settled entries are
 * recognized by their settling plan id) instead of double-paying.
 *
 * RECORD KINDS. Auto-derived entries (kind AUTO: new-package,
 * package-update, test-contribution) carry the slice-7 score points and a
 * caller-supplied scoring-facts hash binding the score report. Manual
 * categories (bug-fix-with-regression-test, security-fix,
 * independent-build-reproduction, maintenance-90-day, independent-review)
 * are not auto-derivable: they enter as CLAIMS binding an evidence root,
 * are validated against their frozen point band at enqueue, and are
 * BLOCKED from settlement with the named rule owner-review-required —
 * per the plan/commit discipline they only settle after owner review in
 * slice 14. Eligibility (the eight gates) is asserted by the flow that
 * enqueues; this layer stores and settles facts, it does not re-verify
 * releases (slice 7 owns scoring, package_eligible owns the gates).
 *
 * IDEMPOTENCE. Entry, plan, fact, and commit ids are domain-separated
 * SHA3-256 hashes of their canonical content, so redelivery is always a
 * dedup no-op or a named duplicate — settling the same reward twice is a
 * duplicate, never a double-pay.
 *
 * No balances exist anywhere in this layer: earned_score and
 * token_rewards_received are separate FACTS (the ranking input and the
 * simulated-token tally), and rankings must never use a balance. */

#ifndef ZCL_VCS_PACKAGE_REWARD_H
#define ZCL_VCS_PACKAGE_REWARD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── the placeholder token (SIMULATION ONLY) ────────────────────────── */

/* The configured placeholder token id for every simulated settlement.
 * These are the 32 ASCII bytes "zcode-placeholder-token-v1-sim!!" — a
 * value that can never collide with a real ZSLP token id (a genesis
 * txid). The real ZCODE token id arrives with the owner-reviewed slice-14
 * transfer flow; until then NO other token id may appear in a receipt. */
#define VCS_REWARD_PLACEHOLDER_TOKEN_ID_TEXT "zcode-placeholder-token-v1-sim!!"

/* The 32-byte placeholder id (borrowed, never NULL). */
const uint8_t *vcs_reward_placeholder_token_id(void);

/* Hex-encode the placeholder id (out is 65 bytes incl. NUL). */
void vcs_reward_placeholder_token_id_hex(char out[65]);

/* ── bounds (frozen; every wire and report is bounded) ──────────────── */

#define VCS_REWARD_MAX_QUEUE_ENTRIES 4096u
#define VCS_REWARD_MAX_FACTS 4096u
#define VCS_REWARD_MAX_PLANS 1024u
#define VCS_REWARD_MAX_COMMITS 1024u
#define VCS_REWARD_MAX_BATCH_ENTRIES 256u /* planned rows per window */
#define VCS_REWARD_MAX_EVAL_ROWS 4096u    /* evaluated rows per plan */
#define VCS_REWARD_RULE_MAX 32u           /* NUL-padded rule strings */
#define VCS_REWARD_MAX_QUEUE_WIRE_BYTES 256u
#define VCS_REWARD_MAX_FACT_WIRE_BYTES 256u
#define VCS_REWARD_MAX_PLAN_WIRE_BYTES (512u * 1024u)
#define VCS_REWARD_MAX_COMMIT_WIRE_BYTES (64u * 1024u)

/* ── categories (mirror the slice-7 scoring table order, frozen) ────── */

enum vcs_reward_category {
    VCS_REWARD_CATEGORY_NEW_PACKAGE = 0,
    VCS_REWARD_CATEGORY_PACKAGE_UPDATE,
    VCS_REWARD_CATEGORY_BUG_FIX_REGRESSION,
    VCS_REWARD_CATEGORY_TEST_CONTRIBUTION,
    VCS_REWARD_CATEGORY_BUILD_REPRODUCTION,
    VCS_REWARD_CATEGORY_SECURITY_FIX,
    VCS_REWARD_CATEGORY_MAINTENANCE_90_DAY,
    VCS_REWARD_CATEGORY_REVIEW,
    VCS_REWARD_CATEGORY_COUNT
};

/* The scoring-table name (e.g. "security-fix"); "unknown" out of range. */
const char *vcs_reward_category_string(enum vcs_reward_category category);

/* The frozen band for one category (from vcs_score_category_table). */
void vcs_reward_category_band(enum vcs_reward_category category,
                              uint32_t *min_out, uint32_t *max_out,
                              bool *automatic_out);

enum vcs_reward_kind {
    VCS_REWARD_KIND_AUTO = 0, /* auto-derived from the slice-7 score */
    VCS_REWARD_KIND_CLAIM,    /* manual claim with an evidence root */
};

const char *vcs_reward_kind_string(enum vcs_reward_kind kind);

/* ── queue states ───────────────────────────────────────────────────── */

enum vcs_reward_state {
    VCS_REWARD_STATE_QUEUED = 0, /* persisted: awaiting settlement */
    VCS_REWARD_STATE_PLANNED,    /* DERIVED at load: named by an
                                    uncommitted plan (never persisted) */
    VCS_REWARD_STATE_SETTLED,    /* persisted: settled (simulated) */
    VCS_REWARD_STATE_REJECTED,   /* persisted: terminal, with a named rule */
};

const char *vcs_reward_state_string(enum vcs_reward_state state);

/* Named rules (the exact strings that appear in plans, receipts, and
 * rejections). */
#define VCS_REWARD_RULE_OWNER_REVIEW "owner-review-required"
#define VCS_REWARD_RULE_DUPLICATE "duplicate-reward"
#define VCS_REWARD_RULE_DAILY_CAP "daily-release-cap"
#define VCS_REWARD_RULE_WEEKLY_CAP "weekly-cap-exhausted"
#define VCS_REWARD_RULE_BATCH_FULL "batch-window-full"

/* ── entries (queue records) ────────────────────────────────────────── */

struct vcs_reward_entry {
    uint8_t entry_id[32]; /* domain-separated hash of the record below */
    enum vcs_reward_kind kind;
    enum vcs_reward_category category;
    uint8_t release_root[32];
    uint8_t contributor[33]; /* compressed secp256k1 pubkey */
    uint32_t points;         /* requested (band-validated at enqueue) */
    uint8_t facts_hash[32];  /* scoring facts hash (auto: caller's score
                                report; claim: derived from the evidence) */
    bool has_evidence_root;
    uint8_t evidence_root[32]; /* claims only */
    enum vcs_reward_state state;
    /* State detail. */
    uint8_t settled_by_plan[32]; /* SETTLED: the settling plan */
    int64_t settled_day;         /* SETTLED: the window day */
    uint8_t planned_by[32];      /* PLANNED (derived): earliest plan id */
    char rejected_rule[VCS_REWARD_RULE_MAX]; /* REJECTED: the named rule */
};

/* ── the ledger (rebuilt in memory from the durable wires) ──────────── */

struct vcs_reward_ledger;

/* Load and replay <zcode_dir>/rewards. Missing directories are an empty
 * ledger, never an error. Corrupt/oversize wires are skipped, logged, and
 * counted; over-bound directories stop the scan and set the truncated
 * flags. NULL only on allocation failure (logged). */
struct vcs_reward_ledger *vcs_reward_ledger_load(const char *zcode_dir);
void vcs_reward_ledger_free(struct vcs_reward_ledger *ledger);

size_t vcs_reward_ledger_entry_count(const struct vcs_reward_ledger *l);
size_t vcs_reward_ledger_fact_count(const struct vcs_reward_ledger *l);
uint32_t vcs_reward_ledger_corrupt_count(const struct vcs_reward_ledger *l);
bool vcs_reward_ledger_truncated(const struct vcs_reward_ledger *l);

/* Entries in ascending entry-id order (deterministic). Borrowed; invalid
 * after any mutation or free of the ledger. */
const struct vcs_reward_entry *vcs_reward_ledger_entry_at(
    const struct vcs_reward_ledger *l, size_t index);
const struct vcs_reward_entry *vcs_reward_ledger_find(
    const struct vcs_reward_ledger *l, const uint8_t entry_id[32]);

struct vcs_reward_queue_tally {
    uint32_t queued;
    uint32_t planned;  /* derived: named by an uncommitted plan */
    uint32_t settled;
    uint32_t rejected;
};

void vcs_reward_queue_tally(const struct vcs_reward_ledger *l,
                            struct vcs_reward_queue_tally *out);

/* ── enqueue (record kinds) ─────────────────────────────────────────── */

enum vcs_reward_enqueue_error {
    VCS_REWARD_ENQUEUE_OK = 0,
    VCS_REWARD_ENQUEUE_DUPLICATE,   /* same entry id known: dedup no-op */
    VCS_REWARD_ENQUEUE_BAD_CATEGORY,/* auto kind with a manual category or
                                       a claim with an automatic one */
    VCS_REWARD_ENQUEUE_BAND,        /* claim points outside the band */
    VCS_REWARD_ENQUEUE_ZERO_POINTS,
    VCS_REWARD_ENQUEUE_EVIDENCE,    /* claim without an evidence root */
    VCS_REWARD_ENQUEUE_BAD_INPUT,   /* null/zero required field */
    VCS_REWARD_ENQUEUE_FULL,        /* VCS_REWARD_MAX_QUEUE_ENTRIES */
    VCS_REWARD_ENQUEUE_IO,          /* durable write failed (logged) */
};

const char *vcs_reward_enqueue_error_string(
    enum vcs_reward_enqueue_error err);

/* Queue an auto-derived reward (kind AUTO) binding the slice-7 score:
 * `category` must be automatic (new-package / package-update /
 * test-contribution), `points` the score total (>0, at most
 * VCS_SCORE_MAX_TOTAL_PER_RELEASE), `facts_hash` a nonzero hash of the
 * score report. entry_id_out always receives the id (also on DUPLICATE). */
enum vcs_reward_enqueue_error vcs_reward_enqueue_auto(
    struct vcs_reward_ledger *l, const uint8_t release_root[32],
    const uint8_t contributor[33], enum vcs_reward_category category,
    uint32_t points, const uint8_t facts_hash[32],
    uint8_t entry_id_out[32]);

/* Queue a manual-category claim (kind CLAIM): `category` must be a manual
 * one, `points` strictly within its frozen band, `evidence_root` a nonzero
 * commitment to the claim's evidence package. Claims never settle in v1:
 * every plan blocks them with owner-review-required. */
enum vcs_reward_enqueue_error vcs_reward_enqueue_claim(
    struct vcs_reward_ledger *l, const uint8_t release_root[32],
    const uint8_t contributor[33], enum vcs_reward_category category,
    uint32_t points, const uint8_t evidence_root[32],
    uint8_t entry_id_out[32]);

/* ── plan (one settlement window batch) ─────────────────────────────── */

enum vcs_reward_disposition {
    VCS_REWARD_DISP_PLANNED = 0, /* in this batch */
    VCS_REWARD_DISP_DEFERRED,    /* cap-zeroed this window; stays queued */
    VCS_REWARD_DISP_BLOCKED,     /* owner-review-required (claims) */
    VCS_REWARD_DISP_DUPLICATE,   /* the ledger already settled this
                                    (release, contributor, category) */
};

const char *vcs_reward_disposition_string(enum vcs_reward_disposition d);

struct vcs_reward_plan_row {
    uint8_t entry_id[32];
    enum vcs_reward_disposition disposition;
    char rule[VCS_REWARD_RULE_MAX]; /* empty when PLANNED */
    uint32_t points_requested;
    uint32_t points_settled;        /* after the period caps */
    bool weekly_cap_clamped;        /* settled < requested via the cap */
};

struct vcs_reward_plan {
    int64_t day;                    /* the settlement window (civil day) */
    uint8_t plan_id[32];            /* hash of day + the planned rows */
    struct vcs_reward_plan_row *rows; /* every evaluated entry, entry-id
                                         order (allocated; plan_free) */
    size_t row_count;
    uint32_t planned_count;
    uint32_t deferred_count;
    uint32_t blocked_count;
    uint32_t duplicate_count;
    uint64_t points_total;          /* sum of settled points */
};

void vcs_reward_plan_free(struct vcs_reward_plan *plan);

/* Assemble the batch for one settlement window from every queued entry,
 * applying the slice-7 period caps against the ledger facts (batch-atomic:
 * entries planned earlier in the same window count against later ones).
 * Pure over the loaded ledger: nothing is persisted and the ledger is not
 * mutated. False on allocation failure (logged) or a negative day
 * (logged). */
bool vcs_reward_plan_build(const struct vcs_reward_ledger *l, int64_t day,
                           struct vcs_reward_plan *out);

enum vcs_reward_plan_persist_error {
    VCS_REWARD_PLAN_PERSIST_OK = 0,
    VCS_REWARD_PLAN_PERSIST_DUPLICATE, /* identical plan already durable */
    VCS_REWARD_PLAN_PERSIST_FULL,      /* VCS_REWARD_MAX_PLANS */
    VCS_REWARD_PLAN_PERSIST_IO,        /* durable write failed (logged) */
};

/* Persist the plan wire (the ONLY mutation planning ever makes). The same
 * window re-planned over the same ledger yields the same plan id and is a
 * dedup no-op. */
enum vcs_reward_plan_persist_error vcs_reward_plan_persist(
    struct vcs_reward_ledger *l, const struct vcs_reward_plan *plan);

/* ── commit (settle a planned batch, SIMULATED) ─────────────────────── */

enum vcs_reward_commit_error {
    VCS_REWARD_COMMIT_OK = 0,
    VCS_REWARD_COMMIT_UNKNOWN_PLAN,  /* no plan wire for this id */
    VCS_REWARD_COMMIT_ALREADY_SETTLED,/* commit record exists: duplicate,
                                         never a double-pay */
    VCS_REWARD_COMMIT_STALE,         /* an entry is missing, rejected, or
                                        settled by another plan */
    VCS_REWARD_COMMIT_CAPS_CHANGED,  /* the ledger moved since the plan;
                                        re-plan the window */
    VCS_REWARD_COMMIT_IO,            /* durable write failed (logged) */
};

const char *vcs_reward_commit_error_string(enum vcs_reward_commit_error e);

struct vcs_reward_commit_result {
    uint32_t settled_count;   /* entries settled (incl. replayed) */
    uint32_t rejected_count;  /* entries rejected at commit (duplicate) */
    uint64_t points_settled;  /* sum over settled entries */
    bool resumed;             /* a previous interrupted attempt replayed */
};

/* Settle a planned batch SIMULATED under the placeholder token id.
 * Re-validates every planned row against the CURRENT ledger (staleness,
 * duplicate-reward, and an exact cap recomputation) before writing; then
 * writes per-entry ledger facts, queue state updates, and the commit
 * record LAST (the idempotence authority). Replay-safe: a crash before
 * the commit record leaves a resumable partial state and re-committing
 * the same plan id finishes it with the identical outcome — never a
 * double-pay. On STALE/CAPS_CHANGED nothing is written; `detail`
 * (when non-NULL, detail_size bytes) names the offending entry/rule. */
enum vcs_reward_commit_error vcs_reward_commit(
    struct vcs_reward_ledger *l, const uint8_t plan_id[32],
    struct vcs_reward_commit_result *out, char *detail, size_t detail_size);

/* ── receipt (the durable evidence of a settled batch) ──────────────── */

enum vcs_reward_receipt_error {
    VCS_REWARD_RECEIPT_OK = 0,
    VCS_REWARD_RECEIPT_UNKNOWN_PLAN, /* no plan wire for this id */
    VCS_REWARD_RECEIPT_NOT_SETTLED,  /* planned but never committed */
    VCS_REWARD_RECEIPT_IO,           /* unreadable/corrupt record (logged) */
};

enum vcs_reward_receipt_outcome {
    VCS_REWARD_RECEIPT_SETTLED = 0,
    VCS_REWARD_RECEIPT_REJECTED,
};

struct vcs_reward_receipt_row {
    uint8_t entry_id[32];
    uint8_t contributor[33];
    enum vcs_reward_category category;
    enum vcs_reward_receipt_outcome outcome;
    char rule[VCS_REWARD_RULE_MAX]; /* REJECTED: the named rule */
    uint32_t points;                /* settled points (0 when rejected) */
};

struct vcs_reward_receipt {
    int64_t day;
    uint8_t plan_id[32];
    /* The placeholder token id — SIMULATION ONLY; the real ZSLP transfer
     * is slice 14. */
    uint8_t token_id[32];
    struct vcs_reward_receipt_row *rows; /* allocated; receipt_free */
    size_t row_count;
    uint32_t settled_count;
    uint32_t rejected_count;
    uint64_t points_total;
};

void vcs_reward_receipt_free(struct vcs_reward_receipt *receipt);

/* Read the durable receipt for a settled batch. */
enum vcs_reward_receipt_error vcs_reward_receipt_load(
    const struct vcs_reward_ledger *l, const uint8_t plan_id[32],
    struct vcs_reward_receipt *out);

/* ── fact access (the slice-9 rankings projection reads these) ──────── */

/* A read-only view of one SETTLED ledger fact. The fact carries NO
 * balance and no transfer semantics: it is an earned-score record
 * (contributor, category, settled points, settlement day) — the only
 * input rankings may ever use. */
struct vcs_reward_fact_view {
    uint8_t entry_id[32];
    uint8_t release_root[32];
    uint8_t contributor[33];
    enum vcs_reward_kind kind;
    enum vcs_reward_category category;
    uint32_t points; /* settled */
    int64_t day;     /* the settlement window (civil day number) */
    uint8_t facts_hash[32];
    uint8_t plan_id[32];
};

/* Copy the fact at `index` (0..vcs_reward_ledger_fact_count) into `out`.
 * False (logged) on NULL inputs or an out-of-range index. */
bool vcs_reward_ledger_fact_at(const struct vcs_reward_ledger *l,
                               size_t index,
                               struct vcs_reward_fact_view *out);

/* ── contributor totals (the zcode.contributor.show integration) ────── */

struct vcs_reward_contributor_totals {
    uint64_t earned_score;      /* settled score points — the ranking fact */
    uint64_t token_rewards_received; /* simulated placeholder-token amount
                                        settled — a SEPARATE fact, never a
                                        balance (balances arrive with the
                                        real token, slice 14) */
    uint32_t settled_entries;
    uint32_t queued_entries;    /* queued + planned, not yet earned */
    uint64_t queued_points;     /* requested points awaiting settlement */
    uint32_t rejected_entries;
};

void vcs_reward_contributor_totals(const struct vcs_reward_ledger *l,
                                   const uint8_t contributor[33],
                                   struct vcs_reward_contributor_totals *out);

#endif /* ZCL_VCS_PACKAGE_REWARD_H */
