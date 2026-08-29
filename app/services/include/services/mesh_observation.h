/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * mesh_observation — the C23 mesh OBSERVATION surface.
 *
 * WHY THIS EXISTS
 * ---------------
 * Mesh verification used to be pronounced by a privileged shell judge run
 * from one box's crontab: it graded the fleet and published a scalar verdict
 * every other reader was expected to trust. That is authority in three
 * separate ways — if that box stops, nobody reaches a verdict; the verdict
 * it emitted (n/4) is one nobody else could derive alone; and readers had to
 * TRUST the conclusion rather than RECOMPUTE it.
 *
 * This surface is the replacement, and it ships in the portable binary every
 * node already runs. Each node publishes ONLY what IT observed. Any reader
 * folds the records it collected into a conclusion IT derives, against ITS
 * OWN validated chain. No box is the judge.
 *
 * WHAT IS AND IS NOT IN A RECORD
 * ------------------------------
 * A record has exactly three kinds of field and no fourth:
 *   1. identity              — who is speaking
 *   2. a measurement with its budget attached — {outcome, stage,
 *      elapsed_us, deadline_us}; never a bare boolean, never a bare duration
 *   3. a claim labelled as a claim — claimed_height / claimed_tip_hash_hex /
 *      claim_age_us, beside claim_verified_locally, which is the EMITTER's
 *      own recomputation of that claim against its own chain
 *
 * There is no `pass`, no `fail`, no `verdict`, no `healthy`, no `n/4`, and
 * deliberately no `reachable: bool` — that field is exactly where "slow"
 * silently becomes "failed".
 *
 * FOUR STANDING RULINGS THIS HEADER ENCODES
 * -----------------------------------------
 *  R1 VERDICTS COMPOSE, NEVER COLLAPSE. The primitive emits a tuple; only a
 *     READER collapses it, and it keeps reachability, freshness, timing and
 *     chain agreement as SEPARATE dimensions.
 *  R2 TIMING IS TELEMETRY, NEVER A GATE INPUT. Two boxes on this fleet are
 *     8-core 7200-rpm HDD machines measured at 91% IO pressure. A threshold
 *     that grades them failed for being slow is a hardware franchise. That
 *     is why mesh_observation_compose() below receives no fsync_us, no
 *     pread_us, no min_ping_us and no stage_elapsed_us: a franchise is not
 *     merely discouraged there, it does not COMPILE.
 *  R3 ANNOUNCEMENTS ARE PROMISES. READY only once descriptor, rendezvous,
 *     circuit and listen are ALL confirmed; every partial stage is its own
 *     named state.
 *  R4 NO VACUOUS PASSES. A conclusion computed over zero items reports
 *     UNVERIFIED, never healthy.
 *
 * E13-NEUTRAL BY CONSTRUCTION: this lives in app/ (the reader/observer
 * layer), never in core/ or lib/validation/. It reports. It never gates
 * block acceptance, and nothing here feeds the systemd watchdog.
 */

#ifndef ZCL_SERVICES_MESH_OBSERVATION_H
#define ZCL_SERVICES_MESH_OBSERVATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "net/netaddr.h"   /* NET_SERVICE_KEY_SIZE */
#include "util/result.h"

struct json_value;

#define MESH_OBS_SCHEMA        "zcl.mesh.observation.v1"
#define MESH_OBS_EDGES_MAX     32   /* connman's connection ceiling */
#define MESH_OBS_ANCHORS       5
#define MESH_OBS_KEYHEX        (NET_SERVICE_KEY_SIZE * 2 + 1)  /* 71 */
#define MESH_OBS_ONION_MAX     64   /* "<56>.onion" + NUL, with slack */
#define MESH_OBS_REASON_MAX    32
#define MESH_OBS_HEXHASH       65   /* 64 hex + NUL */
/* A build-target token — "linux", "macos", "windows", "arm64", "x86_64".
 * Bounded because it arrives from an UNTRUSTED emitter. */
#define MESH_OBS_PLATFORM_MAX  16

/* The largest observation document this build will parse. A peer document
 * is UNTRUSTED input; refusing an oversized body BY NAME is cheaper and
 * more honest than growing a buffer for it. */
#define MESH_OBS_DOC_MAX       (64u * 1024u)

/* The reader-side collector ring. Fixed; nothing grows. */
#define MESH_OBS_SLOTS_MAX     8

/* ── Outcomes ───────────────────────────────────────────────────────────
 *
 * FOUR outcomes, and a deadline may only ever produce the fourth. Ordering
 * is deliberate: NOT_PROBED is 0, so a zeroed struct reads "I did not look",
 * never "it failed". */
enum mesh_obs_outcome {
    MESH_OBS_NOT_PROBED = 0,  /* I did not look. Reachability is MEANINGLESS
                               * here — it is not a negative result.        */
    MESH_OBS_CONFIRMED  = 1,  /* positive evidence: bytes arrived.          */
    MESH_OBS_REFUSED    = 2,  /* positive COUNTER-evidence: RST, protocol
                               * reject, or a contradicting hash. SILENCE IS
                               * NEVER REFUSED.                             */
    MESH_OBS_DEADLINE   = 3,  /* my budget ran out. Always carries elapsed_us
                               * AND deadline_us so a reader re-derives with
                               * its own budget. No composition may map this
                               * to REFUSED and it enters no failure tally.  */
    MESH_OBS_OUTCOME_NUM
};

/* ── Promise ladder (R3) ────────────────────────────────────────────────
 *
 * The first five rungs are the LISTENER's promise about our own onion:
 * READY is reachable only after descriptor + rendezvous + circuit + listen.
 * The remaining rungs are a per-edge dial/handshake ladder. Both share one
 * enum so `stage` always means "the furthest stage actually CONFIRMED". */
enum mesh_obs_stage {
    MESH_STAGE_NONE = 0,
    MESH_STAGE_DESCRIPTOR,
    MESH_STAGE_RENDEZVOUS,
    MESH_STAGE_CIRCUIT,
    MESH_STAGE_LISTEN,
    MESH_STAGE_READY,
    MESH_STAGE_DIALED,
    MESH_STAGE_VERSION_SENT,
    MESH_STAGE_VERSION_RECVD,
    MESH_STAGE_VERACK,
    MESH_STAGE_HANDSHAKE_COMPLETE,
    MESH_STAGE_SERVING,
    MESH_STAGE_NUM
};

/* Static tokens — enums cross the wire as NAMES, never as integers, so a
 * reader on an older build sees "deadline_expired" and can refuse it BY NAME
 * instead of mis-decoding a number. */
const char *mesh_obs_stage_name(enum mesh_obs_stage s);
const char *mesh_obs_outcome_name(enum mesh_obs_outcome o);
bool mesh_obs_stage_from_name(const char *name, enum mesh_obs_stage *out);
bool mesh_obs_outcome_from_name(const char *name, enum mesh_obs_outcome *out);

/* This binary's own build target. Compile-time constants; never "" — a
 * target this source does not name reports "unknown", which is a real
 * answer and is distinguishable from an emitter that said nothing. */
const char *mesh_obs_platform_os(void);
const char *mesh_obs_platform_arch(void);

/* DELIBERATELY NOT AN ENUM. Stage and outcome are closed sets this build
 * defines, so an unrecognised token there is a genuine protocol error and
 * is refused by name. The set of operating systems is NOT closed: refusing
 * a whole document because its emitter runs something this build has never
 * heard of would make the mesh un-extensible, and would silently drop the
 * first node of every new platform — the exact failure this field exists to
 * prevent. So an unknown token is CARRIED VERBATIM, and only a malformed
 * one is refused. Valid: "" (said nothing), or 1..MESH_OBS_PLATFORM_MAX-1
 * characters of [a-z0-9_]. */
bool mesh_obs_platform_token_ok(const char *tok);

/* ── The recompute handle ───────────────────────────────────────────────
 *
 * Fixed offsets BACK from this node's own tip, so two nodes a few blocks
 * apart still share a comparable height. Without the ladder a one-block lead
 * would make every pair uncheckable. */
/* {0, 1, 6, 30, 144} */
extern const int32_t MESH_OBS_ANCHOR_BACK[MESH_OBS_ANCHORS];

struct mesh_obs_anchor {
    int64_t height;
    char    hash_hex[MESH_OBS_HEXHASH];
    bool    present;
};

/* ── What this node says about ITSELF ───────────────────────────────── */
struct mesh_obs_self {
    char    schema[32];                  /* MESH_OBS_SCHEMA                */
    char    onion[MESH_OBS_ONION_MAX];   /* "" when we have no onion yet   */
    char    source_id[MESH_OBS_HEXHASH]; /* build identity of the emitter  */

    /* PLATFORM TRUTH. `tor_stub_build` alone cannot carry it: a Linux box
     * built with plain `make` and a macOS box whose PLATFORM has no
     * embedded Tor at all emit the identical `true`. One is an operator
     * mistake a rebuild fixes; the other is a permanent property of that
     * machine. A reader that cannot tell them apart has to guess, and a
     * fleet view built on that guess is wrong about which boxes can ever
     * be reached. These two tokens are what makes the difference readable.
     *
     * Compile-time constants of the emitting binary, exactly like
     * source_id: they read no file, no environment variable and no working
     * directory, so they answer "what was this executable built for", never
     * "what is this process sitting on right now".
     *
     * "" means the emitter did not say — a real value, never upgraded to a
     * guess. WEIGHTED, NEVER GATED: like every capability field below,
     * mesh_observation_compose() may not branch on either of them. */
    char    os[MESH_OBS_PLATFORM_MAX];
    char    arch[MESH_OBS_PLATFORM_MAX];

    /* chain position — every field recomputable by a reader */
    int64_t tip_height;
    char    tip_hash_hex[MESH_OBS_HEXHASH];
    char    tip_chainwork_hex[MESH_OBS_HEXHASH];
    int64_t tip_time_unix;
    struct mesh_obs_anchor anchors[MESH_OBS_ANCHORS];

    int32_t provable_tip;
    bool    provable_tip_published;  /* separates a real 0 from "not folded" */
    int32_t reducer_floor;

    /* Identity-free minority-work instrument. TELEMETRY, never a grade.
     * arrival_window_blocks == 0 means REFUSED TO JUDGE, not "fine". */
    int64_t implied_hashrate_ratio_milli;
    int32_t arrival_window_blocks;

    /* the promise ladder for MY OWN listener (R3) */
    enum mesh_obs_stage listen_stage;
    bool    tor_requested;
    bool    tor_stub_build;

    /* Self-declared capability, published so a reader may WEIGHT. It is
     * structurally impossible for it to gate: mesh_observation_compose()
     * never receives it. -1 is published AS -1, never as 0. */
    int32_t cores;
    int64_t ram_bytes;
    bool    rotational_known;
    bool    rotational;
    int64_t fsync_us;
    int64_t pread_us;
    char    hw_fingerprint[17];

    /* the sample's own cost */
    int64_t sampled_unix;
    int64_t sampled_monotonic_us;
    int64_t sample_elapsed_us;
    bool    lock_contended;              /* EXPECTED on a contended box    */
    char    unavailable_reason[MESH_OBS_REASON_MAX]; /* static token when a
                                                      * field is dark      */
};

/* ── One row of the adjacency matrix: MY edge to one peer ───────────────
 *
 * Nobody publishes the matrix. A reader composes it from N rows. That is
 * exactly why no single box's 1xN slice can ever be published AS the matrix
 * again. */
struct mesh_obs_edge {
    /* net_service_get_key(): the ONLY identity that distinguishes two
     * onions. Deliberately NOT net_addr_get_group() — that returns the
     * identical key 030f for EVERY torv3 address, so any "distinct groups"
     * bar is unreachable on an onion-only fleet. */
    char    peer_key_hex[MESH_OBS_KEYHEX];
    char    peer_onion[MESH_OBS_ONION_MAX]; /* "" for clearnet; never an IP */
    bool    inbound;

    enum mesh_obs_outcome transport;
    enum mesh_obs_stage   stage;        /* furthest CONFIRMED stage         */
    int64_t stage_elapsed_us;
    int64_t deadline_us;                /* so a reader re-derives with its
                                         * own budget                       */
    int64_t last_recv_age_us;
    int64_t last_send_age_us;
    int64_t connected_age_us;
    int64_t min_ping_us;                /* telemetry, never judged          */

    /* what the peer CLAIMED, kept apart from what I verified */
    int64_t claimed_height;             /* -1 unknown                       */
    char    claimed_tip_hash_hex[MESH_OBS_HEXHASH]; /* "" unknown           */
    int64_t claim_age_us;
    bool    claim_verified_locally;     /* I HAVE that hash at that height  */
    enum mesh_obs_outcome header_service;
};

struct mesh_observation {
    struct mesh_obs_self self;
    struct mesh_obs_edge edges[MESH_OBS_EDGES_MAX];
    /* coverage — reported so a truncated or partly unreadable sample can
     * never look like a complete one */
    int32_t edge_count;
    int32_t edges_truncated;
    int32_t rows_unreadable;
};

/* ── Producer (in-node) ─────────────────────────────────────────────────
 *
 * The sampler reads atomics and takes exactly ONE zcl_mutex_trylock on
 * connman's cs_nodes. Losing that trylock is EXPECTED on a contended box:
 * it sets self.lock_contended, keeps the previous tick's edge rows, and
 * increments rows_unreadable. It NEVER publishes a zero in place of an
 * unread value. No allocation, no DB read, no fsync, O(peers <= 32). */
/* Supervised child, >= 5 s cadence. */
struct zcl_result mesh_observation_register_sampler(void);
void mesh_observation_unregister_sampler(void);
void mesh_observation_sample_once(void);        /* test-callable, no thread */

/* memcpy under a LEAF mutex. false ONLY before the first tick has landed —
 * an unsampled node says "I have nothing", never an empty-but-healthy
 * document. */
bool mesh_observation_snapshot(struct mesh_observation *out);

/* ── Serialization (lib/json only; no new dependency) ───────────────────
 *
 * ONE emitter feeds both the dumpstate body and the served document, so the
 * two can never drift. */
bool mesh_observation_emit_json(const struct mesh_observation *rec,
                                struct json_value *out);

/* Bounded parse of an UNTRUSTED peer document. On any refusal it returns
 * false, writes a distinct static token into reason_out, and leaves *out
 * completely unmodified. A malformed field is never guessed. */
bool mesh_observation_parse_json(const char *body, size_t len,
                                 struct mesh_observation *out,
                                 char reason_out[MESH_OBS_REASON_MAX]);

/* ── Collector (reader side, its OWN thread) ────────────────────────────
 *
 * One blocking onion fetch at a time, one target per round, >= 60 s between
 * rounds, on a dedicated thread — NEVER the shared tick runner, which must
 * never carry blocking I/O. */
struct mesh_obs_slot {
    char    onion[MESH_OBS_ONION_MAX];
    enum mesh_obs_outcome fetch;
    int64_t fetched_unix;
    int64_t elapsed_us;
    int64_t deadline_us;
    bool    parsed;
    char    refusal[MESH_OBS_REASON_MAX];
    struct mesh_observation rec;
};

struct zcl_result mesh_observation_collect_register(void);
void mesh_observation_collect_unregister(void);
int  mesh_observation_collect_snapshot(struct mesh_obs_slot *out, size_t max);
/* Seed one fetch target (an onion, ".onion" suffix optional). Bounded set;
 * a repeat target is a no-op. Returns false when the target set is full or
 * the input is not a usable onion. */
bool mesh_observation_collect_add_target(const char *onion);

/* ── Composer — PURE. The reader derives; nobody pronounces. ────────────
 *
 * No I/O, no locks, no allocation, no globals, no clock read (the reader
 * passes now_unix). Every reader running the same build over the same N
 * records and the same chain gets the same answer, and can replay it
 * offline from the saved documents. The reader's own record is simply
 * slot 0 — it holds no privilege of any kind. */
struct mesh_compose_budget {
    int64_t freshness_secs;   /* default 900 */
    /* COVERAGE, not security: "did I hear from more than myself". Four boxes
     * provisioned by one operator from one build are not four independent
     * parties, and no composition rule can manufacture independence that
     * does not exist. Do NOT read this as an anti-Sybil bar. */
    int     min_independent;  /* default 2 */
};
#define MESH_OBS_FRESHNESS_SECS_DEFAULT 900
#define MESH_OBS_MIN_INDEPENDENT_DEFAULT 2
void mesh_compose_budget_defaults(struct mesh_compose_budget *b);

/* What the READER can look up in ITS OWN validated chain. hash_at returns
 * false when the reader does not hold that height — which is evidence
 * NEITHER way, and is reported as such. */
struct mesh_reader_chain {
    int64_t tip_height;
    char    tip_chainwork_hex[MESH_OBS_HEXHASH];
    bool  (*hash_at)(void *ctx, int64_t height, char out[MESH_OBS_HEXHASH]);
    void   *ctx;
};

enum mesh_state {
    MESH_UNVERIFIED = 0,
    MESH_AGREEING,
    MESH_DISAGREEING,
    MESH_SPLIT_VIEW,
    MESH_STATE_NUM
};
const char *mesh_state_name(enum mesh_state s);

struct mesh_conclusion {
    /* 1. COVERAGE — computed and reported FIRST, always */
    int32_t records_offered;
    int32_t records_parsed;
    int32_t records_fresh;
    int32_t records_silent;
    int32_t records_not_probed;
    int32_t records_malformed;
    int32_t records_stale;

    /* 2. INDEPENDENCE — by identity, NOT by address group */
    int32_t distinct_identities;
    int32_t min_independent_required;   /* the control in force, echoed */

    /* 3. RECOMPUTED CHAIN AGREEMENT — three tallies, NEVER summed */
    int32_t agree_at_anchor;
    int32_t disagree_at_anchor;
    int32_t no_common_height;           /* reader cannot check: evidence
                                         * NEITHER way                    */
    int64_t checked_height;             /* the anchor height actually used */
    char    reader_hash_at_checked[MESH_OBS_HEXHASH];

    /* 4. ADJACENCY — composed here, published by nobody. Reported, and it
     *    NEVER feeds `state`. */
    int32_t edges_asserted;
    int32_t edges_reciprocated;
    int32_t edges_one_sided;
    int32_t edges_contradicted;

    /* 5. WORK */
    char    max_chainwork_hex[MESH_OBS_HEXHASH];
    bool    reader_holds_max_chainwork;

    /* 6. THE STATE, plus the arithmetic that produced it */
    enum mesh_state state;
    char    basis[96];   /* static token + the counts, so a reader with a
                          * different budget re-derives without re-fetching */
};

/* THE fold. See mesh_observation_compose.c for the step-by-step contract.
 * Note what this signature does NOT accept: no fsync_us, no pread_us, no
 * min_ping_us, no stage_elapsed_us, no cores, no rotational. That is R2
 * enforced by the compiler rather than by a promise. `os` and `arch` reach
 * this function only inside a slot's record, and it may not branch on
 * either: a platform is something a reader WEIGHTS, never a bar a machine
 * can be graded against. test_mesh_observation_compose pins that. */
void mesh_observation_compose(const struct mesh_obs_slot *slots, size_t n,
                              const struct mesh_reader_chain *reader,
                              const struct mesh_compose_budget *budget,
                              int64_t now_unix,
                              struct mesh_conclusion *out);

#endif /* ZCL_SERVICES_MESH_OBSERVATION_H */
