/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Typed blocker primitive — every "blocked" state in the codebase is
 * a typed record with a class, deadline, and escape action.
 *
 * Why this exists
 * ----------------
 * A bare string or bool for "blocked" cannot answer:
 *
 *   - Is this blocker recoverable, or permanent?
 *   - What's the deadline before something must escalate?
 *   - What's the escape action when the deadline lapses?
 *   - How many times has it re-fired? Is it spam?
 *
 * Without de-duplication and a durable class distinction, a blocker can
 * re-fire every few seconds for days while the supervisor keeps firing
 * recoveries against a recovery target that stays wedged behind a typeless
 * blocker with no escape.
 *
 * The primitive
 * --------------
 * A blocker is a typed record:
 *   - `class` ∈ {PERMANENT, TRANSIENT, DEPENDENCY, RESOURCE}
 *   - identity (`id`, `owner_subsystem`)
 *   - timing (`since_us`, `escape_deadline_us`, derived `age_us`)
 *   - escape (`escape_action` name; supervisor dispatches via name→fn)
 *   - retry accounting (`retry_count`, `retry_budget`)
 *   - reason (human + structured tail)
 *
 * Every site names a block by calling `blocker_set`
 * with a typed record. The primitive de-duplicates within a token-
 * bucket window (5/min default). A dedicated supervisor child
 * (`chain.blocker_escape`) sweeps the registry, calls the registered
 * `escape_action` on deadline edge.
 *
 * Modern-architecture analogues this implements:
 *   - Hystrix circuit breaker (closed/open/half-open), per-blocker
 *   - Saga compensations: every blocker NAMES its escape, no global handlers
 *   - Observability-driven (Charity Majors): the blocker IS the metric
 *   - Erlang/OTP supervisor signal-only restart: escape is a signal,
 *     child observes and acts on its own loop
 *
 * Ownership / threading rules
 * ----------------------------
 * The primitive owns a static fixed-cap registry (BLOCKER_CAP=128).
 * Records are COPIED into the registry on `blocker_set` — caller can
 * stack-allocate. Reads always go through `blocker_snapshot_all`
 * (copies under lock, releases before return). The supervisor child
 * snapshot-and-dispatches outside the lock; escape callbacks may
 * freely call any blocker_* function.
 *
 * Root-cause chaining
 * -------------------
 * Triage repeatedly surfaces two "unrelated" blockers that are
 * actually one root cause + one downstream symptom — e.g. an earlier
 * stage's body-read failure at height H means the coin that height
 * creates never enters coins_kv, so a much-later height's
 * script_validate.prevout_unresolved is not an independent fault, it is
 * the same fault observed one hop downstream. Every blocker record now
 * carries an optional `caused_by` (the id of the blocker judged to be
 * the root cause, empty = unknown/none) and a small `cause_detail`
 * string. Both are zero-filled by `blocker_init`, so every pre-existing
 * `blocker_set(&r)` call site is unaffected — the fields stay empty
 * unless a caller opts in via `blocker_set_with_cause`. A producer that
 * wants to wire an edge first calls the read-only
 * `blocker_find_by_id_prefix` to discover whether a plausible root
 * blocker is currently active, then calls `blocker_set_with_cause` if
 * so. The JSON dumper renders the chain and classifies each active
 * blocker as root / symptom / orphaned-symptom (root cleared while the
 * symptom, which clears on its own remedy, is still active). */

#ifndef ZCL_UTIL_BLOCKER_H
#define ZCL_UTIL_BLOCKER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BLOCKER_ID_MAX        64
#define BLOCKER_OWNER_MAX     40
/* 256 is measurably too small for four of this tree's own producers (they need
 * 280-361 bytes; see the reason-length contract on blocker_init). It is kept at
 * 256 anyway, and the honest reason is stack cost, not inertia: eleven call
 * sites declare `struct blocker_snapshot x[BLOCKER_CAP]` as a LOCAL, including
 * two request handlers on the 2 MiB API worker stack
 * (engine/controllers/src/api_controller.c pthread_attr_setstacksize). That array
 * is already 77 KiB per frame at 256; 512 makes it 109 KiB (+32 KiB per live
 * frame, plus +32 KiB in the static registry, which is free). Growing a 109 KiB
 * frame on a request path is not a trivially safe change, so the prerequisite
 * is moving those eleven arrays off the stack FIRST. Until then, producers with
 * a long reason use zcl_text_fit and lose a visibly-marked tail instead. */
#define BLOCKER_REASON_MAX    256
#define BLOCKER_ACTION_MAX    64
#define BLOCKER_CAP           128
#define BLOCKER_ESCAPE_CAP    32
#define BLOCKER_CAUSE_DETAIL_MAX 64

/* Default rate limit: a blocker_set with the same `id` more frequently
 * than this is suppressed (fire_count still increments). Tunable via
 * env `ZCL_BLOCKER_RATE_LIMIT_MS` for testing. */
#define BLOCKER_DEFAULT_RATE_LIMIT_MS  12000  /* 5/min */

/* Lifecycle policy for TRANSIENT-class blockers (see "Lifecycle policy"
 * below). Ignored for PERMANENT/DEPENDENCY/RESOURCE — those classes keep
 * their existing "persists until explicitly cleared" semantics unchanged.
 *
 *   BLOCKER_DEFAULT_TRANSIENT_TTL_SECS — a TRANSIENT blocker that has not
 *     re-fired (no blocker_set touch at all, rate-limited or not) within
 *     this window is stale evidence, not a live claim: the supervisor
 *     sweep retires it. Per-blocker overridable via
 *     `blocker_record.transient_ttl_secs` (0 = this default).
 *
 *   BLOCKER_MAX_DEADLINE_REARMS — a TRANSIENT blocker with an
 *     `escape_deadline_secs` but no `escape_action` (nothing to dispatch)
 *     cannot self-clear via the escape path. Rather than sit with a
 *     growing-negative `deadline_remaining_us` forever, the sweep re-arms
 *     the deadline this many times, then flags the blocker `escalated`
 *     (visible in the snapshot/dump) and stops re-arming. The TTL rule
 *     above still applies on top and eventually retires it once it goes
 *     quiet. */
#define BLOCKER_DEFAULT_TRANSIENT_TTL_SECS  1800   /* 30 min */
#define BLOCKER_MAX_DEADLINE_REARMS         3

enum blocker_class {
    BLOCKER_PERMANENT  = 0, /* bad PoW, malformed block, consensus reject
                             * — never auto-retry. Only operator clears. */
    BLOCKER_TRANSIENT  = 1, /* UTXO miss at the time, peer down, queue full
                             * — retry with bounded budget. Default class. */
    BLOCKER_DEPENDENCY = 2, /* waiting on subsystem X — escalate to X's
                             * supervisor child. Escape fires X's escape. */
    BLOCKER_RESOURCE   = 3, /* OOM, disk full, fd exhaustion — operator
                             * action required; escape opens circuit. */
};

const char *blocker_class_name(enum blocker_class c);

/* Caller-owned template. Pass to blocker_set; the registry COPIES it. */
struct blocker_record {
    char     id[BLOCKER_ID_MAX];
    char     owner_subsystem[BLOCKER_OWNER_MAX];
    enum blocker_class class;
    int64_t  escape_deadline_secs;    /* relative from since_us; 0 = none */
    char     escape_action[BLOCKER_ACTION_MAX];
    int32_t  retry_budget;            /* -1 = unbounded (PERMANENT only) */
    char     reason[BLOCKER_REASON_MAX];
    int64_t  transient_ttl_secs;      /* TRANSIENT-only; 0 = default
                                        * (BLOCKER_DEFAULT_TRANSIENT_TTL_SECS).
                                        * Ignored for other classes. */
    /* ADDITIVE (see "Root-cause chaining" above). `blocker_init` zeroes
     * both to empty; existing callers that only ever call `blocker_set`
     * are unaffected. Set via `blocker_set_with_cause`. */
    char     caused_by[BLOCKER_ID_MAX];              /* root-cause blocker id, or "" */
    char     cause_detail[BLOCKER_CAUSE_DETAIL_MAX]; /* small stable detail, or "" */
};

/* ── Reason-length contract ───────────────────────────────────────────
 *
 * A reason longer than BLOCKER_REASON_MAX-1 is still truncated and the call
 * still SUCCEEDS — refusing to name a stall because the sentence ran long
 * would trade a diagnosis for silence, which is the one thing this primitive
 * exists to prevent. What is no longer true is that the cut is invisible:
 * blocker_init routes the reason through zcl_text_fit (base/text_fit.h), which
 *   - leaves a visible `...[cut <len>/256]` marker at the end of the stored
 *     text, so `dumpstate blocker` shows the reader the field is partial, and
 *   - logs one WARN line carrying the FULL untruncated reason, so nothing is
 *     actually lost.
 *
 * WHERE THIS DOES NOT REACH: most producers do not hand blocker_init a long
 * string. They format into their own `char reason[BLOCKER_REASON_MAX]` local
 * and pass an already-cut 255-byte fragment, and by then no callee can tell.
 * A producer whose format can exceed 255 bytes must therefore build into an
 * oversized scratch buffer and call zcl_text_fit itself; four sites in this
 * tree measured 280-361 bytes on their live paths and now do exactly that.
 * A one-line reason with no interpolated path/hash/nested-reason needs nothing.
 *
 * blocker_set's own two `snprintf(s->reason, ..., r->reason)` copies need no
 * guard and deliberately do not have one: `r->reason` is itself a
 * char[BLOCKER_REASON_MAX], so those are equal-capacity field copies that
 * cannot cut. A guard there could never fire, and a guard that cannot fire
 * advertises a protection that does not exist.
 *
 * A cut reason also has one non-cosmetic consequence worth knowing: blocker_set
 * keys fault IDENTITY partly on `reason` (see its comment), so two genuinely
 * different faults whose reasons agree for the first 255 bytes look like one
 * live fault and share an escalation clock. Keeping the distinguishing detail
 * EARLY in the sentence, not in a trailing clause, is what avoids that.
 *
 * Convenience initializer; zeroes the struct and fills required fields,
 * then defaults retry_budget (-1 for PERMANENT, else 0).
 * Return contract:
 *   false — `out`, `id`, or `owner` is NULL, or `id`/`owner` would not
 *           fit (>= BLOCKER_ID_MAX / BLOCKER_OWNER_MAX). The offending
 *           case is logged via LOG_FAIL; `out` may be partially written.
 *   true  — fields stored. `reason` is optional (NULL leaves it empty); an
 *           over-long reason is truncated-and-reported per the contract
 *           above, never rejected. */
bool blocker_init(struct blocker_record *out,
                  const char *id,
                  const char *owner,
                  enum blocker_class class,
                  const char *reason);

/* Set or refresh a blocker. If `r->id` already exists in the registry:
 *   - rate-limited: if last set < rate-limit, only fire_count++; returns 1
 *   - otherwise: replaces fields, fire_count++, since_us untouched; returns 0
 * If new: inserts a record, since_us = now, retry_count = 0; returns 0.
 * Capacity exhaustion → logs LOG_FAIL and returns -1.
 *
 * Return code contract:
 *   0  — fresh write stored (caller may emit event)
 *   1  — rate-limited dup (caller SHOULD suppress event emission)
 *  -1  — error (bad input, cap exhausted) */
int blocker_set(const struct blocker_record *r);

/* Fire-and-forget naming helper for the common "no cheap rung applies —
 * escalate to a named, retry-forever dependency" shape used by several
 * recovery-fallback call sites (sticky_escalator, rewind_driver,
 * recovery_coordinator). Builds a BLOCKER_DEPENDENCY record via
 * `blocker_init`, forces `retry_budget = -1` (unbounded — never
 * auto-expired), and calls `blocker_set`. Silently no-ops if `blocker_init`
 * rejects the id/owner (already logged via LOG_FAIL there). Not for
 * BLOCKER_PERMANENT page-once call sites — those have a different shape. */
static inline void blocker_name_dependency(const char *id, const char *owner,
                                           const char *reason)
{
    struct blocker_record b;
    if (blocker_init(&b, id, owner, BLOCKER_DEPENDENCY, reason)) {
        b.retry_budget = -1;
        (void)blocker_set(&b);
    }
}

/* Additive variant of blocker_set: same storage/rate-limit/return contract,
 * plus records a root-cause edge. `caused_by` is the id of the blocker
 * judged to be the root cause; NULL or "" means no known cause (identical
 * behavior to plain blocker_set). `cause_detail` is optional small stable
 * text describing the edge (e.g. the downstream height); NULL leaves it
 * empty. No existence check is performed on `caused_by` here — the caller
 * is expected to have looked it up first (see blocker_find_by_id_prefix);
 * the dumper flags an edge whose target is no longer active as an
 * "orphaned symptom" rather than silently clearing the symptom.
 * Return contract identical to blocker_set; -1 also on caused_by too long
 * (>= BLOCKER_ID_MAX). */
int blocker_set_with_cause(const struct blocker_record *r,
                           const char *caused_by,
                           const char *cause_detail);

/* Mark a retry attempt against a blocker. Increments retry_count. For a
 * subsystem that retries on its OWN loop; blocker_supervisor_sweep already
 * charges every escape dispatch it makes, so an escape-driven remedy must
 * not double-count by calling this too. */
void blocker_record_retry(const char *id);

/* Remove a blocker. No-op if not present. */
void blocker_clear(const char *id);

/* Test existence + class. Returns -1 if absent. */
int  blocker_class_for(const char *id);

bool blocker_exists(const char *id);

/* Snapshot view for read-side consumers. */
struct blocker_snapshot {
    char     id[BLOCKER_ID_MAX];
    char     owner_subsystem[BLOCKER_OWNER_MAX];
    int      class;                            /* enum blocker_class */
    int64_t  since_us;
    int64_t  age_us;                           /* now - since_us */
    int64_t  escape_deadline_us;               /* absolute deadline, or 0 */
    int64_t  deadline_remaining_us;            /* signed; negative if elapsed */
    char     escape_action[BLOCKER_ACTION_MAX];
    int32_t  retry_count;
    int32_t  retry_budget;
    uint32_t fire_count;
    char     reason[BLOCKER_REASON_MAX];
    bool     escalated;                /* TRANSIENT-only: bounded deadline
                                         * re-arm budget exhausted; needs an
                                         * owner look, never auto-cleared. */
    int32_t  deadline_rearm_count;
    char     caused_by[BLOCKER_ID_MAX];              /* root-cause blocker id, or "" */
    char     cause_detail[BLOCKER_CAUSE_DETAIL_MAX]; /* small stable detail, or "" */
};

/* Copy up to `max` snapshots into `out`. Returns count actually written. */
int blocker_snapshot_all(struct blocker_snapshot *out, int max);

/* Read-only lookup: the first active blocker whose id starts with
 * `id_prefix` (registry scan order — stable within a generation, not
 * insertion-order guaranteed across clears/re-inserts). Copies into `out`.
 * Returns false (out untouched) when id_prefix is NULL/empty, out is NULL,
 * or no active blocker matches. Intended for producers that want to
 * discover a live root-cause blocker before calling
 * blocker_set_with_cause — e.g. a defer path checking whether an upstream
 * stage is currently held on a body-read failure. */
bool blocker_find_by_id_prefix(const char *id_prefix,
                               struct blocker_snapshot *out);

/* Same locked registry copy with the metadata that belongs to that exact
 * snapshot.  `generation_out` advances on every observable registry change;
 * consumers can bind counts/rendering to one captured generation instead of
 * combining independent read calls.  Optional metadata pointers may be NULL. */
int blocker_snapshot_all_with_meta(struct blocker_snapshot *out, int max,
                                   uint64_t *generation_out,
                                   int *escape_dispatched_out,
                                   int *rate_limit_ms_out);

/* Causal operator-status ordering. Resource exhaustion remains the highest
 * generic class; the two shielded-history gaps outrank other permanent
 * symptoms (for example script_validate.prevout_unresolved) because those
 * downstream symptoms cannot be cured until the missing consensus history is
 * restored. All status surfaces use this one selector so they cannot disagree
 * about the primary blocker. The returned pointer aliases caller-owned
 * `snapshots` and remains valid only as long as that array does. */
int blocker_causal_priority(enum blocker_class c, const char *id);
const struct blocker_snapshot *blocker_select_dominant(
    const struct blocker_snapshot *snapshots, int count);

/* Count of active blockers in a class. */
int blocker_count_by_class(enum blocker_class c);

/* Total active blockers. */
int blocker_count_active(void);

/* ── Lifecycle policy — TTL retirement + deadline escalation ─────────
 * A blocker is a live claim, not a log line: the two rules above (TTL
 * retirement, bounded deadline re-arm) are enforced by
 * blocker_supervisor_sweep(). Retirement is never a silent delete — it is
 * counted and the most recent instance is retained for the dump. */

struct blocker_retirement_info {
    bool     valid;                    /* false if nothing retired yet */
    char     id[BLOCKER_ID_MAX];
    char     owner_subsystem[BLOCKER_OWNER_MAX];
    int64_t  retired_at_us;
    uint32_t fire_count_at_retirement;
    char     reason[BLOCKER_REASON_MAX];
};

/* Monotonic count of TRANSIENT blockers TTL-retired since module init /
 * last test reset. Exposed via `dumpstate blocker` as
 * `transient_retired_total`. */
uint32_t blocker_retired_transient_count(void);

/* Most recent TTL retirement. Returns false (out->valid = false) if none
 * has happened yet. */
bool blocker_last_retired(struct blocker_retirement_info *out);

/* JSON dumper backing `z23 dumpstate blocker`.
 * Caller initializes `out` with json_set_object before calling. */
struct json_value;
bool blocker_dump_state_json(struct json_value *out, const char *key);

/* Escape dispatcher.
 * Subsystems register an action name → function. On deadline edge,
 * supervisor sweep dispatches; missing actions log a warning but do
 * not crash. Callback receives a SNAPSHOT (not a live record). */
typedef void (*blocker_escape_fn)(const struct blocker_snapshot *snap);

/* Register `action_name` → `fn`. Caller-owned name pointer must be
 * static-lifetime (interned). Up to BLOCKER_ESCAPE_CAP entries; returns
 * false on overflow or duplicate. */
bool blocker_register_escape(const char *action_name, blocker_escape_fn fn);

/* Look up the function registered for an action name. NULL if unknown. */
blocker_escape_fn blocker_lookup_escape(const char *action_name);

/* ── Hand-off resolution — "named" is only half of it ─────────────────
 * Naming a blocker is necessary but not sufficient. A blocker with an
 * empty `escape_action` and a zero `retry_budget` announces a problem and
 * offers the reader nothing to do about it; repeated eleven thousand
 * times that is a stuck horn, and a stuck horn trains an operator to
 * ignore alarms — which destroys the value of the honest-failure design.
 *
 * The build already enforces that every raisable blocker id declares a
 * remedy: engine/conditions/include/conditions/blocker_remedy_bindings.def
 * (gate tools/scripts/check_blocker_remedy.sh) binds each id/pattern to a
 * condition-engine healer, an ESCAPE(action), or the honest token OWNER.
 * That table was BUILD-time only — it never reached the operator reading
 * `dumpstate blocker`. These three calls carry it to runtime.
 *
 * The primitive deliberately does not know the table (it lives in
 * lib/util; the table lives in app/). The app layer installs a resolver at
 * boot, exactly like `blocker_register_escape` installs escape functions.
 * With no resolver installed every blocker resolves UNKNOWN, which is the
 * pre-existing behaviour rendered honestly rather than silently.
 *
 * Strings returned by a resolver must be STATIC-lifetime (they alias the
 * app-layer tables); the caller never frees them. */
enum blocker_handoff_kind {
    BLOCKER_HANDOFF_UNKNOWN   = 0, /* no resolver installed / id not bound */
    BLOCKER_HANDOFF_AUTOMATIC = 1, /* a condition healer or a registered
                                     * ESCAPE action attempts a cure */
    BLOCKER_HANDOFF_HUMAN     = 2, /* OWNER: no auto-remedy exists; a person
                                     * must decide. `decision` states what. */
};

const char *blocker_handoff_kind_name(enum blocker_handoff_kind k);

struct blocker_handoff {
    enum blocker_handoff_kind kind;
    const char *remedy;    /* condition name / "ESCAPE(action)" / "OWNER"; "" */
    const char *decision;  /* for HUMAN: the decision the operator must make,
                             * spelled out with its tradeoff. "" when the id is
                             * bound OWNER but no decision text is declared yet
                             * — counted as visible debt, never hidden. */
};

typedef bool (*blocker_handoff_resolver_fn)(const char *id,
                                            struct blocker_handoff *out);

/* Install (or, with NULL, remove) the process-wide resolver. Idempotent. */
void blocker_set_handoff_resolver(blocker_handoff_resolver_fn fn);

/* Resolve `id`. Always fills `out` (UNKNOWN + empty strings when there is
 * no resolver or the id is unbound). Returns true when a binding was
 * found. Safe to call from any thread. */
bool blocker_resolve_handoff(const char *id, struct blocker_handoff *out);

/* A HUMAN-handoff blocker older than this has been handed off and is
 * waiting on a person; the dump reports it as `standing` so a long-lived
 * hand-off is visibly distinct from a fresh alarm. */
#define BLOCKER_STANDING_AGE_SECS 3600

/* Sweep registry once. Three passes, TRANSIENT-class only for the first
 * two (PERMANENT/DEPENDENCY/RESOURCE semantics are untouched):
 *   1. TTL retirement — a TRANSIENT blocker inactive past its TTL is
 *      removed and counted (see blocker_retired_transient_count).
 *   2. Deadline re-arm/escalate — a TRANSIENT blocker with an overdue
 *      escape_deadline_us but no escape_action (nothing to dispatch) is
 *      re-armed up to BLOCKER_MAX_DEADLINE_REARMS times, then marked
 *      `escalated` instead of sitting with a growing-negative deadline.
 *   3. Escape dispatch: for each blocker whose escape_deadline_us has
 *      elapsed and whose escape has not yet fired in the current deadline
 *      crossing, with a registered escape_action, fire the escape.
 *      Edge-triggered — the per-crossing latch is re-armed by blocker_set
 *      whenever it anchors a fresh deadline horizon, so a still-live
 *      blocker keeps getting its remedy driven instead of dispatching once
 *      per registry lifetime. Each dispatch CHARGES the record's retry
 *      budget (retry_count++); a blocker with a finite budget
 *      (retry_budget > 0) stops dispatching once it is spent. -1 is
 *      unbounded and 0 means "no bound requested" (blocker_init's default
 *      for non-PERMANENT), neither of which is charged against.
 * Returns the number of escapes dispatched (pass 3 only, unchanged
 * return contract). Intended for a supervisor child running ~1 Hz. */
int blocker_supervisor_sweep(void);

/* Monotonic count of escape dispatches since module init. Exposed through
 * Prometheus and native blocker diagnostics. */
int blocker_escape_dispatched_count(void);

/* Lifecycle: init at boot, before any blocker_set call. shutdown is
 * idempotent. */
bool blocker_module_init(void);
void blocker_module_shutdown(void);

/* Test hooks — wipe state, override clock, query private counters. */
void blocker_reset_for_testing(void);
void blocker_set_clock_for_testing(int64_t now_us);
void blocker_advance_clock_for_testing(int64_t delta_us);
uint32_t blocker_fire_count_for_testing(const char *id);
void blocker_set_rate_limit_ms_for_testing(int ms);

#endif /* ZCL_UTIL_BLOCKER_H */
