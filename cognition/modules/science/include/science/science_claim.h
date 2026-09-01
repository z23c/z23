/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * science_claim — a register for claims about what makes a model write good
 * C23, in which a claim cannot be entered unless it says how it could be
 * shown wrong.
 *
 * WHY A REGISTER AND NOT A DOCUMENT
 * ---------------------------------
 * Everyone who has driven an LLM at a codebase has opinions about what helps:
 * give it the territory brief, give it the failing test first, cap the turn
 * count, hand it the diff instead of the file. Almost none of those opinions
 * were ever measured. They spread because they were repeated, which is the
 * mechanism by which folklore spreads, and a tree that wants 100M lines of
 * PROVEN C23 cannot be steered by folklore about how to write it.
 *
 * The difference between science and pseudoscience is not confidence and it
 * is not tone. It is whether the claim named, IN ADVANCE, an observation that
 * would sink it. A claim that survives because no result could have counted
 * against it has not survived anything. So this module puts the falsifier in
 * the constructor:
 *
 *   science_claim_register() REFUSES a claim that does not name
 *     - which measured number decides it            (metric, closed enum)
 *     - which way that number must move             (direction, up or down)
 *     - the smallest movement that would count      (effect_floor, > 0)
 *     - how many trials must exist first            (sample_floor, > 0)
 *
 * Each refusal names the missing field. There is deliberately no "record a
 * claim now, add the falsifier later" path: a claim without a falsifier is
 * not an incomplete claim, it is a different KIND of statement, and letting
 * it into the register would make every other row in the register mean less.
 *
 * A ZERO EFFECT FLOOR IS NOT A SMALL ONE
 * --------------------------------------
 * effect_floor = 0 is refused rather than accepted-and-warned. With a zero
 * floor every difference is an effect, so noise alone eventually "confirms"
 * the claim in one direction or the other and the claim can never come back
 * INCONCLUSIVE. That is unfalsifiable in practice even though it looks
 * rigorous, and it is the most common way a measured-looking process turns
 * into a rumour mill. Same for sample_floor = 0: a verdict readable off the
 * first trial is a verdict readable off luck.
 *
 * WHY THESE METRICS AND NO OTHERS
 * -------------------------------
 * `enum science_metric` is CLOSED, and science_metric_from_name() is the only
 * way to name one from text — an unrecognised string is refused, never stored.
 * A free-text metric is how "it felt faster" gets into a register wearing the
 * clothes of a measurement.
 *
 * Every metric here is a function of the `zcl.engine_unit.v1` receipt that
 * tools/engine_unit.c already writes for every dispatch, and each of those
 * fields is either counted by the harness or derived by engine_verdict_of().
 * Read that function's contract (engine/engine_verdict.h): it takes the gate's
 * own output, the count of files that actually changed, whether the clock ran
 * out, and whether a group was named. It takes NO exit code and NOTHING the
 * model said about itself. That is precisely why these numbers can serve as
 * evidence, and it is why no metric may ever be added here that depends on the
 * model's self-report — such a metric would let the thing under test grade its
 * own exam.
 *
 * `cost_usd` is in the receipt and is deliberately NOT a metric. It is a
 * vendor price list multiplied by a token count; the price list changes
 * without the model changing, so a claim measured in dollars would flip when
 * nothing about the treatment moved. Completion tokens are the measurement;
 * dollars are a quote. Floats are also barred from this module's canonical
 * bytes, and cost is the only float in the receipt.
 *
 * STATUS IS DERIVED, AND THERE IS NO SETTER
 * -----------------------------------------
 * Look at the API below: nothing takes an `enum science_status` as an input.
 * A claim's status is computed from its trials by science_claim_read() every
 * time it is asked for, and the only way to move it is to record a trial. If
 * a caller could write the status, the register would be recording beliefs
 * about the evidence rather than the evidence, and the first time those two
 * disagreed the register would side with the belief.
 *
 * ONE PRODUCER IS NOT FIVE
 * ------------------------
 * A claim whose every trial was run by its own author is a weak claim even
 * when the arithmetic is perfect: the author chose the tasks, the moment and
 * the arm. Every trial therefore records its producer, and every reading
 * reports how many DISTINCT producers contributed. The register never folds
 * that into the status — "SUPPORTED by 1 producer" and "SUPPORTED by 5" are
 * different facts and are reported as different facts.
 *
 * ARMS, AND WHY A CLAIM NEEDS BOTH
 * --------------------------------
 * A treatment can only raise something relative to not applying it, so each
 * trial is filed under SCIENCE_ARM_CONTROL or SCIENCE_ARM_TREATMENT and the
 * effect is treatment-minus-control. sample_floor is required in EACH arm:
 * fifty treatment trials and no control trials measure nothing at all, and a
 * register that read a verdict off them would be reporting the absolute level
 * of a metric as if it were the effect of a treatment.
 *
 * ARITHMETIC IS INTEGER, IN MILLI-UNITS
 * -------------------------------------
 * All metric values, floors and effects are int64 milli-units (1000 = one
 * unit; a pass rate of 42.5% is 425). No float enters the arithmetic or the
 * canonical bytes, so two machines replaying the same trials reach the same
 * status bit-for-bit. Rates are counted per thousand trials, means are
 * integer means, and SCIENCE_METRIC_TOKENS_PER_LANDED_FILE is a ratio of
 * arm TOTALS (sum tokens / sum landed files), never a mean of per-trial
 * ratios — the mean of ratios lets one tiny denominator dominate, and token
 * efficiency is a property of the arm's whole spend.
 *
 * That last metric has an undefined case that must not be papered over: an
 * arm that landed ZERO files spent tokens and produced nothing, so its
 * tokens-per-landed-file is a division by zero rather than a good score.
 * Silently dropping such trials would make a treatment that writes nothing
 * look infinitely efficient. The reading instead sets `effect_readable` to
 * false, names the reason, and reports SCIENCE_INCONCLUSIVE — the claim is
 * not supported, not refuted, and the caller can see it is unreadable rather
 * than merely small.
 *
 * DURABILITY
 * ----------
 * Claims and trials are appended to a chainlog (chainlog/chainlog.h): SHA3
 * per-frame links, a two-fsync commit sentinel, tamper-evident. Frame
 * payloads are canonical: big-endian, length-prefixed, no padding, no
 * timestamps and no paths, so identical content is identical bytes on any
 * machine and the chainlog's own `seq` is the only ordering. A claim's id is
 * SHA3-256 of its canonical bytes, which makes it content-addressed: the same
 * claim registered twice is the same id and the second registration is
 * refused as a duplicate rather than silently forking the evidence.
 *
 * THE FALSIFIER IS FIXED AT REGISTRATION, STRUCTURALLY
 * ----------------------------------------------------
 * Moving the effect floor after the results arrive is the oldest way to
 * manufacture a finding, so it is not discouraged here, it is impossible.
 * The claim id is SHA3-256 over canonical bytes that INCLUDE the metric, the
 * direction, the effect floor and the sample floor. An edited falsifier
 * therefore cannot be an edit: it hashes to a different id, and the original
 * claim and every trial filed under it stay exactly as recorded.
 *
 * That alone would still let someone register the moved-floor variant beside
 * the original and quote whichever one came out better, so the register also
 * refuses the restatement: a claim whose statement, treatment and metric
 * match one already registered, but whose direction, floor or sample floor
 * differ, is SCIENCE_REFUSED_RESTATED. The prediction a claim made before it
 * had any results is the only prediction it ever gets to have made.
 *
 * REPEATABLE BY A STRANGER, DATA NOT SUMMARIES, CHECKABLE WITHOUT TRUST
 * ---------------------------------------------------------------------
 * Three properties make a record an experiment rather than an anecdote, and
 * all three are enforced by the type system and the refusals, not by habit:
 *
 *   REPEATABLE. Every trial carries `struct science_repro`: the exact command
 *   line, the commit sha of the tree it ran on, the input or seed, and an
 *   environment fingerprint (compiler id and version, optimisation level,
 *   nproc, and whether ZCL_STRESS_TESTS was set). A trial missing any of them
 *   is refused at record time — never stored with a hole, because a hole is
 *   found later by someone who has already reasoned from the rows around it.
 *
 *   DATA. Every trial carries `struct science_samples`: n and the order
 *   statistics, with the unit named. A record that says "7031ms" and not how
 *   many runs that came from is a claim wearing a measurement's clothes. A
 *   run that produced no number says SCIENCE_UNAVAILABLE and why — "I could
 *   not measure" and "I measured zero" are different facts, and a schema that
 *   cannot tell them apart will eventually average them together.
 *
 *   CHECKABLE WITHOUT TRUST. science_claim_verify() and
 *   science_trial_verify() are pure functions of the record's bytes: no
 *   network, no lookup, nothing about who sent it. Ids are SHA3-256 over
 *   canonical bytes that are big-endian, length-prefixed, padding-free and
 *   float-free, so the same content encodes identically on any machine at any
 *   optimisation level — a property the gate pins with fixed golden vectors,
 *   which is the only way a single build can testify about another build. Any
 *   field that changes changes the id. This is what lets one node accept a
 *   result from another without either of them being an authority.
 *
 * A FALSIFIED HYPOTHESIS IS A SUCCESSFUL RECORD
 * ---------------------------------------------
 * SCIENCE_REFUTED is a first-class outcome, stored and reported exactly like
 * SCIENCE_SUPPORTED. A register that can only hold confirmations is not a
 * science register, it is a marketing file — and the seeded claims below
 * exist partly so that the first thing this tree does is put a popular belief
 * where it can lose.
 *
 * A CITATION IS NOT EVIDENCE
 * --------------------------
 * `source` records where a claim came from — a paper, a thread, a hunch. It
 * is provenance and nothing else. A claim carrying the most-cited citation in
 * the world still enters as SCIENCE_UNTESTED and stays there until trials
 * recorded IN THIS TREE reach its sample floor. Believing a result because it
 * was published somewhere is the same error as believing it because someone
 * said it confidently; the register treats both the same way.
 *
 * CONVERGENT PRIOR WORK
 * ---------------------
 * This design is not a local invention. Two 2026 papers arrived at the same
 * shape independently, which is worth recording both because convergence is
 * evidence and because the next reader should know the idea has been tested
 * outside this tree.
 *
 *   arXiv 2604.25850, "Agentic Harness Engineering: Observability-Driven
 *   Automatic Evolution of Coding-Agent Harnesses". Its third pillar is,
 *   verbatim: "decision observability pairs every edit with a self-declared
 *   prediction, later verified against the next round's task-level outcomes.
 *   Together, these pillars turn every edit into a falsifiable contract, so
 *   harness evolution proceeds autonomously without collapsing into
 *   trial-and-error." That is this module's rule reached separately: the
 *   prediction is declared BEFORE the outcome and is checked against a
 *   task-level number rather than against the model's account of itself.
 *   Reported result: ten iterations lifted pass@1 on Terminal-Bench 2 from
 *   69.7% to 77.0%, past a human-designed harness (Codex-CLI, 71.9%); the
 *   frozen harness transferred to SWE-bench-verified at 12% fewer tokens and
 *   gave +5.1 to +10.1pp cross-family gains on three other model families.
 *   Its ablation is the interesting part and is seeded into this register as
 *   an UNTESTED claim, not adopted: it localises the gain to tools,
 *   middleware and long-term memory rather than to the system prompt, which
 *   is the opposite of where prompt-tuning effort naturally goes.
 *
 *   arXiv 2606.05828, "Statistical Priors for Implicit Preferences:
 *   Decoupling Skill Selection as a Local Harness in Personal Agents", finds
 *   that decoupling local statistical selection from remote semantic parsing
 *   beats memory-augmented agents on cumulative regret and test accuracy.
 *   Also seeded as an UNTESTED claim; this tree's cookbook router will
 *   produce the trials that decide it here.
 *
 * Both are cited and both start UNTESTED. See science_seed_install().
 *
 * THIS MODULE GRANTS NOTHING. A SUPPORTED claim is evidence that a treatment
 * helped in the trials recorded. It is not permission, not a policy, and not
 * a reason to skip a gate.
 */

#ifndef ZCL_SCIENCE_CLAIM_H
#define ZCL_SCIENCE_CLAIM_H

#include "engine/engine_verdict.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SCIENCE_STATEMENT_MAX 256u
#define SCIENCE_TREATMENT_MAX 128u
#define SCIENCE_SOURCE_MAX    256u
#define SCIENCE_PRODUCER_MAX  64u
#define SCIENCE_FIELD_MAX     64u   /* engine, model, territory, group */
/* Reproduction block — what a stranger with only this repo needs. */
#define SCIENCE_COMMAND_MAX   512u
#define SCIENCE_COMMIT_MAX    64u
#define SCIENCE_INPUT_MAX     256u
#define SCIENCE_COMPILER_MAX  96u
#define SCIENCE_OPT_MAX       16u
/* Observation block. */
#define SCIENCE_UNIT_MAX      32u
#define SCIENCE_REASON_MAX    160u
#define SCIENCE_CLAIM_ID_BYTES 32u

/* Milli-units: 1000 == one unit of the metric. */
#define SCIENCE_MILLI 1000

/* Per-trial ranges. These exist so the integer arithmetic below cannot
 * overflow rather than as a judgement about plausible values: an arm sum is
 * bounded by CAP x MAX, and every sum is multiplied by SCIENCE_MILLI before
 * division. A billion completion tokens in one dispatch, or a million files
 * changed by one unit, is outside anything this harness can produce, so the
 * bound costs nothing real and a value past it is refused, never clamped. */
#define SCIENCE_TOKENS_MAX 1000000000LL
#define SCIENCE_FILES_MAX  1000000u

/* Fixed capacity. A register that silently forgot old evidence would answer
 * a different question than the one asked, so it refuses instead. */
#define SCIENCE_CLAIM_CAP  256u
#define SCIENCE_TRIAL_CAP  8192u

/* The closed metric set. Every entry is a function of zcl.engine_unit.v1 and
 * of nothing the model said about itself. Adding one is a deliberate edit to
 * this enum AND to science_metric_name(), which is a change a reviewer sees. */
enum science_metric {
    /* Fraction of dispatches whose verdict is a genuine pass, per
     * engine_verdict_is_pass(). Milli-units: 1000 == every trial passed. */
    SCIENCE_METRIC_VERDICT_PASS_RATE = 0,
    /* Mean files changed in the worktree. Answers "did it change anything at
     * all", which is the failure engine_verdict_of() calls NO_CHANGE. */
    SCIENCE_METRIC_FILES_CHANGED,
    /* Mean completion tokens: what the treatment costs in output. */
    SCIENCE_METRIC_COMPLETION_TOKENS,
    /* Arm total completion tokens divided by arm total files_changed: token
     * efficiency. Undefined when an arm landed nothing; see `effect_readable`. */
    SCIENCE_METRIC_TOKENS_PER_LANDED_FILE,
    /* Fraction of dispatches that looked green while running nothing —
     * ENGINE_VERDICT_HOLLOW. A treatment that raises this is making the
     * evidence worse even when the pass rate looks better. */
    SCIENCE_METRIC_HOLLOW_RATE,
    SCIENCE_METRIC_COUNT
};

/* Stable lowercase wire name, or "unknown_metric" for an out-of-range value.
 * Total: never returns NULL. */
const char *science_metric_name(enum science_metric metric);

/* The ONLY text-to-metric path. Returns false for anything not in the enum,
 * which is how a free-text metric is refused rather than stored. */
bool science_metric_from_name(const char *name, enum science_metric *out);

/* Which way the metric must move for the claim to hold. There is no
 * "changes" direction: a claim that is satisfied by movement either way
 * cannot be contradicted by movement either way. */
enum science_direction {
    SCIENCE_DIRECTION_NONE = 0,   /* refused; exists so 0 is not a valid claim */
    SCIENCE_DIRECTION_UP = 1,
    SCIENCE_DIRECTION_DOWN = 2
};
const char *science_direction_name(enum science_direction direction);

enum science_arm {
    SCIENCE_ARM_NONE = 0,         /* refused; exists so 0 is not a valid trial */
    SCIENCE_ARM_CONTROL = 1,      /* the treatment was NOT applied */
    SCIENCE_ARM_TREATMENT = 2     /* the treatment WAS applied */
};
const char *science_arm_name(enum science_arm arm);

/* Derived, never assigned. See "STATUS IS DERIVED" above. */
enum science_status {
    SCIENCE_UNTESTED = 0,      /* an arm has fewer trials than sample_floor */
    SCIENCE_SUPPORTED,         /* effect at/beyond the floor, stated direction */
    SCIENCE_REFUTED,           /* effect at/beyond the floor, OPPOSITE direction */
    SCIENCE_INCONCLUSIVE       /* effect inside the floor, or unreadable */
};
const char *science_status_name(enum science_status status);

/* Every way this module refuses. There is no generic failure: a refusal that
 * cannot name the field it refused on teaches the caller nothing. */
enum science_refusal {
    SCIENCE_OK = 0,
    SCIENCE_REFUSED_ARGUMENT,      /* a NULL where one is not allowed */
    SCIENCE_REFUSED_STATEMENT,     /* empty, or longer than the cap */
    SCIENCE_REFUSED_TREATMENT,     /* empty, or longer than the cap */
    SCIENCE_REFUSED_METRIC,        /* not a member of enum science_metric */
    SCIENCE_REFUSED_DIRECTION,     /* not UP and not DOWN */
    SCIENCE_REFUSED_EFFECT_FLOOR,  /* zero or negative: unfalsifiable */
    SCIENCE_REFUSED_SAMPLE_FLOOR,  /* zero: a verdict off the first trial */
    SCIENCE_REFUSED_ARM,           /* not CONTROL and not TREATMENT */
    SCIENCE_REFUSED_PRODUCER,      /* a trial with no producer is unattributed */
    SCIENCE_REFUSED_FIELD,         /* a receipt field outside its allowed range */
    SCIENCE_REFUSED_VERDICT,       /* not a member of enum engine_verdict */
    SCIENCE_REFUSED_SOURCE,        /* a citation longer than its cap */
    /* Reproduction. A trial missing any of these is refused, never stored
     * with a hole: a record a stranger cannot rerun is not an experiment. */
    SCIENCE_REFUSED_COMMAND,       /* no exact command line */
    SCIENCE_REFUSED_COMMIT,        /* no commit sha for the tree it ran on */
    SCIENCE_REFUSED_INPUT,         /* no input or seed */
    SCIENCE_REFUSED_COMPILER,      /* no compiler id + version */
    SCIENCE_REFUSED_OPTIMISATION,  /* no optimisation level */
    SCIENCE_REFUSED_NPROC,         /* zero cores is not an environment */
    /* Observation. */
    SCIENCE_REFUSED_AVAILABILITY,  /* neither OBSERVED nor UNAVAILABLE */
    SCIENCE_REFUSED_SAMPLES,       /* OBSERVED with n = 0, no unit, or order
                                    * statistics that are not in order */
    SCIENCE_REFUSED_REASON,        /* UNAVAILABLE without saying why */
    SCIENCE_REFUSED_DUPLICATE,     /* this exact claim is already registered */
    SCIENCE_REFUSED_RESTATED,      /* same claim, DIFFERENT falsifier: a floor
                                    * moved after results is a manufactured
                                    * finding, and the original prediction is
                                    * the only one that ever existed */
    SCIENCE_REFUSED_UNKNOWN_CLAIM, /* a trial for a claim nobody registered */
    SCIENCE_REFUSED_FULL,          /* the register's fixed capacity is spent */
    SCIENCE_REFUSED_STORAGE        /* the chainlog refused the append */
};
const char *science_refusal_name(enum science_refusal refusal);

/* What a claim asserts, and how it could be shown wrong. Every field is
 * required; science_claim_register() refuses on the first one missing, in the
 * order the fields are declared here. */
struct science_claim_spec {
    const char *statement;          /* what is asserted */
    const char *treatment;          /* the thing being varied */
    /* THE PREDICTION. These four are declared here, before any trial exists,
     * and are hashed into the claim id — so they cannot be edited later, only
     * restated as a different claim, which the register refuses. */
    enum science_metric metric;     /* which number decides it */
    enum science_direction direction;
    int64_t  effect_floor_milli;    /* smallest effect that would count, > 0 */
    uint32_t sample_floor;          /* trials required IN EACH ARM, > 0 */
    /* Provenance only, and optional: where the claim came from. A citation
     * never shortens the road to SUPPORTED. */
    const char *source;
};

/* WHAT A STRANGER NEEDS TO RERUN THIS, and every field is REQUIRED.
 *
 * An experiment nobody else can repeat is a story about an experiment. The
 * third party this block is written for has this repo and nothing else — not
 * our shell history, not our machine, not us to ask — so the record carries
 * the exact command, the tree it ran on, the input, and enough of the build
 * environment to know whether a different number is a real difference or a
 * different compiler. A trial missing any of these is REFUSED at record time
 * rather than stored with a hole, because a hole is discovered later, by
 * someone who has already drawn a conclusion from the rows around it. */
struct science_repro {
    const char *command;        /* the exact command line that was run */
    const char *commit;         /* commit sha of the tree it ran on */
    const char *input;          /* the input, seed, or fixture identity */
    const char *compiler;       /* compiler id + version, e.g. "gcc 13.3.0" */
    const char *optimisation;   /* "-O0", "-O2", ... */
    uint32_t    nproc;          /* cores the run actually had; > 0 */
    bool        stress_tests;   /* was ZCL_STRESS_TESTS set */
};

/* Could this be measured at all? These are two different facts and the
 * schema is required to tell them apart. Zero is a measurement. */
enum science_availability {
    SCIENCE_AVAILABILITY_NONE = 0, /* refused; 0 is never a valid record */
    SCIENCE_OBSERVED = 1,
    SCIENCE_UNAVAILABLE = 2        /* could not measure; NEVER encoded as 0 */
};
const char *science_availability_name(enum science_availability a);

/* THE DATA, NOT THE CONCLUSION.
 *
 * "7031ms" is a claim. "n=9, min 6.9s, median 7.0s, p95 7.4s, max 7.9s, unit
 * ms" is a measurement, and only the second one lets a stranger say whether
 * their rerun agrees. So a record stores the distribution it saw, and a run
 * that produced no number says SCIENCE_UNAVAILABLE with a reason rather than
 * reporting zero.
 *
 * These observations are DATA the record carries for comparison. They
 * deliberately do NOT feed the claim's status: the status is derived from the
 * receipt fields below, which engine_verdict_of() computed from the gate's
 * own output and which no participant chose. Letting a self-reported
 * distribution move a verdict would reopen the door this module exists to
 * close. */
struct science_samples {
    enum science_availability availability;
    const char *unit;           /* required when OBSERVED, e.g. "ms" */
    uint32_t n;                 /* sample count; > 0 when OBSERVED */
    int64_t  min_milli;         /* min <= median <= p95 <= max, in milli-units */
    int64_t  median_milli;
    int64_t  p95_milli;
    int64_t  max_milli;
    const char *reason;         /* required when UNAVAILABLE: why not */
};

/* One dispatch outcome, in the shape tools/engine_unit.c already emits as
 * zcl.engine_unit.v1, plus the reproduction and observation blocks above.
 * `cost_usd` is intentionally absent — see the header comment. The engine,
 * model, territory and group strings may be NULL, which records as empty;
 * `producer` is required, because an unattributed trial cannot be counted
 * toward the distinct-producer figure that keeps a self-confirmed claim
 * visible. */
struct science_receipt {
    const char *producer;           /* who ran the trial; required */
    enum science_arm arm;
    const char *engine;
    const char *model;
    const char *territory;
    const char *group;
    uint32_t files_changed;
    int32_t  groups_ran;
    int32_t  groups_failed;
    bool     cached;
    int64_t  prompt_tokens;
    int64_t  completion_tokens;
    enum engine_verdict verdict;
    struct science_repro   repro;   /* required, in full */
    struct science_samples observed; /* required; UNAVAILABLE is a valid answer */
};

/* One arm's measured level, in milli-units. */
struct science_arm_reading {
    uint32_t trials;
    int64_t  value_milli;    /* meaningless unless `defined` */
    bool     defined;        /* false only for a zero-denominator ratio */
    uint32_t producers;      /* distinct producers in THIS arm */
};

/* The whole answer for one claim. Filled entirely by science_claim_read();
 * nothing here is writable through the API. */
struct science_reading {
    enum science_status status;
    struct science_arm_reading control;
    struct science_arm_reading treatment;
    int64_t  effect_milli;      /* treatment - control; 0 when unreadable */
    bool     effect_readable;   /* false => status is INCONCLUSIVE by reason */
    const char *reason;         /* never NULL; why the status is what it is */
    uint32_t trials;            /* total trials on the claim */
    uint32_t producers;         /* DISTINCT producers across both arms */
    bool     single_producer;   /* producers <= 1: the claim confirms itself */
    /* Echo of the falsifier, so a reading can be read without the spec. */
    enum science_metric metric;
    enum science_direction direction;
    int64_t  effect_floor_milli;
    uint32_t sample_floor;
};

struct science_register;

/* What opening found. Filled on success and on failure both. */
struct science_open_report {
    enum science_refusal refusal;
    uint32_t claims;
    uint32_t trials;
    uint64_t frames;            /* chainlog records replayed */
    uint64_t torn_bytes;        /* uncommitted tail the chainlog discarded */
    int      chainlog_status;   /* enum zcl_chainlog_status, for the label */
};

/* Open (creating when absent) the claim register backed by the chainlog at
 * `path`, replaying every frame. `report` is required and is filled even when
 * this returns NULL. The caller owns the path: this module never chooses a
 * directory and never touches a node datadir. */
struct science_register *science_open(const char *path,
                                      struct science_open_report *report);
void science_close(struct science_register *reg);

/* Register a claim, refusing on the first missing falsifier. On success
 * `out_claim_id` (optional) receives SHA3-256 of the claim's canonical bytes.
 * Registering byte-identical content twice is SCIENCE_REFUSED_DUPLICATE. */
enum science_refusal science_claim_register(struct science_register *reg,
                                            const struct science_claim_spec *spec,
                                            uint8_t out_claim_id[32]);

/* Attach one dispatch outcome to a claim. This is the ONLY way a claim's
 * status can move. */
enum science_refusal science_trial_record(struct science_register *reg,
                                          const uint8_t claim_id[32],
                                          const struct science_receipt *receipt);

/* Compute the claim's status from its trials, now. Pure with respect to the
 * register: calling it never changes anything. */
enum science_refusal science_claim_read(const struct science_register *reg,
                                        const uint8_t claim_id[32],
                                        struct science_reading *out);

/* Enumeration, for a report over the whole register. */
uint32_t science_claim_count(const struct science_register *reg);
bool science_claim_id_at(const struct science_register *reg, uint32_t index,
                         uint8_t out_id[32]);
bool science_claim_spec_at(const struct science_register *reg, uint32_t index,
                           struct science_claim_spec *out,
                           char statement[SCIENCE_STATEMENT_MAX],
                           char treatment[SCIENCE_TREATMENT_MAX],
                           char source[SCIENCE_SOURCE_MAX]);

/* Canonical claim bytes, exposed so a test can prove the property the
 * durability rests on: identical content gives identical bytes, and any
 * differing field gives differing bytes. Returns the length written, or 0 on
 * refusal (buffer too small, or a spec that would be refused anyway). */
size_t science_claim_canonical(const struct science_claim_spec *spec,
                               uint8_t *out, size_t cap);
size_t science_trial_canonical(const uint8_t claim_id[32],
                               const struct science_receipt *receipt,
                               uint8_t *out, size_t cap);

/* SHA3-256 over science_claim_canonical(). The falsifier is inside those
 * bytes, which is what makes an edited floor a different claim rather than an
 * edit to this one. */
bool science_claim_id(const struct science_claim_spec *spec, uint8_t out[32]);

/* ── peer verification: checking a record without trusting who sent it ───
 *
 * This is the half that separates a science register from a lab notebook. A
 * record that arrives from another node is checked by the receiver ALONE:
 * these two functions are pure functions of the bytes. No network, no
 * lookup, no registry, no key, and no question about who sent it. If they
 * accept, the record is well-formed, carries every field a stranger needs to
 * rerun it, and its id is the hash of exactly these bytes.
 *
 * WHY THE LAYOUT PUTS THE HYPOTHESIS FIRST. A trial frame opens with the
 * version and then the 32-byte claim id, which commits to the whole
 * hypothesis — statement, treatment, metric, direction, effect floor, sample
 * floor — and every observation follows it. A record therefore cannot be
 * re-cut to make a prediction match an outcome after the fact: changing the
 * hypothesis changes the claim id, which changes the trial's own id, and the
 * receiver recomputes both. The prediction is upstream of the result in the
 * bytes, exactly as it was upstream in time.
 *
 * Both refuse rather than repair. A record that does not verify is evidence
 * about the sender, not about the world.
 */
bool science_claim_verify(const uint8_t *frame, size_t len, uint8_t out_id[32]);
bool science_trial_verify(const uint8_t *frame, size_t len,
                          uint8_t out_claim_id[32], uint8_t out_trial_id[32]);

/* SHA3-256 over science_trial_canonical(): the record's content address. */
bool science_trial_id(const uint8_t claim_id[32],
                      const struct science_receipt *receipt, uint8_t out[32]);

/* ── seeds ───────────────────────────────────────────────────────────────
 *
 * Findings from outside this tree, entered as claims TO BE TESTED HERE and
 * never as conclusions. Each carries its citation in `source` and each starts
 * SCIENCE_UNTESTED, because a paper's result is evidence about the tree the
 * paper measured. They exist so that the first thing this register does is
 * disbelieve something interesting rather than confirm something comfortable.
 */
uint32_t science_seed_count(void);
bool science_seed_at(uint32_t index, struct science_claim_spec *out);

/* Register every seed that is not already present. `added` and `already` are
 * optional. Returns the first refusal that was not a duplicate. */
enum science_refusal science_seed_install(struct science_register *reg,
                                          uint32_t *added, uint32_t *already);

#endif /* ZCL_SCIENCE_CLAIM_H */
