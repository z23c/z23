/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: measure the 144-loop MVP experiment — read the Claude session
 *          transcripts and the plan of record, and emit the machine
 *          artifacts the experiment is scored on (agents.tsv, loops.tsv,
 *          snapshots.tsv, kpi.tsv, the progress render). The testable core
 *          carries no main(); tools/dev/mvp_ledger_main.c is the CLI shim
 *          built into build/bin/z23-mvp-ledger.
 *
 * CONTRACT. ~/.local/state/zclassic23/experiments/mvp144/EXPERIMENT.md
 * defines the universe (144 loops), t0, and what a loop costs. This header
 * fixes the SHAPE of the answer; nothing here is hand-typed — every number
 * is folded from a transcript line or a plan line.
 *
 * REFUSALS. A malformed input is refused BY LINE NUMBER with a named
 * reason, never guessed at and never silently skipped:
 *   mvl_line_too_long      a transcript/plan line longer than MVL_LINE_CAP
 *   mvl_bad_json           a transcript line that is not one JSON value
 *   mvl_not_object         a transcript line whose value is not an object
 *   mvl_no_type            a transcript line with no string "type" field
 *   mvl_no_timestamp       an assistant line with no string "timestamp"
 *   mvl_bad_timestamp      a timestamp that is not ISO-8601 UTC
 *   mvl_plan_field         a plan loop line missing state=/loop=/evidence=
 *   mvl_tsv_fields         an agents.tsv row without MVL_AGENT_COLUMNS cells
 *   mvl_tsv_header         an agents/snapshots/kpi .tsv header that differs
 *                          from the one this build writes
 *   mvl_overflow           more rows than the bounded tables hold
 * There is no unbounded growth: line length is capped, every table is a
 * fixed count fixed by these enums, and refusing is always the answer to
 * an input that would exceed one.
 *
 * One refusal does NOT stop the run, because it is a fact about one plan
 * row rather than a malformed input:
 *   sweep_group_unregistered  a row whose evidence is ONLY=<group> naming a
 *                          group the catalog at the ancestry ref does not
 *                          register. The row counts as UNVERIFIED and the
 *                          refusal is reported against its plan line.
 *
 * ATTRIBUTION. An agent's lane comes from its description, by exactly seven
 * rules (see mvl_classify_description). Descriptions outside those rules
 * land in kind "other" with lane "-": their cost is still summed into every
 * total, it is simply not attributed to a loop. That gap is visible rather
 * than hidden — agents.tsv shows exactly which agents were not attributed.
 *
 * EVIDENCE. A plan row's evidence= field is not free text to this tool: its
 * SHAPE decides what it can prove (see enum mvl_evidence_kind). A commit or
 * a commit range is proved by the ancestry list; `ONLY=<group>` is proved by
 * the test-group catalog at that same ref — a sweep is how the experiment
 * verifies a loop whose capability already existed, so it is part of the
 * definition, not a hole in it. A doc path proves nothing and never will.
 * Every one of those inputs is a FILE the caller produced with one git
 * command, so no verdict here depends on a subprocess this tool ran. */
#ifndef ZCL_TOOLS_DEV_MVP_LEDGER_H
#define ZCL_TOOLS_DEV_MVP_LEDGER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

enum {
    MVL_ID_CAP = 48,
    MVL_DESC_CAP = 256,
    MVL_LANE_CAP = 64,
    MVL_KIND_CAP = 16,
    MVL_MODEL_CAP = 48,
    MVL_UTC_CAP = 32,
    MVL_OUTCOME_CAP = 16,
    MVL_ID_TEXT_CAP = 32,
    MVL_TITLE_CAP = 192,
    MVL_STATE_CAP = 24,
    MVL_EVIDENCE_CAP = 160,
    MVL_PATH_CAP = 1024,
    MVL_ERR_CAP = 512,

    /* A transcript line longer than this is refused. The largest line in
     * the measured session is 128 550 bytes, so this is four times the
     * observed worst case and still a hard bound. */
    MVL_LINE_CAP = 524288,

    MVL_MAX_AGENTS = 1024,
    MVL_MAX_LOOPS = 512,
    MVL_MAX_MILESTONES = 64,
    MVL_MAX_TRAIN_LANES = 512,
    MVL_MAX_ANCESTRY = 200000,
    MVL_MAX_NAMES = 4096,       /* registered test groups, or known lanes */

    MVL_AGENT_COLUMNS = 18,
    MVL_MILESTONE_LOOPS = 12,   /* the plan's loops per milestone */
    MVL_TOTAL_BAR_WIDTH = 48,   /* the MVP bar, in characters */

    /* --session is repeatable: each occurrence names one more session
     * directory to fold into the same agents table, so `agents`, `loops`
     * and `kpi` sum every listed session's tokens into one denominator. */
    MVL_MAX_SESSIONS = 32,
};

/* Plan states, in the order the progress bar paints them. MVL_STATE_OTHER
 * is not painted: it counts toward the universe and toward nothing else,
 * which is exactly what the stopgap renderer does with an unknown state. */
enum mvl_state {
    MVL_STATE_LANDED = 0,
    MVL_STATE_TRAIN,
    MVL_STATE_READY,
    MVL_STATE_IN_FLIGHT,
    MVL_STATE_DESIGNING,
    MVL_STATE_VERIFY_FIRST,
    MVL_STATE_QUEUED,
    MVL_STATE_DROPPED,
    MVL_STATE_OTHER,
    MVL_STATE_COUNT,
};

/* One measured agent: one Claude subagent transcript, or the orchestrator's
 * own session transcript. Every count is a sum over that file's assistant
 * lines. */
struct mvl_agent {
    char agent_id[MVL_ID_CAP];
    char description[MVL_DESC_CAP];
    char lane[MVL_LANE_CAP];
    char kind[MVL_KIND_CAP];
    char model[MVL_MODEL_CAP];
    char first_utc[MVL_UTC_CAP];
    char last_utc[MVL_UTC_CAP];
    char outcome[MVL_OUTCOME_CAP];
    /* Scratch, not a column: the transcript splits ONE API request across
     * one assistant line per content block, and every one of those lines
     * repeats the SAME `usage` object. Folding them all would multiply the
     * request's tokens by its block count, so usage is folded once per
     * requestId. A request's blocks are written contiguously. */
    char last_request[MVL_ID_CAP];
    /* Claude Code writes a `<total_tokens>N tokens left` reminder into the
     * transcript. The difference between the first and last one an agent
     * saw is the harness's OWN accounting of what that agent spent, and it
     * is the number the task notification reports — so it is the bridge
     * between this tool and any hand-copied notification figure. It is a
     * lower bound: the turns before the first reminder are not in it. */
    int64_t budget_first;
    int64_t budget_last;
    int64_t first_unix;
    int64_t last_unix;
    int64_t turns;
    int64_t tool_uses;
    int64_t tokens_out;
    int64_t thinking_tokens;
    int64_t tokens_in;              /* input + cache_creation + cache_read */
    int64_t tokens_input;
    int64_t tokens_cache_creation;
    int64_t tokens_cache_read;
};

struct mvl_agents {
    struct mvl_agent *rows;
    size_t count;
    size_t cap;
};

/* What a plan row's evidence= field IS, and therefore what it can prove.
 * The shape is decided by reading the text, never by trusting the row's
 * hand-set state=. */
enum mvl_evidence_kind {
    MVL_EVIDENCE_NONE = 0,  /* "-" or empty: proves nothing */
    MVL_EVIDENCE_COMMIT,    /* one sha, or a comma-separated list of them:
                             * landed when EVERY one is an ancestor */
    MVL_EVIDENCE_RANGE,     /* `a..b`: landed when `b` is an ancestor. `a` is
                             * where the work started and proves nothing. */
    MVL_EVIDENCE_SWEEP,     /* `ONLY=<group>`: verified when <group> is a
                             * registered test group at the ancestry ref */
    MVL_EVIDENCE_OTHER,     /* a doc path, a workflow id, a file:line — real
                             * work, but never a proof that a loop is done */
};

/* How a loop came to be verified, in the order the KPI prefers them. A
 * loop is verified when this is LANDED, SWEEP or VERDICT; the two SWEEP_
 * refusals are reasons a sweep row is NOT verified, kept apart from a plain
 * "no" so a reader can tell "the group is gone" from "nobody asked". */
enum mvl_verified_by {
    MVL_VERIFIED_NO = 0,
    MVL_VERIFIED_LANDED,
    MVL_VERIFIED_SWEEP,
    MVL_VERIFIED_VERDICT,
    MVL_VERIFIED_SWEEP_UNREGISTERED,
    MVL_VERIFIED_SWEEP_NOT_ASKED,
};

/* One plan loop line. `counted` is true for the rows the 144-loop universe
 * is made of: `    L<dd> ` exactly, which is the stopgap renderer's own
 * regex. A letter-suffixed row (L02b) is an extra evidence line under the
 * same plan loop — parsed, joined, never double-counted. */
struct mvl_loop {
    char id[MVL_ID_TEXT_CAP];
    char title[MVL_TITLE_CAP];
    char state[MVL_STATE_CAP];
    char lane[MVL_LANE_CAP];
    char evidence[MVL_EVIDENCE_CAP];
    /* The agent an `INDEPENDENT REVIEW by <agent>` note names, anywhere in
     * the row. Empty when nobody independent looked: the XP game pays an
     * unreviewed author half, and never pays a review nobody wrote. */
    char reviewer[MVL_LANE_CAP];
    size_t line_no;                 /* the plan line, so a refusal names it */
    int milestone;
    int feature;                    /* index into mvl_plan.features, or -1 */
    enum mvl_state state_id;
    bool counted;
};

/* A bounded set of names: the registered test groups at a ref, the lane
 * directories that exist, the lanes a verifier landed. Membership only —
 * order is the order they were read. */
struct mvl_names {
    char (*rows)[MVL_LANE_CAP];
    size_t count;
    size_t cap;
};

/* Everything outside the plan that a loop's status is decided against.
 * Every field may be absent, and absent is never "no": it is "not asked",
 * which the columns and the refusals report as such. */
struct mvl_evidence_world {
    const char (*ancestry)[MVL_ID_CAP];
    size_t ancestry_count;
    const struct mvl_names *verdict_lanes;  /* LAND VERDICT at or after t0 */
    const struct mvl_names *groups;         /* registered at the ref */
};

struct mvl_milestone {
    char id[8];
    char title[MVL_TITLE_CAP];
    int64_t counts[MVL_STATE_COUNT];
    size_t line_no;
    /* The milestone's OWN line carries state=ACCEPTED. Child completion
     * alone never closes a parent, so nothing else opens milestone XP. */
    bool accepted;
};

/* One feature line. It exists so a parent can be scored on its own
 * acceptance rather than on its children's: `accepted` is the only thing
 * that opens feature XP, exactly as the milestone rule reads. */
struct mvl_feature {
    char id[8];
    char title[MVL_TITLE_CAP];
    size_t line_no;
    int milestone;
    bool accepted;
};

struct mvl_plan {
    struct mvl_milestone *milestones;
    size_t milestone_count;
    struct mvl_feature *features;
    size_t feature_count;
    struct mvl_loop *loops;
    size_t loop_count;
    int64_t totals[MVL_STATE_COUNT];
    int64_t universe;               /* rows with counted == true */
};

/* One joined loop row: the loop, plus every agent whose lane is the loop's
 * lane, plus this loop's even share of its train assembler and of the design
 * workflows whose id its evidence names. */
struct mvl_join {
    int64_t agents;
    int64_t tokens_out;
    int64_t tokens_in;              /* input + cache_creation + cache_read */
    int64_t tool_uses;
    int64_t wall_s;
    int64_t verifier_rounds;
    char first_utc[MVL_UTC_CAP];
    char last_utc[MVL_UTC_CAP];
    int landed;                     /* 1 yes, 0 no, -1 not asked */
    enum mvl_verified_by verified_by;
};

/* ── bounded, caller-owned tables ─────────────────────────────────────── */

/* Allocate the fixed tables zeroed, and release them. There is no growth
 * path on purpose: an input with more rows than the table holds is refused
 * (mvl_overflow), never absorbed. */
bool mvl_agents_alloc(struct mvl_agents *agents);
void mvl_agents_free(struct mvl_agents *agents);
bool mvl_plan_alloc(struct mvl_plan *plan);
void mvl_plan_free(struct mvl_plan *plan);

/* ── session scanning (mode `agents`) ──────────────────────────────────── */

/* Parses "YYYY-MM-DDTHH:MM:SS[.fff]Z" into Unix seconds. Fractional seconds
 * are accepted and truncated; anything else is refused. */
bool mvl_parse_timestamp(const char *s, int64_t *out);

/* Derives (lane, kind) from an agent's description, by exactly seven rules:
 *   "Lane <name>[: …]"       → <name>,  build
 *   "Resume <name> lane …"   → <name>,  build
 *   "Re-verify <name> …"     → <name>,  verify
 *   "Verify <name> …"        → <name>,  verify
 *   "Assemble train <n> …"   → train<n>, assemble
 *   "Fix …" / "Resurrect …"  → the first word that names a lane in `known`,
 *                              or "-" when none does, and kind fix
 *   anything else            → "-",     other
 * `known` may be NULL, in which case a Fix/Resurrect row is still kind fix
 * with lane "-" — the work is named, its lane is simply not asserted.
 * A workflow agent has no description; its caller assigns (workflow id,
 * design) directly. */
void mvl_classify_description(const char *desc, const struct mvl_names *known,
                              char *lane, size_t lane_cap, char *kind,
                              size_t kind_cap);

/* ── bounded name sets ────────────────────────────────────────────────── */

bool mvl_names_alloc(struct mvl_names *names, size_t cap);
void mvl_names_free(struct mvl_names *names);
bool mvl_names_add(struct mvl_names *names, const char *name);
bool mvl_names_has(const struct mvl_names *names, const char *name);

/* Every directory name under `lanes_dir` and under `scratch_dir` — the two
 * places a lane leaves a directory behind. A missing directory contributes
 * nothing and is not an error: a box with no lanes has no lanes. */
bool mvl_read_lane_names(const char *lanes_dir, const char *scratch_dir,
                         struct mvl_names *out, char *err, size_t err_cap);

/* Every `ZCL_TEST_GROUP(<name>)` in a test_group_catalog.def. The caller
 * produces the file with one `git show <ref>:tools/dev/test_group_catalog.def`
 * so the sweep decision is made against the SAME ref the ancestry came from,
 * and this tool still runs no subprocess. */
bool mvl_read_groups(const char *path, struct mvl_names *out, char *err,
                     size_t err_cap);

/* Matches one assistant message's text against the outcome vocabulary, in
 * priority order: "LAND <sha>", "FIX <sha>", "READY", "BLOCKED", else "-".
 * A sha is at least seven hex characters. */
const char *mvl_match_outcome(const char *text);

/* Folds one transcript line into `agent`. Non-assistant lines are read and
 * ignored (they still have to parse). `line_no` is 1-based and appears in
 * `err`. Returns false on any refusal named in this header's REFUSALS
 * block. */
bool mvl_fold_line(const char *line, size_t line_no, struct mvl_agent *agent,
                   char *err, size_t err_cap);

/* Folds one whole transcript file. `agent` is zeroed first; `agent_id`,
 * `description`, `lane` and `kind` are copied in by the caller afterwards
 * when it knows them. */
bool mvl_scan_transcript(const char *path, struct mvl_agent *agent,
                         char *err, size_t err_cap);

/* Scans `<session>/subagents/agent-*.jsonl`, then every
 * `<session>/subagents/workflows/<wf>/agent-*.jsonl`, then the orchestrator's
 * own `<session>.jsonl`, appending one row each to `out` in that order. */
bool mvl_scan_session(const char *session_dir, const struct mvl_names *known,
                      struct mvl_agents *out, char *err, size_t err_cap);

/* agents.tsv: one header line plus one row per agent, tab separated. */
bool mvl_write_agents(const char *path, const struct mvl_agents *agents,
                      char *err, size_t err_cap);
bool mvl_read_agents(const char *path, struct mvl_agents *out,
                     char *err, size_t err_cap);
const char *mvl_agents_header(void);

/* ── the plan of record (modes `loops`, `snapshot`, `progress`) ────────── */

bool mvl_parse_plan(const char *path, struct mvl_plan *out,
                    char *err, size_t err_cap);

/* Renders the milestone bars and the MVP bar. Byte-for-byte the output of
 * the stopgap renderer scratch/northstar/progress.sh, which this replaces.
 * Returns the number of bytes the full render would occupy (snprintf
 * semantics), so a caller can detect truncation. */
size_t mvl_render_progress(const struct mvl_plan *plan, char *out,
                           size_t out_cap);

/* The one-line cost tail `progress` prints when a session was given. */
size_t mvl_render_cost(const struct mvl_agents *agents, char *out,
                       size_t out_cap);

/* ── joining agents to loops (mode `loops`) ───────────────────────────── */

/* Reads a `late_picks.txt` and appends its first-column lane names to
 * `lanes`. Comment and blank lines are skipped. */
bool mvl_read_train_lanes(const char *path, struct mvl_names *lanes,
                          char *err, size_t err_cap);

/* Reads one `git rev-list <origin/main>` output into `out`, one full sha per
 * line. This is the whole of the tool's git knowledge: it runs no
 * subprocess, so `loops --ancestry` is reproducible from a file and the
 * ancestry decision is auditable. */
bool mvl_read_ancestry(const char *path, char (*out)[MVL_ID_CAP], size_t cap,
                       size_t *count, char *err, size_t err_cap);

/* Reads `evidence` and says what shape it is. Text alone decides. */
enum mvl_evidence_kind mvl_evidence_kind_of(const char *evidence);

/* True when `evidence` is a commit or a commit range that the ancestry list
 * contains: every sha of a comma-separated list, or the RIGHT side of a
 * `a..b` range. A sweep, a doc path and an empty field are never landed. */
bool mvl_evidence_landed(const char *evidence, const char (*anc)[MVL_ID_CAP],
                         size_t anc_count);

/* What proves this loop, if anything. Evidence is consulted first because
 * it is checkable by a stranger with the same two files; a verifier's
 * VERDICT is the fallback. A sweep whose group is not registered at the ref
 * returns MVL_VERIFIED_SWEEP_UNREGISTERED — a named refusal, not a pass. */
enum mvl_verified_by mvl_loop_verified_by(const struct mvl_loop *loop,
                                          const struct mvl_evidence_world *w);

/* True for the three results that mean the loop is verified. */
bool mvl_is_verified(enum mvl_verified_by by);

/* The column value written for `verified_by`, and the name a refusal uses. */
const char *mvl_verified_by_name(enum mvl_verified_by by);

/* Fills `joins[0..plan->loop_count)`. `trains_dir` may be NULL (no assembler
 * split); every field of `*world` may be absent (landed stays -1). */
void mvl_join_loops(const struct mvl_plan *plan,
                    const struct mvl_agents *agents, const char *trains_dir,
                    const struct mvl_evidence_world *world,
                    struct mvl_join *joins);

bool mvl_write_loops(const char *path, const struct mvl_plan *plan,
                     const struct mvl_join *joins, char *err, size_t err_cap);

/* ── the snapshot ledger (mode `snapshot`) ────────────────────────────── */

const char *mvl_snapshots_header(void);

/* Appends one row to `path`, creating it with the header when absent, and
 * refusing when the file's first line is not this build's header. */
bool mvl_append_snapshot(const char *path, const struct mvl_plan *plan,
                         const struct mvl_agents *agents, const char *utc,
                         const char *origin_main, const char *note,
                         char *err, size_t err_cap);

/* ── the KPI: verified MVP progress per token (mode `kpi`) ────────────── */

/* EXPERIMENT.md §KPI. The numerator is base plan loops (the 144 `L<nn>`
 * rows) whose lane has a verifier VERDICT starting with LAND written at or
 * after t0; letter-suffixed sub-rows are reported beside it, never inside
 * it. The denominator is every measured agent in the window, in three
 * views. TCU is the primary one: output x 5 + input x 1 + cache_creation
 * x 1.25 + cache_read x 0.1, so 1 TCU is one input token's worth of spend.
 * It is computed in hundredths with integer arithmetic — a KPI that moved
 * with the host's floating-point rounding would not be a ground fact. */
struct mvl_kpi {
    int64_t verified_loops;         /* landed + sweep + verdict-only */
    int64_t verified_subrows;
    int64_t landed_loops;
    int64_t sweep_loops;
    int64_t sweep_unregistered;     /* refused rows, reported not counted */
    int64_t tokens_raw;
    int64_t tokens_out;
    int64_t tcu;
};

enum {
    MVL_TCU_OUT = 500,              /* per 100: output x 5 */
    MVL_TCU_INPUT = 100,            /* per 100: input x 1 */
    MVL_TCU_CACHE_CREATION = 125,   /* per 100: cache_creation x 1.25 */
    MVL_TCU_CACHE_READ = 10,        /* per 100: cache_read x 0.1 */
    MVL_TCU_SCALE = 100,
};

/* Collects the lanes whose `<scratch>/v<lane>[digits]/VERDICT` starts with
 * LAND and was written at or after `t0_unix`. The VERDICT's own modified
 * time comes from the portable directory listing, so this runs no stat(2)
 * of its own and no subprocess. A directory name maps to a lane by dropping
 * the leading `v` and any trailing digits. */
bool mvl_verified_lanes(const char *scratch_dir, int64_t t0_unix,
                        struct mvl_names *lanes, char *err, size_t err_cap);

void mvl_compute_kpi(const struct mvl_plan *plan,
                     const struct mvl_agents *agents,
                     const struct mvl_evidence_world *world,
                     struct mvl_kpi *out);

/* Writes one `<plan>:<line>: sweep_group_unregistered: …` line to `sink`
 * for every plan row whose sweep names a group the catalog does not carry,
 * and returns how many it wrote. A refusal a reader cannot see is not a
 * refusal, so this runs on every real invocation that resolves evidence. */
size_t mvl_report_sweep_refusals(const struct mvl_plan *plan,
                                 const struct mvl_evidence_world *world,
                                 const char *plan_path, FILE *sink);

const char *mvl_kpi_header(void);

/* Appends one row to `path`, creating it with the header when absent, and
 * refusing when the file's first line is not this build's header. */
bool mvl_append_kpi(const char *path, const struct mvl_kpi *kpi,
                    const char *utc, const char *window, const char *note,
                    char *err, size_t err_cap);

/* The one-line KPI tail `progress` and `kpi` both print. */
size_t mvl_render_kpi(const struct mvl_kpi *kpi, char *out, size_t out_cap);

/* ── the XP game (mode `xp`) ──────────────────────────────────────────── */

/* WHY. The owner's KPI is verified MVP progress per token, and a KPI nobody
 * competes on moves slowly. `xp` is that KPI turned into a score: it pays
 * for the things the plan of record says are worth the most, and it pays
 * for NOTHING a worker can assert about itself. Every point traces to one
 * of four facts a stranger can recheck — a commit reachable from
 * origin/main, a registered sweep group, a dev.land outcome row, or an
 * INDEPENDENT REVIEW note in the plan. There is no hand-set XP, no bonus
 * for lines, commits or messages, and no rule that reads a state= a worker
 * typed about its own work.
 *
 * The rules are stated once, in docs/work/MVP_GAME_MAP.md ("XP rules v1"),
 * and implemented here. Where a rule needs a signal this tool cannot see,
 * it pays nothing and SAYS SO in the report rather than guessing:
 *   - the speed bonus needs per-loop wall clocks, which exist only when an
 *     agents.tsv was measured (mvl_xp_board.speed_asked);
 *   - the "put origin/main red" penalty needs a red-main signal, which no
 *     input this tool reads carries (mvl_xp_board.main_red_asked, always
 *     false in v1). */

enum {
    MVL_MAX_FEATURES = 512,
    MVL_MAX_OUTCOMES = 8192,
    MVL_MAX_XP_EVENTS = 8192,
    MVL_MAX_XP_AGENTS = 1024,

    /* v1 payouts, in XP. A percentage is applied as a numerator over 100
     * with integer arithmetic, so a score never moves with the host's
     * floating point — the same reason the KPI carries TCU in hundredths. */
    MVL_XP_LOOP = 100,
    MVL_XP_FEATURE = 500,
    MVL_XP_MILESTONE = 2000,
    MVL_XP_REVIEW_PCT = 25,       /* the reviewer's cut of base x mult */
    MVL_XP_PROVISIONAL_PCT = 50,  /* an unreviewed author's cut */
    MVL_XP_SPEED_PCT = 50,        /* faster than the median close */
    MVL_XP_FAIL_PENALTY = 50,     /* subtracted per non-base-move failure */
    MVL_XP_COMBO = 100,
    MVL_XP_COMBO_RUN = 3,         /* landings in a row that pay a combo */
    MVL_XP_PCT = 100,

    MVL_XP_MULT_P0 = 3,
    MVL_XP_MULT_P1 = 2,
    MVL_XP_MULT_P2 = 1,
};

/* What one XP event was paid for. The kind is the audit trail's verb: with
 * the subject and the evidence beside it, a reader can walk any row of
 * xp.tsv back to the fact that produced it. */
enum mvl_xp_kind {
    MVL_XP_KIND_LOOP = 0,
    MVL_XP_KIND_REVIEW,
    MVL_XP_KIND_SPEED,
    MVL_XP_KIND_FEATURE,
    MVL_XP_KIND_MILESTONE,
    MVL_XP_KIND_PENALTY,
    MVL_XP_KIND_COMBO,
    MVL_XP_KIND_COUNT,
};

const char *mvl_xp_kind_name(enum mvl_xp_kind kind);

/* One credited or penalized event — one row of xp_events.tsv. `evidence` is
 * the sha, the sweep group, the outcome's detail or the review note excerpt
 * the payment was derived from; an event with no evidence is never
 * written, because it could not be rechecked. */
struct mvl_xp_event {
    char agent[MVL_LANE_CAP];
    char subject[MVL_ID_TEXT_CAP];      /* M05.F01.L01, or `outcome <seq>` */
    char evidence[MVL_EVIDENCE_CAP];
    int64_t xp;
    int multiplier;
    enum mvl_xp_kind kind;
    bool provisional;                   /* an unreviewed author's half */
};

struct mvl_xp_events {
    struct mvl_xp_event *rows;
    size_t count;
    size_t cap;
};

/* One scored agent — one row of xp.tsv. The agent identity is the LANE the
 * ledger already attributes work by: a plan row's loop=, an outcome row's
 * worktree basename, an agents.tsv row's lane, a review note's named
 * reviewer. `rank` is 0 for an agent with no measured tokens: it is
 * unranked, not last, because a ratio with a zero denominator is not a
 * worse ratio. */
struct mvl_xp_agent {
    char agent[MVL_LANE_CAP];
    int64_t loops;
    int64_t reviewed;
    int64_t xp;
    int64_t tcu;
    int rank;
};

struct mvl_xp_board {
    struct mvl_xp_agent *rows;
    size_t count;
    size_t cap;
    int multipliers[MVL_MAX_MILESTONES];
    int64_t median_wall_s;
    /* False when no loop carried a wall clock, so the speed bonus was not
     * asked rather than answered no. A report says which. */
    bool speed_asked;
    /* False in v1 and reported as such: no input this tool reads says an
     * event put origin/main red, so no -200 row is ever written. */
    bool main_red_asked;
    bool outcomes_present;
};

/* One dev.land outcome row. `agent` is the worktree's last path element,
 * which is the lane the ledger attributes every other fact by. */
struct mvl_outcome {
    char agent[MVL_LANE_CAP];
    char state[MVL_OUTCOME_CAP];
    char detail[MVL_EVIDENCE_CAP];
    char utc[MVL_UTC_CAP];
    int64_t seq;
    size_t line_no;
};

struct mvl_outcomes {
    struct mvl_outcome *rows;
    size_t count;
    size_t cap;
    bool present;                       /* false when the file was absent */
};

bool mvl_xp_alloc(struct mvl_xp_board *board, struct mvl_xp_events *events);
void mvl_xp_free(struct mvl_xp_board *board, struct mvl_xp_events *events);
bool mvl_outcomes_alloc(struct mvl_outcomes *outcomes);
void mvl_outcomes_free(struct mvl_outcomes *outcomes);

/* Reads `~/.local/state/z23/dev/land/outcomes.jsonl`, one JSON object per
 * line. A line that is not one JSON object, or carries no string "state",
 * is REFUSED BY NAME to `refusals` (which may be NULL) and skipped: one bad
 * row of an append-only operational log is a fact about that row, not a
 * reason to score nothing. A missing file is not an error either — the
 * table stays empty, `present` stays false, and the gap is reported the
 * same way. Only an over-long line or a table overflow returns false. */
bool mvl_read_outcomes(const char *path, struct mvl_outcomes *out,
                       FILE *refusals, char *err, size_t err_cap);

/* The priority multiplier a milestone's own TITLE earns, by exactly two
 * keyword sets (see docs/work/MVP_GAME_MAP.md for the table and the words):
 * x3 when the title names consensus, wallet, custody, a shielded payment, a
 * node, sync, the store or reaching tip; x2 when it names the proof,
 * publication, receipt, evidence, candidate or lifecycle machinery those
 * depend on; x1 otherwise. Nothing outside the title decides it. */
int mvl_milestone_multiplier(const char *title);

/* Scores the whole board. Reads the same inputs `loops` and `kpi` do — the
 * plan, the measured agents, the evidence world — plus the outcome rows.
 * `outcomes` may be an empty table (no penalties, no combos). Every payment
 * appends one event; the board is ranked before it returns. */
bool mvl_compute_xp(const struct mvl_plan *plan,
                    const struct mvl_agents *agents,
                    const struct mvl_evidence_world *world,
                    const struct mvl_outcomes *outcomes,
                    struct mvl_xp_board *board, struct mvl_xp_events *events,
                    char *err, size_t err_cap);

/* The scored row for `agent`, or NULL. */
const struct mvl_xp_agent *mvl_xp_find(const struct mvl_xp_board *board,
                                       const char *agent);

/* XP per million TCU, in thousandths — integer arithmetic for the same
 * reason the KPI uses it. Zero for an agent with no measured tokens: the
 * caller must read `rank == 0` as unranked, never as a last place. */
int64_t mvl_xp_per_mtcu_milli(const struct mvl_xp_agent *agent);

/* Folds `<experiments>/tokens_extra.tsv` — the TCU of agents whose
 * transcripts this box never held (Agent B, Grok, Codex), posted as TOKENS
 * mail rows. Header, exactly:
 *   agent<TAB>loop<TAB>in<TAB>out<TAB>cache_write<TAB>cache_read<TAB>utc
 * A different first line is refused (mvl_tsv_header) rather than guessed
 * at. A missing file contributes nothing and is not an error. The board is
 * re-ranked before it returns. */
bool mvl_read_tokens_extra(const char *path, struct mvl_xp_board *board,
                           char *err, size_t err_cap);

const char *mvl_tokens_extra_header(void);
const char *mvl_xp_header(void);
const char *mvl_xp_events_header(void);
bool mvl_write_xp(const char *path, const struct mvl_xp_board *board,
                  char *err, size_t err_cap);
bool mvl_write_xp_events(const char *path, const struct mvl_xp_events *events,
                         char *err, size_t err_cap);

/* The leaderboard, and the same numbers as one JSON object for a board
 * post. Both print the multiplier table, because a score whose weights are
 * invisible is not auditable. snprintf semantics. */
size_t mvl_render_xp(const struct mvl_plan *plan,
                     const struct mvl_xp_board *board, char *out,
                     size_t out_cap);
size_t mvl_render_xp_json(const struct mvl_plan *plan,
                          const struct mvl_xp_board *board, char *out,
                          size_t out_cap);

#endif /* ZCL_TOOLS_DEV_MVP_LEDGER_H */
