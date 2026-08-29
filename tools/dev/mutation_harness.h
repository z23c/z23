/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Mutation testing for Z23 — the parts that can be proved without a build.
 *
 * WHY THIS EXISTS. Every file in this tree compiles under
 * -std=c23 -Wall -Wextra -Werror -pedantic and every registered group is
 * green, and an audit still found a declared validator that was `return
 * true;`, a signature check that hashed bytes nobody wrote, and an index that
 * silently held 32 keys. Nothing in the suite ever inserted a 33rd key. A
 * green suite says "these tests pass"; it does not say "these tests would
 * notice if the code were wrong". Mutation testing measures exactly that
 * second thing, with no human labelling: break the code on purpose, and if
 * nothing goes red, the hole is in the test, not in the mutant.
 *
 * Three pieces live here, all free of the checkout they will be pointed at,
 * so a registered test group can drive the whole thing on a fixture:
 *
 *   1. the operators      — enumerate every mutation site in one C source
 *   2. the build plan     — what to compile, link and run for one mutant
 *   3. the campaign core  — run the plan over the sites and score the result
 *
 * The one safety property that matters is structural rather than careful:
 * NOTHING HERE EVER OPENS THE TARGET SOURCE FOR WRITING. A mutant is compiled
 * from a scratch copy carrying a `#line` directive back to the real path, so
 * __FILE__ and __LINE__ are unchanged and the checkout is never edited at
 * all. There is no restore path to get wrong, no signal handler to race, and
 * an interrupted run cannot leave a truncated file behind — the file was
 * never opened for writing on any path.
 */

#ifndef ZCL_MUTATION_HARNESS_H
#define ZCL_MUTATION_HARNESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── 1. Operators ─────────────────────────────────────────────────────────
 *
 * The operator set is deliberately small. A mutant nobody would ever write
 * is wasted compute AND a wasted line in the survivor report, which is the
 * actual product. Each class below is here because it models a defect class
 * this codebase has really shipped:
 *
 *   RETURN      `return <expr>;` -> `return true;` / `return 0;`
 *               The audit's worst find: a declared validation function whose
 *               body was `return true;` with every argument cast to void.
 *               A test that never constructs a REJECTED input cannot tell
 *               that function from the real one.
 *
 *   RELATIONAL  > <-> >=,  < <-> <=,  == <-> !=
 *               Off-by-one at a bound. The audit's index that held exactly
 *               32 keys and reported success on the 33rd insert is this
 *               class, and so is every capacity check written once and never
 *               driven past its edge.
 *
 *   BOUNDARY    integer literal n -> n+1 and n -> n-1
 *               The constant behind that same bound, including in #define.
 *               A suite that only ever inserts 1 key cannot see 32 change.
 *
 *   LOGICAL     && <-> ||, drop a unary !, true <-> false
 *               The node1 watchdog false negative was literally `A || B`
 *               narrowed to `A`. Dropping a `!` inverts a refusal, which is
 *               how a fail-closed path silently becomes fail-open.
 *
 *   STATEMENT   a call statement whose result is unused -> `(void)0;`
 *               "It hashed bytes that were never written." The write is a
 *               statement nothing reads back; deleting it is exactly that
 *               defect, and only a test that checks the WRITTEN BYTES sees
 *               it go.
 *
 * Operators NOT included, on purpose: arithmetic replacement (+ -> -),
 * constant-to-zero, and wholesale condition negation. They mostly re-find
 * what the five above already find, and they generate mutants no human would
 * write, which lengthens every survivor list without adding a real hole.
 */

#define ZCL_MUT_RULE_MAX 20
#define ZCL_MUT_TEXT_MAX 48

enum zcl_mut_class {
    ZCL_MUT_CLASS_RELATIONAL = 0,
    ZCL_MUT_CLASS_LOGICAL,
    ZCL_MUT_CLASS_BOUNDARY,
    ZCL_MUT_CLASS_RETURN,
    ZCL_MUT_CLASS_STATEMENT,
    ZCL_MUT_CLASS_COUNT
};

struct zcl_mut_site {
    size_t offset; /* byte offset of the edit inside the translation unit */
    size_t span;   /* bytes replaced */
    size_t line;   /* 1-based line of `offset` */
    size_t column; /* 1-based column of `offset` */
    enum zcl_mut_class cls;
    char rule[ZCL_MUT_RULE_MAX];   /* e.g. "ge_to_gt" */
    char before[ZCL_MUT_TEXT_MAX]; /* replaced text, elided with "..." */
    char after[ZCL_MUT_TEXT_MAX];  /* the exact replacement text */
};

const char *zcl_mut_class_name(enum zcl_mut_class cls);

/* Enumerate every mutation site in one translation unit, in file order.
 * String literals, character literals, both comment forms and every
 * preprocessor directive except #define are excluded. Writes up to `cap`
 * sites and returns the TOTAL found, which may exceed `cap`. */
size_t zcl_mut_enumerate(const char *text, size_t len,
                         struct zcl_mut_site *out, size_t cap);

/* Build the mutated image of `text` for one site. `*out` is a fresh
 * NUL-terminated buffer the caller frees. The input is never modified. */
bool zcl_mut_apply(const char *text, size_t len, const struct zcl_mut_site *s,
                   char **out, size_t *out_len);

/* ── 2. Build plan ────────────────────────────────────────────────────────
 *
 * One mutant costs one compile of one translation unit, one link, and one
 * run of one registered group. Deriving the exact compile and link argv from
 * `make -n -W <src> <target>` rather than reimplementing them is the whole
 * reason this is affordable: the flags, the include closure and the link
 * response file all stay whatever the real build says they are, and no
 * epoch, session lease or source-identity stamp is disturbed. */

#define ZCL_MUT_ARGV_MAX 512

struct zcl_mut_argv {
    char *argv[ZCL_MUT_ARGV_MAX + 1]; /* NULL-terminated */
    size_t count;
};

void zcl_mut_argv_free(struct zcl_mut_argv *a);

/* Split one shell command into words, honouring '...', "..." and backslash.
 * No variable expansion, no globbing: a `$tmp` stays the four-character
 * token `$tmp` so the caller can recognise and replace it. */
bool zcl_mut_shell_split(const char *cmd, struct zcl_mut_argv *out);

struct zcl_mut_plan {
    struct zcl_mut_argv compile; /* compiler + flags; -c -o OBJ SRC appended */
    struct zcl_mut_argv link;    /* linker line with -o and @rsp substituted */
    char object[512];            /* the baseline object this TU produces */
    char rsp[512];               /* the link response file to clone */
};

void zcl_mut_plan_free(struct zcl_mut_plan *p);

/* Recover the compile and link commands for `src_rel` from the transcript of
 * `make -n`. Returns false with a reason in `err` when the transcript does
 * not contain both — which is the honest answer when the build changed
 * shape, and is never guessed at. */
bool zcl_mut_plan_from_dryrun(const char *text, const char *src_rel,
                              struct zcl_mut_plan *out, char *err,
                              size_t err_cap);

/* ── 3. Campaign core ─────────────────────────────────────────────────────
 *
 * Every mutant lands in exactly one bucket, and the two that are NOT the
 * test suite's fault are reported apart from the two that are:
 *
 *   KILLED      the group went red. The test noticed. Credit to the test.
 *   SURVIVED    the group stayed green on genuinely different machine code.
 *               A hole: either the line is never reached, or it is reached
 *               and nothing asserts on what it decided. Both are holes.
 *   STILLBORN   the mutant did not compile. -Werror rejected it, not the
 *               test suite, so it is EXCLUDED from the score rather than
 *               counted as a kill. Counting these is how a mutation score
 *               flatters a suite that never ran.
 *   EQUIVALENT  the mutant compiled to a byte-identical object file. Same
 *               machine code cannot behave differently, so NO test could
 *               ever kill it. Excluded, and reported separately.
 *   ERROR       the run did not produce a usable verdict (no SUITE VERDICT
 *               line, or groups_ran == 0). Never silently a survivor.
 *
 * score = KILLED / (KILLED + SURVIVED)
 *
 * Equivalent mutants in general are undecidable, and this does not pretend
 * otherwise. The object-identity test is the cheap SOUND half: what it flags
 * is certainly equivalent. A semantically equivalent mutant with different
 * machine code still lands in SURVIVED, where it depresses the score — which
 * is why a survivor list is read, never a score alone. */

enum zcl_mut_outcome {
    ZCL_MUT_OUTCOME_KILLED = 0,
    ZCL_MUT_OUTCOME_SURVIVED,
    ZCL_MUT_OUTCOME_STILLBORN,
    ZCL_MUT_OUTCOME_EQUIVALENT,
    ZCL_MUT_OUTCOME_ERROR,
    ZCL_MUT_OUTCOME_COUNT
};

const char *zcl_mut_outcome_name(enum zcl_mut_outcome o);

struct zcl_mut_result {
    struct zcl_mut_site site;
    enum zcl_mut_outcome outcome;
    const char *killed_by; /* "test" | "timeout" | "crash" | "" */
    long long ms;
    bool cached;
};

struct zcl_mut_config {
    const char *root;      /* checkout root; all relative paths hang off it */
    const char *src_rel;   /* the file being mutated, relative to root */
    const char *group;     /* registered test group, e.g. test_node_character */
    const char *work_dir;  /* scratch: objects, binaries, cache */
    const char *runner_arg_fmt; /* "--exact=%s" by default */
    int build_timeout_ms;
    int test_timeout_ms;
    bool use_cache;
    bool verbose;
    /* Injected fault used by the harness's own test group: abort the
     * campaign after this many mutants, as an interrupt would. 0 = never. */
    size_t abort_after;
};

struct zcl_mut_report {
    size_t total_sites;
    size_t counts[ZCL_MUT_OUTCOME_COUNT];
    struct zcl_mut_result *results; /* total_sites entries; caller frees */
    size_t result_count;
    unsigned char source_digest_before[32];
    unsigned char source_digest_after[32];
    bool source_unchanged;
    bool aborted;
    long long wall_ms;
    char error[256];
};

void zcl_mut_report_free(struct zcl_mut_report *r);

/* Percent, rounded to one decimal, as a scaled integer (e.g. 873 == 87.3%).
 * Returns -1 when the denominator is zero — a suite with nothing to score
 * has no score, and printing 0% or 100% there would both be lies. */
int zcl_mut_score_tenths(const struct zcl_mut_report *r);

/* Run the whole campaign. `plan` is used verbatim except for the three
 * substitutions the campaign owns: the compiled object, the linked binary
 * and the link response file. Returns false only when the campaign could
 * not start (unreadable source, baseline not green, bad plan); a green run
 * that killed nothing is a true return with a 0% score. */
bool zcl_mut_campaign_run(const struct zcl_mut_config *cfg,
                          const struct zcl_mut_plan *plan,
                          struct zcl_mut_report *out);

/* ── shared process + file helpers ───────────────────────────────────────
 * Exposed because the driver needs the same bounded spawn for `make -n`. */

/* Run argv[] with cwd `dir`, capturing stdout+stderr into a fresh buffer.
 * Returns the exit status, 128+signal when killed, or -1 on a launch
 * failure. A run that exceeds `timeout_ms` is killed and reported as -2. */
int zcl_mut_spawn(const char *dir, char *const argv[], int timeout_ms,
                  char **out, size_t *out_len);

char *zcl_mut_read_file(const char *path, size_t *len_out);
bool zcl_mut_write_file(const char *path, const char *bytes, size_t len);

/* Lowercase hex of the SHA3-256 of `bytes`. `hex` must hold 65 bytes. */
void zcl_mut_digest_hex(const void *bytes, size_t len, char *hex);

/* ── LIMITS: what a mutation score does NOT mean ──────────────────────────
 *
 * Read this before quoting a number at anybody. A mutation score is a
 * measure of one narrow thing — whether a group's assertions are sensitive
 * to a one-token change in one file — and it is easy to over-trust.
 *
 * 1. A 100% score does not mean the code is correct. It means the tests
 *    notice the defects THESE FIVE OPERATORS inject. A wrong algorithm, a
 *    wrong protocol, a missing case nobody wrote code for, a wrong constant
 *    that is wrong in the test too, and every requirement never turned into
 *    code at all are all invisible to it. Mutation testing grades tests
 *    against the code as written; it cannot grade the code against reality.
 *
 * 2. It says nothing about anything not in one translation unit. Races,
 *    deadlocks, lock-order inversions, use-after-free, memory growth,
 *    resource leaks, crash-consistency, upgrade and downgrade paths, and
 *    every wire-format compatibility question are outside its reach. So is
 *    consensus parity: a mutant that changes a consensus predicate and is
 *    killed proves a test noticed, not that the predicate matches
 *    `zclassicd`. TSan, ASan, the fuzzers, the simnet acceptances and the
 *    parity oracles remain the tools for those, unchanged.
 *
 * 3. A SURVIVOR is a hole, but not always in the group you ran. It can mean
 *    the line is dead code, or that it is covered by a DIFFERENT group, or
 *    that the behaviour is genuinely not worth pinning (a log string, a
 *    tuning constant with no contract). Deciding which is a human's job.
 *    Never "fix" a survivor by weakening what a test asserts.
 *
 * 4. Coverage is not subtracted first, deliberately. A mutant on a line the
 *    group never reaches shows up as a SURVIVOR rather than being filtered
 *    out, because "the group never executes this" and "the group executes
 *    this and asserts nothing about it" are both holes, and the audit that
 *    prompted this harness found the first kind. Filtering by coverage
 *    would have hidden exactly the defects it was built to find. The cost
 *    of that choice is real: uncovered mutants still pay a build.
 *
 * 5. The score is only comparable to itself. Different files have different
 *    site mixes — a file dense in integer literals is dominated by boundary
 *    mutants — so a 59% and a 74% on two different files are not a ranking.
 *    Watch one file's score over time; do not league-table the tree.
 *
 * 6. It measures the build it was pointed at. The plan comes from
 *    `make -n` for one target, so a score for `test_parallel` says nothing
 *    about the ASan, TSan, coverage or Windows cross builds, and a mutant
 *    that only a sanitizer would catch is scored SURVIVED here.
 *
 * 7. A mutant that hangs is scored KILLED (by timeout). That is the right
 *    call for a test suite — a wedge IS a failure a human would see — but
 *    it means a slow machine can turn a survivor into a kill. Timeouts are
 *    generous for that reason, and a score measured on a loaded box should
 *    be re-measured before it is acted on.
 */

#endif /* ZCL_MUTATION_HARNESS_H */
