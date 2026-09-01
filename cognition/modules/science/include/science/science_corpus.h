/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * science_corpus — honest distance to 100,000,000 lines of proven, tested,
 * non-duplicated C23.
 *
 * WHY THIS IS NOT A PROGRESS BAR
 * ------------------------------
 * The goal is 100M lines of C23 that are PROVEN, TESTED and NOT DUPLICATED.
 * A report that divides today's line count by 100M and prints a percentage
 * answers a question nobody asked: it measures typing. Every line in the
 * numerator that no test reaches, and every line that is a second copy of a
 * line already here, is progress away from the goal being reported as
 * progress toward it.
 *
 * So this report never produces a single "percent complete" number. It
 * produces four numbers that a reader has to look at together:
 *
 *   lines            what the tree actually holds today
 *   proven           the fraction a REGISTERED TEST demonstrably reaches
 *   duplicates       pairs of bodies that are the same code twice
 *   untested         declared contracts with nothing asserting them
 *
 * and it leads with the unproven remainder, because that is the honest
 * headline. If most of the corpus is unproven the report says most of the
 * corpus is unproven.
 *
 * THE DENOMINATOR IS NAMED, AND IT IS NOT LINES
 * ---------------------------------------------
 * We can count lines exactly. We CANNOT say what fraction of LINES is
 * proven: no artifact in this tree attributes proof at line granularity, and
 * inventing one by, say, crediting every line of a file with one reached
 * symbol in it would be a fabrication dressed as a measurement. What the tree
 * does measure, in docs/CAPABILITY_INVENTORY.jsonl, is per-PUBLIC-SYMBOL
 * reachability from a registered test root. That is the proven fraction this
 * report gives, over that denominator, said out loud. The line-level proven
 * fraction is reported as unmeasured, and it stays unmeasured until something
 * actually measures it.
 *
 * TWO HALVES, ONE TREE — CHECKED
 * ------------------------------
 * The line count comes from walking the maintained C23 roots here and now.
 * The proven and duplicate counts come from the generated inventory artifact,
 * which was produced by a different walk at a different time. Dividing a
 * number from one walk by a number from the other is only meaningful if both
 * walks saw the same tree, so this module checks: `scope_agrees` is true only
 * when the file count it walked equals the file count the inventory recorded.
 * When they disagree the report SAYS SO and the caller must not present the
 * proven fraction as current — the inventory is stale and the fix is
 * `make docs-capability-inventory`, not a smaller font on the caveat.
 *
 * The root list below deliberately mirrors codeindex_inventory_scan.c's, for
 * exactly that reason: the two halves must describe the same universe. The
 * mirror is not assumed, it is the thing `scope_agrees` tests.
 *
 * MISSING EVIDENCE IS NOT ZERO AND IT IS NOT FULL MARKS
 * ----------------------------------------------------
 * When the inventory artifact is absent, `inventory_present` is false and
 * every proven/duplicate figure is zero and meaningless. A caller must report
 * "not measured" rather than "0 duplicates" — the second is a claim, and it
 * is the flattering one.
 */

#ifndef ZCL_SCIENCE_CORPUS_H
#define ZCL_SCIENCE_CORPUS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The owner's north star, written once. */
#define SCIENCE_CORPUS_GOAL_LINES 100000000ull

struct science_corpus_report {
    /* Measured by walking `root` now. */
    uint64_t files_walked;
    uint64_t lines;
    uint64_t bytes;

    /* Read from the generated inventory artifact. All zero and MEANINGLESS
     * when inventory_present is false. */
    bool     inventory_present;
    uint64_t inventory_files_scanned;
    uint64_t inventory_production_files;
    uint64_t inventory_test_files;
    uint64_t capabilities;             /* public headers with a symbol */
    uint64_t symbols_exposed;
    uint64_t symbols_test_reached;     /* a registered test root reaches it */
    uint64_t symbols_test_source_only; /* named in a test, not reached: UNPROVEN */
    uint64_t symbols_no_test;          /* nothing at all: UNPROVEN */
    uint64_t duplicates;               /* duplicate-body candidate pairs */
    uint64_t untested_invariants;      /* declared contracts nothing asserts */

    /* False when the two halves counted different trees; see the header. */
    bool     scope_agrees;
};

/* Walk `root` and read `inventory_path` (may be NULL or absent — then
 * inventory_present is false and the walk half still fills in). Returns false
 * only when the walk itself failed, which is a refusal, not an empty tree. */
bool science_corpus_measure(const char *root, const char *inventory_path,
                            struct science_corpus_report *out);

/* Fraction of PUBLIC SYMBOLS a registered test reaches, in milli (1000 =
 * all). Returns -1 when it cannot be computed — no inventory, or no symbols
 * — and -1 must be rendered as "not measured", never as zero. */
int64_t science_corpus_proven_symbols_milli(
    const struct science_corpus_report *report);

/* Fraction of the 100M-line goal, in milli. This is a line count and says
 * NOTHING about proof; never present it on its own. */
int64_t science_corpus_goal_milli(const struct science_corpus_report *report);

/* One sentence that leads with what is NOT proven. Returns the length
 * written, or 0 when the buffer is too small. */
size_t science_corpus_headline(const struct science_corpus_report *report,
                               char *out, size_t cap);

#endif /* ZCL_SCIENCE_CORPUS_H */
