/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Seed claims: findings from outside this tree, entered as claims TO BE
 * TESTED HERE.
 *
 * A published result is evidence about the tree the authors measured. It is
 * not evidence about this one, and adopting it because it was published is
 * the same mistake as adopting it because someone said it confidently. So
 * every row below carries its citation in `source`, enters the register with
 * a falsifier of OUR choosing on a metric THIS tree measures, and starts
 * SCIENCE_UNTESTED — with zero trials, there is no arithmetic by which it
 * could start anywhere else.
 *
 * The first two are the interesting ones, because they point away from where
 * effort naturally goes. arXiv 2604.25850's ablation localises its harness
 * gain to tools, middleware and long-term memory rather than to the system
 * prompt; almost all prompt-tuning effort goes into the prompt. Both halves
 * of that are seeded, so the tree can find out which one pays here rather
 * than assuming either.
 *
 * The floors are ours and are deliberately not tiny. Five percentage points
 * of first-try pass rate is worth changing a harness for; one is noise with a
 * story attached. Twenty trials an arm is what it takes before a five-point
 * difference means anything at all.
 */

#include "science/science_claim.h"

#include <stddef.h>

/* Effect floors, written once so the reasoning is next to the number.
 * SCIENCE_METRIC_VERDICT_PASS_RATE is in milli, so 50 is five points. */
#define SEED_PASS_RATE_FLOOR_MILLI 50
/* Tokens per landed file, in milli: 100 tokens per landed file. Below that a
 * routing change is not paying for the routing. */
#define SEED_TOKENS_PER_FILE_FLOOR_MILLI (100 * SCIENCE_MILLI)
/* Trials required in EACH arm before any of these may be read. */
#define SEED_SAMPLE_FLOOR 20

static const struct science_claim_spec k_seeds[] = {
    /* The claim most people act on without measuring. The paper's ablation
     * predicts this one does NOT hold; recording it as a claim rather than as
     * a conclusion is the difference between citing the paper and testing it. */
    {
        .statement = "rewriting the system prompt's prose, with tools, "
                     "middleware and retrieved memory unchanged, raises the "
                     "first-try gate pass rate",
        .treatment = "system-prompt prose rewritten; harness structure held "
                     "fixed",
        .metric = SCIENCE_METRIC_VERDICT_PASS_RATE,
        .direction = SCIENCE_DIRECTION_UP,
        .effect_floor_milli = SEED_PASS_RATE_FLOOR_MILLI,
        .sample_floor = SEED_SAMPLE_FLOOR,
        .source = "arXiv 2604.25850, Agentic Harness Engineering: ablations "
                  "localise the gain to tools, middleware and long-term "
                  "memory rather than the system prompt",
    },
    /* The structural half of the same ablation. */
    {
        .statement = "giving the unit a retrieval tool over this tree's code "
                     "index raises the first-try gate pass rate",
        .treatment = "code-index retrieval tool available to the unit",
        .metric = SCIENCE_METRIC_VERDICT_PASS_RATE,
        .direction = SCIENCE_DIRECTION_UP,
        .effect_floor_milli = SEED_PASS_RATE_FLOOR_MILLI,
        .sample_floor = SEED_SAMPLE_FLOOR,
        .source = "arXiv 2604.25850, Agentic Harness Engineering: factual "
                  "harness structure transfers while prose-level strategy "
                  "does not",
    },
    /* The second paper, on the metric the owner cares about. This tree's
     * cookbook router is building exactly the decoupling it describes, so the
     * trials that decide it will arrive from real dispatches. */
    {
        .statement = "selecting the skill locally from usage statistics, "
                     "instead of asking the remote model to choose, lowers "
                     "the tokens spent per landed file",
        .treatment = "local statistical skill selection in front of the "
                     "remote semantic parse",
        .metric = SCIENCE_METRIC_TOKENS_PER_LANDED_FILE,
        .direction = SCIENCE_DIRECTION_DOWN,
        .effect_floor_milli = SEED_TOKENS_PER_FILE_FLOOR_MILLI,
        .sample_floor = SEED_SAMPLE_FLOOR,
        .source = "arXiv 2606.05828, Statistical Priors for Implicit "
                  "Preferences: decoupling local selection from remote "
                  "semantic parsing beats memory-augmented agents",
    },
};

uint32_t science_seed_count(void)
{
    return (uint32_t)(sizeof k_seeds / sizeof k_seeds[0]);
}

bool science_seed_at(uint32_t index, struct science_claim_spec *out)
{
    if (!out || index >= science_seed_count())
        return false;
    *out = k_seeds[index];
    return true;
}

enum science_refusal science_seed_install(struct science_register *reg,
                                          uint32_t *added, uint32_t *already)
{
    if (added)
        *added = 0;
    if (already)
        *already = 0;
    if (!reg)
        return SCIENCE_REFUSED_ARGUMENT;
    for (uint32_t i = 0; i < science_seed_count(); i++) {
        const enum science_refusal r =
            science_claim_register(reg, &k_seeds[i], NULL);
        if (r == SCIENCE_OK) {
            if (added)
                (*added)++;
        } else if (r == SCIENCE_REFUSED_DUPLICATE) {
            /* Installing twice is a no-op, not an error: a seed already in
             * the log keeps the trials already filed under it. */
            if (already)
                (*already)++;
        } else {
            return r;
        }
    }
    return SCIENCE_OK;
}
