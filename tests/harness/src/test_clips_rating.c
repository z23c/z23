/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hermetic coverage of clips_rating_decide (spec 6.6): every row of the
 * ordered decision, the evidence rules, the strictest-rater rule, retraction,
 * the illegal-match and owner-block precedence, the reshare gate, the invalid
 * viewer level, and the refusal of a rater list beyond its bound. Plain
 * structs only: no node, no store and no clock. */

#include "test/test_core.h"

#include "clips_rating/clips_rating.h"

#include <string.h>

/* A post declared General, by an accepted author, with no other evidence.
 * Every row is then decided by the one field a test sets. */
static void cy_base(struct clips_rating_input *in)
{
    memset(in, 0, sizeof(*in));
    in->declared_level = CLIPS_LEVEL_GENERAL;
    in->viewer_level = CLIPS_LEVEL_GENERAL;
    in->accepted_author = true;
}

static struct clips_rating_decision cy_decide(const struct clips_rating_input *in)
{
    struct clips_rating_decision d;
    memset(&d, 0, sizeof(d));
    (void)clips_rating_decide(in, &d);
    return d;
}

int test_clips_rating(void);
int test_clips_rating(void)
{
    int failures = 0;

    TEST("row 9: an ordinary General post by an accepted author is shown") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        ASSERT(clips_rating_decide(&in, &d));
        ASSERT(d.shown);
        ASSERT_EQ(d.evidence, CLIPS_EVIDENCE_AUTHOR);
        PASS();
    }

    TEST("row 1: an illegal-content match hides, and no later row overrides it") {
        struct clips_rating_input in;
        cy_base(&in);
        in.illegal_match = true;
        in.own_key = true;
        in.owner_allowed = true;
        ASSERT(!cy_decide(&in).shown);
        in.own_key = false;
        ASSERT(!cy_decide(&in).shown);
        PASS();
    }

    TEST("row 2: an owner block hides; own key does not beat it") {
        struct clips_rating_input in;
        cy_base(&in);
        in.owner_blocked = true;
        in.own_key = true;
        ASSERT(!cy_decide(&in).shown);
        PASS();
    }

    TEST("own key beats a higher declared level but not an illegal match or a block") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.declared_level = CLIPS_LEVEL_EXPLICIT;
        in.viewer_level = CLIPS_LEVEL_GENERAL;
        in.own_key = true;
        in.accepted_author = false;
        d = cy_decide(&in);
        ASSERT(d.shown);
        ASSERT(d.own);
        ASSERT(!d.rating_above_level);
        in.illegal_match = true;
        ASSERT(!cy_decide(&in).shown);
        in.illegal_match = false;
        in.owner_blocked = true;
        ASSERT(!cy_decide(&in).shown);
        PASS();
    }

    TEST("row 3: own key shows without any other evidence and sets the own flag") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.accepted_author = false;
        in.own_key = true;
        d = cy_decide(&in);
        ASSERT(d.shown);
        ASSERT(d.own);
        ASSERT_EQ(d.evidence, CLIPS_EVIDENCE_NONE);
        PASS();
    }

    TEST("reshare: a target that is not shown hides the reshare, even by the owner") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.is_reshare = true;
        in.target_shown = false;
        in.own_key = true;
        d = cy_decide(&in);
        ASSERT(!d.shown);
        ASSERT(d.target_hidden);
        in.target_shown = true;
        ASSERT(cy_decide(&in).shown);
        PASS();
    }

    TEST("row 4: owner allow shows and beats a block list, not an illegal match") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.accepted_author = false;
        in.owner_allowed = true;
        in.on_block_list = true;
        in.declared_level = CLIPS_LEVEL_EXPLICIT;
        d = cy_decide(&in);
        ASSERT(d.shown);
        ASSERT(d.owner_allowed);
        in.illegal_match = true;
        ASSERT(!cy_decide(&in).shown);
        PASS();
    }

    TEST("row 5: a subscribed block list hides with its flag") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.on_block_list = true;
        d = cy_decide(&in);
        ASSERT(!d.shown);
        ASSERT(d.blocked_by_list);
        PASS();
    }

    TEST("row 6: a held uncleared report hides with its flag") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.report_held = true;
        d = cy_decide(&in);
        ASSERT(!d.shown);
        ASSERT(d.reported);
        PASS();
    }

    TEST("row 7: effective level above the viewer hides; equal shows") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.declared_level = CLIPS_LEVEL_MATURE;
        in.viewer_level = CLIPS_LEVEL_SENSITIVE;
        d = cy_decide(&in);
        ASSERT(!d.shown);
        ASSERT(d.rating_above_level);
        ASSERT_EQ(d.effective_level, CLIPS_LEVEL_MATURE);
        in.viewer_level = CLIPS_LEVEL_MATURE;
        ASSERT(cy_decide(&in).shown);
        PASS();
    }

    TEST("row 8: no evidence hides unless show_unrated is set") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.accepted_author = false;
        d = cy_decide(&in);
        ASSERT(!d.shown);
        ASSERT(d.rating_unverified);
        ASSERT_EQ(d.evidence, CLIPS_EVIDENCE_NONE);
        in.show_unrated = true;
        ASSERT(cy_decide(&in).shown);
        PASS();
    }

    TEST("follow alone is not evidence: with no accepted author or rater it is none") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.accepted_author = false;
        d = cy_decide(&in);
        ASSERT_EQ(d.evidence, CLIPS_EVIDENCE_NONE);
        PASS();
    }

    TEST("the strictest of two raters wins") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.accepted_author = false;
        in.viewer_level = CLIPS_LEVEL_SENSITIVE;
        in.rater_levels[0] = CLIPS_LEVEL_MILD;
        in.rater_levels[1] = CLIPS_LEVEL_MATURE;
        in.rater_count = 2;
        d = cy_decide(&in);
        ASSERT_EQ(d.effective_level, CLIPS_LEVEL_MATURE);
        ASSERT(!d.shown);
        ASSERT(d.rating_above_level);
        ASSERT_EQ(d.evidence, CLIPS_EVIDENCE_RATER);
        in.rater_levels[1] = CLIPS_LEVEL_SENSITIVE;
        ASSERT(cy_decide(&in).shown);
        PASS();
    }

    TEST("a retraction removes the rater: level and evidence are recomputed") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.accepted_author = false;
        in.viewer_level = CLIPS_LEVEL_GENERAL;
        in.rater_levels[0] = CLIPS_LEVEL_MATURE;
        in.rater_count = 1;
        ASSERT_EQ(cy_decide(&in).evidence, CLIPS_EVIDENCE_RATER);
        in.rater_levels[0] = 0;
        d = cy_decide(&in);
        ASSERT_EQ(d.evidence, CLIPS_EVIDENCE_NONE);
        ASSERT_EQ(d.effective_level, CLIPS_LEVEL_GENERAL);
        ASSERT(!d.shown);
        ASSERT(d.rating_unverified);
        PASS();
    }

    TEST("text evidence: a comment with a returned level counts; unverified adds nothing") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.accepted_author = false;
        in.is_comment = true;
        in.target_shown = true;
        in.text_level = 2;
        in.viewer_level = CLIPS_LEVEL_MILD;
        d = cy_decide(&in);
        ASSERT_EQ(d.evidence, CLIPS_EVIDENCE_TEXT);
        ASSERT(d.shown);
        in.text_level = 0;
        d = cy_decide(&in);
        ASSERT_EQ(d.evidence, CLIPS_EVIDENCE_NONE);
        ASSERT(!d.shown);
        in.text_level = 4;
        in.is_comment = false;
        d = cy_decide(&in);
        ASSERT_EQ(d.evidence, CLIPS_EVIDENCE_NONE);
        ASSERT_EQ(d.effective_level, CLIPS_LEVEL_MATURE);
        PASS();
    }

    TEST("an out-of-range viewer level decides as General with show_unrated false") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.accepted_author = false;
        in.declared_level = CLIPS_LEVEL_MILD;
        in.show_unrated = true;
        in.viewer_level = 0;
        d = cy_decide(&in);
        ASSERT(!d.shown);
        ASSERT(d.rating_above_level);
        in.viewer_level = CLIPS_LEVEL_MAX + 1;
        d = cy_decide(&in);
        ASSERT(!d.shown);
        ASSERT(d.rating_above_level);
        PASS();
    }

    TEST("a rater list beyond its bound and a NULL argument are refused as hidden") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.rater_count = CLIPS_RATER_MAX + 1;
        ASSERT(!clips_rating_decide(&in, &d));
        ASSERT(!d.shown);
        ASSERT(!clips_rating_decide(NULL, &d));
        PASS();
    }

    TEST("row 0: an owner's own reshare of a hidden target is hidden before the own-key row") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.is_reshare = true;
        in.target_shown = false;
        in.own_key = true;
        in.owner_allowed = true;
        d = cy_decide(&in);
        ASSERT(!d.shown);
        ASSERT(d.target_hidden);
        ASSERT(!d.own);
        PASS();
    }

    TEST("row 0: a comment on a hidden post is hidden even when its text check passes") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.is_comment = true;
        in.target_shown = false;
        in.text_level = CLIPS_LEVEL_GENERAL;
        d = cy_decide(&in);
        ASSERT(!d.shown);
        ASSERT(d.target_hidden);
        PASS();
    }

    TEST("serve: an owner's own Mature clip above the serve level is refused") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.own_key = true;
        in.accepted_author = false;
        in.declared_level = CLIPS_LEVEL_MATURE;
        ASSERT(clips_rating_decide_serve(&in, CLIPS_LEVEL_SENSITIVE, &d));
        ASSERT(!d.shown);
        ASSERT(d.rating_above_level);
        ASSERT(!d.own);
        PASS();
    }

    TEST("serve: missing evidence does not refuse serving") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.accepted_author = false;
        in.show_unrated = false;
        ASSERT(clips_rating_decide_serve(&in, CLIPS_LEVEL_GENERAL, &d));
        ASSERT(d.shown);
        ASSERT(!d.rating_unverified);
        PASS();
    }

    TEST("serve: rows 1, 2 and 5 hide; owner allow, report and the target gate do not apply") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.illegal_match = true;
        in.owner_allowed = true;
        ASSERT(clips_rating_decide_serve(&in, CLIPS_LEVEL_EXPLICIT, &d));
        ASSERT(!d.shown);
        in.illegal_match = false;
        in.owner_blocked = true;
        ASSERT(clips_rating_decide_serve(&in, CLIPS_LEVEL_EXPLICIT, &d));
        ASSERT(!d.shown);
        in.owner_blocked = false;
        in.on_block_list = true;
        ASSERT(clips_rating_decide_serve(&in, CLIPS_LEVEL_EXPLICIT, &d));
        ASSERT(!d.shown);
        ASSERT(d.blocked_by_list);
        in.on_block_list = false;
        in.report_held = true;
        in.is_reshare = true;
        in.target_shown = false;
        ASSERT(clips_rating_decide_serve(&in, CLIPS_LEVEL_EXPLICIT, &d));
        ASSERT(d.shown);
        PASS();
    }

    TEST("serve: an invalid serve level decides as General") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        cy_base(&in);
        in.declared_level = CLIPS_LEVEL_MILD;
        ASSERT(clips_rating_decide_serve(&in, 0, &d));
        ASSERT(!d.shown);
        ASSERT(d.rating_above_level);
        ASSERT(clips_rating_decide_serve(&in, CLIPS_LEVEL_MAX + 1, &d));
        ASSERT(!d.shown);
        PASS();
    }

    TEST("row 7: for declared levels and viewer levels 1..5, a level above the viewer's is hidden and one at or below is shown") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        for (uint8_t e = CLIPS_LEVEL_GENERAL; e <= CLIPS_LEVEL_MAX; e++) {
            for (uint8_t v = CLIPS_LEVEL_GENERAL; v <= CLIPS_LEVEL_MAX; v++) {
                cy_base(&in);
                in.declared_level = e;
                in.viewer_level = v;
                d = cy_decide(&in);
                ASSERT(d.shown == (e <= v));
                ASSERT(d.rating_above_level == (e > v));
            }
        }
        PASS();
    }

    TEST("row 7: a rater level of 6 or 200 is above every viewer level 1..5") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        const uint8_t bad[] = {6, 200};
        for (size_t i = 0; i < sizeof(bad); i++) {
            cy_base(&in);
            in.rater_count = 1;
            in.rater_levels[0] = bad[i];
            in.viewer_level = CLIPS_LEVEL_MAX;
            d = cy_decide(&in);
            ASSERT(!d.shown);
            ASSERT(d.rating_above_level);
            ASSERT_EQ(d.effective_level, bad[i]);
            ASSERT_EQ(d.evidence, CLIPS_EVIDENCE_AUTHOR);
        }
        PASS();
    }

    TEST("an out-of-range viewer level with no evidence is hidden as unverified even when show_unrated is set") {
        struct clips_rating_input in;
        struct clips_rating_decision d;
        const uint8_t bad[] = {0, 6};
        cy_base(&in);
        in.accepted_author = false;
        in.show_unrated = true;
        for (size_t i = 0; i < sizeof(bad); i++) {
            in.viewer_level = bad[i];
            d = cy_decide(&in);
            ASSERT(!d.shown);
            ASSERT(d.rating_unverified);
            ASSERT(!d.rating_above_level);
        }
        PASS();
    }

    TEST("a declared level outside 1..5 is refused: both decisions return false and leave the outcome hidden") {
        struct clips_rating_input in;
        struct clips_rating_decision dec;
        const uint8_t bad[] = {0, 6};
        for (size_t i = 0; i < sizeof(bad); i++) {
            cy_base(&in);
            in.declared_level = bad[i];
            dec.shown = true;
            ASSERT(!clips_rating_decide(&in, &dec));
            ASSERT(!dec.shown);
            dec.shown = true;
            ASSERT(!clips_rating_decide_serve(&in, CLIPS_LEVEL_MAX, &dec));
            ASSERT(!dec.shown);
        }
        PASS();
    }

_test_next:;
    if (failures == 0)
        printf("test_clips_rating: all passed\n");
    else
        printf("test_clips_rating: %d FAILED\n", failures);
    return failures;
}
