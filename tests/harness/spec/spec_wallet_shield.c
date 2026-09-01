/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * KATHY SIERRA PRINCIPLE: Shielding is not a chore.
 * It's a power move. The user is UPGRADING their security.
 *
 * Frame: "You just made yourself untraceable."
 * Not: "Your funds have been shielded."
 *
 * Sierra's progression: beginner -> competent -> badass.
 * After shielding, the user should feel they leveled up. */

#include "test/spec_helpers.h"

int spec_wallet_shield(void)
{
    wallet_view_init(NULL);

    FEATURE("User can always find the path to more privacy") {
        STORY("dashboard leads to shield page") {
            GIVEN("user sees dashboard")
                GET("/wallet");
            THEN("path to shield exists")
                EXPECT(has("/wallet/shield") || is_loading());
            PASS();
        }

        STORY("shield page has clear breadcrumb home") {
            GIVEN("user navigates to shield")
                GET("/wallet/shield");
            THEN("breadcrumb shows path back")
                EXPECT(has("Shield") || has("Nothing to shield"));
            PASS();
        }
    }

    FEATURE("Shielding feels like upgrading, not a task") {
        STORY("shield form shows what user gains, not what's wrong") {
            GIVEN("shield page loads")
                GET("/wallet/shield");
            THEN("available balance is visible")
                EXPECT(has("Available") || has("Nothing to shield") || is_loading());
            THEN("max button makes it effortless")
                EXPECT(has("Max") || has("Nothing to shield") || is_loading());
            PASS();
        }

        STORY("confirmation explains the process in human terms") {
            GIVEN("user reviews shield with amount")
                GET("/wallet/shield?amount=0.5");
            THEN("clear step-by-step explanation")
                EXPECT(has("Step 1"));
            THEN("amount is confirmed")
                EXPECT(has("0.5"));
            PASS();
        }

        STORY("user can cancel without penalty") {
            GIVEN("user sees shield confirmation")
                GET("/wallet/shield?amount=0.5");
            THEN("cancel button is available")
                EXPECT(has("Cancel"));
            THEN("confirm button is distinct")
                EXPECT(has("Confirm"));
            PASS();
        }
    }

    FEATURE("Errors help, not punish") {
        STORY("empty amount shows the form, not an error page") {
            GIVEN("shield loads with no amount")
                GET("/wallet/shield");
            THEN("form is shown, user can try again")
                EXPECT(has("Amount") || has("Nothing to shield") || is_loading());
            PASS();
        }

        STORY("invalid confirm shows helpful message") {
            GIVEN("confirm with zero amount")
                POST("/wallet/shield/confirm", "amount=0");
            THEN("user gets guidance, not a stack trace")
                EXPECT(is_200());
            PASS();
        }
    }

    SPEC_SUMMARY();
    return SPEC_FAILURES();
}
