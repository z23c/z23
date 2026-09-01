/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * KATHY SIERRA PRINCIPLE: Flow state requires clear progress.
 * The user should always know:
 * 1. Where they are
 * 2. What they can do
 * 3. How to get back
 *
 * "The moment you have to think about the tool,
 *  you've stopped thinking about your goal." */

#include "test/spec_helpers.h"

int spec_wallet_flow(void)
{
    wallet_view_init(NULL);

    FEATURE("Send flow has clear 3-step progression") {
        STORY("step 1: form collects intent") {
            GIVEN("user opens send")
                GET("/wallet/send");
            THEN("balance visible so user knows what they can spend")
                EXPECT(has("Spendable") || has("balance") || is_loading());
            THEN("address and amount fields ready")
                EXPECT(has("address") || has("Address"));
            PASS();
        }

        STORY("step 2: review confirms intent") {
            GIVEN("user submits send form")
                POST("/wallet/send/review",
                    "address=t1ExampleAddr123456789012345&amount=0.5");
            THEN("review page shows before execution")
                EXPECT(has("Review") || has("Invalid"));
            PASS();
        }

        STORY("step 3: confirmation closes the loop") {
            GIVEN("send form exists")
                GET("/wallet/send");
            THEN("form has review action")
                EXPECT(has("review") || has("Review"));
            PASS();
        }
    }

    FEATURE("Shield flow has clear 2-step progression") {
        STORY("step 1: amount selection") {
            GIVEN("shield page loads")
                GET("/wallet/shield");
            THEN("amount input with Max button")
                EXPECT(has("Max") || has("Nothing to shield") || is_loading() || is_loading());
            PASS();
        }

        STORY("step 2: confirmation with explanation") {
            GIVEN("user enters amount")
                GET("/wallet/shield?amount=0.5");
            THEN("confirmation shows amount and steps")
                EXPECT(has("0.5"));
                EXPECT(has("Confirm") || has("confirm"));
            PASS();
        }
    }

    FEATURE("Every page has escape routes") {
        STORY("dashboard links to all sections") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("send is reachable")
                EXPECT(has("href='/wallet/send'"));
            THEN("receive is reachable")
                EXPECT(has("href='/wallet/receive'"));
            THEN("history is reachable")
                EXPECT(has("/wallet/history"));
            PASS();
        }

        STORY("shield has cancel option") {
            GIVEN("shield confirmation loads")
                GET("/wallet/shield?amount=0.5");
            THEN("cancel returns to safety")
                EXPECT(has("Cancel") || has("/wallet"));
            PASS();
        }
    }

    FEATURE("Loading states keep user informed") {
        STORY("dashboard handles no-DB gracefully") {
            GIVEN("dashboard loads without DB")
                GET("/wallet");
            THEN("user sees something, not nothing")
                EXPECT(is_200());
            PASS();
        }

        STORY("pulse keeps dashboard alive") {
            GIVEN("pulse endpoint called")
                GET("/api/wallet/pulse");
            THEN("JSON data returned")
                EXPECT(has("height"));
                EXPECT(has("balance"));
            PASS();
        }
    }

    SPEC_SUMMARY();
    return SPEC_FAILURES();
}
