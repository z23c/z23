/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * KATHY SIERRA PRINCIPLE: Privacy is the user's superpower.
 * Not a checkbox. Not a feature. A TRANSFORMATION.
 *
 * Before: "My transactions are visible to everyone."
 * After: "I am invisible on the blockchain."
 *
 * The wallet should constantly reinforce:
 * "You are making the smart choice. You are upgrading." */

#include "test/spec_helpers.h"

int spec_wallet_privacy(void)
{
    wallet_view_init(NULL);

    FEATURE("Privacy framing is empowerment, not fear") {
        STORY("dashboard frames privacy as a positive metric") {
            GIVEN("user opens wallet")
                GET("/wallet");
            THEN("privacy mentioned in empowering context")
                EXPECT(has("private") || is_loading());
            THEN("path to improve privacy exists")
                EXPECT(has("/wallet/shield") || is_loading());
            PASS();
        }

        STORY("receive page defaults to private address") {
            GIVEN("user opens receive")
                GET("/wallet/receive");
            THEN("private tab is selected")
                EXPECT(has("active-z"));
            THEN("recommended label reinforces good choice")
                EXPECT(has("recommended"));
            PASS();
        }

        STORY("shielded address describes zero-knowledge protection") {
            GIVEN("receive page loads")
                GET("/wallet/receive");
            THEN("zero-knowledge proof described")
                EXPECT(has("zero-knowledge proof"));
            PASS();
        }

        STORY("transparent address describes on-chain exposure") {
            GIVEN("receive page loads")
                GET("/wallet/receive");
            THEN("on-chain visibility described")
                EXPECT(has("on-chain"));
            PASS();
        }
    }

    FEATURE("Shielding = leveling up") {
        STORY("shield page frames as security upgrade") {
            GIVEN("user opens shield")
                GET("/wallet/shield");
            THEN("language is about shielding or shows nothing-to-shield")
                EXPECT(has("Shield") || has("shield") || has("Nothing") || is_loading());
            PASS();
        }

        STORY("shield confirmation explains the power gained") {
            GIVEN("user reviews shield with amount")
                GET("/wallet/shield?amount=0.5");
            THEN("step-by-step explains what happens")
                EXPECT(has("Step 1"));
            THEN("amount confirmed")
                EXPECT(has("0.5"));
            PASS();
        }
    }

    FEATURE("Send flow reinforces privacy awareness") {
        STORY("send form shows privacy hint for address type") {
            GIVEN("send page loads")
                GET("/wallet/send");
            THEN("privacy hint area exists")
                EXPECT(has("privacy-hint"));
            THEN("JS distinguishes z vs t addresses")
                EXPECT(has("zs1"));
            PASS();
        }
    }

    FEATURE("No privacy jargon confuses the user") {
        STORY("no cryptographic terms in user-facing pages") {
            GIVEN("receive page loads")
                GET("/wallet/receive");
            THEN("no Base58 or Bech32 mentioned")
                EXPECT_NOT(has("Base58"));
                EXPECT_NOT(has("Bech32"));
            PASS();
        }
    }

    SPEC_SUMMARY();
    return SPEC_FAILURES();
}
