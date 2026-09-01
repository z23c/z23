/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * KATHY SIERRA PRINCIPLE: The user is the hero, not the software.
 * Every screen should answer: "What can I do? What am I?"
 *
 * Frame: "I control the blockchain. I verify every block.
 *  I host a hidden service. I mint tokens."
 * Not: "Z23 is a full node implementation." */

#include "test/spec_helpers.h"

int spec_wallet_empowerment(void)
{
    wallet_view_init(NULL);

    FEATURE("Dashboard tells user WHO they are") {
        STORY("balance area shows ownership, not just numbers") {
            GIVEN("user opens wallet")
                GET("/wallet");
            THEN("ZCL denomination is clear")
                EXPECT(has("ZCL") || is_loading());
            THEN("actions are immediately available")
                EXPECT(has("Send"));
                EXPECT(has("Receive"));
            PASS();
        }

        STORY("node strip shows the user is part of the network") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("peer count shows network participation")
                EXPECT(has("peers") || is_loading());
            THEN("block height shows chain awareness")
                EXPECT(has("Block") || is_loading());
            PASS();
        }
    }

    FEATURE("Node page makes user feel sovereign") {
        STORY("heading conveys power and control") {
            GIVEN("user opens command center")
                GET("/wallet/node");
            THEN("sovereignty language is present")
                EXPECT(has("sovereign") || has("Sovereign"));
            THEN("user sees their identity on the network")
                EXPECT(has("ZClassic23:0.1.0"));
            PASS();
        }

        STORY("user sees what they control") {
            GIVEN("node page loads")
                GET("/wallet/node");
            THEN("supply shows scale of what user verifies")
                EXPECT(has("Supply") || has("supply"));
            THEN("UTXO set shows depth of verification")
                EXPECT(has("UTXO") || has("utxo") || has("outputs"));
            PASS();
        }
    }

    FEATURE("Shield flow empowers, not lectures") {
        STORY("shield page uses empowering language") {
            GIVEN("shield page loads")
                GET("/wallet/shield");
            THEN("framing is about gaining power, not following instructions")
                EXPECT(has("private") || has("invisible") ||
                       has("unlink") || is_loading());
            PASS();
        }

        STORY("shield confirmation explains the transformation") {
            GIVEN("user reviews shield amount")
                GET("/wallet/shield?amount=0.5");
            THEN("steps explain what user GAINS")
                EXPECT(has("private") || has("Private"));
            THEN("timing explanation gives context")
                EXPECT(has("privacy") || has("Privacy"));
            PASS();
        }
    }

    FEATURE("Receive page makes privacy the obvious default") {
        STORY("private is recommended and explained") {
            GIVEN("receive page loads")
                GET("/wallet/receive");
            THEN("recommended label on private tab")
                EXPECT(has("recommended"));
            THEN("zero-knowledge proof explained")
                EXPECT(has("zero-knowledge proof"));
            PASS();
        }

        STORY("public option honestly explains the tradeoff") {
            GIVEN("receive page loads")
                GET("/wallet/receive");
            THEN("on-chain visibility explained")
                EXPECT(has("on-chain"));
            PASS();
        }
    }

    FEATURE("Send form helps user make smart privacy choices") {
        STORY("address type determines privacy feedback") {
            GIVEN("send page loads")
                GET("/wallet/send");
            THEN("privacy hint area exists")
                EXPECT(has("privacy-hint"));
            THEN("JS handles z-address detection")
                EXPECT(has("zs1"));
            PASS();
        }
    }

    SPEC_SUMMARY();
    return SPEC_FAILURES();
}
