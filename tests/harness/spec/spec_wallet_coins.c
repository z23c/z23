/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * KATHY SIERRA PRINCIPLE: The coin audit is X-ray vision.
 * The user should feel: "I can see every satoshi I own."
 * This is a power user feature that makes the user feel omniscient.
 *
 * Frame: "You see what no one else can see — your exact coins."
 * Not: "Here is a UTXO table." */

#include "test/spec_helpers.h"

int spec_wallet_coins(void)
{
    wallet_view_init(NULL);

    FEATURE("User can audit every coin they own") {
        STORY("coin audit page loads with authority") {
            GIVEN("user opens coin audit")
                GET("/wallet/coins");
            THEN("page loads successfully")
                EXPECT(is_200());
            THEN("user knows this is their coin inventory")
                EXPECT(has("Coin Audit") || is_loading());
            PASS();
        }

        STORY("breadcrumb keeps user oriented") {
            GIVEN("coins page loads")
                GET("/wallet/coins");
            THEN("path back to home is clear")
                EXPECT(has("/wallet") || is_loading());
            PASS();
        }
    }

    FEATURE("Coins page reveals the full picture") {
        STORY("transparent coins are listed") {
            GIVEN("coins page loads")
                GET("/wallet/coins");
            THEN("UTXO data or loading shown")
                EXPECT(has("ZCL") || has("UTXO") || is_loading());
            PASS();
        }

        STORY("shielded notes section exists") {
            GIVEN("coins page loads")
                GET("/wallet/coins");
            THEN("sapling notes section present")
                EXPECT(has("Sapling") || has("Shielded") ||
                       has("Notes") || is_loading());
            PASS();
        }

        STORY("ZSLP tokens are visible") {
            GIVEN("coins page loads")
                GET("/wallet/coins");
            THEN("token section present")
                EXPECT(has("Token") || has("ZSLP") || is_loading());
            PASS();
        }
    }

    FEATURE("No technical jargon scares the user away") {
        STORY("coins page is clean of database internals") {
            GIVEN("coins page loads")
                GET("/wallet/coins");
            THEN("no SQL visible")
                EXPECT_NOT(has("SELECT"));
                EXPECT_NOT(has("sqlite"));
            THEN("no raw error dumps")
                EXPECT_NOT(has("ERROR"));
                EXPECT_NOT(has("segfault"));
            PASS();
        }
    }

    SPEC_SUMMARY();
    return SPEC_FAILURES();
}
