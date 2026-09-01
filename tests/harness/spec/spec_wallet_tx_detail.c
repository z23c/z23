/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * KATHY SIERRA PRINCIPLE: Transaction details are forensics.
 * The user should feel: "I can investigate any transaction."
 * Not: "Here is a hex dump of raw transaction data."
 *
 * Power = understanding. If I can read any tx, I am dangerous. */

#include "test/spec_helpers.h"

int spec_wallet_tx_detail(void)
{
    wallet_view_init(NULL);

    FEATURE("User can investigate any transaction") {
        STORY("valid txid format shows detail page") {
            GIVEN("user navigates to a tx detail")
                GET("/wallet/tx/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
            THEN("page loads without crashing")
                EXPECT(is_200());
            THEN("breadcrumb shows path back")
                EXPECT(has("History") || has("/wallet/history"));
            PASS();
        }

        STORY("invalid txid gets helpful error, not a crash") {
            GIVEN("user enters garbage txid")
                GET("/wallet/tx/not-a-real-txid");
            THEN("page still renders")
                EXPECT(is_200());
            THEN("user gets guidance or loading state")
                EXPECT(has("Invalid") || has("invalid") ||
                       has("Not found") || has("not found") ||
                       is_loading());
            PASS();
        }

        STORY("empty txid is handled gracefully") {
            GIVEN("user hits tx detail with no txid")
                GET("/wallet/tx/");
            THEN("no crash, no blank page")
                EXPECT(is_200());
            PASS();
        }
    }

    FEATURE("No raw hex overwhelms the user") {
        STORY("tx detail page is readable by humans") {
            GIVEN("tx detail loads")
                GET("/wallet/tx/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
            THEN("no database internals leak through")
                EXPECT_NOT(has("sqlite"));
                EXPECT_NOT(has("SELECT"));
            PASS();
        }
    }

    SPEC_SUMMARY();
    return SPEC_FAILURES();
}
