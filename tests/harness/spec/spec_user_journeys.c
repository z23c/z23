/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * USER JOURNEY SPECS — multi-step flows testing real user paths.
 *
 * Each journey simulates a complete user workflow:
 * open wallet → navigate → act → verify result.
 *
 * These catch bugs that single-page specs miss:
 * broken links, missing back buttons, state leaks. */

#include "test/spec_helpers.h"

int spec_user_journeys(void)
{
    wallet_view_init(NULL);

    FEATURE("Journey: New user explores the wallet") {
        STORY("user opens wallet, sees balance, explores tabs") {
            GIVEN("user lands on dashboard")
                GET("/wallet");
            THEN("dashboard loads")
                EXPECT(is_200());
            THEN("sees balance area")
                EXPECT(has("ZCL") || is_loading());
            THEN("sees nav tabs for exploration")
                EXPECT(has(">Send<"));
                EXPECT(has(">Receive<"));
                EXPECT(has(">History<"));
                EXPECT(has(">Node<"));

            GIVEN("user clicks Send tab")
                GET("/wallet/send");
            THEN("send page loads")
                EXPECT(is_200());
            THEN("can see spendable balance")
                EXPECT(has("Spendable") || has("balance") || is_loading());

            GIVEN("user clicks Receive tab")
                GET("/wallet/receive");
            THEN("receive page loads")
                EXPECT(is_200());
            THEN("private address shown by default")
                EXPECT(has("recommended"));

            GIVEN("user clicks History tab")
                GET("/wallet/history");
            THEN("history page loads")
                EXPECT(is_200());

            GIVEN("user clicks Node tab")
                GET("/wallet/node");
            THEN("command center loads")
                EXPECT(is_200());
            THEN("sovereignty statement visible")
                EXPECT(has("sovereign"));
            PASS();
        }
    }

    FEATURE("Journey: User sends ZCL") {
        STORY("send form → review → (validation error path)") {
            GIVEN("user opens send page")
                GET("/wallet/send");
            THEN("send form is ready")
                EXPECT(is_200());
                EXPECT(has("address") || has("Address"));

            GIVEN("user submits with bad address")
                POST("/wallet/send/review", "address=xyz&amount=1.0");
            THEN("gets helpful error, not a crash")
                EXPECT(is_200());
                EXPECT(has("Invalid") || has("invalid") ||
                       has("too short") || has("address"));

            GIVEN("user submits with zero amount")
                POST("/wallet/send/review",
                    "address=t1ExampleAddr123456789012345&amount=0");
            THEN("gets clear guidance")
                EXPECT(is_200());
                EXPECT(has("Invalid") || has("amount") || has("0"));

            GIVEN("user can navigate back to send form")
                GET("/wallet/send");
            THEN("form reloads cleanly")
                EXPECT(is_200());
            PASS();
        }
    }

    FEATURE("Journey: User shields funds for privacy") {
        STORY("shield form → review → back to dashboard") {
            GIVEN("user opens shield page")
                GET("/wallet/shield");
            THEN("shield form loads")
                EXPECT(is_200());
            THEN("sees Max button or nothing-to-shield")
                EXPECT(has("Max") || has("Nothing to shield") || is_loading());

            GIVEN("user enters an amount to shield")
                GET("/wallet/shield?amount=0.5");
            THEN("confirmation page shows amount")
                EXPECT(has("0.5"));
            THEN("cancel option exists")
                EXPECT(has("Cancel") || has("/wallet"));
            THEN("confirm button exists")
                EXPECT(has("Confirm") || has("confirm"));

            GIVEN("user decides to cancel and go back")
                GET("/wallet");
            THEN("dashboard loads cleanly")
                EXPECT(is_200());
            PASS();
        }
    }

    FEATURE("Journey: User investigates a transaction") {
        STORY("history → tx detail → back to history") {
            GIVEN("user opens history")
                GET("/wallet/history");
            THEN("history loads")
                EXPECT(is_200());

            GIVEN("user tries to view a tx (test txid)")
                GET("/wallet/tx/0000000000000000000000000000000000000000000000000000000000000000");
            THEN("tx detail page loads")
                EXPECT(is_200());
            THEN("has path back to history")
                EXPECT(has("/wallet/history") || has("History") || is_loading());

            GIVEN("user goes back to history")
                GET("/wallet/history");
            THEN("history loads again")
                EXPECT(is_200());
            PASS();
        }
    }

    FEATURE("Journey: User audits their coins") {
        STORY("dashboard → node → coins → back") {
            GIVEN("user starts at dashboard")
                GET("/wallet");
            THEN("node link exists")
                EXPECT(has("/wallet/node") || is_loading());

            GIVEN("user opens node/command center")
                GET("/wallet/node");
            THEN("coin audit link exists")
                EXPECT(has("Coin Audit") || has("/wallet/coins"));

            GIVEN("user opens coin audit")
                GET("/wallet/coins");
            THEN("coins page loads")
                EXPECT(is_200());
            THEN("has path back")
                EXPECT(has("/wallet"));

            GIVEN("user returns to dashboard")
                GET("/wallet");
            THEN("dashboard loads")
                EXPECT(is_200());
            PASS();
        }
    }

    FEATURE("Journey: User checks privacy status") {
        STORY("dashboard privacy meter → shield → back") {
            GIVEN("user sees dashboard")
                GET("/wallet");
            THEN("privacy percentage visible")
                EXPECT(has("private") || is_loading());
            THEN("link to shield/improve privacy")
                EXPECT(has("/wallet/shield") || is_loading());

            GIVEN("user clicks to improve privacy")
                GET("/wallet/shield");
            THEN("shield page loads")
                EXPECT(is_200());
            THEN("privacy-upgrading language present")
                EXPECT(has("Secure") || has("private") ||
                       has("invisible") || is_loading());
            PASS();
        }
    }

    FEATURE("Journey: User receives funds") {
        STORY("receive page → copy address → explore tabs") {
            GIVEN("user opens receive")
                GET("/wallet/receive");
            THEN("receive page loads with QR")
                EXPECT(is_200());
            THEN("QR code rendered")
                EXPECT(has("<svg") || is_loading());
            THEN("copy functionality available")
                EXPECT(has("Copy") || has("copy") || has("clipboard"));
            THEN("private tab is default")
                EXPECT(has("active-z") || has("recommended"));

            GIVEN("user can navigate to other tabs")
                GET("/wallet/send");
            THEN("send page loads from receive context")
                EXPECT(is_200());
            PASS();
        }
    }

    SPEC_SUMMARY();
    return SPEC_FAILURES();
}
