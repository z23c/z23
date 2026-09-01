/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * KATHY SIERRA PRINCIPLE: Errors are not punishments.
 * Every error should make the user feel smarter.
 *
 * "A great error message says: here's what happened,
 *  here's what you can do, and here's why it'll work."
 *
 * Bad: "Error 500: Internal Server Error"
 * Good: "That address doesn't look right — check the first few characters." */

#include "test/spec_helpers.h"

int spec_wallet_errors(void)
{
    wallet_view_init(NULL);

    FEATURE("Errors guide the user, never punish") {
        STORY("bad send address gets helpful feedback") {
            GIVEN("user enters invalid address")
                POST("/wallet/send/review", "address=xyz&amount=1.0");
            THEN("response is a real page, not a crash")
                EXPECT(is_200());
            THEN("error is human-readable")
                EXPECT(has("Invalid") || has("invalid") ||
                       has("address") || has("too short"));
            PASS();
        }

        STORY("zero amount send is caught gently") {
            GIVEN("user enters zero amount")
                POST("/wallet/send/review",
                    "address=t1ExampleAddr123456789012345&amount=0");
            THEN("page renders")
                EXPECT(is_200());
            THEN("user gets clear guidance")
                EXPECT(has("Invalid") || has("amount") || has("0"));
            PASS();
        }

        STORY("missing send fields are handled") {
            GIVEN("user submits empty send form")
                POST("/wallet/send/review", "");
            THEN("no crash")
                EXPECT(is_200());
            PASS();
        }

        STORY("zero shield amount is caught") {
            GIVEN("user tries to shield zero")
                POST("/wallet/shield/confirm", "amount=0");
            THEN("page loads")
                EXPECT(is_200());
            PASS();
        }

        STORY("shield with no amount shows form") {
            GIVEN("shield loads with no amount")
                GET("/wallet/shield");
            THEN("form is shown so user can try")
                EXPECT(has("Amount") || has("amount") || is_loading());
            PASS();
        }
    }

    FEATURE("No internal errors leak to the user") {
        STORY("no stack traces on any page") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("no C error patterns")
                EXPECT_NOT(has("segfault"));
                EXPECT_NOT(has("SIGSEGV"));
                EXPECT_NOT(has("core dump"));
                EXPECT_NOT(has("stack trace"));
            PASS();
        }

        STORY("no SQL on any page") {
            GIVEN("dashboard loads")
                GET("/wallet");
                EXPECT_NOT(has("SELECT"));
                EXPECT_NOT(has("INSERT"));
                EXPECT_NOT(has("sqlite3"));
            GIVEN("send page loads")
                GET("/wallet/send");
                EXPECT_NOT(has("SELECT"));
            GIVEN("history page loads")
                GET("/wallet/history");
                EXPECT_NOT(has("SELECT"));
            GIVEN("coins page loads")
                GET("/wallet/coins");
                EXPECT_NOT(has("SELECT"));
            GIVEN("node page loads")
                GET("/wallet/node");
                EXPECT_NOT(has("SELECT"));
            PASS();
        }
    }

    FEATURE("Unknown routes fail gracefully") {
        STORY("nonexistent wallet route returns zero") {
            GIVEN("user hits unknown path")
                size_t len = GET("/wallet/nonexistent");
            THEN("no crash, returns empty")
                EXPECT(len == 0);
            PASS();
        }
    }

    SPEC_SUMMARY();
    return SPEC_FAILURES();
}
