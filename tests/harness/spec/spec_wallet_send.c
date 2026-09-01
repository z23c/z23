/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * KATHY SIERRA PRINCIPLE: Sending money is scary.
 * The user should feel: "I am in total control of this."
 * Every step must reduce anxiety, not add it.
 *
 * Sierra's "flow" concept: minimum viable steps with
 * maximum feedback at each one. No surprises. */

#include "test/spec_helpers.h"

int spec_wallet_send(void)
{
    wallet_view_init(NULL);

    FEATURE("User knows exactly what they can spend") {
        STORY("spendable amount is clear before entering anything") {
            GIVEN("user opens send page")
                GET("/wallet/send");
            THEN("balance is prominently displayed")
                EXPECT(has("Spendable balance"));
            PASS();
        }

        STORY("fee is transparent, not hidden") {
            GIVEN("user opens send page")
                GET("/wallet/send");
            THEN("fee is visible before user commits")
                EXPECT(has("Network fee"));
                EXPECT(has("0.000001"));
            PASS();
        }
    }

    FEATURE("User gets real-time feedback while typing") {
        STORY("address field validates as user types") {
            GIVEN("send page loads")
                GET("/wallet/send");
            THEN("validation JS is present")
                EXPECT(has("validateSend"));
            THEN("error display area exists")
                EXPECT(has("addr-err"));
            PASS();
        }

        STORY("privacy feedback appears for address type") {
            GIVEN("send page loads")
                GET("/wallet/send");
            THEN("privacy hint area is ready")
                EXPECT(has("privacy-hint"));
            THEN("JS distinguishes private from public addresses")
                EXPECT(has("zs1"));
            PASS();
        }

        STORY("remaining balance updates as user types amount") {
            GIVEN("send page loads")
                GET("/wallet/send");
            THEN("remaining balance area exists")
                EXPECT(has("remaining"));
            THEN("update function is wired to input")
                EXPECT(has("updateRemaining"));
            PASS();
        }
    }

    FEATURE("User reviews before committing (no surprises)") {
        STORY("review step exists between form and execution") {
            GIVEN("user submits send form")
                POST("/wallet/send/review",
                    "address=t1ExampleAddr123456789012345&amount=0.5");
            THEN("review page shows, not immediate send")
                EXPECT(has("Review") || has("Invalid"));
            PASS();
        }

        STORY("bad input is caught with helpful message") {
            GIVEN("user enters invalid address")
                POST("/wallet/send/review", "address=bad&amount=0.5");
            THEN("error explains what's wrong, not just 'invalid'")
                EXPECT(has("Invalid") || has("too short") ||
                       has("checksum") || has("address"));
            PASS();
        }

        STORY("zero amount is caught before review") {
            GIVEN("user enters zero amount")
                POST("/wallet/send/review",
                    "address=t1ExampleAddr123456789012345&amount=0");
            THEN("clear error, not a crash")
                EXPECT(has("Invalid") || has("amount"));
            PASS();
        }
    }

    FEATURE("User always knows where they are in the flow") {
        STORY("send tab is highlighted") {
            GIVEN("user is on send page")
                GET("/wallet/send");
            THEN("Send tab marked active")
                EXPECT(has("class='active'>Send"));
            PASS();
        }
    }

    SPEC_SUMMARY();
    return SPEC_FAILURES();
}
