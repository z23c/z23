/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * KATHY SIERRA PRINCIPLE: Receiving money should feel like
 * upgrading to first class. Private by default = "I'm smart
 * for choosing this wallet."
 *
 * The user should think: "This wallet makes ME more private."
 * Not: "This wallet has a privacy feature." */

#include "test/spec_helpers.h"

int spec_wallet_receive(void)
{
    wallet_view_init(NULL);

    FEATURE("Privacy is the natural, obvious default") {
        STORY("private address is shown first, not public") {
            GIVEN("user opens receive page")
                GET("/wallet/receive");
            THEN("private tab is selected by default")
                EXPECT(has("active-z"));
            THEN("word 'recommended' reinforces good choice")
                EXPECT(has("recommended"));
            PASS();
        }

        STORY("shielded address explains zero-knowledge protection") {
            GIVEN("receive page loads")
                GET("/wallet/receive");
            THEN("zero-knowledge proof described")
                EXPECT(has("zero-knowledge proof"));
            PASS();
        }

        STORY("transparent address explains on-chain visibility") {
            GIVEN("receive page loads")
                GET("/wallet/receive");
            THEN("on-chain visibility described")
                EXPECT(has("on-chain"));
            PASS();
        }
    }

    FEATURE("Sharing an address is frictionless") {
        STORY("copy is a single tap, not select-all-copy") {
            GIVEN("receive page loads")
                GET("/wallet/receive");
            THEN("explicit copy button exists")
                EXPECT(has("Copy Address"));
            THEN("clipboard API is used")
                EXPECT(has("navigator.clipboard"));
            PASS();
        }

        STORY("QR code lets user share without typing") {
            GIVEN("receive page loads")
                GET("/wallet/receive");
            THEN("QR code SVG is rendered")
                EXPECT(has("<svg"));
            PASS();
        }
    }

    FEATURE("No cognitive overhead") {
        STORY("user never sees raw address format jargon") {
            GIVEN("receive page loads")
                GET("/wallet/receive");
            THEN("no mention of 'Base58Check' or 'Bech32'")
                EXPECT_NOT(has("Base58"));
                EXPECT_NOT(has("Bech32"));
            PASS();
        }
    }

    SPEC_SUMMARY();
    return SPEC_FAILURES();
}
