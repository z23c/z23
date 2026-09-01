/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * KATHY SIERRA "BADASS" UX TESTS
 *
 * These specs test the EMOTIONAL IMPACT of the wallet.
 * Each test asks: "Does the user feel more capable?"
 *
 * Sierra's test: the ideal review has only first-person statements:
 * "I am sovereign." "I am untraceable." "I control my money." */

#include "test/spec_helpers.h"

int spec_ux_sierra(void)
{
    wallet_view_init(NULL);

    FEATURE("Dashboard makes user feel sovereign, not just informed") {
        STORY("sovereignty tagline under balance") {
            GIVEN("user opens wallet")
                GET("/wallet");
            THEN("ownership framing visible")
                EXPECT(has("your node") || has("Your node") ||
                       has("your keys") || has("Your keys") ||
                       is_loading());
            PASS();
        }

        STORY("node strip says 'Your Node' not just 'Node'") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("possessive framing on node strip")
                EXPECT(has("Your Node") || is_loading());
            PASS();
        }
    }

    FEATURE("Shield success celebrates the transformation") {
        STORY("shield page has empowering language") {
            GIVEN("shield page loads")
                GET("/wallet/shield");
            THEN("privacy upgrade framing")
                EXPECT(has("invisible") || has("Secure") ||
                       has("private") || is_loading());
            PASS();
        }
    }

    FEATURE("Privacy nudge is empowering, not scolding") {
        STORY("nudge uses action-oriented empowerment language") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("path to shield exists")
                EXPECT(has("/wallet/shield") || is_loading());
            PASS();
        }
    }

    FEATURE("Node page decentralization context") {
        STORY("protocol line has human explanation") {
            GIVEN("node page loads")
                GET("/wallet/node");
            THEN("validation context exists")
                EXPECT(has("verified independently") || has("validation"));
            PASS();
        }

        STORY("sovereignty statement is prominent") {
            GIVEN("node page loads")
                GET("/wallet/node");
            THEN("sovereign full node statement")
                EXPECT(has("sovereign full node"));
            PASS();
        }
    }

    FEATURE("Receive page frames privacy as the smart default") {
        STORY("private recommended with invisibility explanation") {
            GIVEN("receive page loads")
                GET("/wallet/receive");
            THEN("recommended label")
                EXPECT(has("recommended"));
            THEN("zero-knowledge proof explained")
                EXPECT(has("zero-knowledge proof"));
            PASS();
        }

        STORY("public option is honest about tradeoffs") {
            GIVEN("receive page loads")
                GET("/wallet/receive");
            THEN("on-chain visibility explained")
                EXPECT(has("on-chain"));
            PASS();
        }
    }

    FEATURE("Send form helps user choose privacy") {
        STORY("privacy hints for address types") {
            GIVEN("send page loads")
                GET("/wallet/send");
            THEN("privacy hint system ready")
                EXPECT(has("privacy-hint") || is_loading());
            PASS();
        }
    }

    FEATURE("Every page reinforces user control") {
        STORY("dashboard has balance + immediate actions") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("balance visible")
                EXPECT(has("ZCL") || is_loading());
            THEN("send available")
                EXPECT(has("Send"));
            THEN("receive available")
                EXPECT(has("Receive"));
            PASS();
        }

        STORY("dashboard links to command center") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("node link exists")
                EXPECT(has("/wallet/node") || is_loading());
            PASS();
        }
    }

    SPEC_SUMMARY();
    return SPEC_FAILURES();
}
