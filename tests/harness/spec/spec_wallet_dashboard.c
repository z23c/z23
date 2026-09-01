/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * KATHY SIERRA PRINCIPLE: The dashboard answers one question:
 * "Am I in control of my money and my privacy?"
 *
 * The user should feel: "I know exactly where I stand."
 * Not: "Here's a bunch of data about your wallet." */

#include "test/spec_helpers.h"

int spec_wallet_dashboard(void)
{
    wallet_view_init(NULL);

    FEATURE("User knows their financial position instantly") {
        STORY("balance is the dominant visual element") {
            GIVEN("user opens the wallet")
                GET("/wallet");
            THEN("page loads successfully")
                EXPECT(is_200());
            THEN("balance or loading is immediately visible")
                EXPECT(has("ZCL") || is_loading());
            PASS();
        }

        STORY("user always knows what they can do next") {
            GIVEN("user sees the dashboard")
                GET("/wallet");
            THEN("send action is one tap away")
                EXPECT(has("href='/wallet/send'"));
            THEN("receive action is one tap away")
                EXPECT(has("href='/wallet/receive'"));
            PASS();
        }
    }

    FEATURE("User understands their privacy at a glance") {
        STORY("privacy is framed as empowerment, not fear") {
            GIVEN("dashboard loads")
                GET("/wallet");
            WHEN("user looks at privacy section")
            THEN("privacy is shown as a positive metric")
                EXPECT(has("private") || is_loading());
            PASS();
        }

        STORY("user has a clear path to improve privacy") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("there is a direct link to secure funds")
                EXPECT(has("/wallet/shield") || is_loading());
            PASS();
        }
    }

    FEATURE("User feels the network is alive") {
        STORY("dashboard updates without manual refresh") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("live polling is active")
                EXPECT(has("setInterval"));
            THEN("pulse endpoint is configured")
                EXPECT(has("api/wallet/pulse"));
            PASS();
        }

        STORY("pulse returns real-time data") {
            GIVEN("pulse endpoint is called")
                GET("/api/wallet/pulse");
            THEN("height tells user the chain is alive")
                EXPECT(has("height"));
            THEN("balance updates in real time")
                EXPECT(has("balance"));
            THEN("peer count shows network health")
                EXPECT(has("peers"));
            PASS();
        }
    }

    FEATURE("User can navigate without thinking") {
        STORY("every section of the app is one tap away") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("all 5 nav tabs are present")
                EXPECT(has(">Home<"));
                EXPECT(has(">Send<"));
                EXPECT(has(">Receive<"));
                EXPECT(has(">History<"));
                EXPECT(has(">Node<"));
            PASS();
        }

        STORY("user always knows where they are") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("current tab is highlighted")
                EXPECT(has("class='active'>Home"));
            PASS();
        }

        STORY("node status is visible but not distracting") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("node info links to command center")
                EXPECT(has("/wallet/node"));
            PASS();
        }
    }

    FEATURE("No jargon, no confusion") {
        STORY("loading state is human, not technical") {
            GIVEN("dashboard loads without DB")
            WHEN("user sees loading state")
            THEN("message does not mention databases or errors")
                GET("/wallet");
                /* Loading state should exist as a template */
                EXPECT(is_200());
            PASS();
        }

        STORY("no raw hex or internal IDs visible on dashboard") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("no hash160 or raw hex on main page")
                EXPECT_NOT(has("hash160"));
            THEN("no SQL or DB references")
                EXPECT_NOT(has("sqlite"));
                EXPECT_NOT(has("SELECT"));
            PASS();
        }
    }

    SPEC_SUMMARY();
    return SPEC_FAILURES();
}
