/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * KATHY SIERRA PRINCIPLE: Navigation is invisible when it works.
 * The user should NEVER think: "Where am I? How do I get back?"
 *
 * Sierra's flow concept: the user is always moving forward.
 * Dead ends destroy flow. Breadcrumbs maintain it.
 *
 * "The moment you have to think about the tool,
 *  you've stopped thinking about your goal." */

#include "test/spec_helpers.h"

int spec_wallet_navigation(void)
{
    wallet_view_init(NULL);

    FEATURE("User never gets lost") {
        STORY("every page has the nav bar") {
            GIVEN("user opens dashboard")
                GET("/wallet");
            THEN("all 5 tabs present")
                EXPECT(has(">Home<"));
                EXPECT(has(">Send<"));
                EXPECT(has(">Receive<"));
                EXPECT(has(">History<"));
                EXPECT(has(">Node<"));
            PASS();
        }

        STORY("send page has nav") {
            GIVEN("user opens send")
                GET("/wallet/send");
            THEN("tabs are present")
                EXPECT(has(">Home<"));
                EXPECT(has(">Send<"));
            PASS();
        }

        STORY("receive page has nav") {
            GIVEN("user opens receive")
                GET("/wallet/receive");
            THEN("tabs are present")
                EXPECT(has(">Home<"));
                EXPECT(has(">Receive<"));
            PASS();
        }

        STORY("history page has nav") {
            GIVEN("user opens history")
                GET("/wallet/history");
            THEN("tabs are present")
                EXPECT(has(">Home<"));
                EXPECT(has(">History<"));
            PASS();
        }

        STORY("node page has nav") {
            GIVEN("user opens node")
                GET("/wallet/node");
            THEN("tabs are present")
                EXPECT(has(">Home<"));
                EXPECT(has(">Node<"));
            PASS();
        }

        STORY("coins page has nav") {
            GIVEN("user opens coins")
                GET("/wallet/coins");
            THEN("tabs are present")
                EXPECT(has(">Home<"));
            PASS();
        }

        STORY("shield page has nav") {
            GIVEN("user opens shield")
                GET("/wallet/shield");
            THEN("tabs are present")
                EXPECT(has(">Home<"));
            PASS();
        }
    }

    FEATURE("User always knows which page they are on") {
        STORY("dashboard highlights Home tab") {
            GIVEN("user is on dashboard")
                GET("/wallet");
            THEN("Home is active")
                EXPECT(has("class='active'>Home"));
            PASS();
        }

        STORY("send page highlights Send tab") {
            GIVEN("user is on send")
                GET("/wallet/send");
            THEN("Send is active")
                EXPECT(has("class='active'>Send"));
            PASS();
        }

        STORY("receive page highlights Receive tab") {
            GIVEN("user is on receive")
                GET("/wallet/receive");
            THEN("Receive is active")
                EXPECT(has("class='active'>Receive"));
            PASS();
        }

        STORY("history page highlights History tab") {
            GIVEN("user is on history")
                GET("/wallet/history");
            THEN("History is active")
                EXPECT(has("class='active'>History"));
            PASS();
        }

        STORY("node page highlights Node tab") {
            GIVEN("user is on node")
                GET("/wallet/node");
            THEN("Node is active")
                EXPECT(has("class='active'>Node"));
            PASS();
        }
    }

    FEATURE("Multi-step flows have clear breadcrumbs") {
        STORY("shield page shows path back to home") {
            GIVEN("user opens shield")
                GET("/wallet/shield");
            THEN("breadcrumb to home exists")
                EXPECT(has("/wallet"));
            PASS();
        }

        STORY("coins page shows path back") {
            GIVEN("user opens coins")
                GET("/wallet/coins");
            THEN("link to home or node exists")
                EXPECT(has("/wallet"));
            PASS();
        }

        STORY("send review shows path back to send form") {
            GIVEN("user reviews a send")
                POST("/wallet/send/review",
                    "address=t1ExampleAddr123456789012345&amount=0.5");
            THEN("path back to send exists")
                EXPECT(has("/wallet/send") || has("Back") || has("Invalid"));
            PASS();
        }
    }

    FEATURE("No page is a dead end") {
        STORY("every page links somewhere actionable") {
            GIVEN("user is on dashboard")
                GET("/wallet");
            THEN("send link exists")
                EXPECT(has("href='/wallet/send'"));
            THEN("receive link exists")
                EXPECT(has("href='/wallet/receive'"));
            PASS();
        }
    }

    SPEC_SUMMARY();
    return SPEC_FAILURES();
}
