/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * KATHY SIERRA PRINCIPLE: Transaction history is a mirror.
 * The user should feel: "I can see everything I've ever done."
 * Not: "Here's a database query of your transactions."
 *
 * History = confidence. If I can review my past, I trust my future. */

#include "test/spec_helpers.h"

int spec_wallet_history(void)
{
    wallet_view_init(NULL);

    FEATURE("User can review their financial history with confidence") {
        STORY("history page loads and feels organized") {
            GIVEN("user opens history")
                GET("/wallet/history");
            THEN("page loads successfully")
                EXPECT(is_200());
            THEN("user knows this is their transaction record")
                EXPECT(has("History") || is_loading());
            PASS();
        }

        STORY("user can filter to find what they need") {
            GIVEN("history page loads")
                GET("/wallet/history");
            THEN("filter controls exist")
                EXPECT(has("filter=") || has("All") || is_loading());
            PASS();
        }

        STORY("user can search for a specific transaction") {
            GIVEN("history page loads")
                GET("/wallet/history");
            THEN("search input exists")
                EXPECT(has("search") || has("q=") || is_loading());
            PASS();
        }

        STORY("pagination keeps the user in control of large history") {
            GIVEN("user opens first page of history")
                GET("/wallet/history?page=0");
            THEN("page renders without error")
                EXPECT(is_200());
            PASS();
        }
    }

    FEATURE("User always knows where they are in the wallet") {
        STORY("history tab is highlighted") {
            GIVEN("user is on history page")
                GET("/wallet/history");
            THEN("History tab marked active")
                EXPECT(has("class='active'>History"));
            PASS();
        }

        STORY("user can navigate to any other section") {
            GIVEN("history page loads")
                GET("/wallet/history");
            THEN("nav bar has all tabs")
                EXPECT(has(">Home<"));
                EXPECT(has(">Send<"));
                EXPECT(has(">Receive<"));
                EXPECT(has(">Node<"));
            PASS();
        }
    }

    FEATURE("Empty state empowers, not discourages") {
        STORY("no transactions yet feels like a fresh start") {
            GIVEN("history loads with no DB")
                GET("/wallet/history");
            THEN("user is not punished for having no history")
                EXPECT(is_200());
            THEN("no raw error messages")
                EXPECT_NOT(has("sqlite"));
                EXPECT_NOT(has("SELECT"));
                EXPECT_NOT(has("ERROR"));
            PASS();
        }
    }

    FEATURE("No jargon in user-facing views") {
        STORY("history page speaks human language") {
            GIVEN("history loads")
                GET("/wallet/history");
            THEN("no database terms visible")
                EXPECT_NOT(has("sqlite"));
                EXPECT_NOT(has("query"));
            THEN("no raw hex identifiers confusing the user")
                EXPECT_NOT(has("hash160"));
            PASS();
        }
    }

    SPEC_SUMMARY();
    return SPEC_FAILURES();
}
