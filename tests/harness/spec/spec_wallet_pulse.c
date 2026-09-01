/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * KATHY SIERRA PRINCIPLE: The pulse is a heartbeat.
 * The user should feel: "My node is alive. The network is alive."
 * Real-time data creates the illusion of life.
 *
 * "The best interfaces feel alive — like they're breathing." */

#include "test/spec_helpers.h"

int spec_wallet_pulse(void)
{
    wallet_view_init(NULL);

    FEATURE("User feels the network is alive without refreshing") {
        STORY("pulse endpoint returns real-time JSON") {
            GIVEN("dashboard polls for updates")
                GET("/api/wallet/pulse");
            THEN("response contains height — the chain is alive")
                EXPECT(has("height"));
            THEN("balance updates in real time")
                EXPECT(has("balance"));
            THEN("peer count shows the network breathing")
                EXPECT(has("peers"));
            PASS();
        }

        STORY("pulse includes sync state for user awareness") {
            GIVEN("pulse endpoint is called")
                GET("/api/wallet/pulse");
            THEN("sync state tells user if they're caught up")
                EXPECT(has("sync"));
            PASS();
        }

        STORY("pulse includes mempool for liveness") {
            GIVEN("pulse endpoint is called")
                GET("/api/wallet/pulse");
            THEN("mempool count shows pending activity")
                EXPECT(has("mempool"));
            PASS();
        }
    }

    FEATURE("Dashboard uses pulse to stay current") {
        STORY("dashboard has polling configured") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("setInterval polls the pulse endpoint")
                EXPECT(has("setInterval"));
                EXPECT(has("api/wallet/pulse"));
            PASS();
        }
    }

    SPEC_SUMMARY();
    return SPEC_FAILURES();
}
