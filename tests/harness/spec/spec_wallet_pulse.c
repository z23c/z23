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
    struct spec_wallet_fixture fixture;
    if (!spec_wallet_fixture_open(&fixture)) return 1;

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

    FEATURE("Unavailable wallet data is explicit") {
        STORY("pulse refuses an absent database") {
            GIVEN("the wallet database is unavailable")
                wallet_view_init(NULL);
                GET("/api/wallet/pulse");
            THEN("the pulse reports unavailability")
                EXPECT(has("503 Service Unavailable"));
                EXPECT(has("Wallet data unavailable"));
                wallet_view_init(fixture.dir);
            PASS();
        }
    }

    SPEC_SUMMARY();
    int failures = SPEC_FAILURES();
    spec_wallet_fixture_close(&fixture);
    return failures;
}
