/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * KATHY SIERRA PRINCIPLE: Running a full node is the ultimate "I Rule!"
 * The user is not a customer. They are a SOVEREIGN.
 *
 * "I don't ask permission. I don't trust third parties.
 *  I validate every block myself. I AM the network."
 *
 * Sierra's test: write the ideal user review.
 * Target: "I run a full ZClassic node. I verify my own transactions.
 *  I host a Tor hidden service. Nobody can censor me." */

#include "test/spec_helpers.h"

int spec_wallet_sovereignty(void)
{
    wallet_view_init(NULL);

    FEATURE("User feels like they ARE the network") {
        STORY("node page conveys power and authority") {
            GIVEN("user opens command center")
                GET("/wallet/node");
            THEN("page title conveys control")
                EXPECT(has("Command Center"));
            THEN("block height shows chain awareness")
                EXPECT(has("Block Height"));
            THEN("peer count shows network membership")
                EXPECT(has("Connected Peers"));
            PASS();
        }

        STORY("version identity makes user feel unique") {
            GIVEN("node page loads")
                GET("/wallet/node");
            THEN("version string shows what they run")
                EXPECT(has("ZClassic23:0.1.0"));
            THEN("protocol capabilities listed")
                EXPECT(has("NODE_NETWORK"));
            PASS();
        }

        STORY("Tor status makes user feel untraceable") {
            GIVEN("node page loads")
                GET("/wallet/node");
            THEN("Tor section exists")
                EXPECT(has("Tor Hidden Service"));
            PASS();
        }
    }

    FEATURE("User can audit their own chain") {
        STORY("coin audit is accessible from node page") {
            GIVEN("node page loads")
                GET("/wallet/node");
            THEN("coin audit linked")
                EXPECT(has("Coin Audit"));
            THEN("block explorer linked")
                EXPECT(has("Block Explorer"));
            PASS();
        }

        STORY("coin audit shows complete UTXO inventory") {
            GIVEN("coins page loads")
                GET("/wallet/coins");
            THEN("UTXO data or loading state shown")
                EXPECT(has("Coin Audit") || is_loading());
            PASS();
        }
    }

    FEATURE("Dashboard is a sovereignty mirror") {
        STORY("balance shows user their exact financial position") {
            GIVEN("user opens wallet")
                GET("/wallet");
            THEN("balance shown prominently")
                EXPECT(has("ZCL") || is_loading());
            PASS();
        }

        STORY("node info on dashboard shows live network") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("node status links to command center")
                EXPECT(has("/wallet/node"));
            PASS();
        }

        STORY("real-time updates prove the node is alive") {
            GIVEN("pulse endpoint called")
                GET("/api/wallet/pulse");
            THEN("height confirms chain tip tracking")
                EXPECT(has("height"));
            THEN("peers confirm network participation")
                EXPECT(has("peers"));
            PASS();
        }
    }

    FEATURE("User's words, not developer words") {
        STORY("no internal identifiers on user-facing pages") {
            GIVEN("dashboard loads")
                GET("/wallet");
                EXPECT_NOT(has("hash160"));
                EXPECT_NOT(has("sqlite"));
                EXPECT_NOT(has("SELECT"));
            GIVEN("node page loads")
                GET("/wallet/node");
                EXPECT_NOT(has("sqlite"));
                EXPECT_NOT(has("SELECT"));
            PASS();
        }
    }

    SPEC_SUMMARY();
    return SPEC_FAILURES();
}
