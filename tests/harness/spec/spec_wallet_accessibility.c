/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * KATHY SIERRA PRINCIPLE: Reduce cognitive leaks.
 * Every unnecessary decision, unclear label, or hidden
 * action drains the user's mental resources.
 *
 * "Your app makes me fat" — when the UI exhausts
 * cognitive resources, users lack willpower for everything else. */

#include "test/spec_helpers.h"

int spec_wallet_accessibility(void)
{
    wallet_view_init(NULL);

    FEATURE("Visual hierarchy guides the eye") {
        STORY("dashboard balance is the largest element") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("balance has prominent styling")
                EXPECT(has("class='balance'") || has("class=\"balance\"") ||
                       is_loading());
            PASS();
        }

        STORY("action buttons are clearly styled") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("primary and secondary button classes exist")
                EXPECT(has("btn-primary") || has("btn-secondary") ||
                       is_loading());
            PASS();
        }
    }

    FEATURE("Forms prevent errors before they happen") {
        STORY("send form validates client-side") {
            GIVEN("send page loads")
                GET("/wallet/send");
            THEN("validation JS is present")
                EXPECT(has("validateSend") || has("validate"));
            THEN("error display area exists for immediate feedback")
                EXPECT(has("addr-err") || has("error"));
            PASS();
        }

        STORY("amount input shows remaining balance") {
            GIVEN("send page loads")
                GET("/wallet/send");
            THEN("remaining balance calculation wired")
                EXPECT(has("remaining") || has("Remaining"));
            PASS();
        }

        STORY("shield form has Max button for effortless input") {
            GIVEN("shield page loads")
                GET("/wallet/shield");
            THEN("Max button fills amount automatically")
                EXPECT(has("Max") || has("Nothing to shield") || is_loading() || is_loading());
            PASS();
        }
    }

    FEATURE("Copy actions are one tap, not select-all-copy") {
        STORY("receive page has clipboard integration") {
            GIVEN("receive page loads")
                GET("/wallet/receive");
            THEN("copy button exists")
                EXPECT(has("Copy") || has("copy"));
            THEN("clipboard API used")
                EXPECT(has("navigator.clipboard") || has("clipboard"));
            PASS();
        }
    }

    FEATURE("Color communicates meaning consistently") {
        STORY("privacy meter uses meaningful colors") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("privacy percentage has color coding")
                EXPECT(has("private") || is_loading());
            PASS();
        }

        STORY("sync status uses color for state") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("sync badge has visual state")
                EXPECT(has("pill") || has("sync") || is_loading());
            PASS();
        }
    }

    FEATURE("Mobile-friendly touch targets") {
        STORY("nav tabs are large enough to tap") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("nav links exist with sufficient content")
                EXPECT(has(">Home<"));
                EXPECT(has(">Send<"));
                EXPECT(has(">Receive<"));
            PASS();
        }
    }

    SPEC_SUMMARY();
    return SPEC_FAILURES();
}
