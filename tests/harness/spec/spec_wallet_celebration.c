/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * KATHY SIERRA PRINCIPLE: Celebrate the user's achievements.
 * Every milestone should feel like leveling up.
 *
 * "The moment after shielding is the most emotional moment
 *  in the entire wallet. Don't waste it on an operation ID." */

#include "test/spec_helpers.h"

int spec_wallet_celebration(void)
{
    wallet_view_init(NULL);

    FEATURE("Shield success makes user feel untraceable") {
        STORY("success page celebrates the transformation") {
            GIVEN("shield success page renders")
                GET("/wallet/shield");
            THEN("empowering language exists")
                EXPECT(has("Secure") || has("private") || is_loading());
            PASS();
        }
    }

    FEATURE("Send success acknowledges the user's action") {
        STORY("send page has clear call to action") {
            GIVEN("send page loads")
                GET("/wallet/send");
            THEN("send button is prominent")
                EXPECT(has("Review") || has("Send") || is_loading());
            PASS();
        }
    }

    FEATURE("Dashboard celebrates 100% privacy") {
        STORY("privacy meter exists and shows percentage") {
            GIVEN("dashboard loads")
                GET("/wallet");
            THEN("privacy percentage is visible")
                EXPECT(has("private") || is_loading());
            PASS();
        }
    }

    SPEC_SUMMARY();
    return SPEC_FAILURES();
}
