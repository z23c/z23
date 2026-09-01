/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * HTML quality specs — verify every rendered page produces
 * valid, secure, well-structured HTML. Not testing user stories
 * (those are in other specs), but testing that the HTML output
 * is production-quality. */

#include "test/spec_helpers.h"

int spec_html_quality(void)
{
    wallet_view_init(NULL);

    FEATURE("Every page produces valid HTML structure") {
        STORY("dashboard has doctype, head, body") {
            GIVEN("dashboard renders")
                GET("/wallet");
            THEN("HTTP 200 response")
                EXPECT(is_200());
            THEN("has HTML structure")
                EXPECT(has("<!DOCTYPE html") || has("<!doctype html"));
            THEN("has charset meta")
                EXPECT(has("charset"));
            THEN("has viewport meta for mobile")
                EXPECT(has("viewport"));
            THEN("body closes properly")
                EXPECT(has("</body>") || has("</html>"));
            PASS();
        }

        STORY("send page has valid structure") {
            GIVEN("send renders")
                GET("/wallet/send");
            THEN("HTTP 200")
                EXPECT(is_200());
            THEN("has doctype")
                EXPECT(has("<!DOCTYPE html") || has("<!doctype html"));
            THEN("has viewport")
                EXPECT(has("viewport"));
            PASS();
        }

        STORY("receive page has valid structure") {
            GIVEN("receive renders")
                GET("/wallet/receive");
            THEN("HTTP 200")
                EXPECT(is_200());
            THEN("has viewport")
                EXPECT(has("viewport"));
            PASS();
        }

        STORY("history page has valid structure") {
            GIVEN("history renders")
                GET("/wallet/history");
            THEN("HTTP 200")
                EXPECT(is_200());
            THEN("has viewport")
                EXPECT(has("viewport"));
            PASS();
        }

        STORY("node page has valid structure") {
            GIVEN("node renders")
                GET("/wallet/node");
            THEN("HTTP 200")
                EXPECT(is_200());
            THEN("has viewport")
                EXPECT(has("viewport"));
            PASS();
        }

        STORY("coins page has valid structure") {
            GIVEN("coins renders")
                GET("/wallet/coins");
            THEN("HTTP 200")
                EXPECT(is_200());
            THEN("has viewport")
                EXPECT(has("viewport"));
            PASS();
        }

        STORY("shield page has valid structure") {
            GIVEN("shield renders")
                GET("/wallet/shield");
            THEN("HTTP 200")
                EXPECT(is_200());
            THEN("has viewport")
                EXPECT(has("viewport"));
            PASS();
        }
    }

    FEATURE("CSS is consistent and present on every page") {
        STORY("dashboard has styled CSS") {
            GIVEN("dashboard renders")
                GET("/wallet");
            THEN("CSS styles present")
                EXPECT(has("<style") || has("stylesheet"));
            THEN("dark theme colors used")
                EXPECT(has("#0a0a0a") || has("#111") || has("#1a1a1a") ||
                       has("background"));
            PASS();
        }

        STORY("send page has consistent styling") {
            GIVEN("send renders")
                GET("/wallet/send");
            THEN("CSS present")
                EXPECT(has("<style") || has("stylesheet"));
            PASS();
        }
    }

    FEATURE("No XSS vectors in rendered HTML") {
        STORY("script injection in URL params is escaped") {
            GIVEN("history with XSS in search param")
                GET("/wallet/history?q=<script>alert(1)</script>");
            THEN("page renders without raw script tag")
                EXPECT_NOT(has("<script>alert"));
            PASS();
        }

        STORY("tx detail with XSS in txid is safe") {
            GIVEN("tx detail with script injection")
                GET("/wallet/tx/<script>alert(1)</script>");
            THEN("no raw script tag in output")
                EXPECT_NOT(has("<script>alert"));
            PASS();
        }
    }

    FEATURE("Every page has proper title") {
        STORY("dashboard has title") {
            GIVEN("dashboard renders")
                GET("/wallet");
            THEN("title tag present")
                EXPECT(has("<title>") || has("<title "));
            THEN("title contains Z23")
                EXPECT(has("Z23"));
            PASS();
        }

        STORY("send page has title") {
            GIVEN("send renders")
                GET("/wallet/send");
            THEN("title present")
                EXPECT(has("<title>"));
            PASS();
        }

        STORY("node page has title") {
            GIVEN("node renders")
                GET("/wallet/node");
            THEN("title present")
                EXPECT(has("<title>"));
            PASS();
        }
    }

    FEATURE("Pulse API returns valid JSON") {
        STORY("pulse response is JSON, not HTML") {
            GIVEN("pulse endpoint called")
                GET("/api/wallet/pulse");
            THEN("response contains JSON structure")
                EXPECT(has("{"));
            THEN("has required fields")
                EXPECT(has("height"));
                EXPECT(has("balance"));
                EXPECT(has("peers"));
            THEN("is NOT HTML")
                EXPECT_NOT(has("<!DOCTYPE"));
                EXPECT_NOT(has("<html"));
            PASS();
        }
    }

    FEATURE("POST endpoints handle edge cases") {
        STORY("send review with empty body") {
            GIVEN("POST with empty body")
                POST("/wallet/send/review", "");
            THEN("renders without crash")
                EXPECT(is_200());
            PASS();
        }

        STORY("send review with very long address") {
            GIVEN("POST with oversized address")
                POST("/wallet/send/review",
                    "address=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    "&amount=1.0");
            THEN("renders without crash")
                EXPECT(is_200());
            PASS();
        }

        STORY("shield confirm with negative amount") {
            GIVEN("POST with negative amount")
                POST("/wallet/shield/confirm", "amount=-1.0");
            THEN("renders without crash")
                EXPECT(is_200());
            PASS();
        }

        STORY("shield confirm with huge amount") {
            GIVEN("POST with absurd amount")
                POST("/wallet/shield/confirm", "amount=999999999.0");
            THEN("renders without crash")
                EXPECT(is_200());
            PASS();
        }

        STORY("send confirm with empty body") {
            GIVEN("POST with empty body")
                POST("/wallet/send/confirm", "");
            THEN("renders without crash")
                EXPECT(is_200());
            PASS();
        }
    }

    FEATURE("History pagination handles edge cases") {
        STORY("negative page number clamped to 0") {
            GIVEN("history with negative page")
                GET("/wallet/history?page=-1");
            THEN("renders successfully")
                EXPECT(is_200());
            PASS();
        }

        STORY("huge page number handled gracefully") {
            GIVEN("history with very large page")
                GET("/wallet/history?page=99999");
            THEN("renders without crash")
                EXPECT(is_200());
            PASS();
        }

        STORY("filter parameter handled") {
            GIVEN("history with filter")
                GET("/wallet/history?filter=sent");
            THEN("renders successfully")
                EXPECT(is_200());
            PASS();
        }

        STORY("search parameter handled") {
            GIVEN("history with search")
                GET("/wallet/history?q=abcdef");
            THEN("renders successfully")
                EXPECT(is_200());
            PASS();
        }
    }

    SPEC_SUMMARY();
    return SPEC_FAILURES();
}
