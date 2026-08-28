/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Native acceptance for the bounded platform glob matcher. */
#include "platform/glob_match.h"

#include <stdio.h>

static int expect(bool value, const char *name)
{
    if (value) return 0;
    fprintf(stderr, "glob_match_acceptance: FAIL %s\n", name);
    return 1;
}

int main(void)
{
    int failures = 0;
    failures += expect(platform_glob_match("tools/*", "tools/a/b", false),
                       "star crosses separators without pathname mode");
    failures += expect(!platform_glob_match("tools/*", "tools/a/b", true),
                       "pathname star stops at separator");
    failures += expect(platform_glob_match("lib/test_*.c", "lib/test_a.c", true),
                       "repository wildcard");
    failures += expect(platform_glob_match("test_[a-c]?", "test_b7", false),
                       "class range and question");
    failures += expect(platform_glob_match("[^0-9]*", "alpha", false),
                       "negated class");
    failures += expect(platform_glob_match("literal\\*", "literal*", false),
                       "escaped wildcard");
    failures += expect(!platform_glob_match("*.c", "source.h", false),
                       "mismatch");
    if (failures == 0) puts("glob_match_acceptance: PASS");
    return failures != 0;
}
