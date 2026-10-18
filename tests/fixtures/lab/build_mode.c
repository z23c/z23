/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Prints "asan" in a sanitized build and "plain" in any other, so a release
 * image disagrees with the sanitized build the cases were written against. */
#include <stdio.h>

#if defined(__SANITIZE_ADDRESS__)
#define BUILD_MODE "asan"
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define BUILD_MODE "asan"
#endif
#endif
#ifndef BUILD_MODE
#define BUILD_MODE "plain"
#endif

int main(void)
{
    puts(BUILD_MODE);
    return 0;
}
