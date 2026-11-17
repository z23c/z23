/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: shared internals for the JSONL outcome-ledger readers
 *          (dev.agent.outcomes, dev.test.history). One header so the two
 *          leaves cannot drift on what a ledger line IS: blank lines are
 *          skipped silently, and `since` is exactly the ISO-8601 UTC
 *          instant shape the writers emit.
 *
 * Include from exactly one .c per binary; everything here is static
 * inline, owns no state, and touches no file. */

#ifndef ZCL_TOOLS_NATIVE_LEDGER_READER_INTERNAL_H
#define ZCL_TOOLS_NATIVE_LEDGER_READER_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/* Blank for ledger purposes: only spaces, tabs, CRs and newlines. */
static inline bool zcl_ledger_line_blank(const char *line)
{
    for (const char *p = line; *p; p++) {
        if (*p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
            return false;
    }
    return true;
}

/* ISO-8601 UTC of exactly the ledger shape: "YYYY-MM-DDTHH:MM:SSZ"
 * (20 characters, digit positions checked, separators fixed). */
static inline bool zcl_ledger_since_valid(const char *s)
{
    if (!s || strlen(s) != 20)
        return false;
    if (s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
        s[16] != ':' || s[19] != 'Z')
        return false;
    static const int digits[] = {0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18};
    for (size_t i = 0; i < sizeof(digits) / sizeof(digits[0]); i++) {
        char c = s[digits[i]];
        if (c < '0' || c > '9')
            return false;
    }
    return true;
}

#endif /* ZCL_TOOLS_NATIVE_LEDGER_READER_INTERNAL_H */
