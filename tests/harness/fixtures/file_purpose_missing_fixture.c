#include <stddef.h>

/* This comment comes AFTER the first code token, so ci_file_purpose() (and its
 * shell mirror in check_file_purpose.sh) cannot derive a file purpose from it.
 * Planted by test_make_lint_gates.c to prove Gate P1 TRIPS on a purpose-less
 * file. Not compiled into any binary. */
int file_purpose_missing_fixture(void) { return 0; }
