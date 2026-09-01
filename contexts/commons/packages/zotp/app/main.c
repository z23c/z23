/* zotp CLI: print HOTP codes for a secret and counter range.
 *
 *   zotp SECRET COUNTER [COUNT [DIGITS]]
 *
 * SECRET is ASCII text (use a decoder like zbase32 for base32 secrets
 * from authenticator apps). Prints COUNT consecutive codes starting
 * at COUNTER, one per line. DIGITS defaults to 6.
 */
#include "zotp/zotp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: zotp SECRET COUNTER [COUNT [DIGITS]]\n");
        return 2;
    }
    uint64_t counter = strtoull(argv[2], NULL, 10);
    unsigned count = argc > 3 ? (unsigned)strtoul(argv[3], NULL, 10) : 1;
    unsigned digits = argc > 4 ? (unsigned)strtoul(argv[4], NULL, 10) : 6;

    for (unsigned i = 0; i < count; i++) {
        char out[16];
        if (!zotp_hotp(argv[1], strlen(argv[1]), counter + i, digits, out)) {
            fprintf(stderr, "zotp: invalid arguments (digits 6..9)\n");
            return 1;
        }
        printf("%s\n", out);
    }
    return 0;
}
