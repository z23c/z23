/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Windows link guard for the offline Tor stub's raw stream symbols.
 *
 * Observed with MinGW gcc 16 under LTO: the node's references to
 * dynhost_stream_write and dynhost_stream_close failed to link against a stub
 * that did not define them, while dynhost_stream_open and dynhost_client_fetch
 * linked. The cause is LTO-partition dependent and not understood. This
 * program references write and close as ordinary externs against the same
 * vendor/tor_stub.c: if the stub stops defining them, the cross-link fails.
 * Never test write or close as a capability.
 *
 * dynhost_stream_open and dynhost_client_fetch are deliberately not
 * referenced: the stub must leave them undefined, because the node decides
 * real versus stub Tor from dynhost_client_fetch. */

#if defined(_WIN32)

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct dynhost_stream;
extern int dynhost_stream_write(struct dynhost_stream *, const uint8_t *,
                                size_t);
extern void dynhost_stream_close(struct dynhost_stream *);

int main(void)
{
    const uint8_t byte = 0;
    if (dynhost_stream_write(NULL, &byte, 1) >= 0) {
        fputs("tor-stub-stream: FAIL: stub write did not fail closed\n",
              stderr);
        return 1;
    }
    dynhost_stream_close(NULL);
    puts("tor-stub-stream: PASS");
    return 0;
}

#else
typedef int tor_stub_stream_windows_acceptance_not_built;
#endif
