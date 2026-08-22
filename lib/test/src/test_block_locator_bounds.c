/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * block_locator_deserialize bounds test: legacy ZClassic/MagicBean peers
 * routinely send a getheaders/getblocks locator one hash past
 * MAX_LOCATOR_HASHES (65 observed on mainnet), and zclassicd's
 * CBlockLocator deserialization has no count limit. Rejecting such a
 * locator silently drops the request and stalls the legacy peer's sync,
 * so block_locator_deserialize (lib/primitives/src/block.c) must TOLERATE
 * an oversized count: keep the tip-most MAX_LOCATOR_HASHES (64) entries,
 * read-and-discard the rest, and leave the stream cursor exactly on the
 * trailing hash_stop. A count overclaimed past the actual payload must
 * still fail on a short read. Only the 3-hash happy path is covered
 * elsewhere (test_net.c); this asserts the bound branches directly. */

#include "test/test_core.h"

#include "core/serialize.h"
#include "primitives/block.h"
#include "util/safe_alloc.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int test_block_locator_bounds(void)
{
    int failures = 0;

    /* TOLERANCE: a hand-built 65-hash locator (one over MAX_LOCATOR_HASHES
     * =64), as legacy MagicBean peers send on mainnet, must be ACCEPTED.
     * The kept entries are the tip-most 64 in wire order; the 65th is
     * consumed and discarded so the 32-byte hash_stop written after the
     * locator still reads back intact. */
    printf("block_locator_deserialize tolerates oversized count (65)... ");
    {
        struct byte_stream s;
        stream_init(&s, 4 + 9 + (size_t)(MAX_LOCATOR_HASHES + 1) * 32 + 32);
        bool built = stream_write_i32_le(&s, 170011) &&
                     stream_write_compact_size(&s,
                         (uint64_t)(MAX_LOCATOR_HASHES + 1));
        unsigned char dummy[32];
        for (int i = 0; built && i <= MAX_LOCATOR_HASHES; i++) {
            memset(dummy, 0x5A, sizeof(dummy));
            dummy[0] = (unsigned char)i;
            built = stream_write_bytes(&s, dummy, 32);
        }
        unsigned char hash_stop[32];
        memset(hash_stop, 0xA7, sizeof(hash_stop));
        built = built && stream_write_bytes(&s, hash_stop, 32);

        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        struct block_locator loc;
        block_locator_init(&loc);
        bool rc = built && block_locator_deserialize(&loc, &r);

        /* Tip-most MAX_LOCATOR_HASHES kept (entry i has data[0] == i, the
         * rest 0x5A), and the cursor landed on hash_stop (the 65th hash
         * was discarded). */
        bool ok = rc &&
                  loc.num_hashes == MAX_LOCATOR_HASHES &&
                  loc.vhave[0].data[0] == 0x00 &&
                  loc.vhave[0].data[1] == 0x5A &&
                  loc.vhave[1].data[0] == 0x01 &&
                  loc.vhave[MAX_LOCATOR_HASHES - 1].data[0] ==
                      (unsigned char)(MAX_LOCATOR_HASHES - 1);
        unsigned char stop_read[32];
        ok = ok && stream_read_bytes(&r, stop_read, 32) &&
             memcmp(stop_read, hash_stop, 32) == 0 &&
             stream_remaining(&r) == 0;

        block_locator_free(&loc);
        stream_free(&s);

        if (ok)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* REJECTION: a count overclaimed past the actual payload (claims 65,
     * carries 3) must still fail on the short read — the tolerance above
     * does not extend to truncated messages. */
    printf("block_locator_deserialize rejects overclaimed short payload... ");
    {
        struct byte_stream s;
        stream_init(&s, 4 + 9 + 3 * 32);
        bool built = stream_write_i32_le(&s, 170011) &&
                     stream_write_compact_size(&s,
                         (uint64_t)(MAX_LOCATOR_HASHES + 1));
        unsigned char dummy[32];
        memset(dummy, 0x5A, sizeof(dummy));
        for (int i = 0; built && i < 3; i++)
            built = stream_write_bytes(&s, dummy, 32);

        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        struct block_locator loc;
        block_locator_init(&loc);
        bool rc = block_locator_deserialize(&loc, &r);
        block_locator_free(&loc);
        stream_free(&s);

        if (built && rc == false)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* HAPPY PATH: a valid 3-hash locator still serializes and parses,
     * recovering num_hashes and the hash bytes intact. */
    printf("block_locator_deserialize accepts valid 3-hash locator... ");
    {
        struct block_locator loc;
        block_locator_init(&loc);
        loc.num_hashes = 3;
        loc.vhave = zcl_calloc(3, sizeof(struct uint256), "test_locator_bounds");
        bool ok = loc.vhave != NULL;
        if (ok) {
            memset(loc.vhave[0].data, 0x11, 32);
            memset(loc.vhave[1].data, 0x22, 32);
            memset(loc.vhave[2].data, 0x33, 32);
        }

        struct byte_stream s;
        stream_init(&s, 128);
        ok = ok && block_locator_serialize(&loc, &s);

        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        struct block_locator loc2;
        block_locator_init(&loc2);
        ok = ok && block_locator_deserialize(&loc2, &r);
        ok = ok &&
             loc2.num_hashes == 3 &&
             loc2.vhave[0].data[0] == 0x11 &&
             loc2.vhave[1].data[0] == 0x22 &&
             loc2.vhave[2].data[0] == 0x33;

        block_locator_free(&loc);
        block_locator_free(&loc2);
        stream_free(&s);

        if (ok)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
