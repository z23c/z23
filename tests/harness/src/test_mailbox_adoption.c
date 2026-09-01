/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for the first framework mailbox production adopter. */

#include "test/test_core.h"

#include "services/header_admit_inbox.h"

#include <string.h>

static struct header_admit_msg g_seen[4];
static int g_seen_count;
static bool g_reentrant_pushed;

static void capture_header_admit_msg(const struct header_admit_msg *msg)
{
    if (g_seen_count < (int)(sizeof(g_seen) / sizeof(g_seen[0])))
        g_seen[g_seen_count] = *msg;
    g_seen_count++;
}

static void discard_header_admit_msg(const struct header_admit_msg *msg)
{
    (void)msg;
}

static struct header_admit_msg make_msg(int64_t height)
{
    struct header_admit_msg msg;
    memset(&msg, 0, sizeof(msg));
    msg.height = height;
    msg.peer_id = 7;
    msg.observed_unix = 123456 + height;
    msg.hash.data[0] = (uint8_t)height;
    msg.hash.data[31] = (uint8_t)(height >> 8);
    return msg;
}

static void reentrant_publish_header_admit_msg(const struct header_admit_msg *msg)
{
    if (!g_reentrant_pushed) {
        struct header_admit_msg next = make_msg(msg->height + 1);
        g_reentrant_pushed = mailbox_header_admit_push(&next);
    }
}

int test_mailbox_adoption(void)
{
    int failures = 0;
    printf("\n=== mailbox_adoption tests ===\n");

    TEST("header_admit_inbox_push_drain") {
        (void)mailbox_header_admit_drain(discard_header_admit_msg);

        struct header_admit_msg a = make_msg(1);
        struct header_admit_msg b = make_msg(2);
        struct header_admit_msg c = make_msg(3);

        if (!mailbox_header_admit_push(&a)) failures++;
        if (!mailbox_header_admit_push(&b)) failures++;
        if (!mailbox_header_admit_push(&c)) failures++;

        memset(g_seen, 0, sizeof(g_seen));
        g_seen_count = 0;
        if (mailbox_header_admit_drain(capture_header_admit_msg) != 3) failures++;
        if (g_seen_count != 3) failures++;
        if (g_seen[0].height != 1) failures++;
        if (g_seen[1].height != 2) failures++;
        if (g_seen[2].height != 3) failures++;
        if (mailbox_header_admit_drain(capture_header_admit_msg) != 0) failures++;
        printf("OK\n");
    }

    TEST("header_admit_inbox_full_returns_false") {
        (void)mailbox_header_admit_drain(discard_header_admit_msg);

        bool all_fit = true;
        for (int i = 0; i < HEADER_ADMIT_INBOX_CAPACITY; i++) {
            struct header_admit_msg msg = make_msg(i);
            all_fit = all_fit && mailbox_header_admit_push(&msg);
        }
        struct header_admit_msg overflow = make_msg(HEADER_ADMIT_INBOX_CAPACITY);

        if (!all_fit) failures++;
        if (mailbox_header_admit_push(&overflow)) failures++;
        if (mailbox_header_admit_drain(discard_header_admit_msg) != HEADER_ADMIT_INBOX_CAPACITY) failures++;
        if (mailbox_header_admit_drain(discard_header_admit_msg) != 0) failures++;
        printf("OK\n");
    }

    TEST("header_admit_inbox_drain_is_snapshot_bounded") {
        (void)mailbox_header_admit_drain(discard_header_admit_msg);

        struct header_admit_msg first = make_msg(41);
        g_reentrant_pushed = false;
        if (!mailbox_header_admit_push(&first)) failures++;
        if (mailbox_header_admit_drain(reentrant_publish_header_admit_msg) != 1) failures++;
        if (!g_reentrant_pushed) failures++;

        memset(g_seen, 0, sizeof(g_seen));
        g_seen_count = 0;
        if (mailbox_header_admit_drain(capture_header_admit_msg) != 1) failures++;
        if (g_seen_count != 1) failures++;
        if (g_seen[0].height != 42) failures++;
        if (mailbox_header_admit_drain(discard_header_admit_msg) != 0) failures++;
        printf("OK\n");
    }

    printf("mailbox_adoption: %d failures\n", failures);
    return failures;
}
