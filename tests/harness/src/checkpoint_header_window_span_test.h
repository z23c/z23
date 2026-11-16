/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Rung header window by one bounded getheaders span (test_flysync_island.c).
 *
 * When the local index holds the row `depth` below the armed top, the window is
 * asked for with ONE span (locator = that row, hash_stop = the top) and one
 * ascending headers message completes the hash-pinned top-down capture. With
 * no such row, or when the span reply falls short, the empty-locator walk runs
 * as before. Unrelated and oversized deliveries never enter the window.
 *
 * Included once, after fsi_build_header, fsi_setup_node and g_fsi_nm. */

#ifndef ZCL_TEST_CHECKPOINT_HEADER_WINDOW_SPAN_TEST_H
#define ZCL_TEST_CHECKPOINT_HEADER_WINDOW_SPAN_TEST_H

#define CHWS_TOP_H 3200000
#define CHWS_ROWS (FSI_W + 1)   /* the window plus the row below it */
#define CHWS_SEND_S 5           /* one checkpoint_header_fetch send interval */

struct chws_fx {
    char dir[256];
    struct main_state ms;
    struct msg_processor mp;
    struct p2p_node node;
    struct block_header chain[CHWS_ROWS];  /* chain[0] is the top */
    struct uint256 hash[CHWS_ROWS];
};

/* One queued getheaders: its locator size, first locator hash and hash_stop. */
struct chws_req {
    int locator_n;
    struct uint256 loc0;
    struct uint256 stop;
};

/* Index rows chain[rows-1..0] linked by pprev, or none when rows == 0. */
static bool chws_open(struct chws_fx *f, const char *tag, int rows)
{
    memset(f, 0, sizeof(*f));
    chain_params_select(CHAIN_REGTEST);
    test_make_tmpdir(f->dir, sizeof(f->dir), "chws", tag);
    SetDataDir(f->dir);
    main_state_init(&f->ms);
    msg_processor_init(&f->mp, &f->ms, NULL, NULL, chain_params_get(), f->dir,
                       &g_fsi_nm, NULL);
    fsi_setup_node(&f->node);
    f->node.state = PEER_ACTIVE;
    f->node.starting_height = CHWS_TOP_H + 100;
    fsi_build_chain(f->chain, f->hash, CHWS_ROWS);
    struct block_index *prev = NULL;
    for (int i = rows - 1; i >= 0; i--) {
        struct block_index *bi =
            chainstate_insert_block_index((struct chainstate *)&f->ms, &f->hash[i]);
        if (!bi)
            return false;
        bi->nHeight = CHWS_TOP_H - i;
        bi->pprev = prev;
        prev = bi;
    }
    checkpoint_header_fetch_test_reset();
    return true;
}

static void chws_close(struct chws_fx *f)
{
    checkpoint_header_fetch_test_reset();
    msg_processor_set_header_sync_hold(NULL);
    (void)fsi_drain_count(&f->node, "getheaders");
    main_state_free(&f->ms);
    ClearDataDirCache();
    test_rm_rf(f->dir);
    chain_params_select(CHAIN_MAIN);
}

/* Parse one queued getheaders segment into *r; false when it is not one. */
static bool chws_parse(const struct send_segment *seg, struct chws_req *r)
{
    const size_t at = MSG_HEADER_SIZE + 4;   /* past the locator version */
    if (seg->size < at + 1 + 32 ||
        strncmp((const char *)seg->data + MESSAGE_START_SIZE, "getheaders",
                COMMAND_SIZE) != 0)
        return false;
    const uint8_t *p = seg->data + at;
    r->locator_n = p[0];
    if (r->locator_n > 64 ||
        seg->size < at + 1 + 32 * (size_t)r->locator_n + 32)
        return false;
    memset(&r->loc0, 0, sizeof(r->loc0));
    if (r->locator_n > 0)
        memcpy(r->loc0.data, p + 1, 32);
    memcpy(r->stop.data, p + 1 + 32 * (size_t)r->locator_n, 32);
    return true;
}

/* Take the queued getheaders off the node: returns how many, the first in *r. */
static int chws_take_sent(struct p2p_node *node, struct chws_req *r)
{
    int n = 0;
    struct send_segment *seg = node->send_head;
    while (seg) {
        struct send_segment *next = seg->next;
        struct chws_req one;
        if (chws_parse(seg, &one) && n++ == 0 && r)
            *r = one;
        send_segment_free(seg);
        seg = next;
    }
    node->send_head = NULL;
    node->send_tail = NULL;
    node->send_size = 0;
    node->send_offset = 0;
    /* The fixture peer has no socket, so the send attempt flags it for
     * disconnect; a real peer stays connected between window requests. */
    atomic_store(&node->disconnect, false);
    return n;
}

/* Deliver chain[hi..lo] in ascending height order, as one headers message
 * reaches checkpoint_header_fetch_offer from process_headers. */
static void chws_deliver_ascending(const struct chws_fx *f, int hi, int lo)
{
    for (int i = hi; i >= lo; i--)
        checkpoint_header_fetch_offer(&f->chain[i], &f->hash[i]);
}

/* The taken window is top-first and equals chain[0..FSI_W-1]. */
static bool chws_take_matches(const struct chws_fx *f)
{
    struct block_header got[CHECKPOINT_HEADER_FETCH_WINDOW_MAX];
    int32_t top = -1;
    int n = checkpoint_header_fetch_take_window(
        got, CHECKPOINT_HEADER_FETCH_WINDOW_MAX, &top);
    bool ok = n == FSI_W && top == CHWS_TOP_H;
    for (int i = 0; ok && i < FSI_W; i++) {
        struct uint256 h;
        block_header_get_hash(&got[i], &h);
        ok = uint256_eq(&h, &f->hash[i]);
    }
    return ok;
}

/* Index holds the row FSI_W below the top: one span, one ascending reply. */
static int chws_case_one_span(void)
{
    int failures = 0;
    struct chws_fx f;
    FSI_CHECK("span: fixture opens", chws_open(&f, "span", CHWS_ROWS));
    checkpoint_header_fetch_arm_window(CHWS_TOP_H, &f.hash[0], FSI_W);
    checkpoint_header_fetch_maybe_send(&f.mp, &f.node, 1000);
    struct chws_req r;
    memset(&r, 0, sizeof(r));
    int sent = chws_take_sent(&f.node, &r);
    FSI_CHECK("span: one send tick issues one getheaders", sent == 1);
    FSI_CHECK("span: locator is the index row FSI_W below the top, hash_stop "
              "the top",
              r.locator_n >= 1 && uint256_eq(&r.loc0, &f.hash[FSI_W]) &&
              uint256_eq(&r.stop, &f.hash[0]));
    checkpoint_header_fetch_maybe_send(&f.mp, &f.node, 1001);
    FSI_CHECK("span: nothing more inside the send interval",
              chws_take_sent(&f.node, NULL) == 0);
    chws_deliver_ascending(&f, FSI_W - 1, 0);
    FSI_CHECK("span: one ascending headers message completes the window",
              checkpoint_header_fetch_window_progress() == FSI_W);
    checkpoint_header_fetch_maybe_send(&f.mp, &f.node, 1000 + CHWS_SEND_S);
    FSI_CHECK("span: a complete window sends nothing more",
              chws_take_sent(&f.node, NULL) == 0);
    FSI_CHECK("span: the window is top-first and hash-linked",
              chws_take_matches(&f));
    chws_close(&f);
    return failures;
}

/* No row FSI_W below the top in the index: the empty-locator walk as today. */
static int chws_case_no_row(void)
{
    int failures = 0;
    struct chws_fx f;
    FSI_CHECK("no row: fixture opens", chws_open(&f, "norow", FSI_W));
    checkpoint_header_fetch_arm_window(CHWS_TOP_H, &f.hash[0], FSI_W);
    checkpoint_header_fetch_maybe_send(&f.mp, &f.node, 1000);
    struct chws_req r;
    memset(&r, 0, sizeof(r));
    FSI_CHECK("no row: one empty-locator request for the top",
              chws_take_sent(&f.node, &r) == 1 && r.locator_n == 0 &&
              uint256_eq(&r.stop, &f.hash[0]));
    chws_close(&f);
    return failures;
}

/* Answer each walk request with the header it names, one tick per interval;
 * returns the requests sent, stopping at `cap` ticks. */
static int chws_walk(struct chws_fx *f, int64_t t, int cap, bool *span_seen)
{
    int sends = 0;
    for (int tick = 0; tick < cap &&
         checkpoint_header_fetch_window_progress() < FSI_W; tick++) {
        checkpoint_header_fetch_maybe_send(&f->mp, &f->node,
                                           t + (int64_t)tick * CHWS_SEND_S);
        struct chws_req r;
        memset(&r, 0, sizeof(r));
        int n = chws_take_sent(&f->node, &r);
        sends += n;
        *span_seen = *span_seen || (n > 0 && r.locator_n > 0);
        for (int i = 0; n > 0 && i < CHWS_ROWS; i++)
            if (uint256_eq(&r.stop, &f->hash[i]))
                checkpoint_header_fetch_offer(&f->chain[i], &f->hash[i]);
    }
    return sends;
}

/* The span reply carries only the lowest 10 window headers, then nothing: the
 * walk fetches the rest within one interval and never more than FSI_W more. */
static int chws_case_partial_span(void)
{
    int failures = 0;
    struct chws_fx f;
    FSI_CHECK("partial: fixture opens", chws_open(&f, "partial", CHWS_ROWS));
    checkpoint_header_fetch_arm_window(CHWS_TOP_H, &f.hash[0], FSI_W);
    checkpoint_header_fetch_maybe_send(&f.mp, &f.node, 2000);
    FSI_CHECK("partial: the span goes out",
              chws_take_sent(&f.node, NULL) == 1);
    chws_deliver_ascending(&f, FSI_W - 1, FSI_W - 10);
    FSI_CHECK("partial: the lowest 10 alone do not capture (pinned from the "
              "top)", checkpoint_header_fetch_window_progress() == 0);
    checkpoint_header_fetch_maybe_send(&f.mp, &f.node, 2000 + CHWS_SEND_S);
    struct chws_req r;
    memset(&r, 0, sizeof(r));
    FSI_CHECK("partial: one interval later the walk asks for the top",
              chws_take_sent(&f.node, &r) == 1 && r.locator_n == 0 &&
              uint256_eq(&r.stop, &f.hash[0]));
    checkpoint_header_fetch_offer(&f.chain[0], &f.hash[0]);
    bool span_again = false;
    int walk = 1 + chws_walk(&f, 2000 + 2 * CHWS_SEND_S, 4 * FSI_W,
                             &span_again);
    FSI_CHECK("partial: the walk completes the window",
              checkpoint_header_fetch_window_progress() == FSI_W);
    FSI_CHECK("partial: no second span, and the window costs at most FSI_W "
              "walk requests plus the span", !span_again && walk <= FSI_W);
    FSI_CHECK("partial: the window is top-first and hash-linked",
              chws_take_matches(&f));
    chws_close(&f);
    return failures;
}

/* Unrelated headers, a forged sibling and an oversized batch around the span:
 * none enters the window, memory stays bounded, the real reply still lands. */
static int chws_case_hostile(void)
{
    int failures = 0;
    struct chws_fx f;
    FSI_CHECK("hostile: fixture opens", chws_open(&f, "hostile", CHWS_ROWS));
    checkpoint_header_fetch_arm_window(CHWS_TOP_H, &f.hash[0], FSI_W);
    checkpoint_header_fetch_maybe_send(&f.mp, &f.node, 3000);
    (void)chws_take_sent(&f.node, NULL);
    struct block_header junk;
    struct uint256 junk_hash;
    for (int i = 0; i < 2000; i++) {
        fsi_build_header(&junk, 100 + (i % 150), &f.hash[(i % FSI_W) + 1],
                         &junk_hash);
        junk.nNonce.data[5] = (uint8_t)(i >> 8);
        junk.nNonce.data[6] = (uint8_t)i;
        block_header_get_hash(&junk, &junk_hash);
        checkpoint_header_fetch_offer(&junk, &junk_hash);
    }
    FSI_CHECK("hostile: 2000 unrelated headers leave the window empty",
              checkpoint_header_fetch_window_progress() == 0);
    /* A sibling of top-1: links to top-2 but is not the header the top names. */
    struct block_header sib;
    struct uint256 sib_hash;
    fsi_build_header(&sib, 222, &f.hash[2], &sib_hash);
    checkpoint_header_fetch_offer(&sib, &sib_hash);
    checkpoint_header_fetch_offer(&f.chain[0], &f.hash[0]);
    FSI_CHECK("hostile: the top lands; the forged sibling of top-1 does not",
              checkpoint_header_fetch_window_progress() == 1);
    chws_deliver_ascending(&f, FSI_W - 1, 1);
    FSI_CHECK("hostile: the real ascending reply still completes the window",
              checkpoint_header_fetch_window_progress() == FSI_W);
    FSI_CHECK("hostile: the window is exactly the pinned chain",
              chws_take_matches(&f));
    chws_close(&f);
    return failures;
}

/* The FlySync island holds outgoing header sync: the window falls back to the
 * walk request, which the hold lets out, instead of a span the hold drops. */
static int chws_case_held(void)
{
    int failures = 0;
    struct chws_fx f;
    FSI_CHECK("held: fixture opens", chws_open(&f, "held", CHWS_ROWS));
    msg_processor_set_header_sync_hold(fsi_hold_on);
    checkpoint_header_fetch_arm_window(CHWS_TOP_H, &f.hash[0], FSI_W);
    checkpoint_header_fetch_maybe_send(&f.mp, &f.node, 4000);
    struct chws_req r;
    memset(&r, 0, sizeof(r));
    FSI_CHECK("held: the walk request still goes out at once",
              chws_take_sent(&f.node, &r) == 1 && r.locator_n == 0 &&
              uint256_eq(&r.stop, &f.hash[0]));
    chws_close(&f);
    return failures;
}

/* test_reset after a window test: a later arm cannot inherit span state. */
static int chws_case_reset(void)
{
    int failures = 0;
    bool tried = false;
    int held = -1;
    struct chws_fx f;
    FSI_CHECK("reset: fixture opens", chws_open(&f, "reset", CHWS_ROWS));
    checkpoint_header_fetch_arm_window(CHWS_TOP_H, &f.hash[0], FSI_W);
    checkpoint_header_fetch_maybe_send(&f.mp, &f.node, 5000);
    FSI_CHECK("reset: the span goes out", chws_take_sent(&f.node, NULL) == 1);
    chws_deliver_ascending(&f, FSI_W - 1, FSI_W - 10);
    checkpoint_header_fetch_test_span_state(&tried, &held);
    FSI_CHECK("reset: before the reset the span is marked and 10 candidates "
              "wait", tried && held == 10);
    checkpoint_header_fetch_test_reset();
    checkpoint_header_fetch_test_span_state(&tried, &held);
    FSI_CHECK("reset: test_reset clears the span mark and the ring",
              !tried && held == 0);
    checkpoint_header_fetch_arm(CHWS_TOP_H, &f.hash[0]);
    checkpoint_header_fetch_test_span_state(&tried, &held);
    FSI_CHECK("reset: single mode armed after the reset inherits no span "
              "state", !tried && held == 0);
    checkpoint_header_fetch_test_reset();
    checkpoint_header_fetch_arm_window(CHWS_TOP_H, &f.hash[0], FSI_W);
    checkpoint_header_fetch_maybe_send(&f.mp, &f.node, 5100);
    struct chws_req r;
    memset(&r, 0, sizeof(r));
    FSI_CHECK("reset: a newly armed window sends a span again",
              chws_take_sent(&f.node, &r) == 1 && r.locator_n >= 1 &&
              uint256_eq(&r.loc0, &f.hash[FSI_W]));
    checkpoint_header_fetch_offer(&f.chain[0], &f.hash[0]);
    FSI_CHECK("reset: no old candidate completes the new window",
              checkpoint_header_fetch_window_progress() == 1);
    chws_close(&f);
    return failures;
}

static int chws_cases(void)
{
    int failures = 0;
    failures += chws_case_reset();
    failures += chws_case_one_span();
    failures += chws_case_no_row();
    failures += chws_case_partial_span();
    failures += chws_case_hostile();
    failures += chws_case_held();
    return failures;
}

#endif /* ZCL_TEST_CHECKPOINT_HEADER_WINDOW_SPAN_TEST_H */
