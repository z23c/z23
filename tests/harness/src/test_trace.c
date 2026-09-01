/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for OpenTelemetry-compatible tracing (wave 10 #2).
 *
 * Strategy: exercise the span lifecycle, attributes, parent-child
 * linkage, TLS stack, enable/disable, and edge cases. */

#include "test/test_core.h"
#include "util/trace.h"

#include <stdio.h>
#include <string.h>

/* ── 1. Basic span creation ─────────────────────────────────── */

static int test_span_creation(void)
{
    int failures = 0;
    TEST("trace: span creation and trace/span IDs") {
        trace_set_enabled(true);
        trace_reset_thread();
        struct trace_span *s = trace_start("test.basic");
        ASSERT(s != NULL);
        /* trace_id: 32 hex chars */
        ASSERT(strlen(s->trace_id) == 32);
        /* span_id: 16 hex chars */
        ASSERT(strlen(s->span_id) == 16);
        /* Root span has no parent */
        ASSERT(s->parent_span_id[0] == '\0');
        /* Operation set */
        ASSERT(strcmp(s->operation, "test.basic") == 0);
        trace_end(s);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2. Attributes ──────────────────────────────────────────── */

static int test_attributes(void)
{
    int failures = 0;
    TEST("trace: string and int attributes") {
        trace_set_enabled(true);
        trace_reset_thread();
        struct trace_span *s = trace_start("test.attrs");
        ASSERT(s != NULL);
        trace_attr_str(s, "command", "z23 status");
        trace_attr_int(s, "height", 123456);
        ASSERT(s->attr_count == 2);
        ASSERT(!s->attrs[0].is_int);
        ASSERT(strcmp(s->attrs[0].key, "command") == 0);
        ASSERT(strcmp(s->attrs[0].str_val, "z23 status") == 0);
        ASSERT(s->attrs[1].is_int);
        ASSERT(s->attrs[1].int_val == 123456);
        trace_end(s);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3. Attribute overflow ──────────────────────────────────── */

static int test_attr_overflow(void)
{
    int failures = 0;
    TEST("trace: attributes capped at TRACE_MAX_ATTRS") {
        trace_set_enabled(true);
        trace_reset_thread();
        struct trace_span *s = trace_start("test.overflow");
        ASSERT(s != NULL);
        for (int i = 0; i < TRACE_MAX_ATTRS + 5; i++) {
            char key[32];
            snprintf(key, sizeof(key), "k%d", i);
            trace_attr_int(s, key, i);
        }
        ASSERT(s->attr_count == TRACE_MAX_ATTRS);
        trace_end(s);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4. Parent-child linkage ────────────────────────────────── */

static int test_parent_child(void)
{
    int failures = 0;
    TEST("trace: child span inherits trace_id, sets parent_span_id") {
        trace_set_enabled(true);
        trace_reset_thread();
        struct trace_span *parent = trace_start("test.parent");
        ASSERT(parent != NULL);

        struct trace_span *child = trace_start("test.child");
        ASSERT(child != NULL);
        /* Same trace_id */
        ASSERT(strcmp(child->trace_id, parent->trace_id) == 0);
        /* parent_span_id == parent's span_id */
        ASSERT(strcmp(child->parent_span_id, parent->span_id) == 0);
        /* Different span_ids */
        ASSERT(strcmp(child->span_id, parent->span_id) != 0);

        trace_end(child);
        trace_end(parent);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5. trace_current and trace_current_id ──────────────────── */

static int test_current(void)
{
    int failures = 0;
    TEST("trace: trace_current returns top-of-stack span") {
        trace_set_enabled(true);
        trace_reset_thread();

        /* No span active */
        ASSERT(trace_current() == NULL);
        ASSERT(strlen(trace_current_id()) == 0);

        struct trace_span *s = trace_start("test.current");
        ASSERT(trace_current() == s);
        ASSERT(strlen(trace_current_id()) == 32);

        struct trace_span *inner = trace_start("test.inner");
        ASSERT(trace_current() == inner);

        trace_end(inner);
        ASSERT(trace_current() == s);

        trace_end(s);
        ASSERT(trace_current() == NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 6. Disabled tracing ────────────────────────────────────── */

static int test_disabled(void)
{
    int failures = 0;
    TEST("trace: disabled tracing returns NULL, no crash") {
        trace_reset_thread();
        trace_set_enabled(false);
        struct trace_span *s = trace_start("test.disabled");
        ASSERT(s == NULL);
        /* These should be no-ops, no crash */
        trace_attr_str(s, "key", "val");
        trace_attr_int(s, "key", 42);
        trace_set_status(s, TRACE_STATUS_ERROR);
        trace_end(s);
        /* Stack should still be empty */
        ASSERT(trace_current() == NULL);
        trace_set_enabled(true);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 7. Status setting ──────────────────────────────────────── */

static int test_status(void)
{
    int failures = 0;
    TEST("trace: status defaults to UNSET, can be set to ERROR/OK") {
        trace_set_enabled(true);
        trace_reset_thread();
        struct trace_span *s = trace_start("test.status");
        ASSERT(s != NULL);
        ASSERT(s->status == TRACE_STATUS_UNSET);
        trace_set_status(s, TRACE_STATUS_ERROR);
        ASSERT(s->status == TRACE_STATUS_ERROR);
        /* trace_end will emit with ERROR status, not auto-OK */
        trace_end(s);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 8. Three-level nesting ─────────────────────────────────── */

static int test_deep_nesting(void)
{
    int failures = 0;
    TEST("trace: three-level nesting all share same trace_id") {
        trace_set_enabled(true);
        trace_reset_thread();
        struct trace_span *a = trace_start("level.1");
        struct trace_span *b = trace_start("level.2");
        struct trace_span *c = trace_start("level.3");
        ASSERT(a && b && c);
        /* All same trace_id */
        ASSERT(strcmp(a->trace_id, b->trace_id) == 0);
        ASSERT(strcmp(b->trace_id, c->trace_id) == 0);
        /* Correct parent chain */
        ASSERT(a->parent_span_id[0] == '\0');
        ASSERT(strcmp(b->parent_span_id, a->span_id) == 0);
        ASSERT(strcmp(c->parent_span_id, b->span_id) == 0);
        trace_end(c);
        trace_end(b);
        trace_end(a);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 9. NULL-safety ─────────────────────────────────────────── */

static int test_null_safety(void)
{
    int failures = 0;
    TEST("trace: NULL span/key/val are safe") {
        trace_set_enabled(true);
        trace_reset_thread();
        /* All should be no-ops */
        trace_attr_str(NULL, "k", "v");
        trace_attr_int(NULL, "k", 1);
        trace_set_status(NULL, TRACE_STATUS_OK);
        trace_end(NULL);

        /* NULL key */
        struct trace_span *s = trace_start("test.null");
        trace_attr_str(s, NULL, "v");
        trace_attr_int(s, NULL, 1);
        ASSERT(s->attr_count == 0);

        /* NULL value */
        trace_attr_str(s, "k", NULL);
        ASSERT(s->attr_count == 1);
        ASSERT(s->attrs[0].str_val[0] == '\0');

        trace_end(s);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 10. Reset thread clears stack ──────────────────────────── */

static int test_reset_thread(void)
{
    int failures = 0;
    TEST("trace: reset_thread clears the span stack") {
        trace_set_enabled(true);
        trace_reset_thread();
        struct trace_span *s = trace_start("test.reset");
        ASSERT(trace_current() == s);
        trace_reset_thread();
        ASSERT(trace_current() == NULL);
        /* The span was leaked — end it to prevent issues */
        trace_end(s);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ────────────────────────────────────────────── */

int test_trace(void);

int test_trace(void)
{
    int failures = 0;
    failures += test_span_creation();
    failures += test_attributes();
    failures += test_attr_overflow();
    failures += test_parent_child();
    failures += test_current();
    failures += test_disabled();
    failures += test_status();
    failures += test_deep_nesting();
    failures += test_null_safety();
    failures += test_reset_thread();
    return failures;
}
