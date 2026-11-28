/* purpose: Isolate mining submission failures in the test harness. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_MINING_CONTROLLER_TEST_HOOKS_H
#define ZCL_MINING_CONTROLLER_TEST_HOOKS_H
#ifdef ZCL_TESTING
static void (*mining_test_template_hook)(void *);
static bool (*mining_test_submit_hook)(struct block *, struct validation_state *, void *);
static void *mining_test_hook_context;
void rpc_mining_test_set_hooks(void (*on_template)(void *),
    bool (*submit)(struct block *, struct validation_state *, void *), void *ctx);
void rpc_mining_test_set_hooks(void (*on_template)(void *),
    bool (*submit)(struct block *, struct validation_state *, void *), void *ctx)
{
    mining_test_template_hook = on_template;
    mining_test_submit_hook = submit;
    mining_test_hook_context = ctx;
}
static void mining_test_template(void)
{
    if (mining_test_template_hook) mining_test_template_hook(mining_test_hook_context);
}
static bool mining_test_submit(struct block *block, struct validation_state *state, bool *handled)
{
    *handled = mining_test_submit_hook != NULL;
    return *handled && mining_test_submit_hook(block, state, mining_test_hook_context);
}
#else
#define mining_test_template() ((void)0)
#define mining_test_submit(block, state, handled) (*(handled) = false, false)
#endif
#endif
