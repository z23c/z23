/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Aggregates focused model test files. */

#include "test/test_core.h"

int test_model_core(void);
int test_model_zslp(void);
int test_model_app(void);
int test_model_wallet_projection(void);

int test_models(void)
{
    int failures = 0;

    failures += test_model_core();
    failures += test_model_zslp();
    failures += test_model_app();
    failures += test_model_wallet_projection();
    return failures;
}
