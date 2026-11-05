/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private vault-intent decode, parse and replay cases that
 * test_transaction_intent runs against vault_intent_private.c. */
#ifndef ZCL_TEST_VAULT_INTENT_PRIVATE_CASES_H
#define ZCL_TEST_VAULT_INTENT_PRIVATE_CASES_H

/* Returns the number of failed cases. Local fixtures only: in-memory node.db,
 * a private temp datadir and an unfunded wallet object; nothing is spent. */
int vault_intent_private_cases(void);

#endif
