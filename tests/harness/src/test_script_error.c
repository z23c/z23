/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: pin the current observable behaviour of ScriptErrorString()
 * (core/modules/script/src/script_error.c). Every ScriptError enumerator
 * maps to its exact description, the table covers every enumerator, and
 * out-of-range values (including SCRIPT_ERR_ERROR_COUNT) map to the
 * generic "unknown error" string, never NULL. Characterization only: the
 * expectations are the literal strings the mapper returns today. */

#include "test/test_core.h"

#include "script/script_error.h"

#include <stddef.h>
#include <string.h>

struct se_row {
    ScriptError err;
    const char *text;
};

static const struct se_row se_rows[] = {
    { SCRIPT_ERR_OK, "No error" },
    { SCRIPT_ERR_UNKNOWN_ERROR, "unknown error" },
    { SCRIPT_ERR_EVAL_FALSE,
      "Script evaluated without error but finished with a "
      "false/empty top stack element" },
    { SCRIPT_ERR_OP_RETURN, "OP_RETURN was encountered" },
    { SCRIPT_ERR_SCRIPT_SIZE, "Script is too big" },
    { SCRIPT_ERR_PUSH_SIZE, "Push value size limit exceeded" },
    { SCRIPT_ERR_OP_COUNT, "Operation limit exceeded" },
    { SCRIPT_ERR_STACK_SIZE, "Stack size limit exceeded" },
    { SCRIPT_ERR_SIG_COUNT,
      "Signature count negative or greater than pubkey count" },
    { SCRIPT_ERR_PUBKEY_COUNT, "Pubkey count negative or limit exceeded" },
    { SCRIPT_ERR_VERIFY, "Script failed an OP_VERIFY operation" },
    { SCRIPT_ERR_EQUALVERIFY, "Script failed an OP_EQUALVERIFY operation" },
    { SCRIPT_ERR_CHECKMULTISIGVERIFY,
      "Script failed an OP_CHECKMULTISIGVERIFY operation" },
    { SCRIPT_ERR_CHECKSIGVERIFY,
      "Script failed an OP_CHECKSIGVERIFY operation" },
    { SCRIPT_ERR_CHECKDATASIGVERIFY,
      "Script failed an OP_CHECKDATASIGVERIFY operation" },
    { SCRIPT_ERR_NUMEQUALVERIFY,
      "Script failed an OP_NUMEQUALVERIFY operation" },
    { SCRIPT_ERR_BAD_OPCODE, "Opcode missing or not understood" },
    { SCRIPT_ERR_DISABLED_OPCODE, "Attempted to use a disabled opcode" },
    { SCRIPT_ERR_INVALID_STACK_OPERATION,
      "Operation not valid with the current stack size" },
    { SCRIPT_ERR_INVALID_ALTSTACK_OPERATION,
      "Operation not valid with the current altstack size" },
    { SCRIPT_ERR_UNBALANCED_CONDITIONAL, "Invalid OP_IF construction" },
    { SCRIPT_ERR_NEGATIVE_LOCKTIME, "Negative locktime" },
    { SCRIPT_ERR_UNSATISFIED_LOCKTIME,
      "Locktime requirement not satisfied" },
    { SCRIPT_ERR_SIG_HASHTYPE,
      "Signature hash type missing or not understood" },
    { SCRIPT_ERR_SIG_DER, "Non-canonical DER signature" },
    { SCRIPT_ERR_MINIMALDATA, "Data push larger than necessary" },
    { SCRIPT_ERR_SIG_PUSHONLY,
      "Only non-push operators allowed in signatures" },
    { SCRIPT_ERR_SIG_HIGH_S,
      "Non-canonical signature: S value is unnecessarily high" },
    { SCRIPT_ERR_SIG_NULLDUMMY,
      "Dummy CHECKMULTISIG argument must be zero" },
    { SCRIPT_ERR_PUBKEYTYPE,
      "Public key is neither compressed or uncompressed" },
    { SCRIPT_ERR_CLEANSTACK,
      "Stack size must be exactly one after execution" },
    { SCRIPT_ERR_SIG_NULLFAIL,
      "Signature must be zero for failed CHECK(MULTI)SIG operation" },
    { SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS,
      "NOPx reserved for soft-fork upgrades" },
};

int test_script_error(void)
{
    int failures = 0;
    TEST_CASE("ScriptErrorString: every enumerator maps to its exact text; "
              "out-of-range values map to \"unknown error\"") {
        const size_t n = sizeof se_rows / sizeof se_rows[0];

        /* The table must cover every enumerator: a new ScriptError value
         * without a row fails here, not silently. */
        ASSERT_EQ(n, (size_t)SCRIPT_ERR_ERROR_COUNT);

        for (size_t i = 0; i < n; i++) {
            ASSERT_EQ(se_rows[i].err, (ScriptError)i);
            ASSERT_STR_EQ(ScriptErrorString(se_rows[i].err), se_rows[i].text);
        }

        /* Out-of-range: the COUNT sentinel, one past it, and a large
         * value all take the default branch. Never NULL. */
        ASSERT(ScriptErrorString(SCRIPT_ERR_ERROR_COUNT) != NULL);
        ASSERT_STR_EQ(ScriptErrorString(SCRIPT_ERR_ERROR_COUNT),
                      "unknown error");
        ASSERT_STR_EQ(ScriptErrorString((ScriptError)(SCRIPT_ERR_ERROR_COUNT + 1)),
                      "unknown error");
        ASSERT_STR_EQ(ScriptErrorString((ScriptError)1000), "unknown error");

        /* Static storage: repeated calls return the same pointer. */
        ASSERT(ScriptErrorString(SCRIPT_ERR_EVAL_FALSE) ==
               ScriptErrorString(SCRIPT_ERR_EVAL_FALSE));
    } TEST_END
    return failures;
}
