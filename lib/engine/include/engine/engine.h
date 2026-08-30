/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine — dispatch ONE scoped unit of work to a model, then judge it here.
 *
 * ── THE LAW THIS MODULE IS BUILT ON ──────────────────────────────────────
 *
 *   THE MODEL PROPOSES. THE GATE DECIDES.
 *
 * A model's output is not deterministic. Ask the same question twice and you
 * get two different answers, so nothing a model says about its own work can
 * be evidence of anything. Z23 is moving toward standing that comes from
 * receipts — claims anyone can re-run and reproduce — and a self-report is
 * the exact opposite of that: it is unreproducible by construction.
 *
 * So the verdict in this module is derived from ONE thing: running the unit's
 * test group and reading how many groups actually executed. Never from the
 * engine's exit code. Never from the engine's report. The signature of
 * engine_verdict_of() (engine/engine_verdict.h) is where that rule is
 * enforced structurally — it accepts no exit code and no model claim, so
 * there is no way to write the wrong thing without changing the function.
 *
 * This is not theoretical. tools/dev/grok-unit.sh records THREE measured ways
 * an engine exits 0 having written nothing, all with an empty diff:
 *
 *   (a) A forced response schema is satisfied on turn ONE by a
 *       {"status":"starting"} object, which ENDS the turn. Measured 3 times
 *       in 17 lanes on this host. A prose warning did not stop it. Nothing
 *       here ever asks a vendor to force a schema; the output contract is
 *       stated IN BAND, at the end of the prompt.
 *   (b) A permission mode in which the engine narrates a plan and never
 *       edits. Measured 2026-08-29.
 *   (c) An unhandled timeout: the unit is killed mid-thought and the caller
 *       sees a partial file set. A timeout here reports itself AS a timeout
 *       (ENGINE_VERDICT_TIMEOUT), never as a pass and never as a plain fail.
 *
 * And the fourth, measured the same night: a unit that produced genuinely
 * good work and printed NO closing report at all. A harness that trusts
 * reports throws that work away. This one does not read reports.
 *
 * ── WHAT THIS MODULE IS ──────────────────────────────────────────────────
 *
 * Pure logic only. No sockets, no processes, no files. Everything here is a
 * function of its arguments, which is what makes the hostile-input tests in
 * lib/test/src/test_engine.c able to say something. The transport (TLS), the
 * isolated worktree, and the gate run live in tools/engine_unit.c, which is
 * compiled straight from source into its own program — deliberately, so that
 * no TLS-client or trust-store symbol ever appears as an undefined reference
 * in a Z23 object file. lib/test/src/test_cold_join_sovereign.c P2 asserts
 * exactly that about the node, and this module must not be the thing that
 * breaks it.
 *
 * ── THE VENDOR INTERFACE ─────────────────────────────────────────────────
 *
 * One interface, a registry of implementations. A vendor declares where it
 * lives, what its request and response look like, and where its key comes
 * from. Adding a third vendor is a row in k_engine_vendors[] and nothing
 * else: no dispatch logic knows any vendor's name.
 */

#ifndef ZCL_ENGINE_H
#define ZCL_ENGINE_H

#include <stdbool.h>
#include <stddef.h>

/* Bounds. Every one of these is a refusal point, not a hint: an engine
 * response arrives from the network and is fully untrusted. */
#define ENGINE_MAX_RESPONSE_BYTES  (4u * 1024u * 1024u)
#define ENGINE_MAX_TEXT_BYTES      (1u * 1024u * 1024u)
#define ENGINE_MAX_PROMPT_BYTES    (512u * 1024u)
#define ENGINE_MAX_CHOICES         64u

/* The wire dialect a vendor speaks.
 *
 * ONE OpenAI-compatible dialect covers almost everything, and that is worth
 * saying out loud because it decides how big this module is. xAI and Z.ai
 * both expose the chat-completions shape, as do Mistral, Groq, Together,
 * DeepSeek and OpenRouter; a vendor is then a URL, a model name, and a key
 * source. Only a genuinely different request document (Anthropic's
 * /v1/messages, Gemini's generateContent) earns a new dialect. The owner's
 * own C client (RhettCreighton/VibePoint, src/llm/llm.h) reached the same
 * conclusion independently: it carries one LLM_PROVIDER_OPENAI_COMPAT case
 * that six vendors share.
 *
 * The two non-HTTP dialects are not exceptions to the interface, they are the
 * point of having one. A subscription-backed CLI is often free where the API
 * bills per token, and this tree ALREADY dispatches one
 * (tools/dev/grok-unit.sh). A caller picks an engine; it does not pick a
 * transport. */
enum engine_wire {
    ENGINE_WIRE_OPENAI_CHAT = 0,  /* POST {messages:[...]} -> {choices:[...]} */
    ENGINE_WIRE_LOCAL_CLI,        /* exec an installed agent CLI, no shell */
    ENGINE_WIRE_LOCAL_FIXTURE     /* no network; a canned reply from a file */
};

/* How a dispatch of this shape gets work into the tree. The distinction the
 * verdict does NOT care about — a diff is a diff — but the applier does. */
enum engine_delivery {
    ENGINE_DELIVERS_ENVELOPE = 0, /* the reply carries file bodies we write */
    ENGINE_DELIVERS_EDITS         /* the engine edited the worktree itself */
};

struct engine_vendor {
    const char      *id;             /* stable selector, e.g. "glm" */
    const char      *display;        /* human name for a transcript line */
    const char      *url;            /* absolute https:// endpoint, or NULL */
    const char      *default_model;
    const char      *key_env;        /* environment variable holding the key */
    const char      *key_file_rel;   /* $HOME-relative 0600 file, or NULL */
    const char      *program;        /* argv[0] for a CLI dialect, else NULL */
    enum engine_wire wire;
    enum engine_delivery delivery;
    bool             costs_money;    /* false only for the fixture engine */
    /* Retry budget. Per vendor, not global: a CLI engine already retries
     * internally, and retrying on top of something that retries multiplies
     * the wall clock invisibly. VibePoint sets 3 for raw APIs and 1 for CLI
     * providers for exactly this reason, and that number is inherited here. */
    int              max_retries;
};

/* The registry. Lookup is by id; iteration exists so a `--engine ?` listing
 * and the tests both enumerate the same table rather than a second copy. */
const struct engine_vendor *engine_by_id(const char *id);
const struct engine_vendor *engine_at(size_t index);
size_t engine_count(void);

/* True when this vendor can be dispatched without a network and without
 * spending money. Exactly one such vendor exists, and it is how the whole
 * lifecycle is exercised on a host with no API key. */
bool engine_is_fixture(const struct engine_vendor *v);

/* True when this vendor needs a key at all. A CLI engine authenticates
 * through its own installed session and must never be handed one. */
bool engine_needs_key(const struct engine_vendor *v);

#endif /* ZCL_ENGINE_H */
