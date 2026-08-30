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


/* ── how a CLI vendor is invoked ──────────────────────────────────────────
 *
 * Two installed agent CLIs are dispatched to today and they do not agree on
 * anything: one reads its prompt from a FILE named by a flag, the other takes
 * the prompt TEXT as an argument. One has a turn cap, the other does not.
 * Hard-coding one of those shapes in the dispatcher is what kept the second
 * vendor out of the tree — the machine the owner works on had a working
 * subscription to it the whole time, and nothing here could reach it.
 *
 * So the argv is a row, like the URL is a row. */

/* Where a CLI vendor expects the prompt to be. */
enum engine_cli_prompt {
    ENGINE_CLI_PROMPT_FILE = 0,  /* a path in argv; the CLI opens the file */
    ENGINE_CLI_PROMPT_ARG        /* the prompt text itself fills one slot */
};

/* An argv slot the caller fills. Anything else in a row is a literal.
 *
 *   {prompt}   the prompt file path, or the prompt text — see cli_prompt
 *   {workdir}  the directory the CLI should work in
 *   {turns}    the repair-turn cap, decimal
 *   {model}    the model id
 *
 * A placeholder a vendor's CLI has no flag for is simply not in its row.
 * That is the point: a missing mapping is an ABSENT flag, never a guessed
 * one. Mapping our turn cap onto a flag that means something else would be
 * worse than leaving the vendor's own default alone. */
#define ENGINE_CLI_PROMPT_TOKEN  "{prompt}"
#define ENGINE_CLI_WORKDIR_TOKEN "{workdir}"
#define ENGINE_CLI_TURNS_TOKEN   "{turns}"
#define ENGINE_CLI_MODEL_TOKEN   "{model}"

/* Longest argv this tree will build for a CLI, argv[0] and the NUL included. */
#define ENGINE_CLI_ARGV_MAX 24u

/* A prompt passed as an ARGUMENT is bounded far below ENGINE_MAX_PROMPT_BYTES.
 * Linux caps a single argv string at MAX_ARG_STRLEN — 32 pages, 131072 bytes
 * — and exec fails with E2BIG above it. That failure would arrive as "could
 * not launch", pointing an operator at the CLI when the answer is the prompt,
 * so it is refused here with its real reason instead. The margin below the
 * kernel's number is deliberate: the limit is per-string on Linux and is not
 * promised by POSIX at all. */
#define ENGINE_CLI_ARG_PROMPT_MAX (96u * 1024u)
struct engine_vendor {
    const char      *id;             /* stable selector, e.g. "glm" */
    const char      *display;        /* human name for a transcript line */
    const char      *url;            /* absolute https:// endpoint, or NULL */
    const char      *default_model;
    const char      *key_env;        /* environment variable holding the key */
    const char      *key_file_rel;   /* $HOME-relative 0600 file, or NULL */
    const char      *program;        /* argv[0] for a CLI dialect, else NULL */
    /* CLI dialect only. NULL-terminated argument template, argv[0] excluded
     * because it is always `program`. NULL for a non-CLI vendor. */
    const char *const *cli_argv;
    enum engine_cli_prompt cli_prompt;
    enum engine_wire wire;
    enum engine_delivery delivery;
    bool             costs_money;    /* false only for the fixture engine */
    /* Exactly one row carries this. It is what a caller gets when they name
     * no engine. A flag rather than an id string elsewhere: a string can name
     * a row that does not exist, a flag cannot, and a test asserts that
     * exactly one row sets it. */
    bool             is_default;
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

/* The engine a caller gets when they name none.
 *
 * It is a CLI row on purpose. A default that needs an API key fails on a
 * fresh host with a message about credentials, which reads as "this tool is
 * broken" rather than "you have not chosen an engine"; a subscription CLI
 * that is already installed just works. Measured on 2026-08-30 this is also
 * the fastest engine the tree can reach — 7s against 41s for the same
 * trivial prompt — and a dispatch harness an operator waits on is one they
 * stop using.
 *
 * Defaulting WHICH engine is not defaulting WHETHER to dispatch. Every path
 * that spends money or writes code still requires its own per-run opt-in. */
const struct engine_vendor *engine_default(void);


/* What a caller supplies for the placeholders. A field a row does not name
 * may be NULL; a field a row DOES name and the caller left empty is a
 * refusal, because an argv slot silently filled with nothing is a different
 * command from the one the row describes. */
struct engine_cli_inputs {
    const char *prompt;   /* file path, or the prompt text; see cli_prompt */
    const char *workdir;
    const char *turns;    /* already rendered decimal */
    const char *model;
};

/* Build the full argv for a CLI vendor into `out`, NULL-terminated.
 *
 * Returns the number of entries written EXCLUDING the terminator, or 0 on any
 * refusal — an unknown placeholder, a placeholder the caller did not supply,
 * an argument-mode prompt over ENGINE_CLI_ARG_PROMPT_MAX, a row with no
 * template, or a `cap` too small to hold the result. Every pointer written
 * borrows from the vendor row or from `in`; nothing is copied and nothing is
 * allocated, so `out` is only valid while both outlive it.
 *
 * This is a pure function on purpose. The exec lives in the dispatch tool,
 * but WHICH ARGUMENTS a vendor receives is a decision, and a decision that
 * only exists inside a tool no test links is a decision nothing can check. */
size_t engine_cli_argv_build(const struct engine_vendor *v,
                             const struct engine_cli_inputs *in,
                             const char **out, size_t cap);

#endif /* ZCL_ENGINE_H */
