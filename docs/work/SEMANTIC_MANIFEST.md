<!-- Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 -->

# Semantic manifest v1: format, sensor, and measured value

A semantic manifest is a canonical byte string that records what a C front end
saw in one translation unit (TU): the compiler, target, argv and include search
list; every file read, by content; each include lookup with its negative
probes; repo macros; declarations; record layouts; enum values; and every
function definition, identified by a hash of its tokens. Z23 reads manifests
only. It never links a compiler to do so.

| Piece | Path | Dependency |
|---|---|---|
| Reader, builder, roots, diff, dump | `contexts/commons/modules/vcs/src/semantic_manifest.c`, `semantic_manifest_build.c`, `semantic_manifest_dump.c` | SHA3 only |
| The producer (the "sensor") | `tools/sensors/clang_manifest.c`, `clang_manifest_ast.c` and the compiler-API-free core `clang_manifest_core.c`, `_paths.c`, `_lookup.c`, `_records.c`, `_facts.c`, `_producer.c` | libclang C API; built by `make clang-manifest` |
| The warm session (`z23-clang-manifest session`) | `tools/sensors/clang_manifest_session.c` and the compiler-API-free checks `clang_manifest_warm.c` | libclang C API; the same binary |
| Tests | `tests/harness/src/test_semantic_manifest.c`, `semantic_warm_directory_cases.h`, `semantic_sensor_session.c`, `tests/fixtures/semantic_manifest/*.bin` | groups `semantic_manifest` (no libclang) and `semantic_sensor` |
| Facts extension and snapshot namespace | `contexts/commons/modules/vcs/src/semantic_manifest_facts.c`, `semantic_namespace.c`, `vcs_path_policy.c` | SHA3, a ZVCS tree object |
| Fuzz harness | `tools/fuzz/fuzz_semantic_manifest.c`, `tests/harness/fuzz_seeds/semantic_manifest/` | libFuzzer; a `FUZZ_TARGETS` entry |
| Windows acceptance | `tests/harness/src/semantic_manifest_windows_acceptance.c`, `semantic_manifest_windows_fixtures.h`, `tests/fixtures/semantic_facts/*.zsm` | row `semantic_manifest` in `platform/modules/platform/tests/windows_acceptance.mk` |
| Facts-narrowed closure | `tools/dev/devloop_facts.c`, `devloop_facts_text.c`, `devloop_facts_bind.c`, `devloop_facts_json.c` | SHA3, the code index |
| Facts tests | `tests/harness/src/test_semantic_facts.c`, `test_semantic_facts_live.c`, `tests/fixtures/semantic_facts/*.zsm` | groups `semantic_facts` (no clang) and `semantic_facts_live` |

The sensor is an external tool. The link gate lists it as outside the base
toolchain (the `check-standalone-tools-link` gate in `tools/lint/lintc/gate_standalone_tools_link.c`), and it never enters
z23, z23-dev, the test harness, or core. The exact root is meant to become one
input, the "semantic root", to the v2 action root later. Its conventions match
the v2 action preimage: fixed field order, length-prefixed and domain-tagged
fields, repo-relative paths, and `@sys` spellings for system paths. Ordered
argv is part of the identity, and the environment allowlist is sorted.

## Byte format

```
manifest     = MAGIC || section(1) || ... || section(9)
MAGIC        = "zcl.semantic_manifest.v1"            (24 bytes, no NUL)
section      = u8 tag || u32le payload_len || payload
payload      = u32le record_count || record*
record       = u32le record_len || record_bytes
root         = SHA3-256("zcl.semantic_root.v1" || manifest)
section_root = SHA3-256("zcl.semantic_section_root.v1" || u8 tag || payload)
hint_root    = SHA3-256("zcl.semantic_hint_root.v1"
                        || (u8 tag || section_root(tag))  for tag in 1,3,4,5,6,7,8)
fn_tokens    = SHA3-256("zcl.semantic_fn_tokens.v1" || (u32le len || token)*)
```

Field primitives inside `record_bytes`:

- `text` is a u32le length followed by the bytes, which contain no NUL and are
  at most 1 MiB long.
- `u8`, `u32le`, `u64le` and `i64le` (two's complement) are fixed-width
  numbers; a digest is 32 raw bytes.
- `list<X>` is a u32le count followed by that many X elements.

**Ordering is canonical, not normalized.** Every section is present exactly
once, in tag order. Records inside a section are strictly increasing by
`memcmp` over `record_bytes`, and a record that is a proper prefix of another
sorts first. A duplicate record is therefore refused. Sorted inner lists use
the same rule over each element's encoding. Because the length prefix is
little-endian, the order is the byte order of the encoding, not lexical order
(`"g"` sorts before `"(indirect)"`). A producer sorts the encoded bytes; it
never compares the strings. The builder
(`vcs_semantic_builder_v1_finish`) sorts and deduplicates, then runs the strict
decoder on its own output and refuses anything the decoder would refuse.

**Paths** are repo-relative (`inc/a.h`) <!-- doc-path-ok: illustrative example path, not a real file --> , `"."` (directory fields only), or
`@sys/<absolute path>` for anything outside the checkout. The components `.`
and `..`, empty components, a leading `/` and a leading `@` other than `@sys`
are refused. The producer refuses a path under `$HOME` that lies outside the
checkout, because such a path has no host-independent spelling, and it
refuses to run at all when `$HOME` is unset, relative or does not resolve,
since it could not then tell such a path from a system one. **Argv/env
text** may contain `@root`, meaning the checkout root. A `/` at a path
boundary is refused unless it begins `/zclassic23` or `/zbuild`. A path
boundary is the start of the text, the position after one of the characters
`=,:;"'` or a space, or the position right after a glued option such as `-I`,
`-isystem`, `-iquote`, `-o` or `-MF`
(`vcs_semantic_argv_path_boundary_v1`).

### Manifest field table

| Tag | Section | Record fields, in order | Records per TU |
|---|---|---|---|
| 1 | identity | text compiler; path-or-empty resource_dir; text target; path main_file; list<argv> argv (order kept); list<dir> quote_dirs; list<dir> angled_dirs; list<dir> ignored_dirs; list<env> env where env = text name, u8 set, argv value | exactly 1 |
| 2 | files | path; digest sha3(content); u8 origin (1 main, 2 repo, 3 system) | every file read |
| 3 | lookups | path includer; text spelled; u8 form (1 quoted, 2 angled); u8 kind (1 include, 2 has_include, 3 include_next); path-or-empty hit; u32 hit_slot; u8 miss_evidence; list<u32> present_slots (strictly increasing) | per directive in a repo file |
| 4 | macros | path; text name; u8 function_like; text body (non-comment tokens after the name, one space apart); u8 used_in_main | per repo definition |
| 5 | decls | path; text kind (function, variable, typedef, struct, union, enum); text name; text canonical type; u8 linkage | per repo file-scope declaration |
| 6 | layouts | path; text name; u8 kind (1 struct, 2 union); u64 size; u64 align; list<field> where field = text name, u64 offset_bits, u32 bit_width (0xffffffff when the field is not a bit-field), text type | per repo record definition |
| 7 | enums | path; text enum_name; text constant; i64 value | per repo enumerator |
| 8 | functions | path; text name; u8 linkage; text type; digest fn_tokens; sorted list<text> callees; sorted list<text> macros expanded inside | per repo function definition; key (path, name) unique |
| 9 | spans | path; text name; u32 begin_line; u32 end_line; u64 begin_offset; u64 end_offset | one per function |

Linkage numbers are 0 invalid, 1 none, 2 internal, 3 unique-external and
4 external. An unnamed tag takes the name of the first repo typedef that names
it, or `""` when there is none. The fields of an anonymous struct or union
member are flattened into the enclosing layout at their absolute offsets.
Callees are direct calls to a declared function, by name. Every other call is
recorded as `(indirect)`.

**Lookup slots.** For a quoted lookup, the slots are: slot 0 is the includer's
directory, then the quote dirs, then the angled dirs. For an angled lookup,
the slots are the angled dirs alone. Every slot below `hit_slot` is asserted
absent unless `present_slots` lists it. A miss has an empty hit and
`hit_slot` = slot count. The miss evidence byte records how the absent slots
were established:

- `1 derived_stat`: the hit is the compiler's. The slots come from the
  compiler's own printed search list, and every probe below the hit was
  confirmed absent by `stat`.
- `2 replayed_stat`: a conditional lookup found by a text scan, resolved
  by replaying that search list, with every probe confirmed by `stat`. The
  scan replays a `__has_include` whose operand is a literal `"x"` or `<x>`,
  or (facts manifests, revision 4) an object-like repo macro every
  definition of which is one plain string literal, found through the
  expansion the front end recorded at the operand. It replays a
  `__has_include_next` the same way, starting at the slot after each one
  its file was entered through (a main file, or a file found in its
  includer's own dir, searches as `__has_include` does); the slots before
  that start are listed in `present[]`, with no claim.
- `0 none`: `include_next`, a computed include, or an absolute include. No
  negative claim is made for these. The text scan also writes a `none`
  record (kind `has_include`, no hit) for every conditional lookup it finds
  in any file, a system header's too, and cannot replay: any other macro
  operand (a predefined
  or command-line macro, a function-like one, a body that is not one plain
  string literal), a `__has_include_next` whose file was entered in a way
  no slot names, `__has_embed`, the GNU `__has_include__` and
  `__has_include_next__` spellings, an `#embed` (or `%:embed`) directive,
  and any of these that a line continuation or a trigraph runs through, or
  whose header name holds `/*` or `//`. It also writes one for a probe
  word in the body of a `#define` in any file, a system header's too
  (the probe is evaluated where the macro expands, against that file's
  directory), and for one in a `-D` value, on the main file. Its spelled
  name is the occurrence's text, prefixed `#embed? ` unless it already starts
  `#embed` or `__has_embed` (for example `#embed? __has_include(OPT_HDR)` or
  `#embed "blob.bin"`). Which words are live comes from clang's own
  lexing: the sensor tokenizes every file the TU read with
  `clang_tokenize`, which re-lexes it raw under the TU's own language
  options, so a word in a comment or in a character, string or raw string
  literal (every prefix, `R`, `u8R`, `uR`, `UR`, `LR`, on one line or
  several, when this front end accepts that spelling) is no identifier
  token and no lookup. Clang 18.1.3 rejects a raw string in GNU mode, with
  no `-std`, and with `-fraw-string-literals`, and it does not define
  `__has_embed` or `#embed`. The sensor tests ask this host's
  `z23-clang-manifest emit` and skip only those cases when that emit
  refuses them. A front end that accepts the syntax still has to record
  the probe.
  A word in a group the preprocessor skipped needs no record (see the
  argument below), though raw lexing covers those groups too
  (the walk reads them for directives). A directive is a `#` or `%:` token first on its logical
  line (comments count as whitespace), then its name. Raw lexing differs
  from the preprocessor's in two places outside the skipped groups (clang
  raw-lexes those, so neither rule applies there), and the sensor lexes both as the
  preprocessor does: after an include-like directive (`#include`,
  `#include_next`, `#import`, `#embed`, `#__include_macros`) or a probe
  word and its `(`, a `<` opens one header name up to its `>`, which never
  opens a comment or a literal; and a `#warning` or `#error` line is plain
  text, where `/*` opens nothing. Where raw tokens run past such a span
  the file is tokenized again from its end. The sensor refuses a TU where
  raw tokens run past a `<`...`>` span on a `#pragma` line (some pragmas
  take a header name) and fails the emit when a file's tokens stop short
  of its last non-blank byte. The scan then reads each live word's operand
  in the text as translation phases 1 and 2 leave it, under the one rule
  it cannot read from the tokens: the sensor parses a small probe file
  with the TU's own argv and reads back whether trigraphs are replaced
  from how it lexes `sizeof("??=")`, so neither an option's arity
  (`-I -std=c17` names no `-std`) nor a macro such as `__STDC_VERSION__`,
  which `-D`, `-U` or an `-include` file can change, misleads it; the
  probe first drops any
  macro named like its own words, and `sizeof('a')` refuses C++. It
  parses with `--no-default-config`, as the TU does, so no clang config
  file adds flags. A system header's own conditionals are scanned too: an
  angled search starts at the repo's `-I` dirs, so a repo dir gaining the
  name flips it. A `__has_include_next` there is replayed from the start
  and from the slot after each search dir that could hold the header
  (other system headers include it with no LOOKUPS record), and is `none`
  when no search dir holds it. A probe word that is the operand of an
  `#ifdef`-like directive (its name right after the `#`), or of a
  `defined` on an `#if` or `#elif` line after nothing but other `defined`
  tests and `! && ||`, is no lookup: anything else before it could be a
  macro that turns the word into a live probe. The sensor refuses every
  `-X` pass-through but `-Xlinker` (whose value only the linker reads) in
  any spelling (`-Xclang`, `-Xclang=`,
  `-Xpreprocessor`, `-Xarch_host`, `-Xcompiler`, `-Xparser` reach the
  front end), `-Wp,` and front-end plugins (a `-D` or `-std` there
  is one the scan cannot read) and `-fms-compatibility` or an MSVC target
  (either turns trigraphs off). The facts
  consumer treats a `none` record as reachable by every created or deleted
  path, and one whose name starts `#embed` or `__has_embed` by every changed
  path (see the universe below).

  Hiding a live probe is impossible by construction: the classification
  above can only add precision, never remove a record. After the token
  walk, the scan normalizes each file's raw bytes by removing every splice
  clang could accept (a backslash, any of space, tab, form feed or vertical
  tab, then `\r\n`, `\n\r`, `\n` or `\r`; and every `??/` splice whatever
  the trigraph mode, since removing too much only finds more words) and
  finds every occurrence of `__has_include` and `__has_embed` (as a word
  or inside one) and every `#`, `%:` or `??=` followed by blanks or block
  comments and `embed`. Each occurrence ends with a record: the replayed
  one when clang's tokens gave it a live lookup token, and otherwise a
  `none` record. Occurrences end with none only where clang itself shows
  they need none. Its own tokens, outside a skipped group, show a comment,
  a literal, part of another token, or the operand of an `#ifdef`-like
  directive or a plain `defined` test; a word in a header name or a
  `#warning` or `#error` line, which only the sensor's own lexing reads as
  such, is recorded. And `clang_getSkippedRanges` shows the groups the
  preprocessor skipped, where nothing is recorded, by this argument (for
  review): a skipped group becomes live only when a live condition that
  controls it changes. That condition reads (a) macro text in files the TU
  reads, and editing such a file puts it in the TU's FILES, so the TU is
  affected and sensed again; (b) argv or the toolchain, which trips the
  identity check; or (c) a probe on a live conditional line, which has
  its own record, reached by the created or deleted path that flips it.
  So any change that makes the group live already makes the TU affected,
  and the new manifest records the probes that are live then. The drop
  is clang's answer, not the sensor's lexing, and the header-name and
  `#warning` rules, whose misreading hid live code in review round 6,
  still apply only outside skipped groups. clang reports consecutive
  skipped groups as one range, from the `#` that opens the first to the
  name of the directive that ends the last, so a range can hold an
  `#elif` line the preprocessor evaluates (`#if 0` ... `#elif A` ...
  `#else`, when A is false). The walk reads the line whose `#` opens a
  range, and every `#elif`, `#elifdef` or `#elifndef` line inside one, as
  live and leaves it out of the drop, up to the first newline between
  clang's tokens, so a block comment that carries the condition onto the
  next line carries the live line with it. The skipping lexer reads a
  range raw, as `clang_tokenize` does, so the walk finds the same
  directives; the operand of the directive that ends a range is outside
  it. `clang_getSkippedRanges` answers for one entry of a file, and the
  X-macro pattern enters one header several times under different
  macros, so the drop applies only to a file entered once: one inclusion
  directive the front end ran names it (the main file: none), counting
  every directive in every file and `-include`, from the preprocessing
  record, which a cold parse and a preamble reparse report alike. Any
  other file is read as skipped whole: nothing in it is marked exempt,
  hidden or skipped, so every occurrence is recorded. A file an include
  guard or `#pragma once` keeps to one entry but several directives name
  is treated the same way, which only widens. Under a warm session's
  preamble the ranges are the preamble's: a change to its region of the
  main file rebuilds it, and a change to a file it holds recreates the TU
  (every FILES digest is checked before a reparse), so they are never
  stale; the session test flips a skipped group in a preamble header
  through a main-file macro and requires the reparse to record the probe
  and equal a cold emit. The
  splice rule is clang's (`getEscapedNewLineSize`) wherever the scan reads
  an operand too, and a lookup token clang lexes whose text the scan
  cannot read as that word refuses the TU. Pasting builds a word with no
  occurrence of its own: it joins the spellings of existing tokens, and
  during a conditional only tokens of `#define` bodies, `#if`, `#elif` and
  `#embed` lines (skipped groups' too, which only widens) and built-in or
  command-line macros can take part. When two or more such spellings in a row spell
  `__has_include`, `__has_include_next` or `__has_embed`, the TU gets one
  `#embed? pasted from <first>` record on its main file. A 50-TU sample of
  the repository has no such TU; the first rule, any `##` in any macro
  body, hit all 50 (glibc and clang's own headers paste), and so did
  requiring the `##` macro be reachable from a conditional (`__GLIBC_USE`,
  `__stdint_join3`).

The compiler never reports probes directly, so no miss here is compiler-exact.
Each miss is derived from exact inputs and is stat-confirmed at sensor time.

**Hint root: a candidate-match hint only.** The hint root leaves out FILES
(content bytes) and SPANS (positions). A comment-only, blank-line or
whitespace edit therefore keeps it equal while the exact root changes. It is
not an identity. System headers enter it only through the identity and
lookups, and a token hash is no proof of equal object code. A hint match may
only nominate a reuse candidate. Acceptance still needs the exact root or a
stronger equivalence check.

### What the libclang sensor does and does not observe

- **Parse.** The sensor parses with the caller's argv and appends `-v
  -Wno-unknown-warning-option -Wno-error`. The appended flags are not part of
  the identity. `-v` makes the front end print its exact search list,
  including ignored nonexistent dirs, which the sensor captures from stderr.
- **Identity argv.** The identity argv drops output-only controls (`-c`,
  `-o X`, `-MD`, `-MMD`, `-MP`, `-MF/-MT/-MQ X`, `-fsyntax-only`) and the
  source path. Any front-end error refuses the manifest.
- **Object compiler.** The front end that parses is not the compiler that
  builds the object. `emit --cc CC` names the object's compiler (a path, or
  a name looked up on `PATH` as `execvp` would) and `--toolchain-id HEX`
  the build's toolchain identity (Make's `$(BUILD_COMPILER_ID)`, from
  `tools/dev/build-epoch-key.sh compiler-id`: the bytes of every program
  the driver names for `cc1`, `cc1plus`, `collect2`, `lto1`, `as` and `ld`,
  the linkers, the runtime and startup objects, the include search roots
  and the compile environment). The identity's `compiler` text becomes
  `<front end version>; object-cc <path> sha3-256 <hex> libs <closure>
  toolchain <id>`: the compiler's realpath, spelled like any other path (a
  compiler under `$HOME` outside the checkout is refused), the SHA3-256 of
  its bytes, and `libs none` for a script or static image or `libs sha3-256
  <hex>` over the realpath and bytes of every shared object the dynamic
  loader maps for it (a dynamically linked clang's `libLLVM` and
  `libclang-cpp`). On Linux the loader's trace mode lists those objects;
  an image whose objects cannot be listed (any other format, or a failed
  trace) is unknown. A compile cache is never the compiler: `--cc` that
  resolves to a `ccache`, `sccache` or `zcc` image is resolved through, as
  the cache's masquerade link runs the next program of the link's name on
  `PATH` that is not a cache, and is unknown when there is none. Without
  `--cc` or `--toolchain-id` the text ends `; object-cc unknown`; a `--cc`
  that resolves to no executable file, or a `--toolchain-id` that is not
  64 lowercase hex digits (or is Make's all-zero unfingerprinted value),
  refuses the manifest. The shared objects of the programs the driver runs
  (gcc's `cc1` links `libisl`, `libmpc` and `libgmp`) are bound only as far
  as the toolchain identity binds them, by those programs' bytes. The byte
  format is unchanged (the field was always free text), so v1 readers and
  older manifests, which carry the front end version alone, still decode.
  A compiler upgrade, or a switch between compilers, changes the IDENTITY
  record and so is identity drift to every consumer. A manifest whose
  IDENTITY says `object-cc unknown`, or names no `object-cc` at all (one
  written before the field existed), cannot show that the object's compiler
  did not change: both consumers fall back for it even when both sides
  carry the same text. The TU consumer calls it `identity-drift`; the
  function-level consumer finds its code generation unbounded
  (`inline-closure-unknown`, `no known object compiler`).
- **Stripped comments.** `clang_tokenize` keeps comments as tokens. The sensor
  drops them from function token hashes and from macro bodies. The
  `comment_only` seed puts a comment inside a function body and inside a
  macro body to pin this.
- **Not observed:**
  - `#undef`. MACROS lists every repo definition, not only the definitions
    still visible at the end of the TU.
  - Entities in system headers. They are covered only by FILES content hashes
    and lookup hits.
- **Clang-specific spellings.** Canonical type spellings come from clang's
  pretty-printer with anonymous-tag locations off, for example
  `union json_value::(unnamed)`. Everything else in the format is
  compiler-neutral. A future native emitter must reproduce these spellings to
  share bytes, or define its own type grammar under a new MAGIC.
- **Two type grammars, never compared.** `clang_getTypePrettyPrinted` is not
  exported by every libclang image: Apple's `libclang.dylib` (Clang 17)
  declares it in its header and does not export it. `make clang-manifest`
  therefore decides by a link probe, not by `CINDEX_VERSION_MINOR`, and
  builds the sensor with `CM_TYPE_PRETTY_PRINTED=1` or `0`. Without the call,
  types are spelled by `clang_getTypeSpelling` of the canonical type, with
  the `(unnamed at path:line:col)` location cut to `(unnamed)`. On the 3
  hotswap TUs tried (`hotswap_loader.c`, `hotswap_activate.c`,
  `hotswap_islands.c`), the two grammars wrote the same records; the grammar
  still differs in general (sugar, spacing, clang versions). The grammar in
  use is a fixed token (`CM_TYPE_GRAMMAR`) that enters the producer digest as
  its own entry (tag `G`, see "Producer digest"). Two manifests written
  under different grammars therefore never name the same producer, and a
  consumer never narrows across them (`producer-changed`).

## Golden vector

`semantic_manifest` builds this manifest with the builder, pins its length,
root and hint root, and checks that adding every record twice, in a different
order, yields the same bytes. The root was cross-checked with an independent
SHA3 (`openssl dgst -sha3-256` over the domain followed by the bytes).

```
identity "golden-cc 1.0" "" "x86_64-pc-linux-gnu" "src/a.c" ["-std=c23","-I@root/inc"] [] ["inc","@sys/usr/include"] [] ["CPATH"=0:"","C_INCLUDE_PATH"=0:""]
files "inc/a.h" ee66867d36d6568cc6df87baed5d1d11ca8fc3bedf059b377474fff50c8419b2 2
files "src/a.c" a051dcdb2edfd0747256f2cd01abacab47279568195e39e163c796d927db772c 1
lookups "src/a.c" "a.h" 1 1 "inc/a.h" 1 1 []
macros "inc/a.h" "A_MAX" 0 "16" 1
decls "src/a.c" "function" "f" "int (void)" 4
layouts "inc/a.h" "pair" 1 8 4 ["x"@0:4294967295:"int","y"@32:4294967295:"int"]
enums "inc/a.h" "mode" "MODE_ON" -1
functions "src/a.c" "f" 4 "int (void)" 6daa7722bb3b1cda0220425a56ffed8b671753a4cc78e67cf3c468ace5aed041 ["g","(indirect)"] ["A_MAX"]
spans "src/a.c" "f" 2 2 18 46
```

- length: 775 bytes
- root: `7ece87deea7ec79254851b5e02eef5f01ecc49829958ef22514208d026c6bb77`
- hint: `5b3caf953603b4c347bd0423e2d52a079d8b8c8b17d4fb22192a7b40a388baf6`

```
7a636c2e73656d616e7469635f6d616e69666573742e763101ae000000010000
00a60000000d000000676f6c64656e2d636320312e3000000000130000007838
365f36342d70632d6c696e75782d676e75070000007372632f612e6302000000
080000002d7374643d6332330b0000002d4940726f6f742f696e630000000002
00000003000000696e6310000000407379732f7573722f696e636c7564650000
00000200000005000000435041544800000000000e000000435f494e434c5544
455f5041544800000000000264000000020000002c00000007000000696e632f
612e68ee66867d36d6568cc6df87baed5d1d11ca8fc3bedf059b377474fff50c
8419b2022c000000070000007372632f612e63a051dcdb2edfd0747256f2cd01
abacab47279568195e39e163c796d927db772c01033000000001000000280000
00070000007372632f612e6303000000612e68010107000000696e632f612e68
0100000001000000000424000000010000001c00000007000000696e632f612e
6805000000415f4d415800020000003136010533000000010000002b00000007
0000007372632f612e630800000066756e6374696f6e01000000660a00000069
6e742028766f696429040660000000010000005800000007000000696e632f61
2e68040000007061697201080000000000000004000000000000000200000001
000000780000000000000000ffffffff03000000696e74010000007920000000
00000000ffffffff03000000696e74072e000000010000002600000007000000
696e632f612e68040000006d6f6465070000004d4f44455f4f4effffffffffff
ffff086b0000000100000063000000070000007372632f612e63010000006604
0a000000696e742028766f6964296daa7722bb3b1cda0220425a56ffed8b6717
53a4cc78e67cf3c468ace5aed0410200000001000000670a00000028696e6469
72656374290100000005000000415f4d41580930000000010000002800000007
0000007372632f612e630100000066020000000200000012000000000000002e
00000000000000
```

## Tests

Both groups are in `tools/dev/test_group_catalog.def`. Both are listed as
external-input groups in `tests/harness/src/testcache.c`, so the test cache
never serves either one.

- `semantic_manifest` needs no libclang. It covers the golden vector, the
  canonical folding, and 11 refusals: truncation, empty input, magic, section
  order, an absolute path, `..`, a host path in argv, an off-allowlist env
  name, record order, a main-file mismatch, and a trailing byte. It then
  replays every seed below over the checked-in fixture manifests.
  It also leaves seven sections empty and requires `finish()` to succeed
  with zero records in each, reads facts revision 2 back, renders the dump's
  composites exactly, and recomputes the Windows acceptance ledger digest from the
  fixture files on disk (see "Windows acceptance"). It also dry-runs the
  `clang-facts` rule against the dev object rule (see "The producer: the
  libclang sensor").
- `semantic_sensor` runs the sensor live, and prints a visible SKIP when the
  sensor binary has not been built. It proves:
  - the `root` command reports `unreadable` and exits 2 when a failed read
    retains an allocation. `make clang-manifest` also builds a test executable
    from the command source with a deterministic failed-reader fixture
    (`tests/fixtures/semantic_sensor/root_failed_read.c`, outside the
    directories the Windows manifest ledger reads);
  - the fixture tree gives byte-identical manifests before and after
    `git commit` and at two different absolute roots, with an absolute
    `-I<root>/...` in argv on both;
  - each seed changes the exact root, changes the hint root (except
    `comment_only`), changes exactly the listed sections, and names the one
    changed function where there is one.
  - the warm session writes the bytes a cold process writes after every
    edit of "Warm session", reports the TU reuse the contract requires, and
    with the fault flag never writes a warm manifest the oracle rejected.

Setting `ZCL_SEMANTIC_FIXTURE_OUT=tests/fixtures/semantic_manifest` refreshes
the fixture manifests and prints the golden vector.

| Seed | Edit | Sections changed (exactly) | Hint root |
|---|---|---|---|
| header_decl | add a prototype to the header | files, decls | changes |
| flag_define | append `-DEXTRA=1` | identity | changes |
| flag_opt | `-O2` → `-O0` | identity | changes |
| flag_reorder | swap `-std=c23` and `-O2` | identity | changes |
| macro_body | `SHAPE_MAX 16` → `17` | files, macros | changes |
| layout_add | add a struct field | files, layouts, spans | changes |
| layout_reorder | swap two struct fields | files, layouts | changes |
| shadow_header | copy of `shape.h` in the earlier `-I` dir | every section but identity (lookups explain the move) | changes |
| fn_body | `+ SHAPE_MAX` → `- SHAPE_MAX` in `helper` | files, functions (only `helper`) | changes |
| comment_only | comments before a function, inside a body, inside a macro body | files, spans | equal |


## Cost and value

- **Cost.** The sensor is an extra pass: 1.2 to 1.6 times a stock clang
  `-fsyntax-only` parse (about 42 to 176 ms p50 per TU), about 0.5 to 0.6 times
  the gcc dev compile of a mid or large TU, and 2 times on a tiny TU where
  process and libclang startup dominate. It adds latency unless its hint
  nominates reuse that a later exact check accepts.
- **Structure value.** The manifest localizes a real edit to named functions
  (about 5% of main-file definitions move per commit), names the header
  layout, declaration or macro records that fan out to includers, and
  separates a comment-only change (hint root equal, exact root different)
  from a semantic one, which a content hash cannot do.
- **Consumer.** A latency gain comes only from a consumer that uses a
  hint-root match to nominate reuse and accepts on the exact root or a
  stronger equivalence check; see "The facts consumer".

## Facts extension and its producer

The optional extension `zcl.semantic_facts.v1` adds six sections after SPANS.
They are present as a block or absent. A manifest without them keeps its exact
v1 bytes.

| Tag | Section | Record fields, in order |
|---|---|---|
| 10 | facts | text extension name; digest namespace_root (ZVCS tree hash, or zero); digest producer (or zero); u32 max_records; u64 max_section_bytes; u8 complete |
| 11 | symbols | text canonical id; path; text kind; u8 linkage; u8 defined |
| 12 | refs | text from-id; u8 kind (1 call, 2 address, 3 variable, 4 type, 5 enumerator, 6 macro); text to-id |
| 13 | unknowns | text site id; u8 kind (1 indirect call, 2 inline asm, 3 external call, 4 volatile, 5 atomic, 6 unresolved); text detail; u32 occurrences |
| 14 | probes | path includer; text spelled; u8 form; u8 kind; u8 absence claimed; list of (u32 slot, u8 reason) for every slot whose absence is UNKNOWN |
| 15 | truncated | text section name; u32 records kept; u32 records dropped |

The builder writes FACTS and TRUNCATED itself; a producer never adds to them.

- **Canonical ids** are compiler-neutral: `prefix:name` for external linkage,
  `prefix:path:name` otherwise. Prefixes: `f` function, `v` variable, `t`
  typedef, `s` struct, `u` union, `e` enum, `k` enumerator, `m` macro
  (`m:@builtin:NAME` for a builtin macro, `m:@predefined:NAME` for one defined
  outside any file, such as `-D`).
- **Unknown effects are records, never omissions.** A call through a pointer,
  inline asm, a call of a function declared in no repo file, and each
  volatile or `_Atomic` access is written as an UNKNOWN at its site.
- **Negative lookups need the snapshot owner.** The preprocessor only reports
  hits. A probe slot is proved absent only against the immutable ZVCS tree
  named by `namespace_root` (`vcs_semantic_namespace_v1_absent`, which reloads
  the tree object and re-derives its hash). Without it every claimed slot is
  UNKNOWN, with a reason: no snapshot, outside the checkout, excluded by
  snapshot policy, stale (the snapshot holds the path), not a directory, or
  unresolved.
- **Bounded.** The default caps are 65,536 records and 16 MiB per section.
  A section cut by a cap leaves a TRUNCATED record and `complete = 0`; such a
  manifest is valid but not authoritative, and every consumer falls back.
- **Producer digest.** FACTS names the code that wrote the facts:
  SHA3-256 over `zcl.semantic_producer.v1` and, sorted by file name, the
  producer image's own bytes (the sensor executable, read through
  `os_proc_open_self_exe`, so neither argv[0] nor a wrapper script can choose
  it), the GNU build id of every loaded `libclang*` or `libLLVM*` image
  (the front end), and the type grammar token (entry name `type-grammar`),
  each as
  `u8 tag ('S' bytes, 'B' build id, 'G' type grammar) || u32 name_len || name || u32 id_len || id`
  (`tools/sensors/clang_manifest_producer.c`). Build ids are the linker's
  content hash, so no front end library is re-read per run. An image
  without a build id, a platform without `dl_iterate_phdr`, or no type
  grammar leaves the digest zero: the manifest is valid, and no consumer
  narrows with it.
- **Darwin.** On Mach-O the digest hashes the bytes of each image actually
  selected (the sensor and the libclang it loaded): the file and its
  read-only mapped segments, bound to the backing vnode and revalidated
  before and after the parse, so a replaced file cannot be hashed in place
  of the mapped one; the facts emitter refuses rather than write a zero
  digest (see "Darwin producer identity" below). An `LC_UUID` alone is not
  accepted as an image identity: a link can pin or choose it (this
  repository's own Mach-O fixture builds pin one), so it does not bind the
  bytes.

### The producer: the libclang sensor

`build/bin/z23-clang-manifest emit --facts` is the only producer of facts
manifests. It reads the front end through the libclang C API and hands every
observation to a compiler-API-free C23 core (`tools/sensors/clang_manifest_core.h`
and its `.c` siblings), which alone spells paths, probes include slots,
replays `__has_include` and encodes every record.

The sensor is a **second parse**, not part of the compile. Its measured cost
is in the benchmark above: 1.2–1.6× a stock `clang -fsyntax-only` of the same
TU (42–176 ms p50 on the three measured TUs), about 0.5–0.6× the real gcc dev
compile of a mid or large TU, and 2× on a tiny one, where process and
libclang startup dominate. It never replaces the compile, so every manifest
adds that latency. It never changes an object either, because it writes none.

`make clang-facts` runs the sensor over every TU of one component
(`CLANG_FACTS_COMPONENT`, default `engine/modules/hotswap`) with each TU's
own dev object compile, writing `build/clang-facts/<src>.zsm`: `--cc` is the
object's compiler (`$(CC)` without its compile-cache wrapper),
`--toolchain-id` is `$(BUILD_COMPILER_ID)` (omitted, so the compiler is
unknown, when the parse fingerprinted none), and the argv after `--` is the
object's `$(DEV_COMPILE_CFLAGS)` as its target sees it, plus
`$(ZCL_TU_RANDOM_SEED)`. The hot directories' `-O2` reaches the object
and the manifest from one assignment (`DEV_HOT_SRC_DIRS`); the
`semantic_manifest` group, which needs only `make` and so runs where the
sensor is not built, dry-runs both rules and requires equal compiler and
argv for one TU of every `DEV_HOT_SRC_DIRS` directory, every dev object or
object directory the Makefile gives its own `DEV_COMPILE_CFLAGS` or `CC`
(read from `make -p`, which must list every hot directory), and ordinary
samples. The identity TU
(`platform/modules/util/src/clientversion.c`) is refused: its object also
bakes a host-local build receipt that only its own object rule may name, so
a plan that reads it has no manifest and falls back.
`CLANG_FACTS_TREE=<hex>` names the ZVCS tree the namespace probes are proved
against. The target is opt-in: nothing else depends on it, and the sensor
never enters z23, z23-dev, the test harness link or core. A manifest is
rewritten when its source, a header of the component or the sensor changes,
and when its compile does: the rule keeps two stamps, recomputed on every
run and replaced only when their bytes change. `build/clang-facts/<src>.argv`
holds the TU's sensor arguments (compiler, toolchain identity and flags, so
a `ZCL_DEV_HOT_OPT` or `CFLAGS` change re-senses every TU it reaches), and
`build/clang-facts/.object-cc` the object compiler's IDENTITY text
(`z23-clang-manifest object-cc`, so a new compiler, or new shared objects
under an unchanged driver, re-senses every TU). The `semantic_sensor` group
runs the rule twice unchanged (no re-sense), then with another hot
optimizer and another toolchain identity (each re-senses). The stamps are
the re-sense trigger, not a check: the planner does not compare an after
manifest's IDENTITY with the current compile.
The planner binds every after manifest to the tree it plans against (rule 9
below), so a dependency the target misses can only cause a fallback.

Known limits:

- An ignored (nonexistent) search dir is recorded in IDENTITY but not
  snapshot-probed.
- The canonical type spellings are clang's (see "What the libclang sensor
  does and does not observe").

**Second entries.** An `alias`, `weakref` or `ifunc` attribute, or an asm
label, gives a body a second entry the facts would otherwise not name. The
sensor records each as an ADDRESS ref to the target: the file-scope
definition of that spelling, or both `f:` and `v:` of the name when none is
visible. An asm label also takes its own definition's address. The
consumer's `address-taken` rule then refuses to narrow a changed target.

**Attributes that name a function.** `cleanup(f)` on a local, and any
other attribute whose argument names a function, makes the compile call or
pair that function from the declaration's owner where no expression names
it. The sensor tokenizes each attribute libclang leaves unexposed and
records a CALL ref from the owner (the enclosing function, or the declared
function or variable) to every identifier argument that names a file-scope
function, with an external-call UNKNOWN when that function is external. An
identifier argument that names nothing visible is an UNRESOLVED UNKNOWN,
unless the attribute is one whose arguments never name a function
(`format`, `access`, `aligned`, `section` and the like). An attribute clang
does not know is dropped by the front end with no cursor, so the sensor
cannot see it; gcc's `malloc(f)` form is a clang error, so such a TU gets
no manifest and its plan falls back.

There is no in-compile clang plugin: it would be C++ against clang's unstable
plugin API, and Z23 keeps compiled code to C23 over a compiler's C API. The
sensor's second parse is what the tree pays. A future in-compile producer must
beat that cost (a plugin measured about 10 percent of compile CPU).

### Warm session

`build/bin/z23-clang-manifest session [--verify-cold] [--no-warm]
[--max-tus N]` serves a batch of emits from one process. Each stdin line is
one request: the arguments `emit` takes, separated by TAB (a leading `emit`
field is optional). A relative `--root` is resolved against the directory
the session started in. Each request writes its manifest to its `--out`,
exactly as `emit` would, and prints one JSON line on stdout:

```
{"seq","ok","source","out","root","bytes","tu","written","verify","trust",
 "reason","sections","warm_ms","warm_parse_ms","cold_ms","bind_ms"}
```

A refused request prints `{"seq","ok":false,"source","why"}`.

**Protocol.** A line ends at LF, and trailing CRs are dropped. An empty line
ends the session: nothing after it is read. End of input ends it too, after
a last line without an LF is served as a request. Either way the session
prints one summary line (`requests`, `refused`, `warm_written`,
`cold_written`, `verified_equal`, `mismatches`, `evicted`, `created`,
`reparsed`, `recreated`). A request line is refused whole, never truncated
or partly served, when it holds a NUL byte (`request line has a NUL byte`),
is not valid UTF-8 (`request line is not UTF-8`), or is longer than
256 × `PATH_MAX` bytes, 1 MiB on Linux (`request line too long`; the reader
holds one buffer of that size and reads an overlong line to its end without
keeping it). Every reply string is ASCII: quote, backslash, control bytes
and DEL are escaped, and every code point past ASCII is written as a `\uXXXX`
escape (a surrogate pair past U+FFFF), so a JSON decoder returns a source or
out path's exact UTF-8. A byte of a reason that is not UTF-8 (a path the tree
spells so) is written as U+FFFD. `--max-tus` takes digits only, 1 to 256; a
sign, space or trailing byte (`64x`) is a usage error (exit 2). The exit
status is 3 if any request was refused, else 0. There is no daemon, socket
or service: the warm state lives
only as long as the process. The source is
`tools/sensors/clang_manifest_session.c`; the compiler-API-free checks are
in `tools/sensors/clang_manifest_warm.c`.

The shadow-directory reader counts a name only after its duplication succeeds
(`cm_sdir_add` in `tools/sensors/clang_manifest_warm.c`). If duplication fails,
the reader refuses the scan and sorts only the names already retained. The
`semantic_manifest` directory regression refuses the second duplication and
checks the production reader's sorting input and retained count.

**What stays warm.** Only the `CXTranslationUnit` and its preamble. The
session parses with `DetailedPreprocessingRecord | PrecompiledPreamble |
CreatePreambleOnFirstParse`, keeps preambles in memory where libclang has
`StorePreamblesInMemory` (not Apple's), and reparses with the main file
handed in as an unsaved buffer. The buffer holds the exact bytes this emit
read and hashed. Every extraction starts from a fresh `cm_state`: no cursor,
source location or file handle survives an emit. The table holds up to
`--max-tus` TUs (default 64, at most 256) and disposes the least recently
used one when it is full.

**When a TU is recreated** (disposed and parsed again), with the `reason`
the reply carries:

| Reason | Trigger |
|---|---|
| `first-parse`, `no-live-tu` | no TU yet, or the last one was dropped |
| `argv-untrackable` | checked on every emit, even with argv unchanged: an argument starts with `@` (a response file) or `-fmodule`, or starts `--config`, `-fimplicit-module-maps`, `-fbuiltin-module-map` or `-fcxx-modules`. No manifest hashes a response or config file, and an implicit module map can pull in headers the file set never names, so such a TU is never reparsed |
| `argv-changed` | the request's argv, and so flags, C mode, target, sysroot or resource dir, differs |
| `producer-changed`, `producer-unnamed` | the producer digest (sensor bytes, libclang build ids, type grammar), recomputed on every emit, moved or cannot be named |
| `file-changed <path>` | a non-main file the accepted manifest read no longer has its SHA3; this also catches an edit that keeps size and mtime, which libclang's own preamble check misses |
| `lookup-unbound <name>` | the accepted manifest has a lookup with no negative claim (`include_next`, computed, absolute, or a conditional lookup the text scan cannot replay: see `0 none` above, for example `__has_embed` or `#embed`), which cannot be re-checked |
| `include-shadow-appeared <dir>/<name>`, `include-shadow-vanished ...` | the shadow candidates changed (below) |
| `warm-unusable: <why>` | a reparse failed a post-check: `main file bytes differ`, `preamble-file-differs <path>`, `identity-moved`, `lookup-moved <name>`, or its own manifest failed the binding checks (`file-changed <path>`, `lookup-unbound <name>`, `include-shadow-appeared ...`, `include-shadow-vanished ...`); the reparse is discarded and retried once as a fresh parse |

**Shadow candidates.** A reused preamble keeps how every include inside it
resolved, including includes made inside system headers, which no LOOKUPS
record covers. libclang revalidates the files it read, not the search slots
it skipped. So a header copied into an earlier `-I` dir under a name a
system header includes would leave a warm reparse stale while a cold parse read
the copy (for example glibc bits/wordsize.h under `<stdint.h>`). The candidates are: for every non-main file of the manifest,
under every search dir (quote, then angled) that holds it, each earlier
search dir that now holds the same relative name, or that no longer exists.
The list is taken right after the parse that builds a preamble, before that
parse's cold check, and every later reparse needs the same list. A header
that appears between the parse and the listing therefore makes the cold
check fail instead of hiding in the baseline. Each dir is read with
`readdir` once per check, and deeper names are checked with `stat`.

**Verified and qualified.** A warm manifest is written only when it is
*verified* or *qualified*:

- *Verified*: a cold parse in the same process (`cm_cold_front`, the same
  code path `emit` runs) produced the byte-identical manifest. The first
  emit after a TU is created or recreated is always verified this way, and
  it writes the cold bytes. `--verify-cold` verifies every emit.
- *Qualified*: a reparse of a TU that has been verified since it was
  created, whose pre-checks passed (producer, argv, file SHA3s, shadow
  candidates, no unbound lookup) and whose manifest passed the post-checks.
  The post-checks are: the main file's FILES digest equals the SHA3 of the
  unsaved buffer; every non-main file both manifests read has the same
  digest; IDENTITY is equal; and every LOOKUPS record whose key (includer,
  spelled, form, kind) the accepted manifest also has is byte-identical. The
  warm extraction probes each slot below a hit with a fresh `stat`, so a
  header newly beside the includer, a slot that went away, or a moved hit
  changes that record. Then the reparse's own manifest is bound exactly as
  the next emit's pre-checks would bind it, because no cold parse checks
  it: every non-main file it read still has the SHA3 it records, it made no
  lookup without a negative claim, and its shadow candidates equal the TU's
  baseline. This catches a file or shadow that moved after the pre-checks
  ran, and anything only this reparse read (an include or a computed
  include added below the preamble).

**Trust in the reply.** Every successful reply carries `"trust"`, the
session's statement of what the written bytes rest on:

| `trust` | `written` | `verify` | The bytes written |
|---|---|---|---|
| `verified` | `cold` | `equal` | the cold front end's, and a warm parse of this same emit produced the identical bytes |
| `cold` | `cold` | `skipped` or `mismatch` | the cold front end's; no warm result matched them this emit (none was tried, it was unusable, or it differed) |
| `qualified` | `warm` | `skipped` | a warm reparse's, used on the pre- and post-checks above alone, with no cold parse this emit |

A `qualified` manifest is **advisory only**. A consumer may use it to narrow
work (an impact plan's closure, which files to look at first), but must
never treat it as equal to a cold emit where the result needs proof, for
example to publish a proof receipt or to accept a reuse: for that, emit cold
or run the session with `--verify-cold`, where every reply is `verified` or
`cold`. The label lives only in the reply line, a signal of this session
run: the manifest bytes and format carry no trust label, and a `.zsm` file
alone does not say how it was produced.

On a mismatch the cold bytes are written, never the warm ones. The reply
reports `"verify":"mismatch"` and the changed sections, stderr says so, and
warm reuse stays off for that TU (`"tu":"none"`, `"reason":"warm-disabled"`)
while the TU keeps its table slot. The disabled flag lives in that slot. When
the table is full, the least recently used slot is evicted, a disabled one
included; a later request for the same source then creates a new TU with
warm reuse on, and like every new TU its first emit is verified against the
cold oracle again. So a disabled TU stays cold for the rest of the session
only while the session serves no more distinct TUs than `--max-tus`.
`--no-warm` makes every emit cold.

**Fault flag.** `ZCL_CLANG_MANIFEST_INJECT_WARM_MISMATCH=1` flips the last
byte of every warm manifest before it is used. It is registered in
`engine/composition/flags.def`, and the `semantic_sensor` group uses it to
prove that the oracle catches a bad warm manifest and never writes it.

**libclang behaviour the session works around.** With a preamble,
`clang_getInclusions` omits files included after the preamble (for example
`hotswap_loader.c`'s late `#include <dlfcn.h>`). It also reports such a file
at depth 0, the main file's depth. The sensor therefore names the main file
by identity (`clang_getFile` of the source), and closes the file table with
`clang_findIncludesInFile` over every file read. Every front-end instance
prints its own `-v` search list block, so the sensor parses the last one.

**Cost** (12 `engine/modules/hotswap` TUs, dev compile argv, `--facts`):

- A qualified reparse after a body edit costs about 33 ms per request end to
  end against about 60 ms per cold process (1.8 times faster). Roughly 23 ms
  of the saving is process start-up, libclang loading and file writing; about
  11 ms is the parse. Extraction and the post-checks (about 15.6 ms) do not
  change, and the pre-checks cost about 3.7 ms per TU.
- A new or recreated TU costs about 101 ms per request: a warm emit that
  builds the preamble plus the mandatory cold check. That is about 41 ms more
  than a cold process, so a TU pays back after its second qualified reparse. A
  header edit recreates exactly the TUs that read the header; that round
  roughly matches cold.
- `--verify-cold` is an oracle mode: every emit pays a warm and a cold parse.
- A table smaller than the working set evicts every TU before its next
  request, so every request pays the first-parse price (about 1.65 times
  cold). The default of 64 TUs is sized for a module-sized batch; a hotswap TU
  costs about 4 MB resident with its preamble in memory.

**Cold oracle.**

- Warm manifests are byte-identical to a separate cold process's manifest of the
  same input, including under `--verify-cold`. Plain manifests match a sensor
  built without the warm session; facts manifests differ only in the FACTS
  producer digest, which names the sensor binary.
- The `semantic_sensor` group proves it live on a fixture tree through these
  edits: a body edit, a main-file macro edit, a header macro edit, a header
  edit that keeps size and mtime, a header layout edit, a header shadowing
  in an earlier `-I` dir, a header shadowing beside the includer, a header
  shadowing one a system header includes, a flag change, and a body edit
  after it. Each one checks the reported TU reuse, and each written manifest
  is compared byte for byte with a cold process. The group then runs the
  qualified mode and the fault flag. A second fixture adds a `cleanup(f)`
  local, an `alias("x")` definition and an asm label declared in a header
  inside the preamble; after a body edit, an alias retarget and a label
  edit, each written manifest carries the attribute and alias refs a cold
  process derives, verified and qualified.
- Mutants were checked against the group:
  - dropping the file pre-check is caught (`preamble-file-differs`);
  - dropping the lookup post-check turns the beside-the-includer shadow into
    an oracle mismatch;
  - dropping the shadow candidates fails both the verified case (TU
    reparsed, not recreated) and the qualified case.

**Known limits** (`--verify-cold` covers each):

- Includes that a system header makes by a name no manifest file carries
  are not listed (a system header's `__has_include` is: see the miss
  evidence above). A quoted include from a system header's own directory is
  not listed either. Both need a write into a system directory or an
  unrelated new name in a search dir.
- A header edited between the pre-check and the reparse, with its size and
  mtime restored, is not seen. The front end would reuse the preamble, and
  the FILES post-check hashes what the front end read.
- A file read through `#embed` inside the preamble is not in FILES, so it
  is not bound.
- The environment is fixed for the life of the process. The IDENTITY env
  allowlist is read from it, and the cold oracle runs under the same
  environment.
- USRs are not used: every identity is still the core's canonical id, so
  the bytes cannot change.
- The Darwin paths (`producer_before`, no `StorePreamblesInMemory`) compile
  in the code but were neither built nor measured on a Mac for this change.
### Facts revision 2

Facts revision 2 (`zcl.semantic_facts.v2`) adds the `@scope` and `@cond`
pseudo-sites, which record file-scope and conditional macro uses, and names
an anonymous member's nearest named record. Readers accept both extension
names and report the revision (`vcs_semantic_facts_v1_info`).
`vcs_semantic_manifest_v1_each` hands a reader every record with its exact
encoded bytes, so a reader can digest records without re-encoding them. No
v1 byte changes.

### Facts revision 3

Facts revision 3 (`zcl.semantic_facts.v3`) adds the `@assert:<path>`
pseudo-site. The sensor walks each `static_assert` written in `<path>`
outside every function definition, at file scope and in a struct or
union's member list (an unnamed member record's included), as that site:
each entity its condition names (types, `sizeof` and `offsetof` operands,
enumerators, functions, variables) is a ref of it, and each macro expanded
inside it is a MACRO ref to `m:<defpath>:<name>`. When a macro writes the
assertion (`CHECK(x)`), the site covers that invocation's arguments too. A
block-scope assertion stays part of its function's refs. An assertion emits
no bytes, but when what it reads changes it can stop holding, and every
reader of `<path>` then stops compiling. A revision-2 manifest makes no
such claim, so the consumer cannot tell from one that no assertion reads a
change. Readers accept all three extension names.

### Facts revision 4

Facts revision 4 (`zcl.semantic_facts.v4`) changes no record layout. It
names a producer whose text scan replays two more conditional lookups
into `replayed_stat` LOOKUPS and PROBES records: a `__has_include` whose
operand is an object-like repo macro that expands to one plain string
literal, and a `__has_include_next` from the slot after the one its file
was entered through (see the miss evidence above). An earlier revision
records both as `none`. Readers accept all four extension names; a
revision-3 manifest stays valid, and the consumer treats its unbound
records as it treats any `none` record, which can only widen.

Revision 4 also records probes the text scan once could not see: one a `-D` value writes,
one in any `#define` body, a system header's too (each unbound, as
the macro is evaluated where it expands); one after a pre-C23 `'`, which
opens a character literal rather than a digit separator; one a trigraph
`??/` splices in an ISO mode before C23; and one after a comment between
a probe word and a header name. `tests/harness/src/semantic_sensor_probe.c`
checks each record. It also
records a system header's own conditionals (a
plain angled search there starts at the repo's `-I` dirs), and treats a
probe word only tested by an `#ifdef`-like directive or a plain `defined`
test as no lookup. The sensor
now refuses every `-X` pass-through but `-Xlinker`, `-Wp,`, front-end
plugins,
`-fms-compatibility` and an MSVC target instead of
scanning under rules it cannot read; the same test file checks each
refusal; each spelling but the separate `-Xclang` and `-Xpreprocessor`
forms was accepted before. It also reads the trigraph and digit separator
rules from the front end's own parse of a probe file rather than from
argv, where a value of `-I`, `-iquote` or `-Xlinker` spelled like `-std`
misled it (each case is in the same test file). The probe measures by
lexing and typing alone: a first version read `__STDC_VERSION__` and
`sizeof`, which `-D__STDC_VERSION__=202311L`, `-U__STDC_VERSION__`, an
`-include` file that undefines it, and `-Dsizeof(x)=2` each made lie.

Four review rounds each found a gap between the scan's own lexer and
clang's (trigraphs, digit separators, macros that lie about the language,
raw strings), so the scan no longer lexes: which words are live comes
from `clang_tokenize` under the TU's language options
(`tools/sensors/clang_manifest_tokens.c`), and the digit separator
measurement is gone. A probe after a raw string holding `" /*` (under
`-std=gnu23`, with no `-std`, with `-fraw-string-literals`, with each
prefix, and across lines) and one after a `#warning` line holding `/*`
recorded nothing before; each is a case in the same test file.

Six review rounds in a row found a way for the scan to hide a live
probe, so it now records every occurrence the floor above finds unless
clang's tokens show it is none. Ten cases recorded nothing before, and
each is in the same test file: a probe after a skipped `#error`, `%:error`
or `#warning` line holding `/*` and after a skipped `#include <a/*>`
(the header name and text rules applied inside skipped groups, which clang
raw-lexes, so `/*` opened a comment that hid live lines); an `#embed` after
such a skipped line; a word split by a splice with a form feed before its
newline, by a lone `\r`, or by `\n\r`; `CAT(__has_, include)("opt.h")`;
and a `__has_embed` after `HI(<nope.h/*>)` where `HI` aliases
`__has_include`. A lone `__has_embed` is the control case. Every
conditional record with no claim now reaches every changed path. With
every occurrence in a skipped group recorded, 4 TUs of a 50-TU sample of
the repository gained one (the `#ifdef __has_include` inside the skipped
`#ifdef __USE_GNU` group of glibc's unistd_ext header); dropping the
skipped groups, as argued above, brings that to 0 of 50, and the spawn TU's
LOOKUPS are unchanged. Three more cases pin the range boundary: an
`#elif __has_include` right after a skipped group (inside clang's merged
range when it is false), a probe on the line after the `#else` that ends
one, and a probe after a skipped group nested in a live one. The session
test's spellings that cannot be replayed moved from `#if 0` into live
lines or `#define` bodies, and a skipped group holding them now keeps its
TU warm.

Review round 7 found two ways the skipped-group drop lost a live probe,
each now a case in the probe test file: a header the TU includes twice
whose first entry skips the probe's group and whose second does not (the
ranges came from one entry and were applied to both), and an `#if` or a
merged-range `#elif` whose condition a block comment carries past the
line's first newline (the kept line ended at that newline). Entries are
counted from inclusion directives rather than `clang_getInclusions`,
which under a preamble misses a file entered again after it. The sample
stays at 0 of 50 and the spawn TU's LOOKUPS are unchanged.

### Darwin producer identity

The sensor records a producer digest on Mach-O: each selected dyld image's file and its read-only mapped
segments, bound to the backing vnode and revalidated before and after the
parse; the facts emitter reuses that pre-parse digest and refuses rather
than write a zero one. The link probe that builds the sensor without
`clang_getTypePrettyPrinted` is provided too. On Linux
the records are byte-identical. The `__APPLE__` branches are verified on the
Mac only.

### Fuzzing the reader

`tools/fuzz/fuzz_semantic_manifest.c` (a `FUZZ_TARGETS` entry, built with
libFuzzer under ASan and UBSan) drives every reader entry point:
validate, both roots, `vcs_semantic_section_v1_each`,
`vcs_semantic_manifest_v1_each`, `vcs_semantic_absent_v1_each`,
`vcs_semantic_facts_v1_info` and the dump. It rebuilds each accepted input
from its decoded records and requires byte-identical output and an equal
root, because the canonical form admits exactly one encoding. The dump must
be deterministic and free of NUL bytes, and the facts info must agree with
the sections present. Seeds are under
`tests/harness/fuzz_seeds/semantic_manifest/`; they include facts
revision 1 manifests, which the reader still accepts.

The first seed found undefined behavior: the builder sorted every section,
including an empty one whose record array was still NULL. `finish()` now
skips the sort for an empty list, and a `semantic_manifest` case leaves
seven sections empty and requires each to read back as zero records.

### Windows acceptance

`semantic_manifest` is a row in
`platform/modules/platform/tests/windows_acceptance.mk`. Its program,
`tests/harness/src/semantic_manifest_windows_acceptance.c`, is strict C23
and calls no Windows API. It builds the golden vector and pins its length,
root and hint root. It strict-decodes every fixture under
`tests/fixtures/semantic_manifest/` and `tests/fixtures/semantic_facts/`,
which `tests/harness/src/semantic_manifest_windows_fixtures.h` embeds at
compile time, and folds each fixture's name, root and hint root into one
SHA3 ledger digest. It also checks the decoder's refusals. The
`semantic_manifest` group case `smt_t_ledger` computes the same ledger from
the fixture files on disk and pins the same digest. The header is
generated with `od -An -v -tu1 -w16` per fixture, in `LC_ALL=C ls` order;
regenerate it and both pinned digests whenever a fixture file changes.
`make windows-portability-acceptance` cross-links the program. Running the
`.exe` on Windows is not observed on the Linux host.

## The facts consumer

Two consumers read these manifests to narrow the feedback closure of
`dev.change.plan`: the `.c` path, and the declaration-identity consumer for a
change set that holds a header. Neither makes a plan proof-admissible.

### Facts-narrowed change closure

`dev.change.plan` takes an optional `"facts"` directory. For each changed
file it reads `<facts>/<file>.before.zsm`, `<file>.after.zsm` and
`<file>.before` (the before source); the after source is the working tree.
`tools/dev/devloop_facts.c` then decides, in this order, and the first failed
rule names the fallback to the unchanged file-seeded closure:

0. no changed file is a source compiled into the producer: the sensor's own
   sources and every repo file they include (`producer-source-changed`);
1. every changed file is a `.c` with a manifest pair (`not-c-source`,
   `no-manifest`);
2. each manifest is valid, carries facts, is complete and names its
   producer, and both name the same producer (`invalid-manifest`,
   `no-facts`, `manifest-truncated`, `producer-unknown`,
   `producer-changed`);
3. each manifest's main file is the changed file and its FILES digest is the
   SHA3 of the source bytes given (`source-mismatch`);
4. only files, functions, spans, refs, unknowns and facts differ
   (`identity-changed`, `include-resolution-changed`, `macro-changed`,
   `declaration-changed`, `layout-changed`, `enum-changed`,
   `symbols-changed`, `namespace-probes-changed`). This whole-section rule
   is the `.c` path's only: a change set with a header in it is planned by
   the declaration-identity consumer below, which taints DECLS, LAYOUTS,
   ENUMS and MACROS records per canonical id instead of refusing on any
   section difference;
5. no function was added or removed (`function-added`, `function-removed`);
6. the main file's text outside its function definitions is unchanged after
   collapsing comment and whitespace runs, with literals, splices and
   pp-numbers kept verbatim (`file-scope-changed`); and so is each
   definition's head, the text before its body where storage class,
   `__attribute__`, C23 `[[attributes]]`, return type and declarator live,
   with every whitespace run one space unless the head holds a `#`
   (`function-head-changed`): a constructor, weak or visibility attribute
   changes what the program does without touching the body's tokens;
7. every seed resolves to its FUNCTIONS record (`seed-unresolved`); no
   changed function has an UNKNOWN other than an external call, and none has
   its address taken in either manifest (`unknown-effect`, `address-taken`);
8. refs, unknowns and included files outside the changed functions are
   identical (`facts-changed-outside-seeds`);
9. the after manifest is the parse of the tree the plan runs against
   (`tools/dev/devloop_facts_bind.c`): every other file it read, repo or
   system, still has its SHA3; every include slot it saw absent is still
   absent and every ignored search dir still does not exist, so no header
   created since shadows one it used (`after-stale`); and it has no lookup
   without a negative claim, such as `include_next` or a computed include,
   which could not be re-checked (`lookup-unbound`);
10. the compile identity names an optimizer whose re-emitted code the facts
    can bound (`inline-closure-unknown` otherwise; see "Code generation"
    below), and no function the closure reaches is defined in a header,
    where every reader emits it;
11. every main-file function that expands `__LINE__`, directly or through
    a macro body, and whose lines moved or whose line bytes changed joins
    the seeds; file-scope code that expands `__LINE__`, and any use of
    `__COUNTER__`, is `position-dependent`.

When every rule holds, the seeds are the functions whose FUNCTIONS record
changed, the moved `__LINE__` users, and every main-file function the
code-generation closure adds to them on either side. The reverse-caller walk is the planner's own: `codeindex_callers` by
name, `CI_CLOSURE_DEFAULT_DEPTH` levels, the same proof-owner terminals and
the same group folding, over the index `codeindex_open` keeps current with
the tree. A caller batch that fills or the symbol cap is `closure-bounded`,
which also falls back. A comment-only edit has no seeds and reaches only the
changed file.

**A narrowed plan is feedback only.** Its SEMANTIC dimension is INCOMPLETE
with reason `facts-narrowed`, so `zcl_devloop_plan_proof_admissible` refuses
it. Token or AST similarity never authorizes proof reuse. The plan's
`"facts"` object names the verdict, the reason, the seeds and the number of
files reached.

Positions are bound: by rule 11 on the `.c` path, and by the header path's
position and code-moved rules below. The address of an external function
taken in a TU with no manifest here is caught only through the include
graph: every reader of the header that declares a seed must have a
manifest, and when the graph cannot list the readers (truncated or
unavailable) the plan falls back (`indirect-unknown`, or the universe's
`include-graph-*` reason). A TU without a manifest that takes the address
through its own `extern` declaration, without including the declaring
header, is outside that check; the file-seeded closure has the same blind
spot.

### Code generation

The facts name what the source says, not what the compiler emits. A changed
function can change the bytes of others: a caller that inlines it, an
internal callee that takes its constants, any function that reads a static
variable whose read-only or addressability summary changed. Rule 10 bounds
this by the optimizer the IDENTITY record names
(`tools/dev/devloop_facts_codegen.c`):

| model | when the identity holds | what joins the seeds |
|---|---|---|
| unbounded | `-O2`, `-O3`, `-O4`, `-Os`, `-Oz`, `-Ofast`, `-flto`, `-fwhole-program`, an `-fipa-*` clone, merge or propagation flag, `-finline-small-functions`, `-finline-functions`, or profile feedback, anywhere in the record | nothing: `inline-closure-unknown` |
| callers | no `-O`, or `-O0` | the transitive callers of a changed function (only `always_inline` bodies move) |
| component | `-O1`, `-O`, `-Og` | every function that names a member by call, address or variable reference, and every internal function or internal variable a member names (a header's static too: its reader may fold the value it stores), to a fixed point |

The component model covers inlining and callee summaries flowing up, and
constant propagation, dead-argument elimination and coldness flowing down
into internal callees, as gcc and clang do at `-O1`. It is an assumption
about the compiler, not a fact the manifest records: IDENTITY names the
object compiler's bytes (so a change of compiler is drift), not how much
interprocedural work its `-O1` does, so a compiler whose `-O1` does more
must be added to the unbounded list. The dev build is
`-Og` without `-ffunction-sections`.

### Declaration-identity consumer

A change set that holds a header (or any file that is not a `.c`) is planned
by `tools/dev/devloop_facts_consumer.c` and its parts (`_tu.c`,
`_obligations.c`, `_walk.c`, `_hdr.c`, and the index in
`devloop_facts_index.c`, `_graph.c`, `_codegen.c`). It reads every
`<tu>.after.zsm` under the facts directory (the candidates) with its
`.before.zsm`, and decides each TU from its own pair.

**The index.** One manifest becomes a graph of canonical ids. Every record
of an entity is attached to its id: MACROS to `m:<path>:<name>` and the
name group `m:<name>`, LAYOUTS to `s:`/`u:<path>:<name>`, ENUMS to the
enumerator and its enum, DECLS and FUNCTIONS to `f:`/`v:<name>` or the
path-qualified id, REFS and UNKNOWNS to their site, including the revision-2
pseudo-sites `@scope:<path>` (a macro expanded outside any function) and
`@cond:<path>` (an identifier a conditional directive tests), and the
revision-3 `@assert:<path>` (what a `static_assert` outside a function
reads), which is never a root. Edges are
every REFS record, a tag named in a record's canonical type text, a typedef
to its tag, a macro to the name group of every identifier in its body, and
a bare tag id `s:N` (how REFS and SYMBOLS name a tag the sensor gives
external linkage) to the path-qualified `s:<path>:N` its DECLS and LAYOUTS
rows use. Each entity has two digests: one over its records outside the
main file (a header's view of it), one over all of them.

**The universe.** A candidate that read a changed file (in either
manifest) is a member, and so is one whose LOOKUPS hit a changed path or
whose PROBES claim a changed path absent: a `__has_include` of a header
created or deleted reads no file on the side where it is absent, and gcc's
depfiles omit such a probe altogether.
A lookup with no negative claim (`0 none`) may now resolve to any
created or deleted path, and an `#embed` or `__has_embed` also weighs or
reads what it finds, so such a lookup makes its candidate a member of
every change that creates or deletes a path (every change at all, for
the embed spellings) and, unless another rule already affects the TU as
more than a compile, `lookup-unbound` (`fxc_unbound_verdict`,
`tools/dev/devloop_facts_tu.c`). A manifest before facts revision 3, on
either side, counts as such a lookup: its producer recorded no
conditional lookup, so nothing bounds the ones its TU made. A changed
path is created or deleted when the tree has nothing there or the facts
directory holds no `<path>.before` text of it.
The members are cross-checked against the depfile
graph (`codeindex_reverse_includes`): a TU the graph says reads a changed
file but no manifest pair describes is affected (`facts-missing`, or
`include-resolution-change` when it has an after manifest). A graph that
is truncated or unavailable leaves the universe incomplete, and so does a
deleted path, which the graph refuses (`include_input_missing`,
`cognition/modules/codeindex/src/codeindex_impact.c`) and whose
after-state depfiles no longer name it: its old readers are unknown. (A
producer could name them: a later lane may attest the before readers
with a marker bound to the change, carrying the attested path set and the
SHA3-256 of every before manifest, with every `.before` that has no
`.after` read as `facts-missing`. An unbound marker is no evidence, since
gcc's depfiles omit a probe.) A candidate
that read no changed file is checked too: a changed IDENTITY, include
resolution, file set or unrequested file read, or a missing before side,
affects it whole and makes the universe incomplete. A changed file that is
neither C text (`.c`, `.h`) nor prose (`.md`, `docs/`) and that no
manifest read, such as a makefile or a flag file, affects every candidate
(`build-input-changed`) when make can change an object with it (see
"Build inputs make reads" below); otherwise it compiles nothing. An
unreadable candidate manifest leaves the universe incomplete
(`facts-invalid`).

**Search-dir deltas** (`tools/dev/devloop_facts_sdir.c`). When a pair's
IDENTITY records differ only in the `-I`, `-iquote`, `-isystem` and
`-idirafter` options of argv and in the quote, angled and ignored dir
lists, the consumer replays both sides' LOOKUPS instead of widening: each
lookup's key (includer, spelling, form, kind), its answer, its hit and the
dir its hit slot names under that side's lists must match, and the file
set must be the same. Then the TU is decided as with an equal identity; a
TU whose lookups moved is `search-dir-resolution-change`, affected whole,
and a TU that read no changed file joins the plan alone (its file-seeded
closure) rather than making the change universal. Any search-dir change
leaves the universe incomplete (`search-dir-delta`), so a plan it narrows
is feedback, never proof. Nothing is proved, and the TU stays
`identity-drift`, when any other argv word, the compiler, target, resource
dir, main file or environment differs; when argv carries a forced include,
module, VFS overlay or pass-through option (`-include`, `-imacros`,
`-fmodule*`, `-fimplicit-module-maps`, `-ivfsoverlay`, `-Xclang`,
`-Xpreprocessor`, `-Wp,`); when a search-dir value is not spelled exactly
as its canonical list entry (a symlink, `./` or `..` changes the opened
names `__FILE__` expands to); when a lookup makes no claim
(`include_next`, a computed or unbound spelling, `#embed`) or its replay
saw another file first; when a file is read that no claimed lookup
reached; or when the TU reads a system header, whose own includes the
sensor does not record.

**Each member**, in order; the first rule that fires is its reason:

| reason | affected | broadened | what fired |
|---|---|---|---|
| `truncated`, `producer-unknown`, `producer-mismatch` | yes | yes | the evidence cannot be trusted |
| `identity-drift` | yes | yes | compiler, target, flags or environment changed, or either side's IDENTITY names no known object compiler (`object-cc unknown`, or no `object-cc` at all) |
| `include-resolution-change` | yes | yes | LOOKUPS, PROBES or the file set changed |
| `search-dir-resolution-change` | yes | yes | only search dirs changed, and a lookup, probe answer or the file set moved under them |
| `source-changed` | yes | yes | the TU's own main file changed |
| `position-dependent` | yes | yes | the TU expands `__COUNTER__` on either side: its values count every expansion before them in the TU, so any edit above one may renumber it |
| `macro-unattributed` | yes | yes | a revision-1 manifest cannot attribute a macro change |
| `unrequested-change` | yes | yes | a file it read changed that the request does not name |
| `after-stale` and the rule-9 reasons | yes | yes | the after manifest is not the parse of this tree |
| `macro-conditional`, `header-unattributed`, `position-unknown` | yes | yes | a conditional or other directive of a changed header changed, a changed text names no id the header declares, or the header's positions could not be read |
| `interface`, `macro-conditional`, `header-text` | yes | no | a dirty id (by digest, by `@cond` site, by a changed text chunk naming it) reaches a root: a main-file entity, an `@scope`/`@cond` site, a function or variable a header defines; a root that is not a main-file function broadens the TU, except a function another file defines with internal linkage (a header's `static inline`), which is the TU's own copy and seeds instead |
| `code-moved`, `position` | yes | no | a header function's code moved (a `__LINE__` it expands moves too); a header declaration the debug info records moved |
| `interface-changed`, `implementation-changed` | yes | yes | the TU's interface or implementation root differs although no reached id is dirty |
| `lookup-unbound` | yes | yes | none of the above, while a lookup of either side makes no negative claim (`0 none`) and the change creates or deletes a path, or changes any path while the lookup is an `#embed` or `__has_embed`; or either side is a manifest before facts revision 3 and the change creates or deletes a path: nothing bounds which file it now finds or reads |
| `static-assert` | yes, compile only | no | none of the above, while an `@assert:<path>` site of the TU (a `static_assert` of its own file scope, or of a header it reads) reaches a dirty id, or expands `__LINE__` while `<path>` changed: the assertion may stop holding and the TU stop compiling, though its object cannot change. The TU is in the compile set with no seed and no test obligation |
| `static-assert-unattributed` | yes, compile only | no | none of the above, while either side is a manifest before facts revision 3, which records no `static_assert`: nothing rules out an assertion that reads the change |
| `debug-position` | yes, compile only | no | none of the above, while the compile writes debug information (`-g1` and above, or any `-g` spelling it does not know; the last `-g` option decides, but a bare `-g`, `-ggdb` or `-gdwarf-N` keeps a higher level already set) and a file it read changed: clang's DWARF 5 line tables (its default since clang 14) record the MD5 of every file in the TU's file table, so any byte of such a file changes the object, a comment that keeps the line count too; `-g2` and above also record the line and column of every type, function and variable the TU uses, and `-g3` (or `-fdebug-macro`) every `#define`, and `-gembed-source` (with any level, unless `-gno-embed-source` follows) every byte of the file itself. The TU is in the compile set (`compile_only`) and adds no seed and no test obligation. Only a compile whose object compiler is known to write no checksum (gcc) and that embeds no source may narrow this, at `-g2` and above, to a changed file with a token outside comments on a moved or changed line; the identity does not name the object compiler yet, so nothing narrows it. `-g0` or no `-g` never fires it |
| `name-collision` | yes | yes | an id shares its name with a new or removed external id |
| `unaffected` | no | no | no changed id reaches its code |

An id is dirty when its digest differs between the two sides, when a
changed header text chunk names it, or when its whole-record digest differs
(a main-file entity whose records a header change re-expanded).

**Obligations.** A broadened TU contributes its whole file-seeded plan
(`tu-broadened`). For the others, the seeds are the main-file functions a
dirty id reaches, grown by the code-generation closure; a non-main
function in that closure with external linkage (a header definition every
reader emits) broadens the TU instead, and an unbounded optimizer refuses
(`inline-closure-unknown`). A function another file defines with internal
linkage, such as a header's `static inline`, is compiled by each reader as
its own copy under the id `f:<header>:<name>`: it seeds like a main-file
function, so the walk reaches its callers in every reader and a manifest
that takes its address refuses. Such a copy is also a root of its TU even
where nothing there calls it: gcc emits an unreferenced plain `static` at
`-O0`, and a `used` or `constructor` attribute, which the facts do not
record, emits it at any level. The caller walk keeps a caller only when its
manifest names the callee's canonical id. A seed whose address some
manifest takes (`address-taken`), a header-declared seed with a reader
that has no manifest or with readers the graph cannot list
(`indirect-unknown`), a walk that fills its bounds (`closure-bounded`), or
an incomplete universe restores the file-seeded plan; when the
incompleteness is a build input, an outsider's drift or an unreadable
candidate, the plan also carries `closure_universal`, the whole catalog.
The `.c` path applies the same incomplete-universe fallback. Once its rule
chain narrows, it also takes the members' seeds: a TU that `#include`s a
changed `.c` (a unity build, a test reaching its statics) compiles its
functions under the names its own manifest records, perhaps renamed by a
macro. When a member ends broadened, whichever rule broadened it, every
changed `.c` it read on either side seeds it: every function that `.c`
defines there, and every includer function that reaches one, joins the walk
on both sides, whatever the dirty flags marked. The seeding covers every
changed `.c` whose digests differ, not only the first one a rule met. A member
broadened because its own evidence cannot be trusted (`truncated`,
`producer-unknown`, `producer-mismatch`, `facts-missing`) seeds nothing
instead, and when it read a changed `.c` other than its main file the
universe is incomplete. So is it when the depfile graph says a TU reads a
changed `.c` that no manifest pair here records reading. The walk runs again
over every changed file and affected TU whenever a member adds a seed or a
TU other than a changed file is affected (a moved declaration alone changes
the includer's `-g1` bytes), and each broadened member other than a changed
file's own TU adds its file-seeded plan, as on the header path.

**The reply.** `dev.change.plan` with `"facts"` adds a `facts` object:
the verdict (`narrowed`, `reason`, `detail`, `seeds`, `seeds_total`,
`reached_files`), `consumer` (`zcl.semantic_consumer.v1`), `obligations`
(`reason`, `plain`, `plain_universal`, `facts`, and each group with its
reason, up to a byte bound), `universe` (`applied`, `complete`, `reason`,
`detail`, `total`, `affected`, `offset`, `listed`, `next_offset`),
`make_guards` (`premises`, and each missing include the root makefile
provably skips: `include`, `include_at`, `guard`, `guard_at`, `premises`,
`globbed` with each path's `found`, up to a byte bound, with
`skipped_total` and `skipped_listed`, and `plan`: the premises the whole
reading rests on with the `include` and `command` they name) and
`tus`, one page of entries from `facts_offset` (at least one per page),
each with its path, the four identities (`source`, `fact`, `interface`,
`implementation`; `action` and `artifact` null with a reason when their
evidence is absent), `affected`, `broadened`, `compile_only` (affected for
its object bytes only: no obligation), `reason` and `detail`.

### Build inputs make reads

A changed file that is neither C text nor prose, that no manifest read and
that the depfile graph lists no reader for, widens the compile set to every
candidate (`build-input-changed`) only when make can change an object with
it. `tools/dev/devloop_facts_make.c` reads the makefiles (`Makefile`, the
`*.mk` files and every file they `include`) and
`tools/dev/devloop_facts_make_reach.c` and
`tools/dev/devloop_facts_make_goal.c` decide which of their lines run
while an object is built. The path widens when:

- it is a makefile, or a directory a sub-make is pointed at: it can change
  flags or recipes;
- a line that counts names it. Every definition, directive and conditional
  counts (make reads them as it parses: flags, `$(shell cat f.args)`,
  `$(wildcard ...)` source lists), and so do the rule line and recipe of a
  reached rule and a recipe line that can run make;
- the makefile text cannot be read to its end, and UNKNOWN widens every
  path: a makefile too large to read; a reference with no closing bracket
  anywhere in the text; a conditional or `define` still open at the end of
  a file; an `include`, `-include` or `sinclude` word that is not one
  literal file (a glob, a `$(wildcard)`, a reference no single definition
  gives); a missing file a mandatory `include` names; a missing file an
  optional include names when any rule could make it (a rule a `define`
  holds, a match-anything rule `%:` or `.DEFAULT` included) unless a
  conditional provably skips its include line (below); and a
  `$(shell)`, `!=` or `$(file)` that make runs while it reads the
  makefiles and that writes a file, or names a missing optional include
  (below). A missing optional file no rule makes is read by nobody, and a
  depfile an include names (`$(OBJS:.o=.d)`, a literal `.d`) is left to
  the depfile graph.

Otherwise its compile set is empty. Its test groups stay selected: the
plain plan's path groups, the impact rules and the runtime-input handling
decide those, not this rule.

**Generated includes.** An optional include that does not exist yet but
a rule can make is made before anything else and then read, and what its
recipe writes is text no line holds: UNKNOWN, whatever the recipe is. The
recipe is not read as shell. An include and a rule target name one file
however each spells a leading `./` (`./build/gen.mk` is `build/gen.mk`,
as make reads it; a doubled `/` stays, as make keeps it). An optional
include that exists is read as a
makefile, like any other. It is taken as current: its rule remakes it
only when one of that rule's prerequisites changed, and a changed path
that reaches that rule already widens. A rule in any file make reads can
remake it this way; another rule's recipe that rewrites it as a side
effect runs only when that rule runs, which the same premise covers.

**Guarded includes.** A missing optional include is made only when make
reads its include line. `tools/dev/devloop_facts_make_include.c` reads the
conditionals of the root makefile around each one, and
`tools/dev/devloop_facts_make_value.c` what their sides expand to. The
include is skipped, and no longer UNKNOWN, when a conditional around it is
provably not taken: its `ifneq (A,B)` has both sides provably one text,
its `ifeq (A,B)` has sides that provably differ, or an earlier branch of
its `else` chain provably holds. A side expands to a bounded set of texts,
or to any text. The reading only errs toward "taken": any text is what
comes of a function it does not model (all but `strip`, `if`, `and`, `or`,
`filter`, `filter-out`, `wildcard`, `addprefix`, `addsuffix`, `notdir`,
`findstring`), a variable no line assigns (the environment's), one a line
before the directive does not surely assign (at the top level, or in every
branch of a chain that ends in a plain `else`), one with a `?=` (but
`ZCL_TARGET` and `ZCL_TOR` under `host-target-default-tor`, below), `+=`,
`!=`, `:::=` or `define`, one another file, a target-specific value, an
`undefine` or an `$(eval)` can set (the lines of a `define` an
`$(eval $(call ...))` reads, the variable of a literal `$(eval X := ...)`;
any other `$(eval)`, or a `load`, opens every variable), an automatic
variable, a substitution reference, and a `$(shell)` other than the compile
epoch's. A variable several branches assign is the union of the values of
every assignment before the directive, less those in a branch make
provably does not take: the branch's own `ifeq`/`ifneq`, read at its line
the same way, provably fails, an earlier condition of its `else` chain
provably holds, or a branch around it is not taken. A condition the
reading cannot decide keeps every assignment under it, so pruning only
drops what make never runs; what a pruning reading used is recorded with
the skip it serves. `$(wildcard)` globs the tree the plan
reads as make's glob does (a `*`, `?` or `[...]` never matches a leading
`.`); its value is the empty text when nothing matches and any text
otherwise, since how make spells a match (its sorted order, a trailing
`/`, a doubled `/`) is not read. `$(filter-out $(wildcard X),X)` is the
words of X that name no file. Otherwise `$(filter)` and `$(filter-out)`
keep or drop a word only when every pattern provably matches or misses
it: a pattern with a `\` escape, or one that holds the goals or the
epoch, makes the value any text, unless the word is itself the goals or
the epoch. A reading is not used when a `$(shell)` or `!=` command make
runs as it reads the makefiles names (as above, for a missing include)
the last component with no pattern of a path the reading globbed, or the
directories before its first pattern: that command may create a match.
The names a command holds are followed through the definitions. Make
restarts when it remakes a makefile it read (the root one or an
existing include that a rule targets, a pattern, match-anything or
`.DEFAULT` rule too, or a computed rule whose text names it; a depfile a
rule ending in `.d` or in a pattern may target; an include outside the
tree; one a built-in rule may remake, because a file beside it or a
rule target spells its stem with a suffix, `base,v`, `s.base`, or an
`RCS` or `SCCS` directory, or a pattern target may): it reads every
makefile again, after everything the first parse ran and after the
recipes that remade a makefile, which may create any path (their text, a
variable a later line sets, a script). The reading is then not used at
all. Only a command no later than the deciding
directive counts (one on a line of the root makefile at or before it, or
on any line of another makefile, its names followed through the
definitions make has read by then) when make reads the include in its
first parse alone: no makefile make reads can be remade, or the include
sits in a branch that `ifeq ($(strip $(MAKE_RESTARTS)),)` (or
`ifeq ($(MAKE_RESTARTS),)`, either side, braces too) opens while no line
can set `MAKE_RESTARTS`, which make sets to the restart count on every
parse after the first. A command on a later line of the root makefile
then runs after make read the directive. What such a command creates is
in the tree the next build reads, which that build's own plan globs. The
real Makefile remakes its view and vendor markers, so it restarts; its
Tor marker sits under the `MAKE_RESTARTS` test. Its compile epoch hashes
the link flags, Tor archives included, and
`$(eval $(call BUILD_NODE_TOOL,...))` expands rules whose recipes link
them; both come after the Tor marker's directive.
The planner reads one tree, the one the plan is for. Five named premises
carry what the text does not hold:

- `no-repair-goal`: no goal on the make command line is `vendor-ready`,
  `deploy` or `install` (the names the reading knows as repair goals), so
  a `$(filter)` of `MAKECMDGOALS` by those patterns alone is empty;
- `epoch-one-component`: the compile epoch `$(call zcl_compile_epoch,...)`
  computes with `$(shell)` is one path component other than `.` and `..`,
  or none, so `$(wildcard build/obj/epochs/$(EPOCH)/.unverified)` globs
  `build/obj/epochs/*/.unverified` and `build/obj/epochs/.unverified`;
- `build-reads-planned-tree` (every skip): the build reads the tree the
  plan globbed, and an include that exists under `build/` is current; a
  missing include is looked for nowhere but the tree (not in make's
  default include directories such as `/usr/include`, which do not hold
  a repo-relative path like `build/gen.mk`);
- `no-command-line-override` (every skip): no command-line assignment or
  `make -e` environment value overrides a variable the makefile sets with
  `=` or `:=`, and no command-line `-I dir` (`--include-dir`) gives make
  another directory in which a missing include may be found;
- `host-target-default-tor`: `ZCL_TARGET` and `ZCL_TOR` hold the value
  their `?=` line gives (`host`, `full`): no command-line, environment or
  `make -e` value sets them. It applies only to a variable whose one line
  in any makefile is a `?=` of the root makefile that make surely reads
  before the directive; one another line can set (`:=` in any branch,
  `+=`, a target-specific value), or whose `?=` comes later, is any text,
  as is every other `?=` variable. With it, a host build prunes the
  branch that sets `ZCL_CROSS_TRIPLE`, so `TOR_MISSING_ARCHIVES` is the
  host Tor archives the tree lacks, and the marker
  `build/identity/tor-inputs-ready.mk` is skipped once every one exists.
  A cross target (`ZCL_TARGET=windows-x86_64` as the default) widens:
  the reading unions the empty triple with the one a later `:=` sets,
  so it globs the host tree as well as the cross one.

A `MAKEFLAGS += -I dir` in the makefile text is a residual: make 4.4
re-reads `MAKEFLAGS` and searches that directory for a later include. The
real Makefile adds only `-r` to `MAKEFLAGS`.

Each skipped include is recorded in the plan's `facts.make_guards.skipped`
with the directive read (`guard`, `guard_at`), the premises that reading
used and every path it globbed with what that found, so a reviewer can
falsify the narrow; `facts.make_guards.premises` names every premise.

One more premise is the whole plan's, not a skip's:
`parse-commands-no-include-writes`, a command make runs as it reads the
makefiles that is not provably read-only creates or rewrites no optional
include make reads, missing or existing, and no path a skip globbed,
even through text no name check reads (a script it runs, `$(addsuffix)`,
`$$n`, `cp tpl/* build/`). Such a command is a `$(shell)` body, the same
through `$(call shell,...)`, a `!=` value, the arguments of a `$(call)`
whose function name is computed in any part or is `call` itself
(`$(call $(F),...)`, `$(call s$(H)ell,...)`, `$(call call,shell,...)`,
never read-only), or the text of an `$(eval)` that holds a reference or
`$$(` (never read-only: make expands it into lines no check reads). A
command is provably read-only when it is one simple command of `printf`,
`echo`, `cat`, `uname`, `nproc`, `pwd`, `true`, `false`, `test`,
`basename`, `dirname` or `pkg-config` with no make reference,
substitution, quote, redirection, separator, assignment or glob in its
text, and no line assigns `SHELL`, `.SHELLFLAGS` or `PATH` (plain,
`override`, `export`, `define` or target-specific; a computed name or an
`$(eval)` naming one counts), and no variable is exported (`export X`, a
bare `export`, `.EXPORT_ALL_VARIABLES`; make passes exported variables
such as `LD_PRELOAD` to `$(shell)`): with one reassigned or exported, the
named program may not be the one that runs. When an optional include
make reads (missing after the skips, or existing), or a skip resting on
a glob, is read while any other command runs, `facts.make_guards.plan`
records the premise with the first such include (missing, else skipped,
else existing; `includes` missing, `skips` resting on a glob and
`existing` in all), and the first such command as written with where it
is (`command`, `command_at`, `commands` in all).

A second plan premise is `computed-targets-not-includes`: a rule whose
targets a function computes (`$(addprefix ./,...)`, `$(foreach ...)`,
`$(subst ...)`, `$(call ID,...)`, `$(value N)`, any call) or a variable
whose value no text spells (one a `$(shell)` sets), and whose target text
as written names no missing optional include, makes none. A computed
target whose text names a missing include's path or basename, directly
or through a variable whose definition does (the name check above), is
UNKNOWN; the rest are recorded in `facts.make_guards.plan` with the first
such rule as written and where it is (`target`, `target_at`, `targets`
in all), on every plan with a missing optional include. What a function
spells only once make runs it (`$(subst Q,.,build/genQmk)`) is the
residual this premise names.

A line that is no definition, no directive and no rule its text spells,
and that holds a reference, is read the same way over its whole text:
what it expands to may be a rule (`R := build/gen.mk:` then `$(R)`,
`build/gen.mk$(C)` with `C := :`, a top-level `$(call RULE,...)`,
`$(foreach ...)`, `$(if ...)` or `$(eval ...)`). A lone `$(error)`,
`$(warning)` or `$(info)` expands to nothing and is not counted. A
computed rule also names a missing include when its target text, or a
static rule's target pattern (`$(OBJS): build/%.mk: tools/%.in`), holds a
`%` pattern matching the include, directly or through a variable whose
definition does (`OBJS := $(patsubst tools/%.in,build/%.mk,...)`). A lone
`%` counts only in the rule's own text: in a definition it is the common
`$(patsubst %,...)` or `-flag=%` argument. The real Makefile's
`$(foreach ...,$(eval $(call ...)))` and `$(eval $(call BUILD_NODE_TOOL,...))`
lines name no missing include and are recorded; its
`$(foreach d,...,$(d)/%.o ...): DEV_COMPILE_CFLAGS = ...` line is a
target-specific value and makes nothing.

The real Makefile records both on every plan: the gitignored
`contexts/commons/apps/local_gui_apps.mk` is missing in every checkout.
Of the Makefile's identity markers, `epoch-recovery-ready.mk` is skipped
when no epoch object directory holds `.unverified` (under
`epoch-one-component`). `vendor-inputs-ready.mk` and `tor-inputs-ready.mk`
stay read: `ZCL_TARGET ?= host` and `ZCL_TOR ?= full` can come from the
command line, so their cross-target archive paths are in the union and
`$(ZCL_TOR)` is any text. `view-inputs-ready.mk` stays read: its guards
test flags a goal may set. A tree that lacks one of those three widens
every build input.

**Makefile text that writes a file.** A `$(shell)` or `!=` command that
make runs while it reads the makefiles can rewrite an include before make
reads it, missing or not. `$(call shell,...)` runs its arguments the same
way, and a `$(call)` whose function name is computed in any part or is
`call` itself (`$(call $(F),...)`, `$(call s$(H)ell,...)`,
`$(call call,shell,...)`) may run any function. Any line but a recipe
line (a tab-led line a `define` holds is one too) whose `$(shell)`
(direct or through `$(call shell,...)`) or `!=` text, as written, writes
a file is UNKNOWN: outside quotes, a redirection to anything but a
descriptor (`2>&1`, `>&2`) or `/dev/null`, or a `tee`. Quote tracking
stops at a command substitution inside double quotes. So is a `$(file)`
that is not a read
(`$(file >f,...)`, `$(file >>f,...)`, an operator a reference spells,
also through `$(call file,...)`), and any computed `$(call $(F),...)`.
A plain `$(shell git ...)` or `$(shell cat f)` writes nothing and reads
as before. A parse-time command (the same forms) whose text names an
optional include may create or rewrite it: UNKNOWN. A missing include is
named by its path, its basename or its directory (a root include's
directory is in every command); an existing one by its path or basename
(`$(shell cp t build/gen.mk)` over an old `build/gen.mk`). A reference
to a variable whose definition names one counts (transitively; an
`$(eval)` line or a computed name holding it counts for every variable):
`$(shell cp t build/gen.mk)`, `X != ln -sf t build/gen.mk`,
`$(shell cp tpl/* build/)`. The names are matched as text, so a short
directory such as `d` matches more commands than create anything in it,
which only widens.

A line names a path by its literal path or basename, a directory it lives
under (with or without the trailing `/`), or a glob (`*`, `?`, `[...]`,
and `%` in make's own text; in a recipe or a `$(shell)` argument `%` is
shell text, as in `printf '%s'`). A glob also names a path under a root the
text cannot expand, so `$(CURDIR)/tools/tsan.supp` names
`tools/tsan.supp`. A variable with one path-like definition is expanded;
any other reference matches anything.

**Reached rules.** A rule is reached when a target is not a literal
`.PHONY` name (it builds a file: an object, a generated source or header, a
link), when it is the default goal (the first rule with a target that is
neither a pattern nor led by `.` without a `/`, as GNU make picks it), or
when a line that reaches spells one of its `.PHONY` names. A line reaches
when it is a directive, the prerequisites of a reached rule, a recipe line
of a reached rule that can run make, a recipe line of any rule whose make
command can also build a file goal (a sub-make builds the goals it names
whether or not its own rule runs), or the definition of a live variable. A
variable is live when a line that reaches references or spells it; make's
hooks (`.DEFAULT_GOAL`, `.EXTRA_PREREQS`, `VPATH`, `GPATH`, `MAKEFILES`,
`.LIBPATTERNS`) always are, and a computed name makes live every variable
its glob matches. A line can run make when it holds the command `make` in
any case (`$(MAKE)`, `$(MAKE_COMMAND)`, `gmake`), `$(eval)` or `$(file)`,
or references or spells a variable whose value can, closed over
references.

**Goals no text spells.** A goal word or prerequisite whose value the text
does not hold reaches every `.PHONY` name it can glob: a word computed by
a transforming call (`$(patsubst)`, `$(addprefix)`, `$(subst)`,
`$(basename)`, any call but the ones that pass their argument words
through), an automatic variable (`$@`, `$*`, `$<`, `$(@F)`) or a
substitution reference on one (`$(@:build/%.o=gen-%)`). A goal word with a
backslash or other shell escape (`gen\-a`, `printf "make gen\n" | sh`)
reaches every rule. Text piped into `sh`, `bash`, `xargs` or `eval` is a
goal position; so is a `{ ... }` or `( ... )` group whose closer is
followed by `|`, and an `echo` inside it is not quiet.

Text whose value is only tested or printed reaches nothing: `$(if)`'s
condition, `$(filter)`'s and `$(filter-out)`'s patterns, `$(foreach)`'s
variable name, and `$(error)`, `$(info)`, `$(warning)`, `$(origin)` and
`$(flavor)`. A reference there to a variable that can run make, and a call
that runs something (`$(shell)`, `$(eval)`, `$(file)`, `$(call)`,
`$(value)`), still reach. A recipe command that only prints reaches
nothing either: an `echo` or `printf` with no command substitution, not
piped into another command, redirected only to a descriptor or
`/dev/null`, and referencing only automatic variables or variables every
definition of which is plain text (no quote, separator, redirection,
command substitution, `make`, or `$(shell)`, `$(file)`, `$(eval)`,
`$(wildcard)` or `$(realpath)` call). A word led by `-`, `@` or `+`
names only a target spelled that way.

What stays conservative: a recipe line after a conditional whose branches
change the rule counts; `.ONESHELL` and `.RECIPEPREFIX` make every recipe
line count; under `.SECONDEXPANSION` a prerequisite list's escaped
references reach.

**The premise.** A `.PHONY` rule nothing reaches runs only when someone
names it as a goal, and then in full: make never treats a phony target as
up to date. What it reads is a prerequisite of no object, and what it does
through make (a recipe line that runs make, a prerequisite another rule
shares) is followed. Its other commands are opaque programs, the same
premise the text scan makes for any script a recipe runs. A hand-run goal
that rewrites a file an object reads (a `make regen` that rewrites a
generated header) changes that object when it runs, not when its script is
edited; the planner plans the edit.

**Accepted, because the editing commit is what triggers.** These can make
GNU make read a changed path for an object while the scan narrows; each is
accepted because the plan answers for the commit that edits the path, and
none of them runs as part of building that commit's objects:

- a script or program that runs make internally (a recipe runs a script
  that calls `make gen` itself): the script is an opaque program, the
  same premise the text scan makes for any script a recipe runs;
- an optional include that exists and whose rule, or another rule's
  recipe, would rewrite it: it is read as it stands, and it changes only
  when a rule that writes it runs, which a changed path reaching that rule
  already widens;
- a parse-time `$(shell)` whose command writes a file only through a
  variable's value (`$(shell cmd $(TO))` with `TO := > f`), a `$(call)`,
  or a script it runs: the check reads the command as written. Following
  the references instead makes the real Makefile UNKNOWN: its
  `zcl_compile_epoch` and `zcl_testcache_toolkey` commands expand a
  computed name (`$($(2))`), and recipe-text variables (`mvp_gate`,
  `INSTALL_C23_PRODUCTS`) hold redirections;
- a hand-run goal (`make core-seal`, a `.PHONY` rule whose sub-make names
  only other `.PHONY` goals): it runs when someone names it, and what it
  rewrites changes objects then;
- a sub-make in a rule nothing reaches that names a `.PHONY` generator
  beside the goals that build objects, on one line (`ci: ; $(MAKE) gen
  all`) or on two (`$(MAKE) gen`, then `$(MAKE) build/a.o`): that rule is
  itself a hand-run goal. Reaching every goal of every line that runs make
  instead widens the real Makefile's `tools/verify` and fixture paths
  (a `coverage` recipe runs `gcovr --filter 'tools/'`) and roughly triples the compiles
  and facts groups a replay selects.
  Following a sub-make's goals when a `.PHONY` goal's prerequisites reach
  a file rule (`$(MAKE) gen all` with `all: build/a.o`) keeps the plan narrow, but it widens a `ci` rule's `$(MAKE) coverage lint` when `lint`
  has a file prerequisite, and 15 of the real tree's scripts that only
  such goals run. A recipe after the rule line's `;` is a recipe line,
  so `ci: ; $(MAKE) gen build/a.o` reaches `gen` as the tab-led form does;
- a goal a recipe reads at run time (`$$target` from a shell loop over
  words the shell computes): its words exist only when the recipe runs;
- a variable set only on the command line or in the environment
  (`make GOAL=gen`): the text holds no definition of it;
- a depfile an include names: its prerequisite lines name only what its
  compile read, which the depfile graph answers for;
- a target spelled `$(1)` inside a `define` that `$(call)` or `$(eval)`
  instantiates with arguments no line spells;
- a missing optional include a conditional provably skips, read under
  the premise `no-repair-goal` (no command-line goal is `vendor-ready`,
  `deploy` or `install`) or `epoch-one-component` (the compile epoch
  `zcl_compile_epoch` computes with `$(shell)` is one path component, or
  none), and always under `build-reads-planned-tree` (the build reads the
  tree the plan globbed; an include that exists under `build/` is
  current) and `no-command-line-override` (a variable the root makefile
  assigns with `=` or `:=` has the value the makefile sets, as the rest
  of the scan already takes a single definition as the value): the plan
  is for the build of the edited commit's objects, and each such reading
  is recorded with its premises and the paths it globbed (Guarded
  includes, above);
- a missing optional include, or a path a skip globbed, that a
  parse-time command creates without its text naming the path, its
  basename or its directory, or an existing optional include one
  rewrites without naming its path or basename (`$(shell
  tools/mkgen.sh)` whose script writes `build/gen.mk`,
  `$(shell cp tpl/* build/)` over an old `build/gen.mk`), read under
  the named premise `parse-commands-no-include-writes` and recorded in
  `facts.make_guards.plan` (Guarded includes, above): a script is an
  opaque program, and composed text is not followed; an existing
  include's directory is not a name. Refusing every parse-time command
  but a known read-only one while an optional include is read instead
  makes every real plan UNKNOWN: the gitignored
  `contexts/commons/apps/local_gui_apps.mk` is missing in every checkout,
  and the real Makefile runs repo scripts (`dev-linker-select.sh`,
  `process-start-token.sh`) as it reads;
- a rule whose targets a function computes into a missing optional
  include's name without its text naming it (`$(subst Q,.,build/genQmk):`),
  or a reference line that expands to such a rule (`$(R)` with
  `R := $(subst Q,.,build/genQmk):`), read under the named premise
  `computed-targets-not-includes` and
  recorded in `facts.make_guards.plan`: letting every computed target
  make every missing include instead widens every real plan (the real
  Makefile computes about a hundred rule targets);
- a `MAKEFLAGS += -I dir` whose directory holds a missing include (make
  4.4 re-reads `MAKEFLAGS`); the real Makefile adds only `-r`;
- a define an `$(eval $(call NAME,...))` reads, read as its lines are
  written: a call argument that spells an `=` or a newline into one of
  them is not followed.

### Falsification

`semantic_facts` plans each edit below from a fixture pair the sensor wrote
(`tests/fixtures/semantic_facts/*.zsm`, refreshed by
`ZCL_SEMANTIC_FACTS_FIXTURE_OUT`), over a tree holding that edit.
`semantic_facts_live` writes the same pairs with the sensor at test time and
requires the same verdicts. Every fallback must be exactly the file-seeded
plan: the same groups, dimensions and rendered JSON. Only comment and
whitespace edits inside the main file may narrow, and they must leave every
fact unchanged.

| case | edit | facts evidence | verdict |
|---|---|---|---|
| (a) | `struct fx_pair` gains a field in the public header | LAYOUTS changes | `layout-changed`; the header among the changed files, first or last, is `not-c-source` |
| (a) | a header field's type changes, the layout does not | LAYOUTS changes | `layout-changed` |
| (b) | body of `FX_SCALE`, which `fx_helper` expands | MACROS changes; `fx_helper` refs `m:<header>:FX_SCALE` | `macro-changed` |
| (c) | `typedef int fx_num` becomes `long`; the header gains a prototype | DECLS changes | `declaration-changed` |
| (d) | a new `fx.h` beside the source shadows the `-I` one | LOOKUPS changes | `include-resolution-changed`; a stale after manifest (the shadow created after the parse) is `after-stale` |
| (d) | `"fx.h"` becomes `<fx.h>` | LOOKUPS changes | `include-resolution-changed` |
| (d) | a search dir is prepended to argv | IDENTITY changes | `identity-changed` |
| (e) | producer digest forged, zeroed or different before and after; a sensor one byte different | FACTS | `producer-changed`, `producer-unknown` |
| (e) | a sensor source or a file it includes is among the changed files | none needed | `producer-source-changed` |
| (g) | `__attribute__((constructor))`, `((weak))` or `((visibility("hidden")))` on a definition | FILES only; the head text changes | `function-head-changed` |
| (g) | `[[gnu::cold]]` before a definition | the attribute lies before the definition's span | `file-scope-changed` |
| (h) | a seed resolves to no FUNCTIONS record (test fault) | none | `seed-unresolved` |
| (f) | comment in a function, whitespace reflow of a function and its head | FILES and SPANS only | narrowed, seeding only `fx_where`, which expands `__LINE__` below the edit (rule 11) |
| (f) | comment in the public header | FILES only | `facts-changed-outside-seeds`: an included file's digest changed outside the changed functions, so it falls back although no fact changed (conservative) |
| (i) | `fx_other`'s body gains `0 * __COUNTER__` | FUNCTIONS; the body expands `__COUNTER__` | `position-dependent` (rule 11) |

The tests reject each of these mutants of `tools/dev/devloop_facts.c`:

| mutant | result |
|---|---|
| rule 9 always passes | stale-shadow case narrows; test fails |
| producer compare removed | a different producer narrows; test fails |
| zero-producer check removed | an unnamed producer narrows; test fails |
| section rule removed | the five section-changed cases still fall back, via rule 8; reason assertions fail |
| section rule and rule 8 removed | all six header-side cases (a to d and the header comment) narrow; test fails |
| `.c` check applied to the first changed file only | a header listed after a `.c` still falls back, as `no-manifest`; reason assertion fails |

The section rule and rule 8 are each enough on their own to stop a narrowing
after a header-side edit.

### Falsification of the consumer

`semantic_consumer` runs the consumer over a five-TU fixture tree around one
header (`tests/harness/src/semantic_consumer_fixture.c`), from manifests the
sensor wrote (`tests/fixtures/semantic_consumer/<variant>/`, refreshed by
`ZCL_SEMANTIC_CONSUMER_FIXTURE_OUT` through `semantic_consumer_live`). Each
variant names the affected TUs, each TU's reason, the obligations verdict,
the universe's completeness, whether the whole catalog is in scope, and the
seeds the compile may re-emit. `semantic_consumer_live` compiles every
variant (`-std=c23 -Og -g1`) and fails on any TU whose object changed that
the consumer left unaffected. At the fixture's `-g1` every reader of a changed
header that no other rule reaches is affected compile only (`debug-position`);
a reader that reaches only a bare prototype whose declaration moved is
compile only too (`position`; a moved declaration with a body still folds
in as `code-moved`, fully affected, since its own span carries the code).
The table names the TUs with a test obligation.
Read as facts revision 2 on either side, the gline0 reader the table leaves
unaffected compiles instead (`static-assert-unattributed`), with no test
obligation.

| variant | edit | affected TUs | obligations |
|---|---|---|---|
| layout | `struct cx_big` gains a field | its two users (one through `cx_big_t`) | narrowed |
| macro | `CX_CAP` 64 to 65 sizes `cx_big` | the same two | narrowed |
| cond | `CX_MODE`, tested in one TU's `#if` | that TU (`macro-conditional`) | narrowed |
| nested | `CX_BASE`, used only in `CX_SCALE`'s body | the TU expanding `CX_SCALE` | narrowed |
| typedef | `cx_count` becomes `long` | the TU naming it | narrowed |
| tail | a comment after every declaration | none with a test obligation; all five compile only (`debug-position`: each line table records the header's MD5) | narrowed |
| top | a comment before every declaration | the four TUs whose debug positions move (`position`); each reaches only a bare header prototype, so each joins the compile set with no test obligation | narrowed |
| signature | `cx_sum`'s parameter type, header and definer | the definer and its callers | narrowed |
| static | a static's body; another TU has a same-name static | its TU; seeds the static and its caller | narrowed |
| address | a body whose address another TU takes | its TU | `address-taken` |
| shadowed | a byte-identical header beside the TUs | all five (`include-resolution-change`) | narrowed, every TU broadened (the include graph keeps the quoted include no depfile lists as an edge, so it is complete) |
| drift | a flag every TU compiles with, and a tail comment | all five (`identity-drift`) | narrowed, every TU broadened |
| local | `CX_PAD` sizes a struct named only inside `cx_sum` | the definer; seeds `cx_sum` | narrowed |
| makefile | a makefile no compile records reading | all five (`build-input-changed`) | `build-input-changed`, whole catalog |
| tool | the makefile, and every compile gains a flag | all five (`identity-drift`) | `identity-drift`, whole catalog |
| body | `cx_sum`'s body, declared in the header, alone | the definer; seeds `cx_sum` | narrowed |
| counter | a header function gains a `__COUNTER__` (against a tree where one TU already expands it) | all five (`position-dependent`) | narrowed, every TU broadened |
| hstatic | a TU stores 6, not 5, in a header's static (against a tree that already has it) | its TU; seeds the setter and the reader | narrowed |
| alias | `cx_sum`'s body, which an `alias` names too (against a tree with the alias) | the definer | `address-taken` |
| hasinc | a header only a `__has_include` probes is created | all five (`include-resolution-change`) | narrowed, every TU broadened |
| hasdel | the same header deleted again (planned against hasinc) | all five | `include-graph-truncated` (the include graph cannot list a deleted input's readers) |
| cleanup | the body of a `cleanup` handler another function's local names (against a tree with both) | the definer; seeds the handler and the function that runs it | narrowed |
| unity | `cx_sum`'s body, which another TU compiles by `#include "cx_c.c"` under `#define cx_sum cx_e_sum` (and `cx_hook`, `cx_get`, `cx_tail` as `cx_e_hook`, `cx_e_get`, `cx_e_tail`, so nothing is defined twice) | the definer, and the includer (`header-unattributed`) | narrowed; seeds `cx_sum`, `cx_e_sum` and `cx_use_e` |
| unity_move | a comment line moves `cx_tail`'s declaration below `cx_get` in the included `cx_c.c` | the definer, and the includer (`position`); the plan reaches both | narrowed |
| unity2 | `cx_sum`'s body, and a line that moves `cx_sum2` (which returns `__LINE__`, renamed `cx_e_sum2` in the includer) | the definer, and the includer (`header-unattributed`) | narrowed; seeds `cx_sum2`, `cx_e_sum2` and `cx_e_sum` |
| ctr_unity | `cx_sum`'s body, included by a TU that also expands `__COUNTER__` | the definer, and the includer (`position-dependent`, broadened before any text rule) | narrowed; seeds `cx_sum` and `cx_e_sum` |
| unity_ab | the bodies of `cx_sum` and `cx_top_a`, both `.c` files included by one TU under renames | `cx_a.c`, `cx_c.c`, and the includer (`header-unattributed`) | narrowed; seeds `cx_e_sum` and `cx_e_top_a`: every changed `.c`, not the first |
| unity_addr | `cx_sum`'s body, while `cx_d.c` takes the address of `cx_e_hook`, which only the includer defines from `cx_c.c` | the definer, and the includer (`header-unattributed`) | falls back `address-taken` |
| unity_trunc | as `unity`, with the includer's after manifest cut by a record cap | the definer, and the includer (`truncated`) | falls back, universe incomplete `truncated` |
| unity_nobefore | as `unity`, with the includer's before manifest withheld | the definer, and the includer (`facts-missing`) | falls back, universe incomplete `facts-missing` |
| unity_nofacts | the static `cx_twice` in `cx_a.c`, which an includer with no manifest compiles | `cx_a.c`, and the includer (`facts-missing`, from the depfile graph) | falls back, universe incomplete `facts-missing` |
| unity_add | `cx_sum`'s body, and `cx_e.c` gains its `#include "cx_c.c"` (both requested) | the definer, and the includer (`include-resolution-change`) | falls back `include-resolution-changed` |
| hinl | the body of the header's `static inline cx_inl`, which `cx_b.c`'s `cx_inl_b` calls (against a tree with both), at `-O1` | all five: every reader defines its own copy (`interface`) | narrowed; seeds `cx_inl` and `cx_inl_b` |
| hinl0 | the same at `-O0`, where `cx_b.c` emits `cx_inl` out of line | all five (`interface`) | narrowed; seeds `cx_inl` and `cx_inl_b` |
| hinl_addr | the same, while `cx_d.c` returns `cx_inl`'s address | all five (`interface`) | `address-taken` |
| gline | a comment line above every declaration of the header, compiled `-g`, while `cx_e.c` names only `struct cx_small` (against a tree with that use) | the four TUs whose named declarations moved (`position`, compile only: each reaches only a bare prototype), and `cx_e.c` (`debug-position`, compile only, not reached by the walk) | narrowed |
| gline0 | the same at `-g0` | the four (`position`, compile only); `cx_e.c` unaffected | narrowed |
| lineinl | a comment line above the header's `static inline cx_lineinl`, which expands `__LINE__` (`cx_b.c` calls it) | all five: every reader's own copy's span overlaps the moved region (`code-moved`; its token hash reads the same, since it hashes `__LINE__`'s spelling, not its expansion, so span is what catches this) | narrowed; seeds `cx_lineinl` and `cx_lineinl_b` |

Each variant is a minimized reproducer of a dependency that a differential
comparison against cold clang objects found missed. Without the includer
seeding, `unity_move` and `unity2` miss `cx_e_sum` and `cx_e_top_a`, and
`unity_addr` narrows with no obligation. `unity_trunc`, `unity_nobefore` and
`unity_nofacts` pin the incompleteness rule above. `hinl0` (fuzz family F12,
`F12_header_static_inline_O0`) pins the reader's own copy seeding, and
`gline` pins a `DW_AT_decl_line` move in a reader the consumer must not call
unaffected. A narrowed
plan must reach every changed file and every affected TU but a
compile-only one, which the fold must not name (the walk may still reach it from a seed another TU adds), checked as sets through test hooks on the files the fold named and
the files the walk reached. A count check would not do: with a fold that
drops the affected TUs, `unity2` reaches 3 files where 2 are needed and
`unity_ab` 3 where 3 are needed, yet both miss `cx_e.c`, and the set check
fails them. Each is planned against its own before tree, a `p_` variant the
fixture produces but does not judge.

A `.c`-only change whose seed a header declares falls back when the depfile
graph is absent and a reader's facts are withheld.

Each mutant drops one rule and must leave a table-affected TU unaffected,
a required seed out or the whole catalog out of scope; the counts are over
every variant:

| mutant | rule dropped | table-affected TUs or seeds missed |
|---|---|---|
| `NO_TYPE_CLOSURE` | typedef and tag edges | 2 |
| `NO_MACRO_CLOSURE` | macro-body edges | 1 |
| `NO_POSITION` | header positions, and moved `__LINE__` users on the `.c` path | 6 |
| `NO_TAG_ALIAS` | `s:N` no longer reaches `s:<path>:N` | 2 |
| `NO_CODEGEN_CLOSURE` | seeds are the changed functions only | 3 |
| `NO_OUTSIDER` | TUs that read no changed file never drift; build inputs and probed paths ignored | 22 |

The `__COUNTER__` member rule has no mutant switch; with it disabled by
hand, the counter variant misses all five TUs and the test fails.

`semantic_facts` holds the `.c` path's rule 11: `fx_where` expands
`__LINE__` through `FX_WHERE`, and the comment and whitespace edits above it
must seed it.

**A behavior mutant on real code.** Flipping `memcmp(...) == 0` to `!= 0` in
the static `has_suffix` of `engine/modules/hotswap/src/hotswap_loader.c`
turns `test_hotswap_loader`, `test_hotswap_rollback` and
`test_os_sandbox_hotswap_interaction` red. A seed is every function the
compile may re-emit with the static, among them `hotswap_dump_state_json`,
whose address a manifest takes, so the plan falls back (`address-taken`,
22 groups of 22), which selects all three. The rule: a seed is every function whose code the
compile may change, not the function whose source changed, and any such
function whose address is taken refuses the narrowing. The fixture's
`static` and `address` variants and the `NO_CODEGEN_CLOSURE` mutant hold it.

gcc `-O1` can fold a benign `has_suffix` edit to an identical
object. Which TUs rebuild is decided by object bytes, not by source: a
source-level seed can leave its object unchanged, and the witness below
counts a TU as changed only when its object bytes differ.

### Differential fuzzing: `semantic_facts_fuzz`

`semantic_facts_fuzz` holds the whole chain (sensor, facts, `.c` path,
consumer, closure) to a cold compiler. A case is a small C23 project of
three to eight TUs and one to four headers before and after one edit:

- **generated** (`tests/harness/src/semantic_fuzz_gen.c`,
  `semantic_fuzz_templ.c`): 42 function templates (inline, macro,
  `_Generic`, layout, enum, weak, constructor, `__LINE__`, `__COUNTER__`,
  `__has_include`, alias, cleanup, header-static, `constexpr` and more)
  under one of seventeen mutation kinds (plus the data and path kinds
  below), the same bytes for the same seed
  and profile. The `no-ctr-line` profile drops `__COUNTER__` and
  `__LINE__`, whose users make most plans `position-dependent`, so its
  plans narrow; `gcc-deps` writes the depfiles with gcc, which omits
  `__has_include` probes;
- **fixed** (`tests/harness/src/semantic_fuzz_repro.c`): every minimized
  reproducer a run found (F1 to F15) and the shapes that must keep
  passing. They run on every run.

Each TU is compiled with the clang of the LLVM whose libclang the sensor
links (the sensor's `DT_RUNPATH`), `-std=c23 -O1 -ffunction-sections
-fdata-sections` plus the project's flags, and sensed with the same argv,
on both sides, unless a toolchain case says otherwise (below). The change
set is planned in process exactly as
`dev.change.plan` with `"facts"` plans it, and two oracles judge the plan:

1. every TU the plan leaves unaffected, or out of its universe, has a
   byte-identical object;
2. in a changed object, every function and every data object
   (`STT_OBJECT`) whose bytes changed, or whose relocations now address
   other content, is a seed of the narrowed plan, or is covered by a
   fallback, or by a broadened TU after a header change; and every other
   symbol at a seed's address (an alias) is a seed too. The symbols,
   sections and RELA entries are read from the ELF tables. A relocation
   against a section or local symbol is resolved to what it addresses,
   never to the section's name: the NUL-terminated string in a merged
   string section, the constant in a merged constant section, the object
   whose bytes hold the addressed offset (its bytes and the position
   inside it), the function that holds it (by name), else the section
   bytes from there to the next symbol or the section end. A change only
   in a relocation's addend or target symbol counts as benign when every
   such relocation resolves to the same content on both sides; an addend
   into an undefined or global symbol is never benign. A data object is
   covered by a variable seed (`v:...`), or, for a function's static
   (`t0_kk.a`), by its function's seed. A
   seed covers a function by canonical id, not by bare name: `f:<name>`
   an external symbol, `f:<path>:<name>` a local one whose path is the TU
   itself or a header (a header static), so a same-name static in another
   file is not covered by it.

fails the group. Every fixed reproducer always runs. On top of those, the
default run adds a fixed list of 6 (seed, profile, kind) cases (about 45s
standalone with the fixed reproducers at SFZ_CASES_AT_ONCE), and must yield narrowed
verdicts that seed a changed function, so the group cannot pass on
fallbacks alone; `ZCL_STRESS_TESTS=1` runs the full 51-case list instead,
held to the same invariant.
`ZCL_SEMANTIC_FUZZ_SEEDS=FIRST:COUNT[:PROFILE[:KIND[:CC[:OPT]]]]` runs a
long range instead of either, and wins over `ZCL_STRESS_TESTS`; only such
a range run may draw an edit that changes no file (NOOP), which fails a
fixed reproducer or a default seed. `KIND` `any` draws the kind. `CC`
names the object compiler of both sides (`clang`, the sensor's, by
default; `gcc` or any name on `PATH`), or `BEFORE>AFTER` for a compiler
that changes between the sides; `OPT` replaces `-O1` with comma-separated
flags in both argvs, or is `COMPILE/SENSOR` when the sensor is handed
other flags than the compile. The sensor is told each side's actual
object compiler with `--cc` and a fixed stand-in toolchain identity with
`--toolchain-id`, as the `clang-facts` rule tells it. The toolchain
reproducers (`k_sfz_tool_repros`) set the same fields. A reproducer marked
known-RED names the fix it waits for and the exact false-negative lines it
reports until then; it holds only when it fails with exactly those lines,
and any other outcome (an ERROR, a different miss, or a PASS, which means
the mark is stale) fails the group.
These fixed reproducers must pass: F7 (a `cleanup()` handler inlined into a
function that is not seeded) and F7_cleanup_same_name (the same miss while
another file's same-name static also changes, which a seed matched by bare name
would hide); both F8 shapes (a `.c` that `#include`s another `.c`: an edit to
the included file seeds the includer's functions); F9 (the IDENTITY record
names the object compiler's realpath and byte SHA3-256, and the consumer
senses each TU with its own object's compiler and flags); F12 (a TU's own
copy of another file's internal-linkage function, such as a header
`static inline`, seeds like a main-file function and roots its TU); and F10
(all three spellings: the digits after `-O` and `--optimize` are read
numerically, and an unrecognized spelling widens instead of falling to `-O0`
or no optimizer). F11 forces the sensor to a different optimizer level than
the compile (OPT `COMPILE/SENSOR`) regardless of what the Makefile rule
passes, so it stays known-RED: it misses exactly `t0_q` and `t0_eq`.
F13 (a file only `__has_embed` probes is deleted), F14 (a header probed
through a macro operand or `__has_include_next` is deleted) and F15 (the
same header created, with gcc depfiles, which omit the probe) hold because
the sensor records every probe and the consumer reads every probe it cannot
bound as reachable: the text scan records a lookup for each probe, replays a string-literal macro operand and a
`__has_include_next` into stat-confirmed slots (facts revision 4), and
leaves the rest `0 none`; the consumer makes a TU with a `none` lookup a
member, `lookup-unbound`, whenever a path is created or deleted (any
changed path, for `#embed` and `__has_embed`). A deleted path's plan
still falls back on the include graph, which refuses it; the facts
universe the case judges holds t0 by these rules alone. All five
must pass with over-selection 0. The mutant `NO_UNBOUND` makes a `none`
lookup reach no changed path: `F13_has_embed_deleted_mutant` and
`pass_probe_dash_d_gcc_deps_mutant` must then report exactly `t0.c`
planned unaffected (not in the universe). F14 and F15 hold by the replay
alone, which records a hit or stat-confirmed absent slots for the probed
header.
The fixed shapes
`pass_embed_created` (an `#embed` of a created file),
`pass_has_include_shadow_gcc_deps` (a literal `__has_include` shadowed
by a file created in an earlier `-I` dir), `pass_has_embed_header_deleted`
(the probe sits in a header), `pass_has_include_macro_elsewhere` (a
created path the macro operand's replayed search never visits, which must
leave the plan with no TU), `pass_probe_word_in_comment` (a path only a
comment and a string literal name is created: no TU) and
`pass_probe_after_separator` (a real `__has_embed` after a C23 digit
separator and a string holding a comment opener, which a lexer that took
the separator for a quote would hide) pin over-selection 0. Four more
create the header inc1/opt.h under gcc depfiles, each probed where the
scan once could not see it: through a `-D` value's macro
(`pass_probe_dash_d_gcc_deps`; t1 compiles with the same `-D`, so its
pin is 1), after a `-std=c17` character literal `'a/*'` that a C23 lexer
reads as a digit separator and a comment (`pass_probe_c17_apostrophe_gcc_deps`),
through a word a `-std=c17` trigraph `??/` splices
(`pass_probe_trigraph_gcc_deps`), and after a probe whose header name,
past a comment, holds `/*` (`pass_probe_comment_hdr_gcc_deps`). All
four pin over-selection 0 except the `-D` case.

The one known-RED reproducer is a toolchain case (no text edit the
consumer misreads):

| reproducer | toolchain | missed | root cause |
|---|---|---|---|
| F11_hot_icf | gcc `-O2` objects, sensor told `-Og` | `t0_q` (an alias of `t0_p` after ipa-icf), `t0_eq` | a sensor deliberately handed other optimizer flags than the compile (`OPT` `COMPILE/SENSOR`) models the wrong codegen no matter what the real Makefile rule passes; the real rule's own drift is covered by `F9_cc_drift` |

The passing shapes beside it hold the model where the spelling is
canonical: gcc `-O1` seeds the specialized static, and gcc `-O2` and
`-O3` fall back (`inline-closure-unknown`).

The decoy reproducers (`pass_opt_decoy_*`) guard the optimizer parse
against spellings of a level that are no optimizer flag: gcc at `-O2`
followed by `-DMODE=-O0` or `-Ix-O0`, or with `CFLAGS_EXTRA`
`-DLVL=-O0` or `-Wl,-O0` last in the argv (and clang with the
`-DLVL=-O0` one), gcc at `-O0` followed by `-Xlinker -O1`, and the level
flipping `-O0` to `-O2` and back between the sides while the
`-DLVL=-O0` decoy stays last and unchanged (`OPT` `BEFORE>AFTER`). A
reader that took the last `-O` spelling for the level would model the
`-O2` compiles as `-O0` and miss `t0_s.constprop.0`, the miss
F10_opt_spelling_O02 pins; each must pass.

Four generator kinds edit only data: `data_string` (a string literal in
a body, of the same length or longer, so a later literal moves),
`data_table` (an entry of a file-scope static const table read at a
runtime index), `data_hconst` (an entry of a header static const table
that several TUs read) and `data_index` (a header index macro into a
global array another TU defines). They render a data layer only in their
own cases, so every other kind's project stays byte-identical for its
seed, and an unforced draw picks one of them one time in five. The
reproducers D1 to D6 pin the same shapes plus a header macro that
initializes a global const and a static const table inside a function.

Seven path kinds change what a path resolves to while the includer's
text stays the same. They too render their layer only in their own
cases, and a range runs one only when it names it (never drawn):
`symlink_retarget` (a header that is a symbolic link names another
body), `file_macro` (a header returning `__FILE__` and `__FILE_NAME__`
moves to the other include directory as a file or a link, or gains a
same-bytes copy that shadows it), `pragma_alias` (a `#pragma once` header
reached through a second path, a link that becomes a same-bytes file or
names a same-bytes copy, so the header is read twice, or the reverse),
`macro_include` (`#include SEL_HDR` names the other header), `embed_data`
(a byte or the length of a file `#embed` reads), `hasembed` (a file
`__has_embed` probes is created or deleted) and `hasinc_macro` (a header
probed through a macro operand or `__has_include_next` is created or
deleted). A case lays a link out as a link and compares it as git does,
by its target text, so an edit to the file a link names changes only
that file's path. The sensor records the path a link resolves to, so a
TU that reads a header through a link is a reader of its target; a
changed link is no regular file to the include graph, so a retarget
falls back (`include-graph-truncated`). Before the probe fix above, in 64
no-ctr-line seeds of each, only `hasembed` (26) and `hasinc_macro` (10)
missed, every miss the deletion of a file only a probe names (F13, F14);
with gcc depfiles (48 gcc-deps seeds) `hasinc_macro` also missed 12
creations, under narrowed plans (F15). With it, seeds 1 to 64 of
`hasembed` and `hasinc_macro` (no-ctr-line), and seeds 1 to 48 of
`hasinc_macro` and `shadow` (gcc-deps) and of `hasinc` (no-ctr-line),
find no miss; under mutant `NO_UNBOUND` the `hasembed` seeds miss in 29
of 64 and the `hasinc_macro` seeds in 9 of 64 (no-ctr-line) and 7 of 48
(gcc-deps), and every range measures the same over-selection with the
rule as without it. 48 gcc-deps seeds each of `symlink_retarget`,
`pragma_alias`, `macro_include` and `file_macro`, and 48 all-profile
seeds each of `pragma_alias` and `embed_data`, found no miss. The
`#embed` kinds need a compiler with `#embed` for the depfiles, so they
do not run under gcc-deps with gcc 14. The reproducers
`pass_has_embed_created`, `pass_has_embed_build_input`,
`pass_link_retarget` and `pass_link_target_edit` pin the shapes around
them that pass.

Cases run four at once, each in its own
process with two compiles or sensor runs at once. A compile or sensor
run still going after 120 s, or a case process that has not reported
after 240 s, is killed with SIGKILL and the case is an ERROR. Every
compile, sensor and gcc run gets only `PATH`, `LC_ALL=C`, `HOME` and a
`TMPDIR` inside the case, so an inherited `CPATH` or `C_INCLUDE_PATH`
cannot change what they read. The default
run of 94
cases (43 fixed, 51 seeds) takes about 11 s and yields 73 narrowed verdicts and 52 seeded
changed functions.

### Measured results

Two studies bound what the consumer buys. Both compare against the
conservative set (every TU whose depfile names a changed file, or every TU when
a build input changed) and require zero missed dependencies and zero uncovered
new-byte functions; both hold today.

- **Consumer on `engine/modules/hotswap` (66 TUs).** Every seed
  passes. Compile executions avoided against the conservative set: 101 over
  all seeds, from macro edits (`d_macro_used`, `k_macro`) and signature and
  layout edits that reach fewer readers than the depfile set. A flag or
  toolchain drift seed (`identity-drift`) predicts every TU, wider than the
  depfile set, which is unsound there. A no-op `#if` term in a header runs more
  test groups than the plain plan, because the consumer does not evaluate the
  `#if`. Most function-body edits fall back (`address-taken`) because the
  module registers its handlers by address.
- **Real commits.** Of 19 recent commits, 7 narrowed; the rest fell back on
  real declaration or file-scope changes in the edited file. Across the
  narrowed ones, execution groups fell from 483 to 192. No narrowing was
  false. Whole commits also touch harness files, scripts or docs, so the
  saving applies to the edit loop, where one production `.c` is planned at a
  time.

**A narrowed plan is not proof.** Proof still runs the full closure, so the
saving is feedback work only.

## Replay on real history

The tables above plan single edits and extracted commits. `z23-sem-replay`
(`tools/dev/sem_replay*.c`, `make sem-replay-bin`) checks the facts plan
against what an incremental build actually does, one real commit at a time,
in a dedicated worktree:

1. Check out the parent, run make's test-fast object build with the compile
   cache off so every recipe compiles, snapshot every object of the live
   epoch (`build/test-obj/.current-epoch`), and run the sensor on each TU
   whose depfile names a changed file, as `make clang-facts` runs it: `--cc`
   names the object's compiler (its argv's compiler word, past a compile
   cache) and `--toolchain-id` make's `BUILD_COMPILER_ID`. Without them
   IDENTITY says "object-cc unknown" and the planner broadens every reader
   (identity-drift), a plan no real facts directory produces.
2. Check out the commit and make again; this is the measured incremental
   build. A TU is in make's set when its object's inode or mtime moved, and
   in the changed set when its object's bytes changed. Sense the same bound
   at the commit.
3. Plan the commit's changed files with `dev.change.plan`, once plain and
   once with the facts directory. The facts plan's compile set is the
   affected TUs of a complete universe, every TU when the plan widens to the
   whole catalog, or the plain set when it falls back.
4. Compare make's set, the changed set, the plain set (TUs whose depfile
   names a changed file) and the facts set. A changed object the facts set
   leaves out is a miss. `objcopy --strip-debug` splits misses into code
   misses (the stripped objects still differ) and debug-only misses (only
   line information moved). A TU whose compile argv changed between the two
   sides is counted apart as an argv miss.
5. Stop on a code miss: the step exits 3, writes the TU to `MISSES.tsv`, and
   keeps the facts directory for the reproduction. Debug-only and argv
   misses are counted and do not stop the run. When either build failed,
   misses are recorded and the run continues.
6. Also compare the other direction: a TU a plan selected (facts or plain)
   whose object bytes did not move (`facts \ changed`, `plain \ changed`) is
   false-wide, an over-selection. It is counted, never fatal, and never
   stops the run.

Each step writes `run/<NN>_<commit>/result.tsv` and the sets behind it.
`report` prints a headline (compiler executions the facts plan avoided
against make, test-group executions it avoided against the plain plan, the
false-narrow total, which must be 0, and the false-wide totals for facts and
for plain), the per-commit table, totals by change kind and by facts
compile-set mode, the fallback reasons ranked by the compile CPU and the
catalog test groups the facts plan runs beyond the plain plan, and the
sensor's CPU against each set's compile CPU. Test groups come in two units:
catalog groups (the execution set a plan runs) and plan tokens (its path and
closure group entries; the facts plan's tokens are its obligations). One
token can expand to several catalog groups, so the facts plan's catalog
groups are exactly its obligations expanded, never a wider set; compare
each unit only with itself. `repro` rebuilds every object and checks the
bytes are reproducible. `catalog` compiles every TU cold with make's argv
to price TUs make never rebuilt.

The replay is bounded by the history it is given. A commit that touches no
compiled input measures nothing. The false-narrow check is only as strong as
make's dependency tracking: a TU make did not rebuild and whose bytes did
not change cannot be a false negative.

**This is a reporting tool, not a gate.** Nothing in `make ff`, `t-fast`,
`t-fast-exact`, landing or proof runs a replay or reads its output. Its
self-test, the `sem_replay` test group, runs the built binary on a
three-commit fixture repository with stand-in sensor and planner programs.
The test checks: a facts reply that omits the changed TU exits 3 and names
that TU; a correct narrowing reports exact counts, including a false-wide
vs plain that occurs naturally (a recompiled, byte-identical TU); and a
planted over-selection reports the exact false-wide count for facts without
stopping the run.

The replay utility selects `_DARWIN_C_SOURCE=1` before its headers when
`__APPLE__` is defined and the caller has not selected `_DARWIN_C_SOURCE`
(`tools/dev/sem_replay_util.c:5`). The self-test also observes the default,
preservation of a caller-selected value, and absence of this default outside
the Apple branch through child exit statuses from `sr_run`
(`tests/harness/src/test_sem_replay.c:924`). These macro-contract fixtures
use the host libc and explicit declarations; they do not establish Darwin
SDK declaration coverage.

## A future native C23 compiler

A native front end emits the same contract by linking the same core and
calling its `cm_*` entry points in the same order: files, identity, lookups,
macro definitions and expansions, declarations, layouts, enums, function
definitions with their token hash and spans, then the facts sites. The core
has no compiler API. What the front end must reproduce is the libclang
sensor's reading of the front end: type sugar normalization, raw token
spelling with comments dropped from token hashes and macro bodies, the
cursor visit order, the preprocessing record's expansion and inclusion
rules, the rebuilt search list, the identity argv, and clang's canonical
type spellings. A different type grammar needs a new MAGIC. Emitting from
inside the compile, as such a front end would, removes the second parse.
