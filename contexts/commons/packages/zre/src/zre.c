/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: linear-time regular expressions (see the header for the syntax
 *          and semantics contract).
 *
 * Pipeline: pattern -> recursive-descent parse into a bounded AST arena ->
 * Thompson NFA codegen (SPLIT/SAVE instructions, relative targets) -> pike
 * VM simulation. The VM visits each instruction at most once per input
 * position (gen-stamp dedup), which is where the linear-time guarantee
 * comes from; empty loops such as (a*)* are pruned by the same mechanism.
 */
#include "zre/zre.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- NFA instructions ------------------------------------------------ */

enum { OP_CHAR, OP_CLASS, OP_ANY, OP_MATCH, OP_SPLIT, OP_JMP, OP_SAVE,
       OP_BOL, OP_EOL };

typedef struct {
  int32_t x, y;     /* SPLIT: relative targets; SAVE: slot; patch link */
  uint32_t cls[8];  /* CLASS: 256-bit byte set */
  uint8_t op, c;    /* CHAR: literal byte in c */
} inst;

struct zre_prog {
  size_t ncap;   /* capture groups (not counting group 0) */
  size_t ninst;
  inst code[];
};

/* ---- AST ------------------------------------------------------------- */

enum { N_EMPTY, N_CHAR, N_ANY, N_CLASS, N_BOL, N_EOL, N_CONCAT, N_ALT,
       N_REP, N_GROUP };

typedef struct {
  uint32_t cls[8]; /* N_CLASS */
  int32_t next;    /* sibling in a CONCAT/ALT list, -1 ends the list */
  int32_t child;   /* first child (CONCAT/ALT list head, REP/GROUP body) */
  int32_t min;     /* N_REP repeat bounds; max -1 = unbounded */
  int32_t max;
  uint8_t kind;
  uint8_t c;  /* N_CHAR */
  uint8_t cap; /* N_GROUP: capture slot 1..ZRE_MAX_GROUPS, 0 = (?:...) */
} node;

/* ---- ASCII helpers (locale-independent) ------------------------------ */

static bool is_digit(int c) { return c >= '0' && c <= '9'; }
static bool is_upper(int c) { return c >= 'A' && c <= 'Z'; }
static bool is_lower(int c) { return c >= 'a' && c <= 'z'; }
static bool is_hex(int c) {
  return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
static int hex_val(int c) {
  if (is_digit(c))
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return c - 'A' + 10;
}
static bool is_punct(int c) {
  return c > 0x20 && c < 0x7F && !is_digit(c) && !is_upper(c) &&
         !is_lower(c);
}

/* ---- byte-class bitmaps ---------------------------------------------- */

static void bm_set(uint32_t b[8], int c) { b[c >> 5] |= 1u << (c & 31); }
static bool bm_get(const uint32_t b[8], int c) {
  return (b[c >> 5] >> (c & 31)) & 1u;
}
static void bm_range(uint32_t b[8], int lo, int hi) {
  for (int c = lo; c <= hi; c++)
    bm_set(b, c);
}
static void bm_merge(uint32_t b[8], const uint32_t a[8]) {
  for (int i = 0; i < 8; i++)
    b[i] |= a[i];
}
static void bm_not(uint32_t b[8]) {
  for (int i = 0; i < 8; i++)
    b[i] = ~b[i];
}
static void bm_digits(uint32_t b[8]) { bm_range(b, '0', '9'); }
static void bm_word(uint32_t b[8]) {
  bm_range(b, '0', '9');
  bm_range(b, 'a', 'z');
  bm_range(b, 'A', 'Z');
  bm_set(b, '_');
}
static void bm_space(uint32_t b[8]) {
  bm_set(b, ' ');
  bm_set(b, '\t');
  bm_set(b, '\n');
  bm_set(b, '\r');
  bm_set(b, '\f');
  bm_set(b, '\v');
}

/* ---- parser ----------------------------------------------------------- */

typedef struct {
  const char *pat;
  size_t len, pos;
  node *nodes;
  size_t nnodes, capnodes;
  size_t ncap;
  int depth;
  char *errbuf;
  size_t errcap;
  zre_status err;
} parser;

static zre_status fail(parser *p, zre_status st, const char *what) {
  if (p->err == ZRE_OK) {
    p->err = st;
    if (p->errbuf && p->errcap)
      snprintf(p->errbuf, p->errcap, "zre: %s at offset %zu", what, p->pos);
  }
  return st;
}

static int32_t new_node(parser *p, int kind) {
  if (p->err != ZRE_OK || p->nnodes >= p->capnodes) {
    fail(p, ZRE_ERR_PROGRAM, "program too large");
    return -1;
  }
  node *n = &p->nodes[p->nnodes];
  memset(n, 0, sizeof(*n));
  n->kind = (uint8_t)kind;
  n->next = -1;
  n->child = -1;
  n->max = -1;
  return (int32_t)p->nnodes++;
}

/* An escape yields either one literal byte or a whole shorthand class. */
typedef struct {
  bool is_class;
  uint8_t c;
  uint32_t cls[8];
} esc_val;

static bool parse_escape(parser *p, esc_val *out) {
  if (p->pos >= p->len) {
    fail(p, ZRE_ERR_ESCAPE, "trailing '\\'");
    return false;
  }
  int c = (unsigned char)p->pat[p->pos++];
  out->is_class = false;
  memset(out->cls, 0, sizeof(out->cls));
  switch (c) {
  case 'd':
    out->is_class = true;
    bm_digits(out->cls);
    return true;
  case 'D':
    out->is_class = true;
    bm_digits(out->cls);
    bm_not(out->cls);
    return true;
  case 'w':
    out->is_class = true;
    bm_word(out->cls);
    return true;
  case 'W':
    out->is_class = true;
    bm_word(out->cls);
    bm_not(out->cls);
    return true;
  case 's':
    out->is_class = true;
    bm_space(out->cls);
    return true;
  case 'S':
    out->is_class = true;
    bm_space(out->cls);
    bm_not(out->cls);
    return true;
  case 'n': out->c = '\n'; return true;
  case 't': out->c = '\t'; return true;
  case 'r': out->c = '\r'; return true;
  case 'f': out->c = '\f'; return true;
  case 'v': out->c = '\v'; return true;
  case 'x':
    if (p->pos + 2 > p->len || !is_hex((unsigned char)p->pat[p->pos]) ||
        !is_hex((unsigned char)p->pat[p->pos + 1])) {
      fail(p, ZRE_ERR_ESCAPE, "'\\x' needs two hex digits");
      return false;
    }
    out->c = (uint8_t)(hex_val((unsigned char)p->pat[p->pos]) * 16 +
                       hex_val((unsigned char)p->pat[p->pos + 1]));
    p->pos += 2;
    return true;
  default:
    if (is_digit(c)) {
      fail(p, ZRE_ERR_UNSUPPORTED, "backreferences are not supported");
      return false;
    }
    if (is_punct(c)) {
      out->c = (uint8_t)c;
      return true;
    }
    fail(p, ZRE_ERR_ESCAPE, "unknown escape");
    return false;
  }
}

/* One class item: a (possibly escaped) literal byte or a shorthand class
 * merged into the class bitmap. Shorthands cannot be range endpoints. */
static bool class_item(parser *p, uint32_t bm[8], bool *is_class,
                       uint8_t *ch) {
  int c = (unsigned char)p->pat[p->pos];
  if (c == '\\') {
    p->pos++;
    esc_val e;
    if (!parse_escape(p, &e))
      return false;
    if (e.is_class) {
      bm_merge(bm, e.cls);
      *is_class = true;
      return true;
    }
    *ch = e.c;
    *is_class = false;
    return true;
  }
  p->pos++;
  *ch = (uint8_t)c;
  *is_class = false;
  return true;
}

/* At '['; consumes through the closing ']'. */
static bool parse_class(parser *p, uint32_t bm[8]) {
  p->pos++; /* '[' */
  bool negate = false;
  if (p->pos < p->len && p->pat[p->pos] == '^') {
    negate = true;
    p->pos++;
  }
  memset(bm, 0, 8 * sizeof(uint32_t));
  bool first = true;
  for (;;) {
    if (p->pos >= p->len) {
      fail(p, ZRE_ERR_CLASS, "unterminated character class");
      return false;
    }
    if (p->pat[p->pos] == ']' && !first) {
      p->pos++;
      break;
    }
    first = false;
    bool lo_is_class = false;
    uint8_t lo = 0;
    if (!class_item(p, bm, &lo_is_class, &lo))
      return false;
    if (lo_is_class)
      continue; /* shorthand merged; never a range endpoint */
    /* Range? '-' present and not the class's last character. */
    if (p->pos < p->len && p->pat[p->pos] == '-' && p->pos + 1 < p->len &&
        p->pat[p->pos + 1] != ']') {
      p->pos++; /* '-' */
      bool hi_is_class = false;
      uint8_t hi = 0;
      if (p->pos >= p->len || p->pat[p->pos] == ']') {
        fail(p, ZRE_ERR_CLASS, "unterminated character class");
        return false;
      }
      if (!class_item(p, bm, &hi_is_class, &hi))
        return false;
      if (hi_is_class) {
        fail(p, ZRE_ERR_CLASS, "shorthand class as range endpoint");
        return false;
      }
      if (hi < lo) {
        fail(p, ZRE_ERR_CLASS, "inverted range");
        return false;
      }
      bm_range(bm, lo, hi);
    } else {
      bm_set(bm, lo);
    }
  }
  if (negate)
    bm_not(bm);
  return true;
}

static int32_t parse_alt(parser *p);

static int32_t parse_atom(parser *p) {
  if (p->pos >= p->len)
    return new_node(p, N_EMPTY);
  int c = (unsigned char)p->pat[p->pos];
  switch (c) {
  case '(': {
    p->pos++;
    uint8_t cap = 0;
    bool capture = true;
    if (p->pos < p->len && p->pat[p->pos] == '?') {
      if (p->pos + 1 < p->len && p->pat[p->pos + 1] == ':') {
        capture = false;
        p->pos += 2;
      } else {
        fail(p, ZRE_ERR_UNSUPPORTED,
             "only (?:...) non-capturing groups are supported");
        return -1;
      }
    }
    if (++p->depth > (int)ZRE_MAX_NEST) {
      fail(p, ZRE_ERR_NEST, "groups nested too deep");
      return -1;
    }
    if (capture) {
      if (p->ncap >= ZRE_MAX_GROUPS) {
        fail(p, ZRE_ERR_GROUPS, "too many capture groups");
        return -1;
      }
      cap = (uint8_t)++p->ncap;
    }
    int32_t body = parse_alt(p);
    p->depth--;
    if (p->err != ZRE_OK)
      return -1;
    if (p->pos >= p->len || p->pat[p->pos] != ')') {
      fail(p, ZRE_ERR_UNBALANCED, "unbalanced '('");
      return -1;
    }
    p->pos++;
    int32_t g = new_node(p, N_GROUP);
    if (g < 0)
      return -1;
    p->nodes[g].child = body;
    p->nodes[g].cap = cap;
    return g;
  }
  case '.':
    p->pos++;
    return new_node(p, N_ANY);
  case '[': {
    int32_t n = new_node(p, N_CLASS);
    if (n < 0)
      return -1;
    if (!parse_class(p, p->nodes[n].cls))
      return -1;
    return n;
  }
  case '^':
    p->pos++;
    return new_node(p, N_BOL);
  case '$':
    p->pos++;
    return new_node(p, N_EOL);
  case '\\': {
    p->pos++;
    esc_val e;
    if (!parse_escape(p, &e))
      return -1;
    int32_t n = new_node(p, e.is_class ? N_CLASS : N_CHAR);
    if (n < 0)
      return -1;
    if (e.is_class)
      memcpy(p->nodes[n].cls, e.cls, sizeof(e.cls));
    else
      p->nodes[n].c = e.c;
    return n;
  }
  default: {
    p->pos++;
    int32_t n = new_node(p, N_CHAR);
    if (n < 0)
      return -1;
    p->nodes[n].c = (uint8_t)c;
    return n;
  }
  }
}

static bool is_postfix(int c) {
  return c == '*' || c == '+' || c == '?' || c == '{';
}

/* Parse a counted repeat body after '{'; bounds out via min and max.
 * The caller has verified the next byte is a digit. */
static bool parse_counted(parser *p, int32_t *min, int32_t *max) {
  size_t m = 0, n = 0;
  bool have_n = false, open_ended = false;
  while (p->pos < p->len && is_digit((unsigned char)p->pat[p->pos])) {
    m = m * 10 + (size_t)(p->pat[p->pos] - '0');
    if (m > ZRE_MAX_REPEAT) {
      fail(p, ZRE_ERR_REPEAT, "repeat bound over 255");
      return false;
    }
    p->pos++;
  }
  if (p->pos < p->len && p->pat[p->pos] == ',') {
    p->pos++;
    if (p->pos < p->len && is_digit((unsigned char)p->pat[p->pos])) {
      have_n = true;
      while (p->pos < p->len && is_digit((unsigned char)p->pat[p->pos])) {
        n = n * 10 + (size_t)(p->pat[p->pos] - '0');
        if (n > ZRE_MAX_REPEAT) {
          fail(p, ZRE_ERR_REPEAT, "repeat bound over 255");
          return false;
        }
        p->pos++;
      }
    } else {
      open_ended = true;
    }
  } else {
    have_n = true;
    n = m;
  }
  if (p->pos >= p->len || p->pat[p->pos] != '}') {
    fail(p, ZRE_ERR_REPEAT, "unterminated counted repeat");
    return false;
  }
  p->pos++;
  if (have_n && n < m) {
    fail(p, ZRE_ERR_REPEAT, "repeat upper bound below lower bound");
    return false;
  }
  *min = (int32_t)m;
  *max = open_ended ? -1 : (int32_t)n;
  return true;
}

static int32_t parse_repeat(parser *p) {
  if (p->pos < p->len &&
      (p->pat[p->pos] == '*' || p->pat[p->pos] == '+' || p->pat[p->pos] == '?')) {
    fail(p, ZRE_ERR_REPEAT, "repeat with no preceding atom");
    return -1;
  }
  int32_t atom = parse_atom(p);
  if (atom < 0)
    return -1;
  if (p->pos >= p->len)
    return atom;
  int c = (unsigned char)p->pat[p->pos];
  int32_t min, max;
  if (c == '*') {
    min = 0;
    max = -1;
    p->pos++;
  } else if (c == '+') {
    min = 1;
    max = -1;
    p->pos++;
  } else if (c == '?') {
    min = 0;
    max = 1;
    p->pos++;
  } else if (c == '{' && p->pos + 1 < p->len &&
             is_digit((unsigned char)p->pat[p->pos + 1])) {
    p->pos++; /* '{' */
    if (!parse_counted(p, &min, &max))
      return -1;
  } else {
    return atom; /* no postfix */
  }
  int kind = p->nodes[atom].kind;
  if (kind == N_BOL || kind == N_EOL) {
    fail(p, ZRE_ERR_REPEAT, "repeat of an anchor");
    return -1;
  }
  /* A postfix on a postfix ("a**", "a*?" — lazy forms do not exist). */
  if (p->pos < p->len && is_postfix((unsigned char)p->pat[p->pos]) &&
      (p->pat[p->pos] != '{' ||
       (p->pos + 1 < p->len && is_digit((unsigned char)p->pat[p->pos + 1])))) {
    fail(p, ZRE_ERR_REPEAT, "stacked repeat postfix");
    return -1;
  }
  int32_t r = new_node(p, N_REP);
  if (r < 0)
    return -1;
  p->nodes[r].child = atom;
  p->nodes[r].min = min;
  p->nodes[r].max = max;
  return r;
}

static int32_t parse_concat(parser *p) {
  int32_t head = -1, *tail = &head;
  size_t count = 0;
  while (p->pos < p->len && p->pat[p->pos] != ')' && p->pat[p->pos] != '|') {
    int32_t it = parse_repeat(p);
    if (it < 0)
      return -1;
    *tail = it;
    tail = &p->nodes[it].next;
    count++;
  }
  if (count == 0)
    return new_node(p, N_EMPTY);
  if (count == 1)
    return head;
  int32_t n = new_node(p, N_CONCAT);
  if (n < 0)
    return -1;
  p->nodes[n].child = head;
  return n;
}

static int32_t parse_alt(parser *p) {
  int32_t head = -1, *tail = &head;
  size_t count = 0;
  for (;;) {
    int32_t it = parse_concat(p);
    if (it < 0)
      return -1;
    *tail = it;
    tail = &p->nodes[it].next;
    count++;
    if (p->pos < p->len && p->pat[p->pos] == '|') {
      p->pos++;
      continue;
    }
    break;
  }
  if (count == 1)
    return head;
  int32_t n = new_node(p, N_ALT);
  if (n < 0)
    return -1;
  p->nodes[n].child = head;
  return n;
}

/* ---- code generator ----------------------------------------------------
 * Dangling fixups are linked lists threaded through the unresolved target
 * fields themselves; an entry encodes inst_index*2 + field (0 = x, 1 = y)
 * and the field holds the next entry or -1. patch() then writes relative
 * targets. */

typedef struct {
  inst *code;
  size_t n, cap;
  const node *nodes;
  zre_status err;
  char *errbuf;
  size_t errcap;
} emitter;

static zre_status gen_fail(emitter *e, zre_status st, const char *what) {
  if (e->err == ZRE_OK) {
    e->err = st;
    if (e->errbuf && e->errcap)
      snprintf(e->errbuf, e->errcap, "zre: %s", what);
  }
  return st;
}

static int32_t emit(emitter *e, int op) {
  if (e->err != ZRE_OK || e->n >= e->cap) {
    gen_fail(e, ZRE_ERR_PROGRAM, "compiled program over instruction bound");
    return -1;
  }
  inst *in = &e->code[e->n];
  memset(in, 0, sizeof(*in));
  in->op = (uint8_t)op;
  in->x = 0;
  in->y = 0;
  return (int32_t)e->n++;
}

static int32_t list1(int32_t idx, int field) { return idx * 2 + field; }

static int32_t lappend(emitter *e, int32_t l1, int32_t l2) {
  if (l1 < 0)
    return l2;
  if (l2 < 0)
    return l1;
  int32_t p = l1;
  for (;;) {
    int32_t *f = (p & 1) ? &e->code[p >> 1].y : &e->code[p >> 1].x;
    if (*f < 0) {
      *f = l2;
      return l1;
    }
    p = *f;
  }
}

static void patch(emitter *e, int32_t list, int32_t target) {
  while (list >= 0) {
    int32_t *f = (list & 1) ? &e->code[list >> 1].y : &e->code[list >> 1].x;
    int32_t next = *f;
    *f = target - (list >> 1); /* relative target */
    list = next;
  }
}

/* Unresolved fields are initialized to -1 (end of patch list). */
static int32_t emit_split(emitter *e) {
  int32_t s = emit(e, OP_SPLIT);
  if (s >= 0) {
    e->code[s].x = 1; /* preferred branch: the next instruction */
    e->code[s].y = -1;
  }
  return s;
}

/* Every fragment ends with an explicit dangling JMP: fall-through alone
 * cannot express loop-backs or alternation ends. A compaction pass after
 * codegen removes JMPs whose target is simply the next instruction. */
static int32_t emit_jmp(emitter *e) {
  int32_t j = emit(e, OP_JMP);
  if (j >= 0)
    e->code[j].x = -1; /* dangling */
  return j;
}

static int32_t gen(emitter *e, int32_t ni);

/* One copy of a repeat body at the current position, sequenced after the
 * dangling outs *io. On return *io is the child's own dangling list (the
 * previous list is consumed by patching it to the child's start). */
static void gen_seq(emitter *e, int32_t child, int32_t *io) {
  int32_t cs = (int32_t)e->n;
  int32_t d = gen(e, child);
  if (e->err != ZRE_OK)
    return;
  if (*io >= 0)
    patch(e, *io, cs);
  *io = d;
}

/* Leaf: one consuming/zero-width instruction followed by the mandatory
 * dangling end JMP. Returns the JMP's patch entry. */
static int32_t gen_leaf(emitter *e, int op, uint8_t c, const uint32_t *cls) {
  int32_t i = emit(e, op);
  if (i < 0)
    return -1;
  if (op == OP_CHAR)
    e->code[i].c = c;
  if (op == OP_CLASS)
    memcpy(e->code[i].cls, cls, sizeof(e->code[i].cls));
  int32_t j = emit_jmp(e);
  if (j < 0)
    return -1;
  return list1(j, 0);
}

static int32_t gen(emitter *e, int32_t ni) {
  const node *n = &e->nodes[ni];
  switch (n->kind) {
  case N_EMPTY:
    return -1;
  case N_CHAR:
    return gen_leaf(e, OP_CHAR, n->c, NULL);
  case N_ANY:
    return gen_leaf(e, OP_ANY, 0, NULL);
  case N_CLASS:
    return gen_leaf(e, OP_CLASS, 0, n->cls);
  case N_BOL:
    return gen_leaf(e, OP_BOL, 0, NULL);
  case N_EOL:
    return gen_leaf(e, OP_EOL, 0, NULL);
  case N_GROUP: {
    if (n->cap == 0)
      return gen(e, n->child);
    int32_t s1 = emit(e, OP_SAVE);
    if (s1 < 0)
      return -1;
    e->code[s1].x = 2 * n->cap;
    int32_t d = gen(e, n->child);
    if (e->err != ZRE_OK)
      return -1;
    if (d >= 0)
      patch(e, d, (int32_t)e->n);
    int32_t s2 = emit(e, OP_SAVE);
    if (s2 < 0)
      return -1;
    e->code[s2].x = 2 * n->cap + 1;
    int32_t j = emit_jmp(e);
    if (j < 0)
      return -1;
    return list1(j, 0);
  }
  case N_CONCAT: {
    int32_t out = -1;
    for (int32_t c = n->child; c >= 0; c = e->nodes[c].next) {
      gen_seq(e, c, &out);
      if (e->err != ZRE_OK)
        return -1;
    }
    return out;
  }
  case N_ALT: {
    int32_t out = -1, py = -1;
    for (int32_t c = n->child; c >= 0; c = e->nodes[c].next) {
      if (py >= 0) {
        patch(e, py, (int32_t)e->n); /* previous split's fallback: here */
        py = -1;
      }
      if (e->nodes[c].next >= 0) {
        int32_t s = emit_split(e);
        if (s < 0)
          return -1;
        py = list1(s, 1);
      }
      int32_t d = gen(e, c);
      if (e->err != ZRE_OK)
        return -1;
      out = lappend(e, out, d);
    }
    return out;
  }
  case N_REP: {
    int32_t child = n->child;
    int32_t min = n->min, max = n->max;
    if (min == 0 && max == -1) { /* star */
      int32_t s = emit_split(e);
      if (s < 0)
        return -1;
      int32_t d = gen(e, child);
      if (e->err != ZRE_OK)
        return -1;
      if (d >= 0)
        patch(e, d, s);
      return list1(s, 1);
    }
    if (min == 1 && max == -1) { /* plus */
      int32_t st = (int32_t)e->n;
      int32_t d = gen(e, child);
      if (e->err != ZRE_OK)
        return -1;
      int32_t s = emit_split(e);
      if (s < 0)
        return -1;
      e->code[s].x = st - s; /* loop back */
      if (d >= 0)
        patch(e, d, s);
      return list1(s, 1);
    }
    if (min == 0 && max == 1) { /* quest */
      int32_t s = emit_split(e);
      if (s < 0)
        return -1;
      int32_t d = gen(e, child);
      if (e->err != ZRE_OK)
        return -1;
      return lappend(e, d, list1(s, 1));
    }
    /* General counted: min mandatory copies, then either an unbounded
     * tail ({m,} = m copies then star) or (max-min) optional copies. */
    int32_t out = -1;
    for (int32_t i = 0; i < min; i++) {
      gen_seq(e, child, &out);
      if (e->err != ZRE_OK)
        return -1;
    }
    if (max < 0) {
      int32_t cs = (int32_t)e->n;
      if (out >= 0)
        patch(e, out, cs);
      int32_t s = emit_split(e);
      if (s < 0)
        return -1;
      int32_t d = gen(e, child);
      if (e->err != ZRE_OK)
        return -1;
      if (d >= 0)
        patch(e, d, s);
      return list1(s, 1);
    }
    for (int32_t i = min; i < max; i++) {
      int32_t cs = (int32_t)e->n;
      if (out >= 0)
        patch(e, out, cs);
      int32_t s = emit_split(e);
      if (s < 0)
        return -1;
      int32_t d = gen(e, child);
      if (e->err != ZRE_OK)
        return -1;
      out = lappend(e, d, list1(s, 1));
    }
    return out;
  }
  default:
    gen_fail(e, ZRE_ERR_PROGRAM, "internal: unknown AST node");
    return -1;
  }
}

/* ---- pike VM -----------------------------------------------------------
 * Threads are (pc, capture slots). Per input position a gen-stamp array
 * guarantees each pc is expanded at most once: that is the linear-time
 * argument. Workspace is heap-allocated per call and sized by the compiled
 * program, never by the text. */

#define ZRE_SLOTS (2u * ZRE_MAX_CAPS)

typedef struct {
  int32_t pc;
  size_t slots[ZRE_SLOTS];
} thread;

typedef struct {
  thread *cur, *nxt; /* thread lists */
  size_t ncur, nnxt;
  thread *stack; /* addthread work stack */
  size_t nstack, capstack;
  uint32_t *seen, gen;
} vm;

/* Expand epsilon closures (SPLIT/JMP/SAVE/BOL/EOL) of (pc, slots) at input
 * position pos, appending real (CHAR/CLASS/ANY/MATCH) threads to list.
 * Split x-branches are pushed last so they pop first: depth-first in
 * priority order, exactly like recursive addthread. */
static void addthread(vm *v, const zre_prog *p, thread **list, size_t *nl,
                      int32_t pc, const size_t *slots, size_t pos,
                      size_t textlen) {
  if (v->nstack >= v->capstack)
    return; /* unreachable by sizing; drop rather than overflow */
  thread *top = &v->stack[v->nstack++];
  top->pc = pc;
  memcpy(top->slots, slots, sizeof(top->slots));
  while (v->nstack > 0) {
    thread t = v->stack[--v->nstack]; /* pop into a local: no aliasing */
    if (v->seen[t.pc] == v->gen)
      continue;
    v->seen[t.pc] = v->gen;
    const inst *in = &p->code[t.pc];
    switch (in->op) {
    case OP_SPLIT:
      /* Push the fallback first so the preferred x branch pops first:
       * depth-first in priority order, like recursive addthread. */
      if (v->nstack + 2 > v->capstack)
        break; /* unreachable by sizing */
      v->stack[v->nstack] = t;
      v->stack[v->nstack].pc += in->y;
      v->nstack++;
      v->stack[v->nstack] = t;
      v->stack[v->nstack].pc += in->x;
      v->nstack++;
      break;
    case OP_SAVE:
      t.slots[in->x] = pos;
      if (v->nstack < v->capstack) {
        v->stack[v->nstack] = t;
        v->stack[v->nstack].pc += 1;
        v->nstack++;
      }
      break;
    case OP_JMP:
      if (v->nstack < v->capstack) {
        v->stack[v->nstack] = t;
        v->stack[v->nstack].pc += in->x;
        v->nstack++;
      }
      break;
    case OP_BOL:
      if (pos == 0 && v->nstack < v->capstack) {
        v->stack[v->nstack] = t;
        v->stack[v->nstack].pc += 1;
        v->nstack++;
      }
      break;
    case OP_EOL:
      if (pos == textlen && v->nstack < v->capstack) {
        v->stack[v->nstack] = t;
        v->stack[v->nstack].pc += 1;
        v->nstack++;
      }
      break;
    default: /* CHAR, CLASS, ANY, MATCH */
      (*list)[(*nl)++] = t;
      break;
    }
  }
}

bool zre_match(const zre_prog *prog, const char *text, size_t len,
               zre_span caps[], size_t max_caps) {
  if (!prog || (!text && len > 0) || (!caps && max_caps > 0))
    return false;
  size_t ninst = prog->ninst;
  vm v;
  memset(&v, 0, sizeof(v));
  v.cur = malloc(ninst * sizeof(thread));
  v.nxt = malloc(ninst * sizeof(thread));
  v.stack = malloc((2 * ninst + 2) * sizeof(thread));
  v.capstack = 2 * ninst + 2;
  v.seen = calloc(ninst, sizeof(uint32_t));
  if (!v.cur || !v.nxt || !v.stack || !v.seen) {
    free(v.cur);
    free(v.nxt);
    free(v.stack);
    free(v.seen);
    return false;
  }

  bool matched = false;
  size_t mslots[ZRE_SLOTS];
  for (size_t i = 0; i < ZRE_SLOTS; i++)
    mslots[i] = ZRE_NOMATCH;

  for (size_t sp = 0; sp <= len; sp++) {
    bool cut = false; /* this step's MATCH cut lower-priority threads */
    if (!matched) {
      /* Lowest-priority thread: a match attempt starting here. */
      size_t init[ZRE_SLOTS];
      for (size_t i = 0; i < ZRE_SLOTS; i++)
        init[i] = ZRE_NOMATCH;
      init[0] = sp;
      v.gen++;
      addthread(&v, prog, &v.cur, &v.ncur, 0, init, sp, len);
    }
    v.gen++;
    for (size_t i = 0; i < v.ncur; i++) {
      thread *t = &v.cur[i];
      const inst *in = &prog->code[t->pc];
      switch (in->op) {
      case OP_CHAR:
        if (sp < len && (uint8_t)text[sp] == in->c)
          addthread(&v, prog, &v.nxt, &v.nnxt, t->pc + 1, t->slots, sp + 1,
                    len);
        break;
      case OP_CLASS:
        if (sp < len && bm_get(in->cls, (unsigned char)text[sp]))
          addthread(&v, prog, &v.nxt, &v.nnxt, t->pc + 1, t->slots, sp + 1,
                    len);
        break;
      case OP_ANY:
        if (sp < len && text[sp] != '\n')
          addthread(&v, prog, &v.nxt, &v.nnxt, t->pc + 1, t->slots, sp + 1,
                    len);
        break;
      case OP_MATCH:
        /* Priority order makes this the leftmost-first winner; cut all
         * lower-priority threads for the rest of this step. */
        memcpy(mslots, t->slots, sizeof(mslots));
        mslots[1] = sp;
        matched = true;
        cut = true;
        break;
      default:
        break; /* epsilon ops never sit in a thread list */
      }
      if (cut)
        break;
    }
    thread *tmp = v.cur;
    v.cur = v.nxt;
    v.nxt = tmp;
    v.ncur = v.nnxt;
    v.nnxt = 0;
    if (v.ncur == 0 && matched)
      break;
  }

  if (matched && caps) {
    size_t nspans = prog->ncap + 1;
    for (size_t i = 0; i < max_caps; i++) {
      if (i < nspans) {
        caps[i].start = mslots[2 * i];
        caps[i].end = mslots[2 * i + 1];
      } else {
        caps[i].start = ZRE_NOMATCH;
        caps[i].end = ZRE_NOMATCH;
      }
    }
  }
  free(v.cur);
  free(v.nxt);
  free(v.stack);
  free(v.seen);
  return matched;
}

/* ---- public entry points ---------------------------------------------- */

zre_status zre_compile(const char *pattern, size_t len, zre_prog **prog_out,
                       char *errbuf, size_t errbuf_cap) {
  if (errbuf && errbuf_cap)
    errbuf[0] = '\0';
  if (!prog_out)
    return ZRE_ERR_ARG;
  *prog_out = NULL;
  parser p;
  memset(&p, 0, sizeof(p));
  p.errbuf = errbuf;
  p.errcap = errbuf_cap;
  if (!pattern)
    return fail(&p, ZRE_ERR_ARG, "NULL pattern");
  if (len > ZRE_MAX_PATTERN)
    return fail(&p, ZRE_ERR_TOO_LONG, "pattern over byte bound");
  p.pat = pattern;
  p.len = len;

  /* Each pattern byte yields well under two AST nodes. */
  p.capnodes = 2 * len + 8;
  p.nodes = malloc(p.capnodes * sizeof(node));
  if (!p.nodes)
    return fail(&p, ZRE_ERR_MEMORY, "out of memory");

  int32_t root = parse_alt(&p);
  if (p.err == ZRE_OK && p.pos < p.len)
    fail(&p, ZRE_ERR_UNBALANCED, "unbalanced ')'");
  if (p.err != ZRE_OK) {
    free(p.nodes);
    return p.err;
  }

  emitter e;
  memset(&e, 0, sizeof(e));
  e.cap = ZRE_MAX_PROG;
  e.nodes = p.nodes;
  e.errbuf = errbuf;
  e.errcap = errbuf_cap;
  e.code = malloc(e.cap * sizeof(inst));
  if (!e.code) {
    free(p.nodes);
    return fail(&p, ZRE_ERR_MEMORY, "out of memory");
  }
  int32_t dangling = gen(&e, root);
  if (e.err == ZRE_OK) {
    patch(&e, dangling, (int32_t)e.n);
    if (emit(&e, OP_MATCH) < 0)
      gen_fail(&e, ZRE_ERR_PROGRAM, "compiled program over instruction bound");
  }
  if (e.err != ZRE_OK) {
    free(e.code);
    free(p.nodes);
    return e.err;
  }

  zre_prog *prog = malloc(sizeof(zre_prog) + e.n * sizeof(inst));
  if (!prog) {
    free(e.code);
    free(p.nodes);
    return fail(&p, ZRE_ERR_MEMORY, "out of memory");
  }
  prog->ncap = p.ncap;

  /* Compaction: drop JMPs whose target is the next instruction (plain
   * fall-through), remapping every SPLIT/JMP relative target. Removed
   * JMPs can chain, so targets resolve by walking. */
  {
    uint32_t newidx[ZRE_MAX_PROG];
    size_t m = 0;
    for (size_t i = 0; i < e.n; i++) {
      if (e.code[i].op == OP_JMP && e.code[i].x == 1) {
        newidx[i] = UINT32_MAX; /* removed */
      } else {
        newidx[i] = (uint32_t)m++;
      }
    }
    for (size_t i = 0; i < e.n; i++) {
      if (newidx[i] == UINT32_MAX)
        continue;
      inst tmp = e.code[i];
      if (tmp.op == OP_SPLIT || tmp.op == OP_JMP) {
        int32_t tx = (int32_t)i + tmp.x;
        while (newidx[tx] == UINT32_MAX)
          tx += e.code[tx].x; /* skip a removed fall-through JMP */
        tmp.x = (int32_t)newidx[tx] - (int32_t)newidx[i];
        if (tmp.op == OP_SPLIT) {
          int32_t ty = (int32_t)i + tmp.y;
          while (newidx[ty] == UINT32_MAX)
            ty += e.code[ty].x;
          tmp.y = (int32_t)newidx[ty] - (int32_t)newidx[i];
        }
      }
      prog->code[newidx[i]] = tmp;
    }
    prog->ninst = m;
  }
  free(e.code);
  free(p.nodes);
  *prog_out = prog;
  return ZRE_OK;
}

size_t zre_groups(const zre_prog *prog) { return prog ? prog->ncap : 0; }

void zre_free(zre_prog *prog) { free(prog); }

const char *zre_strerror(zre_status st) {
  switch (st) {
  case ZRE_OK: return "ok";
  case ZRE_ERR_ARG: return "bad argument";
  case ZRE_ERR_TOO_LONG: return "pattern too long";
  case ZRE_ERR_UNBALANCED: return "unbalanced parenthesis";
  case ZRE_ERR_CLASS: return "malformed character class";
  case ZRE_ERR_ESCAPE: return "bad escape";
  case ZRE_ERR_REPEAT: return "bad repeat";
  case ZRE_ERR_UNSUPPORTED: return "unsupported construct";
  case ZRE_ERR_NEST: return "groups nested too deep";
  case ZRE_ERR_GROUPS: return "too many capture groups";
  case ZRE_ERR_PROGRAM: return "compiled program too large";
  case ZRE_ERR_MEMORY: return "out of memory";
  }
  return "unknown error";
}
