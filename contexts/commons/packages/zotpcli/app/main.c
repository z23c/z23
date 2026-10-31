/* zotpcli — TOTP/HOTP authenticator CLI.
 *
 * A minimal oathtool-style tool with a local entry store. Commands:
 *
 *   zotpcli [--store PATH] [--passphrase PW] [--verbose] <cmd> ...
 *
 *   add --label L --secret B32 [--issuer I] [--hotp] [--digits N]
 *       [--period N] [--counter N]
 *   import URI              add an entry from an otpauth:// URI
 *   code LABEL              print the current code (HOTP consumes the
 *                           counter; TOTP uses time(2) unless --now T)
 *   list                    one line per entry
 *   show LABEL              full details, incl. base32 and hex secret
 *   remove LABEL
 *   export [--pem]          otpauth URIs, or PEM armor of the store file
 *   verify                  check store integrity (MAC), print summary
 *
 * The passphrase may also come from the ZOTPCLI_PASSPHRASE environment
 * variable. See README.md for the honest statement of what the store
 * MAC protects (integrity, not confidentiality).
 */
#include "zotpcli/zotpcli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "zarg/zarg.h"
#include "zfmt/zfmt.h"
#include "zhex/zhex.h"
#include "zlog/zlog.h"
#include "zpem/zpem.h"
#include "zstr/zstr.h"
#include "ztime/ztime.h"

#define DEFAULT_STORE "zotpcli.store"
#define PEM_LABEL "ZOTPCLI STORE"

static void log_emit(void *ctx, const char *line)
{
    (void)ctx;
    fputs(line, stderr);
}

static zlog_sink g_log = { log_emit, NULL, ZLOG_WARN, true, "zotpcli" };

/* --- bounded file IO -------------------------------------------------- */

static int read_file(const char *path, zbuf *out)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    uint8_t chunk[4096];
    size_t n;
    while ((n = fread(chunk, 1, sizeof chunk, fp)) > 0) {
        if (zbuf_write(out, chunk, n) != ZBUF_OK) {
            fclose(fp);
            return -2; /* over the 1 MiB bound or OOM */
        }
    }
    int bad = ferror(fp);
    fclose(fp);
    return bad ? -1 : 0;
}

static int write_file(const char *path, const void *data, size_t len)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    int ok = fwrite(data, 1, len, fp) == len;
    if (fclose(fp) != 0) ok = 0;
    return ok ? 0 : -1;
}

/* 16 bytes of CSPRNG salt for a new store; fail-closed. */
static int random_salt(uint8_t salt[ZOTPCLI_SALT_LEN])
{
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) return -1;
    size_t n = fread(salt, 1, ZOTPCLI_SALT_LEN, fp);
    fclose(fp);
    return n == ZOTPCLI_SALT_LEN ? 0 : -1;
}

/* --- store load/save ---------------------------------------------------- */

/* Returns ZOTPCLI_OK when a store was loaded, ZOTPCLI_ERR_NOTFOUND when
 * the file does not exist (fresh store), or the decode error. A
 * present-but-malformed file is NOT confused with a missing one. */
static zotpcli_err load_store(const char *path, const char *pass,
                              zotpcli_store *s)
{
    zbuf raw;
    if (zbuf_init(&raw, ZOTPCLI_MAX_FILE) != ZBUF_OK)
        return ZOTPCLI_ERR_NOMEM;
    int rc = read_file(path, &raw);
    if (rc != 0) {
        zbuf_free(&raw);
        if (rc == -1) return ZOTPCLI_ERR_NOTFOUND; /* fopen failed */
        zlog_error(&g_log, "store file too large or read error");
        return ZOTPCLI_ERR_FORMAT;
    }
    zotpcli_err e = zotpcli_store_decode(s, raw.data, zbuf_len(&raw), pass);
    zbuf_free(&raw);
    return e;
}

static zotpcli_err save_store(const char *path, const char *pass,
                              zotpcli_store *s)
{
    if (random_salt(s->salt) != 0) {
        zlog_error(&g_log, "could not read /dev/urandom for KDF salt");
        return ZOTPCLI_ERR_KDF;
    }
    zbuf out;
    if (zbuf_init(&out, ZOTPCLI_MAX_FILE) != ZBUF_OK)
        return ZOTPCLI_ERR_NOMEM;
    zotpcli_err e = zotpcli_store_encode(s, pass, s->salt, &out);
    if (e == ZOTPCLI_OK && write_file(path, out.data, zbuf_len(&out)) != 0) {
        zlog_error(&g_log, "could not write store file");
        e = ZOTPCLI_ERR_FORMAT;
    }
    zbuf_free(&out);
    return e;
}

/* --- option parsing ------------------------------------------------------ */

enum {
    O_STORE, O_PASS, O_NOW, O_VERBOSE, O_HELP,
    O_LABEL, O_ISSUER, O_SECRET, O_DIGITS, O_PERIOD, O_COUNTER,
    O_HOTP, O_PEM
};

static const zarg_opt g_spec[] = {
    { 's', "store",      ZARG_STR,  "store file path (default " DEFAULT_STORE ")" },
    { 'p', "passphrase", ZARG_STR,  "store MAC passphrase (or ZOTPCLI_PASSPHRASE)" },
    { 0,   "now",        ZARG_U64,  "override current Unix time (testing)" },
    { 'v', "verbose",    ZARG_BOOL, "info-level diagnostics on stderr" },
    { 'h', "help",       ZARG_BOOL, "show usage" },
    { 0,   "label",      ZARG_STR,  "entry label for add" },
    { 0,   "issuer",     ZARG_STR,  "entry issuer for add" },
    { 0,   "secret",     ZARG_STR,  "base32 secret for add" },
    { 0,   "digits",     ZARG_U64,  "code digits, 6..8 (default 6)" },
    { 0,   "period",     ZARG_U64,  "TOTP period seconds (default 30)" },
    { 0,   "counter",    ZARG_U64,  "initial HOTP counter (default 0)" },
    { 0,   "hotp",       ZARG_BOOL, "add a counter-based (HOTP) entry" },
    { 0,   "pem",        ZARG_BOOL, "export: PEM armor instead of URIs" },
};

typedef struct {
    const char *store_path;
    const char *passphrase;
    const char *label;
    const char *issuer;
    const char *secret;
    const char *cmd;
    const char *arg[4]; /* positional arguments after the command */
    size_t narg;
    uint64_t now;
    uint64_t digits;
    uint64_t period;
    uint64_t counter;
    bool have_now, have_digits, have_period, have_counter;
    bool verbose, help, hotp, pem;
} options;

enum opt_field_kind { OPT_FIELD_STR, OPT_FIELD_U64, OPT_FIELD_BOOL };

typedef struct {
    size_t spec_index;
    enum opt_field_kind kind;
    size_t off;      /* value field offset in options */
    size_t have_off; /* OPT_FIELD_U64 rows: offset of the have_ flag */
} opt_field;

static const opt_field g_opt_fields[] = {
    { O_STORE,   OPT_FIELD_STR,  offsetof(options, store_path), 0 },
    { O_PASS,    OPT_FIELD_STR,  offsetof(options, passphrase), 0 },
    { O_NOW,     OPT_FIELD_U64,  offsetof(options, now),
      offsetof(options, have_now) },
    { O_VERBOSE, OPT_FIELD_BOOL, offsetof(options, verbose), 0 },
    { O_HELP,    OPT_FIELD_BOOL, offsetof(options, help), 0 },
    { O_LABEL,   OPT_FIELD_STR,  offsetof(options, label), 0 },
    { O_ISSUER,  OPT_FIELD_STR,  offsetof(options, issuer), 0 },
    { O_SECRET,  OPT_FIELD_STR,  offsetof(options, secret), 0 },
    { O_DIGITS,  OPT_FIELD_U64,  offsetof(options, digits),
      offsetof(options, have_digits) },
    { O_PERIOD,  OPT_FIELD_U64,  offsetof(options, period),
      offsetof(options, have_period) },
    { O_COUNTER, OPT_FIELD_U64,  offsetof(options, counter),
      offsetof(options, have_counter) },
    { O_HOTP,    OPT_FIELD_BOOL, offsetof(options, hotp), 0 },
    { O_PEM,     OPT_FIELD_BOOL, offsetof(options, pem), 0 },
};

/* Stores one parsed option into *o; unknown spec indices are ignored. */
static void apply_option(options *o, const zarg_item *it)
{
    for (size_t i = 0; i < sizeof g_opt_fields / sizeof g_opt_fields[0]; i++) {
        const opt_field *f = &g_opt_fields[i];
        if (f->spec_index != it->spec_index) continue;
        char *base = (char *)o;
        switch (f->kind) {
        case OPT_FIELD_STR:
            *(const char **)(base + f->off) = it->value;
            break;
        case OPT_FIELD_U64:
            *(uint64_t *)(base + f->off) = it->u64;
            *(bool *)(base + f->have_off) = true;
            break;
        case OPT_FIELD_BOOL:
            *(bool *)(base + f->off) = true;
            break;
        }
        return;
    }
}

static int parse_options(int argc, char **argv, options *o)
{
    memset(o, 0, sizeof *o);
    o->store_path = DEFAULT_STORE;

    zarg_parser p;
    zarg_err e = zarg_init(&p, g_spec, sizeof g_spec / sizeof g_spec[0],
                           argc, argv);
    if (e != ZARG_OK) {
        zlog_error(&g_log, zarg_err_str(e));
        return -1;
    }
    zarg_item it;
    while ((e = zarg_next(&p, &it)) == ZARG_OK && it.kind != ZARG_ITEM_END) {
        if (it.kind == ZARG_ITEM_POS) {
            if (it.pos_index == 0) {
                o->cmd = it.text;
            } else if (o->narg < sizeof o->arg / sizeof o->arg[0]) {
                o->arg[o->narg++] = it.text;
            } else {
                zlog_error(&g_log, "too many arguments");
                return -1;
            }
            continue;
        }
        apply_option(o, &it);
    }
    if (e != ZARG_OK) {
        char msg[96];
        zfmt f;
        zfmt_init(&f, msg, sizeof msg);
        zfmt_str(&f, "option error: ");
        zfmt_str(&f, zarg_err_str(e));
        zfmt_str(&f, " at argv[");
        zfmt_u64(&f, p.err_index);
        zfmt_char(&f, ']');
        zlog_error(&g_log, zfmt_cstr(&f));
        return -1;
    }
    if (o->verbose) g_log.threshold = ZLOG_INFO;
    if (!o->passphrase) o->passphrase = getenv("ZOTPCLI_PASSPHRASE");
    return 0;
}

static int64_t current_now(const options *o)
{
    if (o->have_now) return (int64_t)o->now;
    return (int64_t)time(NULL); /* time(2): system wall clock, UTC */
}

/* --- commands -------------------------------------------------------------- */

/* Which cmd_add entry-field check failed; cmd_add logs per code. */
enum add_field_err {
    ADD_FIELD_OK,
    ADD_FIELD_LABEL,
    ADD_FIELD_ISSUER,
    ADD_FIELD_SECRET,
    ADD_FIELD_DIGITS,
    ADD_FIELD_PERIOD
};

/* Fills label, issuer and secret of *e from *o; on ADD_FIELD_SECRET
 * failure *ze holds the decode error. */
static enum add_field_err fill_entry_identity(const options *o,
                                              zotpcli_entry *e,
                                              zotpcli_err *ze)
{
    if (zstr_copy(e->label, sizeof e->label, o->label) >= sizeof e->label)
        return ADD_FIELD_LABEL;
    if (o->issuer &&
        zstr_copy(e->issuer, sizeof e->issuer, o->issuer) >= sizeof e->issuer)
        return ADD_FIELD_ISSUER;
    *ze = zotpcli_b32_decode_secret(o->secret, e->secret, sizeof e->secret,
                                    &e->secret_len);
    if (*ze != ZOTPCLI_OK)
        return ADD_FIELD_SECRET;
    return ADD_FIELD_OK;
}

/* Applies the hotp, digits, period and counter options to *e; returns the
 * ADD_FIELD_* code for an out-of-range value. */
static enum add_field_err fill_entry_params(const options *o, zotpcli_entry *e)
{
    if (o->hotp) e->kind = ZOTPCLI_HOTP;
    if (o->have_digits) {
        if (o->digits < ZOTPCLI_MIN_DIGITS || o->digits > ZOTPCLI_MAX_DIGITS)
            return ADD_FIELD_DIGITS;
        e->digits = (unsigned)o->digits;
    }
    if (o->have_period) {
        if (o->period == 0 || o->period > ZOTPCLI_MAX_PERIOD)
            return ADD_FIELD_PERIOD;
        e->period = (unsigned)o->period;
    }
    if (o->have_counter) e->counter = o->counter;
    return ADD_FIELD_OK;
}

/* Loads the store into *s, adds *e and saves; sets *past_load once the store
 * loaded (or was absent), marking later errors as add/save failures. */
static zotpcli_err store_add_entry(const options *o, const zotpcli_entry *e,
                                   zotpcli_store *s, bool *past_load)
{
    zotpcli_err ze = load_store(o->store_path, o->passphrase, s);
    if (ze != ZOTPCLI_OK && ze != ZOTPCLI_ERR_NOTFOUND) return ze;
    *past_load = true;
    ze = zotpcli_store_add(s, e);
    if (ze == ZOTPCLI_OK) ze = save_store(o->store_path, o->passphrase, s);
    return ze;
}

static int cmd_add(const options *o)
{
    if (!o->label || !o->secret) {
        zlog_error(&g_log, "add requires --label and --secret");
        return 2;
    }
    zotpcli_entry e;
    zotpcli_entry_init(&e);
    zotpcli_err ze = ZOTPCLI_OK;
    enum add_field_err fe = fill_entry_identity(o, &e, &ze);
    if (fe == ADD_FIELD_LABEL) {
        zlog_error(&g_log, "label too long");
        return 2;
    }
    if (fe == ADD_FIELD_ISSUER) {
        zlog_error(&g_log, "issuer too long");
        return 2;
    }
    if (fe == ADD_FIELD_SECRET) {
        zlog_error(&g_log, zotpcli_err_str(ze));
        return 1;
    }
    fe = fill_entry_params(o, &e);
    if (fe == ADD_FIELD_DIGITS) {
        zlog_error(&g_log, "digits out of range (6..8)");
        return 2;
    }
    if (fe == ADD_FIELD_PERIOD) {
        zlog_error(&g_log, "period out of range");
        return 2;
    }
    zotpcli_store s;
    if (zotpcli_store_init(&s) != ZOTPCLI_OK) return 1;
    bool past_load = false;
    ze = store_add_entry(o, &e, &s, &past_load);
    if (ze == ZOTPCLI_OK) {
        zlog_info(&g_log, "entry added");
    } else if (past_load) {
        zlog_error(&g_log, zotpcli_err_str(ze));
    }
    zotpcli_store_free(&s);
    return ze == ZOTPCLI_OK ? 0 : 1;
}

static int cmd_import(const options *o)
{
    if (o->narg < 1) {
        zlog_error(&g_log, "import requires an otpauth:// URI argument");
        return 2;
    }
    zotpcli_entry e;
    zotpcli_err ze = zotpcli_otpauth_parse(o->arg[0], &e);
    if (ze != ZOTPCLI_OK) {
        zlog_error(&g_log, zotpcli_err_str(ze));
        return 1;
    }
    zotpcli_store s;
    if (zotpcli_store_init(&s) != ZOTPCLI_OK) return 1;
    ze = load_store(o->store_path, o->passphrase, &s);
    if (ze != ZOTPCLI_OK && ze != ZOTPCLI_ERR_NOTFOUND) goto fail;
    ze = zotpcli_store_add(&s, &e);
    if (ze == ZOTPCLI_OK) ze = save_store(o->store_path, o->passphrase, &s);
    if (ze == ZOTPCLI_OK) {
        char msg[ZOTPCLI_MAX_LABEL + 32];
        zfmt f;
        zfmt_init(&f, msg, sizeof msg);
        zfmt_str(&f, "imported ");
        zfmt_str(&f, e.label);
        zlog_info(&g_log, zfmt_cstr(&f));
    } else {
        zlog_error(&g_log, zotpcli_err_str(ze));
    }
fail:
    zotpcli_store_free(&s);
    return ze == ZOTPCLI_OK ? 0 : 1;
}

static int cmd_code(const options *o)
{
    if (o->narg < 1) {
        zlog_error(&g_log, "code requires a label");
        return 2;
    }
    zotpcli_store s;
    if (zotpcli_store_init(&s) != ZOTPCLI_OK) return 1;
    zotpcli_err ze = load_store(o->store_path, o->passphrase, &s);
    int rc = 1;
    if (ze != ZOTPCLI_OK) {
        zlog_error(&g_log, zotpcli_err_str(ze));
        goto out;
    }
    zotpcli_entry *e = zotpcli_store_find_mut(&s, o->arg[0]);
    if (!e) {
        zlog_error(&g_log, zotpcli_err_str(ZOTPCLI_ERR_NOTFOUND));
        goto out;
    }
    int64_t now = current_now(o);
    char code[ZOTPCLI_MAX_DIGITS + 1];
    if (!zotpcli_code(e, now, code)) {
        zlog_error(&g_log, "could not generate code");
        goto out;
    }
    if (e->kind == ZOTPCLI_TOTP) {
        /* Civil rendering of the end of the current time step. */
        uint64_t ctr = zotpcli_totp_counter(e, now);
        ztime_instant until = { (int64_t)((ctr + 1) * e->period), 0 };
        char when[32];
        char line[96];
        zfmt f;
        zfmt_init(&f, line, sizeof line);
        zfmt_str(&f, code);
        if (ztime_format(&until, when, sizeof when) > 0) {
            zfmt_str(&f, "  # valid until ");
            zfmt_str(&f, when);
        }
        puts(zfmt_cstr(&f));
    } else {
        puts(code);
        /* HOTP consumes the counter; persist the increment. */
        e->counter++;
        ze = save_store(o->store_path, o->passphrase, &s);
        if (ze != ZOTPCLI_OK) {
            zlog_error(&g_log, zotpcli_err_str(ze));
            goto out;
        }
    }
    rc = 0;
out:
    zotpcli_store_free(&s);
    return rc;
}

static int cmd_list(const options *o)
{
    zotpcli_store s;
    if (zotpcli_store_init(&s) != ZOTPCLI_OK) return 1;
    zotpcli_err ze = load_store(o->store_path, o->passphrase, &s);
    if (ze != ZOTPCLI_OK) {
        zlog_error(&g_log, zotpcli_err_str(ze));
        zotpcli_store_free(&s);
        return 1;
    }
    char line[320];
    for (size_t i = 0; i < zotpcli_store_count(&s); i++) {
        const zotpcli_entry *e = zotpcli_store_get(&s, i);
        zfmt f;
        zfmt_init(&f, line, sizeof line);
        zfmt_str(&f, e->label);
        zfmt_str(&f, "\t");
        zfmt_str(&f, e->kind == ZOTPCLI_HOTP ? "hotp" : "totp");
        if (e->issuer[0]) {
            zfmt_str(&f, "\t");
            zfmt_str(&f, e->issuer);
        }
        if (!zfmt_ok(&f)) {
            zlog_error(&g_log, "output truncated");
            break;
        }
        puts(line);
    }
    zotpcli_store_free(&s);
    return 0;
}

static int cmd_show(const options *o)
{
    if (o->narg < 1) {
        zlog_error(&g_log, "show requires a label");
        return 2;
    }
    zotpcli_store s;
    if (zotpcli_store_init(&s) != ZOTPCLI_OK) return 1;
    zotpcli_err ze = load_store(o->store_path, o->passphrase, &s);
    int rc = 1;
    if (ze != ZOTPCLI_OK) {
        zlog_error(&g_log, zotpcli_err_str(ze));
        goto out;
    }
    const zotpcli_entry *e = zotpcli_store_find(&s, o->arg[0]);
    if (!e) {
        zlog_error(&g_log, zotpcli_err_str(ZOTPCLI_ERR_NOTFOUND));
        goto out;
    }
    {
        char b32[216];
        char hex[2u * ZOTPCLI_MAX_SECRET + 1];
        if (zotpcli_b32_encode_secret(e->secret, e->secret_len, b32,
                                      sizeof b32) != ZOTPCLI_OK ||
            zhex_encode(e->secret, e->secret_len, hex) != ZHEX_OK) {
            zlog_error(&g_log, "render failed");
            goto out;
        }
        hex[2 * e->secret_len] = '\0';
        char line[512];
        zfmt f;
        zfmt_init(&f, line, sizeof line);
        zfmt_str(&f, "label:   "); zfmt_str(&f, e->label);
        zfmt_str(&f, "\ntype:    ");
        zfmt_str(&f, e->kind == ZOTPCLI_HOTP ? "hotp" : "totp");
        zfmt_str(&f, "\nissuer:  ");
        zfmt_str(&f, e->issuer[0] ? e->issuer : "(none)");
        zfmt_str(&f, "\ndigits:  "); zfmt_u64(&f, e->digits);
        zfmt_str(&f, "\nperiod:  "); zfmt_u64(&f, e->period);
        zfmt_str(&f, "\ncounter: "); zfmt_u64(&f, e->counter);
        zfmt_str(&f, "\nsecret base32: "); zfmt_str(&f, b32);
        zfmt_str(&f, "\nsecret hex:    "); zfmt_str(&f, hex);
        if (!zfmt_ok(&f)) {
            zlog_error(&g_log, "output truncated");
            goto out;
        }
        puts(line);
    }
    rc = 0;
out:
    zotpcli_store_free(&s);
    return rc;
}

static int cmd_remove(const options *o)
{
    if (o->narg < 1) {
        zlog_error(&g_log, "remove requires a label");
        return 2;
    }
    zotpcli_store s;
    if (zotpcli_store_init(&s) != ZOTPCLI_OK) return 1;
    zotpcli_err ze = load_store(o->store_path, o->passphrase, &s);
    int rc = 1;
    if (ze != ZOTPCLI_OK) {
        zlog_error(&g_log, zotpcli_err_str(ze));
        goto out;
    }
    if (!zotpcli_store_remove(&s, o->arg[0])) {
        zlog_error(&g_log, zotpcli_err_str(ZOTPCLI_ERR_NOTFOUND));
        goto out;
    }
    ze = save_store(o->store_path, o->passphrase, &s);
    if (ze != ZOTPCLI_OK) {
        zlog_error(&g_log, zotpcli_err_str(ze));
        goto out;
    }
    zlog_info(&g_log, "entry removed");
    rc = 0;
out:
    zotpcli_store_free(&s);
    return rc;
}

static int cmd_export(const options *o)
{
    if (o->pem) {
        /* Armor the exact store file bytes (base64 inside PEM). */
        zbuf raw;
        if (zbuf_init(&raw, ZOTPCLI_MAX_FILE) != ZBUF_OK) return 1;
        int frc = read_file(o->store_path, &raw);
        if (frc != 0) {
            zlog_error(&g_log, "store file unreadable");
            zbuf_free(&raw);
            return 1;
        }
        size_t need = zpem_encoded_len(zbuf_len(&raw), strlen(PEM_LABEL));
        char *pem = malloc(need + 1);
        if (!pem) {
            zbuf_free(&raw);
            zlog_error(&g_log, "out of memory");
            return 1;
        }
        size_t pem_len = 0;
        zpem_err pe = zpem_encode(PEM_LABEL, strlen(PEM_LABEL), raw.data,
                                  zbuf_len(&raw), pem, need + 1, &pem_len);
        zbuf_free(&raw);
        if (pe != ZPEM_OK) {
            free(pem);
            zlog_error(&g_log, zpem_err_str(pe));
            return 1;
        }
        fwrite(pem, 1, pem_len, stdout);
        free(pem);
        return 0;
    }

    zotpcli_store s;
    if (zotpcli_store_init(&s) != ZOTPCLI_OK) return 1;
    zotpcli_err ze = load_store(o->store_path, o->passphrase, &s);
    int rc = 1;
    if (ze != ZOTPCLI_OK) {
        zlog_error(&g_log, zotpcli_err_str(ze));
        goto out;
    }
    for (size_t i = 0; i < zotpcli_store_count(&s); i++) {
        char uri[ZOTPCLI_MAX_URI + 1];
        ze = zotpcli_otpauth_format(zotpcli_store_get(&s, i), uri,
                                    sizeof uri);
        if (ze != ZOTPCLI_OK) {
            zlog_error(&g_log, zotpcli_err_str(ze));
            goto out;
        }
        puts(uri);
    }
    rc = 0;
out:
    zotpcli_store_free(&s);
    return rc;
}

static int cmd_verify(const options *o)
{
    zotpcli_store s;
    if (zotpcli_store_init(&s) != ZOTPCLI_OK) return 1;
    zotpcli_err ze = load_store(o->store_path, o->passphrase, &s);
    if (ze != ZOTPCLI_OK) {
        zlog_error(&g_log, zotpcli_err_str(ze));
        zotpcli_store_free(&s);
        return 1;
    }
    char msg[96];
    zfmt f;
    zfmt_init(&f, msg, sizeof msg);
    zfmt_str(&f, "ok: integrity verified, ");
    zfmt_u64(&f, zotpcli_store_count(&s));
    zfmt_str(&f, " entries");
    puts(zfmt_cstr(&f));
    zotpcli_store_free(&s);
    return 0;
}

static int usage(void)
{
    static char buf[2048];
    size_t n = zarg_usage(g_spec, sizeof g_spec / sizeof g_spec[0],
                          "zotpcli [--opts] <add|import|code|list|show|"
                          "remove|export|verify> [args]", buf, sizeof buf);
    fwrite(buf, 1, n < sizeof buf ? n : sizeof buf - 1, stderr);
    return 2;
}

int main(int argc, char **argv)
{
    options o;
    if (parse_options(argc, argv, &o) != 0) return 2;
    if (o.help || !o.cmd) return usage();

    if (zstr_casecmp(o.cmd, "add") == 0) return cmd_add(&o);
    if (zstr_casecmp(o.cmd, "import") == 0) return cmd_import(&o);
    if (zstr_casecmp(o.cmd, "code") == 0) return cmd_code(&o);
    if (zstr_casecmp(o.cmd, "list") == 0) return cmd_list(&o);
    if (zstr_casecmp(o.cmd, "show") == 0) return cmd_show(&o);
    if (zstr_casecmp(o.cmd, "remove") == 0) return cmd_remove(&o);
    if (zstr_casecmp(o.cmd, "export") == 0) return cmd_export(&o);
    if (zstr_casecmp(o.cmd, "verify") == 0) return cmd_verify(&o);

    zlog_error(&g_log, "unknown command");
    return usage();
}
