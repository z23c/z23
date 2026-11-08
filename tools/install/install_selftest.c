/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * install_selftest - mutation tests for the install front door.
 *
 * The front door is two programs, and this harness drives both end to end:
 *
 *   platform/packaging/install/install.sh   the shim served at the domain. It
 *                                  names the machine, fetches ONE bootstrap
 *                                  binary, checks its SHA-256 against a baked
 *                                  digest, and runs it.
 *   build/bin/z23-bootstrap        the C23 program that shim fetches, which
 *                                  makes every decision the shim used to make:
 *                                  the three pin channels, their agreement
 *                                  rule, the platform refusal, the installer
 *                                  verification and the handoff.
 *
 * It lives out of install.sh on purpose: that script is served at the domain
 * and has to stay short enough that a careful person reads it before handing
 * it to a shell, so no test code ships in the bytes a stranger reads.
 *
 * Every verification either program performs is exercised in both directions:
 * the agreeing case installs, and each way of breaking agreement refuses
 * without the fetched installer ever being executed. Run from
 * `tools/scripts/install_z23.sh --selftest`, which the check-z23-release-install
 * lint gate already runs.
 *
 * The pure judgement inside the bootstrap (pin parsing, the agreement rule,
 * the platform triple, the DNS TXT wire format) is also proved by the
 * z23_front_door test group (tests/harness/src/test_z23_front_door.c), which
 * can feed it hostile datagrams byte by byte. This harness proves the same
 * decisions survive a real process, a real fork/exec and a real handoff.
 *
 * Usage: install_selftest [--root REPO]   run the front-door cases
 *        install_selftest --selftest      qualify signal handling and cleanup
 *
 * The scratch root is removed on exit and on SIGINT, SIGTERM and SIGHUP.
 * Z23_BOOTSTRAP_BIN overrides the bootstrap under test.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "install_selftest.h"

constexpr char ISF_MANIFEST_SHA[] = "1234567812345678123456781234567812345678123456781234567812345678";
constexpr char ISF_OTHER_SHA[] = "fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98";
constexpr char ISF_ZERO_SHA[] = "0000000000000000000000000000000000000000000000000000000000000000";

/* The scripts the harness writes. The curl, uname and stub programs run
 * under the minimal PATH built below, so each is POSIX sh. */
constexpr char ISF_ARGV_STUB[] = "#!/bin/sh\nprintf '%s\\n' \"$@\" >\"$Z23_FD_TEST_ARGV_LOG\"\n";
constexpr char ISF_TOUCH_STUB[] = "#!/bin/sh\ntouch \"$Z23_FD_TEST_ARGV_LOG\"\n";
constexpr char ISF_MOCK_CURL[] =
    "#!/bin/sh\n"
    "set -eu\n"
    "[ \"$#\" -eq 10 ] || exit 2\n"
    "[ \"$1\" = --connect-timeout ] && [ \"$3\" = --max-time ] || exit 2\n"
    "[ \"$5\" = --max-filesize ] && [ \"$7\" = -fsSL ] && [ \"$9\" = -o ] || exit 2\n"
    "max_bytes=\"$6\"; url=\"$8\"; dest=\"${10}\"\n"
    "printf '%s max-bytes=%s\\n' \"$url\" \"$max_bytes\" >>\"$Z23_FD_TEST_CURL_LOG\"\n"
    "case \"$url\" in\n"
    "    https://front.invalid/bootstrap/*/z23-bootstrap)\n"
    "        path=\"$Z23_FD_TEST_HTTP/boot/${Z23_FD_TEST_BOOTSTRAP:-z23-bootstrap}\" ;;\n"
    "    *) exit 22 ;;\n"
    "esac\n"
    "[ -f \"$path\" ] || exit 22\n"
    "[ \"$(wc -c <\"$path\")\" -le \"$max_bytes\" ] || exit 63\n"
    "cp -- \"$path\" \"$dest\"\n";
constexpr char ISF_MOCK_UNAME[] =
    "#!/bin/sh\n"
    "case \"${1:-}\" in\n"
    "    -s) echo \"${Z23_FD_TEST_UNAME_S:-Linux}\" ;;\n"
    "    -m) echo \"${Z23_FD_TEST_UNAME_M:-x86_64}\" ;;\n"
    "    *) echo \"${Z23_FD_TEST_UNAME_S:-Linux}\" ;;\n"
    "esac\n";

struct isf_ctx {
    const char *repo;
    const char *root;
    const char *front_door;
    const char *bootstrap;
    const char *boottmp;
    const char *out, *err, *argv, *curl;
    const char *good_pin, *other_pin, *zero_pin;
    char installer_sha[ISF_HEX_LEN + 1];
    char boot_sha[ISF_HEX_LEN + 1];
    int rc;
};

static struct isf_ctx isf_c;

static char *isf_r(const char *rel)
{
    return isf_fmt("%s/%s", isf_c.root, rel);
}

/* ---- assertions --------------------------------------------------------- */

static void isf_need(bool ok, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void isf_need(bool ok, const char *fmt, ...)
{
    va_list ap;
    char *msg;

    if (ok)
        return;
    va_start(ap, fmt);
    msg = isf_vfmt(fmt, ap);
    va_end(ap);
    isf_die("%s", msg);
}

static void isf_has(const char *path, const char *text, const char *msg)
{
    isf_need(isf_file_has(path, text), "%s", msg);
}

static void isf_lacks(const char *path, const char *text, const char *msg)
{
    isf_need(!isf_file_has(path, text), "%s", msg);
}

static void isf_has_line(const char *path, const char *line, const char *msg)
{
    isf_need(isf_file_has_line(path, line), "%s", msg);
}

static void isf_rc_is(int want, const char *msg)
{
    isf_need(isf_c.rc == want, "%s (rc=%d)", msg, isf_c.rc);
}

static void isf_write_or_die(const char *path, const char *text, unsigned mode)
{
    isf_need(isf_write_file(path, text, mode), "cannot write %s: %s", path, strerror(errno));
}

/* ---- preparation -------------------------------------------------------- */

static void isf_make_dirs(void)
{
    static const char *const dirs[] = {"http/front", "http/repo", "http/boot", "minbin", "unamebin",
                                       "dns", "resolv", "tmp"};

    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++)
        isf_need(isf_mkdir_p(isf_r(dirs[i])), "cannot create %s: %s", dirs[i], strerror(errno));
}

static void isf_make_scratch(void)
{
    const char *tmp = getenv("TMPDIR");
    char *dir = isf_fmt("%s/z23-front-door-selftest.XXXXXX", tmp != nullptr && *tmp != '\0' ? tmp : "/tmp");

    isf_need(mkdtemp(dir) != nullptr, "mktemp failed");
    isf_set_root(dir);
    isf_c.root = dir;
}

/* The real installer is never run here: a stub records the argv it was
 * handed, which is how the handoff (source, manifest digest, and one
 * attestation record per source) is proved. */
static void isf_make_installer(void)
{
    isf_write_or_die(isf_r("http/front/install_z23.sh"), ISF_ARGV_STUB, 0644);
    isf_need(isf_sha256_hex(isf_r("http/front/install_z23.sh"), isf_c.installer_sha), "cannot digest the stub");
    isf_c.good_pin = isf_fmt("z23-pin-v1:%s:%s", ISF_MANIFEST_SHA, isf_c.installer_sha);
    isf_c.other_pin = isf_fmt("z23-pin-v1:%s:%s", ISF_OTHER_SHA, isf_c.installer_sha);
    isf_c.zero_pin = isf_fmt("z23-pin-v1:%s:%s", ISF_ZERO_SHA, ISF_ZERO_SHA);
    isf_write_or_die(isf_r("http/front/tampered.sh"), ISF_TOUCH_STUB, 0644);
}

static void isf_make_pins(void)
{
    isf_write_or_die(isf_r("http/repo/RELEASE_PIN"), isf_fmt("%s\n", isf_c.good_pin), 0644);
    isf_write_or_die(isf_r("http/repo/RELEASE_PIN.other"), isf_fmt("%s\n", isf_c.other_pin), 0644);
    isf_write_or_die(isf_r("http/repo/RELEASE_PIN.html"), "<html>404</html>\n", 0644);
    isf_write_or_die(isf_r("http/repo/RELEASE_PIN.unset"), isf_fmt("%s\n", isf_c.zero_pin), 0644);
    isf_write_or_die(isf_r("dns/good"), isf_fmt("\"%s\"\n", isf_c.good_pin), 0644);
    isf_write_or_die(isf_r("dns/other"), isf_fmt("\"%s\"\n", isf_c.other_pin), 0644);
    isf_write_or_die(isf_r("dns/portal"), "\"this-domain-is-parked\"\n", 0644);
    isf_write_or_die(isf_r("dns/silent"), "", 0644);
    /* A container with no resolver configured at all. Nothing is mocked here:
     * the bootstrap reads this file with the same code that reads
     * /etc/resolv.conf and finds no nameserver in it. */
    isf_write_or_die(isf_r("resolv/empty.conf"), "", 0644);
}

/* The bootstrap the shim is supposed to fetch. A stub, because what the shim
 * must prove is the digest gate and the argv forwarding, not what the real
 * bootstrap then decides; that is proved directly in part 2. */
static void isf_make_boot_stub(void)
{
    isf_write_or_die(isf_r("http/boot/z23-bootstrap"), ISF_ARGV_STUB, 0644);
    isf_need(isf_sha256_hex(isf_r("http/boot/z23-bootstrap"), isf_c.boot_sha), "cannot digest the stub");
    /* case_cut_shim_installs replaces the served bootstrap with the one a real
     * release cut produced; this is the copy it puts back afterwards. */
    isf_need(isf_copy_file(isf_r("http/boot/z23-bootstrap"), isf_r("http/boot/z23-bootstrap.orig")),
             "cannot copy the stub");
    isf_write_or_die(isf_r("http/boot/tampered"), ISF_TOUCH_STUB, 0644);
}

static void isf_link_tool(const char *name, const char *source_name)
{
    char *found = isf_find_in_path(source_name, getenv("PATH"));

    isf_need(found != nullptr, "required tool not found on PATH: %s", source_name);
    isf_need(symlink(found, isf_r(isf_fmt("minbin/%s", name))) == 0, "cannot link %s: %s", name, strerror(errno));
}

/* A SHA-256 tool the shim can use on this machine, in the order the shim
 * prefers them. shasum is a perl program, so it brings perl along. */
static void isf_link_digest_tool(void)
{
    const char *path = getenv("PATH");

    if (isf_find_in_path("sha256sum", path) != nullptr) {
        isf_link_tool("sha256sum", "sha256sum");
    } else if (isf_find_in_path("shasum", path) != nullptr && isf_find_in_path("perl", path) != nullptr) {
        isf_link_tool("shasum", "shasum");
        isf_link_tool("perl", "perl");
    } else {
        isf_link_tool("openssl", "openssl");
    }
}

/* A deliberately minimal PATH: exactly the commands install.sh may use on a
 * bare machine, plus bash, which the bootstrap requires before it hands off
 * to the bash installer. Nothing else is reachable, so a missing tool is a
 * real condition here and not a mocked one. */
static void isf_make_tools(void)
{
    static const char *const tools[] = {"sh", "bash", "uname", "mktemp", "rm", "cp", "cat", "sed", "cut", "wc", "chmod"};

    for (size_t i = 0; i < sizeof tools / sizeof tools[0]; i++)
        isf_link_tool(tools[i], tools[i]);
    isf_link_digest_tool();
    isf_write_or_die(isf_r("minbin/curl"), ISF_MOCK_CURL, 0755);
    isf_write_or_die(isf_r("unamebin/uname"), ISF_MOCK_UNAME, 0755);
}

static void isf_prepare(void)
{
    const char *over = getenv("Z23_BOOTSTRAP_BIN");

    isf_make_scratch();
    isf_make_dirs();
    isf_make_installer();
    isf_make_pins();
    isf_make_boot_stub();
    isf_make_tools();
    isf_c.front_door = isf_fmt("%s/platform/packaging/install/install.sh", isf_c.repo);
    isf_c.bootstrap = over != nullptr && *over != '\0' ? over : isf_fmt("%s/build/bin/z23-bootstrap", isf_c.repo);
    isf_need(access(isf_c.bootstrap, X_OK) == 0,
             "the C23 bootstrap is missing at %s — run `make z23-bootstrap`", isf_c.bootstrap);
}

/* ---- running a program with a fixed environment ------------------------- */

static void isf_add_extras(struct isf_env *env, va_list ap)
{
    for (const char *kv = va_arg(ap, const char *); kv != nullptr; kv = va_arg(ap, const char *))
        isf_env_add(env, kv);
}

static void isf_name_case(const char *name)
{
    isf_c.out = isf_r(isf_fmt("%s.out", name));
    isf_c.err = isf_r(isf_fmt("%s.err", name));
    isf_c.argv = isf_r(isf_fmt("%s.argv", name));
    isf_c.curl = isf_r(isf_fmt("%s.curl", name));
    isf_need(isf_rm_rf(isf_c.argv), "cannot remove %s", isf_c.argv);
}

static int isf_exec(const char *exe, char *const argv[], const struct isf_env *env, const char *out,
                    const char *err)
{
    struct isf_job job = {.path = exe, .argv = argv, .envp = (char *const *)env->kv, .out_path = out, .err_path = err};

    return isf_run(&job);
}

/* ══ Part 1: the shim served at the domain ═════════════════════════════════
 * isf_run_shim(case, path-prefix, KEY=VALUE..., nullptr) */
static void isf_run_shim(const char *name, const char *path_prefix, ...)
{
    struct isf_env env = {};
    const char *root = isf_c.root;
    char *path = isf_fmt("%s%s/unamebin:%s/minbin", path_prefix, root, root);
    char *sh = isf_find_in_path("sh", path);
    char *argv[] = {(char *)"sh", (char *)isf_c.front_door, (char *)"--print-pin", nullptr};
    va_list ap;

    isf_need(sh != nullptr, "no sh on the shim PATH");
    isf_name_case(name);
    isf_write_or_die(isf_c.curl, "", 0644);
    isf_env_set(&env, "PATH", path);
    isf_env_set(&env, "HOME", root);
    isf_env_set(&env, "TMPDIR", root);
    isf_env_set(&env, "Z23_FD_TEST_HTTP", isf_r("http"));
    isf_env_set(&env, "Z23_FD_TEST_ARGV_LOG", isf_c.argv);
    isf_env_set(&env, "Z23_FD_TEST_CURL_LOG", isf_c.curl);
    isf_env_set(&env, "Z23_INSTALL_TEST_ORIGIN", "https://front.invalid");
    va_start(ap, path_prefix);
    isf_add_extras(&env, ap);
    va_end(ap);
    isf_c.rc = isf_exec(sh, argv, &env, isf_c.out, isf_c.err);
}

/* The sentinel is the whole reason this scaffold is safe to serve today: no
 * bootstrap is published, so the shim must refuse before it touches a network. */
static void isf_case_shim_sentinel(void)
{
    /* Exercise the one currently published platform even when this self-test
     * runs natively on an unpublished Mac. Platform refusal is a separate
     * case below; it must not hide the all-zero sentinel branch here. */
    isf_run_shim("shim-sentinel", isf_r("unamebin:"), "Z23_FD_TEST_UNAME_S=Linux",
                 "Z23_FD_TEST_UNAME_M=x86_64", nullptr);
    isf_rc_is(1, "the all-zero bootstrap digest must refuse");
    isf_has(isf_c.err, "no Z23 bootstrap is pinned into this script yet", "the sentinel refusal must say nothing is pinned");
    isf_need(!isf_file_nonempty(isf_c.curl), "the sentinel refusal still made a request");
    isf_say("PASS the all-zero bootstrap digest refuses before any request");
}

static void isf_case_shim_platform(void)
{
    char *boot_sha = isf_fmt("Z23_INSTALL_TEST_BOOT_SHA256=%s", isf_c.boot_sha);

    isf_run_shim("shim-platform", isf_r("unamebin:"), "Z23_FD_TEST_UNAME_S=Darwin",
                 "Z23_FD_TEST_UNAME_M=arm64", boot_sha, nullptr);
    isf_rc_is(1, "an unpublished platform must refuse");
    isf_has(isf_c.err, "no Z23 bootstrap is published for darwin-arm64", "the refusal must name this machine");
    isf_has(isf_c.err, "published: linux-x86_64", "the refusal must name what we do publish");
    isf_need(!isf_file_nonempty(isf_c.curl), "an unpublished platform still made a request");
    isf_say("PASS the shim refuses an unpublished platform by name, before any request");
}

static void isf_case_shim_digest(void)
{
    char *boot_sha = isf_fmt("Z23_INSTALL_TEST_BOOT_SHA256=%s", isf_c.boot_sha);

    isf_run_shim("shim-tampered", "", boot_sha, "Z23_FD_TEST_BOOTSTRAP=tampered", nullptr);
    isf_rc_is(1, "a swapped bootstrap must refuse");
    isf_has(isf_c.err, "bootstrap digest mismatch", "a swapped bootstrap must name the digest mismatch");
    isf_need(!isf_is_file(isf_c.argv), "a swapped bootstrap was executed anyway");

    isf_run_shim("shim-handoff", "", boot_sha, nullptr);
    isf_need(isf_c.rc == 0, "a matching bootstrap must run (rc=%d): %s", isf_c.rc, isf_slurp_trim(isf_c.err));
    isf_need(isf_is_file(isf_c.argv), "a matching bootstrap never ran");
    isf_has_line(isf_c.argv, "--print-pin", "the shim must forward its argv to the bootstrap");
    isf_has(isf_c.curl, "z23-bootstrap max-bytes=33554432", "the bootstrap fetch was not bounded");
    isf_say("PASS the fetched bootstrap is digest-verified before it runs, and gets our argv");
}

/* The release cut and the shim have to agree about the digest. Every case
 * above hands the shim its digest through Z23_INSTALL_TEST_BOOT_SHA256, which
 * proves the comparison but says nothing about where a real digest comes
 * from. It comes from `build_release.sh --front-door`, which packages the
 * bootstrap and stamps its SHA-256 into a COPY of this shim. If the stamp and
 * the packaged bytes ever disagreed, every install would refuse with "digest
 * mismatch" and the pair would still each look correct on their own. So run
 * the real cut and then run the shim it produced, with no override at all. */
static const char *isf_find_true(void)
{
    static const char *const candidates[] = {"/usr/bin/true", "/bin/true"};

    for (size_t i = 0; i < sizeof candidates / sizeof candidates[0]; i++)
        if (access(candidates[i], X_OK) == 0)
            return candidates[i];
    return nullptr;
}

static void isf_cut_front_door(const char *cutbin, const char *cut)
{
    char *script = isf_fmt("%s/platform/packaging/release/build_release.sh", isf_c.repo);
    char *err = isf_r("cut.err");
    char *argv[] = {script, (char *)"--front-door", (char *)"--bin", (char *)cutbin,
                    (char *)"--out", (char *)cut, nullptr};
    struct isf_job job = {.path = script, .argv = argv, .out_path = "/dev/null", .err_path = err};
    int rc = isf_run(&job);

    isf_need(rc == 0, "the front-door cut refused a complete input: %s", isf_slurp_trim(err));
}

static void isf_check_cut_shim(const char *cut)
{
    char *cut_boot = isf_fmt("%s/bootstrap/linux-x86_64/z23-bootstrap", cut);

    isf_need(!isf_file_has_line(isf_fmt("%s/install.sh", cut), "BOOT_LINUX_X86_64=\"$BOOT_ZERO\""),
             "the cut shim still carries the sentinel");
    isf_need(isf_copy_file(cut_boot, isf_r("http/boot/z23-bootstrap")), "cannot serve the cut bootstrap");
    isf_c.front_door = isf_fmt("%s/install.sh", cut);
    isf_run_shim("cut-handoff", "", nullptr);
    isf_need(isf_c.rc == 0, "the cut shim refused the bytes the same cut packaged (rc=%d): %s", isf_c.rc,
             isf_slurp_trim(isf_c.err));

    /* ...and the stamp is a real check, not a formality: one changed byte in
     * the served bootstrap and the same cut shim refuses. */
    isf_need(isf_copy_file(isf_r("http/boot/tampered"), isf_r("http/boot/z23-bootstrap")), "cannot serve the tampered bootstrap");
    isf_run_shim("cut-tampered", "", nullptr);
    isf_rc_is(1, "the cut shim accepted bytes it did not name");
    isf_has(isf_c.err, "bootstrap digest mismatch", "the cut shim must name the digest mismatch");
}

static void isf_case_cut_shim_installs(void)
{
    const char *saved = isf_c.front_door;
    const char *truebin = isf_find_true();
    char *cut = isf_r("cut");
    char *cutbin = isf_r("cutbin");

    isf_need(isf_mkdir_p(cutbin), "cannot create %s", cutbin);
    /* A real ELF, because the only currently published front-door bootstrap is
     * linux-x86_64 and the cutter correctly refuses to relabel a native Mach-O
     * as ELF. true(1) also ignores argv and exits 0, which is all the handoff
     * needs here; argv forwarding is proved by case_shim_digest above. */
    isf_need(truebin != nullptr, "no true(1) binary to stand in for a bootstrap");
    if (!isf_starts_with_elf_magic(truebin)) {
        isf_say("UNOBSERVED Linux front-door cut: host true(1) is not ELF");
        return;
    }
    isf_need(isf_copy_file(truebin, isf_fmt("%s/z23-bootstrap", cutbin)), "cannot copy %s", truebin);
    isf_need(chmod(isf_fmt("%s/z23-bootstrap", cutbin), 0755) == 0, "cannot chmod the stand-in");
    isf_cut_front_door(cutbin, cut);
    isf_check_cut_shim(cut);
    isf_c.front_door = saved;
    isf_need(isf_copy_file(isf_r("http/boot/z23-bootstrap.orig"), isf_r("http/boot/z23-bootstrap")),
             "cannot restore the served bootstrap");
    isf_say("PASS a real release cut stamps a digest the shim then accepts, and only that one");
}

/* ══ Part 2: the C23 bootstrap, end to end ═════════════════════════════════
 * isf_run_boot(case, KEY=VALUE..., nullptr): a real process, real files, a
 * real fork/exec of the verified installer. */
static char *isf_kv(const char *key, const char *value)
{
    return isf_fmt("%s=%s", key, value);
}

static void isf_run_boot(const char *name, ...)
{
    struct isf_env env = {};
    const char *root = isf_c.root;
    char *tmp = isf_r(isf_fmt("tmp/%s", name));
    char *argv[] = {(char *)isf_c.bootstrap, nullptr};
    va_list ap;

    isf_name_case(name);
    isf_need(isf_rm_rf(tmp) && isf_mkdir_p(tmp), "cannot prepare %s", tmp);
    isf_c.boottmp = tmp;
    isf_env_set(&env, "PATH", isf_r("minbin"));
    isf_env_set(&env, "HOME", root);
    isf_env_set(&env, "TMPDIR", tmp);
    isf_env_set(&env, "Z23_FD_TEST_ARGV_LOG", isf_c.argv);
    isf_env_set(&env, "Z23_INSTALL_TEST_ORIGIN", isf_fmt("file://%s/http/front", root));
    isf_env_set(&env, "Z23_INSTALL_TEST_PIN_REPO_URL", isf_fmt("file://%s/http/repo/RELEASE_PIN", root));
    isf_env_set(&env, "Z23_INSTALL_TEST_RESOLV_CONF", isf_r("resolv/empty.conf"));
    isf_env_set(&env, "Z23_INSTALL_TEST_UNAME_S", "Linux");
    isf_env_set(&env, "Z23_INSTALL_TEST_UNAME_M", "x86_64");
    va_start(ap, name);
    isf_add_extras(&env, ap);
    va_end(ap);
    isf_c.rc = isf_exec(isf_c.bootstrap, argv, &env, isf_c.out, isf_c.err);
}

static char *isf_baked(const char *pin)
{
    return isf_kv("Z23_INSTALL_TEST_BAKED_PIN", pin);
}

static char *isf_dns(const char *name)
{
    return isf_kv("Z23_INSTALL_TEST_DNS", isf_r(isf_fmt("dns/%s", name)));
}

static char *isf_repo_pin(const char *name)
{
    return isf_kv("Z23_INSTALL_TEST_PIN_REPO_URL", isf_fmt("file://%s/http/repo/%s", isf_c.root, name));
}

/* Direction 1: everything agrees, and the handoff carries the evidence. */
static void isf_case_boot_all_agree(void)
{
    isf_run_boot("boot-all-agree", isf_baked(isf_c.good_pin), isf_dns("good"), nullptr);
    isf_need(isf_c.rc == 0, "three agreeing sources must install (rc=%d): %s", isf_c.rc, isf_slurp_trim(isf_c.err));
    isf_need(isf_is_file(isf_c.argv), "three agreeing sources never reached the installer");
    isf_has_line(isf_c.argv, isf_fmt("--manifest-sha256=%s", ISF_MANIFEST_SHA),
                 "the agreed manifest digest was not handed to the installer");
    isf_has_line(isf_c.argv, isf_fmt("--source=file://%s/http/front/release/linux-x86_64", isf_c.root),
                 "the release source was not handed to the installer");
    for (const char *const *o = (const char *const[]){"baked", "dns", "repo", nullptr}; *o != nullptr; o++)
        isf_has_line(isf_c.argv, isf_fmt("--attest=%s=%s", *o, isf_c.good_pin),
                     isf_fmt("attestation for %s was not passed through", *o));
    isf_lacks(isf_c.err, "agreed by", "a full quorum must not announce a degraded one");
    isf_say("PASS all three sources agree -> installs, evidence passed through");
}

/* Runs the bootstrap with exactly the given environment entries. */
static int isf_boot_with(const char *out, const char *err, const char *const *kv, const char *const *args)
{
    struct isf_env env = {};
    char *argv[4] = {(char *)isf_c.bootstrap, nullptr, nullptr, nullptr};

    for (; *kv != nullptr; kv++)
        isf_env_add(&env, *kv);
    for (size_t i = 0; args[i] != nullptr; i++)
        argv[i + 1] = (char *)args[i];
    return isf_exec(isf_c.bootstrap, argv, &env, out, err);
}

/* Exercise install modes against the same pinned argv-recording installer;
 * these modes must not introduce a new provenance or transport bypass. */
static void isf_apps_run(const char *name, const char *const *args,
                         const char *dns, const char *origin)
{
    isf_name_case(name);
    char *tmp = isf_r(isf_fmt("tmp/%s", name));
    isf_need(isf_rm_rf(tmp) && isf_mkdir_p(tmp), "cannot prepare %s", tmp);
    isf_c.boottmp = tmp;
    const char *kv[] = {
        isf_kv("PATH", isf_r("minbin")), isf_kv("HOME", isf_c.root), isf_kv("TMPDIR", tmp),
        isf_kv("Z23_FD_TEST_ARGV_LOG", isf_c.argv),
        isf_kv("Z23_INSTALL_TEST_ORIGIN", isf_fmt("file://%s", origin)),
        isf_repo_pin("RELEASE_PIN"), isf_dns(dns), isf_baked(isf_c.good_pin),
        isf_kv("Z23_INSTALL_TEST_RESOLV_CONF", isf_r("resolv/empty.conf")),
        "Z23_INSTALL_TEST_UNAME_S=Linux", "Z23_INSTALL_TEST_UNAME_M=x86_64", nullptr};
    isf_c.rc = isf_boot_with(isf_c.out, isf_c.err, kv, args);
}

static void isf_apps_handoff(bool apps)
{
    const char *args[] = {apps ? "--apps" : nullptr, nullptr};
    isf_apps_run(apps ? "apps-exact" : "default-exact", args, "good", isf_r("http/front"));
    isf_rc_is(0, "agreed, verified installer must run");
    const char *expected = isf_fmt(
        "--source=file://%s/http/front/release/linux-x86_64\n--manifest-sha256=%s\n"
        "--attest=baked=%s\n--attest=dns=%s\n--attest=repo=%s%s",
        isf_c.root, ISF_MANIFEST_SHA, isf_c.good_pin, isf_c.good_pin, isf_c.good_pin,
        apps ? "\n--apps" : "");
    isf_need(isf_is_file(isf_c.argv) && !strcmp(isf_slurp_trim(isf_c.argv), expected),
             "installer argv must be exact, with --apps only when requested");
    isf_need(isf_dir_empty(isf_c.boottmp), "verified handoff leaked scratch");
}

static void isf_apps_bad_args(void)
{
    const char *cases[][3] = {
        {"--apps", "--apps", nullptr}, {"--print-pin", "--print-pin", nullptr},
        {"--apps", "--print-pin", nullptr}, {"--print-pin", "--apps", nullptr},
        {"--apps", "SENSITIVE_BOOTSTRAP_MARKER_9f3a", nullptr},
        {"--apps=1", nullptr, nullptr}};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        isf_apps_run(isf_fmt("apps-invalid-%zu", i), cases[i], "good", isf_r("http/front"));
        isf_rc_is(1, "unsupported, duplicate or conflicting modes must refuse");
        isf_has(isf_c.err, "unsupported bootstrap argument", "argument refusal must precede provenance work");
        isf_lacks(isf_c.err, "SENSITIVE_BOOTSTRAP_MARKER_9f3a", "extra argument must not be disclosed");
        isf_lacks(isf_c.out, "SENSITIVE_BOOTSTRAP_MARKER_9f3a", "extra argument must not be printed");
        isf_need(isf_dir_empty(isf_c.boottmp), "invalid mode created scratch");
        isf_need(!isf_is_file(isf_c.argv), "invalid mode ran installer");
    }
}

static void isf_apps_provenance(void)
{
    const char *apps[] = {"--apps", nullptr}, *print[] = {"--print-pin", nullptr};
    isf_apps_run("apps-disagree", apps, "other", isf_r("http/front"));
    isf_rc_is(1, "--apps must refuse disagreeing provenance");
    isf_has(isf_c.err, "disagree", "--apps must retain quorum refusal");
    isf_need(!isf_is_file(isf_c.argv), "disagreement ran installer");
    char *swap = isf_r("http/apps-swap");
    isf_need(isf_mkdir_p(swap) &&
        isf_copy_file(isf_r("http/front/tampered.sh"), isf_fmt("%s/install_z23.sh", swap)),
        "cannot stage tampered installer");
    isf_apps_run("apps-tampered", apps, "good", swap);
    isf_rc_is(1, "--apps must refuse unverified installer bytes");
    isf_has(isf_c.err, "installer digest mismatch", "--apps must retain digest verification");
    isf_need(!isf_is_file(isf_c.argv), "tampered installer ran");
    isf_apps_run("apps-pin-only", print, "good", isf_r("http/front"));
    isf_rc_is(0, "pin inspection must remain read-only");
    isf_need(!strcmp(isf_slurp_trim(isf_c.out), isf_c.good_pin), "pin output changed");
    isf_need(!isf_is_file(isf_c.argv), "pin inspection ran installer");
}

static void isf_case_boot_apps(void)
{
    isf_apps_handoff(false);
    isf_apps_handoff(true);
    isf_apps_bad_args();
    isf_apps_provenance();
    isf_say("PASS --apps forwards only after verified quorum; default and pin-only remain distinct");
}

static void isf_print_pin_resolves(const char *base[3])
{
    const char *kv[] = {base[0], base[1], base[2],
                        isf_kv("Z23_INSTALL_TEST_ORIGIN", isf_fmt("file://%s/http/front", isf_c.root)),
                        isf_kv("Z23_INSTALL_TEST_PIN_REPO_URL",
                               isf_fmt("file://%s/http/repo/RELEASE_PIN", isf_c.root)),
                        isf_kv("Z23_INSTALL_TEST_RESOLV_CONF", isf_r("resolv/empty.conf")),
                        isf_baked(isf_c.good_pin), isf_dns("good"), nullptr};
    const char *args[] = {"--print-pin", nullptr};

    isf_c.rc = isf_boot_with(isf_r("printpin.out"), isf_r("printpin.err"), kv, args);
    isf_rc_is(0, "--print-pin must resolve the channels");
    isf_has_line(isf_r("printpin.out"), isf_c.good_pin, "--print-pin must print the agreed pin and nothing else");
}

static void isf_print_pin_refusals(const char *base[3])
{
    static const char marker[] = "SENSITIVE_BOOTSTRAP_MARKER_9f3a";
    const char *bare[] = {base[0], base[1], base[2], nullptr};
    const char *bad[] = {marker, nullptr};
    const char *extra[] = {"--print-pin", marker, nullptr};
    char *extra_argv = isf_r("extra.argv");
    const char *with_log[] = {base[0], base[1], base[2], isf_kv("Z23_FD_TEST_ARGV_LOG", extra_argv),
                              isf_kv("Z23_INSTALL_TEST_ORIGIN", isf_fmt("file://%s/http/front", isf_c.root)),
                              isf_kv("Z23_INSTALL_TEST_PIN_REPO_URL",
                                     isf_fmt("file://%s/http/repo/RELEASE_PIN", isf_c.root)),
                              nullptr};

    isf_c.rc = isf_boot_with(isf_r("badarg.out"), isf_r("badarg.err"), bare, bad);
    isf_rc_is(1, "an unknown argument must refuse");
    isf_need(!isf_file_has(isf_r("badarg.out"), marker) && !isf_file_has(isf_r("badarg.err"), marker),
             "the sensitive argument was disclosed");
    isf_has(isf_r("badarg.err"), "unsupported bootstrap argument", "an unknown argument refusal must be explanatory");

    /* Even the diagnostic mode accepts exactly one switch. A sensitive marker
     * supplied as a second argument must never be echoed, and argc refusal must
     * happen before scratch creation, network access, or installer handoff. */
    isf_need(isf_rm_rf(isf_c.boottmp) && isf_mkdir_p(isf_c.boottmp), "cannot reset %s", isf_c.boottmp);
    isf_c.rc = isf_boot_with(isf_r("extra.out"), isf_r("extra.err"), with_log, extra);
    isf_rc_is(1, "--print-pin with an extra argument must refuse");
    isf_need(!isf_file_has(isf_r("extra.out"), marker) && !isf_file_has(isf_r("extra.err"), marker),
             "the sensitive extra argument was disclosed");
    isf_has(isf_r("extra.err"), "unsupported bootstrap argument",
            "the extra bootstrap argument refusal must be explanatory");
    isf_need(isf_dir_empty(isf_c.boottmp), "argument refusal created scratch state");
    isf_need(!isf_is_file(extra_argv), "argument refusal reached the installer handoff");
}

/* --print-pin is forwarded through the shim, so the bootstrap owns it. */
static void isf_case_boot_print_pin(void)
{
    char *tmp = isf_r("tmp/boot-print-pin");
    const char *base[3] = {isf_kv("PATH", isf_r("minbin")), isf_kv("HOME", isf_c.root), isf_kv("TMPDIR", tmp)};

    isf_need(isf_mkdir_p(tmp), "cannot create %s", tmp);
    isf_c.boottmp = tmp;
    isf_print_pin_resolves(base);
    isf_print_pin_refusals(base);
    isf_say("PASS --print-pin resolves the channels and installs nothing");
}

/* Direction 2: one source disagrees. Never a majority vote. */
static void isf_case_boot_disagreement(void)
{
    isf_run_boot("boot-dns-split", isf_baked(isf_c.good_pin), isf_dns("other"), nullptr);
    isf_rc_is(1, "a disagreeing DNS record must refuse");
    isf_has(isf_c.err, "release pin disagreement between baked and dns", "the disagreement must name both origins");
    isf_has(isf_c.err, isf_fmt("attested pin baked=%s", isf_c.good_pin),
            "the disagreement must print the pin each origin attested");
    isf_has(isf_c.err, isf_fmt("attested pin dns=%s", isf_c.other_pin), "the disagreement must print the dissenting pin");
    isf_need(!isf_is_file(isf_c.argv), "a disagreement still ran the installer");

    isf_run_boot("boot-repo-split", isf_baked(isf_c.good_pin), isf_dns("good"), isf_repo_pin("RELEASE_PIN.other"),
                 nullptr);
    isf_rc_is(1, "a disagreeing repository pin must refuse");
    isf_has(isf_c.err, "release pin disagreement between baked and repo",
            "the repository disagreement must name both origins");
    isf_need(!isf_is_file(isf_c.argv), "a repository disagreement still ran the installer");
    isf_say("PASS one dissenting source -> refuses, 2-against-1 never wins");
}

/* Unreachable is not disagreement, and two is the floor. */
static void isf_unreachable_dns(void)
{
    /* No resolver configured at all. Baked + repository still carry a quorum,
     * and the refusal-free path says out loud what was missing. */
    isf_run_boot("boot-no-resolver", isf_baked(isf_c.good_pin), nullptr);
    isf_need(isf_c.rc == 0, "two agreeing sources must install (rc=%d): %s", isf_c.rc, isf_slurp_trim(isf_c.err));
    isf_has(isf_c.err, "agreed by 2 of 3 sources (unreachable: dns=no-resolver)", "a degraded quorum must be announced");
    isf_has_line(isf_c.argv, "--attest-unreachable=dns=no-resolver",
                 "the unreachable source must be declared to the installer");

    /* A resolver that answers with nothing at all. */
    isf_run_boot("boot-dns-silent", isf_baked(isf_c.good_pin), isf_dns("silent"), nullptr);
    isf_need(isf_c.rc == 0, "an empty DNS answer must not break a real quorum");
    isf_has(isf_c.err, "unreachable: dns=no-answer", "an empty TXT answer must be reported as no-answer");

    /* A captive portal answers with something that is not a pin. That is
     * unreachable, NOT a disagreement. */
    isf_run_boot("boot-portal", isf_baked(isf_c.good_pin), isf_dns("portal"), nullptr);
    isf_need(isf_c.rc == 0, "a portal TXT answer must not break a real quorum");
    isf_has(isf_c.err, "unreachable: dns=malformed-answer", "a non-pin TXT answer must be reported as malformed");
    isf_lacks(isf_c.err, "disagreement", "a non-pin TXT answer was reported as a disagreement");
}

static void isf_unreachable_repo(void)
{
    /* An HTML error page from the repository host is the same class. */
    isf_run_boot("boot-repo-html", isf_baked(isf_c.good_pin), isf_repo_pin("RELEASE_PIN.html"), nullptr);
    isf_rc_is(1, "baked alone must not install");
    isf_has(isf_c.err, "release pin quorum: 1 of 3 sources answered", "a single answering source must be refused by count");
    isf_has(isf_c.err, "repo=malformed-answer", "an HTML answer must be reported as malformed");

    /* Nothing reachable but the baked value: still a refusal, never a silent
     * degradation to one source. */
    isf_run_boot("boot-alone", isf_baked(isf_c.good_pin), isf_repo_pin("MISSING"), nullptr);
    isf_rc_is(1, "one source must never be enough");
    isf_has(isf_c.err, "two independent sources are required", "the quorum refusal must state the requirement");
    isf_has(isf_c.err, "repo=fetch-failed", "an unreachable repository must be named with its reason");
    isf_need(!isf_is_file(isf_c.argv), "a failed quorum still ran the installer");
}

static void isf_unreachable_sentinels(void)
{
    /* No release pinned into the bootstrap at all: the sentinel is a missing
     * source, not a pin, and DNS + repository carry the quorum without it. */
    isf_run_boot("boot-unpinned", isf_baked(isf_c.zero_pin), isf_dns("good"), nullptr);
    isf_need(isf_c.rc == 0, "dns+repo must carry a quorum without a baked pin (rc=%d)", isf_c.rc);
    isf_has(isf_c.err, "unreachable: baked=no-release-pinned", "an unpinned bootstrap must say so");

    /* Before the first release is cut, the repository file carries the unset
     * sentinel. That is "nothing is pinned here", not a dissenting pin. */
    isf_run_boot("boot-repo-unset", isf_baked(isf_c.good_pin), isf_dns("good"), isf_repo_pin("RELEASE_PIN.unset"),
                 nullptr);
    isf_need(isf_c.rc == 0, "an unset repository pin must not break a real quorum (rc=%d)", isf_c.rc);
    isf_has(isf_c.err, "unreachable: repo=malformed-answer", "the unset sentinel must be reported as no pin");
    isf_lacks(isf_c.err, "disagreement", "the unset sentinel was reported as a disagreement");

    /* The checked-in repository pin must always be a well-formed pin record,
     * sentinel or real, or source 3 is dead the moment a release lands. */
    isf_need(isf_file_has_pin_line(isf_fmt("%s/platform/packaging/install/RELEASE_PIN", isf_c.repo)),
             "platform/packaging/install/RELEASE_PIN is not a z23-pin-v1 record");
}

static void isf_case_boot_unreachable(void)
{
    isf_unreachable_dns();
    isf_unreachable_repo();
    isf_unreachable_sentinels();
    isf_say("PASS unreachable is counted, named, and never called disagreement");
}

/* The installer's own bytes are pinned too. */
static void isf_case_boot_installer_digest(void)
{
    char *swap = isf_r("http/swap");

    isf_run_boot("boot-tampered", isf_baked(isf_c.good_pin), isf_dns("good"),
                 isf_kv("Z23_INSTALL_TEST_ORIGIN", isf_fmt("file://%s/http/front-tampered", isf_c.root)), nullptr);
    isf_rc_is(1, "an unfetchable installer must refuse");
    isf_has(isf_c.err, "could not fetch", "an unfetchable installer must say so");

    isf_need(isf_mkdir_p(swap), "cannot create %s", swap);
    isf_need(isf_copy_file(isf_r("http/front/tampered.sh"), isf_fmt("%s/install_z23.sh", swap)),
             "cannot stage the swapped installer");
    isf_run_boot("boot-swapped", isf_baked(isf_c.good_pin), isf_dns("good"),
                 isf_kv("Z23_INSTALL_TEST_ORIGIN", isf_fmt("file://%s", swap)), nullptr);
    isf_rc_is(1, "a swapped installer must refuse");
    isf_has(isf_c.err, "installer digest mismatch", "a swapped installer must name the digest mismatch");
    isf_need(!isf_is_file(isf_c.argv), "a swapped installer was executed anyway");
    isf_say("PASS the served installer is verified before it runs");
}

/* A machine we publish no runtime for is told so, by name. */
static void isf_case_boot_platform(void)
{
    isf_run_boot("boot-unpublished", isf_baked(isf_c.good_pin), isf_dns("good"), "Z23_INSTALL_TEST_UNAME_S=Darwin",
                 "Z23_INSTALL_TEST_UNAME_M=arm64", nullptr);
    isf_rc_is(1, "an unpublished platform must refuse");
    isf_has(isf_c.err, "no Z23 runtime is published for darwin-arm64", "the refusal must name this machine");
    isf_has(isf_c.err, "published: linux-x86_64", "the refusal must name what we do publish");
    /* Nothing was consulted and nothing was created: the scratch directory is
     * made only after this refusal can no longer happen, so an empty TMPDIR is
     * proof that no channel was read and no byte was written. */
    isf_lacks(isf_c.err, "release pin", "an unpublished platform still consulted the pin channels");
    isf_need(isf_dir_empty(isf_c.boottmp), "an unpublished platform still created scratch state");
    isf_say("PASS an unpublished platform is refused by name, before any request");
}

/* ---- entry -------------------------------------------------------------- */

static void isf_run_cases(void)
{
    isf_case_shim_sentinel();
    isf_case_shim_platform();
    isf_case_shim_digest();
    isf_case_cut_shim_installs();
    isf_case_boot_all_agree();
    isf_case_boot_apps();
    isf_case_boot_print_pin();
    isf_case_boot_disagreement();
    isf_case_boot_unreachable();
    isf_case_boot_installer_digest();
    isf_case_boot_platform();
    isf_say("front door selftest PASS");
}

[[noreturn]] static void isf_usage(void)
{
    fputs("usage: install_selftest [--root REPO | --selftest]\n", stderr);
    exit(2);
}

static char *isf_self_path(const char *argv0)
{
    char *found = strchr(argv0, '/') != nullptr ? isf_fmt("%s", argv0) : isf_find_in_path(argv0, getenv("PATH"));

    if (found == nullptr)
        isf_die("cannot locate %s", argv0);
    return found;
}

int main(int argc, char **argv)
{
    const char *repo = ".";
    bool signals = false;

    if (argc == 3 && strcmp(argv[1], "--hold-child") == 0)
        isf_hold_child(argv[2]);
    isf_signals_init();
    if (argc == 3 && strcmp(argv[1], "--root") == 0)
        repo = argv[2];
    else if (argc == 2 && strcmp(argv[1], "--selftest") == 0)
        signals = true;
    else if (argc != 1)
        isf_usage();
    if (isf_hold_requested()) {
        isf_make_scratch();
        isf_finish(isf_hold_main(isf_self_path(argv[0])));
    }
    if (signals)
        isf_finish(isf_signals_selftest(isf_self_path(argv[0])));
    isf_c.repo = repo;
    isf_prepare();
    isf_run_cases();
    isf_finish(0);
}
