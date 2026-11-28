/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: fixed local fix-admission mode over the package verifier child rail.
 * Included after the existing child executor; never an independent runner. */

static bool pv_fix_admit_beneath(const char *parent, const char *child)
{
    size_t n = strlen(parent);
    if (n == 1 && parent[0] == '/') return child[1] != '\0';
    return strlen(child) > n && memcmp(parent, child, n) == 0 && child[n] == '/';
}

static bool pv_fix_admit_paths(char *source, char *build)
{
    struct stat st;
    if (strcmp(source, build) == 0 ||
        pv_fix_admit_beneath(source, build) || pv_fix_admit_beneath(build, source)) {
        fprintf(stderr, "fix-admit: source and build grants overlap\n");
        return false;
    }
    if (stat(source, &st) != 0 || !S_ISDIR(st.st_mode) ||
        stat(build, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "fix-admit: grants must be directories\n");
        return false;
    }
    return true;
}

static bool pv_fix_admit_llvm_name(const char *base)
{
    if (strncmp(base, "llvm-", 5) != 0 || !isdigit((unsigned char)base[5]))
        return false;
    for (const char *p = base + 5; *p; ++p)
        if (!isdigit((unsigned char)*p) && *p != '.') return false;
    return true;
}

static bool pv_fix_admit_toolchain_overlap(const char *toolchain,
                                           const char *source, const char *build)
{
    return !strcmp(toolchain, source) || !strcmp(toolchain, build) ||
           pv_fix_admit_beneath(toolchain, source) ||
           pv_fix_admit_beneath(toolchain, build) ||
           pv_fix_admit_beneath(source, toolchain) ||
           pv_fix_admit_beneath(build, toolchain);
}

static bool pv_fix_admit_toolchain_grant(
    const char *compiler, const char *source, const char *build,
    char toolchain[4096], struct os_sandbox_path_rule *rules,
    size_t *count, size_t cap)
{
    if (!realpath(compiler, toolchain)) return true;
    char *bin = strrchr(toolchain, '/');
    if (bin) *bin = '\0';
    bin = bin ? strrchr(toolchain, '/') : NULL;
    if (!bin || strcmp(bin, "/bin") != 0) return false;
    *bin = '\0';
    if (!strcmp(toolchain, "/usr") || !strcmp(toolchain, "/lib") ||
        pv_fix_admit_beneath("/usr", toolchain) ||
        pv_fix_admit_beneath("/lib", toolchain)) return true;
    const char *base = strrchr(toolchain, '/');
    base = base ? base + 1 : toolchain;
    if (!pv_fix_admit_llvm_name(base) ||
        pv_fix_admit_toolchain_overlap(toolchain, source, build) ||
        *count >= cap) return false;
    rules[(*count)++] = (struct os_sandbox_path_rule){
        .path = toolchain, .allow_read = true, .allow_execute = true };
    return true;
}

static int pv_fix_admit_outcome(const struct pv_run *run)
{
    if (!run->launched || run->sandbox_fail || run->timed_out ||
        run->headroom_exhausted || run->budget_exceeded ||
        !run->exited || run->term_signal != 0 ||
        (run->exited && run->exit_code == PV_CHILD_EXEC_FAIL)) {
        fprintf(stderr, "fix-admit: child setup, confinement or resource failure exit=%d signal=%d: %.512s\n",
                run->exit_code, run->term_signal, run->stderr_buf);
        return 5;
    }
    if (run->exited && run->exit_code == 0) return 0;
    /* Red evidence requires a completed test assertion exit, never a crash,
     * timeout or resource death (including signals without resource flags). */
    fprintf(stderr, "fix-admit: child failed exit=%d signal=%d: %.512s\n",
            run->exit_code, run->term_signal, run->stderr_buf);
    return 10;
}

/* argv: MODE SOURCE BUILD COMMAND [ARGS...]. Trusted caller derives argv;
 * package bytes never choose grants, environment or evidence paths. */
static int pv_fix_admit_mode(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr, "fix-admit: source, build and command required\n");
        return 5;
    }
    char source[4096], build[4096];
    if (!realpath(argv[2], source) || !realpath(argv[3], build)) {
        fprintf(stderr, "fix-admit: grant path unavailable\n");
        return 5;
    }
    if (!pv_fix_admit_paths(source, build)) return 5;
    if (os_sandbox_package_confinement() != OS_SANDBOX_PACKAGE_CONFINEMENT_LANDLOCK_SECCOMP) {
        fprintf(stderr, "fix-admit: qualified confinement unavailable\n");
        return 5;
    }
    bool compile = strcmp(argv[1], "--fix-admit-compile") == 0;
    struct os_sandbox_path_rule rules[PV_CHILD_GRANT_BASE_CAP + 1u];
    size_t count = pv_child_grants(source, build, NULL, 0, rules,
                                   PV_CHILD_GRANT_BASE_CAP);
    if (!count) {
        fprintf(stderr, "fix-admit: grant construction failed\n");
        return 5;
    }
    char toolchain[4096];
    if (compile && !pv_fix_admit_toolchain_grant(
            argv[4], source, build, toolchain, rules, &count,
            sizeof(rules) / sizeof(rules[0]))) return 5;
    char tmpdir[4200];
    int n = snprintf(tmpdir, sizeof(tmpdir), "TMPDIR=%s", build);
    if (n < 0 || (size_t)n >= sizeof(tmpdir)) {
        fprintf(stderr, "fix-admit: temporary path too long\n");
        return 5;
    }
    const char *const env[] = {tmpdir, "LANG=C", "TZ=UTC", NULL};
    const struct os_sandbox_rlimits limits = {
        .as_bytes = UINT64_C(512) * 1024u * 1024u, .cpu_seconds = 60,
        .nproc = PV_COMPILE_NPROC, .fsize_bytes = PV_TEST_FSIZE_BYTES,
        .nofile = PV_TEST_NOFILE, .core_bytes = 0,
    };
    g_pv_fix_admit = true;
    struct pv_run run = pv_run_child(compile ? PV_PROCESS_COMPILER : PV_PROCESS_TEST,
        (const char *const *)(argv + 4), build, &limits, true, rules, count, env, 60000);
    return pv_fix_admit_outcome(&run);
}
