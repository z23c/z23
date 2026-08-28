/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Windows child-process classification inside cold-start spawn. */

    wchar_t command[32768];
    size_t used = 0;
    command[0] = L'\0';
    for (size_t ai = 0; child_argv[ai]; ai++) {
        wchar_t arg[32768];
        int converted = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                             child_argv[ai], -1, arg,
                                             (int)(sizeof(arg) / sizeof(*arg)));
        if (converted <= 0 || (ai && used + 1 >= 32768)) {
            cold_start_reason_copy(reason, reason_n,
                                   "child argument conversion failed");
            return COLD_START_TRANSIENT;
        }
        if (ai)
            command[used++] = L' ';
        if (used + 2 >= 32768)
            return COLD_START_TRANSIENT;
        command[used++] = L'"';
        size_t slashes = 0;
        for (const wchar_t *p = arg;; p++) {
            if (*p == L'\\') {
                slashes++;
                continue;
            }
            size_t copies = slashes;
            if (*p == L'"' || *p == L'\0')
                copies *= 2;
            if (used + copies + 2 >= 32768)
                return COLD_START_TRANSIENT;
            while (copies--)
                command[used++] = L'\\';
            slashes = 0;
            if (*p == L'\0')
                break;
            if (*p == L'"')
                command[used++] = L'\\';
            command[used++] = *p;
        }
        command[used++] = L'"';
        command[used] = L'\0';
    }

    SECURITY_ATTRIBUTES sa = {.nLength = sizeof(sa),
                              .lpSecurityDescriptor = NULL,
                              .bInheritHandle = TRUE};
    HANDLE pipe_read = NULL;
    HANDLE pipe_write = NULL;
    if (!CreatePipe(&pipe_read, &pipe_write, &sa, 0) ||
        !SetHandleInformation(pipe_read, HANDLE_FLAG_INHERIT, 0)) {
        if (pipe_read) CloseHandle(pipe_read);
        if (pipe_write) CloseHandle(pipe_write);
        cold_start_reason_copy(reason, reason_n, "stderr pipe creation failed");
        return COLD_START_TRANSIENT;
    }
    STARTUPINFOW si = {.cb = sizeof(si),
                       .dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW,
                       .wShowWindow = SW_HIDE,
                       .hStdInput = GetStdHandle(STD_INPUT_HANDLE),
                       .hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE),
                       .hStdError = pipe_write};
    PROCESS_INFORMATION pi = {0};
    HANDLE job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    bool job_ok = job && SetInformationJobObject(
                              job, JobObjectExtendedLimitInformation, &limits,
                              sizeof(limits));
    BOOL spawned = job_ok && CreateProcessW(
        NULL, command, NULL, NULL, TRUE, CREATE_NO_WINDOW | CREATE_SUSPENDED,
        NULL, NULL, &si, &pi);
    CloseHandle(pipe_write);
    if (!spawned || !AssignProcessToJobObject(job, pi.hProcess) ||
        ResumeThread(pi.hThread) == (DWORD)-1) {
        if (spawned) {
            TerminateProcess(pi.hProcess, 127);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        CloseHandle(pipe_read);
        if (job) CloseHandle(job);
        cold_start_reason_copy(reason, reason_n, "CreateProcessW failed");
        return COLD_START_TRANSIENT;
    }
    CloseHandle(pi.hThread);
    char tail[COLD_START_TAIL_CAP + 1];
    size_t tail_len = 0;
    char chunk[1024];
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(pipe_read, chunk, sizeof(chunk), &got, NULL) || got == 0)
            break;
        (void)fwrite(chunk, 1, got, stderr);
        (void)fflush(stderr);
        cold_start_tail_append(tail, &tail_len, COLD_START_TAIL_CAP, chunk,
                               (size_t)got);
    }
    CloseHandle(pipe_read);
    DWORD waited = WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 127;
    bool exited = waited == WAIT_OBJECT_0 &&
                  GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(job);
    tail[tail_len] = '\0';
    if (exited && exit_code == 0)
        return COLD_START_OK;
    char refusal[COLD_START_REASON_MAX];
    if (cold_start_extract_refusal(tail, refusal, sizeof(refusal))) {
        cold_start_reason_copy(reason, reason_n, refusal);
        return COLD_START_BLOCKED;
    }
    char msg[96];
    if (exited)
        snprintf(msg, sizeof(msg), "child exited with code %lu",
                 (unsigned long)exit_code);
    else
        snprintf(msg, sizeof(msg), "child wait failed");
    cold_start_reason_copy(reason, reason_n, msg);
    LOG_WARN(COLD_START_SUBSYS, "%s", msg);
    return COLD_START_TRANSIENT;
