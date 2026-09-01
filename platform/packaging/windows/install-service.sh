#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# purpose: Install the canonical native z23.exe as a supervised per-user task.

set -euo pipefail

die()
{
    printf 'windows-service: REFUSE: %s\n' "$*" >&2
    exit 2
}

case "$(uname -s 2>/dev/null || true)" in
    MINGW*|MSYS*) ;;
    *) die 'native Windows MSYS2 environment required' ;;
esac

ACTION=${1:-install}
SOURCE_BINARY=${Z23_WINDOWS_BINARY:-build/bin/z23.exe}
INSTALL_ROOT=${Z23_WINDOWS_INSTALL_ROOT:-${LOCALAPPDATA:-}/Z23}
TASK_NAME=${Z23_WINDOWS_TASK_NAME:-Z23}
START_AFTER_INSTALL=${Z23_WINDOWS_START_AFTER_INSTALL:-1}
WINDOWS_ROOT=${WINDIR:-${SystemRoot:-}}
test -n "$WINDOWS_ROOT" || die 'Windows system root is unavailable'
WINDOWS_SYSTEM=$(cygpath -u "$WINDOWS_ROOT/System32")
SCHTASKS=${Z23_WINDOWS_SCHTASKS:-$WINDOWS_SYSTEM/schtasks.exe}
WHOAMI=${Z23_WINDOWS_WHOAMI:-$WINDOWS_SYSTEM/whoami.exe}
ICACLS=${Z23_WINDOWS_ICACLS:-$WINDOWS_SYSTEM/icacls.exe}
POWERSHELL=${Z23_WINDOWS_POWERSHELL:-$WINDOWS_SYSTEM/WindowsPowerShell/v1.0/powershell.exe}

test -n "$INSTALL_ROOT" || die 'LOCALAPPDATA is unavailable; set Z23_WINDOWS_INSTALL_ROOT'
case "$TASK_NAME" in
    *[!A-Za-z0-9._-]*|'') die 'task name must contain only letters, digits, dot, underscore, or hyphen' ;;
esac

BIN_DIR=$INSTALL_ROOT/bin
DATA_DIR=$INSTALL_ROOT/data
INSTALLED_BINARY=$BIN_DIR/z23.exe
TASK_XML=$INSTALL_ROOT/z23-task.xml
IDENTITY_FILE=$INSTALL_ROOT/z23.exe.sha256

windows_path()
{
    cygpath -aw "$1"
}

xml_escape()
{
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g' -e "s/'/\&apos;/g"
}

task_call()
{
    MSYS2_ARG_CONV_EXCL='*' "$SCHTASKS" "$@"
}

current_sid()
{
    local line sid
    line=$(MSYS2_ARG_CONV_EXCL='*' "$WHOAMI" /user /fo csv /nh 2>/dev/null) ||
        die 'could not query the current Windows SID'
    sid=$(printf '%s\n' "$line" | tr -d '\r' |
        sed -n 's/^"[^"]*","\([^"]*\)".*$/\1/p')
    case "$sid" in
        S-1-*) printf '%s' "$sid" ;;
        *) die 'current Windows SID response was malformed' ;;
    esac
}

secure_tree()
{
    local sid=$1 entry entry_win user_grant system_grant list
    list=$(mktemp) || die 'could not allocate ACL work list'
    if ! find "$INSTALL_ROOT" -depth -print0 >"$list"; then
        rm -f -- "$list"
        die 'could not enumerate the install tree for ACL restriction'
    fi
    while IFS= read -r -d '' entry; do
        entry_win=$(windows_path "$entry")
        if test -d "$entry"; then
            user_grant="*$sid:(OI)(CI)F"
            system_grant='*S-1-5-18:(OI)(CI)F'
        else
            user_grant="*$sid:F"
            system_grant='*S-1-5-18:F'
        fi
        # Reset removes arbitrary explicit entries left by a prior owner or
        # permissive parent. Removing inheritance next leaves a blank,
        # protected DACL before the two exact authority grants are installed.
        MSYS2_ARG_CONV_EXCL='*' "$ICACLS" "$entry_win" /reset \
            >/dev/null || die "could not reset ACL: $entry"
        MSYS2_ARG_CONV_EXCL='*' "$ICACLS" "$entry_win" /inheritance:r \
            >/dev/null || die "could not disable ACL inheritance: $entry"
        MSYS2_ARG_CONV_EXCL='*' "$ICACLS" "$entry_win" \
            "/grant:r" "$user_grant" "/grant:r" "$system_grant" \
            >/dev/null || die "could not restrict ACL: $entry"
    done <"$list"
    rm -f -- "$list"
}

installed_process_running()
{
    test -x "$POWERSHELL" || die 'Windows PowerShell is unavailable'
    Z23_EXPECTED_BINARY=$(windows_path "$INSTALLED_BINARY") \
        MSYS2_ARG_CONV_EXCL='*' "$POWERSHELL" -NoProfile -NonInteractive \
        -Command '$p=$env:Z23_EXPECTED_BINARY; if (Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $p }) { exit 0 } else { exit 1 }'
}

write_task_xml()
{
    local sid=$1 exe_win data_win work_win sid_xml exe_xml data_xml work_xml
    sid_xml=$(printf '%s' "$sid" | xml_escape)
    exe_win=$(windows_path "$INSTALLED_BINARY")
    data_win=$(windows_path "$DATA_DIR")
    work_win=$(windows_path "$BIN_DIR")
    exe_xml=$(printf '%s' "$exe_win" | xml_escape)
    data_xml=$(printf '%s' "$data_win" | xml_escape)
    work_xml=$(printf '%s' "$work_win" | xml_escape)
    umask 077
    {
        printf '%s\n' '<?xml version="1.0"?>'
        printf '%s\n' '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        printf '%s\n' '  <RegistrationInfo><Description>Z23 native C23 full node (per-user)</Description></RegistrationInfo>'
        printf '%s\n' '  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>'"$sid_xml"'</UserId></LogonTrigger></Triggers>'
        printf '%s\n' '  <Principals><Principal id="Author"><UserId>'"$sid_xml"'</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>'
        printf '%s\n' '  <Settings>'
        printf '%s\n' '    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>'
        printf '%s\n' '    <AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>'
        printf '%s\n' '    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden>'
        printf '%s\n' '    <RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority>'
        printf '%s\n' '    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>'
        printf '%s\n' '  </Settings>'
        printf '%s\n' '  <Actions Context="Author"><Exec><Command>'"$exe_xml"'</Command><Arguments>-datadir=&quot;'"$data_xml"'&quot;</Arguments><WorkingDirectory>'"$work_xml"'</WorkingDirectory></Exec></Actions>'
        printf '%s\n' '</Task>'
    } >"$TASK_XML"
}

install_service()
{
    test -f "$SOURCE_BINARY" || die "canonical binary missing: $SOURCE_BINARY"
    test -x "$SOURCE_BINARY" || die "canonical binary is not executable: $SOURCE_BINARY"
    test -x "$SCHTASKS" || die 'schtasks.exe is unavailable'
    test -x "$WHOAMI" || die 'whoami.exe is unavailable'
    test -x "$ICACLS" || die 'icacls.exe is unavailable'

    local sid installed_hash staging
    sid=$(current_sid)
    umask 077
    mkdir -p "$BIN_DIR" "$DATA_DIR"
    secure_tree "$sid"

    if installed_process_running; then
        die 'installed node is running; request a graceful node shutdown before updating'
    fi
    staging=$BIN_DIR/.z23.exe.installing.$$
    trap 'rm -f -- "$staging"' EXIT HUP INT TERM
    cp -- "$SOURCE_BINARY" "$staging"
    tools/scripts/check_c23_node_binary.sh "$staging" >/dev/null ||
        die 'staged canonical binary failed the native dependency audit'
    installed_hash=$(sha256sum <"$staging" | awk '{print $1}')
    test -n "$installed_hash" || die 'could not hash the staged binary'
    mv -f -- "$staging" "$INSTALLED_BINARY"
    trap - EXIT HUP INT TERM
    printf '%s *%s\n' "$installed_hash" 'bin/z23.exe' >"$IDENTITY_FILE"
    write_task_xml "$sid"
    secure_tree "$sid"

    task_call /Create /F /TN "$TASK_NAME" /XML "$(windows_path "$TASK_XML")" >/dev/null ||
        die 'Task Scheduler registration failed'
    if test "$START_AFTER_INSTALL" = 1; then
        task_call /Run /TN "$TASK_NAME" >/dev/null || die 'Task Scheduler start failed'
    fi
    printf 'windows-service: PASS task=%s binary_sha256=%s datadir=%s\n' \
        "$TASK_NAME" "$installed_hash" "$(windows_path "$DATA_DIR")"
}

status_service()
{
    test -x "$SCHTASKS" || die 'schtasks.exe is unavailable'
    task_call /Query /TN "$TASK_NAME" /V /FO LIST
    test -f "$IDENTITY_FILE" || die 'installed binary identity receipt is missing'
    (cd "$INSTALL_ROOT" && sha256sum -c "$(basename "$IDENTITY_FILE")") ||
        die 'installed binary identity verification failed'
}

remove_service()
{
    test -x "$SCHTASKS" || die 'schtasks.exe is unavailable'
    if installed_process_running; then
        die 'installed node is running; request a graceful node shutdown before removal'
    fi
    if task_call /Query /TN "$TASK_NAME" >/dev/null 2>&1; then
        task_call /Delete /F /TN "$TASK_NAME" >/dev/null ||
            die 'Task Scheduler removal failed'
    fi
    printf 'windows-service: PASS task removed; datadir preserved at %s\n' \
        "$(windows_path "$DATA_DIR")"
}

case "$ACTION" in
    install) install_service ;;
    status) status_service ;;
    remove) remove_service ;;
    *) die 'usage: install-service.sh {install|status|remove}' ;;
esac
