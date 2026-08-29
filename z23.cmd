@echo off
rem Copyright 2026 Rhett Creighton - Apache License 2.0
rem z23.cmd — Windows front-door wrapper for the Z23 C23 developer journey.
rem
rem This wrapper lives in the checkout root and intercepts the high-level
rem developer commands so they work from an ordinary Windows terminal without
rem manual MSYS2 or PATH setup. Every other command passes through to the
rem built native z23.exe.
rem
rem   z23 setup              bootstrap MSYS2 UCRT64, packages, and the build
rem   z23 new <name>         scaffold a new GUI app from packages/zhello
rem   z23 dev [name]         build and run the current or named GUI app
rem   z23 ship [name]        package the app for distribution
rem   z23 reproduce <root>   rebuild and verify a shipped app on this machine
rem   z23 <anything else>    delegate to build\bin\z23.exe

setlocal EnableDelayedExpansion

set "Z23_ROOT=%~dp0"
set "Z23_ROOT=%Z23_ROOT:~0,-1%"
set "Z23_BIN=%Z23_ROOT%\build\bin\z23.exe"
set "Z23_MSYS2_ROOT=%Z23_MSYS2_ROOT%"
if "%Z23_MSYS2_ROOT%"=="" set "Z23_MSYS2_ROOT=C:\msys64"
set "Z23_BASH=%Z23_MSYS2_ROOT%\usr\bin\bash.exe"
set "MSYSTEM=UCRT64"

if /i "%~1"=="setup" goto :do_setup
if /i "%~1"=="new" goto :do_new
if /i "%~1"=="dev" goto :do_dev
if /i "%~1"=="ship" goto :do_ship
if /i "%~1"=="reproduce" goto :do_reproduce

if not exist "%Z23_BIN%" (
    echo z23: no built binary at %Z23_BIN% >&2
    echo z23: run 'z23 setup' first, then 'make z23' in UCRT64. >&2
    exit /b 1
)
"%Z23_BIN%" %*
exit /b %ERRORLEVEL%

:do_setup
powershell.exe -ExecutionPolicy Bypass -File "%Z23_ROOT%\tools\scripts\windows_setup.ps1" -CheckoutRoot "%Z23_ROOT%"
exit /b %ERRORLEVEL%

:do_new
set "APP_NAME=%~2"
if "%APP_NAME%"=="" (
    echo z23 new: missing app name. Usage: z23 new ^<name^> >&2
    exit /b 1
)
call :require_bash
"%Z23_BASH%" -lc "cd \"$(cygpath -u \"$Z23_ROOT\")\" && make new-app NAME=\"$APP_NAME\""
exit /b %ERRORLEVEL%

:do_dev
set "APP_NAME=%~2"
if "%APP_NAME%"=="" (
    rem No app named; default to the first scaffolded GUI app, or zhello.
    for /f "usebackq delims=" %%a in (`powershell.exe -NoProfile -Command "if (Test-Path '%Z23_ROOT%\config\gui_apps.mk') { (Select-String -Path '%Z23_ROOT%\config\gui_apps.mk' -Pattern '^GUI_APPS \+= (\w+)$' | Select-Object -First 1).Matches.Groups[1].Value } else { 'zhello' }"`) do set "APP_NAME=%%a"
)
if "%APP_NAME%"=="" set "APP_NAME=zhello"
call :require_bash
"%Z23_BASH%" -lc "cd \"$(cygpath -u \"$Z23_ROOT\")\" && make %APP_NAME%"
exit /b %ERRORLEVEL%

:do_ship
echo z23 ship: Windows ship is not implemented in this slice; use 'make ^<app^>-app' in UCRT64. >&2
exit /b 1

:do_reproduce
echo z23 reproduce: Windows reproduce is not implemented in this slice. >&2
exit /b 1

:require_bash
if not exist "%Z23_BASH%" (
    echo z23: MSYS2 bash not found at %Z23_BASH% >&2
    echo z23: run 'z23 setup' first. >&2
    exit /b 1
)
exit /b 0
