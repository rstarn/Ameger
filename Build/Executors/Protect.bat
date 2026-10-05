@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem ---------------------------------------------------------------------------
rem Protect.bat - VMProtect orchestrator.
rem
rem Calls the two protection stages in order and aggregates their results. The
rem payload runs first: protecting it rewrites the PayloadSha256 pin, so the
rem launcher is protected against a release whose pin has already settled.
rem
rem Both stages fail closed and are individually idempotent, so a repeat run
rem that finds an unchanged protected binary is a no-op rather than a second
rem virtualization pass over already-virtualized code.
rem
rem Usage:
rem   Protect.bat              both stages
rem   Protect.bat dll          payload only
rem   Protect.bat exe          launcher only
rem   Protect.bat /nopause     suppress the pause (also CREATE_NO_PAUSE=1)
rem ---------------------------------------------------------------------------

set "NO_PAUSE=0"
if defined CREATE_NO_PAUSE set "NO_PAUSE=%CREATE_NO_PAUSE%"
if /i "%~1"=="/nopause" set "NO_PAUSE=1"

set "C_RESET="
set "C_GREEN="
set "C_RED="
set "C_YELLOW="
if /i not "%AMEGER_NO_COLOR%"=="1" for /f %%A in ('echo prompt $E ^| cmd') do set "ESC=%%A"
if defined ESC (
    set "C_RESET=%ESC%[0m"
    set "C_GREEN=%ESC%[92m"
    set "C_RED=%ESC%[91m"
    set "C_YELLOW=%ESC%[93m"
)

rem This script lives in Build\Executors\, so the repository root is two levels
rem up. Rooting at "%~dp0.." resolved to Build\ itself.
for %%I in ("%~dp0..\..") do set "ROOT=%%~fI"
set "BUILD_DIR=%ROOT%\Build"
set "OUT_ROOT=%BUILD_DIR%\Release"
set "DLL_DIR=%OUT_ROOT%\DLLs"
set "STAGE_DIR=%BUILD_DIR%\Executors\Protection"
set "PROTECT_DLL=%STAGE_DIR%\ProtectDLL.bat"
set "PROTECT_EXE=%STAGE_DIR%\ProtectEXE.bat"

set "STAGE=%~1"
if /i "%STAGE%"=="/nopause" set "STAGE="
if defined STAGE (
  if /i not "%STAGE%"=="dll" if /i not "%STAGE%"=="exe" (
    echo %C_RED%ERROR: unknown stage "%STAGE%"; use dll or exe.%C_RESET%
    goto :usage_error
  )
)

if not exist "%OUT_ROOT%" (
  echo   %C_RED%ERROR: release folder not found: %OUT_ROOT%%C_RESET%
  echo   %C_RED%       Run Create.bat before protecting anything.%C_RESET%
  goto :failure
)
if not exist "%PROTECT_DLL%" (
  echo   %C_RED%ERROR: missing stage script: %PROTECT_DLL%%C_RESET%
  goto :failure
)
if not exist "%PROTECT_EXE%" (
  echo   %C_RED%ERROR: missing stage script: %PROTECT_EXE%%C_RESET%
  goto :failure
)

echo [%C_GREEN%1%C_RESET%/%C_GREEN%3%C_RESET%] Preparing...
echo.
echo   %C_GREEN%[+]%C_RESET% Release:   %C_GREEN%%OUT_ROOT%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Stages:    %STAGE_DIR%
echo   %C_GREEN%[+]%C_RESET% Runtime:   %C_YELLOW%skipped by design (manual-mapped)%C_RESET%
echo.
echo.

set "DLL_RESULT=skipped"
set "EXE_RESULT=skipped"

if defined STAGE if /i "%STAGE%"=="exe" goto :run_exe

echo [%C_GREEN%2%C_RESET%/%C_GREEN%3%C_RESET%] Protecting payload...
echo.
call "%PROTECT_DLL%" /nopause
if errorlevel 1 (
  set "DLL_RESULT=failed"
  goto :summarize
)
set "DLL_RESULT=ok"

:run_exe
if defined STAGE if /i "%STAGE%"=="dll" goto :summarize
echo [%C_GREEN%2%C_RESET%/%C_GREEN%3%C_RESET%] Protecting launcher...
echo.
call "%PROTECT_EXE%" /nopause
if errorlevel 1 (
  set "EXE_RESULT=failed"
  goto :summarize
)
set "EXE_RESULT=ok"

:summarize
echo.
echo [%C_GREEN%3%C_RESET%/%C_GREEN%3%C_RESET%] Summary...
echo.
call :report "Payload" "%DLL_RESULT%"
call :report "Launcher" "%EXE_RESULT%"
echo.
if /i "%DLL_RESULT%"=="failed" goto :stage_failed
if /i "%EXE_RESULT%"=="failed" goto :stage_failed
echo Protection completed successfully.
echo.
echo Payload:     %C_GREEN%%DLL_DIR%\Jlov.dll%C_RESET%
echo Interface x64: %C_GREEN%%OUT_ROOT%\Host - x64.exe%C_RESET%
echo.
if "%NO_PAUSE%"=="0" pause
exit /b 0

:report
if /i "%~2"=="ok" (
  echo   %C_GREEN%OK%C_RESET%    %~1
  exit /b 0
)
if /i "%~2"=="skipped" (
  echo   %C_YELLOW%-  %C_RESET%   %~1 ^(skipped^)
  exit /b 0
)
echo   %C_RED%FAIL%C_RESET%  %~1
exit /b 0

:stage_failed
echo.
echo %C_RED%Protection failed; the release is not shippable.%C_RESET%
goto :failure

:usage_error
if "%NO_PAUSE%"=="0" pause
exit /b 1

:failure
if "%NO_PAUSE%"=="0" pause
exit /b 1