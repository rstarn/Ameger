@echo off
setlocal EnableExtensions DisableDelayedExpansion

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

for %%I in ("%~dp0..") do set "ROOT=%%~fI"
set "BUILD_DIR=%ROOT%\Build"
set "OUT_ROOT=%ROOT%\Build\Release"
set "DEPS_RELEASE=%OUT_ROOT%"
set "RELEASE_CACHE=%OUT_ROOT%\Cache"
set "CACHE_RUNTIME=%RELEASE_CACHE%\Runtime"
set "CACHE_INTERFACE=%RELEASE_CACHE%\Injector"
set "SCRIPTS_DIR=%BUILD_DIR%\Scripts"
set "TIMESTAMP_SCRIPT=%SCRIPTS_DIR%\AddPE.ps1"
set "MUTATE_SCRIPT=%SCRIPTS_DIR%\BuildPE.ps1"
set "SEED_SCRIPT=%SCRIPTS_DIR%\CreateSeeds.ps1"
set "CONFIG_SCRIPT=%SCRIPTS_DIR%\ProtectConfig.ps1"
set "CONFIG_MASTER=%BUILD_DIR%\Configuration.ini"
rem Auto-VMProtect (optional, on by default):
rem   AMEGER_SKIP_VMP=1             skip protection for both binaries
rem   AMEGER_VMP_CON                full path to VMProtect_Con.exe override
rem   AMEGER_VMP_RUNTIME_PROJECT    .vmp project for the runtime DLL override
rem   AMEGER_VMP_INTERFACE_PROJECT  .vmp project for the interface EXE override
rem The DLL is protected BEFORE its SHA-256 is hashed (the Interface embeds
rem that hash and refuses a mismatched DLL). The EXE is protected AFTER its
rem timestamp/mutate steps (nothing embeds the EXE hash). Missing console ->
rem warning + unprotected build; failing protection -> fatal (fail closed).
set "VMP_SCRIPT=%SCRIPTS_DIR%\CompileVmp.ps1"
set "VMP_RUNTIME_PROJECT=%BUILD_DIR%\Runtime.vmp"
set "VMP_INTERFACE_PROJECT=%BUILD_DIR%\Interface.vmp"
rem VMProtect SDK markers (Ultra regions inside the runtime DLL source):
rem   AMEGER_VMP_MARKERS=0  compile markers as no-ops (no SDK needed)
rem   AMEGER_VMP_SDK        SDK root override (default "C:\Program Files\VMProtect Ultimate")
rem Markers are no-ops when unprotected, so AMEGER_SKIP_VMP builds are unaffected.
set "LIBRARY_PROJ=%ROOT%\Interface\Template\AmegerInjector.vcxproj"
set "INTERFACE_PROJ=%ROOT%\Interface\Template\AmegerInjectorInterface.vcxproj"
set "OUT64=%OUT_ROOT%"
set "LIBRARY64_OBJ=%CACHE_RUNTIME%"
set "INTERFACE64_OBJ=%CACHE_INTERFACE%"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "MSBUILD="

echo [%C_GREEN%1%C_RESET%/%C_GREEN%6%C_RESET%] Checking MSBuild...
echo.
call :find_msbuild
if errorlevel 1 goto :msbuild_error
if not defined AMEGER_PLATFORM_TOOLSET call :select_toolset
set "TOOLSET_ARG="
if defined AMEGER_PLATFORM_TOOLSET set "TOOLSET_ARG=/p:PlatformToolset=%AMEGER_PLATFORM_TOOLSET%"
set "SDK_ARG="
if defined AMEGER_WINDOWS_SDK_VERSION set "SDK_ARG=/p:WindowsTargetPlatformVersion=%AMEGER_WINDOWS_SDK_VERSION%"
echo   %C_GREEN%[+]%C_RESET% MSBuild: %C_GREEN%%MSBUILD%%C_RESET%
if defined AMEGER_PLATFORM_TOOLSET echo   %C_GREEN%[+]%C_RESET% Platform toolset: %C_GREEN%%AMEGER_PLATFORM_TOOLSET%%C_RESET%
if defined AMEGER_WINDOWS_SDK_VERSION echo   %C_GREEN%[+]%C_RESET% Windows SDK: %C_GREEN%%AMEGER_WINDOWS_SDK_VERSION%%C_RESET%
echo.
echo.

echo [%C_GREEN%2%C_RESET%/%C_GREEN%6%C_RESET%] Checking projects...
echo.
if not exist "%LIBRARY_PROJ%" goto :source_error
if not exist "%INTERFACE_PROJ%" goto :source_error
echo   %C_GREEN%[+]%C_RESET% Runtime and Interface projects present.
echo.
echo.

echo [%C_GREEN%3%C_RESET%/%C_GREEN%6%C_RESET%] Cleaning Release and Cache...
echo.
call :clean_directory "%OUT_ROOT%"
if errorlevel 1 goto :clean_error
call :clean_directory "%BUILD_DIR%\obj"
if errorlevel 1 goto :clean_error
call :prepare_cache
if errorlevel 1 goto :clean_error
echo   %C_GREEN%[+]%C_RESET% Clean layout prepared in %C_GREEN%%RELEASE_CACHE%%C_RESET%.
echo.
echo.

echo [%C_GREEN%4%C_RESET%/%C_GREEN%6%C_RESET%] Building Injector...
set "MUTATE_ARGS="
if /i "%AMEGER_SKIP_TIMESTAMP%"=="1" goto :seeds_ready
where powershell.exe >nul 2>&1
if errorlevel 1 goto :seeds_missing
if not exist "%SEED_SCRIPT%" goto :seeds_missing
set "AmegerMmapSentinel="
for /f "usebackq tokens=1,2 delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SEED_SCRIPT%"`) do set "%%A=%%B"
if not defined AmegerMmapSentinel goto :seeds_missing
set "MUTATE_ARGS=/p:AmegerMmapSentinel=%AmegerMmapSentinel%"
echo.
echo   %C_GREEN%[+]%C_RESET% Per-build sentinel: %C_GREEN%%AmegerMmapSentinel%%C_RESET%
goto :seeds_ready

:seeds_missing
echo.
echo   %C_YELLOW%Warning: per-build sentinels unavailable; using default constants.%C_RESET%

:seeds_ready
set "MARKER_ARGS="
if defined AMEGER_VMP_MARKERS set "MARKER_ARGS=/p:AmegerVmpMarkers=%AMEGER_VMP_MARKERS%"
set "VMP_SDK_ARGS="
if defined AMEGER_VMP_SDK set "VMP_SDK_ARGS=/p:AmegerVmpSdk=""%AMEGER_VMP_SDK%"""
set "MUTATE_ARGS=%MUTATE_ARGS% %MARKER_ARGS% %VMP_SDK_ARGS%"
call :build_project "%LIBRARY_PROJ%" x64 "%DEPS_RELEASE%" "%LIBRARY64_OBJ%" "%TOOLSET_ARG%" "%SDK_ARG%" "%MUTATE_ARGS%"
if errorlevel 1 goto :build_error
echo.
if /i "%AMEGER_SKIP_TIMESTAMP%"=="1" goto :runtime_timestamp_ready
if not exist "%TIMESTAMP_SCRIPT%" goto :runtime_timestamp_missing
where powershell.exe >nul 2>&1
if errorlevel 1 goto :hash_error
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%TIMESTAMP_SCRIPT%" "%DEPS_RELEASE%\Ameger Injector - x64.dll"
if errorlevel 1 goto :timestamp_fatal
goto :runtime_timestamp_ready

:runtime_timestamp_missing
echo   %C_YELLOW%Warning: AddPE.ps1 was not found; runtime hash still uses current bytes.%C_RESET%

:runtime_timestamp_ready
if /i "%AMEGER_SKIP_TIMESTAMP%"=="1" goto :runtime_mutate_ready
if not exist "%MUTATE_SCRIPT%" goto :runtime_mutate_missing
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%MUTATE_SCRIPT%" "%DEPS_RELEASE%\Ameger Injector - x64.dll"
if errorlevel 1 goto :mutate_fatal
goto :runtime_mutate_ready

:runtime_mutate_missing
echo   %C_YELLOW%Warning: BuildPE.ps1 was not found; runtime keeps stock PE headers.%C_RESET%
goto :runtime_mutate_ready

:runtime_mutate_ready
if /i "%AMEGER_SKIP_VMP%"=="1" goto :runtime_vmp_skipped
where powershell.exe >nul 2>&1
if errorlevel 1 goto :runtime_vmp_missing
set "VMP_RT_PROJ_ARG="
if defined AMEGER_VMP_RUNTIME_PROJECT set "VMP_RT_PROJ_ARG=-Project ""%AMEGER_VMP_RUNTIME_PROJECT%"""
if not defined VMP_RT_PROJ_ARG if exist "%VMP_RUNTIME_PROJECT%" set "VMP_RT_PROJ_ARG=-Project ""%VMP_RUNTIME_PROJECT%"""
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VMP_SCRIPT%" -InputFile "%DEPS_RELEASE%\Ameger Injector - x64.dll" %VMP_RT_PROJ_ARG% -AutoProcedures
if errorlevel 2 goto :runtime_vmp_missing
if errorlevel 1 goto :vmp_fatal
echo   %C_GREEN%[+]%C_RESET% Runtime DLL protected with VMProtect.
goto :runtime_vmp_ready

:runtime_vmp_missing
echo   %C_YELLOW%Warning: VMProtect unavailable; runtime DLL ships unprotected.%C_RESET%
goto :runtime_vmp_ready

:runtime_vmp_skipped
echo   %C_YELLOW%VMProtect skipped for runtime DLL (AMEGER_SKIP_VMP=1).%C_RESET%

:runtime_vmp_ready
where powershell.exe >nul 2>&1
if errorlevel 1 goto :hash_error
set "RUNTIME_SHA256="
for /f "usebackq tokens=1,2 delims==" %%A in (`powershell.exe -NoLogo -NoProfile -Command "$h=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes('%DEPS_RELEASE%\Ameger Injector - x64.dll'))) -replace '-',''); Write-Output ('RUNTIME_SHA256=' + $h); Write-Output ('H0=0x' + $h.Substring(0,8)); Write-Output ('H1=0x' + $h.Substring(8,8)); Write-Output ('H2=0x' + $h.Substring(16,8)); Write-Output ('H3=0x' + $h.Substring(24,8)); Write-Output ('H4=0x' + $h.Substring(32,8)); Write-Output ('H5=0x' + $h.Substring(40,8)); Write-Output ('H6=0x' + $h.Substring(48,8)); Write-Output ('H7=0x' + $h.Substring(56,8))"`) do set "%%A=%%B"
if not defined RUNTIME_SHA256 goto :hash_error
if not defined H0 goto :hash_error
if not defined H1 goto :hash_error
if not defined H2 goto :hash_error
if not defined H3 goto :hash_error
if not defined H4 goto :hash_error
if not defined H5 goto :hash_error
if not defined H6 goto :hash_error
if not defined H7 goto :hash_error
set "RUNTIME_HASH_ARGS=/p:AmegerRuntimeHash0=%H0% /p:AmegerRuntimeHash1=%H1% /p:AmegerRuntimeHash2=%H2% /p:AmegerRuntimeHash3=%H3% /p:AmegerRuntimeHash4=%H4% /p:AmegerRuntimeHash5=%H5% /p:AmegerRuntimeHash6=%H6% /p:AmegerRuntimeHash7=%H7%"
rem Value column is shared with BuildPE.ps1's closing summary line; both start
rem at 2-space indent. "10/10 mutations applied" is 23 chars, "Runtime SHA-256:"
rem is 16, so the 8 spaces below land the hash under the path. If you retune one,
rem retune the other.
echo   %C_GREEN%[+]%C_RESET% Runtime SHA-256:        %RUNTIME_SHA256%
echo.
call :build_project "%INTERFACE_PROJ%" x64 "%OUT64%" "%INTERFACE64_OBJ%" "%TOOLSET_ARG%" "%SDK_ARG%" "%RUNTIME_HASH_ARGS% %MARKER_ARGS% %VMP_SDK_ARGS%"
if errorlevel 1 goto :build_error
echo.
echo.

echo [%C_GREEN%5%C_RESET%/%C_GREEN%6%C_RESET%] Deploying release binaries...
echo.
echo   %C_GREEN%[+]%C_RESET% Runtime binaries are in %C_GREEN%%OUT_ROOT%%C_RESET%.
if exist "%CONFIG_MASTER%" call :protect_config
if /i "%AMEGER_VMP_MARKERS%"=="0" goto :sdk_copy_skipped
set "VMP_SDK_DIR=%AMEGER_VMP_SDK%"
if not defined VMP_SDK_DIR set "VMP_SDK_DIR=C:\Program Files\VMProtect Ultimate"
if not exist "%VMP_SDK_DIR%\Lib\Windows\VMProtectSDK64.dll" goto :sdk_fatal
copy /y "%VMP_SDK_DIR%\Lib\Windows\VMProtectSDK64.dll" "%OUT_ROOT%\" >nul
if errorlevel 1 goto :sdk_fatal
echo   %C_GREEN%[+]%C_RESET% VMProtect SDK runtime deployed.
goto :sdk_copy_ready

:sdk_copy_skipped
echo   %C_YELLOW%VMProtect SDK runtime not needed (markers disabled).%C_RESET%

:sdk_copy_ready
echo.
echo.

echo [%C_GREEN%6%C_RESET%/%C_GREEN%6%C_RESET%] Sweeping intermediates into Cache and verifying...
echo.
call :verify "%OUT64%\Injector - x64.exe" "x64 Interface"
if errorlevel 1 goto :verify_error
call :verify "%DEPS_RELEASE%\Ameger Injector - x64.dll" "x64 runtime"
if errorlevel 1 goto :verify_error
call :remove_import_artifacts "%DEPS_RELEASE%"
if errorlevel 1 goto :cleanup_error
call :sweep_artifacts
if errorlevel 1 goto :cleanup_error
echo.
echo   %C_GREEN%[+]%C_RESET% Cache groups: Runtime, Interface.
echo.
echo.

if /i "%AMEGER_SKIP_TIMESTAMP%"=="1" goto :timestamp_skipped
if not exist "%TIMESTAMP_SCRIPT%" goto :timestamp_missing
where powershell.exe >nul 2>&1
if errorlevel 1 goto :timestamp_missing
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%TIMESTAMP_SCRIPT%" "%OUT64%\Injector - x64.exe"
if errorlevel 1 goto :timestamp_error
if /i "%AMEGER_SKIP_TIMESTAMP%"=="1" goto :timestamp_skipped
if not exist "%MUTATE_SCRIPT%" goto :timestamp_skipped
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%MUTATE_SCRIPT%" "%OUT64%\Injector - x64.exe"
if errorlevel 1 goto :mutate_exe_error

:timestamp_skipped
call :protect_exe
if errorlevel 1 goto :vmp_fatal
echo.
echo %C_GREEN%Build completed successfully.%C_RESET%
echo.
echo Cache:   %C_GREEN%%RELEASE_CACHE%%C_RESET%
echo Interface x64: %C_GREEN%%OUT64%\Injector - x64.exe%C_RESET%
echo Runtime DLL: %C_GREEN%%DEPS_RELEASE%\Ameger Injector - x64.dll%C_RESET%
echo.
if "%NO_PAUSE%"=="0" pause
exit /b 0

:find_msbuild
if exist "%VSWHERE%" for /f "usebackq delims=" %%M in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" 2^>nul`) do if not defined MSBUILD if exist "%%M" set "MSBUILD=%%M"
if defined MSBUILD exit /b 0
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\18\Professional\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\18\Professional\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\18\Enterprise\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\18\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if defined MSBUILD exit /b 0
for /f "delims=" %%M in ('where msbuild.exe 2^>nul') do if not defined MSBUILD set "MSBUILD=%%M"
if defined MSBUILD exit /b 0
exit /b 1

:select_toolset
if defined AMEGER_PLATFORM_TOOLSET exit /b 0
if not exist "%VSWHERE%" exit /b 0
set "VS_VERSION="
for /f "usebackq delims=" %%V in (`"%VSWHERE%" -latest -products * -property installationVersion 2^>nul`) do if not defined VS_VERSION set "VS_VERSION=%%V"
if not defined VS_VERSION exit /b 0
for /f "tokens=1 delims=." %%V in ("%VS_VERSION%") do set "VS_MAJOR=%%V"
if "%VS_MAJOR%"=="18" set "AMEGER_PLATFORM_TOOLSET=v145"
if "%VS_MAJOR%"=="17" set "AMEGER_PLATFORM_TOOLSET=v143"
exit /b 0

:clean_directory
if exist "%~1" rmdir /s /q "%~1"
if exist "%~1" exit /b 1
exit /b 0

:prepare_cache
if not exist "%DEPS_RELEASE%" mkdir "%DEPS_RELEASE%"
if not exist "%RELEASE_CACHE%" mkdir "%RELEASE_CACHE%"
if not exist "%CACHE_RUNTIME%" mkdir "%CACHE_RUNTIME%"
if not exist "%CACHE_INTERFACE%" mkdir "%CACHE_INTERFACE%"
if not exist "%CACHE_RUNTIME%" exit /b 1
if not exist "%CACHE_INTERFACE%" exit /b 1
exit /b 0

:build_project
set "PROJECT=%~1"
set "ARCH=%~2"
set "PROJECT_OUT=%~3"
set "PROJECT_INT=%~4"
set "TOOLSET_ARG=%~5"
set "SDK_ARG=%~6"
set "HASH_ARG=%~7"
if not exist "%PROJECT%" exit /b 2
if not exist "%PROJECT_OUT%" mkdir "%PROJECT_OUT%"
if not exist "%PROJECT_OUT%" exit /b 2
if not exist "%PROJECT_INT%" mkdir "%PROJECT_INT%"
if not exist "%PROJECT_INT%" exit /b 2
echo   %C_GREEN%Building%C_RESET% %PROJECT% %C_RED%(%ARCH%)%C_RESET%
"%MSBUILD%" "%PROJECT%" /nologo /m /nodeReuse:false /v:minimal /t:Build /p:Configuration=Release /p:Platform=%~2 "/p:OutDir=%~3\\" "/p:IntDir=%~4\\" %~5 %~6 %~7
exit /b %ERRORLEVEL%

:verify
if not exist "%~1" exit /b 1
echo   %C_GREEN%OK%C_RESET% %~2: %C_GREEN%"%~1"%C_RESET%
exit /b 0

:remove_import_artifacts
for %%F in ("%~1\*.lib" "%~1\*.exp") do if exist "%%~F" del /f /q "%%~F"
exit /b 0

:sweep_artifacts
for %%F in ("%DEPS_RELEASE%\Ameger Injector - *.pdb") do if exist "%%~F" move "%%~F" "%CACHE_RUNTIME%\" >nul
for %%F in ("%OUT64%\Injector - x64.pdb") do if exist "%%~F" move "%%~F" "%CACHE_INTERFACE%\" >nul
exit /b 0

:protect_config
rem Ship a DPAPI-encrypted copy of the config next to the EXE so the deployed
rem folder exposes no readable target name or stealth toggles. The plaintext
rem master in Build\ stays the editable source of truth.
if /i "%AMEGER_ENCRYPT_CONFIG%"=="0" (
  echo   %C_YELLOW%Config encryption disabled; shipping plaintext.%C_RESET%
  exit /b 0
)
if not exist "%CONFIG_SCRIPT%" (
  echo   %C_YELLOW%Warning: ProtectConfig.ps1 not found; shipping plaintext config.%C_RESET%
  exit /b 0
)
where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo   %C_YELLOW%Warning: PowerShell unavailable; shipping plaintext config.%C_RESET%
  exit /b 0
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%CONFIG_SCRIPT%" -Source "%CONFIG_MASTER%" -Destination "%OUT_ROOT%\Configuration.ini"
if errorlevel 1 (
  echo   %C_YELLOW%Warning: config encryption failed; shipping plaintext config.%C_RESET%
  exit /b 0
)
echo   %C_GREEN%[+]%C_RESET% Configuration encrypted for deployment.
exit /b 0

:protect_exe
if /i "%AMEGER_SKIP_VMP%"=="1" (  echo   %C_YELLOW%VMProtect skipped for interface EXE via AMEGER_SKIP_VMP=1.%C_RESET%
  exit /b 0
)
where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo   %C_YELLOW%Warning: PowerShell unavailable; interface EXE ships unprotected.%C_RESET%
  exit /b 0
)
set "VMP_EXE_PROJ_ARG="
if defined AMEGER_VMP_INTERFACE_PROJECT set "VMP_EXE_PROJ_ARG=-Project ""%AMEGER_VMP_INTERFACE_PROJECT%"""
if not defined VMP_EXE_PROJ_ARG if exist "%VMP_INTERFACE_PROJECT%" set "VMP_EXE_PROJ_ARG=-Project ""%VMP_INTERFACE_PROJECT%"""
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VMP_SCRIPT%" -InputFile "%OUT64%\Injector - x64.exe" %VMP_EXE_PROJ_ARG% -AutoProcedures
if errorlevel 2 (
  echo   %C_YELLOW%Warning: VMProtect unavailable; interface EXE ships unprotected.%C_RESET%
  exit /b 0
)
if errorlevel 1 exit /b 1
echo   %C_GREEN%[+]%C_RESET% Interface EXE protected with VMProtect.
exit /b 0

:msbuild_error
echo %C_RED%ERROR: MSBuild was not found.%C_RESET%
goto :failure

:source_error
echo %C_RED%ERROR: one or more required project files are missing.%C_RESET%
goto :failure

:clean_error
echo %C_RED%ERROR: unable to prepare the Release or Cache directory.%C_RESET%
goto :failure

:build_error
echo %C_RED%ERROR: a project build failed.%C_RESET%
goto :failure

:hash_error
echo %C_RED%ERROR: unable to calculate the runtime DLL SHA-256.%C_RESET%
goto :failure

:verify_error
echo %C_RED%ERROR: one or more expected binaries are missing.%C_RESET%
goto :failure

:cleanup_error
echo %C_RED%ERROR: unable to remove generated import artifacts.%C_RESET%
goto :failure

:timestamp_missing
echo %C_RED%WARNING: AddPE.ps1 or PowerShell was not found; binaries were not retimestamped.%C_RESET%
goto :success_without_timestamp

:timestamp_fatal
echo %C_RED%ERROR: unable to retimestamp the runtime DLL; refusing to continue with an inconsistent build.%C_RESET%
goto :failure

:mutate_fatal
echo %C_RED%ERROR: unable to mutate the runtime DLL; refusing to continue with an inconsistent build.%C_RESET%
goto :failure

:vmp_fatal
echo %C_RED%ERROR: VMProtect failed; refusing to continue with an inconsistent build.%C_RESET%
echo %C_RED%Check the .vmp project procedures against the target binary.%C_RESET%
goto :failure

:sdk_fatal
echo %C_RED%ERROR: VMProtectSDK64.dll not found in "%VMP_SDK_DIR%\Lib\Windows".%C_RESET%
echo %C_RED%The runtime DLL imports it for Ultra markers; install the SDK or set AMEGER_VMP_MARKERS=0.%C_RESET%
goto :failure

:mutate_exe_error
echo %C_YELLOW%WARNING: interface PE mutation failed; binary remains usable.%C_RESET%
goto :timestamp_skipped

:timestamp_error
echo %C_RED%WARNING: retimestamping failed; binaries remain usable.%C_RESET%
goto :success_without_timestamp

:success_without_timestamp
call :protect_exe
if errorlevel 1 goto :vmp_fatal
echo.
echo %C_GREEN%Build completed successfully.%C_RESET%
echo.
echo Cache:   %C_GREEN%%RELEASE_CACHE%%C_RESET%
echo Interface x64: %C_GREEN%%OUT64%\Injector - x64.exe%C_RESET%
echo Runtime DLL: %C_GREEN%%DEPS_RELEASE%\Ameger Injector - x64.dll%C_RESET%
if "%NO_PAUSE%"=="0" pause
exit /b 0

:failure
if "%NO_PAUSE%"=="0" pause
exit /b 1
