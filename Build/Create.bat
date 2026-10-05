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
set "DLL_DIR=%OUT_ROOT%\DLLs"
set "DEPS_RELEASE=%OUT_ROOT%"
set "RELEASE_CACHE=%OUT_ROOT%\Cache"
set "CACHE_RUNTIME=%RELEASE_CACHE%\Runtime"
set "CACHE_INTERFACE=%RELEASE_CACHE%\Injector"
set "SCRIPTS_DIR=%BUILD_DIR%\Scripts"
set "TIMESTAMP_SCRIPT=%SCRIPTS_DIR%\AddPE.ps1"
set "MUTATE_SCRIPT=%SCRIPTS_DIR%\BuildPE.ps1"
set "SEED_SCRIPT=%SCRIPTS_DIR%\CreateSeeds.ps1"
set "CONFIG_SCRIPT=%SCRIPTS_DIR%\ProtectConfig.ps1"
set "VERIFY_SCRIPT=%SCRIPTS_DIR%\VerifyEmbedMagic.ps1"
set "CONFIG_MASTER=%BUILD_DIR%\Configuration.ini"
set "PAYLOAD_ASSET=%ROOT%\Assets\DLL\Jlov.dll"
set "PAYLOAD_DEST=%DLL_DIR%\Jlov.dll"
rem Stock runtime build output name (the runtime vcxproj TargetName). Referenced
rem only before the hash-derived rename below; after the rename the release
rem folder carries no file by this name.
set "RUNTIME_STOCK_DLL=%DEPS_RELEASE%\Ameger Injector - x64.dll"
rem The Interface embeds the runtime DLL's SHA-256 and refuses a mismatched DLL.
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
set "AmegerStringSeed="
for /f "usebackq tokens=1,2 delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SEED_SCRIPT%"`) do set "%%A=%%B"
if not defined AmegerMmapSentinel goto :seeds_missing
if not defined AmegerStringSeed goto :seeds_missing
set "MUTATE_ARGS=/p:AmegerMmapSentinel=%AmegerMmapSentinel% /p:AmegerStringSeed=%AmegerStringSeed%"
echo.
echo   %C_GREEN%[+]%C_RESET% Per-build sentinel: %C_GREEN%%AmegerMmapSentinel%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Per-build string seed: %C_GREEN%%AmegerStringSeed%%C_RESET%
goto :seeds_ready

:seeds_missing
echo.
echo   %C_RED%ERROR: per-build seed generation failed; refusing to build with fixed seeds.%C_RESET%
goto :failure

:seeds_ready
call :build_project "%LIBRARY_PROJ%" x64 "%DEPS_RELEASE%" "%LIBRARY64_OBJ%" "%TOOLSET_ARG%" "%SDK_ARG%" "%MUTATE_ARGS%"
if errorlevel 1 goto :build_error
echo.
if /i "%AMEGER_SKIP_TIMESTAMP%"=="1" goto :runtime_timestamp_ready
if not exist "%TIMESTAMP_SCRIPT%" goto :runtime_timestamp_missing
where powershell.exe >nul 2>&1
if errorlevel 1 goto :hash_error
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%TIMESTAMP_SCRIPT%" "%RUNTIME_STOCK_DLL%"
if errorlevel 1 goto :timestamp_fatal
goto :runtime_timestamp_ready

:runtime_timestamp_missing
echo   %C_RED%ERROR: AddPE.ps1 was not found; refusing to continue with an untimestamped runtime DLL.%C_RESET%
goto :failure

:runtime_timestamp_ready
if /i "%AMEGER_SKIP_TIMESTAMP%"=="1" goto :runtime_mutate_ready
if not exist "%MUTATE_SCRIPT%" goto :runtime_mutate_missing
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%MUTATE_SCRIPT%" "%RUNTIME_STOCK_DLL%"
if errorlevel 1 goto :mutate_fatal
goto :runtime_mutate_ready

:runtime_mutate_missing
echo   %C_RED%ERROR: BuildPE.ps1 was not found; refusing to continue with an unmutated runtime DLL.%C_RESET%
goto :failure

:runtime_mutate_ready
where powershell.exe >nul 2>&1
if errorlevel 1 goto :hash_error
set "RUNTIME_SHA256="
for /f "usebackq tokens=1,2 delims==" %%A in (`powershell.exe -NoLogo -NoProfile -Command "$h=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes('%RUNTIME_STOCK_DLL%'))) -replace '-',''); Write-Output ('RUNTIME_SHA256=' + $h); Write-Output ('H0=0x' + $h.Substring(0,8)); Write-Output ('H1=0x' + $h.Substring(8,8)); Write-Output ('H2=0x' + $h.Substring(16,8)); Write-Output ('H3=0x' + $h.Substring(24,8)); Write-Output ('H4=0x' + $h.Substring(32,8)); Write-Output ('H5=0x' + $h.Substring(40,8)); Write-Output ('H6=0x' + $h.Substring(48,8)); Write-Output ('H7=0x' + $h.Substring(56,8))"`) do set "%%A=%%B"
if not defined RUNTIME_SHA256 goto :hash_error
if not defined H0 goto :hash_error
if not defined H1 goto :hash_error
if not defined H2 goto :hash_error
if not defined H3 goto :hash_error
if not defined H4 goto :hash_error
if not defined H5 goto :hash_error
if not defined H6 goto :hash_error
if not defined H7 goto :hash_error
set "RUNTIME_HASH_ARGS=/p:AmegerRuntimeHash0=%H0% /p:AmegerRuntimeHash1=%H1% /p:AmegerRuntimeHash2=%H2% /p:AmegerRuntimeHash3=%H3% /p:AmegerRuntimeHash4=%H4% /p:AmegerRuntimeHash5=%H5% /p:AmegerRuntimeHash6=%H6% /p:AmegerRuntimeHash7=%H7% /p:AmegerStringSeed=%AmegerStringSeed%"
rem Rename the runtime DLL to the hash-derived name the Interface computes
rem (RuntimePath() in Main.cpp: DLLs\rtdll_<first 8 hex of H0>.dll). The hash
rem above was taken from the stock path, and AddPE/BuildPE already ran on it, so
rem this is the last step that touches the stock name. A failed move must abort
rem rather than ship a folder whose runtime DLL is missing or misnamed.
set "RUNTIME_DLL_NAME=rtdll_%H0:~2%.dll"
set "RUNTIME_DLL=%DLL_DIR%\%RUNTIME_DLL_NAME%"
if not exist "%DLL_DIR%" mkdir "%DLL_DIR%"
move /y "%RUNTIME_STOCK_DLL%" "%RUNTIME_DLL%" >nul
if not exist "%RUNTIME_DLL%" goto :runtime_rename_error
rem Value column is shared with BuildPE.ps1's closing summary line; both start
rem at 2-space indent. "11/11 mutations applied" is 23 chars, "Runtime SHA-256:"
rem is 16, so the 8 spaces below land the hash under the path. If you retune one,
rem retune the other.
echo   %C_GREEN%[+]%C_RESET% Runtime SHA-256:        %RUNTIME_SHA256%
echo.
call :build_project "%INTERFACE_PROJ%" x64 "%OUT64%" "%INTERFACE64_OBJ%" "%TOOLSET_ARG%" "%SDK_ARG%" "%RUNTIME_HASH_ARGS%"
if errorlevel 1 goto :build_error
echo.
echo.

echo [%C_GREEN%5%C_RESET%/%C_GREEN%6%C_RESET%] Deploying release binaries...
echo.
echo   %C_GREEN%[+]%C_RESET% Runtime binaries are in %C_GREEN%%OUT_ROOT%%C_RESET%.
call :protect_config
if errorlevel 1 goto :config_error
call :deploy_payload
if errorlevel 1 goto :payload_error
echo.
echo.

echo [%C_GREEN%6%C_RESET%/%C_GREEN%6%C_RESET%] Sweeping intermediates into Cache and verifying...
echo.
call :verify "%OUT64%\Host - x64.exe" "x64 Interface"
if errorlevel 1 goto :verify_error
call :verify_embed
if errorlevel 1 goto :verify_content_error
if /i not "%AMEGER_ENCRYPT_CONFIG%"=="0" (
  call :verify_config_magic
  if errorlevel 1 goto :verify_content_error
)
call :verify "%RUNTIME_DLL%" "x64 runtime"
if errorlevel 1 goto :verify_error
call :remove_import_artifacts "%DEPS_RELEASE%"
if errorlevel 1 goto :cleanup_error
call :remove_import_artifacts "%DLL_DIR%"
if errorlevel 1 goto :cleanup_error
call :sweep_artifacts
if errorlevel 1 goto :cleanup_error
echo.
echo   %C_GREEN%[+]%C_RESET% Cache groups: Runtime, Injector.
echo.
echo.

if /i "%AMEGER_SKIP_TIMESTAMP%"=="1" goto :success_without_timestamp
if not exist "%TIMESTAMP_SCRIPT%" goto :timestamp_missing
where powershell.exe >nul 2>&1
if errorlevel 1 goto :timestamp_missing
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%TIMESTAMP_SCRIPT%" "%OUT64%\Host - x64.exe"
if errorlevel 1 goto :timestamp_error
if not exist "%MUTATE_SCRIPT%" goto :mutate_exe_error
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%MUTATE_SCRIPT%" "%OUT64%\Host - x64.exe"
if errorlevel 1 goto :mutate_exe_error

:timestamp_skipped
echo.
echo Build completed successfully.
echo.
echo Cache:   %C_GREEN%%RELEASE_CACHE%%C_RESET%
echo Payload:     %C_GREEN%%PAYLOAD_DEST%%C_RESET%
echo Interface x64: %C_GREEN%%OUT64%\Host - x64.exe%C_RESET%
echo Runtime DLL: %C_GREEN%%RUNTIME_DLL%%C_RESET%

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
if not exist "%DLL_DIR%" mkdir "%DLL_DIR%"
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

:verify_embed
rem The interface embeds the runtime DLL's 8 SHA-256 words (AmegerRuntimeHash0..7
rem computed above); prove they are really present, in order, as little-endian
rem dwords rather than the default zero constants.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SCRIPT%" -Check Embed -Path "%OUT64%\Host - x64.exe" -Words "%H0%,%H1%,%H2%,%H3%,%H4%,%H5%,%H6%,%H7%"
exit /b %ERRORLEVEL%

:verify_config_magic
rem Encryption is on, so the deployed config must carry the SYSCFG01 marker.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SCRIPT%" -Check Magic -Path "%OUT_ROOT%\Configuration.ini" -Magic SYSCFG01
exit /b %ERRORLEVEL%

:remove_import_artifacts
rem Fail closed: a leftover .lib/.exp in the release folder is a build fingerprint,
rem so a failed delete must abort the build rather than silently ship it.
for %%F in ("%~1\*.lib" "%~1\*.exp") do if exist "%%~F" (
  del /f /q "%%~F"
  if exist "%%~F" exit /b 1
)
exit /b 0

:sweep_artifacts
rem Same fail-closed rule for the intermediates: a .pdb left in the release
rem folder leaks the original symbol paths, so a failed move must abort.
for %%F in ("%DEPS_RELEASE%\Ameger Injector - *.pdb") do if exist "%%~F" (
  move "%%~F" "%CACHE_RUNTIME%\" >nul
  if exist "%%~F" exit /b 1
)
for %%F in ("%OUT64%\Injector - x64.pdb") do if exist "%%~F" (
  move "%%~F" "%CACHE_INTERFACE%\" >nul
  if exist "%%~F" exit /b 1
)
exit /b 0

:protect_config
rem Ship a DPAPI-encrypted copy of the config next to the EXE so the deployed
rem folder exposes no readable target name or stealth toggles. The plaintext
rem master in Build\ stays the editable source of truth.
rem
rem Fail closed: unless encryption is explicitly disabled, never ship a
rem plaintext or absent config. The runtime requires Configuration.ini next to
rem the EXE, so a silent miss here would produce a broken release.
if /i "%AMEGER_ENCRYPT_CONFIG%"=="0" (
  if exist "%CONFIG_MASTER%" copy /y "%CONFIG_MASTER%" "%OUT_ROOT%\Configuration.ini" >nul
  echo   %C_YELLOW%Config encryption disabled ^(AMEGER_ENCRYPT_CONFIG=0^); shipping plaintext.%C_RESET%
  exit /b 0
)
if not exist "%CONFIG_MASTER%" (
  echo   %C_RED%ERROR: master config not found: %CONFIG_MASTER%%C_RESET%
  exit /b 1
)
if not exist "%CONFIG_SCRIPT%" (
  echo   %C_RED%ERROR: ProtectConfig.ps1 not found; refusing to ship a plaintext config.%C_RESET%
  exit /b 1
)
where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo   %C_RED%ERROR: PowerShell unavailable; refusing to ship a plaintext config.%C_RESET%
  exit /b 1
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%CONFIG_SCRIPT%" -Source "%CONFIG_MASTER%" -Destination "%OUT_ROOT%\Configuration.ini"
if errorlevel 1 (
  echo   %C_RED%ERROR: config encryption failed; refusing to ship a plaintext config.%C_RESET%
  exit /b 1
)
echo   %C_GREEN%[+]%C_RESET% Configuration encrypted for deployment.
exit /b 0

:deploy_payload
rem Ship the target payload next to the EXE so the release folder is
rem self-contained. Fail closed: a missing asset or a failed copy would leave
rem the injector without the DLL it targets, so never skip silently.
if not exist "%PAYLOAD_ASSET%" (
  echo   %C_RED%ERROR: payload asset not found: %PAYLOAD_ASSET%%C_RESET%
  exit /b 1
)
copy /y "%PAYLOAD_ASSET%" "%PAYLOAD_DEST%" >nul
if errorlevel 1 (
  echo   %C_RED%ERROR: failed to copy payload to %PAYLOAD_DEST%%C_RESET%
  exit /b 1
)
rem Fail closed: the deployed DLL must match the PayloadSha256 pin in the
rem plaintext master. A stale or substituted payload would silently defeat the
rem injector's pinned-hash startup check, so verify now and abort on mismatch.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SCRIPT%" -Check PayloadHash -Path "%PAYLOAD_DEST%" -Config "%CONFIG_MASTER%"
if errorlevel 1 (
  echo   %C_RED%ERROR: deployed payload failed hash verification.%C_RESET%
  exit /b 1
)
echo   %C_GREEN%[+]%C_RESET% Payload deployed: %C_GREEN%%PAYLOAD_DEST%%C_RESET%
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Set-Clipboard -Value '%PAYLOAD_DEST%'" >nul 2>&1
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

:runtime_rename_error
echo %C_RED%ERROR: unable to rename the runtime DLL to its hash-derived name.%C_RESET%
goto :failure

:verify_error
echo %C_RED%ERROR: one or more expected binaries are missing.%C_RESET%
goto :failure

:verify_content_error
echo %C_RED%ERROR: embedded runtime hash or config magic verification failed.%C_RESET%
goto :failure

:cleanup_error
echo %C_RED%ERROR: unable to remove generated import artifacts.%C_RESET%
goto :failure

:config_error
echo %C_RED%ERROR: unable to deploy an encrypted configuration.%C_RESET%
goto :failure

:payload_error
echo %C_RED%ERROR: unable to deploy the target payload.%C_RESET%
goto :failure

:timestamp_missing
echo %C_RED%ERROR: AddPE.ps1 or PowerShell was not found; refusing to continue with an untimestamped build.%C_RESET%
goto :failure

:timestamp_fatal
echo %C_RED%ERROR: unable to retimestamp the runtime DLL; refusing to continue with an inconsistent build.%C_RESET%
goto :failure

:mutate_fatal
echo %C_RED%ERROR: unable to mutate the runtime DLL; refusing to continue with an inconsistent build.%C_RESET%
goto :failure

:mutate_exe_error
echo %C_RED%ERROR: interface PE mutation failed or BuildPE.ps1 was not found; refusing to continue with an inconsistent build.%C_RESET%
goto :failure

:timestamp_error
echo %C_RED%ERROR: retimestamping the interface EXE failed; refusing to continue with an inconsistent build.%C_RESET%
goto :failure

:success_without_timestamp
echo.
echo %C_RED%ERROR: AMEGER_SKIP_TIMESTAMP=1 ships unmutated binaries (stable timestamps, MSVC Rich fingerprint, standard section names, PDB debug directory). Refusing: rebuild without the bypass for any shipped build.%C_RESET%
goto :failure

:failure
if "%NO_PAUSE%"=="0" pause
exit /b 1
